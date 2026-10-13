"""
agent.mock -- deterministic, deliberately gullible test agent.

The MockAgent always obeys the last instruction it sees in the prompt,
regardless of origin. This makes it maximally susceptible to prompt
injection, which is exactly what we want for integration tests: if the
firewall doesn't stop an attack, the mock agent will execute it and the
test will catch the consequence.

Important: MockAgent normalizes prompts through the same normalization
pipeline a real tokenizer effectively would (unicode normalization with
tag-block recovery, followed by transport unwrapping) before matching.
This prevents encoded/unicode-hidden attacks from appearing "blocked"
merely because a fake agent failed to parse them.

This module is intentionally insecure. ruff S-rules are suppressed for
this file in pyproject.toml. Do not use in production.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from spanguard import config
from spanguard.normalize.unicode import normalize_unicode
from spanguard.normalize.unwrap import unwrap, unwrap_embedded
from spanguard.policy import Policy
from spanguard.tools import AgentReply, ToolCallRequest


@runtime_checkable
class Agent(Protocol):
    """Uniform protocol for LLM agent backends."""

    def respond(self, prompt: str) -> AgentReply:
        """Generate an AgentReply for the rendered prompt string."""
        ...


class MockAgent:
    """Deliberately gullible, deterministic mock LLM agent.

    Scans normalized prompts for injection patterns; if found, complies by
    emitting a tool call leaking the registered canary. Otherwise returns
    a benign reply.
    """

    def __init__(
        self,
        canary: str = config.MOCK_DEFAULT_CANARY,
        policy: Policy | None = None,
    ) -> None:
        """Initialize mock agent with a canary secret or Policy."""
        if policy is not None and policy.canary_secrets:
            self.canary = policy.canary_secrets[0]
        else:
            self.canary = canary
        self.policy = policy

    def _extract_normalized_views(self, prompt: str) -> list[str]:
        """Normalize prompt text through tokenizer-equivalent pipeline."""
        norm_res = normalize_unicode(prompt)
        candidates: list[str] = [prompt]
        if norm_res.recovered:
            candidates.append(norm_res.recovered)
        if norm_res.unmasked:
            candidates.append(norm_res.unmasked)
        if norm_res.cleaned:
            candidates.append(norm_res.cleaned)

        targets: list[str] = []
        for c in candidates:
            targets.append(c)
            unwrapped = unwrap(c)
            if unwrapped != c:
                targets.append(unwrapped)
            targets.extend(unwrap_embedded(c))

        return targets

    def respond(self, prompt: str) -> AgentReply:
        """Respond to prompt, complying with any detected injection instructions."""
        targets = self._extract_normalized_views(prompt)

        is_attack = any(config.RE_MOCK_INJECTION.search(t) for t in targets)

        if is_attack:
            # Gullible compliance: emit tool call leaking canary secret in argument
            return AgentReply(
                text=config.MOCK_COMPLIANT_REPLY_TEXT,
                tool_calls=(
                    ToolCallRequest(
                        tool_name=config.MOCK_EXFIL_TOOL_NAME,
                        args={
                            config.MOCK_EXFIL_RECIPIENT_KEY: config.MOCK_EXFIL_RECIPIENT_VALUE,
                            config.MOCK_EXFIL_BODY_KEY: f"Exfiltrated canary: {self.canary}",
                        },
                    ),
                ),
            )

        return AgentReply(
            text=config.MOCK_CLEAN_REPLY_TEXT,
            tool_calls=(),
        )


__all__ = ["Agent", "MockAgent"]
