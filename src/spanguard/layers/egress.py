"""
layers.egress -- outbound egress and data-exfiltration detection layer.

Inspects model responses (AgentReply text and tool call arguments) for:
    1. Registered canary leaks across the bounded readings closure
       (plain text, spaced-out, base64, hex, reversed, rot13, zero-width).
    2. Disallowed outbound URL destinations (with label-boundary suffix matching,
       optional scheme, and protocol-relative support).
    3. CamoLeak defense: scanning URL query strings and paths on allowlisted hosts.
    4. Outbound byte limit caps (per-string and aggregate across an AgentReply).

All findings emitted by this layer check structural facts and have invariant=True
and severity=CRITICAL.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from spanguard import config
from spanguard.normalize.views import readings
from spanguard.policy import Policy, PolicyError, normalize_canary
from spanguard.tools import AgentReply
from spanguard.verdict import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from spanguard.context import Context

# ---------------------------------------------------------------------------
# Allowlist label-boundary matcher
# ---------------------------------------------------------------------------


def is_host_allowlisted(host: str, allowlist: Sequence[str]) -> bool:
    """Return True if host matches an entry in allowlist on a domain label boundary.

    Matches:
        - Exact host match: 'example.com' matches 'example.com' or '.example.com'
        - Subdomain label boundary: 'mail.example.com' matches '.example.com'
    Rejects:
        - Boundary evasion: 'evilexample.com' does NOT match '.example.com'
    """
    host_clean = host.lower()
    for allowed in allowlist:
        allowed_clean = allowed.lower()
        suffix = allowed_clean.lstrip(".")
        if host_clean == suffix or host_clean.endswith("." + suffix):
            return True
    return False


# ---------------------------------------------------------------------------
# String extraction helper
# ---------------------------------------------------------------------------


def _extract_strings(value: object) -> list[str]:
    """Extract strings from argument keys and values: both are outbound data."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for key, v in value.items():
            if isinstance(key, str):
                strings.append(key)
            strings.extend(_extract_strings(v))
        return strings
    if isinstance(value, (list, tuple, set, frozenset)):
        strings = []
        for item in value:
            strings.extend(_extract_strings(item))
        return strings
    return []


# ---------------------------------------------------------------------------
# EgressLayer
# ---------------------------------------------------------------------------


class EgressLayer:
    """Invariant egress inspection layer.

    Scans outbound text and tool call arguments for canary leaks, disallowed
    hosts, and byte overruns.
    """

    name: str = config.LAYER_EGRESS

    def __init__(
        self,
        canaries: Sequence[str] | None = None,
        policy: Policy | None = None,
    ) -> None:
        """Initialize with optional canaries or Policy, enforcing length floor."""
        self.canaries: tuple[str, ...] = tuple(canaries) if canaries is not None else ()
        self.policy: Policy | None = policy

        for c in self.canaries:
            normalized = normalize_canary(c)
            if len(normalized) < config.MIN_CANARY_LENGTH:
                raise PolicyError(
                    f"Canary secret is too short after normalization "
                    f"({len(normalized)} < {config.MIN_CANARY_LENGTH}): {c!r}"
                )

    def _scan_canaries(self, text: str, canaries: Sequence[str]) -> list[Finding]:
        """Scan text across readings closure for any registered canary."""
        findings: list[Finding] = []
        if not text or not canaries:
            return findings

        variants = readings(text, max_variants=config.EGRESS_MAX_VARIANTS)
        normalized_canaries = [normalize_canary(c) for c in canaries]

        for _, norm_c in zip(canaries, normalized_canaries, strict=True):
            matched = False
            for variant in variants:
                norm_v = normalize_canary(variant)
                if norm_c in norm_v:
                    matched = True
                    break
            if matched:
                findings.append(
                    Finding(
                        layer=config.LAYER_EGRESS,
                        rule=config.RULE_CANARY_LEAK,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=config.EVIDENCE_CANARY_LEAK,
                    )
                )
        return findings

    def inspect_reply(
        self,
        reply_or_ctx: AgentReply | Context,
        policy_or_reply: Policy | AgentReply,
        policy: Policy | None = None,
        ctx: Context | None = None,
    ) -> list[Finding]:
        """Inspect all outbound surfaces of an AgentReply."""
        target_reply: AgentReply
        target_policy: Policy

        if isinstance(reply_or_ctx, AgentReply):
            target_reply = reply_or_ctx
            target_policy = (
                policy_or_reply
                if isinstance(policy_or_reply, Policy)
                else (self.policy or Policy())
            )
        elif isinstance(policy_or_reply, AgentReply):
            target_reply = policy_or_reply
            target_policy = policy if policy is not None else (self.policy or Policy())
        else:
            msg = "Either reply_or_ctx or policy_or_reply must be an AgentReply"
            raise TypeError(msg)

        all_canaries: tuple[str, ...] = tuple(
            dict.fromkeys((*self.canaries, *target_policy.canary_secrets))
        )

        # 1. Collect all outbound strings
        outbound_strings: list[str] = []
        if target_reply.text:
            outbound_strings.append(target_reply.text)
        for call in target_reply.tool_calls:
            outbound_strings.append(call.tool_name)
            outbound_strings.extend(_extract_strings(call.args))

        # 2. Check byte limits
        total_bytes = 0
        for s in outbound_strings:
            byte_len = len(s.encode("utf-8"))
            if byte_len > config.MAX_EGRESS_BYTES:
                return [
                    Finding(
                        layer=config.LAYER_EGRESS,
                        rule=config.RULE_EGRESS_BYTE_LIMIT_EXCEEDED,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=config.EVIDENCE_BYTE_LIMIT_STRING.format(
                            actual=byte_len,
                            limit=config.MAX_EGRESS_BYTES,
                        ),
                    )
                ]
            total_bytes += byte_len

        if total_bytes > config.MAX_EGRESS_BYTES:
            return [
                Finding(
                    layer=config.LAYER_EGRESS,
                    rule=config.RULE_EGRESS_BYTE_LIMIT_EXCEEDED,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    span_index=None,
                    evidence=config.EVIDENCE_BYTE_LIMIT_AGGREGATE.format(
                        actual=total_bytes,
                        limit=config.MAX_EGRESS_BYTES,
                    ),
                )
            ]

        # 3. Process URLs, check allowlist, and check query strings / paths
        findings: list[Finding] = []

        for s in outbound_strings:
            url_matches = list(config.RE_URL.finditer(s))
            for match in url_matches:
                host = match.group(1)

                if not is_host_allowlisted(host, target_policy.host_allowlist):
                    findings.append(
                        Finding(
                            layer=config.LAYER_EGRESS,
                            rule=config.RULE_DISALLOWED_HOST,
                            severity=Severity.CRITICAL,
                            invariant=True,
                            span_index=None,
                            # A hostname may itself contain a registered secret.
                            evidence=config.EVIDENCE_DISALLOWED_HOST,
                        )
                    )
                # Inspect the authority as well as the path/query. Secrets can
                # leave in DNS labels even on an allowlisted parent domain.
                findings.extend(self._scan_canaries(match.group(0), all_canaries))

            # 4. Scan non-URL text for canaries
            text_without_urls = config.RE_URL.sub("", s)
            findings.extend(self._scan_canaries(text_without_urls, all_canaries))

        return findings

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
        reply: AgentReply | None = None,
    ) -> list[Finding]:
        """Conform to the uniform Layer protocol."""
        if reply is None:
            return []
        return self.inspect_reply(reply, policy, ctx=ctx)
