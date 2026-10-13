"""
layers.toolauth -- invariant tool-call authorization layer.

Authorizes tool invocations based on causal provenance and declared guards:
    - Guard.NO_UNTRUSTED_INFLUENCE: Refuses invocation if Context is tainted by DATA.
    - Guard.USER_CONFIRMED: Refuses invocation unless explicitly confirmed.
    - Guard.ARGS_ALLOWLISTED: Refuses invocation if unexpected argument keys are present.
    - Schema validation: Validates argument values and required keys against arg_schema.

All findings emitted by this layer have invariant=True and severity=CRITICAL.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pydantic import ValidationError

from spanguard import config
from spanguard.policy import Policy
from spanguard.tools import Guard, Tool, ToolCallRequest
from spanguard.verdict import Finding, Severity

if TYPE_CHECKING:
    from spanguard.context import Context
    from spanguard.tools import AgentReply

# ---------------------------------------------------------------------------
# Guard-to-rule mapping (verified by structural test)
# ---------------------------------------------------------------------------

GUARD_RULE_MAP: dict[Guard, str] = {
    Guard.NO_UNTRUSTED_INFLUENCE: config.RULE_TOOL_UNTRUSTED_INFLUENCE,
    Guard.USER_CONFIRMED: config.RULE_TOOL_NOT_CONFIRMED,
    Guard.ARGS_ALLOWLISTED: config.RULE_TOOL_ARGS_NOT_ALLOWLISTED,
}


# ---------------------------------------------------------------------------
# ToolAuthLayer
# ---------------------------------------------------------------------------


class ToolAuthLayer:
    """Invariant tool authorization layer.

    Evaluates ToolCallRequests against registered Tools, causal Context taint,
    and declared Guard requirements.
    """

    name: str = config.LAYER_TOOLAUTH

    def __init__(
        self,
        tools: Sequence[Tool] | dict[str, Tool] | None = None,
    ) -> None:
        """Initialize with an optional collection or map of registered Tools."""
        if tools is None:
            self.tools: dict[str, Tool] = {}
        elif isinstance(tools, dict):
            self.tools = dict(tools)
        else:
            self.tools = {tool.name: tool for tool in tools}

    def inspect_call(
        self,
        ctx: Context,
        call: ToolCallRequest,
        tool: Tool | None = None,
        policy: Policy | None = None,
    ) -> list[Finding]:
        """Inspect a single ToolCallRequest against a Tool and Context.

        Returns invariant=True findings if any authorization guard fails.
        """
        findings: list[Finding] = []
        target_tool = tool if tool is not None else self.tools.get(call.tool_name)

        if target_tool is None:
            findings.append(
                Finding(
                    layer=config.LAYER_TOOLAUTH,
                    rule=config.RULE_TOOL_UNKNOWN,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    span_index=None,
                    evidence=f"Tool '{call.tool_name}' is not registered",
                )
            )
            return findings

        # Check policy forbidden effects
        if policy is not None and policy.forbidden_tool_effects:
            for effect in target_tool.effects:
                if effect.value in policy.forbidden_tool_effects:
                    findings.append(
                        Finding(
                            layer=config.LAYER_TOOLAUTH,
                            rule=config.RULE_FORBIDDEN_TOOL_EFFECT,
                            severity=Severity.CRITICAL,
                            invariant=True,
                            span_index=None,
                            evidence=(
                                f"Tool '{target_tool.name}' possesses forbidden "
                                f"effect '{effect.value}'"
                            ),
                        )
                    )

        # 1. Guard.NO_UNTRUSTED_INFLUENCE: refuse if context is tainted
        if Guard.NO_UNTRUSTED_INFLUENCE in target_tool.guards and ctx.tainted_by:
            origins_str = ", ".join(f"{o.channel}:{o.ref}" for o in ctx.tainted_by)
            findings.append(
                Finding(
                    layer=config.LAYER_TOOLAUTH,
                    rule=config.RULE_TOOL_UNTRUSTED_INFLUENCE,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    span_index=None,
                    evidence=(
                        f"Tool '{target_tool.name}' called with untrusted influence "
                        f"from origins: {origins_str}"
                    ),
                )
            )

        # 2. Guard.USER_CONFIRMED: refuse unless call was explicitly confirmed
        if Guard.USER_CONFIRMED in target_tool.guards and not call.user_confirmed:
            findings.append(
                Finding(
                    layer=config.LAYER_TOOLAUTH,
                    rule=config.RULE_TOOL_NOT_CONFIRMED,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    span_index=None,
                    evidence=f"Tool '{target_tool.name}' requires explicit user confirmation",
                )
            )

        # 3. Guard.ARGS_ALLOWLISTED: check both directions (unexpected keys & permitted allowlist)
        if Guard.ARGS_ALLOWLISTED in target_tool.guards:
            unexpected_keys = set(call.args.keys()) - set(target_tool.permitted_args)
            if unexpected_keys:
                findings.append(
                    Finding(
                        layer=config.LAYER_TOOLAUTH,
                        rule=config.RULE_TOOL_ARGS_NOT_ALLOWLISTED,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=(
                            f"Tool '{target_tool.name}' called with unpermitted argument "
                            f"keys: {sorted(unexpected_keys)}"
                        ),
                    )
                )

        # 4. Schema validation: validate argument values & required keys
        if target_tool.arg_schema is not None:
            # Check for keys unrecognized by schema
            schema_fields = set(target_tool.arg_schema.model_fields.keys())
            unrecognized_schema_keys = set(call.args.keys()) - schema_fields
            if unrecognized_schema_keys and not any(
                f.rule == config.RULE_TOOL_ARGS_NOT_ALLOWLISTED for f in findings
            ):
                findings.append(
                    Finding(
                        layer=config.LAYER_TOOLAUTH,
                        rule=config.RULE_TOOL_ARGS_NOT_ALLOWLISTED,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=(
                            f"Tool '{target_tool.name}' argument keys not declared in "
                            f"schema: {sorted(unrecognized_schema_keys)}"
                        ),
                    )
                )

            # Validate complete schema (catches missing required keys and type invalidity)
            try:
                target_tool.arg_schema.model_validate(call.args)
            except ValidationError as err:
                findings.append(
                    Finding(
                        layer=config.LAYER_TOOLAUTH,
                        rule=config.RULE_TOOL_SCHEMA_VIOLATION,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=(
                            f"Tool '{target_tool.name}' argument schema validation failed: "
                            f"{type(err).__name__}"
                        ),
                    )
                )

        return findings

    def inspect_reply(
        self,
        ctx: Context,
        reply: AgentReply,
        policy: Policy | None = None,
    ) -> list[Finding]:
        """Inspect all tool call requests within an AgentReply."""
        findings: list[Finding] = []
        for call in reply.tool_calls:
            findings.extend(self.inspect_call(ctx, call, policy=policy))
        return findings

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
        reply: AgentReply | None = None,
    ) -> list[Finding]:
        """Conform to the Layer protocol (or evaluate reply if passed)."""
        if reply is None:
            return []
        return self.inspect_reply(ctx, reply, policy=policy)
