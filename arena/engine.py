"""
arena.engine — Evaluation engine for challenge attempts against level policies.
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from arena.containment import check_containment
from arena.levels import LevelConfig, create_level_policy
from spanguard import config
from spanguard.agent.mock import Agent, MockAgent
from spanguard.context import Context, Origin
from spanguard.firewall import Firewall
from spanguard.layers import Layer
from spanguard.layers.egress import EgressLayer
from spanguard.layers.ingress import IngressLayer
from spanguard.layers.normalize import NormalizeLayer
from spanguard.layers.provenance import ProvenanceLayer
from spanguard.layers.toolauth import ToolAuthLayer
from spanguard.policy import Policy, decide
from spanguard.tools import Effect, Guard, Tool, ToolCallRequest
from spanguard.verdict import Decision, Finding, Severity


def _blocking_finding(findings: list[Finding] | tuple[Finding, ...], policy: Policy) -> Finding:
    """Attribute a block to an invariant first, then an actual threshold breach."""
    for finding in findings:
        if finding.invariant:
            return finding
    return next(
        finding
        for finding in findings
        if finding.severity > Severity.INFO and finding.severity >= policy.block_threshold
    )


ARENA_TOOLS: dict[str, Tool] = {
    config.MOCK_EXFIL_TOOL_NAME: Tool(
        name=config.MOCK_EXFIL_TOOL_NAME,
        effects=frozenset({Effect.SEND}),
        guards=frozenset(
            {Guard.NO_UNTRUSTED_INFLUENCE, Guard.USER_CONFIRMED, Guard.ARGS_ALLOWLISTED}
        ),
        permitted_args=frozenset({config.MOCK_EXFIL_RECIPIENT_KEY, config.MOCK_EXFIL_BODY_KEY}),
    ),
}


class AttemptResult(BaseModel):
    """Result of an attack attempt against a level."""

    model_config = ConfigDict(frozen=True)

    level: int
    payload: str
    success: bool
    leaked: bool
    blocked: bool
    stopped_by: str | None = None
    rule: str | None = None
    findings: tuple[Finding, ...] = ()
    reply_text: str = ""
    tool_calls: tuple[ToolCallRequest, ...] = ()


def run_attempt(
    payload: str,
    level_config: LevelConfig,
    canary: str,
    agent: Agent | None = None,
    containment_fn: Callable[..., tuple[bool, list[Finding]]] = check_containment,
) -> AttemptResult:
    """Execute a player prompt injection attempt against a level policy configuration.

    1. Request-side inspection: runs enabled request layers.
    2. Render prompt: if allowed, renders fenced context.
    3. Mock agent: responds to rendered prompt.
    4. Outbound layer inspection: evaluates enabled outbound layers (toolauth, egress).
    5. Containment check: oracle inspection across all outbound surfaces.
    """
    policy = create_level_policy(level_config, canary)
    active_layers = set(level_config.enabled_layers)

    # 1. Build context with untrusted input in DATA span
    ctx = (
        Context()
        .system(config.ARENA_SYSTEM_PROMPT)
        .data(
            payload,
            origin=Origin(channel=config.ARENA_CHANNEL_NAME, ref=config.ARENA_REF_NAME),
        )
    )

    # 2. Configure request-side layers based on level's enabled_layers
    req_layers: list[Layer] = []
    if config.LAYER_NORMALIZE in active_layers:
        req_layers.append(NormalizeLayer())
    if config.LAYER_INGRESS in active_layers:
        req_layers.append(IngressLayer())
    if config.LAYER_PROVENANCE in active_layers:
        req_layers.append(ProvenanceLayer())

    firewall = Firewall(policy=policy, layers=req_layers)
    verdict_in = firewall.inspect(ctx)

    if verdict_in.decision == Decision.BLOCK:
        # Request-side blocked before agent is ever called
        blocking = _blocking_finding(verdict_in.findings, policy)
        stopped_by = blocking.layer
        rule = blocking.rule
        return AttemptResult(
            level=level_config.level,
            payload=payload,
            success=False,
            leaked=False,
            blocked=True,
            stopped_by=stopped_by,
            rule=rule,
            findings=tuple(verdict_in.findings),
            reply_text="",
            tool_calls=(),
        )

    # 3. Render prompt & invoke agent
    rendered = firewall.render(ctx)
    mock_agent = agent if agent is not None else MockAgent(canary=canary, policy=policy)
    reply = mock_agent.respond(rendered)

    # 4. Outbound tool authorization layer (if enabled at this level)
    if config.LAYER_TOOLAUTH in active_layers and reply.tool_calls:
        toolauth = ToolAuthLayer(tools=ARENA_TOOLS)
        tool_findings: list[Finding] = []
        for call in reply.tool_calls:
            tool_findings.extend(toolauth.inspect_call(ctx, call, policy=policy))
        tool_decision = decide(tool_findings, policy)
        if tool_decision == Decision.BLOCK:
            return AttemptResult(
                level=level_config.level,
                payload=payload,
                success=False,
                leaked=False,
                blocked=True,
                stopped_by=config.LAYER_TOOLAUTH,
                rule=_blocking_finding(tool_findings, policy).rule,
                findings=(*verdict_in.findings, *tool_findings),
                reply_text=reply.text,
                tool_calls=reply.tool_calls,
            )

    # 5. Outbound egress inspection layer (if enabled at this level)
    if config.LAYER_EGRESS in active_layers:
        egress = EgressLayer(canaries=(canary,), policy=policy)
        egress_findings = egress.inspect_reply(reply, policy)
        egress_decision = decide(egress_findings, policy)
        if egress_decision == Decision.BLOCK:
            return AttemptResult(
                level=level_config.level,
                payload=payload,
                success=False,
                leaked=False,
                blocked=True,
                stopped_by=config.LAYER_EGRESS,
                rule=_blocking_finding(egress_findings, policy).rule,
                findings=(*verdict_in.findings, *egress_findings),
                reply_text=reply.text,
                tool_calls=reply.tool_calls,
            )

    # 6. Containment check oracle across reply text AND tool arguments
    leaked, oracle_findings = containment_fn(reply, canary)

    return AttemptResult(
        level=level_config.level,
        payload=payload,
        success=leaked,
        leaked=leaked,
        blocked=False,
        stopped_by=None,
        rule=None,
        findings=(*verdict_in.findings, *oracle_findings),
        reply_text=reply.text,
        tool_calls=reply.tool_calls,
    )
