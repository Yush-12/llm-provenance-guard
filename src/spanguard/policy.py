"""
policy -- scoring policy and decision logic.

    Policy      Frozen model holding all tunable firewall parameters.
                Defaults are read from config.py -- never inline.
    escalate()  Pure function: promote scored findings to invariant when
                strict_data is enabled.  Findings in, findings out.
                Does not call into any layer, does not perform I/O.
    decide()    Pure function: derive a Decision from findings + policy.
                Same input always produces the same output.
                Contract:
                  1. Any invariant finding -> BLOCK unconditionally.
                  2. Among non-invariant findings with severity > INFO,
                     if max severity >= block_threshold -> BLOCK.
                  3. Otherwise -> ALLOW.
                INFO findings never affect the decision, invariant or not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from spanguard import config
from spanguard.verdict import Decision, Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence


class PolicyError(ValueError):
    """Raised when policy parameters are invalid or misconfigured."""


def normalize_canary(s: str) -> str:
    """Normalize canary string using whitespace collapse, strip, and casefold.

    The exact same normalization applied at match time to ensure length thresholds
    and substring checks evaluate identical forms.
    """
    return config.RE_WHITESPACE_COLLAPSE.sub(" ", s).strip().casefold()


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class Policy(BaseModel):
    """All tunable parameters for a firewall instance.

    Fields
    ------
    enabled_layers       Ordered names of layers the Firewall will run.
                         Empty tuple means all layers run (resolved by
                         Firewall, not here).
    block_threshold      Minimum Severity for a scored finding to trigger
                         BLOCK.  Invariant findings always block regardless.
                         Default: Severity.MEDIUM (from config).
    strict_data          When True, escalate() promotes findings whose
                         rule is in strict_data_rules to invariant=True.
    strict_data_rules    Rule names subject to strict_data promotion.
                         Actual rule name constants live in config.py and
                         will be wired in the ingress phase.
    canary_secrets       Registered secret strings.  Egress layer checks
                         all encodings of these against model output.
    host_allowlist       URLs/hostnames the model is permitted to emit in
                         tool call arguments.  Toolauth layer enforces.
    forbidden_tool_effects
                         Set of Effect names the policy prohibits entirely,
                         regardless of taint status.  Wired in tools phase.
    """

    model_config = ConfigDict(frozen=True)

    enabled_layers: tuple[str, ...] = Field(default=())
    block_threshold: Severity = Field(default=Severity(config.DEFAULT_BLOCK_THRESHOLD_ORDINAL))
    strict_data: bool = False
    strict_data_rules: tuple[str, ...] = Field(default=())
    canary_secrets: tuple[str, ...] = Field(default=())
    host_allowlist: tuple[str, ...] = Field(default=())
    forbidden_tool_effects: frozenset[str] = Field(default_factory=frozenset)
    audit_log_path: str | None = None
    policy_id: str = config.DEFAULT_POLICY_ID

    def __init__(self, **data: object) -> None:

        super().__init__(**data)
        for canary in self.canary_secrets:
            normalized = normalize_canary(canary)
            if len(normalized) < config.MIN_CANARY_LENGTH:
                raise PolicyError(
                    f"Canary secret is too short after normalization "
                    f"({len(normalized)} < {config.MIN_CANARY_LENGTH}): {canary!r}"
                )


# ---------------------------------------------------------------------------
# escalate
# ---------------------------------------------------------------------------


def escalate(findings: Sequence[Finding], policy: Policy) -> list[Finding]:
    """Promote findings to invariant when strict_data mode is active.

    When ``policy.strict_data`` is False, findings are returned unchanged.
    When True, any finding whose ``rule`` appears in
    ``policy.strict_data_rules`` and is not already invariant is replaced
    with a copy where ``invariant=True``.

    Pure function: no I/O, no mutation of arguments.  Finding is frozen so
    "promotion" always produces a new Finding instance via model_copy().
    """
    if not policy.strict_data:
        return list(findings)

    result: list[Finding] = []
    for finding in findings:
        if finding.rule in policy.strict_data_rules and not finding.invariant:
            result.append(finding.model_copy(update={"invariant": True}))
        else:
            result.append(finding)
    return result


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------


def decide(findings: Sequence[Finding], policy: Policy) -> Decision:
    """Derive a Decision from findings and policy.

    Pure function -- same inputs always return the same Decision.

    Decision algorithm (strict priority order):
    1. Any finding with invariant=True -> BLOCK, unconditionally.
       Thresholds cannot soften an invariant; this branch is not skipped
       for any severity level.
    2. Among remaining (non-invariant) findings, discard INFO severity.
       INFO exists for "this layer is disabled" notices and similar
       annotations -- it must never change the outcome.
    3. If any non-INFO scored findings remain and their maximum severity
       is >= policy.block_threshold -> BLOCK.
    4. Otherwise -> ALLOW (including the case of zero findings).
    """
    # --- Rule 1: invariant short-circuit ---
    if any(f.invariant for f in findings):
        return Decision.BLOCK

    # --- Rule 2+3: scored path with INFO stripped ---
    scored = [f for f in findings if f.severity > Severity.INFO]
    if not scored:
        return Decision.ALLOW

    if max(f.severity for f in scored) >= policy.block_threshold:
        return Decision.BLOCK

    return Decision.ALLOW
