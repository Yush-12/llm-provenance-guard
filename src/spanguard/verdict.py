"""
verdict -- detection output types.

    Severity   Ordered enum (INFO < LOW < MEDIUM < HIGH < CRITICAL).
               Implemented as IntEnum so that >= and max() work natively.
               Ordinal values are defined in config.py; do not write them
               inline anywhere else.
    Decision   Enum: ALLOW | BLOCK. No SANITIZE -- the firewall reports,
               it never silently rewrites content the model sees.
    Finding    Frozen model: one detection result from one layer.
               invariant=True  -> structural fact, always forces BLOCK.
               invariant=False -> scored heuristic, compared to threshold.
    Verdict    Frozen model: aggregated decision + full finding list.
               blocking_findings is a @property so it can never disagree
               with the stored decision.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """Ordered severity levels for findings.

    Integer values are ordinals only -- do not compare against raw ints
    in application code.  Use the enum members (Severity.HIGH >= Severity.LOW).
    Ordinal constants live in config.py; enum values here must stay in sync.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class Decision(StrEnum):
    """Final verdict on whether to allow or block a request.

    SANITIZE is intentionally absent: the firewall reports findings, it
    never rewrites content the model sees.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single detection result produced by one layer.

    Fields
    ------
    layer       Name of the layer that produced this finding (e.g.
                'provenance', 'ingress').
    rule        Identifier for the specific rule within the layer (e.g.
                'delimiter-forgery', 'imperative-verb').  All rule name
                strings must be defined in config.py.
    severity    How bad this finding is if it is correct.
    invariant   The load-bearing field.
                  True  -> structural fact; BLOCK is unconditional.
                  False -> scored heuristic; policy threshold applies.
    span_index  Index into Context.spans identifying the span that
                triggered this finding.  None when not applicable (e.g.
                an egress finding about the full response).
    evidence    Human-readable excerpt or description for rendering.
    """

    model_config = ConfigDict(frozen=True)

    layer: str
    rule: str
    severity: Severity
    invariant: bool
    span_index: int | None
    evidence: str


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


class Verdict(BaseModel):
    """Aggregated result of running all layers against a Context.

    decision           The final ALLOW or BLOCK determination.
    findings           Every Finding produced across all layers, in order.
    blocking_findings  Computed @property -- the findings that caused a
                       BLOCK, so callers can render 'BLOCKED by <layer>/<rule>'.
                       Never a stored field; always derived from findings +
                       decision so the two cannot disagree.
    """

    model_config = ConfigDict(frozen=True)

    decision: Decision
    findings: tuple[Finding, ...]

    @property
    def blocking_findings(self) -> tuple[Finding, ...]:
        """Return the findings responsible for a BLOCK decision.

        For an ALLOW verdict, returns an empty tuple.
        For a BLOCK caused by invariant findings, returns those findings.
        For a BLOCK caused by a scored threshold breach, returns the
        non-INFO scored findings (the caller can re-apply the threshold
        themselves if they need the subset that crossed it).
        """
        if self.decision is Decision.ALLOW:
            return ()
        invariant_hits = tuple(f for f in self.findings if f.invariant)
        if invariant_hits:
            return invariant_hits
        # Scored block: return the non-INFO findings that could have driven it
        return tuple(f for f in self.findings if not f.invariant and f.severity > Severity.INFO)
