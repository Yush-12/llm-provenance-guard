"""
audit -- opt-in JSONL audit logging.

This is the ONLY module in the core library permitted to perform I/O,
and only when explicitly enabled by the caller via a configured file path.

Defines:
    AuditFinding       Sanitized finding representation (evidence digested).
    AuditOrigin        Sanitized origin representation (ref digested).
    AuditSpan          Sanitized span metadata (no raw prompt text stored).
    AuditRecord        Frozen, JSON-serializable firewall verdict event.
    AuditWriter        Context manager and writer appending JSONL audit records.
    digest_value       Truncated SHA-256 hashing for attacker-influenced fields.
    build_audit_record Pure function constructing an AuditRecord from a Verdict.
    write_audit_record Opt-in function writing an AuditRecord to a JSONL path.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from spanguard import config
from spanguard.context import Context
from spanguard.policy import Policy
from spanguard.verdict import Verdict

# ---------------------------------------------------------------------------
# Digest computation
# ---------------------------------------------------------------------------


def digest_value(value: str) -> str:
    """Compute a truncated SHA-256 digest of an attacker-influenced string."""
    if not value:
        return ""
    h = hashlib.sha256(value.encode(config.AUDIT_FILE_ENCODING)).hexdigest()
    return h[: config.AUDIT_DIGEST_LENGTH]


# ---------------------------------------------------------------------------
# Audit Models
# ---------------------------------------------------------------------------


class AuditFinding(BaseModel):
    """Sanitized finding representation for audit logging."""

    model_config = ConfigDict(frozen=True)

    layer: str
    rule: str
    severity: str
    invariant: bool
    span_index: int | None = None
    evidence_digest: str


class AuditOrigin(BaseModel):
    """Sanitized origin representation for audit logging."""

    model_config = ConfigDict(frozen=True)

    channel: str
    ref_digest: str


class AuditSpan(BaseModel):
    """Sanitized span metadata (no raw prompt text stored)."""

    model_config = ConfigDict(frozen=True)

    index: int
    trust: str
    origin: AuditOrigin | None = None


class AuditRecord(BaseModel):
    """Immutable, JSON-serializable audit log entry for a firewall verdict."""

    model_config = ConfigDict(frozen=True)

    timestamp_utc: str
    decision: str
    findings: tuple[AuditFinding, ...] = Field(default=())
    spans: tuple[AuditSpan, ...] = Field(default=())
    nonce: str | None = None
    policy_id: str = config.DEFAULT_POLICY_ID
    elapsed_ms: float | None = None


# ---------------------------------------------------------------------------
# Record Builder (Pure Function)
# ---------------------------------------------------------------------------


def build_audit_record(
    verdict: Verdict,
    ctx: Context | None = None,
    policy: Policy | None = None,
    policy_id: str | None = None,
    elapsed_ms: float | None = None,
) -> AuditRecord:
    """Construct an AuditRecord from a Verdict and optional Context summary.

    Pure function: performs no I/O. Digests all attacker-influenced fields:
    - Finding evidence is converted to evidence_digest
    - Span origin.ref is converted to ref_digest
    Raw prompt text is intentionally omitted from the audit record.
    """
    now_iso = datetime.now(UTC).isoformat()

    resolved_policy_id = config.DEFAULT_POLICY_ID
    if policy_id is not None:
        resolved_policy_id = policy_id
    elif policy is not None and policy.policy_id:
        resolved_policy_id = policy.policy_id

    # 1. Sanitize and digest findings
    audit_findings: list[AuditFinding] = []
    for f in verdict.findings:
        audit_findings.append(
            AuditFinding(
                layer=f.layer,
                rule=f.rule,
                severity=f.severity.name,
                invariant=f.invariant,
                span_index=f.span_index,
                evidence_digest=digest_value(f.evidence),
            )
        )

    # 2. Sanitize and digest context spans (metadata only, no prompt text)
    audit_spans: list[AuditSpan] = []
    nonce: str | None = None
    if ctx is not None:
        nonce = ctx.nonce
        for idx, span in enumerate(ctx.spans):
            audit_origin: AuditOrigin | None = None
            if span.origin is not None:
                audit_origin = AuditOrigin(
                    channel=span.origin.channel,
                    ref_digest=digest_value(span.origin.ref),
                )
            audit_spans.append(
                AuditSpan(
                    index=idx,
                    trust=span.trust.value,
                    origin=audit_origin,
                )
            )

    return AuditRecord(
        timestamp_utc=now_iso,
        decision=verdict.decision.value,
        findings=tuple(audit_findings),
        spans=tuple(audit_spans),
        nonce=nonce,
        policy_id=resolved_policy_id,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Record Writer (Opt-In I/O)
# ---------------------------------------------------------------------------


def write_audit_record(
    verdict: Verdict,
    ctx: Context | None = None,
    path: str | Path | None = None,
    policy: Policy | None = None,
    policy_id: str | None = None,
    elapsed_ms: float | None = None,
) -> AuditRecord:
    """Build and write an AuditRecord as a JSONL line to the configured path.

    Gated behind explicit path configuration. If no path is provided,
    configured in policy, or set in config, NO writing occurs (safe default).
    """
    record = build_audit_record(
        verdict=verdict,
        ctx=ctx,
        policy=policy,
        policy_id=policy_id,
        elapsed_ms=elapsed_ms,
    )

    dest_path: str | Path | None = path
    if dest_path is None and policy is not None:
        dest_path = policy.audit_log_path
    if dest_path is None:
        dest_path = config.DEFAULT_AUDIT_LOG_PATH

    # Safe default: no path configured -> no I/O
    if not dest_path:
        return record

    target_file = Path(dest_path)
    if target_file.parent and not target_file.parent.exists():
        target_file.parent.mkdir(parents=True, exist_ok=True)

    with target_file.open(
        mode=config.AUDIT_FILE_MODE,
        encoding=config.AUDIT_FILE_ENCODING,
    ) as f:
        f.write(record.model_dump_json() + config.JSONL_NEWLINE)

    return record


# ---------------------------------------------------------------------------
# AuditWriter
# ---------------------------------------------------------------------------


class AuditWriter:
    """Context manager wrapper for write_audit_record."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = path

    def write(
        self,
        verdict: Verdict,
        ctx: Context | None = None,
        policy: Policy | None = None,
        policy_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> AuditRecord:
        return write_audit_record(
            verdict,
            ctx=ctx,
            path=self.path,
            policy=policy,
            policy_id=policy_id,
            elapsed_ms=elapsed_ms,
        )

    def __enter__(self) -> AuditWriter:
        return self

    def __exit__(self, *args: object) -> None:
        pass
