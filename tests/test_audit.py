"""
tests.test_audit -- tests for audit logging:
    - spanguard.audit (AuditRecord, AuditFinding, AuditSpan, AuditOrigin,
      digest_value, build_audit_record, write_audit_record, AuditWriter)
    - Digesting attacker-influenced evidence text
    - Digesting attacker-influenced origin.ref
    - Safe unconfigured path no-op (no I/O without explicit opt-in)
    - Valid JSONL appending on configured path
"""

from __future__ import annotations

import json
from pathlib import Path

from spanguard.audit import (
    AuditWriter,
    build_audit_record,
    digest_value,
    write_audit_record,
)
from spanguard.context import Context, Origin
from spanguard.policy import Policy
from spanguard.verdict import Decision, Finding, Severity, Verdict


class TestAuditLogging:
    def test_1_finding_evidence_digested_not_raw(self) -> None:
        """Test 1: Sensitive evidence in a finding is digested; raw text never appears in record."""
        raw_sensitive = "SUPER_SECRET_LEAKED_PAYLOAD_EXFILTRATION_DATA_99"
        finding = Finding(
            layer="ingress",
            rule="chat-template-forgery",
            severity=Severity.HIGH,
            invariant=False,
            span_index=0,
            evidence=raw_sensitive,
        )
        verdict = Verdict(decision=Decision.BLOCK, findings=(finding,))

        record = build_audit_record(verdict)
        serialized = record.model_dump_json()

        # The entire serialized record must NOT contain raw sensitive evidence anywhere
        assert raw_sensitive not in serialized

        # The serialized record MUST contain the deterministic digest
        expected_digest = digest_value(raw_sensitive)
        assert expected_digest in serialized
        assert len(expected_digest) > 0

    def test_2_data_span_origin_ref_digested_not_raw(self) -> None:
        """Test 2: Attacker-influenced origin.ref in DATA span is digested; raw ref never appears."""
        raw_attacker_ref = "ATTACKER_INJECTED_PROXY_METADATA_REF_7777"
        origin = Origin(channel="inferred_proxy", ref=raw_attacker_ref)
        ctx = Context().data("Sensitive prompt payload text", origin=origin)
        verdict = Verdict(decision=Decision.ALLOW, findings=())

        record = build_audit_record(verdict, ctx=ctx)
        serialized = record.model_dump_json()

        # The entire serialized record must NOT contain raw ref anywhere
        assert raw_attacker_ref not in serialized

        # The serialized record MUST contain the deterministic digest of ref
        expected_digest = digest_value(raw_attacker_ref)
        assert expected_digest in serialized

        # Sensitive prompt text must also NEVER be stored in audit record
        assert "Sensitive prompt payload text" not in serialized

    def test_3_no_audit_path_configured_is_noop(self, tmp_path: Path) -> None:
        """Test 3: With no audit path configured, write is a no-op (no raise, no file created)."""
        target_path = tmp_path / "never_created.jsonl"
        verdict = Verdict(decision=Decision.ALLOW, findings=())

        # No path passed, default policy has None path
        record = write_audit_record(verdict, path=None)

        assert record is not None
        assert not target_path.exists()
        assert len(list(tmp_path.iterdir())) == 0

    def test_4_configured_audit_path_appends_valid_jsonl(self, tmp_path: Path) -> None:
        """Test 4: With configured path, writes append valid JSONL (one JSON object per line)."""
        log_file = tmp_path / "audit_output.jsonl"
        verdict_allow = Verdict(decision=Decision.ALLOW, findings=())
        verdict_block = Verdict(decision=Decision.BLOCK, findings=())

        # Perform multiple sequential writes
        write_audit_record(verdict_allow, path=log_file)
        write_audit_record(verdict_block, path=log_file)
        write_audit_record(verdict_allow, path=log_file)

        assert log_file.exists()
        lines = [line.strip() for line in log_file.read_text(encoding="utf-8").strip().split("\n")]
        assert len(lines) == 3

        # Parse every line back to confirm valid JSONL format
        parsed_records = [json.loads(line) for line in lines]
        assert parsed_records[0]["decision"] == "ALLOW"
        assert parsed_records[1]["decision"] == "BLOCK"
        assert parsed_records[2]["decision"] == "ALLOW"

    def test_5_audit_writer_context_manager(self, tmp_path: Path) -> None:
        """Test 5: AuditWriter context manager writes records to file."""
        log_file = tmp_path / "writer_test.jsonl"
        verdict = Verdict(decision=Decision.BLOCK, findings=())

        with AuditWriter(path=log_file) as writer:
            writer.write(verdict)

        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        record_data = json.loads(lines[0])
        assert record_data["decision"] == "BLOCK"

    def test_6_policy_configured_audit_path(self, tmp_path: Path) -> None:
        """Test 6: Policy carrying audit_log_path routes write_audit_record automatically."""
        log_file = tmp_path / "policy_audit.jsonl"
        policy = Policy(audit_log_path=str(log_file))
        verdict = Verdict(decision=Decision.ALLOW, findings=())

        write_audit_record(verdict, policy=policy)

        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        record_data = json.loads(lines[0])
        assert record_data["decision"] == "ALLOW"
