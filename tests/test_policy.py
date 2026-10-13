"""
tests.test_policy -- tests for Severity, Decision, Finding, Verdict, Policy,
escalate(), and decide().

Validates invariant short-circuit priority, scoring algebra, and threshold boundaries.
"""

import pytest
from pydantic import ValidationError

from spanguard.policy import Policy, decide, escalate
from spanguard.verdict import Decision, Finding, Severity, Verdict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(
    *,
    severity: Severity,
    invariant: bool,
    layer: str = "test",
    rule: str = "test-rule",
    span_index: int | None = None,
    evidence: str = "",
) -> Finding:
    return Finding(
        layer=layer,
        rule=rule,
        severity=severity,
        invariant=invariant,
        span_index=span_index,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_severity_has_five_levels(self) -> None:
        assert set(Severity) == {
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        }

    def test_severity_ordering(self) -> None:
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_max(self) -> None:
        levels = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.MEDIUM]
        assert max(levels) == Severity.CRITICAL

    def test_severity_ge(self) -> None:
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.MEDIUM

    def test_severity_comparison_against_self(self) -> None:
        for s in Severity:
            assert s >= s
            assert not s < s


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_finding_is_frozen(self) -> None:
        f = make_finding(severity=Severity.HIGH, invariant=True)
        with pytest.raises(ValidationError):
            f.invariant = False  # type: ignore[misc]

    def test_finding_accepts_none_span_index(self) -> None:
        f = make_finding(severity=Severity.LOW, invariant=False, span_index=None)
        assert f.span_index is None

    def test_finding_accepts_int_span_index(self) -> None:
        f = make_finding(severity=Severity.LOW, invariant=False, span_index=3)
        assert f.span_index == 3


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_verdict_block_reports_blocking_invariant_findings(self) -> None:
        inv = make_finding(severity=Severity.CRITICAL, invariant=True, rule="bad-nonce")
        scored = make_finding(severity=Severity.LOW, invariant=False, rule="low-signal")
        v = Verdict(decision=Decision.BLOCK, findings=(inv, scored))
        assert inv in v.blocking_findings
        assert scored not in v.blocking_findings

    def test_verdict_allow_has_no_blocking_findings(self) -> None:
        f = make_finding(severity=Severity.LOW, invariant=False)
        v = Verdict(decision=Decision.ALLOW, findings=(f,))
        assert v.blocking_findings == ()

    def test_verdict_is_frozen(self) -> None:
        v = Verdict(decision=Decision.ALLOW, findings=())
        with pytest.raises(ValidationError):
            v.decision = Decision.BLOCK  # type: ignore[misc]


# ---------------------------------------------------------------------------
# decide() -- the seven mandatory tests
# ---------------------------------------------------------------------------


class TestDecide:
    # Test 1: invariant finding always blocks regardless of threshold
    def test_invariant_finding_blocks_even_at_max_threshold(self) -> None:
        """BLOCK must fire on invariant=True even when threshold is CRITICAL."""
        f = make_finding(severity=Severity.LOW, invariant=True)
        policy = Policy(block_threshold=Severity.CRITICAL)
        assert decide([f], policy) is Decision.BLOCK

    # Test 2: scored finding below threshold → ALLOW
    def test_scored_below_threshold_allows(self) -> None:
        f = make_finding(severity=Severity.LOW, invariant=False)
        policy = Policy(block_threshold=Severity.HIGH)
        assert decide([f], policy) is Decision.ALLOW

    # Test 3: scored finding at threshold → BLOCK
    def test_scored_at_threshold_blocks(self) -> None:
        f = make_finding(severity=Severity.HIGH, invariant=False)
        policy = Policy(block_threshold=Severity.HIGH)
        assert decide([f], policy) is Decision.BLOCK

    # Test 3 extension: scored finding above threshold → BLOCK
    def test_scored_above_threshold_blocks(self) -> None:
        f = make_finding(severity=Severity.CRITICAL, invariant=False)
        policy = Policy(block_threshold=Severity.HIGH)
        assert decide([f], policy) is Decision.BLOCK

    # Test 4: INFO finding never affects the decision
    def test_info_finding_never_blocks(self) -> None:
        """Even with block_threshold=INFO, an INFO finding must not cause BLOCK.

        Gut-check: removing the INFO filter makes this test go red because
        INFO >= INFO threshold would then trigger the BLOCK path.
        """
        f = make_finding(severity=Severity.INFO, invariant=False)
        policy = Policy(block_threshold=Severity.INFO)
        assert decide([f], policy) is Decision.ALLOW

    def test_only_info_findings_always_allow(self) -> None:
        """A verdict with ONLY INFO findings is ALLOW regardless of threshold."""
        findings = [
            make_finding(severity=Severity.INFO, invariant=False, rule="r1"),
            make_finding(severity=Severity.INFO, invariant=False, rule="r2"),
        ]
        # Even the most permissive threshold must not be triggered by INFO
        for threshold in Severity:
            assert decide(findings, Policy(block_threshold=threshold)) is Decision.ALLOW

    def test_empty_findings_always_allow(self) -> None:
        policy = Policy()
        assert decide([], policy) is Decision.ALLOW

    # Test 7: decide() is a pure function
    def test_decide_is_pure(self) -> None:
        """Calling decide() twice with the same inputs gives the same output."""
        f = make_finding(severity=Severity.HIGH, invariant=False)
        policy = Policy(block_threshold=Severity.MEDIUM)
        result_a = decide([f], policy)
        result_b = decide([f], policy)
        assert result_a is result_b

    def test_decide_does_not_mutate_findings(self) -> None:
        f = make_finding(severity=Severity.HIGH, invariant=False)
        original_invariant = f.invariant
        policy = Policy(block_threshold=Severity.MEDIUM)
        decide([f], policy)
        assert f.invariant == original_invariant

    def test_mixed_invariant_and_scored_blocks_on_invariant(self) -> None:
        """When both invariant and scored findings present, invariant drives BLOCK."""
        inv = make_finding(severity=Severity.LOW, invariant=True)
        below = make_finding(severity=Severity.LOW, invariant=False)
        policy = Policy(block_threshold=Severity.CRITICAL)
        # Would ALLOW on scored path alone, but BLOCK because of invariant
        assert decide([inv, below], policy) is Decision.BLOCK


# ---------------------------------------------------------------------------
# escalate() -- tests 5 and 6
# ---------------------------------------------------------------------------


class TestEscalate:
    # Test 5: strict_data=False → findings unchanged
    def test_strict_data_false_leaves_findings_unchanged(self) -> None:
        findings = [
            make_finding(severity=Severity.HIGH, invariant=False, rule="ingress.imperative"),
            make_finding(severity=Severity.MEDIUM, invariant=False, rule="ingress.role-swap"),
        ]
        policy = Policy(
            strict_data=False,
            strict_data_rules=("ingress.imperative", "ingress.role-swap"),
        )
        result = escalate(findings, policy)
        assert all(not r.invariant for r in result)

    # Test 6: strict_data=True → configured rules promoted to invariant
    def test_strict_data_true_promotes_configured_rules(self) -> None:
        """Control: removing the promotion logic makes this test go red."""
        target_rule = "ingress.imperative"
        f = make_finding(severity=Severity.HIGH, invariant=False, rule=target_rule)
        policy = Policy(
            strict_data=True,
            strict_data_rules=(target_rule,),
        )
        result = escalate([f], policy)
        assert result[0].invariant is True

    def test_strict_data_true_leaves_unlisted_rules_alone(self) -> None:
        listed = make_finding(severity=Severity.HIGH, invariant=False, rule="r-listed")
        unlisted = make_finding(severity=Severity.HIGH, invariant=False, rule="r-unlisted")
        policy = Policy(strict_data=True, strict_data_rules=("r-listed",))
        result = escalate([listed, unlisted], policy)
        promoted = {r.rule: r.invariant for r in result}
        assert promoted["r-listed"] is True
        assert promoted["r-unlisted"] is False

    def test_escalate_does_not_mutate_original_findings(self) -> None:
        f = make_finding(severity=Severity.HIGH, invariant=False, rule="r")
        policy = Policy(strict_data=True, strict_data_rules=("r",))
        escalate([f], policy)
        assert f.invariant is False  # original untouched

    def test_escalate_is_pure(self) -> None:
        findings = [make_finding(severity=Severity.HIGH, invariant=False, rule="r")]
        policy = Policy(strict_data=True, strict_data_rules=("r",))
        result_a = escalate(findings, policy)
        result_b = escalate(findings, policy)
        assert result_a[0].invariant == result_b[0].invariant

    def test_escalate_already_invariant_stays_invariant(self) -> None:
        """Promoting an already-invariant finding is a no-op (still invariant)."""
        f = make_finding(severity=Severity.HIGH, invariant=True, rule="r")
        policy = Policy(strict_data=True, strict_data_rules=("r",))
        result = escalate([f], policy)
        assert result[0].invariant is True


# ---------------------------------------------------------------------------
# Policy defaults
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_policy_default_block_threshold_is_medium(self) -> None:
        p = Policy()
        assert p.block_threshold == Severity.MEDIUM

    def test_policy_default_strict_data_is_false(self) -> None:
        assert Policy().strict_data is False

    def test_policy_is_frozen(self) -> None:
        p = Policy()
        with pytest.raises(ValidationError):
            p.strict_data = True  # type: ignore[misc]

    def test_policy_canary_secrets_default_empty(self) -> None:
        assert Policy().canary_secrets == ()

    def test_policy_stub_fields_exist(self) -> None:
        """Stub fields for future phases must be present even if unused."""
        p = Policy()
        _ = p.enabled_layers
        _ = p.host_allowlist
        _ = p.forbidden_tool_effects
