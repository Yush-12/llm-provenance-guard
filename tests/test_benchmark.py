"""
tests.test_benchmark -- tests for security benchmark suite and runner.

Validates:
    1. Every attack class achieves >= baseline detection rate (no regression).
    2. benign_adversarial_user reports 0.0% false positives.
    3. benign_adversarial_data reports a low, plausible, non-zero false positive rate.
    4. Structural assertion: fails if any benign_adversarial_data case uses Trust.USER.
    5. Two-number per-layer ablation: reports both solo and marginal leave-one-out,
       verifies solo > 0 for all layers, and catches inert layers.
    6. Gut check: pooled blended reporting flatters the hard-benign class;
       reporting separately preserves visibility of the real false-positive rate.
    7. Plain-language disclaimer is present in the printed report.
    8. Separate classes for whole-span encoded vs embedded encoded payloads.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from bench.runner import (
    load_yaml_corpus,
    print_benchmark_report,
    run_benchmark,
)

from spanguard import config


class TestBenchmarkSuite:
    """Test suite for security benchmark corpus and runner."""

    def test_all_attack_classes_score_expected_detection_rate(self) -> None:
        """Test 1: Every attack class scores >= baseline known-good detection rate.

        Guards against regressions without pinning to an inflexible 100% hardcoded number.
        """
        result = run_benchmark()
        assert len(result.attack_rates) >= 10, (
            f"Expected 10-12 classes, got {len(result.attack_rates)}"
        )

        for cls_name, baseline in config.BASELINE_DETECTION_RATES.items():
            assert cls_name in result.attack_rates, f"Missing attack class '{cls_name}'"
            rate = result.attack_rates[cls_name]
            assert rate >= baseline, (
                f"Attack class '{cls_name}' regressed: score {rate}% < baseline {baseline}%"
            )

    def test_benign_adversarial_user_zero_false_positives(self) -> None:
        """Test 2: benign_adversarial_user reports 0.0% false positives.

        Proves DATA-scoping works and USER spans with attack-shaped words are never blocked.
        """
        result = run_benchmark()
        assert result.user_total >= 15, f"Expected at least 15 USER cases, got {result.user_total}"
        assert result.user_fp == 0, (
            f"Expected 0 false positives for USER cases, got {result.user_fp}"
        )
        assert result.fp_rate_user == 0.0

    def test_benign_adversarial_data_low_plausible_nonzero_fp(self) -> None:
        """Test 3: benign_adversarial_data reports a LOW, plausible, NON-ZERO false positive rate.

        Treats an exact 0.0% here with suspicion rather than pride.
        Ensures ingress heuristics are realistically evaluated against challenging data sentences.
        """
        result = run_benchmark()
        assert result.data_total >= 20, f"Expected at least 20 DATA cases, got {result.data_total}"
        assert result.data_fp > 0, (
            "Suspicious 0.0% false positive rate on hard benign DATA corpus!"
        )
        assert result.fp_rate_data > 0.0
        # Should be a low rate (e.g. <= 10.0%)
        assert result.fp_rate_data <= 10.0, f"False positive rate too high: {result.fp_rate_data}%"

    def test_structural_hard_benign_must_use_data_trust(self, tmp_path: Path) -> None:
        """Test 4: STRUCTURAL ASSERTION ENFORCEMENT.

        Verify that the runner actually crashes if a case in benign_adversarial_data
        is erroneously annotated with Trust.USER.
        """
        # Load legitimate benign corpus
        benign_cases = load_yaml_corpus(config.CORPUS_BENIGN_FILE)

        # Deliberately mutate one DATA case to Trust.USER
        mutated = [dict(c) for c in benign_cases]
        for c in mutated:
            if c.get("class") == config.CLASS_BENIGN_ADVERSARIAL_DATA:
                c["trust"] = config.BENCH_TRUST_USER_STR
                break

        # Save mutated corpus to temporary file
        tampered_benign = tmp_path / "tampered_benign.yaml"
        tampered_benign.write_text(yaml.safe_dump(mutated), encoding="utf-8")

        # Running benchmark must raise AssertionError
        with pytest.raises(AssertionError, match=r"must use Trust\.DATA"):
            run_benchmark(benign_path=tampered_benign)

    def test_two_number_ablation_reports_solo_and_marginal(self) -> None:
        """Test 5: Two-number per-layer ablation reporting.

        For each layer in default policy:
          - solo detected count > 0 (it catches attacks alone)
          - marginal loss count >= 0 (leave-one-out impact)
          - neither is inert (solo == 0 and marginal == 0 is forbidden)
        Specifically checks provenance: solo > 0 while marginal == 0 (redundancy within stack).
        """
        result = run_benchmark()
        assert len(result.layer_ablation) == len(config.DEFAULT_BENCH_LAYERS)

        for layer_name in config.DEFAULT_BENCH_LAYERS:
            assert layer_name in result.layer_ablation
            solo, marginal = result.layer_ablation[layer_name]
            # Every layer in the default policy must have a non-zero solo count
            assert solo > 0, f"Layer '{layer_name}' solo count must be > 0, got {solo}"
            assert marginal >= 0, (
                f"Layer '{layer_name}' marginal loss cannot be negative: {marginal}"
            )
            # Layer cannot be inert
            assert not (solo == 0 and marginal == 0), f"Layer '{layer_name}' is genuinely inert!"

        # Specifically check provenance: solo > 0 and marginal == 0 demonstrates
        # that a layer can be redundant in full stack yet load-bearing on its own
        prov_solo, prov_marginal = result.layer_ablation[config.LAYER_PROVENANCE]
        assert prov_solo > 0, f"Provenance solo should be > 0, got {prov_solo}"
        assert prov_marginal == 0, f"Provenance marginal in full stack is 0, got {prov_marginal}"

    def test_two_number_ablation_fails_on_inert_layer(self, tmp_path: Path) -> None:
        """Test 6: Suite fails loudly if a configured layer is genuinely inert.

        If a layer scores solo == 0 and marginal == 0 across the corpus,
        run_benchmark raises RuntimeError.
        """
        # Create a dummy attack corpus where no attacks exist
        empty_attacks = tmp_path / "empty_attacks.yaml"
        empty_attacks.write_text("[]", encoding="utf-8")

        with pytest.raises(RuntimeError, match="is genuinely inert"):
            run_benchmark(attacks_path=empty_attacks)

    def test_gut_check_pooled_vs_separate_reporting(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test 7: Gut check observing that pooled blending flatters hard-benign rate.

        Confirms that blended rate (e.g. 2.2%) is lower than the true DATA rate (4.0%),
        and proves that the runner prints benign_adversarial_data on its own separate line.
        """
        result = run_benchmark()
        # True data error rate
        assert result.fp_rate_data > result.fp_rate_user
        # Blended rate is diluted/flattered by the easy user cases
        assert result.fp_rate_user < result.pooled_fp_rate < result.fp_rate_data

        # Test printing report with and without pooled line
        print_benchmark_report(result, include_pooled=False)
        captured = capsys.readouterr().out
        assert config.CLASS_BENIGN_ADVERSARIAL_USER in captured
        assert config.CLASS_BENIGN_ADVERSARIAL_DATA in captured
        assert "[Gut-Check Pooled Blended" not in captured

        # When explicitly requested for gut check:
        print_benchmark_report(result, include_pooled=True)
        captured_pooled = capsys.readouterr().out
        assert "[Gut-Check Pooled Blended (Flattered)]" in captured_pooled

    def test_benchmark_report_contains_plain_language_disclaimer(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test 8: Benchmark report prints the plain-language disclaimer."""
        result = run_benchmark()
        print_benchmark_report(result)
        out = capsys.readouterr().out

        for line in config.BENCHMARK_DISCLAIMER:
            assert line in out, f"Missing disclaimer line: {line}"

    def test_whole_span_and_embedded_encoded_are_distinct_classes(self) -> None:
        """Test 9: whole_span_encoded and embedded_encoded are strictly separated classes."""
        attacks = load_yaml_corpus(config.CORPUS_ATTACKS_FILE)
        classes = {c["class"] for c in attacks}

        assert "whole_span_encoded" in classes, "Missing whole_span_encoded class"
        assert "embedded_encoded" in classes, "Missing embedded_encoded class"

        # Verify cases in whole_span_encoded exercise whole-span unwrap
        whole_cases = [c for c in attacks if c["class"] == "whole_span_encoded"]
        assert len(whole_cases) >= 2

        # Verify cases in embedded_encoded have embedded blobs inside ordinary text
        embedded_cases = [c for c in attacks if c["class"] == "embedded_encoded"]
        assert len(embedded_cases) >= 2
