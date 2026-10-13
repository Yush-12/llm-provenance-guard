"""
bench.runner -- security benchmark suite and layer ablation runner.

Evaluates spanguard detection and false-positive performance across:
    1. 11 attack classes (YAML corpus).
    2. Two separate benign corpora (USER adversarial vs DATA adversarial).
    3. Two-number per-layer ablation (solo vs marginal leave-one-out).

Outputs plain-language disclaimer regarding benchmark boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from spanguard import config
from spanguard.context import Context, Origin
from spanguard.firewall import Firewall
from spanguard.layers import Layer
from spanguard.layers.egress import EgressLayer
from spanguard.layers.ingress import IngressLayer
from spanguard.layers.normalize import NormalizeLayer
from spanguard.layers.provenance import ProvenanceLayer
from spanguard.layers.toolauth import ToolAuthLayer
from spanguard.policy import Policy, decide
from spanguard.tools import AgentReply, Effect, Guard, Tool, ToolCallRequest
from spanguard.verdict import Decision

STANDARD_BENCH_TOOLS: dict[str, Tool] = {
    config.BENCH_TOOL_SEND_EMAIL: Tool(
        name=config.BENCH_TOOL_SEND_EMAIL,
        effects=frozenset({Effect.SEND}),
        guards=frozenset(
            {Guard.NO_UNTRUSTED_INFLUENCE, Guard.USER_CONFIRMED, Guard.ARGS_ALLOWLISTED}
        ),
        permitted_args=frozenset({config.BENCH_TOOL_ARG_RECIPIENT, config.BENCH_TOOL_ARG_BODY}),
    ),
}


@dataclass(frozen=True)
class BenchmarkResult:
    """Aggregated benchmark evaluation metrics."""

    attack_rates: dict[str, float]
    fp_rate_user: float
    fp_rate_data: float
    user_total: int
    user_fp: int
    data_total: int
    data_fp: int
    layer_ablation: dict[str, tuple[int, int]]  # layer -> (solo_detected, marginal_lost)
    pooled_fp_rate: float


def load_yaml_corpus(path: str | Path) -> list[dict[str, Any]]:
    """Load list of corpus cases from YAML file."""
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    if not isinstance(data, list):
        msg = f"Expected list of cases in {path}, got {type(data).__name__}"
        raise ValueError(msg)
    return data


def evaluate_attack_case(case: dict[str, Any], policy: Policy) -> bool:
    """Evaluate whether an attack case is detected and blocked under policy."""
    active_layers = (
        set(policy.enabled_layers) if policy.enabled_layers else set(config.DEFAULT_BENCH_LAYERS)
    )

    # 1. Request-side prompt evaluation
    if "prompt" in case:
        ctx = Context()
        prompt_template = case["prompt"]
        prompt_text = prompt_template.replace("{nonce}", ctx.nonce)
        trust_str = case.get("trust", config.BENCH_TRUST_DATA_STR)

        if trust_str == config.BENCH_TRUST_DATA_STR:
            ctx = ctx.data(
                prompt_text,
                origin=Origin(channel=config.BENCH_CHANNEL_UNTRUSTED, ref="case-1"),
            )
        else:
            ctx = ctx.user(prompt_text)

        # Build firewall with active request layers
        req_layers: list[Layer] = []
        if "normalize" in active_layers:
            req_layers.append(NormalizeLayer())
        if "ingress" in active_layers:
            req_layers.append(IngressLayer())
        if "provenance" in active_layers:
            req_layers.append(ProvenanceLayer())

        firewall = Firewall(policy=policy, layers=req_layers)
        verdict = firewall.inspect(ctx)
        if verdict.decision == Decision.BLOCK:
            return True

    # 2. Tool-call evaluation
    if "tool_call" in case and "toolauth" in active_layers:
        call_spec = case["tool_call"]
        call = ToolCallRequest(
            tool_name=call_spec["name"],
            args=call_spec.get("args", {}),
            user_confirmed=call_spec.get("user_confirmed", False),
        )
        ctx = Context()
        if case.get("trust", config.BENCH_TRUST_DATA_STR) == config.BENCH_TRUST_DATA_STR:
            ctx = ctx.data(
                "Tainted influence context",
                origin=Origin(channel=config.BENCH_CHANNEL_UNTRUSTED, ref="1"),
            )
        else:
            ctx = ctx.user("Clean user context")

        toolauth = ToolAuthLayer(tools=STANDARD_BENCH_TOOLS)
        findings = toolauth.inspect_call(ctx, call, policy=policy)
        decision = decide(findings, policy)
        if decision == Decision.BLOCK:
            return True

    # 3. Egress outbound reply evaluation
    if "reply" in case and "egress" in active_layers:
        reply_spec = case["reply"]
        reply = AgentReply(text=reply_spec.get("text", ""))
        egress = EgressLayer()
        findings = egress.inspect_reply(reply, policy)
        decision = decide(findings, policy)
        if decision == Decision.BLOCK:
            return True

    return False


def run_benchmark(
    attacks_path: str | Path = config.CORPUS_ATTACKS_FILE,
    benign_path: str | Path = config.CORPUS_BENIGN_FILE,
) -> BenchmarkResult:
    """Execute full benchmark evaluation across attack and benign corpora."""
    attacks = load_yaml_corpus(attacks_path)
    benign = load_yaml_corpus(benign_path)

    # 1. Structural verification of benign corpus trust annotations
    for case in benign:
        c_class = case.get("class")
        c_trust = case.get("trust")
        if (
            c_class == config.CLASS_BENIGN_ADVERSARIAL_DATA
            and c_trust != config.BENCH_TRUST_DATA_STR
        ):
            msg = (
                f"Case '{case.get('id')}' in {config.CLASS_BENIGN_ADVERSARIAL_DATA} "
                f"must use Trust.DATA, got {c_trust}"
            )
            raise AssertionError(msg)
        if (
            c_class == config.CLASS_BENIGN_ADVERSARIAL_USER
            and c_trust != config.BENCH_TRUST_USER_STR
        ):
            msg = (
                f"Case '{case.get('id')}' in {config.CLASS_BENIGN_ADVERSARIAL_USER} "
                f"must use Trust.USER, got {c_trust}"
            )
            raise AssertionError(msg)

    # Base full-stack policy
    base_policy = Policy(
        canary_secrets=(config.DEFAULT_BENCH_CANARY,),
        host_allowlist=config.DEFAULT_BENCH_HOST_ALLOWLIST,
        enabled_layers=config.DEFAULT_BENCH_LAYERS,
        strict_data=True,
        strict_data_rules=config.BENCH_STRICT_DATA_RULES,
    )

    # 2. Evaluate attack detection rate per class
    classes: set[str] = {c["class"] for c in attacks}
    attack_rates: dict[str, float] = {}

    for cls_name in sorted(classes):
        cls_cases = [c for c in attacks if c["class"] == cls_name]
        detected = sum(1 for c in cls_cases if evaluate_attack_case(c, base_policy))
        rate = (detected / len(cls_cases)) * 100.0 if cls_cases else 0.0
        attack_rates[cls_name] = rate

    # 3. Evaluate benign false-positive rates (SEPARATED)
    user_cases = [c for c in benign if c["class"] == config.CLASS_BENIGN_ADVERSARIAL_USER]
    data_cases = [c for c in benign if c["class"] == config.CLASS_BENIGN_ADVERSARIAL_DATA]

    user_fp = 0
    for c in user_cases:
        ctx = Context().user(c["text"])
        firewall = Firewall(policy=base_policy)
        if firewall.inspect(ctx).decision == Decision.BLOCK:
            user_fp += 1
    fp_rate_user = (user_fp / len(user_cases)) * 100.0 if user_cases else 0.0

    data_fp = 0
    for idx, c in enumerate(data_cases):
        ctx = Context().data(
            c["text"],
            origin=Origin(channel=config.BENCH_CHANNEL_SUPPORT, ref=f"ticket-{idx}"),
        )
        firewall = Firewall(policy=base_policy)
        if firewall.inspect(ctx).decision == Decision.BLOCK:
            data_fp += 1
    fp_rate_data = (data_fp / len(data_cases)) * 100.0 if data_cases else 0.0

    pooled_fp = user_fp + data_fp
    pooled_total = len(user_cases) + len(data_cases)
    pooled_fp_rate = (pooled_fp / pooled_total) * 100.0 if pooled_total else 0.0

    # 4. Two-number layer ablation
    total_detected_full = sum(1 for c in attacks if evaluate_attack_case(c, base_policy))
    layer_ablation: dict[str, tuple[int, int]] = {}

    for layer_name in config.DEFAULT_BENCH_LAYERS:
        # (a) Solo pass: ONLY layer_name enabled
        solo_policy = Policy(
            canary_secrets=(config.DEFAULT_BENCH_CANARY,),
            host_allowlist=config.DEFAULT_BENCH_HOST_ALLOWLIST,
            enabled_layers=(layer_name,),
            strict_data=True,
            strict_data_rules=config.BENCH_STRICT_DATA_RULES,
        )
        solo_detected = sum(1 for c in attacks if evaluate_attack_case(c, solo_policy))

        # (b) Marginal pass: all enabled EXCEPT layer_name (leave-one-out)
        without_layers = tuple(item for item in config.DEFAULT_BENCH_LAYERS if item != layer_name)
        marginal_policy = Policy(
            canary_secrets=(config.DEFAULT_BENCH_CANARY,),
            host_allowlist=config.DEFAULT_BENCH_HOST_ALLOWLIST,
            enabled_layers=without_layers,
            strict_data=True,
            strict_data_rules=config.BENCH_STRICT_DATA_RULES,
        )
        without_detected = sum(1 for c in attacks if evaluate_attack_case(c, marginal_policy))
        marginal_lost = total_detected_full - without_detected

        # Fail loudly if layer is genuinely inert
        if solo_detected == 0 and marginal_lost == 0:
            msg = (
                f"Layer '{layer_name}' is genuinely inert: "
                f"solo_detected=0, marginal_lost=0 across attack corpus!"
            )
            raise RuntimeError(msg)

        layer_ablation[layer_name] = (solo_detected, marginal_lost)

    return BenchmarkResult(
        attack_rates=attack_rates,
        fp_rate_user=fp_rate_user,
        fp_rate_data=fp_rate_data,
        user_total=len(user_cases),
        user_fp=user_fp,
        data_total=len(data_cases),
        data_fp=data_fp,
        layer_ablation=layer_ablation,
        pooled_fp_rate=pooled_fp_rate,
    )


def print_benchmark_report(result: BenchmarkResult, include_pooled: bool = False) -> None:
    """Print formatted benchmark evaluation report with standard disclaimer."""
    print("\n" + "=" * 70)
    for line in config.BENCHMARK_DISCLAIMER:
        print(line)
    print("=" * 70)

    print("\n--- Detection Rate Per Attack Class ---")
    for cls_name, rate in sorted(result.attack_rates.items()):
        print(f"  {cls_name:<28}: {rate:>5.1f}%")

    print("\n--- False Positive Rates (Reported Separately) ---")
    print(
        f"  {config.CLASS_BENIGN_ADVERSARIAL_USER:<28}: {result.fp_rate_user:>5.1f}% ({result.user_fp}/{result.user_total})"
    )
    print(
        f"  {config.CLASS_BENIGN_ADVERSARIAL_DATA:<28}: {result.fp_rate_data:>5.1f}% ({result.data_fp}/{result.data_total})"
    )
    if include_pooled:
        print(
            f"  [Gut-Check Pooled Blended (Flattered)]: {result.pooled_fp_rate:>5.1f}% ({result.user_fp + result.data_fp}/{result.user_total + result.data_total})"
        )

    print("\n--- Two-Number Layer Ablation ---")
    print(f"  {'Layer':<16} {'Solo Detected':<16} {'Marginal Loss (Leave-One-Out)'}")
    for layer_name, (solo, marginal) in result.layer_ablation.items():
        print(f"  {layer_name:<16} {solo:<16} {marginal}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    res = run_benchmark()
    print_benchmark_report(res)
