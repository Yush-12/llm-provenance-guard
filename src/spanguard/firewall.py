"""
firewall -- top-level orchestration and fail-closed inspection.

Coordinates request-side inspection layers:
    1. NormalizeLayer
    2. IngressLayer
    3. ProvenanceLayer

Entry points:
    inspect(ctx) -> Verdict: Runs enabled layers, applies escalate() and decide().
                              Fails closed on any layer exception.
    render(ctx) -> str: Builds the final prompt string with per-request nonce fencing.
"""

from __future__ import annotations

from collections.abc import Sequence

from spanguard import config
from spanguard.context import Context, Trust
from spanguard.layers import Layer
from spanguard.layers.ingress import IngressLayer
from spanguard.layers.normalize import NormalizeLayer
from spanguard.layers.provenance import ProvenanceLayer
from spanguard.policy import Policy, decide, escalate
from spanguard.verdict import Finding, Severity, Verdict


class Firewall:
    """The central firewall orchestrator.

    Executes request-side inspection layers against untrusted context spans,
    evaluates policy decisions, and renders securely delimited prompts.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        layers: Sequence[Layer] | None = None,
    ) -> None:
        """Initialize Firewall with a Policy and inspection layers."""
        self.policy: Policy = policy if policy is not None else Policy()
        if layers is None:
            self.layers: tuple[Layer, ...] = (
                NormalizeLayer(),
                IngressLayer(),
                ProvenanceLayer(),
            )
        else:
            self.layers = tuple(layers)

    def inspect(self, ctx: Context) -> Verdict:
        """Execute request-side inspection pipeline with fail-closed error handling.

        Returns an aggregated Verdict indicating ALLOW or BLOCK.
        """
        findings: list[Finding] = []

        for layer in self.layers:
            layer_name = getattr(layer, "name", type(layer).__name__.lower().removesuffix("layer"))

            # Check if layer is disabled by policy
            if self.policy.enabled_layers and layer_name not in self.policy.enabled_layers:
                findings.append(
                    Finding(
                        layer=layer_name,
                        rule=config.RULE_LAYER_DISABLED,
                        severity=Severity.INFO,
                        invariant=False,
                        span_index=None,
                        evidence=f"Layer '{layer_name}' disabled by policy",
                    )
                )
                continue

            # Fail-closed execution: any exception in a layer blocks the request
            try:
                layer_findings = layer.inspect(ctx, self.policy)
                findings.extend(layer_findings)
            except Exception as exc:
                findings.append(
                    Finding(
                        layer=layer_name,
                        rule=config.RULE_LAYER_ERROR,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=None,
                        evidence=type(exc).__name__,
                    )
                )

        escalated_findings = escalate(findings, self.policy)
        decision = decide(escalated_findings, self.policy)
        return Verdict(decision=decision, findings=tuple(escalated_findings))

    def render(self, ctx: Context) -> str:
        """Render prompt text from Context, wrapping DATA spans in per-request unforgeable fences.

        This is the sole sanctioned path to convert a Context into a string for model submission.
        """
        rendered_spans: list[str] = []

        for span in ctx.spans:
            if span.trust == Trust.DATA and span.origin is not None:
                open_fence = config.FENCE_OPEN_TEMPLATE.format(
                    nonce=ctx.nonce,
                    channel=span.origin.channel,
                    ref=span.origin.ref,
                )
                close_fence = config.FENCE_CLOSE_TEMPLATE.format(nonce=ctx.nonce)
                rendered_spans.append(f"{open_fence}\n{span.text}\n{close_fence}")

            else:
                rendered_spans.append(span.text)

        return config.PROMPT_SPAN_SEPARATOR.join(rendered_spans)
