"""
layers.provenance -- invariant provenance and delimiter integrity layer.

Checks structural facts:
    Delimiter forgery: A DATA span contains this Context's own closing fence marker
    verbatim. That indicates an active attempt to escape delimiter isolation.
    Always an invariant=True CRITICAL finding.
"""

from __future__ import annotations

from spanguard import config
from spanguard.context import Context, Trust
from spanguard.policy import Policy
from spanguard.verdict import Finding, Severity


class ProvenanceLayer:
    """Invariant provenance and delimiter integrity layer.

    Scans DATA spans for delimiter forgery targeting this context's own nonce.
    Findings are invariant=True structural facts.
    """

    name: str = config.LAYER_PROVENANCE

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        """Inspect DATA spans for forged closing delimiters matching ctx.nonce."""
        findings: list[Finding] = []
        own_closing = config.FENCE_CLOSE_MARKER_TEMPLATE.format(nonce=ctx.nonce)

        for idx, span in enumerate(ctx.spans):
            if span.trust != Trust.DATA:
                continue

            if own_closing in span.text:
                findings.append(
                    Finding(
                        layer=config.LAYER_PROVENANCE,
                        rule=config.RULE_DELIMITER_FORGERY,
                        severity=Severity.CRITICAL,
                        invariant=True,
                        span_index=idx,
                        evidence="Forged closing delimiter detected matching context nonce",
                    )
                )

        return findings
