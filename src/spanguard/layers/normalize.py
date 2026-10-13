"""
layers.normalize -- normalization inspection layer.

Inspects each DATA span in the context (and only DATA spans).
SYSTEM and USER text is authenticated prompt content and is never inspected
by content-reading layers.

Emits scored (invariant=False) findings for Unicode anomalies and transport
encodings detected within untrusted data.
"""

from __future__ import annotations

from spanguard import config
from spanguard.context import Context, Trust
from spanguard.normalize.unicode import normalize_unicode
from spanguard.normalize.unwrap import (
    try_decode_base64,
    try_decode_hex,
    try_decode_percent,
    try_decode_quoted_printable,
)
from spanguard.policy import Policy
from spanguard.verdict import Finding, Severity


class NormalizeLayer:
    """Normalization inspection layer.

    Reports Unicode and transport-encoding anomalies discovered in DATA spans.
    All findings emitted by this layer have invariant=False.
    """

    name: str = config.LAYER_NORMALIZE

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        """Inspect all DATA spans in ctx, returning a list of findings."""
        findings: list[Finding] = []
        severity = Severity(config.NORMALIZE_FINDING_SEVERITY_ORDINAL)

        for idx, span in enumerate(ctx.spans):
            # Content-reading layers only inspect untrusted DATA spans
            if span.trust != Trust.DATA:
                continue

            text = span.text

            # 1. Unicode anomalies
            unicode_res = normalize_unicode(text)
            if unicode_res.has_tags:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_TAG_BLOCK,
                        severity=severity,
                        evidence="Unicode tag-block characters detected in DATA span",
                        span_index=idx,
                        invariant=False,
                    )
                )
            if unicode_res.has_zero_width:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_ZERO_WIDTH,
                        severity=severity,
                        evidence="Zero-width invisible characters detected in DATA span",
                        span_index=idx,
                        invariant=False,
                    )
                )
            if unicode_res.has_bidi:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_BIDI_CONTROL,
                        severity=severity,
                        evidence="Bidirectional override control characters detected in DATA span",
                        span_index=idx,
                        invariant=False,
                    )
                )
            if unicode_res.has_confusables:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_CONFUSABLE,
                        severity=severity,
                        evidence="Confusable homoglyphs detected in DATA span",
                        span_index=idx,
                        invariant=False,
                    )
                )

            # 2. Whole-span transport decode checks
            whole_b64 = try_decode_base64(text)
            if whole_b64 is not None:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_WHOLE_SPAN_BASE64,
                        severity=severity,
                        evidence="Whole DATA span consists of base64-encoded text",
                        span_index=idx,
                        invariant=False,
                    )
                )
            elif try_decode_hex(text) is not None:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_WHOLE_SPAN_HEX,
                        severity=severity,
                        evidence="Whole DATA span consists of hex-encoded text",
                        span_index=idx,
                        invariant=False,
                    )
                )
            elif try_decode_quoted_printable(text) is not None:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_WHOLE_SPAN_QUOTED_PRINTABLE,
                        severity=severity,
                        evidence="Whole DATA span consists of quoted-printable text",
                        span_index=idx,
                        invariant=False,
                    )
                )
            elif try_decode_percent(text) is not None:
                findings.append(
                    Finding(
                        layer=config.LAYER_NORMALIZE,
                        rule=config.RULE_WHOLE_SPAN_PERCENT,
                        severity=severity,
                        evidence="Whole DATA span consists of percent-encoded text",
                        span_index=idx,
                        invariant=False,
                    )
                )

            # 3. Embedded run transport decode checks
            if whole_b64 is None:
                stripped_text = text.strip()
                embedded_b64_found = False
                for match in config.RE_BASE64_RUN.finditer(text):
                    run_str = match.group(0)
                    if run_str == stripped_text:
                        continue
                    if try_decode_base64(run_str) is not None:
                        embedded_b64_found = True
                        break
                if embedded_b64_found:
                    findings.append(
                        Finding(
                            layer=config.LAYER_NORMALIZE,
                            rule=config.RULE_EMBEDDED_BASE64,
                            severity=severity,
                            evidence="Embedded base64 run detected in DATA span",
                            span_index=idx,
                            invariant=False,
                        )
                    )

                embedded_hex_found = False
                for match in config.RE_HEX_RUN.finditer(text):
                    run_str = match.group(0)
                    if run_str == stripped_text:
                        continue
                    if try_decode_hex(run_str) is not None:
                        embedded_hex_found = True
                        break
                if embedded_hex_found:
                    findings.append(
                        Finding(
                            layer=config.LAYER_NORMALIZE,
                            rule=config.RULE_EMBEDDED_HEX,
                            severity=severity,
                            evidence="Embedded hex run detected in DATA span",
                            span_index=idx,
                            invariant=False,
                        )
                    )

        return findings
