"""
layers.ingress -- scored heuristic ingress layer.

THE ONLY LAYER EXPLICITLY ALLOWED TO BE WRONG.

Inspects DATA spans only. Scans for prompt injection patterns:
    1. Chat-template / delimiter forgery (<|im_start|>, [INST], etc.) -> HIGH severity.
    2. Imperative-mood role adoption and instruction overrides -> MEDIUM severity.

All findings have invariant=False by default (strict_data policy escalation
can promote them at the firewall policy level; this layer itself never does).
"""

from __future__ import annotations

from spanguard import config
from spanguard.context import Context, Trust
from spanguard.normalize.views import readings
from spanguard.policy import Policy
from spanguard.verdict import Finding, Severity


class IngressLayer:
    """Scored heuristic ingress detection layer.

    Inspects DATA spans across normalized view readings to identify
    forged chat-template delimiters and second-person imperative overrides.
    """

    name: str = config.LAYER_INGRESS

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        """Inspect all DATA spans in ctx, returning heuristic findings."""
        findings: list[Finding] = []

        for idx, span in enumerate(ctx.spans):
            # Ingress scopes strictly to untrusted DATA spans
            if span.trust != Trust.DATA:
                continue

            # Track seen rules per span to avoid redundant duplicate findings across readings
            span_rules_seen: set[str] = set()

            # Explore normalized readings bounded by INGRESS_MAX_VARIANTS
            variants = readings(span.text, max_variants=config.INGRESS_MAX_VARIANTS)

            for variant in variants:
                # 1. Chat-template / control token forgery (HIGH severity)
                if config.RULE_CHAT_TEMPLATE_FORGERY not in span_rules_seen:
                    chat_match = config.RE_CHAT_TEMPLATE.search(variant)
                    if chat_match:
                        findings.append(
                            Finding(
                                layer=config.LAYER_INGRESS,
                                rule=config.RULE_CHAT_TEMPLATE_FORGERY,
                                severity=Severity.HIGH,
                                invariant=False,
                                span_index=idx,
                                evidence=f"Chat template token detected: {chat_match.group(0)}",
                            )
                        )
                        span_rules_seen.add(config.RULE_CHAT_TEMPLATE_FORGERY)

                # 2. Imperative role override (MEDIUM severity)
                if config.RULE_IMPERATIVE_ROLE_OVERRIDE not in span_rules_seen:
                    role_match = config.RE_BARE_IMPERATIVE_ROLE.search(
                        variant
                    ) or config.RE_SECOND_PERSON_ROLE.search(variant)
                    if role_match:
                        findings.append(
                            Finding(
                                layer=config.LAYER_INGRESS,
                                rule=config.RULE_IMPERATIVE_ROLE_OVERRIDE,
                                severity=Severity.MEDIUM,
                                invariant=False,
                                span_index=idx,
                                evidence=(
                                    f"Imperative role override detected: "
                                    f"{role_match.group(0).strip()}"
                                ),
                            )
                        )
                        span_rules_seen.add(config.RULE_IMPERATIVE_ROLE_OVERRIDE)

                # 3. Instruction override (MEDIUM severity)
                if config.RULE_INSTRUCTION_OVERRIDE not in span_rules_seen:
                    inst_match = config.RE_INSTRUCTION_OVERRIDE.search(variant)
                    if inst_match:
                        findings.append(
                            Finding(
                                layer=config.LAYER_INGRESS,
                                rule=config.RULE_INSTRUCTION_OVERRIDE,
                                severity=Severity.MEDIUM,
                                invariant=False,
                                span_index=idx,
                                evidence=(
                                    f"Instruction override detected: {inst_match.group(0).strip()}"
                                ),
                            )
                        )
                        span_rules_seen.add(config.RULE_INSTRUCTION_OVERRIDE)

        return findings
