"""
tests.test_layer_normalize -- tests for Layer protocol and NormalizeLayer.
    - spanguard.layers.Layer
    - spanguard.layers.normalize.NormalizeLayer

Validates observation layer protocol, Unicode tag extraction, and DATA span scoping.
"""

from __future__ import annotations

import base64

from spanguard import config
from spanguard.context import Context, Origin
from spanguard.layers import Layer
from spanguard.layers.normalize import NormalizeLayer
from spanguard.policy import Policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encode_tag_block(ascii_text: str) -> str:
    """Encode an ASCII string into Unicode tag-block characters."""
    return "".join(chr(config.UNICODE_TAG_START + ord(c)) for c in ascii_text)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLayerProtocol:
    def test_normalize_layer_satisfies_protocol(self) -> None:
        """NormalizeLayer must implement the Layer protocol."""
        layer = NormalizeLayer()
        assert isinstance(layer, Layer)


class TestNormalizeLayer:
    def test_data_span_with_tag_block_produces_finding(self) -> None:
        """Test 1: A DATA span containing tag-block characters produces a finding

        naming that rule category.
        """
        tagged_text = f"Payload: {_encode_tag_block('INJECT')} end"
        ctx = Context().data(tagged_text, origin=Origin(channel="web", ref="item-1"))
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        assert len(findings) >= 1
        tag_findings = [f for f in findings if f.rule == config.RULE_TAG_BLOCK]
        assert len(tag_findings) == 1
        assert tag_findings[0].layer == config.LAYER_NORMALIZE
        assert tag_findings[0].span_index == 0
        assert tag_findings[0].invariant is False

    def test_data_span_ordinary_prose_produces_no_findings(self) -> None:
        """Test 2: A DATA span containing ordinary prose produces no findings."""
        ctx = Context().data(
            "The shipment of 40 units arrived at warehouse B yesterday.",
            origin=Origin(channel="database", ref="orders/123"),
        )
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        assert findings == []

    def test_user_span_with_tag_block_produces_no_findings(self) -> None:
        """Test 3: A USER span with tag-block characters produces NO findings.

        Design rationale:
        The normalize layer (and all content-reading layers in this project)
        only inspects DATA spans. USER and SYSTEM text represents authenticated
        prompts and user intent; they are not untrusted retrieved payloads.
        The exact same tag-block characters originating from USER must NOT
        generate findings from this layer.
        """
        tagged_text = f"User instruction with tags: {_encode_tag_block('SECRET')}"
        ctx = Context().user(tagged_text)
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        assert findings == [], "USER span must not be inspected by NormalizeLayer"

    def test_system_span_with_tag_block_produces_no_findings(self) -> None:
        """SYSTEM spans are also trusted prompt text and must produce no findings."""
        tagged_text = f"System prompt with tags: {_encode_tag_block('DIRECTIVE')}"
        ctx = Context().system(tagged_text)
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        assert findings == [], "SYSTEM span must not be inspected by NormalizeLayer"

    def test_all_normalize_findings_are_not_invariant(self) -> None:
        """Test 4: Every finding produced by NormalizeLayer must have invariant=False.

        Content-reading layers report scored/heuristic observations about payload shape;
        they never claim invariant structural facts.
        """
        tagged_text = f"Data with {_encode_tag_block('HIDDEN')}"
        blob = base64.b64encode(b"INJECTED_CODE").decode("ascii")
        embedded_text = f"order #8814 {blob} against the shipment"

        ctx = (
            Context()
            .data(tagged_text, origin=Origin(channel="api", ref="1"))
            .data(embedded_text, origin=Origin(channel="api", ref="2"))
        )
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        assert len(findings) >= 2
        for f in findings:
            assert f.invariant is False, f"Finding {f.rule} must have invariant=False"

    def test_data_span_with_embedded_base64_produces_finding(self) -> None:
        """A DATA span containing an embedded base64 payload produces an embedded-base64 finding."""
        blob = base64.b64encode(b"EXECUTE_PAYLOAD_NOW").decode("ascii")
        text = f"Reference id: {blob} verified by auditor"

        ctx = Context().data(text, origin=Origin(channel="webhook", ref="hook-4"))
        policy = Policy()
        layer = NormalizeLayer()

        findings = layer.inspect(ctx, policy)
        embedded_findings = [f for f in findings if f.rule == config.RULE_EMBEDDED_BASE64]
        assert len(embedded_findings) == 1
        assert embedded_findings[0].span_index == 0
        assert embedded_findings[0].invariant is False
