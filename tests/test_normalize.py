"""
tests.test_normalize -- tests for normalization modules:
    - spanguard.normalize.unicode
    - spanguard.normalize.unwrap
    - spanguard.normalize.views

Validates Unicode unmasking, transport unwrapping, and readings transitive closure.
"""

from __future__ import annotations

import base64
import codecs
import time

from spanguard import config
from spanguard.normalize.unicode import (
    NormalizeResult,
    decode_tag_block,
    fold_confusables,
    has_bidi,
    has_confusables,
    has_zero_width,
    normalize_unicode,
    strip_bidi,
    strip_zero_width,
)
from spanguard.normalize.unwrap import (
    can_attempt_quoted_printable,
    is_mostly_encoded,
    is_printable_text,
    unwrap,
    unwrap_embedded,
)
from spanguard.normalize.views import readings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encode_tag_block(ascii_text: str) -> str:
    """Encode an ASCII string into Unicode tag-block characters (U+E0000+)."""
    return "".join(chr(config.UNICODE_TAG_START + ord(c)) for c in ascii_text)


# ---------------------------------------------------------------------------
# Test 1: Tag-block round-trip
# ---------------------------------------------------------------------------


class TestUnicodeTagBlock:
    def test_pure_tag_block_decode(self) -> None:
        """Decode pure tag block: visible is empty, recovered has the text."""
        hidden = "INJECTION PAYLOAD"
        tagged = _encode_tag_block(hidden)
        visible, recovered, unmasked = decode_tag_block(tagged)

        assert visible == ""
        assert recovered == hidden
        assert unmasked == hidden

    def test_interspersed_tag_block_round_trip(self) -> None:
        """Tag characters interspersed with real text:

        - visible: human-visible text without hidden tag characters
        - recovered: hidden payload concatenated alone
        - unmasked: hidden characters substituted in original positions
        """
        hidden = "DROP TABLES"
        tagged = _encode_tag_block(hidden)
        interspersed = f"Please summarize: {tagged} Thank you."

        visible, recovered, unmasked = decode_tag_block(interspersed)
        assert visible == "Please summarize:  Thank you."
        assert recovered == hidden
        assert unmasked == f"Please summarize: {hidden} Thank you."

    def test_normalize_unicode_reports_tags(self) -> None:
        """normalize_unicode() flags tag-block anomaly and populates fields."""
        hidden = "EXECUTE"
        tagged = _encode_tag_block(hidden)
        text = f"Notice: {tagged}"

        res: NormalizeResult = normalize_unicode(text)
        assert res.has_tags is True
        assert config.UNICODE_CAT_TAG in res.categories
        assert res.recovered == hidden
        assert res.visible == "Notice: "
        assert res.unmasked == f"Notice: {hidden}"


# ---------------------------------------------------------------------------
# Test 2: Zero-width / bidi / confusable detection
# ---------------------------------------------------------------------------


class TestUnicodeAnomalies:
    def test_plain_ascii_fires_no_anomalies(self) -> None:
        """Plain English prose must NOT fire any anomaly detectors."""
        plain = "The quick brown fox jumps over the lazy dog. 12345."
        res = normalize_unicode(plain)

        assert res.has_tags is False
        assert res.has_zero_width is False
        assert res.has_bidi is False
        assert res.has_confusables is False
        assert len(res.categories) == 0
        assert res.cleaned == plain

    def test_zero_width_detection_and_stripping(self) -> None:
        """Crafted zero-width characters fire detection and are stripped."""
        zw_char = chr(config.ZERO_WIDTH_CODEPOINTS[0])  # U+200B ZWSP
        crafted = f"hel{zw_char}lo wo{zw_char}rld"

        assert has_zero_width(crafted) is True
        assert strip_zero_width(crafted) == "hello world"

        res = normalize_unicode(crafted)
        assert res.has_zero_width is True
        assert config.UNICODE_CAT_ZERO_WIDTH in res.categories
        assert res.cleaned == "hello world"

    def test_bidi_detection_and_stripping(self) -> None:
        """Trojan Source bidi overrides fire detection and are stripped."""
        bidi_char = chr(config.BIDI_CONTROL_CODEPOINTS[0])  # U+202A LRE
        crafted = f"admin{bidi_char}access"

        assert has_bidi(crafted) is True
        assert strip_bidi(crafted) == "adminaccess"

        res = normalize_unicode(crafted)
        assert res.has_bidi is True
        assert config.UNICODE_CAT_BIDI in res.categories
        assert res.cleaned == "adminaccess"

    def test_confusables_folding(self) -> None:
        """Cyrillic look-alikes that NFKC preserves must fold to Latin."""
        # Cyrillic small 'а' (U+0430) and 'о' (U+043E)
        cyrillic_a = chr(0x0430)
        cyrillic_o = chr(0x043E)
        crafted = f"p{cyrillic_a}ssw{cyrillic_o}rd"

        assert has_confusables(crafted) is True
        assert fold_confusables(crafted) == "password"

        res = normalize_unicode(crafted)
        assert res.has_confusables is True
        assert config.UNICODE_CAT_CONFUSABLE in res.categories
        assert res.cleaned == "password"


# ---------------------------------------------------------------------------
# Test 3: Whole-span (_mostly) base64 check
# ---------------------------------------------------------------------------


class TestWholeSpanEncoding:
    def test_mostly_encoded_fires_on_valid_base64_span(self) -> None:
        """Fires when text consists almost entirely of base64 alphabet."""
        encoded = base64.b64encode(b"This is a secret instruction payload.").decode("ascii")
        assert len(encoded) >= config.MIN_ENCODED_LENGTH
        assert is_mostly_encoded(encoded, config.BASE64_ALPHABET_CHARS) is True

    def test_mostly_encoded_rejects_short_strings(self) -> None:
        """Does NOT fire on strings below the configured length floor."""
        assert is_mostly_encoded("short", config.BASE64_ALPHABET_CHARS) is False

    def test_mostly_encoded_rejects_plain_english_prose(self) -> None:
        """Prose containing spaces and punctuation fails the ratio check."""
        prose = "This is a normal sentence with spaces and punctuation!"
        # Spaces and punctuation '!' are not in the base64 alphabet
        assert is_mostly_encoded(prose, config.BASE64_ALPHABET_CHARS) is False


# ---------------------------------------------------------------------------
# Test 4: Embedded-run detection
# ---------------------------------------------------------------------------


class TestEmbeddedRunDetection:
    def test_embedded_base64_in_sentence_is_found_and_decoded(self) -> None:
        """Embedded check: a base64 blob in the middle of a sentence is decoded

        where a whole-span-only check would miss it completely.
        Exact required shape: 'order #8814 ... <blob> ... against the shipment'.
        """
        secret_payload = "INJECT_SUPERUSER_COMMAND"
        b64_blob = base64.b64encode(secret_payload.encode("utf-8")).decode("ascii")
        sentence = f"order #8814 {b64_blob} against the shipment"

        # Control: whole-span check on the entire sentence FAILS
        assert is_mostly_encoded(sentence, config.BASE64_ALPHABET_CHARS) is False

        # Embedded detection SUCCEEDS and extracts the payload
        embedded_results = unwrap_embedded(sentence)
        assert any(secret_payload in item for item in embedded_results)


# ---------------------------------------------------------------------------
# Test 5: Quoted-printable gating
# ---------------------------------------------------------------------------


class TestQuotedPrintableGating:
    def test_qp_does_not_fire_on_innocent_key_value_string(self) -> None:
        """Gating: '=30' is technically QP, but 'retries=3, timeout=30' must NOT be corrupted."""
        innocent = "retries=3, timeout=30"
        assert can_attempt_quoted_printable(innocent) is False
        assert unwrap(innocent) == innocent

    def test_qp_fires_when_valid_hex_escapes_present(self) -> None:
        """Fires when at least QP_MIN_HEX_ESCAPES real hex escapes exist."""
        qp_encoded = "Hello=20World=21"
        assert can_attempt_quoted_printable(qp_encoded) is True
        assert "Hello World!" in unwrap(qp_encoded)

    def test_qp_fires_on_soft_line_break(self) -> None:
        """Fires when a soft line break is present."""
        qp_soft = "Hello =\r\nWorld"
        assert can_attempt_quoted_printable(qp_soft) is True
        assert "Hello World" in unwrap(qp_soft)


# ---------------------------------------------------------------------------
# Test 6: Deeply nested base64 recursion budget & speed
# ---------------------------------------------------------------------------


class TestDeeplyNestedBase64:
    def test_twelve_layer_nested_base64_unwraps_fast(self) -> None:
        """Deeply nested base64 (10+ layers) unwraps correctly in < 1 second.

        Documents that MAX_DECODE_DEPTH is a semantic control against unbounded
        re-interpretation, not primarily a performance control.
        """
        payload = "CONFIDENTIAL_DIRECTIVE_ALPHA"
        current = payload
        layers = 12
        for _ in range(layers):
            current = base64.b64encode(current.encode("utf-8")).decode("ascii")

        start = time.perf_counter()
        result = unwrap(current)
        duration = time.perf_counter() - start

        assert result == payload
        assert duration < 1.0  # Must finish in well under a second


# ---------------------------------------------------------------------------
# Test 7: The Closure vs Pipeline asymmetry (The Core Architectural Proof)
# ---------------------------------------------------------------------------


class TestBoundedClosureOrderIndependence:
    """The core architectural proof:

    Case A: unwrap-then-strip (attacker did dash-join THEN base64)
    Case B: strip-then-unwrap (attacker did base64 THEN dash-join)
    A single fixed unwrap-then-strip pipeline passes Case A but FAILS Case B.
    The bounded closure discovers the plain secret in both cases.
    """

    SECRET: str = "AUTHENTICATIONKEY9981"

    def test_case_a_unwrap_then_strip(self) -> None:
        """Case A: attacker did dash-join then base64 -> requires unwrap then strip."""
        dash_first = "-".join(self.SECRET)
        case_a_input = base64.b64encode(dash_first.encode("utf-8")).decode("ascii")

        readings_a = readings(case_a_input)
        assert self.SECRET in readings_a, "Case A (unwrap-then-strip) must find secret"

    def test_case_b_strip_then_unwrap(self) -> None:
        """Case B: attacker did base64 then dash-join -> requires strip then unwrap."""
        b64_first = base64.b64encode(self.SECRET.encode("utf-8")).decode("ascii")
        case_b_input = "-".join(b64_first)

        readings_b = readings(case_b_input)
        assert self.SECRET in readings_b, "Case B (strip-then-unwrap) must find secret"


# ---------------------------------------------------------------------------
# Test 8: readings() variant budget termination
# ---------------------------------------------------------------------------


class TestBoundedClosureBudget:
    def test_readings_terminates_and_respects_max_variants(self) -> None:
        """With a tiny max_variants, readings() stops and returns <= max_variants items."""
        complex_input = "order #8814 SGVsbG8gV29ybGQh against the shipment"
        budget = 3

        start = time.perf_counter()
        variants = readings(complex_input, max_variants=budget)
        elapsed = time.perf_counter() - start

        assert len(variants) <= budget
        assert elapsed < 1.0


# ---------------------------------------------------------------------------
# Additional controls: printable ratio excludes zero-width & bidi
# ---------------------------------------------------------------------------


class TestPrintableRatioDenominator:
    def test_zero_width_and_bidi_excluded_from_denominator(self) -> None:
        """Zero-width characters interleaved in text must NOT penalize printable ratio."""
        secret = "CLEAN_TEXT"
        # Interleave zero-width spaces heavily (50% of the string)
        zw = chr(config.ZERO_WIDTH_CODEPOINTS[0])
        interleaved = zw.join(secret)

        # Standard ratio check without denominator filtering would score < 0.5
        # is_printable_text() must exclude ZW/bidi from denominator and return True
        assert is_printable_text(interleaved) is True

    def test_binary_garbage_is_rejected(self) -> None:
        """NUL bytes and non-printable control codes are rejected."""
        garbage = "\x00\x01\x02\x03\x04\x05binary_stream"
        assert is_printable_text(garbage) is False


class TestRot13View:
    def test_rot13_is_in_closure_readings(self) -> None:
        """Rot13 is present in the closure variants."""
        secret = "AGENT_COMMAND"
        encoded = codecs.encode(secret, "rot_13")
        variants = readings(encoded)
        assert secret in variants
