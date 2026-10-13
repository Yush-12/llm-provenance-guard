"""
tests.test_context — tests for Trust, Origin, Span, and Context models.

Validates frozen immutability, structural origin invariants, and derivation rules.
"""

import pytest
from pydantic import ValidationError

from spanguard.context import Context, Origin, Span, Trust

# ---------------------------------------------------------------------------
# Trust enum
# ---------------------------------------------------------------------------


class TestTrust:
    def test_trust_has_exactly_three_values(self) -> None:
        """Closed enum -- no new values may be added silently."""
        assert set(Trust) == {Trust.SYSTEM, Trust.USER, Trust.DATA}

    def test_trust_values_are_distinct(self) -> None:
        values = [t.value for t in Trust]
        assert len(values) == len(set(values)) == 3


# ---------------------------------------------------------------------------
# Span validator: invalid states must be unrepresentable
# ---------------------------------------------------------------------------


class TestSpanInvalidStates:
    def test_data_span_without_origin_raises(self) -> None:
        """Control: DATA + no origin → ValidationError (invariant #1)."""
        with pytest.raises(ValidationError):
            Span(trust=Trust.DATA, text="untrusted content")

    def test_system_span_with_origin_raises(self) -> None:
        """Control: SYSTEM + origin set → ValidationError (invariant #2)."""
        origin = Origin(channel="ticket", ref="T-123")
        with pytest.raises(ValidationError):
            Span(trust=Trust.SYSTEM, text="system prompt", origin=origin)

    def test_user_span_with_origin_raises(self) -> None:
        """Control: USER + origin set → ValidationError (also invariant #2)."""
        origin = Origin(channel="email", ref="msg-42")
        with pytest.raises(ValidationError):
            Span(trust=Trust.USER, text="user message", origin=origin)


class TestSpanValidStates:
    def test_data_span_with_origin_succeeds(self) -> None:
        origin = Origin(channel="ticket", ref="T-123")
        span = Span(trust=Trust.DATA, text="data content", origin=origin)
        assert span.origin == origin
        assert span.trust is Trust.DATA

    def test_system_span_without_origin_succeeds(self) -> None:
        span = Span(trust=Trust.SYSTEM, text="system prompt")
        assert span.origin is None

    def test_user_span_without_origin_succeeds(self) -> None:
        span = Span(trust=Trust.USER, text="hello")
        assert span.origin is None

    def test_span_is_immutable(self) -> None:
        """Frozen model: mutation must raise."""
        origin = Origin(channel="wiki", ref="page-7")
        span = Span(trust=Trust.DATA, text="x", origin=origin)
        with pytest.raises(ValidationError):
            span.text = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Context: taint tracking and immutability
# ---------------------------------------------------------------------------


class TestContextTaint:
    def test_fresh_context_has_empty_tainted_by(self) -> None:
        """No spans → no taint."""
        ctx = Context(spans=())
        assert ctx.tainted_by == ()

    def test_data_span_taints_context(self) -> None:
        """After adding a DATA span, its origin appears in tainted_by."""
        origin = Origin(channel="ticket", ref="T-1")
        ctx = Context(spans=()).data("payload", origin)
        assert origin in ctx.tainted_by

    def test_taint_persists_after_subsequent_user_span(self) -> None:
        """Taint does NOT decay when a USER span is appended afterward."""
        origin = Origin(channel="ticket", ref="T-2")
        ctx = Context(spans=()).data("payload", origin).user("follow-up")
        assert origin in ctx.tainted_by

    def test_tainted_by_lists_all_data_origins(self) -> None:
        """Multiple DATA spans → all their origins are captured."""
        o1 = Origin(channel="ticket", ref="T-1")
        o2 = Origin(channel="email", ref="msg-9")
        ctx = Context(spans=()).data("a", o1).data("b", o2)
        assert o1 in ctx.tainted_by
        assert o2 in ctx.tainted_by
        assert len(ctx.tainted_by) == 2

    def test_system_spans_do_not_add_to_taint(self) -> None:
        ctx = Context(spans=()).system("be helpful")
        assert ctx.tainted_by == ()

    def test_user_spans_do_not_add_to_taint(self) -> None:
        ctx = Context(spans=()).user("hello")
        assert ctx.tainted_by == ()


# ---------------------------------------------------------------------------
# Context: builder immutability
# ---------------------------------------------------------------------------


class TestContextImmutability:
    def test_builder_does_not_mutate_original(self) -> None:
        """Calling .user() on ctx must not alter ctx.spans."""
        ctx = Context(spans=())
        original_spans = ctx.spans
        _ = ctx.user("new span")  # discard result
        assert ctx.spans == original_spans  # original unchanged

    def test_builder_returns_new_context(self) -> None:
        ctx = Context(spans=())
        ctx2 = ctx.user("hello")
        assert ctx is not ctx2
        assert len(ctx.spans) == 0
        assert len(ctx2.spans) == 1

    def test_context_is_immutable(self) -> None:
        """Frozen model: direct field mutation must raise."""
        ctx = Context(spans=())
        with pytest.raises(ValidationError):
            ctx.spans = ()  # type: ignore[misc]

    def test_tainted_by_has_no_setter(self) -> None:
        """`tainted_by` must not be settable.

        Pydantic frozen models intercept __setattr__ and raise ValidationError
        before Python's property descriptor raises AttributeError.  Either
        exception is an acceptable proof that setting is impossible.
        """
        ctx = Context(spans=())
        with pytest.raises((AttributeError, ValidationError)):
            ctx.tainted_by = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Context: nonce uniqueness
# ---------------------------------------------------------------------------


class TestContextNonce:
    def test_two_contexts_have_different_nonces(self) -> None:
        """CSPRNG default factory must not be shared or cached."""
        ctx1 = Context(spans=())
        ctx2 = Context(spans=())
        assert ctx1.nonce != ctx2.nonce

    def test_nonce_is_nonempty_string(self) -> None:
        ctx = Context(spans=())
        assert isinstance(ctx.nonce, str)
        assert len(ctx.nonce) > 0

    def test_builder_preserves_nonce(self) -> None:
        """Appending a span must not change the nonce (same request session)."""
        ctx = Context(spans=())
        ctx2 = ctx.user("hello")
        assert ctx2.nonce == ctx.nonce
