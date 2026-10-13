"""
context -- trust levels, provenance origins, spans, and prompt context.

    Trust      Closed three-value enum: SYSTEM > USER > DATA.
               Not an int -- there is no meaningful arithmetic between levels.
    Origin     Frozen model: channel + ref identifying where DATA came from.
    Span       Frozen model: trust + text + origin.
               Validator enforces BOTH directions:
                 DATA  + no origin  -> invalid (unrepresentable)
                 !DATA + origin set -> invalid (caller confusion caught here)
    Context    Frozen model: ordered tuple of Spans + per-request nonce.
               Builder methods (.system/.user/.data) return new instances.
               tainted_by is a @property -- never a stored flag.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from spanguard.config import NONCE_BYTE_LENGTH

# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------


class Trust(StrEnum):
    """Closed provenance-trust enum.  Values are not numeric scores."""

    SYSTEM = "SYSTEM"
    USER = "USER"
    DATA = "DATA"


# ---------------------------------------------------------------------------
# Origin
# ---------------------------------------------------------------------------


class Origin(BaseModel):
    """Identifies the external source of a DATA span.

    Both fields are required: the firewall uses (channel, ref) pairs to
    correlate taint across the lifetime of a request.
    """

    model_config = ConfigDict(frozen=True)

    channel: str
    """Logical source category, e.g. 'ticket', 'email', 'wiki'."""

    ref: str
    """Identifier within the channel, e.g. a ticket ID or message ID."""


# ---------------------------------------------------------------------------
# Span
# ---------------------------------------------------------------------------


class Span(BaseModel):
    """A single piece of text with its provenance attached.

    Invariants enforced at construction time (never downstream):
      - DATA trust  requires  an Origin (untrusted text must declare its source)
      - non-DATA trust forbids an Origin (would signal caller confusion)
    """

    model_config = ConfigDict(frozen=True)

    trust: Trust
    text: str
    origin: Origin | None = None

    @model_validator(mode="after")
    def _validate_origin_consistency(self) -> Self:
        """Enforce the bidirectional invariant between trust and origin."""
        if self.trust is Trust.DATA and self.origin is None:
            msg = "A DATA span must have an Origin (untrusted text must declare its source)."
            raise ValueError(msg)
        if self.trust is not Trust.DATA and self.origin is not None:
            msg = (
                f"A {self.trust.value} span must not have an Origin "
                f"(only DATA spans carry provenance)."
            )
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def _generate_nonce() -> str:
    """Return a fresh cryptographically random hex nonce.

    Length is controlled by config.NONCE_BYTE_LENGTH -- never inline here.
    """
    return secrets.token_hex(NONCE_BYTE_LENGTH)


class Context(BaseModel):
    """Ordered, immutable collection of Spans for one firewall request.

    The nonce is a per-request unforgeable delimiter seed; it is generated
    once at construction and preserved across builder calls so all spans in a
    request share the same fence token.

    tainted_by is a computed @property -- not a field -- so it can never
    disagree with the actual span contents.
    """

    model_config = ConfigDict(frozen=True)

    spans: tuple[Span, ...] = Field(default=())
    nonce: str = Field(default_factory=_generate_nonce)

    # ------------------------------------------------------------------
    # Derived state -- computed, never stored
    # ------------------------------------------------------------------

    @property
    def tainted_by(self) -> tuple[Origin, ...]:
        """Return the Origins of every DATA span present.

        Pure derivation from self.spans -- no separate flag, no cache.
        Taint does not decay: once a DATA span is in the Context it stays.
        """
        return tuple(
            span.origin
            for span in self.spans
            if span.trust is Trust.DATA
            if span.origin is not None  # always true for DATA, but mypy needs this
        )

    # ------------------------------------------------------------------
    # Builder methods -- each returns a NEW Context, never mutates self
    # ------------------------------------------------------------------

    def _append(self, span: Span) -> Context:
        """Return a new Context with *span* appended and the same nonce."""
        return Context(spans=(*self.spans, span), nonce=self.nonce)

    def system(self, text: str) -> Context:
        """Return a new Context with a SYSTEM span appended."""
        return self._append(Span(trust=Trust.SYSTEM, text=text))

    def user(self, text: str) -> Context:
        """Return a new Context with a USER span appended."""
        return self._append(Span(trust=Trust.USER, text=text))

    def data(self, text: str, origin: Origin) -> Context:
        """Return a new Context with a DATA span appended."""
        return self._append(Span(trust=Trust.DATA, text=text, origin=origin))
