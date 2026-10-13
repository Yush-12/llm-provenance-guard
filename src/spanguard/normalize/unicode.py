"""
normalize.unicode -- Unicode anomaly detection and normalisation.

Pure functions reading strings and reporting detected anomalies:
    - Unicode tag blocks (U+E0000 - U+E007F) decoded to ASCII
    - Zero-width character stripping (U+200B, U+200C, etc.)
    - Bidi control override stripping (Trojan Source range)
    - Confusable homoglyph folding (Cyrillic look-alikes)
    - NFKC canonical equivalence normalization

All codepoint sets and ranges are sourced strictly from config.py.
No I/O.
"""

from __future__ import annotations

import unicodedata

from pydantic import BaseModel, ConfigDict, Field

from spanguard import config

# ---------------------------------------------------------------------------
# Character sets built from pure-ASCII codepoint integers in config.py
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS: frozenset[str] = frozenset(chr(cp) for cp in config.ZERO_WIDTH_CODEPOINTS)

BIDI_CHARS: frozenset[str] = frozenset(chr(cp) for cp in config.BIDI_CONTROL_CODEPOINTS)

CONFUSABLES_MAP: dict[str, str] = {
    chr(src): chr(dst) for src, dst in config.CONFUSABLE_CODEPOINT_PAIRS
}


# ---------------------------------------------------------------------------
# NormalizeResult
# ---------------------------------------------------------------------------


class NormalizeResult(BaseModel):
    """Result of Unicode anomaly inspection and normalisation.

    Fields
    ------
    cleaned          Fully normalized text (unmasked -> stripped -> folded -> NFKC).
    visible          Human-visible characters only (hidden tag-block characters omitted).
    recovered        Hidden payload characters decoded from tag-blocks, concatenated.
    unmasked         Text with tag-block characters replaced in-place by their ASCII
                     counterparts (what a tokenizer effectively sees).
    categories       Set of category labels that fired during analysis.
    has_tags         True if Unicode tag-block characters were present.
    has_zero_width   True if zero-width invisible characters were present.
    has_bidi         True if bidirectional override/isolate controls were present.
    has_confusables  True if confusable homoglyphs were detected and folded.
    """

    model_config = ConfigDict(frozen=True)

    cleaned: str
    visible: str
    recovered: str
    unmasked: str
    categories: frozenset[str] = Field(default_factory=frozenset)
    has_tags: bool = False
    has_zero_width: bool = False
    has_bidi: bool = False
    has_confusables: bool = False


# ---------------------------------------------------------------------------
# Tag-block handling
# ---------------------------------------------------------------------------


def decode_tag_block(text: str) -> tuple[str, str, str]:
    """Inspect text for Unicode tag-block characters (U+E0000 through U+E007F).

    Returns a 3-tuple:
        (visible, recovered, unmasked)
    where:
        visible:   only non-tag characters (human appearance)
        recovered: only the decoded tag characters (hidden payload alone)
        unmasked:  decoded tag characters substituted into original positions
    """
    visible_chars: list[str] = []
    recovered_chars: list[str] = []
    unmasked_chars: list[str] = []

    for c in text:
        cp = ord(c)
        if config.UNICODE_TAG_START <= cp <= config.UNICODE_TAG_END:
            ascii_char = chr(cp - config.UNICODE_TAG_START)
            recovered_chars.append(ascii_char)
            unmasked_chars.append(ascii_char)
        else:
            visible_chars.append(c)
            unmasked_chars.append(c)

    return (
        "".join(visible_chars),
        "".join(recovered_chars),
        "".join(unmasked_chars),
    )


# ---------------------------------------------------------------------------
# Zero-width detection and stripping
# ---------------------------------------------------------------------------


def has_zero_width(text: str) -> bool:
    """Return True if any configured zero-width codepoints are present."""
    return any(c in ZERO_WIDTH_CHARS for c in text)


def strip_zero_width(text: str) -> str:
    """Remove all zero-width characters from text."""
    return "".join(c for c in text if c not in ZERO_WIDTH_CHARS)


# ---------------------------------------------------------------------------
# Bidi control detection and stripping
# ---------------------------------------------------------------------------


def has_bidi(text: str) -> bool:
    """Return True if any configured Trojan Source bidi control characters are present."""
    return any(c in BIDI_CHARS for c in text)


def strip_bidi(text: str) -> str:
    """Remove all bidi override and isolate control characters from text."""
    return "".join(c for c in text if c not in BIDI_CHARS)


# ---------------------------------------------------------------------------
# Confusable homoglyph folding
# ---------------------------------------------------------------------------


def has_confusables(text: str) -> bool:
    """Return True if any configured confusable homoglyphs are present."""
    return any(c in CONFUSABLES_MAP for c in text)


def fold_confusables(text: str) -> str:
    """Replace configured confusable homoglyphs with their canonical Latin equivalents."""
    return "".join(CONFUSABLES_MAP.get(c, c) for c in text)


# ---------------------------------------------------------------------------
# Combined Unicode normalization
# ---------------------------------------------------------------------------


def normalize_unicode(text: str) -> NormalizeResult:
    """Perform full Unicode anomaly analysis, stripping, folding, and NFKC normalisation.

    Pure function: reads text and reports findings; does not block or decide.
    """
    visible, recovered, unmasked = decode_tag_block(text)
    tags_fired = len(recovered) > 0
    zw_fired = has_zero_width(text)
    bidi_fired = has_bidi(text)
    confusable_fired = has_confusables(text) or has_confusables(unmasked)

    categories: set[str] = set()
    if tags_fired:
        categories.add(config.UNICODE_CAT_TAG)
    if zw_fired:
        categories.add(config.UNICODE_CAT_ZERO_WIDTH)
    if bidi_fired:
        categories.add(config.UNICODE_CAT_BIDI)
    if confusable_fired:
        categories.add(config.UNICODE_CAT_CONFUSABLE)

    # Clean unmasked text so decoded tag characters are visible and clean
    cleaned = unmasked
    if zw_fired:
        cleaned = strip_zero_width(cleaned)
    if bidi_fired:
        cleaned = strip_bidi(cleaned)
    if confusable_fired:
        cleaned = fold_confusables(cleaned)

    # Canonical equivalence NFKC fold
    cleaned = unicodedata.normalize("NFKC", cleaned)

    return NormalizeResult(
        cleaned=cleaned,
        visible=visible,
        recovered=recovered,
        unmasked=unmasked,
        categories=frozenset(categories),
        has_tags=tags_fired,
        has_zero_width=zw_fired,
        has_bidi=bidi_fired,
        has_confusables=confusable_fired,
    )
