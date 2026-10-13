"""
normalize.unwrap -- transport-layer decoding and embedded run detection.

Pure functions that decode transport encodings:
    - Base64 (standard and URL-safe)
    - Hexadecimal
    - Percent-encoding (URL)
    - Quoted-printable (gated against key-value corruption)

Includes:
    - Whole-span "mostly" encoding ratio checks
    - Bounded embedded run scanning within sentences
    - Recursive unwrapping bounded by MAX_DECODE_DEPTH
    - Printable ratio checks excluding zero-width and bidi characters

All thresholds, bounds, and compiled regexes are sourced strictly from config.py.
No I/O.
"""

from __future__ import annotations

import base64
import quopri
import urllib.parse

from spanguard import config
from spanguard.normalize.unicode import BIDI_CHARS, ZERO_WIDTH_CHARS

# Set of characters excluded from the printable ratio denominator so
# interleaved invisible characters do not penalize valid text.
_EXCLUDED_FROM_RATIO: frozenset[str] = ZERO_WIDTH_CHARS | BIDI_CHARS


# ---------------------------------------------------------------------------
# Printable check
# ---------------------------------------------------------------------------


def is_printable_text(s: str) -> bool:
    """Check if decoded text meets the MIN_PRINTABLE_RATIO threshold.

    Excludes zero-width and bidi characters from the denominator so that
    interleaved invisible characters do not lower the printable ratio
    and cause an otherwise valid secret or payload to be rejected.
    """
    if not s:
        return False

    filtered = [c for c in s if c not in _EXCLUDED_FROM_RATIO]
    if not filtered:
        return False

    printable_count = sum(1 for c in filtered if c.isprintable() or c in ("\n", "\r", "\t"))
    return (printable_count / len(filtered)) >= config.MIN_PRINTABLE_RATIO


# ---------------------------------------------------------------------------
# Whole-span check
# ---------------------------------------------------------------------------


def is_mostly_encoded(
    text: str,
    alphabet_chars: frozenset[str],
    min_length: int = config.MIN_ENCODED_LENGTH,
    ratio: float = config.MOSTLY_ENCODED_RATIO,
) -> bool:
    """Return True if text consists almost entirely of characters from the codec alphabet.

    Requires at least min_length characters before evaluating.
    """
    stripped = text.strip()
    if len(stripped) < min_length:
        return False

    count = sum(1 for c in stripped if c in alphabet_chars)
    return (count / len(stripped)) >= ratio


# ---------------------------------------------------------------------------
# Quoted-printable gating
# ---------------------------------------------------------------------------


def can_attempt_quoted_printable(s: str) -> bool:
    """Determine whether quoted-printable decoding may be attempted.

    Gated control: do not fire on plain '=' strings like 'retries=3, timeout=30'.
    Requires either a soft line break ('=\r\n' or '=\n') or at least
    QP_MIN_HEX_ESCAPES real hex escapes ('=XX') before attempting decode.
    """
    if "=" not in s:
        return False

    # Soft line break
    if config.RE_QP_SOFT_BREAK.search(s):
        return True

    # Real hex escapes
    hex_escapes = config.RE_QP_HEX_ESCAPE.findall(s)
    return len(hex_escapes) >= config.QP_MIN_HEX_ESCAPES


# ---------------------------------------------------------------------------
# Individual transport decoders
# ---------------------------------------------------------------------------


def try_decode_base64(s: str) -> str | None:
    """Attempt to decode a base64 string (standard or url-safe).

    Returns decoded string if valid UTF-8 and meets printable ratio, else None.
    """
    candidate = s.strip()
    if len(candidate) < config.MIN_ENCODED_LENGTH:
        return None

    if not is_mostly_encoded(candidate, config.BASE64_ALPHABET_CHARS):
        return None

    # Add missing padding if needed
    pad_needed = (4 - len(candidate) % 4) % 4
    padded = candidate + ("=" * pad_needed)

    # 1. Standard base64 with strict character validation
    try:
        raw_std = base64.b64decode(padded.encode("ascii", errors="strict"), validate=True)
        if raw_std:
            decoded_std = raw_std.decode("utf-8")
            if is_printable_text(decoded_std):
                return decoded_std
    except Exception:
        pass

    # 2. URL-safe base64 with strict character validation
    try:
        urlsafe_std = padded.replace("-", "+").replace("_", "/")
        raw_url = base64.b64decode(urlsafe_std.encode("ascii", errors="strict"), validate=True)
        if raw_url:
            decoded_url = raw_url.decode("utf-8")
            if is_printable_text(decoded_url):
                return decoded_url
    except Exception:
        pass

    return None


def try_decode_hex(s: str) -> str | None:
    """Attempt to decode a hexadecimal string.

    Returns decoded string if valid UTF-8 and meets printable ratio, else None.
    """
    candidate = s.strip()
    if len(candidate) < config.MIN_ENCODED_LENGTH or len(candidate) % 2 != 0:
        return None

    if not is_mostly_encoded(candidate, config.HEX_ALPHABET_CHARS):
        return None

    try:
        raw_bytes = bytes.fromhex(candidate)
        if not raw_bytes:
            return None
        decoded_str = raw_bytes.decode("utf-8")
        if is_printable_text(decoded_str):
            return decoded_str
    except Exception:
        return None

    return None


def try_decode_quoted_printable(s: str) -> str | None:
    """Attempt to decode quoted-printable text if gating check passes."""
    if not can_attempt_quoted_printable(s):
        return None

    try:
        raw_bytes = quopri.decodestring(s.encode("utf-8", errors="replace"))
        decoded_str = raw_bytes.decode("utf-8", errors="replace")
        if decoded_str != s and is_printable_text(decoded_str):
            return decoded_str
    except Exception:
        return None

    return None


def try_decode_percent(s: str) -> str | None:
    """Attempt to decode percent-encoded (URL) escapes."""
    if not config.RE_PERCENT_ESCAPE.search(s):
        return None

    try:
        decoded_str = urllib.parse.unquote(s, errors="strict")
        if decoded_str != s and is_printable_text(decoded_str):
            return decoded_str
    except Exception:
        return None

    return None


# ---------------------------------------------------------------------------
# Embedded-run detection
# ---------------------------------------------------------------------------


def unwrap_embedded(text: str) -> list[str]:
    """Scan text for maximal runs of codec alphabet characters and decode them.

    Bounded by MAX_EMBEDDED_RUNS to avoid pathological unbounded work.
    Returns decoded payloads and replaced full strings.
    """
    results: list[str] = []
    run_count = 0

    # Scan for base64 candidates
    for match in config.RE_BASE64_RUN.finditer(text):
        if run_count >= config.MAX_EMBEDDED_RUNS:
            break
        run_str = match.group(0)
        decoded = try_decode_base64(run_str)
        if decoded is not None:
            results.append(decoded)
            # Replaced sentence with decoded run
            replaced = text[: match.start()] + decoded + text[match.end() :]
            results.append(replaced)
            run_count += 1

    # Scan for hex candidates
    for match in config.RE_HEX_RUN.finditer(text):
        if run_count >= config.MAX_EMBEDDED_RUNS:
            break
        run_str = match.group(0)
        decoded = try_decode_hex(run_str)
        if decoded is not None:
            results.append(decoded)
            replaced = text[: match.start()] + decoded + text[match.end() :]
            results.append(replaced)
            run_count += 1

    return results


# ---------------------------------------------------------------------------
# Recursive unwrap
# ---------------------------------------------------------------------------


def unwrap(text: str, max_depth: int = config.MAX_DECODE_DEPTH) -> str:
    """Recursively decode text across transport codecs up to max_depth.

    Input size is capped at MAX_NORMALIZE_BYTES.

    NOTE on MAX_DECODE_DEPTH:
    This recursion depth budget is a semantic control against unbounded
    re-interpretation of the same bytes, not primarily a performance control.
    Each decode step shrinks or preserves the input, so total work across
    nesting is geometrically bounded already.
    """
    if len(text.encode("utf-8")) > config.MAX_NORMALIZE_BYTES:
        return text

    current = text
    for _ in range(max_depth):
        next_candidate = (
            try_decode_base64(current)
            or try_decode_hex(current)
            or try_decode_quoted_printable(current)
            or try_decode_percent(current)
        )
        if next_candidate is not None and next_candidate != current:
            current = next_candidate
        else:
            break

    return current
