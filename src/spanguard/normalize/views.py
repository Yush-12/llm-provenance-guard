"""
normalize.views -- bounded closure over reversible text readings.

Provides:
    readings(text, max_variants) -> set[str]

    A bounded closure over a tuple of view functions:
        - Unicode normalisation (tag-block, zero-width, bidi, confusable, NFKC)
        - Transport unwrapping (base64, hex, percent, quoted-printable)
        - Embedded run decoding
        - Separator stripping (aggressive, for matching)
        - Whitespace noise collapse (narrower, for search)
        - Rot13 substitution
        - String reversal

Why this must be a closure and not a fixed pipeline:
The correct inverse sequence depends on the forward sequence chosen by the
attacker. For example:
    base64(dash_joined(secret)) requires unwrap THEN strip_separators.
    dash_joined(base64(secret)) requires strip_separators THEN unwrap.
A single fixed pipeline gets approximately half of all possible stacks wrong.
The bounded closure explores the graph of readings order-independently.
"""

from __future__ import annotations

import codecs
from collections.abc import Callable

from spanguard import config
from spanguard.normalize.unicode import normalize_unicode
from spanguard.normalize.unwrap import unwrap, unwrap_embedded

# ---------------------------------------------------------------------------
# Individual view functions
# ---------------------------------------------------------------------------


def _view_unicode(s: str) -> list[str]:
    """Produce Unicode-normalized variants of s."""
    res = normalize_unicode(s)
    variants: list[str] = []
    if res.cleaned != s:
        variants.append(res.cleaned)
    if res.recovered and res.recovered != s:
        variants.append(res.recovered)
    if res.unmasked != s:
        variants.append(res.unmasked)
    return variants


def _view_unwrap(s: str) -> list[str]:
    """Produce recursively unwrapped variant of s."""
    return [u] if (u := unwrap(s)) != s else []


def _view_embedded(s: str) -> list[str]:
    """Produce decoded embedded runs found within s."""
    return unwrap_embedded(s)


def _view_strip_separators(s: str) -> list[str]:
    """Strip delimiters/separators, preserving base64 padding '='."""
    variants: list[str] = []
    for sep in config.COMMON_SEPARATORS:
        if sep in s and (stripped := s.replace(sep, "")) != s:
            variants.append(stripped)

    all_stripped = config.RE_SEPARATORS.sub("", s)
    if all_stripped and all_stripped != s and all_stripped not in variants:
        variants.append(all_stripped)
    return variants


def _view_strip_noise(s: str) -> list[str]:
    """Collapse multiple whitespace runs to a single space."""
    return [c] if (c := config.RE_WHITESPACE_COLLAPSE.sub(" ", s).strip()) and c != s else []


def _view_rot13(s: str) -> list[str]:
    """Apply rot13 substitution."""
    return [r] if (r := codecs.encode(s, "rot_13")) != s else []


def _view_reversed(s: str) -> list[str]:
    """Reverse string."""
    return [r] if (r := s[::-1]) != s else []


VIEW_FUNCTIONS: tuple[Callable[[str], list[str]], ...] = (
    _view_unicode,
    _view_unwrap,
    _view_embedded,
    _view_strip_separators,
    _view_strip_noise,
    _view_rot13,
    _view_reversed,
)


# ---------------------------------------------------------------------------
# Bounded closure
# ---------------------------------------------------------------------------


def readings(
    text: str,
    max_variants: int = config.DEFAULT_MAX_VARIANTS,
) -> set[str]:
    """Compute a bounded closure of normalized readings over text.

    Explores reversible transforms order-independently until convergence,
    round budget (MAX_VARIANT_ROUNDS), or max_variants is reached.
    Catches ValueError and UnicodeError per view transform to guarantee resilience.
    """
    if max_variants <= 0:
        return set()

    seen: set[str] = {text}
    frontier: set[str] = {text}

    for _ in range(config.MAX_VARIANT_ROUNDS):
        if not frontier or len(seen) >= max_variants:
            break

        next_frontier: set[str] = set()
        for candidate in frontier:
            for view_fn in VIEW_FUNCTIONS:
                try:
                    derived = view_fn(candidate)
                except (ValueError, UnicodeError):
                    continue

                for item in derived:
                    if not item or item in seen:
                        continue
                    seen.add(item)
                    next_frontier.add(item)
                    if len(seen) >= max_variants:
                        break
                if len(seen) >= max_variants:
                    break
            if len(seen) >= max_variants:
                break

        frontier = next_frontier

    if len(seen) > max_variants:
        return set(list(seen)[:max_variants])

    return seen
