"""
normalize — reversible text normalisation pipeline.

Sub-modules
-----------
unicode    Detect and strip Unicode anomalies: tag blocks (U+E0000),
           zero-width characters, bidi override controls, and confusable
           homoglyph substitutions.
unwrap     Transport-layer decode: base64, hex, URL-percent, HTML entities,
           and nested combinations thereof.
views      BoundedView — a closure over a piece of text and its reversible
           normalised readings, used by layers to inspect text without
           permanently mutating it.
"""
