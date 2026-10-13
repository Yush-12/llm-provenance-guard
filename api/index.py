"""
api/index.py — Vercel serverless function entrypoint forwarding to main.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from main import app  # noqa: E402

__all__ = ["app"]
