"""
main.py — Root ASGI entrypoint for Spanguard on Vercel and local development.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root and src/ to sys.path so serverless functions can resolve imports
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

from arena.app import app  # noqa: E402
from proxy.app import app as proxy_app  # noqa: E402

# Include OpenAI-compatible proxy routes on the same ASGI app
for route in proxy_app.routes:
    if getattr(route, "path", "").startswith("/v1"):
        app.routes.append(route)

__all__ = ["app"]
