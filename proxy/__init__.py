"""
proxy — OpenAI-chat-completions-compatible FastAPI surface for Spanguard.
"""

from __future__ import annotations

from proxy.app import app, create_app
from proxy.infer import infer_context

__all__ = ["app", "create_app", "infer_context"]
