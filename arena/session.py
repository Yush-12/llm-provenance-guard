"""
arena.session — In-memory session store with LRU eviction and TTL expiry.

Provides demo session tracking and per-session attempt rate limiting
without persistent database dependencies.
"""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from spanguard import config


class ArenaSession(BaseModel):
    """An active player challenge session."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    secret: str
    created_at: float
    last_accessed: float
    attempt_count: int = 0
    bypasses: list[dict[str, Any]] = Field(default_factory=list)


class SessionManager:
    """Thread-safe, in-memory LRU session store with TTL expiry and rate limiting."""

    def __init__(
        self,
        max_sessions: int = config.ARENA_SESSION_MAX_COUNT,
        ttl_seconds: int = config.ARENA_SESSION_TTL_SECONDS,
        max_attempts: int = config.ARENA_MAX_ATTEMPTS_PER_SESSION,
    ) -> None:
        self.max_sessions: int = max_sessions
        self.ttl_seconds: int = ttl_seconds
        self.max_attempts: int = max_attempts
        self._sessions: OrderedDict[str, ArenaSession] = OrderedDict()

    def clean_expired(self, current_time: float | None = None) -> int:
        """Evict sessions that have exceeded the TTL window."""
        now = current_time if current_time is not None else time.time()
        expired_keys = [
            sid for sid, s in self._sessions.items() if (now - s.last_accessed) > self.ttl_seconds
        ]
        for sid in expired_keys:
            del self._sessions[sid]
        return len(expired_keys)

    def create_session(
        self,
        secret: str | None = None,
        current_time: float | None = None,
    ) -> ArenaSession:
        """Create a new session with a unique canary secret and enforce LRU capacity."""
        now = current_time if current_time is not None else time.time()
        self.clean_expired(now)

        while len(self._sessions) >= self.max_sessions:
            self._sessions.popitem(last=False)

        session_id = secrets.token_hex(config.NONCE_BYTE_LENGTH)
        canary_secret = (
            secret
            if secret is not None
            else f"{config.ARENA_CANARY_PREFIX}{secrets.token_hex(config.ARENA_CANARY_LENGTH)}"
        )

        session = ArenaSession(
            session_id=session_id,
            secret=canary_secret,
            created_at=now,
            last_accessed=now,
            attempt_count=0,
        )
        self._sessions[session_id] = session
        return session

    def get_session(
        self,
        session_id: str,
        current_time: float | None = None,
    ) -> ArenaSession | None:
        """Retrieve an active session, updating its LRU position and access timestamp."""
        now = current_time if current_time is not None else time.time()
        session = self._sessions.get(session_id)
        if session is None:
            return None

        if (now - session.last_accessed) > self.ttl_seconds:
            del self._sessions[session_id]
            return None

        session.last_accessed = now
        self._sessions.move_to_end(session_id)
        return session

    def check_rate_limit(self, session: ArenaSession) -> bool:
        """Return True if session has remaining attempts; False if rate limited."""
        return session.attempt_count < self.max_attempts

    def increment_attempts(self, session: ArenaSession) -> int:
        """Increment the session attempt counter and return new count."""
        session.attempt_count += 1
        return session.attempt_count
