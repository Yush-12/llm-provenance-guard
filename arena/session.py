"""
arena.session — In-memory session store with LRU eviction and TTL expiry.
"""

from __future__ import annotations

import secrets
import time
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
    """In-memory session store with LRU eviction, TTL expiry, and attempt rate limiting."""

    def __init__(
        self,
        max_sessions: int = config.ARENA_SESSION_MAX_COUNT,
        ttl_seconds: int = config.ARENA_SESSION_TTL_SECONDS,
        max_attempts: int = config.ARENA_MAX_ATTEMPTS_PER_SESSION,
    ) -> None:
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self._sessions: dict[str, ArenaSession] = {}

    def clean_expired(self, current_time: float | None = None) -> int:
        now = current_time if current_time is not None else time.time()
        expired = [
            sid for sid, s in self._sessions.items() if (now - s.last_accessed) > self.ttl_seconds
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def create_session(
        self, secret: str | None = None, current_time: float | None = None
    ) -> ArenaSession:
        now = current_time if current_time is not None else time.time()
        self.clean_expired(now)
        while len(self._sessions) >= self.max_sessions:
            del self._sessions[next(iter(self._sessions))]

        sid = secrets.token_hex(config.NONCE_BYTE_LENGTH)
        canary = (
            secret
            or f"{config.ARENA_CANARY_PREFIX}{secrets.token_hex(config.ARENA_CANARY_LENGTH)}"
        )
        session = ArenaSession(session_id=sid, secret=canary, created_at=now, last_accessed=now)
        self._sessions[sid] = session
        return session

    def get_session(
        self, session_id: str, current_time: float | None = None
    ) -> ArenaSession | None:
        now = current_time if current_time is not None else time.time()
        session = self._sessions.get(session_id)
        if not session or (now - session.last_accessed) > self.ttl_seconds:
            self._sessions.pop(session_id, None)
            return None
        session.last_accessed = now
        self._sessions[session_id] = self._sessions.pop(session_id)
        return session

    def check_rate_limit(self, session: ArenaSession) -> bool:
        return session.attempt_count < self.max_attempts

    def increment_attempts(self, session: ArenaSession) -> int:
        session.attempt_count += 1
        return session.attempt_count
