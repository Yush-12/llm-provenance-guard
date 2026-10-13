"""
arena.app — FastAPI application for the Spanguard 6-level challenge arena.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from arena.engine import AttemptResult, run_attempt
from arena.levels import load_all_levels
from arena.session import SessionManager
from spanguard import config


class AttemptRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    level: int
    payload: str = Field(min_length=1, max_length=config.ARENA_MAX_PAYLOAD_CHARS)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        """Bound work before normalization; preserve the submitted bytes."""
        if not value.strip():
            raise ValueError("Payload must contain non-whitespace text")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as err:
            raise ValueError("Payload must contain valid Unicode") from err
        return value


def create_arena_app(
    session_manager: SessionManager | None = None,
    levels_dir: str | None = None,
) -> FastAPI:
    """Create and configure the Arena FastAPI application."""
    app = FastAPI(title="Spanguard Provenance Arena")
    sessions = session_manager if session_manager is not None else SessionManager()

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    index_html = (static_dir / "index.html").read_text(encoding="utf-8")
    levels = load_all_levels(levels_dir=levels_dir)
    levels_by_id = {level.level: level for level in levels}

    @app.exception_handler(RequestValidationError)
    async def invalid_attempt(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not reflect raw payloads (including malformed Unicode) in errors.
        return JSONResponse(
            status_code=422,
            content={
                "detail": (
                    "Provide a session, a numeric level, and a non-empty UTF-8 payload "
                    f"of at most {config.ARENA_MAX_PAYLOAD_CHARS} characters."
                )
            },
        )

    @app.get(config.ARENA_ENDPOINT_ROOT, response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve the arena workbench without mixing presentation and API code."""
        return HTMLResponse(content=index_html)

    @app.get(config.ARENA_ENDPOINT_LEVELS)
    async def list_levels() -> list[dict[str, Any]]:
        """List all 6 challenge levels."""
        return [lvl.model_dump() for lvl in levels]

    @app.post(config.ARENA_ENDPOINT_SESSION)
    async def create_or_get_session() -> dict[str, Any]:
        """Create a new player session."""
        session = sessions.create_session()
        return {
            config.ARENA_RESP_SESSION_ID_KEY: session.session_id,
            config.ARENA_RESP_ATTEMPTS_USED_KEY: session.attempt_count,
            config.ARENA_RESP_ATTEMPTS_LEFT_KEY: sessions.max_attempts - session.attempt_count,
            "max_payload_chars": config.ARENA_MAX_PAYLOAD_CHARS,
        }

    @app.post(config.ARENA_ENDPOINT_ATTEMPT)
    async def attempt(req: AttemptRequest) -> JSONResponse:
        """Execute an injection attempt against a level."""
        session = sessions.get_session(req.session_id)
        if session is None:
            raise HTTPException(
                status_code=config.HTTP_404_NOT_FOUND,
                detail=config.ARENA_MSG_SESSION_NOT_FOUND,
            )

        if not sessions.check_rate_limit(session):
            raise HTTPException(
                status_code=config.HTTP_429_TOO_MANY_REQUESTS,
                detail=config.ARENA_MSG_RATE_LIMITED,
            )

        try:
            level_config = levels_by_id[req.level]
        except KeyError as err:
            raise HTTPException(
                status_code=config.PROXY_HTTP_400,
                detail=config.ARENA_MSG_INVALID_LEVEL,
            ) from err

        # Run attempt against level policy
        result: AttemptResult = run_attempt(
            payload=req.payload,
            level_config=level_config,
            canary=session.secret,
        )

        sessions.increment_attempts(session)

        # If Level 6+ was bypassed, record to harvest log
        if result.level >= config.ARENA_LEVEL_MAX and result.leaked:
            from arena.harvest import record_bypass

            record_bypass(result, session.session_id)

        response_payload = {
            config.ARENA_RESP_SESSION_ID_KEY: session.session_id,
            config.ARENA_RESP_LEVEL_KEY: result.level,
            config.ARENA_RESP_SUCCESS_KEY: result.success,
            config.ARENA_RESP_LEAKED_KEY: result.leaked,
            config.ARENA_RESP_BLOCKED_KEY: result.blocked,
            config.ARENA_RESP_STOPPED_BY_KEY: result.stopped_by,
            config.ARENA_RESP_RULE_KEY: result.rule,
            config.ARENA_RESP_FINDINGS_KEY: [f.model_dump() for f in result.findings],
            config.ARENA_RESP_ATTEMPTS_USED_KEY: session.attempt_count,
            config.ARENA_RESP_ATTEMPTS_LEFT_KEY: max(
                0, sessions.max_attempts - session.attempt_count
            ),
            config.ARENA_RESP_MESSAGE_KEY: (
                config.ARENA_MSG_LEAK_DETECTED if result.leaked else config.ARENA_MSG_CONTAINED
            ),
        }
        return JSONResponse(status_code=config.PROXY_HTTP_200, content=response_payload)

    return app


app = create_arena_app()
