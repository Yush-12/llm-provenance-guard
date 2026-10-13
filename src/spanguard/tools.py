"""
tools -- tool definitions, side-effect categories, guards, and call requests.

    Effect            Side-effect categories (READ, SEND, SPEND, WRITE, EXECUTE).
    Guard             Authorization requirements a tool declares:
                        - NO_UNTRUSTED_INFLUENCE (blocked if context is tainted)
                        - USER_CONFIRMED (blocked unless explicitly confirmed)
                        - ARGS_ALLOWLISTED (blocked if unexpected keys or invalid schema)
    Tool              Description of a registered tool: name, effects, guards,
                      permitted_args, and arg_schema.
    ToolCallRequest   Request by a model to invoke a tool with arguments.
    AgentReply        The text and tool calls emitted in an agent turn.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Effect(StrEnum):
    """Side-effect categories produced by tool invocations."""

    READ = "READ"
    SEND = "SEND"
    SPEND = "SPEND"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"


class Guard(StrEnum):
    """Authorization requirements declared by tools."""

    NO_UNTRUSTED_INFLUENCE = "NO_UNTRUSTED_INFLUENCE"
    USER_CONFIRMED = "USER_CONFIRMED"
    ARGS_ALLOWLISTED = "ARGS_ALLOWLISTED"


class Tool(BaseModel):
    """Registered tool specification."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    effects: frozenset[Effect] = Field(default_factory=frozenset)
    guards: frozenset[Guard] = Field(default_factory=frozenset)
    permitted_args: frozenset[str] = Field(default_factory=frozenset)
    arg_schema: type[BaseModel] | None = None


class ToolCallRequest(BaseModel):
    """Request by an agent/model to invoke a tool."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    user_confirmed: bool = False


class AgentReply(BaseModel):
    """Output turn produced by an agent."""

    model_config = ConfigDict(frozen=True)

    text: str = ""
    tool_calls: tuple[ToolCallRequest, ...] = Field(default=())
