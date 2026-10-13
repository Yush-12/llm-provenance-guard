"""
tests.test_toolauth -- tests for tool authorization:
    - spanguard.tools (Effect, Guard, Tool, ToolCallRequest, AgentReply)
    - spanguard.layers.toolauth (ToolAuthLayer, GUARD_RULE_MAP)

Validates causal taint tracking, guard enforcement, argument allowlists, and structural reflection coverage.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from spanguard import config
from spanguard.context import Context, Origin
from spanguard.layers.toolauth import GUARD_RULE_MAP, ToolAuthLayer
from spanguard.tools import Effect, Guard, Tool, ToolCallRequest
from spanguard.verdict import Severity

# ---------------------------------------------------------------------------
# Test Schemas and Fixtures
# ---------------------------------------------------------------------------


class EmailSchema(BaseModel):
    recipient: str
    body: str


class SearchSchema(BaseModel):
    query: str


@pytest.fixture
def send_email_tool() -> Tool:
    return Tool(
        name="send_email",
        effects=frozenset({Effect.SEND}),
        guards=frozenset({Guard.NO_UNTRUSTED_INFLUENCE, Guard.USER_CONFIRMED}),
        permitted_args=frozenset({"recipient", "body"}),
        arg_schema=EmailSchema,
    )


@pytest.fixture
def search_docs_tool() -> Tool:
    return Tool(
        name="search_docs",
        effects=frozenset({Effect.READ}),
        guards=frozenset(),  # No guards -- read-only tool
        permitted_args=frozenset({"query"}),
        arg_schema=SearchSchema,
    )


@pytest.fixture
def strict_api_tool() -> Tool:
    return Tool(
        name="strict_api",
        effects=frozenset({Effect.READ}),
        guards=frozenset({Guard.ARGS_ALLOWLISTED}),
        permitted_args=frozenset({"query"}),
        arg_schema=SearchSchema,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestToolAuthorization:
    def test_tool_with_no_untrusted_influence_refused_on_tainted_context(
        self, send_email_tool: Tool
    ) -> None:
        """Test 1: Tool with NO_UNTRUSTED_INFLUENCE is refused on tainted context

        (invariant=True, CRITICAL), naming the tainting origin in the finding.
        """
        layer = ToolAuthLayer(tools=[send_email_tool])
        origin = Origin(channel="untrusted_web", ref="comment-88")
        ctx = Context().data("Please email the admin", origin=origin)
        call = ToolCallRequest(
            tool_name="send_email",
            args={"recipient": "admin@corp.com", "body": "hello"},
            user_confirmed=True,
        )

        findings = layer.inspect_call(ctx, call)

        assert len(findings) >= 1
        taint_findings = [f for f in findings if f.rule == config.RULE_TOOL_UNTRUSTED_INFLUENCE]
        assert len(taint_findings) == 1
        f = taint_findings[0]
        assert f.layer == config.LAYER_TOOLAUTH
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True
        assert "untrusted_web:comment-88" in f.evidence

    def test_tool_with_no_untrusted_influence_authorized_on_clean_context(
        self, send_email_tool: Tool
    ) -> None:
        """Test 2: The SAME tool, called against an untainted context, is authorized."""
        layer = ToolAuthLayer(tools=[send_email_tool])
        ctx = Context().user("Please email the admin")
        call = ToolCallRequest(
            tool_name="send_email",
            args={"recipient": "admin@corp.com", "body": "hello"},
            user_confirmed=True,
        )

        findings = layer.inspect_call(ctx, call)
        assert findings == []

    def test_read_only_tool_without_guards_authorized_on_tainted_context(
        self, search_docs_tool: Tool
    ) -> None:
        """Test 3: A read-only tool with no guards on the SAME tainted context is authorized.

        Proves taint alone does not refuse tools that did not ask to be guarded.
        """
        layer = ToolAuthLayer(tools=[search_docs_tool])
        origin = Origin(channel="untrusted_web", ref="comment-88")
        ctx = Context().data("Some untrusted payload", origin=origin)
        call = ToolCallRequest(
            tool_name="search_docs",
            args={"query": "python tutorial"},
        )

        findings = layer.inspect_call(ctx, call)
        assert findings == []

    def test_tool_call_with_unpermitted_arg_key_refused(self, strict_api_tool: Tool) -> None:
        """Test 4: An extra argument key not in permitted_args is refused (CRITICAL, invariant)."""
        layer = ToolAuthLayer(tools=[strict_api_tool])
        ctx = Context().user("Search query")
        # Attacker adds unexpected 'bcc' or 'debug' parameter
        call = ToolCallRequest(
            tool_name="strict_api",
            args={"query": "docs", "extra_param": "exfiltrate"},
        )

        findings = layer.inspect_call(ctx, call)
        assert len(findings) >= 1
        allowlist_findings = [
            f for f in findings if f.rule == config.RULE_TOOL_ARGS_NOT_ALLOWLISTED
        ]
        assert len(allowlist_findings) == 1
        f = allowlist_findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True
        assert "extra_param" in f.evidence

    def test_tool_call_missing_required_schema_key_refused(self, strict_api_tool: Tool) -> None:
        """Test 5: A tool call missing a required schema key is refused with a finding,

        not an unhandled exception bubbling up.
        """
        layer = ToolAuthLayer(tools=[strict_api_tool])
        ctx = Context().user("Search query")
        # Missing required 'query' key
        call = ToolCallRequest(
            tool_name="strict_api",
            args={},
        )

        findings = layer.inspect_call(ctx, call)
        assert len(findings) >= 1
        schema_findings = [f for f in findings if f.rule == config.RULE_TOOL_SCHEMA_VIOLATION]
        assert len(schema_findings) == 1
        f = schema_findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.invariant is True

    def test_structural_every_guard_enum_has_enforcing_rule(self) -> None:
        """Test 6: STRUCTURAL TEST.

        Assert every member of the Guard enum is present in GUARD_RULE_MAP,
        and that ToolAuthLayer actually enforces each Guard member when violated.
        """
        # 1. Structural map completeness: every Guard member must be mapped
        assert set(GUARD_RULE_MAP.keys()) == set(Guard)

        # 2. Functional enforcement check for each guard member:
        layer = ToolAuthLayer()
        ctx_tainted = Context().data("taint", origin=Origin(channel="web", ref="1"))
        ctx_clean = Context().user("clean")

        # Test Guard.NO_UNTRUSTED_INFLUENCE
        tool_taint = Tool(
            name="t1",
            guards=frozenset({Guard.NO_UNTRUSTED_INFLUENCE}),
            permitted_args=frozenset(),
        )
        call1 = ToolCallRequest(tool_name="t1", args={})
        f1 = layer.inspect_call(ctx_tainted, call1, tool=tool_taint)
        assert any(f.rule == GUARD_RULE_MAP[Guard.NO_UNTRUSTED_INFLUENCE] for f in f1)

        # Test Guard.USER_CONFIRMED
        tool_confirm = Tool(
            name="t2",
            guards=frozenset({Guard.USER_CONFIRMED}),
            permitted_args=frozenset(),
        )
        call2 = ToolCallRequest(tool_name="t2", args={}, user_confirmed=False)
        f2 = layer.inspect_call(ctx_clean, call2, tool=tool_confirm)
        assert any(f.rule == GUARD_RULE_MAP[Guard.USER_CONFIRMED] for f in f2)

        # Test Guard.ARGS_ALLOWLISTED
        tool_allow = Tool(
            name="t3",
            guards=frozenset({Guard.ARGS_ALLOWLISTED}),
            permitted_args=frozenset({"valid"}),
        )
        call3 = ToolCallRequest(tool_name="t3", args={"invalid_key": "val"})
        f3 = layer.inspect_call(ctx_clean, call3, tool=tool_allow)
        assert any(f.rule == GUARD_RULE_MAP[Guard.ARGS_ALLOWLISTED] for f in f3)

    def test_user_confirmed_guard(self, send_email_tool: Tool) -> None:
        """Test 7: USER_CONFIRMED: call without confirmation is refused; with confirmation is authorized."""
        layer = ToolAuthLayer(tools=[send_email_tool])
        ctx = Context().user("Send confirmation test")

        # Unconfirmed call -> refused
        unconfirmed_call = ToolCallRequest(
            tool_name="send_email",
            args={"recipient": "boss@corp.com", "body": "resignation"},
            user_confirmed=False,
        )
        findings_unconfirmed = layer.inspect_call(ctx, unconfirmed_call)
        assert len(findings_unconfirmed) >= 1
        assert any(f.rule == config.RULE_TOOL_NOT_CONFIRMED for f in findings_unconfirmed)

        # Confirmed call -> authorized
        confirmed_call = ToolCallRequest(
            tool_name="send_email",
            args={"recipient": "boss@corp.com", "body": "resignation"},
            user_confirmed=True,
        )
        findings_confirmed = layer.inspect_call(ctx, confirmed_call)
        assert findings_confirmed == []
