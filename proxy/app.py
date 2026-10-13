"""
proxy.app — OpenAI-chat-completions-compatible FastAPI proxy surface.

DOCUMENTED WEAKNESS OF PROXY MODE:
----------------------------------
WARNING: Content PASTED into a plain "user" message (which is exactly what
most naive RAG integrations do — dump retrieved documents into the user turn)
will be inferred as Trust.USER, NOT Trust.DATA.

This means request-side DATA-scoped ingress heuristics will NOT inspect it.

This is a real, documented weakness of proxy mode specifically, not a bug —
the invariant layers (toolauth and egress canary matching on the RESPONSE side)
still function correctly even when the request-side inference is weak; only
the request-side DATA-scoped detection is what is weakened.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from proxy.infer import infer_context
from spanguard import config
from spanguard.agent.mock import Agent, MockAgent
from spanguard.firewall import Firewall
from spanguard.layers.egress import EgressLayer
from spanguard.policy import Policy, decide
from spanguard.verdict import Decision

logger = logging.getLogger(config.PROXY_LOGGER_NAME)
logger.warning(config.PROXY_MODE_WEAKNESS_WARNING)


def create_app(
    firewall: Firewall | None = None,
    agent: Agent | None = None,
    egress: EgressLayer | None = None,
    policy: Policy | None = None,
) -> FastAPI:
    """Create and configure the FastAPI proxy application.

    Supports pluggable Firewall, Agent, EgressLayer, and Policy.
    """
    logger.warning(config.PROXY_MODE_WEAKNESS_WARNING)

    effective_policy = policy if policy is not None else Policy()
    effective_firewall = firewall if firewall is not None else Firewall(policy=effective_policy)
    effective_agent = agent if agent is not None else MockAgent(policy=effective_policy)
    effective_egress = egress if egress is not None else EgressLayer()

    fastapi_app = FastAPI(title=config.PROXY_RESPONSE_MODEL)

    @fastapi_app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=config.PROXY_HTTP_400,
            content={
                config.PROXY_RESP_ERROR_KEY: {
                    config.PROXY_RESP_DETAIL_KEY: config.PROXY_MALFORMED_REQUEST_MESSAGE
                }
            },
        )

    @fastapi_app.post(config.PROXY_ENDPOINT_CHAT_COMPLETIONS)
    async def chat_completions(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=config.PROXY_HTTP_400,
                content={
                    config.PROXY_RESP_ERROR_KEY: {
                        config.PROXY_RESP_DETAIL_KEY: config.PROXY_MALFORMED_REQUEST_MESSAGE
                    }
                },
            )

        if not isinstance(body, dict):
            return JSONResponse(
                status_code=config.PROXY_HTTP_400,
                content={
                    config.PROXY_RESP_ERROR_KEY: {
                        config.PROXY_RESP_DETAIL_KEY: config.PROXY_MALFORMED_REQUEST_MESSAGE
                    }
                },
            )

        messages = body.get(config.PROXY_MSG_MESSAGES_KEY)
        if not isinstance(messages, list):
            return JSONResponse(
                status_code=config.PROXY_HTTP_400,
                content={
                    config.PROXY_RESP_ERROR_KEY: {
                        config.PROXY_RESP_DETAIL_KEY: config.PROXY_MALFORMED_REQUEST_MESSAGE
                    }
                },
            )

        # 1. Infer provenance context from flat messages
        ctx = infer_context(messages)

        # 2. Inspect request through firewall
        verdict_in = effective_firewall.inspect(ctx)
        if verdict_in.decision == Decision.BLOCK:
            findings_dump = [f.model_dump() for f in verdict_in.findings]
            return JSONResponse(
                status_code=config.PROXY_HTTP_400,
                content={
                    config.PROXY_RESP_ERROR_KEY: {
                        config.PROXY_RESP_MESSAGE_KEY: config.PROXY_BLOCK_REQUEST_MESSAGE,
                        config.PROXY_RESP_DECISION_KEY: verdict_in.decision.value,
                        config.PROXY_RESP_FINDINGS_KEY: findings_dump,
                    },
                    config.PROXY_RESP_DECISION_KEY: verdict_in.decision.value,
                    config.PROXY_RESP_FINDINGS_KEY: findings_dump,
                },
            )

        # 3. Render prompt with cryptographic nonce fences
        rendered = effective_firewall.render(ctx)

        # 4. Call Agent backend
        reply = effective_agent.respond(rendered)

        # 5. Inspect response through egress firewall
        egress_findings = effective_egress.inspect_reply(reply, effective_policy)
        verdict_out = decide(egress_findings, effective_policy)
        if verdict_out == Decision.BLOCK:
            findings_dump = [f.model_dump() for f in egress_findings]
            return JSONResponse(
                status_code=config.PROXY_HTTP_400,
                content={
                    config.PROXY_RESP_ERROR_KEY: {
                        config.PROXY_RESP_MESSAGE_KEY: config.PROXY_BLOCK_EGRESS_MESSAGE,
                        config.PROXY_RESP_DECISION_KEY: verdict_out.value,
                        config.PROXY_RESP_FINDINGS_KEY: findings_dump,
                    },
                    config.PROXY_RESP_DECISION_KEY: verdict_out.value,
                    config.PROXY_RESP_FINDINGS_KEY: findings_dump,
                },
            )

        # 6. Assemble OpenAI-compatible chat completion payload
        message_obj: dict[str, Any] = {
            config.PROXY_MSG_ROLE_KEY: config.PROXY_ROLE_ASSISTANT,
            config.PROXY_MSG_CONTENT_KEY: reply.text,
        }
        if reply.tool_calls:
            tool_calls_list: list[dict[str, Any]] = []
            for tc in reply.tool_calls:
                call_id = (
                    f"{config.PROXY_TOOL_CALL_ID_PREFIX}"
                    f"{secrets.token_hex(config.NONCE_BYTE_LENGTH)}"
                )
                tool_calls_list.append(
                    {
                        config.PROXY_RESP_ID_KEY: call_id,
                        config.PROXY_RESP_TYPE_KEY: config.PROXY_RESP_TYPE_FUNCTION,
                        config.PROXY_RESP_FUNCTION_KEY: {
                            config.PROXY_ORIGIN_REF_FIELD: tc.tool_name,
                            config.PROXY_RESP_ARGUMENTS_KEY: json.dumps(tc.args),
                        },
                    }
                )
            message_obj[config.PROXY_RESP_TOOL_CALLS_KEY] = tool_calls_list

        response_payload: dict[str, Any] = {
            config.PROXY_RESP_ID_KEY: f"{config.PROXY_ID_PREFIX}{secrets.token_hex(config.NONCE_BYTE_LENGTH)}",
            config.PROXY_RESP_OBJECT_KEY: config.PROXY_OBJECT_CHAT_COMPLETION,
            config.PROXY_RESP_CREATED_KEY: int(time.time()),
            config.PROXY_RESP_MODEL_KEY: config.PROXY_RESPONSE_MODEL,
            config.PROXY_RESP_CHOICES_KEY: [
                {
                    config.PROXY_RESP_INDEX_KEY: config.PROXY_CHOICE_DEFAULT_INDEX,
                    config.PROXY_RESP_MESSAGE_KEY: message_obj,
                    config.PROXY_RESP_FINISH_REASON_KEY: config.PROXY_DEFAULT_FINISH_REASON,
                }
            ],
        }
        return JSONResponse(
            status_code=config.PROXY_HTTP_200,
            content=response_payload,
        )

    return fastapi_app


app = create_app()
