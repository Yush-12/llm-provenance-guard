"""
proxy.infer — Context inference from OpenAI-style flat message histories.

DOCUMENTED WEAKNESS OF PROXY MODE:
----------------------------------
Real client libraries send a flat list of {role, content} messages —
there is no slot in that protocol for "this message is untrusted
retrieved content."

`infer_context(messages) -> Context` does the best it reasonably can:
  - "system" role maps to Trust.SYSTEM
  - "user" role maps to Trust.USER
  - tool/function roles map to Trust.DATA with an Origin inferred from the
    identifying name field
  - unrecognized roles default safely to Trust.DATA with unknown Origin

BE EXPLICIT: Content PASTED into a plain "user" message (which is exactly what
most naive RAG integrations do — dump retrieved documents into the user turn)
will be inferred as Trust.USER, NOT Trust.DATA. This means request-side
DATA-scoped ingress heuristics will NOT inspect it.

This is a real, documented weakness of proxy mode specifically, not a bug —
the invariant layers (toolauth and egress canary matching on the RESPONSE side)
still function correctly even when the inference is wrong; only the request-side
DATA-scoped detection is what is weakened.
"""

from __future__ import annotations

from spanguard import config
from spanguard.context import Context, Origin, Span, Trust


def infer_context(messages: object) -> Context:
    """Infer a Spanguard Context from an OpenAI chat completion messages array.

    Maps:
      - 'system' -> Trust.SYSTEM
      - 'user' -> Trust.USER
      - 'tool' / 'function' -> Trust.DATA with Origin(channel, ref)
      - Unrecognized role -> Safe default (Trust.DATA with unknown Origin)
    """
    if not isinstance(messages, list | tuple):
        return Context()

    spans: list[Span] = []

    for msg in messages:
        if isinstance(msg, dict):
            role_val = msg.get(config.PROXY_MSG_ROLE_KEY)
            role = str(role_val) if role_val is not None else ""
            content_val = msg.get(config.PROXY_MSG_CONTENT_KEY)
            content = "" if content_val is None else str(content_val)

            if role == config.PROXY_ROLE_SYSTEM:
                spans.append(Span(trust=Trust.SYSTEM, text=content))
            elif role == config.PROXY_ROLE_USER:
                spans.append(Span(trust=Trust.USER, text=content))
            elif role in config.PROXY_DATA_ROLES:
                channel = (
                    config.PROXY_ORIGIN_CHANNEL_TOOL
                    if role == config.PROXY_ROLE_TOOL
                    else config.PROXY_ORIGIN_CHANNEL_FUNCTION
                )
                ref_val = msg.get(config.PROXY_ORIGIN_REF_FIELD)
                ref = str(ref_val) if ref_val else config.PROXY_ORIGIN_REF_FALLBACK
                spans.append(
                    Span(
                        trust=Trust.DATA,
                        text=content,
                        origin=Origin(channel=channel, ref=ref),
                    )
                )
            else:
                # Unrecognized role defaults safely to Trust.DATA
                if Trust.DATA.value == config.PROXY_UNRECOGNIZED_ROLE_DEFAULT_TRUST:
                    spans.append(
                        Span(
                            trust=Trust.DATA,
                            text=content,
                            origin=Origin(
                                channel=config.PROXY_ORIGIN_CHANNEL_UNKNOWN,
                                ref=config.PROXY_ORIGIN_REF_UNKNOWN,
                            ),
                        )
                    )
                else:
                    spans.append(Span(trust=Trust.USER, text=content))
        else:
            # Unrecognized element shape defaults safely to Trust.DATA
            if Trust.DATA.value == config.PROXY_UNRECOGNIZED_ROLE_DEFAULT_TRUST:
                spans.append(
                    Span(
                        trust=Trust.DATA,
                        text=str(msg),
                        origin=Origin(
                            channel=config.PROXY_ORIGIN_CHANNEL_UNKNOWN,
                            ref=config.PROXY_ORIGIN_REF_UNKNOWN,
                        ),
                    )
                )
            else:
                spans.append(Span(trust=Trust.USER, text=str(msg)))

    return Context(spans=tuple(spans))
