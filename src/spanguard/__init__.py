"""
spanguard — structural provenance firewall against LLM prompt injection.

Sub-packages
------------
context    Trust levels, Origin, Span, and Context objects.
verdict    Severity, Decision, Finding, Verdict (output of each layer).
policy     Policy dataclass, escalate() and decide() logic.
firewall   Top-level orchestration: fencing, taint propagation, fail-closed.
tools      Effect, Guard, Tool, ToolCallRequest, AgentReply.
audit      JSONL audit records (opt-in I/O).
config     Every constant, threshold, and regex fragment — nowhere else.
normalize  Unicode normalisation, transport-decode unwrapping, bounded views.
layers     Detection layers (ingress, provenance, toolauth, egress, …).
agent      Deterministic mock LLM agent for testing.
"""
