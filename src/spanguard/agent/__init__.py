"""
agent — mock LLM agent for deterministic testing.

Sub-modules
-----------
mock    A deliberately gullible, deterministic fake LLM that always follows
        the last instruction it sees.  Used in integration tests to verify
        that the firewall blocks attacks that a real model would obey.
        Marked with ruff S-suppression because its insecure behaviour is
        intentional — that is the point.
"""
