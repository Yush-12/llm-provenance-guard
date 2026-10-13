"""
layers -- detection layers that run inside the Firewall pipeline.

All inspection layers implement the Layer protocol:
    inspect(self, ctx: Context, policy: Policy) -> list[Finding]
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from spanguard.context import Context
from spanguard.policy import Policy
from spanguard.verdict import Finding


@runtime_checkable
class Layer(Protocol):
    """Uniform protocol implemented by all firewall inspection layers.

    Uniformity ensures the orchestration pipeline can execute all layers
    without layer-specific branching.
    """

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        """Inspect the prompt Context and return a list of findings."""
        ...


__all__ = ["Layer"]
