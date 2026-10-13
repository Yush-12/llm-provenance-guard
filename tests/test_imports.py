"""
tests.test_imports — package and module smoke tests.

These tests verify that the package and all its sub-modules can be
imported without error, with all public symbols present.
"""

import importlib

import pytest

# Every core module that must be importable.
_MODULES = [
    "spanguard",
    "spanguard.config",
    "spanguard.context",
    "spanguard.verdict",
    "spanguard.policy",
    "spanguard.firewall",
    "spanguard.tools",
    "spanguard.audit",
    "spanguard.normalize",
    "spanguard.normalize.unicode",
    "spanguard.normalize.unwrap",
    "spanguard.normalize.views",
    "spanguard.layers",
    "spanguard.layers.normalize",
    "spanguard.layers.ingress",
    "spanguard.layers.provenance",
    "spanguard.layers.toolauth",
    "spanguard.layers.egress",
    "spanguard.agent",
    "spanguard.agent.mock",
    "spanguard.proxy",
    "proxy",
    "proxy.infer",
    "proxy.app",
    "spanguard.arena",
    "arena",
    "arena.app",
    "arena.engine",
    "arena.containment",
    "arena.levels",
    "arena.session",
    "arena.harvest",
]


@pytest.mark.parametrize("module_name", _MODULES)
def test_module_importable(module_name: str) -> None:
    """Each spanguard module must import cleanly with no side-effects."""
    mod = importlib.import_module(module_name)
    assert mod is not None
