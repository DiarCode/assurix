"""Engine dispatch integration test for the unified planner.

There is one planner in Assurix: ``EGATSPlanner``, registered under the
canonical name ``"planner"``. This test locks in that registry
contract at the engine level. Behavioural checks for the planner
itself live in ``tests/unit/test_planner_egats.py``.
"""
from __future__ import annotations

import pytest

from src.agents.planner_egats import EGATSPlanner
from src.orchestrator.engine import WorkflowEngine


class TestPlannerDispatch:
    """Lock the planner registry contract on the engine."""

    def test_engine_registry_contains_planner(self) -> None:
        """WorkflowEngine must register the single ``planner`` key on init."""
        engine = WorkflowEngine()
        assert "planner" in engine.agents, "planner missing from engine.agents"
        assert engine.agents["planner"] is EGATSPlanner

    def test_no_legacy_planner_aliases(self) -> None:
        """Legacy planner names must NOT be in the registry."""
        engine = WorkflowEngine()
        for legacy in ("planner_egats", "planner_linear"):
            assert legacy not in engine.agents, (
                f"Legacy name {legacy!r} must not be registered"
            )

    def test_unknown_planner_raises_on_execute(self) -> None:
        """Unknown agent names must NOT silently fall back at execute time."""
        engine = WorkflowEngine()
        assert "planner_does_not_exist" not in engine.agents
