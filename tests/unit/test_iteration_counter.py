"""Iteration counter: the LATS backtracking loop must terminate at
``max_iterations``.

Before the v1/v2 cleanup, ``engine.py`` only incremented
``engagement.iteration_count`` when ``next_agent == "planner"``. After
the cleanup the only planner name is ``"planner"``, so every
re-enqueue of the planner ticks the counter, and the
``validation -> reporter`` branch fires when ``iteration_count >=
max_iterations``.
"""

from __future__ import annotations

from src.orchestrator.state import WorkflowRouter


def test_next_agent_routes_to_planner_for_backtracking() -> None:
    """Under the cap, validation must route back to the planner."""
    assert (
        WorkflowRouter.next_agent("validation", iteration_count=2, max_iterations=10)
        == "planner"
    )


def test_next_agent_routes_to_reporter_at_cap() -> None:
    """At or above max_iterations, validation must route to reporter."""
    assert (
        WorkflowRouter.next_agent("validation", iteration_count=10, max_iterations=10)
        == "reporter"
    )
    assert (
        WorkflowRouter.next_agent("validation", iteration_count=11, max_iterations=10)
        == "reporter"
    )


def test_planner_name_in_flow() -> None:
    """The flow table must have a 'planner' key routing to recon."""
    from src.orchestrator.state import WorkflowRouter

    assert WorkflowRouter._flow.get("planner") == "recon"


def test_no_planner_egats_in_flow() -> None:
    """Legacy 'planner_egats' must NOT be in the flow table."""
    from src.orchestrator.state import WorkflowRouter

    assert "planner_egats" not in WorkflowRouter._flow
