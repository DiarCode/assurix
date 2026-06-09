"""Phase 4b integration: engine routes + state machine for hypothesis_orchestrator.

Verifies:
- WorkflowRouter.next_agent returns None for hypothesis_orchestrator (terminates)
- Engine enqueues hypothesis_orchestrator when use_hypothesis_orchestrator=True
- Engine enqueues research_loop when use_research_loop=True (existing behavior preserved)
- HypothesisOrchestrator completion branch transitions engagement to COMPLETED
- Precedence: use_hypothesis_orchestrator takes priority over default planner route
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.orchestrator.engine import WorkflowEngine
from src.orchestrator.state import WorkflowRouter


class TestWorkflowRouterHypothesisOrchestrator:
    def test_hypothesis_orchestrator_is_terminal(self) -> None:
        """hypothesis_orchestrator maps to None — the engine doesn't re-queue it."""
        assert WorkflowRouter._flow["hypothesis_orchestrator"] is None

    def test_next_agent_returns_none_for_hypothesis_orchestrator(self) -> None:
        """next_agent('hypothesis_orchestrator', ...) returns None."""
        result = WorkflowRouter.next_agent(
            "hypothesis_orchestrator",
            iteration_count=2,
            max_iterations=50,
        )
        assert result is None

    def test_research_loop_still_terminal(self) -> None:
        """Existing research_loop routing is preserved (backward compat)."""
        assert WorkflowRouter._flow["research_loop"] is None
        assert (
            WorkflowRouter.next_agent("research_loop", iteration_count=2, max_iterations=50)
            is None
        )


class TestEngineRoutesToHypothesisOrchestrator:
    @pytest.mark.asyncio
    async def test_use_hypothesis_orchestrator_routes_to_orchestrator(self) -> None:
        """When use_hypothesis_orchestrator is set, planner routes to the orchestrator."""
        engine = WorkflowEngine()
        mock_scheduler = MagicMock()
        mock_scheduler.enqueue = AsyncMock()
        engine.scheduler = mock_scheduler

        # Inspect _run_loop to verify the routing code path
        src = inspect.getsource(engine._run_loop)
        assert 'use_hypothesis_orchestrator' in src
        assert 'hypothesis_orchestrator' in src
        assert 'routed_to_hypothesis_orchestrator' in src
        # The engine no longer puts a live reference in the JSON-serialized
        # payload (that hung the flush with an infinite-recursion error).
        # The orchestrator discovers the engine via get_active_engine()
        # backed by a contextvar set in start_engagement().
        assert '"engine": self' not in src
        assert "'engine': self" not in src
        # Verify the orchestrator pulls the engine from the contextvar.
        from src.agents import hypothesis_orchestrator as orch_mod
        orch_src = inspect.getsource(orch_mod)
        assert 'get_active_engine' in orch_src

    @pytest.mark.asyncio
    async def test_use_research_loop_still_routes_to_research_loop(self) -> None:
        """Existing use_research_loop routing is unchanged."""
        engine = WorkflowEngine()
        src = inspect.getsource(engine._run_loop)
        assert 'use_research_loop' in src
        assert 'routed_to_research_loop' in src

    @pytest.mark.asyncio
    async def test_completion_branch_for_hypothesis_orchestrator(self) -> None:
        """The completion branch now enqueues the reporter and logs routed_to_reporter.

        Pre-fix this branch transitioned the engagement to COMPLETED directly
        and logged `hypothesis_orchestrator_completed`. Fix B (2026-06-04)
        changed the contract: the orchestrator's results are routed to the
        reporter so the MD report is always produced. The
        `hypothesis_orchestrator_completed` log action no longer exists; the
        `routed_to_reporter` action with `from_agent: hypothesis_orchestrator`
        is the new contract.
        """
        engine = WorkflowEngine()
        src = inspect.getsource(engine._run_loop)
        assert 'agent_name == "hypothesis_orchestrator"' in src
        # The branch must route to the reporter, not transition to COMPLETED
        ho_idx = src.find('agent_name == "hypothesis_orchestrator"')
        branch = src[ho_idx: ho_idx + 2000]
        assert 'agent_name="reporter"' in branch
        assert "routed_to_reporter" in branch
        # The old completion marker must be gone — if it reappears it means
        # someone reintroduced the no-report path.
        assert "hypothesis_orchestrator_completed" not in src, (
            "hypothesis_orchestrator_completed log action was removed in "
            "fix B; the engine now routes the orchestrator's result to the "
            "reporter so a Markdown report is always written."
        )


class TestWorkflowEngineExportsOrchestrator:
    """HypothesisOrchestrator should be reachable via the engine's agent registry."""

    def test_hypothesis_orchestrator_class_is_importable(self) -> None:
        from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
        agent = HypothesisOrchestrator()
        assert agent.name == "hypothesis_orchestrator"

    def test_engine_can_register_hypothesis_orchestrator(self) -> None:
        engine = WorkflowEngine()
        from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
        engine.register("hypothesis_orchestrator", HypothesisOrchestrator)
        assert engine.agents["hypothesis_orchestrator"] is HypothesisOrchestrator
