"""Regression: ResearchLoop must respect a cumulative wall-clock budget.

The browser agent has a per-call `asyncio.wait_for` ceiling (see Fix A),
but a series of investigations can still exhaust the engagement's total
research time. Fix G adds:

1. A cumulative budget `total_budget_seconds` initialized at the top of
   `execute()`, sourced from `settings.research_loop_max_total_seconds`
   (default 1800s = 30 min) and overridable via the payload key
   `research_loop_max_total_seconds`.
2. A budget guard at the top of the outer iteration `while` loop.
3. A budget guard at the top of the inner hypothesis-investigation
   `for` loop, so long batches don't run to completion after the budget
   is already blown.

This test pins the source so a regression that drops the budget guard
fails CI.
"""

from __future__ import annotations

import inspect


class TestBudgetInit:
    def test_execute_initializes_budget(self) -> None:
        """execute() must derive a budget from settings + payload override."""
        from src.agents.research_loop import ResearchLoopAgent

        src = inspect.getsource(ResearchLoopAgent.execute)
        assert "research_loop_max_total_seconds" in src, (
            "ResearchLoop.execute() must initialize a "
            "`research_loop_max_total_seconds` budget."
        )
        assert "started_at" in src
        assert "time.monotonic" in src
        # Must read from settings for the default
        assert "settings.research_loop_max_total_seconds" in src

    def test_execute_uses_payload_override(self) -> None:
        """The payload may override the default via the same key."""
        from src.agents.research_loop import ResearchLoopAgent

        src = inspect.getsource(ResearchLoopAgent.execute)
        # The budget must be payload.get(key, settings.value)
        assert 'payload.get(\n                "research_loop_max_total_seconds"' in src or \
            'payload.get("research_loop_max_total_seconds"' in src


class TestOuterLoopGuard:
    def test_outer_loop_has_budget_break(self) -> None:
        """The outer `while iteration < self._max_research_iterations:` must
        break early when the budget is exceeded."""
        from src.agents.research_loop import ResearchLoopAgent

        src = inspect.getsource(ResearchLoopAgent.execute)
        # Find the outer while loop
        outer_idx = src.find("while iteration < self._max_research_iterations")
        # Look at the first 800 chars of the body
        body = src[outer_idx: outer_idx + 800]
        assert "started_at" in body
        assert "total_budget_seconds" in body
        assert "terminating" in body or "skipping" in body


class TestInnerLoopGuard:
    def test_inner_loop_has_budget_break(self) -> None:
        """The inner hypothesis-investigation `for` must break early on
        budget exhaustion so we don't run all N hypotheses to completion."""
        from src.agents.research_loop import ResearchLoopAgent

        src = inspect.getsource(ResearchLoopAgent.execute)
        # The inner loop iterates over viable_hypotheses
        inner_idx = src.find("for hypothesis_index, hypothesis_data in enumerate(viable_hypotheses):")
        # Or a pre-fix variant using `for hypothesis_data in viable_hypotheses:`
        if inner_idx == -1:
            inner_idx = src.find("for hypothesis_data in viable_hypotheses:")
        body = src[inner_idx: inner_idx + 800]
        assert "started_at" in body
        assert "total_budget_seconds" in body
        assert "skipping remaining" in body or "terminating" in body


class TestConfigWiring:
    def test_setting_is_registered(self) -> None:
        """The default 1800s setting must be wired into Settings."""
        from src.core.config import Settings

        assert hasattr(Settings(), "research_loop_max_total_seconds")
        # Default is 1800 (= 30 min)
        assert Settings().research_loop_max_total_seconds == 1800
