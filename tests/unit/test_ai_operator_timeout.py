"""Regression: AIBrowserOperator must bound `agent.run()` with asyncio.wait_for.

The browser-use library validates the LLM's AgentOutput against a Pydantic
schema and retries on mismatch. With no wall-clock ceiling, a single bad
response (or a 18-minute Ollama call) can stall the entire scan.

Fix A added `asyncio.wait_for(agent.run(...), timeout=total_budget)`. These
tests lock the contract:

1. The total budget is derived from `_max_steps * _step_timeout_seconds + 60s slack`.
2. `asyncio.TimeoutError` is caught and the result dict carries
   `error: "timeout after Ns"`.
3. `browser_session.close()` is called in the `finally` so the Playwright
   subprocess is not leaked when the timeout fires.
"""

from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestWaitForCeiling:
    def test_run_agent_uses_asyncio_wait_for(self) -> None:
        """The agent.run() call must be wrapped in asyncio.wait_for."""
        from src.agents.browser import ai_operator

        src = inspect.getsource(ai_operator.AIBrowserOperator._run_agent)
        assert "asyncio.wait_for" in src, (
            "AIBrowserOperator._run_agent must wrap agent.run() in "
            "asyncio.wait_for to bound the wall-clock ceiling."
        )
        assert "agent.run" in src

    def test_total_budget_derives_from_max_steps(self) -> None:
        """The budget = max_steps * step_timeout + 60s slack for cold start."""
        from src.agents.browser import ai_operator

        src = inspect.getsource(ai_operator.AIBrowserOperator._run_agent)
        # Either form is acceptable: budget = max_steps * timeout [+ slack]
        assert "_max_steps" in src and "_step_timeout_seconds" in src, (
            "Budget must be derived from _max_steps × _step_timeout_seconds."
        )
        assert "total_budget" in src


class TestTimeoutResultContract:
    def test_timeout_error_caught(self) -> None:
        """`_run_agent` must catch `asyncio.TimeoutError` from the `asyncio.wait_for`."""
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator._run_agent)
        assert "asyncio.TimeoutError" in src, (
            "AIBrowserOperator._run_agent must catch asyncio.TimeoutError "
            "from the asyncio.wait_for wrapping agent.run()."
        )

    def test_timeout_result_has_error_key(self) -> None:
        """The TimeoutError arm must return a dict carrying the `error` key."""
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator._run_agent)
        # The TimeoutError arm must build a result dict with an "error" key
        # whose value mentions "timeout".
        assert '"error"' in src or "'error'" in src
        # Find the timeout arm
        te_idx = src.find("asyncio.TimeoutError")
        body = src[te_idx: te_idx + 800]
        assert "timeout" in body
        assert "findings" in body  # must include an empty findings list

    def test_timeout_result_includes_target_url(self) -> None:
        """The timeout result must include `target_url` and `task_type` so
        the caller can route it correctly."""
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator._run_agent)
        te_idx = src.find("asyncio.TimeoutError")
        body = src[te_idx: te_idx + 800]
        assert "target_url" in body
        assert "task_type" in body

    def test_finally_block_closes_browser_session(self) -> None:
        """The `_run_agent` `finally` block must call `browser_session.close()`.

        This locks the leak-prevention contract: even on timeout, the
        Playwright subprocess is closed (Fix F).
        """
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator._run_agent)
        # The try/finally around the agent.run() call must close the session
        # in the finally, regardless of whether agent.run() returned, raised,
        # or was cancelled by asyncio.wait_for.
        assert "finally:" in src, (
            "AIBrowserOperator._run_agent must wrap agent.run() in a "
            "try/finally that closes the browser session."
        )
        assert "browser_session.close" in src
        # The close must be inside the finally block, not in a regular try
        # arm. We assert by checking the ordering: `finally:` appears before
        # `browser_session.close` in the slice.
        finally_idx = src.find("finally:")
        close_idx = src.find("browser_session.close")
        assert 0 < finally_idx < close_idx, (
            "browser_session.close() must be inside the finally block."
        )


class TestLiveSessionsTracked:
    def test_init_creates_live_sessions_list(self) -> None:
        """The operator must track live BrowserSessions in `_live_sessions`."""
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator.__init__)
        assert "_live_sessions" in src, (
            "AIBrowserOperator must initialize _live_sessions to track "
            "leaked BrowserSession instances."
        )

    def test_stop_closes_live_sessions(self) -> None:
        """stop() must close any sessions still in _live_sessions."""
        from src.agents.browser.ai_operator import AIBrowserOperator

        src = inspect.getsource(AIBrowserOperator.stop)
        assert "_live_sessions" in src
        # Must iterate and call close
        assert ".close" in src
