"""Regression: agent exceptions must flip the engagement to FAILED.

Prior to the v2 fix, the engine's per-iteration `except Exception` block
only marked the JOB failed; the engagement row stayed `RUNNING` forever.
The CLI's polling loop watches the engagement status, so `assurix scan`
hung until Ctrl+C.

Fix C also flips the engagement to FAILED (when the state machine permits)
and emits an `engagement_failed` event so downstream consumers (the CLI
poll, dashboards) can react.

This test pins the source so any regression that drops the engagement
flip fails CI.
"""

from __future__ import annotations

import inspect


class TestAgentFailureFlipsEngagement:
    def test_exception_handler_marks_job_failed(self) -> None:
        """The per-iteration except block must call mark_failed on the job."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        # Find the iteration-level except block
        assert "mark_failed" in src
        assert 'action="agent_failed"' in src or "agent_failed" in src

    def test_exception_handler_flips_engagement_to_failed(self) -> None:
        """The handler must also set eng.status = FAILED so the CLI poll exits."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        # The handler must transition engagement.status to FAILED
        assert "EngagementStatus.FAILED" in src, (
            "engine._run_loop must reference EngagementStatus.FAILED when "
            "an agent raises."
        )
        assert "eng.status = EngagementStatus.FAILED" in src
        # And must use the state-machine guard so we don't violate transitions
        assert "EngagementStateMachine.can_transition" in src
        # And must set completed_at
        assert "completed_at = datetime.now(UTC)" in src or "completed_at=datetime.now" in src

    def test_exception_handler_emits_engagement_failed_event(self) -> None:
        """The handler must emit an event so dashboards can react."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        assert "engagement_failed" in src, (
            "engine._run_loop must emit an `engagement_failed` event when "
            "an agent raises."
        )
        assert "self.events.emit" in src

    def test_handler_logs_at_warning_level(self) -> None:
        """We log agent failures at WARNING so the operator sees them."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        # Find the per-iteration except
        assert "agent %s failed" in src
        assert "logger.warning" in src

    def test_continue_after_failure(self) -> None:
        """The loop must `continue` after a single failure so the engine
        survives transient errors and doesn't kill the whole task."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        # The `except Exception` block ends with `continue` to the next iter
        # rather than `raise`, so a single bad job doesn't kill the engine.
        # We assert by finding the marker pattern: the failure block ends
        # with `continue` before Phase 3.
        assert "                continue" in src
