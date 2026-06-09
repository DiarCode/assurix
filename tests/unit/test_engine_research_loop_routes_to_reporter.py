"""Regression: research_loop result must be routed into the reporter.

Prior to the v2 fix, the engine flipped the engagement to COMPLETED directly
after research_loop ran, never enqueuing the reporter. As a result no
`data/reports/<ts>_<target>_<eng8>.md` file was ever written.

Fix B routes the research_loop's `findings` → `validated_findings` into a
`reporter` enqueue. The same routing is applied to `hypothesis_orchestrator`
since it has the same terminal-returns-no-report contract.

This test locks the engine source so any regression that drops the routing
fails CI.
"""

from __future__ import annotations

import inspect


class TestResearchLoopRoutesToReporter:
    def test_research_loop_branch_enqueues_reporter(self) -> None:
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        # Find the research_loop branch
        assert 'agent_name == "research_loop"' in src, (
            "engine._run_loop must have a research_loop branch"
        )
        # That branch must enqueue the reporter
        rl_idx = src.find('agent_name == "research_loop"')
        # Look at the next ~2000 chars — the branch body
        branch = src[rl_idx: rl_idx + 2000]
        assert 'agent_name="reporter"' in branch, (
            "research_loop branch must enqueue the reporter agent"
        )
        assert "routed_to_reporter" in branch, (
            "research_loop branch must emit routed_to_reporter audit log"
        )

    def test_research_loop_maps_findings_to_validated_findings(self) -> None:
        """The reporter's payload must carry the research_loop's findings
        under the `validated_findings` key, not the raw `findings` key —
        that's the contract the reporter consumes."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        rl_idx = src.find('agent_name == "research_loop"')
        branch = src[rl_idx: rl_idx + 2000]
        assert '"validated_findings"' in branch, (
            "research_loop branch must rename `findings` → `validated_findings` "
            "for the reporter."
        )
        assert 'result.get("findings"' in branch

    def test_research_loop_branch_uses_previous_result_wrapper(self) -> None:
        """The reporter's payload contract is `previous_result.*`."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        rl_idx = src.find('agent_name == "research_loop"')
        branch = src[rl_idx: rl_idx + 2000]
        assert '"previous_result"' in branch, (
            "research_loop branch must wrap result in `previous_result` key "
            "to match the reporter's payload contract."
        )


class TestHypothesisOrchestratorRoutesToReporter:
    def test_hypothesis_orchestrator_branch_enqueues_reporter(self) -> None:
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        assert 'agent_name == "hypothesis_orchestrator"' in src
        ho_idx = src.find('agent_name == "hypothesis_orchestrator"')
        branch = src[ho_idx: ho_idx + 2000]
        assert 'agent_name="reporter"' in branch
        assert "routed_to_reporter" in branch
        assert '"validated_findings"' in branch


class TestRoutingLogIncludesFromAgent:
    def test_research_loop_log_distinguishes_from_hypothesis_orchestrator(self) -> None:
        """The routed_to_reporter audit log must record which agent triggered it."""
        from src.orchestrator.engine import WorkflowEngine

        src = inspect.getsource(WorkflowEngine._run_loop)
        assert '"from_agent": "research_loop"' in src
        assert '"from_agent": "hypothesis_orchestrator"' in src
