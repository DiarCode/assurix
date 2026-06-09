"""State machine and workflow routing logic."""

from src.db.models import EngagementStatus


class WorkflowRouter:
    """Determines the next agent in the cyclic workflow.

    Flow: planner -> recon -> pentester -> reasoner -> validation -> (reporter or planner).
    LATS backtracking: validation may re-queue the planner until max_iterations is reached.
    ResearchLoop and HypothesisOrchestrator run at the engagement level and
    dispatch sub-investigations via engine.submit_and_await(); they route
    to themselves so the engine doesn't re-queue them mid-execution.
    """

    _flow: dict[str, str | None] = {
        "planner": "recon",
        "validation": "reporter",
        "planner_mcts": "recon",
        "recon": "pentester",
        "pentester": "reasoner",
        "webapp": "reasoner",
        "reasoner": "validation",
        # HypothesisOrchestrator dispatches sub-investigations and terminates
        # by transitioning the engagement to COMPLETED. Routing it to itself
        # prevents the engine from re-queuing it mid-execution.
        "hypothesis_orchestrator": None,
        # ResearchLoop terminates via the RESEARCHING engagement state.
        "research_loop": None,
    }

    @classmethod
    def next_agent(
        cls, current_agent: str, iteration_count: int, max_iterations: int
    ) -> str | None:
        """Return the next agent name, or None to stop."""
        if current_agent == "reasoner":
            # Route through validation before reporter (Mythos enhancement)
            return "validation"
        if current_agent == "validation":
            if iteration_count >= max_iterations:
                return "reporter"
            # LATS backtracking: re-queue the planner for another cycle.
            return "planner"
        return cls._flow.get(current_agent)

    @classmethod
    def is_terminal(cls, agent_name: str) -> bool:
        return agent_name == "reporter"


class EngagementStateMachine:
    """Manage engagement lifecycle transitions.

    Mythos addition: RESEARCHING state between RUNNING and COMPLETED.
    When the ResearchLoop's reflection phase produces no new hypotheses,
    the engagement transitions to RESEARCHING, awaiting human sign-off
    before moving to COMPLETED.
    """

    _transitions: dict[EngagementStatus, set[EngagementStatus]] = {
        EngagementStatus.PENDING: {EngagementStatus.RUNNING, EngagementStatus.CANCELLED},
        EngagementStatus.RUNNING: {
            EngagementStatus.RESEARCHING,
            EngagementStatus.PAUSED,
            EngagementStatus.COMPLETED,
            EngagementStatus.FAILED,
            EngagementStatus.CANCELLED,
        },
        EngagementStatus.RESEARCHING: {
            EngagementStatus.COMPLETED,
            EngagementStatus.PAUSED,
            EngagementStatus.FAILED,
            EngagementStatus.CANCELLED,
        },
        EngagementStatus.PAUSED: {EngagementStatus.RUNNING, EngagementStatus.RESEARCHING, EngagementStatus.CANCELLED},
        EngagementStatus.COMPLETED: set(),
        EngagementStatus.FAILED: set(),
        EngagementStatus.CANCELLED: set(),
    }

    @classmethod
    def can_transition(cls, current: EngagementStatus, target: EngagementStatus) -> bool:
        return target in cls._transitions.get(current, set())

    @classmethod
    def transition(cls, current: EngagementStatus, target: EngagementStatus) -> EngagementStatus:
        if not cls.can_transition(current, target):
            raise ValueError(f"Invalid transition from {current} to {target}")
        return target
