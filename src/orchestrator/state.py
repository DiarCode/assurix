"""State machine and workflow routing logic."""

from src.db.models import EngagementStatus


class WorkflowRouter:
    """Determines the next agent in the cyclic workflow.

    Phase 2+ flow: planner -> recon -> webapp -> reasoner -> validation -> (reporter or planner)
    With MCTS: planner_mcts -> recon -> webapp -> reasoner -> (reporter or planner_mcts)
    The webapp agent internally runs parallel AI investigators.
    """

    _flow: dict[str, str | None] = {
        "planner": "recon",
        "validation": "reporter",
        "planner_mcts": "recon",
        "recon": "pentester",
        "pentester": "reasoner",
        "webapp": "reasoner",
        "reasoner": "validation",
        
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
            # LATS backtracking: if validation invalidates findings, re-queue planner
            return "planner_mcts" if iteration_count > 0 else "planner"
        return cls._flow.get(current_agent)

    @classmethod
    def is_terminal(cls, agent_name: str) -> bool:
        return agent_name == "reporter"


class EngagementStateMachine:
    """Manage engagement lifecycle transitions."""

    _transitions: dict[EngagementStatus, set[EngagementStatus]] = {
        EngagementStatus.PENDING: {EngagementStatus.RUNNING, EngagementStatus.CANCELLED},
        EngagementStatus.RUNNING: {
            EngagementStatus.PAUSED,
            EngagementStatus.COMPLETED,
            EngagementStatus.FAILED,
            EngagementStatus.CANCELLED,
        },
        EngagementStatus.PAUSED: {EngagementStatus.RUNNING, EngagementStatus.CANCELLED},
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
