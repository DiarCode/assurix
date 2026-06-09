"""8-state hypothesis state machine (per plan §3.1.1).

This is the FSM that governs a hypothesis's lifecycle in the Mythos
ResearchLoop. The 4-state enum (PENDING/INVESTIGATING/CONFIRMED/FALSIFIED)
from the v1 implementation is replaced by an 8-state machine with explicit
gates between states. A fall-back to the 2-state pattern
(CANDIDATE -> VALIDATED in one step) is FORBIDDEN and is asserted-illegal
by the HypothesisStateMachine.transit() call.

States (8):
  UNKNOWN              - hypothesis class generated but not yet a candidate
  CANDIDATE            - active investigation candidate (formerly PENDING)
  NEEDS_CORROBORATION  - first evidence collected; needs second-source
  NEEDS_SAFE_VALIDATION- evidence strong but reproducer not yet safe
  VALIDATED            - corroborated + reproducer succeeded
  REJECTED             - falsified by evidence
  OUT_OF_SCOPE         - not applicable to the engagement
  SUPERSEDED           - replaced by a more specific hypothesis

Transitions (allowed):
  UNKNOWN             -> CANDIDATE
  UNKNOWN             -> OUT_OF_SCOPE
  CANDIDATE           -> NEEDS_CORROBORATION
  CANDIDATE           -> REJECTED
  CANDIDATE           -> OUT_OF_SCOPE
  CANDIDATE           -> SUPERSEDED
  NEEDS_CORROBORATION -> NEEDS_SAFE_VALIDATION
  NEEDS_CORROBORATION -> REJECTED
  NEEDS_CORROBORATION -> SUPERSEDED
  NEEDS_SAFE_VALIDATION -> VALIDATED
  NEEDS_SAFE_VALIDATION -> REJECTED
  NEEDS_SAFE_VALIDATION -> SUPERSEDED
  VALIDATED           -> SUPERSEDED   (new superseding evidence)
  REJECTED            -> SUPERSEDED   (new evidence invalidates the rejection)

FORBIDDEN shortcuts (these raise IllegalTransition):
  UNKNOWN             -> VALIDATED       (skip corroboration)
  CANDIDATE           -> VALIDATED       (skip the 2-step corroboration)
  CANDIDATE           -> NEEDS_SAFE_VALIDATION  (skip NEEDS_CORROBORATION)
  NEEDS_CORROBORATION -> VALIDATED       (skip NEEDS_SAFE_VALIDATION)

The machine is intentionally separate from the Hypothesis ORM model so
that (1) the in-process state can be tested without a database, and (2)
the column-type in the DB is decoupled from the Python class hierarchy.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

logger = logging.getLogger(__name__)


class HypothesisState(StrEnum):
    """8-state lifecycle for a hypothesis class."""

    UNKNOWN = "unknown"
    CANDIDATE = "candidate"
    NEEDS_CORROBORATION = "needs_corroboration"
    NEEDS_SAFE_VALIDATION = "needs_safe_validation"
    VALIDATED = "validated"
    REJECTED = "rejected"
    OUT_OF_SCOPE = "out_of_scope"
    SUPERSEDED = "superseded"


# Allowed transitions, expressed as a frozenset of (from, to) pairs.
ALLOWED_TRANSITIONS: frozenset[tuple[HypothesisState, HypothesisState]] = frozenset({
    (HypothesisState.UNKNOWN, HypothesisState.CANDIDATE),
    (HypothesisState.UNKNOWN, HypothesisState.OUT_OF_SCOPE),
    (HypothesisState.CANDIDATE, HypothesisState.NEEDS_CORROBORATION),
    (HypothesisState.CANDIDATE, HypothesisState.REJECTED),
    (HypothesisState.CANDIDATE, HypothesisState.OUT_OF_SCOPE),
    (HypothesisState.CANDIDATE, HypothesisState.SUPERSEDED),
    (HypothesisState.NEEDS_CORROBORATION, HypothesisState.NEEDS_SAFE_VALIDATION),
    (HypothesisState.NEEDS_CORROBORATION, HypothesisState.REJECTED),
    (HypothesisState.NEEDS_CORROBORATION, HypothesisState.SUPERSEDED),
    (HypothesisState.NEEDS_SAFE_VALIDATION, HypothesisState.VALIDATED),
    (HypothesisState.NEEDS_SAFE_VALIDATION, HypothesisState.REJECTED),
    (HypothesisState.NEEDS_SAFE_VALIDATION, HypothesisState.SUPERSEDED),
    (HypothesisState.VALIDATED, HypothesisState.SUPERSEDED),
    (HypothesisState.REJECTED, HypothesisState.SUPERSEDED),
})


class IllegalTransition(Exception):
    """Raised when a state transition is not in ALLOWED_TRANSITIONS.

    Per plan §3.1.1 (BL-5): the FSM is a gate, not a log. Shortcuts
    (CANDIDATE -> VALIDATED in one step) are FORBIDDEN and must raise
    rather than silently coerce.
    """


@dataclass
class StateTransition:
    """A single transition in the hypothesis lifecycle.

    Stored as a JSON array on the Hypothesis.state_transitions column.
    The sha256 of (from, to, evidence_hash, timestamp) is the immutable
    chain-of-custody record per plan §4.1.
    """

    from_state: HypothesisState
    to_state: HypothesisState
    evidence_hash: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    reason: str = ""


class HypothesisStateMachine:
    """The 8-state FSM with immutable evidence chain.

    Per plan §3.1.1: the FSM is a gate, not a log. Each transit() call
    appends to the transitions list and is asserted-illegal if not in
    ALLOWED_TRANSITIONS. The 2-state fall-back pattern (CANDIDATE ->
    VALIDATED in one step) is FORBIDDEN and raises IllegalTransition.
    """

    def __init__(self, initial: HypothesisState = HypothesisState.UNKNOWN) -> None:
        self._state: HypothesisState = initial
        self._transitions: list[StateTransition] = []
        self._confidence: float = 0.5
        self._last_transition_at: str | None = None

    @property
    def state(self) -> HypothesisState:
        return self._state

    @property
    def transitions(self) -> list[StateTransition]:
        return list(self._transitions)

    @property
    def confidence(self) -> float:
        """Confidence is decayed on each transition (plan §3.1.1)."""
        return self._confidence

    @property
    def last_transition_at(self) -> str | None:
        return self._last_transition_at

    def transit(self, target: HypothesisState, evidence_hash: str, reason: str = "") -> StateTransition:
        """Move from the current state to ``target``.

        Raises IllegalTransition if the transition is not allowed.
        Appends a StateTransition to the chain and decays confidence.
        """
        if (self._state, target) not in ALLOWED_TRANSITIONS:
            raise IllegalTransition(
                f"Cannot transition from {self._state.value} to {target.value}. "
                f"Allowed transitions are: "
                + ", ".join(f"{a.value}->{b.value}" for a, b in sorted(ALLOWED_TRANSITIONS, key=lambda x: (x[0].value, x[1].value)))
            )

        transition = StateTransition(
            from_state=self._state,
            to_state=target,
            evidence_hash=evidence_hash,
            reason=reason,
        )
        self._transitions.append(transition)
        self._state = target
        self._last_transition_at = transition.timestamp

        # Confidence decay: each transition applies a multiplicative decay
        # factor. Reaching VALIDATED requires surviving 4 decays (UNKNOWN,
        # CANDIDATE, NEEDS_CORROBORATION, NEEDS_SAFE_VALIDATION → VALIDATED
        # is the 4th). The decay reflects the principle that confidence
        # compounds through corroboration, not single-shot LLM outputs.
        decay_factor = {
            HypothesisState.UNKNOWN: 1.0,            # no decay at genesis
            HypothesisState.CANDIDATE: 0.95,
            HypothesisState.NEEDS_CORROBORATION: 0.92,
            HypothesisState.NEEDS_SAFE_VALIDATION: 0.90,
            HypothesisState.VALIDATED: 1.0,         # terminal: do not decay
            HypothesisState.REJECTED: 1.0,
            HypothesisState.OUT_OF_SCOPE: 1.0,
            HypothesisState.SUPERSEDED: 1.0,
        }.get(target, 0.95)
        self._confidence *= decay_factor

        logger.debug(
            "FSM transition %s -> %s (evidence=%s, reason=%s, conf=%.3f)",
            transition.from_state.value,
            transition.to_state.value,
            evidence_hash[:12],
            reason[:60],
            self._confidence,
        )
        return transition

    def can_transit(self, target: HypothesisState) -> bool:
        """Test whether the target is reachable from the current state."""
        return (self._state, target) in ALLOWED_TRANSITIONS


__all__ = [
    "HypothesisState",
    "ALLOWED_TRANSITIONS",
    "IllegalTransition",
    "StateTransition",
    "HypothesisStateMachine",
]
