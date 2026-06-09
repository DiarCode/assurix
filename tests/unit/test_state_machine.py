"""Unit tests for the 8-state hypothesis state machine (per plan §3.1.1, BL-5)."""
from __future__ import annotations

import pytest

from src.reasoning.state_machine import (
    ALLOWED_TRANSITIONS,
    HypothesisState,
    HypothesisStateMachine,
    IllegalTransition,
    StateTransition,
)


def test_initial_state_is_unknown() -> None:
    fsm = HypothesisStateMachine()
    assert fsm.state == HypothesisState.UNKNOWN
    assert fsm.transitions == []


def test_full_4_step_path_to_validated() -> None:
    """Per plan §3.1.1: the path to VALIDATED is 4 transitions."""
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "hash-1", "first evidence")
    fsm.transit(HypothesisState.NEEDS_CORROBORATION, "hash-2", "second source")
    fsm.transit(HypothesisState.NEEDS_SAFE_VALIDATION, "hash-3", "reproducer")
    fsm.transit(HypothesisState.VALIDATED, "hash-4", "exploit succeeded")
    assert fsm.state == HypothesisState.VALIDATED
    assert len(fsm.transitions) == 4
    assert [t.to_state for t in fsm.transitions] == [
        HypothesisState.CANDIDATE,
        HypothesisState.NEEDS_CORROBORATION,
        HypothesisState.NEEDS_SAFE_VALIDATION,
        HypothesisState.VALIDATED,
    ]


def test_shortcut_to_validated_is_illegal() -> None:
    """Plan §3.1.1 (BL-5): the 2-state fall-back is FORBIDDEN."""
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    with pytest.raises(IllegalTransition):
        fsm.transit(HypothesisState.VALIDATED, "h2")


def test_unknown_to_validated_is_illegal() -> None:
    """Plan §3.1.1: skip corroboration is FORBIDDEN."""
    fsm = HypothesisStateMachine()
    with pytest.raises(IllegalTransition):
        fsm.transit(HypothesisState.VALIDATED, "h1")


def test_candidate_to_needs_safe_validation_is_illegal() -> None:
    """Cannot skip NEEDS_CORROBORATION."""
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    with pytest.raises(IllegalTransition):
        fsm.transit(HypothesisState.NEEDS_SAFE_VALIDATION, "h2")


def test_rejection_path() -> None:
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    fsm.transit(HypothesisState.REJECTED, "h2", "falsified")
    assert fsm.state == HypothesisState.REJECTED


def test_supersede_from_validated() -> None:
    """Validated can be superseded by new evidence."""
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    fsm.transit(HypothesisState.NEEDS_CORROBORATION, "h2")
    fsm.transit(HypothesisState.NEEDS_SAFE_VALIDATION, "h3")
    fsm.transit(HypothesisState.VALIDATED, "h4")
    fsm.transit(HypothesisState.SUPERSEDED, "h5", "newer hypothesis")
    assert fsm.state == HypothesisState.SUPERSEDED
    assert len(fsm.transitions) == 5


def test_confidence_decays_on_each_transition() -> None:
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    c1 = fsm.confidence
    fsm.transit(HypothesisState.NEEDS_CORROBORATION, "h2")
    c2 = fsm.confidence
    assert c2 < c1
    fsm.transit(HypothesisState.NEEDS_SAFE_VALIDATION, "h3")
    fsm.transit(HypothesisState.VALIDATED, "h4")
    # VALIDATED is terminal; no further decay
    c_final = fsm.confidence
    fsm.transit(HypothesisState.SUPERSEDED, "h5")
    assert fsm.confidence == c_final  # superseded does not decay


def test_can_transit_checks() -> None:
    fsm = HypothesisStateMachine()
    assert fsm.can_transit(HypothesisState.CANDIDATE) is True
    assert fsm.can_transit(HypothesisState.VALIDATED) is False
    fsm.transit(HypothesisState.CANDIDATE, "h1")
    assert fsm.can_transit(HypothesisState.NEEDS_CORROBORATION) is True
    assert fsm.can_transit(HypothesisState.NEEDS_SAFE_VALIDATION) is False


def test_state_transition_serializable() -> None:
    """StateTransition must be JSON-serializable for the state_transitions column."""
    import json
    fsm = HypothesisStateMachine()
    fsm.transit(HypothesisState.CANDIDATE, "abc123", "first")
    payload = json.dumps([t.__dict__ for t in fsm.transitions])
    assert "candidate" in payload
    assert "abc123" in payload


def test_all_8_states_reachable() -> None:
    """Each of the 8 states is reachable from UNKNOWN via some path."""
    reachable = set()
    for src, dst in ALLOWED_TRANSITIONS:
        reachable.add(src)
        reachable.add(dst)
    assert reachable == set(HypothesisState)
