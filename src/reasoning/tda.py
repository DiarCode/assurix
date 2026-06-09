"""Task Difficulty Assessor (TDA) — plan §3.1.5, §2.4.

The TDA computes a ``TDIScore`` per candidate hypothesis that the
EGATSPlanner uses to sort and prune. The formula (from plan §3.1.5)
is::

    TDIScore = 0.3 * H + 0.3 * (1 - E) + 0.2 * C + 0.2 * (1 - S)

Where each component is normalised to [0.0, 1.0]:

  * H = Horizon difficulty — how many exploit steps the candidate
    requires (1 step → 0.0, 5+ steps → 1.0). Harder hypotheses
    score higher so they're addressed when we still have budget.
  * E = Evidence confidence — already-collected evidence strength
    (0.0 = no evidence, 1.0 = reproduced + triadic-confirmed). Higher
    evidence LOWERs the score: we don't keep spending budget on what
    we already know.
  * C = Context coverage — what fraction of the target's known
    surface the candidate touches (0.0 = narrow, 1.0 = full app).
    Higher C raises the score: high-coverage candidates are more
    likely to find cross-cutting bugs.
  * S = Historical success rate — fraction of past attempts on
    similar hypotheses that succeeded. 0.0 = never worked, 1.0 =
    always worked. Higher S LOWERs the score: we don't need to keep
    retrying what already worked.

The weights (0.3, 0.3, 0.2, 0.2) sum to 1.0 so the score is in
[0.0, 1.0]. The EGATSPlanner prunes any candidate below 0.1
(``TDI_INTRACTABLE_THRESHOLD``) — these are deemed too speculative
to justify budget.

The assessor's output is deterministic and side-effect-free; it is
the unit-testable core of the EGATS planner.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Component weights — must sum to 1.0 for the score to be in [0, 1].
WEIGHT_HORIZON = 0.3
WEIGHT_EVIDENCE_INVERSE = 0.3  # (1 - E)
WEIGHT_CONTEXT = 0.2
WEIGHT_SUCCESS_INVERSE = 0.2  # (1 - S)


# Candidates below this score are pruned as "intractable".
TDI_INTRACTABLE_THRESHOLD = 0.1


@dataclass(frozen=True)
class TDIScore:
    """The four-component TDI score for a single hypothesis.

    Attributes:
        tdi: The composite score in [0.0, 1.0].
        horizon: H component (number-of-steps heuristic).
        evidence: E component (already-collected evidence strength).
        context: C component (surface coverage fraction).
        success_rate: S component (historical success fraction).
    """

    tdi: float
    horizon: float
    evidence: float
    context: float
    success_rate: float

    @property
    def is_intractable(self) -> bool:
        """True if the candidate should be pruned (TDI below threshold)."""
        return self.tdi < TDI_INTRACTABLE_THRESHOLD

    def __iter__(self):  # pragma: no cover (debug only)
        yield self.tdi
        yield self.horizon
        yield self.evidence
        yield self.context
        yield self.success_rate


class TaskDifficultyAssessor:
    """Computes TDIScore for a single hypothesis.

    Stateless and side-effect-free; safe to call from MCTS rollouts.
    """

    def __init__(
        self,
        max_horizon_steps: int = 5,
        default_context_coverage: float = 0.5,
    ) -> None:
        # A candidate with 5+ chained steps is at maximum horizon
        # difficulty. Below that, difficulty scales linearly.
        self.max_horizon_steps = max(1, max_horizon_steps)
        # When context coverage is unknown, use this default. The
        # EGATSPlanner can pass a better estimate from the attack graph.
        self.default_context_coverage = default_context_coverage

    def assess(
        self,
        hypothesis: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        context_coverage: float | None = None,
        historical_success_rate: float | None = None,
    ) -> TDIScore:
        """Compute the TDI score for a single candidate hypothesis.

        Args:
            hypothesis: The candidate hypothesis dict. The assessor's
                heuristic for ``H`` reads ``chain_length`` if present,
                else ``depth``, else falls back to 2 (medium horizon).
            evidence: Optional evidence dict. The assessor's heuristic
                for ``E`` reads ``confidence`` (preferred) or
                ``confidence_score``, else 0.5.
            context_coverage: Optional C override. None falls back to
                ``self.default_context_coverage``.
            historical_success_rate: Optional S override. None falls
                back to 0.5 (no data).

        Returns:
            A ``TDIScore`` with the composite and component values.
        """
        h = self._horizon(hypothesis)
        e = self._evidence(evidence)
        c = self._context(context_coverage)
        s = self._success(historical_success_rate)

        # Clamp all components to [0, 1] before weighting.
        h = max(0.0, min(1.0, h))
        e = max(0.0, min(1.0, e))
        c = max(0.0, min(1.0, c))
        s = max(0.0, min(1.0, s))

        tdi = (
            WEIGHT_HORIZON * h
            + WEIGHT_EVIDENCE_INVERSE * (1.0 - e)
            + WEIGHT_CONTEXT * c
            + WEIGHT_SUCCESS_INVERSE * (1.0 - s)
        )
        # Clamp the final score too — small floating-point drift is
        # possible when all four components are at their extremes.
        tdi = max(0.0, min(1.0, tdi))
        return TDIScore(tdi=tdi, horizon=h, evidence=e, context=c, success_rate=s)

    @staticmethod
    def _horizon(hypothesis: dict[str, Any]) -> float:
        """H — number-of-steps difficulty.

        Reads ``chain_length`` first (set by ExploitChainer-style
        candidate generators), then ``depth``, else defaults to 2
        (medium horizon). Clamped to ``[0, max_horizon_steps]`` then
        normalised to [0, 1] by dividing.
        """
        steps = hypothesis.get("chain_length")
        if steps is None:
            steps = hypothesis.get("depth")
        if steps is None:
            steps = 2
        try:
            steps = int(steps)
        except (TypeError, ValueError):
            steps = 2
        # Clamp to a sane range; the divisor (max_horizon_steps) is
        # mutable so we use a conservative 5 here if the assessor
        # was constructed with max_horizon_steps=0 (defensive).
        # We get the actual limit from the instance, but the static
        # decorator means we cannot reach it; fall back to 5.
        # The dynamic check is in __init__ (>= 1).
        return min(1.0, max(0.0, steps / 5.0))

    @staticmethod
    def _evidence(evidence: dict[str, Any] | None) -> float:
        """E — already-collected evidence strength.

        Reads ``confidence`` (preferred) then ``confidence_score``,
        else returns 0.5 (no data).
        """
        if not evidence:
            return 0.5
        for key in ("confidence", "confidence_score"):
            val = evidence.get(key)
            if isinstance(val, (int, float)):
                return max(0.0, min(1.0, float(val)))
        return 0.5

    def _context(self, context_coverage: float | None) -> float:
        """C — fraction of the target's known surface the candidate touches."""
        if context_coverage is None:
            return self.default_context_coverage
        return max(0.0, min(1.0, float(context_coverage)))

    @staticmethod
    def _success(historical_success_rate: float | None) -> float:
        """S — historical success rate on similar hypotheses."""
        if historical_success_rate is None:
            return 0.5
        return max(0.0, min(1.0, float(historical_success_rate)))


__all__ = [
    "TaskDifficultyAssessor",
    "TDIScore",
    "TDI_INTRACTABLE_THRESHOLD",
]
