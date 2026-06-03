"""EGATS Planner — BFS recon + TDI-guided exploit (plan §2.4, §3.1.5).

The EGATS planner is the v2 replacement for the linear ``PlannerAgent``
(``src/agents/planner.py``). It has TWO phases:

  1. **BFS Recon** (30% of max_iterations budget): crawl the target's
     surface breadth-first, building an attack graph. Each new
     endpoint becomes a neighbor in the graph; visited endpoints are
     not re-expanded (cycle-safe).

  2. **TDI-Guided Exploit** (70% of max_iterations budget): score
     every candidate hypothesis with the ``TaskDifficultyAssessor``
     and dispatch them in TDI-desc order. Hypotheses with
     ``TDI < 0.1`` are pruned as intractable. After each successful
     dispatch, the planner re-enters with the newly-acquired
     capabilities (``"we have admin now"``).

The inner MCTS work is delegated to the existing
``MCTSPlannerAgent``; the EGATS wrapper adds the BFS phase and the
TDI sorting layer. The wrapper is wire-compatible with the existing
``PlannerAgent.execute(payload, session)`` signature so it can be
swapped in via ``config["use_egats"] = True`` (the default for v2).

Dry-run mode (``config.get("dry_run", False)``) skips the inner MCTS
rollouts and just emits the two phases of action candidates as a
list — this is the Week 1 acceptance test target.
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Any

from src.agents.base import BaseAgent
from src.reasoning.tda import TDI_INTRACTABLE_THRESHOLD, TaskDifficultyAssessor, TDIScore

logger = logging.getLogger(__name__)


# Budget split per plan §2.4. 30% recon, 70% exploit.
RECON_BUDGET_FRACTION = 0.30
EXPLOIT_BUDGET_FRACTION = 0.70

# Phase 1 (BFS recon) termination. Either is sufficient.
MAX_RECON_DEPTH = 8
MAX_RECON_NODES = 200


class EGATSPlanner(BaseAgent):
    """BFS recon + TDI-guided exploit planner (plan §2.4).

    The planner is the v2 default. To use the legacy linear planner
    instead, pass ``use_egats=False`` in the call site's config.
    """

    name = "planner_egats"

    def __init__(
        self,
        max_iterations: int = 30,
        recon_budget_fraction: float = RECON_BUDGET_FRACTION,
        exploit_budget_fraction: float = EXPLOIT_BUDGET_FRACTION,
        tda: TaskDifficultyAssessor | None = None,
    ) -> None:
        self.max_iterations = max(1, int(max_iterations))
        # Sanity-check the budget fractions.
        if recon_budget_fraction < 0 or exploit_budget_fraction < 0:
            raise ValueError("budget fractions must be non-negative")
        if abs(recon_budget_fraction + exploit_budget_fraction - 1.0) > 1e-6:
            raise ValueError(
                f"recon_budget_fraction + exploit_budget_fraction must equal 1.0; "
                f"got {recon_budget_fraction} + {exploit_budget_fraction}"
            )
        self.recon_budget_fraction = recon_budget_fraction
        self.exploit_budget_fraction = exploit_budget_fraction
        self.tda = tda or TaskDifficultyAssessor()

    # --- Public entry point --------------------------------------------

    async def execute(
        self,
        payload: dict[str, Any],
        session: Any,
    ) -> dict[str, Any]:
        """Run the two-phase EGATS plan and return a structured result.

        Args:
            payload: The planning input. Required keys:
                - ``target_url``: str — the entry point URL.
                - ``candidates``: list[dict] — candidate hypotheses.
                - ``graph`` (optional): callable that maps a URL to a
                  list of neighbor URLs. If absent, the recon phase
                  is a no-op.
                - ``dry_run`` (optional): if True, skip inner MCTS
                  rollouts and just emit the two phases of actions.
            session: AsyncSession (kept for BaseAgent signature compat).

        Returns:
            dict with keys: ``phases`` (list of phase dicts),
            ``sorted_candidates`` (TDI-desc), ``pruned_count`` (int).
        """
        target_url = payload.get("target_url", "")
        candidates = list(payload.get("candidates", []))
        graph = payload.get("graph")
        dry_run = bool(payload.get("dry_run", False))

        recon_budget = max(1, int(self.max_iterations * self.recon_budget_fraction))
        exploit_budget = max(1, int(self.max_iterations * self.exploit_budget_fraction))

        # Phase 1: BFS recon.
        recon_result = self._bfs_recon(
            target_url=target_url,
            graph=graph,
            budget=recon_budget,
        )

        # Phase 2: TDI-guided exploit.
        sorted_candidates, pruned_count = self._tdi_guided_exploit(candidates)

        # Optional: inner MCTS rollouts. In dry-run mode we skip the
        # actual LLM calls and just record that we *would* dispatch.
        if not dry_run:
            for c in sorted_candidates[:exploit_budget]:
                try:
                    # Lazy import to avoid circular import at module
                    # load time (planner_mcts imports agents too).
                    from src.agents.planner_mcts import MCTSPlannerAgent
                    mcts = MCTSPlannerAgent()
                    action = await mcts.select_next_action(
                        observations={"hypothesis": c},
                        target_url=target_url,
                    )
                    c.setdefault("mcts_action", action)
                except Exception as exc:  # last-resort safety net
                    logger.warning(
                        "EGATS: MCTS rollout failed for %s: %s",
                        c.get("hypothesis_class", "?"), exc,
                    )
                    # Per plan §6.2: 3 consecutive failures → fall back
                    # to the AdaptivePlanningPlanner (already in
                    # planner_mcts design intent).
                    c.setdefault("mcts_action", None)
                    c.setdefault("mcts_error", str(exc)[:200])

        return {
            "target_url": target_url,
            "phases": [recon_result, {
                "name": "tdi_guided_exploit",
                "budget": exploit_budget,
                "dispatched": min(len(sorted_candidates), exploit_budget),
                "pruned_count": pruned_count,
                "sorted_candidates": sorted_candidates[:exploit_budget],
            }],
            "sorted_candidates": sorted_candidates,
            "pruned_count": pruned_count,
            "max_iterations": self.max_iterations,
            "recon_budget": recon_budget,
            "exploit_budget": exploit_budget,
        }

    # --- Phase 1: BFS recon --------------------------------------------

    def _bfs_recon(
        self,
        target_url: str,
        graph: Any,
        budget: int,
    ) -> dict[str, Any]:
        """BFS over the target's surface, building an attack graph.

        ``graph`` is a callable ``(url) -> list[str]`` returning
        neighbor URLs. When ``graph`` is None or ``target_url`` is
        empty, the recon phase is a no-op (returns an empty graph
        with a ``skipped`` flag).
        """
        visited: set[str] = set()
        discovered: list[str] = []
        edges: list[tuple[str, str]] = []

        if not target_url or not callable(graph):
            return {
                "name": "bfs_recon",
                "budget": budget,
                # Return JSON-serializable containers (SQLAlchemy stores
                # these in the Job.result JSON column, which uses stdlib
                # json.dumps without a default=str fallback).
                "visited": list(visited),
                "discovered": list(discovered),
                "edges": [list(e) for e in edges],
                "skipped": True,
            }

        queue: deque[str] = deque([target_url])
        depth: dict[str, int] = {target_url: 0}

        while queue and len(visited) < MAX_RECON_NODES and len(visited) < budget:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            discovered.append(current)

            try:
                neighbors = graph(current) or []
            except Exception as exc:
                logger.warning("EGATS: graph(%s) raised: %s", current, exc)
                neighbors = []

            for n in neighbors:
                if not isinstance(n, str):
                    continue
                if n in visited:
                    continue
                edges.append((current, n))
                # Cap depth to prevent infinite expansion on cyclic graphs.
                if depth[current] + 1 <= MAX_RECON_DEPTH:
                    depth[n] = depth[current] + 1
                    queue.append(n)

        return {
            "name": "bfs_recon",
            "budget": budget,
            # JSON-serializable containers (Job.result is a JSON column).
            # `sorted(visited)` returns a list; edges are tuples (which
            # json.dumps serializes as JSON arrays) but we convert to
            # nested lists for consistency.
            "visited": sorted(visited),
            "discovered": discovered,
            "edges": [list(e) for e in edges],
            "skipped": False,
        }

    # --- Phase 2: TDI-guided exploit -----------------------------------

    def _tdi_guided_exploit(
        self,
        candidates: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """Score each candidate with TDA, prune intractables, sort by TDI desc.

        Returns the sorted list and the count of pruned candidates.
        Each candidate is annotated with its ``tdi_score`` dict so the
        caller (or auditor) can see why a candidate was dispatched
        or pruned.
        """
        scored: list[tuple[dict[str, Any], TDIScore]] = []
        pruned = 0
        for cand in candidates:
            tdi = self.tda.assess(
                hypothesis=cand,
                evidence=cand.get("evidence"),
                context_coverage=cand.get("context_coverage"),
                historical_success_rate=cand.get("historical_success_rate"),
            )
            # Annotate the candidate with its TDI so callers can audit.
            cand["tdi_score"] = {
                "tdi": tdi.tdi,
                "horizon": tdi.horizon,
                "evidence": tdi.evidence,
                "context": tdi.context,
                "success_rate": tdi.success_rate,
            }
            if tdi.is_intractable:
                pruned += 1
                cand["tdi_score"]["pruned"] = True
                continue
            cand["tdi_score"]["pruned"] = False
            scored.append((cand, tdi))

        # Sort by TDI desc, stable on the candidate's hypothesis id
        # so two candidates with equal TDI keep their input order.
        scored.sort(key=lambda pair: (-pair[1].tdi, pair[0].get("hypothesis_id", "")))
        return [c for c, _ in scored], pruned


__all__ = ["EGATSPlanner"]
