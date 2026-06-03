"""Unit tests for TaskDifficultyAssessor (TDA) + EGATSPlanner (plan §3.1.5).

Coverage:
  TDA:
    1. Default values when no inputs provided.
    2. H component reads chain_length.
    3. H component reads depth as fallback.
    4. E component reads confidence, then confidence_score.
    5. C component respects override and default.
    6. S component respects override and default.
    7. Weights sum to 1.0 (the score lives in [0, 1]).
    8. Components clamped to [0, 1] before weighting.
    9. is_intractable below threshold (0.1).
    10. is_intractable at-or-above threshold.

  EGATSPlanner:
    11. execute emits two phases in dry-run mode.
    12. BFS recon visits target and its neighbors (capped by budget).
    13. BFS recon is cycle-safe.
    14. BFS recon is depth-capped.
    15. BFS recon is no-op when target_url missing or graph is None.
    16. TDI sort is descending.
    17. Pruned count matches is_intractable.
    18. Recon + exploit budget split is 30/70.
    19. Invalid budget fractions raise.
    20. max_iterations clamps to >= 1.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.agents.planner_egats import (
    EGATSPlanner,
    EXPLOIT_BUDGET_FRACTION,
    MAX_RECON_DEPTH,
    MAX_RECON_NODES,
    RECON_BUDGET_FRACTION,
)
from src.reasoning.tda import (
    TDI_INTRACTABLE_THRESHOLD,
    TaskDifficultyAssessor,
    TDIScore,
    WEIGHT_CONTEXT,
    WEIGHT_EVIDENCE_INVERSE,
    WEIGHT_HORIZON,
    WEIGHT_SUCCESS_INVERSE,
)


# --- TDA ----------------------------------------------------------------

class TestTaskDifficultyAssessor:
    def test_default_values(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({"hypothesis_id": "h1"})
        # With no inputs, defaults are: H=0.4 (2/5), E=0.5, C=0.5, S=0.5
        assert 0.0 <= s.tdi <= 1.0
        assert s.horizon == pytest.approx(0.4)  # 2 steps / 5
        assert s.evidence == 0.5
        assert s.context == 0.5
        assert s.success_rate == 0.5

    def test_h_reads_chain_length(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({"chain_length": 5})
        assert s.horizon == pytest.approx(1.0)  # clamped at max
        s2 = a.assess({"chain_length": 1})
        assert s2.horizon == pytest.approx(0.2)

    def test_h_reads_depth_fallback(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({"depth": 3})
        assert s.horizon == pytest.approx(0.6)

    def test_h_invalid_type_falls_back_to_default(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({"chain_length": "not_an_int"})
        assert s.horizon == pytest.approx(0.4)  # fallback default = 2

    def test_e_reads_confidence(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({}, evidence={"confidence": 0.9})
        assert s.evidence == 0.9

    def test_e_reads_confidence_score_fallback(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({}, evidence={"confidence_score": 0.3})
        assert s.evidence == 0.3

    def test_e_no_evidence_returns_default(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({}, evidence=None)
        assert s.evidence == 0.5

    def test_c_respects_override(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({}, context_coverage=0.8)
        assert s.context == 0.8

    def test_c_default_from_constructor(self) -> None:
        a = TaskDifficultyAssessor(default_context_coverage=0.7)
        s = a.assess({})
        assert s.context == 0.7

    def test_s_respects_override(self) -> None:
        a = TaskDifficultyAssessor()
        s = a.assess({}, historical_success_rate=0.1)
        assert s.success_rate == 0.1

    def test_weights_sum_to_one(self) -> None:
        total = (
            WEIGHT_HORIZON
            + WEIGHT_EVIDENCE_INVERSE
            + WEIGHT_CONTEXT
            + WEIGHT_SUCCESS_INVERSE
        )
        assert total == pytest.approx(1.0)

    def test_components_clamped(self) -> None:
        """Out-of-range inputs are clamped before weighting."""
        a = TaskDifficultyAssessor()
        # confidence > 1 should be clamped to 1.0
        s = a.assess({}, evidence={"confidence": 5.0})
        assert s.evidence == 1.0
        # success_rate < 0 should be clamped to 0.0
        s2 = a.assess({}, historical_success_rate=-1.0)
        assert s2.success_rate == 0.0
        # chain_length > 5 should be clamped to 1.0
        s3 = a.assess({"chain_length": 100})
        assert s3.horizon == 1.0

    def test_score_in_unit_range(self) -> None:
        a = TaskDifficultyAssessor()
        for chain in (0, 1, 3, 10):
            for conf in (0.0, 0.5, 1.0):
                for cov in (0.0, 0.5, 1.0):
                    for sr in (0.0, 0.5, 1.0):
                        s = a.assess(
                            {"chain_length": chain},
                            evidence={"confidence": conf},
                            context_coverage=cov,
                            historical_success_rate=sr,
                        )
                        assert 0.0 <= s.tdi <= 1.0

    def test_intractable_below_threshold(self) -> None:
        """A short-horizon, fully-evidenced, fully-successful candidate
        has a low TDI (only the H term contributes). With chain_length=1
        (H=0.2) and E=1, C=0, S=1: TDI = 0.3*0.2 = 0.06 — intractable.
        """
        a = TaskDifficultyAssessor()
        s = a.assess(
            {"chain_length": 1},  # H = 0.2
            evidence={"confidence": 1.0},  # E = 1.0 → (1-E) = 0
            context_coverage=0.0,  # C = 0
            historical_success_rate=1.0,  # S = 1.0 → (1-S) = 0
        )
        # Only the H term contributes: 0.3 * 0.2 = 0.06
        assert s.tdi == pytest.approx(0.3 * 0.2)
        assert s.is_intractable is True
        assert s.tdi < TDI_INTRACTABLE_THRESHOLD

    def test_high_tdi_above_threshold(self) -> None:
        """A speculative, multi-step, no-evidence, no-history candidate."""
        a = TaskDifficultyAssessor()
        s = a.assess({"chain_length": 5})  # H = 1.0
        # defaults: E=0.5, C=0.5, S=0.5
        # TDI = 0.3*1 + 0.3*0.5 + 0.2*0.5 + 0.2*0.5 = 0.3 + 0.15 + 0.1 + 0.1 = 0.65
        assert s.tdi == pytest.approx(0.65)
        assert not s.is_intractable


# --- EGATSPlanner -------------------------------------------------------

class TestEGATSPlanner:
    def test_budget_split_is_thirty_seventy(self) -> None:
        assert RECON_BUDGET_FRACTION == pytest.approx(0.30)
        assert EXPLOIT_BUDGET_FRACTION == pytest.approx(0.70)

    def test_invalid_budget_fractions_raise(self) -> None:
        with pytest.raises(ValueError, match="must equal 1.0"):
            EGATSPlanner(recon_budget_fraction=0.5, exploit_budget_fraction=0.6)
        with pytest.raises(ValueError, match="non-negative"):
            EGATSPlanner(recon_budget_fraction=-0.1, exploit_budget_fraction=1.1)

    def test_max_iterations_clamps_to_one(self) -> None:
        p = EGATSPlanner(max_iterations=0)
        assert p.max_iterations == 1

    def test_dry_run_emits_two_phases(self) -> None:
        p = EGATSPlanner(max_iterations=20)
        result = asyncio.run(p.execute(
            payload={
                "target_url": "https://t.example/",
                "candidates": [
                    {"hypothesis_id": "h1", "chain_length": 3},
                    {"hypothesis_id": "h2", "chain_length": 1},
                ],
                "dry_run": True,
            },
            session=None,
        ))
        assert "phases" in result
        assert len(result["phases"]) == 2
        assert result["phases"][0]["name"] == "bfs_recon"
        assert result["phases"][1]["name"] == "tdi_guided_exploit"

    def test_recon_visits_target_and_neighbors(self) -> None:
        p = EGATSPlanner(max_iterations=20)
        # Graph: A -> B, C; B -> D
        graph = {
            "https://t.example/": ["https://t.example/b", "https://t.example/c"],
            "https://t.example/b": ["https://t.example/d"],
            "https://t.example/c": [],
            "https://t.example/d": [],
        }
        def g(url: str) -> list[str]:
            return graph.get(url, [])
        result = asyncio.run(p.execute(
            payload={
                "target_url": "https://t.example/",
                "candidates": [],
                "graph": g,
                "dry_run": True,
            },
            session=None,
        ))
        recon = result["phases"][0]
        assert recon["visited"] == [
            "https://t.example/",
            "https://t.example/b",
            "https://t.example/c",
            "https://t.example/d",
        ]

    def test_recon_is_cycle_safe(self) -> None:
        p = EGATSPlanner(max_iterations=20)
        # Graph with a cycle: A <-> B
        def g(url: str) -> list[str]:
            if url == "A":
                return ["B"]
            if url == "B":
                return ["A"]
            return []
        result = asyncio.run(p.execute(
            payload={
                "target_url": "A",
                "candidates": [],
                "graph": g,
                "dry_run": True,
            },
            session=None,
        ))
        recon = result["phases"][0]
        # A and B each visited once, no infinite expansion.
        assert recon["visited"] == ["A", "B"]

    def test_recon_is_depth_capped(self) -> None:
        p = EGATSPlanner(max_iterations=200)
        # Chain of length 20: each node has exactly one child.
        def g(url: str) -> list[str]:
            try:
                n = int(url.rsplit("/", 1)[-1])
            except ValueError:
                return []
            return [f"node/{n + 1}"] if n + 1 < 20 else []
        result = asyncio.run(p.execute(
            payload={
                "target_url": "node/0",
                "candidates": [],
                "graph": g,
                "dry_run": True,
            },
            session=None,
        ))
        recon = result["phases"][0]
        # Depth is capped at MAX_RECON_DEPTH (=8); should not visit
        # the full chain.
        assert len(recon["visited"]) <= MAX_RECON_DEPTH + 1

    def test_recon_is_noop_when_target_url_missing(self) -> None:
        p = EGATSPlanner(max_iterations=10)
        result = asyncio.run(p.execute(
            payload={"target_url": "", "candidates": [], "dry_run": True},
            session=None,
        ))
        assert result["phases"][0]["skipped"] is True

    def test_recon_is_noop_when_graph_is_none(self) -> None:
        p = EGATSPlanner(max_iterations=10)
        result = asyncio.run(p.execute(
            payload={
                "target_url": "https://t.example/",
                "candidates": [],
                "graph": None,
                "dry_run": True,
            },
            session=None,
        ))
        assert result["phases"][0]["skipped"] is True

    def test_tdi_sort_is_descending(self) -> None:
        p = EGATSPlanner(max_iterations=20)
        # High chain_length, no evidence → high TDI
        # Low chain_length, full evidence → low TDI
        cands = [
            {"hypothesis_id": "low", "chain_length": 1, "evidence": {"confidence": 1.0}},
            {"hypothesis_id": "high", "chain_length": 5, "evidence": {"confidence": 0.0}},
            {"hypothesis_id": "mid", "chain_length": 3, "evidence": {"confidence": 0.5}},
        ]
        result = asyncio.run(p.execute(
            payload={
                "target_url": "https://t.example/",
                "candidates": cands,
                "dry_run": True,
            },
            session=None,
        ))
        sorted_ids = [c["hypothesis_id"] for c in result["sorted_candidates"]]
        assert sorted_ids[0] == "high"
        assert sorted_ids[-1] == "low"

    def test_pruned_count_matches_intractables(self) -> None:
        """Candidates with TDI < 0.1 should be pruned."""
        p = EGATSPlanner(max_iterations=20)
        # H=0.2 (1 step), E=1.0 (high evidence), C=0, S=1.0
        # → TDI = 0.06 (intractable)
        cands = [
            {"hypothesis_id": "intractable", "chain_length": 1,
             "evidence": {"confidence": 1.0}, "context_coverage": 0.0,
             "historical_success_rate": 1.0},
            {"hypothesis_id": "viable", "chain_length": 3},
        ]
        result = asyncio.run(p.execute(
            payload={"target_url": "https://t.example/", "candidates": cands, "dry_run": True},
            session=None,
        ))
        assert result["pruned_count"] == 1
        # Intractable is NOT in the sorted list.
        sorted_ids = [c["hypothesis_id"] for c in result["sorted_candidates"]]
        assert "intractable" not in sorted_ids
        assert "viable" in sorted_ids

    def test_each_candidate_gets_tdi_annotation(self) -> None:
        p = EGATSPlanner(max_iterations=10)
        result = asyncio.run(p.execute(
            payload={
                "target_url": "https://t.example/",
                "candidates": [{"hypothesis_id": "h1", "chain_length": 3}],
                "dry_run": True,
            },
            session=None,
        ))
        c = result["sorted_candidates"][0]
        assert "tdi_score" in c
        assert "tdi" in c["tdi_score"]
        assert "pruned" in c["tdi_score"]
        assert c["tdi_score"]["pruned"] is False

    def test_recon_budget_is_thirty_percent(self) -> None:
        """For max_iterations=100: recon=30, exploit=70."""
        p = EGATSPlanner(max_iterations=100)
        result = asyncio.run(p.execute(
            payload={"target_url": "", "candidates": [], "dry_run": True},
            session=None,
        ))
        assert result["recon_budget"] == 30
        assert result["exploit_budget"] == 70
        assert result["max_iterations"] == 100
