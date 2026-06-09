"""Tests for benchmark infrastructure: ground truth, scoring, pass@k, run_scored."""

import pytest
from pathlib import Path

from src.benchmark.registry import load_ground_truth, get_suite, list_suites
from src.benchmark.scoring import (
    classify_result, confusion_matrix, overall_scores, pass_at_k,
    precision, recall, f1_score, false_positive_rate, category_scores,
)
from src.benchmark.runner import BenchmarkRunner


# --- Ground Truth Loading ---

class TestGroundTruthLoading:
    @pytest.mark.parametrize("suite_name", list_suites())
    def test_ground_truth_loads(self, suite_name):
        cases = load_ground_truth(suite_name)
        assert len(cases) > 0, f"Suite {suite_name} has no test cases"

    @pytest.mark.parametrize("suite_name", list_suites())
    def test_ground_truth_has_required_fields(self, suite_name):
        cases = load_ground_truth(suite_name)
        for tc in cases:
            assert "id" in tc, f"Missing id in {suite_name}"
            assert "category" in tc, f"Missing category in {suite_name}"
            assert "expected_findings" in tc, f"Missing expected_findings in {suite_name}"
            assert "expected_safe" in tc, f"Missing expected_safe in {suite_name}"
            assert "timeout_seconds" in tc, f"Missing timeout_seconds in {suite_name}"

    @pytest.mark.parametrize("suite_name", list_suites())
    def test_ground_truth_has_safe_cases(self, suite_name):
        cases = load_ground_truth(suite_name)
        safe_cases = [tc for tc in cases if tc.get("expected_safe")]
        assert len(safe_cases) >= 3, f"{suite_name} needs >= 3 safe cases, got {len(safe_cases)}"

    @pytest.mark.parametrize("suite_name", list_suites())
    def test_ground_truth_has_vuln_cases(self, suite_name):
        cases = load_ground_truth(suite_name)
        vuln_cases = [tc for tc in cases if not tc.get("expected_safe")]
        assert len(vuln_cases) >= 15, f"{suite_name} needs >= 15 vuln cases, got {len(vuln_cases)}"

    def test_unknown_suite_returns_empty(self):
        cases = load_ground_truth("nonexistent_suite")
        assert cases == []


# --- Scoring ---

class TestClassifyResult:
    def test_true_positive(self):
        result = classify_result(
            expected_findings=[{"title": "XSS", "cwe_id": "CWE-79", "category": "xss"}],
            expected_safe=False,
            actual_findings=[{"title": "XSS Found", "cwe_id": "CWE-79", "category": "xss"}],
        )
        assert result["tp"] is True
        assert result["fp"] is False

    def test_false_positive_on_safe_target(self):
        result = classify_result(
            expected_findings=[],
            expected_safe=True,
            actual_findings=[{"title": "False Alarm"}],
        )
        assert result["fp"] is True
        assert result["tn"] is False

    def test_true_negative(self):
        result = classify_result(
            expected_findings=[], expected_safe=True, actual_findings=[],
        )
        assert result["tn"] is True
        assert result["fp"] is False

    def test_false_negative(self):
        result = classify_result(
            expected_findings=[{"title": "SQLi", "cwe_id": "CWE-89", "category": "sqli"}],
            expected_safe=False,
            actual_findings=[],
        )
        assert result["fn"] is True
        assert result["tp"] is False


class TestOverallScores:
    def test_basic_scoring(self):
        results = [
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "xss"},
            {"tp": False, "fp": True, "tn": False, "fn": False, "category": "xss"},
            {"tp": False, "fp": False, "tn": True, "fn": False, "category": "safe"},
            {"tp": False, "fp": False, "tn": False, "fn": True, "category": "sqli"},
        ]
        scores = overall_scores(results)
        assert scores["tp"] == 1
        assert scores["fp"] == 1
        assert scores["tn"] == 1
        assert scores["fn"] == 1
        assert scores["total"] == 4

    def test_weighted_score(self):
        results = [
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "xss"},
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "xss"},
        ]
        weights = {"precision": 0.3, "recall": 0.3, "f1": 0.3, "fpr": 0.1}
        scores = overall_scores(results, weights=weights)
        assert "weighted_score" in scores
        assert 0 <= scores["weighted_score"] <= 1

    def test_no_weights_gives_no_weighted_score(self):
        results = [
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "xss"},
        ]
        scores = overall_scores(results)
        assert "weighted_score" not in scores


class TestPassAtK:
    def test_all_pass(self):
        assert pass_at_k([True, True, True], k=1) == 1.0

    def test_all_fail(self):
        assert pass_at_k([False, False, False], k=1) == 0.0

    def test_mixed(self):
        result = pass_at_k([False, False, False, False, False, True, True, True], k=3)
        assert 0 < result < 1

    def test_k_greater_than_n_minus_c(self):
        result = pass_at_k([True, True, True], k=1)
        assert result == 1.0


class TestSuiteWeights:
    @pytest.mark.parametrize("suite_name", list_suites())
    def test_suite_has_weights(self, suite_name):
        suite = get_suite(suite_name)
        assert suite is not None
        weights = suite.scoring_weights
        assert len(weights) > 0, f"Suite {suite_name} has no scoring weights"
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.01, f"Suite {suite_name} weights sum to {total}, expected 1.0"


class TestCategoryScores:
    def test_category_breakdown(self):
        results = [
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "xss"},
            {"tp": False, "fp": True, "tn": False, "fn": False, "category": "xss"},
            {"tp": True, "fp": False, "tn": False, "fn": False, "category": "sqli"},
        ]
        scores = category_scores(results)
        assert "xss" in scores
        assert "sqli" in scores
        assert scores["xss"]["total"] == 2
        assert scores["sqli"]["total"] == 1


class TestBenchmarkRunnerDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_produces_results(self):
        from src.db.session import init_db, get_db_session, dispose_engine
        await init_db()
        try:
            runner = BenchmarkRunner()
            async with get_db_session() as session:
                result = await runner.run_dry("cybergym", session)
            run = result["run"]
            assert run.status == "completed"
            assert run.precision is not None
            assert run.f1 is not None
            assert run.weighted_score is not None
            assert run.pass_at_k_score is not None
            assert run.k_value == 3
        finally:
            await dispose_engine()

    @pytest.mark.asyncio
    async def test_dry_run_all_suites(self):
        from src.db.session import init_db, get_db_session, dispose_engine
        await init_db()
        try:
            runner = BenchmarkRunner()
            for suite_name in list_suites():
                async with get_db_session() as session:
                    result = await runner.run_dry(suite_name, session)
                run = result["run"]
                assert run.status == "completed", f"{suite_name} did not complete"
                assert run.weighted_score is not None, f"{suite_name} missing weighted_score"
                assert run.pass_at_k_score is not None, f"{suite_name} missing pass_at_k_score"
        finally:
            await dispose_engine()

    @pytest.mark.asyncio
    async def test_run_scored(self):
        from src.db.session import init_db, get_db_session, dispose_engine
        await init_db()
        try:
            runner = BenchmarkRunner()
            test_results = [
                {"actual_findings": [{"title": "XSS", "severity": "high", "cwe_id": "CWE-79", "category": "xss"}], "confidence_score": 0.8, "response_time_ms": 1500},
                {"actual_findings": [], "confidence_score": 0.5, "response_time_ms": 800},
            ]
            async with get_db_session() as session:
                run = await runner.run_scored("cybergym", session, test_results[:2], k=3)
            assert run.status == "completed"
            assert run.k_value == 3
            assert run.pass_at_k_score is not None
        finally:
            await dispose_engine()