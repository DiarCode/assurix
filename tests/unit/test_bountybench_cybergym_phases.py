"""BountyBench phase-aware scoring + CyberGym PoC scoring.

Plan §3.6: validate the two phase-aware benchmark scorers in isolation
and against the real ``BenchmarkRunner.run_dry`` path so we never need
a live target to exercise the integration.
"""

from __future__ import annotations

import json
import random  # noqa: F401  -- intentionally re-imported inside tests
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.benchmark.models import Base
from src.benchmark.phase_scorer import (
    aggregate_bountybench_phases,
    aggregate_cybergym_poc,
    score_bountybench_phase,
    score_cybergym_poc,
)
from src.benchmark.registry import get_suite, load_ground_truth
from src.benchmark.runner import BenchmarkRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def in_memory_session() -> AsyncIterator[AsyncSession]:
    """SQLite in-memory session with all ORM tables created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Unit tests — BountyBench phase scorer
# ---------------------------------------------------------------------------


class TestBountyBenchPhaseScorer:
    """BountyBench Detect / Exploit / Patch phase classification."""

    def test_vulnerable_case_detected_only(self) -> None:
        """A finding that matches CWE but lacks exploit/patch evidence."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "SQL Injection", "cwe_id": "CWE-89"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "SQL Injection",
                    "cwe_id": "CWE-89",
                    "description": "Parameter is concatenated into query.",
                    "confidence_score": 0.9,
                }
            ],
            test_case_id="bb-injection-001",
        )
        assert result.detected is True
        assert result.exploited is False
        assert result.patched is False
        assert result.phases_passed == 1

    def test_vulnerable_case_detected_and_exploited(self) -> None:
        """Finding includes evidence of exploitation."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "SQL Injection", "cwe_id": "CWE-89"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "SQL Injection",
                    "cwe_id": "CWE-89",
                    "description": "Extracted admin credentials via UNION SELECT",
                    "evidence": "Triggered database dump, response body: <creds>",
                    "confidence_score": 0.95,
                }
            ],
            test_case_id="bb-injection-001",
        )
        assert result.detected is True
        assert result.exploited is True
        assert result.patched is False
        assert result.exploit_evidence != ""

    def test_vulnerable_case_all_three_phases(self) -> None:
        """Finding includes exploit + patch_suggestion."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "SQL Injection", "cwe_id": "CWE-89"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "SQL Injection",
                    "cwe_id": "CWE-89",
                    "description": "Triggered database dump",
                    "evidence": "union select extracted data",
                    "patch_suggestion": "Use parameterized query to sanitize input",
                    "confidence_score": 0.95,
                }
            ],
            test_case_id="bb-injection-001",
        )
        assert result.detected is True
        assert result.exploited is True
        assert result.patched is True
        assert result.phases_passed == 3

    def test_vulnerable_case_unmatched_is_not_detected(self) -> None:
        """A finding that doesn't match CWE/title/category should not count."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "SQL Injection", "cwe_id": "CWE-89"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "XSS",
                    "cwe_id": "CWE-79",
                    "description": "Script injection",
                    "confidence_score": 0.7,
                }
            ],
            test_case_id="bb-injection-001",
        )
        assert result.detected is False
        assert result.exploited is False
        assert result.patched is False

    def test_safe_case_with_no_findings(self) -> None:
        """Safe control case: agent correctly reports nothing."""
        result = score_bountybench_phase(
            expected_findings=[],
            expected_safe=True,
            actual_findings=[],
            test_case_id="bb-safe-001",
        )
        assert result.detected is True
        assert result.exploited is True
        assert result.patched is True

    def test_safe_case_with_false_positive_fails_all(self) -> None:
        """Safe control case but agent reports a finding — false positive."""
        result = score_bountybench_phase(
            expected_findings=[],
            expected_safe=True,
            actual_findings=[
                {
                    "title": "Phantom vuln",
                    "cwe_id": "CWE-89",
                    "description": "false positive",
                    "confidence_score": 0.4,
                }
            ],
            test_case_id="bb-safe-001",
        )
        assert result.detected is False
        assert result.exploited is False
        assert result.patched is False

    def test_evidence_dict_is_coerced(self) -> None:
        """Evidence passed as a dict should not crash the scorer."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "SSRF", "cwe_id": "CWE-918"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "SSRF",
                    "cwe_id": "CWE-918",
                    "description": "Cloud metadata credential access",
                    "evidence": {
                        "request": "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "response": "<AccessKeyId>...</AccessKeyId>",
                    },
                    "confidence_score": 0.95,
                }
            ],
            test_case_id="bb-ssrf-002",
        )
        assert result.detected is True
        assert result.exploited is True

    def test_patch_from_description_keyword(self) -> None:
        """If no patch_suggestion field, scan description for patch keywords."""
        result = score_bountybench_phase(
            expected_findings=[{"title": "XSS", "cwe_id": "CWE-79"}],
            expected_safe=False,
            actual_findings=[
                {
                    "title": "XSS",
                    "cwe_id": "CWE-79",
                    "description": (
                        "Reflected XSS — fix: output encoding and CSP header"
                    ),
                    "evidence": "Triggered alert(1)",
                    "confidence_score": 0.85,
                }
            ],
            test_case_id="bb-xss-001",
        )
        assert result.detected is True
        assert result.exploited is True
        assert result.patched is True


class TestBountyBenchPhaseAggregate:
    """BountyBench phase aggregation across test cases."""

    def test_aggregate_vulnerable_only(self) -> None:
        per_case = [
            score_bountybench_phase(
                expected_findings=[{"title": "SQL Injection", "cwe_id": "CWE-89"}],
                expected_safe=False,
                actual_findings=[
                    {
                        "title": "SQL Injection",
                        "cwe_id": "CWE-89",
                        "description": "extracted credentials via union select",
                        "confidence_score": 0.9,
                    }
                ],
                test_case_id="bb-injection-001",
            ),
            score_bountybench_phase(
                expected_findings=[{"title": "SSRF", "cwe_id": "CWE-918"}],
                expected_safe=False,
                actual_findings=[],  # missed
                test_case_id="bb-ssrf-001",
            ),
        ]
        test_cases = [
            {"id": "bb-injection-001", "expected_safe": False},
            {"id": "bb-ssrf-001", "expected_safe": False},
        ]
        agg = aggregate_bountybench_phases(per_case, test_cases)
        assert agg.total_vulnerable == 2
        assert agg.total_safe == 0
        assert agg.detect_rate == 0.5
        assert agg.exploit_rate == 0.5
        assert agg.patch_rate == 0.0
        assert agg.all_phases_rate == 0.0

    def test_aggregate_mixed_vulnerable_and_safe(self) -> None:
        per_case = [
            score_bountybench_phase(
                expected_findings=[{"title": "XSS", "cwe_id": "CWE-79"}],
                expected_safe=False,
                actual_findings=[],  # miss
                test_case_id="bb-xss-001",
            ),
            score_bountybench_phase(
                expected_findings=[],
                expected_safe=True,
                actual_findings=[],  # correct TN
                test_case_id="bb-safe-001",
            ),
            score_bountybench_phase(
                expected_findings=[],
                expected_safe=True,
                actual_findings=[  # false positive
                    {"title": "phantom", "cwe_id": "CWE-79"}
                ],
                test_case_id="bb-safe-002",
            ),
        ]
        test_cases = [
            {"id": "bb-xss-001", "expected_safe": False},
            {"id": "bb-safe-001", "expected_safe": True},
            {"id": "bb-safe-002", "expected_safe": True},
        ]
        agg = aggregate_bountybench_phases(per_case, test_cases)
        assert agg.total_vulnerable == 1
        assert agg.total_safe == 2
        assert agg.detect_rate == 0.0  # missed the only vuln
        assert agg.safe_true_negative_rate == 0.5  # 1/2 safe correct

    def test_aggregate_to_dict_roundtrip(self) -> None:
        per_case = [
            score_bountybench_phase(
                expected_findings=[{"title": "X", "cwe_id": "CWE-89"}],
                expected_safe=False,
                actual_findings=[],
                test_case_id="x-1",
            )
        ]
        agg = aggregate_bountybench_phases(
            per_case, [{"id": "x-1", "expected_safe": False}]
        )
        d = agg.to_dict()
        # Should be JSON-serializable
        json.dumps(d)
        assert d["total_vulnerable"] == 1
        assert d["total_safe"] == 0
        assert d["detect_rate"] == 0.0


# ---------------------------------------------------------------------------
# Unit tests — CyberGym PoC scorer
# ---------------------------------------------------------------------------


class TestCyberGymPoCScorer:
    """CyberGym PoC quality scoring."""

    def test_no_poc_means_not_executable(self) -> None:
        score = score_cybergym_poc(
            test_case={"id": "xss-1", "category": "xss", "expected_safe": False},
            actual_findings=[
                {
                    "title": "XSS",
                    "cwe_id": "CWE-79",
                    "description": "Reflected XSS in search.",
                    "confidence_score": 0.8,
                }
            ],
        )
        assert score.poc_present is False
        assert score.poc_executable is False
        assert score.passed is False

    def test_poc_with_curl_marker(self) -> None:
        score = score_cybergym_poc(
            test_case={"id": "xss-1", "category": "xss", "expected_safe": False},
            actual_findings=[
                {
                    "title": "XSS",
                    "cwe_id": "CWE-79",
                    "poc": "curl -G --data-urlencode 'q=<script>alert(1)</script>' http://target/search",
                    "confidence_score": 0.9,
                }
            ],
        )
        assert score.poc_present is True
        assert score.poc_targeted is True
        assert score.poc_executable is True
        assert score.passed is True

    def test_poc_targeted_via_sink_keyword(self) -> None:
        score = score_cybergym_poc(
            test_case={"id": "sqli-1", "category": "sqli", "expected_safe": False},
            actual_findings=[
                {
                    "title": "SQLi",
                    "cwe_id": "CWE-89",
                    "poc": "q=admin' OR 1=1 -- -  # union select username from users",
                    "confidence_score": 0.9,
                }
            ],
        )
        assert score.poc_present is True
        assert score.poc_targeted is True
        assert score.poc_executable is True

    def test_safe_case_no_poc_required(self) -> None:
        score = score_cybergym_poc(
            test_case={"id": "safe-1", "category": "xss", "expected_safe": True},
            actual_findings=[],
        )
        assert score.poc_present is False
        assert score.poc_executable is False

    def test_safe_case_with_poc_is_a_failure(self) -> None:
        """Safe control case is short-circuited — the per-case score
        reports the agent's literal artifact count (here: zero), and
        the aggregate translates ``poc_present=True`` on a safe case
        into a false-positive signal."""
        score = score_cybergym_poc(
            test_case={"id": "safe-1", "category": "xss", "expected_safe": True},
            actual_findings=[
                {
                    "title": "phantom",
                    "cwe_id": "CWE-79",
                    "poc": "alert(1)",
                    "confidence_score": 0.5,
                }
            ],
        )
        # Safe-case short-circuit: the per-case fields all read False
        # because we don't want to credit a phantom PoC on a safe target.
        # The aggregate handles the FP accounting via
        # ``safe_true_negative_rate``.
        assert score.poc_present is False
        assert score.poc_executable is False
        assert score.passed is False

    def test_evidence_as_dict(self) -> None:
        """PoC supplied as a dict should not crash the scorer."""
        score = score_cybergym_poc(
            test_case={"id": "xss-1", "category": "xss", "expected_safe": False},
            actual_findings=[
                {
                    "title": "XSS",
                    "cwe_id": "CWE-79",
                    "poc": {
                        "request": "GET /search?q=<script>alert(1)</script>",
                        "response": "<script>alert(1)</script>",
                    },
                }
            ],
        )
        assert score.poc_present is True
        assert score.poc_executable is True


class TestCyberGymPoCAggregate:
    """CyberGym PoC aggregation."""

    def test_aggregate_pass_rate(self) -> None:
        per_case = [
            score_cybergym_poc(
                test_case={"id": "xss-1", "category": "xss", "expected_safe": False},
                actual_findings=[
                    {
                        "title": "XSS",
                        "cwe_id": "CWE-79",
                        "poc": "alert(1)",
                    }
                ],
            ),
            score_cybergym_poc(
                test_case={"id": "sqli-1", "category": "sqli", "expected_safe": False},
                actual_findings=[],  # no PoC
            ),
            score_cybergym_poc(
                test_case={"id": "safe-1", "category": "xss", "expected_safe": True},
                actual_findings=[],
            ),
        ]
        test_cases = [
            {"id": "xss-1", "category": "xss", "expected_safe": False},
            {"id": "sqli-1", "category": "sqli", "expected_safe": False},
            {"id": "safe-1", "category": "xss", "expected_safe": True},
        ]
        agg = aggregate_cybergym_poc(per_case, test_cases)
        assert agg.total_vulnerable == 2
        assert agg.total_safe == 1
        assert agg.poc_pass_rate == 0.5  # 1/2
        assert agg.safe_true_negative_rate == 1.0  # 1/1

    def test_aggregate_no_test_cases(self) -> None:
        agg = aggregate_cybergym_poc([], [])
        assert agg.poc_pass_rate == 0.0
        assert agg.total_vulnerable == 0


# ---------------------------------------------------------------------------
# Integration tests — wired into BenchmarkRunner
# ---------------------------------------------------------------------------


class TestRunnerIntegration:
    """Wire the phase scorers into the real ``BenchmarkRunner.run_dry``."""

    @pytest.mark.asyncio
    async def test_bountybench_dry_run_populates_phase_columns(
        self, in_memory_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """run_dry on BountyBench should populate the four phase rates."""
        # Patch the random module inside runner so the dry-run TP-rate
        # sampling is deterministic.  Always trigger TP (random < 0.7)
        # and never trigger FP (random < 0.15).
        import src.benchmark.runner as runner_module
        monkeypatch.setattr(runner_module.random, "random", lambda: 0.0)

        suite = get_suite("bountybench")
        assert suite is not None
        test_cases = load_ground_truth("bountybench")
        vuln = [tc for tc in test_cases if not tc.get("expected_safe")]
        safe = [tc for tc in test_cases if tc.get("expected_safe")]
        assert len(vuln) >= 3
        assert len(safe) >= 1

        runner = BenchmarkRunner(max_iterations=1, timeout_per_case=60)
        result = await runner.run_dry("bountybench", in_memory_session)
        await in_memory_session.commit()

        run = result["run"]
        # Detect should be 1.0 — every vuln case had at least one matching finding
        assert run.bountybench_detect_rate == 1.0
        # Exploit: at least one BountyBench ground-truth title contains an
        # exploit keyword (e.g. "credential" in "SSRF to Cloud Metadata
        # Credential Access"), so exploit_rate > 0 is expected and correct.
        # The exact value depends on the ground truth, so we just assert
        # the column is populated and within [0, 1].
        assert run.bountybench_exploit_rate is not None
        assert 0.0 <= run.bountybench_exploit_rate <= 1.0
        # Patch rate is 0 because synthetic dry-run findings have no
        # patch_suggestion and don't embed patch keywords.
        assert run.bountybench_patch_rate == 0.0
        # All three at once is 0 (no patch evidence)
        assert run.bountybench_all_phases_rate == 0.0
        # Per-case detail is persisted
        assert run.bountybench_phase_detail is not None
        detail = run.bountybench_phase_detail
        assert detail["total_vulnerable"] == len(vuln)
        assert detail["total_safe"] == len(safe)
        # CyberGym columns are not touched for BountyBench runs
        assert run.cybergym_poc_pass_rate is None
        assert run.cybergym_poc_detail is None

    @pytest.mark.asyncio
    async def test_bountybench_dry_run_with_seed_rng(
        self, in_memory_session: AsyncSession
    ) -> None:
        """With a real RNG, phase rates should fall in [0, 1]."""
        runner = BenchmarkRunner(max_iterations=1, timeout_per_case=60)
        result = await runner.run_dry("bountybench", in_memory_session)
        await in_memory_session.commit()

        run = result["run"]
        assert 0.0 <= run.bountybench_detect_rate <= 1.0
        assert 0.0 <= run.bountybench_exploit_rate <= 1.0
        assert 0.0 <= run.bountybench_patch_rate <= 1.0
        assert 0.0 <= run.bountybench_all_phases_rate <= 1.0
        assert run.bountybench_phase_detail is not None

    @pytest.mark.asyncio
    async def test_cybergym_dry_run_populates_poc_column(
        self, in_memory_session: AsyncSession
    ) -> None:
        """run_dry on CyberGym should populate the PoC pass rate."""
        suite = get_suite("cybergym")
        assert suite is not None

        runner = BenchmarkRunner(max_iterations=1, timeout_per_case=60)
        result = await runner.run_dry("cybergym", in_memory_session)
        await in_memory_session.commit()

        run = result["run"]
        # run_dry synthesizes findings with no ``poc`` field, so executable
        # PoC rate should be 0.0
        assert run.cybergym_poc_pass_rate == 0.0
        assert run.cybergym_poc_detail is not None
        detail = run.cybergym_poc_detail
        # PoC scoring collapses to total_vulnerable + total_safe
        assert detail["total_vulnerable"] + detail["total_safe"] > 0
        # BountyBench columns are not touched for CyberGym runs
        assert run.bountybench_detect_rate is None
        assert run.bountybench_phase_detail is None

    @pytest.mark.asyncio
    async def test_cyberarena_does_not_populate_phase_columns(
        self, in_memory_session: AsyncSession
    ) -> None:
        """Other suites must NOT be force-scored by the phase logic."""
        suite = get_suite("cyberarena")
        if suite is None:
            pytest.skip("cyberarena not registered")
        runner = BenchmarkRunner(max_iterations=1, timeout_per_case=60)
        result = await runner.run_dry("cyberarena", in_memory_session)
        await in_memory_session.commit()

        run = result["run"]
        assert run.bountybench_detect_rate is None
        assert run.bountybench_phase_detail is None
        assert run.cybergym_poc_pass_rate is None
        assert run.cybergym_poc_detail is None
