"""Execute benchmark suites against live targets and collect results."""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.benchmark.models import BenchmarkResult, BenchmarkRun
from src.benchmark.registry import get_suite, load_ground_truth
from src.benchmark.scoring import classify_result, overall_scores, category_scores, pass_at_k

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """Run benchmark test cases through the Assurix workflow engine."""

    def __init__(self, max_iterations: int = 3, timeout_per_case: int = 300) -> None:
        self.max_iterations = max_iterations
        self.timeout_per_case = timeout_per_case

    async def run_suite(
        self,
        suite_name: str,
        session: AsyncSession,
        target_url_override: str | None = None,
        config: dict | None = None,
    ) -> BenchmarkRun:
        suite = get_suite(suite_name)
        if not suite:
            raise ValueError(f"Unknown benchmark suite: {suite_name}")
        test_cases = load_ground_truth(suite_name)
        if not test_cases:
            raise ValueError(f"No ground truth data for suite: {suite_name}")

        run = BenchmarkRun(
            suite_name=suite_name, status="running",
            config=config or {}, started_at=datetime.now(UTC),
        )
        session.add(run)
        await session.flush()

        results: list[dict] = []
        for tc in test_cases:
            target_url = target_url_override or tc.get("target_url", "")
            if not target_url:
                continue
            start_time = time.monotonic()
            try:
                actual_findings = await self._run_test_case(target_url, tc, session)
            except Exception as e:
                logger.error(f"Test case {tc.get('id')} failed: {e}")
                actual_findings = []
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            classification = classify_result(
                expected_findings=tc.get("expected_findings"),
                expected_safe=tc.get("expected_safe", False),
                actual_findings=actual_findings,
            )
            result_row = BenchmarkResult(
                run_id=run.id,
                test_case_id=tc.get("id", str(uuid.uuid4())),
                category=tc.get("category", "uncategorized"),
                expected=tc.get("expected_findings"),
                actual=actual_findings if actual_findings else None,
                tp=classification.get("tp", False),
                fp=classification.get("fp", False),
                tn=classification.get("tn", False),
                fn=classification.get("fn", False),
                confidence_score=max(
                    (f.get("confidence_score", 0.7) for f in actual_findings), default=0.0
                ),
                severity_expected=(
                    tc.get("expected_findings", [{}])[0].get("severity")
                    if tc.get("expected_findings") else None
                ),
                severity_actual=actual_findings[0].get("severity") if actual_findings else None,
                response_time_ms=elapsed_ms,
                details=classification,
            )
            session.add(result_row)
            results.append({
                "tp": result_row.tp, "fp": result_row.fp,
                "tn": result_row.tn, "fn": result_row.fn,
                "category": result_row.category,
            })

        scores = overall_scores(results, weights=suite.scoring_weights or None)
        run.precision = scores["precision"]
        run.recall = scores["recall"]
        run.f1 = scores["f1"]
        run.fpr = scores["fpr"]
        run.accuracy = scores["accuracy"]
        run.weighted_score = scores.get("weighted_score")
        pass_results = [bool(r.get("tp") or r.get("tn")) for r in results]
        run.pass_at_k_score = pass_at_k(pass_results, k=3)
        run.k_value = 3
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await session.flush()
        return run

    async def _run_test_case(self, target_url, test_case, session):
        from src.db.models import Target, Engagement, Finding
        from src.db.session import get_db_session
        from src.orchestrator.engine import WorkflowEngine
        from src.agents.planner import PlannerAgent
        from src.agents.planner_mcts import MCTSPlannerAgent
        from src.agents.reasoner import ReasonerAgent
        from src.agents.recon import ReconAgent
        from src.agents.reporter import ReporterAgent
        from src.agents.validation import ValidationAgent
        from src.agents.webapp import WebappAgent
        from src.agents.pentester import PentesterAgent

        result_obj = await session.execute(select(Target).where(Target.url == target_url))
        target = result_obj.scalar_one_or_none()
        if target is None:
            target = Target(name=target_url, url=target_url, target_type="webapp", verified=True)
            session.add(target)
            await session.flush()

        engagement = Engagement(
            target_id=target.id,
            config={"max_iterations": self.max_iterations, "benchmark": True},
        )
        session.add(engagement)
        await session.flush()

        engine = WorkflowEngine()
        engine.register("planner", PlannerAgent)
        engine.register("planner_mcts", MCTSPlannerAgent)
        engine.register("recon", ReconAgent)
        engine.register("webapp", WebappAgent)
        engine.register("pentester", PentesterAgent)
        engine.register("reasoner", ReasonerAgent)
        engine.register("validation", ValidationAgent)
        engine.register("reporter", ReporterAgent)

        await engine.start_engagement(session, engagement.id, target_url=target_url)
        engine.start()

        deadline = time.monotonic() + self.timeout_per_case
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            async with get_db_session() as check_session:
                eng = await check_session.get(Engagement, engagement.id)
                if eng and eng.status in ("completed", "failed"):
                    break
        else:
            await engine.stop()
        await engine.stop()

        async with get_db_session() as fs:
            rows = await fs.execute(select(Finding).where(Finding.engagement_id == engagement.id))
            findings = rows.scalars().all()

        return [
            {
                "title": f.title, "severity": f.severity, "cwe_id": f.cwe_id,
                "confidence_score": f.confidence_score, "description": f.description,
                "source_agent": f.source_agent,
            }
            for f in findings
        ]

    async def run_dry(self, suite_name, session):
        """Run benchmark with simulated results for testing without live targets."""
        suite = get_suite(suite_name)
        if not suite:
            raise ValueError(f"Unknown benchmark suite: {suite_name}")
        test_cases = load_ground_truth(suite_name)
        if not test_cases:
            raise ValueError(f"No ground truth data for suite: {suite_name}")

        run = BenchmarkRun(
            suite_name=suite_name, status="running",
            config={"dry_run": True}, started_at=datetime.now(UTC),
        )
        session.add(run)
        await session.flush()

        results: list[dict] = []
        for tc in test_cases:
            expected = tc.get("expected_findings", [])
            expected_safe = tc.get("expected_safe", False)
            actual: list[dict] = []
            if not expected_safe and expected:
                for exp in expected:
                    if random.random() < 0.7:
                        actual.append({
                            "title": exp.get("title", "finding"),
                            "severity": exp.get("severity", "medium"),
                            "cwe_id": exp.get("cwe_id", ""),
                            "confidence_score": 0.8,
                            "category": tc.get("category", ""),
                        })
            if random.random() < 0.15:
                actual.append({
                    "title": f"False positive on {tc.get('id', 'unknown')}",
                    "severity": "low", "cwe_id": "CWE-200",
                    "confidence_score": 0.4, "category": tc.get("category", ""),
                })
            classification = classify_result(expected, expected_safe, actual)
            result_row = BenchmarkResult(
                run_id=run.id,
                test_case_id=tc.get("id", str(uuid.uuid4())),
                category=tc.get("category", "uncategorized"),
                expected=expected or None,
                actual=actual or None,
                tp=classification.get("tp", False),
                fp=classification.get("fp", False),
                tn=classification.get("tn", False),
                fn=classification.get("fn", False),
                confidence_score=0.75,
                severity_expected=expected[0].get("severity") if expected else None,
                severity_actual=actual[0].get("severity") if actual else None,
                response_time_ms=random.randint(500, 5000),
                details=classification,
            )
            session.add(result_row)
            results.append({
                "tp": result_row.tp, "fp": result_row.fp,
                "tn": result_row.tn, "fn": result_row.fn,
                "category": result_row.category,
            })

        scores = overall_scores(results, weights=suite.scoring_weights or None)
        run.precision = scores["precision"]
        run.recall = scores["recall"]
        run.f1 = scores["f1"]
        run.fpr = scores["fpr"]
        run.accuracy = scores["accuracy"]
        run.weighted_score = scores.get("weighted_score")
        pass_results = [bool(r.get("tp") or r.get("tn")) for r in results]
        run.pass_at_k_score = pass_at_k(pass_results, k=3)
        run.k_value = 3
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await session.flush()
        return run

    async def run_scored(
        self,
        suite_name: str,
        session: AsyncSession,
        results: list[dict],
        k: int = 3,
    ) -> BenchmarkRun:
        """Score pre-existing results against ground truth without live targets."""
        suite = get_suite(suite_name)
        if not suite:
            raise ValueError(f"Unknown benchmark suite: {suite_name}")
        test_cases = load_ground_truth(suite_name)
        if not test_cases:
            raise ValueError(f"No ground truth data for suite: {suite_name}")

        run = BenchmarkRun(
            suite_name=suite_name, status="running",
            config={"scored": True}, started_at=datetime.now(UTC),
        )
        session.add(run)
        await session.flush()

        scored: list[dict] = []
        for tc, res in zip(test_cases, results):
            expected = tc.get("expected_findings", [])
            expected_safe = tc.get("expected_safe", False)
            actual_findings = res.get("actual_findings", [])
            classification = classify_result(expected, expected_safe, actual_findings)
            result_row = BenchmarkResult(
                run_id=run.id,
                test_case_id=tc.get("id", str(uuid.uuid4())),
                category=tc.get("category", "uncategorized"),
                expected=expected or None,
                actual=actual_findings if actual_findings else None,
                tp=classification.get("tp", False),
                fp=classification.get("fp", False),
                tn=classification.get("tn", False),
                fn=classification.get("fn", False),
                confidence_score=res.get("confidence_score", 0.75),
                severity_expected=expected[0].get("severity") if expected else None,
                severity_actual=actual_findings[0].get("severity") if actual_findings else None,
                response_time_ms=res.get("response_time_ms", 0),
                details=classification,
            )
            session.add(result_row)
            scored.append({
                "tp": result_row.tp, "fp": result_row.fp,
                "tn": result_row.tn, "fn": result_row.fn,
                "category": result_row.category,
            })

        scores = overall_scores(scored, weights=suite.scoring_weights or None)
        run.precision = scores["precision"]
        run.recall = scores["recall"]
        run.f1 = scores["f1"]
        run.fpr = scores["fpr"]
        run.accuracy = scores["accuracy"]
        run.weighted_score = scores.get("weighted_score")
        pass_results = [bool(r.get("tp") or r.get("tn")) for r in scored]
        run.pass_at_k_score = pass_at_k(pass_results, k=k)
        run.k_value = k
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await session.flush()
        return run
