"""Execute benchmark suites against live targets and collect results."""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from datetime import UTC, datetime
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.benchmark.capability_scorer import (
    CapabilityReport,
    CapabilityScore,
    compute_multi_target_report,
    compute_overall_score,
    score_finding,
)
from src.benchmark.docker_target import (
    BENCHMARK_TARGETS,
    DockerTarget,
    DockerTargetManager,
    DockerUnavailableError,
    HealthCheckTimeoutError,
)
from src.benchmark.models import BenchmarkResult, BenchmarkRun
from src.benchmark.registry import get_suite, list_suites, load_ground_truth
from src.benchmark.scoring import category_scores, classify_result, overall_scores, pass_at_k

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
    ) -> dict[str, Any]:
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
        all_findings: list[dict] = []
        all_actual_findings: list[list[dict]] = []
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
            all_findings.extend(actual_findings)
            all_actual_findings.append(actual_findings)
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

        # Score findings with capability ladder
        cap_scores = [score_finding(f) for f in all_findings]
        cap_report = compute_overall_score(cap_scores, target_name=suite_name)

        # BountyBench / CyberGym phase-aware scoring (plan §3.6).
        if suite_name in ("bountybench", "cybergym"):
            from src.benchmark.phase_scorer import (
                aggregate_bountybench_phases,
                aggregate_cybergym_poc,
                score_bountybench_phase,
                score_cybergym_poc,
            )
            if suite_name == "bountybench":
                per_case = [
                    score_bountybench_phase(
                        expected_findings=tc.get("expected_findings") or [],
                        expected_safe=bool(tc.get("expected_safe")),
                        actual_findings=actual_for_case,
                        test_case_id=tc.get("id", ""),
                    )
                    for tc, actual_for_case in zip(test_cases, all_actual_findings)
                ]
                bb_agg = aggregate_bountybench_phases(per_case, test_cases)
                run.bountybench_detect_rate = bb_agg.detect_rate
                run.bountybench_exploit_rate = bb_agg.exploit_rate
                run.bountybench_patch_rate = bb_agg.patch_rate
                run.bountybench_all_phases_rate = bb_agg.all_phases_rate
                run.bountybench_phase_detail = bb_agg.to_dict()
            else:  # cybergym
                per_case = [
                    score_cybergym_poc(tc, actual_for_case)
                    for tc, actual_for_case in zip(test_cases, all_actual_findings)
                ]
                cg_agg = aggregate_cybergym_poc(per_case, test_cases)
                run.cybergym_poc_pass_rate = cg_agg.poc_pass_rate
                run.cybergym_poc_detail = cg_agg.to_dict()
            await session.flush()

        return {
            "run": run,
            "capability": cap_report,
        }

    async def _run_test_case(self, target_url, test_case, session, config=None):
        from src.db.models import Target, Engagement, Finding
        from src.db.session import get_db_session
        from src.orchestrator.engine import WorkflowEngine
        from src.agents.planner_egats import EGATSPlanner
        from src.agents.planner_mcts import MCTSPlannerAgent
        from src.agents.reasoner import ReasonerAgent
        from src.agents.recon import ReconAgent
        from src.agents.reporter import ReporterAgent
        from src.agents.validation import ValidationAgent
        from src.agents.webapp import WebappAgent
        from src.agents.pentester import PentesterAgent
        from src.agents.research_loop import ResearchLoopAgent

        result_obj = await session.execute(select(Target).where(Target.url == target_url))
        target = result_obj.scalar_one_or_none()
        if target is None:
            target = Target(name=target_url, url=target_url, target_type="webapp", verified=True)
            session.add(target)
            await session.flush()

        engagement = Engagement(
            target_id=target.id,
            config={
                "max_iterations": self.max_iterations,
                "benchmark": True,
                **(config or {}),
            },
        )
        session.add(engagement)
        await session.flush()

        # Build extra_payload from config for auth cookie propagation
        extra_payload = {}
        if config and config.get("auth_cookies"):
            extra_payload["auth_cookies"] = config["auth_cookies"]
            extra_payload["auth_setup_complete"] = config.get("auth_setup_complete", True)

        engine = WorkflowEngine()
        engine.register("planner", EGATSPlanner)
        engine.register("planner_mcts", MCTSPlannerAgent)
        engine.register("recon", ReconAgent)
        engine.register("webapp", WebappAgent)
        engine.register("pentester", PentesterAgent)
        engine.register("reasoner", ReasonerAgent)
        engine.register("validation", ValidationAgent)
        engine.register("reporter", ReporterAgent)
        engine.register("research_loop", ResearchLoopAgent)

        await engine.start_engagement(
            session, engagement.id, target_url=target_url,
            extra_payload=extra_payload or None,
        )
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
        all_findings: list[dict] = []
        all_actual_findings: list[list[dict]] = []
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
            all_findings.extend(actual)
            all_actual_findings.append(actual)
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

        # Score findings with capability ladder
        cap_scores = [score_finding(f) for f in all_findings]
        cap_report = compute_overall_score(cap_scores, target_name=suite_name)

        # BountyBench / CyberGym phase-aware scoring — see run_suite
        # for the production-path equivalent.
        if suite_name in ("bountybench", "cybergym"):
            from src.benchmark.phase_scorer import (
                aggregate_bountybench_phases,
                aggregate_cybergym_poc,
                score_bountybench_phase,
                score_cybergym_poc,
            )
            if suite_name == "bountybench":
                per_case = [
                    score_bountybench_phase(
                        expected_findings=tc.get("expected_findings") or [],
                        expected_safe=bool(tc.get("expected_safe")),
                        actual_findings=actual_for_case,
                        test_case_id=tc.get("id", ""),
                    )
                    for tc, actual_for_case in zip(test_cases, all_actual_findings)
                ]
                bb_agg = aggregate_bountybench_phases(per_case, test_cases)
                run.bountybench_detect_rate = bb_agg.detect_rate
                run.bountybench_exploit_rate = bb_agg.exploit_rate
                run.bountybench_patch_rate = bb_agg.patch_rate
                run.bountybench_all_phases_rate = bb_agg.all_phases_rate
                run.bountybench_phase_detail = bb_agg.to_dict()
            else:  # cybergym
                per_case = [
                    score_cybergym_poc(tc, actual_for_case)
                    for tc, actual_for_case in zip(test_cases, all_actual_findings)
                ]
                cg_agg = aggregate_cybergym_poc(per_case, test_cases)
                run.cybergym_poc_pass_rate = cg_agg.poc_pass_rate
                run.cybergym_poc_detail = cg_agg.to_dict()
            await session.flush()

        return {
            "run": run,
            "capability": cap_report,
        }

    async def run_live(
        self,
        session: AsyncSession,
        *,
        target_names: list[str] | None = None,
        timeout_per_target: int = 300,
        config: dict | None = None,
    ) -> dict[str, Any]:
        """Run the Assurix pipeline against live Docker targets and score with capability tiers.

        Spins up Docker containers for each target, runs the full pipeline,
        scores findings using the capability ladder, and reports real metrics
        including exploit depth, time-to-exploit, and token cost.

        Falls back gracefully if Docker is unavailable (logs warning and skips).

        Args:
            session: Database session for persisting results.
            target_names: Specific targets to run (e.g. ``["juice-shop"]``).
                If ``None``, runs all targets in ``BENCHMARK_TARGETS``.
            timeout_per_target: Max seconds per target scan (default 300 = 5 min).
            config: Optional config dict stored in the BenchmarkRun.
                Supports ``use_research_loop`` and ``ab_comparison`` keys.

        Returns:
            A dict with the BenchmarkRun, per-target CapabilityReports,
            the multi-target aggregate report, and optionally MythosMetrics.
        """
        self._run_config = config or {}
        docker_mgr = DockerTargetManager()

        # Resolve which targets to run
        names = target_names or list(BENCHMARK_TARGETS.keys())
        targets: list[DockerTarget] = []
        for name in names:
            target = BENCHMARK_TARGETS.get(name)
            if target is None:
                logger.warning("Unknown benchmark target: %s (skipping)", name)
                continue
            targets.append(target)

        if not targets:
            raise ValueError(
                f"No valid targets specified. Available: {', '.join(BENCHMARK_TARGETS.keys())}"
            )

        # Create the parent BenchmarkRun record
        run = BenchmarkRun(
            suite_name="live_benchmark",
            status="running",
            config={
                **(config or {}),
                "mode": "live",
                "targets": [t.name for t in targets],
                "timeout_per_target": timeout_per_target,
            },
            started_at=datetime.now(UTC),
        )
        session.add(run)
        await session.flush()

        capability_reports: dict[str, CapabilityReport] = {}
        all_results: list[dict] = []
        mythos_metrics: dict[str, Any] | None = None

        for target in targets:
            target_url: str | None = None
            logger.info("=== Running live benchmark against %s ===", target.name)

            # --- Spin up Docker container ---
            try:
                target_url = await docker_mgr.start(target)
            except DockerUnavailableError as exc:
                logger.warning(
                    "Docker unavailable for %s: %s. Skipping.", target.name, exc
                )
                continue
            except (HealthCheckTimeoutError, Exception) as exc:
                logger.error(
                    "Failed to start %s: %s. Skipping.", target.name, exc
                )
                continue

            ab_comparison = config and config.get("ab_comparison")
            use_research_loop = config and config.get("use_research_loop")

            # --- A/B comparison mode (sequential-with-restart) ---
            if ab_comparison:
                # Phase 1: Linear pipeline run
                linear_findings: list[dict] = []
                scan_start = time.monotonic()
                try:
                    linear_findings = await self._scan_live_target(
                        target_url=target_url,
                        target_name=target.name,
                        session=session,
                        timeout=timeout_per_target,
                        config={**self._run_config, "use_research_loop": False},
                        on_timeout=lambda t=target.name: asyncio.ensure_future(docker_mgr.stop(t)),
                    )
                except Exception as exc:
                    logger.error("Linear pipeline failed for %s: %s", target.name, exc)

                # Phase 2: Stop and restart container for clean state
                try:
                    await docker_mgr.stop(target.name)
                    await asyncio.sleep(2)  # allow --rm async cleanup
                    target_url = await docker_mgr.start(target)
                except Exception as exc:
                    logger.error("A/B restart failed for %s: %s", target.name, exc)
                    run.config.setdefault("ab_failures", []).append(target.name)
                    # Score linear results and continue to next target
                    self._score_and_persist_findings(
                        linear_findings, target, run, session, capability_reports, all_results,
                    )
                    continue

                # Phase 3: ResearchLoop run
                rl_findings: list[dict] = []
                try:
                    rl_findings = await self._scan_live_target(
                        target_url=target_url,
                        target_name=target.name,
                        session=session,
                        timeout=timeout_per_target,
                        config={**self._run_config, "use_research_loop": True},
                        on_timeout=lambda t=target.name: asyncio.ensure_future(docker_mgr.stop(t)),
                    )
                except Exception as exc:
                    logger.error("ResearchLoop pipeline failed for %s: %s", target.name, exc)

                # Score RL findings (the main comparison target)
                self._score_and_persist_findings(
                    rl_findings, target, run, session, capability_reports, all_results,
                )

                # Compute Mythos metrics if ResearchLoop was used
                try:
                    mythos_metrics = self._compute_mythos_for_target(
                        rl_findings, linear_findings, target, session,
                    )
                except Exception as exc:
                    logger.warning("Mythos metrics computation failed for %s: %s", target.name, exc)

                # --- Tear down Docker container ---
                try:
                    await docker_mgr.stop(target.name)
                except Exception as exc:
                    logger.warning("Failed to stop container for %s: %s", target.name, exc)

                continue

            # --- Standard (non-A/B) pipeline ---
            scan_start = time.monotonic()
            actual_findings: list[dict] = []
            try:
                actual_findings = await self._scan_live_target(
                    target_url=target_url,
                    target_name=target.name,
                    session=session,
                    timeout=timeout_per_target,
                    config=self._run_config,
                    on_timeout=lambda t=target.name: asyncio.ensure_future(docker_mgr.stop(t)),
                )
            except Exception as exc:
                logger.error("Pipeline failed for %s: %s", target.name, exc)
            elapsed_s = time.monotonic() - scan_start

            # --- No-findings early termination: create FN rows ---
            if not actual_findings:
                logger.warning("No findings produced for %s — recording FN rows", target.name)

            # --- Score findings with capability ladder ---
            self._score_and_persist_findings(
                actual_findings, target, run, session, capability_reports, all_results,
            )

            # Compute Mythos metrics if ResearchLoop was used
            if use_research_loop:
                try:
                    mythos_metrics = self._compute_mythos_for_target(
                        actual_findings, None, target, session,
                    )
                except Exception as exc:
                    logger.warning("Mythos metrics computation failed for %s: %s", target.name, exc)

            # --- Tear down Docker container ---
            try:
                await docker_mgr.stop(target.name)
            except Exception as exc:
                logger.warning("Failed to stop container for %s: %s", target.name, exc)

        # --- Compute aggregate metrics ---
        if all_results:
            scores = overall_scores(all_results)
            run.precision = scores["precision"]
            run.recall = scores["recall"]
            run.f1 = scores["f1"]
            run.fpr = scores["fpr"]
            run.accuracy = scores["accuracy"]
            run.weighted_score = scores.get("weighted_score")
            pass_results = [bool(r.get("tp") or r.get("tn")) for r in all_results]
            run.pass_at_k_score = pass_at_k(pass_results, k=3)
            run.k_value = 3

        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await session.flush()

        multi_report = compute_multi_target_report(capability_reports)

        return {
            "run": run,
            "capability_reports": capability_reports,
            "aggregate": multi_report,
            "mythos_metrics": mythos_metrics,
        }

    def _score_and_persist_findings(
        self,
        actual_findings: list[dict],
        target: DockerTarget,
        run: BenchmarkRun,
        session: AsyncSession,
        capability_reports: dict[str, CapabilityReport],
        all_results: list[dict],
    ) -> None:
        """Score findings with capability ladder and persist BenchmarkResult rows."""
        cap_scores: list[CapabilityScore] = [
            score_finding(f) for f in actual_findings
        ]

        # Compute time-to-exploit metrics
        time_to_first_t1: float | None = None
        time_to_first_t2: float | None = None
        time_to_exploit: float | None = None
        for cs in cap_scores:
            if cs.capability_tier <= 2 and time_to_exploit is None:
                time_to_exploit = 0.0  # placeholder — real value from elapsed_s
            if cs.capability_tier == 1 and time_to_first_t1 is None:
                time_to_first_t1 = 0.0
            if cs.capability_tier <= 2 and time_to_first_t2 is None:
                time_to_first_t2 = 0.0

        unguided_success_rate = float(len(actual_findings) > 0)

        token_cost_per_t1: float | None = None
        if time_to_first_t1 is not None:
            token_cost_per_t1 = 0.0  # placeholder

        report = compute_overall_score(
            cap_scores,
            target_name=target.name,
            unguided_success_rate=unguided_success_rate,
            time_to_first_t1=time_to_first_t1,
            time_to_first_t2=time_to_first_t2,
            time_to_exploit=time_to_exploit,
            token_cost_per_t1=token_cost_per_t1,
        )
        capability_reports[target.name] = report

        # --- Persist each finding as a BenchmarkResult ---
        for cs in cap_scores:
            result_row = BenchmarkResult(
                run_id=run.id,
                test_case_id=f"live_{target.name}_{cs.finding_type}",
                category=cs.tier_name,
                expected=None,
                actual={
                    "finding_type": cs.finding_type,
                    "tier": cs.tier_label,
                    "tier_name": cs.tier_name,
                    "description": cs.description,
                    "evidence": cs.evidence,
                    "confidence": cs.confidence,
                },
                tp=cs.capability_tier <= 2,
                fp=cs.capability_tier >= 4,
                tn=False,
                fn=False,
                confidence_score=cs.confidence,
                severity_expected=None,
                severity_actual=_tier_to_severity(cs.capability_tier),
                response_time_ms=0,
                details={
                    "capability_tier": cs.capability_tier,
                    "tier_label": cs.tier_label,
                    "target": target.name,
                },
            )
            session.add(result_row)
            all_results.append({
                "tp": result_row.tp,
                "fp": result_row.fp,
                "tn": result_row.tn,
                "fn": result_row.fn,
                "category": result_row.category,
            })

        # --- No-findings case: create FN rows so aggregate scores aren't distorted ---
        if not actual_findings:
            result_row = BenchmarkResult(
                run_id=run.id,
                test_case_id=f"live_{target.name}_no_findings",
                category="none",
                expected=None,
                actual=None,
                tp=False,
                fp=False,
                tn=False,
                fn=True,
                confidence_score=0.0,
                severity_expected=None,
                severity_actual=None,
                response_time_ms=0,
                details={"target": target.name, "no_findings": True},
            )
            session.add(result_row)
            all_results.append({
                "tp": False, "fp": False, "tn": False, "fn": True, "category": "none",
            })

    async def _compute_mythos_for_target(
        self,
        rl_findings: list[dict],
        linear_findings: list[dict] | None,
        target: DockerTarget,
        session: AsyncSession,
    ) -> dict[str, Any] | None:
        """Compute Mythos metrics for a ResearchLoop run.

        Queries the DB for Hypothesis and ProvenanceLink rows to compute
        hypothesis hit rate, provenance completeness, and novel findings.
        """
        from src.benchmark.capability_scorer import compute_mythos_metrics
        from src.db.models import Hypothesis, HypothesisStatus, ProvenanceLink, Finding
        from src.db.session import get_db_session

        try:
            async with get_db_session() as mythos_session:
                from sqlalchemy import select as sa_select
                from src.db.models import Engagement, Target as TargetModel

                tgt_result = await mythos_session.execute(
                    sa_select(TargetModel).where(TargetModel.name == target.name)
                )
                tgt = tgt_result.scalar_one_or_none()
                if not tgt:
                    return None

                eng_result = await mythos_session.execute(
                    sa_select(Engagement)
                    .where(Engagement.target_id == tgt.id)
                    .order_by(Engagement.started_at.desc())
                    .limit(1)
                )
                engagement = eng_result.scalar_one_or_none()
                if not engagement:
                    return None

                # Query hypotheses
                hyp_rows = await mythos_session.execute(
                    sa_select(Hypothesis).where(
                        Hypothesis.engagement_id == engagement.id
                    )
                )
                hypotheses = list(hyp_rows.scalars().all())

                # Query findings
                find_rows = await mythos_session.execute(
                    sa_select(Finding).where(
                        Finding.engagement_id == engagement.id
                    )
                )
                db_findings = list(find_rows.scalars().all())

                # Query provenance links
                finding_ids = [f.id for f in db_findings]
                if finding_ids:
                    link_rows = await mythos_session.execute(
                        sa_select(ProvenanceLink).where(
                            ProvenanceLink.finding_id.in_(finding_ids)
                        )
                    )
                    provenance_links = list(link_rows.scalars().all())
                else:
                    provenance_links = []

                research_iterations = engagement.config.get("research_iterations", 0)

                metrics = compute_mythos_metrics(
                    hypotheses=hypotheses,
                    findings=db_findings,
                    provenance_links=provenance_links,
                    linear_findings=linear_findings,
                    research_iterations=research_iterations,
                )
                return {
                    "hypothesis_hit_rate": metrics.hypothesis_hit_rate,
                    "provenance_chain_completeness": metrics.provenance_chain_completeness,
                    "novel_findings_vs_linear": metrics.novel_findings_vs_linear,
                    "research_iterations": metrics.research_iterations,
                    "confirmed_hypotheses": metrics.confirmed_hypotheses,
                    "hit_rate_pass": metrics.hit_rate_pass,
                    "provenance_pass": metrics.provenance_pass,
                    "novel_pass": metrics.novel_pass,
                    "reflection_pass": metrics.reflection_pass,
                    "overall_pass": metrics.overall_pass,
                }
        except Exception as exc:
            logger.warning("Mythos metrics computation error for %s: %s", target.name, exc)
            return None

    async def _scan_live_target(
        self,
        target_url: str,
        target_name: str,
        session: AsyncSession,
        timeout: int = 300,
        config: dict | None = None,
        on_timeout: Any | None = None,
    ) -> list[dict]:
        """Run the full Assurix pipeline against a live target and return findings.

        Args:
            target_url: URL of the live target.
            target_name: Name of the target (e.g. 'dvwa', 'juice-shop').
            session: Database session.
            timeout: Maximum seconds before hard timeout.
            config: Optional config dict merged into engagement.config.
                Supports ``use_research_loop`` and ``auth_cookies`` keys.
            on_timeout: Optional async callback invoked when timeout expires
                (e.g., to kill the Docker container).  Preserves URL-agnostic design.
        """
        from src.db.models import Engagement, Finding, Target
        from src.db.session import get_db_session
        from src.orchestrator.engine import WorkflowEngine
        from src.agents.planner_egats import EGATSPlanner
        from src.agents.planner_mcts import MCTSPlannerAgent
        from src.agents.reasoner import ReasonerAgent
        from src.agents.recon import ReconAgent
        from src.agents.reporter import ReporterAgent
        from src.agents.validation import ValidationAgent
        from src.agents.webapp import WebappAgent
        from src.agents.pentester import PentesterAgent
        from src.agents.research_loop import ResearchLoopAgent

        # Ensure a Target row exists
        result_obj = await session.execute(
            select(Target).where(Target.url == target_url)
        )
        target = result_obj.scalar_one_or_none()
        if target is None:
            target = Target(
                name=target_name, url=target_url, target_type="webapp", verified=True
            )
            session.add(target)
            await session.flush()

        # DVWA: authenticate and set security level before scanning
        extra_payload: dict[str, Any] = {}
        if target_name == "dvwa":
            try:
                from src.benchmark.target_setup import setup_dvwa
                cookies = await setup_dvwa(target_url)
                extra_payload["auth_cookies"] = cookies
                extra_payload["auth_setup_complete"] = True
                logger.info("DVWA auth complete for %s", target_url)
            except Exception as exc:
                logger.warning("DVWA setup failed for %s: %s", target_url, exc)

        engagement = Engagement(
            target_id=target.id,
            config={
                "max_iterations": self.max_iterations,
                "benchmark": True,
                "target_name": target_name,
                **(config or {}),
            },
        )
        session.add(engagement)
        await session.flush()

        engine = WorkflowEngine()
        engine.register("planner", EGATSPlanner)
        engine.register("planner_mcts", MCTSPlannerAgent)
        engine.register("recon", ReconAgent)
        engine.register("webapp", WebappAgent)
        engine.register("pentester", PentesterAgent)
        engine.register("reasoner", ReasonerAgent)
        engine.register("validation", ValidationAgent)
        engine.register("reporter", ReporterAgent)
        engine.register("research_loop", ResearchLoopAgent)

        await engine.start_engagement(
            session, engagement.id, target_url=target_url,
            extra_payload=extra_payload or None,
        )
        engine.start()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            async with get_db_session() as check_session:
                eng = await check_session.get(Engagement, engagement.id)
                if eng and eng.status in ("completed", "failed"):
                    break
        else:
            logger.warning(
                "Timeout on %s (%s). Stopping engine and killing container.",
                target_name, engagement.id,
            )
            await engine.stop()
            if on_timeout:
                try:
                    await on_timeout()
                except Exception as exc:
                    logger.warning("on_timeout callback failed for %s: %s", target_name, exc)

        await engine.stop()

        async with get_db_session() as fs:
            rows = await fs.execute(
                select(Finding).where(Finding.engagement_id == engagement.id)
            )
            findings = rows.scalars().all()

        return [
            {
                "title": f.title,
                "severity": f.severity,
                "cwe_id": f.cwe_id,
                "confidence_score": f.confidence_score,
                "description": f.description,
                "source_agent": f.source_agent,
            }
            for f in findings
        ]

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


def _tier_to_severity(tier: int) -> str:
    """Map a capability tier to a severity label for the BenchmarkResult row."""
    mapping = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
    return mapping.get(tier, "info")
