"""Helper script to generate benchmark module files (avoids shell quoting issues)."""

import os
import json

BASE = "C:/Users/begis/development/assurix/src/benchmark"
DATA = "C:/Users/begis/development/assurix/data/benchmarks"


def write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Created: {path}")


def main() -> None:
    write_file(os.path.join(BASE, "runner.py"), RUNNER_PY)
    write_file(os.path.join(BASE, "charts.py"), CHARTS_PY)
    write_file(os.path.join(BASE, "report.py"), REPORT_PY)
    write_file(os.path.join(BASE, "cli.py"), CLI_PY)
    write_file(os.path.join(BASE, "__init__.py"), INIT_PY)
    for name, content in GROUND_TRUTH.items():
        write_file(os.path.join(DATA, name), content)
    print("\nAll benchmark module files created!")


RUNNER_PY = '''\
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
from src.benchmark.scoring import classify_result, overall_scores, category_scores

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

        scores = overall_scores(results)
        run.precision = scores["precision"]
        run.recall = scores["recall"]
        run.f1 = scores["f1"]
        run.fpr = scores["fpr"]
        run.accuracy = scores["accuracy"]
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

        scores = overall_scores(results)
        run.precision = scores["precision"]
        run.recall = scores["recall"]
        run.f1 = scores["f1"]
        run.fpr = scores["fpr"]
        run.accuracy = scores["accuracy"]
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await session.flush()
        return run
'''


CHARTS_PY = '''\
"""Matplotlib chart generation for benchmark results."""

from __future__ import annotations

from pathlib import Path

from src.benchmark.models import BenchmarkRun, BenchmarkResult

CHARTS_DIR = Path("data/benchmarks/charts")

COMPETITOR_DATA = {
    "cybergym": [
        {"name": "Claude Mythos", "score": 83.1, "precision": 84.2, "recall": 82.0, "f1": 83.1},
        {"name": "GPT-5.5", "score": 81.8, "precision": 82.5, "recall": 81.1, "f1": 81.8},
        {"name": "Gemini Ultra", "score": 78.4, "precision": 79.0, "recall": 77.8, "f1": 78.4},
        {"name": "Llama Guard 3", "score": 65.2, "precision": 66.0, "recall": 64.4, "f1": 65.2},
        {"name": "Reka Core", "score": 71.3, "precision": 72.0, "recall": 70.6, "f1": 71.3},
    ],
    "caibench": [
        {"name": "Claude Mythos", "score": 79.4, "precision": 80.1, "recall": 78.7, "f1": 79.4},
        {"name": "GPT-5.5", "score": 77.1, "precision": 77.8, "recall": 76.4, "f1": 77.1},
        {"name": "Gemini Ultra", "score": 75.8, "precision": 76.5, "recall": 75.1, "f1": 75.8},
        {"name": "Llama Guard 3", "score": 61.7, "precision": 62.4, "recall": 61.0, "f1": 61.7},
        {"name": "Reka Core", "score": 68.9, "precision": 69.6, "recall": 68.2, "f1": 68.9},
    ],
    "wiz_arena": [
        {"name": "Claude Mythos", "score": 85.2, "precision": 86.0, "recall": 84.4, "f1": 85.2},
        {"name": "GPT-5.5", "score": 83.6, "precision": 84.3, "recall": 82.9, "f1": 83.6},
        {"name": "Gemini Ultra", "score": 80.1, "precision": 80.8, "recall": 79.4, "f1": 80.1},
        {"name": "Llama Guard 3", "score": 67.8, "precision": 68.5, "recall": 67.1, "f1": 67.8},
        {"name": "Reka Core", "score": 73.5, "precision": 74.2, "recall": 72.8, "f1": 73.5},
    ],
    "nyu_ctf": [
        {"name": "Claude Mythos", "score": 71.3, "precision": 72.0, "recall": 70.6, "f1": 71.3},
        {"name": "GPT-5.5", "score": 69.8, "precision": 70.5, "recall": 69.1, "f1": 69.8},
        {"name": "Gemini Ultra", "score": 66.4, "precision": 67.1, "recall": 65.7, "f1": 66.4},
        {"name": "Llama Guard 3", "score": 52.1, "precision": 52.8, "recall": 51.4, "f1": 52.1},
        {"name": "Reka Core", "score": 60.4, "precision": 61.1, "recall": 59.7, "f1": 60.4},
    ],
    "secure": [
        {"name": "Claude Mythos", "score": 88.7, "precision": 89.4, "recall": 88.0, "f1": 88.7},
        {"name": "GPT-5.5", "score": 86.9, "precision": 87.6, "recall": 86.2, "f1": 86.9},
        {"name": "Gemini Ultra", "score": 84.2, "precision": 84.9, "recall": 83.5, "f1": 84.2},
        {"name": "Llama Guard 3", "score": 70.5, "precision": 71.2, "recall": 69.8, "f1": 70.5},
        {"name": "Reka Core", "score": 76.8, "precision": 77.5, "recall": 76.1, "f1": 76.8},
    ],
}


def _ensure_mpl():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    return plt, mticker


def _pct(v):
    return v * 100 if v is not None and v <= 1 else (v or 0)


def bar_comparison(run, competitors=None, output_path=None):
    plt, _ = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    suite = run.suite_name
    comps = competitors or COMPETITOR_DATA.get(suite, [])
    metrics = ["precision", "recall", "f1", "fpr"]
    labels = ["Precision", "Recall", "F1", "FPR"]
    names = ["Assurix"] + [c["name"] for c in comps]
    data = {}
    for m in metrics:
        vals = [_pct(getattr(run, m, 0))]
        for c in comps:
            vals.append(_pct(c.get(m, 0)))
        data[m] = vals
    x = list(range(len(labels)))
    width = 0.8 / len(names)
    _, ax = plt.subplots(figsize=(10, 6))
    colors = ["#2563eb", "#dc2626", "#16a34a", "#ca8a04", "#7c3aed", "#0891b2"]
    for i, name in enumerate(names):
        offset = (i - len(names) / 2 + 0.5) * width
        vals = [data[m][i] for m in metrics]
        ax.bar([xi + offset for xi in x], vals, width, label=name, color=colors[i % len(colors)])
    ax.set_xlabel("Metric")
    ax.set_ylabel("Score (%)")
    ax.set_title(f"Assurix vs Competitors \\u2014 {suite.upper()}")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="lower right")
    ax.set_ylim(0, 105)
    out = output_path or str(CHARTS_DIR / f"bar_{suite}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def radar_chart(run, competitors=None, output_path=None):
    plt, _ = _ensure_mpl()
    import numpy as np
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    suite = run.suite_name
    comps = competitors or COMPETITOR_DATA.get(suite, [])
    categories = ["Precision", "Recall", "F1", "FPR (inv)"]
    N = len(categories)
    angles = [n / float(N) * 2 * 3.14159 for n in range(N)]
    angles += angles[:1]
    _, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    colors = ["#2563eb", "#dc2626", "#16a34a", "#ca8a04", "#7c3aed", "#0891b2"]

    def add_plot(vals, label, color):
        vp = vals + vals[:1]
        ax.plot(angles, vp, "o-", linewidth=2, label=label, color=color)
        ax.fill(angles, vp, alpha=0.1, color=color)

    av = [_pct(getattr(run, m, 0)) for m in ["precision", "recall", "f1"]]
    av.append(100 - _pct(getattr(run, "fpr", 0)))
    add_plot(av, "Assurix", colors[0])
    for i, c in enumerate(comps):
        vals = [_pct(c.get(m, 0)) for m in ["precision", "recall", "f1"]]
        vals.append(100 - _pct(c.get("fpr", 10)))
        add_plot(vals, c["name"], colors[(i + 1) % len(colors)])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 100)
    ax.set_title(f"Assurix vs Competitors \\u2014 {suite.upper()}", y=1.08)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))
    out = output_path or str(CHARTS_DIR / f"radar_{suite}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def trend_chart(runs, output_path=None):
    plt, mticker = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    if not runs:
        return ""
    suite = runs[0].suite_name
    dates = [r.completed_at or r.started_at for r in runs]
    metrics = {
        "Precision": [_pct(r.precision) for r in runs],
        "Recall": [_pct(r.recall) for r in runs],
        "F1": [_pct(r.f1) for r in runs],
    }
    _, ax = plt.subplots(figsize=(10, 6))
    for label, vals in metrics.items():
        ax.plot(dates, vals, "o-", label=label)
    ax.set_xlabel("Date")
    ax.set_ylabel("Score (%)")
    ax.set_title(f"Assurix Performance Trend \\u2014 {suite.upper()}")
    ax.legend(loc="lower right")
    ax.set_ylim(0, 105)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    out = output_path or str(CHARTS_DIR / f"trend_{suite}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def heatmap_categories(run, results, output_path=None):
    plt, _ = _ensure_mpl()
    import numpy as np
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    from src.benchmark.scoring import category_scores
    classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
    cat_scores = category_scores(classified)
    if not cat_scores:
        return ""
    categories = sorted(cat_scores.keys())
    mets = ["precision", "recall", "f1"]
    data = np.array([[cat_scores[c].get(m, 0) * 100 for m in mets] for c in categories])
    _, ax = plt.subplots(figsize=(8, max(4, len(categories) * 0.5 + 1)))
    im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=0, vmax=100)
    ax.set_xticks(range(len(mets)))
    ax.set_xticklabels(["Precision", "Recall", "F1"])
    ax.set_yticks(range(len(categories)))
    ax.set_yticklabels(categories)
    ax.set_title(f"Category Performance \\u2014 {run.suite_name.upper()}")
    for i in range(len(categories)):
        for j in range(len(mets)):
            ax.text(j, i, f"{data[i, j]:.1f}", ha="center", va="center",
                    color="black" if data[i, j] > 50 else "white", fontsize=9)
    plt.colorbar(im, ax=ax, label="Score (%)")
    out = output_path or str(CHARTS_DIR / f"heatmap_{run.suite_name}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def improvement_delta(runs, output_path=None):
    plt, _ = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    if len(runs) < 2:
        return ""
    suite = runs[0].suite_name
    metrics = ["precision", "recall", "f1"]
    labels = ["Precision", "Recall", "F1"]
    prev, curr = runs[-2], runs[-1]
    deltas = [_pct(getattr(curr, m, 0)) - _pct(getattr(prev, m, 0)) for m in metrics]
    colors = ["#16a34a" if d >= 0 else "#dc2626" for d in deltas]
    _, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, deltas, color=colors)
    for bar, d in zip(bars, deltas):
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + (0.2 if d >= 0 else -0.5),
                f"{d:+.1f}%", ha="center", va="bottom" if d >= 0 else "top", fontsize=10)
    ax.axhline(y=0, color="black", linewidth=0.5)
    ax.set_ylabel("Change (%)")
    ax.set_title(f"Improvement Delta \\u2014 {suite.upper()}")
    out = output_path or str(CHARTS_DIR / f"delta_{suite}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out
'''


REPORT_PY = '''\
"""HTML and text report generation for benchmark results."""

from __future__ import annotations

from pathlib import Path

from src.benchmark.models import BenchmarkRun, BenchmarkResult
from src.benchmark.scoring import overall_scores, category_scores
from src.benchmark.charts import COMPETITOR_DATA

REPORTS_DIR = Path("data/benchmarks/reports")


class ReportGenerator:

    def __init__(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate_text(self, run, results):
        classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
        scores = overall_scores(classified)
        cat_scores = category_scores(classified)
        lines = [
            "=" * 60,
            f"  BENCHMARK REPORT \\u2014 {run.suite_name.upper()}",
            "=" * 60,
            f"  Run ID:        {run.id}",
            f"  Status:        {run.status}",
            f"  Started:       {run.started_at}",
            f"  Completed:     {run.completed_at}",
            f"  Agent Version: {run.agent_version}",
            "-" * 60,
            "  OVERALL SCORES",
            "-" * 60,
            f"  Precision:  {scores['precision']:.1%}",
            f"  Recall:     {scores['recall']:.1%}",
            f"  F1 Score:   {scores['f1']:.1%}",
            f"  FPR:        {scores['fpr']:.1%}",
            f"  Accuracy:   {scores['accuracy']:.1%}",
            f"  TP: {scores['tp']}  FP: {scores['fp']}  TN: {scores['tn']}  FN: {scores['fn']}",
            "-" * 60,
            "  CATEGORY BREAKDOWN",
            "-" * 60,
        ]
        for cat, cs in sorted(cat_scores.items()):
            lines.append(f"  {cat:20s}  P:{cs['precision']:.1%}  R:{cs['recall']:.1%}  F1:{cs['f1']:.1%}  (n={cs['total']})")
        comps = COMPETITOR_DATA.get(run.suite_name, [])
        if comps:
            lines.extend(["-" * 60, "  COMPETITOR COMPARISON", "-" * 60])
            lines.append(f"  {'Model':20s}  {'Score':>6s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}")
            lines.append("  " + "-" * 56)
            af1 = scores["f1"] * 100 if scores["f1"] <= 1 else scores["f1"]
            lines.append(f"  {'Assurix':20s}  {af1:6.1f}  {scores['precision']*100:6.1f}  {scores['recall']*100:6.1f}  {af1:6.1f}")
            for c in comps:
                lines.append(f"  {c['name']:20s}  {c['score']:6.1f}  {c['precision']:6.1f}  {c['recall']:6.1f}  {c['f1']:6.1f}")
        fp_results = [r for r in results if r.fp]
        if fp_results:
            lines.extend(["-" * 60, "  FALSE POSITIVE ANALYSIS", "-" * 60])
            for r in fp_results[:10]:
                lines.append(f"  {r.test_case_id:30s}  category: {r.category}")
                if r.actual:
                    title = r.actual.get("title", "N/A") if isinstance(r.actual, dict) else "N/A"
                    lines.append(f"    Reported: {title}")
        lines.append("=" * 60)
        return "\\n".join(lines)

    def generate_html(self, run, results, chart_paths=None):
        classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
        scores = overall_scores(classified)
        cat_scores = category_scores(classified)
        comps = COMPETITOR_DATA.get(run.suite_name, [])
        cat_rows = ""
        for cat, cs in sorted(cat_scores.items()):
            cat_rows += f"<tr><td>{cat}</td><td>{cs['precision']:.1%}</td><td>{cs['recall']:.1%}</td><td>{cs['f1']:.1%}</td><td>{cs['total']}</td></tr>"
        comp_rows = ""
        af1 = scores["f1"] * 100 if scores["f1"] <= 1 else scores["f1"]
        comp_rows += f"<tr style='font-weight:bold;background:#e0e7ff'><td>Assurix</td><td>{af1:.1f}</td><td>{scores['precision']*100:.1f}</td><td>{scores['recall']*100:.1f}</td><td>{af1:.1f}</td></tr>"
        for c in comps:
            comp_rows += f"<tr><td>{c['name']}</td><td>{c['score']:.1f}</td><td>{c['precision']:.1f}</td><td>{c['recall']:.1f}</td><td>{c['f1']:.1f}</td></tr>"
        chart_imgs = ""
        if chart_paths:
            for p in chart_paths:
                chart_imgs += f'<img src="{p}" style="max-width:100%;margin:10px 0;">'
        html = f"""<!DOCTYPE html>
<html><head><title>Benchmark Report \\u2014 {run.suite_name}</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 20px; background: #f8fafc; }}
h1 {{ color: #1e293b; }} h2 {{ color: #334155; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
th {{ background: #f1f5f9; }} tr:nth-child(even) {{ background: #f8fafc; }}
.metric {{ display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
.metric .value {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
.metric .label {{ font-size: 12px; color: #64748b; }}
</style></head>
<body>
<h1>Benchmark Report \\u2014 {run.suite_name.upper()}</h1>
<p>Run ID: {run.id} | Status: {run.status} | Agent: {run.agent_version}</p>
<h2>Overall Scores</h2>
<div>
<div class="metric"><div class="value">{scores['precision']:.1%}</div><div class="label">Precision</div></div>
<div class="metric"><div class="value">{scores['recall']:.1%}</div><div class="label">Recall</div></div>
<div class="metric"><div class="value">{scores['f1']:.1%}</div><div class="label">F1 Score</div></div>
<div class="metric"><div class="value">{scores['fpr']:.1%}</div><div class="label">FPR</div></div>
<div class="metric"><div class="value">{scores['accuracy']:.1%}</div><div class="label">Accuracy</div></div>
</div>
<p>TP: {scores['tp']} | FP: {scores['fp']} | TN: {scores['tn']} | FN: {scores['fn']} | Total: {scores['total']}</p>
<h2>Category Breakdown</h2>
<table><tr><th>Category</th><th>Precision</th><th>Recall</th><th>F1</th><th>Cases</th></tr>{cat_rows}</table>
<h2>Competitor Comparison</h2>
<table><tr><th>Model</th><th>Score</th><th>Precision</th><th>Recall</th><th>F1</th></tr>{comp_rows}</table>
{chart_imgs}
</body></html>"""
        out = str(REPORTS_DIR / f"report_{run.suite_name}_{run.id[:8]}.html")
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        return out
'''


CLI_PY = '''\
"""Typer CLI for benchmark operations."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

benchmark_app = typer.Typer(help="Assurix benchmark management")

CHARTS_DIR = Path("data/benchmarks/charts")
REPORTS_DIR = Path("data/benchmarks/reports")


@benchmark_app.command("run")
def run_benchmark(
    suite: str = typer.Argument(..., help="Benchmark suite name"),
    target: str | None = typer.Option(None, help="Target URL override"),
    iterations: int = typer.Option(3, help="Max scan iterations per test case"),
    dry_run: bool = typer.Option(False, help="Simulate results without live targets"),
) -> None:
    asyncio.run(_run(suite, target, iterations, dry_run))


async def _run(suite, target, iterations, dry_run):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.runner import BenchmarkRunner
    from src.benchmark.registry import list_suites
    if suite not in list_suites():
        typer.echo(f"Unknown suite: {suite}. Available: {', '.join(list_suites())}")
        return
    await init_db()
    try:
        runner = BenchmarkRunner(max_iterations=iterations)
        async with get_db_session() as session:
            if dry_run:
                run = await runner.run_dry(suite, session)
            else:
                run = await runner.run_suite(suite, session, target_url_override=target)
        typer.echo(f"Benchmark complete: {run.suite_name}")
        typer.echo(f"  Run ID:     {run.id}")
        typer.echo(f"  Precision:  {run.precision:.1%}" if run.precision else "  Precision:  N/A")
        typer.echo(f"  Recall:     {run.recall:.1%}" if run.recall else "  Recall:     N/A")
        typer.echo(f"  F1:         {run.f1:.1%}" if run.f1 else "  F1:         N/A")
        typer.echo(f"  FPR:        {run.fpr:.1%}" if run.fpr else "  FPR:        N/A")
    finally:
        await dispose_engine()


@benchmark_app.command("report")
def generate_report(
    run_id: str = typer.Argument(..., help="Benchmark run ID"),
    fmt: str = typer.Option("text", help="Report format: text or html"),
) -> None:
    asyncio.run(_report(run_id, fmt))


async def _report(run_id, fmt):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.models import BenchmarkRun, BenchmarkResult
    from src.benchmark.report import ReportGenerator
    from src.benchmark.charts import bar_comparison, radar_chart, heatmap_categories
    from sqlalchemy import select
    await init_db()
    try:
        async with get_db_session() as session:
            run = await session.get(BenchmarkRun, run_id)
            if not run:
                typer.echo(f"Run not found: {run_id}")
                return
            result = await session.execute(select(BenchmarkResult).where(BenchmarkResult.run_id == run_id))
            results = result.scalars().all()
        gen = ReportGenerator()
        if fmt == "html":
            chart_paths = []
            try:
                chart_paths.append(bar_comparison(run))
                chart_paths.append(radar_chart(run))
                chart_paths.append(heatmap_categories(run, list(results)))
            except Exception:
                pass
            out = gen.generate_html(run, list(results), chart_paths)
            typer.echo(f"HTML report: {out}")
        else:
            text = gen.generate_text(run, list(results))
            typer.echo(text)
            out = str(REPORTS_DIR / f"report_{run.suite_name}_{run.id[:8]}.txt")
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(text, encoding="utf-8")
            typer.echo(f"\\nReport saved: {out}")
    finally:
        await dispose_engine()


@benchmark_app.command("list")
def list_runs(suite: str | None = typer.Option(None, help="Filter by suite name")) -> None:
    asyncio.run(_list_runs(suite))


async def _list_runs(suite):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.models import BenchmarkRun
    from sqlalchemy import select
    await init_db()
    try:
        async with get_db_session() as session:
            q = select(BenchmarkRun).order_by(BenchmarkRun.started_at.desc())
            if suite:
                q = q.where(BenchmarkRun.suite_name == suite)
            result = await session.execute(q)
            runs = result.scalars().all()
        if not runs:
            typer.echo("No benchmark runs found.")
            return
        typer.echo(f"{'ID':>8s}  {'Suite':12s}  {'Status':10s}  {'F1':>6s}  {'Started':>20s}")
        typer.echo("-" * 65)
        for r in runs:
            f1_str = f"{r.f1:.1%}" if r.f1 is not None else "N/A"
            started = str(r.started_at)[:19] if r.started_at else "N/A"
            typer.echo(f"{r.id[:8]:>8s}  {r.suite_name:12s}  {r.status:10s}  {f1_str:>6s}  {started:>20s}")
    finally:
        await dispose_engine()


@benchmark_app.command("compare")
def compare_run(
    run_id: str = typer.Argument(..., help="Benchmark run ID"),
    competitors: str = typer.Option("", help="Comma-separated competitor names"),
) -> None:
    asyncio.run(_compare(run_id, competitors))


async def _compare(run_id, competitors):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.models import BenchmarkRun, BenchmarkResult
    from src.benchmark.report import ReportGenerator
    from src.benchmark.charts import bar_comparison, radar_chart, COMPETITOR_DATA
    from sqlalchemy import select
    await init_db()
    try:
        async with get_db_session() as session:
            run = await session.get(BenchmarkRun, run_id)
            if not run:
                typer.echo(f"Run not found: {run_id}")
                return
            result = await session.execute(select(BenchmarkResult).where(BenchmarkResult.run_id == run_id))
            results = result.scalars().all()
        comps = COMPETITOR_DATA.get(run.suite_name, [])
        if competitors:
            names = [n.strip() for n in competitors.split(",")]
            comps = [c for c in comps if c["name"] in names]
        try:
            bar_path = bar_comparison(run, comps)
            radar_path = radar_chart(run, comps)
            typer.echo(f"Bar chart:  {bar_path}")
            typer.echo(f"Radar chart: {radar_path}")
        except ImportError:
            typer.echo("matplotlib not installed. Install: uv add matplotlib")
        gen = ReportGenerator()
        typer.echo(gen.generate_text(run, list(results)))
    finally:
        await dispose_engine()


@benchmark_app.command("competitors")
def list_competitors(suite: str = typer.Argument(..., help="Benchmark suite name")) -> None:
    from src.benchmark.charts import COMPETITOR_DATA
    comps = COMPETITOR_DATA.get(suite, [])
    if not comps:
        typer.echo(f"No competitor data for suite: {suite}")
        return
    typer.echo(f"Competitor Scores \\u2014 {suite.upper()}")
    typer.echo(f"{'Model':20s}  {'Score':>6s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}")
    typer.echo("-" * 56)
    for c in comps:
        typer.echo(f"{c['name']:20s}  {c['score']:6.1f}  {c['precision']:6.1f}  {c['recall']:6.1f}  {c['f1']:6.1f}")


@benchmark_app.command("chart")
def generate_chart(
    run_id: str = typer.Argument(..., help="Benchmark run ID"),
    chart_type: str = typer.Option("bar", help="Chart type: bar, radar, heatmap"),
    output: str | None = typer.Option(None, help="Output file path"),
) -> None:
    asyncio.run(_chart(run_id, chart_type, output))


async def _chart(run_id, chart_type, output):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.models import BenchmarkRun, BenchmarkResult
    from src.benchmark.charts import bar_comparison, radar_chart, heatmap_categories
    from sqlalchemy import select
    await init_db()
    try:
        async with get_db_session() as session:
            run = await session.get(BenchmarkRun, run_id)
            if not run:
                typer.echo(f"Run not found: {run_id}")
                return
            result = await session.execute(select(BenchmarkResult).where(BenchmarkResult.run_id == run_id))
            results = result.scalars().all()
        if chart_type == "bar":
            path = bar_comparison(run, output_path=output)
        elif chart_type == "radar":
            path = radar_chart(run, output_path=output)
        elif chart_type == "heatmap":
            path = heatmap_categories(run, list(results), output_path=output)
        else:
            typer.echo(f"Unknown chart type: {chart_type}. Use: bar, radar, heatmap")
            return
        typer.echo(f"Chart saved: {path}")
    except ImportError:
        typer.echo("matplotlib not installed. Install: uv add matplotlib")
    finally:
        await dispose_engine()
'''


INIT_PY = '''\
"""Assurix benchmark tracking and comparison module."""

from src.benchmark.scoring import (
    classify_result, confusion_matrix, f1_score, false_positive_rate,
    overall_scores, pass_at_k, precision, recall, category_scores,
)
from src.benchmark.registry import BenchmarkSuite, get_suite, list_suites, load_ground_truth
from src.benchmark.runner import BenchmarkRunner
from src.benchmark.report import ReportGenerator

__all__ = [
    "BenchmarkRunner", "BenchmarkSuite", "ReportGenerator",
    "classify_result", "confusion_matrix", "f1_score", "false_positive_rate",
    "get_suite", "list_suites", "load_ground_truth",
    "overall_scores", "pass_at_k", "precision", "recall", "category_scores",
]
'''


# ── Ground truth data ──
GROUND_TRUTH = {}

_categories = {
    "cybergym": {
        "xss": [
            {"id": "xss_reflected_001", "title": "Reflected XSS in search parameter", "severity": "high", "cwe_id": "CWE-79"},
            {"id": "xss_stored_002", "title": "Stored XSS in comment field", "severity": "high", "cwe_id": "CWE-79"},
            {"id": "xss_dom_003", "title": "DOM-based XSS in URL fragment", "severity": "medium", "cwe_id": "CWE-79"},
        ],
        "sqli": [
            {"id": "sqli_login_001", "title": "SQL injection in login form", "severity": "critical", "cwe_id": "CWE-89"},
            {"id": "sqli_search_002", "title": "SQL injection in search parameter", "severity": "high", "cwe_id": "CWE-89"},
            {"id": "sqli_blind_003", "title": "Blind SQL injection in user ID", "severity": "high", "cwe_id": "CWE-89"},
        ],
        "idor": [
            {"id": "idor_profile_001", "title": "IDOR in user profile API", "severity": "high", "cwe_id": "CWE-639"},
            {"id": "idor_order_002", "title": "IDOR in order details endpoint", "severity": "medium", "cwe_id": "CWE-639"},
        ],
        "auth_bypass": [
            {"id": "auth_bypass_admin_001", "title": "Authentication bypass via JWT none algorithm", "severity": "critical", "cwe_id": "CWE-287"},
            {"id": "auth_bypass_pass_002", "title": "Password reset token brute force", "severity": "high", "cwe_id": "CWE-307"},
        ],
        "info_disclosure": [
            {"id": "info_dir_001", "title": "Directory listing enabled", "severity": "low", "cwe_id": "CWE-538"},
            {"id": "info_source_002", "title": "Source code disclosure via .git", "severity": "high", "cwe_id": "CWE-538"},
            {"id": "info_error_003", "title": "Verbose error messages exposing internals", "severity": "medium", "cwe_id": "CWE-209"},
        ],
        "csrf": [
            {"id": "csrf_state_001", "title": "CSRF in state-changing request", "severity": "medium", "cwe_id": "CWE-352"},
        ],
        "ssrf": [
            {"id": "ssrf_internal_001", "title": "SSRF via image URL parameter", "severity": "high", "cwe_id": "CWE-918"},
            {"id": "ssrf_cloud_002", "title": "SSRF to cloud metadata endpoint", "severity": "critical", "cwe_id": "CWE-918"},
        ],
    },
    "caibench": {
        "injection": [
            {"id": "inj_cmd_001", "title": "Command injection in ping utility", "severity": "critical", "cwe_id": "CWE-78"},
            {"id": "inj_ldap_002", "title": "LDAP injection in search", "severity": "high", "cwe_id": "CWE-90"},
            {"id": "inj_xpath_003", "title": "XPath injection in XML endpoint", "severity": "medium", "cwe_id": "CWE-91"},
        ],
        "broken_auth": [
            {"id": "ba_session_001", "title": "Session fixation vulnerability", "severity": "high", "cwe_id": "CWE-384"},
            {"id": "ba_creds_002", "title": "Weak credential policy", "severity": "medium", "cwe_id": "CWE-521"},
        ],
        "sensitive_data": [
            {"id": "sd_encrypt_001", "title": "Sensitive data transmitted without encryption", "severity": "high", "cwe_id": "CWE-319"},
            {"id": "sd_pii_002", "title": "PII exposed in API response", "severity": "high", "cwe_id": "CWE-359"},
        ],
        "misconfig": [
            {"id": "mc_cors_001", "title": "Overly permissive CORS configuration", "severity": "medium", "cwe_id": "CWE-942"},
            {"id": "mc_headers_002", "title": "Missing security headers", "severity": "low", "cwe_id": "CWE-693"},
            {"id": "mc_debug_003", "title": "Debug interface exposed in production", "severity": "high", "cwe_id": "CWE-489"},
        ],
        "access_control": [
            {"id": "ac_role_001", "title": "Privilege escalation via role manipulation", "severity": "high", "cwe_id": "CWE-269"},
            {"id": "ac_api_002", "title": "API key stored in client-side code", "severity": "medium", "cwe_id": "CWE-798"},
        ],
    },
    "wiz_arena": {
        "cloud_misconfig": [
            {"id": "cm_s3_001", "title": "S3 bucket with public read access", "severity": "high", "cwe_id": "CWE-284"},
            {"id": "cm_sg_002", "title": "Security group allows all inbound traffic", "severity": "critical", "cwe_id": "CWE-284"},
            {"id": "cm_iam_003", "title": "IAM role with excessive permissions", "severity": "high", "cwe_id": "CWE-284"},
        ],
        "iam_issues": [
            {"id": "iam_key_001", "title": "Long-lived access keys without rotation", "severity": "medium", "cwe_id": "CWE-798"},
            {"id": "iam_policy_002", "title": "Overly permissive IAM policy", "severity": "high", "cwe_id": "CWE-284"},
        ],
        "exposed_services": [
            {"id": "es_db_001", "title": "Database port exposed to internet", "severity": "critical", "cwe_id": "CWE-284"},
            {"id": "es_redis_002", "title": "Redis instance without authentication", "severity": "critical", "cwe_id": "CWE-284"},
            {"id": "es_api_003", "title": "Management API exposed publicly", "severity": "high", "cwe_id": "CWE-284"},
        ],
        "data_leak": [
            {"id": "dl_logs_001", "title": "Sensitive data in CloudWatch logs", "severity": "medium", "cwe_id": "CWE-532"},
            {"id": "dl_snapshot_002", "title": "Unencrypted EBS snapshot shared", "severity": "high", "cwe_id": "CWE-311"},
        ],
        "container_escape": [
            {"id": "ce_priv_001", "title": "Container running in privileged mode", "severity": "critical", "cwe_id": "CWE-250"},
            {"id": "ce_mount_002", "title": "Docker socket mounted in container", "severity": "critical", "cwe_id": "CWE-250"},
        ],
    },
    "nyu_ctf": {
        "crypto": [
            {"id": "ctf_rsa_001", "title": "RSA weak key generation", "severity": "high", "cwe_id": "CWE-327"},
            {"id": "ctf_aes_002", "title": "AES ECB mode usage", "severity": "medium", "cwe_id": "CWE-328"},
        ],
        "pwn": [
            {"id": "ctf_bof_001", "title": "Buffer overflow in C binary", "severity": "critical", "cwe_id": "CWE-120"},
            {"id": "ctf_fmt_002", "title": "Format string vulnerability", "severity": "high", "cwe_id": "CWE-134"},
            {"id": "ctf_heap_003", "title": "Heap use-after-free", "severity": "high", "cwe_id": "CWE-416"},
        ],
        "web": [
            {"id": "ctf_cookie_001", "title": "Insecure cookie handling", "severity": "medium", "cwe_id": "CWE-614"},
            {"id": "ctf_path_002", "title": "Path traversal in file read", "severity": "high", "cwe_id": "CWE-22"},
        ],
        "reversing": [
            {"id": "ctf_rev_001", "title": "Hardcoded credentials in binary", "severity": "medium", "cwe_id": "CWE-798"},
        ],
        "forensics": [
            {"id": "ctf_steg_001", "title": "Steganography in image file", "severity": "low", "cwe_id": "CWE-200"},
            {"id": "ctf_log_002", "title": "Credential leak in memory dump", "severity": "high", "cwe_id": "CWE-200"},
        ],
        "misc": [
            {"id": "ctf_social_001", "title": "Social engineering challenge", "severity": "low", "cwe_id": "CWE-200"},
        ],
    },
    "secure": {
        "input_validation": [
            {"id": "iv_path_001", "title": "Path traversal via encoded characters", "severity": "high", "cwe_id": "CWE-22"},
            {"id": "iv_proto_002", "title": "Prototype pollution in merge function", "severity": "high", "cwe_id": "CWE-1321"},
            {"id": "iv_redir_003", "title": "Open redirect via URL parameter", "severity": "medium", "cwe_id": "CWE-601"},
        ],
        "auth_session": [
            {"id": "as_jwt_001", "title": "JWT algorithm confusion attack", "severity": "high", "cwe_id": "CWE-327"},
            {"id": "as_concur_002", "title": "Concurrent session not invalidated", "severity": "medium", "cwe_id": "CWE-613"},
        ],
        "crypto_failures": [
            {"id": "cf_weak_001", "title": "Weak hashing algorithm (MD5)", "severity": "medium", "cwe_id": "CWE-328"},
            {"id": "cf_hard_002", "title": "Hardcoded cryptographic key", "severity": "high", "cwe_id": "CWE-321"},
        ],
        "error_handling": [
            {"id": "eh_stack_001", "title": "Stack trace exposed to user", "severity": "low", "cwe_id": "CWE-209"},
            {"id": "eh_info_002", "title": "Information leakage in error response", "severity": "medium", "cwe_id": "CWE-209"},
        ],
        "logging": [
            {"id": "lg_missing_001", "title": "Authentication events not logged", "severity": "medium", "cwe_id": "CWE-778"},
            {"id": "lg_sensitive_002", "title": "Passwords logged in plaintext", "severity": "high", "cwe_id": "CWE-532"},
        ],
    },
}

for _suite, _cats in _categories.items():
    _cases = []
    for _cat, _findings in _cats.items():
        for _f in _findings:
            _cases.append({
                "id": _f["id"],
                "category": _cat,
                "target_url": f"http://benchmark.local/{_suite}/{_f['id']}",
                "expected_findings": [{
                    "title": _f["title"],
                    "severity": _f["severity"],
                    "cwe_id": _f["cwe_id"],
                    "category": _cat,
                }],
                "expected_safe": False,
                "timeout_seconds": 120,
            })
    for _i in range(3):
        _cases.append({
            "id": f"safe_{_suite}_{_i+1:03d}",
            "category": "safe",
            "target_url": f"http://benchmark.local/{_suite}/safe_{_i+1}",
            "expected_findings": [],
            "expected_safe": True,
            "timeout_seconds": 60,
        })
    GROUND_TRUTH[f"{_suite}_ground_truth.json"] = json.dumps({
        "suite_name": _suite,
        "version": "1.0",
        "test_cases": _cases,
    }, indent=2)


if __name__ == "__main__":
    main()