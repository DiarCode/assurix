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
        if run.weighted_score is not None:
            typer.echo(f"  Weighted:   {run.weighted_score:.1%}")
        if run.pass_at_k_score is not None:
            typer.echo(f"  Pass@{run.k_value}:     {run.pass_at_k_score:.1%}")
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
            typer.echo(f"\nReport saved: {out}")
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
    typer.echo(f"Competitor Scores \u2014 {suite.upper()}")
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


@benchmark_app.command("score")
def score_results(
    suite: str = typer.Argument(..., help="Benchmark suite name"),
    results_file: str = typer.Argument(..., help="JSON file with pre-existing results"),
    k: int = typer.Option(3, help="k value for pass@k"),
) -> None:
    """Score pre-existing results against ground truth without live targets."""
    asyncio.run(_score(suite, results_file, k))


async def _score(suite, results_file, k):
    import json
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.runner import BenchmarkRunner
    from src.benchmark.registry import list_suites
    if suite not in list_suites():
        typer.echo(f"Unknown suite: {suite}. Available: {', '.join(list_suites())}")
        return
    try:
        results = json.loads(Path(results_file).read_text(encoding="utf-8"))
    except Exception as e:
        typer.echo(f"Error reading results file: {e}")
        return
    await init_db()
    try:
        runner = BenchmarkRunner()
        async with get_db_session() as session:
            run = await runner.run_scored(suite, session, results, k=k)
        typer.echo(f"Scored: {run.suite_name}")
        typer.echo(f"  Run ID:       {run.id}")
        typer.echo(f"  Precision:    {run.precision:.1%}" if run.precision else "  Precision:    N/A")
        typer.echo(f"  Recall:       {run.recall:.1%}" if run.recall else "  Recall:       N/A")
        typer.echo(f"  F1:           {run.f1:.1%}" if run.f1 else "  F1:           N/A")
        if run.weighted_score is not None:
            typer.echo(f"  Weighted:     {run.weighted_score:.1%}")
        if run.pass_at_k_score is not None:
            typer.echo(f"  Pass@{run.k_value}:       {run.pass_at_k_score:.1%}")
    finally:
        await dispose_engine()


@benchmark_app.command("seed-competitors")
def seed_competitors(suite: str = typer.Argument(..., help="Benchmark suite name")) -> None:
    """Show competitor data available for a benchmark suite."""
    from src.benchmark.charts import COMPETITOR_DATA
    comps = COMPETITOR_DATA.get(suite, [])
    if not comps:
        typer.echo(f"No competitor data for suite: {suite}")
        return
    typer.echo(f"Competitor Scores — {suite.upper()}")
    typer.echo(f"{'Model':20s}  {'Score':>6s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}")
    typer.echo("-" * 56)
    for c in comps:
        typer.echo(f"{c['name']:20s}  {c['score']:6.1f}  {c['precision']:6.1f}  {c['recall']:6.1f}  {c['f1']:6.1f}")
