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
    tiers: bool = typer.Option(False, help="Show T1-T5 capability tier scoring"),
) -> None:
    asyncio.run(_run(suite, target, iterations, dry_run, tiers))


async def _run(suite, target, iterations, dry_run, tiers):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.runner import BenchmarkRunner
    from src.benchmark.registry import list_suites
    from src.benchmark.capability_scorer import TIER_NAMES
    if suite not in list_suites():
        typer.echo(f"Unknown suite: {suite}. Available: {', '.join(list_suites())}")
        return
    await init_db()
    try:
        runner = BenchmarkRunner(max_iterations=iterations)
        async with get_db_session() as session:
            if dry_run:
                result = await runner.run_dry(suite, session)
            else:
                result = await runner.run_suite(suite, session, target_url_override=target)
        run = result["run"]
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

        if tiers:
            cap = result["capability"]
            typer.echo(f"\n--- Capability Ladder ---")
            typer.echo(f"  Best tier:  {cap.best_tier_label} ({cap.best_tier_name})")
            typer.echo(f"  Avg tier:   {cap.average_tier:.2f}")
            typer.echo(f"  Findings:   {cap.total_findings}")
            typer.echo(f"  Success:    {cap.unguided_success_rate:.1%}")
            if cap.time_to_exploit is not None:
                typer.echo(f"  Time-to-exploit: {cap.time_to_exploit:.1f}s")
            typer.echo(f"\n--- Tier Distribution ---")
            for tier in sorted(cap.tier_distribution.keys()):
                count = cap.tier_distribution[tier]
                typer.echo(f"  T{tier} ({TIER_NAMES.get(tier, '?'):>24s}): {count}")
            typer.echo(f"\n--- Finding Details ---")
            for cs in cap.scores:
                typer.echo(f"  [{cs.tier_label}] {cs.finding_type}: {cs.tier_name} (confidence: {cs.confidence:.0%})")
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


@benchmark_app.command("live")
def run_live_benchmark(
    targets: str = typer.Option("", help="Comma-separated target names (e.g. juice-shop,dvwa). Default: all"),
    timeout: int = typer.Option(300, help="Timeout per target in seconds"),
    iterations: int = typer.Option(3, help="Max scan iterations per target"),
    research_loop: bool = typer.Option(False, help="Use ResearchLoop instead of linear pipeline"),
    ab_compare: bool = typer.Option(False, help="Run A/B comparison (linear vs ResearchLoop)"),
) -> None:
    """Run live benchmark against Docker-based vulnerable targets with capability scoring."""
    target_list = [t.strip() for t in targets.split(",") if t.strip()] or None
    asyncio.run(_run_live(target_list, timeout, iterations, research_loop, ab_compare))


async def _run_live(target_names, timeout, iterations, research_loop, ab_compare):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.runner import BenchmarkRunner
    from src.benchmark.docker_target import BENCHMARK_TARGETS, DockerUnavailableError
    from src.benchmark.capability_scorer import TIER_NAMES
    typer.echo("Starting live benchmark...")
    typer.echo(f"  Targets:  {', '.join(target_names or BENCHMARK_TARGETS.keys())}")
    typer.echo(f"  Timeout:  {timeout}s per target")
    typer.echo(f"  Max iterations: {iterations}")
    if research_loop:
        typer.echo("  ResearchLoop: enabled")
    if ab_compare:
        typer.echo("  A/B comparison: enabled")
    await init_db()
    try:
        runner = BenchmarkRunner(max_iterations=iterations, timeout_per_case=timeout)
        config = {
            "use_research_loop": research_loop,
            "ab_comparison": ab_compare,
        }
        async with get_db_session() as session:
            result = await runner.run_live(
                session,
                target_names=target_names,
                timeout_per_target=timeout,
                config=config,
            )
        run = result["run"]
        aggregate = result["aggregate"]
        capability_reports = result["capability_reports"]

        typer.echo(f"\n{'=' * 60}")
        typer.echo(f"Live Benchmark Complete")
        typer.echo(f"  Run ID:     {run.id}")
        typer.echo(f"  Status:     {run.status}")
        if run.precision is not None:
            typer.echo(f"  Precision:  {run.precision:.1%}")
        if run.recall is not None:
            typer.echo(f"  Recall:     {run.recall:.1%}")
        if run.f1 is not None:
            typer.echo(f"  F1:         {run.f1:.1%}")

        typer.echo(f"\n--- Capability Ladder ---")
        typer.echo(f"  Best tier overall:  T{aggregate['best_tier_overall']} ({TIER_NAMES.get(aggregate['best_tier_overall'], '?')})")
        typer.echo(f"  Avg tier overall:   {aggregate['average_tier_overall']:.2f}")
        typer.echo(f"  Total findings:     {aggregate['total_findings_overall']}")
        typer.echo(f"  Unguided success:    {aggregate['unguided_success_rate_avg']:.1%}")
        if aggregate.get("time_to_exploit_avg") is not None:
            typer.echo(f"  Avg time-to-exploit: {aggregate['time_to_exploit_avg']:.1f}s")
        if aggregate.get("token_cost_per_t1_avg") is not None:
            typer.echo(f"  Avg token cost/T1:  {aggregate['token_cost_per_t1_avg']:.0f}")

        typer.echo(f"\n--- Tier Distribution ---")
        for tier in sorted(aggregate.get("tier_distribution_overall", {}).keys()):
            count = aggregate["tier_distribution_overall"][tier]
            typer.echo(f"  T{tier} ({TIER_NAMES.get(tier, '?'):>24s}): {count}")

        for name, report in capability_reports.items():
            typer.echo(f"\n--- {name} ---")
            typer.echo(f"  Best tier:  {report.best_tier_label} ({report.best_tier_name})")
            typer.echo(f"  Avg tier:   {report.average_tier:.2f}")
            typer.echo(f"  Findings:   {report.total_findings}")
            typer.echo(f"  Success:    {report.unguided_success_rate:.1%}")
            if report.time_to_exploit is not None:
                typer.echo(f"  Time-to-exploit: {report.time_to_exploit:.1f}s")
            if report.token_cost_per_t1 is not None:
                typer.echo(f"  Token cost/T1:   {report.token_cost_per_t1:.0f}")

        # Display Mythos metrics if available
        mythos = result.get("mythos_metrics")
        if mythos:
            typer.echo(f"\n--- Mythos Metrics ---")
            typer.echo(f"  Hypothesis hit rate:     {mythos['hypothesis_hit_rate']:.1%} ({'PASS' if mythos['hit_rate_pass'] else 'FAIL'}: >=50%)")
            typer.echo(f"  Provenance completeness: {mythos['provenance_chain_completeness']:.1%} ({'PASS' if mythos['provenance_pass'] else 'FAIL'}: =100%)")
            typer.echo(f"  Novel vs linear:         {mythos['novel_findings_vs_linear']} ({'PASS' if mythos['novel_pass'] else 'FAIL'}: >=1)")
            typer.echo(f"  Reflection quality:      {mythos['research_iterations']} iterations, {mythos['confirmed_hypotheses']} confirmed ({'PASS' if mythos['reflection_pass'] else 'FAIL'}: <5 iter, >=2 confirmed)")
            typer.echo(f"  Overall:                 {'PASS' if mythos['overall_pass'] else 'FAIL'}")
    except DockerUnavailableError as e:
        typer.echo(f"\nDocker is not available: {e}")
        typer.echo("Please ensure Docker is installed and running.")
        raise typer.Exit(code=1)
    finally:
        await dispose_engine()


@benchmark_app.command("cyberarena")
def run_cyberarena(
    targets: str = typer.Option("", help="Comma-separated target names (e.g. juice-shop,dvwa). Default: all"),
    timeout: int = typer.Option(300, help="Timeout per target in seconds"),
    iterations: int = typer.Option(3, help="Max scan iterations per target"),
    research_loop: bool = typer.Option(False, help="Use ResearchLoop instead of linear pipeline"),
    ab_compare: bool = typer.Option(True, help="A/B comparison (default: True for cyberarena)"),
) -> None:
    """Run CyberArena benchmark against DVWA, Juice Shop, WebGoat with endpoint-level ground truth."""
    target_list = [t.strip() for t in targets.split(",") if t.strip()] or None
    asyncio.run(_run_cyberarena(target_list, timeout, iterations, research_loop, ab_compare))


async def _run_cyberarena(target_names, timeout, iterations, research_loop, ab_compare):
    from src.db.session import init_db, dispose_engine, get_db_session
    from src.benchmark.runner import BenchmarkRunner
    from src.benchmark.docker_target import BENCHMARK_TARGETS, DockerUnavailableError
    from src.benchmark.capability_scorer import TIER_NAMES
    typer.echo("Starting CyberArena benchmark...")
    typer.echo(f"  Targets:  {', '.join(target_names or BENCHMARK_TARGETS.keys())}")
    typer.echo(f"  Timeout:  {timeout}s per target")
    typer.echo(f"  Max iterations: {iterations}")
    if research_loop:
        typer.echo("  ResearchLoop: enabled")
    typer.echo(f"  A/B comparison: {'enabled' if ab_compare else 'disabled'}")
    await init_db()
    try:
        runner = BenchmarkRunner(max_iterations=iterations, timeout_per_case=timeout)
        config = {
            "use_research_loop": research_loop,
            "ab_comparison": ab_compare,
        }
        async with get_db_session() as session:
            result = await runner.run_live(
                session,
                target_names=target_names,
                timeout_per_target=timeout,
                config=config,
            )
        run = result["run"]
        aggregate = result["aggregate"]
        capability_reports = result["capability_reports"]

        typer.echo(f"\n{'=' * 60}")
        typer.echo(f"CyberArena Benchmark Complete")
        typer.echo(f"  Run ID:     {run.id}")
        typer.echo(f"  Status:     {run.status}")
        if run.precision is not None:
            typer.echo(f"  Precision:  {run.precision:.1%}")
        if run.recall is not None:
            typer.echo(f"  Recall:     {run.recall:.1%}")
        if run.f1 is not None:
            typer.echo(f"  F1:         {run.f1:.1%}")

        typer.echo(f"\n--- Capability Ladder ---")
        typer.echo(f"  Best tier overall:  T{aggregate['best_tier_overall']} ({TIER_NAMES.get(aggregate['best_tier_overall'], '?')})")
        typer.echo(f"  Avg tier overall:   {aggregate['average_tier_overall']:.2f}")
        typer.echo(f"  Total findings:     {aggregate['total_findings_overall']}")
        typer.echo(f"  Unguided success:    {aggregate['unguided_success_rate_avg']:.1%}")

        typer.echo(f"\n--- Tier Distribution ---")
        for tier in sorted(aggregate.get("tier_distribution_overall", {}).keys()):
            count = aggregate["tier_distribution_overall"][tier]
            typer.echo(f"  T{tier} ({TIER_NAMES.get(tier, '?'):>24s}): {count}")

        for name, report in capability_reports.items():
            typer.echo(f"\n--- {name} ---")
            typer.echo(f"  Best tier:  {report.best_tier_label} ({report.best_tier_name})")
            typer.echo(f"  Avg tier:   {report.average_tier:.2f}")
            typer.echo(f"  Findings:   {report.total_findings}")
            typer.echo(f"  Success:    {report.unguided_success_rate:.1%}")
            if report.time_to_exploit is not None:
                typer.echo(f"  Time-to-exploit: {report.time_to_exploit:.1f}s")

        # Display Mythos metrics if available
        mythos = result.get("mythos_metrics")
        if mythos:
            typer.echo(f"\n--- Mythos Metrics ---")
            typer.echo(f"  Hypothesis hit rate:     {mythos['hypothesis_hit_rate']:.1%} ({'PASS' if mythos['hit_rate_pass'] else 'FAIL'}: >=50%)")
            typer.echo(f"  Provenance completeness: {mythos['provenance_chain_completeness']:.1%} ({'PASS' if mythos['provenance_pass'] else 'FAIL'}: =100%)")
            typer.echo(f"  Novel vs linear:         {mythos['novel_findings_vs_linear']} ({'PASS' if mythos['novel_pass'] else 'FAIL'}: >=1)")
            typer.echo(f"  Reflection quality:      {mythos['research_iterations']} iterations, {mythos['confirmed_hypotheses']} confirmed ({'PASS' if mythos['reflection_pass'] else 'FAIL'}: <5 iter, >=2 confirmed)")
            typer.echo(f"  Overall:                 {'PASS' if mythos['overall_pass'] else 'FAIL'}")
    except DockerUnavailableError as e:
        typer.echo(f"\nDocker is not available: {e}")
        typer.echo("Please ensure Docker is installed and running.")
        raise typer.Exit(code=1)
    finally:
        await dispose_engine()
def list_targets() -> None:
    """List available Docker benchmark targets."""
    from src.benchmark.docker_target import BENCHMARK_TARGETS
    typer.echo("Available Benchmark Targets")
    typer.echo(f"{'Name':15s}  {'Image':40s}  {'Port':>5s}  {'Timeout':>7s}")
    typer.echo("-" * 75)
    for name, target in BENCHMARK_TARGETS.items():
        typer.echo(f"{name:15s}  {target.image:40s}  {target.port:>5d}  {target.health_check_timeout:>7d}s")


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
