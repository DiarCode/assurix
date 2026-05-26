"""Typer CLI entry point for local execution."""

import asyncio

import typer
from sqlalchemy import select

from src.db.models import Engagement, Target
from src.db.session import get_db_session, init_db
from src.orchestrator.engine import WorkflowEngine
from src.benchmark.cli import benchmark_app

app = typer.Typer(help="Assurix — Authorized Autonomous Security Validation Platform")
app.add_typer(benchmark_app, name="benchmark")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain to scan"),
    name: str | None = typer.Option(None, help="Human-readable target name"),
    iterations: int = typer.Option(3, help="Maximum scan iterations"),
) -> None:
    """Start a security validation scan against a target."""
    asyncio.run(_run_scan(target, name, iterations))


async def _run_scan(target_url: str, name: str | None, max_iterations: int) -> None:
    from src.db.session import dispose_engine

    await init_db()
    try:
        async with get_db_session() as session:
            result = await session.execute(select(Target).where(Target.url == target_url))
            target = result.scalar_one_or_none()
            if target is None:
                target = Target(
                    name=name or target_url,
                    url=target_url,
                    target_type="webapp",
                    verified=True,
                )
                session.add(target)
                await session.flush()

            engagement = Engagement(
                target_id=target.id,
                config={"max_iterations": max_iterations},
            )
            session.add(engagement)
            await session.flush()

            engine = WorkflowEngine()
            from src.agents.planner import PlannerAgent
            from src.agents.planner_mcts import MCTSPlannerAgent
            from src.agents.reasoner import ReasonerAgent
            from src.agents.recon import ReconAgent
            from src.agents.reporter import ReporterAgent
            from src.agents.validation import ValidationAgent
            from src.agents.webapp import WebappAgent
            from src.agents.pentester import PentesterAgent

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
        typer.echo(f"Scan started: engagement_id={engagement.id}")
        typer.echo("Press Ctrl+C to stop early (results are checkpointed).")
        try:
            while True:
                await asyncio.sleep(5)
                async with get_db_session() as session:
                    eng = await session.get(Engagement, engagement.id)
                    if eng and eng.status in ("completed", "failed"):
                        typer.echo(f"Scan finished: {eng.status}")
                        break
        except KeyboardInterrupt:
            typer.echo("Stopping scan...")
            await engine.stop()
    finally:
        await dispose_engine()


@app.command()
def server(
    host: str = typer.Option("0.0.0.0", help="API server host"),
    port: int = typer.Option(8000, help="API server port"),
) -> None:
    """Run the FastAPI development server."""
    import uvicorn

    uvicorn.run("src.api.main:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
