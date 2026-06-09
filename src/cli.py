"""Assurix CLI — `assurix scan <target>` only.

No mode flags. No orchestrator flags. No depth-pass flags. No
strict-gate flags. No version flags. The default config IS the only
config. Full deep mode is the only mode that exists.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from sqlalchemy import select, update

from src.core.audit import log_action
from src.core.config import get_settings
from src.db.models import Engagement, EngagementStatus, Finding, Target
from src.db.session import dispose_engine, get_db_session, init_db

app = typer.Typer(
    name="assurix",
    help="Assurix — Authorized Autonomous Security Validation Platform",
    no_args_is_help=True,
    add_completion=False,
    invoke_without_command=True,
)


@app.callback()
def _root(
    ctx: typer.Context,
) -> None:
    """Assurix root — see subcommands."""

# Canonical default engagement config. Single source of truth for
# the operator-only controls (depth pass, strict gate, research loop,
# hypothesis orchestrator, mode, max iterations). The CLI does not
# expose any of these as flags — full deep mode is always on.
DEFAULT_ENGAGEMENT_CONFIG: dict = {
    "max_iterations": 200,
    "use_research_loop": True,
    "use_hypothesis_orchestrator": True,
    "use_depth_pass": True,
    "strict_finding_gate": True,
    "depth_pass_budget_minutes": 30,
    "depth_pass_max_invocations": 200,
    "mode": "offensive",
}


def _register_default_agents(engine) -> None:
    """Register all built-in agents on the engine.

    The single planner (EGATSPlanner) is registered under the
    canonical name ``"planner"``. There is no v1 / v2 / mode
    distinction at the agent-registry level.
    """
    from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
    from src.agents.pentester import PentesterAgent
    from src.agents.planner_egats import EGATSPlanner
    from src.agents.planner_mcts import MCTSPlannerAgent
    from src.agents.reasoner import ReasonerAgent
    from src.agents.recon import ReconAgent
    from src.agents.reporter import ReporterAgent
    from src.agents.research_loop import ResearchLoopAgent
    from src.agents.validation import ValidationAgent
    from src.agents.webapp import WebappAgent

    engine.register("planner", EGATSPlanner)
    engine.register("planner_mcts", MCTSPlannerAgent)
    engine.register("recon", ReconAgent)
    engine.register("webapp", WebappAgent)
    engine.register("pentester", PentesterAgent)
    engine.register("reasoner", ReasonerAgent)
    engine.register("validation", ValidationAgent)
    engine.register("reporter", ReporterAgent)
    engine.register("hypothesis_orchestrator", HypothesisOrchestrator)
    engine.register("research_loop", ResearchLoopAgent)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain to scan"),
) -> None:
    """Run a full deep security scan against TARGET.

    Assurix always runs in full deep mode: EGATS planning, browser
    recon, exploitation, reasoning, validation, depth pass, and a
    written report. No mode flags. No version flags. Just the target.
    """
    asyncio.run(_run_scan(target))


async def _cleanup_stale_engagements(stale_threshold_hours: int = 1) -> int:
    """Flip stale RUNNING/RESEARCHING/PAUSED engagements to FAILED.

    Called at CLI startup. Scans left over from prior crashes (engine
    killed, host reboot, Ctrl+C during a Ctrl+C-safe path) can leave
    rows that block the dashboard and confuse operators. We mark them
    FAILED with a `cleanup_reason: "stale_on_startup"` audit log so the
    trace is preserved.

    Returns the number of rows updated.
    """
    threshold = datetime.now(UTC) - timedelta(hours=stale_threshold_hours)
    async with get_db_session() as session:
        result = await session.execute(
            update(Engagement)
            .where(
                Engagement.status.in_([
                    EngagementStatus.RUNNING,
                    EngagementStatus.RESEARCHING,
                    EngagementStatus.PAUSED,
                ]),
                Engagement.started_at.is_not(None),
                Engagement.started_at < threshold,
            )
            .values(
                status=EngagementStatus.FAILED,
                completed_at=datetime.now(UTC),
            )
            .returning(Engagement.id)
        )
        await session.commit()
        cleaned = [row[0] for row in result.fetchall()]
    for eng_id in cleaned:
        typer.echo(f"Cleaned up stale engagement {eng_id[:8]}")
    return len(cleaned)


async def _run_scan(target_url: str) -> None:
    """Create engagement, register agents, start engine, monitor, report path."""
    await init_db()
    # Sweep stale engagements from prior runs before we start the new one.
    # This makes the CLI self-healing — no operator intervention needed
    # after a crash.
    await _cleanup_stale_engagements()
    try:
        config = dict(DEFAULT_ENGAGEMENT_CONFIG)

        async with get_db_session() as session:
            result = await session.execute(select(Target).where(Target.url == target_url))
            target = result.scalar_one_or_none()
            if target is None:
                target = Target(
                    name=target_url,
                    url=target_url,
                    target_type="webapp",
                    verified=True,  # full deep mode requires verification
                )
                session.add(target)
                await session.flush()

            engagement = Engagement(target_id=target.id, config=config)
            session.add(engagement)
            await session.flush()
            engagement_id = engagement.id

            from src.orchestrator.engine import WorkflowEngine

            engine = WorkflowEngine()
            _register_default_agents(engine)
            await engine.start_engagement(session, engagement_id, target_url=target_url)

        typer.echo(f"Scan started: engagement_id={engagement_id}")
        typer.echo("Mode: full deep (EGATS + recon + pentester + reasoner + validation + depth pass + report).")
        typer.echo("Press Ctrl+C to stop early (results are checkpointed).")

        engine.start()
        report_path: Path | None = None
        engine_died: BaseException | None = None
        try:
            while True:
                await asyncio.sleep(5)
                # Health check 1: is the engine task still alive?
                # If `_run_loop` or `_start_and_run` died with an
                # unhandled exception, the engagement row is stuck
                # `running` and nothing is touching it. Detect this and
                # break the polling loop so the CLI can report the
                # failure and clean up.
                if engine._task and engine._task.done():
                    try:
                        engine_died = engine._task.exception()
                    except (asyncio.CancelledError, asyncio.InvalidStateError):
                        engine_died = None
                    typer.echo(
                        "Engine task ended unexpectedly"
                        + (f": {engine_died!r}" if engine_died else "")
                        + "; stopping scan."
                    )
                    break
                # Health check 2: has the engagement reached a terminal state?
                async with get_db_session() as session:
                    eng = await session.get(Engagement, engagement_id)
                    # Compare against string literals: the ORM can return
                    # `eng.status` as a plain str (rather than the
                    # EngagementStatus StrEnum) depending on the column
                    # coercion path. StrEnum members compare equal to
                    # their str value, so the `in` check works in both
                    # cases, but accessing `.value` on a bare str raises
                    # AttributeError — guard with `getattr`.
                    if eng and eng.status in (
                        EngagementStatus.COMPLETED,
                        EngagementStatus.FAILED,
                    ):
                        status_str = getattr(
                            eng.status, "value", eng.status
                        )
                        typer.echo(f"Scan finished: {status_str}")
                        report_path = await _latest_report_for(
                            session, engagement_id, target_url
                        )
                        break
        except KeyboardInterrupt:
            typer.echo("Stopping scan...")
            await engine.stop()

        if report_path is not None:
            typer.echo(f"Report: {report_path}")
        else:
            # Find the most recent report in data/reports/ as a best-effort fallback
            reports_dir = Path("data/reports")
            if reports_dir.is_dir():
                latest = max(reports_dir.glob("*.md"), default=None, key=lambda p: p.stat().st_mtime)
                if latest:
                    typer.echo(f"Report: {latest}")
    finally:
        await dispose_engine()


async def _latest_report_for(
    session, engagement_id: str, target_url: str
) -> Path | None:
    """Return the report file path associated with this engagement, if one exists.

    The reporter agent writes to ``data/reports/<timestamp>_<target>_<eng8>.md``
    and updates the ``LATEST.md`` symlink. We resolve the path by glob on
    the engagement_id_short, which is appended to the filename.
    """
    reports_dir = Path("data/reports")
    if not reports_dir.is_dir():
        return None
    eng8 = engagement_id.replace("-", "")[:8]
    matches = list(reports_dir.glob(f"*_{eng8}.md"))
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime)
    return None


if __name__ == "__main__":
    app()
