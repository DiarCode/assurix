"""Core asyncio workflow engine with SQLite durability."""

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.audit import log_action
from src.core.exceptions import PolicyBlockedError
from src.db.models import Engagement, EngagementStatus, Job
from src.db.session import get_db_session
from src.orchestrator.events import EventBus
from src.orchestrator.scheduler import JobScheduler
from src.orchestrator.state import WorkflowRouter
from src.agents.validation import ValidationAgent

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """Orchestrates multi-agent cyclic workflows with checkpointing."""

    def __init__(self) -> None:
        self.agents: dict[str, Any] = {}
        self.scheduler = JobScheduler()
        self.events = EventBus()
        self._running = False
        self._task: asyncio.Task[Any] | None = None

    def register(self, name: str, agent_cls: Any) -> None:
        """Register an agent class by name."""
        self.agents[name] = agent_cls

    async def start_engagement(self, session: AsyncSession, engagement_id: str, *, target_url: str = "") -> None:
        """Initialize an engagement and enqueue the first job."""
        engagement = await session.get(Engagement, engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")
        engagement.status = EngagementStatus.RUNNING
        engagement.started_at = datetime.now(UTC)
        await session.flush()

        await self.scheduler.enqueue(
            session=session,
            engagement_id=engagement_id,
            agent_name="planner",
            payload={"iteration": 0, "phase": "initial", "target_url": target_url},
            priority=1,
        )
        await log_action(
            session=session,
            action="engagement_started",
            actor="engine",
            payload={"engagement_id": engagement_id},
        )

    async def _run_loop(self) -> None:
        """Main engine loop: dequeue, execute, checkpoint."""
        self._running = True
        while self._running:
            async with get_db_session() as session:
                job_data = await self.scheduler.dequeue()
                if job_data is None:
                    await asyncio.sleep(1)
                    continue

                job_id, engagement_id, payload = job_data
                await self.scheduler.mark_running(session, job_id)

                # Resolve agent
                job = await session.get(Job, job_id)  # type: ignore[call-arg]
                agent_name = job.agent_name if job else ""
                agent_cls = self.agents.get(agent_name)
                if agent_cls is None:
                    await self.scheduler.mark_failed(
                        session, job_id, f"Unknown agent: {agent_name}"
                    )
                    continue

                # Execute
                try:
                    agent = agent_cls()
                    result = await agent.execute(payload, session)
                except PolicyBlockedError:
                    raise
                except Exception as exc:
                    await self.scheduler.mark_failed(session, job_id, str(exc))
                    await log_action(
                        session=session,
                        action="agent_failed",
                        actor=agent_name,
                        payload={"engagement_id": engagement_id, "error": str(exc)},
                    )
                    continue

                await self.scheduler.mark_completed(session, job_id, result)
                await log_action(
                    session=session,
                    action="agent_completed",
                    actor=agent_name,
                    payload={"engagement_id": engagement_id, "result_summary": str(result)[:500]},
                )

                # Route next agent
                engagement = await session.get(Engagement, engagement_id)  # type: ignore[call-arg]
                if engagement and agent_name != "reporter":
                    # Self-reflective loop: reasoner can request targeted re-investigation
                    if agent_name == "reasoner" and result.get("re_investigate"):
                        reinvestigation_targets = result.get("re_investigate", [])
                        logger.info(
                            "Reasoner requests re-investigation: %d targets",
                            len(reinvestigation_targets),
                        )
                        await self.scheduler.enqueue(
                            session=session,
                            engagement_id=engagement_id,
                            agent_name="webapp",
                            payload={
                                "iteration": engagement.iteration_count,
                                "previous_result": result,
                                "target_url": payload.get("target_url", ""),
                                "re_investigation": reinvestigation_targets,
                            },
                            priority=2,
                        )
                        await log_action(
                            session=session,
                            action="re_investigation_requested",
                            actor="engine",
                            payload={
                                "engagement_id": engagement_id,
                                "targets": [t.get("task_type", "") for t in reinvestigation_targets[:5]],
                            },
                        )
                    else:
                        next_agent = WorkflowRouter.next_agent(
                            agent_name,
                            engagement.iteration_count,
                            engagement.config.get("max_iterations", 50),
                        )
                        if next_agent:
                            if next_agent == "planner":
                                engagement.iteration_count += 1
                            await self.scheduler.enqueue(
                                session=session,
                                engagement_id=engagement_id,
                                agent_name=next_agent,
                                payload={
                                    "iteration": engagement.iteration_count,
                                    "previous_result": result,
                                    "target_url": payload.get("target_url", ""),
                                },
                                priority=1,
                            )
                        else:
                            engagement.status = EngagementStatus.COMPLETED
                            engagement.completed_at = datetime.now(UTC)
                            await self.events.emit(
                                "engagement_completed",
                                {"engagement_id": engagement_id},
                            )

                await session.commit()

    def start(self) -> None:
        """Start the engine loop in a background task."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._start_and_run())

    async def _start_and_run(self) -> None:
        """Load pending jobs then run the main loop."""
        async with get_db_session() as session:
            await self.scheduler.load_pending(session)
            await session.commit()
        await self._run_loop()

    async def stop(self) -> None:
        """Gracefully stop the engine loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task


# Global singleton engine instance
engine = WorkflowEngine()
