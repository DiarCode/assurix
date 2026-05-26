"""PriorityQueue + SQLite job store for the workflow engine."""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Job, JobStatus


class JobScheduler:
    """Manages job queue with priority ordering and SQLite durability."""

    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, str, dict[str, Any]]] = (
            asyncio.PriorityQueue()
        )
        self._lock = asyncio.Lock()

    async def enqueue(
        self,
        session: AsyncSession,
        engagement_id: str,
        agent_name: str,
        payload: dict[str, Any],
        priority: int = 5,
    ) -> Job:
        """Persist a job to SQLite and add it to the in-memory queue."""
        job = Job(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            agent_name=agent_name,
            status=JobStatus.QUEUED,
            priority=priority,
            payload=payload,
        )
        session.add(job)
        await session.flush()
        await self._queue.put(
            (
                priority,
                job.id,
                {"engagement_id": engagement_id, "agent_name": agent_name, "payload": payload},
            )
        )
        return job

    async def dequeue(self) -> tuple[str, str, dict[str, Any]] | None:
        """Retrieve the highest-priority job from the queue."""
        try:
            priority, job_id, data = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            return job_id, data["engagement_id"], data["payload"]
        except TimeoutError:
            return None

    async def mark_running(self, session: AsyncSession, job_id: str) -> None:
        result = await session.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()
        if job:
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(UTC)
            await session.flush()

    async def mark_completed(
        self, session: AsyncSession, job_id: str, result_data: dict[str, Any]
    ) -> None:
        res = await session.execute(select(Job).where(Job.id == job_id))
        job = res.scalar_one_or_none()
        if job:
            job.status = JobStatus.COMPLETED
            job.result = result_data
            job.completed_at = datetime.now(UTC)
            await session.flush()

    async def mark_failed(self, session: AsyncSession, job_id: str, error: str) -> None:
        res = await session.execute(select(Job).where(Job.id == job_id))
        job = res.scalar_one_or_none()
        if job:
            job.retry_count += 1
            if job.retry_count >= job.max_retries:
                job.status = JobStatus.FAILED
                job.result = {"error": error}
                job.completed_at = datetime.now(UTC)
            else:
                job.status = JobStatus.RETRYING
                # Re-enqueue with lower priority
                await self._queue.put(
                    (
                        job.priority + job.retry_count,
                        job.id,
                        {
                            "engagement_id": job.engagement_id,
                            "agent_name": job.agent_name,
                            "payload": job.payload,
                        },
                    )
                )
            await session.flush()

    async def load_pending(self, session: AsyncSession) -> None:
        """Hydrate the in-memory queue from SQLite on startup."""
        stmt = select(Job).where(Job.status.in_([JobStatus.QUEUED, JobStatus.RETRYING]))
        result = await session.execute(stmt)
        for job in result.scalars().all():
            await self._queue.put(
                (
                    job.priority + job.retry_count,
                    job.id,
                    {
                        "engagement_id": job.engagement_id,
                        "agent_name": job.agent_name,
                        "payload": job.payload,
                    },
                )
            )
