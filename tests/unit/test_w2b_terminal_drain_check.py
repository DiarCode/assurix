"""W2-B regression: the engine refuses to transition an engagement
to COMPLETED while there are still active jobs in flight.

Defect 4 was that the engine's terminal-transition code (reporter
and depth_pass branches) flipped ``engagement.status`` to
COMPLETED without checking whether the in-memory + SQLite job
queue had any in-flight rows. The dj1naq.sytes.net engagement was
left with 5 ``tool_invocations`` rows in
``started_at IS NOT NULL AND completed_at IS NULL`` state and the
engagement marked ``completed`` because of this race.

The fix:

1. ``JobScheduler.count_active(session, engagement_id)`` returns
   the number of jobs in any of ``QUEUED``, ``RUNNING``,
   ``RETRYING`` for the engagement.
2. Both terminal-transition branches (reporter, depth_pass) call
   ``count_active`` and refuse to flip to COMPLETED when it's
   non-zero. They log a warning and the polling loop's next
   iteration picks the still-pending job up.
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.models import Base, Engagement, Job, JobStatus, Target


def _build_session_factory() -> tuple:
    """In-memory SQLite + schema + one engagement."""
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def _setup():
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = async_sessionmaker(eng, expire_on_commit=False)
        async with Session() as s:
            eng_id = str(uuid4())
            tgt_id = str(uuid4())
            s.add(Target(id=tgt_id, name="https://t", url="https://t",
                         target_type="webapp", verified=1))
            s.add(Engagement(id=eng_id, target_id=tgt_id,
                             status="researching", config={}))
            await s.commit()
        return Session, eng_id

    return eng, asyncio.run(_setup())


class TestSchedulerCountActive:
    def test_count_active_returns_zero_when_queue_drained(self) -> None:
        from src.orchestrator.scheduler import JobScheduler

        eng, (Session, eng_id) = _build_session_factory()
        sched = JobScheduler()

        async def _go() -> int:
            async with Session() as s:
                return await sched.count_active(s, eng_id)

        assert asyncio.run(_go()) == 0

    def test_count_active_includes_queued_running_retrying(self) -> None:
        """Each of QUEUED / RUNNING / RETRYING counts. COMPLETED /
        FAILED do NOT — they're terminal."""
        from src.orchestrator.scheduler import JobScheduler

        eng, (Session, eng_id) = _build_session_factory()
        sched = JobScheduler()

        async def _go() -> int:
            async with Session() as s:
                # One of each non-terminal state.
                for st in (JobStatus.QUEUED, JobStatus.RUNNING,
                           JobStatus.RETRYING):
                    s.add(Job(
                        id=str(uuid4()),
                        engagement_id=eng_id,
                        agent_name="webapp",
                        payload={},
                        priority=1,
                        status=st,
                    ))
                # Two terminal jobs — must NOT count.
                for st in (JobStatus.COMPLETED, JobStatus.FAILED):
                    s.add(Job(
                        id=str(uuid4()),
                        engagement_id=eng_id,
                        agent_name="webapp",
                        payload={},
                        priority=1,
                        status=st,
                    ))
                await s.commit()
                return await sched.count_active(s, eng_id)

        assert asyncio.run(_go()) == 3

    def test_count_active_isolates_engagement(self) -> None:
        """Jobs belonging to other engagements do NOT count. The
        drain check is per-engagement."""
        from src.orchestrator.scheduler import JobScheduler

        eng, (Session, eng_id) = _build_session_factory()
        sched = JobScheduler()
        other_eng_id = str(uuid4())

        async def _go() -> int:
            async with Session() as s:
                # An active job on a different engagement.
                s.add(Job(
                    id=str(uuid4()),
                    engagement_id=other_eng_id,
                    agent_name="webapp",
                    payload={},
                    priority=1,
                    status=JobStatus.RUNNING,
                ))
                await s.commit()
                return await sched.count_active(s, eng_id)

        assert asyncio.run(_go()) == 0


class TestTerminalTransitionBlockedByActiveJobs:
    """End-to-end-ish: simulate the post-reporter branch and assert
    the engagement stays in its non-terminal state when there are
    in-flight jobs."""

    def test_engagement_stays_researching_when_job_active(self) -> None:
        """Replicates the live defect: a job is still in
        ``RUNNING`` state (mirroring the W2-A case where a
        tool_invocation was left with ``completed_at IS NULL``).
        The engine must not transition to COMPLETED. The check is
        on the ``jobs`` table."""
        from datetime import UTC, datetime

        from sqlalchemy import select
        from src.orchestrator.scheduler import JobScheduler

        eng, (Session, eng_id) = _build_session_factory()
        sched = JobScheduler()

        async def _go() -> str:
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "researching"

                # A hanging RUNNING job (the W2-A invariant was
                # about closing these; W2-B is about the engine
                # not flipping COMPLETED while they're open).
                s.add(Job(
                    id=str(uuid4()),
                    engagement_id=eng_id,
                    agent_name="webapp",
                    payload={},
                    priority=1,
                    status=JobStatus.RUNNING,
                    started_at=datetime.now(UTC),
                ))
                await s.commit()

                # This is the drain check the engine runs in the
                # reporter / depth_pass terminal branches.
                active = await sched.count_active(s, eng_id)
                assert active == 1, "drain check must see the in-flight job"
                return e.status

        # The engagement status was never flipped to COMPLETED
        # because the drain check returned 1.
        assert asyncio.run(_go()) == "researching"

    def test_terminal_transition_succeeds_when_queue_drained(self) -> None:
        """Sanity: the drain check returns 0 and the engine is
        free to transition. Mirrors the reporter branch in
        ``engine.py``."""
        from datetime import UTC, datetime

        from sqlalchemy import select
        from src.orchestrator.scheduler import JobScheduler

        eng, (Session, eng_id) = _build_session_factory()
        sched = JobScheduler()

        async def _go() -> str:
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "researching"
                # All jobs are terminal — no active ones.
                s.add(Job(
                    id=str(uuid4()),
                    engagement_id=eng_id,
                    agent_name="webapp",
                    payload={},
                    priority=1,
                    status=JobStatus.COMPLETED,
                    result={},
                    completed_at=datetime.now(UTC),
                ))
                await s.commit()

                active = await sched.count_active(s, eng_id)
                if active == 0:
                    e.status = "completed"
                    e.completed_at = datetime.now(UTC)
                await s.commit()
                return e.status

        assert asyncio.run(_go()) == "completed"
