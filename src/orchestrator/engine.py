"""Core asyncio workflow engine with SQLite durability."""

import asyncio
import contextvars
import logging
from contextlib import suppress
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.audit import log_action, set_active_engagement
from src.core.exceptions import PolicyBlockedError
from src.db.models import Engagement, EngagementStatus, Job
from src.db.session import get_db_session

# Active WorkflowEngine instance for the current scan, used by agents
# (HypothesisOrchestrator) to dispatch follow-up work via
# submit_and_await(). Set by start_engagement(); cleared by stop().
_active_engine: ContextVar["WorkflowEngine | None"] = ContextVar(
    "_active_engine", default=None
)
from src.orchestrator.events import EventBus
from src.orchestrator.scheduler import JobScheduler
from src.orchestrator.state import EngagementStateMachine, WorkflowRouter
from src.agents.validation import ValidationAgent
try:
    # DepthPassAgent is opt-in via engagement.config.use_depth_pass (default True
    # for offensive mode). Imported lazily so tests that stub the engine don't
    # have to load the full depth module.
    from src.agents.depth_pass import DepthPassAgent
    _DEPTH_PASS_AGENT_AVAILABLE = True
except Exception:  # pragma: no cover — defensive
    DepthPassAgent = None  # type: ignore[assignment]
    _DEPTH_PASS_AGENT_AVAILABLE = False

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """Orchestrates multi-agent cyclic workflows with checkpointing."""

    def __init__(self) -> None:
        self.agents: dict[str, Any] = {}
        self.scheduler = JobScheduler()
        self.events = EventBus()
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        # Phase depth-pass: register DepthPassAgent in the agent registry so
        # the engine can route ``reporter -> depth_pass`` when
        # ``engagement.config.use_depth_pass`` is True. Lazy-import guarded so
        # tests that mock ``self.agents = {}`` are unaffected.
        if _DEPTH_PASS_AGENT_AVAILABLE and DepthPassAgent is not None:
            self.agents["depth_pass"] = DepthPassAgent
        # v2 planner registration (plan §3.1.5). ``planner`` and
        # ``planner_egats`` both map to EGATSPlanner; ``planner_linear``
        # is a one-release deprecation alias for the legacy linear OWASP
        # planner. Resolution goes through
        # ``src.agents.planner_factory.resolve_planner_class`` so the
        # dispatch table lives in one place.
        from src.agents.planner_factory import resolve_planner_class

        for _planner_name in ("planner", "planner_egats", "planner_linear"):
            try:
                self.agents[_planner_name] = resolve_planner_class(_planner_name)
            except Exception:  # pragma: no cover — defensive
                logger.exception(
                    "Failed to register planner agent_name=%s", _planner_name
                )
        # Phase 4a: future-key → asyncio.Future for submit_and_await() correlation.
        # _run_loop() resolves the future after agent execution completes by
        # reading the future_key from the result/payload metadata.
        self._pending_futures: dict[str, asyncio.Future[dict[str, Any]]] = {}
        # The engagement this engine instance is dedicated to. Jobs from other
        # engagements (left over from prior scans) are dropped by _run_loop to
        # keep the engine scoped to a single engagement per CLI run.
        self._engagement_id: str | None = None

    def register(self, name: str, agent_cls: Any) -> None:
        """Register an agent class by name."""
        self.agents[name] = agent_cls

    async def submit_and_await(
        self,
        session: AsyncSession,
        engagement_id: str,
        agent_name: str,
        payload: dict[str, Any],
        *,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Submit a job to the engine and await its result.

        Phase 4a: Enables external callers (HypothesisOrchestrator, CLI app,
        research_loop migration) to dispatch work through the durable engine
        pipeline and await the result without bypassing checkpointing/audit.

        Uses a ``future_key`` carried in the payload to correlate the
        ``asyncio.Future`` with the result produced by ``_run_loop()`` after
        the agent executes. The scheduler's own job id is opaque to the caller
        and isn't part of the API contract.

        Args:
            session: DB session used for the enqueue.
            engagement_id: Target engagement.
            agent_name: Registered agent class name to dispatch.
            payload: Job payload (forwarded to the agent and used for future
                key correlation — a ``_assurix_future_key`` field is injected
                and must be preserved through the pipeline).
            timeout: Seconds to wait for the future to resolve before raising
                ``asyncio.TimeoutError``.

        Returns:
            The agent's result dict.

        Raises:
            asyncio.TimeoutError: If the future doesn't resolve in time.
        """
        future = asyncio.get_running_loop().create_future()
        future_key = str(uuid4())
        self._pending_futures[future_key] = future
        # Mutate a copy so callers don't see a foreign key on their payload.
        job_payload = dict(payload)
        job_payload["_assurix_future_key"] = future_key

        await self.scheduler.enqueue(
            session=session,
            engagement_id=engagement_id,
            agent_name=agent_name,
            payload=job_payload,
        )

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_futures.pop(future_key, None)
            logger.warning(
                "submit_and_await timed out: agent=%s engagement=%s key=%s",
                agent_name, engagement_id, future_key,
            )
            raise

    async def _resolve_future_for(self, agent_name: str, payload: dict, result: dict) -> None:
        """Resolve a registered future if the payload carried a future_key.

        Called by ``_run_loop()`` after agent execution completes. Safe to
        call when no future is registered for the key (the result is dropped
        in that case — normal linear pipeline doesn't need awaiters).
        """
        future_key = result.get("_assurix_future_key") or payload.get("_assurix_future_key")
        if not future_key:
            return
        future = self._pending_futures.pop(future_key, None)
        if future is None or future.done():
            return
        future.set_result(result)
        logger.debug(
            "Resolved future for agent=%s key=%s", agent_name, future_key,
        )

    async def start_engagement(self, session: AsyncSession, engagement_id: str, *, target_url: str = "", extra_payload: dict | None = None) -> None:
        """Initialize an engagement and enqueue the first job.

        Args:
            session: Database session.
            engagement_id: ID of the engagement to start.
            target_url: URL of the target to scan.
            extra_payload: Optional dict merged into the first job payload AND
                stored in ``engagement.config["extra_payload"]`` for downstream
                propagation.  Carried forward in ``_run_loop()`` only when
                ``engagement.config.get("benchmark")`` is True (avoids polluting
                production scan payloads with auth artifacts).
        """
        engagement = await session.get(Engagement, engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")
        # Pin this engine to a single engagement so jobs left over from
        # previous scans cannot be picked up by _run_loop / load_pending.
        self._engagement_id = engagement_id
        # Make the engagement_id available to log_action() calls made from
        # any agent (planner, recon, etc.) during this engagement.
        set_active_engagement(engagement_id)
        # Make this engine instance discoverable to downstream agents
        # (HypothesisOrchestrator) without putting a live reference into
        # the JSON-serialized Job payload.
        _active_engine.set(self)
        engagement.status = EngagementStatus.RUNNING
        engagement.started_at = datetime.now(UTC)

        # Persist extra_payload in engagement config for downstream routing
        _extra = extra_payload or {}
        if _extra:
            config = dict(engagement.config) if engagement.config else {}
            config["extra_payload"] = _extra
            engagement.config = config

        await session.flush()

        await self.scheduler.enqueue(
            session=session,
            engagement_id=engagement_id,
            agent_name="planner",
            payload={"iteration": 0, "phase": "initial", "target_url": target_url, **_extra},
            priority=1,
        )
        await log_action(
            session=session,
            action="engagement_started",
            actor="engine",
            payload={"engagement_id": engagement_id},
        )

    async def _run_loop(self) -> None:
        """Main engine loop: dequeue, execute, checkpoint.

        Concurrency model:
        - Dequeue and DB bookkeeping (mark_running/completed, log_action,
          routing, commit) all happen inside ONE short-lived session per job.
        - Agent execution (``agent.execute``) happens OUTSIDE that session,
          with its own short-lived read-only session. This prevents the
          engine from holding a DB connection (and a write transaction) for
          the duration of an agent's LLM call — which can be 30+ seconds
          and would otherwise serialize the CLI's polling loop and any
          other concurrent reader through aiosqlite's per-connection lock.

        Why: previously the engine held a session for the entire agent
        execute. With aiosqlite (single-threaded per connection), the
        CLI's polling session could deadlock against the engine's session
        because both competed for the same connection's executor thread.
        Splitting the work into two sessions eliminates that.
        """
        self._running = True
        iter_n = 0
        while self._running:
            iter_n += 1
            if iter_n <= 3 or iter_n % 10 == 0:
                logger.info("engine._run_loop iter=%d dequeue phase", iter_n)

            # Phase 1: dequeue + bookkeeping in a short-lived session.
            async with get_db_session() as session:
                job_data = await self.scheduler.dequeue()
                if job_data is None:
                    await asyncio.sleep(1)
                    continue

                job_id, engagement_id, payload = job_data
                if (
                    self._engagement_id is not None
                    and engagement_id != self._engagement_id
                ):
                    logger.warning(
                        "Dropping job %s from foreign engagement %s "
                        "(this engine is pinned to %s)",
                        job_id, engagement_id, self._engagement_id,
                    )
                    await self.scheduler.mark_failed(
                        session, job_id, "Foreign engagement (stale leftover job)"
                    )
                    continue

                await self.scheduler.mark_running(session, job_id)
                # Resolve the agent class (this is just a dict lookup, no I/O)
                job = await session.get(Job, job_id)  # type: ignore[call-arg]
                agent_name = job.agent_name if job else ""
                agent_cls = self.agents.get(agent_name)
                if agent_cls is None:
                    await self.scheduler.mark_failed(
                        session, job_id, f"Unknown agent: {agent_name}"
                    )
                    continue

                # Snapshot the engagement row for routing decisions AFTER the
                # agent returns. We do this here (read while the session is
                # still open) so we don't need to re-query later.
                engagement = await session.get(Engagement, engagement_id)  # type: ignore[call-arg]
                engagement_config = dict(engagement.config) if engagement and engagement.config else {}
                engagement_iteration = engagement.iteration_count if engagement else 0
                # Commit so the mark_running + agent class resolution are
                # durable BEFORE the long-running agent.execute starts.
                await session.commit()

            # Phase 2: execute the agent OUTSIDE any DB session. The agent
            # gets its own short-lived session to persist findings/provenance
            # and any other DB-touching work it does.
            try:
                logger.info(
                    "engine._run_loop iter=%d executing agent %s",
                    iter_n, agent_name,
                )
                async with get_db_session() as agent_session:
                    logger.info(
                        "engine._run_loop iter=%d opened agent session, calling execute",
                        iter_n,
                    )
                    result = await agent_cls().execute(payload, agent_session)
                    logger.info(
                        "engine._run_loop iter=%d execute returned, committing agent session",
                        iter_n,
                    )
                    await agent_session.commit()
                    logger.info(
                        "engine._run_loop iter=%d agent session committed",
                        iter_n,
                    )
                logger.info(
                    "engine._run_loop iter=%d agent %s returned",
                    iter_n, agent_name,
                )
            except PolicyBlockedError:
                raise
            except Exception as exc:
                logger.warning(
                    "engine._run_loop iter=%d agent %s failed: %s",
                    iter_n, agent_name, exc,
                )
                async with get_db_session() as err_session:
                    await self.scheduler.mark_failed(err_session, job_id, str(exc))
                    await log_action(
                        session=err_session,
                        action="agent_failed",
                        actor=agent_name,
                        payload={"engagement_id": engagement_id, "error": str(exc)},
                    )
                    await err_session.commit()
                continue

            # Phase 3: post-execute bookkeeping in a fresh short session.
            # Wrapped in try/except so a transient DB / serialization
            # error in this phase doesn't kill the whole engine task;
            # we mark the job failed and `continue` to the next
            # iteration (the engine's outer while-loop survives).
            logger.info("engine._run_loop iter=%d entering post-execute phase", iter_n)
            try:
                async with get_db_session() as session:
                    await self.scheduler.mark_completed(session, job_id, result)
                await log_action(
                    session=session,
                    action="agent_completed",
                    actor=agent_name,
                    payload={
                        "engagement_id": engagement_id,
                        "result_summary": str(result)[:500],
                    },
                )
                logger.debug("engine._run_loop iter=%d agent_completed logged", iter_n)
                # Phase 4a: resolve any submit_and_await future before
                # routing. Must happen before commit so the result is
                # durable when the awaiter resumes.
                logger.debug("engine._run_loop iter=%d calling _resolve_future_for", iter_n)
                await self._resolve_future_for(agent_name, payload, result)
                logger.debug("engine._run_loop iter=%d _resolve_future_for done", iter_n)

                # Re-load the engagement (it may have been mutated by the
                # agent or by an external process).
                logger.debug("engine._run_loop iter=%d loading engagement", iter_n)
                engagement = await session.get(Engagement, engagement_id)  # type: ignore[call-arg]
                logger.info("engine._run_loop iter=%d engagement loaded, has_engagement=%s", iter_n, engagement is not None)
                if not engagement:
                    await session.commit()
                    continue

                # Carry extra_payload forward (benchmark runs only)
                _extra: dict[str, Any] = {}
                if engagement.config.get("benchmark"):
                    _extra = engagement.config.get("extra_payload", {})

                logger.info("engine._run_loop iter=%d routing logic, agent=%s", iter_n, agent_name)
                if agent_name != "reporter" or engagement.config.get("use_depth_pass", False):
                    # Phase depth-pass: ``reporter -> depth_pass`` edge. When
                    # ``use_depth_pass`` is set, the reporter is no longer
                    # terminal — we enqueue the depth pass and keep the
                    # engagement in RUNNING. The depth pass signals
                    # completion via ``result.get("depth_pass_complete")`` on
                    # its return, which the second branch below handles.
                    if (
                        agent_name == "reporter"
                        and engagement.config.get("use_depth_pass", False)
                        and "depth_pass" in self.agents
                    ):
                        # Idempotency lock: skip if depth pass already ran in
                        # the last 60 minutes (per plan §Risks). Also bail if
                        # an operator has cancelled mid-flight.
                        if engagement.config.get("depth_pass_cancelled"):
                            logger.info(
                                "depth_pass cancelled by operator for engagement=%s",
                                engagement_id,
                            )
                        else:
                            started_at = engagement.config.get("depth_pass_started_at")
                            if started_at:
                                try:
                                    from datetime import datetime as _dt
                                    delta = (_dt.now(UTC) - _dt.fromisoformat(started_at)).total_seconds()
                                    if delta < 3600:
                                        logger.info(
                                            "depth_pass already started %ds ago for engagement=%s — skipping",
                                            int(delta), engagement_id,
                                        )
                                    else:
                                        started_at = None  # stale, allow rerun
                                except Exception:
                                    started_at = None
                            if not started_at:
                                # Stamp start time so a duplicate routing
                                # pass (or a manual cancel + rerun) is a
                                # no-op while the depth pass is live.
                                #
                                # SECURITY (FIX 7): The check+stamp pattern
                                # below is racy under two parallel
                                # ``reporter`` routing passes because the
                                # engine has no row-level lock to gate the
                                # read-then-write of ``started_at``. We
                                # accept this race as a documented
                                # limitation: the engine is single-instance
                                # per CLI run per the plan §Implementation
                                # Architecture, so the only way to get two
                                # concurrent reporter routings is operator
                                # action (manually invoking two
                                # ``start_engagement`` calls). In that
                                # trust model, the worst case is one
                                # duplicate ``depth_pass`` enqueue — not a
                                # safety violation, just wasted work. The
                                # depth pass itself is idempotent (it
                                # short-circuits on existing dedup_keys).
                                cfg = dict(engagement.config or {})
                                cfg["depth_pass_started_at"] = datetime.now(UTC).isoformat()
                                engagement.config = cfg

                                await self.scheduler.enqueue(
                                    session=session,
                                    engagement_id=engagement_id,
                                    agent_name="depth_pass",
                                    payload={
                                        "phase": "main",
                                        "engagement_id": engagement_id,
                                        "iteration": engagement.iteration_count,
                                        "previous_result": result,
                                        "target_url": payload.get("target_url", ""),
                                        "config": cfg,
                                        **_extra,
                                    },
                                    priority=1,
                                )
                                await log_action(
                                    session=session,
                                    action="routed_to_depth_pass",
                                    actor="engine",
                                    payload={"engagement_id": engagement_id},
                                )
                                # IMPORTANT: do NOT transition to COMPLETED
                                # here — depth_pass will run on the next
                                # iteration and either complete or fail. The
                                # transition to COMPLETED happens in the
                                # depth_pass branch below.
                            else:
                                # Already started, but reporter fired again
                                # (replay / second routing). Treat reporter
                                # as terminal this time to avoid an infinite
                                # depth_pass -> reporter loop.
                                if EngagementStateMachine.can_transition(
                                    engagement.status, EngagementStatus.COMPLETED
                                ):
                                    engagement.status = EngagementStatus.COMPLETED
                                    engagement.completed_at = datetime.now(UTC)
                                    await self.events.emit(
                                        "engagement_completed",
                                        {"engagement_id": engagement_id},
                                    )
                    elif agent_name == "depth_pass":
                        # Post-depth-pass: if the agent signalled completion
                        # (its result dict carries ``depth_pass_complete``),
                        # transition the engagement to COMPLETED. If the
                        # depth pass returned without that flag, treat as
                        # best-effort completion — the budget aborted cleanly.
                        depth_pass_complete = bool(result.get("depth_pass_complete"))
                        if depth_pass_complete and EngagementStateMachine.can_transition(
                            engagement.status, EngagementStatus.COMPLETED
                        ):
                            engagement.status = EngagementStatus.COMPLETED
                            engagement.completed_at = datetime.now(UTC)
                            await self.events.emit(
                                "engagement_completed",
                                {"engagement_id": engagement_id},
                            )
                        # Clear the idempotency lock so a manual rerun can
                        # start a fresh depth pass.
                        cfg = dict(engagement.config or {})
                        cfg.pop("depth_pass_started_at", None)
                        engagement.config = cfg
                        await log_action(
                            session=session,
                            action="depth_pass_routing_completed",
                            actor="engine",
                            payload={
                                "engagement_id": engagement_id,
                                "depth_pass_complete": depth_pass_complete,
                                "aborted_reason": result.get("aborted_reason"),
                                "findings_count": len(result.get("findings", [])),
                                "chains_count": len(result.get("chains", [])),
                            },
                        )
                    elif agent_name == "planner" and engagement.config.get("use_research_loop", False):
                        await self.scheduler.enqueue(
                            session=session,
                            engagement_id=engagement_id,
                            agent_name="research_loop",
                            payload={
                                "engagement_id": engagement_id,
                                "iteration": engagement.iteration_count,
                                "previous_result": result,
                                "target_url": payload.get("target_url", ""),
                                **_extra,
                            },
                            priority=1,
                        )
                        await log_action(
                            session=session,
                            action="routed_to_research_loop",
                            actor="engine",
                            payload={"engagement_id": engagement_id},
                        )
                    elif agent_name == "planner" and engagement.config.get("use_hypothesis_orchestrator", False):
                        logger.debug("engine._run_loop iter=%d about to enqueue hypothesis_orchestrator", iter_n)
                        # NOTE: do not put a live engine reference into the
                        # payload — it is persisted as JSON and would hang
                        # the flush with an infinite-recursion serializer
                        # error. The orchestrator reads the engine from a
                        # contextvar (set in start_engagement).
                        await self.scheduler.enqueue(
                            session=session,
                            engagement_id=engagement_id,
                            agent_name="hypothesis_orchestrator",
                            payload={
                                "engagement_id": engagement_id,
                                "iteration": engagement.iteration_count,
                                "previous_result": result,
                                "target_url": payload.get("target_url", ""),
                                **_extra,
                            },
                            priority=1,
                        )
                        logger.info("engine._run_loop iter=%d enqueue done, logging", iter_n)
                        await log_action(
                            session=session,
                            action="routed_to_hypothesis_orchestrator",
                            actor="engine",
                            payload={"engagement_id": engagement_id},
                        )
                        logger.debug("engine._run_loop iter=%d log_action done", iter_n)
                    elif agent_name == "reasoner" and result.get("re_investigate"):
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
                                **_extra,
                            },
                            priority=2,
                        )
                        await log_action(
                            session=session,
                            action="re_investigation_requested",
                            actor="engine",
                            payload={
                                "engagement_id": engagement_id,
                                "targets": [
                                    t.get("task_type", "")
                                    for t in reinvestigation_targets[:5]
                                ],
                            },
                        )
                    elif agent_name == "research_loop":
                        if EngagementStateMachine.can_transition(
                            engagement.status, EngagementStatus.COMPLETED
                        ):
                            engagement.status = EngagementStatus.COMPLETED
                            engagement.completed_at = datetime.now(UTC)
                            await self.events.emit(
                                "engagement_completed",
                                {"engagement_id": engagement_id},
                            )
                        await log_action(
                            session=session,
                            action="research_loop_completed",
                            actor="engine",
                            payload={"engagement_id": engagement_id},
                        )
                    elif agent_name == "hypothesis_orchestrator":
                        if EngagementStateMachine.can_transition(
                            engagement.status, EngagementStatus.COMPLETED
                        ):
                            engagement.status = EngagementStatus.COMPLETED
                            engagement.completed_at = datetime.now(UTC)
                            await self.events.emit(
                                "engagement_completed",
                                {"engagement_id": engagement_id},
                            )
                        await log_action(
                            session=session,
                            action="hypothesis_orchestrator_completed",
                            actor="engine",
                            payload={"engagement_id": engagement_id},
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
                                    **_extra,
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
            except Exception as phase3_exc:
                logger.warning(
                    "engine._run_loop iter=%d post-execute phase failed: %s",
                    iter_n, phase3_exc,
                )
                async with get_db_session() as err_s:
                    await self.scheduler.mark_failed(err_s, job_id, f"Post-execute error: {phase3_exc!r}")
                    await err_s.commit()
                continue

    def start(self) -> None:
        """Start the engine loop in a background task."""
        if self._task is None or self._task.done():
            # asyncio.create_task() does NOT propagate ContextVars by
            # default — the new task would see None for the active
            # engagement_id and engine bindings set by start_engagement().
            # Copy the current context so agents that call log_action()
            # or get_active_engine() see the right values.
            self._task = asyncio.create_task(
                self._start_and_run(), context=contextvars.copy_context()
            )

    async def _start_and_run(self) -> None:
        """Load pending jobs then run the main loop."""
        async with get_db_session() as session:
            # Only hydrate jobs for the engagement this engine is dedicated to.
            # Stale jobs from prior scans (other engagements) must NOT be loaded
            # — the engine has no context for them and they would block progress
            # on the current scan.
            await self.scheduler.load_pending(session, self._engagement_id)
            await session.commit()
        await self._run_loop()

    async def stop(self) -> None:
        """Gracefully stop the engine loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        # Clear the active engine binding so a future scan (if any) starts
        # from a clean state.
        if _active_engine.get() is self:
            _active_engine.set(None)


def get_active_engine() -> "WorkflowEngine | None":
    """Return the WorkflowEngine instance bound by start_engagement().

    Used by agents (e.g. HypothesisOrchestrator) to dispatch follow-up
    work via submit_and_await() without requiring a live engine reference
    in the JSON-serialized Job payload.
    """
    return _active_engine.get()


# Global singleton engine instance
engine = WorkflowEngine()
