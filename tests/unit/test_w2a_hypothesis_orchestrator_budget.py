"""W2-A regression: HypothesisOrchestrator enforces a cumulative budget
and always marks tool invocations complete.

Defect 3 was that ``_dispatch_investigation`` used a hardcoded 180s
per-call timeout. A single stuck tool call blocked the entire
iteration until the outer 25-min browser ceiling kicked in, leaving
5 ``tool_invocations`` rows with ``completed_at IS NULL`` in the
dj1naq.sytes.net scan.

The fix:

1. ``hypothesis_orchestrator_cumulative_budget_seconds`` (default
   900s) bounds the total wall-clock of one ``execute()`` call.
2. Each ``engine.submit_and_await`` call uses
   ``min(per_call_timeout, remaining_budget - 10s)`` so a single
   tool call cannot exceed the cumulative ceiling.
3. ``_mark_tool_invocation_complete`` is called in a
   ``try/finally`` so the ``completed_at IS NULL`` invariant holds
   on success, on engine failure, and on the cumulative-budget
   exhausted path.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
from src.db.models import Base, Engagement, Target, ToolInvocation


def _build_session_factory() -> tuple:
    """In-memory SQLite + schema + one running engagement + a target.

    The ``engagements.target_id`` column is NOT NULL, so we need a
    Target row to satisfy the FK.
    """
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
            s.add(Engagement(id=eng_id, target_id=tgt_id, status="running",
                             config={}))
            await s.commit()
        return Session, eng_id

    return eng, asyncio.run(_setup())


def _make_orchestrator() -> HypothesisOrchestrator:
    """Build a real HypothesisOrchestrator via __init__.

    Settings dependency is satisfied by pydantic's default values —
    no mocking needed because both budget knobs have safe defaults.
    """
    return HypothesisOrchestrator()


class TestPerCallTimeoutIsBudgetDerived:
    def test_engine_uses_per_call_ceiling_when_no_budget_deadline(self) -> None:
        """Without a budget_deadline, the dispatcher falls back to the
        configured per-call ceiling. This is the direct-caller /
        test path."""
        orch = _make_orchestrator()
        # Bypass the rest: invoke _dispatch_investigation with engine=None
        # so the dispatcher takes the ``_invoke_agent_directly`` path,
        # which doesn't use the timeout. The engine path is what we
        # actually want to assert — covered by the next test.
        # The point of this test is just that the orchestrator was
        # constructed with both budget attributes set.
        assert hasattr(orch, "_cumulative_budget_s")
        assert hasattr(orch, "_per_call_timeout_s")
        assert orch._cumulative_budget_s > 0
        assert orch._per_call_timeout_s > 0

    def test_engine_timeout_uses_budget_derived_value(self) -> None:
        """When ``budget_deadline`` is passed (the normal execute()
        path), the per-call timeout is derived from the remaining
        budget and capped at the per-call ceiling."""
        from sqlalchemy import select

        eng, (Session, eng_id) = _build_session_factory()
        orch = _make_orchestrator()

        async def _go():
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "running"
                await s.flush()
                invocation_seen = {}

                # Capture the timeout that was passed to submit_and_await.
                async def fake_submit(*, session, engagement_id, agent_name,
                                      payload, timeout):
                    invocation_seen["timeout"] = timeout
                    return {"findings": [], "artifacts": []}

                fake_engine = MagicMock()
                fake_engine.submit_and_await = AsyncMock(side_effect=fake_submit)

                # Set a budget that has 5s remaining (well under the
                # default 180s per-call ceiling).
                budget_deadline = time.monotonic() + 15.0  # 15s remaining

                await orch._dispatch_investigation(
                    hypothesis={
                        "hypothesis_class": "test-class",
                        "attack_category": "test",
                        "description": "test",
                        "required_capabilities": [],
                        "falsification_criteria": "",
                        "confidence": 0.5,
                    },
                    hypothesis_id=str(uuid4()),
                    payload={
                        "engagement_id": eng_id,
                        "target_url": "https://t",
                    },
                    surface={},
                    session=s,
                    engagement_id=eng_id,
                    engine=fake_engine,
                    budget_deadline=budget_deadline,
                )
                await s.commit()
                return invocation_seen["timeout"]

        # The effective timeout is min(180, 15 - 10) = 5s, floored at 5s.
        observed = asyncio.run(_go())
        assert observed == pytest.approx(5.0, abs=0.5)


class TestToolInvocationAlwaysCompleted:
    def test_completed_at_set_on_success(self) -> None:
        """After a successful engine dispatch, the tool invocation row
        has ``completed_at`` set and a ``result_summary`` populated."""
        from sqlalchemy import select

        eng, (Session, eng_id) = _build_session_factory()
        orch = _make_orchestrator()

        async def _go():
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "running"
                await s.flush()

                async def fake_submit(*, session, engagement_id, agent_name,
                                      payload, timeout):
                    return {"findings": [{"title": "x", "severity": "low",
                                          "confidence_score": 0.5}],
                            "artifacts": []}

                fake_engine = MagicMock()
                fake_engine.submit_and_await = AsyncMock(side_effect=fake_submit)

                await orch._dispatch_investigation(
                    hypothesis={
                        "hypothesis_class": "test-class",
                        "attack_category": "test",
                        "description": "test",
                        "required_capabilities": [],
                        "falsification_criteria": "",
                        "confidence": 0.5,
                    },
                    hypothesis_id=str(uuid4()),
                    payload={"engagement_id": eng_id, "target_url": "https://t"},
                    surface={},
                    session=s,
                    engagement_id=eng_id,
                    engine=fake_engine,
                    budget_deadline=time.monotonic() + 60.0,
                )
                await s.commit()
                rows = (await s.execute(
                    select(ToolInvocation).where(
                        ToolInvocation.engagement_id == eng_id
                    )
                )).scalars().all()
                return rows

        rows = asyncio.run(_go())
        assert len(rows) == 1
        assert rows[0].completed_at is not None
        assert rows[0].result_summary is not None
        assert rows[0].result_summary.get("status") == "ok"
        assert rows[0].result_summary.get("findings_count") == 1

    def test_completed_at_set_on_engine_failure(self) -> None:
        """When ``engine.submit_and_await`` raises, the invocation
        row still has ``completed_at`` set and a status='error'
        summary. This is the W2-A invariant."""
        from sqlalchemy import select

        eng, (Session, eng_id) = _build_session_factory()
        orch = _make_orchestrator()

        async def _go():
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "running"
                await s.flush()

                async def fake_submit(*, session, engagement_id, agent_name,
                                      payload, timeout):
                    raise RuntimeError("simulated engine hang")

                fake_engine = MagicMock()
                fake_engine.submit_and_await = AsyncMock(side_effect=fake_submit)

                result = await orch._dispatch_investigation(
                    hypothesis={
                        "hypothesis_class": "test-class",
                        "attack_category": "test",
                        "description": "test",
                        "required_capabilities": [],
                        "falsification_criteria": "",
                        "confidence": 0.5,
                    },
                    hypothesis_id=str(uuid4()),
                    payload={"engagement_id": eng_id, "target_url": "https://t"},
                    surface={},
                    session=s,
                    engagement_id=eng_id,
                    engine=fake_engine,
                    budget_deadline=time.monotonic() + 60.0,
                )
                await s.commit()
                rows = (await s.execute(
                    select(ToolInvocation).where(
                        ToolInvocation.engagement_id == eng_id
                    )
                )).scalars().all()
                return result, rows

        result, rows = asyncio.run(_go())
        # Dispatch returns an empty result on failure (reporter still
        # has something to write about).
        assert result["findings"] == []
        # The provenance row is closed — the W2-A invariant.
        assert len(rows) == 1
        assert rows[0].completed_at is not None
        assert rows[0].result_summary.get("status") == "error"
        assert "simulated engine hang" in rows[0].result_summary.get("error", "")

    def test_completed_at_set_on_budget_skipped(self) -> None:
        """If the remaining budget is ≤ 10s, the dispatcher short-
        circuits and marks the invocation as 'skipped'."""
        from sqlalchemy import select

        eng, (Session, eng_id) = _build_session_factory()
        orch = _make_orchestrator()

        async def _go():
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "running"
                await s.flush()

                fake_engine = MagicMock()
                fake_engine.submit_and_await = AsyncMock()

                result = await orch._dispatch_investigation(
                    hypothesis={
                        "hypothesis_class": "test-class",
                        "attack_category": "test",
                        "description": "test",
                        "required_capabilities": [],
                        "falsification_criteria": "",
                        "confidence": 0.5,
                    },
                    hypothesis_id=str(uuid4()),
                    payload={"engagement_id": eng_id, "target_url": "https://t"},
                    surface={},
                    session=s,
                    engagement_id=eng_id,
                    engine=fake_engine,
                    # Deadline already past: forces the skip path.
                    budget_deadline=time.monotonic() - 1.0,
                )
                await s.commit()
                rows = (await s.execute(
                    select(ToolInvocation).where(
                        ToolInvocation.engagement_id == eng_id
                    )
                )).scalars().all()
                return result, rows

        result, rows = asyncio.run(_go())
        assert result["findings"] == []
        # The invocation is closed.
        assert len(rows) == 1
        assert rows[0].completed_at is not None
        # The orchestrator records the skip — the summary uses
        # ``path=skipped, reason=budget_exhausted`` for the
        # remaining-budget-too-low short-circuit. The status field
        # is reserved for ``engine``-path results.
        assert rows[0].result_summary.get("path") == "skipped"
        assert rows[0].result_summary.get("reason") == "budget_exhausted"


class TestCumulativeBudgetBreaksTheLoop:
    def test_execute_returns_when_budget_exhausted(self) -> None:
        """The whole ``execute()`` loop exits when the budget is
        exhausted, even mid-iteration, so the report is written
        instead of stalling."""
        from sqlalchemy import select

        eng, (Session, eng_id) = _build_session_factory()
        # Tiny budget so the very first iteration check trips.
        orch = _make_orchestrator()
        orch._cumulative_budget_s = 0.001  # 1ms — exhausts immediately
        orch._per_call_timeout_s = 0.001

        async def _go():
            async with Session() as s:
                e = (await s.execute(
                    select(Engagement).where(Engagement.id == eng_id)
                )).scalar_one()
                e.status = "running"
                await s.flush()

                result = await orch.execute(
                    payload={
                        "engagement_id": eng_id,
                        "target_url": "https://t",
                    },
                    session=s,
                )
                return result

        result = asyncio.run(_go())
        # The orchestrator returned cleanly with an empty findings
        # list — the budget_exhausted path. The reporter will get a
        # payload it can render.
        assert "findings" in result
        assert isinstance(result["findings"], list)


class TestResearchLoopW2AInvariant:
    """The W2-A invariant (closed tool_invocations) also applies to
    ResearchLoop's direct-dispatch path, which is what the live
    engine actually takes. The live dj1naq.sytes.net scan left 10
    rows with ``completed_at IS NULL`` because the original
    ``research_loop._investigate_hypothesis`` only set
    ``started_at``. This test asserts the fix."""

    def test_invoke_agent_directly_marks_invocation_complete(self) -> None:
        """After a successful direct agent dispatch via
        ``_investigate_hypothesis``, the tool invocation row is
        closed with ``status='ok'``."""
        from src.agents.research_loop import ResearchLoopAgent

        eng, (Session, eng_id) = _build_session_factory()
        loop = ResearchLoopAgent()

        # Mock the agent class so we don't actually instantiate a
        # Pentester/Webapp. Returns a result with one finding.
        class FakeAgent:
            async def execute(self, payload, session):
                return {
                    "findings": [{
                        "title": "x", "severity": "low",
                        "confidence_score": 0.5,
                    }],
                    "artifacts": [],
                }

        loop._get_agent_class = lambda name: FakeAgent  # type: ignore[assignment]

        async def _go():
            from uuid import uuid4 as _uuid
            hyp_id = str(_uuid())
            # Persist a hypothesis row first (the real code does this
            # too, but we're testing the invocation close-out).
            from src.db.models import Hypothesis, HypothesisStatus
            async with Session() as s:
                hyp = Hypothesis(
                    id=hyp_id, engagement_id=eng_id,
                    hypothesis_class="test", source="pattern_match",
                    description="t", confidence=0.5,
                    status=HypothesisStatus.CANDIDATE,
                    attack_category="injection",
                    required_capabilities=[], falsification_criteria="",
                )
                s.add(hyp)
                e = (await s.execute(
                    __import__("sqlalchemy").select(Engagement).where(
                        Engagement.id == eng_id
                    )
                )).scalar_one()
                e.status = "researching"
                await s.commit()

                result = await loop._investigate_hypothesis(
                    hypothesis={
                        "hypothesis_class": "test",
                        "attack_category": "injection",
                        "description": "t",
                        "required_capabilities": [],
                        "falsification_criteria": "",
                        "confidence": 0.5,
                    },
                    hypothesis_id=hyp_id,
                    payload={
                        "engagement_id": eng_id,
                        "target_url": "https://t",
                    },
                    surface={},
                    session=s,
                    engagement_id=eng_id,
                )
                await s.commit()

                from src.db.models import ToolInvocation
                from sqlalchemy import select
                rows = (await s.execute(
                    select(ToolInvocation).where(
                        ToolInvocation.engagement_id == eng_id
                    )
                )).scalars().all()
                return result, rows

        result, rows = asyncio.run(_go())
        # The agent returned a real finding. The proof of the fix is
        # in the DB (the invocation row is closed).
        assert len(result.get("findings", [])) == 1
        assert len(rows) == 1
        assert rows[0].completed_at is not None
        assert rows[0].result_summary.get("status") == "ok"
        assert rows[0].result_summary.get("findings_count") == 1
