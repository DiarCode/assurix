"""Phase 5 / Plan §3.3.1 — chains endpoint reads from the dedicated column.

The GET /scans/{id}/chains endpoint is now a single-column read. The
reasoner populates ``engagement.chains`` at the end of its run, and the
endpoint returns that column verbatim — no LLM call, no graph rebuild,
no fallback rebuild path.

These tests exercise the new read path through the FastAPI app with
the ``get_db`` dependency overridden to use an in-memory SQLite engine.
We also pin the endpoint's contract:

  * 404 when the engagement does not exist
  * 200 with empty list when the reasoner has not run yet
  * 200 with the persisted chains (and chain_run_at) when populated

If a future contributor reintroduces the LLM-call-on-read fallback, the
"isolated from LLM" tests will catch it because we never construct an
LLM client in this test module.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.api.deps import get_db
from src.api.routers.scans import router
from src.db.models import Base, Engagement, Target, TargetType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def app_and_session() -> AsyncGenerator[tuple[FastAPI, AsyncSession], None]:
    """In-process FastAPI app + a session bound to an isolated in-memory
    SQLite engine.

    We override ``get_db`` so the endpoint reads from OUR engine, not
    the global cached engine. This is the standard FastAPI pattern for
    test isolation.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False,
    )

    app = FastAPI()
    # The router is mounted at /scans in the main app; we mirror that
    # prefix here so the in-process app matches the production routing.
    app.include_router(router, prefix="/scans")

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db

    async with session_maker() as session:
        yield app, session

    await engine.dispose()


async def _create_engagement(session: AsyncSession) -> Engagement:
    """Create a target + engagement with default config. The engagement
    is committed (the router's get_db overrides flush on commit, so we
    need the row visible)."""
    target = Target(
        id="tgt-test-1",
        name="test-target",
        target_type=TargetType.WEBAPP,
        url="https://example.com",
    )
    session.add(target)
    await session.flush()

    eng = Engagement(
        id="eng-test-1",
        target_id=target.id,
        status="pending",
        config={},
    )
    session.add(eng)
    await session.flush()
    return eng


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChainsEndpointReadsFromColumn:
    async def test_404_when_scan_does_not_exist(
        self, app_and_session: tuple[FastAPI, AsyncSession],
    ) -> None:
        app, _ = app_and_session
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/scans/no-such-id/chains")
        assert response.status_code == 404

    async def test_empty_chains_when_reasoner_has_not_run(
        self, app_and_session: tuple[FastAPI, AsyncSession],
    ) -> None:
        app, session = app_and_session
        await _create_engagement(session)
        await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/scans/eng-test-1/chains")
        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"] == "eng-test-1"
        assert body["chain_count"] == 0
        assert body["chains"] == []
        assert body["chain_run_at"] is None

    async def test_returns_persisted_chains(
        self, app_and_session: tuple[FastAPI, AsyncSession],
    ) -> None:
        app, session = app_and_session
        eng = await _create_engagement(session)
        # Simulate the reasoner having already populated the column.
        sample_chains: list[dict[str, Any]] = [
            {
                "name": "XSSPlusCSPGap -> JWTAlgNone",
                "pattern": "XSSPlusCSPGap",
                "steps": [
                    {"order": 0, "finding_class": "xss",
                     "finding_title": "Stored XSS", "severity": "high",
                     "grants_capability": "privilege_escalation", "url": "",
                     "evidence": ""},
                ],
                "severity": "critical",
                "skill_level": "intermediate",
                "likelihood": "probable",
                "business_impact": "high",
                "capability_path": ["privilege_escalation"],
                "description": "XSS chain",
            },
        ]
        eng.chains = sample_chains
        eng.chain_run_at = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
        await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/scans/eng-test-1/chains")
        assert response.status_code == 200
        body = response.json()
        assert body["chain_count"] == 1
        assert body["chains"] == sample_chains
        # SQLite strips tzinfo; we just check the ISO prefix.
        assert body["chain_run_at"] is not None
        assert body["chain_run_at"].startswith("2026-06-03T12:00:00")

    async def test_endpoint_does_not_call_attack_graph_builder(
        self, app_and_session: tuple[FastAPI, AsyncSession],
    ) -> None:
        """The /chains endpoint must NOT import or invoke
        ``AttackGraphBuilder`` — that would re-introduce the LLM-backed
        rebuild-on-read fallback. We assert that the read path is
        independent by stubbing the import to raise if touched.

        This is the regression test for the slop warning: a future
        contributor adding a fallback path here will see this test
        fail.
        """
        import sys

        app, session = app_and_session
        await _create_engagement(session)
        await session.commit()

        # Patch at the route module level. If the route imports
        # AttackGraphBuilder, the ImportError is raised inside the
        # request handler and the response is 500.
        original_import = __builtins__["__import__"] if isinstance(
            __builtins__, dict,
        ) else __builtins__.__import__

        def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "src.graph.attack_graph" or name.endswith(
                ".attack_graph",
            ):
                raise AssertionError(
                    "GET /scans/{id}/chains must not import "
                    "AttackGraphBuilder — the column-based read path "
                    "is the contract."
                )
            return original_import(name, *args, **kwargs)

        if isinstance(__builtins__, dict):
            __builtins__["__import__"] = guarded_import
        else:
            __builtins__.__import__ = guarded_import

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test",
            ) as client:
                response = await client.get("/scans/eng-test-1/chains")
        finally:
            if isinstance(__builtins__, dict):
                __builtins__["__import__"] = original_import
            else:
                __builtins__.__import__ = original_import
            _ = sys  # silence linter

        assert response.status_code == 200, (
            "Importing AttackGraphBuilder should not happen on this "
            "read path; the test must fail if the import is attempted."
        )
