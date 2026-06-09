"""Reporter agent: findings must be persisted to the DB before the MD file is written.

The DB row is the source of truth for any future report regeneration;
the MD file is a derived view. This test verifies that the reporter's
``_persist_findings`` inserts one row per finding into the ``findings``
table via the session it was given.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from src.agents.reporter import ReporterAgent


@pytest.fixture
async def in_memory_db():
    """Provide a session_maker bound to an in-memory SQLite DB with the schema applied."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from src.db.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def temp_cwd():
    """chdir to a temp dir, restore cwd after the test (and don't leak to siblings)."""
    original = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(original)


@pytest.mark.asyncio
async def test_persist_findings_inserts_one_row_per_finding(in_memory_db, temp_cwd) -> None:
    from src.db.models import Engagement, Finding, Severity, Target

    async with in_memory_db() as s:
        t = Target(name="test", url="http://test", target_type="webapp", verified=True)
        s.add(t)
        await s.flush()
        eng = Engagement(target_id=t.id, config={})
        s.add(eng)
        await s.flush()
        eng_id = eng.id

        findings = [
            {
                "title": "Reflected XSS",
                "description": "User input rendered without encoding",
                "severity": "high",
                "confidence_score": 0.8,
                "validated": True,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021",
                "remediation": "Output-encode all user input",
                "source_agent": "pentester",
                "dedup_key": "abc123",
                "evidence": {"request": "GET /?q=<script>"},
            },
            {
                "title": "Open redirect",
                "description": "next= parameter accepts arbitrary URLs",
                "severity": "medium",
                "confidence_score": 0.6,
                "validated": True,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021",
                "remediation": "Whitelist redirect targets",
                "source_agent": "pentester",
                "dedup_key": "def456",
            },
        ]

        agent = ReporterAgent()
        from src.llm.frontier_client import UnifiedLLMClient

        with patch.object(UnifiedLLMClient, "chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "{}"
            with patch.object(UnifiedLLMClient, "close", new_callable=AsyncMock):
                async with in_memory_db() as reporter_session:
                    payload = {
                        "engagement_id": eng_id,
                        "previous_result": {
                            "validated_findings": findings,
                            "attack_paths": [],
                            "target_url": "http://test",
                            "surface": {},
                            "analysis_notes": "",
                        },
                    }
                    result = await agent.execute(payload, reporter_session)
                    await reporter_session.commit()

        async with in_memory_db() as s:
            rows = (
                await s.execute(
                    select(Finding).where(Finding.engagement_id == eng_id)
                )
            ).scalars().all()

        assert len(rows) == 2, f"Expected 2 finding rows, got {len(rows)}"
        titles = {r.title for r in rows}
        assert "Reflected XSS" in titles
        assert "Open redirect" in titles
        sevs = {r.severity for r in rows}
        assert Severity.HIGH in sevs
        assert Severity.MEDIUM in sevs

        dedup_keys = {r.dedup_key for r in rows}
        assert "abc123" in dedup_keys
        assert "def456" in dedup_keys

        assert result["report_path"]
        assert Path(result["report_path"]).exists()


@pytest.mark.asyncio
async def test_persist_findings_handles_empty_list(in_memory_db, temp_cwd) -> None:
    """A zero-finding run must not crash and must not insert rows."""
    from sqlalchemy import func

    from src.db.models import Engagement, Finding, Target

    async with in_memory_db() as s:
        t = Target(name="t", url="http://t", target_type="webapp", verified=True)
        s.add(t)
        await s.flush()
        eng = Engagement(target_id=t.id, config={})
        s.add(eng)
        await s.flush()
        eng_id = eng.id

    agent = ReporterAgent()
    from src.llm.frontier_client import UnifiedLLMClient

    with patch.object(UnifiedLLMClient, "chat", new_callable=AsyncMock) as mock_chat:
        mock_chat.return_value = "{}"
        with patch.object(UnifiedLLMClient, "close", new_callable=AsyncMock):
            async with in_memory_db() as reporter_session:
                payload = {
                    "engagement_id": eng_id,
                    "previous_result": {
                        "validated_findings": [],
                        "attack_paths": [],
                        "target_url": "http://t",
                        "surface": {},
                        "analysis_notes": "",
                    },
                }
                result = await agent.execute(payload, reporter_session)
                await reporter_session.commit()

    async with in_memory_db() as s:
        count = (
            await s.execute(
                select(func.count())
                .select_from(Finding)
                .where(Finding.engagement_id == eng_id)
            )
        ).scalar()
    assert count == 0
    assert Path(result["report_path"]).exists()
    body = Path(result["report_path"]).read_text()
    assert "No exploitable vulnerabilities" in body
