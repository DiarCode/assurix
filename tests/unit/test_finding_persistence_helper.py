"""W1-B regression: the shared ``persist_findings`` helper is the
contract by which investigation agents INSERT findings at the source.

The original reporter-only test (test_finding_persistence.py) covers
the reporter's finalization path. This file covers the per-agent
persistence helper that closes defect 2 — the 14 raw findings from
the live ``d546573b-...`` engagement that were collected into the
HAR blob but never reached the ``findings`` table.
"""
from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.agents._finding_persistence import persist_findings
from src.db.models import Base, Engagement, EvidenceArtifact, Finding, Target


def _build_session_factory() -> tuple[Any, str]:
    """In-memory SQLite + created schema + one engagement."""
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def _setup() -> tuple[Any, str]:
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = async_sessionmaker(eng, expire_on_commit=False)
        async with Session() as s:
            eng_id = str(uuid4())
            tgt_id = str(uuid4())
            s.add(Target(id=tgt_id, name="https://t", url="https://t", target_type="webapp", verified=1))
            s.add(Engagement(id=eng_id, target_id=tgt_id, status="running", config={}))
            await s.commit()
        return Session, eng_id

    Session, eng_id = asyncio.run(_setup())
    return Session, eng_id


class TestPersistFindingsHelper:
    def test_persists_simple_findings(self) -> None:
        Session, eng_id = _build_session_factory()

        async def _go() -> int:
            findings = [
                {"title": "XSS", "description": "reflected", "severity": "high",
                 "confidence_score": 0.8, "category": "xss", "param": "q", "url": "https://t/"},
                {"title": "CSP missing", "description": "no header", "severity": "medium",
                 "confidence_score": 0.6, "category": "headers", "url": "https://t/"},
            ]
            async with Session() as s:
                n = await persist_findings(s, eng_id, findings, source_agent="webapp", target_url="https://t/")
                await s.commit()
            return n

        n = asyncio.run(_go())
        assert n == 2

    def test_persists_evidence_artifact_when_evidence_is_dict(self) -> None:
        Session, eng_id = _build_session_factory()

        async def _go() -> tuple[int, int]:
            findings = [
                {"title": "f1", "description": "x", "severity": "low", "confidence_score": 0.5,
                 "evidence": {"request": "GET /x", "response": "200"}},
            ]
            async with Session() as s:
                await persist_findings(s, eng_id, findings, source_agent="pentester", target_url="https://t/")
                await s.commit()
                from sqlalchemy import select
                f_rows = (await s.execute(select(Finding).where(Finding.engagement_id == eng_id))).scalars().all()
                a_rows = (await s.execute(select(EvidenceArtifact).where(EvidenceArtifact.engagement_id == eng_id))).scalars().all()
                return len(f_rows), len(a_rows)

        findings_n, arts_n = asyncio.run(_go())
        assert findings_n == 1
        assert arts_n == 1

    def test_set_metadata_is_coerced_to_list(self) -> None:
        """The SQLAlchemy JSON column has no default=str fallback; sets
        would crash the flush. The helper must coerce."""
        Session, eng_id = _build_session_factory()

        async def _go() -> Any:
            findings = [
                {"title": "set-test", "description": "x", "severity": "info", "confidence_score": 0.3,
                 "tags": {"a", "b", "c"}},
            ]
            async with Session() as s:
                await persist_findings(s, eng_id, findings, source_agent="reasoner", target_url="https://t/")
                await s.commit()
                from sqlalchemy import select
                row = (await s.execute(select(Finding).where(Finding.engagement_id == eng_id))).scalar_one()
                return row

        row = asyncio.run(_go())
        assert isinstance(row.finding_metadata["tags"], list)

    def test_malformed_finding_is_skipped_not_fatal(self) -> None:
        """A bad-severity finding should be coerced to info, not
        crash the whole batch."""
        Session, eng_id = _build_session_factory()

        async def _go() -> int:
            findings = [
                {"title": "ok", "description": "x", "severity": "low", "confidence_score": 0.4},
                {"title": "bad-sev", "description": "x", "severity": "OMEGA-CRITICAL", "confidence_score": 0.4},
            ]
            async with Session() as s:
                n = await persist_findings(s, eng_id, findings, source_agent="webapp", target_url="https://t/")
                await s.commit()
            return n

        n = asyncio.run(_go())
        assert n == 2  # both inserted; bad severity coerced to info

    def test_empty_findings_list_is_noop(self) -> None:
        Session, eng_id = _build_session_factory()

        async def _go() -> int:
            async with Session() as s:
                n = await persist_findings(s, eng_id, [], source_agent="webapp", target_url="https://t/")
            return n

        assert asyncio.run(_go()) == 0

    def test_dedup_key_is_stable_across_calls(self) -> None:
        """The same (target, category, param) should hash to the same
        dedup_key across two calls — the reporter relies on this for
        dedup at report time."""
        Session, eng_id = _build_session_factory()
        f = {"title": "X", "description": "x", "severity": "low", "confidence_score": 0.4,
             "category": "xss", "param": "q", "url": "https://t/"}

        async def _go() -> tuple[str, str]:
            async with Session() as s:
                await persist_findings(s, eng_id, [f], source_agent="webapp", target_url="https://t/")
                await s.commit()
            async with Session() as s:
                await persist_findings(s, eng_id, [f], source_agent="webapp", target_url="https://t/")
                await s.commit()
            from sqlalchemy import select
            async with Session() as s:
                rows = (await s.execute(select(Finding).where(Finding.engagement_id == eng_id))).scalars().all()
                return rows[0].dedup_key, rows[1].dedup_key

        k1, k2 = asyncio.run(_go())
        assert k1 == k2
        assert k1 is not None
        assert len(k1) == 16
