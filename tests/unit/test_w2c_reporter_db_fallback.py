"""W2-C regression: the reporter recovers findings from the
``findings`` table when the in-memory ``previous_result.findings``
is empty.

Defect: the live dj1naq.sytes.net scan produced 29 Finding rows in
the DB (W1-B working correctly), but the reporter's
``previous_result.findings`` was empty because the research_loop
summary result returns ``{"findings": []}``. Result: the report
read "No exploitable vulnerabilities were confirmed" even though
the DB had 1 critical, 4 high, 12 medium, and 12 low/info findings.

The fix: when ``previous_result.findings`` is empty AND we have an
``engagement_id``, the reporter queries the ``findings`` table and
rebuilds the in-memory list from the rows. Per CLAUDE.md, the DB
row is the source of truth — this is honoring the existing
contract at report-render time, not adding a workaround layer.
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.models import Base, Engagement, Finding, Target


def _build_session_factory() -> tuple:
    """In-memory SQLite + schema + one engagement + 4 finding rows."""
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
            # 4 findings spanning the severity range, mirroring the
            # live dj1naq.sytes.net distribution.
            for sev, conf, title in [
                ("critical", 0.95, "Command Injection: echo marker reflected"),
                ("high", 0.95, "Missing Content-Security-Policy header"),
                ("medium", 0.6, "Potential XSS reflection"),
                ("low", 0.5, "Missing X-Content-Type-Options"),
            ]:
                s.add(Finding(
                    id=str(uuid4()),
                    engagement_id=eng_id,
                    title=title,
                    description=f"test description for {title}",
                    severity=sev,
                    confidence_score=conf,
                    validated=True,
                    source_agent="webapp",
                    finding_metadata={
                        "evidence": {"request": "GET /x", "response": "200"},
                    },
                    dedup_key=f"test-{sev}",
                ))
            await s.commit()
        return Session, eng_id

    return eng, asyncio.run(_setup())


class TestReporterDBFallback:
    def test_load_findings_from_db_returns_rows(self) -> None:
        """The helper alone: given 4 rows, returns 4 dicts with the
        expected shape (the fields the rest of the reporter reads)."""
        eng, (Session, eng_id) = _build_session_factory()
        from src.agents.reporter import ReporterAgent

        async def _go():
            async with Session() as s:
                return await ReporterAgent()._load_findings_from_db(
                    s, eng_id
                )

        result = asyncio.run(_go())
        assert len(result) == 4
        titles = {f["title"] for f in result}
        assert "Command Injection: echo marker reflected" in titles
        for f in result:
            for key in ("title", "description", "severity",
                        "confidence_score", "validated", "source_agent",
                        "dedup_key", "evidence"):
                assert key in f, f"missing {key} in finding {f.get('title')}"

    def test_load_findings_from_db_preserves_severity_distribution(self) -> None:
        """The DB rows span the full severity range; the helper
        should preserve that distribution (no implicit re-sorting
        or downgrading)."""
        eng, (Session, eng_id) = _build_session_factory()
        from src.agents.reporter import ReporterAgent

        async def _go():
            async with Session() as s:
                return await ReporterAgent()._load_findings_from_db(
                    s, eng_id
                )

        result = asyncio.run(_go())
        sev_counts: dict[str, int] = {}
        for f in result:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        assert sev_counts == {
            "critical": 1, "high": 1, "medium": 1, "low": 1,
        }

    def test_load_findings_from_db_empty_when_no_rows(self) -> None:
        """An engagement with no finding rows returns an empty
        list — the reporter then renders the zero-findings branch
        and writes the report as before. The fallback is
        opt-in by emptiness, not the default path."""
        eng2 = create_async_engine("sqlite+aiosqlite:///:memory:")

        async def _setup_empty():
            async with eng2.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            Session = async_sessionmaker(eng2, expire_on_commit=False)
            async with Session() as s:
                eng_id = str(uuid4())
                tgt_id = str(uuid4())
                s.add(Target(id=tgt_id, name="https://t", url="https://t",
                             target_type="webapp", verified=1))
                s.add(Engagement(id=eng_id, target_id=tgt_id,
                                 status="researching", config={}))
                await s.commit()
            return Session, eng_id

        Session, eng_id = asyncio.run(_setup_empty())
        from src.agents.reporter import ReporterAgent

        async def _go():
            async with Session() as s:
                return await ReporterAgent()._load_findings_from_db(
                    s, eng_id
                )

        assert asyncio.run(_go()) == []

    def test_finding_row_to_dict_preserves_metadata(self) -> None:
        """Evidence and other metadata fields are surfaced from
        the JSON column into the dict shape, so the report's
        detailed-findings section has the data it needs."""
        from src.agents.reporter import ReporterAgent

        class FakeRow:
            title = "t"
            description = "d"
            severity = "high"
            confidence_score = 0.9
            validated = True
            cwe_id = "CWE-79"
            owasp_category = "A03:2021"
            remediation = "fix it"
            source_agent = "webapp"
            dedup_key = "k1"
            finding_metadata = {
                "evidence": {"request": "GET /", "response": "200"},
                "poc": "curl ...",
            }

        out = ReporterAgent._finding_row_to_dict(FakeRow())
        assert out["cwe_id"] == "CWE-79"
        assert out["owasp_category"] == "A03:2021"
        assert out["remediation"] == "fix it"
        assert out["evidence"] == {"request": "GET /", "response": "200"}
        assert out["poc"] == "curl ..."
