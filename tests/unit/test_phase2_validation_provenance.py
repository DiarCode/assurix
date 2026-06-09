"""Phase 2: Validation & Provenance — unit tests.

Verifies:
- _validate_cmdi routes correctly and handles echo + time-differential
- ReportValidator warns but never downgrades for missing provenance
- PentesterAgent._persist_findings_with_provenance creates ProvenanceLink rows
- json_report no longer downgrades for missing poc
- SPA catch-all fix: only triggers when URL has no query params
- ProvenanceLink FKs are nullable in the ORM
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest


class TestValidateCmdi:
    """ValidationAgent should route CMDI findings to _validate_cmdi."""

    def test_cmdi_keyword_routes_to_handler(self) -> None:
        """The keyword check should include cmdi, command injection, CWE-78, os command."""
        from src.agents.validation import ValidationAgent
        agent = ValidationAgent()
        # Inspect source: keyword set must include cmdi/CWE-78
        import inspect
        src = inspect.getsource(agent._validate_finding)
        assert "cmdi" in src
        assert "command injection" in src
        assert "cwe-78" in src

    def test_validate_cmdi_method_exists(self) -> None:
        from src.agents.validation import ValidationAgent
        assert hasattr(ValidationAgent, "_validate_cmdi")
        assert asyncio.iscoroutinefunction(ValidationAgent._validate_cmdi)

    def test_validate_cmdi_handles_echo_marker(self) -> None:
        """When echo marker is reflected, exploit_verified=True."""
        from src.agents.validation import ValidationAgent
        agent = ValidationAgent()
        client = MagicMock()
        marker = "assurix_cmdi_7193b2"
        # First call: injected (echo reflected) — should return immediately
        injected_resp = MagicMock()
        injected_resp.status_code = 200
        injected_resp.text = f"output: {marker} was echoed"
        client.get = AsyncMock(return_value=injected_resp)

        finding = {"title": "CMDI: command injection in q", "url": "http://t/q?x=1"}
        result = asyncio.run(agent._validate_cmdi(finding, finding["url"], client))
        assert result["exploit_verified"] is True
        assert "echo marker" in result["verification_evidence"].lower()

    def test_validate_cmdi_no_marker_no_sleep(self) -> None:
        """When no echo and no sleep, exploit_verified=False."""
        from src.agents.validation import ValidationAgent
        agent = ValidationAgent()
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "static response, no marker"
        client.get = AsyncMock(return_value=resp)

        finding = {"title": "CMDI", "url": "http://t/q?x=1"}
        result = asyncio.run(agent._validate_cmdi(finding, finding["url"], client))
        assert result["exploit_verified"] is False


class TestReportValidatorNoDowngrade:
    """ReportValidator must warn, never downgrade, for missing provenance."""

    def _make_finding(self, severity: str = "critical") -> MagicMock:
        f = MagicMock()
        f.id = str(uuid4())
        f.title = "Test Finding"
        f.description = "Test desc"
        f.severity = MagicMock()
        f.severity.value = severity
        f.confidence_score = 0.8
        f.validated = True
        f.cwe_id = "CWE-78"
        f.owasp_category = "A03:2021"
        f.remediation = "Fix it"
        f.source_agent = "pentester"
        f.finding_metadata = {"evidence": "marker reflected"}
        return f

    def test_missing_provenance_does_not_downgrade(self) -> None:
        """A CRITICAL finding with no provenance links should stay CRITICAL."""
        from src.reporting.validator import ReportValidator
        v = ReportValidator()
        finding = self._make_finding("critical")
        # No provenance links
        validated, issues = v.validate_findings([finding], provenance_links=[])
        assert len(validated) == 1
        assert validated[0]["severity"] == "critical", (
            f"Expected severity=critical, got {validated[0]['severity']}"
        )
        assert "downgraded_from" not in validated[0]
        assert validated[0].get("provenance_warning") is True
        # At least one warning should be present
        assert any(i.severity == "warning" for i in issues)

    def test_missing_poc_does_not_downgrade(self) -> None:
        """A CRITICAL finding without 'poc' must NOT be downgraded (json_report)."""
        from src.reporting.json_report import JSONReportGenerator
        g = JSONReportGenerator()
        finding = self._make_finding("critical")
        finding.finding_metadata = {"evidence": "some evidence"}  # no poc
        result = g._validate_findings([finding])
        assert result[0]["severity"] == "critical"

    def test_poc_removed_from_required_fields(self) -> None:
        """poc is no longer in the downgrade-trigger required list."""
        from src.reporting.json_report import CONFIRMED_REQUIRED_FIELDS
        assert "poc" not in CONFIRMED_REQUIRED_FIELDS


class TestProvenanceLinkNullable:
    """ProvenanceLink FKs (hypothesis_id, tool_invocation_id) must be nullable."""

    def test_hypothesis_id_nullable(self) -> None:
        from src.db.models import ProvenanceLink
        col = ProvenanceLink.__table__.c.hypothesis_id
        assert col.nullable is True

    def test_tool_invocation_id_nullable(self) -> None:
        from src.db.models import ProvenanceLink
        col = ProvenanceLink.__table__.c.tool_invocation_id
        assert col.nullable is True

    def test_finding_id_still_not_nullable(self) -> None:
        """finding_id remains NOT NULL — the only required FK."""
        from src.db.models import ProvenanceLink
        col = ProvenanceLink.__table__.c.finding_id
        assert col.nullable is False


class TestSPAFix:
    """SPA catch-all detection must not fire when URL has injection query params."""

    def test_url_with_query_params_skips_spa_check(self) -> None:
        """If parsed.query is non-empty, we should not check for SPA markers first."""
        import inspect
        from src.agents.validation import ValidationAgent
        src = inspect.getsource(ValidationAgent._validate_generic)
        # The fix: gate SPA check on `not has_query_params`
        assert "has_query_params" in src
        # And `not has_query_params and` precedes the SPA marker check
        assert "not has_query_params and any" in src


class TestPersistFindingsWithProvenance:
    """PentesterAgent._persist_findings_with_provenance must attach ProvenanceLink rows."""

    def test_method_exists(self) -> None:
        from src.agents.pentester import PentesterAgent
        assert hasattr(PentesterAgent, "_persist_findings_with_provenance")
        assert asyncio.iscoroutinefunction(PentesterAgent._persist_findings_with_provenance)

    def test_creates_provenance_link_per_finding(self) -> None:
        """Each finding should get a ProvenanceLink with tool_name='pentester'."""
        from src.agents.pentester import PentesterAgent
        agent = PentesterAgent()
        # Mock session
        session = MagicMock()
        session.add = MagicMock()
        findings = [
            {"title": "F1", "severity": "critical", "description": "d1"},
            {"title": "F2", "severity": "high", "description": "d2"},
        ]
        result = asyncio.run(
            agent._persist_findings_with_provenance(
                findings=findings,
                session=session,
                engagement_id="eng-1",
                tool_name="pentester",
            )
        )
        # 2 findings + 2 provenance links = 4 add() calls
        assert session.add.call_count == 4
        # Each persisted finding has an id
        assert all("id" in f for f in result)
        # Check that we created ProvenanceLink rows with tool_name="pentester"
        prov_calls = [
            c for c in session.add.call_args_list
            if c.args[0].__class__.__name__ == "ProvenanceLink"
        ]
        assert len(prov_calls) == 2
        assert all(c.args[0].tool_name == "pentester" for c in prov_calls)
