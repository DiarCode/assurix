"""Phase 4b: HypothesisOrchestrator — unit tests.

Verifies:
- Surface_hypotheses generated for every URL param (CMDI/XSS/SSRF/SQLi/IDOR)
- Surface_hypotheses generated for every form (auth_bypass/CSRF)
- Reasoning_hypotheses generated from detected technologies (Nuxt/PHP/Express/payment)
- API-rich surfaces get a bulk-idor hypothesis
- _select_agent routes attack categories to the right agent
- Convergence detection terminates after idle iterations
- _persist_finding creates a ProvenanceLink record
- Engine-mediated dispatch calls engine.submit_and_await() and forwards the result
- Direct-agent fallback works when no engine is injected
- Slug helper produces valid kebab-case
- HypothesisOrchestrator.name = "hypothesis_orchestrator"
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
from src.db.models import (
    Engagement,
    EngagementStatus,
    Finding,
    Hypothesis,
    HypothesisStatus,
    ProvenanceLink,
    Severity,
    ToolInvocation,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal async session
# ---------------------------------------------------------------------------


class _FakeScalarResult:
    def __init__(self, items):
        self._items = list(items) if items is not None else []

    def scalars(self):
        return _FakeScalars(self._items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def first(self):
        return self._items[0] if self._items else None


class _FakeScalars:
    def __init__(self, items):
        self._items = list(items) if items is not None else []

    def all(self):
        return list(self._items)

    def first(self):
        return self._items[0] if self._items else None

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


def _make_session(*, scalars_results=None):
    """Build a mock AsyncSession.

    scalars_results: a list of lists; .execute() pops one per call and wraps
    in _FakeScalarResult. Use None for empty results. Each entry supports
    scalars().all(), .first(), and scalar_one_or_none() — covering all
    access patterns used by HypothesisOrchestrator and the audit module.
    """
    queue = list(scalars_results or [])
    session = AsyncMock()
    session.flush = AsyncMock()

    async def _execute(stmt):
        if queue:
            return _FakeScalarResult(queue.pop(0))
        return _FakeScalarResult([])

    session.execute = AsyncMock(side_effect=_execute)
    session.add = MagicMock()
    session.get = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# Surface hypotheses
# ---------------------------------------------------------------------------


class TestSurfaceHypotheses:
    def test_endpoints_produce_cmdi_xss_ssrf_sqli_idor(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)  # bypass __init__
        surface = {"endpoints": ["/api/users", "/api/products/123"]}
        hyps = orch.generate_surface_hypotheses(surface)
        categories = [h["attack_category"] for h in hyps]
        # Each endpoint should yield 5 categories
        assert categories.count("injection") == 2
        assert "xss" in categories
        assert "ssrf" in categories
        assert "idor" in categories
        # All have required_capabilities tagged
        for h in hyps:
            assert "required_capabilities" in h
            assert len(h["required_capabilities"]) >= 1
            assert h["source"] == "pattern_match"

    def test_forms_produce_auth_bypass_and_csrf(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        surface = {
            "forms": [
                {"action": "/login", "method": "POST"},
                {"action": "/api/checkout", "method": "POST"},
            ]
        }
        hyps = orch.generate_surface_hypotheses(surface)
        cats = [h["attack_category"] for h in hyps]
        assert cats.count("auth_bypass") == 2
        assert cats.count("csrf") == 2

    def test_empty_surface_returns_empty_list(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch.generate_surface_hypotheses({}) == []
        assert orch.generate_surface_hypotheses({"endpoints": None, "forms": None}) == []


# ---------------------------------------------------------------------------
# Reasoning hypotheses
# ---------------------------------------------------------------------------


class TestReasoningHypotheses:
    def test_nuxt_triggers_ssr_cache_hypothesis(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        hyps = orch.generate_reasoning_hypotheses({}, ["Nuxt.js"])
        classes = [h["hypothesis_class"] for h in hyps]
        assert "ssr-cache-poisoning" in classes

    def test_php_triggers_type_juggling(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        hyps = orch.generate_reasoning_hypotheses({}, ["PHP/8.0"])
        classes = [h["hypothesis_class"] for h in hyps]
        assert "php-type-juggling" in classes

    def test_express_triggers_proto_pollution(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        hyps = orch.generate_reasoning_hypotheses({}, ["Express"])
        classes = [h["hypothesis_class"] for h in hyps]
        assert "express-prototype-pollution" in classes

    def test_payment_triggers_price_and_csrf(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        # Trigger via surface data, since the regex matches surface text too
        hyps = orch.generate_reasoning_hypotheses(
            {}, technologies=["payment", "checkout"]
        )
        classes = [h["hypothesis_class"] for h in hyps]
        assert "cart-price-manipulation" in classes
        assert "payment-csrf" in classes

    def test_api_endpoints_trigger_bulk_idor(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        surface = {
            "endpoints": ["/api/users", "/api/orders", "/api/products"],
            "technologies": [],
        }
        hyps = orch.generate_reasoning_hypotheses(surface, [])
        classes = [h["hypothesis_class"] for h in hyps]
        assert "api-idor-bulk" in classes


# ---------------------------------------------------------------------------
# _select_agent routing
# ---------------------------------------------------------------------------


class TestSelectAgent:
    def test_routes_business_logic_to_webapp(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch._select_agent({"attack_category": "business_logic"}) == "webapp"
        assert orch._select_agent({"attack_category": "race_condition"}) == "webapp"
        assert orch._select_agent({"attack_category": "auth_bypass"}) == "webapp"
        assert orch._select_agent({"attack_category": "csrf"}) == "webapp"

    def test_routes_injection_to_pentester(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch._select_agent({"attack_category": "injection"}) == "pentester"
        assert orch._select_agent({"attack_category": "xss"}) == "pentester"
        assert orch._select_agent({"attack_category": "ssrf"}) == "pentester"
        assert orch._select_agent({"attack_category": "idor"}) == "pentester"
        assert orch._select_agent({"attack_category": "privilege_escalation"}) == "pentester"

    def test_routes_data_exposure_to_reasoner(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch._select_agent({"attack_category": "data_exposure"}) == "reasoner"
        assert orch._select_agent({"attack_category": "misconfig"}) == "reasoner"
        assert orch._select_agent({"attack_category": "crypto_flaw"}) == "reasoner"

    def test_defaults_to_pentester(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch._select_agent({"attack_category": "unknown"}) == "pentester"
        assert orch._select_agent({}) == "pentester"


# ---------------------------------------------------------------------------
# Engine dispatch
# ---------------------------------------------------------------------------


class TestEngineDispatch:
    @pytest.mark.asyncio
    async def test_engine_submit_and_await_is_called(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)

        engine = MagicMock()
        engine.submit_and_await = AsyncMock(return_value={
            "findings": [{"title": "XSS", "severity": "high"}],
            "artifacts": [],
        })

        session = _make_session()
        # _record_tool_invocation uses session.add; the fake handles it
        result = await orch._dispatch_investigation(
            hypothesis={"hypothesis_class": "xss-test", "attack_category": "xss",
                        "required_capabilities": ["xss"], "description": "x",
                        "falsification_criteria": "y"},
            hypothesis_id="h-1",
            payload={"target_url": "http://x", "previous_result": {}, "iteration": 0},
            surface={},
            session=session,
            engagement_id="e-1",
            engine=engine,
        )

        assert engine.submit_and_await.await_count == 1
        kwargs = engine.submit_and_await.await_args.kwargs
        assert kwargs["engagement_id"] == "e-1"
        assert kwargs["agent_name"] == "pentester"  # xss routes to pentester
        assert kwargs["payload"]["hypothesis_id"] == "h-1"
        assert kwargs["payload"]["target_url"] == "http://x"
        # Result is forwarded
        assert result["findings"][0]["title"] == "XSS"

    @pytest.mark.asyncio
    async def test_engine_dispatch_failure_returns_empty(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        engine = MagicMock()
        engine.submit_and_await = AsyncMock(side_effect=RuntimeError("boom"))
        session = _make_session()
        result = await orch._dispatch_investigation(
            hypothesis={"hypothesis_class": "x", "attack_category": "xss",
                        "required_capabilities": ["xss"], "description": "",
                        "falsification_criteria": ""},
            hypothesis_id="h-1",
            payload={"target_url": "http://x", "previous_result": {}, "iteration": 0},
            surface={},
            session=session,
            engagement_id="e-1",
            engine=engine,
        )
        assert result == {"findings": [], "artifacts": []}

    @pytest.mark.asyncio
    async def test_direct_agent_fallback_works(self) -> None:
        """When no engine is injected, the orchestrator instantiates the
        agent class directly. We don't run real agent logic — we just
        verify the fallback path is wired up (returns a dict with the
        expected shape)."""
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)

        # Patch _invoke_agent_directly to return a known value
        orch._invoke_agent_directly = AsyncMock(return_value={
            "findings": [{"title": "direct"}],
            "artifacts": [],
        })
        session = _make_session()
        result = await orch._dispatch_investigation(
            hypothesis={"hypothesis_class": "y", "attack_category": "xss",
                        "required_capabilities": ["xss"], "description": "",
                        "falsification_criteria": ""},
            hypothesis_id="h-2",
            payload={"target_url": "http://y", "previous_result": {}, "iteration": 0},
            surface={},
            session=session,
            engagement_id="e-2",
            engine=None,
        )
        assert result["findings"][0]["title"] == "direct"
        assert orch._invoke_agent_directly.await_count == 1


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistFinding:
    @pytest.mark.asyncio
    async def test_creates_finding_with_provenance_link(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        session = _make_session(
            scalars_results=[[ToolInvocation(id="ti-1", tool_name="pentester")]]
        )

        # Capture the objects added to the session
        added: list = []
        session.add = MagicMock(side_effect=lambda obj: added.append(obj))

        finding = await orch._persist_finding(
            session=session,
            engagement_id="e-1",
            finding_data={
                "title": "XSS in /api/users",
                "description": "reflected XSS",
                "severity": "high",
                "confidence": 0.8,
                "hypothesis_class": "xss-test",
                "attack_category": "xss",
                "source_agent": "pentester",
            },
            hypotheses_investigated=[
                {"hypothesis_id": "h-1", "status": HypothesisStatus.VALIDATED},
            ],
        )
        assert finding is not None
        # Finding was added to session
        assert any(isinstance(o, Finding) for o in added)
        # ProvenanceLink was added
        assert any(isinstance(o, ProvenanceLink) for o in added)
        # ProvenanceLink points to hypothesis + tool invocation
        pl = next(o for o in added if isinstance(o, ProvenanceLink))
        assert pl.hypothesis_id == "h-1"
        assert pl.tool_invocation_id == "ti-1"
        assert pl.tool_name == "pentester"
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_severity_falls_back_to_info_on_invalid(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        session = _make_session(scalars_results=[[]])
        added: list = []
        session.add = MagicMock(side_effect=lambda obj: added.append(obj))
        finding = await orch._persist_finding(
            session=session,
            engagement_id="e-1",
            finding_data={"title": "x", "severity": "bogus-value"},
            hypotheses_investigated=[],
        )
        assert finding is not None
        assert finding.severity == Severity.INFO


# ---------------------------------------------------------------------------
# Convergence
# ---------------------------------------------------------------------------


class TestConvergence:
    @pytest.mark.asyncio
    async def test_terminates_after_idle_iterations(self) -> None:
        """With no viable hypotheses, the orchestrator should hit the
        convergence threshold and stop."""
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        orch._max_orchestration_iterations = 10
        orch._convergence_idle = 3

        # Stub out everything to keep the test focused
        orch._generate_hypotheses = AsyncMock(return_value=[])
        orch._dispatch_investigation = AsyncMock()
        orch._reflect = AsyncMock(return_value=[])
        orch._load_findings = AsyncMock(return_value=[])
        orch._load_surface = MagicMock(return_value={})
        orch._persist_finding = AsyncMock()
        orch._compile_results = MagicMock(
            return_value={"agent": "hypothesis_orchestrator"}
        )

        session = _make_session()
        # Need an engagement to load
        engagement = MagicMock(spec=Engagement)
        engagement.status = EngagementStatus.RUNNING
        engagement.config = {}
        session.get = AsyncMock(return_value=engagement)

        result = await orch.execute(
            {
                "engagement_id": "e-1",
                "target_url": "http://x",
                "engine": None,
            },
            session,
        )
        # _generate_hypotheses was called 3 times (until convergence)
        assert orch._generate_hypotheses.await_count == 3
        # _dispatch_investigation was never called (no viable hypotheses)
        assert orch._dispatch_investigation.await_count == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestSlug:
    def test_slug_basic(self) -> None:
        orch = HypothesisOrchestrator.__new__(HypothesisOrchestrator)
        assert orch._slug("/api/users") == "api-users"
        assert orch._slug("XSS surface") == "xss-surface"
        assert orch._slug("") == "x"

    def test_agent_name(self) -> None:
        assert HypothesisOrchestrator.name == "hypothesis_orchestrator"
