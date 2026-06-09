"""Unit tests for ResearchLoopAgent — deterministic mock tests for orchestration paths.

Tests cover:
- ResearchLoopAgent instantiation and configuration
- Hypothesis generation dispatch
- Investigation agent routing
- Reflection phase integration
- Termination conditions
- Result compilation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import UTC, datetime

from src.agents.research_loop import ResearchLoopAgent, MAX_RESEARCH_ITERATIONS, MIN_HYPOTHESIS_CONFIDENCE
from src.reasoning.hypothesis_generator import HypothesisGenerator
from src.db.models import (
    Engagement, EngagementStatus, Hypothesis, HypothesisSource, HypothesisStatus,
    Finding, Severity, ToolInvocation, ProvenanceLink,
)
from src.orchestrator.state import EngagementStateMachine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_llm():
    """Mock OllamaClient that returns deterministic responses."""
    llm = AsyncMock()
    llm.generate = AsyncMock(return_value='[]')
    llm.extract_json = MagicMock(return_value=[])
    return llm


@pytest.fixture
def research_loop(mock_llm):
    """ResearchLoopAgent with mocked LLM client."""
    agent = ResearchLoopAgent()
    agent.llm = mock_llm
    agent.hypothesis_generator.llm = mock_llm
    agent.reflection.llm = mock_llm
    return agent


@pytest.fixture
def sample_surface():
    """Sample attack surface data."""
    return {
        "technologies": ["Django", "PostgreSQL", "Nginx"],
        "pages": ["/login", "/dashboard", "/api/v1/users"],
        "forms": [{"action": "/login", "method": "POST"}],
        "endpoints": ["/api/v1/users", "/api/v1/admin"],
        "auth_pages": ["/login"],
        "headers": {"X-Frame-Options": "DENY"},
    }


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {"title": "XSS in search", "severity": "high", "owasp_category": "A03:2021"},
        {"title": "Missing CSRF token", "severity": "medium", "owasp_category": "A01:2021"},
    ]


# ---------------------------------------------------------------------------
# Instantiation Tests
# ---------------------------------------------------------------------------

class TestResearchLoopInstantiation:
    def test_agent_name(self, research_loop):
        assert research_loop.name == "research_loop"

    def test_has_hypothesis_generator(self, research_loop):
        assert research_loop.hypothesis_generator is not None

    def test_has_reflection_phase(self, research_loop):
        assert research_loop.reflection is not None

    def test_max_iterations_default(self, research_loop):
        assert research_loop._max_research_iterations == MAX_RESEARCH_ITERATIONS

    def test_min_confidence_threshold(self):
        assert MIN_HYPOTHESIS_CONFIDENCE == 0.3


# ---------------------------------------------------------------------------
# Agent Routing Tests
# ---------------------------------------------------------------------------

class TestAgentRouting:
    """Test that hypotheses are routed to the correct agent based on category."""

    @pytest.mark.parametrize(
        "category,capabilities,expected_agent",
        [
            ("business_logic", [], "webapp"),
            ("race_condition", [], "webapp"),
            ("auth_bypass", [], "webapp"),
            ("csrf", [], "webapp"),
            ("injection", [], "pentester"),
            ("xss", [], "pentester"),
            ("ssrf", [], "pentester"),
            ("idor", [], "pentester"),
            ("privilege_escalation", [], "pentester"),
            ("api_abuse", [], "pentester"),
            ("data_exposure", [], "reasoner"),
            ("misconfig", [], "reasoner"),
            ("crypto_flaw", [], "reasoner"),
            # Capability-based routing
            ("unknown", ["xss"], "webapp"),
            ("unknown", ["auth_bypass"], "webapp"),
            ("unknown", ["business_logic"], "webapp"),
            ("unknown", ["fuzzing"], "pentester"),
        ],
    )
    def test_select_agent(self, research_loop, category, capabilities, expected_agent):
        hypothesis = {
            "attack_category": category,
            "required_capabilities": capabilities,
        }
        assert research_loop._select_agent(hypothesis) == expected_agent

    def test_select_agent_default_is_pentester(self, research_loop):
        """Unknown category with no matching capabilities defaults to pentester."""
        hypothesis = {"attack_category": "unknown_category", "required_capabilities": ["unknown_tag"]}
        assert research_loop._select_agent(hypothesis) == "pentester"


# ---------------------------------------------------------------------------
# State Machine Tests
# ---------------------------------------------------------------------------

class TestEngagementStateMachine:
    def test_running_to_researching(self):
        assert EngagementStateMachine.can_transition(
            EngagementStatus.RUNNING, EngagementStatus.RESEARCHING
        )

    def test_researching_to_completed(self):
        assert EngagementStateMachine.can_transition(
            EngagementStatus.RESEARCHING, EngagementStatus.COMPLETED
        )

    def test_researching_to_paused(self):
        assert EngagementStateMachine.can_transition(
            EngagementStatus.RESEARCHING, EngagementStatus.PAUSED
        )

    def test_researching_to_failed(self):
        assert EngagementStateMachine.can_transition(
            EngagementStatus.RESEARCHING, EngagementStatus.FAILED
        )

    def test_invalid_transition(self):
        assert not EngagementStateMachine.can_transition(
            EngagementStatus.PENDING, EngagementStatus.COMPLETED
        )

    def test_researching_cannot_go_to_running(self):
        """Once researching, cannot go back to running."""
        assert not EngagementStateMachine.can_transition(
            EngagementStatus.RESEARCHING, EngagementStatus.RUNNING
        )


# ---------------------------------------------------------------------------
# Result Compilation Tests
# ---------------------------------------------------------------------------

class TestResultCompilation:
    def test_compile_results_empty(self, research_loop):
        result = research_loop._compile_results(
            hypotheses_investigated=[],
            findings=[],
            artifacts=[],
            iterations=0,
        )
        assert result["findings"] == []
        assert result["artifacts"] == []
        assert result["hypotheses_investigated"] == 0
        assert result["hypotheses_confirmed"] == 0
        assert result["hypotheses_falsified"] == 0
        assert result["research_iterations"] == 0
        assert result["agent"] == "research_loop"

    def test_compile_results_with_findings(self, research_loop):
        hypotheses = [
            {"status": HypothesisStatus.VALIDATED, "hypothesis_class": "xss_reflected"},
            {"status": HypothesisStatus.REJECTED, "hypothesis_class": "sqli_auth_bypass"},
        ]
        findings = [
            {"title": "XSS found", "severity": "high"},
            {"title": "CSRF missing", "severity": "medium"},
            {"title": "Info disclosure", "severity": "info"},
        ]
        result = research_loop._compile_results(
            hypotheses_investigated=hypotheses,
            findings=findings,
            artifacts=[{"type": "screenshot"}],
            iterations=2,
        )
        assert result["hypotheses_investigated"] == 2
        assert result["hypotheses_confirmed"] == 1
        assert result["hypotheses_falsified"] == 1
        assert result["total_findings"] == 3
        assert result["high_severity_findings"] == 1
        assert result["research_iterations"] == 2


# ---------------------------------------------------------------------------
# Finding Dict Conversion Tests
# ---------------------------------------------------------------------------

class TestFindingConversion:
    def test_finding_to_dict(self, research_loop):
        finding = Finding(
            id="test-id",
            engagement_id="eng-id",
            title="XSS vulnerability",
            description="Reflected XSS in search parameter",
            severity=Severity.HIGH,
            confidence_score=0.85,
            validated=True,
            cwe_id="CWE-79",
            owasp_category="A03:2021",
            source_agent="pentester",
            finding_metadata={"tool": "xss_pipeline"},
        )
        result = research_loop._finding_to_dict(finding)
        assert result["title"] == "XSS vulnerability"
        assert result["severity"] == "high"
        assert result["confidence"] == 0.85
        assert result["validated"] is True
        assert result["cwe_id"] == "CWE-79"


# ---------------------------------------------------------------------------
# Dedup Key Tests (via HypothesisGenerator)
# ---------------------------------------------------------------------------

class TestDedupKey:
    def test_dedup_key_format(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        h = {"attack_category": "XSS", "hypothesis_class": "Reflected_XSS"}
        key = HypothesisGenerator._dedup_key(h)
        assert key == "xss:reflected_xss"

    def test_dedup_key_lowercase(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        h = {"attack_category": "Injection", "hypothesis_class": "SQL_Auth_Bypass"}
        key = HypothesisGenerator._dedup_key(h)
        assert key == "injection:sql_auth_bypass"


# ---------------------------------------------------------------------------
# Pattern Matching Tests
# ---------------------------------------------------------------------------

class TestPatternMatching:
    def test_match_patterns_empty_surface(self):
        """Pattern matching should return empty list for empty surface."""
        gen = HypothesisGenerator(llm_client=None)
        result = gen._match_patterns({})
        # Should return patterns or empty — depends on pattern library content
        assert isinstance(result, list)

    def test_infer_capabilities_xss(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        pattern = MagicMock()
        pattern.name = "Reflected XSS"
        caps = HypothesisGenerator._infer_capabilities(pattern)
        assert "xss" in caps

    def test_infer_capabilities_sql(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        pattern = MagicMock()
        pattern.name = "SQL Injection Authentication Bypass"
        caps = HypothesisGenerator._infer_capabilities(pattern)
        assert "sqli" in caps
        assert "auth_bypass" in caps

    def test_infer_capabilities_default_fuzzing(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        pattern = MagicMock()
        pattern.name = "Unknown Pattern"
        caps = HypothesisGenerator._infer_capabilities(pattern)
        assert "fuzzing" in caps

    def test_infer_falsification_xss(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        pattern = MagicMock()
        pattern.name = "Reflected XSS in Search"
        criteria = HypothesisGenerator._infer_falsification(pattern)
        assert "script execution" in criteria.lower() or "XSS" in criteria or "reflected" in criteria.lower()

    def test_infer_falsification_sql(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        pattern = MagicMock()
        pattern.name = "SQL Injection Login Bypass"
        criteria = HypothesisGenerator._infer_falsification(pattern)
        assert "sql" in criteria.lower() or "injection" in criteria.lower()


# ---------------------------------------------------------------------------
# Merge and Dedup Tests
# ---------------------------------------------------------------------------

class TestMergeAndDedup:
    def test_merge_empty_lists(self):
        gen = HypothesisGenerator(llm_client=None)
        result = gen._merge_and_dedup([], [])
        assert result == []

    def test_merge_no_duplicates(self):
        gen = HypothesisGenerator(llm_client=None)
        pattern = [{"attack_category": "xss", "hypothesis_class": "reflected_xss", "source": "pattern_match"}]
        novel = [{"attack_category": "business_logic", "hypothesis_class": "cart_manipulation", "source": "llm_generated"}]
        result = gen._merge_and_dedup(pattern, novel)
        assert len(result) == 2

    def test_merge_deduplicates(self):
        gen = HypothesisGenerator(llm_client=None)
        pattern = [{"attack_category": "xss", "hypothesis_class": "reflected_xss", "source": "pattern_match"}]
        novel = [{"attack_category": "xss", "hypothesis_class": "reflected_xss", "source": "llm_generated"}]
        result = gen._merge_and_dedup(pattern, novel)
        assert len(result) == 1
        assert result[0]["source"] == "pattern_match"  # Pattern match takes priority

    def test_pattern_hypotheses_take_priority(self):
        gen = HypothesisGenerator(llm_client=None)
        pattern = [{"attack_category": "injection", "hypothesis_class": "sqli_auth", "source": "pattern_match", "confidence": 0.6}]
        novel = [{"attack_category": "injection", "hypothesis_class": "sqli_auth", "source": "llm_generated", "confidence": 0.4}]
        result = gen._merge_and_dedup(pattern, novel)
        assert len(result) == 1
        assert result[0]["source"] == "pattern_match"


# ---------------------------------------------------------------------------
# Surface Summary Tests
# ---------------------------------------------------------------------------

class TestSurfaceSummary:
    def test_summarize_surface_empty(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        result = HypothesisGenerator._summarize_surface({})
        assert "No surface data" in result

    def test_summarize_surface_with_data(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        surface = {
            "technologies": ["Django", "PostgreSQL"],
            "pages": ["/login", "/admin"],
            "endpoints": ["/api/v1/users"],
        }
        result = HypothesisGenerator._summarize_surface(surface)
        assert "Django" in result
        assert "2" in result  # 2 pages

    def test_summarize_findings_empty(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        result = HypothesisGenerator._summarize_findings([])
        assert "No previous findings" in result

    def test_summarize_findings_with_data(self):
        from src.reasoning.hypothesis_generator import HypothesisGenerator
        findings = [
            {"title": "XSS", "severity": "high", "owasp_category": "A03"},
            {"title": "CSRF", "severity": "medium", "owasp_category": "A01"},
        ]
        result = HypothesisGenerator._summarize_findings(findings)
        assert "XSS" in result
        assert "CSRF" in result


# ---------------------------------------------------------------------------
# Regression: audit-log payload must be JSON-serializable
# ---------------------------------------------------------------------------


class TestAuditLogPayloadSerialization:
    """The `hypotheses_generated` audit-log payload must not contain sets.

    `audit_logs.payload` is a JSON column with no `default=str` fallback
    (see egats-set-serialization memory). If `_generate_hypotheses` builds
    the payload with a set comprehension, the INSERT raises
    ``TypeError: Object of type set is not JSON serializable`` and the
    ResearchLoop silently terminates with "no hypotheses generated" —
    taking the whole reflection/learning loop offline.

    The bug has been seen in production: see the admin.arboard.kz scan
    log from 2026-06-04 where the engine caught the exception in its
    Phase 3 wrapper but the ResearchLoop returned an empty list.
    """

    @pytest.mark.asyncio
    async def test_hypotheses_generated_payload_is_json_native(self) -> None:
        """`_generate_hypotheses` must hand JSON-native values to log_action."""
        import json

        from src.agents import research_loop as rl_module
        from src.agents.research_loop import ResearchLoopAgent

        # Two hypotheses, one with an explicit source and one with the default.
        fake_hypotheses = [
            {"id": "h1", "source": "pattern", "vuln_type": "xss"},
            {"id": "h2", "source": "pattern", "vuln_type": "sqli"},
            {"id": "h3", "vuln_type": "ssrf"},  # no source key — falls back to "unknown"
        ]

        agent = ResearchLoopAgent()
        # Patch the inner hypothesis generator. The attribute lookup is
        # direct (not via MagicMock __getattr__), so we wrap the real
        # instance in a small holder and replace generate_hypotheses on it.
        from src.reasoning.hypothesis_generator import HypothesisGenerator

        original_gen = agent.hypothesis_generator
        # Replace the bound method on the existing instance so `await
        # self.hypothesis_generator.generate_hypotheses(...)` resolves to
        # our AsyncMock rather than a MagicMock auto-attribute.
        original_gen.generate_hypotheses = AsyncMock(return_value=fake_hypotheses)

        # Capture the payload the agent actually hands to log_action.
        captured: dict = {}

        async def fake_log_action(*, session, action, actor, payload, **kwargs):
            captured["action"] = action
            captured["actor"] = actor
            captured["payload"] = payload
            # The real log_action calls session.execute() — skip that.

        # The real log_action will await on a MagicMock session, which
        # raises TypeError. Replace the module-level reference so the
        # patched version runs instead.
        original_log_action = rl_module.log_action
        rl_module.log_action = fake_log_action
        try:
            session = MagicMock()
            result = await agent._generate_hypotheses(
                surface={},
                findings=[],
                session=session,
                engagement_id="00000000-0000-0000-0000-000000000000",
            )
        finally:
            rl_module.log_action = original_log_action

        assert result == fake_hypotheses
        assert captured["action"] == "hypotheses_generated"
        # The critical assertion: json.dumps(payload) must not raise.
        # If sources is a set, this raises TypeError on the bare json
        # serializer used by SQLAlchemy's JSON column.
        serialized = json.dumps(captured["payload"])
        assert "pattern" in serialized
        assert "unknown" in serialized
        # sources must be a list (JSON-native), not a set
        assert isinstance(captured["payload"]["sources"], list)