"""Unit tests for ReflectionPhase — behavioral contract tests.

Tests cover:
- Termination condition (returns empty list when no productive leads remain)
- New hypothesis generation (returns hypotheses when gaps identified)
- Deduplication against existing hypotheses
- Surface and findings summarization
- Coverage analysis
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.reasoning.reflection import ReflectionPhase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_llm():
    """Mock LLM client returning deterministic responses."""
    llm = AsyncMock()
    llm.generate = AsyncMock()
    llm.extract_json = MagicMock()
    return llm


@pytest.fixture
def reflection(mock_llm):
    """ReflectionPhase with mocked LLM client."""
    return ReflectionPhase(llm_client=mock_llm)


@pytest.fixture
def sample_hypotheses():
    return [
        {
            "hypothesis_class": "reflected_xss",
            "attack_category": "xss",
            "description": "Reflected XSS in search parameter",
            "source": "pattern_match",
            "confidence": 0.7,
            "status": "confirmed",
        },
        {
            "hypothesis_class": "sqli_auth_bypass",
            "attack_category": "injection",
            "description": "SQL injection in login form",
            "source": "pattern_match",
            "confidence": 0.6,
            "status": "falsified",
        },
    ]


@pytest.fixture
def sample_results():
    return [
        {
            "hypothesis_id": "h1",
            "hypothesis_class": "reflected_xss",
            "attack_category": "xss",
            "status": "confirmed",
            "findings_count": 2,
        },
        {
            "hypothesis_id": "h2",
            "hypothesis_class": "sqli_auth_bypass",
            "attack_category": "injection",
            "status": "falsified",
            "findings_count": 0,
        },
    ]


@pytest.fixture
def sample_findings():
    return [
        {"title": "Reflected XSS in search", "severity": "high", "owasp_category": "A03:2021"},
        {"title": "Missing CSP header", "severity": "medium", "owasp_category": "A05:2021"},
    ]


@pytest.fixture
def sample_surface():
    return {
        "technologies": ["Django", "PostgreSQL", "Nginx"],
        "pages": ["/login", "/dashboard", "/api/v1/users"],
        "endpoints": ["/api/v1/users", "/api/v1/admin"],
        "forms": [{"action": "/login", "method": "POST"}],
        "auth_pages": ["/login"],
    }


# ---------------------------------------------------------------------------
# Termination Tests
# ---------------------------------------------------------------------------

class TestTerminationCondition:
    @pytest.mark.asyncio
    async def test_returns_empty_when_should_not_continue(self, reflection, mock_llm):
        """Reflection should return empty list when LLM says should_continue=false."""
        mock_llm.generate.return_value = '{"should_continue": false, "new_hypotheses": []}'
        mock_llm.extract_json.return_value = {
            "should_continue": False,
            "coverage_assessment": "Adequate coverage",
            "gaps_identified": [],
            "new_hypotheses": [],
        }

        result = await reflection.evaluate(
            hypotheses=[{"hypothesis_class": "xss", "attack_category": "xss", "status": "confirmed"}],
            results=[{"status": "confirmed", "findings_count": 1}],
            findings=[{"title": "XSS found", "severity": "high"}],
            surface={"technologies": ["Django"]},
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_hypotheses_and_no_findings(self, reflection, mock_llm):
        """Reflection should return empty list when there are no hypotheses or findings."""
        result = await reflection.evaluate(
            hypotheses=[],
            results=[],
            findings=[],
            surface={},
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_llm_failure(self, reflection, mock_llm):
        """Reflection should return empty list when LLM call fails."""
        mock_llm.generate.side_effect = Exception("LLM connection error")

        result = await reflection.evaluate(
            hypotheses=[{"hypothesis_class": "xss", "attack_category": "xss"}],
            results=[],
            findings=[{"title": "XSS found", "severity": "high"}],
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_invalid_llm_response(self, reflection, mock_llm):
        """Reflection should return empty list when LLM returns invalid JSON."""
        mock_llm.generate.return_value = "not json"
        mock_llm.extract_json.return_value = None

        result = await reflection.evaluate(
            hypotheses=[{"hypothesis_class": "xss", "attack_category": "xss"}],
            results=[],
            findings=[{"title": "XSS", "severity": "high"}],
        )
        assert result == []


# ---------------------------------------------------------------------------
# New Hypothesis Generation Tests
# ---------------------------------------------------------------------------

class TestNewHypothesisGeneration:
    @pytest.mark.asyncio
    async def test_returns_new_hypotheses_when_gaps_identified(self, reflection, mock_llm):
        """Reflection should return new hypotheses when LLM identifies gaps."""
        mock_llm.generate.return_value = "reflection result"
        mock_llm.extract_json.return_value = {
            "should_continue": True,
            "coverage_assessment": "Missing business logic testing",
            "gaps_identified": ["No race condition testing performed"],
            "new_hypotheses": [
                {
                    "hypothesis_class": "race_condition_checkout",
                    "attack_category": "race_condition",
                    "description": "Race condition in checkout flow",
                    "required_capabilities": ["race_condition"],
                    "falsification_criteria": "No state inconsistency after 5 concurrent requests",
                    "confidence": 0.4,
                },
            ],
        }

        result = await reflection.evaluate(
            hypotheses=[{"hypothesis_class": "xss", "attack_category": "xss", "status": "confirmed"}],
            results=[{"status": "confirmed"}],
            findings=[{"title": "XSS found", "severity": "high"}],
            surface={"technologies": ["Django"]},
        )
        assert len(result) == 1
        assert result[0]["hypothesis_class"] == "race_condition_checkout"
        assert result[0]["source"] == "llm_generated"

    @pytest.mark.asyncio
    async def test_validates_new_hypotheses(self, reflection, mock_llm):
        """Reflection should validate new hypotheses and skip invalid ones."""
        mock_llm.generate.return_value = "reflection result"
        mock_llm.extract_json.return_value = {
            "should_continue": True,
            "coverage_assessment": "Missing auth testing",
            "gaps_identified": ["Auth bypass not tested"],
            "new_hypotheses": [
                {
                    "hypothesis_class": "auth_bypass_admin",
                    "attack_category": "auth_bypass",
                    "description": "Admin panel auth bypass",
                    "required_capabilities": ["auth_bypass"],
                    "confidence": 0.5,
                },
                {
                    "description": "Missing hypothesis_class field",
                    "attack_category": "unknown",
                },
            ],
        }

        result = await reflection.evaluate(
            hypotheses=[{"hypothesis_class": "xss", "attack_category": "xss"}],
            results=[],
            findings=[],
        )
        # Second hypothesis should be filtered out (missing required fields)
        assert len(result) == 1
        assert result[0]["hypothesis_class"] == "auth_bypass_admin"


# ---------------------------------------------------------------------------
# Deduplication Tests
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_is_duplicate_same_category_and_class(self, reflection):
        new = {"attack_category": "xss", "hypothesis_class": "reflected_xss"}
        existing = [{"attack_category": "xss", "hypothesis_class": "reflected_xss"}]
        assert reflection._is_duplicate(new, existing) is True

    def test_is_duplicate_different_category(self, reflection):
        new = {"attack_category": "injection", "hypothesis_class": "reflected_xss"}
        existing = [{"attack_category": "xss", "hypothesis_class": "reflected_xss"}]
        assert reflection._is_duplicate(new, existing) is False

    def test_is_duplicate_different_class(self, reflection):
        new = {"attack_category": "xss", "hypothesis_class": "stored_xss"}
        existing = [{"attack_category": "xss", "hypothesis_class": "reflected_xss"}]
        assert reflection._is_duplicate(new, existing) is False

    def test_is_duplicate_empty_existing(self, reflection):
        new = {"attack_category": "xss", "hypothesis_class": "reflected_xss"}
        assert reflection._is_duplicate(new, []) is False

    @pytest.mark.asyncio
    async def test_reflection_dedup_against_existing(self, reflection, mock_llm):
        """Reflection should not generate hypotheses that duplicate existing ones."""
        mock_llm.generate.return_value = "reflection result"
        mock_llm.extract_json.return_value = {
            "should_continue": True,
            "coverage_assessment": "Missing auth testing",
            "gaps_identified": ["Auth bypass"],
            "new_hypotheses": [
                {
                    "hypothesis_class": "reflected_xss",  # Already exists!
                    "attack_category": "xss",  # Same category too
                    "description": "Duplicate XSS test",
                    "required_capabilities": ["xss"],
                    "confidence": 0.3,
                },
            ],
        }

        existing = [{"attack_category": "xss", "hypothesis_class": "reflected_xss"}]
        result = await reflection.evaluate(
            hypotheses=existing,
            results=[],
            findings=[],
        )
        # Duplicate should be filtered out
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Summarization Tests
# ---------------------------------------------------------------------------

class TestSummarization:
    def test_summarize_hypotheses_empty(self, reflection):
        result = reflection._summarize_hypotheses([], [])
        assert "No hypotheses" in result

    def test_summarize_hypotheses_with_data(self, reflection, sample_hypotheses, sample_results):
        result = reflection._summarize_hypotheses(sample_hypotheses, sample_results)
        assert "reflected_xss" in result
        assert "sqli_auth_bypass" in result

    def test_summarize_findings_empty(self, reflection):
        result = reflection._summarize_findings([])
        assert "No findings" in result

    def test_summarize_findings_with_data(self, reflection, sample_findings):
        result = reflection._summarize_findings(sample_findings)
        assert "XSS" in result
        assert "CSP" in result

    def test_summarize_surface_empty(self, reflection):
        result = reflection._summarize_surface(None)
        assert "No surface data" in result

    def test_summarize_surface_with_data(self, reflection, sample_surface):
        result = reflection._summarize_surface(sample_surface)
        assert "Django" in result
        assert "3" in result  # 3 pages

    def test_analyze_coverage(self, reflection):
        hypotheses = [
            {"attack_category": "xss"},
            {"attack_category": "injection"},
        ]
        findings = [
            {"owasp_category": "A03:2021"},
            {"attack_category": "xss"},
        ]
        result = reflection._analyze_coverage(hypotheses, findings)
        assert "xss" in result
        assert "injection" in result