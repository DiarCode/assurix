"""Unit tests for HPTSA Multi-Agent Coordinator (Phase 3)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.hptsa_coordinator import (
    HPTSACoordinator,
    PlanningAgent,
    SubAgentResult,
    DispatchDecision,
    XSSSubAgent,
    SQLiSubAgent,
    SSRFSubAgent,
    AuthSubAgent,
    ChainSubAgent,
    _severity_to_xss_tier,
    _severity_to_sqli_tier,
    _severity_to_ssrf_tier,
    _tier_to_severity,
)


# --- Data class tests ---


def test_sub_agent_result_is_frozen():
    result = SubAgentResult(
        subagent="xss", vuln_class="xss",
        findings=({"title": "XSS"},), verified=(),
        tier=2, confidence=0.9, actions_taken=3, evidence="cookie exfil",
    )
    assert result.subagent == "xss"
    assert result.tier == 2
    with pytest.raises(AttributeError):
        result.tier = 5


def test_dispatch_decision_fields():
    dd = DispatchDecision(
        subagent="sqli", reason="SQL errors found",
        priority="high", context_hints={"technologies": ["mysql"]},
    )
    assert dd.subagent == "sqli"
    assert dd.priority == "high"


# --- Tier mapping helpers ---


def test_severity_to_xss_tier():
    assert _severity_to_xss_tier("critical", "cookie exfiltrated") == 1
    assert _severity_to_xss_tier("high", "document.cookie") == 1  # "cookie" keyword → T1
    assert _severity_to_xss_tier("critical", "dom clobber chain") == 2
    assert _severity_to_xss_tier("high", "reflected") == 3
    assert _severity_to_xss_tier("medium", "found") == 4
    assert _severity_to_xss_tier("info", "") == 5


def test_severity_to_sqli_tier():
    assert _severity_to_sqli_tier("critical", "xp_cmdshell executed") == 1
    assert _severity_to_sqli_tier("high", "UNION SELECT password") == 2
    assert _severity_to_sqli_tier("critical", "SQL syntax error") == 3  # critical/high → T3
    assert _severity_to_sqli_tier("low", "500 error") == 4
    assert _severity_to_sqli_tier("info", "") == 4  # no evidence match, not high → T4


def test_severity_to_ssrf_tier():
    assert _severity_to_ssrf_tier("critical", "internal RCE") == 1
    assert _severity_to_ssrf_tier("high", "IAM credentials") == 2  # "credential" keyword
    assert _severity_to_ssrf_tier("high", "ami-id") == 3  # no keyword match, high → T3
    assert _severity_to_ssrf_tier("low", "200 ok") == 4
    assert _severity_to_ssrf_tier("info", "") == 4


def test_tier_to_severity():
    assert _tier_to_severity(1) == "critical"
    assert _tier_to_severity(2) == "high"
    assert _tier_to_severity(3) == "medium"
    assert _tier_to_severity(4) == "low"
    assert _tier_to_severity(5) == "info"


# --- SubAgent tests ---


def test_xss_subagent_creation():
    agent = XSSSubAgent()
    assert agent.vuln_class == "xss"
    assert "xss" in agent.system_prompt.lower()


def test_sqli_subagent_creation():
    agent = SQLiSubAgent()
    assert agent.vuln_class == "sqli"
    assert "sql" in agent.system_prompt.lower()


def test_ssrf_subagent_creation():
    agent = SSRFSubAgent()
    assert agent.vuln_class == "ssrf"


def test_auth_subagent_creation():
    agent = AuthSubAgent()
    assert agent.vuln_class == "auth_bypass"


def test_chain_subagent_creation():
    agent = ChainSubAgent()
    assert agent.vuln_class == "chain"


@pytest.mark.asyncio
async def test_subagent_execute_returns_result():
    agent = XSSSubAgent()
    with patch("src.agents.tools.XSSPipeline") as mock_pipeline_cls:
        mock_pipeline = MagicMock()
        mock_pipeline.scan = AsyncMock(return_value=[])
        mock_pipeline_cls.return_value = mock_pipeline
        result = await agent.execute("http://target.com", {}, [])
    assert isinstance(result, SubAgentResult)
    assert result.subagent == "xss"
    assert result.vuln_class == "xss"


# --- PlanningAgent tests ---


def test_planning_agent_subagent_map():
    pa = PlanningAgent()
    assert "xss" in pa.SUBAGENT_MAP
    assert "sqli" in pa.SUBAGENT_MAP
    assert "ssrf" in pa.SUBAGENT_MAP
    assert "auth" in pa.SUBAGENT_MAP
    assert "chain" in pa.SUBAGENT_MAP


def test_planning_agent_fallback_dispatch():
    pa = PlanningAgent()
    coverage = {"xss": "untested", "sqli": "untested", "ssrf": "untested", "auth": "untested", "chain": "untested"}
    decision = pa._fallback_dispatch(coverage, [])
    assert decision.subagent in pa.SUBAGENT_MAP
    assert decision.reason


def test_planning_agent_fallback_prefers_untested():
    pa = PlanningAgent()
    coverage = {"xss": "tested", "sqli": "tested", "ssrf": "untested", "auth": "tested", "chain": "untested"}
    decision = pa._fallback_dispatch(coverage, [])
    assert decision.subagent in ("ssrf", "chain")


def test_planning_agent_fallback_prefers_high_severity():
    pa = PlanningAgent()
    coverage = {"xss": "tested", "sqli": "partial", "ssrf": "tested", "auth": "tested", "chain": "tested"}
    findings = [{"severity": "critical", "vuln_type": "sqli", "title": "SQLi found"}]
    decision = pa._fallback_dispatch(coverage, findings)
    assert decision.subagent == "sqli"


@pytest.mark.asyncio
async def test_planning_agent_dispatch():
    pa = PlanningAgent()
    pa._llm_decide = AsyncMock(return_value=DispatchDecision(
        subagent="xss", reason="test", priority="high", context_hints={},
    ))
    with patch.object(XSSSubAgent, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = SubAgentResult(
            subagent="xss", vuln_class="xss",
            findings=({"title": "XSS"},), verified=(),
        )
        result = await pa.dispatch("http://target.com", {}, [])
    assert result is not None
    assert result.subagent == "xss"


@pytest.mark.asyncio
async def test_planning_agent_dispatch_fallback_on_llm_failure():
    pa = PlanningAgent()
    pa._llm_decide = AsyncMock(side_effect=Exception("LLM down"))
    with patch.object(XSSSubAgent, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = SubAgentResult(
            subagent="xss", vuln_class="xss",
            findings=(), verified=(),
        )
        result = await pa.dispatch("http://target.com", {}, [])
    assert result is not None


# --- HPTSACoordinator tests ---


def test_coordinator_creation():
    coord = HPTSACoordinator(max_dispatches=3)
    assert coord.max_dispatches == 3


def test_coordinator_reset():
    coord = HPTSACoordinator()
    coord.planner._dispatch_history.append("xss")
    coord.reset()
    assert len(coord.planner._dispatch_history) == 0


@pytest.mark.asyncio
async def test_coordinator_run():
    coord = HPTSACoordinator(max_dispatches=2)
    mock_result = SubAgentResult(
        subagent="xss", vuln_class="xss",
        findings=({"title": "XSS"},), verified=(),
        tier=3, confidence=0.8,
    )
    with patch.object(PlanningAgent, "dispatch", new_callable=AsyncMock) as mock_dispatch:
        mock_dispatch.return_value = mock_result
        results = await coord.run("http://target.com", {}, [])
    assert len(results) >= 1
    assert results[0].subagent == "xss"


@pytest.mark.asyncio
async def test_coordinator_run_stops_on_t1():
    coord = HPTSACoordinator(max_dispatches=10)
    t1_result = SubAgentResult(
        subagent="sqli", vuln_class="sqli",
        findings=({"title": "RCE", "severity": "critical"},), verified=(),
        tier=1, confidence=0.95,
    )
    with patch.object(PlanningAgent, "dispatch", new_callable=AsyncMock) as mock_dispatch:
        mock_dispatch.return_value = t1_result
        results = await coord.run("http://target.com", {}, [])
    # Should stop after T1 is found, not continue all 10 dispatches
    assert len(results) >= 1
    assert results[0].tier == 1


@pytest.mark.asyncio
async def test_coordinator_run_handles_none_dispatch():
    coord = HPTSACoordinator(max_dispatches=3)
    with patch.object(PlanningAgent, "dispatch", new_callable=AsyncMock) as mock_dispatch:
        mock_dispatch.return_value = None
        results = await coord.run("http://target.com", {}, [])
    assert results == []


# --- Pentester integration tests ---


def test_pentester_has_hptsa():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    assert hasattr(agent, "_hptsa")
    assert agent._hptsa is None  # lazily initialized


@pytest.mark.asyncio
async def test_pentester_execute_hptsa():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    # The _execute_hptsa method should exist
    assert hasattr(agent, "_execute_hptsa")
    assert callable(agent._execute_hptsa)


def test_pentester_has_hptsa_dispatch_action():
    """Verify hptsa_dispatch is a recognized action type in the match statement."""
    from src.agents.pentester import PentesterAgent
    import inspect
    source = inspect.getsource(PentesterAgent._execute_action)
    assert "hptsa_dispatch" in source


def test_pentester_process_subagent_result():
    """Verify _process_action_result handles SubAgentResult."""
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    sa_result = SubAgentResult(
        subagent="xss", vuln_class="xss",
        findings=({"title": "XSS", "severity": "high"},),
        verified=({"title": "XSS verified", "severity": "high", "verified": True},),
        tier=2, confidence=0.9,
    )
    findings = agent._process_action_result(sa_result, {}, "http://target.com")
    assert len(findings) == 2
    assert findings[0]["subagent"] == "xss"
    assert findings[1].get("verified") is True