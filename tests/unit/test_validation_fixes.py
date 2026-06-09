"""Unit tests for Phase 1 benchmark improvement fixes.

Verifies: P0 (validation FP fixes), P5 (session manager), P8 (POST/cookie/header fuzzing),
P9 (endpoint-aware testing), RC-8 (response dedup hashing).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.agents.validation import ValidationAgent
from src.agents.tools.session import SharedSessionManager
from src.agents.tools.fuzzer import Fuzzer
from src.agents.tools.response_dedup import ResponseDeduplicator


# --- P0: Validation FP Fix Tests ---


def _mock_response(status_code: int, text: str = "", headers: dict | None = None) -> httpx.Response:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = httpx.Headers(headers or {})
    return resp


@pytest.mark.asyncio
async def test_validate_exposure_no_sensitive_markers_is_unverified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_mock_response(200, "<html><body>Just a page</body></html>"))
    result = await agent._validate_exposure({"title": "Exposed .env"}, "http://target/.env", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_exposure_spa_catchall_is_unverified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_mock_response(200, '<html><body><div id="root"></div></body></html>'))
    result = await agent._validate_exposure({"title": "Sensitive path"}, "http://target/admin", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_exposure_with_secret_is_verified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_mock_response(200, 'db_password=secret123'))
    result = await agent._validate_exposure({"title": "Exposed config"}, "http://target/config.yml", client)
    assert result["exploit_verified"] is True


@pytest.mark.asyncio
async def test_validate_sqli_500_without_sql_keywords_is_unverified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, "normal page"),
        _mock_response(500, "Internal Server Error"),
    ])
    result = await agent._validate_sqli({"title": "SQL Injection"}, "http://target/page?id=1'", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_sqli_500_with_sql_keywords_is_verified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, "normal page"),
        _mock_response(500, "You have an error in your SQL syntax"),
    ])
    result = await agent._validate_sqli({"title": "SQL Injection"}, "http://target/page?id=1'", client)
    assert result["exploit_verified"] is True


@pytest.mark.asyncio
async def test_validate_ssrf_reachable_url_is_unverified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    same_body = "<html><body>Normal page content</body></html>"
    client.get = AsyncMock(side_effect=[
        _mock_response(200, same_body),
        _mock_response(200, same_body),
    ])
    result = await agent._validate_ssrf({"title": "SSRF"}, "http://target/fetch?url=http://internal", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_ssrf_with_metadata_is_verified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, "normal"),
        _mock_response(200, "ami-id: ami-12345\ninstance-type: t2.micro"),
    ])
    result = await agent._validate_ssrf({"title": "SSRF"}, "http://target/fetch?url=http://169.254.169.254", client)
    assert result["exploit_verified"] is True


@pytest.mark.asyncio
async def test_validate_idor_no_user_fields_is_unverified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_mock_response(200, json.dumps({"message": "ok"})))
    result = await agent._validate_idor({"title": "IDOR"}, "http://target/api/users/1", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_idor_same_response_different_ids_is_unverified():
    agent = ValidationAgent()
    same_json = json.dumps({"id": 1, "email": "test@test.com"})
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, same_json),
        _mock_response(200, same_json),
    ])
    result = await agent._validate_idor({"title": "IDOR"}, "http://target/api/users/1", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_generic_soft404_is_unverified():
    agent = ValidationAgent()
    same_body = "<html><body>Default page content here</body></html>"
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, same_body),
        _mock_response(200, same_body),
    ])
    result = await agent._validate_generic({"title": "Info disclosure"}, "http://target/something", client)
    assert result["exploit_verified"] is False


@pytest.mark.asyncio
async def test_validate_generic_different_response_is_verified():
    agent = ValidationAgent()
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _mock_response(200, "<html><body>Short</body></html>"),
        _mock_response(200, "<html><body>" + "x" * 500 + "</body></html>"),
    ])
    result = await agent._validate_generic({"title": "Info disclosure"}, "http://target/interesting", client)
    assert result["exploit_verified"] is True


# --- RC-8: Response Dedup Fix Tests ---


def test_dedup_uses_response_body_field():
    dedup = ResponseDeduplicator()
    findings = [
        {"title": "A", "url": "http://target/a", "response_body": "actual-http-body-A", "evidence": "different evidence text", "description": "desc"},
        {"title": "B", "url": "http://target/b", "response_body": "actual-http-body-A", "evidence": "totally different evidence", "description": "other desc"},
    ]
    result = dedup.dedup_findings(findings)
    assert len(result) == 1


def test_dedup_falls_back_to_evidence_when_no_response_body():
    dedup = ResponseDeduplicator()
    findings = [
        {"title": "A", "url": "http://target/a", "evidence": "same-evidence", "description": "same-desc"},
        {"title": "B", "url": "http://target/b", "evidence": "same-evidence", "description": "same-desc"},
    ]
    result = dedup.dedup_findings(findings)
    assert len(result) == 1


# --- P5: Session Manager Tests ---


def test_session_manager_creation():
    mgr = SharedSessionManager()
    assert not mgr.is_authenticated("http://target.com")


@pytest.mark.asyncio
async def test_session_manager_get_client():
    mgr = SharedSessionManager()
    client = mgr.get_client("http://target.com")
    assert isinstance(client, httpx.AsyncClient)
    await mgr.close()


# --- P8: Fuzzer New Methods Tests ---


def test_fuzzer_has_post_body_method():
    f = Fuzzer()
    assert hasattr(f, "fuzz_post_body") and callable(f.fuzz_post_body)


def test_fuzzer_has_cookies_method():
    f = Fuzzer()
    assert hasattr(f, "fuzz_cookies") and callable(f.fuzz_cookies)


def test_fuzzer_has_headers_injection_method():
    f = Fuzzer()
    assert hasattr(f, "fuzz_headers_injection") and callable(f.fuzz_headers_injection)


# --- P9: Endpoint-Aware Testing ---


def test_idor_validator_accepts_extra_paths():
    from src.agents.tools.idor_validator import IDORValidator
    import inspect
    sig = inspect.signature(IDORValidator.validate_idor)
    assert "extra_paths" in sig.parameters


def test_timing_analyzer_accepts_paths_param():
    from src.agents.tools.timing_analyzer import TimingAnalyzer
    import inspect
    sig = inspect.signature(TimingAnalyzer.test_blind_sqli)
    assert "paths" in sig.parameters
    assert "param" in sig.parameters


# --- P1: Vulnerability-Specific Pipelines ---


def test_xss_pipeline_exists():
    from src.agents.tools.vuln_pipelines import XSSPipeline
    p = XSSPipeline()
    assert hasattr(p, "scan") and callable(p.scan)


def test_sqli_pipeline_exists():
    from src.agents.tools.vuln_pipelines import SQLiPipeline
    p = SQLiPipeline()
    assert hasattr(p, "scan") and callable(p.scan)


def test_ssrf_pipeline_exists():
    from src.agents.tools.vuln_pipelines import SSRFPipeline
    p = SSRFPipeline()
    assert hasattr(p, "scan") and callable(p.scan)


def test_cmdi_pipeline_exists():
    from src.agents.tools.vuln_pipelines import CommandInjectionPipeline
    p = CommandInjectionPipeline()
    assert hasattr(p, "scan") and callable(p.scan)


def test_sqli_pipeline_has_deep_detection():
    from src.agents.tools.vuln_pipelines import SQLiPipeline
    p = SQLiPipeline()
    assert len(p.ERROR_PAYLOADS) > 0
    assert len(p.BOOLEAN_TRUE_PAYLOADS) > 0
    assert len(p.TIME_PAYLOADS) > 0
    assert len(p.SQL_ERROR_PATTERNS) > 10


def test_ssrf_pipeline_has_cloud_metadata():
    from src.agents.tools.vuln_pipelines import SSRFPipeline
    p = SSRFPipeline()
    assert len(p.CLOUD_METADATA_URLS) >= 4  # AWS, GCP, Alibaba, Azure
    assert len(p.INTERNAL_SERVICES) >= 4
    assert len(p.PROTOCOL_SMUGGLING) >= 2
    assert "ami-id" in p.METADATA_MARKERS


# --- P3: Adversarial Debate Validation ---


def test_adversarial_validator_fp_filter():
    from src.agents.adversarial import AdversarialValidator
    v = AdversarialValidator()
    # SPA catch-all should be filtered as obvious FP
    fp_finding = {"title": "Admin accessible", "evidence": '<div id="root">', "description": "page"}
    assert v._is_obvious_fp(fp_finding) is True


def test_adversarial_validator_real_finding_not_filtered():
    from src.agents.adversarial import AdversarialValidator
    v = AdversarialValidator()
    # Real finding should NOT be filtered
    real_finding = {"title": "SQL Injection in search", "evidence": "SQL syntax error detected", "description": "sqli"}
    assert v._is_obvious_fp(real_finding) is False


def test_adversarial_validator_login_redirect_filtered():
    from src.agents.adversarial import AdversarialValidator
    v = AdversarialValidator()
    finding = {"title": "Redirects to login page", "evidence": "302 redirect", "description": "redirect"}
    assert v._is_obvious_fp(finding) is True


@pytest.mark.asyncio
async def test_validation_agent_has_adversarial_phase():
    from src.agents.validation import ValidationAgent
    agent = ValidationAgent()
    # Verify the agent references adversarial validation in execute
    import inspect
    source = inspect.getsource(agent.execute)
    assert "AdversarialValidator" in source or "adversarial" in source.lower()


# --- P2: ReAct Loop Tests ---


def test_pentester_has_react_methods():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    assert hasattr(agent, '_think') and callable(agent._think)
    assert hasattr(agent, '_select_action') and callable(agent._select_action)
    assert hasattr(agent, '_execute_action') and callable(agent._execute_action)
    assert hasattr(agent, '_reflect') and callable(agent._reflect)
    assert hasattr(agent, '_observe') and callable(agent._observe)


def test_pentester_uses_context_manager():
    from src.agents.pentester import PentesterAgent
    from src.agents.context import ContextManager
    agent = PentesterAgent()
    assert isinstance(agent.ctx, ContextManager)


def test_pentester_uses_mcts_planner():
    from src.agents.pentester import PentesterAgent
    from src.agents.planner_mcts import MCTSPlannerAgent
    agent = PentesterAgent()
    assert isinstance(agent.mcts_planner, MCTSPlannerAgent)


def test_pentester_has_convergence_threshold():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    assert agent.convergence_threshold >= 1


# --- P4: LATS Tree Search Tests ---


def test_mcts_node_ucb1_unvisited_is_inf():
    from src.agents.planner_mcts import MCTSNode
    node = MCTSNode(task_type="test", target="http://x")
    assert node.ucb1 == float("inf")


def test_mcts_node_ucb1_visited():
    from src.agents.planner_mcts import MCTSNode
    root = MCTSNode(task_type="root", target="http://x", visits=10)
    child = MCTSNode(task_type="test", target="http://x", visits=5, total_reward=3.0, parent=root)
    assert child.ucb1 > 0
    assert child.avg_reward == 0.6


def test_mcts_planner_has_select_next_action():
    from src.agents.planner_mcts import MCTSPlannerAgent
    planner = MCTSPlannerAgent()
    assert hasattr(planner, 'select_next_action') and callable(planner.select_next_action)


def test_mcts_planner_has_llm_expand():
    from src.agents.planner_mcts import MCTSPlannerAgent
    planner = MCTSPlannerAgent()
    assert hasattr(planner, '_llm_expand_actions') and callable(planner._llm_expand_actions)


def test_mcts_planner_has_add_hypothesis_nodes():
    from src.agents.planner_mcts import MCTSPlannerAgent
    planner = MCTSPlannerAgent()
    assert hasattr(planner, '_add_hypothesis_nodes') and callable(planner._add_hypothesis_nodes)


def test_mcts_planner_reset_tree():
    from src.agents.planner_mcts import MCTSPlannerAgent, MCTSNode
    planner = MCTSPlannerAgent()
    planner._tree = MCTSNode(task_type="root", target="http://x")
    planner.reset_tree()
    assert planner._tree is None


def test_mcts_node_expanded_flag():
    from src.agents.planner_mcts import MCTSNode
    node = MCTSNode(task_type="test", target="http://x")
    assert node.expanded is False


# --- P6: Context Compaction Tests ---


def test_context_manager_creation():
    from src.agents.context import ContextManager
    ctx = ContextManager()
    assert ctx.observation_count == 0
    assert ctx.finding_count == 0
    assert not ctx.has_compacted_data


def test_context_manager_add_observation():
    from src.agents.context import ContextManager
    ctx = ContextManager(window_size=5)
    ctx.add_observation({"action": "fuzz", "url": "http://x", "result": "ok"})
    assert ctx.observation_count == 1


def test_context_manager_compaction():
    from src.agents.context import ContextManager
    ctx = ContextManager(window_size=3)
    for i in range(5):
        ctx.add_observation({"action": f"action_{i}", "url": f"http://x/{i}", "result": f"result_{i}"})
    assert ctx.observation_count == 3  # only last 3 kept
    assert ctx.has_compacted_data  # older ones compacted


def test_context_manager_confirmed_findings():
    from src.agents.context import ContextManager
    ctx = ContextManager()
    ctx.confirm_finding({"title": "XSS found", "severity": "high"})
    assert ctx.finding_count == 1
    findings = ctx.get_confirmed_findings()
    assert len(findings) == 1
    assert findings[0]["title"] == "XSS found"


def test_context_manager_failed_attempts():
    from src.agents.context import ContextManager
    ctx = ContextManager()
    ctx.record_failed_attempt("fuzz_dirs", "http://x/admin", "403")
    assert ctx.is_failed_attempt("fuzz_dirs", "http://x/admin")
    assert not ctx.is_failed_attempt("fuzz_params", "http://x/admin")


def test_context_manager_llm_context():
    from src.agents.context import ContextManager
    ctx = ContextManager()
    ctx.add_observation({"action": "scan", "url": "http://x", "result_summary": "found XSS"})
    ctx.confirm_finding({"title": "XSS", "severity": "high", "evidence": "reflected"})
    ctx.record_failed_attempt("fuzz_dirs", "http://x/admin", "no findings")
    context = ctx.get_context_for_llm()
    assert "XSS" in context
    assert "Failed Attempts" in context
    assert "scan" in context


def test_context_manager_reset():
    from src.agents.context import ContextManager
    ctx = ContextManager()
    ctx.add_observation({"action": "scan", "url": "http://x", "result": "ok"})
    ctx.confirm_finding({"title": "Test", "severity": "medium"})
    ctx.reset()
    assert ctx.observation_count == 0
    assert ctx.finding_count == 0


# --- P7: Bayesian Hypothesis Wiring Tests ---


def test_pentester_has_seed_hypotheses():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    assert hasattr(agent, '_seed_hypotheses') and callable(agent._seed_hypotheses)


def test_pentester_has_update_hypotheses():
    from src.agents.pentester import PentesterAgent
    agent = PentesterAgent()
    assert hasattr(agent, '_update_hypotheses') and callable(agent._update_hypotheses)


@pytest.mark.asyncio
async def test_bayesian_hypothesis_seeding():
    from src.agents.browser.memory import FindingMemory
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        memory = FindingMemory("test", Path(tmpdir))
        from src.agents.pentester import PentesterAgent
        agent = PentesterAgent()
        await agent._seed_hypotheses(memory, {"technologies": ["php", "mysql"], "auth_pages": ["/login"], "endpoints": ["/api/users/1"]}, "http://target.com")
        active = memory.get_active_hypotheses()
        bayesian = [h for h in active if "posterior" in h]
        assert len(bayesian) >= 4  # xss, sqli, auth, idor at minimum


def test_bayesian_hypothesis_update_positive():
    from src.agents.browser.memory import FindingMemory
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        memory = FindingMemory("test", Path(tmpdir))
        memory.add_bayesian_hypothesis("sqli_hypothesis", "SQLi possible", "sqli", prior=0.5)
        result = memory.update_hypothesis("sqli_hypothesis", likelihood_for=0.9, likelihood_against=0.1, new_evidence_for=["SQL error found"])
        assert result is not None
        assert result["posterior"] > 0.5  # should increase


def test_bayesian_hypothesis_update_negative():
    from src.agents.browser.memory import FindingMemory
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        memory = FindingMemory("test", Path(tmpdir))
        memory.add_bayesian_hypothesis("sqli_hypothesis", "SQLi possible", "sqli", prior=0.5)
        result = memory.update_hypothesis("sqli_hypothesis", likelihood_for=0.1, likelihood_against=0.9, new_evidence_against=["no SQL errors"])
        assert result is not None
        assert result["posterior"] < 0.5  # should decrease