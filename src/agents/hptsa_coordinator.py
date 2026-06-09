"""HPTSA — Hierarchical Planning with Task-Specific Sub-Agents.

Implements the architecture from the Stanford/UMD HPTSA paper:
a PlanningAgent coordinates overall strategy by dispatching to
task-specific subagents, each focused on a single vulnerability class.

Key insight: Task-specific agents outperform generalist agents by 4.3x
because they can focus reasoning on a single attack class with
specialized prompts, tools, and context management.

Architecture:
    HPTSACoordinator (entry point for PentesterAgent)
      └── PlanningAgent (decides which subagent to dispatch)
            ├── XSSSubAgent
            ├── SQLiSubAgent
            ├── SSRFSubAgent
            ├── AuthSubAgent
            └── ChainSubAgent (multi-step chaining)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from src.agents.context import ContextManager
from src.llm.frontier_client import UnifiedLLMClient
from src.llm.json_utils import extract_json_from_response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubAgentResult:
    """Result from a sub-agent execution."""

    subagent: str
    vuln_class: str
    findings: tuple[dict[str, Any], ...]
    verified: tuple[dict[str, Any], ...]
    tier: int = 5
    confidence: float = 0.0
    actions_taken: int = 0
    evidence: str = ""


@dataclass
class DispatchDecision:
    """Planning agent's decision on which subagent to dispatch."""

    subagent: str
    reason: str
    priority: str = "medium"
    context_hints: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sub-agent specialized prompts
# ---------------------------------------------------------------------------

XSS_SUBAGENT_SYSTEM = """You are an XSS exploitation specialist. Your ONLY focus is finding
and proving cross-site scripting vulnerabilities.

Strategy:
1. Test ALL input reflection points (parameters, headers, path segments, POST bodies)
2. Use context-aware payloads matching the target's technology stack
3. Escalate from detection to proof: if reflection is found, attempt cookie exfiltration
4. Classify findings by tier:
   - T4: Reflected marker only (no JS execution context)
   - T3: Stored XSS with persistent context or DOM clobbering
   - T2: Cookie/token exfiltration via JS execution
   - T1: Account takeover via stored XSS + session hijacking

Available XSS payload types:
- HTML injection: script, img onerror, svg onload, body onload
- Event handlers: onclick, onmouseover, onfocus, onblur
- DOM-based: location.hash, innerHTML assignment
- Template injection: constructor-based, expression language
- Encoded variants: URL-encoded, double-encoded, Unicode, HTML entities

Always check: is the input reflected? In what context (HTML, JS, attribute)?
What encoding/filtering is applied? Can you break out of the context?"""

SQLI_SUBAGENT_SYSTEM = """You are a SQL injection exploitation specialist. Your ONLY focus is
finding and proving SQL injection vulnerabilities.

Strategy:
1. Test ALL database interaction points (search, login, API filters, pagination)
2. Start with error-based detection, escalate to data extraction
3. Escalate through tiers:
   - T4: Error-based detection (syntax errors, type mismatches)
   - T3: Boolean-based blind (different responses for TRUE/FALSE)
   - T2: UNION-based data extraction (user tables, credentials, configs)
   - T1: Stacked queries / INTO OUTFILE / xp_cmdshell for RCE

SQLi payload progression:
- Detection: single quote, double quote, backslash
- Boolean: ' AND 1=1--, ' AND 1=2--
- UNION: ' UNION SELECT NULL--, column count, table enumeration
- Data extraction: FROM users, FROM information_schema.tables
- RCE: '; EXEC xp_cmdshell--, '; INTO OUTFILE--

Always test: number of columns, data types, visible column positions.
Check for WAF patterns that filter keywords (try case variations, comments)."""

SSRF_SUBAGENT_SYSTEM = """You are an SSRF exploitation specialist. Your ONLY focus is
finding and proving Server-Side Request Forgery vulnerabilities.

Strategy:
1. Test ALL URL-accepting parameters (fetch, proxy, redirect, callback, upload)
2. Escalate from internal access to credential theft:
   - T4: Internal service reached (localhost, 127.0.0.1)
   - T3: Cloud metadata endpoint accessed (169.254.169.254)
   - T2: IAM credentials extracted from metadata
   - T1: Redis/Gopher protocol for RCE

SSRF payload targets:
- Local: http://127.0.0.1, http://localhost, http://[::1]
- Cloud metadata: http://169.254.169.254/latest/meta-data/
- Internal ports: http://127.0.0.1:6379 (Redis), :9200 (Elasticsearch)
- Protocol smuggling: gopher://, dict://, file:///

Always check: can you control the full URL? Is redirect following enabled?
Are there IP allowlist bypasses (DNS rebinding, decimal IP, IPv6)?"""

AUTH_SUBAGENT_SYSTEM = """You are an authentication/authorization exploitation specialist.
Your ONLY focus is finding and proving auth bypass and privilege escalation.

Strategy:
1. Test ALL authentication mechanisms (session, JWT, OAuth, API keys)
2. Escalate from detection to account takeover:
   - T4: Weak password policy or missing rate limiting
   - T3: Auth bypass (broken access control on specific endpoints)
   - T2: Privilege escalation (user to admin role manipulation)
   - T1: Full account takeover (credential stuffing + admin access)

Auth test payloads:
- Session: modify session cookies, predict session IDs
- JWT: algorithm confusion (none/HS256), key confusion, claim manipulation
- OAuth: redirect_uri manipulation, state parameter bypass
- IDOR: sequential ID substitution, UUID prediction
- Role manipulation: role=admin, X-Forwarded-For spoofing

Always check: what auth mechanism is used? Where is the trust boundary?
Can you cross it? What roles exist and can you escalate?"""

CHAIN_SUBAGENT_SYSTEM = """You are an exploit chaining specialist. Your focus is combining
multiple lower-severity findings into higher-impact attack chains.

Chain patterns to test:
1. XSS + CSRF: stored XSS that performs admin actions
2. SQLi + auth: extract credentials, login, escalate
3. SSRF + internal service: Redis unauth to RCE
4. IDOR + privilege escalation: admin account takeover
5. Info disclosure + credential reuse: full compromise

When chaining:
- Start with the highest-tier primitive as the base
- Look for findings that provide authenticated access
- Check if lower-tier findings can be combined for higher impact
- Document each step of the chain with evidence

Output the full chain as a sequence of (finding, action, evidence) tuples."""

PLANNING_AGENT_SYSTEM = """You are a security assessment planning coordinator.
Given the current target state and findings, decide which specialized
sub-agent to dispatch next for maximum impact.

Available sub-agents:
- xss: Specialized in cross-site scripting detection and exploitation
- sqli: Specialized in SQL injection and database extraction
- ssrf: Specialized in SSRF and cloud credential harvesting
- auth: Specialized in authentication bypass and privilege escalation
- chain: Specialized in combining multiple findings into attack chains

Decision criteria:
1. Which vulnerability class has the MOST untested surface area?
2. Which class has findings that could be ESCALATED (T4 to T2 to T1)?
3. Which class matches the target's TECHNOLOGY STACK?
4. Are there ENOUGH findings for a meaningful chain attempt?
5. Which class has HISTORICALLY been most successful on similar targets?

Respond in JSON:
{
  "subagent": "xss|sqli|ssrf|auth|chain|none",
  "reason": "why this subagent should run next",
  "priority": "critical|high|medium|low",
  "context_hints": {
    "focus_endpoints": ["urls to prioritize"],
    "techniques": ["specific techniques to try"],
    "skip": ["techniques already exhausted"]
  }
}

If no subagent should run (all classes exhausted), respond with "none"."""


# ---------------------------------------------------------------------------
# Sub-agents
# ---------------------------------------------------------------------------


class _BaseSubAgent:
    """Base class for HPTSA task-specific sub-agents."""

    name: str = "base"
    vuln_class: str = "unknown"
    system_prompt: str = ""

    def __init__(self) -> None:
        self.ctx = ContextManager(window_size=15)
        self._findings: list[dict[str, Any]] = []
        self._verified: list[dict[str, Any]] = []

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        """Execute the sub-agent's specialized attack strategy."""
        raise NotImplementedError

    def _add_finding(self, finding: dict[str, Any]) -> None:
        """Record a raw finding from this sub-agent."""
        self._findings.append(finding)

    def _add_verified(self, finding: dict[str, Any]) -> None:
        """Record a verified finding with exploitation evidence."""
        self._verified.append(finding)

    def _build_result(self, actions_taken: int = 0, evidence: str = "") -> SubAgentResult:
        """Build the frozen SubAgentResult from accumulated state."""
        best_tier = 5
        best_conf = 0.0
        for f in self._verified:
            t = f.get("tier", 5)
            c = f.get("confidence", 0.0)
            if t < best_tier or (t == best_tier and c > best_conf):
                best_tier = t
                best_conf = c
        for f in self._findings:
            t = f.get("tier", 5)
            c = f.get("confidence", 0.0)
            if t < best_tier or (t == best_tier and c > best_conf):
                best_tier = t
                best_conf = c

        return SubAgentResult(
            subagent=self.name,
            vuln_class=self.vuln_class,
            findings=tuple(self._findings),
            verified=tuple(self._verified),
            tier=best_tier,
            confidence=best_conf,
            actions_taken=actions_taken,
            evidence=evidence,
        )


class XSSSubAgent(_BaseSubAgent):
    """Specialized XSS exploitation sub-agent."""

    name = "xss"
    vuln_class = "xss"
    system_prompt = XSS_SUBAGENT_SYSTEM

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        from src.agents.tools import XSSPipeline

        hints = context_hints or {}
        actions_taken = 0
        evidence_parts: list[str] = []

        # 1. Run XSS pipeline for detection
        pipeline = XSSPipeline()
        try:
            endpoints = hints.get("focus_endpoints") or observations.get("endpoints", [])
            results = await pipeline.scan(target_url, endpoints=endpoints or None)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    sev = getattr(r, "severity", "medium")
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "xss",
                        "severity": sev,
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-79",
                        "tier": _severity_to_xss_tier(sev, getattr(r, "evidence", "")),
                        "confidence": 0.7 if sev in ("high", "critical") else 0.5,
                    })
                    evidence_parts.append(f"[XSS detection] {r.finding}")
        except Exception as exc:
            logger.warning("XSSSubAgent pipeline failed: %s", exc)

        # 2. Attempt exploitation via ExploitBuilder if available
        try:
            from src.agents.exploit_builder import ExploitBuilder
            builder = ExploitBuilder()
            try:
                primitives = await builder.build_primitives_for_class(
                    "xss", target_url, confirmed_findings,
                )
                actions_taken += 1
                verified = await builder.verify_primitives(primitives, target_url)
                for v in verified:
                    entry = v.to_dict() if hasattr(v, "to_dict") else v
                    self._add_verified(entry)
                    evidence_parts.append(
                        f"[XSS verify] tier=T{v.tier} verified={v.verified}"
                    )
            finally:
                await builder.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("XSSSubAgent exploit builder failed: %s", exc)

        # 3. LLM-guided deep XSS reasoning if findings exist
        if self._findings or self._verified:
            await self._llm_reason(target_url, observations, confirmed_findings, hints)
            actions_taken += 1

        return self._build_result(actions_taken=actions_taken, evidence="; ".join(evidence_parts))

    async def _llm_reason(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        hints: dict[str, Any],
    ) -> None:
        """Use LLM for deeper XSS context analysis."""
        try:
            llm = UnifiedLLMClient()
            try:
                findings_summary = json.dumps([
                    {"title": f.get("title"), "tier": f.get("tier"), "evidence": f.get("evidence", "")[:100]}
                    for f in (self._findings + self._verified)[:5]
                ])
                tech = observations.get("technologies", [])
                prompt = (
                    f"Target: {target_url}\n"
                    f"Technologies: {json.dumps(tech[:5])}\n"
                    f"XSS findings so far: {findings_summary}\n"
                    f"Focus: {hints.get('techniques', ['all XSS contexts'])}\n\n"
                    "Analyze the XSS findings. Which XSS context (HTML body, attribute, "
                    "JavaScript, URL) is most likely exploitable? Suggest specific "
                    "payload variants that would bypass common filters. "
                    "Respond in JSON: {\"best_context\": \"...\", \"payloads\": [\"...\"], "
                    "\"bypass_technique\": \"...\", \"estimated_tier\": 1-5}"
                )
                response = await llm.chat(
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    task_type="exploitation",
                    max_tokens=2048,
                )
                parsed = extract_json_from_response(response)
                if isinstance(parsed, dict) and parsed.get("payloads"):
                    self._add_finding({
                        "title": f"XSS LLM analysis: {parsed.get('best_context', 'unknown')}",
                        "vuln_class": "xss",
                        "severity": _tier_to_severity(parsed.get("estimated_tier", 4)),
                        "evidence": f"Bypass: {parsed.get('bypass_technique', '')}. Payloads: {parsed.get('payloads', [])[:3]}",
                        "url": target_url,
                        "cwe_id": "CWE-79",
                        "tier": parsed.get("estimated_tier", 4),
                        "confidence": 0.6,
                    })
            finally:
                await llm.close()
        except Exception as exc:
            logger.warning("XSSSubAgent LLM reasoning failed: %s", exc)


class SQLiSubAgent(_BaseSubAgent):
    """Specialized SQL injection exploitation sub-agent."""

    name = "sqli"
    vuln_class = "sqli"
    system_prompt = SQLI_SUBAGENT_SYSTEM

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        from src.agents.tools import SQLiPipeline, TimingAnalyzer

        hints = context_hints or {}
        actions_taken = 0
        evidence_parts: list[str] = []

        # 1. SQLi pipeline
        pipeline = SQLiPipeline()
        try:
            endpoints = hints.get("focus_endpoints") or observations.get("endpoints", [])
            results = await pipeline.scan(target_url, endpoints=endpoints or None)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    sev = getattr(r, "severity", "medium")
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "sqli",
                        "severity": sev,
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-89",
                        "tier": _severity_to_sqli_tier(sev, getattr(r, "evidence", "")),
                        "confidence": 0.8 if sev == "critical" else 0.6,
                    })
                    evidence_parts.append(f"[SQLi detection] {r.finding}")
        except Exception as exc:
            logger.warning("SQLiSubAgent pipeline failed: %s", exc)

        # 2. Timing-based blind SQLi
        try:
            timing = TimingAnalyzer()
            timing_paths = [
                ep for ep in observations.get("endpoints", [])
                if "?" in ep or any(p in ep for p in ("/api/", "/search", "/login"))
            ][:8]
            if timing_paths:
                timing_results = await timing.test_blind_sqli(target_url, paths=timing_paths)
                actions_taken += 1
                for r in timing_results if isinstance(timing_results, list) else [timing_results]:
                    if hasattr(r, "finding") and r.finding:
                        self._add_finding({
                            "title": r.finding,
                            "vuln_class": "sqli",
                            "severity": getattr(r, "severity", "high"),
                            "evidence": getattr(r, "evidence", ""),
                            "url": target_url,
                            "cwe_id": "CWE-89",
                            "tier": 2,
                            "confidence": 0.7,
                        })
                        evidence_parts.append(f"[Blind SQLi] {r.finding}")
        except Exception as exc:
            logger.warning("SQLiSubAgent timing test failed: %s", exc)

        # 3. ExploitBuilder for verification
        try:
            from src.agents.exploit_builder import ExploitBuilder
            builder = ExploitBuilder()
            try:
                primitives = await builder.build_primitives_for_class(
                    "sqli", target_url, confirmed_findings,
                )
                actions_taken += 1
                verified = await builder.verify_primitives(primitives, target_url)
                for v in verified:
                    entry = v.to_dict() if hasattr(v, "to_dict") else v
                    self._add_verified(entry)
                    evidence_parts.append(
                        f"[SQLi verify] tier=T{v.tier} verified={v.verified}"
                    )
            finally:
                await builder.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("SQLiSubAgent exploit builder failed: %s", exc)

        # 4. LLM-guided data extraction strategy
        if self._findings or self._verified:
            await self._llm_reason(target_url, observations, confirmed_findings, hints)
            actions_taken += 1

        return self._build_result(actions_taken=actions_taken, evidence="; ".join(evidence_parts))

    async def _llm_reason(
        self, target_url: str, observations: dict, confirmed: list[dict], hints: dict,
    ) -> None:
        try:
            llm = UnifiedLLMClient()
            try:
                findings_summary = json.dumps([
                    {"title": f.get("title"), "tier": f.get("tier")}
                    for f in (self._findings + self._verified)[:5]
                ])
                prompt = (
                    f"Target: {target_url}\n"
                    f"SQLi findings: {findings_summary}\n"
                    f"Confirmed DB indicators: {[f.get('evidence','')[:80] for f in confirmed[:3]]}\n\n"
                    "If SQLi is confirmed, suggest: (1) UNION column count, "
                    "(2) table enumeration strategy, (3) data extraction targets. "
                    "Respond in JSON: {\"column_count\": N, \"tables\": [...], "
                    "\"extraction_payloads\": [...], \"estimated_tier\": 1-5}"
                )
                response = await llm.chat(
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    task_type="exploitation",
                    max_tokens=2048,
                )
                parsed = extract_json_from_response(response)
                if isinstance(parsed, dict) and parsed.get("extraction_payloads"):
                    self._add_finding({
                        "title": "SQLi LLM extraction strategy",
                        "vuln_class": "sqli",
                        "severity": _tier_to_severity(parsed.get("estimated_tier", 3)),
                        "evidence": f"Tables: {parsed.get('tables', [])}. Payloads: {parsed.get('extraction_payloads', [])[:2]}",
                        "url": target_url,
                        "cwe_id": "CWE-89",
                        "tier": parsed.get("estimated_tier", 3),
                        "confidence": 0.65,
                    })
            finally:
                await llm.close()
        except Exception as exc:
            logger.warning("SQLiSubAgent LLM reasoning failed: %s", exc)


class SSRFSubAgent(_BaseSubAgent):
    """Specialized SSRF exploitation sub-agent."""

    name = "ssrf"
    vuln_class = "ssrf"
    system_prompt = SSRF_SUBAGENT_SYSTEM

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        from src.agents.tools import SSRFPipeline

        hints = context_hints or {}
        actions_taken = 0
        evidence_parts: list[str] = []

        # 1. SSRF pipeline
        pipeline = SSRFPipeline()
        try:
            results = await pipeline.scan(target_url)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    sev = getattr(r, "severity", "medium")
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "ssrf",
                        "severity": sev,
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-918",
                        "tier": _severity_to_ssrf_tier(sev, getattr(r, "evidence", "")),
                        "confidence": 0.7,
                    })
                    evidence_parts.append(f"[SSRF detection] {r.finding}")
        except Exception as exc:
            logger.warning("SSRFSubAgent pipeline failed: %s", exc)

        # 2. ExploitBuilder verification
        try:
            from src.agents.exploit_builder import ExploitBuilder
            builder = ExploitBuilder()
            try:
                primitives = await builder.build_primitives_for_class(
                    "ssrf", target_url, confirmed_findings,
                )
                actions_taken += 1
                verified = await builder.verify_primitives(primitives, target_url)
                for v in verified:
                    entry = v.to_dict() if hasattr(v, "to_dict") else v
                    self._add_verified(entry)
                    evidence_parts.append(
                        f"[SSRF verify] tier=T{v.tier} verified={v.verified}"
                    )
            finally:
                await builder.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("SSRFSubAgent exploit builder failed: %s", exc)

        # 3. LLM reasoning
        if self._findings or self._verified:
            await self._llm_reason(target_url, observations, confirmed_findings, hints)
            actions_taken += 1

        return self._build_result(actions_taken=actions_taken, evidence="; ".join(evidence_parts))

    async def _llm_reason(
        self, target_url: str, observations: dict, confirmed: list[dict], hints: dict,
    ) -> None:
        try:
            llm = UnifiedLLMClient()
            try:
                findings_summary = json.dumps([
                    {"title": f.get("title"), "tier": f.get("tier")}
                    for f in (self._findings + self._verified)[:5]
                ])
                prompt = (
                    f"Target: {target_url}\nSSRF findings: {findings_summary}\n\n"
                    "Analyze SSRF findings. Can internal cloud metadata be reached? "
                    "Suggest: (1) metadata endpoints to test, (2) protocol smuggling "
                    "vectors, (3) credential extraction approach. "
                    "Respond in JSON: {\"metadata_endpoints\": [...], "
                    "\"protocol_vectors\": [...], \"estimated_tier\": 1-5}"
                )
                response = await llm.chat(
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    task_type="exploitation",
                    max_tokens=2048,
                )
                parsed = extract_json_from_response(response)
                if isinstance(parsed, dict) and (parsed.get("metadata_endpoints") or parsed.get("protocol_vectors")):
                    self._add_finding({
                        "title": "SSRF LLM analysis",
                        "vuln_class": "ssrf",
                        "severity": _tier_to_severity(parsed.get("estimated_tier", 4)),
                        "evidence": f"Metadata: {parsed.get('metadata_endpoints', [])}. Protocols: {parsed.get('protocol_vectors', [])}",
                        "url": target_url,
                        "cwe_id": "CWE-918",
                        "tier": parsed.get("estimated_tier", 4),
                        "confidence": 0.6,
                    })
            finally:
                await llm.close()
        except Exception as exc:
            logger.warning("SSRFSubAgent LLM reasoning failed: %s", exc)


class AuthSubAgent(_BaseSubAgent):
    """Specialized authentication bypass and privilege escalation sub-agent."""

    name = "auth"
    vuln_class = "auth_bypass"
    system_prompt = AUTH_SUBAGENT_SYSTEM

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        from src.agents.tools import AuthTester, IDORValidator, CredentialTester

        hints = context_hints or {}
        actions_taken = 0
        evidence_parts: list[str] = []

        # 1. Auth bypass tests
        auth = AuthTester()
        try:
            results = await auth.test_auth_bypass(target_url)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "auth_bypass",
                        "severity": getattr(r, "severity", "high"),
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-284",
                        "tier": 2 if "admin" in r.finding.lower() or "privilege" in r.finding.lower() else 3,
                        "confidence": 0.75,
                    })
                    evidence_parts.append(f"[Auth bypass] {r.finding}")
        except Exception as exc:
            logger.warning("AuthSubAgent auth bypass failed: %s", exc)

        # 2. IDOR tests
        idor = IDORValidator()
        try:
            extra_paths = [
                ep for ep in observations.get("endpoints", [])
                if any(c in ep for c in ("/api/", "/user", "/account"))
            ][:10]
            results = await idor.validate_idor(target_url, extra_paths=extra_paths or None)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "auth_bypass",
                        "severity": getattr(r, "severity", "high"),
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-639",
                        "tier": 1 if "admin" in r.finding.lower() else 2,
                        "confidence": 0.7,
                    })
                    evidence_parts.append(f"[IDOR] {r.finding}")
        except Exception as exc:
            logger.warning("AuthSubAgent IDOR test failed: %s", exc)

        # 3. Credential testing
        try:
            cred = CredentialTester()
            login_pages = [p for p in observations.get("auth_pages", [])]
            login_paths = [p if isinstance(p, str) else p.get("url", "") for p in login_pages] if login_pages else None
            results = await cred.test_credentials(target_url, login_paths=login_paths)
            actions_taken += 1
            for r in results if isinstance(results, list) else [results]:
                if hasattr(r, "finding") and r.finding:
                    self._add_finding({
                        "title": r.finding,
                        "vuln_class": "auth_bypass",
                        "severity": getattr(r, "severity", "critical"),
                        "evidence": getattr(r, "evidence", ""),
                        "url": target_url,
                        "cwe_id": "CWE-307",
                        "tier": 1 if "credential" in r.finding.lower() else 3,
                        "confidence": 0.8,
                    })
                    evidence_parts.append(f"[Credentials] {r.finding}")
        except Exception as exc:
            logger.warning("AuthSubAgent credential test failed: %s", exc)

        # 4. ExploitBuilder for auth_bypass primitives
        try:
            from src.agents.exploit_builder import ExploitBuilder
            builder = ExploitBuilder()
            try:
                primitives = await builder.build_primitives_for_class(
                    "auth_bypass", target_url, confirmed_findings,
                )
                actions_taken += 1
                verified = await builder.verify_primitives(primitives, target_url)
                for v in verified:
                    entry = v.to_dict() if hasattr(v, "to_dict") else v
                    self._add_verified(entry)
                    evidence_parts.append(
                        f"[Auth verify] tier=T{v.tier} verified={v.verified}"
                    )
            finally:
                await builder.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("AuthSubAgent exploit builder failed: %s", exc)

        return self._build_result(actions_taken=actions_taken, evidence="; ".join(evidence_parts))


class ChainSubAgent(_BaseSubAgent):
    """Specialized multi-step exploit chaining sub-agent."""

    name = "chain"
    vuln_class = "chain"
    system_prompt = CHAIN_SUBAGENT_SYSTEM

    async def execute(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        context_hints: dict[str, Any] | None = None,
    ) -> SubAgentResult:
        actions_taken = 0
        evidence_parts: list[str] = []

        if len(confirmed_findings) < 2:
            return self._build_result(
                actions_taken=0,
                evidence="Need at least 2 confirmed findings for chaining",
            )

        # 1. Use ExploitBuilder to chain findings
        try:
            from src.agents.exploit_builder import ExploitBuilder
            builder = ExploitBuilder()
            try:
                # Find the highest-tier primitive to use as chain base
                primitives = builder.find_primitives(confirmed_findings)
                if primitives:
                    base_prim = primitives[0]
                    chain_result = await builder.chain_findings(
                        primitive=base_prim,
                        other_findings=confirmed_findings,
                        observations=observations,
                    )
                    actions_taken += 1
                    if chain_result:
                        if isinstance(chain_result, dict):
                            self._add_verified(chain_result)
                            evidence_parts.append(
                                f"[Chain] {chain_result.get('finding', 'chain discovered')}"
                            )
                        elif hasattr(chain_result, "to_dict"):
                            self._add_verified(chain_result.to_dict())
                            evidence_parts.append(
                                f"[Chain] {getattr(chain_result, 'finding', 'chain discovered')}"
                            )
            finally:
                await builder.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("ChainSubAgent exploit builder failed: %s", exc)

        # 2. LLM-guided chain analysis
        if confirmed_findings:
            await self._llm_reason(target_url, observations, confirmed_findings, context_hints or {})
            actions_taken += 1

        return self._build_result(actions_taken=actions_taken, evidence="; ".join(evidence_parts))

    async def _llm_reason(
        self, target_url: str, observations: dict, confirmed: list[dict], hints: dict,
    ) -> None:
        try:
            llm = UnifiedLLMClient()
            try:
                findings_summary = json.dumps([
                    {
                        "title": f.get("title"),
                        "tier": f.get("tier"),
                        "vuln_class": f.get("vuln_class", f.get("cwe_id", "")),
                        "severity": f.get("severity"),
                    }
                    for f in confirmed[:10]
                ])
                prompt = (
                    f"Target: {target_url}\n"
                    f"Confirmed findings: {findings_summary}\n\n"
                    "Analyze these findings for exploit chains. Which 2-3 findings "
                    "can be combined for higher impact? Describe the chain steps. "
                    "Respond in JSON: {\"chains\": [{\"steps\": [\"step1\", \"step2\"], "
                    "\"combined_tier\": 1-5, \"impact\": \"description\"}]}"
                )
                response = await llm.chat(
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    task_type="exploitation",
                    max_tokens=2048,
                )
                parsed = extract_json_from_response(response)
                if isinstance(parsed, dict) and parsed.get("chains"):
                    for chain in parsed["chains"][:3]:
                        self._add_finding({
                            "title": f"Chain: {' -> '.join(chain.get('steps', []))}",
                            "vuln_class": "chain",
                            "severity": _tier_to_severity(chain.get("combined_tier", 3)),
                            "evidence": chain.get("impact", ""),
                            "url": target_url,
                            "cwe_id": "CWE-284",
                            "tier": chain.get("combined_tier", 3),
                            "confidence": 0.6,
                        })
            finally:
                await llm.close()
        except Exception as exc:
            logger.warning("ChainSubAgent LLM reasoning failed: %s", exc)


# ---------------------------------------------------------------------------
# Planning Agent
# ---------------------------------------------------------------------------


class PlanningAgent:
    """Coordinates which sub-agent to dispatch based on target state.

    Uses Tree-of-Thought reasoning to decide the best next sub-agent,
    considering: untested surface area, finding escalation potential,
    technology stack match, historical success, and chain opportunities.
    """

    SUBAGENT_MAP: dict[str, type[_BaseSubAgent]] = {
        "xss": XSSSubAgent,
        "sqli": SQLiSubAgent,
        "auth": AuthSubAgent,
        "ssrf": SSRFSubAgent,
        "chain": ChainSubAgent,
    }

    def __init__(self) -> None:
        self._dispatch_history: list[str] = []
        self._subagent_cache: dict[str, _BaseSubAgent] = {}

    async def plan(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
    ) -> DispatchDecision:
        """Decide which sub-agent to dispatch next."""
        # Build context for LLM decision
        vuln_coverage = self._compute_coverage(observations, confirmed_findings)
        dispatch_summary = self._summarize_dispatches()

        try:
            llm = UnifiedLLMClient()
            try:
                prompt = (
                    f"Target: {target_url}\n"
                    f"Vulnerability coverage: {json.dumps(vuln_coverage)}\n"
                    f"Already dispatched: {dispatch_summary}\n"
                    f"Confirmed findings count: {len(confirmed_findings)}\n"
                    f"Technologies: {json.dumps(observations.get('technologies', [])[:5])}\n"
                    f"Endpoints: {len(observations.get('endpoints', []))}\n"
                    f"Auth pages: {len(observations.get('auth_pages', []))}\n\n"
                    "Based on the coverage gaps and findings, which sub-agent "
                    "should be dispatched next? Consider: (1) untested classes, "
                    "(2) findings that can be escalated, (3) enough findings for chains."
                )
                response = await llm.chat(
                    messages=[
                        {"role": "system", "content": PLANNING_AGENT_SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    task_type="think",
                    max_tokens=2048,
                )
                parsed = extract_json_from_response(response)
                if isinstance(parsed, dict) and parsed.get("subagent") in self.SUBAGENT_MAP:
                    return DispatchDecision(
                        subagent=parsed["subagent"],
                        reason=parsed.get("reason", ""),
                        priority=parsed.get("priority", "medium"),
                        context_hints=parsed.get("context_hints", {}),
                    )
            finally:
                await llm.close()
        except Exception as exc:
            logger.warning("PlanningAgent LLM decision failed: %s", exc)

        # Fallback: dispatch uncovered classes first
        return self._fallback_dispatch(vuln_coverage, confirmed_findings)

    async def dispatch(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
    ) -> SubAgentResult | None:
        """Plan and execute the best sub-agent for the current state."""
        decision = await self.plan(target_url, observations, confirmed_findings)

        if decision.subagent == "none":
            logger.info("PlanningAgent: all sub-agents exhausted, no dispatch")
            return None

        subagent_cls = self.SUBAGENT_MAP.get(decision.subagent)
        if subagent_cls is None:
            logger.warning("PlanningAgent: unknown subagent %s", decision.subagent)
            return None

        logger.info(
            "PlanningAgent dispatching %s (priority=%s, reason=%s)",
            decision.subagent, decision.priority, decision.reason[:100],
        )

        # Reuse or create sub-agent instance
        if decision.subagent not in self._subagent_cache:
            self._subagent_cache[decision.subagent] = subagent_cls()

        subagent = self._subagent_cache[decision.subagent]
        self._dispatch_history.append(decision.subagent)

        try:
            result = await subagent.execute(
                target_url=target_url,
                observations=observations,
                confirmed_findings=confirmed_findings,
                context_hints=decision.context_hints,
            )
            return result
        except Exception as exc:
            logger.error("SubAgent %s execution failed: %s", decision.subagent, exc)
            return SubAgentResult(
                subagent=decision.subagent,
                vuln_class=decision.subagent,
                findings=(),
                verified=(),
                tier=5,
                confidence=0.0,
                actions_taken=0,
                evidence=f"Sub-agent failed: {exc}",
            )

    def _compute_coverage(
        self,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
    ) -> dict[str, str]:
        """Compute which vulnerability classes have been tested."""
        dispatched_set = set(self._dispatch_history)
        tested_classes: set[str] = set()
        for f in confirmed_findings:
            vc = f.get("vuln_class", "").lower()
            cwe = f.get("cwe_id", "").lower()
            if "xss" in vc or "79" in cwe:
                tested_classes.add("xss")
            if "sqli" in vc or "sql" in vc or "89" in cwe:
                tested_classes.add("sqli")
            if "ssrf" in vc or "918" in cwe:
                tested_classes.add("ssrf")
            if "auth" in vc or "bypass" in vc or "287" in cwe or "639" in cwe:
                tested_classes.add("auth")

        coverage: dict[str, str] = {}
        for cls in ("xss", "sqli", "ssrf", "auth"):
            if cls in dispatched_set or cls in tested_classes:
                coverage[cls] = "tested"
            else:
                coverage[cls] = "untested"
        coverage["chain"] = "available" if len(confirmed_findings) >= 2 else "insufficient_findings"
        return coverage

    def _summarize_dispatches(self) -> str:
        """Summarize which sub-agents have been dispatched."""
        if not self._dispatch_history:
            return "none yet"
        counts: dict[str, int] = {}
        for d in self._dispatch_history:
            counts[d] = counts.get(d, 0) + 1
        return ", ".join(f"{k}:{v}" for k, v in counts.items())

    def _fallback_dispatch(
        self,
        coverage: dict[str, str],
        confirmed_findings: list[dict[str, Any]],
    ) -> DispatchDecision:
        """Rule-based fallback when LLM planning fails."""
        for cls in ("sqli", "xss", "auth", "ssrf"):
            if coverage.get(cls) == "untested":
                return DispatchDecision(
                    subagent=cls,
                    reason=f"Vuln class {cls} is untested",
                    priority="high",
                )

        if len(confirmed_findings) >= 2 and coverage.get("chain") == "available":
            return DispatchDecision(
                subagent="chain",
                reason="All classes tested, attempting exploit chaining",
                priority="high",
            )

        counts: dict[str, int] = {}
        for d in self._dispatch_history:
            counts[d] = counts.get(d, 0) + 1
        for cls in ("sqli", "xss", "auth", "ssrf"):
            if counts.get(cls, 0) < 2:
                return DispatchDecision(
                    subagent=cls,
                    reason=f"Re-dispatching {cls} (dispatched {counts.get(cls, 0)} times)",
                    priority="medium",
                )

        return DispatchDecision(subagent="none", reason="All classes exhausted")

    def reset(self) -> None:
        """Reset dispatch history for a new engagement."""
        self._dispatch_history.clear()
        self._subagent_cache.clear()


# ---------------------------------------------------------------------------
# Top-level coordinator
# ---------------------------------------------------------------------------


class HPTSACoordinator:
    """Entry point for the HPTSA multi-agent architecture.

    Replaces the flat MCTS heuristic with hierarchical planning.
    The PlanningAgent dispatches specialized sub-agents, each focused
    on a single vulnerability class with tailored prompts and tools.

    Usage::

        coordinator = HPTSACoordinator()
        results = await coordinator.run(target_url, observations, findings)

    Returns a list of all SubAgentResults from dispatched sub-agents.
    """

    def __init__(self, max_dispatches: int = 5) -> None:
        self.max_dispatches = max_dispatches
        self.planner = PlanningAgent()

    async def run(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
    ) -> list[SubAgentResult]:
        """Run the HPTSA loop: plan -> dispatch -> collect results.

        Dispatches up to ``max_dispatches`` sub-agents, each chosen
        by the PlanningAgent based on current coverage and findings.
        """
        results: list[SubAgentResult] = []
        all_findings: list[dict[str, Any]] = list(confirmed_findings)

        for _ in range(self.max_dispatches):
            result = await self.planner.dispatch(
                target_url=target_url,
                observations=observations,
                confirmed_findings=all_findings,
            )
            if result is None:
                break

            results.append(result)

            # Merge new findings into the pool for next planning cycle
            for f in result.findings:
                all_findings.append(f)
            for f in result.verified:
                all_findings.append(f)

            # Stop if we hit T1 — maximum impact achieved
            if result.tier == 1:
                logger.info(
                    "HPTSA: T1 achieved by %s, stopping dispatch loop",
                    result.subagent,
                )
                break

        return results

    def reset(self) -> None:
        """Reset for a new engagement."""
        self.planner.reset()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_to_xss_tier(severity: str, evidence: str) -> int:
    """Map XSS severity + evidence to capability tier."""
    ev = evidence.lower()
    if any(kw in ev for kw in ("cookie", "token", "session hijack", "account takeover")):
        return 1
    if any(kw in ev for kw in ("dom clobber", "prototype pollution", "stored")):
        return 2
    if severity in ("critical", "high"):
        return 3
    if severity == "medium":
        return 4
    return 5


def _severity_to_sqli_tier(severity: str, evidence: str) -> int:
    """Map SQLi severity + evidence to capability tier."""
    ev = evidence.lower()
    if any(kw in ev for kw in ("stacked query", "into outfile", "rce", "xp_cmdshell")):
        return 1
    if any(kw in ev for kw in ("union", "data extraction", "database dump", "credential")):
        return 2
    if severity in ("critical", "high"):
        return 3
    return 4


def _severity_to_ssrf_tier(severity: str, evidence: str) -> int:
    """Map SSRF severity + evidence to capability tier."""
    ev = evidence.lower()
    if any(kw in ev for kw in ("redis", "gopher", "rce")):
        return 1
    if any(kw in ev for kw in ("metadata", "credential", "iam", "169.254")):
        return 2
    if severity in ("critical", "high"):
        return 3
    return 4


def _tier_to_severity(tier: int) -> str:
    """Map a capability tier back to a severity label."""
    mapping = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
    return mapping.get(tier, "info")