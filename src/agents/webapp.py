"""OWASP DAST agent with AI-driven browser for deep interactive security testing."""

import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.browser.ai_operator import AIBrowserOperator
from src.agents.browser.memory import FindingMemory
from src.agents.browser.missing_code import MissingCodeDetector
from src.agents.browser.operator import BrowserOperator
from src.agents.browser.session import BrowserSession, BrowserSessionConfig
from src.core.audit import log_action
from src.core.config import get_settings

logger = logging.getLogger(__name__)

MARKER = "aJ7xK9mP2qR"


class WebappAgent(BaseAgent):
    """Runs HTTP-level checks + AI-driven browser vulnerability investigations."""

    name = "webapp"

    def __init__(self, browser_session: BrowserSession | None = None) -> None:
        # Plan §3.1.3.bis: WebappAgent MUST use BrowserSession, not construct
        # AIBrowserOperator or BrowserOperator directly. The session is
        # optional to keep the call site in agent.run() flexible, but if
        # not provided, a session is constructed with default config
        # (primary_operator="agent").
        self.browser_session = browser_session or BrowserSession(
            engagement_id="default",  # overridden by execute()'s engagement_id
            config=BrowserSessionConfig(primary_operator="agent"),
        )

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        previous = payload.get("previous_result", {})
        target_url = previous.get("target_url", "")
        surface = previous.get("surface", {})
        suspicious_points = previous.get("suspicious_points", [])
        headers = surface.get("headers", {})
        forms = surface.get("forms", [])
        endpoints = surface.get("endpoints", [])
        auth_pages = surface.get("auth_pages", [])
        inputs = surface.get("inputs", [])
        buttons = surface.get("buttons", [])
        scripts = surface.get("scripts", [])
        meta_tags = surface.get("meta_tags", {})
        console_errors = surface.get("console_errors", [])
        text_content = surface.get("text_content", "")

        if not target_url:
            return {"findings": [], "artifacts": [], "tests_run": []}

        findings: list[dict] = []
        artifacts: list[dict] = []
        tests_run: list[dict] = []

        # Seed pre-authenticated cookies if provided (benchmark DVWA support)
        auth_cookies = payload.get("auth_cookies")
        client_cookies = auth_cookies if auth_cookies else None

        # Phase 1: HTTP-level fast checks (no browser needed)
        hf = self._analyze_security_headers(headers, target_url)
        findings.extend(hf)
        tests_run.append({"test": "header_security", "findings": len(hf)})

        cf = self._analyze_cookies(surface.get("cookies", []), target_url)
        findings.extend(cf)
        tests_run.append({"test": "cookie_security", "findings": len(cf)})

        cspf = self._analyze_csp(headers, target_url)
        findings.extend(cspf)
        tests_run.append({"test": "csp_analysis", "findings": len(cspf)})

        idf = self._check_info_disclosure(headers, target_url)
        findings.extend(idf)
        tests_run.append({"test": "info_disclosure", "findings": len(idf)})

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, http2=True, cookies=client_cookies) as client:
            injf = await self._test_injection_reflection(client, target_url, forms, endpoints)
            findings.extend(injf)
            tests_run.append({"test": "injection_reflection", "findings": len(injf)})

        tf = self._check_transport_security(headers, target_url)
        findings.extend(tf)
        tests_run.append({"test": "transport_security", "findings": len(tf)})

        jsf = self._analyze_javascript(scripts, console_errors, meta_tags, target_url)
        findings.extend(jsf)
        tests_run.append({"test": "javascript_analysis", "findings": len(jsf)})

        # Mythos-level: SSRF surface analysis
        ssrf = self._check_ssrf_surface(endpoints, target_url)
        findings.extend(ssrf)
        tests_run.append({"test": "ssrf_surface", "findings": len(ssrf)})

        # Mythos-level: JWT/token surface analysis
        jwtf = self._check_jwt_surface(headers, scripts, target_url)
        findings.extend(jwtf)
        tests_run.append({"test": "jwt_surface", "findings": len(jwtf)})

        # Mythos-level: Race condition indicator analysis
        rcf = self._check_race_condition_indicators(headers, forms, endpoints, target_url)
        findings.extend(rcf)
        tests_run.append({"test": "race_condition_indicators", "findings": len(rcf)})

        # Mythos-level: Second-order injection surface
        soif = self._check_second_order_injection(forms, endpoints, target_url)
        findings.extend(soif)
        tests_run.append({"test": "second_order_injection", "findings": len(soif)})

        # Missing Code Detection — R3 innovation: detect absent security controls
        try:
            missing_detector = MissingCodeDetector()
            missing_findings = await missing_detector.detect(surface)
            findings.extend(missing_findings)
            tests_run.append({"test": "missing_code", "findings": len(missing_findings)})
        except Exception as exc:
            logger.warning("Missing code detection failed: %s", exc)

        # LLM-enhanced missing code detection for deeper analysis
        if findings:
            try:
                missing_detector = MissingCodeDetector()
                llm_missing = await missing_detector.llm_detect(surface, findings)
                findings.extend(llm_missing)
                tests_run.append({"test": "missing_code_llm", "findings": len(llm_missing)})
            except Exception as exc:
                logger.debug("LLM missing code detection failed: %s", exc)

        # Phase 2: AI-driven browser vulnerability investigation
        settings = get_settings()
        engagement_id = payload.get("engagement_id", "default")
        memory = FindingMemory(engagement_id=engagement_id, artifacts_dir=settings.artifacts_dir)

        # Build context string for AI agents
        context_parts = [
            f"Target: {target_url}",
            f"Technologies: {', '.join(surface.get('technologies', []))}",
            f"Forms: {len(forms)}",
            f"Auth pages: {len(auth_pages)}",
            f"Endpoints: {', '.join(endpoints[:10])}",
        ]
        if auth_pages:
            context_parts.append(f"Auth details: {str(auth_pages)[:500]}")
        if findings:
            finding_summaries = [f"[{f.get('severity', '?')}] {f.get('title', '')}" for f in findings[:10]]
            context_parts.append(f"HTTP findings: {'; '.join(finding_summaries)}")
        if suspicious_points:
            sp_summaries = [f"{sp.get('sp_type', '?')}@{sp.get('location', '?')} (conf={sp.get('confidence', 0):.2f})" for sp in suspicious_points[:10]]
            context_parts.append(f"Suspicious points: {'; '.join(sp_summaries)}")
        context = "\n".join(context_parts)

        ai_browser = self.browser_session.ai_operator
        try:
            await ai_browser.start()

            # Determine which investigations to run based on surface data + suspicious points
            investigation_types = []
            sp_types = {sp.get("sp_type", "") for sp in suspicious_points}
            if forms or inputs or sp_types & {"xss_sink", "missing_csp", "form_with_inputs", "js_dangerous_pattern"}:
                investigation_types.append("xss_hunt")
            if auth_pages or sp_types & {"auth_form", "missing_auth", "missing_csrf", "missing_rate_limit"}:
                investigation_types.append("auth_test")
            if endpoints or scripts or sp_types & {"api_endpoint", "missing_validation"}:
                investigation_types.append("api_discover")
            if sp_types & {"missing_cors_policy", "missing_csp"} or not investigation_types:
                investigation_types.append("error_probe")

            # Mythos-level: SSRF investigation for URL-accepting endpoints
            if endpoints or sp_types & {"api_endpoint"}:
                investigation_types.append("ssrf_hunt")

            # Mythos-level: Business logic for forms with workflows
            if forms or auth_pages or sp_types & {"auth_form", "missing_csrf", "missing_rate_limit"}:
                investigation_types.append("business_logic")

            # Mythos-level: Advanced auth for login/auth flows
            if auth_pages or sp_types & {"auth_form", "missing_auth"}:
                investigation_types.append("advanced_auth")

            # Mythos-level: Race condition for transaction endpoints
            if any(kw in target_url.lower() for kw in ("cart", "checkout", "pay", "order", "transfer", "withdraw", "deposit", "book")):
                investigation_types.append("race_condition")

            # Mythos enhancement: GraphQL scan for API endpoints
            if endpoints or sp_types & {"api_endpoint"}:
                investigation_types.append("graphql_scan")

            # Mythos enhancement: WebSocket scan for real-time features
            if any(kw in target_url.lower() for kw in ("chat", "live", "realtime", "stream", "ws", "socket")):
                investigation_types.append("websocket_scan")

            # Mythos enhancement: Timing analysis for injection-prone endpoints
            if sp_types & {"xss_sink", "missing_validation", "api_endpoint"}:
                investigation_types.append("timing_analyze")

            # Mythos enhancement: Credential testing for login pages
            if auth_pages or sp_types & {"auth_form", "default_credentials"}:
                investigation_types.append("credential_test")

            investigation_types = list(dict.fromkeys(investigation_types))[:6]

            # Ensure at least one investigation runs
            if not investigation_types:
                investigation_types = ["xss_hunt", "error_probe"]

            ai_results = await ai_browser.run_parallel_investigations(
                target_url=target_url,
                investigation_types=investigation_types,
                context=context,
            )

            for result in ai_results:
                inv_type = result.get("task_type", "unknown")
                ai_findings = result.get("findings", [])

                for finding in ai_findings:
                    content = finding.get("content", "")
                    action = finding.get("action", "")
                    if content or action:
                        findings.append({
                            "title": f"AI {inv_type}: {content[:100] or action}",
                            "description": content[:500],
                            "severity": "medium",
                            "source_agent": "webapp_ai",
                            "confidence_score": 0.6,
                            "evidence": {"ai_finding": content[:300], "action": action[:100]},
                        })

                # Add security tool results
                for tool_result in result.get("security_tool_results", []):
                    tool_content = tool_result.get("content", str(tool_result))[:500]
                    if tool_content:
                        findings.append({
                            "title": f"AI tool result: {tool_content[:100]}",
                            "description": tool_content,
                            "severity": "info",
                            "source_agent": "webapp_ai",
                            "confidence_score": 0.7,
                            "evidence": tool_result,
                        })

                # Record in memory for anti-hallucination
                memory.add_finding(
                    title=f"AI investigation: {inv_type}",
                    severity="info",
                    description=f"Completed {inv_type} investigation on {target_url}",
                    evidence_ref=f"ai_{inv_type}_{result.get('steps_taken', 0)}",
                    vuln_type=inv_type,
                    url=target_url,
                )

                tests_run.append({
                    "test": f"ai_{inv_type}",
                    "findings": len(ai_findings),
                    "urls_visited": len(result.get("visited_urls", [])),
                })

        except Exception as exc:
            logger.error("AI browser investigation failed: %s", exc)
            artifacts.append({"type": "ai_error", "content": str(exc)})

            # Fallback: scripted browser tests
            browser = self.browser_session.legacy_operator
            await browser.start()
            try:
                domf = await self._test_dom_xss(browser, target_url, inputs, text_content)
                findings.extend(domf)
                tests_run.append({"test": "dom_xss", "findings": len(domf)})

                if forms:
                    formf = await self._test_form_interaction(browser, target_url, forms)
                    findings.extend(formf)
                    tests_run.append({"test": "form_interaction", "findings": len(formf)})

                if auth_pages:
                    authf = await self._test_auth_flows(browser, target_url, auth_pages)
                    findings.extend(authf)
                    tests_run.append({"test": "auth_flow", "findings": len(authf)})

                errf = await self._test_error_pages(browser, target_url)
                findings.extend(errf)
                tests_run.append({"test": "error_pages", "findings": len(errf)})
            finally:
                await browser.stop()
        finally:
            try:
                await ai_browser.stop()
            except Exception:
                pass

        artifacts.append({
            "type": "har",
            "content": {"tests_run": tests_run, "total_findings": len(findings)},
        })

        await log_action(
            session=session, action="webapp_scan_completed", actor="webapp",
            payload={"target_url": target_url, "findings_count": len(findings)},
        )

        # W1-B: persist findings to the DB at the source so they
        # survive even if the reporter is skipped, the engagement is
        # terminated early, or a downstream agent swallows the result.
        # The reporter's own _persist_findings is idempotent (dedup_key
        # indexed), so this is a no-op on re-runs.
        engagement_id = payload.get("engagement_id", "")
        if engagement_id and findings:
            from src.agents._finding_persistence import persist_findings
            await persist_findings(
                session=session,
                engagement_id=engagement_id,
                findings=findings,
                source_agent="webapp",
                target_url=target_url,
            )

        return {
            "findings": findings,
            "artifacts": artifacts,
            "tests_run": tests_run,
            "target_url": target_url,
            "surface": surface,
        }

    # --- HTTP-level tests (fast, no browser needed) ---

    def _analyze_security_headers(self, headers: dict, target: str) -> list[dict]:
        findings: list[dict] = []
        checks = {
            "x-frame-options": ("medium", "A05:2021", "Missing X-Frame-Options — clickjacking possible", "CWE-693"),
            "x-content-type-options": ("low", "A05:2021", "Missing X-Content-Type-Options — MIME sniffing", None),
            "referrer-policy": ("low", "A05:2021", "Missing Referrer-Policy — URL leaks in Referer", None),
            "permissions-policy": ("info", "A05:2021", "Missing Permissions-Policy — browser features unrestricted", None),
        }
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for hdr, (sev, owasp, desc, cwe) in checks.items():
            if hdr not in lower_headers:
                findings.append({
                    "title": f"Missing {hdr} header",
                    "description": desc,
                    "severity": sev, "owasp_category": owasp, "cwe_id": cwe,
                    "confidence_score": 0.9,
                    "evidence": {"missing_header": hdr},
                    "source_agent": "webapp",
                })

        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            findings.append({
                "title": "Missing HSTS header",
                "description": "No Strict-Transport-Security — browsers may access via HTTP",
                "severity": "medium", "owasp_category": "A02:2021", "cwe_id": "CWE-319",
                "confidence_score": 0.95, "evidence": {"missing_header": "strict-transport-security"},
                "source_agent": "webapp",
            })
        elif "includeSubDomains" not in hsts:
            findings.append({
                "title": "HSTS missing includeSubDomains",
                "description": "HSTS does not protect subdomains",
                "severity": "low", "owasp_category": "A02:2021",
                "confidence_score": 0.8, "evidence": {"hsts_value": hsts},
                "source_agent": "webapp",
            })
        return findings

    def _analyze_cookies(self, cookies: list[dict], target: str) -> list[dict]:
        findings: list[dict] = []
        for c in cookies:
            name = c.get("name", "")
            if not c.get("secure", False):
                findings.append({
                    "title": f"Cookie '{name}' missing Secure flag",
                    "description": f"Cookie '{name}' sent over unencrypted connections",
                    "severity": "low", "owasp_category": "A02:2021",
                    "confidence_score": 0.9, "evidence": {"cookie_name": name, "secure": False},
                    "source_agent": "webapp",
                })
            if not c.get("httponly", False):
                findings.append({
                    "title": f"Cookie '{name}' missing HttpOnly flag",
                    "description": f"Cookie '{name}' accessible via JavaScript — XSS exfiltration risk",
                    "severity": "medium", "owasp_category": "A07:2021",
                    "confidence_score": 0.9, "evidence": {"cookie_name": name, "httponly": False},
                    "source_agent": "webapp",
                })
        return findings

    def _analyze_csp(self, headers: dict, target: str) -> list[dict]:
        findings: list[dict] = []
        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append({
                "title": "Missing Content-Security-Policy header",
                "description": "No CSP — no protection against XSS and content injection",
                "severity": "high", "owasp_category": "A05:2021", "cwe_id": "CWE-693",
                "confidence_score": 0.95, "evidence": {"missing_header": "content-security-policy"},
                "source_agent": "webapp",
            })
            return findings

        unsafe = {
            "'unsafe-eval'": ("high", "CSP allows unsafe-eval — code execution risk"),
            "'unsafe-inline'": ("medium", "CSP allows unsafe-inline — XSS bypass possible"),
        }
        for pattern, (sev, desc) in unsafe.items():
            if pattern in csp:
                directive = "unknown"
                for part in csp.split(";"):
                    part = part.strip()
                    if pattern in part:
                        directive = part.split()[0] if part.split() else "unknown"
                        break
                findings.append({
                    "title": f"CSP contains {pattern} in {directive}",
                    "description": desc,
                    "severity": sev, "owasp_category": "A05:2021", "cwe_id": "CWE-693",
                    "confidence_score": 0.85,
                    "evidence": {"csp_directive": pattern, "directive_name": directive, "csp_value": csp[:500]},
                    "source_agent": "webapp",
                })

        if "default-src *" in csp or "script-src *" in csp:
            findings.append({
                "title": "CSP uses wildcard (*)",
                "description": "CSP wildcard effectively disables script restrictions",
                "severity": "medium", "owasp_category": "A05:2021",
                "confidence_score": 0.85, "evidence": {"csp_value": csp[:500]},
                "source_agent": "webapp",
            })
        return findings

    def _check_info_disclosure(self, headers: dict, target: str) -> list[dict]:
        findings: list[dict] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for hdr in ("x-powered-by", "x-aspnet-version", "x-runtime"):
            val = lower_headers.get(hdr, "")
            if val:
                findings.append({
                    "title": f"Information disclosure via {hdr}",
                    "description": f"{hdr} reveals: {val}",
                    "severity": "low", "owasp_category": "A01:2021",
                    "confidence_score": 0.95, "evidence": {"header": hdr, "value": val},
                    "source_agent": "webapp",
                })
        return findings

    async def _test_injection_reflection(
        self, client: httpx.AsyncClient, target_url: str, forms: list[dict], endpoints: list[str]
    ) -> list[dict]:
        findings: list[dict] = []
        test_urls = [target_url]
        for ep in endpoints[:5]:
            if not ep.startswith("browser:"):
                test_urls.append(f"{target_url.rstrip('/')}{ep}")

        for url in test_urls[:10]:
            try:
                resp = await client.get(url, params={"q": f'">{MARKER}'})
                if MARKER in resp.text:
                    idx = resp.text.index(MARKER)
                    ctx = resp.text[max(0, idx - 50):idx + len(MARKER) + 50]
                    if "<" in ctx or ">" in ctx:
                        findings.append({
                            "title": "Potential XSS reflection",
                            "description": f"Input reflected in HTML at {url} — parameter 'q' not encoded",
                            "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-79",
                            "confidence_score": 0.6,
                            "evidence": {"url": url, "parameter": "q", "context": ctx[:200]},
                            "source_agent": "webapp",
                        })
            except httpx.RequestError:
                continue

        for form in forms[:5]:
            action = form.get("action", target_url)
            method = form.get("method", "GET").upper()
            try:
                data = {"input": MARKER, "q": MARKER, "search": MARKER}
                if method == "POST":
                    resp = await client.post(action, data=data)
                else:
                    resp = await client.get(action, params=data)
                if MARKER in resp.text:
                    findings.append({
                        "title": "Potential injection in form",
                        "description": f"Form at {action} reflects input without encoding",
                        "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-79",
                        "confidence_score": 0.5,
                        "evidence": {"form_action": action, "method": method},
                        "source_agent": "webapp",
                    })
            except httpx.RequestError:
                continue
        return findings

    def _check_transport_security(self, headers: dict, target: str) -> list[dict]:
        findings: list[dict] = []
        if target.startswith("http://"):
            findings.append({
                "title": "Target accessible over HTTP",
                "description": "Site serves content over unencrypted HTTP",
                "severity": "medium", "owasp_category": "A02:2021", "cwe_id": "CWE-319",
                "confidence_score": 0.9, "evidence": {"scheme": "http"},
                "source_agent": "webapp",
            })
        return findings

    def _analyze_javascript(
        self, scripts: list[str], console_errors: list[str],
        meta_tags: dict, target_url: str
    ) -> list[dict]:
        findings: list[dict] = []

        for src in scripts:
            parsed = urlparse(src)
            if parsed.netloc and parsed.netloc != urlparse(target_url).netloc:
                risky_domains = ["cdnjs.cloudflare.com", "ajax.googleapis.com", "cdn.jsdelivr.net"]
                if any(d in parsed.netloc for d in risky_domains):
                    findings.append({
                        "title": "External JavaScript loaded without SRI",
                        "description": f"Script from {parsed.netloc} may lack Subresource Integrity — supply chain attack risk",
                        "severity": "low", "owasp_category": "A08:2021", "cwe_id": "CWE-353",
                        "confidence_score": 0.5,
                        "evidence": {"script_src": src},
                        "source_agent": "webapp",
                    })

        error_signatures = {
            "stack trace": ("Stack trace in console — information disclosure", "medium"),
            "internal server error": ("Internal error details exposed in console", "medium"),
            "unauthorized": ("Authentication error details in console", "low"),
            "forbidden": ("Authorization error details in console", "low"),
            "debug": ("Debug information in console output", "low"),
            "deprecated": ("Deprecated API usage detected", "info"),
        }
        for error in console_errors[:20]:
            error_lower = error.lower()
            for sig, (desc, sev) in error_signatures.items():
                if sig in error_lower:
                    findings.append({
                        "title": f"Console error: {desc}",
                        "description": f"Browser console revealed: {error[:200]}",
                        "severity": sev, "owasp_category": "A01:2021",
                        "confidence_score": 0.7,
                        "evidence": {"console_error": error[:500]},
                        "source_agent": "webapp",
                    })
                    break

        if "csrf-token" in str(meta_tags.values()).lower():
            findings.append({
                "title": "CSRF token in meta tag (potentially exposed to JS)",
                "description": "CSRF token present in HTML meta tags — accessible to any JavaScript on the page",
                "severity": "info", "owasp_category": "A01:2021",
                "confidence_score": 0.4,
                "evidence": {"meta_tags": str(meta_tags)[:500]},
                "source_agent": "webapp",
            })

        return findings

    def _check_ssrf_surface(self, endpoints: list[str], target_url: str) -> list[dict]:
        """Mythos: Identify SSRF-vulnerable surface areas from endpoints and URL patterns."""
        findings: list[dict] = []
        ssrf_indicators = {
            "url": ("URL parameter may accept external URLs — SSRF risk", "CWE-918"),
            "image": ("Image URL parameter — potential SSRF via image fetching", "CWE-918"),
            "fetch": ("Fetch/import URL parameter — SSRF risk", "CWE-918"),
            "import": ("Import URL parameter — SSRF risk", "CWE-918"),
            "proxy": ("Proxy/forward endpoint — potential SSRF proxy", "CWE-918"),
            "redirect": ("Redirect parameter — open redirect or SSRF", "CWE-601"),
            "callback": ("Callback URL parameter — SSRF via webhook", "CWE-918"),
            "webhook": ("Webhook URL parameter — SSRF via webhook", "CWE-918"),
            "pdf": ("PDF generation endpoint — SSRF via HTML-to-PDF", "CWE-918"),
            "preview": ("Preview/thumbnail endpoint — SSRF via URL fetching", "CWE-918"),
        }
        for ep in endpoints:
            ep_lower = ep.lower()
            for indicator, (desc, cwe) in ssrf_indicators.items():
                if indicator in ep_lower:
                    findings.append({
                        "title": f"Potential SSRF via {indicator} endpoint: {ep[:80]}",
                        "description": desc,
                        "severity": "high", "owasp_category": "A10:2021", "cwe_id": cwe,
                        "confidence_score": 0.6,
                        "evidence": {"endpoint": ep, "indicator": indicator},
                        "source_agent": "webapp",
                    })
                    break
        return findings

    def _check_jwt_surface(self, headers: dict, scripts: list[str], target_url: str) -> list[dict]:
        """Mythos: Detect JWT tokens and common misconfigurations."""
        findings: list[dict] = []
        import base64

        # Check Authorization header pattern
        auth_header = headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                parts = token.split(".")
                if len(parts) == 3:
                    # Decode header
                    pad = 4 - len(parts[0]) % 4
                    header_b64 = parts[0] + "=" * pad
                    header_json = base64.urlsafe_b64decode(header_b64).decode("utf-8", errors="ignore")
                    if '"alg"' in header_json:
                        alg = ""
                        if "none" in header_json.lower() or "None" in header_json:
                            findings.append({
                                "title": "JWT uses 'none' algorithm — authentication bypass",
                                "description": "JWT token uses 'none' algorithm which bypasses signature verification",
                                "severity": "critical", "owasp_category": "A02:2021", "cwe_id": "CWE-327",
                                "confidence_score": 0.95,
                                "evidence": {"jwt_header": header_json[:200]},
                                "source_agent": "webapp",
                            })
                        elif "HS256" in header_json or "HS384" in header_json or "HS512" in header_json:
                            findings.append({
                                "title": "JWT uses symmetric algorithm (HMAC) — potential algorithm confusion",
                                "description": "JWT uses HS256/384/512 — if RS256 is expected, algorithm confusion attack may be possible",
                                "severity": "medium", "owasp_category": "A02:2021", "cwe_id": "CWE-327",
                                "confidence_score": 0.5,
                                "evidence": {"jwt_header": header_json[:200]},
                                "source_agent": "webapp",
                            })
            except Exception:
                pass

        # Check for JWT in JavaScript
        combined_scripts = " ".join(scripts)[:5000]
        jwt_indicators = [
            ("localStorage.setItem('jwt'", "JWT stored in localStorage — XSS exfiltration risk"),
            ("localStorage.setItem('token'", "Auth token stored in localStorage — XSS exfiltration risk"),
            ("sessionStorage.setItem('jwt'", "JWT stored in sessionStorage — XSS exfiltration risk"),
            ("jwt_decode", "JWT decode on client side — token content visible to XSS"),
        ]
        for indicator, desc in jwt_indicators:
            if indicator in combined_scripts:
                findings.append({
                    "title": desc.split("—")[0].strip(),
                    "description": desc,
                    "severity": "medium", "owasp_category": "A07:2021",
                    "confidence_score": 0.7,
                    "evidence": {"indicator": indicator},
                    "source_agent": "webapp",
                })
                break

        return findings

    def _check_race_condition_indicators(self, headers: dict, forms: list[dict], endpoints: list[str], target_url: str) -> list[dict]:
        """Mythos: Identify endpoints likely vulnerable to race conditions."""
        findings: list[dict] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Check for missing rate limiting on sensitive endpoints
        rate_headers = [k for k in headers if "rate" in k.lower() or "retry-after" in k.lower() or "x-ratelimit" in k.lower()]
        if not rate_headers:
            auth_pages = [ep for ep in endpoints if any(kw in ep.lower() for kw in ("login", "auth", "signin", "password"))]
            if auth_pages:
                findings.append({
                    "title": "No rate limiting on authentication endpoints",
                    "description": "No rate limiting headers detected on endpoints with auth flows — brute-force and race condition risk",
                    "severity": "high", "owasp_category": "A07:2021", "cwe_id": "CWE-307",
                    "confidence_score": 0.7,
                    "evidence": {"auth_endpoints": auth_pages[:5], "missing_headers": list(rate_headers)},
                    "source_agent": "webapp",
                })

        # Check for financial/transactional endpoints without idempotency
        financial_keywords = ("pay", "checkout", "order", "transfer", "withdraw", "deposit", "purchase", "cart", "refund")
        for ep in endpoints:
            if any(kw in ep.lower() for kw in financial_keywords):
                idempotency_headers = [k for k in headers if "idempotency" in k.lower()]
                if not idempotency_headers:
                    findings.append({
                        "title": f"Financial endpoint without idempotency key: {ep[:60]}",
                        "description": f"Endpoint {ep[:60]} appears to be financial but lacks idempotency headers — race condition risk",
                        "severity": "medium", "owasp_category": "A04:2021", "cwe_id": "CWE-367",
                        "confidence_score": 0.55,
                        "evidence": {"endpoint": ep},
                        "source_agent": "webapp",
                    })
                    break

        return findings

    def _check_second_order_injection(self, forms: list[dict], endpoints: list[str], target_url: str) -> list[dict]:
        """Mythos: Identify surface areas where stored input may be consumed unsafely (second-order injection)."""
        findings: list[dict] = []
        storage_indicators = ("profile", "setting", "comment", "message", "post", "review", "name", "bio", "description", "address")

        for form in forms[:5]:
            inputs = form.get("inputs", form.get("fields", []))
            action = form.get("action", "unknown")
            if not isinstance(inputs, list):
                continue
            input_names = [inp.get("name", "").lower() for inp in inputs if isinstance(inp, dict)]
            has_storage_input = any(any(ind in name for ind in storage_indicators) for name in input_names)
            if has_storage_input:
                findings.append({
                    "title": f"Form with storage inputs at {action[:60]} — potential second-order injection",
                    "description": "Form accepts data that may be stored and later consumed unsafely (profile, comment, message fields)",
                    "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-89",
                    "confidence_score": 0.45,
                    "evidence": {"form_action": action, "input_names": input_names[:5]},
                    "source_agent": "webapp",
                })

        # Check for API endpoints that likely consume stored data
        consumption_indicators = ("export", "report", "search", "query", "list", "feed", "api/users", "api/data")
        for ep in endpoints[:10]:
            if any(ind in ep.lower() for ind in consumption_indicators):
                findings.append({
                    "title": f"Data consumption endpoint: {ep[:60]} — potential second-order injection target",
                    "description": "Endpoint likely consumes stored data — if stored input is not sanitized at consumption time, second-order injection is possible",
                    "severity": "low", "owasp_category": "A03:2021", "cwe_id": "CWE-89",
                    "confidence_score": 0.35,
                    "evidence": {"endpoint": ep},
                    "source_agent": "webapp",
                })
                break

        return findings

    # --- Fallback scripted browser tests (used when AI agent fails) ---

    async def _test_dom_xss(
        self, browser: BrowserOperator, target_url: str,
        inputs: list[dict], text_content: str
    ) -> list[dict]:
        findings: list[dict] = []
        dom_payloads = [f"?q={MARKER}", f"?search={MARKER}", f"?id={MARKER}"]
        for payload in dom_payloads:
            url = f"{target_url.rstrip('/')}{payload}"
            page_data = await browser.browse_page(url)
            if "error" in page_data:
                continue
            html = page_data.get("html", "")
            if MARKER in html:
                idx = html.index(MARKER)
                ctx = html[max(0, idx - 80):idx + len(MARKER) + 80]
                before = html[max(0, idx - 5):idx]
                after = html[idx + len(MARKER):idx + len(MARKER) + 5]
                if "<" in before or "<" in after or ">" in ctx:
                    findings.append({
                        "title": "Potential DOM-based XSS reflection",
                        "description": f"URL parameter reflected in DOM at {url}",
                        "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-79",
                        "confidence_score": 0.6,
                        "evidence": {"url": url, "context": ctx[:300], "reflection_type": "dom"},
                        "source_agent": "webapp",
                    })
        return findings

    async def _test_form_interaction(
        self, browser: BrowserOperator, target_url: str, forms: list[dict]
    ) -> list[dict]:
        findings: list[dict] = []
        for i, form in enumerate(forms[:3]):
            form_inputs = form.get("inputs", form.get("fields", []))
            mapped_data: dict[str, str] = {}
            if isinstance(form_inputs, list):
                for inp in form_inputs:
                    name = inp.get("name", "")
                    inp_type = inp.get("type", "text")
                    if not name:
                        continue
                    if inp_type in ("password",):
                        mapped_data[name] = "TestP@ss123"
                    elif inp_type in ("email",):
                        mapped_data[name] = f"test@{MARKER}.com"
                    elif inp_type in ("search", "text", ""):
                        mapped_data[name] = f'<img src=x onerror="{MARKER}">'
                    else:
                        mapped_data[name] = MARKER
            if not mapped_data:
                continue
            result = await browser.fill_and_submit_form(target_url, form_index=i, data=mapped_data)
            if result.get("submitted"):
                resp_html = result.get("response_html", "")
                resp_text = result.get("response_text", "")
                if MARKER in resp_html or MARKER in resp_text:
                    findings.append({
                        "title": "Input reflected in form response",
                        "description": f"Form at {target_url} (index {i}) reflects XSS probe",
                        "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-79",
                        "confidence_score": 0.5,
                        "evidence": {"form_index": i, "reflected": True},
                        "source_agent": "webapp",
                    })
                sql_errors = ["sql syntax", "mysql_fetch", "pg_query", "sqlstate", "ora-", "microsoft odbc", "sqlite_", "psql:"]
                for err_sig in sql_errors:
                    if err_sig in resp_text.lower():
                        findings.append({
                            "title": "Potential SQL error disclosure in form response",
                            "description": f"Form submission triggered SQL error: {err_sig}",
                            "severity": "medium", "owasp_category": "A03:2021", "cwe_id": "CWE-89",
                            "confidence_score": 0.6,
                            "evidence": {"error_signature": err_sig, "form_index": i},
                            "source_agent": "webapp",
                        })
                        break
        return findings

    async def _test_auth_flows(
        self, browser: BrowserOperator, target_url: str, auth_pages: list[dict]
    ) -> list[dict]:
        findings: list[dict] = []
        for auth_page in auth_pages[:2]:
            page_url = auth_page.get("url", target_url)
            auth_type = auth_page.get("auth_type", "")
            login_form = auth_page.get("login_form", {})
            if auth_type == "form_login" and login_form:
                has_csrf = False
                form_inputs = login_form.get("fields", login_form.get("inputs", []))
                if isinstance(form_inputs, list):
                    for inp in form_inputs:
                        name = inp.get("name", "").lower()
                        if "csrf" in name or "token" in name or "nonce" in name:
                            has_csrf = True
                            break
                if not has_csrf:
                    findings.append({
                        "title": "Login form missing CSRF token",
                        "description": f"Authentication form at {page_url} lacks CSRF protection",
                        "severity": "medium", "owasp_category": "A01:2021", "cwe_id": "CWE-352",
                        "confidence_score": 0.8,
                        "evidence": {"page_url": page_url},
                        "source_agent": "webapp",
                    })
                has_autocomplete_off = False
                if isinstance(form_inputs, list):
                    for inp in form_inputs:
                        if inp.get("type") == "password" and inp.get("autocomplete", "") == "off":
                            has_autocomplete_off = True
                            break
                if not has_autocomplete_off:
                    findings.append({
                        "title": "Password field allows browser autocomplete",
                        "description": f"Password field at {page_url} does not set autocomplete='off'",
                        "severity": "info", "owasp_category": "A07:2021",
                        "confidence_score": 0.7,
                        "evidence": {"page_url": page_url},
                        "source_agent": "webapp",
                    })
                if not login_form.get("hasCaptcha", False):
                    findings.append({
                        "title": "Login form lacks brute-force protection (no CAPTCHA)",
                        "description": f"No CAPTCHA detected on login form at {page_url}",
                        "severity": "low", "owasp_category": "A07:2021", "cwe_id": "CWE-307",
                        "confidence_score": 0.6,
                        "evidence": {"page_url": page_url},
                        "source_agent": "webapp",
                    })
            elif auth_type == "oauth_sso":
                findings.append({
                    "title": "OAuth/SSO authentication detected",
                    "description": f"Site uses OAuth/SSO authentication at {page_url}",
                    "severity": "info", "owasp_category": "A07:2021",
                    "confidence_score": 0.7,
                    "evidence": {"page_url": page_url, "auth_type": auth_type},
                    "source_agent": "webapp",
                })
        return findings

    async def _test_error_pages(self, browser: BrowserOperator, target_url: str) -> list[dict]:
        findings: list[dict] = []
        error_urls = [
            f"{target_url.rstrip('/')}/assurix-test-nonexistent-404-page",
            f"{target_url.rstrip('/')}/..%2f..%2f..%2fetc%2fpasswd",
        ]
        for url in error_urls:
            page_data = await browser.browse_page(url)
            if "error" in page_data:
                continue
            text = page_data.get("text_content", "").lower()
            html = page_data.get("html", "")
            disclosure_signatures = [
                ("traceback", "Python traceback exposed", "medium"),
                ("stack trace", "Stack trace exposed in error page", "medium"),
                ("exception", "Exception details exposed", "medium"),
                ("apache/", "Server version disclosed", "low"),
                ("nginx/", "Server version disclosed", "low"),
                ("/var/www/", "Server path disclosed", "medium"),
                ("c:\\", "Windows path disclosed", "medium"),
                ("root:", "System file content disclosed", "critical"),
            ]
            for sig, desc, sev in disclosure_signatures:
                if sig in text or sig in html.lower():
                    findings.append({
                        "title": f"Error page discloses: {desc}",
                        "description": f"Error page at {url} reveals {desc}",
                        "severity": sev, "owasp_category": "A01:2021",
                        "confidence_score": 0.7,
                        "evidence": {"url": url, "signature": sig},
                        "source_agent": "webapp",
                    })
                    break
        return findings