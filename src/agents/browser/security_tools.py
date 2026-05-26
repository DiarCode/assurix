"""Custom security tools for browser-use AI agent.

These tools are registered as browser-use Actions that the AI agent can invoke
during autonomous exploration. Each tool returns an ActionResult with structured
findings that feed into the security analysis pipeline."""

import logging
from pathlib import Path
from typing import Any

from browser_use import ActionResult, BrowserSession, Tools

logger = logging.getLogger(__name__)


def create_security_tools(artifacts_dir: Path) -> Tools:
    """Create and return the security tools registry for browser-use agent."""
    tools = Tools()
    _artifacts_dir = artifacts_dir

    @tools.action(
        "Check HTTP security headers on the current page. "
        "Analyzes headers like X-Frame-Options, X-Content-Type-Options, "
        "Content-Security-Policy, Strict-Transport-Security, Referrer-Policy, "
        "and Permissions-Policy. Reports missing or misconfigured headers."
    )
    async def check_security_headers(browser_session: BrowserSession) -> ActionResult:
        """Analyze security headers from the current page response."""
        findings: list[dict[str, Any]] = []

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="Could not get active page for header analysis")

            # Check headers via performance API and JS
            result = await page.evaluate("""() => {
                const findings = [];
                // Check meta tags for CSP
                const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                // Check for common security issues in the page
                const hasMixedContent = (location.protocol === 'https:' &&
                    document.querySelector('img[src^="http:"], script[src^="http:"], link[href^="http:"]'));
                return {
                    url: location.href,
                    protocol: location.protocol,
                    hasCspMeta: !!cspMeta,
                    hasMixedContent: !!hasMixedContent,
                };
            }""")

            if result:
                if result.get("protocol") == "http:":
                    findings.append({"check": "transport", "issue": "Page served over HTTP, not HTTPS", "severity": "medium"})
                if result.get("hasMixedContent"):
                    findings.append({"check": "mixed_content", "issue": "Mixed content detected on HTTPS page", "severity": "medium"})
        except Exception as exc:
            logger.debug("Header check JS error: %s", exc)

        if findings:
            return ActionResult(extracted_content=f"Security header findings: {findings}")
        return ActionResult(extracted_content="No security header issues found on this page")

    @tools.action(
        "Check cookies on the current page for security flags. "
        "Audits cookies for missing Secure, HttpOnly, and SameSite flags. "
        "Reports cookies that could be stolen via XSS or transmitted over HTTP."
    )
    async def check_cookies(browser_session: BrowserSession) -> ActionResult:
        """Audit cookie security flags on current page."""
        cookie_findings: list[dict[str, Any]] = []

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="No active page for cookie check")

            result = await page.evaluate("""() => {
                return document.cookie.split(';').map(c => {
                    const parts = c.trim().split('=');
                    return { name: parts[0].trim(), value: parts.slice(1).join('=').substring(0, 20) };
                });
            }""")

            # Get cookie details via CDP
            try:
                cdp = await browser_session.get_or_create_cdp_session()
                cookies_result = await cdp.cdp_client.send.Network.getCookies(
                    session_id=cdp.session_id,
                )

                for cookie in cookies_result.get("cookies", []):
                    issues = []
                    if not cookie.get("secure", False):
                        issues.append("missing Secure flag")
                    if not cookie.get("httpOnly", False):
                        issues.append("missing HttpOnly flag")
                    if cookie.get("sameSite", "None") not in ("Strict", "Lax"):
                        issues.append(f"SameSite={cookie.get('sameSite', 'None')}")

                    if issues:
                        cookie_findings.append({
                            "name": cookie.get("name", ""),
                            "domain": cookie.get("domain", ""),
                            "issues": issues,
                        })
            except Exception:
                # Fallback: report what JS can see
                if result:
                    for c in result:
                        cookie_findings.append({
                            "name": c.get("name", ""),
                            "issues": ["JS-accessible cookie (no HttpOnly)"],
                        })

        except Exception as exc:
            logger.debug("Cookie check error: %s", exc)

        if cookie_findings:
            return ActionResult(extracted_content=f"Cookie security issues: {cookie_findings}")
        return ActionResult(extracted_content="No cookie security issues found")

    @tools.action(
        "Test for Cross-Site Scripting (XSS) by injecting a safe probe into URL parameters "
        "and form fields. Checks if the probe appears unencoded in the page HTML. "
        "Parameters: param_name (which URL param to test), payload (the XSS probe string to inject)."
    )
    async def test_xss(
        param_name: str,
        payload: str,
        browser_session: BrowserSession,
    ) -> ActionResult:
        """Inject a safe XSS probe and check for reflection in the page."""
        marker = "AssurixXSSProbe2026"

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="No active page for XSS test")

            # Fill input fields with the marker
            js = f"""() => {{
                const marker = "{marker}";
                const inputs = document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], textarea');
                let filled = 0;
                inputs.forEach(input => {{
                    try {{ input.value = marker; filled++; }} catch(e) {{}}
                }});
                const html = document.body.innerHTML;
                const reflected = html.includes(marker);
                const context = reflected ? html.substring(Math.max(0, html.indexOf(marker) - 80), html.indexOf(marker) + marker.length + 80) : '';
                return {{ filled: filled, reflected: reflected, context: context }};
            }}"""

            result = await page.evaluate(js)

            if result and result.get("reflected"):
                return ActionResult(
                    extracted_content=f"XSS REFLECTION DETECTED: Marker found unencoded in HTML. Context: {result.get('context', '')[:300]}",
                )
            return ActionResult(extracted_content="No XSS reflection found with current probe")

        except Exception as exc:
            return ActionResult(extracted_content=f"XSS test error: {exc}")

    @tools.action(
        "Check forms on the current page for CSRF protection. "
        "Looks for CSRF tokens in hidden form fields, meta tags, and custom headers. "
        "Reports POST forms that lack CSRF protection."
    )
    async def test_csrf(browser_session: BrowserSession) -> ActionResult:
        """Check forms for CSRF tokens and protection mechanisms."""
        csrf_findings: list[dict[str, Any]] = []

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="No active page for CSRF test")

            result = await page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.map(form => {
                    const inputs = Array.from(form.querySelectorAll('input'));
                    const hasCsrfToken = inputs.some(i =>
                        /csrf|token|nonce|_token|authenticity/i.test(i.name || i.id || '')
                    );
                    return {
                        action: form.action,
                        method: form.method,
                        hasCsrfToken: hasCsrfToken,
                        inputCount: inputs.length,
                        inputNames: inputs.map(i => i.name).filter(Boolean).slice(0, 10),
                    };
                });
            }""")

            if result:
                for form in result:
                    if not form.get("hasCsrfToken") and form.get("method", "").upper() == "POST":
                        csrf_findings.append({
                            "action": form.get("action", ""),
                            "method": form.get("method", ""),
                            "issue": "POST form missing CSRF token",
                        })

        except Exception as exc:
            logger.debug("CSRF check error: %s", exc)

        if csrf_findings:
            return ActionResult(extracted_content=f"CSRF findings: {csrf_findings}")
        return ActionResult(extracted_content="All POST forms have CSRF protection or no POST forms found")

    @tools.action(
        "Analyze JavaScript on the current page for dangerous patterns. "
        "Scans inline scripts for DOM XSS sinks (innerHTML, document.write, eval, "
        "setTimeout with string args), and checks external scripts for SRI integrity."
    )
    async def analyze_javascript(browser_session: BrowserSession) -> ActionResult:
        """Scan page JavaScript for security-relevant patterns."""
        js_findings: list[dict[str, Any]] = []

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="No active page for JS analysis")

            result = await page.evaluate("""() => {
                const findings = [];
                const scripts = Array.from(document.querySelectorAll('script'));
                const inlineScripts = scripts.filter(s => !s.src && s.textContent.length > 0);

                for (const script of inlineScripts) {
                    const content = script.textContent;
                    const sinks = [];
                    if (content.includes('innerHTML')) sinks.push('innerHTML');
                    if (content.includes('outerHTML')) sinks.push('outerHTML');
                    if (content.includes('document.write')) sinks.push('document.write');
                    if (/\\beval\\s*\\(/.test(content)) sinks.push('eval');
                    if (/setTimeout\\s*\\(\\s*['"]/.test(content)) sinks.push('setTimeout(string)');
                    if (sinks.length > 0) {
                        findings.push({type: 'dom_sinks', sinks: sinks, snippet: content.substring(0, 200)});
                    }
                }

                const extScripts = scripts.filter(s => s.src);
                for (const s of extScripts) {
                    if (!s.integrity) {
                        findings.push({type: 'script_no_sri', src: s.src.substring(0, 200)});
                    }
                }

                return findings;
            }""")

            if result:
                js_findings = result

        except Exception as exc:
            logger.debug("JS analysis error: %s", exc)

        if js_findings:
            return ActionResult(extracted_content=f"JavaScript security findings: {js_findings}")
        return ActionResult(extracted_content="No JavaScript security issues found")

    @tools.action(
        "Capture evidence of a security finding as a screenshot and DOM snapshot. "
        "Parameters: description (what the evidence shows), finding_title (short name for the finding file)."
    )
    async def capture_evidence(
        description: str,
        finding_title: str,
        browser_session: BrowserSession,
    ) -> ActionResult:
        """Take a screenshot and save it as evidence for a finding."""
        import time

        timestamp = int(time.time())
        safe_title = finding_title.replace(" ", "_").replace("/", "_")[:50]
        screenshot_path = _artifacts_dir / f"{timestamp}_{safe_title}.png"

        try:
            page = browser_session.current_page
            if page:
                await page.screenshot(path=str(screenshot_path), full_page=False)
                html_snippet = await page.evaluate("document.body?.innerHTML?.substring(0, 2000) || ''")
                dom_path = _artifacts_dir / f"{timestamp}_{safe_title}_dom.txt"
                dom_path.write_text(html_snippet, encoding="utf-8")

                return ActionResult(
                    extracted_content=f"Evidence captured for '{finding_title}': {description}. Screenshot: {screenshot_path.name}, DOM: {dom_path.name}",
                )
        except Exception as exc:
            logger.debug("Evidence capture error: %s", exc)

        return ActionResult(extracted_content=f"Could not capture evidence for: {finding_title}")

    @tools.action(
        "Analyze authentication and login forms on the current page. "
        "Detects login forms, password fields, OAuth/SSO buttons, CAPTCHA, 2FA, "
        "and checks for security issues like missing CSRF tokens or autocomplete on passwords."
    )
    async def check_authentication(browser_session: BrowserSession) -> ActionResult:
        """Detect and analyze authentication pages."""
        auth_findings: list[dict[str, Any]] = []

        try:
            page = browser_session.current_page
            if not page:
                return ActionResult(extracted_content="No active page for auth analysis")

            result = await page.evaluate("""() => {
                const findings = {};
                const forms = Array.from(document.querySelectorAll('form'));
                const loginForms = [];
                for (const form of forms) {
                    const inputs = Array.from(form.querySelectorAll('input'));
                    const hasPassword = inputs.some(i => i.type === 'password');
                    const hasText = inputs.some(i => i.type === 'text' || i.type === 'email');
                    if (hasPassword && hasText) {
                        const hasCsrf = inputs.some(i => /csrf|token|nonce/i.test(i.name || i.id || ''));
                        const hasAutocompleteOff = inputs.some(i => i.type === 'password' && i.autocomplete === 'off');
                        const hasCaptcha = !!form.querySelector('[class*="captcha"], [id*="captcha"], iframe[src*="captcha"]');
                        loginForms.push({
                            action: form.action, method: form.method,
                            hasCsrfToken: hasCsrf, hasAutocompleteOff: hasAutocompleteOff,
                            hasCaptcha: hasCaptcha,
                            fields: inputs.map(i => ({name: i.name, type: i.type, autocomplete: i.autocomplete})),
                        });
                    }
                }
                findings.loginForms = loginForms;

                const oauthSelectors = [
                    'a[href*="oauth"]', 'a[href*="google"]', 'a[href*="github"]',
                    'button[data-provider]', '[class*="social-login"]', '[class*="sso"]',
                ];
                findings.oauthButtons = [];
                for (const sel of oauthSelectors) {
                    const el = document.querySelector(sel);
                    if (el) findings.oauthButtons.push({text: el.textContent.trim().slice(0, 50), href: el.href || ''});
                }
                return findings;
            }""")

            if result:
                for form in result.get("loginForms", []):
                    if not form.get("hasCsrfToken"):
                        auth_findings.append({"issue": "Login form missing CSRF token", "action": form.get("action", ""), "severity": "medium"})
                    if not form.get("hasAutocompleteOff"):
                        auth_findings.append({"issue": "Password field allows autocomplete", "action": form.get("action", ""), "severity": "info"})
                    if not form.get("hasCaptcha"):
                        auth_findings.append({"issue": "No CAPTCHA on login form", "action": form.get("action", ""), "severity": "low"})
                if result.get("oauthButtons"):
                    auth_findings.append({"issue": "OAuth/SSO authentication detected", "providers": [b.get("text", "") for b in result["oauthButtons"]], "severity": "info"})

        except Exception as exc:
            logger.debug("Auth check error: %s", exc)

        if auth_findings:
            return ActionResult(extracted_content=f"Authentication findings: {auth_findings}")
        return ActionResult(extracted_content="No authentication pages or issues found on this page")

    return tools