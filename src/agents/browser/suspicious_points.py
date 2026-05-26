"""Suspicious Point detection for targeted security investigation.

Adapted from R1's binary-level Suspicious Points for web applications.
Instead of instruction addresses, web SPs are:
- DOM elements (forms, inputs, buttons with handlers)
- Network endpoints (API routes, redirects)
- Handler bindings (event listeners, onclick attributes)
- State transitions (auth flows, session changes)
- Missing elements (no CSRF token, no rate limiting) — R3 innovation
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SuspiciousPoint:
    """A location in the application surface that warrants deeper investigation."""

    sp_type: str  # "dom_element" | "endpoint" | "handler" | "state" | "missing"
    location: str  # CSS selector, URL, or descriptor
    reason: str  # Why this is suspicious
    confidence: float  # 0.0-1.0
    investigated: bool = False
    findings: list[dict] = field(default_factory=list)
    vuln_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.sp_type,
            "location": self.location,
            "reason": self.reason,
            "confidence": self.confidence,
            "investigated": self.investigated,
            "findings_count": len(self.findings),
            "vuln_types": self.vuln_types,
        }


class SuspiciousPointDetector:
    """Identifies suspicious points from surface data using heuristics.

    Two-tier detection:
    1. Heuristic tier: pattern match against surface data (fast, no LLM cost)
    2. LLM tier: ask model "what looks suspicious?" (expensive, high coverage)
    """

    MISSING_RULES = {
        "no_csrf_token": (
            "missing", "form_missing_csrf",
            "Form lacks CSRF token — vulnerable to cross-site request forgery",
            0.8, ["csrf", "form"],
        ),
        "no_rate_limiting": (
            "missing", "response_headers",
            "No rate limiting headers — brute-force vulnerability possible",
            0.6, ["brute_force", "auth"],
        ),
        "wildcard_cors": (
            "missing", "CORS_policy",
            "Wildcard CORS — any origin can make cross-origin requests",
            0.7, ["cors", "api"],
        ),
        "no_csp": (
            "missing", "response_headers",
            "No Content-Security-Policy — XSS and injection attacks not mitigated",
            0.9, ["xss", "injection"],
        ),
        "no_input_sanitization": (
            "missing", "input_fields",
            "Form accepts input without visible sanitization",
            0.5, ["xss", "injection"],
        ),
        "session_in_url": (
            "state", "url_parameters",
            "Session identifier in URL — session hijacking risk",
            0.9, ["session", "auth"],
        ),
        "jwt_in_localstorage": (
            "state", "localStorage",
            "JWT stored in localStorage — accessible to XSS attacks",
            0.7, ["xss", "auth"],
        ),
        "inline_event_handler": (
            "handler", "DOM_inline_handler",
            "Inline event handler — potential XSS sink",
            0.6, ["xss", "dom"],
        ),
        "document_write": (
            "handler", "DOM_dangerous_sink",
            "document.write usage — DOM XSS sink",
            0.7, ["xss", "dom"],
        ),
        "eval_usage": (
            "handler", "JS_eval",
            "eval() usage — code injection risk",
            0.8, ["xss", "injection"],
        ),
        "api_no_auth": (
            "endpoint", "API_endpoint",
            "API endpoint accessible without authentication",
            0.7, ["auth", "api"],
        ),
        "open_redirect": (
            "endpoint", "redirect_endpoint",
            "URL parameter may enable open redirect",
            0.6, ["redirect", "phishing"],
        ),
        "file_upload": (
            "endpoint", "upload_endpoint",
            "File upload endpoint — needs type/size validation",
            0.7, ["upload", "rce"],
        ),
    }

    def detect(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect suspicious points from surface data using heuristics.

        Two-tier detection:
        1. Heuristic tier: pattern match against surface data (fast, no LLM cost)
        2. LLM tier: ask model "what looks suspicious?" (expensive, high coverage)
        """
        points: list[SuspiciousPoint] = []

        points.extend(self._detect_from_headers(surface))
        points.extend(self._detect_from_forms(surface))
        points.extend(self._detect_from_cookies(surface))
        points.extend(self._detect_from_endpoints(surface))
        points.extend(self._detect_from_javascript(surface))
        points.extend(self._detect_from_auth(surface))
        points.extend(self._detect_missing_code(surface))
        points.extend(self._detect_ssrf_surface(surface))
        points.extend(self._detect_business_logic_surface(surface))

        # Deduplicate by location
        seen: set[str] = set()
        unique: list[SuspiciousPoint] = []
        for p in points:
            key = f"{p.sp_type}:{p.location}"
            if key not in seen:
                seen.add(key)
                unique.append(p)

        unique.sort(key=lambda p: p.confidence, reverse=True)
        return unique[:30]

    def _detect_from_headers(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from HTTP response headers."""
        points: list[SuspiciousPoint] = []
        headers = surface.get("headers", {})

        # Missing security headers (combined)
        security_headers = {
            "content-security-policy": ("Missing Content-Security-Policy — XSS not mitigated", 0.9, ["xss", "injection"]),
            "strict-transport-security": ("Missing HSTS — browsers may access via HTTP", 0.85, ["transport"]),
            "x-frame-options": ("Missing X-Frame-Options — clickjacking possible", 0.75, ["clickjacking"]),
            "x-content-type-options": ("Missing X-Content-Type-Options — MIME sniffing", 0.6, ["misconfig"]),
            "referrer-policy": ("Missing Referrer-Policy — URL leaks in Referer", 0.5, ["info_disclosure"]),
            "permissions-policy": ("Missing Permissions-Policy — browser features unrestricted", 0.4, ["misconfig"]),
        }

        lower_headers = {k.lower(): v for k, v in headers.items()}
        for header, (reason, confidence, vuln_types) in security_headers.items():
            if header not in lower_headers:
                points.append(SuspiciousPoint(
                    sp_type="missing", location="response_headers",
                    reason=reason, confidence=confidence, vuln_types=vuln_types,
                ))

        # Wildcard CORS
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            points.append(SuspiciousPoint(
                sp_type="missing", location="CORS_policy",
                reason="Wildcard CORS — any origin can make cross-origin requests",
                confidence=0.7, vuln_types=["cors", "api"],
            ))

        # No rate limiting
        rate_headers = [k for k in headers if "rate" in k.lower() or "retry-after" in k.lower()]
        if not rate_headers:
            points.append(SuspiciousPoint(
                sp_type="missing", location="response_headers",
                reason="No rate limiting headers — brute-force vulnerability possible",
                confidence=0.6, vuln_types=["brute_force", "auth"],
            ))

        # Info disclosure headers
        for hdr in ("x-powered-by", "x-aspnet-version", "x-runtime"):
            if headers.get(hdr):
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=f"header_{hdr}",
                    reason=f"Information disclosure via {hdr}: {headers[hdr]}",
                    confidence=0.7, vuln_types=["info_disclosure"],
                ))

        return points

    def _detect_from_forms(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from HTML forms."""
        points: list[SuspiciousPoint] = []
        forms = surface.get("forms", [])

        for form in forms:
            action = form.get("action", "unknown")
            inputs = form.get("inputs", form.get("fields", []))

            has_csrf = False
            if isinstance(inputs, list):
                for inp in inputs:
                    name = inp.get("name", "").lower()
                    if "csrf" in name or "token" in name or "nonce" in name:
                        has_csrf = True
                        break

            if not has_csrf:
                points.append(SuspiciousPoint(
                    sp_type="missing", location=f"form_at_{action}",
                    reason="Form lacks CSRF token — vulnerable to cross-site request forgery",
                    confidence=0.8, vuln_types=["csrf", "form"],
                ))

            if isinstance(inputs, list):
                for inp in inputs:
                    if inp.get("type") == "password" and inp.get("autocomplete", "") != "off":
                        points.append(SuspiciousPoint(
                            sp_type="dom_element", location=f"password_field_at_{action}",
                            reason="Password field allows browser autocomplete",
                            confidence=0.4, vuln_types=["auth"],
                        ))
                        break

        return points

    def _detect_from_cookies(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from cookies."""
        points: list[SuspiciousPoint] = []
        cookies = surface.get("cookies", [])

        for c in cookies:
            name = c.get("name", "")
            if not c.get("secure", False):
                points.append(SuspiciousPoint(
                    sp_type="state", location=f"cookie_{name}",
                    reason=f"Cookie '{name}' missing Secure flag",
                    confidence=0.9, vuln_types=["cookie", "transport"],
                ))
            if not c.get("httponly", False):
                points.append(SuspiciousPoint(
                    sp_type="state", location=f"cookie_{name}",
                    reason=f"Cookie '{name}' missing HttpOnly flag — XSS exfiltration risk",
                    confidence=0.9, vuln_types=["cookie", "xss"],
                ))
        return points

    def _detect_from_endpoints(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from API endpoints."""
        points: list[SuspiciousPoint] = []
        endpoints = surface.get("endpoints", [])

        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ("login", "auth", "signin", "session")):
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=ep,
                    reason="Authentication endpoint — test for brute-force, session issues",
                    confidence=0.7, vuln_types=["auth", "brute_force"],
                ))
            if any(kw in ep_lower for kw in ("upload", "file", "attachment")):
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=ep,
                    reason="File upload endpoint — needs type/size validation",
                    confidence=0.7, vuln_types=["upload", "rce"],
                ))
            if any(kw in ep_lower for kw in ("admin", "config", "settings", "dashboard")):
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=ep,
                    reason="Admin/config endpoint — test for auth bypass",
                    confidence=0.7, vuln_types=["auth", "privilege_escalation"],
                ))
            if any(kw in ep_lower for kw in ("redirect", "return", "next", "url")):
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=ep,
                    reason="URL parameter may enable open redirect",
                    confidence=0.6, vuln_types=["redirect", "phishing"],
                ))
        return points

    def _detect_from_javascript(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from JavaScript content."""
        points: list[SuspiciousPoint] = []
        scripts = surface.get("scripts", [])
        text_content = surface.get("text_content", "")

        dangerous_patterns = {
            "eval(": ("eval_usage", 0.8, ["xss", "injection"]),
            "document.write(": ("document_write", 0.7, ["xss", "dom"]),
            "innerHTML": ("inline_event_handler", 0.5, ["xss", "dom"]),
            "outerHTML": ("inline_event_handler", 0.5, ["xss", "dom"]),
            "insertAdjacentHTML": ("inline_event_handler", 0.5, ["xss", "dom"]),
            "document.cookie": ("session_in_url", 0.6, ["session"]),
            "localStorage": ("jwt_in_localstorage", 0.4, ["xss", "auth"]),
        }

        combined = " ".join(scripts) + " " + text_content[:5000]
        for pattern, (_, base_conf, vuln_types) in dangerous_patterns.items():
            if pattern in combined:
                points.append(SuspiciousPoint(
                    sp_type="handler", location=f"JS_{pattern.replace('(', '').replace('.', '_')}",
                    reason=f"JavaScript contains {pattern} — potential security risk",
                    confidence=base_conf, vuln_types=vuln_types,
                ))

        for src in scripts:
            if src.startswith("http") and "integrity" not in src:
                points.append(SuspiciousPoint(
                    sp_type="endpoint", location=src[:100],
                    reason=f"External script without Subresource Integrity: {src[:60]}",
                    confidence=0.5, vuln_types=["supply_chain"],
                ))

        return points

    def _detect_from_auth(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect SPs from authentication pages."""
        points: list[SuspiciousPoint] = []
        auth_pages = surface.get("auth_pages", [])

        for auth in auth_pages:
            url = auth.get("url", "unknown")
            auth_type = auth.get("auth_type", "")
            login_form = auth.get("login_form", {})

            if auth_type == "form_login":
                has_captcha = login_form.get("hasCaptcha", False) if isinstance(login_form, dict) else False
                if not has_captcha:
                    points.append(SuspiciousPoint(
                        sp_type="missing", location=f"login_at_{url}",
                        reason="Login form lacks brute-force protection (no CAPTCHA)",
                        confidence=0.6, vuln_types=["brute_force", "auth"],
                    ))

            points.append(SuspiciousPoint(
                sp_type="state", location=f"auth_page_{url}",
                reason=f"Authentication page detected ({auth_type}) — deep testing warranted",
                confidence=0.7, vuln_types=["auth"],
            ))
        return points

    def _detect_missing_code(self, surface: dict) -> list[SuspiciousPoint]:
        """Detect absent security controls — R3 'Missing Code' detection.

        Finds vulnerabilities defined by what's NOT there, not what IS present.
        """
        points: list[SuspiciousPoint] = []
        forms = surface.get("forms", [])

        # Forms without input validation
        for form in forms[:5]:
            inputs = form.get("inputs", form.get("fields", []))
            if isinstance(inputs, list):
                has_validation = any(
                    inp.get("pattern") or inp.get("maxlength") or inp.get("minlength")
                    or inp.get("type") in ("number", "email", "url", "date")
                    for inp in inputs
                )
                has_text_inputs = any(
                    inp.get("type") in ("text", "search", "") for inp in inputs
                )
                if has_text_inputs and not has_validation:
                    action = form.get("action", "unknown")
                    points.append(SuspiciousPoint(
                        sp_type="missing", location=f"form_validation_{action}",
                        reason="Form text inputs lack validation attributes — injection risk",
                        confidence=0.4, vuln_types=["xss", "injection"],
                    ))

        return points

    def _detect_ssrf_surface(self, surface: dict) -> list[SuspiciousPoint]:
        """Mythos: Detect SSRF-vulnerable surface areas."""
        points: list[SuspiciousPoint] = []
        endpoints = surface.get("endpoints", [])

        ssrf_keywords = {
            "url": ("URL parameter that may accept external URLs — SSRF risk", 0.7, ["ssrf"]),
            "image": ("Image URL parameter — potential SSRF via image fetching", 0.6, ["ssrf"]),
            "fetch": ("Fetch/import endpoint — SSRF risk", 0.7, ["ssrf"]),
            "import": ("Import URL parameter — SSRF risk", 0.6, ["ssrf"]),
            "proxy": ("Proxy/forward endpoint — potential SSRF proxy", 0.7, ["ssrf"]),
            "callback": ("Callback URL parameter — SSRF via webhook", 0.7, ["ssrf"]),
            "webhook": ("Webhook URL parameter — SSRF via webhook", 0.7, ["ssrf"]),
        }

        for ep in endpoints:
            ep_lower = ep.lower()
            for keyword, (reason, confidence, vuln_types) in ssrf_keywords.items():
                if keyword in ep_lower:
                    points.append(SuspiciousPoint(
                        sp_type="endpoint", location=ep[:100],
                        reason=reason, confidence=confidence, vuln_types=vuln_types,
                    ))
                    break

        return points

    def _detect_business_logic_surface(self, surface: dict) -> list[SuspiciousPoint]:
        """Mythos: Detect business logic vulnerability surface areas."""
        points: list[SuspiciousPoint] = []
        endpoints = surface.get("endpoints", [])
        forms = surface.get("forms", [])

        financial_keywords = {
            "pay": ("Payment endpoint — test for price manipulation and race conditions", 0.7, ["business_logic", "race_condition"]),
            "checkout": ("Checkout flow — test for step-skipping and price manipulation", 0.7, ["business_logic"]),
            "cart": ("Cart endpoint — test for quantity manipulation and race conditions", 0.7, ["business_logic", "race_condition"]),
            "order": ("Order endpoint — test for state manipulation and IDOR", 0.6, ["business_logic", "idor"]),
            "transfer": ("Transfer endpoint — test for race conditions and amount manipulation", 0.8, ["business_logic", "race_condition"]),
            "withdraw": ("Withdrawal endpoint — high-value race condition target", 0.8, ["business_logic", "race_condition"]),
            "deposit": ("Deposit endpoint — test for race conditions and double-spend", 0.7, ["business_logic", "race_condition"]),
            "refund": ("Refund endpoint — test for double-refund race condition", 0.7, ["business_logic", "race_condition"]),
            "book": ("Booking endpoint — test for race conditions and state manipulation", 0.6, ["business_logic", "race_condition"]),
        }

        for ep in endpoints:
            ep_lower = ep.lower()
            for keyword, (reason, confidence, vuln_types) in financial_keywords.items():
                if keyword in ep_lower:
                    points.append(SuspiciousPoint(
                        sp_type="endpoint", location=ep[:100],
                        reason=reason, confidence=confidence, vuln_types=vuln_types,
                    ))
                    break

        for form in forms[:5]:
            action = form.get("action", "").lower()
            if any(kw in action for kw in ("register", "signup", "checkout", "submit", "create")):
                points.append(SuspiciousPoint(
                    sp_type="dom_element", location=f"form_at_{action}",
                    reason="Multi-step form — test for step-skipping and state manipulation",
                    confidence=0.5, vuln_types=["business_logic"],
                ))

        return points

