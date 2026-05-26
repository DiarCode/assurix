"""Vulnerability Pattern Library for ZCAT (Zero-Shot Cross-Application Transfer).

Seeded with OWASP Top 10 patterns. Patterns can be matched against findings
to enable cross-target knowledge transfer.
"""

from dataclasses import dataclass, field


@dataclass
class VulnerabilityPattern:
    """A reusable vulnerability pattern that can match findings across targets."""

    name: str
    cwe: str
    category: str
    indicators: list[str]
    severity: str
    description: str
    applicability_conditions: list[str] = field(default_factory=list)

    def matches_finding(self, finding: dict) -> float:
        """Return match score (0.0-1.0) for a finding against this pattern."""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        combined = f"{title} {description}"

        matches = sum(1 for ind in self.indicators if ind.lower() in combined)
        if not matches:
            return 0.0

        if finding.get("cwe_id", "") == self.cwe:
            return 1.0

        if finding.get("owasp_category", "").lower() == self.category.lower():
            return min(1.0, matches / len(self.indicators) + 0.3)

        return min(1.0, matches / len(self.indicators) + 0.1)


class VulnerabilityPatternLibrary:
    """Library of vulnerability patterns for cross-application transfer."""

    def __init__(self) -> None:
        self.patterns: list[VulnerabilityPattern] = self._seed_patterns()

    def match(self, finding: dict) -> list[tuple[VulnerabilityPattern, float]]:
        """Match a finding against known patterns. Returns pattern + score pairs."""
        results = []
        for pattern in self.patterns:
            score = pattern.matches_finding(finding)
            if score > 0.3:
                results.append((pattern, score))
        return sorted(results, key=lambda x: x[1], reverse=True)

    def get_applicable_patterns(self, surface: dict) -> list[VulnerabilityPattern]:
        """Get patterns applicable to a target based on surface data."""
        techs = " ".join(surface.get("technologies", [])).lower()
        applicable = []
        for pattern in self.patterns:
            if not pattern.applicability_conditions:
                applicable.append(pattern)
                continue
            for condition in pattern.applicability_conditions:
                if condition.lower() in techs:
                    applicable.append(pattern)
                    break
        return applicable

    def _seed_patterns(self) -> list[VulnerabilityPattern]:
        """Seed with OWASP Top 10 vulnerability patterns."""
        return [
            VulnerabilityPattern(
                name="Reflected XSS", cwe="CWE-79", category="A03:2021",
                indicators=["xss", "reflected", "script", "injection", "dom-based"],
                severity="high",
                description="User input is reflected in the response without proper encoding",
                applicability_conditions=["react", "vue", "angular", "jquery"],
            ),
            VulnerabilityPattern(
                name="Missing CSRF Token", cwe="CWE-352", category="A01:2021",
                indicators=["csrf", "token", "cross-site request", "form"],
                severity="medium",
                description="State-changing form lacks CSRF protection",
            ),
            VulnerabilityPattern(
                name="Broken Authentication", cwe="CWE-287", category="A07:2021",
                indicators=["auth", "login", "session", "password", "brute"],
                severity="high",
                description="Authentication mechanism has weaknesses",
                applicability_conditions=["login", "auth", "session"],
            ),
            VulnerabilityPattern(
                name="Missing Security Headers", cwe="CWE-693", category="A05:2021",
                indicators=["header", "csp", "hsts", "x-frame", "x-content-type"],
                severity="medium",
                description="Security headers are missing or misconfigured",
            ),
            VulnerabilityPattern(
                name="SQL Injection", cwe="CWE-89", category="A03:2021",
                indicators=["sql", "injection", "database", "query", "error"],
                severity="critical",
                description="User input is concatenated into SQL queries",
            ),
            VulnerabilityPattern(
                name="Insecure Cookie Flags", cwe="CWE-614", category="A02:2021",
                indicators=["cookie", "secure", "httponly", "samesite"],
                severity="low",
                description="Cookies missing Secure/HttpOnly/SameSite flags",
            ),
            VulnerabilityPattern(
                name="Information Disclosure", cwe="CWE-200", category="A01:2021",
                indicators=["disclosure", "error", "stack trace", "version", "powered-by"],
                severity="low",
                description="Server reveals sensitive information in responses",
            ),
            VulnerabilityPattern(
                name="Open Redirect", cwe="CWE-601", category="A01:2021",
                indicators=["redirect", "url", "next", "return", "forward"],
                severity="medium",
                description="Application redirects to user-controlled URLs",
            ),
            VulnerabilityPattern(
                name="Missing Rate Limiting", cwe="CWE-307", category="A07:2021",
                indicators=["rate", "limit", "brute", "throttle", "login"],
                severity="medium",
                description="No rate limiting on authentication or sensitive endpoints",
                applicability_conditions=["login", "auth"],
            ),
            VulnerabilityPattern(
                name="Unrestricted File Upload", cwe="CWE-434", category="A04:2021",
                indicators=["upload", "file", "attachment", "mime"],
                severity="high",
                description="File upload lacks type/size validation",
            ),
            VulnerabilityPattern(
                name="Missing CORS Policy", cwe="CWE-942", category="A05:2021",
                indicators=["cors", "origin", "access-control", "wildcard"],
                severity="medium",
                description="CORS policy is missing or too permissive",
            ),
            VulnerabilityPattern(
                name="Outdated Components", cwe="CWE-1104", category="A06:2021",
                indicators=["outdated", "version", "library", "dependency", "cve"],
                severity="medium",
                description="Application uses components with known vulnerabilities",
            ),
            VulnerabilityPattern(
                name="API Without Auth", cwe="CWE-306", category="A01:2021",
                indicators=["api", "auth", "unauthenticated", "missing"],
                severity="high",
                description="API endpoint accessible without authentication",
            ),
            VulnerabilityPattern(
                name="Sensitive Data Exposure", cwe="CWE-319", category="A02:2021",
                indicators=["http", "unencrypted", "tls", "hsts", "transport"],
                severity="medium",
                description="Data transmitted without encryption",
            ),
            VulnerabilityPattern(
                name="DOM-based XSS", cwe="CWE-79", category="A03:2021",
                indicators=["dom", "innerhtml", "document.write", "eval", "sink"],
                severity="high",
                description="Client-side JavaScript processes untrusted data unsafely",
                applicability_conditions=["react", "vue", "angular", "jquery"],
            ),
            # Mythos-level patterns: business logic, SSRF, race conditions, advanced auth

            VulnerabilityPattern(
                name="SSRF", cwe="CWE-918", category="A10:2021",
                indicators=["ssrf", "url fetch", "internal request", "cloud metadata", "webhook", "proxy"],
                severity="high",
                description="Server-side Request Forgery — application fetches user-supplied URLs",
                applicability_conditions=["api", "webhook", "proxy", "fetch", "import"],
            ),
            VulnerabilityPattern(
                name="Business Logic Bypass", cwe="CWE-840", category="A04:2021",
                indicators=["business logic", "workflow", "step skip", "state machine", "price tampering",
                            "negative quantity", "privilege escalation", "idor"],
                severity="high",
                description="Application business logic can be bypassed to achieve unintended behavior",
            ),
            VulnerabilityPattern(
                name="Race Condition", cwe="CWE-367", category="A04:2021",
                indicators=["race condition", "concurrent", "toctou", "double spend", "timing",
                            "idempotency", "double submit", "atomic"],
                severity="medium",
                description="Race condition allows concurrent operations to break application logic",
                applicability_conditions=["payment", "cart", "checkout", "transfer", "booking"],
            ),
            VulnerabilityPattern(
                name="IDOR", cwe="CWE-639", category="A01:2021",
                indicators=["idor", "insecure direct", "object reference", "user id", "parameter tampering",
                            "authorization bypass", "cross-tenant"],
                severity="high",
                description="Insecure Direct Object Reference — accessing resources by manipulating identifiers",
            ),
            VulnerabilityPattern(
                name="JWT Algorithm Confusion", cwe="CWE-327", category="A02:2021",
                indicators=["jwt", "token", "algorithm", "none algorithm", "key confusion",
                            "hs256", "rs256", "jws"],
                severity="critical",
                description="JWT uses weak or confused algorithm — signature bypass possible",
                applicability_conditions=["jwt", "token", "bearer", "jws"],
            ),
            VulnerabilityPattern(
                name="Prototype Pollution", cwe="CWE-1321", category="A03:2021",
                indicators=["prototype pollution", "__proto__", "constructor.prototype", "object.assign",
                            "merge", "deep merge", "lodash"],
                severity="high",
                description="Prototype pollution allows property injection on all JavaScript objects",
                applicability_conditions=["node", "express", "lodash", "jquery"],
            ),
            VulnerabilityPattern(
                name="Deserialization Injection", cwe="CWE-502", category="A08:2021",
                indicators=["deserialization", "pickle", "serialize", "unserialize", "yaml.load",
                            "objectinputstream", "json.parse", "marshalling"],
                severity="critical",
                description="Unsafe deserialization of untrusted data leads to remote code execution",
            ),
            VulnerabilityPattern(
                name="Privilege Escalation", cwe="CWE-269", category="A01:2021",
                indicators=["privilege escalation", "role manipulation", "admin access", "horizontal escalation",
                            "vertical escalation", "permission bypass", "authorization bypass"],
                severity="critical",
                description="User can access functionality or data beyond their authorized permissions",
            ),
            VulnerabilityPattern(
                name="Second-Order Injection", cwe="CWE-89", category="A03:2021",
                indicators=["second-order", "stored injection", "delayed injection", "indirect injection",
                            "data consumption", "export injection"],
                severity="high",
                description="Malicious input stored then consumed unsafely in a different context",
            ),
            VulnerabilityPattern(
                name="OAuth Misconfiguration", cwe="CWE-303", category="A07:2021",
                indicators=["oauth", "redirect_uri", "state parameter", "authorization code",
                            "token leakage", "callback", "sso", "openid"],
                severity="high",
                description="OAuth/SSO implementation has configuration flaws enabling account takeover",
                applicability_conditions=["oauth", "sso", "openid", "google", "github"],
            ),
        ]