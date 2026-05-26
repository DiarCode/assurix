"""PoC Pipeline — generates executable proof-of-concept for validated findings.

Generates:
- XSS -> curl command or browser script that demonstrates reflection
- Missing header -> curl command showing absence
- CSRF -> HTML form that auto-submits
- Info disclosure -> curl command revealing data
- Auth bypass -> curl command demonstrating access
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class PoCPipeline:
    """Generates executable proof-of-concept commands for validated findings."""

    def generate_poc(self, finding: dict[str, Any], target_url: str = "") -> dict[str, Any]:
        """Generate a PoC for a given finding."""
        title = finding.get("title", "").lower()
        cwe = finding.get("cwe_id", "")
        evidence = finding.get("evidence", {})

        poc_generators = {
            "xss": self._poc_xss,
            "csrf": self._poc_csrf,
            "cors": self._poc_cors,
            "missing": self._poc_missing_header,
            "cookie": self._poc_cookie,
            "injection": self._poc_injection,
            "info_disclosure": self._poc_info_disclosure,
            "redirect": self._poc_redirect,
            "auth": self._poc_auth,
            "upload": self._poc_upload,
        }

        # Match finding to PoC generator by title keyword
        for keyword, generator in poc_generators.items():
            if keyword in title:
                return generator(finding, target_url)

        # CWE-based matching
        cwe_pocs = {
            "CWE-79": self._poc_xss,
            "CWE-352": self._poc_csrf,
            "CWE-693": self._poc_missing_header,
            "CWE-319": self._poc_missing_header,
            "CWE-306": self._poc_auth,
            "CWE-434": self._poc_upload,
            "CWE-601": self._poc_redirect,
            "CWE-200": self._poc_info_disclosure,
            "CWE-89": self._poc_injection,
            "CWE-614": self._poc_cookie,
            "CWE-307": self._poc_auth,
        }
        if cwe in cwe_pocs:
            return cwe_pocs[cwe](finding, target_url)

        return self._poc_generic(finding, target_url)

    @staticmethod
    def _poc_xss(finding: dict, target_url: str) -> dict[str, Any]:
        url = finding.get("evidence", {}).get("url", target_url)
        param = finding.get("evidence", {}).get("parameter", "q")
        return {
            "poc_type": "xss",
            "title": f"XSS PoC: {finding.get('title', 'Reflected XSS')}",
            "command": f'curl -s "{url}?{param}=%3Cscript%3Ealert(1)%3C/script%3E" | grep -i "script.*alert"',
            "html_poc": (
                f'<html><body>\n'
                f'<form action="{url}" method="GET">\n'
                f'  <input type="hidden" name="{param}" value=\'<script>alert("XSS")</script>\'>\n'
                f'  <input type="submit" value="Test XSS">\n'
                f'</form>\n</body></html>'
            ),
            "description": f"Send crafted input to {url} parameter '{param}' and check for reflection.",
            "severity": finding.get("severity", "medium"),
            "cwe": finding.get("cwe_id", "CWE-79"),
        }

    @staticmethod
    def _poc_csrf(finding: dict, target_url: str) -> dict[str, Any]:
        action = finding.get("evidence", {}).get("form_action", finding.get("expected_location", target_url))
        return {
            "poc_type": "csrf",
            "title": f"CSRF PoC: {finding.get('title', 'Cross-Site Request Forgery')}",
            "command": f"# CSRF PoC — auto-submitting form to {action}",
            "html_poc": (
                f'<html><body>\n'
                f'<form action="{action}" method="POST" id="csrf-form">\n'
                f'  <input type="hidden" name="action" value="test">\n'
                f'</form>\n'
                f'<script>document.getElementById("csrf-form").submit();</script>\n'
                f'</body></html>'
            ),
            "description": f"Auto-submitting form to {action} — demonstrates CSRF vulnerability.",
            "severity": finding.get("severity", "medium"),
            "cwe": finding.get("cwe_id", "CWE-352"),
        }

    @staticmethod
    def _poc_cors(finding: dict, target_url: str) -> dict[str, Any]:
        url = target_url or finding.get("evidence", {}).get("url", "https://example.com")
        return {
            "poc_type": "cors",
            "title": f"CORS PoC: {finding.get('title', 'Wildcard CORS')}",
            "command": f'curl -s -H "Origin: https://evil.example.com" -I "{url}" | grep -i "access-control-allow-origin"',
            "html_poc": None,
            "description": f"Send request with evil Origin header to {url} and check CORS response.",
            "severity": finding.get("severity", "medium"),
            "cwe": finding.get("cwe_id", "CWE-942"),
        }

    @staticmethod
    def _poc_missing_header(finding: dict, target_url: str) -> dict[str, Any]:
        url = target_url or "https://example.com"
        header = finding.get("evidence", {}).get("missing_header", "")
        return {
            "poc_type": "missing_header",
            "title": f"Missing Header PoC: {finding.get('title', 'Missing security header')}",
            "command": f'curl -sI "{url}" | grep -i "{header}" || echo "CONFIRMED: {header} header is missing"',
            "html_poc": None,
            "description": f"Verify that the {header} header is absent from the response.",
            "severity": finding.get("severity", "medium"),
            "cwe": finding.get("cwe_id", "CWE-693"),
        }

    @staticmethod
    def _poc_cookie(finding: dict, target_url: str) -> dict[str, Any]:
        url = target_url or "https://example.com"
        cookie_name = finding.get("evidence", {}).get("cookie_name", "session")
        flag = "Secure" if "Secure" in finding.get("title", "") else "HttpOnly"
        return {
            "poc_type": "cookie",
            "title": f"Cookie PoC: {finding.get('title', 'Insecure cookie flag')}",
            "command": f'curl -sI "{url}" | grep -i "set-cookie" | grep -v "{flag}" || echo "CONFIRMED: Cookie missing {flag} flag"',
            "html_poc": None,
            "description": f"Verify cookie '{cookie_name}' is missing the {flag} flag.",
            "severity": finding.get("severity", "low"),
            "cwe": finding.get("cwe_id", "CWE-614"),
        }

    @staticmethod
    def _poc_injection(finding: dict, target_url: str) -> dict[str, Any]:
        form_action = finding.get("evidence", {}).get("form_action", finding.get("evidence", {}).get("url", target_url))
        return {
            "poc_type": "injection",
            "title": f"Injection PoC: {finding.get('title', 'Potential injection')}",
            "command": f'curl -s "{form_action}?q=%27%22%3Ctest%3E" | grep -i "test\\|error\\|sql\\|syntax"',
            "html_poc": None,
            "description": f"Send injection probes to {form_action} and check for error reflection.",
            "severity": finding.get("severity", "high"),
            "cwe": finding.get("cwe_id", "CWE-89"),
        }

    @staticmethod
    def _poc_info_disclosure(finding: dict, target_url: str) -> dict[str, Any]:
        header = finding.get("evidence", {}).get("header", finding.get("evidence", {}).get("missing_header", ""))
        url = target_url or "https://example.com"
        return {
            "poc_type": "info_disclosure",
            "title": f"Info Disclosure PoC: {finding.get('title', 'Information disclosure')}",
            "command": f'curl -sI "{url}" | grep -i "{header}" || echo "Header not present or empty"',
            "html_poc": None,
            "description": f"Verify that {header} header discloses sensitive information.",
            "severity": finding.get("severity", "low"),
            "cwe": finding.get("cwe_id", "CWE-200"),
        }

    @staticmethod
    def _poc_redirect(finding: dict, target_url: str) -> dict[str, Any]:
        url = target_url or "https://example.com"
        return {
            "poc_type": "redirect",
            "title": f"Open Redirect PoC: {finding.get('title', 'Open redirect')}",
            "command": f'curl -sI "{url}?redirect=https://evil.example.com" | grep -i "location.*evil"',
            "html_poc": None,
            "description": "Test if the application redirects to arbitrary URLs.",
            "severity": finding.get("severity", "medium"),
            "cwe": finding.get("cwe_id", "CWE-601"),
        }

    @staticmethod
    def _poc_auth(finding: dict, target_url: str) -> dict[str, Any]:
        url = finding.get("expected_location", finding.get("evidence", {}).get("page_url", target_url))
        return {
            "poc_type": "auth",
            "title": f"Auth PoC: {finding.get('title', 'Authentication issue')}",
            "command": f'curl -s "{url}" -o /dev/null -w "%{{http_code}}"  # Should return 401/403 if auth required',
            "html_poc": None,
            "description": f"Access {url} without authentication and check if sensitive data is returned.",
            "severity": finding.get("severity", "high"),
            "cwe": finding.get("cwe_id", "CWE-306"),
        }

    @staticmethod
    def _poc_upload(finding: dict, target_url: str) -> dict[str, Any]:
        url = finding.get("expected_location", target_url)
        return {
            "poc_type": "upload",
            "title": f"Upload PoC: {finding.get('title', 'File upload vulnerability')}",
            "command": f'curl -s -X POST -F "file=@test.txt" "{url}" -o /dev/null -w "%{{http_code}}"',
            "html_poc": None,
            "description": f"Attempt file upload to {url} and verify upload restrictions.",
            "severity": finding.get("severity", "high"),
            "cwe": finding.get("cwe_id", "CWE-434"),
        }

    @staticmethod
    def _poc_generic(finding: dict, target_url: str) -> dict[str, Any]:
        url = target_url or "https://example.com"
        return {
            "poc_type": "generic",
            "title": f"PoC: {finding.get('title', 'Security finding')}",
            "command": f'curl -sI "{url}" | head -20',
            "html_poc": None,
            "description": finding.get("description", "Verify the finding manually."),
            "severity": finding.get("severity", "info"),
            "cwe": finding.get("cwe_id", ""),
        }