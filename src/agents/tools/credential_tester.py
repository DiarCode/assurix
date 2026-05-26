"""LLM-guided credential testing on discovered login pages.

Analyzes login form structure, establishes baselines with known-invalid
credentials, tests technology-specific defaults, and validates successful
logins against protected resources.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# Technology-specific default credentials
TECH_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "wordpress": [("admin", "admin"), ("admin", "password"), ("admin", "wordpress"), ("admin", "admin123")],
    "apache": [("admin", "admin"), ("admin", "apache"), ("root", "root")],
    "nginx": [("admin", "admin"), ("root", "root"), ("nginx", "nginx")],
    "tomcat": [("admin", "admin"), ("tomcat", "tomcat"), ("admin", "tomcat")],
    "jenkins": [("admin", "admin"), ("admin", "jenkins"), ("admin", "password")],
    "django": [("admin", "admin"), ("admin", "password123")],
    "flask": [("admin", "admin"), ("admin", "secret")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("admin", "admin"), ("pma", "pma")],
    "grafana": [("admin", "admin"), ("admin", "grafana")],
    "elastic": [("elastic", "elastic"), ("elastic", "changeme")],
    "redis": [("", ""), ("default", "")],
    "gitlab": [("root", "root"), ("admin", "admin")],
    "jira": [("admin", "admin"), ("admin", "password")],
}

COMMON_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "letmein"), ("admin", "welcome"),
    ("root", "root"), ("root", "password"), ("root", "toor"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("administrator", "administrator"), ("operator", "operator"),
]

LOGIN_FORM_INDICATORS = [
    '<form', 'type="password"', 'type="email"', 'name="password"',
    'name="username"', 'name="email"', 'name="login"',
    'name="user"', 'id="password"', 'id="username"',
]

PROTECTED_PATHS = ["/admin", "/dashboard", "/api/me", "/api/profile", "/account"]


@dataclass
class CredentialResult:
    url: str
    test_type: str
    severity: str
    finding: str | None = None
    evidence: str = ""
    username: str = ""
    password: str = ""
    is_valid: bool = False


class CredentialTester:
    """LLM-guided credential testing on discovered login pages."""

    def __init__(self, max_concurrent: int = 3, timeout: float = 10.0, rate_rps: float = 2.0) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self._delay = 1.0 / rate_rps if rate_rps > 0 else 0

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            if self._delay:
                await asyncio.sleep(self._delay + random.uniform(0, 0.5))  # jitter
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=True, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    def _analyze_login_form(self, html: str) -> dict | None:
        """Extract login form structure from HTML."""
        html_lower = html.lower()
        if not any(ind in html_lower for ind in LOGIN_FORM_INDICATORS):
            return None

        action = "/"
        if 'action="' in html_lower:
            start = html_lower.index('action="') + 8
            end = html_lower.index('"', start)
            action = html[start:end]

        fields: dict[str, str] = {}
        for field_type, patterns in [
            ("username", ['name="username"', 'name="email"', 'name="login"', 'name="user"', 'id="username"', 'id="email"']),
            ("password", ['name="password"', 'name="passwd"', 'name="pass"', 'id="password"', 'id="passwd"']),
            ("csrf", ['name="csrf"', 'name="_token"', 'name="authenticity_token"', 'name="csrfmiddlewaretoken"']),
        ]:
            for pattern in patterns:
                if pattern in html_lower:
                    idx = html_lower.index(pattern)
                    val_start = html_lower.find('value="', idx)
                    if val_start != -1 and val_start - idx < 100:
                        val_end = html_lower.index('"', val_start + 7)
                        fields[field_type] = html[val_start + 7:val_end]
                    else:
                        name_start = html_lower.find('name="', idx)
                        if name_start != -1 and name_start - idx < 50:
                            name_end = html_lower.index('"', name_start + 6)
                            fields[field_type] = html[name_start + 6:name_end]
                    break

        return {
            "action": action,
            "fields": fields,
            "has_csrf": "csrf" in fields,
        }

    async def _establish_baseline(
        self, client: httpx.AsyncClient, login_url: str, form_info: dict,
    ) -> dict:
        """Send known-invalid credentials to establish response baseline."""
        username_field = form_info.get("fields", {}).get("username", "username")
        password_field = form_info.get("fields", {}).get("password", "password")

        data = {
            username_field: "assurix_invalid_user_98765",
            password_field: "assurix_invalid_pass_98765",
        }

        # Get CSRF token from login page
        get_resp = await self._request(client, "GET", login_url)
        if get_resp and get_resp.status_code == 200:
            page_text = get_resp.text.lower()
            for token_name in ['name="csrfmiddlewaretoken"', 'name="_token"', 'name="authenticity_token"', 'name="csrf"']:
                if token_name in page_text:
                    idx = page_text.index(token_name)
                    val_start = page_text.find('value="', idx)
                    if val_start != -1 and val_start - idx < 150:
                        val_end = page_text.index('"', val_start + 7)
                        data[token_name.split('"')[1]] = get_resp.text[val_start + 7:val_end]
                        break

        resp = await self._request(client, "POST", login_url, data=data)
        if resp is None:
            return {"status": 0, "body_length": 0, "text": "", "headers": {}}

        return {
            "status": resp.status_code,
            "body_length": len(resp.text),
            "text": resp.text[:1000],
            "headers": dict(resp.headers),
        }

    def _is_login_success(self, resp: httpx.Response | None, baseline: dict) -> bool:
        """Determine if a login attempt succeeded by comparing to baseline."""
        if resp is None:
            return False
        if resp.status_code != baseline.get("status", 0):
            if resp.status_code == 200 and baseline.get("status", 0) in (401, 403):
                return True
            if resp.status_code in (302, 303) and baseline.get("status", 0) not in (302, 303):
                return True
        if resp.status_code == baseline.get("status", 0):
            if abs(len(resp.text) - baseline.get("body_length", 0)) > 500:
                body_lower = resp.text.lower()
                success_indicators = ["welcome", "dashboard", "logout", "sign out", "my account", "profile"]
                return any(ind in body_lower for ind in success_indicators)
        return False

    async def test_credentials(
        self, base_url: str, login_paths: list[str] | None = None,
        technologies: list[str] | None = None,
    ) -> list[CredentialResult]:
        """Test default and common credentials on discovered login pages."""
        results: list[CredentialResult] = []

        async with httpx.AsyncClient(verify=False) as client:
            if login_paths is None:
                login_paths = ["/login", "/signin", "/auth/login", "/admin/login", "/api/login"]

            discovered_forms: list[tuple[str, dict]] = []

            for path in login_paths:
                url = urljoin(base_url, path.lstrip("/"))
                resp = await self._request(client, "GET", url)
                if resp and resp.status_code == 200:
                    form_info = self._analyze_login_form(resp.text)
                    if form_info:
                        discovered_forms.append((url, form_info))
                        results.append(CredentialResult(
                            url=url, test_type="login_discovery",
                            severity="info",
                            finding=f"Login form discovered at {path}",
                            evidence=f"Form action: {form_info['action']}, Fields: {list(form_info['fields'].keys())}, CSRF: {form_info['has_csrf']}",
                        ))

            for login_url, form_info in discovered_forms:
                baseline = await self._establish_baseline(client, login_url, form_info)

                # Build credential list: tech-specific + common
                creds_to_test: list[tuple[str, str]] = []
                if technologies:
                    for tech in technologies:
                        tech_lower = tech.lower()
                        for key in TECH_DEFAULTS:
                            if key in tech_lower:
                                creds_to_test.extend(TECH_DEFAULTS[key])
                creds_to_test.extend(COMMON_CREDENTIALS)
                seen_creds: set[tuple[str, str]] = set()
                unique_creds: list[tuple[str, str]] = []
                for c in creds_to_test:
                    if c not in seen_creds:
                        seen_creds.add(c)
                        unique_creds.append(c)

                username_field = form_info.get("fields", {}).get("username", "username")
                password_field = form_info.get("fields", {}).get("password", "password")

                for username, password in unique_creds[:20]:
                    data = {username_field: username, password_field: password}

                    # Re-fetch CSRF token
                    get_resp = await self._request(client, "GET", login_url)
                    if get_resp and get_resp.status_code == 200:
                        page_text = get_resp.text.lower()
                        for token_name in ['name="csrfmiddlewaretoken"', 'name="_token"', 'name="authenticity_token"', 'name="csrf"']:
                            if token_name in page_text:
                                idx = page_text.index(token_name)
                                val_start = page_text.find('value="', idx)
                                if val_start != -1 and val_start - idx < 150:
                                    val_end = page_text.index('"', val_start + 7)
                                    data[token_name.split('"')[1]] = get_resp.text[val_start + 7:val_end]
                                break

                    resp = await self._request(client, "POST", login_url, data=data)
                    if resp is None:
                        continue

                    # Rate limiting / lockout detection
                    if resp.status_code == 429:
                        results.append(CredentialResult(
                            url=login_url, test_type="rate_limit",
                            severity="info",
                            finding="Rate limiting detected — stopping credential tests",
                            evidence=f"HTTP 429 after testing {username}",
                        ))
                        break
                    if resp.status_code == 403 and "lock" in resp.text.lower():
                        results.append(CredentialResult(
                            url=login_url, test_type="lockout",
                            severity="info",
                            finding="Account lockout detected — stopping credential tests",
                            evidence=f"Lockout response after testing {username}",
                        ))
                        break

                    if self._is_login_success(resp, baseline):
                        # Validate against protected resource
                        valid = False
                        for prot_path in PROTECTED_PATHS[:2]:
                            prot_url = urljoin(base_url, prot_path.lstrip("/"))
                            prot_resp = await self._request(client, "GET", prot_url)
                            if prot_resp and prot_resp.status_code == 200:
                                valid = True
                                break

                        results.append(CredentialResult(
                            url=login_url, test_type="credential_test",
                            severity="critical" if valid else "high",
                            finding=f"Valid credentials found: {username}:{password[:2]}***",
                            evidence=f"Login succeeded with {username} (validated: {valid})",
                            username=username, password=password, is_valid=True,
                        ))
                        break

        return results