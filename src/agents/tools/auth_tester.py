"""Authentication testing: login automation, JWT analysis, session testing, IDOR, privilege escalation."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login", "/auth", "/admin/login",
]
PRIVILEGE_PATHS = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/api/admin", "/api/users", "/api/config", "/api/settings",
    "/dashboard", "/profile", "/account", "/me", "/api/me", "/api/profile",
]


@dataclass
class AuthResult:
    test: str
    url: str
    severity: str
    finding: str | None = None
    evidence: str = ""


class AuthTester:
    """Automated authentication security testing."""

    def __init__(self, max_concurrent: int = 5, timeout: float = 10.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout

    async def _request(self, client, method, url, **kwargs):
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=True, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def discover_login_pages(self, base_url: str) -> list[AuthResult]:
        results: list[AuthResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            for path in COMMON_LOGIN_PATHS:
                url = urljoin(base_url, path)
                resp = await self._request(client, "GET", url)
                if not resp or resp.status_code != 200:
                    continue
                body = resp.text.lower()
                has_form = "<form" in body and "password" in body
                results.append(AuthResult(
                    test="login_discovery", url=url, severity="info",
                    finding=f"Login page found at {path}" + (" (has form)" if has_form else ""),
                    evidence=f"Status: {resp.status_code}, Has form: {has_form}",
                ))
        return results

    async def test_jwt_vulnerabilities(self, token: str) -> list[AuthResult]:
        results: list[AuthResult] = []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return results
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            if header.get("alg", "").lower() == "none":
                results.append(AuthResult(
                    test="jwt_none_algorithm", url="", severity="critical",
                    finding="JWT uses none algorithm - signature bypass possible",
                    evidence=f"Header: {json.dumps(header)}",
                ))
            if header.get("alg") == "HS256" and "kid" not in header:
                results.append(AuthResult(
                    test="jwt_algorithm_confusion", url="", severity="high",
                    finding="JWT HS256 without kid - algorithm confusion risk",
                    evidence=f"Header: {json.dumps(header)}",
                ))
            if "exp" not in payload:
                results.append(AuthResult(
                    test="jwt_no_expiry", url="", severity="medium",
                    finding="JWT has no expiration claim - may be valid indefinitely",
                    evidence=f"Claims: {list(payload.keys())}",
                ))
            role = payload.get("role", "")
            if role in ("admin", "administrator", "root", "superuser"):
                results.append(AuthResult(
                    test="jwt_admin_claim", url="", severity="medium",
                    finding=f"JWT contains admin role: {role}",
                    evidence=f"Role: {role}",
                ))
        except Exception:
            pass
        return results

    async def test_auth_bypass(self, base_url: str) -> list[AuthResult]:
        results: list[AuthResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            for path in PRIVILEGE_PATHS:
                url = urljoin(base_url, path)
                for hdrs in [{}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Original-URL": "/admin"}, {"Cookie": "role=admin"}]:
                    resp = await self._request(client, "GET", url, headers=hdrs)
                    if not resp or resp.status_code != 200:
                        continue
                    body = resp.text.lower()[:500]
                    if any(kw in body for kw in ("admin", "dashboard", "manage", "settings", "users")):
                        hdr_desc = str(hdrs) if hdrs else "no auth"
                        results.append(AuthResult(
                            test="auth_bypass", url=url, severity="high",
                            finding=f"Protected endpoint accessible: {path} ({hdr_desc})",
                            evidence=f"Status: {resp.status_code}",
                        ))
                        break
        return results

    async def test_idor(self, base_url: str, auth_cookies: dict | None = None) -> list[AuthResult]:
        results: list[AuthResult] = []
        idor_paths = ["/api/users/1", "/api/users/2", "/api/accounts/1", "/api/profile/1", "/user/1", "/profile/1"]
        async with httpx.AsyncClient(verify=False, cookies=auth_cookies) as client:
            for path in idor_paths:
                url = urljoin(base_url, path)
                resp = await self._request(client, "GET", url)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    results.append(AuthResult(
                        test="idor", url=url, severity="medium",
                        finding=f"Possible IDOR: {path} accessible without authorization",
                        evidence=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                    ))
        return results