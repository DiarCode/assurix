"""HTTP request interception, modification, and comparison for security testing."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class InterceptResult:
    url: str
    method: str
    original_status: int
    modified_status: int
    original_length: int
    modified_length: int
    original_time: float
    modified_time: float
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""


class RequestInterceptor:
    """Capture, modify, and compare HTTP requests for vulnerability detection."""

    def __init__(self, max_concurrent: int = 5, timeout: float = 10.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def compare_responses(self, base_url: str, modifications: list[dict]) -> list[InterceptResult]:
        """Compare baseline response with modified requests to detect anomalies."""
        results: list[InterceptResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            import time
            start = time.monotonic()
            baseline = await self._request(client, "GET", base_url)
            baseline_time = time.monotonic() - start
            if not baseline:
                return results
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
            baseline_status = baseline.status_code

            for mod in modifications:
                start = time.monotonic()
                resp = await self._request(client, mod.get("method", "GET"),
                                           mod.get("url", base_url),
                                           headers=mod.get("headers"),
                                           json=mod.get("json"),
                                           content=mod.get("content"),
                                           cookies=mod.get("cookies"))
                elapsed = time.monotonic() - start
                if not resp:
                    continue
                mod_len = len(resp.text)
                status_diff = resp.status_code != baseline_status
                length_diff = abs(mod_len - baseline_len)
                time_diff = abs(elapsed - baseline_time)
                finding = None
                severity = "info"
                if status_diff:
                    finding = f"Status changed: {baseline_status} -> {resp.status_code}"
                    severity = "medium"
                elif length_diff > baseline_len * 0.5:
                    finding = f"Response length changed significantly: {baseline_len}B -> {mod_len}B"
                    severity = "low"
                elif time_diff > 3.0:
                    finding = f"Response time changed: {baseline_time:.2f}s -> {elapsed:.2f}s (possible injection)"
                    severity = "medium"
                if finding:
                    results.append(InterceptResult(
                        url=mod.get("url", base_url), method=mod.get("method", "GET"),
                        original_status=baseline_status, modified_status=resp.status_code,
                        original_length=baseline_len, modified_length=mod_len,
                        original_time=baseline_time, modified_time=elapsed,
                        finding=finding, severity=severity,
                        evidence=mod.get("description", str(mod.get("headers", "")))[:200],
                    ))
        return results

    async def test_header_manipulation(self, url: str) -> list[InterceptResult]:
        """Test authorization bypass via header manipulation."""
        modifications = [
            {"headers": {"X-Forwarded-For": "127.0.0.1"}, "description": "X-Forwarded-For bypass"},
            {"headers": {"X-Original-URL": "/admin"}, "description": "X-Original-URL bypass"},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}, "description": "Custom IP auth bypass"},
            {"headers": {"X-Forwarded-Host": "localhost"}, "description": "X-Forwarded-Host bypass"},
            {"headers": {"X-Rewrite-URL": "/admin"}, "description": "X-Rewrite-URL bypass"},
            {"headers": {"Authorization": "Bearer admin"}, "description": "Bearer token bypass"},
            {"headers": {"Cookie": "role=admin; is_admin=1"}, "description": "Cookie role bypass"},
            {"method": "PUT"}, {"method": "DELETE"}, {"method": "PATCH"},
            {"method": "OPTIONS"}, {"method": "TRACE"},
        ]
        return await self.compare_responses(url, modifications)

    async def test_cookie_manipulation(self, url: str, cookies: dict) -> list[InterceptResult]:
        """Test session manipulation via cookie changes."""
        modifications = []
        session_cookies = ["session", "sessionid", "PHPSESSID", "JSESSIONID", "connect.sid", "_sid", "token"]
        for cookie_name in session_cookies:
            for value in ["admin", "1", "true", "administrator", "root"]:
                test_cookies = {**cookies, cookie_name: value}
                modifications.append({"cookies": test_cookies, "description": f"Cookie {cookie_name}={value}"})
        return await self.compare_responses(url, modifications)

    async def test_token_substitution(self, url: str, token_name: str = "Authorization") -> list[InterceptResult]:
        """Test token substitution attacks."""
        fake_tokens = [
            "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.sig",
            "Basic YWRtaW46YWRtaW4=",
            "admin",
            "1",
            "true",
        ]
        modifications = [{"headers": {token_name: token}, "description": f"Token: {token[:50]}"} for token in fake_tokens]
        return await self.compare_responses(url, modifications)

    async def test_method_override(self, url: str) -> list[InterceptResult]:
        """Test HTTP method override attacks."""
        modifications = [
            {"headers": {"X-HTTP-Method-Override": "PUT"}, "description": "Method override: PUT"},
            {"headers": {"X-HTTP-Method-Override": "DELETE"}, "description": "Method override: DELETE"},
            {"headers": {"X-HTTP-Method-Override": "PATCH"}, "description": "Method override: PATCH"},
            {"method": "POST", "headers": {"X-Method-Override": "DELETE"}, "content": b"", "description": "POST with DELETE override"},
        ]
        return await self.compare_responses(url, modifications)
