"""IDOR validation with multi-account differential testing and SPA-aware discrimination.

Replaces the basic test_idor() in AuthTester with BACScan-style feedback-driven
oracle approach that distinguishes real IDOR from SPA catch-alls and login redirects.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from .response_dedup import ResponseDeduplicator

logger = logging.getLogger(__name__)

IDOR_TEST_PATHS = [
    "/api/users/1", "/api/users/2", "/api/users/9999",
    "/api/accounts/1", "/api/accounts/2",
    "/api/profile/1", "/api/profile/2",
    "/user/1", "/user/2",
    "/profile/1", "/profile/2",
    "/api/v1/users/1", "/api/v1/users/2",
    "/api/v2/users/1", "/api/v2/users/2",
]

SPA_INDICATORS = [
    '<div id="root">', '<div id="app">', '<div id="__next">',
    '<div id="__nuxt">', '<div id="app-root">',
    'ng-app', 'ng-controller', 'data-reactroot',
    'window.__INITIAL_STATE__', 'window.__NUXT__',
    '<script id="__NEXT_DATA__"',
]

LOGIN_INDICATORS = [
    'login', 'signin', 'sign-in', 'password', 'auth/login',
    '/login', '/signin', '/auth',
]


@dataclass
class IDORResult:
    url: str
    severity: str
    finding: str | None = None
    evidence: str = ""
    confidence: float = 0.0
    is_real_idor: bool = False


class IDORValidator:
    """Multi-account differential IDOR testing with SPA-aware discrimination."""

    def __init__(self, max_concurrent: int = 5, timeout: float = 10.0) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.dedup = ResponseDeduplicator()

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    def _is_spa_shell(self, body: str) -> bool:
        """Check if response is an SPA catch-all shell (not real data)."""
        body_lower = body.lower()
        return any(indicator.lower() in body_lower for indicator in SPA_INDICATORS)

    def _is_login_page(self, body: str, status_code: int, headers: httpx.Headers) -> bool:
        """Check if response is a login page or auth redirect."""
        if status_code in (301, 302, 303, 307, 308):
            location = headers.get("location", "").lower()
            return any(ind in location for ind in LOGIN_INDICATORS)
        if status_code == 401:
            return True
        body_lower = body.lower()
        return (
            "<form" in body_lower
            and any(ind in body_lower for ind in ("password", "signin", "sign-in", "login"))
        )

    def _is_json_user_data(self, body: str, status_code: int) -> bool:
        """Check if response appears to be real user data (JSON with user fields)."""
        if status_code != 200:
            return False
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                user_fields = {"id", "email", "username", "name", "phone", "user_id", "user"}
                return bool(set(str(k).lower() for k in data.keys()) & user_fields)
            if isinstance(data, list) and data:
                first = data[0]
                if isinstance(first, dict):
                    return bool(set(str(k).lower() for k in first.keys()) & user_fields)
        except (json.JSONDecodeError, TypeError):
            pass
        return False

    async def _collect_responses(
        self, client: httpx.AsyncClient, base_url: str, paths: list[str],
        cookies: dict | None = None,
    ) -> dict[str, httpx.Response | None]:
        """Probe multiple IDOR paths and collect responses."""
        results: dict[str, httpx.Response | None] = {}
        for path in paths:
            url = urljoin(base_url, path)
            resp = await self._request(client, "GET", url, cookies=cookies)
            results[path] = resp
        return results

    def _analyze_responses(
        self, responses: dict[str, httpx.Response | None], base_url: str,
    ) -> list[IDORResult]:
        """Analyze collected responses to identify real IDOR vs false positives."""
        results: list[IDORResult] = []
        baseline_body = ""
        baseline_len = 0

        # Establish baseline from first successful response
        for path, resp in responses.items():
            if resp and resp.status_code == 200:
                baseline_body = resp.text
                baseline_len = len(baseline_body)
                break

        for path, resp in responses.items():
            if resp is None:
                continue
            url = urljoin(base_url, path)

            if resp.status_code == 200:
                result = self._check_200_response(resp, url, path, baseline_body, baseline_len)
                if result:
                    results.append(result)
            elif resp.status_code in (301, 302, 303, 307, 308):
                result = self._check_redirect_response(resp, url, path)
                if result:
                    results.append(result)

        return results

    def _check_200_response(
        self, resp: httpx.Response, url: str, path: str,
        baseline_body: str, baseline_len: int,
    ) -> IDORResult | None:
        """Classify a 200 response: real IDOR, SPA shell, or login page."""
        body = resp.text
        headers = resp.headers

        # Tier 1: Login redirect disguised as 200
        if self._is_login_page(body, 200, headers):
            return IDORResult(
                url=url, severity="info",
                finding=f"IDOR false positive: {path} returns login page",
                evidence=f"Response contains login form, not user data",
                confidence=0.9, is_real_idor=False,
            )

        # Tier 2: SPA catch-all shell
        if self._is_spa_shell(body):
            # Compare body length to baseline — if similar, it's the same SPA page
            body_len = len(body)
            if baseline_len > 0 and abs(body_len - baseline_len) < baseline_len * 0.05:
                return IDORResult(
                    url=url, severity="info",
                    finding=f"IDOR false positive: {path} returns SPA catch-all",
                    evidence=f"SPA shell response (length {body_len} ~= baseline {baseline_len})",
                    confidence=0.85, is_real_idor=False,
                )
            # Even if different length, SPA shell is suspicious
            if self.dedup.is_soft_404(url, body, url, baseline_body):
                return IDORResult(
                    url=url, severity="info",
                    finding=f"IDOR false positive: {path} returns SPA shell (simhash match)",
                    evidence="SimHash similarity indicates SPA catch-all",
                    confidence=0.8, is_real_idor=False,
                )

        # Tier 3: JSON with user data — likely real IDOR
        if self._is_json_user_data(body, 200):
            return IDORResult(
                url=url, severity="high",
                finding=f"IDOR confirmed: {path} returns user-specific JSON data",
                evidence=f"JSON response with user fields (status 200, no auth required)",
                confidence=0.9, is_real_idor=True,
            )

        # Tier 4: HTML with different content from baseline
        if baseline_len > 0 and abs(len(body) - baseline_len) > baseline_len * 0.3:
            return IDORResult(
                url=url, severity="medium",
                finding=f"Possible IDOR: {path} returns distinct content",
                evidence=f"Body length {len(body)} significantly differs from baseline {baseline_len}",
                confidence=0.5, is_real_idor=False,
            )

        return None

    def _check_redirect_response(
        self, resp: httpx.Response, url: str, path: str,
    ) -> IDORResult | None:
        """Classify a redirect response: auth gate vs real IDOR redirect."""
        location = resp.headers.get("location", "").lower()

        # Login redirect = auth gate, not IDOR
        if any(ind in location for ind in LOGIN_INDICATORS):
            return IDORResult(
                url=url, severity="info",
                finding=f"IDOR false positive: {path} redirects to login",
                evidence=f"302 -> {resp.headers.get('location', '')}",
                confidence=0.9, is_real_idor=False,
            )

        # Redirect to different user page could be IDOR
        if "/user" in location or "/profile" in location or "/account" in location:
            return IDORResult(
                url=url, severity="low",
                finding=f"Possible IDOR: {path} redirects to user page",
                evidence=f"302 -> {resp.headers.get('location', '')}",
                confidence=0.4, is_real_idor=False,
            )

        return None

    async def validate_idor(
        self, base_url: str, auth_cookies: dict | None = None,
        extra_paths: list[str] | None = None,
    ) -> list[IDORResult]:
        """Run full IDOR validation with SPA-aware discrimination.

        Args:
            base_url: The target base URL.
            auth_cookies: Optional authenticated session cookies for multi-account testing.
            extra_paths: Additional IDOR paths to test beyond defaults.

        Returns:
            List of IDORResult with is_real_idor flag distinguishing true positives.
        """
        paths = list(IDOR_TEST_PATHS)
        if extra_paths:
            paths.extend(extra_paths)

        results: list[IDORResult] = []

        # Phase 1: Unauthenticated testing
        async with httpx.AsyncClient(verify=False) as client:
            responses = await self._collect_responses(client, base_url, paths)
            results.extend(self._analyze_responses(responses, base_url))

        # Phase 2: Authenticated testing (if cookies available)
        if auth_cookies:
            async with httpx.AsyncClient(verify=False, cookies=auth_cookies) as client:
                responses = await self._collect_responses(client, base_url, paths, cookies=auth_cookies)
                auth_results = self._analyze_responses(responses, base_url)
                # Compare authenticated vs unauthenticated for differential testing
                for ar in auth_results:
                    if ar.is_real_idor:
                        results.append(ar)

        # Filter: only report real IDOR or notable false positives
        reported: list[IDORResult] = []
        seen_urls: set[str] = set()
        for r in results:
            if r.url not in seen_urls:
                seen_urls.add(r.url)
                reported.append(r)

        return reported