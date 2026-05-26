"""Parameter, directory, and content fuzzing for offensive security testing."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx

from .payload_generator import PayloadGenerator, Payload

logger = logging.getLogger(__name__)

COMMON_PATHS = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "graphql",
    "swagger", "swagger-ui", "api-docs", "docs", "redoc", "openapi.json",
    ".env", ".git", ".git/config", ".svn", ".DS_Store", "web.config",
    "robots.txt", "sitemap.xml", "favicon.ico", "crossdomain.xml",
    "wp-admin", "wp-login.php", "wp-json", "xmlrpc.php",
    "config", "config.json", "config.yml", "config.yaml", "settings.py",
    "debug", "trace", "profiler", "actuator", "actuator/health", "actuator/env",
    "phpinfo.php", "info.php", "server-status", "server-info",
    ".well-known/security.txt", "security.txt",
    "backup", "db", "database", "sql", "dump", "export",
    "uploads", "files", "media", "static", "assets", "public",
    "console", "shell", "terminal", "cmd", "exec",
    "test", "demo", "staging", "dev",
    "user", "users", "account", "profile", "me",
    "search", "query", "filter", "sort",
    "auth", "oauth", "token", "verify",
    "password", "reset", "forgot", "change",
    "upload", "import", "download", "export", "report",
    "webhook", "callback", "notify", "event",
]

COMMON_PARAMS = [
    "id", "user_id", "uid", "uuid", "key", "token", "session",
    "page", "limit", "offset", "sort", "order", "filter", "q", "query", "search",
    "redirect", "url", "next", "return", "callback", "ref",
    "file", "path", "dir", "document", "attachment",
    "action", "method", "type", "format", "view",
    "debug", "test", "admin", "role", "permission",
    "email", "username", "name", "phone",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

FUZZ_HEADERS = {
    "X-Forwarded-For": ["127.0.0.1", "0.0.0.0", "localhost"],
    "X-Original-URL": ["/admin", "/dashboard", "/api/admin"],
    "X-Rewrite-URL": ["/admin", "/dashboard"],
    "X-Custom-IP-Authorization": ["127.0.0.1"],
    "X-Forwarded-Host": ["localhost", "127.0.0.1"],
    "X-HTTP-Method-Override": ["PUT", "DELETE", "PATCH"],
}


@dataclass
class FuzzResult:
    url: str
    method: str
    status_code: int
    body_length: int
    response_time: float
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""


class Fuzzer:
    """High-performance async fuzzer for parameter and content discovery."""

    # Similarity threshold: if a response body is this similar to the baseline, it's a soft-404
    SOFT_404_LENGTH_THRESHOLD = 0.05  # 5% body length difference = same page
    SOFT_404_HASH_THRESHOLD = 0.85    # 85% content similarity = same page

    def __init__(self, max_concurrent: int = 10, timeout: float = 10.0, rate_rps: float = 20.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.rate_rps = rate_rps
        self.payload_gen = PayloadGenerator()
        self._delay = 1.0 / rate_rps if rate_rps > 0 else 0

    def _is_soft_404(self, resp: httpx.Response, baseline_body: str, baseline_len: int) -> bool:
        """Detect catch-all responses (SPAs, custom 404s returning 200)."""
        if not resp or resp.status_code != 200:
            return False
        body = resp.text
        body_len = len(body)
        # If body length is within 5% of baseline, it's almost certainly the same page
        if baseline_len > 0 and abs(body_len - baseline_len) / baseline_len < self.SOFT_404_LENGTH_THRESHOLD:
            return True
        # Quick content similarity: check if first 500 chars match baseline
        if baseline_len > 0 and body[:500] == baseline_body[:500]:
            return True
        return False

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            if self._delay:
                await asyncio.sleep(self._delay)
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def fuzz_parameters(self, base_url: str, existing_params: dict | None = None, categories: list[str] | None = None) -> list[FuzzResult]:
        """Inject payloads into URL parameters to find injection vulnerabilities."""
        categories = categories or ["xss", "sqli", "ssrf"]
        results: list[FuzzResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            if not baseline:
                return results
            baseline_body = baseline.text
            baseline_len = len(baseline_body)

            params_to_test = existing_params or {p: "test" for p in COMMON_PARAMS[:20]}
            for category in categories:
                payloads = self.payload_gen.get_payloads(category, limit=5)
                for param, orig_value in params_to_test.items():
                    for payload in payloads:
                        qs = parse_qs(urlparse(base_url).query)
                        qs[param] = [payload.value]
                        parsed = urlparse(base_url)
                        new_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(qs, doseq=True), parsed.fragment,
                        ))
                        start = time.monotonic()
                        resp = await self._request(client, "GET", new_url)
                        elapsed = time.monotonic() - start
                        if not resp:
                            continue
                        finding = self._analyze_response(resp, baseline_body, baseline_len, payload)
                        if finding:
                            results.append(FuzzResult(
                                url=new_url, method="GET", status_code=resp.status_code,
                                body_length=len(resp.text), response_time=elapsed,
                                finding=finding, severity=payload.severity,
                                evidence=f"Payload: {payload.value[:80]} | Response: {resp.text[:200]}",
                            ))
        return results

    async def fuzz_directory(self, base_url: str, wordlist: list[str] | None = None) -> list[FuzzResult]:
        """Discover hidden directories and files, with soft-404 detection."""
        paths = wordlist or COMMON_PATHS
        results: list[FuzzResult] = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False) as client:
            # Get baseline response for soft-404 detection
            baseline = await self._request(client, "GET", base + "/")
            baseline_body = baseline.text if baseline else ""
            baseline_len = len(baseline_body) if baseline else 0

            for path in paths:
                url = urljoin(base + "/", path.lstrip("/"))
                resp = await self._request(client, "GET", url)
                if not resp:
                    continue
                if resp.status_code == 200:
                    # Skip soft 404s (catch-all responses)
                    if self._is_soft_404(resp, baseline_body, baseline_len):
                        continue
                    finding = None
                    if any(kw in path.lower() for kw in (".env", ".git", "config", "debug", "sql", "dump")):
                        finding = f"Sensitive path discovered: {path}"
                    elif "admin" in path.lower():
                        finding = f"Admin endpoint accessible: {path}"
                    results.append(FuzzResult(
                        url=url, method="GET", status_code=resp.status_code,
                        body_length=len(resp.text), response_time=0,
                        finding=finding, severity="medium" if finding else "info",
                        evidence=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                    ))
                elif resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    results.append(FuzzResult(
                        url=url, method="GET", status_code=resp.status_code,
                        body_length=0, response_time=0,
                        finding=f"Redirect at {path} -> {location[:80]}", severity="info",
                        evidence=f"Location: {location}",
                    ))
                elif resp.status_code == 403:
                    results.append(FuzzResult(
                        url=url, method="GET", status_code=403,
                        body_length=0, response_time=0,
                        finding=f"Forbidden endpoint: {path}", severity="low",
                        evidence="403 Forbidden — may be bypassable",
                    ))
                elif resp.status_code == 401:
                    results.append(FuzzResult(
                        url=url, method="GET", status_code=401,
                        body_length=0, response_time=0,
                        finding=f"Auth-required endpoint: {path}", severity="low",
                        evidence="401 Unauthorized — test for auth bypass",
                    ))
        return results

    async def fuzz_http_methods(self, url: str) -> list[FuzzResult]:
        """Test HTTP method override and uncommon methods."""
        results: list[FuzzResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", url)
            if not baseline:
                return results
            for method in HTTP_METHODS:
                resp = await self._request(client, method, url)
                if not resp:
                    continue
                if resp.status_code != baseline.status_code and resp.status_code not in (405, 501):
                    results.append(FuzzResult(
                        url=url, method=method, status_code=resp.status_code,
                        body_length=len(resp.text), response_time=0,
                        finding=f"Method {method} returned {resp.status_code} (baseline: {baseline.status_code})",
                        severity="medium",
                        evidence=f"{method} {url} -> {resp.status_code}",
                    ))
            for header, values in FUZZ_HEADERS.items():
                for value in values:
                    resp = await self._request(client, "GET", url, headers={header: value})
                    if not resp:
                        continue
                    if resp.status_code != baseline.status_code:
                        results.append(FuzzResult(
                            url=url, method="GET", status_code=resp.status_code,
                            body_length=len(resp.text), response_time=0,
                            finding=f"Header {header}: {value} changed status from {baseline.status_code} to {resp.status_code}",
                            severity="high",
                            evidence=f"{header}: {value} -> {resp.status_code}",
                        ))
        return results

    async def fuzz_content_type(self, url: str, body: dict | None = None) -> list[FuzzResult]:
        """Test different content types for the same request body."""
        import json as _json
        results: list[FuzzResult] = []
        body = body or {"username": "test", "password": "test"}
        content_types = [
            ("application/json", lambda b: _json.dumps(b)),
            ("application/x-www-form-urlencoded", lambda b: urlencode(b)),
            ("application/xml", lambda b: f"<root>{''.join(f'<{k}>{v}</{k}>' for k,v in b.items())}</root>"),
        ]
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "POST", url, json=body)
            if not baseline:
                return results
            for ct, encoder in content_types:
                try:
                    encoded_body = encoder(body)
                    resp = await self._request(client, "POST", url, content=encoded_body, headers={"Content-Type": ct})
                except Exception:
                    continue
                if not resp:
                    continue
                if resp.status_code != baseline.status_code or abs(len(resp.text) - len(baseline.text)) > 100:
                    results.append(FuzzResult(
                        url=url, method="POST", status_code=resp.status_code,
                        body_length=len(resp.text), response_time=0,
                        finding=f"Content-Type {ct} produced different response",
                        severity="medium",
                        evidence=f"CT: {ct} -> {resp.status_code} ({len(resp.text)}B vs baseline {len(baseline.text)}B)",
                    ))
        return results

    def _analyze_response(self, resp: httpx.Response, baseline_body: str, baseline_len: int, payload: Payload) -> str | None:
        """Check if a fuzzed response indicates a vulnerability."""
        body = resp.text
        if payload.detection and payload.detection in body:
            return f"{payload.description} — payload reflected/triggered in response"
        if resp.status_code == 500:
            return f"Server error with {payload.category} payload — possible {payload.description}"
        if len(body) > 0 and abs(len(body) - baseline_len) > baseline_len * 0.5:
            return f"Significant response length change with {payload.category} payload"
        if payload.category == "sqli" and any(err in body.lower() for err in ("sql syntax", "mysql", "postgresql", "sqlite", "ora-", "odbc")):
            return f"SQL error detected — possible {payload.description}"
        if payload.category == "path_traversal" and ("root:" in body or "[extensions]" in body):
            return f"Path traversal successful — {payload.description}"
        if payload.category == "cmdi" and ("uid=" in body or "root" in body.lower()[:100]):
            return f"Command injection detected — {payload.description}"
        return None

    async def fuzz_post_body(self, base_url: str, endpoints: list[str] | None = None) -> list[FuzzResult]:
        """Fuzz POST body parameters for injection vulnerabilities."""
        results: list[FuzzResult] = []
        targets = endpoints or ["/", "/login", "/api/v1/users", "/search", "/api/login"]
        async with httpx.AsyncClient(verify=False) as client:
            for endpoint in targets:
                url = urljoin(base_url, endpoint.lstrip("/"))
                baseline = await self._request(client, "POST", url, data={"test": "value"})
                if not baseline:
                    continue
                baseline_body = baseline.text
                baseline_len = len(baseline_body)
                for category in ["xss", "sqli", "cmdi"]:
                    payloads = self.payload_gen.get_payloads(category, limit=3)
                    for payload in payloads:
                        for content_type, encode in [
                            ("application/x-www-form-urlencoded", lambda p: urlencode({"input": p.value, "data": p.value})),
                            ("application/json", lambda p: f'{{"input":"{p.value}","data":"{p.value}"}}'),
                        ]:
                            try:
                                body = encode(payload)
                                start = time.monotonic()
                                resp = await self._request(client, "POST", url, content=body, headers={"Content-Type": content_type})
                                elapsed = time.monotonic() - start
                                if not resp:
                                    continue
                                finding = self._analyze_response(resp, baseline_body, baseline_len, payload)
                                if finding:
                                    results.append(FuzzResult(
                                        url=url, method="POST", status_code=resp.status_code,
                                        body_length=len(resp.text), response_time=elapsed,
                                        finding=f"POST body {finding}", severity=payload.severity,
                                        evidence=f"CT: {content_type} | Payload: {payload.value[:80]} | Response: {resp.text[:200]}",
                                    ))
                            except Exception:
                                continue
        return results

    async def fuzz_cookies(self, base_url: str) -> list[FuzzResult]:
        """Test injection payloads in common cookie names."""
        results: list[FuzzResult] = []
        cookie_names = ["session", "token", "user", "lang", "theme", "csrf_token", "auth", "id"]
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            if not baseline:
                return results
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
            for cookie_name in cookie_names:
                for category in ["xss", "sqli"]:
                    payloads = self.payload_gen.get_payloads(category, limit=2)
                    for payload in payloads:
                        cookies = {cookie_name: payload.value}
                        start = time.monotonic()
                        resp = await self._request(client, "GET", base_url, cookies=cookies)
                        elapsed = time.monotonic() - start
                        if not resp:
                            continue
                        finding = self._analyze_response(resp, baseline_body, baseline_len, payload)
                        if finding:
                            results.append(FuzzResult(
                                url=base_url, method="GET", status_code=resp.status_code,
                                body_length=len(resp.text), response_time=elapsed,
                                finding=f"Cookie {cookie_name}: {finding}", severity=payload.severity,
                                evidence=f"Cookie: {cookie_name}={payload.value[:80]} | Response: {resp.text[:200]}",
                            ))
        return results

    async def fuzz_headers_injection(self, base_url: str) -> list[FuzzResult]:
        """Test injection payloads in Referer, User-Agent, Accept-Language, X-Forwarded-For."""
        results: list[FuzzResult] = []
        injectable_headers = {
            "Referer": "referer",
            "User-Agent": "user_agent",
            "Accept-Language": "accept_language",
            "X-Forwarded-For": "x_forwarded_for",
            "X-Original-URL": "x_original_url",
        }
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            if not baseline:
                return results
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
            for header_name, _ in injectable_headers.items():
                for category in ["xss", "ssrf"]:
                    payloads = self.payload_gen.get_payloads(category, limit=2)
                    for payload in payloads:
                        headers = {header_name: payload.value}
                        start = time.monotonic()
                        resp = await self._request(client, "GET", base_url, headers=headers)
                        elapsed = time.monotonic() - start
                        if not resp:
                            continue
                        finding = self._analyze_response(resp, baseline_body, baseline_len, payload)
                        if finding:
                            results.append(FuzzResult(
                                url=base_url, method="GET", status_code=resp.status_code,
                                body_length=len(resp.text), response_time=elapsed,
                                finding=f"Header {header_name}: {finding}", severity=payload.severity,
                                evidence=f"{header_name}: {payload.value[:80]} | Response: {resp.text[:200]}",
                            ))
        return results