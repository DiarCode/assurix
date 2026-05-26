"""Brute-force attacks: directory, credential, parameter, and extension enumeration."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx

logger = logging.getLogger(__name__)

DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel", "control",
    "api", "api/v1", "api/v2", "api/admin", "api/users", "api/config",
    "config", "backup", "db", "database", "sql", "dump", "export", "import",
    ".env", ".env.bak", ".env.local", ".env.production",
    ".git", ".git/config", ".git/HEAD", ".gitignore", ".svn", ".DS_Store",
    "wp-admin", "wp-login.php", "wp-config.php", "wp-content",
    "xmlrpc.php", "wp-json/wp/v2/users",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "swagger-ui", "swagger-ui/", "api-docs", "api/swagger",
    "graphql", "graphiql", "playground",
    "debug", "trace", "profiler", "phpinfo.php", "info.php", "test",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "console", "shell", "webshell", "cmd",
    "server-status", "server-info", "nginx_status",
    "uploads", "upload", "files", "media", "static", "assets", "public",
    "user", "users", "account", "accounts", "profile", "me",
    "search", "query", "filter",
    "auth", "oauth", "token", "verify", "confirm",
    "password", "reset", "forgot", "change",
    "webhook", "callback", "notify", "event",
    "health", "status", "ping", "version", "info",
    ".well-known/security.txt", "security.txt", "favicon.ico",
    "config.json", "config.yml", "config.yaml", "settings.py",
    "package.json", "composer.json", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv",
    "README.md", "CHANGELOG.md", "LICENSE",
]

CRED_USERNAME = ["admin", "administrator", "root", "user", "test", "guest", "demo", "operator", "manager", "support", "service", "api", "system"]
CRED_PASSWORD = ["admin", "password", "123456", "admin123", "root", "test", "guest", "welcome", "letmein", "monkey", "dragon", "master", "qwerty", "login", "princess", "abc123", "password1", "123456789"]

EXT_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", ".tmp", ".copy", ".backup", ".txt", ".log", ".sql", ".csv", ".json", ".xml", ".yaml", ".conf", ".cfg", ".ini", ".env", ".zip", ".tar", ".gz"]

HIDDEN_PARAMS = [
    "admin", "debug", "test", "dev", "internal", "debug_mode",
    "role", "user_role", "is_admin", "is_staff", "is_superuser",
    "access", "permission", "privilege", "level", "group",
    "id", "user_id", "account_id", "org_id", "tenant_id",
    "page_size", "limit", "max", "count", "per_page",
    "sort", "order_by", "direction", "fields", "select",
    "callback", "format", "output", "type", "verbose", "version",
]


@dataclass
class BruteResult:
    url: str
    category: str
    value: str
    status_code: int
    body_length: int
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""


class BruteForcer:
    """Async brute-force engine for directories, credentials, and parameters."""

    SOFT_404_LENGTH_THRESHOLD = 0.05

    def __init__(self, max_concurrent: int = 10, timeout: float = 10.0, rate_rps: float = 15.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.rate_rps = rate_rps
        self._delay = 1.0 / rate_rps if rate_rps > 0 else 0

    def _is_soft_404(self, resp: httpx.Response, baseline_len: int) -> bool:
        """Detect catch-all 200 responses (SPAs, custom error pages)."""
        if not resp or resp.status_code != 200:
            return False
        body_len = len(resp.text)
        if baseline_len > 0 and abs(body_len - baseline_len) / baseline_len < self.SOFT_404_LENGTH_THRESHOLD:
            return True
        return False

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            if self._delay:
                await asyncio.sleep(self._delay)
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=True, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html[:2000], re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""

    async def brute_force_directories(self, base_url: str, wordlist: list[str] | None = None) -> list[BruteResult]:
        paths = wordlist or DIR_WORDLIST
        results: list[BruteResult] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", origin + "/")
            baseline_len = len(baseline.text) if baseline else 0

            for path in paths:
                url = urljoin(origin + "/", path.lstrip("/"))
                resp = await self._request(client, "GET", url)
                if not resp:
                    continue
                if resp.status_code == 200:
                    if self._is_soft_404(resp, baseline_len):
                        continue
                    finding = None
                    severity = "info"
                    if any(kw in path.lower() for kw in (".env", ".git", "config", "debug", "sql", "dump", "backup")):
                        finding, severity = f"Sensitive path discovered: /{path}", "high"
                    elif any(kw in path.lower() for kw in ("admin", "dashboard", "panel", "console", "shell")):
                        finding, severity = f"Admin/control path accessible: /{path}", "medium"
                    elif any(kw in path.lower() for kw in ("swagger", "api-docs", "graphql")):
                        finding, severity = f"API documentation accessible: /{path}", "medium"
                    results.append(BruteResult(
                        url=url, category="directory", value=f"/{path}",
                        status_code=resp.status_code, body_length=len(resp.text),
                        finding=finding, severity=severity,
                        evidence=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                    ))
                elif resp.status_code == 403:
                    results.append(BruteResult(
                        url=url, category="directory", value=f"/{path}",
                        status_code=403, body_length=0,
                        finding=f"Access forbidden: /{path} — may be bypassable", severity="low",
                        evidence="403 Forbidden",
                    ))
                elif resp.status_code == 401:
                    results.append(BruteResult(
                        url=url, category="directory", value=f"/{path}",
                        status_code=401, body_length=0,
                        finding=f"Auth required: /{path}", severity="low",
                        evidence="401 Unauthorized",
                    ))
        return results

    async def brute_force_credentials(self, base_url: str, login_path: str = "/login",
                                       usernames: list[str] | None = None,
                                       passwords: list[str] | None = None) -> list[BruteResult]:
        usernames = usernames or CRED_USERNAME
        passwords = passwords or CRED_PASSWORD
        results: list[BruteResult] = []
        url = urljoin(base_url, login_path)

        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", url)
            if not baseline:
                return results
            baseline_len, baseline_status = len(baseline.text), baseline.status_code
            found = False
            for username in usernames:
                for password in passwords:
                    if found:
                        break
                    for ct, data_fn in [
                        ("application/x-www-form-urlencoded", lambda u, p: f"username={u}&password={p}"),
                        ("application/json", lambda u, p: f'{{"username":"{u}","password":"{p}"}}'),
                    ]:
                        resp = await self._request(client, "POST", url, content=data_fn(username, password), headers={"Content-Type": ct})
                        if not resp:
                            continue
                        if resp.status_code != baseline_status and resp.status_code in (200, 301, 302, 303):
                            results.append(BruteResult(
                                url=url, category="credential", value=f"{username}:{password}",
                                status_code=resp.status_code, body_length=len(resp.text),
                                finding=f"Possible valid credentials: {username}:{password}",
                                severity="critical",
                                evidence=f"Status: {resp.status_code} (baseline: {baseline_status})",
                            ))
                            found = True
                            break
                        diff = abs(len(resp.text) - baseline_len)
                        if diff > baseline_len * 0.3 and resp.status_code == baseline_status:
                            results.append(BruteResult(
                                url=url, category="credential", value=f"{username}:{password}",
                                status_code=resp.status_code, body_length=len(resp.text),
                                finding=f"Different response for {username}:{password}",
                                severity="medium",
                                evidence=f"Length diff: {diff}B ({ct})",
                            ))
        return results

    async def brute_force_parameters(self, base_url: str, params: list[str] | None = None) -> list[BruteResult]:
        params = params or HIDDEN_PARAMS
        results: list[BruteResult] = []

        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            if not baseline:
                return results
            baseline_len, baseline_status = len(baseline.text), baseline.status_code

            for param in params:
                parsed = urlparse(base_url)
                qs = parse_qs(parsed.query)
                qs[param] = ["1"]
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(qs, doseq=True), parsed.fragment,
                ))
                resp = await self._request(client, "GET", new_url)
                if not resp:
                    continue
                diff = abs(len(resp.text) - baseline_len)
                if resp.status_code != baseline_status:
                    results.append(BruteResult(
                        url=new_url, category="parameter", value=param,
                        status_code=resp.status_code, body_length=len(resp.text),
                        finding=f"Hidden parameter '{param}' changed status from {baseline_status} to {resp.status_code}",
                        severity="medium",
                        evidence=f"Param: {param}=1 -> {resp.status_code}",
                    ))
                elif diff > baseline_len * 0.2:
                    results.append(BruteResult(
                        url=new_url, category="parameter", value=param,
                        status_code=resp.status_code, body_length=len(resp.text),
                        finding=f"Hidden parameter '{param}' changed response size by {diff}B",
                        severity="low",
                        evidence=f"Param: {param}=1 -> {diff}B change",
                    ))
        return results

    async def brute_force_extensions(self, base_url: str, known_paths: list[str] | None = None) -> list[BruteResult]:
        known_paths = known_paths or ["index", "config", "admin", "backup", "database", ".env", "wp-config"]
        results: list[BruteResult] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", origin + "/")
            baseline_len = len(baseline.text) if baseline else 0

            for path in known_paths:
                for ext in EXT_EXTENSIONS:
                    url = urljoin(origin + "/", path.lstrip("/") + ext)
                    resp = await self._request(client, "GET", url)
                    if resp and resp.status_code == 200:
                        if self._is_soft_404(resp, baseline_len):
                            continue
                        severity = "high" if any(kw in ext for kw in (".env", ".sql", ".bak", ".old", ".conf")) else "info"
                        results.append(BruteResult(
                            url=url, category="extension", value=f"{path}{ext}",
                            status_code=resp.status_code, body_length=len(resp.text),
                            finding=f"Backup/config file found: {path}{ext}",
                            severity=severity,
                            evidence=f"Status: 200, Length: {len(resp.text)}",
                        ))
        return results