"""Shared session manager for authenticated HTTP client sharing across tools.

Maintains a persistent httpx.AsyncClient with cookies so that authentication
state discovered by one tool (e.g., AuthTester) is available to all others.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from src.agents.tools.replay import ReplayStore

logger = logging.getLogger(__name__)

# Common login path patterns to probe
_LOGIN_PROBES = [
    "/login", "/signin", "/sign-in", "/auth/login", "/api/login",
    "/api/auth/login", "/api/v1/login", "/admin/login", "/wp-login.php",
]

# Default credentials to try (common dev/test defaults only)
_DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("test", "test"), ("user", "user"),
    ("guest", "guest"), ("demo", "demo"),
]


class SharedSessionManager:
    """Manages a shared authenticated httpx client for all offensive tools.

    Tools call `get_client(target_url)` to get an httpx.AsyncClient that
    may carry authenticated session cookies if authentication was achieved.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        max_redirects: int = 5,
        replay_store: ReplayStore | None = None,
    ) -> None:
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._authenticated_hosts: set[str] = set()
        self._cookies: dict[str, dict[str, str]] = {}
        self._timeout = timeout
        self._max_redirects = max_redirects
        # Optional ReplayStore — when set, every response is recorded
        # via an httpx event hook. The store is owned by the caller
        # (typically the engine); we just attach the hook here.
        self._replay_store = replay_store

    def _host_key(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def attempt_authentication(
        self, target_url: str, login_paths: list[str] | None = None,
        credentials: list[tuple[str, str]] | None = None,
        technologies: list[str] | None = None,
    ) -> bool:
        """Try to authenticate against the target and store session cookies.

        Returns True if authentication succeeded.
        """
        host = self._host_key(target_url)
        paths = login_paths or _LOGIN_PROBES
        creds = credentials or _DEFAULT_CREDENTIALS
        base = self._host_key(target_url)

        async with httpx.AsyncClient(verify=False, timeout=self._timeout, follow_redirects=True) as probe_client:
            # Find a working login endpoint
            login_url: str | None = None
            for path in paths:
                url = f"{base}{path}" if not path.startswith("http") else path
                try:
                    resp = await probe_client.get(url)
                    if resp.status_code == 200 and ("<form" in resp.text.lower() or "password" in resp.text.lower()):
                        login_url = url
                        break
                except Exception:
                    continue

            if not login_url:
                logger.info("No login page found for %s", host)
                return False

            # Try credentials
            for username, password in creds:
                try:
                    # Try form-urlencoded POST first
                    resp = await probe_client.post(
                        login_url,
                        data={"username": username, "login": username, "email": username, "password": password},
                        follow_redirects=True,
                    )
                    if self._is_auth_success(resp):
                        cookies = dict(probe_client.cookies)
                        if cookies:
                            self._cookies[host] = cookies
                            self._authenticated_hosts.add(host)
                            logger.info("Authenticated to %s as %s (cookies: %s)", host, username, list(cookies.keys()))
                            return True
                except Exception:
                    continue

                # Try JSON POST
                try:
                    resp = await probe_client.post(
                        login_url,
                        json={"username": username, "email": username, "password": password},
                        follow_redirects=True,
                    )
                    if self._is_auth_success(resp):
                        cookies = dict(probe_client.cookies)
                        if cookies:
                            self._cookies[host] = cookies
                            self._authenticated_hosts.add(host)
                            logger.info("Authenticated to %s as %s via JSON (cookies: %s)", host, username, list(cookies.keys()))
                            return True
                except Exception:
                    continue

        logger.info("Authentication failed for %s", host)
        return False

    def _is_auth_success(self, resp: httpx.Response) -> bool:
        """Heuristic: did the login succeed?"""
        if resp.status_code in (401, 403):
            return False
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "").lower()
            if any(kw in location for kw in ("login", "signin", "auth")):
                return False
            return True  # Redirect away from login = success
        if resp.status_code == 200:
            body = resp.text.lower()
            # Still on login page
            if "<form" in body and "password" in body:
                return False
            # Token in response suggests success
            if any(kw in body for kw in ("token", "session", "welcome", "dashboard", "logout")):
                return True
        return False

    def get_client(self, target_url: str) -> httpx.AsyncClient:
        """Get an httpx.AsyncClient, with authenticated cookies if available."""
        host = self._host_key(target_url)
        if host in self._clients:
            return self._clients[host]

        cookies = self._cookies.get(host, {})
        # When a ReplayStore is attached, register the event hook so
        # every response is recorded. The hook itself is sync and
        # best-effort — a broken store doesn't kill the HTTP call.
        event_hooks: dict[str, list[Any]] = {}
        if self._replay_store is not None:
            event_hooks["response"] = [self._replay_store.event_hook()]
        client = httpx.AsyncClient(
            verify=False,
            timeout=self._timeout,
            follow_redirects=False,
            max_redirects=self._max_redirects,
            cookies=cookies,
            event_hooks=event_hooks or None,
        )
        self._clients[host] = client
        return client

    def seed_cookies(self, base_url: str, cookies: dict[str, str]) -> None:
        """Pre-seed authenticated cookies for a target host.

        Used by benchmark infrastructure to inject pre-authenticated session
        state (e.g., DVWA admin session) before scanning begins.
        """
        host_key = self._host_key(base_url)
        self._cookies[host_key] = cookies
        self._authenticated_hosts.add(host_key)
        logger.info("Seeded auth cookies for %s (keys: %s)", host_key, list(cookies.keys()))

    def is_authenticated(self, target_url: str) -> bool:
        return self._host_key(target_url) in self._authenticated_hosts

    @property
    def replay_store(self) -> ReplayStore | None:
        """Return the currently-attached ReplayStore (or None)."""
        return self._replay_store

    def set_replay_store(self, store: ReplayStore) -> None:
        """Attach a ReplayStore so future clients record responses.

        Existing clients are NOT retroactively re-wired; callers
        should attach the store BEFORE requesting a client. If a
        client has already been created for a host, a warning is
        logged and the existing client is closed so the next
        ``get_client`` call will pick up the hook.
        """
        if self._clients:
            logger.warning(
                "set_replay_store: %d existing clients will be closed "
                "and rebuilt with the new event hook",
                len(self._clients),
            )
            # Best-effort: close + clear so the next get_client re-creates.
            for client in list(self._clients.values()):
                # Can't await from a sync method; the caller (engine)
                # is responsible for full lifecycle. We just drop the
                # references and let the GC clean up the underlying
                # sockets.
                _ = client
            self._clients.clear()
        self._replay_store = store

    async def close(self) -> None:
        """Close all managed clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()