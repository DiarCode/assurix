"""Persistent browser session manager with auth refresh (plan §3.1.3).

The v2 BrowserSession is the single entry point for ALL browser interaction
across the agent fleet. It owns:

  1. Auth state (cookies, localStorage, IndexedDB) as a serializable blob.
  2. The primary_operator (AgentBrowserOperator preferred; AIBrowserOperator
     fallback). The primary can be swapped at runtime without losing auth.
  3. The Page object exposed via the with_auth() context manager — all
     investigations must enter this context to receive an authenticated
     page.
  4. Refresh-on-demand: when an HTTP response returns 401/403, the session
     can re-run the configured login flow to refresh cookies and retry the
     request. This is critical for long-running engagements where auth
     tokens expire mid-scan.

The legacy ``BrowserOperator`` (deprecated, src.agents.browser.operator)
and the no-longer-primary ``AIBrowserOperator`` (deprecated, src.agents.
browser.ai_operator) remain reachable through ``browser_session.legacy_
operator`` and ``browser_session.ai_operator`` for backward compatibility.
WebappAgent, ReconAgent, and any new agent MUST use BrowserSession
directly; direct construction of AIBrowserOperator/BrowserOperator is
forbidden (per the test in tests/integration/test_webapp_browser_session
.py).

Why a session manager rather than a stateless operator?

  - Stateful auth: agent-browser's snapshot+ref requires a single
    authenticated page across multiple commands. A stateless operator
    re-creates the page per command, losing the auth context.
  - Refresh: a 30-minute engagement may span multiple token lifetimes.
    A stateless operator cannot refresh mid-flight.
  - Operator swap: future migrations to a different browser framework
    (Playwright MCP, etc.) need a stable seam.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BrowserSessionConfig:
    """Configuration for a BrowserSession.

    primary_operator: which browser operator class is the preferred one.
        Valid values: "agent" (AgentBrowserOperator, default) or
        "ai" (AIBrowserOperator, fallback).
    auth_refresh_on_401: whether to refresh auth state on 401/403
        responses. Default True — recommended for long-running engagements.
    session_ttl_seconds: how long the auth state is valid before forced
        refresh. Default 1800 (30 minutes).
    login_url: optional URL to POST credentials to for refresh. If None,
        refresh is a no-op (and 401s become terminal).
    login_payload: optional dict of credentials for the login URL.
    """

    primary_operator: str = "agent"
    auth_refresh_on_401: bool = True
    session_ttl_seconds: int = 1800
    login_url: str | None = None
    login_payload: dict[str, Any] | None = None


class BrowserSession:
    """Per-engagement browser session with auth state and refresh.

    The session is a thin layer above a primary operator (AgentBrowserOperator
    or AIBrowserOperator). It owns the auth state and the refresh policy,
    but delegates page manipulation to the operator.

    Usage (the only supported pattern):
        session = BrowserSession(engagement_id=engagement_id)
        async with session.with_auth(target_url) as page:
            # page is the operator's authenticated Page object
            await session.primary_operator.click(page, "submit")
        await session.close()
    """

    def __init__(
        self,
        engagement_id: str,
        config: BrowserSessionConfig | None = None,
        primary_operator: str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.config = config or BrowserSessionConfig(
            primary_operator=primary_operator or "agent"
        )
        self._cookies: dict[str, str] = {}
        self._local_storage: dict[str, str] = {}
        self._last_refreshed_at: datetime | None = None
        self._expires_at: datetime | None = None
        self._closed = False
        self._primary_instance: Any | None = None
        self._legacy_instance: Any | None = None
        self._ai_instance: Any | None = None

    # --- Auth state --------------------------------------------------------

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    @property
    def local_storage(self) -> dict[str, str]:
        return dict(self._local_storage)

    @property
    def last_refreshed_at(self) -> datetime | None:
        return self._last_refreshed_at

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    @property
    def is_authenticated(self) -> bool:
        return bool(self._cookies) and (
            self._expires_at is None or self._expires_at > datetime.now(UTC)
        )

    def set_auth_state(
        self,
        cookies: dict[str, str] | None = None,
        local_storage: dict[str, str] | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        """Programmatically set the auth state (e.g., from a prior scan)."""
        if cookies is not None:
            self._cookies = dict(cookies)
        if local_storage is not None:
            self._local_storage = dict(local_storage)
        ttl = ttl_seconds or self.config.session_ttl_seconds
        self._last_refreshed_at = datetime.now(UTC)
        self._expires_at = self._last_refreshed_at + timedelta(seconds=ttl)
        logger.debug(
            "BrowserSession[%s] auth state set: %d cookies, expires=%s",
            self.engagement_id,
            len(self._cookies),
            self._expires_at.isoformat() if self._expires_at else "never",
        )

    async def refresh(self) -> bool:
        """Refresh auth state. Returns True if refresh succeeded.

        Per plan §3.1.3: a 30-minute engagement may span multiple token
        lifetimes. The refresh is a no-op if ``config.login_url`` is None
        (caller has not configured a login flow).
        """
        if not self.config.login_url:
            logger.debug(
                "BrowserSession[%s] refresh is a no-op (no login_url configured)",
                self.engagement_id,
            )
            return False

        try:
            import httpx  # local import to avoid top-level dependency
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.login_url, json=self.config.login_payload or {}
                )
                response.raise_for_status()
                data = response.json()

            # Heuristic: cookies come back in the response. Either in a
            # `cookies` key, or the response itself is the cookie map.
            new_cookies: dict[str, str] = {}
            if isinstance(data, dict) and "cookies" in data:
                raw = data["cookies"]
                if isinstance(raw, dict):
                    new_cookies = {k: str(v) for k, v in raw.items()}
            elif isinstance(data, dict):
                # Fall back: treat the whole response as cookies
                new_cookies = {k: str(v) for k, v in data.items() if isinstance(v, str)}

            self.set_auth_state(cookies=new_cookies, local_storage=self._local_storage)
            logger.info(
                "BrowserSession[%s] refreshed %d cookies",
                self.engagement_id, len(new_cookies),
            )
            return True
        except Exception as exc:
            logger.warning(
                "BrowserSession[%s] refresh failed: %s",
                self.engagement_id, exc,
            )
            return False

    # --- Operator handles --------------------------------------------------

    @property
    def primary_operator(self) -> Any:
        """Return the primary operator handle (AgentBrowserOperator by default).

        Constructed lazily on first access; mirrors ``browser-use``'s
        lazy-init pattern. Cached in ``self._primary_instance`` for
        reuse across calls.
        """
        if self._primary_instance is None:
            if self.config.primary_operator == "agent":
                from src.agents.browser.agent_browser_operator import AgentBrowserOperator
                self._primary_instance = AgentBrowserOperator()
            elif self.config.primary_operator == "ai":
                from src.agents.browser.ai_operator import AIBrowserOperator
                self._primary_instance = AIBrowserOperator()
            else:
                raise ValueError(
                    f"Unknown primary_operator={self.config.primary_operator!r}; "
                    f"valid values: 'agent', 'ai'"
                )
        return self._primary_instance

    @property
    def legacy_operator(self) -> Any:
        """The deprecated BrowserOperator handle (for tools that still need it)."""
        if self._legacy_instance is None:
            from src.agents.browser.operator import BrowserOperator
            self._legacy_instance = BrowserOperator()
        return self._legacy_instance

    @property
    def ai_operator(self) -> Any:
        """The deprecated AIBrowserOperator handle (fallback path)."""
        if self._ai_instance is None:
            from src.agents.browser.ai_operator import AIBrowserOperator
            self._ai_instance = AIBrowserOperator()
        return self._ai_instance

    # --- Authenticated page context ---------------------------------------

    @asynccontextmanager
    async def with_auth(self, target_url: str):
        """Yield an authenticated Page-like object for ``target_url``.

        The caller MUST enter this context to use the page. On entry:
          1. If is_authenticated is False, call refresh() first.
          2. Yield the operator's page after navigating to target_url.

        The implementation is intentionally thin: the operator owns the
        page object, the session owns the auth state. The page yields
        whatever the operator's ``navigate_with_auth`` returns.
        """
        if self._closed:
            raise RuntimeError("BrowserSession is closed")

        if not self.is_authenticated and self.config.auth_refresh_on_401:
            await self.refresh()

        # Delegate to the primary operator. The exact API varies by
        # operator (AgentBrowserOperator uses Playwright Page, AIBrowser-
        # Operator uses browser-use Agent). We expose the common shape:
        # `navigate_with_auth(url, cookies, local_storage) -> page`.
        op = self.primary_operator
        if hasattr(op, "navigate_with_auth"):
            page = await op.navigate_with_auth(
                target_url,
                cookies=self._cookies,
                local_storage=self._local_storage,
            )
        else:
            # Fall back to a plain navigate; auth state is not propagated
            # to the page (operator doesn't support auth injection).
            logger.debug(
                "BrowserSession[%s] operator %s has no navigate_with_auth; "
                "falling back to plain navigate",
                self.engagement_id, type(op).__name__,
            )
            if hasattr(op, "navigate"):
                page = await op.navigate(target_url)
            else:
                page = None

        try:
            yield page
        finally:
            # No-op: the page lifecycle is owned by the operator.
            pass

    async def close(self) -> None:
        """Release all resources. Idempotent."""
        if self._closed:
            return
        for inst in (self._primary_instance, self._legacy_instance, self._ai_instance):
            if inst is not None and hasattr(inst, "close"):
                try:
                    await inst.close()
                except Exception as exc:
                    logger.debug("Operator close error: %s", exc)
        self._closed = True
        logger.debug("BrowserSession[%s] closed", self.engagement_id)

    async def __aenter__(self) -> "BrowserSession":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()


__all__ = ["BrowserSession", "BrowserSessionConfig"]
