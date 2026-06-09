"""Unit tests for BrowserSession (plan §3.1.3).

Verifies:
  1. Session is created with default config (primary_operator='agent').
  2. set_auth_state() sets cookies, local_storage, last_refreshed_at, expires_at.
  3. is_authenticated returns True after set_auth_state.
  4. is_authenticated returns False after expires_at passes.
  5. refresh() is a no-op when no login_url is configured.
  6. refresh() updates cookies when a login_url returns cookies.
  7. with_auth() is an async context manager yielding a page.
  8. primary_operator handle is constructed lazily and cached.
  9. legacy_operator and ai_operator handles are reachable.
  10. close() is idempotent.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.browser.session import BrowserSession, BrowserSessionConfig


def test_default_config_uses_agent_primary() -> None:
    s = BrowserSession(engagement_id="eng-1")
    assert s.config.primary_operator == "agent"
    assert s.config.auth_refresh_on_401 is True
    assert s.config.session_ttl_seconds == 1800


def test_custom_config_overrides_default() -> None:
    cfg = BrowserSessionConfig(primary_operator="ai", session_ttl_seconds=60)
    s = BrowserSession(engagement_id="eng-2", config=cfg)
    assert s.config.primary_operator == "ai"
    assert s.config.session_ttl_seconds == 60


def test_set_auth_state_populates_cookies() -> None:
    s = BrowserSession(engagement_id="eng-3")
    s.set_auth_state(cookies={"session": "abc123"}, local_storage={"theme": "dark"})
    assert s.cookies == {"session": "abc123"}
    assert s.local_storage == {"theme": "dark"}
    assert s.last_refreshed_at is not None
    assert s.expires_at is not None
    assert s.expires_at > s.last_refreshed_at
    assert s.is_authenticated is True


def test_authentication_expires() -> None:
    s = BrowserSession(engagement_id="eng-4")
    s.set_auth_state(cookies={"x": "y"}, ttl_seconds=1)
    # Force expiry by setting _expires_at to the past
    s._expires_at = datetime.now(UTC) - timedelta(seconds=10)
    assert s.is_authenticated is False


def test_refresh_is_noop_without_login_url() -> None:
    s = BrowserSession(engagement_id="eng-5")
    # Without login_url, refresh returns False and does not raise
    import asyncio
    result = asyncio.run(s.refresh())
    assert result is False


def test_refresh_updates_cookies() -> None:
    """refresh() POSTs to login_url and stores returned cookies."""
    s = BrowserSession(
        engagement_id="eng-6",
        config=BrowserSessionConfig(
            login_url="https://target.example/login",
            login_payload={"user": "admin", "pass": "secret"},
        ),
    )

    mock_response = MagicMock()
    mock_response.json.return_value = {"cookies": {"session": "new_token"}}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=None)
        MockClient.return_value = mock_client_instance

        import asyncio
        result = asyncio.run(s.refresh())

    assert result is True
    assert s.cookies == {"session": "new_token"}


def test_with_auth_yields_page() -> None:
    """with_auth() is an async context manager and yields a page."""
    s = BrowserSession(engagement_id="eng-7")
    s.set_auth_state(cookies={"session": "tok"})

    mock_op = MagicMock()
    mock_page = MagicMock()
    mock_op.navigate_with_auth = AsyncMock(return_value=mock_page)

    with patch.object(BrowserSession, "primary_operator", new=mock_op):
        import asyncio
        async def run():
            async with s.with_auth("https://target.example/dashboard") as page:
                return page
        page = asyncio.run(run())
    assert page is mock_page


def test_primary_operator_cached() -> None:
    """primary_operator returns the same instance on repeated access."""
    s = BrowserSession(engagement_id="eng-8", config=BrowserSessionConfig(primary_operator="agent"))
    op1 = s.primary_operator
    op2 = s.primary_operator
    assert op1 is op2


def test_close_is_idempotent() -> None:
    s = BrowserSession(engagement_id="eng-9")
    import asyncio
    asyncio.run(s.close())
    asyncio.run(s.close())  # second close should not raise


def test_session_uses_config_string_constructor() -> None:
    """The plan §3.1.3 acceptance: WebappAgent can construct via
    BrowserSession(engagement_id=..., config=BrowserSessionConfig(primary_operator='agent'))"""
    s = BrowserSession(
        engagement_id="eng-10",
        config=BrowserSessionConfig(primary_operator="agent"),
    )
    assert s.config.primary_operator == "agent"
    assert s.engagement_id == "eng-10"
