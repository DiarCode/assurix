"""Unit tests for DVWA target setup (authentication and security level configuration)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.benchmark.target_setup import _extract_dvfa_csrf_token, setup_dvwa


class TestExtractCSRFToken:
    """Tests for CSRF token extraction from DVWA login page."""

    def test_extracts_token_from_standard_form(self):
        html = '''
        <form method="post" action="login.php">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="hidden" name="user_token" value="abc123def456abc123def456abc123de">
            <input type="submit" value="Login" name="Login">
        </form>
        '''
        token = _extract_dvfa_csrf_token(html)
        assert token == "abc123def456abc123def456abc123de"

    def test_extracts_token_from_reversed_attributes(self):
        html = '''
        <input type="hidden" value="f47ac10bcb584938a1de616e8720c1e2" name="user_token">
        '''
        token = _extract_dvfa_csrf_token(html)
        assert token == "f47ac10bcb584938a1de616e8720c1e2"

    def test_returns_none_when_no_token(self):
        html = '<form><input type="text" name="username"></form>'
        token = _extract_dvfa_csrf_token(html)
        assert token is None

    def test_extracts_token_with_single_quotes(self):
        html = "<input name='user_token' value='a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'>"
        token = _extract_dvfa_csrf_token(html)
        assert token == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"


class TestSetupDvwa:
    """Tests for the full DVWA setup flow."""

    @pytest.mark.asyncio
    async def test_setup_dvwa_returns_cookies(self):
        """setup_dvwa should return a dict of cookies after successful auth."""
        mock_response_login = MagicMock()
        mock_response_login.status_code = 200
        mock_response_login.text = '''
        <form method="post">
            <input name="user_token" value="abc123def456abc123def456abc123de">
        </form>
        '''
        mock_response_login.headers = {}

        mock_response_security = MagicMock()
        mock_response_security.status_code = 200
        mock_response_security.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response_login)
        mock_client.post = AsyncMock(return_value=mock_response_security)
        mock_client.cookies = MagicMock()
        mock_client.cookies.__iter__ = MagicMock(return_value=iter(["PHPSESSID", "security"]))
        mock_client.cookies.__getitem__ = MagicMock(return_value="test_value")
        # Make dict() work on cookies
        mock_client.cookies = {"PHPSESSID": "abc123", "security": "low"}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.benchmark.target_setup.httpx.AsyncClient", return_value=mock_client):
            cookies = await setup_dvwa("http://localhost:80")
            assert isinstance(cookies, dict)
            assert len(cookies) > 0

    @pytest.mark.asyncio
    async def test_setup_dvwa_posts_security_low(self):
        """setup_dvwa should POST security=low to the security page."""
        mock_response_login = MagicMock()
        mock_response_login.status_code = 200
        mock_response_login.text = '<input name="user_token" value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4">'
        mock_response_login.headers = {}

        mock_response_security = MagicMock()
        mock_response_security.status_code = 200
        mock_response_security.headers = {}

        post_calls = []

        async def mock_post(url, **kwargs):
            post_calls.append({"url": url, "kwargs": kwargs})
            return mock_response_security

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response_login)
        mock_client.post = mock_post
        mock_client.cookies = {"PHPSESSID": "abc123", "security": "low"}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.benchmark.target_setup.httpx.AsyncClient", return_value=mock_client):
            await setup_dvwa("http://localhost:80")

        # Verify security POST was made
        security_calls = [c for c in post_calls if "security" in c["url"]]
        assert len(security_calls) >= 1
        # Verify the data contains security=low
        data = security_calls[0]["kwargs"].get("data", {})
        assert data.get("security") == "low"

    @pytest.mark.asyncio
    async def test_setup_dvwa_extracts_csrf_token(self):
        """setup_dvwa should extract CSRF token and include it in the login POST."""
        mock_response_login = MagicMock()
        mock_response_login.status_code = 200
        mock_response_login.text = '<input name="user_token" value="abc123def456abc123def456abc123de">'
        mock_response_login.headers = {}

        mock_response_security = MagicMock()
        mock_response_security.status_code = 200
        mock_response_security.headers = {}

        post_calls = []

        async def mock_post(url, **kwargs):
            post_calls.append({"url": url, "kwargs": kwargs})
            return mock_response_security

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response_login)
        mock_client.post = mock_post
        mock_client.cookies = {"PHPSESSID": "abc123", "security": "low"}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.benchmark.target_setup.httpx.AsyncClient", return_value=mock_client):
            await setup_dvwa("http://localhost:80")

        # Verify login POST includes the user_token
        login_calls = [c for c in post_calls if "login" in c["url"]]
        assert len(login_calls) >= 1
        data = login_calls[0]["kwargs"].get("data", {})
        assert data.get("user_token") == "abc123def456abc123def456abc123de"