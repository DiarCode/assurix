"""Target setup procedures for benchmark containers.

Handles authentication and configuration of Docker targets before scanning.
DVWA requires login + security level set to 'low' for vulnerabilities to be exploitable.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _extract_dvfa_csrf_token(html: str) -> str | None:
    """Extract the user_token CSRF token from a DVWA login form.

    DVWA embeds a hidden ``user_token`` field in the login form.
    The token looks like a 32-char hex string (MD5).
    """
    match = re.search(
        r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]{32})['\"]",
        html,
    )
    if match:
        return match.group(1)

    # Fallback: look for any hidden input named user_token
    match = re.search(
        r"<input[^>]+name=['\"]user_token['\"][^>]+value=['\"]([^'\"]+)['\"]",
        html,
    )
    if match:
        return match.group(1)

    # Reversed attribute order
    match = re.search(
        r"<input[^>]+value=['\"]([^'\"]+)['\"][^>]+name=['\"]user_token['\"]",
        html,
    )
    if match:
        return match.group(1)

    return None


async def setup_dvwa(target_url: str) -> dict[str, str]:
    """Authenticate to DVWA and set security level to 'low'.

    Returns dict of cookies to include in subsequent requests.

    Steps:
        1. GET login page to extract CSRF token
        2. POST login with admin:password
        3. POST security level to 'low'

    Raises:
        RuntimeError: If authentication or security level change fails.
    """
    base = target_url.rstrip("/")

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
        # 1. GET login page to get CSRF token
        login_page = await client.get(f"{base}/login.php")
        if login_page.status_code != 200:
            raise RuntimeError(
                f"DVWA login page returned {login_page.status_code}, expected 200"
            )

        token = _extract_dvfa_csrf_token(login_page.text)
        if not token:
            logger.warning(
                "DVWA: could not extract CSRF token from login page, "
                "attempting login without it"
            )

        # 2. POST login with admin:password
        login_data: dict[str, Any] = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
        }
        if token:
            login_data["user_token"] = token

        login_resp = await client.post(f"{base}/login.php", data=login_data)

        # Check login succeeded (redirect away from login page or 200 on index)
        if login_resp.status_code not in (200, 302):
            raise RuntimeError(
                f"DVWA login failed with status {login_resp.status_code}"
            )

        # Follow redirect if 302
        if login_resp.status_code == 302:
            location = login_resp.headers.get("location", "")
            if "login" in location.lower():
                raise RuntimeError(
                    f"DVWA login redirected back to login page: {location}"
                )

        # 3. Set security level to low
        security_resp = await client.post(
            f"{base}/dvwa/security.php",
            data={"security": "low", "seclev_submit": "Submit"},
        )
        if security_resp.status_code not in (200, 302):
            logger.warning(
                "DVWA security level change returned %d (expected 200/302)",
                security_resp.status_code,
            )

        # 4. Return cookies (PHPSESSID + security level)
        cookies = dict(client.cookies)
        if not cookies:
            raise RuntimeError("DVWA: no cookies received after authentication")

        logger.info(
            "DVWA setup complete: authenticated with cookies %s",
            list(cookies.keys()),
        )
        return cookies