"""WebSocket security testing: CSWSH, auth testing, and message fuzzing."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# Patterns for discovering WebSocket URLs in HTML/JS
WS_URL_PATTERNS = [
    re.compile(r'new\s+WebSocket\(["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'ws[s]?://[^\s"\'<>]+', re.IGNORECASE),
    re.compile(r'Socket\(["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'connect\(["\']([^"\']+ws[^"\']+)["\']', re.IGNORECASE),
]

CSWSH_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://spoofed-origin.com",
]

FUZZ_MESSAGES = [
    '{"type":"message","data":"<script>alert(1)</script>"}',
    '{"type":"message","data":"{{7*7}}"}',
    '{"type":"message","data":"${7*7}"}',
    '{"type":"message","data":"__proto__"}',
    '{"type":"message","data":"' + "A" * 10000 + '"}',
    '{"type":"subscribe","channel":"admin"}',
    '{"type":"authenticate","token":"invalid"}',
]

PROTECTED_PATHS = ["/admin", "/dashboard", "/api/me", "/api/profile", "/account"]


@dataclass
class WebSocketResult:
    url: str
    test_type: str
    severity: str
    finding: str | None = None
    evidence: str = ""


class WebSocketScanner:
    """WebSocket security testing: CSWSH, authentication, and message fuzzing."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def scan(self, base_url: str) -> list[WebSocketResult]:
        """Run full WebSocket security scan against a target."""
        results: list[WebSocketResult] = []

        # Phase 1: Discover WebSocket URLs
        ws_urls = await self._discover_urls(base_url)
        if not ws_urls:
            ws_urls = self._generate_common_urls(base_url)

        for ws_url in ws_urls[:5]:
            await self._test_cswsh(ws_url, results)
            await self._test_auth(ws_url, base_url, results)
            await self._test_fuzz(ws_url, results)
            await self._test_rate_limit(ws_url, results)

        return results

    async def _discover_urls(self, base_url: str) -> list[str]:
        """Discover WebSocket URLs from HTML/JS content."""
        urls: set[str] = set()
        async with httpx.AsyncClient(verify=False) as client:
            try:
                resp = await client.get(base_url, timeout=self.timeout, follow_redirects=True)
                if resp.status_code != 200:
                    return list(urls)
                content = resp.text

                for pattern in WS_URL_PATTERNS:
                    for match in pattern.finditer(content):
                        url = match.group(1) if match.lastindex else match.group(0)
                        if url.startswith("ws"):
                            urls.add(url)
                        elif url.startswith("/"):
                            parsed = base_url.replace("https://", "wss://").replace("http://", "ws://")
                            urls.add(f"{parsed.rstrip('/')}{url}")

                # Check common JS files
                js_links = re.findall(r'src=["\']([^"\']+\.js)["\']', content)
                for js_link in js_links[:5]:
                    js_url = urljoin(base_url, js_link)
                    try:
                        js_resp = await client.get(js_url, timeout=self.timeout)
                        if js_resp.status_code == 200:
                            for pattern in WS_URL_PATTERNS:
                                for match in pattern.finditer(js_resp.text):
                                    url = match.group(1) if match.lastindex else match.group(0)
                                    if url.startswith("ws"):
                                        urls.add(url)
                    except Exception:
                        pass

            except Exception:
                pass

        return list(urls)

    def _generate_common_urls(self, base_url: str) -> list[str]:
        """Generate common WebSocket URL patterns."""
        http_base = base_url.replace("wss://", "https://").replace("ws://", "http://")
        if http_base.startswith("https://"):
            ws_base = "wss://" + http_base[8:]
        elif http_base.startswith("http://"):
            ws_base = "ws://" + http_base[7:]
        else:
            ws_base = "wss://" + http_base
        return [
            ws_base.rstrip("/") + "/ws",
            ws_base.rstrip("/") + "/websocket",
            ws_base.rstrip("/") + "/socket",
            ws_base.rstrip("/") + "/live",
            ws_base.rstrip("/") + "/stream",
        ]

    async def _test_cswsh(self, ws_url: str, results: list[WebSocketResult]) -> None:
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        # Try HTTP-based upgrade check first (works without websockets library)
        async with httpx.AsyncClient(verify=False) as client:
            http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
            for origin in CSWSH_ORIGINS:
                try:
                    resp = await client.get(
                        http_url,
                        headers={
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            "Sec-WebSocket-Version": "13",
                            "Origin": origin,
                        },
                        timeout=self.timeout,
                    )
                    if resp.status_code in (101, 200):
                        results.append(WebSocketResult(
                            url=ws_url, test_type="cswsh",
                            severity="high",
                            finding=f"WebSocket accepts connections from arbitrary origin: {origin}",
                            evidence=f"Server accepted upgrade with Origin: {origin}",
                        ))
                        break  # One CSWSH finding is enough
                except Exception:
                    pass

        # Try with websockets library if available
        try:
            import websockets
            for origin in CSWSH_ORIGINS:
                try:
                    async with websockets.connect(ws_url, origin=origin, open_timeout=self.timeout):
                        results.append(WebSocketResult(
                            url=ws_url, test_type="cswsh",
                            severity="high",
                            finding=f"WebSocket accepts connections from arbitrary origin: {origin}",
                            evidence=f"Connection succeeded with Origin: {origin}",
                        ))
                        break
                except Exception:
                    pass
        except ImportError:
            pass

    async def _test_auth(self, ws_url: str, base_url: str, results: list[WebSocketResult]) -> None:
        """Test authenticated vs unauthenticated WebSocket access."""
        try:
            import websockets
        except ImportError:
            results.append(WebSocketResult(
                url=ws_url, test_type="auth_unavailable",
                severity="info",
                finding="WebSocket auth testing skipped (websockets library not available)",
                evidence="Install: pip install websockets",
            ))
            return

        try:
            async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    results.append(WebSocketResult(
                        url=ws_url, test_type="ws_auth",
                        severity="medium",
                        finding="WebSocket accessible without authentication",
                        evidence=f"Received message without auth: {str(msg)[:200]}",
                    ))
                except asyncio.TimeoutError:
                    results.append(WebSocketResult(
                        url=ws_url, test_type="ws_auth",
                        severity="low",
                        finding="WebSocket connection established without authentication",
                        evidence="Connection succeeded, no messages received",
                    ))
        except Exception:
            pass

    async def _test_fuzz(self, ws_url: str, results: list[WebSocketResult]) -> None:
        """Fuzz WebSocket messages for injection vulnerabilities."""
        try:
            import websockets
        except ImportError:
            return

        for msg in FUZZ_MESSAGES[:5]:
            try:
                async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                    await ws.send(msg)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        if isinstance(response, str):
                            if "<script>" in response or "alert(1)" in response:
                                results.append(WebSocketResult(
                                    url=ws_url, test_type="ws_xss",
                                    severity="high",
                                    finding="WebSocket XSS: injected content reflected in response",
                                    evidence=f"Payload reflected: {response[:200]}",
                                ))
                            elif "49" in response or "77" in response:
                                results.append(WebSocketResult(
                                    url=ws_url, test_type="ws_injection",
                                    severity="medium",
                                    finding="WebSocket template injection: expression evaluated",
                                    evidence=f"Expression evaluated in response: {response[:200]}",
                                ))
                    except asyncio.TimeoutError:
                        pass
            except Exception:
                pass

    async def _test_rate_limit(self, ws_url: str, results: list[WebSocketResult]) -> None:
        """Test for WebSocket rate limiting."""
        try:
            import websockets
        except ImportError:
            return

        try:
            async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                sent = 0
                for _ in range(50):
                    try:
                        await ws.send('{"type":"ping"}')
                        sent += 1
                    except Exception:
                        break
                if sent >= 50:
                    results.append(WebSocketResult(
                        url=ws_url, test_type="ws_rate_limit",
                        severity="low",
                        finding="WebSocket has no message rate limiting",
                        evidence=f"Sent {sent} messages without rate limit",
                    ))
        except Exception:
            pass