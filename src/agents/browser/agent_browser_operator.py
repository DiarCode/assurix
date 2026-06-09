"""agent-browser (Vercel) integration — primary browser automation.

agent-browser is a Rust CLI built on Chrome DevTools Protocol that provides
deterministic snapshot+ref workflow for AI-driven crawling. This module
shells out to the ``agent-browser`` binary via asyncio.create_subprocess_exec.

When agent-browser is not installed on PATH, ``is_available`` is False and
the operator methods return None / no-op. Downstream code (CrawlStrategy,
ReconAgent) falls back to HTTPX-only surface discovery.

Install the binary via ``bin/install_browser.sh`` (idempotent). The operator
never raises on import or construction — missing binary is treated as a
soft-fail so the rest of the engine boots even on minimal containers.

API surface mirrors the spec (plan v2 Phase 3):
  - open(url), snapshot(), click(ref), fill(ref, text)
  - navigate(url), get_links(), get_network_requests()
  - screenshot(path), save_session(name), load_session(name)
  - batch(commands), close()
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _safe_resolve_binary() -> str | None:
    """Resolve the agent-browser binary path, never raising.

    Returns the absolute path string when available, else None. Wrapped in
    a broad try/except so unusual PATH/shutil conditions (e.g. OSError on
    read-only filesystems, ImportError on a missing shim) do not crash the
    engine on import.
    """
    try:
        return shutil.which("agent-browser")
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Failed to resolve agent-browser binary: %s", exc)
        return None


class AgentBrowserOperator:
    """Async wrapper around the ``agent-browser`` CLI (Vercel).

    All public methods are async and return parsed JSON / strings. When
    agent-browser is not installed, every call returns None and logs a
    warning. The fallback path is HTTPX-only recon — see
    ``src.agents.recon``.
    """

    def __init__(self, engagement_id: str = "default", headless: bool = True) -> None:
        self.engagement_id = engagement_id
        self.headless = headless
        try:
            self._binary = _safe_resolve_binary()
            self.is_available = self._binary is not None
        except Exception as exc:  # pragma: no cover — defensive
            # Last-resort guard: never let operator construction crash the
            # engine. We degrade to HTTPX-only recon and continue.
            logger.warning(
                "agent-browser operator init failed (%s) — falling back to "
                "HTTPX-only recon",
                exc,
            )
            self._binary = None
            self.is_available = False
        if not self.is_available:
            logger.warning(
                "agent-browser not found on PATH — falling back to HTTPX-only recon. "
                "Run bin/install_browser.sh to install it."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def open(self, url: str) -> dict[str, Any] | None:
        """Open a URL in the browser. Returns ``{"ok": True, "url": ...}`` on success."""
        return await self._run(["open", url], parse_json=False)

    async def snapshot(self, interactive_only: bool = True) -> dict[str, Any] | None:
        """Capture a DOM snapshot with ``@eN`` refs for interactive elements.

        Returns a parsed dict like
        ``{"refs": {"@e1": {"tag": "button", "text": "Login"}}, "title": "..."}``
        on success. None if unavailable.
        """
        args = ["snapshot", "-i", "--json"] if interactive_only else ["snapshot", "--json"]
        result = await self._run(args, parse_json=True)
        return result if isinstance(result, dict) else None

    async def click(self, ref: str) -> dict[str, Any] | None:
        """Click the element identified by ref (e.g. '@e1')."""
        return await self._run(["click", ref], parse_json=False)

    async def fill(self, ref: str, text: str) -> dict[str, Any] | None:
        """Fill text into the element identified by ref."""
        return await self._run(["fill", ref, text], parse_json=False)

    async def navigate(self, url: str) -> dict[str, Any] | None:
        """Navigate the current page to a new URL."""
        return await self._run(["open", url], parse_json=False)

    async def get_links(self) -> list[dict[str, Any]]:
        """Extract link refs and URLs from the current snapshot."""
        snap = await self.snapshot(interactive_only=False)
        if not snap:
            return []
        links: list[dict[str, Any]] = []
        for ref, info in (snap.get("refs") or {}).items():
            if (info.get("tag") or "").lower() == "a":
                links.append({"ref": ref, "href": info.get("href"), "text": info.get("text", "")})
        return links

    async def get_network_requests(self) -> list[dict[str, Any]]:
        """Return captured network requests for API endpoint discovery."""
        result = await self._run(["network", "requests", "--json"], parse_json=True)
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "requests" in result:
            return list(result["requests"])
        return []

    async def screenshot(self, path: str | Path) -> dict[str, Any] | None:
        """Save a screenshot to ``path``."""
        return await self._run(["screenshot", str(path)], parse_json=False)

    async def save_session(self, name: str) -> dict[str, Any] | None:
        """Persist the current browser session (cookies, storage, tabs)."""
        return await self._run(["state", "save", name], parse_json=False)

    async def load_session(self, name: str) -> dict[str, Any] | None:
        """Load a previously saved browser session."""
        return await self._run(["state", "load", name], parse_json=False)

    async def batch(self, commands: list[str]) -> dict[str, Any] | None:
        """Run multiple agent-browser commands in one subprocess call."""
        return await self._run(["batch", *commands], parse_json=False)

    async def new_tab(self, url: str = "", label: str = "") -> dict[str, Any] | None:
        """Open a new tab, optionally navigating to url and labelling it."""
        args = ["tab", "new"]
        if label:
            args.extend(["--label", label])
        if url:
            args.append(url)
        return await self._run(args, parse_json=False)

    async def close(self) -> dict[str, Any] | None:
        """Close the browser session."""
        return await self._run(["close"], parse_json=False)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run(
        self, args: list[str], parse_json: bool = True
    ) -> dict[str, Any] | list[Any] | str | None:
        """Shell out to agent-browser and return the parsed result."""
        if not self.is_available or not self._binary:
            return None

        try:
            cmd = [self._binary, *args]
        except TypeError as exc:  # pragma: no cover — defensive
            logger.warning("agent-browser command build failed: %s", exc)
            self.is_available = False
            return None

        if self.headless and "--headless" not in args:
            cmd.insert(1, "--headless")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            logger.warning("agent-browser %s timed out", args[0])
            return None
        except FileNotFoundError:
            logger.warning("agent-browser binary disappeared")
            self.is_available = False
            return None
        except Exception as exc:
            logger.warning("agent-browser subprocess failed: %s", exc)
            return None

        if proc.returncode != 0:
            err_text = (stderr or b"").decode("utf-8", errors="replace")[:500]
            logger.warning("agent-browser %s returned %d: %s", args[0], proc.returncode, err_text)
            return None

        out_text = (stdout or b"").decode("utf-8", errors="replace").strip()
        if not out_text:
            return None

        if not parse_json:
            return out_text

        try:
            return json.loads(out_text)
        except json.JSONDecodeError:
            # Some commands return non-JSON (e.g. plain text confirmation)
            return {"stdout": out_text}
