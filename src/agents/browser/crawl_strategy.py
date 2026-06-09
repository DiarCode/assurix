"""CrawlStrategy — surface discovery for the HypothesisOrchestrator.

Combines multiple signals to build a complete picture of the target's
attack surface:
  - agent-browser: interactive BFS via snapshot+ref
  - HTTPX: shallow link discovery (used as fallback)
  - robots.txt: hidden paths from Disallow entries
  - sitemap.xml: known pages (crawl > 90% when present)
  - network requests: API endpoints from JS-driven navigation

When agent-browser is unavailable, the strategy falls back to HTTPX-only
and adjusts its detection threshold (per plan §3 degraded-mode note).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from src.agents.browser.agent_browser_operator import AgentBrowserOperator

logger = logging.getLogger(__name__)


@dataclass
class SurfaceData:
    """Aggregated attack surface for a target.

    Fields:
      pages:        URLs discovered across all sources
      endpoints:    API endpoints (paths only, no query)
      forms:        Discovered forms [{action, method, fields}]
      technologies: Detected tech (headers, meta tags, JS bundles)
      auth_pages:   URLs containing login/auth keywords
      cookies:      Set-Cookie values seen
      headers:      HTTP response headers from the landing page
      meta_tags:    <meta> tag name→content map
      js_bundles:   Paths to JS bundles
    """
    pages: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    auth_pages: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    meta_tags: dict[str, str] = field(default_factory=dict)
    js_bundles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pages": self.pages,
            "endpoints": self.endpoints,
            "forms": self.forms,
            "technologies": self.technologies,
            "auth_pages": self.auth_pages,
            "cookies": self.cookies,
            "headers": self.headers,
            "meta_tags": self.meta_tags,
            "js_bundles": self.js_bundles,
        }


class CrawlStrategy:
    """Multi-source surface discovery."""

    def __init__(
        self,
        max_pages: int = 200,
        max_depth: int = 3,
        follow_external: bool = False,
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.follow_external = follow_external
        self._visited: set[str] = set()

    async def crawl(
        self,
        target_url: str,
        agent_browser: AgentBrowserOperator | None = None,
    ) -> SurfaceData:
        """Discover the target's attack surface using all available sources."""
        surface = SurfaceData()
        tasks = [
            self._fetch_landing(target_url, surface),
            self._fetch_robots(target_url, surface),
            self._fetch_sitemap(target_url, surface),
        ]

        # agent-browser BFS if available
        if agent_browser and agent_browser.is_available:
            tasks.append(self._bfs_with_browser(target_url, agent_browser, surface))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Dedupe pages
        surface.pages = sorted(set(surface.pages))
        surface.endpoints = sorted(set(surface.endpoints))
        surface.js_bundles = sorted(set(surface.js_bundles))

        # Infer technologies from headers
        surface.technologies = self._infer_technologies(surface)

        logger.info(
            "CrawlStrategy: %d pages, %d endpoints, %d forms, %d auth_pages",
            len(surface.pages), len(surface.endpoints),
            len(surface.forms), len(surface.auth_pages),
        )
        return surface

    # ------------------------------------------------------------------
    # Source: landing page (always)
    # ------------------------------------------------------------------

    async def _fetch_landing(self, target_url: str, surface: SurfaceData) -> None:
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(target_url)
                surface.headers = dict(resp.headers)
                surface.pages.append(target_url)

                # Cookies
                for k, v in resp.cookies.items():
                    surface.cookies.append(f"{k}={v}")

                # Meta tags + JS bundles from HTML
                html = resp.text
                surface.meta_tags = self._extract_meta_tags(html)
                surface.js_bundles.extend(self._extract_js_bundles(html, target_url))
                surface.forms.extend(self._extract_forms(html, target_url))

                # First-level links via regex (lightweight, no BeautifulSoup)
                surface.pages.extend(self._extract_links(html, target_url))
        except Exception as exc:
            logger.warning("landing page fetch failed: %s", exc)

    # ------------------------------------------------------------------
    # Source: robots.txt
    # ------------------------------------------------------------------

    async def _fetch_robots(self, target_url: str, surface: SurfaceData) -> None:
        robots_url = urljoin(target_url, "/robots.txt")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(robots_url)
                if resp.status_code != 200:
                    return
                # Disallow entries are hidden paths not linked from anywhere
                for match in re.finditer(r"Disallow:\s*(\S+)", resp.text, re.IGNORECASE):
                    path = match.group(1).strip()
                    if not path or path.startswith("*"):
                        continue
                    full = urljoin(target_url, path)
                    surface.pages.append(full)
                    if self._looks_like_auth(path):
                        surface.auth_pages.append(full)
                # Sitemap: hint
                for match in re.finditer(r"Sitemap:\s*(\S+)", resp.text, re.IGNORECASE):
                    surface.pages.append(match.group(1).strip())
        except Exception as exc:
            logger.debug("robots.txt fetch failed: %s", exc)

    # ------------------------------------------------------------------
    # Source: sitemap.xml
    # ------------------------------------------------------------------

    async def _fetch_sitemap(self, target_url: str, surface: SurfaceData) -> None:
        """Fetch and parse sitemap.xml.

        Uses regex extraction rather than ElementTree to avoid XXE and
        billion-laughs vulnerabilities from untrusted XML. Sitemaps are
        simple <loc>URL</loc> documents — a regex is sufficient and safer.
        """
        sitemap_url = urljoin(target_url, "/sitemap.xml")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(sitemap_url)
                if resp.status_code != 200:
                    return
                # Reject responses that contain external entity references (defense in depth)
                if b"<!ENTITY" in resp.content or b"<!DOCTYPE" in resp.content:
                    logger.warning("sitemap contains DOCTYPE/ENTITY — refusing to parse")
                    return
                for match in re.finditer(r"<loc>([^<]+)</loc>", resp.text, re.IGNORECASE):
                    surface.pages.append(match.group(1).strip())
        except Exception as exc:
            logger.debug("sitemap fetch failed: %s", exc)

    # ------------------------------------------------------------------
    # Source: agent-browser BFS (interactive)
    # ------------------------------------------------------------------

    async def _bfs_with_browser(
        self,
        target_url: str,
        agent_browser: AgentBrowserOperator,
        surface: SurfaceData,
    ) -> None:
        """BFS through interactive elements when agent-browser is available."""
        queue: list[tuple[str, int]] = [(target_url, 0)]
        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self._visited or depth > self.max_depth:
                continue
            if not self._same_origin(url, target_url) and not self.follow_external:
                continue
            self._visited.add(url)

            await agent_browser.navigate(url)
            snapshot = await agent_browser.snapshot(interactive_only=True)
            if not snapshot:
                continue

            # Discover links from snapshot
            for link in await agent_browser.get_links():
                href = link.get("href")
                if href:
                    full = urljoin(url, href)
                    surface.pages.append(full)
                    if self._looks_like_auth(full):
                        surface.auth_pages.append(full)
                    queue.append((full, depth + 1))

            # Capture API endpoints from network
            for req in await agent_browser.get_network_requests():
                parsed = urlparse(req.get("url", ""))
                if parsed.scheme in ("http", "https"):
                    surface.endpoints.append(parsed.path)

    # ------------------------------------------------------------------
    # HTML parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_meta_tags(html: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for match in re.finditer(
            r'<meta\s+[^>]*?(?:name|property)=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            out[match.group(1).lower()] = match.group(2)
        return out

    @staticmethod
    def _extract_js_bundles(html: str, base_url: str) -> list[str]:
        bundles: list[str] = []
        for pattern in (
            r'<script\s+[^>]*src=["\']([^"\']+\.js)',
            r'<link\s+[^>]*rel=["\']modulepreload["\'][^>]*href=["\']([^"\']+\.js)',
        ):
            for match in re.finditer(pattern, html, re.IGNORECASE):
                src = match.group(1)
                if src.startswith("http"):
                    bundles.append(src)
                else:
                    bundles.append(urljoin(base_url, src))
        return bundles

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> list[dict[str, Any]]:
        forms: list[dict[str, Any]] = []
        for form_match in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            form_tag = form_match.group(0)
            action_m = re.search(r'action=["\']([^"\']*)', form_tag, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)', form_tag, re.IGNORECASE)
            action = action_m.group(1) if action_m else ""
            method = (method_m.group(1) if method_m else "GET").upper()
            fields: list[str] = []
            for input_m in re.finditer(
                r'<(?:input|textarea|select)\b[^>]*?(?:name|id)=["\']([^"\']+)',
                form_match.group(1), re.IGNORECASE,
            ):
                fields.append(input_m.group(1))
            forms.append({
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "fields": fields,
            })
        return forms

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[str]:
        links: list[str] = []
        for m in re.finditer(r'<a\s+[^>]*href=["\']([^"\']+)', html, re.IGNORECASE):
            href = m.group(1)
            if href.startswith(("javascript:", "mailto:", "#")):
                continue
            links.append(urljoin(base_url, href))
        return links

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    AUTH_KEYWORDS = ("login", "signin", "auth", "admin", "account", "register", "signup", "session", "oauth")

    @classmethod
    def _looks_like_auth(cls, url: str) -> bool:
        path = url.lower()
        return any(kw in path for kw in cls.AUTH_KEYWORDS)

    @staticmethod
    def _same_origin(url_a: str, url_b: str) -> bool:
        a, b = urlparse(url_a), urlparse(url_b)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)

    @staticmethod
    def _infer_technologies(surface: SurfaceData) -> list[str]:
        techs: set[str] = set()
        server = surface.headers.get("server", "").lower()
        if "nginx" in server:
            techs.add("nginx")
        if "apache" in server:
            techs.add("apache")
        powered = surface.headers.get("x-powered-by", "").lower()
        for kw in ("php", "express", "next", "nuxt", "rails", "django", "flask", "tomcat"):
            if kw in powered:
                techs.add(kw)
        if any("/_nuxt/" in js for js in surface.js_bundles):
            techs.add("nuxt")
        if any("/_next/" in js for js in surface.js_bundles):
            techs.add("next")
        if any("react" in js.lower() for js in surface.js_bundles):
            techs.add("react")
        if "wp-content" in str(surface.pages) or "wp-includes" in str(surface.pages):
            techs.add("wordpress")
        return sorted(techs)
