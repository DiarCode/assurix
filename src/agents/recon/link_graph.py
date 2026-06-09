"""Adjacency graph for the EGATS planner's BFS recon phase.

The planner's ``_bfs_recon`` (src/agents/planner_egats.py) consumes a
callable ``graph(url) -> list[str]`` that returns neighbor URLs. The
engine, however, persists job payloads as JSON, so a live callable
can't travel through the durable job contract.

This module provides ``LinkGraph`` — a JSON-friendly adjacency
container with a ``neighbors(url)`` method that the planner can call
just like a callable. The engine serialises/deserialises it via
``to_dict`` / ``from_dict``.

Why a new module (and not a method on ``ReconAgent``):
- ``ReconAgent`` is async and tied to the HTTPX fetch + AI browser
  pipeline. ``LinkGraph`` is a pure data structure that the planner
  can call from sync code without blocking on I/O.
- Adjacency is reusable across planner invocations. Storing it in
  ``engagement.config["link_graph"]`` lets the LATS-backtracking
  branch (engine.py:671-672) reuse the same graph without re-crawling.

JSON contract: ``to_dict`` returns ``{"adjacency": {url: [neighbor, ...]}}``.
``from_dict`` accepts either that shape or a list of edges ``[[a, b], ...]``
for backwards-compat with the planner's pre-existing return format.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
    re.IGNORECASE,
)


class LinkGraph:
    """URL adjacency map with a sync ``neighbors`` API.

    The graph is keyed by absolute URL. ``neighbors(url)`` returns a
    list of absolute URLs reachable from ``url`` via anchor, script,
    or meta-refresh links — same-domain only.

    The graph is mutable: callers can extend it via ``add_edge`` /
    ``add_node``. ``populate`` does an HTTP-driven BFS to seed it.
    """

    def __init__(self, root_url: str = "") -> None:
        self.root_url = root_url
        # adjacency[url] -> set[neighbor_url]; URL → sorted list on read.
        self._adjacency: dict[str, set[str]] = {}

    # --- Population -----------------------------------------------------

    @staticmethod
    def _normalize(url: str) -> str:
        """Normalize a URL to ``scheme://host/path`` (no query, no fragment).

        The planner's BFS treats query strings and fragments as opaque
        endpoints. Stripping them keeps the adjacency compact and
        cycle-safe.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/") or url

    def add_edge(self, src: str, dst: str) -> None:
        src_n = self._normalize(src)
        dst_n = self._normalize(dst)
        if not src_n or not dst_n or src_n == dst_n:
            return
        # Same-domain only — the recon scope is one host.
        if urlparse(src_n).netloc != urlparse(dst_n).netloc:
            return
        self._adjacency.setdefault(src_n, set()).add(dst_n)
        self._adjacency.setdefault(dst_n, set())  # ensure node exists

    def add_node(self, url: str) -> None:
        url_n = self._normalize(url)
        if url_n:
            self._adjacency.setdefault(url_n, set())

    @staticmethod
    def extract_links(html: str, base_url: str) -> set[str]:
        """Pull <a href>, <script src>, and meta-refresh targets from HTML."""
        links: set[str] = set()
        for match in LINK_RE.findall(html):
            full = urljoin(base_url, match)
            n = LinkGraph._normalize(full)
            if n:
                links.add(n)
        for match in SCRIPT_SRC_RE.findall(html):
            full = urljoin(base_url, match)
            n = LinkGraph._normalize(full)
            if n:
                links.add(n)
        for match in META_REFRESH_RE.findall(html):
            full = urljoin(base_url, match.strip())
            n = LinkGraph._normalize(full)
            if n:
                links.add(n)
        return links

    async def populate(
        self,
        target_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        max_pages: int = 30,
        max_depth: int = 2,
        timeout: float = 10.0,
    ) -> int:
        """BFS-crawl ``target_url`` and seed adjacency.

        Returns the number of pages fetched. ``client`` is owned by the
        caller; if absent, a temporary client is created with the given
        ``timeout``. ``max_pages`` and ``max_depth`` mirror the recon
        agent's defaults (``src/agents/recon.py:52``).
        """
        self.root_url = target_url
        self._adjacency.clear()
        if not target_url:
            return 0

        owns_client = client is None
        if owns_client:
            client = httpx.AsyncClient(
                timeout=timeout, follow_redirects=True, max_redirects=5,
            )
        try:
            visited: set[str] = set()
            queue: list[tuple[str, int]] = [(target_url, 0)]
            fetched = 0
            while queue and fetched < max_pages:
                url, depth = queue.pop(0)
                url_n = self._normalize(url)
                if not url_n or url_n in visited or depth > max_depth:
                    continue
                visited.add(url_n)
                try:
                    resp = await client.get(url_n)
                except httpx.RequestError as exc:
                    logger.debug("LinkGraph.populate: fetch %s failed: %s", url_n, exc)
                    continue
                fetched += 1
                self.add_node(url_n)
                ct = resp.headers.get("content-type", "")
                if resp.status_code == 200 and "text/html" in ct:
                    for neighbor in self.extract_links(resp.text, url_n):
                        self.add_edge(url_n, neighbor)
                        if neighbor not in visited:
                            queue.append((neighbor, depth + 1))
            return fetched
        finally:
            if owns_client:
                await client.aclose()

    # --- Lookup (callable-like API used by the planner) ----------------

    def neighbors(self, url: str) -> list[str]:
        """Return the sorted neighbor list for ``url`` (the planner's contract)."""
        url_n = self._normalize(url)
        if url_n not in self._adjacency:
            return []
        return sorted(self._adjacency[url_n])

    def __call__(self, url: str) -> list[str]:
        # Convenience: planners/tests that pass the graph as a callable.
        return self.neighbors(url)

    # --- Properties for the planner's result ---------------------------

    @property
    def nodes(self) -> list[str]:
        return sorted(self._adjacency.keys())

    @property
    def edges(self) -> list[list[str]]:
        out: list[list[str]] = []
        for src, neighbors in self._adjacency.items():
            for dst in neighbors:
                out.append([src, dst])
        return out

    # --- (De)serialization ---------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_url": self.root_url,
            "adjacency": {src: sorted(nbrs) for src, nbrs in self._adjacency.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "LinkGraph | None":
        """Reconstruct a graph from a serialized dict.

        Returns None when ``data`` is missing/empty so callers can
        short-circuit the planner's no-op path. Accepts two shapes:
        - ``{"adjacency": {url: [nbr, ...]}, "root_url": str}`` — new
        - ``[[a, b], [a, c], ...]`` — legacy edge-list, build adjacency
        """
        if not data:
            return None
        g = cls()
        if isinstance(data, list):
            # Legacy edge-list form.
            for edge in data:
                if (
                    isinstance(edge, (list, tuple))
                    and len(edge) == 2
                    and isinstance(edge[0], str)
                    and isinstance(edge[1], str)
                ):
                    g.add_edge(edge[0], edge[1])
            return g
        if not isinstance(data, dict):
            return None
        g.root_url = data.get("root_url", "")
        adj = data.get("adjacency", {})
        if not isinstance(adj, dict):
            return g
        for src, neighbors in adj.items():
            if not isinstance(src, str):
                continue
            g._adjacency.setdefault(g._normalize(src), set())
            if isinstance(neighbors, list):
                for n in neighbors:
                    if isinstance(n, str):
                        g.add_edge(src, n)
        return g


__all__ = ["LinkGraph"]
