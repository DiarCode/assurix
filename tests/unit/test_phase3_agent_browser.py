"""Phase 3: agent-browser integration — unit tests.

Verifies:
- AgentBrowserOperator.is_available is False when binary not on PATH
- AgentBrowserOperator methods return None gracefully when unavailable
- SurfaceData dataclass is well-formed
- CrawlStrategy produces a SurfaceData with HTTPX-only sources
- browser/__init__.py exports the new symbols (not the deprecated ones)
- ai_operator and operator carry DEPRECATED docstrings
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestAgentBrowserOperatorAvailability:
    def test_is_available_false_when_binary_missing(self) -> None:
        """If agent-browser is not on PATH, is_available is False."""
        with patch("shutil.which", return_value=None):
            from src.agents.browser.agent_browser_operator import AgentBrowserOperator
            op = AgentBrowserOperator()
            assert op.is_available is False

    def test_methods_return_none_when_unavailable(self) -> None:
        """All async methods return None when agent-browser is missing."""
        with patch("shutil.which", return_value=None):
            from src.agents.browser.agent_browser_operator import AgentBrowserOperator
            op = AgentBrowserOperator()
            assert asyncio.run(op.open("http://x")) is None
            assert asyncio.run(op.snapshot()) is None
            assert asyncio.run(op.click("@e1")) is None
            assert asyncio.run(op.fill("@e1", "text")) is None
            assert asyncio.run(op.get_links()) == []
            assert asyncio.run(op.get_network_requests()) == []
            assert asyncio.run(op.screenshot("/tmp/x.png")) is None
            assert asyncio.run(op.save_session("s1")) is None
            assert asyncio.run(op.load_session("s1")) is None
            assert asyncio.run(op.batch(["open", "x"])) is None
            assert asyncio.run(op.new_tab("http://x", "tab1")) is None
            assert asyncio.run(op.close()) is None


class TestSurfaceData:
    def test_surface_data_default(self) -> None:
        from src.agents.browser.crawl_strategy import SurfaceData
        s = SurfaceData()
        assert s.pages == []
        assert s.endpoints == []
        assert s.forms == []
        assert s.technologies == []
        assert s.auth_pages == []
        assert s.cookies == []
        assert s.headers == {}
        assert s.meta_tags == {}
        assert s.js_bundles == []

    def test_surface_data_to_dict(self) -> None:
        from src.agents.browser.crawl_strategy import SurfaceData
        s = SurfaceData(pages=["http://x"], endpoints=["/api/v1"], forms=[{"action": "/login", "method": "POST", "fields": ["u", "p"]}])
        d = s.to_dict()
        assert d["pages"] == ["http://x"]
        assert d["endpoints"] == ["/api/v1"]
        assert d["forms"][0]["action"] == "/login"


class TestCrawlStrategy:
    def test_looks_like_auth(self) -> None:
        from src.agents.browser.crawl_strategy import CrawlStrategy
        assert CrawlStrategy._looks_like_auth("http://t/login") is True
        assert CrawlStrategy._looks_like_auth("http://t/admin/users") is True
        assert CrawlStrategy._looks_like_auth("http://t/products/123") is False

    def test_same_origin(self) -> None:
        from src.agents.browser.crawl_strategy import CrawlStrategy
        assert CrawlStrategy._same_origin("http://t/a", "http://t/b") is True
        assert CrawlStrategy._same_origin("http://t/a", "https://t/b") is False
        assert CrawlStrategy._same_origin("http://t/a", "http://other/b") is False

    def test_infer_technologies_from_nginx_header(self) -> None:
        from src.agents.browser.crawl_strategy import CrawlStrategy, SurfaceData
        s2 = SurfaceData(headers={"server": "nginx/1.18", "x-powered-by": "PHP/8.0"})
        techs = CrawlStrategy._infer_technologies(s2)
        assert "nginx" in techs
        assert "php" in techs

    def test_infer_technologies_from_nuxt_bundles(self) -> None:
        from src.agents.browser.crawl_strategy import SurfaceData, CrawlStrategy
        s = SurfaceData(js_bundles=["https://x/_nuxt/entry.123.js"])
        techs = CrawlStrategy._infer_technologies(s)
        assert "nuxt" in techs


class TestBrowserModuleExports:
    def test_new_exports_present(self) -> None:
        from src.agents.browser import AgentBrowserOperator, CrawlStrategy, SurfaceData
        assert AgentBrowserOperator is not None
        assert CrawlStrategy is not None
        assert SurfaceData is not None

    def test_legacy_not_in_default_globals(self) -> None:
        """Legacy operators should not be eagerly imported via the package."""
        import src.agents.browser as b
        # The lazy export list shouldn't include AIBrowserOperator/BrowserOperator
        # (downstream code can still import them directly from their modules)
        assert "AIBrowserOperator" not in b.__all__
        assert "BrowserOperator" not in b.__all__


class TestDeprecationDocstrings:
    def test_ai_operator_docstring_marks_deprecated(self) -> None:
        from src.agents.browser import ai_operator
        assert "DEPRECATED" in (ai_operator.__doc__ or "")

    def test_playwright_operator_docstring_marks_deprecated(self) -> None:
        from src.agents.browser import operator
        assert "DEPRECATED" in (operator.__doc__ or "")
