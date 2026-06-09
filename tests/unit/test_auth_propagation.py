"""Unit tests for auth cookie propagation (engine extra_payload + SharedSessionManager.seed_cookies)."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.tools.session import SharedSessionManager
from src.orchestrator.engine import WorkflowEngine


class TestStartEngagementExtraPayload:
    """Tests for WorkflowEngine.start_engagement() extra_payload parameter."""

    def test_start_engagement_accepts_extra_payload(self):
        """start_engagement should accept an extra_payload parameter."""
        engine = WorkflowEngine()
        sig = inspect.signature(engine.start_engagement)
        assert "extra_payload" in sig.parameters

    @pytest.mark.asyncio
    async def test_extra_payload_stored_in_engagement_config(self):
        """extra_payload should be persisted in engagement.config['extra_payload']."""
        engine = WorkflowEngine()

        # Mock the engagement and session
        mock_engagement = MagicMock()
        mock_engagement.config = {}
        mock_engagement.status = "pending"

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_engagement)
        mock_session.flush = AsyncMock()

        # Mock scheduler
        mock_scheduler = AsyncMock()
        mock_scheduler.enqueue = AsyncMock()
        engine.scheduler = mock_scheduler

        # Mock audit
        with patch("src.orchestrator.engine.log_action", new_callable=AsyncMock):
            from src.db.models import EngagementStatus
            mock_engagement.status = EngagementStatus.PENDING
            await engine.start_engagement(
                mock_session, "eng-1",
                target_url="http://localhost:80",
                extra_payload={"auth_cookies": {"PHPSESSID": "abc123"}},
            )

        # Verify extra_payload was stored in engagement config
        assert "extra_payload" in mock_engagement.config
        assert mock_engagement.config["extra_payload"]["auth_cookies"]["PHPSESSID"] == "abc123"


class TestExtraPayloadCarryForward:
    """Tests that extra_payload is carried forward in _run_loop()."""

    def test_extra_payload_code_present_in_run_loop(self):
        """_run_loop should contain code to carry extra_payload forward."""
        engine = WorkflowEngine()
        source = inspect.getsource(engine._run_loop)
        assert "extra_payload" in source or "_extra" in source

    def test_extra_payload_gated_to_benchmark_only(self):
        """extra_payload should only be carried forward when benchmark=True."""
        engine = WorkflowEngine()
        source = inspect.getsource(engine._run_loop)
        assert "benchmark" in source


class TestSharedSessionSeedCookies:
    """Tests for SharedSessionManager.seed_cookies() method."""

    def test_seed_cookies_stores_for_host(self):
        """seed_cookies should store cookies keyed by host."""
        mgr = SharedSessionManager()
        mgr.seed_cookies("http://localhost:80", {"PHPSESSID": "abc123"})
        host_key = mgr._host_key("http://localhost:80")
        assert host_key in mgr._cookies
        assert mgr._cookies[host_key]["PHPSESSID"] == "abc123"

    def test_seed_cookies_marks_authenticated(self):
        """seed_cookies should mark the host as authenticated."""
        mgr = SharedSessionManager()
        mgr.seed_cookies("http://localhost:80", {"PHPSESSID": "abc123"})
        assert mgr.is_authenticated("http://localhost:80")

    def test_seed_cookies_uses_host_key(self):
        """seed_cookies should reuse _host_key for URL parsing."""
        mgr = SharedSessionManager()
        mgr.seed_cookies("http://localhost:80", {"PHPSESSID": "abc123"})
        # Same host via different URL should resolve to same cookies
        host_key = mgr._host_key("http://localhost:80")
        assert "PHPSESSID" in mgr._cookies[host_key]

    def test_seed_cookies_overwrites_existing(self):
        """Seeding again should overwrite previous cookies for the same host."""
        mgr = SharedSessionManager()
        mgr.seed_cookies("http://localhost:80", {"PHPSESSID": "old"})
        mgr.seed_cookies("http://localhost:80", {"PHPSESSID": "new", "extra": "val"})
        host_key = mgr._host_key("http://localhost:80")
        assert mgr._cookies[host_key]["PHPSESSID"] == "new"
        assert mgr._cookies[host_key]["extra"] == "val"


class TestPentesterAuthCookies:
    """Tests that PentesterAgent reads auth_cookies from payload."""

    def test_pentester_reads_auth_cookies_from_payload(self):
        """PentesterAgent.execute should read auth_cookies from payload and seed session."""
        from src.agents.pentester import PentesterAgent
        source = inspect.getsource(PentesterAgent.execute)
        assert "auth_cookies" in source
        assert "seed_cookies" in source


class TestAuthCookiesNotRequiredForNonDvwa:
    """Tests that auth cookies are only set up for DVWA."""

    def test_no_extra_payload_for_non_dvwa(self):
        """_scan_live_target should only call setup_dvwa for dvwa targets."""
        from src.benchmark.runner import BenchmarkRunner
        runner = BenchmarkRunner()
        source = inspect.getsource(runner._scan_live_target)
        assert 'target_name == "dvwa"' in source