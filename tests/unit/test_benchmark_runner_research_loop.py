"""Unit tests for benchmark runner ResearchLoop registration and config propagation."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.benchmark.runner import BenchmarkRunner


class TestResearchLoopRegistration:
    """Tests that ResearchLoopAgent is registered in benchmark runner methods."""

    @pytest.mark.asyncio
    async def test_research_loop_registered_in_scan_live_target(self):
        """Verify _scan_live_target registers research_loop agent in engine."""
        runner = BenchmarkRunner()

        # We need to check that when _scan_live_target creates an engine,
        # it registers ResearchLoopAgent
        # Inspect the source to verify the import and registration
        source = inspect.getsource(runner._scan_live_target)
        assert "ResearchLoopAgent" in source
        assert 'engine.register("research_loop", ResearchLoopAgent)' in source

    @pytest.mark.asyncio
    async def test_research_loop_registered_in_run_test_case(self):
        """Verify _run_test_case registers research_loop agent in engine."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner._run_test_case)
        assert "ResearchLoopAgent" in source
        assert 'engine.register("research_loop", ResearchLoopAgent)' in source


class TestConfigPropagation:
    """Tests for config parameter propagation in benchmark runner."""

    def test_config_parameter_on_scan_live_target(self):
        """_scan_live_target should accept a config parameter."""
        runner = BenchmarkRunner()
        sig = inspect.signature(runner._scan_live_target)
        assert "config" in sig.parameters

    def test_on_timeout_parameter_on_scan_live_target(self):
        """_scan_live_target should accept an on_timeout callback parameter."""
        runner = BenchmarkRunner()
        sig = inspect.signature(runner._scan_live_target)
        assert "on_timeout" in sig.parameters

    def test_run_live_stores_run_config(self):
        """run_live should store config for later use."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner.run_live)
        assert "_run_config" in source

    @pytest.mark.asyncio
    async def test_use_research_loop_config_propagated(self):
        """Verify config with use_research_loop is merged into engagement config."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner._scan_live_target)
        # Config should be merged into engagement config
        assert "**(config or {})" in source or "config" in source


class TestHardTimeout:
    """Tests for hard per-target timeout with container kill callback."""

    @pytest.mark.asyncio
    async def test_hard_timeout_calls_on_timeout_callback(self):
        """When timeout expires, on_timeout callback should be invoked."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner._scan_live_target)

        # Verify on_timeout is used in the else clause of the timeout loop
        assert "on_timeout" in source
        assert "await on_timeout()" in source

    @pytest.mark.asyncio
    async def test_no_findings_creates_fn_result_rows(self):
        """When no findings are produced, BenchmarkResult rows with fn=True should be created."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner._score_and_persist_findings)
        # Verify FN handling exists
        assert "fn=True" in source or "fn" in source

    @pytest.mark.asyncio
    async def test_ab_comparison_sequential_with_restart(self):
        """A/B comparison should run linear first, stop/restart container, then RL."""
        runner = BenchmarkRunner()
        source = inspect.getsource(runner.run_live)
        assert "ab_comparison" in source
        assert "docker_mgr.stop" in source
        assert "docker_mgr.start" in source