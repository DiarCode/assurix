"""Phase 5: CLI app tests for the unified Assurix CLI.

The CLI is intentionally minimal: only `assurix scan <target>` and
`--help`. No modes, no orchestrators, no depth-pass flags, no
strict-gate flags. The default engagement config IS the only config.

These tests verify:
- The CLI exposes only the `scan` command (plus default --help).
- The agent registry contains exactly the expected names (no v1/v2
  aliases).
- The engagement is created with the canonical full-deep config.
- The canonical config is the operator-only contract (the CLI never
  accepts overrides for those keys).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from src.cli import (
    DEFAULT_ENGAGEMENT_CONFIG,
    _register_default_agents,
    app,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# App structure — minimal surface
# ---------------------------------------------------------------------------


class TestAppStructure:
    def test_top_level_commands(self) -> None:
        """The CLI exposes only `scan` (no status, targets, report, server, benchmark)."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.stdout
        # Lock the subcommand shape: the parent usage line must show
        # `Usage: assurix [OPTIONS] COMMAND [ARGS]...` (i.e. `scan` is a
        # subcommand, not a hoisted argument). If the Typer app collapses
        # into a single command, the parent usage would become
        # `Usage: assurix [OPTIONS] TARGET`. See `invoke_without_command=True`
        # + `@app.callback()` in `src/cli.py`.
        assert "COMMAND" in result.stdout, (
            f"`scan` must be a subcommand, but parent usage was:\n{result.stdout}"
        )
        # And the subcommand's own usage must accept TARGET.
        sub = runner.invoke(app, ["scan", "--help"])
        assert sub.exit_code == 0
        assert "Usage: assurix scan" in sub.stdout
        assert "TARGET" in sub.stdout
        # Verify removed commands are not registered as Typer subcommands.
        # We check the registered command names directly rather than the
        # rendered help text, because words like "report" can legitimately
        # appear in command docstrings ("writes a written report").
        from src.cli import app as typer_app
        registered = {cmd.name for cmd in (typer_app.registered_commands or [])}
        for removed in ("status", "targets", "report", "server", "benchmark"):
            assert removed not in registered, (
                f"Removed command {removed!r} must not be registered"
            )

    def test_no_mode_flag(self) -> None:
        """The scan command must not expose --mode / --orchestrator / etc."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        for removed in (
            "--mode",
            "--orchestrator",
            "--no-depth-pass",
            "--depth-pass-budget-minutes",
            "--iterations",
            "--strict-finding-gate",
        ):
            assert removed not in result.stdout, (
                f"Removed flag {removed!r} must not appear in scan --help"
            )

    def test_scan_help_shows_target_only(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.stdout or "target" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    def test_register_includes_canonical_agents(self) -> None:
        engine = MagicMock()
        _register_default_agents(engine)
        registered_names = {call.args[0] for call in engine.register.call_args_list}
        for required in (
            "planner",
            "planner_mcts",
            "hypothesis_orchestrator",
            "research_loop",
            "recon",
            "pentester",
            "reporter",
        ):
            assert required in registered_names, f"{required} missing from registry"

    def test_no_legacy_planner_aliases(self) -> None:
        engine = MagicMock()
        _register_default_agents(engine)
        registered_names = {call.args[0] for call in engine.register.call_args_list}
        for removed in ("planner_linear", "planner_egats"):
            assert removed not in registered_names, (
                f"Removed alias {removed!r} must not be registered"
            )

    def test_register_hypothesis_orchestrator_class_is_correct(self) -> None:
        engine = MagicMock()
        _register_default_agents(engine)
        from src.agents.hypothesis_orchestrator import HypothesisOrchestrator
        for call in engine.register.call_args_list:
            if call.args[0] == "hypothesis_orchestrator":
                assert call.args[1] is HypothesisOrchestrator
                return
        pytest.fail("hypothesis_orchestrator not registered")


# ---------------------------------------------------------------------------
# Default engagement config — single source of truth
# ---------------------------------------------------------------------------


class TestDefaultConfig:
    def test_full_deep_mode_is_default(self) -> None:
        """The canonical config must enable the full deep mode stack."""
        assert DEFAULT_ENGAGEMENT_CONFIG["use_depth_pass"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["strict_finding_gate"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["use_research_loop"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["use_hypothesis_orchestrator"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["mode"] == "offensive"
        assert DEFAULT_ENGAGEMENT_CONFIG["max_iterations"] >= 100


# ---------------------------------------------------------------------------
# Scan flow (mocked)
# ---------------------------------------------------------------------------


class TestScanFlow:
    """Verify the engagement config the CLI builds for `assurix scan <target>`."""

    @pytest.mark.asyncio
    async def test_run_scan_uses_full_deep_config(self) -> None:
        from src.cli import _run_scan
        from src.db.models import Target

        captured: dict = {}

        with patch("src.cli.init_db", new_callable=AsyncMock):
            class _FakeSession:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *a):
                    return None

                async def execute(self, stmt):
                    return MagicMock(scalar_one_or_none=MagicMock(return_value=None))

                def add(self, obj):
                    captured.setdefault("added", []).append(obj)

                async def flush(self):
                    pass

                async def commit(self):
                    pass

                async def get(self, *args, **kwargs):
                    return MagicMock(
                        status=MagicMock(value="running"),
                        iteration_count=0,
                    )

            fake_session = _FakeSession()
            with patch("src.cli.get_db_session", return_value=fake_session):
                with patch("src.cli.dispose_engine", new_callable=AsyncMock):
                    # WorkflowEngine is imported inside _run_scan, so patch
                    # it where it's looked up (the workflow_engine module).
                    with patch(
                        "src.orchestrator.engine.WorkflowEngine"
                    ) as MockEngine:
                        MockEngine.return_value.start_engagement = AsyncMock()
                        MockEngine.return_value.start = MagicMock()
                        MockEngine.return_value.stop = AsyncMock()
                        with pytest.raises(asyncio.TimeoutError):
                            await asyncio.wait_for(
                                _run_scan("http://target"),
                                timeout=1.0,
                            )

        added = captured.get("added", [])
        target_objs = [o for o in added if isinstance(o, Target)]
        eng_objs = [o for o in added if hasattr(o, "config") and hasattr(o, "target_id")]

        # Target was created
        assert len(target_objs) == 1
        assert target_objs[0].verified is True  # full deep mode → verified

        # Engagement was created with the canonical full-deep config
        assert len(eng_objs) == 1
        cfg = eng_objs[0].config
        assert cfg.get("use_depth_pass") is True
        assert cfg.get("strict_finding_gate") is True
        assert cfg.get("use_research_loop") is True
        assert cfg.get("use_hypothesis_orchestrator") is True
        assert cfg.get("mode") == "offensive"
        assert cfg.get("max_iterations") >= 100

    @pytest.mark.asyncio
    async def test_run_scan_reuses_existing_target(self) -> None:
        """If the target already exists, do not create a duplicate target row."""
        from src.cli import _run_scan
        from src.db.models import Target

        existing_target = MagicMock(spec=Target)
        existing_target.id = "existing-id"
        existing_target.url = "http://already-exists"

        with patch("src.cli.init_db", new_callable=AsyncMock):

            class _FakeSession:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *a):
                    return None

                async def execute(self, stmt):
                    return MagicMock(scalar_one_or_none=MagicMock(return_value=existing_target))

                def add(self, obj):
                    if isinstance(obj, Target):
                        raise AssertionError("Should not add a new Target row")

                async def flush(self):
                    pass

                async def commit(self):
                    pass

                async def get(self, *args, **kwargs):
                    return MagicMock(status=MagicMock(value="running"), iteration_count=0)

            with patch("src.cli.get_db_session", return_value=_FakeSession()):
                with patch("src.cli.dispose_engine", new_callable=AsyncMock):
                    with patch(
                        "src.orchestrator.engine.WorkflowEngine"
                    ) as MockEngine:
                        MockEngine.return_value.start_engagement = AsyncMock()
                        MockEngine.return_value.start = MagicMock()
                        MockEngine.return_value.stop = AsyncMock()
                        with pytest.raises(asyncio.TimeoutError):
                            await asyncio.wait_for(
                                _run_scan("http://already-exists"),
                                timeout=1.0,
                            )
