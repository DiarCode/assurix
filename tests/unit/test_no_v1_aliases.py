"""No v1/v2 aliases. The codebase has one planner, one mode, and no
versioned names anywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_planner_factory_module_deleted() -> None:
    """``src.agents.planner_factory`` must not exist."""
    assert not Path("src/agents/planner_factory.py").exists()


def test_legacy_planner_module_deleted() -> None:
    """``src.agents.planner`` (v1) must not exist."""
    assert not Path("src/agents/planner.py").exists()


def test_planner_egats_module_renamed_to_planner_name() -> None:
    """EGATSPlanner is the only planner, registered under ``name = 'planner'``."""
    from src.agents.planner_egats import EGATSPlanner

    assert EGATSPlanner.name == "planner"


def test_no_planner_linear_imports_in_source() -> None:
    """No source file should import from the legacy ``planner`` module."""
    src_root = Path("src")
    for py in src_root.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        text = py.read_text()
        # The CLI / API / benchmark code may mention the strings for
        # documentation purposes; the *imports* must be gone.
        assert "from src.agents.planner_factory" not in text, (
            f"{py} still imports from planner_factory"
        )
        assert "from src.agents.planner import" not in text, (
            f"{py} still imports from legacy planner"
        )
        assert "import src.agents.planner_factory" not in text, (
            f"{py} still imports planner_factory"
        )


def test_no_planner_linear_strings_in_source() -> None:
    """The strings 'planner_linear' and 'planner_egats' must not appear
    in production source (tests may reference them for migration
    verification)."""
    src_root = Path("src")
    bad_substrings = ("'planner_linear'", '"planner_linear"',
                      "'planner_egats'", '"planner_egats"')
    for py in src_root.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        text = py.read_text()
        for bad in bad_substrings:
            assert bad not in text, (
                f"{py} contains {bad} — remove the v1/v2 alias"
            )


def test_engine_registers_only_planner() -> None:
    """WorkflowEngine must register only the 'planner' key from the planner family."""
    from src.orchestrator.engine import WorkflowEngine

    engine = WorkflowEngine()
    planner_keys = {k for k in engine.agents.keys() if "planner" in k}
    assert planner_keys == {"planner"}, (
        f"Expected only 'planner' in engine.agents, got {planner_keys}"
    )


def test_cli_minimal_surface() -> None:
    """The CLI must expose only `scan` and the default --help."""
    from src.cli import app

    # Typer's `registered_commands` is a list of Click Command objects;
    # `cmd.name` is the registered name (None for the default Typer
    # group). Use the Click introspection helpers to find scan.
    registered_names = set()
    for cmd in (app.registered_commands or []):
        name = cmd.name or cmd.callback.__name__ if cmd.callback else None
        registered_names.add(name)
    # Typer's default-group entry is a sentinel; filter it out.
    registered_names.discard(None)
    assert registered_names == {"scan"}, (
        f"Expected only 'scan', got {registered_names}"
    )


def test_scan_help_has_no_mode_flag() -> None:
    """`scan --help` must not advertise any mode / orchestrator flag."""
    from typer.testing import CliRunner

    from src.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for removed in (
        "--mode", "--orchestrator", "--no-depth-pass",
        "--iterations", "--strict-finding-gate",
    ):
        assert removed not in result.stdout, (
            f"Removed flag {removed!r} still in scan --help"
        )
