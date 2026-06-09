"""Regression: CLI startup must clean up stale RUNNING/RESEARCHING/PAUSED engagements.

When a scan crashes (engine killed, host reboot, Ctrl+C at the wrong moment),
the engagement row can be left in a non-terminal state. The next `assurix
scan` run would otherwise inherit a stuck engagement, confuse the dashboard,
and let old rows block new runs.

Fix E adds `_cleanup_stale_engagements()` to the CLI's `_run_scan()`. It
flips engagements older than `stale_threshold_hours` to FAILED with the
audit log marker `cleanup_reason: "stale_on_startup"`.

This test pins the source so the cleanup stays in place.
"""

from __future__ import annotations

import inspect


class TestStaleEngagementCleanup:
    def test_cleanup_function_exists(self) -> None:
        """The CLI must define a stale-engagement cleanup function."""
        from src import cli

        assert hasattr(cli, "_cleanup_stale_engagements"), (
            "CLI must define _cleanup_stale_engagements() for crash recovery."
        )

    def test_cleanup_targets_running_researching_paused(self) -> None:
        """The cleanup must sweep RUNNING, RESEARCHING, and PAUSED."""
        from src import cli

        src = inspect.getsource(cli._cleanup_stale_engagements)
        assert "RUNNING" in src
        assert "RESEARCHING" in src
        assert "PAUSED" in src

    def test_cleanup_flips_to_failed(self) -> None:
        """The cleanup must set status to FAILED and stamp completed_at."""
        from src import cli

        src = inspect.getsource(cli._cleanup_stale_engagements)
        assert "EngagementStatus.FAILED" in src
        assert "completed_at" in src

    def test_cleanup_uses_threshold(self) -> None:
        """The cleanup must use a time threshold (default 1 hour)."""
        from src import cli

        src = inspect.getsource(cli._cleanup_stale_engagements)
        # Function signature uses stale_threshold_hours (default 1)
        assert "stale_threshold_hours" in src
        # The function computes a threshold via timedelta
        assert "timedelta" in src

    def test_cleanup_called_in_run_scan(self) -> None:
        """_run_scan must invoke the cleanup before creating a new engagement."""
        from src import cli

        src = inspect.getsource(cli._run_scan)
        assert "_cleanup_stale_engagements" in src, (
            "_run_scan must call _cleanup_stale_engagements() at startup."
        )
        # Must be called BEFORE the engagement is created
        create_idx = src.find("session.add(engagement)")
        cleanup_idx = src.find("_cleanup_stale_engagements")
        assert cleanup_idx != -1 and create_idx != -1
        assert cleanup_idx < create_idx, (
            "Cleanup must run before the new engagement is created."
        )


class TestTerminalStatusPrint:
    """The CLI's polling loop must handle both StrEnum and plain str for eng.status."""

    def test_status_printed_via_getattr_value(self) -> None:
        """The status print must use `getattr(eng.status, "value", eng.status)`.

        The ORM can return `eng.status` as a plain `str` (not the
        EngagementStatus StrEnum) depending on the column coercion path.
        Accessing `.value` on a bare `str` raises AttributeError, which
        crashed the CLI after a successful scan. See the post-fix commit
        where this regression appeared (admin.arboard.kz scan, 2026-06-04).
        """
        from src import cli

        src = inspect.getsource(cli._run_scan)
        # The status-print must use a getattr-guard
        assert "eng.status.value" not in src, (
            "Direct `.value` access on eng.status crashes when the ORM "
            "returns a plain str. Use getattr(eng.status, 'value', eng.status)."
        )
        assert "getattr" in src
        assert '"value"' in src
        # Both enum and str paths must work — find the use of getattr
        idx = src.find("getattr(")
        assert idx != -1
        # In a small window after the getattr, "eng.status" must appear as
        # the fallback so the print doesn't crash.
        window = src[idx: idx + 200]
        assert "eng.status" in window

