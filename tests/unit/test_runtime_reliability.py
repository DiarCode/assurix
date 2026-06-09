"""Unit tests for the 4 runtime reliability blockers (plan §Step 1).

Verifies the bugs that silently degraded the previous scans:

1. ``bin/install_browser.sh`` exists and is executable.
2. ``Settings.database_path`` defaults to a project-relative path, not
   the absolute ``/data/assurix.db`` from the legacy config.
3. ``Settings.resolve_writable_database_path`` falls back to ``tempdir``
   when the configured directory is read-only.
4. ``PentesterAgent._execute_action`` returns ``None`` for unknown action
   types — it does NOT silently fall back to directory fuzz (the bug
   that produced duplicate "info_disclosure" findings).
5. ``AgentBrowserOperator``'s binary resolution tolerates a missing
   binary (the optional-dependency contract).
"""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Database-path default
# ---------------------------------------------------------------------------


class TestDatabasePath:
    def test_default_database_path_is_relative(self) -> None:
        """The default database_url must NOT be ``/data/assurix.db``.

        Plan §Step 1 fixes the legacy default
        ``sqlite+aiosqlite:///data/assurix.db`` (which made the path
        absolute and broke read-only deployments) to the project-relative
        ``./data/assurix.db``. This test guards against regression.

        We instantiate a Settings subclass with ``env_file=None`` AND
        temporarily clear ``DATABASE_URL`` from ``os.environ`` — a
        developer's local ``.env`` may have set the env var; the field
        default is what we are regression-guarding.
        """
        import os
        from pydantic_settings import SettingsConfigDict
        from src.core.config import Settings

        class _Clean(Settings):
            model_config = SettingsConfigDict(
                env_file=None, env_file_encoding="utf-8", extra="ignore"
            )

        saved = os.environ.pop("DATABASE_URL", None)
        try:
            s = _Clean()
            # The default URL embeds the path; we want a project-relative one.
            assert s.database_url == "sqlite+aiosqlite:///./data/assurix.db", (
                f"default database_url drifted: {s.database_url!r}"
            )
            # And the resolved Path must be relative to the project root,
            # not the absolute /data/foo that triggered the original bug.
            path = s.database_path
            assert not str(path).startswith("/data/"), (
                f"database_path is absolute /data/... — legacy bug regression: {path!r}"
            )
            # The basename must still be the documented file.
            assert path.name == "assurix.db"
        finally:
            if saved is not None:
                os.environ["DATABASE_URL"] = saved

    def test_database_path_override_takes_precedence(self) -> None:
        """``ASSURIX_DATABASE_PATH`` env var overrides the default."""
        from src.core.config import Settings
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "override.db"
            s = Settings(ASSURIX_DATABASE_PATH=str(custom))
            # ``database_path`` calls ``.resolve()`` which on macOS
            # returns ``/private/tmp/...`` for paths under ``/tmp``.
            # Compare with ``resolve()`` applied to the custom path so
            # the test is portable.
            assert s.database_path == custom.resolve()

    def test_database_path_falls_back_on_readonly(self, tmp_path: Path) -> None:
        """When the configured directory is read-only, fall back to ``tempdir``.

        Plan §Step 1 adds ``read_only_fallback=True`` by default and the
        helper ``resolve_writable_database_path()`` writes a probe file
        to test writability. If the probe fails (read-only dir), the
        helper returns ``tempfile.gettempdir() / assurix.db`` and logs
        a TECHNIQUE MEMORY WILL NOT PERSIST warning.
        """
        from src.core.config import Settings

        # Make a path inside an unwriteable directory.
        unwritable = tmp_path / "readonly" / "assurix.db"
        unwritable.parent.mkdir()
        # chmod -w on the parent so the write probe fails.
        unwritable.parent.chmod(stat.S_IRUSR | stat.S_IXUSR)

        try:
            s = Settings(
                ASSURIX_DATABASE_PATH=str(unwritable),
                read_only_fallback=True,
            )
            resolved = s.resolve_writable_database_path()
            # Must NOT return the unwritable path.
            assert resolved != unwritable
            # Must be inside the tempdir.
            assert str(resolved).startswith(tempfile.gettempdir())
            assert resolved.name == "assurix.db"
        finally:
            # Restore writability so the test runner can clean up.
            unwritable.parent.chmod(stat.S_IRWXU)


# ---------------------------------------------------------------------------
# Pentester: unknown action types
# ---------------------------------------------------------------------------


class TestPentesterUnknownAction:
    @pytest.mark.asyncio
    async def test_pentester_unknown_action_skips_not_fuzz(self) -> None:
        """An unknown LATS action type must log + return None, NOT directory-fuzz.

        The bug: the legacy ``case _`` branch fell through to
        ``fuzz_directory``, which produced duplicate "info_disclosure"
        findings. The fix (plan §Step 1) returns ``None`` and logs a
        warning. We assert both the return value and that the fuzzer
        was NOT called.
        """
        from src.agents.pentester import PentesterAgent

        agent = PentesterAgent()
        # Replace the fuzzer with a mock so we can assert it was not called.
        agent.fuzzer = MagicMock()
        agent.fuzzer.fuzz_directory = AsyncMock(
            return_value={"findings": [{"title": "should_not_appear"}]}
        )
        agent.auth_tester = MagicMock()
        agent.auth_tester.discover_login_pages = AsyncMock(return_value=[])
        agent.credential_tester = MagicMock()
        agent.credential_tester.test_credentials = AsyncMock(return_value=[])
        agent.idor_validator = MagicMock()
        agent.idor_validator.validate_idor = AsyncMock(return_value=[])
        agent.timing_analyzer = MagicMock()
        agent.timing_analyzer.test_blind_sqli = AsyncMock(return_value=[])
        agent.graphql_scanner = MagicMock()
        agent.graphql_scanner.scan = AsyncMock(return_value=[])
        agent.websocket_scanner = MagicMock()
        agent.websocket_scanner.scan = AsyncMock(return_value=[])
        agent.xss_pipeline = MagicMock()
        agent.xss_pipeline.scan = AsyncMock(return_value=[])
        agent.sqli_pipeline = MagicMock()
        agent.sqli_pipeline.scan = AsyncMock(return_value=[])
        agent.ssrf_pipeline = MagicMock()
        agent.ssrf_pipeline.scan = AsyncMock(return_value=[])
        agent.cmdi_pipeline = MagicMock()
        agent.cmdi_pipeline.scan = AsyncMock(return_value=[])
        agent.brute_forcer = MagicMock()
        agent.brute_forcer.brute_force_directories = AsyncMock(return_value=[])
        agent.brute_forcer.brute_force_parameters = AsyncMock(return_value=[])
        agent.brute_forcer.brute_force_extensions = AsyncMock(return_value=[])
        agent.request_interceptor = MagicMock()
        agent.request_interceptor.test_header_manipulation = AsyncMock(return_value=[])

        result = await agent._execute_action(
            action_type="definitely_not_a_real_action_type_xyz",
            target="https://example.com",
            observations={"endpoints": []},
            session_mgr=MagicMock(),
        )

        # Must NOT be the directory-fuzz result.
        assert result is None, (
            f"unknown action should return None, got {result!r}"
        )
        # The fuzzer must not have been called at all.
        agent.fuzzer.fuzz_directory.assert_not_called()
        agent.fuzzer.fuzz_parameters.assert_not_called()
        agent.fuzzer.fuzz_post_body.assert_not_called()


# ---------------------------------------------------------------------------
# Browser binary resolution
# ---------------------------------------------------------------------------


class TestBrowserBinaryResolution:
    def test_safe_resolve_binary_tolerates_missing_binary(self) -> None:
        """``_safe_resolve_binary`` must not raise when the binary is missing.

        The plan §Step 1 fix wraps the binary lookup in try/except so a
        read-only deployment (no browser binary) does not crash the
        scan. We patch ``shutil.which`` to return ``None`` so the
        helper bails early; the assertion is that it returns cleanly
        rather than raising.
        """
        from src.agents.browser import agent_browser_operator as abo

        with patch(
            "src.agents.browser.agent_browser_operator.shutil.which",
            return_value=None,
        ):
            # Should not raise.
            result = abo._safe_resolve_binary()
        assert result is None, (
            f"_safe_resolve_binary should return None on missing binary, got {result!r}"
        )


# ---------------------------------------------------------------------------
# Install script
# ---------------------------------------------------------------------------


class TestInstallBrowserScript:
    def test_install_browser_sh_exists_and_is_executable(self) -> None:
        """``bin/install_browser.sh`` must exist and be executable.

        Plan §Step 1 introduces the script; the runtime reliability test
        catches accidental deletion or chmod -x regressions.
        """
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "bin" / "install_browser.sh"
        assert script.exists(), f"{script} missing"
        mode = script.stat().st_mode
        assert mode & stat.S_IXUSR, f"{script} is not executable (mode={oct(mode)})"
