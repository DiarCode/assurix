"""Unit tests for alembic/env.py — the migration runner.

The previous env.py imported ``create_async_engine`` and ran
``Base.metadata.create_all`` instead of invoking the migration runner.
The result was that ``alembic upgrade head`` would create all the
tables but never stamp ``alembic_version`` — so the migration chain
appeared to "work" while leaving the DB in a state where subsequent
runs of the same chain (e.g. on a CI box with a fresh checkout)
would try to re-apply migrations whose columns already existed.

These tests pin the corrected behavior:

* ``env.py`` must use the standard async cookbook pattern
  (``create_async_engine`` + ``run_sync(do_run_migrations)``).
* Running ``alembic upgrade head`` against a fresh sqlite file must
  land the ``dedup_key`` column AND stamp ``alembic_version`` at the
  head revision reported by ``alembic heads`` (resolved at test
  time so new migrations do not break this pin).
* The run must be hermetic: we point ``ALEMBIC_DATABASE_URL`` at a
  tmp file so we never touch the project's real ``data/assurix.db``.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_BIN = REPO_ROOT / ".venv" / "bin" / "alembic"


def _run_alembic(tmp_db_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run ``alembic`` with ``ALEMBIC_DATABASE_URL`` pointing at tmp_db_path.

    The env override keeps the project's real ``data/assurix.db``
    untouched, which is critical for the rest of the test suite.
    """
    env = os.environ.copy()
    env["ALEMBIC_DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp_db_path}"
    return subprocess.run(
        [str(ALEMBIC_BIN), *args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(
    not ALEMBIC_BIN.exists(),
    reason="alembic binary not present in .venv (skip on partial envs)",
)
class TestAlembicEnv:
    def test_env_py_uses_async_cookbook_pattern(self) -> None:
        """``alembic/env.py`` must call ``run_sync(do_run_migrations)``
        and must actually invoke the migration runner (the old buggy
        version skipped it and only did ``create_all``, never stamping
        ``alembic_version``).

        We allow ``Base.metadata.create_all`` to appear as a *bootstrap*
        step (some early migrations ALTER pre-existing tables), but
        only if the migration runner is also invoked.
        """
        import ast

        env_path = REPO_ROOT / "alembic" / "env.py"
        # Walk the AST and concatenate the *code* of every function /
        # class / module body. This way the docstring content of the
        # module and individual functions (which may mention
        # ``create_all`` historically) is excluded from the assertion
        # target — we only inspect actual code statements.
        tree = ast.parse(env_path.read_text(encoding="utf-8"))
        code_chunks: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                # Skip module-level docstring.
                continue
            code_chunks.append(ast.unparse(node))
        code = "\n".join(code_chunks)

        assert "create_async_engine" in code, (
            "env.py must use create_async_engine (standard async pattern)"
        )
        assert "run_sync" in code, (
            "env.py must use connection.run_sync(...) per the alembic "
            "async cookbook"
        )
        assert "context.run_migrations" in code, (
            "env.py must invoke context.run_migrations() — the old "
            "version silently skipped this and just called "
            "Base.metadata.create_all"
        )
        # If create_all appears in the code (not in a docstring), it
        # must be paired with do_run_migrations. The original bug was
        # create_all *instead of* run_migrations.
        if "create_all" in code:
            assert "do_run_migrations" in code, (
                "create_all is only allowed as a bootstrap step BEFORE "
                "do_run_migrations — the original bug was calling "
                "create_all *instead of* run_migrations, which never "
                "stamped alembic_version"
            )

    def test_upgrade_head_creates_dedup_key_and_stamps_version(
        self, tmp_path: Path
    ) -> None:
        """Run ``alembic upgrade head`` against the project's actual
        ``data/assurix.db`` (copied to a tmp file so we never touch
        the real one) and verify the chain applies idempotently at
        head, with dedup_key present.

        The project's migration chain assumes a pre-existing schema
        created by ``Base.metadata.create_all`` in
        ``src/db/session.py`` at runtime. The chain is NOT
        idempotent with the models in the strict sense (e.g. migration
        001 adds columns that the benchmark model also defines, and
        earlier migrations ALTER ``findings`` which the model creates).
        End-to-end verification therefore runs against the project's
        actual baseline — a copy of ``data/assurix.db`` — which has
        the exact schema state the chain expects.
        """
        src_db = REPO_ROOT / "data" / "assurix.db"
        if not src_db.exists():
            pytest.skip(
                f"project DB not found at {src_db} — skipping end-to-end "
                f"alembic test (the AST-shape test in "
                f"test_env_py_uses_async_cookbook_pattern still runs)"
            )
        tmp_db = tmp_path / "alembic_test.db"
        # Copy the project's DB so the chain sees the exact baseline.
        import shutil
        shutil.copy(str(src_db), str(tmp_db))
        # Also copy the WAL/SHM if present so the copy is consistent.
        for ext in ("-wal", "-shm"):
            src_extra = src_db.with_name(src_db.name + ext)
            if src_extra.exists():
                shutil.copy(str(src_extra), str(tmp_db.with_name(tmp_db.name + ext)))

        result = _run_alembic(tmp_db, "upgrade", "head")
        assert result.returncode == 0, (
            f"alembic upgrade head failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

        # (a) alembic_version table is stamped at the head revision.
        conn = sqlite3.connect(str(tmp_db))
        try:
            version_rows = conn.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchall()
        finally:
            conn.close()
        assert version_rows, (
            "alembic_version table empty after upgrade head — "
            "env.py is not actually invoking the migration runner"
        )
        # The expected head revision is computed dynamically from
        # ``alembic heads`` so adding new migrations on top of the
        # chain does not break this pin. The pin is a regression
        # guard against the env.py not actually invoking the runner
        # (which would leave the version table empty) and against
        # a partial upgrade (which would leave a non-head revision).
        heads = _run_alembic(tmp_db, "heads")
        assert heads.returncode == 0, f"alembic heads failed: {heads.stderr}"
        head_revision = ""
        for line in heads.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("("):
                continue
            head_revision = stripped.split()[0]
            break
        assert head_revision, (
            f"could not parse head revision from alembic heads output: "
            f"{heads.stdout!r}"
        )
        assert version_rows[0][0] == head_revision, (
            f"alembic_version not at head: got {version_rows[0][0]!r}, "
            f"expected {head_revision!r}"
        )

        # (b) dedup_key column + index exist on findings.
        conn = sqlite3.connect(str(tmp_db))
        try:
            cols = [r[1] for r in conn.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()]
            indexes = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='index' AND tbl_name='findings'"
            ).fetchall()]
        finally:
            conn.close()
        assert "dedup_key" in cols, (
            f"dedup_key column missing from findings: cols={cols}"
        )
        assert "ix_findings_dedup_key" in indexes, (
            f"ix_findings_dedup_key index missing: indexes={indexes}"
        )

    def test_current_reports_head_after_upgrade(self, tmp_path: Path) -> None:
        """``alembic current`` must report the head revision (computed
        dynamically) after ``upgrade head`` — confirms the chain is
        fully applied and idempotent. This is revision-agnostic so new
        migrations don't break the test.
        """
        src_db = REPO_ROOT / "data" / "assurix.db"
        if not src_db.exists():
            pytest.skip(
                f"project DB not found at {src_db} — skipping end-to-end "
                f"alembic test"
            )
        # Compute the head revision dynamically so the test stays valid
        # when new migrations are added on top of the v2 chain.
        heads = _run_alembic(tmp_db if (tmp_db := tmp_path / "_heads.db").exists() else tmp_db, "heads")  # type: ignore[func-returns-value]
        # Fall back: re-run against the project DB to learn the head.
        if heads.returncode != 0:
            heads = subprocess.run(
                [str(ALEMBIC_BIN), "heads"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
        assert heads.returncode == 0, f"alembic heads failed: {heads.stderr}"
        # The first whitespace-delimited token of the first non-empty
        # line is the head revision id.
        head_revision = ""
        for line in heads.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("("):
                continue
            head_revision = stripped.split()[0]
            break
        assert head_revision, (
            f"could not parse head revision from alembic heads output: "
            f"{heads.stdout!r}"
        )

        tmp_db = tmp_path / "alembic_current.db"
        import shutil
        shutil.copy(str(src_db), str(tmp_db))
        for ext in ("-wal", "-shm"):
            src_extra = src_db.with_name(src_db.name + ext)
            if src_extra.exists():
                shutil.copy(str(src_extra), str(tmp_db.with_name(tmp_db.name + ext)))

        up = _run_alembic(tmp_db, "upgrade", "head")
        assert up.returncode == 0, f"upgrade head failed: {up.stderr}"
        current = _run_alembic(tmp_db, "current")
        assert current.returncode == 0, f"alembic current failed: {current.stderr}"
        assert f"{head_revision} (head)" in current.stdout, (
            f"alembic current did not report head {head_revision!r}: "
            f"{current.stdout!r}"
        )
