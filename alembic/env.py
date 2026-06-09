"""Alembic migration environment — async pattern.

Standard async pattern from the Alembic cookbook:
https://alembic.sqlalchemy.org/en/latest/cookbook.html#using-asyncio-with-alembic

Reads the SQLAlchemy URL from ``alembic.ini`` (or the ``ALEMBIC_DATABASE_URL``
env override) and runs migrations against the live ``Base.metadata`` from
``src.db.models``. ``alembic upgrade head`` actually invokes the migration
runner (creates ``alembic_version`` and applies the chain), instead of
silently doing ``Base.metadata.create_all`` and skipping the version table.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from src.db.models import Base
# Note: we deliberately do NOT ``import src.benchmark.models`` here.
# The benchmark module's tables are managed outside the migration
# chain; including them would register ``benchmark_runs`` on
# ``Base.metadata`` with the weighted_score / pass_at_k_score /
# k_value columns already present, conflicting with 001's
# ADD COLUMN (which assumes a pre-existing but incomplete table).

# Alembic Config object — exposes values from alembic.ini.
config = context.config

# Override URL via env var so CI / test environments can target a
# temporary sqlite file without rewriting alembic.ini.
_env_url = os.environ.get("ALEMBIC_DATABASE_URL")
if _env_url:
    config.set_main_option("sqlalchemy.url", _env_url)

# Configure Python logging from alembic.ini (if present).
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata for ``autogenerate`` support. Migrations are written by hand
# in this project, but exposing the metadata is required for the
# cookbook pattern.
target_metadata = Base.metadata


def do_run_migrations(connection: Connection) -> None:
    """Run migrations against the given sync Connection (run_sync target)."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite forbids FK-altering ALTERs without batch mode; mirror
        # the project's ``render_as_batch=True`` convention.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Create an async engine, connect, and run migrations via run_sync.

    The standard async cookbook pattern. The project bootstraps its
    tables via ``Base.metadata.create_all`` in ``src/db/session.py`` at
    first run; the migration chain assumes those tables exist
    (specifically, 001_add_benchmark_weights ALTERs the pre-existing
    ``benchmark_runs`` table rather than creating it). This is
    intentional: the migrations only define *schema changes* over the
    baseline, not the baseline itself.
    """
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    raise RuntimeError(
        "Offline mode is not supported in this project; "
        "alembic must run online against the live database."
    )

asyncio.run(run_migrations_online())
