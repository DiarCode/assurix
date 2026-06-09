"""Add dedup_key column to findings table.

Revision ID: 20260601224500
Revises: phase2_make_provenance_fks_nullable
Create Date: 2026-06-01 22:45:00

Adds a nullable ``dedup_key VARCHAR(64)`` column to the ``findings``
table plus an index. The column is *nullable* for backwards compatibility
with rows that pre-date the dedup-aware creation pipeline (old findings
get a best-effort backfill below; rows with no usable URL/severity/title
remain NULL and are excluded from deduplication).

Backfill strategy (per plan §Step 4):
    For each existing row, compute
    ``sha256( COALESCE(json_extract(finding_metadata, '$.source_url'), '')
              || '|' || COALESCE(severity, '')
              || '|' || COALESCE(title, ''))``
    and store the first 16 hex chars of the digest in ``dedup_key``.

The column lives in the main findings table — at report time,
``_deduplicate_findings()`` groups by ``dedup_key`` and keeps the
highest-confidence entry per group.
"""
from __future__ import annotations

import hashlib
import json

import sqlalchemy as sa
from alembic import op

revision = "20260601224500"
down_revision = "phase2_make_provenance_fks_nullable"
branch_labels = None
depends_on = None


def _backfill_dedup_keys() -> None:
    """Compute dedup_key for every existing row where it is NULL.

    Uses Python-side hashing so the digest is a real sha256 (per the
    plan's acceptance criteria). For a small findings table the round
    trip to Python is fine; for a large table a one-shot UPDATE in raw
    SQL with SQLite's built-in ``substr``+``hex`` would be cheaper, but
    Python keeps the logic consistent with ``_compute_dedup_key()`` in
    the reporting layer (same algorithm, same field order).
    """
    bind = op.get_bind()
    # Pull only the columns we need
    rows = bind.execute(
        sa.text(
            "SELECT id, title, severity, finding_metadata "
            "FROM findings WHERE dedup_key IS NULL"
        )
    ).fetchall()

    if not rows:
        return

    for row in rows:
        # ``row`` may be a Row / RowMapping depending on driver; access
        # both by index and by key defensively.
        if hasattr(row, "_mapping"):
            row = row._mapping
        try:
            title = row["title"] or ""
        except (KeyError, TypeError):
            title = row[1] or ""
        try:
            severity = row["severity"] or ""
        except (KeyError, TypeError):
            severity = row[2] or ""
        try:
            metadata = row["finding_metadata"] or {}
        except (KeyError, TypeError):
            metadata = row[3] or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    metadata = {}

        source_url = ""
        if isinstance(metadata, dict):
            source_url = metadata.get("source_url") or ""

        payload = f"{source_url}|{severity}|{title}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

        try:
            finding_id = row["id"]
        except (KeyError, TypeError):
            finding_id = row[0]

        bind.execute(
            sa.text("UPDATE findings SET dedup_key = :k WHERE id = :i"),
            {"k": digest, "i": finding_id},
        )


def upgrade() -> None:
    """Add dedup_key column + index, and backfill existing rows."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column("dedup_key", sa.String(length=64), nullable=True)
        )
        batch_op.create_index(
            "ix_findings_dedup_key",
            ["dedup_key"],
            unique=False,
        )

    # Backfill existing rows. Idempotent: only updates rows where
    # dedup_key IS NULL, so re-running is safe.
    _backfill_dedup_keys()


def downgrade() -> None:
    """Drop the index and column."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_index("ix_findings_dedup_key")
        batch_op.drop_column("dedup_key")
