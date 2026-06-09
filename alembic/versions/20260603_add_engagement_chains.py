"""Persist ExploitChainer output on the Engagement.

Revision ID: 20260603_add_engagement_chains
Revises: 2026_07_01_assurix_v2_architecture
Create Date: 2026-06-03

Plan §3.3.1: chains are written by the reasoner at the end of its run,
and the GET /scans/{id}/chains endpoint reads from a dedicated column
rather than re-running the LLM-backed graph builder on every read.

Adds two columns to ``engagements``:

  * ``chains`` (JSON, default='[]') — list of Chain dicts from the
    ExploitChainer.
  * ``chain_run_at`` (DateTime, nullable) — wall-clock time of the
    last successful chainer run, for observability.

Both are non-destructive: existing rows get ``chains='[]'`` and
``chain_run_at=NULL`` automatically.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260603_add_engagement_chains"
down_revision = "2026_07_01_assurix_v2_architecture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the chains + chain_run_at columns to engagements."""
    with op.batch_alter_table("engagements") as batch_op:
        batch_op.add_column(
            sa.Column(
                "chains",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "chain_run_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )


def downgrade() -> None:
    """Drop the new columns."""
    with op.batch_alter_table("engagements") as batch_op:
        batch_op.drop_column("chain_run_at")
        batch_op.drop_column("chains")
