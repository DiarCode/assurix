"""Add BountyBench + CyberGym phase columns to benchmark_runs.

Revision ID: 20260603_add_benchmark_phase_columns
Revises: 20260603_add_engagement_chains

Plan §3.6 (V&V): persist per-phase scoring for the two suites where
phase-aware metrics are the primary signal:

  * BountyBench — Detect/Exploit/Patch triple plus an ``all_phases``
    rollup, plus a JSON dump of the per-case detail.
  * CyberGym   — PoC pass rate plus a JSON dump of per-case PoC
    quality indicators (present / targeted / executable / sink).

All columns are nullable Float / JSON so existing rows stay valid.  The
runner fills them when ``suite_name in {"bountybench", "cybergym"}``.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260603_add_benchmark_phase_columns"
down_revision = "20260603_add_engagement_chains"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the phase-scoring columns to ``benchmark_runs``."""
    with op.batch_alter_table("benchmark_runs") as batch_op:
        batch_op.add_column(
            sa.Column("bountybench_detect_rate", sa.Float(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("bountybench_exploit_rate", sa.Float(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("bountybench_patch_rate", sa.Float(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("bountybench_all_phases_rate", sa.Float(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("bountybench_phase_detail", sa.JSON(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("cybergym_poc_pass_rate", sa.Float(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("cybergym_poc_detail", sa.JSON(), nullable=True)
        )


def downgrade() -> None:
    """Drop the phase-scoring columns."""
    with op.batch_alter_table("benchmark_runs") as batch_op:
        batch_op.drop_column("cybergym_poc_detail")
        batch_op.drop_column("cybergym_poc_pass_rate")
        batch_op.drop_column("bountybench_phase_detail")
        batch_op.drop_column("bountybench_all_phases_rate")
        batch_op.drop_column("bountybench_patch_rate")
        batch_op.drop_column("bountybench_exploit_rate")
        batch_op.drop_column("bountybench_detect_rate")
