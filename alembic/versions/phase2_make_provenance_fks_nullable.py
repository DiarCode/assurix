"""Make ProvenanceLink hypothesis_id and tool_invocation_id nullable.

Revision ID: phase2_make_provenance_fks_nullable
Revises: 860281fd287e
Create Date: 2026-06-01

Standard-pipeline findings (e.g. those produced by PentesterAgent) have no
Hypothesis or ToolInvocation record, so the FKs must be nullable to allow
the standard pipeline to also create ProvenanceLink rows.

When both FKs are null, the tool_name column carries the agent name
(e.g. "pentester") so the chain is still traceable.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "phase2_make_provenance_fks_nullable"
down_revision = "860281fd287e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Make hypothesis_id and tool_invocation_id nullable on provenance_links."""
    with op.batch_alter_table("provenance_links") as batch_op:
        batch_op.alter_column(
            "hypothesis_id",
            existing_type=sa.String(length=36),
            nullable=True,
        )
        batch_op.alter_column(
            "tool_invocation_id",
            existing_type=sa.String(length=36),
            nullable=True,
        )


def downgrade() -> None:
    """Restore NOT NULL on hypothesis_id and tool_invocation_id.

    NOTE: downgrade will fail if any provenance_links rows have NULL FKs.
    """
    with op.batch_alter_table("provenance_links") as batch_op:
        batch_op.alter_column(
            "hypothesis_id",
            existing_type=sa.String(length=36),
            nullable=False,
        )
        batch_op.alter_column(
            "tool_invocation_id",
            existing_type=sa.String(length=36),
            nullable=False,
        )
