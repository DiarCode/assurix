"""Assurix v2 architecture migration (plan §3.0).

Revision ID: 2026_07_01_assurix_v2_architecture
Revises: 20260601224500
Create Date: 2026-07-01 00:00:00

This is the load-bearing migration for 4 weeks of v2 architecture work.
It is destructive: the 4-state HypothesisStatus enum (PENDING/INVESTIGATING/
CONFIRMED/FALSIFIED) is replaced by the 8-state enum (UNKNOWN/CANDIDATE/
NEEDS_CORROBORATION/NEEDS_SAFE_VALIDATION/VALIDATED/REJECTED/OUT_OF_SCOPE/
SUPERSEDED). Per plan §3.0, the migration is AUTHORITATIVE — if the model
and the migration disagree, the migration wins.

Step ordering (critical for atomicity):
  1. Backfill defaults (set NULL state_transitions/evidence_hash to []/NULL
     before the column type changes; SQLite/Postgres both allow this on
     existing rows).
  2. 4->8 enum swap on the hypotheses.status column:
       a. UPDATE each legacy value to its mapped new value (4->4 mapping,
          lossless: PENDING->CANDIDATE, INVESTIGATING->NEEDS_CORROBORATION,
          CONFIRMED->VALIDATED, FALSIFIED->REJECTED).
       b. ALTER the column type if needed (VARCHAR vs enum). For SQLite
          the column is just a String(20) so no type change is needed.
  3. Add graph_edges.capability (String(50), nullable).
  4. Add Hypothesis columns: state_transitions, evidence_hash,
     confidence_decay, last_transition_at.
  5. Add findings columns: reproducer_run_id, adversary_run_id,
     validator_run_id, evidence_hash, chain_eligible.
  6. Create new tables: evidence_blobs, verifier_runs, attack_chain_edges,
     browser_sessions, tool_skills, waf_signatures.

Downgrade note (lossy, per plan §3.0 / MINOR-4):
  NEW_TO_LEGACY collapse:
    out_of_scope + superseded       -> falsified
    needs_corroboration + needs_safe_validation -> investigating
  This is acceptable because the destructive migration is one-way in
  production. Document in the PR description.

Exercises an optional pre-check: if any hypothesis row is currently in
state 'investigating' it will be lost-collapsed on downgrade to
'investigating' (which is also the legacy value, so lossless there).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "2026_07_01_assurix_v2_architecture"
down_revision: Union[str, None] = "20260601224500"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# 4 -> 8 mapping (LOSSY: 4 values map cleanly to 4 of the 8; the other 4
# 8-state values (UNKNOWN, NEEDS_SAFE_VALIDATION, OUT_OF_SCOPE, SUPERSEDED)
#  have no legacy counterpart and are introduced by the new code).
LEGACY_TO_NEW = {
    "pending": "candidate",
    "investigating": "needs_corroboration",
    "confirmed": "validated",
    "falsified": "rejected",
}

# 8 -> 4 mapping (LOSSY: 4 of the 8 values collapse into 2 of the 4 legacy
# values; see downgrade note above).
NEW_TO_LEGACY = {
    "unknown": "pending",
    "candidate": "pending",
    "needs_corroboration": "investigating",
    "needs_safe_validation": "investigating",  # LOSSI
    "validated": "confirmed",
    "rejected": "falsified",
    "out_of_scope": "falsified",  # LOSSY
    "superseded": "falsified",     # LOSSY
}


def _column_exists(table: str, column: str) -> bool:
    """Return True if ``column`` exists on ``table`` (idempotent migration)."""
    bind = op.get_bind()
    insp = inspect(bind)
    return column in {c["name"] for c in insp.get_columns(table)}


def _table_exists(table: str) -> bool:
    bind = op.get_bind()
    insp = inspect(bind)
    return table in insp.get_table_names()


def upgrade() -> None:
    """Apply the v2 architecture schema changes.

    Step ordering (corrected for forward-only schema):
      1. ADD new columns first (so backfill UPDATEs in step 2 have a target).
      2. Backfill defaults on the freshly-added columns (idempotent).
      3. 4->8 enum swap (UPDATEs only; the column is just String(20) so
         no type ALTER is required).
      4. Create new tables.
    """

    # --- Step 1: ADD new columns ---
    bind = op.get_bind()

    # graph_edges.capability (or whole table)
    if not _table_exists("graph_edges"):
        op.create_table(
            "graph_edges",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("source_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("target_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("edge_type", sa.String(length=50), nullable=False, index=True),
            sa.Column("properties", sa.JSON, default=dict),
            sa.Column("capability", sa.String(length=50), nullable=True),
        )
    elif not _column_exists("graph_edges", "capability"):
        with op.batch_alter_table("graph_edges") as batch_op:
            batch_op.add_column(sa.Column("capability", sa.String(length=50), nullable=True))

    # Hypothesis additive columns
    if not _column_exists("hypotheses", "state_transitions"):
        with op.batch_alter_table("hypotheses") as batch_op:
            batch_op.add_column(sa.Column("state_transitions", sa.JSON, default=list))
    if not _column_exists("hypotheses", "evidence_hash"):
        with op.batch_alter_table("hypotheses") as batch_op:
            batch_op.add_column(sa.Column("evidence_hash", sa.String(length=64), nullable=True))
    if not _column_exists("hypotheses", "confidence_decay"):
        with op.batch_alter_table("hypotheses") as batch_op:
            batch_op.add_column(sa.Column("confidence_decay", sa.Float, default=0.5))
    if not _column_exists("hypotheses", "last_transition_at"):
        with op.batch_alter_table("hypotheses") as batch_op:
            batch_op.add_column(
                sa.Column("last_transition_at", sa.DateTime(timezone=True), nullable=True)
            )

    # Findings additive columns (triad provenance + chain)
    # chain_eligible is NOT NULL with a default of FALSE; the others are nullable.
    finding_columns = [
        ("reproducer_run_id", sa.String(length=36), True),
        ("adversary_run_id", sa.String(length=36), True),
        ("validator_run_id", sa.String(length=36), True),
        ("evidence_hash", sa.String(length=64), True),
        ("chain_eligible", sa.Boolean, False),  # NOT NULL with default FALSE
    ]
    for col_name, col_type, nullable in finding_columns:
        if not _column_exists("findings", col_name):
            with op.batch_alter_table("findings") as batch_op:
                if col_name == "chain_eligible":
                    # Server default + the column can be NOT NULL safely on SQLite
                    batch_op.add_column(
                        sa.Column(col_name, col_type, nullable=nullable, server_default=sa.text("0"))
                    )
                else:
                    batch_op.add_column(sa.Column(col_name, col_type, nullable=nullable))

    # --- Step 2: Backfill defaults on freshly-added columns ---
    bind.execute(
        sa.text(
            "UPDATE hypotheses SET state_transitions = '[]' "
            "WHERE state_transitions IS NULL"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE hypotheses SET confidence_decay = 0.5 "
            "WHERE confidence_decay IS NULL"
        )
    )

    # --- Step 3: 4->8 enum swap (UPDATEs only) ---
    for legacy_val, new_val in LEGACY_TO_NEW.items():
        bind.execute(
            sa.text("UPDATE hypotheses SET status = :new WHERE status = :old"),
            {"new": new_val, "old": legacy_val},
        )

    # --- Step 4: Create new tables ---
    if not _table_exists("evidence_blobs"):
        op.create_table(
            "evidence_blobs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("content_sha256", sa.String(length=64), nullable=False, unique=True, index=True),
            sa.Column("blob", sa.LargeBinary, nullable=True),
            sa.Column("blob_metadata", sa.JSON, default=dict),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if not _table_exists("verifier_runs"):
        op.create_table(
            "verifier_runs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("hypothesis_id", sa.String(length=36), nullable=True, index=True),
            sa.Column("finding_id", sa.String(length=36), nullable=True, index=True),
            sa.Column("verifier_role", sa.String(length=20), nullable=False),  # reproducer|adversary|validator
            sa.Column("verdict", sa.String(length=20), nullable=False),  # pass|fail|inconclusive
            sa.Column("evidence_hash", sa.String(length=64), nullable=True),
            sa.Column("confidence", sa.Float, default=0.0),
            sa.Column("notes", sa.Text, nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _table_exists("attack_chain_edges"):
        op.create_table(
            "attack_chain_edges",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("from_finding_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("to_finding_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("chain_pattern", sa.String(length=50), nullable=False),
            sa.Column("capability", sa.String(length=50), nullable=True),
            sa.Column("severity_delta", sa.Float, default=0.0),
            sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if not _table_exists("browser_sessions"):
        op.create_table(
            "browser_sessions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=False, index=True),
            sa.Column("primary_operator", sa.String(length=50), nullable=False, default="agent"),
            sa.Column("auth_state", sa.JSON, default=dict),
            sa.Column("cookies_blob", sa.LargeBinary, nullable=True),
            sa.Column("storage_state_blob", sa.LargeBinary, nullable=True),
            sa.Column("last_refreshed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if not _table_exists("tool_skills"):
        op.create_table(
            "tool_skills",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("engagement_id", sa.String(length=36), nullable=True, index=True),
            sa.Column("name", sa.String(length=100), nullable=False, unique=True),
            sa.Column("description", sa.Text, nullable=False),
            sa.Column("preconditions", sa.JSON, default=list),
            sa.Column("effects", sa.JSON, default=list),
            sa.Column("capability_tags", sa.JSON, default=list),
            sa.Column("version", sa.Integer, default=1),
            sa.Column("enabled", sa.Boolean, default=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if not _table_exists("waf_signatures"):
        op.create_table(
            "waf_signatures",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("vendor", sa.String(length=50), nullable=False, index=True),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("signature_pattern", sa.Text, nullable=False),
            sa.Column("bypass_strategies", sa.JSON, default=list),
            sa.Column("version", sa.String(length=20), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )


def downgrade() -> None:
    """Reverse the v2 architecture changes.

    Note: this is LOSSY. The 8-state enum collapses 2-to-1 in two cases:
        out_of_scope + superseded       -> falsified
        needs_corroboration + needs_safe_validation -> investigating
    Downgrading is for development/sandbox use only — production data
    that depends on the 8-state distinction cannot be perfectly reversed.
    """
    # Drop new tables (in reverse dependency order)
    for table in (
        "waf_signatures",
        "tool_skills",
        "browser_sessions",
        "attack_chain_edges",
        "verifier_runs",
        "evidence_blobs",
    ):
        if _table_exists(table):
            op.drop_table(table)

    # Drop findings columns
    for col_name in (
        "chain_eligible",
        "evidence_hash",
        "validator_run_id",
        "adversary_run_id",
        "reproducer_run_id",
    ):
        if _column_exists("findings", col_name):
            with op.batch_alter_table("findings") as batch_op:
                batch_op.drop_column(col_name)

    # Drop hypothesis columns
    for col_name in (
        "last_transition_at",
        "confidence_decay",
        "evidence_hash",
        "state_transitions",
    ):
        if _column_exists("hypotheses", col_name):
            with op.batch_alter_table("hypotheses") as batch_op:
                batch_op.drop_column(col_name)

    # Drop graph_edges.capability (column or whole table)
    if _table_exists("graph_edges") and _column_exists("graph_edges", "capability"):
        with op.batch_alter_table("graph_edges") as batch_op:
            batch_op.drop_column("capability")

    # 8 -> 4 enum swap (UPDATEs first, then optionally ALTER)
    bind = op.get_bind()
    for new_val, legacy_val in NEW_TO_LEGACY.items():
        bind.execute(
            sa.text("UPDATE hypotheses SET status = :legacy WHERE status = :new"),
            {"legacy": legacy_val, "new": new_val},
        )
