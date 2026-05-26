"""Add weighted_score, pass_at_k_score, k_value to benchmark_runs

Revision ID: 001
Revises: None
Create Date: 2026-05-26
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("benchmark_runs", sa.Column("weighted_score", sa.Float(), nullable=True))
    op.add_column("benchmark_runs", sa.Column("pass_at_k_score", sa.Float(), nullable=True))
    op.add_column("benchmark_runs", sa.Column("k_value", sa.Integer(), nullable=True))

def downgrade() -> None:
    op.drop_column("benchmark_runs", "k_value")
    op.drop_column("benchmark_runs", "pass_at_k_score")
    op.drop_column("benchmark_runs", "weighted_score")
