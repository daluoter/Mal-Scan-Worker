"""Root artifact-tree resource accounting.

Revision ID: 006_root_analysis_budgets
Revises: 005_add_artifact_risk_fields
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "006_root_analysis_budgets"
down_revision = "005_add_artifact_risk_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_budgets",
        sa.Column("root_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("max_files", sa.Integer(), nullable=False),
        sa.Column("max_bytes", sa.BigInteger(), nullable=False),
        sa.Column("timeout_seconds", sa.Float(), nullable=False),
        sa.Column("used_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("used_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["root_job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("root_job_id"),
        sa.CheckConstraint("used_files >= 0 AND used_files <= max_files"),
        sa.CheckConstraint("used_bytes >= 0 AND used_bytes <= max_bytes"),
        sa.CheckConstraint("max_files > 0 AND max_bytes > 0 AND timeout_seconds > 0"),
    )
    op.create_table(
        "budget_reservations",
        sa.Column("root_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reservation_key", sa.String(512), nullable=False),
        sa.Column("files", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["root_job_id"], ["analysis_budgets.root_job_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("root_job_id", "reservation_key"),
        sa.CheckConstraint("files >= 0 AND bytes >= 0"),
    )


def downgrade() -> None:
    op.drop_table("budget_reservations")
    op.drop_table("analysis_budgets")
