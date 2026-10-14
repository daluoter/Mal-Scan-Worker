"""Fence stale job writes with a server-generated analysis attempt identity.

Revision ID: 007_add_job_analysis_attempt
Revises: 006_root_analysis_budgets
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "007_add_job_analysis_attempt"
down_revision = "006_root_analysis_budgets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column("analysis_attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("jobs", "analysis_attempt_id")
