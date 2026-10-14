"""Persistent root artifact-tree expansion accounting."""
from __future__ import annotations

import uuid

from sqlalchemy import BigInteger, CheckConstraint, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from malscan.models.base import Base


class AnalysisBudget(Base):
    __tablename__ = "analysis_budgets"
    __table_args__ = (
        CheckConstraint("used_files >= 0 AND used_files <= max_files"),
        CheckConstraint("used_bytes >= 0 AND used_bytes <= max_bytes"),
        CheckConstraint("max_files > 0 AND max_bytes > 0 AND timeout_seconds > 0"),
    )

    root_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True
    )
    max_files: Mapped[int] = mapped_column(Integer, nullable=False)
    max_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    used_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class BudgetReservation(Base):
    __tablename__ = "budget_reservations"
    __table_args__ = (CheckConstraint("files >= 0 AND bytes >= 0"),)
    root_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_budgets.root_job_id", ondelete="CASCADE"),
        primary_key=True,
    )
    reservation_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    files: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
