"""Root-wide expansion accounting with an independent execution-attempt deadline.

Files/bytes are durable and cumulative across descendants. Reservations store
absolute high-water marks, so retrying the same immutable output does not spend
its allocation twice. A new execution attempt opens a new time window; it never
resets accounting or extends another running attempt's deadline. Password waits
and queue idle time therefore do not consume a later attempt's time window.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from uuid import UUID


class BudgetExceeded(RuntimeError):  # noqa: N818
    """A resource limit prevents further analysis, without implying malware."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class BudgetLimits:
    max_files: int = 100
    max_bytes: int = 500_000_000
    timeout_seconds: float = 3600

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_files, bool)
            or not isinstance(self.max_files, int)
            or isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or self.max_files < 1
            or self.max_bytes < 1
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("budget limits must be positive finite values")


@dataclass(frozen=True)
class BudgetSnapshot:
    limits: BudgetLimits
    used_files: int
    used_bytes: int
    deadline_at: datetime
    reservations: dict[str, dict[str, int]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": asdict(self.limits),
            "used_files": self.used_files,
            "used_bytes": self.used_bytes,
            "deadline_at": self.deadline_at.isoformat(),
            "time_scope": "analysis_attempt",
            "accounting_scope": "root_artifact_tree",
            "reservations": self.reservations,
        }


class RootBudget(Protocol):
    async def reserve(self, key: str, files: int, bytes: int) -> BudgetSnapshot:
        ...

    async def snapshot(self) -> BudgetSnapshot:
        ...

    async def check_deadline(self) -> None:
        ...


def reservation_key(job_id: str, source: str, origin: str) -> str:
    """Bounded identity; preserve original origin separately in artifact metadata."""
    return hashlib.sha256(f"{job_id}\0{source}\0{origin}".encode()).hexdigest()


def _validate_reservation(key: str, files: int, bytes: int) -> None:
    if not key or len(key) > 512:
        raise ValueError("invalid budget reservation identity")
    if (
        not isinstance(files, int)
        or isinstance(files, bool)
        or not isinstance(bytes, int)
        or isinstance(bytes, bool)
        or files < 0
        or bytes < 0
    ):
        raise ValueError("budget reservations must be non-negative integer counts")


def _updated_counts(
    limits: BudgetLimits,
    used_files: int,
    used_bytes: int,
    old_files: int,
    old_bytes: int,
    files: int,
    bytes: int,
) -> tuple[int, int, int, int]:
    files, bytes = max(files, old_files), max(bytes, old_bytes)
    next_files, next_bytes = (
        used_files + files - old_files,
        used_bytes + bytes - old_bytes,
    )
    if next_files > limits.max_files:
        raise BudgetExceeded("root_file_limit")
    if next_bytes > limits.max_bytes:
        raise BudgetExceeded("root_expanded_bytes_limit")
    return next_files, next_bytes, files, bytes


class InMemoryRootBudget:
    def __init__(self, limits: BudgetLimits, *, deadline_at: datetime | None = None) -> None:
        self.limits = limits
        self.deadline_at = deadline_at or datetime.now(timezone.utc) + timedelta(
            seconds=limits.timeout_seconds
        )
        if self.deadline_at.tzinfo is None:
            raise ValueError("budget deadline requires a timezone")
        self._files = 0
        self._bytes = 0
        self._reservations: dict[str, dict[str, int]] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_snapshot(
        cls,
        snapshot: dict[str, Any],
        *,
        new_attempt: bool = False,
    ) -> InMemoryRootBudget:
        limits = BudgetLimits(**snapshot["limits"])
        deadline = None if new_attempt else datetime.fromisoformat(snapshot["deadline_at"])
        budget = cls(limits, deadline_at=deadline)
        for key, value in snapshot.get("reservations", {}).items():
            _validate_reservation(key, value["files"], value["bytes"])
            budget._reservations[key] = dict(value)
        budget._files = sum(value["files"] for value in budget._reservations.values())
        budget._bytes = sum(value["bytes"] for value in budget._reservations.values())
        if budget._files != snapshot["used_files"] or budget._bytes != snapshot["used_bytes"]:
            raise ValueError("budget snapshot counters do not match reservations")
        if budget._files > limits.max_files or budget._bytes > limits.max_bytes:
            raise ValueError("budget snapshot exceeds its limits")
        return budget

    async def check_deadline(self) -> None:
        if datetime.now(timezone.utc) >= self.deadline_at:
            raise BudgetExceeded("analysis_attempt_deadline")

    def _snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            self.limits,
            self._files,
            self._bytes,
            self.deadline_at,
            {key: dict(value) for key, value in self._reservations.items()},
        )

    async def snapshot(self) -> BudgetSnapshot:
        async with self._lock:
            return self._snapshot()

    async def reserve(self, key: str, files: int, bytes: int) -> BudgetSnapshot:
        _validate_reservation(key, files, bytes)
        async with self._lock:
            await self.check_deadline()
            old = self._reservations.get(key, {"files": 0, "bytes": 0})
            self._files, self._bytes, files, bytes = _updated_counts(
                self.limits,
                self._files,
                self._bytes,
                old["files"],
                old["bytes"],
                files,
                bytes,
            )
            self._reservations[key] = {"files": files, "bytes": bytes}
            return self._snapshot()


class PostgresRootBudget:
    """PostgreSQL adapter: row lock serializes all reservations for a root tree."""

    def __init__(self, engine: Any, root_job_id: UUID, limits: BudgetLimits) -> None:
        self.engine = engine
        self.root_job_id = root_job_id
        self.limits = limits
        self.deadline_at = datetime.now(timezone.utc) + timedelta(seconds=limits.timeout_seconds)

    @classmethod
    async def initialize(
        cls,
        engine: Any,
        root_job_id: str,
        limits: BudgetLimits,
    ) -> PostgresRootBudget:
        from malscan.models.budget import AnalysisBudget
        from sqlalchemy import select
        from sqlalchemy.dialects.postgresql import insert
        from sqlalchemy.ext.asyncio import AsyncSession

        root_id = UUID(root_job_id)
        async with AsyncSession(engine) as session, session.begin():
            await session.execute(
                insert(AnalysisBudget)
                .values(
                    root_job_id=root_id,
                    max_files=limits.max_files,
                    max_bytes=limits.max_bytes,
                    timeout_seconds=limits.timeout_seconds,
                    used_files=0,
                    used_bytes=0,
                )
                .on_conflict_do_nothing(index_elements=["root_job_id"])
            )
            row: AnalysisBudget = (
                await session.execute(
                    select(AnalysisBudget).where(AnalysisBudget.root_job_id == root_id)
                )
            ).scalar_one()
            stored_limits = BudgetLimits(row.max_files, row.max_bytes, row.timeout_seconds)
        return cls(engine, root_id, stored_limits)

    async def check_deadline(self) -> None:
        if datetime.now(timezone.utc) >= self.deadline_at:
            raise BudgetExceeded("analysis_attempt_deadline")

    async def _snapshot_in_session(self, session: Any, row: Any) -> BudgetSnapshot:
        from malscan.models.budget import BudgetReservation
        from sqlalchemy import select

        rows = (
            (
                await session.execute(
                    select(BudgetReservation).where(
                        BudgetReservation.root_job_id == self.root_job_id
                    )
                )
            )
            .scalars()
            .all()
        )
        return BudgetSnapshot(
            self.limits,
            row.used_files,
            row.used_bytes,
            self.deadline_at,
            {item.reservation_key: {"files": item.files, "bytes": item.bytes} for item in rows},
        )

    async def snapshot(self) -> BudgetSnapshot:
        from malscan.models.budget import AnalysisBudget
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(self.engine) as session, session.begin():
            row: AnalysisBudget = (
                await session.execute(
                    select(AnalysisBudget)
                    .where(AnalysisBudget.root_job_id == self.root_job_id)
                    .with_for_update()
                )
            ).scalar_one()
            return await self._snapshot_in_session(session, row)

    async def reserve(self, key: str, files: int, bytes: int) -> BudgetSnapshot:
        from malscan.models.budget import AnalysisBudget, BudgetReservation
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession

        _validate_reservation(key, files, bytes)
        async with AsyncSession(self.engine) as session, session.begin():
            row: AnalysisBudget = (
                await session.execute(
                    select(AnalysisBudget)
                    .where(AnalysisBudget.root_job_id == self.root_job_id)
                    .with_for_update()
                )
            ).scalar_one()
            await self.check_deadline()
            reservation = (
                await session.execute(
                    select(BudgetReservation).where(
                        BudgetReservation.root_job_id == self.root_job_id,
                        BudgetReservation.reservation_key == key,
                    )
                )
            ).scalar_one_or_none()
            old_files, old_bytes = (reservation.files, reservation.bytes) if reservation else (0, 0)
            row.used_files, row.used_bytes, files, bytes = _updated_counts(
                self.limits,
                row.used_files,
                row.used_bytes,
                old_files,
                old_bytes,
                files,
                bytes,
            )
            if reservation is None:
                reservation = BudgetReservation(
                    root_job_id=self.root_job_id,
                    reservation_key=key,
                    files=files,
                    bytes=bytes,
                )
                session.add(reservation)
            else:
                reservation.files, reservation.bytes = files, bytes
            await session.flush()
            return await self._snapshot_in_session(session, row)
