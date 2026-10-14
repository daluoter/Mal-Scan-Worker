"""Database operations for job status updates."""

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from malscan_worker.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Portable analysis has no database. Queue entry points validate configuration
# before using this adapter; importing shared stages must not require credentials.
_engine = (
    create_async_engine(
        settings.database_url,
        echo=False,
        pool_size=5,
        max_overflow=10,
    )
    if settings.database_url
    else None
)


def advisory_key(namespace: str, value: str) -> int:
    """Use a stable PostgreSQL bigint key, separate from Python's salted hashes."""
    digest = hashlib.sha256(f"malscan:{namespace}:{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@asynccontextmanager
async def job_execution_lock(job_id: str) -> AsyncIterator[bool]:
    """Serialize deliveries for a job without holding row locks during analysis.

    The connection owns the session lock. An invalidated connection or crashed
    process releases it; it must never return to the pool with the lock held.
    """
    from sqlalchemy import text

    if _engine is None:
        raise ValueError("DATABASE_URL is required for queue job execution")
    key = advisory_key("job", str(UUID(job_id)))
    async with _engine.connect() as connection:
        result = await connection.execute(
            text("SELECT pg_try_advisory_lock(:lock_key)"), {"lock_key": key}
        )
        acquired = bool(result.scalar_one())
        await connection.commit()
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    await connection.execute(
                        text("SELECT pg_advisory_unlock(:lock_key)"), {"lock_key": key}
                    )
                    await connection.commit()
                except Exception:
                    await connection.invalidate()
                    raise


async def get_job_for_context(job_id: str, session: AsyncSession | None = None) -> Any | None:
    """Fetch Job record instance for pipeline context.

    If session is provided, use it; otherwise create a temporary one.
    """
    from malscan.models.job import Job
    from sqlalchemy import select

    if session:
        stmt = select(Job).where(Job.id == UUID(job_id))
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async with AsyncSession(_engine) as session:
        stmt = select(Job).where(Job.id == UUID(job_id))
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


class StaleAnalysisAttemptError(RuntimeError):
    """A newer delivery owns this job; the old worker must not write results."""


# Compatibility name for queue adapters using the initial contract.
StaleAnalysisAttempt = StaleAnalysisAttemptError


_active_analysis_attempt: ContextVar[tuple[str, UUID] | None] = ContextVar(
    "malscan_active_analysis_attempt", default=None
)


def current_analysis_attempt(job_id: str | None = None) -> UUID | None:
    """Return the server-generated identity in this task's execution scope."""
    active = _active_analysis_attempt.get()
    if active is None:
        return None
    if job_id is not None and str(UUID(job_id)) != active[0]:
        raise StaleAnalysisAttempt("Analysis attempt belongs to a different job")
    return active[1]


@asynccontextmanager
async def job_analysis_attempt(job_id: str) -> AsyncIterator[str]:
    """Claim a fresh attempt while the caller holds the per-job advisory lock.

    The UUID is not read from a message. Resetting the ContextVar prevents a
    subsequent delivery from accidentally reusing this attempt's ownership.
    """
    from sqlalchemy import text

    if _active_analysis_attempt.get() is not None:
        raise RuntimeError("Analysis attempt scopes must not be nested")
    canonical_job_id = str(UUID(job_id))
    attempt_id = uuid4()
    async with AsyncSession(_engine) as session:
        result = await session.execute(
            text(
                "UPDATE jobs SET analysis_attempt_id = :attempt_id, updated_at = :updated_at "
                "WHERE id = :job_id AND status <> 'done' RETURNING id"
            ),
            {
                "job_id": UUID(job_id),
                "attempt_id": attempt_id,
                "updated_at": datetime.now(timezone.utc),
            },
        )
        if result.scalar_one_or_none() is None:
            await session.rollback()
            raise StaleAnalysisAttempt("Job is absent or already finalized")
        await session.commit()
    token = _active_analysis_attempt.set((canonical_job_id, attempt_id))
    try:
        yield str(attempt_id)
    finally:
        _active_analysis_attempt.reset(token)


def _job_attempt_fence(job_id: str) -> tuple[str, dict[str, Any]]:
    attempt = current_analysis_attempt(job_id)
    if attempt is None:
        # Legacy/unscoped callers can only touch jobs never claimed by a worker.
        return "analysis_attempt_id IS NULL", {}
    return "analysis_attempt_id = :active_attempt_id", {"active_attempt_id": attempt}


async def _write_job_fields(
    job_id: str, assignments: str, values: dict[str, Any], *, returning: str = "id"
) -> Any:
    """Apply a trusted internal update only if this delivery still owns the job."""
    from sqlalchemy import text

    fence, fence_values = _job_attempt_fence(job_id)
    async with AsyncSession(_engine) as session:
        try:
            result = await session.execute(
                text(
                    f"UPDATE jobs SET {assignments}, updated_at = :updated_at "
                    f"WHERE id = :job_id AND {fence} RETURNING {returning}"
                ),
                {
                    **values,
                    **fence_values,
                    "job_id": UUID(job_id),
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            changed = result.scalar_one_or_none()
            if changed is None:
                raise StaleAnalysisAttempt(
                    "Job write rejected: analysis attempt is no longer active"
                )
            await session.commit()
            return changed
        except Exception:
            await session.rollback()
            raise


async def update_job_status(
    job_id: str, status: str, error_message: str | None = None, **kwargs: Any
) -> None:
    """Update status, rejecting stale writes and surfacing persistence failures."""
    await _write_job_fields(
        job_id,
        "status = :status, error_message = :error_message, "
        "current_stage = :current_stage, stages_done = :stages_done",
        {
            "status": status,
            "error_message": error_message,
            "current_stage": kwargs.get("current_stage"),
            "stages_done": kwargs.get("stages_done", 0),
        },
    )
    log.info("job_status_updated", job_id=job_id, status=status)


async def update_job_stage(job_id: str, stage: str, stages_done: int) -> None:
    """Persist current stage within the active attempt."""
    await _write_job_fields(
        job_id,
        "current_stage = :stage, stages_done = :stages_done",
        {"stage": stage, "stages_done": stages_done},
    )


async def update_job_result(job_id: str, result: dict[str, Any]) -> None:
    """Compatibility entry point with the same strict persistence guarantee."""
    await update_job_result_strict(job_id, result)


async def update_job_result_strict(job_id: str, result: dict[str, Any]) -> None:
    """Store results only for the active server-generated analysis attempt."""
    attempt_id = current_analysis_attempt(job_id)
    payload = dict(result)
    if attempt_id is not None:
        payload["analysis_attempt_id"] = str(attempt_id)
    else:
        payload.pop("analysis_attempt_id", None)
    await _write_job_fields(job_id, "result = :result", {"result": json.dumps(payload)})


async def increment_password_attempts(job_id: str) -> int:
    """Increment retry count atomically only for the active analysis attempt."""
    return int(
        await _write_job_fields(
            job_id,
            "password_attempts = password_attempts + 1",
            {},
            returning="password_attempts",
        )
    )


async def create_artifact(
    *,
    parent_id: str | None,
    root_id: str | None,
    depth: int,
    sha256: str,
    size: int,
    original_filename: str,
    origin_path: str | None = None,
    extraction_source: str | None = None,
    archive_type: str | None = None,
    extraction_note: str | None = None,
    occurrence_index: int | None = None,
    job_id: str | None = None,
    root_job_id: str | None = None,
    md5: str | None = None,
    sha1: str | None = None,
    mime: str | None = None,
    verdict: str | None = None,
    score: int | None = None,
    risk_level: str | None = None,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Create an artifact record. Returns dict with 'id' key.

    Uses its own session to avoid polluting the pipeline session.
    """
    from uuid import NAMESPACE_URL, uuid4, uuid5
    from uuid import UUID as _UUID

    if occurrence_index is not None and (
        isinstance(occurrence_index, bool) or occurrence_index < 0
    ):
        raise ValueError("Invalid artifact occurrence index")

    artifact_id = uuid4()

    async with AsyncSession(_engine) as session:
        try:
            from sqlalchemy import text

            # An extraction may commit a child just before its checkpoint fails.
            # Reuse that occurrence on retry, preserving separate origin paths.
            scope = root_job_id or job_id
            if scope:
                identity: dict[str, Any] = {
                    "root_job_id": _UUID(scope),
                    "parent_id": _UUID(parent_id) if parent_id else None,
                    "sha256": sha256,
                    "original_filename": original_filename,
                    "origin_path": origin_path,
                    "extraction_source": extraction_source,
                }
                if occurrence_index is not None:
                    # Archive entry ordinals distinguish identical names/bytes,
                    # while replaying that exact entry reuses its stable UUID.
                    identity["occurrence_index"] = occurrence_index
                lock_identity = json.dumps(identity, default=str, sort_keys=True)
                if occurrence_index is not None:
                    artifact_id = uuid5(NAMESPACE_URL, "malscan:artifact:" + lock_identity)
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": advisory_key("artifact", lock_identity)},
                )
                found = (
                    await session.execute(
                        text("SELECT id FROM artifacts WHERE id = :id"),
                        {"id": artifact_id},
                    )
                    if occurrence_index is not None
                    else await session.execute(
                        text(
                            "SELECT id FROM artifacts WHERE root_job_id = :root_job_id "
                            "AND parent_id IS NOT DISTINCT FROM :parent_id "
                            "AND sha256 = :sha256 AND original_filename = :original_filename "
                            "AND origin_path IS NOT DISTINCT FROM :origin_path "
                            "AND extraction_source IS NOT DISTINCT FROM :extraction_source "
                            "ORDER BY created_at, id LIMIT 1"
                        ),
                        identity,
                    )
                )
                existing = found.scalar_one_or_none() if found is not None else None
                if existing is not None:
                    await session.commit()
                    return {"id": str(existing)}

            stmt = text(
                """
                INSERT INTO artifacts (
                    id, parent_id, root_id, depth,
                    sha256, md5, sha1, size, mime, original_filename,
                    origin_path, extraction_source, archive_type, extraction_note,
                    job_id, root_job_id, verdict, score, risk_level, policy_version, created_at
                ) VALUES (
                    :id, :parent_id, :root_id, :depth,
                    :sha256, :md5, :sha1, :size, :mime, :original_filename,
                    :origin_path, :extraction_source, :archive_type, :extraction_note,
                    :job_id, :root_job_id, :verdict, :score,
                    :risk_level, :policy_version, :created_at
                )
                """
            )
            await session.execute(
                stmt,
                {
                    "id": artifact_id,
                    "parent_id": _UUID(parent_id) if parent_id else None,
                    "root_id": _UUID(root_id) if root_id else None,
                    "depth": depth,
                    "sha256": sha256,
                    "md5": md5,
                    "sha1": sha1,
                    "size": size,
                    "mime": mime,
                    "original_filename": original_filename,
                    "origin_path": origin_path,
                    "extraction_source": extraction_source,
                    "archive_type": archive_type,
                    "extraction_note": extraction_note,
                    "job_id": _UUID(job_id) if job_id else None,
                    "root_job_id": _UUID(root_job_id) if root_job_id else None,
                    "verdict": verdict,
                    "score": score,
                    "risk_level": risk_level,
                    "policy_version": policy_version,
                    "created_at": datetime.now(timezone.utc),
                },
            )
            await session.commit()
            return {"id": str(artifact_id)}
        except Exception:
            await session.rollback()
            raise


async def ensure_root_artifact(
    *,
    job_id: str,
    root_job_id: str,
    sha256: str,
    size: int,
    original_filename: str,
    existing_artifact_id: str | None,
) -> dict[str, str]:
    """Ensure every job has a canonical root artifact reference."""
    if existing_artifact_id:
        return {"id": existing_artifact_id, "root_id": existing_artifact_id}

    record = await create_artifact(
        parent_id=None,
        root_id=None,
        depth=0,
        sha256=sha256,
        size=size,
        original_filename=original_filename,
        extraction_source="upload",
        archive_type=None,
        job_id=job_id,
        root_job_id=root_job_id,
    )
    return {"id": record["id"], "root_id": record["id"]}


def _artifact_attempt_fence() -> tuple[str, dict[str, Any]]:
    active = _active_analysis_attempt.get()
    if active is None:
        return (
            "NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id = artifacts.job_id "
            "AND jobs.analysis_attempt_id IS NOT NULL)",
            {},
        )
    return (
        "EXISTS (SELECT 1 FROM jobs WHERE jobs.id = artifacts.job_id "
        "AND jobs.id = :attempt_job_id AND jobs.analysis_attempt_id = :active_attempt_id)",
        {"attempt_job_id": UUID(active[0]), "active_attempt_id": active[1]},
    )


async def update_artifact_risk(
    artifact_id: str,
    verdict: str,
    score: int,
    risk_level: str,
    policy_version: str,
) -> None:
    """Update the denormalized risk metadata on an artifact record."""
    from uuid import UUID as _UUID

    from sqlalchemy import text

    fence, fence_values = _artifact_attempt_fence()
    async with AsyncSession(_engine) as session:
        try:
            stmt = text(
                f"""
                UPDATE artifacts
                SET verdict = :verdict,
                    score = :score,
                    risk_level = :risk_level,
                    policy_version = :policy_version
                WHERE id = :id AND {fence}
                RETURNING id
                """
            )
            changed = await session.execute(
                stmt,
                {
                    **fence_values,
                    "id": _UUID(artifact_id),
                    "verdict": verdict,
                    "score": score,
                    "risk_level": risk_level,
                    "policy_version": policy_version,
                },
            )
            if changed.scalar_one_or_none() is None:
                raise StaleAnalysisAttempt(
                    "Artifact write rejected: analysis attempt is no longer active"
                )
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def update_artifact_verdict(
    artifact_id: str,
    verdict: str,
    score: int,
) -> None:
    """Compatibility shim until pipeline callers send risk metadata."""
    from uuid import UUID as _UUID

    from sqlalchemy import text

    fence, fence_values = _artifact_attempt_fence()
    async with AsyncSession(_engine) as session:
        try:
            stmt = text(
                f"""
                UPDATE artifacts
                SET verdict = :verdict,
                    score = :score
                WHERE id = :id AND {fence}
                RETURNING id
                """
            )
            changed = await session.execute(
                stmt,
                {
                    **fence_values,
                    "id": _UUID(artifact_id),
                    "verdict": verdict,
                    "score": score,
                },
            )
            if changed.scalar_one_or_none() is None:
                raise StaleAnalysisAttempt(
                    "Artifact write rejected: analysis attempt is no longer active"
                )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
