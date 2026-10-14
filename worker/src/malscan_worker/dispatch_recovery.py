"""Recover durable child jobs whose database commit outlived MQ publication.

Scope is linked recursive children, not original upload dispatch or password
submission. Messages contain file identity and lineage, never stored passwords.
Duplicate publication is deliberate: the consumer's claim lock fences execution.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from malscan_worker.db import _engine
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()

QUEUED_CHILDREN = text(
    """
    SELECT DISTINCT ON (j.id)
        j.id AS job_id, j.file_id, f.sha256, a.original_filename,
        a.id AS artifact_id, a.parent_id, a.root_id AS root_artifact_id, a.root_job_id
    FROM jobs AS j
    JOIN files AS f ON f.id = j.file_id
    JOIN artifacts AS a ON a.job_id = j.id
    WHERE j.status = 'queued' AND j.parent_job_id IS NOT NULL
      AND j.updated_at <= :cutoff
    ORDER BY j.id, a.created_at
    LIMIT :limit
"""
)

ANCESTOR_HASHES = text(
    """
    WITH RECURSIVE ancestors AS (
        SELECT id, parent_id, sha256, 0 AS hops FROM artifacts WHERE id = :parent_id
        UNION ALL
        SELECT a.id, a.parent_id, a.sha256, p.hops + 1
        FROM artifacts AS a JOIN ancestors AS p ON a.id = p.parent_id
        WHERE p.hops < 100
    )
    SELECT DISTINCT sha256 FROM ancestors
"""
)


async def reconcile_queued_children(limit: int = 50) -> int:
    if not 1 <= limit <= 1000:
        raise ValueError("Recovery batch size must be between 1 and 1000")
    if _engine is None:
        raise ValueError("Child dispatch recovery requires a configured database")
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=5)
    payloads: list[dict[str, Any]] = []
    async with AsyncSession(_engine) as session:
        rows = (
            (
                await session.execute(
                    QUEUED_CHILDREN,
                    {
                        "cutoff": cutoff,
                        "limit": limit,
                    },
                )
            )
            .mappings()
            .all()
        )
        for row in rows:
            ancestors: list[str] = list(
                (
                    await session.execute(
                        ANCESTOR_HASHES,
                        {
                            "parent_id": row["parent_id"],
                        },
                    )
                )
                .scalars()
                .all()
            )
            payloads.append(
                {
                    "job_id": str(row["job_id"]),
                    "file_id": str(row["file_id"]),
                    "storage_key": row["sha256"],
                    "sha256": row["sha256"],
                    "original_filename": row["original_filename"],
                    "artifact_id": str(row["artifact_id"]),
                    "root_artifact_id": str(row["root_artifact_id"]),
                    "root_job_id": str(row["root_job_id"]),
                    "ancestor_hashes": sorted(set(ancestors)),
                }
            )
    if not payloads:
        return 0
    submitter = await InternalJobSubmitter.get_instance()
    published = 0
    for payload in payloads:
        try:
            await submitter.publish_payload(payload)
        except Exception:
            log.warning("queued_child_recovery_publish_failed", job_id=payload["job_id"])
        else:
            published += 1
    return published


async def recovery_loop(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await reconcile_queued_children()
        except Exception:
            log.warning("queued_child_recovery_round_failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass
