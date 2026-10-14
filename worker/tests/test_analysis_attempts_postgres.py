"""Opt-in PostgreSQL verification of stale write rejection.

Run against a prepared development database with MALSCAN_TEST_POSTGRES=1.
This creates and cleans up only its own file, job, and artifact records.
"""

import asyncio
import os
from uuid import UUID, uuid4

import pytest
from malscan.models import File, Job
from malscan.models.artifact import Artifact
from malscan_worker import db
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.skipif(
    os.environ.get("MALSCAN_TEST_POSTGRES") != "1",
    reason="Opt-in development PostgreSQL test",
)


@pytest.mark.asyncio
async def test_replaced_delivery_cannot_overwrite_postgres_results_or_artifact_risk():
    file_id, job_id, artifact_id = uuid4(), uuid4(), uuid4()
    async with AsyncSession(db._engine) as session:
        session.add(
            File(
                id=file_id,
                sha256=uuid4().hex + uuid4().hex,
                filename="attempt-fencing-test.bin",
                size=1,
                content_type="application/octet-stream",
            )
        )
        await session.flush()
        session.add(Job(id=job_id, file_id=file_id, status="scanning", stages_total=1))
        await session.flush()
        session.add(
            Artifact(
                id=artifact_id,
                root_job_id=job_id,
                job_id=job_id,
                sha256=uuid4().hex + uuid4().hex,
                size=1,
                original_filename="attempt-fencing-test.bin",
                depth=0,
            )
        )
        await session.commit()
    old_claimed = asyncio.Event()
    replacement_finished = asyncio.Event()
    attempts = []
    rejected = []

    async def old_delivery():
        async with db.job_analysis_attempt(str(job_id)) as attempt:
            attempts.append(attempt)
            old_claimed.set()
            await replacement_finished.wait()
            for write in (
                lambda: db.update_job_result_strict(str(job_id), {"score": 99}),
                lambda: db.update_job_status(str(job_id), "done"),
                lambda: db.update_job_stage(str(job_id), "stale-stage", 99),
                lambda: db.increment_password_attempts(str(job_id)),
                lambda: db.update_artifact_risk(
                    str(artifact_id), "malicious", 99, "malicious", "test"
                ),
            ):
                with pytest.raises(db.StaleAnalysisAttempt):
                    await write()
                rejected.append(True)

    async def replacement():
        await old_claimed.wait()
        async with db.job_analysis_attempt(str(job_id)) as attempt:
            attempts.append(attempt)
            await db.update_job_result_strict(
                str(job_id), {"score": 5, "analysis_attempt_id": "forged"}
            )
            await db.update_job_stage(str(job_id), "current-stage", 1)
            assert await db.increment_password_attempts(str(job_id)) == 1
            await db.update_artifact_risk(str(artifact_id), "clean", 5, "low", "test")
            replacement_finished.set()

    try:
        await asyncio.wait_for(asyncio.gather(old_delivery(), replacement()), timeout=30)
        assert len(rejected) == 5
        assert attempts[0] != attempts[1]
        async with AsyncSession(db._engine) as session:
            job = (await session.execute(select(Job).where(Job.id == job_id))).scalar_one()
            artifact = (
                await session.execute(select(Artifact).where(Artifact.id == artifact_id))
            ).scalar_one()
            assert job.analysis_attempt_id == UUID(attempts[1])
            assert job.result == {"score": 5, "analysis_attempt_id": attempts[1]}
            assert job.status == "scanning" and job.current_stage == "current-stage"
            assert job.password_attempts == 1
            assert artifact.score == 5 and artifact.verdict == "clean"
        assert db.current_analysis_attempt() is None
    finally:
        async with AsyncSession(db._engine) as session:
            await session.execute(delete(Artifact).where(Artifact.id == artifact_id))
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.execute(delete(File).where(File.id == file_id))
            await session.commit()


@pytest.mark.asyncio
async def test_identical_archive_occurrences_keep_distinct_stable_artifact_ids(monkeypatch):
    """A replay is idempotent; distinct entry ordinals retain separate provenance."""
    engine = create_async_engine(db.settings.database_url, poolclass=NullPool)
    monkeypatch.setattr(db, "_engine", engine)
    file_id, job_id, root_artifact_id = uuid4(), uuid4(), uuid4()
    try:
        async with AsyncSession(engine) as session:
            source_hash = uuid4().hex + uuid4().hex
            session.add(
                File(
                    id=file_id,
                    sha256=source_hash,
                    size=1,
                    filename="ordinal-test.zip",
                    content_type="application/zip",
                )
            )
            await session.flush()
            session.add(Job(id=job_id, file_id=file_id, status="scanning", stages_total=1))
            await session.flush()
            session.add(
                Artifact(
                    id=root_artifact_id,
                    root_id=root_artifact_id,
                    root_job_id=job_id,
                    job_id=job_id,
                    sha256=source_hash,
                    size=1,
                    original_filename="ordinal-test.zip",
                    depth=0,
                )
            )
            await session.commit()
        parameters = {
            "parent_id": str(root_artifact_id),
            "root_id": str(root_artifact_id),
            "root_job_id": str(job_id),
            "depth": 1,
            "sha256": "b" * 64,
            "size": 1,
            "original_filename": "same.bin",
            "origin_path": "same.bin",
            "extraction_source": "archive-extract",
            "archive_type": "zip",
        }
        zero, one, replay_zero = await asyncio.gather(
            db.create_artifact(**parameters, occurrence_index=0),
            db.create_artifact(**parameters, occurrence_index=1),
            db.create_artifact(**parameters, occurrence_index=0),
        )
        assert zero["id"] != one["id"]
        assert zero["id"] == replay_zero["id"]
        async with AsyncSession(engine) as session:
            artifacts = (
                (await session.execute(select(Artifact).where(Artifact.root_job_id == job_id)))
                .scalars()
                .all()
            )
            assert len(artifacts) == 3  # The root plus two occurrences, despite replay.
            assert {str(item.id) for item in artifacts if item.parent_id} == {zero["id"], one["id"]}
    finally:
        async with AsyncSession(engine) as session:
            await session.execute(delete(Artifact).where(Artifact.root_job_id == job_id))
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.execute(delete(File).where(File.id == file_id))
            await session.commit()
        await engine.dispose()
