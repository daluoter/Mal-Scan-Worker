"""Internal job submission utility for recursive analysis."""

import asyncio
import json
from typing import Any, Optional, cast
from uuid import UUID

import aio_pika
import structlog
from malscan.models.file import File
from malscan.models.job import Job, JobStatus
from malscan_worker.config import get_settings
from malscan_worker.db import _engine
from minio import Minio
from minio.error import S3Error
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

log = structlog.get_logger()
settings = get_settings()


def get_minio_client() -> Minio:
    """Only instantiate the self-hosted backend storage adapter when used."""
    from malscan.storage import get_minio_client as factory

    return cast(Minio, factory())


async def upload_to_minio(file_path: str, key: str, content_type: str) -> str:
    from malscan.storage import upload_file_path

    result = await upload_file_path(file_path, key, content_type)
    if not isinstance(result, str):
        raise RuntimeError("Storage upload returned an invalid object key")
    return result


class InternalJobSubmitter:
    """Singleton class to manage MQ connections and submit sub-jobs safely."""

    _instance: Optional["InternalJobSubmitter"] = None
    _connection: aio_pika.abc.AbstractRobustConnection | None = None
    _channel: aio_pika.abc.AbstractChannel | None = None
    _exchange: aio_pika.abc.AbstractExchange | None = None

    def __new__(cls) -> "InternalJobSubmitter":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    async def get_instance(cls) -> "InternalJobSubmitter":
        """Get the singleton instance and ensure connection is established."""
        instance = cls()
        await instance._ensure_connection()
        return instance

    async def _ensure_connection(self) -> None:
        """Ensure RabbitMQ connection is active. Reconnect if necessary.
        Uses connect_robust to handle connection drops automatically.
        """
        if self._connection is None or self._connection.is_closed:
            log.info("initializing_internal_job_submitter_mq_connection")
            # Connect_robust handles automatic reconnects and heartbeats
            self._connection = await aio_pika.connect_robust(
                settings.rabbitmq_url,
                client_properties={"connection_name": "malscan_worker_submitter"},
            )
            self._channel = await self._connection.channel(
                publisher_confirms=True,
                on_return_raises=True,
            )
            # Default exchange for direct queue routing
            self._exchange = self._channel.default_exchange
            log.info("internal_job_submitter_mq_connected")

    async def close(self) -> None:
        """Close RabbitMQ connection."""
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
            self._connection = None
            self._channel = None
            self._exchange = None
            log.info("internal_job_submitter_mq_closed")

    async def publish_payload(self, payload: dict[str, Any]) -> None:
        """Publish a durable identity with broker confirmation or raise."""
        await self._ensure_connection()
        if self._exchange is None:
            raise RuntimeError("RabbitMQ publisher is unavailable")
        await self._exchange.publish(
            aio_pika.Message(
                body=json.dumps(payload).encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT
            ),
            routing_key=settings.rabbitmq_queue,
            mandatory=True,
        )

    async def _storage_object_exists(self, key: str) -> bool:
        """Check whether an object key exists in MinIO uploads bucket."""

        def _check_exists() -> bool:
            client = get_minio_client()
            try:
                client.stat_object(settings.minio_bucket_uploads, key)
                return True
            except S3Error as e:
                if e.code == "NoSuchKey":
                    return False
                raise

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _check_exists)

    async def submit_subjob(
        self,
        *,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job_id: str,
        parent_job_depth: int,
        artifact_id: str | None = None,
        root_artifact_id: str | None = None,
        root_job_id: str | None = None,
        ancestor_hashes: set[str] | None = None,
    ) -> str | None:
        """Submit a new sub-job for analysis.

        Uses its own independent DB session to avoid polluting the caller's
        session (which would expire all ORM objects on commit and cause
        "greenlet_spawn has not been called" errors in SQLAlchemy async).

        Args:
            file_path: Path to the extracted file on disk.
            filename: Original filename of the extracted file.
            content_type: MIME content type.
            sha256_hash: SHA256 hash of the extracted file.
            file_size: Size in bytes.
            parent_job_id: Parent job UUID as string.
            parent_job_depth: Recursion depth of the parent job.

        Returns:
            The sub-job UUID as string, or None if skipped/failed.
        """
        # Ensure parent constraints
        max_depth = getattr(settings, "max_job_depth", 3)
        if parent_job_depth >= max_depth:
            log.warning(
                "max_recursion_depth_reached",
                parent_job_id=parent_job_id,
                depth=parent_job_depth,
                filename=filename,
            )
            return None

        # The artifact link and child job are committed together. An artifact
        # lock prevents concurrent parent retries from creating multiple jobs;
        # the hash lock also serializes deduplicated File insertion.
        publish_needed = True
        async with AsyncSession(_engine) as db:
            sub_job = None
            if artifact_id is not None:
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 0))").bindparams(
                        identity=f"malscan-child:{artifact_id}"
                    )
                )
                linked = (
                    await db.execute(
                        text("SELECT job_id FROM artifacts WHERE id = :artifact_id").bindparams(
                            artifact_id=UUID(artifact_id)
                        )
                    )
                ).scalar_one_or_none()
                if isinstance(linked, (UUID, str)):
                    sub_job = (
                        await db.execute(select(Job).where(Job.id == UUID(str(linked))))
                    ).scalar_one_or_none()
                    if sub_job is not None:
                        publish_needed = sub_job.status == JobStatus.QUEUED.value

            if sub_job is None:
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 0))").bindparams(
                        identity=f"malscan-file:{sha256_hash}"
                    )
                )
                existing_file = (
                    await db.execute(select(File).where(File.sha256 == sha256_hash))
                ).scalar_one_or_none()
                if existing_file:
                    file_record = existing_file
                    # Dedup rows may outlive object storage lifecycle.
                    if not await self._storage_object_exists(sha256_hash):
                        await upload_to_minio(file_path, sha256_hash, content_type)
                else:
                    await upload_to_minio(file_path, sha256_hash, content_type)
                    file_record = File(
                        sha256=sha256_hash,
                        size=file_size,
                        filename=filename,
                        content_type=content_type,
                    )
                    db.add(file_record)
                    await db.flush()
                sub_job = Job(
                    file_id=file_record.id,
                    status=JobStatus.QUEUED.value,
                    stages_total=settings.stages_total,
                    parent_job_id=UUID(parent_job_id),
                    depth=parent_job_depth + 1,
                )
                db.add(sub_job)
                await db.flush()
                if artifact_id is not None:
                    # A failed link aborts this transaction. Publishing a child
                    # without a durable identity would make retries duplicate it.
                    await db.execute(
                        text("UPDATE artifacts SET job_id = :job_id WHERE id = :artifact_id"),
                        {"job_id": sub_job.id, "artifact_id": UUID(artifact_id)},
                        execution_options={"artifact_job_link": True},
                    )
            sub_job_id = str(sub_job.id)
            file_id_str = str(sub_job.file_id)
            await db.commit()

        if not publish_needed:
            return sub_job_id

        log.info(
            "sub_job_created",
            job_id=sub_job_id,
            parent_id=parent_job_id,
            filename=filename,
        )

        # 4. Publish to MQ (outside of DB session)
        message_body = {
            "job_id": sub_job_id,
            "file_id": file_id_str,
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
            "artifact_id": artifact_id,
            "root_artifact_id": root_artifact_id,
            "root_job_id": root_job_id,
            "ancestor_hashes": list(ancestor_hashes or set()),
        }

        try:
            await self.publish_payload(message_body)
            log.info("sub_job_published_to_mq", job_id=sub_job_id)
        except Exception as e:
            # MQ failed — update job status via explicit UPDATE
            log.error(
                "rabbitmq_sub_publish_failed",
                job_id=sub_job_id,
                error=str(e),
            )
            async with AsyncSession(_engine) as db:
                await db.execute(
                    update(Job)
                    .where(Job.id == UUID(sub_job_id))
                    .values(
                        status=JobStatus.QUEUED.value,
                        error_message="Child dispatch failed; retry is required",
                    )
                )
                await db.commit()
            raise RuntimeError("Child dispatch failed; retry is required") from e

        return sub_job_id
