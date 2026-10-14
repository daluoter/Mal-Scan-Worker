"""RabbitMQ consumer for processing jobs with retry and DLQ support."""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

import aio_pika
import structlog
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from malscan_worker.config import get_settings
from malscan_worker.db import (
    StaleAnalysisAttempt,
    get_job_for_context,
    increment_password_attempts,
    job_analysis_attempt,
    job_execution_lock,
    update_artifact_risk,
    update_job_result_strict,
    update_job_status,
)
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.metrics import job_total, worker_active_jobs
from malscan_worker.pipeline import finalize_deferred_sandbox_job, run_pipeline
from malscan_worker.reporting import build_password_attempts_exhausted_report
from malscan_worker.retry import RETRY_COUNT_HEADER, close_retry_publisher, publish_retry

log = structlog.get_logger()
settings = get_settings()

# Get standard logging logger for tenacity before_sleep_log
_logger = logging.getLogger(__name__)

# Connection retry settings - allow 15 minutes for RabbitMQ to be ready
MAX_CONNECTION_RETRIES = 90
RETRY_DELAY = 10  # seconds

# Message processing settings
DLQ_QUEUE = "malscan-dlq"
MAX_MESSAGE_RETRIES = 3


def _get_retry_count(message: aio_pika.abc.AbstractIncomingMessage) -> int:
    """Read native retry count and retain compatibility with x-death deliveries.

    RabbitMQ adds x-death header when a message is dead-lettered.
    Each entry in the array represents a dead-letter event with a count.

    Args:
        message: The incoming RabbitMQ message.

    Returns:
        Greatest recorded retry count; native re-publication increments its header.
    """
    headers = message.headers or {}
    x_death = headers.get("x-death")

    native_count = headers.get(RETRY_COUNT_HEADER, 0)
    native_count = (
        native_count
        if (
            isinstance(native_count, int)
            and not isinstance(native_count, bool)
            and native_count >= 0
        )
        else 0
    )
    if not x_death or not isinstance(x_death, list):
        return native_count

    # x-death is a list of dicts, each with a 'count' field
    total_count = 0
    for entry in x_death:
        if isinstance(entry, dict):
            count = entry.get("count", 0)
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                total_count += count

    return max(native_count, total_count)


async def _retry_or_dead_letter(
    message: aio_pika.abc.AbstractIncomingMessage,
    *,
    sandbox: bool = False,
) -> None:
    """Count real failed attempts; ordinary nack/requeue cannot update x-death."""
    retry_count = _get_retry_count(message)
    if retry_count >= MAX_MESSAGE_RETRIES:
        await message.reject(requeue=False)
        return
    try:
        await asyncio.sleep(min(2**retry_count, 8))
        await publish_retry(
            message,
            routing_key=settings.rabbitmq_sandbox_queue if sandbox else settings.rabbitmq_queue,
            retry_count=retry_count + 1,
        )
    except Exception as exc:
        log.warning("retry_publication_unconfirmed", error_type=type(exc).__name__)
        await message.reject(requeue=True)
        return
    await message.ack()


async def _with_job_execution_lock(
    message: aio_pika.abc.AbstractIncomingMessage,
    handler: Callable[[aio_pika.abc.AbstractIncomingMessage], Awaitable[None]],
    *,
    sandbox: bool = False,
) -> None:
    """Serialize deliveries per job and acknowledge already-finalized duplicates."""
    try:
        body = json.loads(message.body.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        await message.reject(requeue=False)
        return
    job_id = body.get("job_id") if isinstance(body, dict) else None
    if not isinstance(job_id, str) or not job_id:
        await message.reject(requeue=False)
        return
    try:
        async with job_execution_lock(job_id) as acquired:
            if not acquired:
                await asyncio.sleep(0.25)
                await message.reject(requeue=True)
                return
            job = await get_job_for_context(job_id)
            status = getattr(job, "status", None)
            stage = getattr(job, "current_stage", None)
            if status == "done" or (not sandbox and stage in {"sandbox", "sandbox_pending"}):
                await message.ack()
                return
            async with job_analysis_attempt(job_id):
                await handler(message)
    except StaleAnalysisAttempt:
        log.info("stale_job_delivery_ignored", job_id=job_id)
        await message.ack()
    except Exception as exc:
        log.error("job_lock_or_state_failed", job_id=job_id, error_type=type(exc).__name__)
        if getattr(message, "processed", False) is True:
            return
        await _retry_or_dead_letter(message, sandbox=sandbox)


async def process_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    await _with_job_execution_lock(message, _process_message)


async def _process_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    """Process a single job message with retry tracking.

    Failed processing publishes a confirmed replacement with incremented native
    retry metadata before acknowledging this delivery. Exhausted retries are
    dead-lettered; uncertain publication retains the original delivery.
    """
    job_id = None
    file_id = None
    retry_count = _get_retry_count(message)

    try:
        # Parse message
        body = json.loads(message.body.decode())
        job_id = body.get("job_id")
        file_id = body.get("file_id")

        log.info(
            "job_received",
            job_id=job_id,
            file_id=file_id,
            retry_count=retry_count,
        )

        worker_active_jobs.inc()
        job_total.labels(status="scanning").inc()

        try:
            if job_id:
                await update_job_status(job_id, "scanning")
            # Run the analysis pipeline
            pipeline_result = await run_pipeline(body)
            final_status = str(pipeline_result.get("status") or "done")
            if final_status == "done":
                job_total.labels(status="done").inc()

            # Acknowledge successful processing
            await message.ack()

        except StaleAnalysisAttempt:
            await message.ack()
        except ArchivePasswordRequiredError:
            if job_id:
                await update_job_status(
                    job_id,
                    "password_required",
                    error_message=(
                        "Archive is password-protected. " "Please provide a password to continue."
                    ),
                )
            await message.ack()

        except ArchiveWrongPasswordError as exc:
            try:
                attempts = await increment_password_attempts(job_id) if job_id else 0

                if job_id and attempts < 3:
                    await update_job_status(
                        job_id,
                        "password_required",
                        error_message="Wrong archive password. Please try again.",
                    )
                elif job_id and attempts >= 3:
                    report_payload = build_password_attempts_exhausted_report(
                        body,
                        existing_report=getattr(exc, "partial_report", None),
                    )
                    await update_job_result_strict(job_id, report_payload)
                    artifact_id = body.get("artifact_id")
                    risk = report_payload.get("risk") or {}
                    if artifact_id:
                        try:
                            await update_artifact_risk(
                                artifact_id=artifact_id,
                                verdict=report_payload.get("verdict", "unknown"),
                                score=int(report_payload.get("score", 0) or 0),
                                risk_level=str(report_payload.get("risk_level") or "clean"),
                                policy_version=str(risk.get("policy_version") or "unknown"),
                            )
                        except Exception:
                            log.exception(
                                "failed_to_update_artifact_risk_exhausted_password",
                                artifact_id=artifact_id,
                                job_id=job_id,
                            )
                    await update_job_status(job_id, "done")

                await message.ack()
            except StaleAnalysisAttempt:
                await message.ack()
            except Exception as e:
                log.error(
                    "password_retry_flow_failed",
                    job_id=job_id,
                    file_id=file_id,
                    error=str(e),
                    retry_count=retry_count,
                )
                if retry_count < MAX_MESSAGE_RETRIES:
                    await _retry_or_dead_letter(message)
                else:
                    if job_id:
                        await update_job_status(
                            job_id,
                            "failed",
                            error_message=f"Max retries exceeded: {e}",
                        )
                    await message.reject(requeue=False)

        except Exception as e:
            log.error(
                "job_failed",
                job_id=job_id,
                file_id=file_id,
                error=str(e),
                retry_count=retry_count,
            )
            job_total.labels(status="failed").inc()

            # Check if we should retry or send to DLQ
            if retry_count < MAX_MESSAGE_RETRIES:
                log.warning(
                    "job_retry_scheduled",
                    job_id=job_id,
                    retry_count=retry_count,
                    max_retries=MAX_MESSAGE_RETRIES,
                )
                # Reject with requeue to try again
                await _retry_or_dead_letter(message)
            else:
                log.warning(
                    "job_sent_to_dlq",
                    job_id=job_id,
                    retry_count=retry_count,
                    reason="max_retries_exceeded",
                )
                # Update job status to failed before sending to DLQ
                if job_id:
                    await update_job_status(
                        job_id, "failed", error_message=f"Max retries exceeded: {e}"
                    )
                # Reject without requeue - message goes to DLQ
                await message.reject(requeue=False)

        finally:
            worker_active_jobs.dec()

    except json.JSONDecodeError as e:
        log.error("invalid_message_format", error=str(e))
        # Don't requeue invalid messages - send to DLQ
        await message.reject(requeue=False)


async def process_sandbox_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    await _with_job_execution_lock(message, _process_sandbox_message, sandbox=True)


async def _process_sandbox_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    """Process a deferred sandbox job message with retry tracking."""
    job_id = None
    file_id = None
    retry_count = _get_retry_count(message)

    try:
        body = json.loads(message.body.decode())
        job_id = body.get("job_id")
        file_id = body.get("file_id")

        log.info(
            "sandbox_job_received",
            job_id=job_id,
            file_id=file_id,
            retry_count=retry_count,
        )

        worker_active_jobs.inc()
        job_total.labels(status="scanning").inc()

        try:
            if job_id:
                await update_job_status(
                    job_id,
                    "scanning",
                    current_stage="sandbox",
                    stages_done=settings.stages_total - 1,
                )
            await finalize_deferred_sandbox_job(body)
            job_total.labels(status="done").inc()
            await message.ack()
        except StaleAnalysisAttempt:
            await message.ack()
        except Exception as e:
            log.error(
                "sandbox_job_failed",
                job_id=job_id,
                file_id=file_id,
                error=str(e),
                retry_count=retry_count,
            )
            job_total.labels(status="failed").inc()
            if retry_count < MAX_MESSAGE_RETRIES:
                await _retry_or_dead_letter(message, sandbox=True)
            else:
                if job_id:
                    await update_job_status(
                        job_id,
                        "failed",
                        error_message=f"Sandbox max retries exceeded: {e}",
                    )
                await message.reject(requeue=False)
        finally:
            worker_active_jobs.dec()
    except json.JSONDecodeError as e:
        log.error("invalid_sandbox_message_format", error=str(e))
        await message.reject(requeue=False)


@retry(
    stop=stop_after_attempt(MAX_CONNECTION_RETRIES),
    wait=wait_fixed(RETRY_DELAY),
    before_sleep=before_sleep_log(_logger, logging.WARNING),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def connect_with_retry() -> aio_pika.abc.AbstractRobustConnection:
    """Connect to RabbitMQ with retry logic.

    Uses fixed 10-second intervals for RabbitMQ startup scenarios.
    Maximum 90 retries = 15 minutes total wait time.
    """
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    log.info("rabbitmq_connected")
    return connection


async def start_consumer(shutdown_event: asyncio.Event) -> None:
    """Start consuming messages from RabbitMQ with DLQ support."""
    connection = await connect_with_retry()

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)

        # Declare DLQ first (result unused but ensures queue exists)
        _ = await channel.declare_queue(
            DLQ_QUEUE,
            durable=True,
        )
        log.info("dlq_declared", queue=DLQ_QUEUE)

        # Declare main queue with DLQ configuration
        # Note: If the queue already exists with different arguments,
        # this will silently use the existing queue configuration.
        try:
            queue = await channel.declare_queue(
                settings.rabbitmq_queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": DLQ_QUEUE,
                },
            )
        except aio_pika.exceptions.ChannelPreconditionFailed:
            # Queue exists with different arguments - use it as-is
            log.warning(
                "queue_dlq_config_skipped",
                queue=settings.rabbitmq_queue,
                reason="queue_already_exists_with_different_arguments",
            )
            # A precondition failure closes the channel; preserve the existing
            # queue through a fresh channel rather than deleting its messages.
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            queue = await channel.declare_queue(
                settings.rabbitmq_queue,
                durable=True,
                passive=True,  # Just get the existing queue
            )

        log.info("consumer_started", queue=settings.rabbitmq_queue, dlq=DLQ_QUEUE)

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                if shutdown_event.is_set():
                    break
                await process_message(message)

    log.info("consumer_stopped")
    await close_retry_publisher()


async def start_sandbox_consumer(shutdown_event: asyncio.Event) -> None:
    """Start consuming deferred sandbox messages."""
    connection = await connect_with_retry()

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)

        _ = await channel.declare_queue(DLQ_QUEUE, durable=True)

        try:
            queue = await channel.declare_queue(
                settings.rabbitmq_sandbox_queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": DLQ_QUEUE,
                },
            )
        except aio_pika.exceptions.ChannelPreconditionFailed:
            log.warning(
                "sandbox_queue_dlq_config_skipped",
                queue=settings.rabbitmq_sandbox_queue,
                reason="queue_already_exists_with_different_arguments",
            )
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            queue = await channel.declare_queue(
                settings.rabbitmq_sandbox_queue,
                durable=True,
                passive=True,
            )

        log.info("sandbox_consumer_started", queue=settings.rabbitmq_sandbox_queue, dlq=DLQ_QUEUE)

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                if shutdown_event.is_set():
                    break
                await process_sandbox_message(message)

    log.info("sandbox_consumer_stopped")
    await close_retry_publisher()
