"""RabbitMQ publisher for deferred sandbox jobs."""

from __future__ import annotations

import json
from typing import Any

import aio_pika
import structlog

from malscan_worker.config import get_settings

log = structlog.get_logger()

_connection: aio_pika.abc.AbstractRobustConnection | None = None
_channel: aio_pika.abc.AbstractChannel | None = None


async def init_sandbox_publisher() -> None:
    """Initialize the shared sandbox publisher connection."""
    global _connection, _channel

    settings = get_settings()
    if (
        _connection is not None
        and not _connection.is_closed
        and _channel is not None
        and not _channel.is_closed
    ):
        return

    if _connection is None or _connection.is_closed:
        _connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    _channel = await _connection.channel(publisher_confirms=True, on_return_raises=True)
    try:
        await _channel.declare_queue(
            settings.rabbitmq_sandbox_queue,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "malscan-dlq",
            },
        )
    except aio_pika.exceptions.ChannelPreconditionFailed:
        log.warning(
            "sandbox_publisher_queue_dlq_config_skipped",
            queue=settings.rabbitmq_sandbox_queue,
            reason="queue_already_exists_with_different_arguments",
        )
        # RabbitMQ closes a channel after a precondition failure. Use a fresh
        # confirmed channel for a passive lookup of the already-created queue.
        _channel = await _connection.channel(publisher_confirms=True, on_return_raises=True)
        await _channel.declare_queue(
            settings.rabbitmq_sandbox_queue,
            durable=True,
            passive=True,
        )
    log.info("sandbox_publisher_initialized", queue=settings.rabbitmq_sandbox_queue)


async def close_sandbox_publisher() -> None:
    """Close the shared sandbox publisher connection."""
    global _connection, _channel

    if _channel is not None and not _channel.is_closed:
        await _channel.close()
    if _connection is not None and not _connection.is_closed:
        await _connection.close()
    _connection = None
    _channel = None


async def publish_sandbox_job(job_data: dict[str, Any]) -> None:
    """Publish a deferred sandbox job to the sandbox queue."""
    settings = get_settings()
    if _connection is None or _connection.is_closed or _channel is None or _channel.is_closed:
        await init_sandbox_publisher()
    if _channel is None or _channel.is_closed:
        raise RuntimeError("Sandbox publisher channel is not available")

    message = aio_pika.Message(
        body=json.dumps(job_data).encode(),
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        content_type="application/json",
    )
    await _channel.default_exchange.publish(
        message, routing_key=settings.rabbitmq_sandbox_queue, mandatory=True
    )
    log.info(
        "sandbox_job_published",
        job_id=job_data.get("job_id"),
        queue=settings.rabbitmq_sandbox_queue,
    )
