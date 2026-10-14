"""Confirmed, bounded RabbitMQ retry publication without changing queue topology."""

from __future__ import annotations

import asyncio
from typing import Any

import aio_pika
from pamqp.commands import Basic

from malscan_worker.config import get_settings

RETRY_COUNT_HEADER = "x-malscan-retry-count"
_connection: aio_pika.abc.AbstractRobustConnection | None = None
_channel: aio_pika.abc.AbstractChannel | None = None
_initialization_lock = asyncio.Lock()


async def _confirmed_channel() -> aio_pika.abc.AbstractChannel:
    global _connection, _channel
    async with _initialization_lock:
        if _connection is None or _connection.is_closed:
            _connection = await aio_pika.connect_robust(get_settings().rabbitmq_url, timeout=15)
            _channel = None
        if _channel is None or _channel.is_closed:
            _channel = await _connection.channel(
                publisher_confirms=True,
                on_return_raises=True,
            )
        return _channel


async def publish_retry(
    message: aio_pika.abc.AbstractIncomingMessage,
    *,
    routing_key: str,
    retry_count: int,
) -> None:
    """Retain the original until the broker confirms its replacement message.

    The body stays opaque: archive passwords are not decoded, printed or logged.
    Mandatory publication treats an unroutable queue as failure, retaining the
    original delivery. A connection loss after acceptance may leave a duplicate;
    the consumer's execution lock and durable completion guard handle that case.
    """
    if not isinstance(retry_count, int) or isinstance(retry_count, bool) or retry_count < 1:
        raise ValueError("retry_count must be a positive integer")
    channel = await _confirmed_channel()
    headers: dict[str, Any] = dict(message.headers or {})
    headers[RETRY_COUNT_HEADER] = retry_count
    replacement = aio_pika.Message(
        body=message.body,
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        content_type=getattr(message, "content_type", None) or "application/json",
        content_encoding=getattr(message, "content_encoding", None),
        correlation_id=getattr(message, "correlation_id", None),
        message_id=getattr(message, "message_id", None),
        headers=headers,
    )
    confirmation = await channel.default_exchange.publish(
        replacement,
        routing_key=routing_key,
        mandatory=True,
        timeout=15,
    )
    if not isinstance(confirmation, Basic.Ack):
        raise RuntimeError("Retry publication was not acknowledged by the broker")


async def close_retry_publisher() -> None:
    global _connection, _channel
    if _channel is not None and not _channel.is_closed:
        await _channel.close()
    if _connection is not None and not _connection.is_closed:
        await _connection.close()
    _channel = None
    _connection = None
