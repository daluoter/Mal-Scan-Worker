"""Bounded replacement publication, confirmation and original-delivery recovery."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker import consumer, retry
from pamqp.commands import Basic


def incoming(*, count=0):
    return SimpleNamespace(
        body=b'{"job_id":"job","archive_password":"opaque-password"}',
        headers={retry.RETRY_COUNT_HEADER: count, "trace": "keep"},
        content_type="application/json",
        content_encoding=None,
        correlation_id="correlation",
        message_id="message-id",
        ack=AsyncMock(),
        reject=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_retry_publication_preserves_opaque_body_and_requires_confirmed_route(mocker):
    message = incoming(count=1)
    publish = AsyncMock(return_value=Basic.Ack(delivery_tag=3))
    mocker.patch(
        "malscan_worker.retry._confirmed_channel",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(default_exchange=SimpleNamespace(publish=publish)),
    )
    await retry.publish_retry(message, routing_key="static-queue", retry_count=2)
    replacement = publish.await_args.args[0]
    assert replacement.body == message.body
    assert replacement.headers[retry.RETRY_COUNT_HEADER] == 2
    assert replacement.headers["trace"] == "keep"
    assert replacement.correlation_id == "correlation"
    assert publish.await_args.kwargs == {
        "routing_key": "static-queue",
        "mandatory": True,
        "timeout": 15,
    }
    assert message.headers[retry.RETRY_COUNT_HEADER] == 1
    message.ack.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("confirmation", [None, True, Basic.Nack(delivery_tag=3)])
async def test_unconfirmed_or_rejected_publication_is_a_failure(mocker, confirmation):
    publish = AsyncMock(return_value=confirmation)
    mocker.patch(
        "malscan_worker.retry._confirmed_channel",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(default_exchange=SimpleNamespace(publish=publish)),
    )
    with pytest.raises(RuntimeError, match="not acknowledged"):
        await retry.publish_retry(incoming(), routing_key="queue", retry_count=1)


@pytest.mark.asyncio
async def test_broker_confirmation_precedes_original_ack(mocker):
    message = incoming(count=2)
    sequence = []

    async def publish(_message, *, routing_key, retry_count):
        assert routing_key == consumer.settings.rabbitmq_queue
        assert retry_count == 3
        sequence.append("confirmed")

    async def ack():
        sequence.append("acked")

    message.ack.side_effect = ack
    mocker.patch("malscan_worker.consumer.publish_retry", side_effect=publish)
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    await consumer._retry_or_dead_letter(message)
    assert sequence == ["confirmed", "acked"]
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_publish_failure_retains_original_without_incrementing_header(mocker):
    message = incoming(count=1)
    mocker.patch(
        "malscan_worker.consumer.publish_retry",
        new_callable=AsyncMock,
        side_effect=ConnectionError("Connection lost during confirmation"),
    )
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    await consumer._retry_or_dead_letter(message)
    message.ack.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=True)
    assert message.headers[retry.RETRY_COUNT_HEADER] == 1


@pytest.mark.asyncio
async def test_exhausted_native_retries_dead_letter_without_republication(mocker):
    message = incoming(count=consumer.MAX_MESSAGE_RETRIES)
    publish = mocker.patch("malscan_worker.consumer.publish_retry", new_callable=AsyncMock)
    await consumer._retry_or_dead_letter(message)
    publish.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=False)
    message.ack.assert_not_awaited()


@pytest.mark.asyncio
async def test_dynamic_retries_use_dynamic_queue(mocker):
    publish = mocker.patch("malscan_worker.consumer.publish_retry", new_callable=AsyncMock)
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    message = incoming()
    await consumer._retry_or_dead_letter(message, sandbox=True)
    assert publish.await_args.kwargs["routing_key"] == consumer.settings.rabbitmq_sandbox_queue
    assert publish.await_args.kwargs["retry_count"] == 1
    message.ack.assert_awaited_once()


@pytest.mark.parametrize("value", [-1, True, "3", None])
def test_invalid_native_count_does_not_bypass_bounded_retry(value):
    assert (
        consumer._get_retry_count(SimpleNamespace(headers={retry.RETRY_COUNT_HEADER: value})) == 0
    )


def test_native_and_legacy_count_keep_the_larger_recorded_count():
    message = incoming(count=2)
    message.headers["x-death"] = [{"count": 3}]
    assert consumer._get_retry_count(message) == 3


@pytest.mark.asyncio
async def test_new_retry_channel_requires_confirms_and_unroutable_returns(mocker, monkeypatch):
    channel = SimpleNamespace(is_closed=False)
    connection = SimpleNamespace(is_closed=False, channel=AsyncMock(return_value=channel))
    monkeypatch.setattr(retry, "_connection", None)
    monkeypatch.setattr(retry, "_channel", None)
    mocker.patch(
        "malscan_worker.retry.aio_pika.connect_robust",
        new_callable=AsyncMock,
        return_value=connection,
    )
    assert await retry._confirmed_channel() is channel
    connection.channel.assert_awaited_once_with(publisher_confirms=True, on_return_raises=True)


@pytest.mark.asyncio
async def test_persistent_processing_failure_stops_after_three_confirmed_retries(mocker):
    @asynccontextmanager
    async def unlocked(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", unlocked)
    mocker.patch("malscan_worker.consumer.job_analysis_attempt", unlocked)
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context", new_callable=AsyncMock, return_value=None
    )
    status = mocker.patch("malscan_worker.consumer.update_job_status", new_callable=AsyncMock)
    analyze = mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Persistent analysis failure"),
    )
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    replacements = []

    async def confirmed(message, **_kwargs):
        replacements.append(message)
        return Basic.Ack(delivery_tag=len(replacements))

    mocker.patch(
        "malscan_worker.retry._confirmed_channel",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(default_exchange=SimpleNamespace(publish=confirmed)),
    )
    delivery = incoming()
    for count in range(4):
        assert consumer._get_retry_count(delivery) == count
        await consumer.process_message(delivery)
        if count < 3:
            delivery.ack.assert_awaited_once()
            delivery.reject.assert_not_awaited()
            replacement = replacements[-1]
            delivery = incoming()
            delivery.headers = replacement.headers
        else:
            delivery.ack.assert_not_awaited()
            delivery.reject.assert_awaited_once_with(requeue=False)
    assert analyze.await_count == 4
    assert len(replacements) == 3
    assert status.await_args.args[1] == "failed"
