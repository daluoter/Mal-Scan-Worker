"""Tests for deferred sandbox publisher initialization behavior."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_init_sandbox_publisher_reuses_queue_when_arguments_drift(
    monkeypatch,
) -> None:
    from malscan_worker.sandbox import publisher

    class DummyPreconditionFailedError(Exception):
        pass

    calls: list[dict[str, object]] = []
    channel_options: list[dict[str, object]] = []

    class DummyChannel:
        def __init__(self) -> None:
            self.is_closed = False
            self.default_exchange = SimpleNamespace()

        async def declare_queue(
            self,
            name: str,
            durable: bool,
            arguments: dict[str, object] | None = None,
            passive: bool = False,
        ) -> object:
            calls.append(
                {
                    "name": name,
                    "durable": durable,
                    "arguments": arguments,
                    "passive": passive,
                }
            )
            if not passive:
                self.is_closed = True
                raise DummyPreconditionFailedError("queue already exists")
            assert not self.is_closed
            return object()

        async def close(self) -> None:
            self.is_closed = True

    class DummyConnection:
        def __init__(self) -> None:
            self.is_closed = False

        async def channel(self, **kwargs) -> DummyChannel:
            channel_options.append(kwargs)
            return DummyChannel()

        async def close(self) -> None:
            self.is_closed = True

    async def fake_connect_robust(_url: str) -> DummyConnection:
        return DummyConnection()

    monkeypatch.setattr(
        publisher.aio_pika.exceptions,
        "ChannelPreconditionFailed",
        DummyPreconditionFailedError,
    )
    monkeypatch.setattr(
        publisher,
        "get_settings",
        lambda: SimpleNamespace(
            rabbitmq_url="amqp://guest:guest@localhost:5672/",
            rabbitmq_sandbox_queue="malscan.jobs.sandbox",
        ),
    )
    monkeypatch.setattr(
        publisher.aio_pika,
        "connect_robust",
        fake_connect_robust,
    )

    publisher._connection = None
    publisher._channel = None
    try:
        await publisher.init_sandbox_publisher()
    finally:
        publisher._connection = None
        publisher._channel = None

    assert calls == [
        {
            "name": "malscan.jobs.sandbox",
            "durable": True,
            "arguments": {
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "malscan-dlq",
            },
            "passive": False,
        },
        {
            "name": "malscan.jobs.sandbox",
            "durable": True,
            "arguments": None,
            "passive": True,
        },
    ]
    assert channel_options == [
        {"publisher_confirms": True, "on_return_raises": True},
        {"publisher_confirms": True, "on_return_raises": True},
    ]
