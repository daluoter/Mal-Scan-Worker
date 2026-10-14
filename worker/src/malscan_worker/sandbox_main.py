"""Dedicated sandbox worker entry point."""

from __future__ import annotations

import asyncio
import signal
import sys

import structlog

from malscan_worker.config import get_settings
from malscan_worker.consumer import start_sandbox_consumer
from malscan_worker.metrics import start_metrics_server
from malscan_worker.sandbox import resolve_sandbox_provider_name
from malscan_worker.sandbox.preflight import PreflightConfig, check_sandbox_readiness

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger()
settings = get_settings()
shutdown_event = asyncio.Event()


def handle_shutdown(signum: int, frame: object) -> None:
    """Handle shutdown signals."""
    log.info("sandbox_shutdown_signal_received", signal=signum)
    shutdown_event.set()


async def main() -> int:
    """Main entrypoint for the dedicated sandbox worker."""
    if not settings.sandbox_enabled:
        log.info("sandbox_worker_disabled")
        return 0
    settings.require_service_configuration()
    provider = resolve_sandbox_provider_name(settings)
    if provider != "mock":
        readiness = await check_sandbox_readiness(
            PreflightConfig(
                provider=provider,
                base_url=settings.sandbox_base_url,
                api_token=settings.sandbox_api_token,
            )
        )
        if not readiness["success"]:
            log.error("sandbox_worker_preflight_failed", status=readiness["status"])
            return 1
    log.info(
        "sandbox_worker_starting",
        rabbitmq_queue=settings.rabbitmq_sandbox_queue,
        metrics_port=settings.metrics_port,
    )

    metrics_runner = await start_metrics_server(port=settings.metrics_port)
    log.info("sandbox_metrics_server_started", port=settings.metrics_port)

    try:
        await start_sandbox_consumer(shutdown_event)
    finally:
        await metrics_runner.cleanup()
        log.info("sandbox_worker_shutdown_complete")
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        log.info("sandbox_worker_interrupted")
        sys.exit(0)
