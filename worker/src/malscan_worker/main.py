"""Worker main entry point."""

import asyncio
import signal
import sys
from contextlib import suppress

import structlog

from malscan_worker.config import get_settings
from malscan_worker.consumer import start_consumer
from malscan_worker.dispatch_recovery import recovery_loop
from malscan_worker.metrics import start_metrics_server
from malscan_worker.sandbox.publisher import close_sandbox_publisher, init_sandbox_publisher
from malscan_worker.utils.submission import InternalJobSubmitter

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger()
settings = get_settings()

# Shutdown flag
shutdown_event = asyncio.Event()


def handle_shutdown(signum: int, frame: object) -> None:
    """Handle shutdown signals."""
    log.info("shutdown_signal_received", signal=signum)
    shutdown_event.set()


async def main() -> None:
    """Main entry point."""
    settings.require_service_configuration()
    log.info(
        "worker_starting",
        rabbitmq_queue=settings.rabbitmq_queue,
        metrics_port=settings.metrics_port,
    )

    # Start metrics server
    metrics_runner = await start_metrics_server(port=settings.metrics_port)
    log.info("metrics_server_started", port=settings.metrics_port)
    recovery_task: asyncio.Task[None] | None = None

    try:
        # Pre-initialize the InternalJobSubmitter MQ connection at startup.
        # This prevents a race condition where lazy-initialization of the aio_pika
        # connection inside ArchiveExtractStage would interrupt SQLAlchemy's async
        # greenlet context, causing "greenlet_spawn has not been called" errors on
        # the first job that processes an archive.
        await InternalJobSubmitter.get_instance()
        log.info("internal_job_submitter_initialized")
        await init_sandbox_publisher()
        log.info("sandbox_publisher_initialized")
        recovery_task = asyncio.create_task(recovery_loop(shutdown_event))

        # Start RabbitMQ consumer
        await start_consumer(shutdown_event)
    except Exception as e:
        log.error("worker_error", error=str(e))
        raise
    finally:
        # Cleanup
        if recovery_task is not None:
            recovery_task.cancel()
            with suppress(asyncio.CancelledError):
                await recovery_task
        submitter_instance = InternalJobSubmitter._instance
        if submitter_instance:
            await submitter_instance.close()
        await close_sandbox_publisher()
        await metrics_runner.cleanup()
        log.info("worker_shutdown_complete")


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("worker_interrupted")
        sys.exit(0)
