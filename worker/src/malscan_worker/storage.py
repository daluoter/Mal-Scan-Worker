"""MinIO storage client for file download operations."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import structlog
from minio import Minio
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from malscan_worker.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Thread pool for running sync MinIO operations
_executor = ThreadPoolExecutor(max_workers=4)

# Get standard logging logger for tenacity before_sleep_log
_logger = logging.getLogger(__name__)

# Singleton MinIO client
_minio_client: Minio | None = None


def get_minio_client() -> Minio:
    """Get or create the MinIO client instance (Singleton)."""
    global _minio_client
    if _minio_client is None:
        endpoint = settings.minio_endpoint
        if not endpoint or not settings.minio_access_key or not settings.minio_secret_key:
            raise ValueError("MinIO endpoint and credentials are required for self-hosted storage")
        _minio_client = Minio(
            endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
    return _minio_client


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    before_sleep=before_sleep_log(_logger, logging.WARNING),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
def _download_file_sync(key: str, dest_dir: Path) -> Path:
    """Synchronous file download from MinIO with retry.

    Uses exponential backoff retry strategy:
    - Maximum 3 attempts
    - Wait times: 1s -> 2s -> 4s
    - Total maximum wait: ~7 seconds

    Args:
        key: Storage key (SHA256 hash).
        dest_dir: Destination directory.

    Returns:
        Path to the downloaded file.

    Raises:
        Exception: If download fails after all retries.
    """
    client = get_minio_client()
    bucket = settings.minio_bucket_uploads

    # Create destination directory if needed
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Download file
    dest_path = dest_dir / f"{key}.bin"
    client.fget_object(
        bucket_name=bucket,
        object_name=key,
        file_path=str(dest_path),
    )

    log.info(
        "file_downloaded_from_minio",
        bucket=bucket,
        key=key,
        dest_path=str(dest_path),
    )

    return dest_path


async def download_file(key: str, dest_dir: Path) -> Path:
    """Download file from MinIO asynchronously.

    Args:
        key: Storage key (typically SHA256 hash).
        dest_dir: Destination directory.

    Returns:
        Path to the downloaded file.

    Raises:
        Exception: If download fails after retries.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _executor,
        partial(_download_file_sync, key, dest_dir),
    )
