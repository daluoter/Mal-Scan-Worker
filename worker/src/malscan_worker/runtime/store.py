"""Verified filesystem and S3-compatible stores (MinIO, AWS S3, Cloudflare R2)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit
from urllib.request import getproxies_environment, proxy_bypass

from malscan_worker.runtime.manifest import file_identity, validate_key


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".json-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def copy_verified(stream: BinaryIO, destination: Path, *, sha256: str, size: int) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
    digest = hashlib.sha256()
    received = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            while chunk := stream.read(min(1024 * 1024, size - received + 1)):
                received += len(chunk)
                if received > size:
                    raise ValueError("Artifact exceeds declared size")
                digest.update(chunk)
                output.write(chunk)
            if received != size or digest.hexdigest() != sha256:
                raise ValueError("Artifact identity mismatch")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        return destination
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class LocalObjectStore:
    """Directory-backed store; all keys are confined beneath its resolved root."""

    def __init__(self, root: Path, *, read_only: bool = False):
        self.root = root.resolve()
        self.read_only = read_only
        if not read_only:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, key: str) -> Path:
        path = self.root.joinpath(*validate_key(key).split("/"))
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise ValueError("Object key escapes storage root")
        return path

    async def fetch(self, key: str, destination: Path, *, sha256: str, size: int) -> Path:
        path = self._path(key)

        def operation() -> Path:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Stored artifact is not a regular file")
            with path.open("rb") as stream:
                return copy_verified(stream, destination, sha256=sha256, size=size)

        return await asyncio.to_thread(operation)

    async def put_file(
        self,
        key: str,
        source: Path,
        *,
        sha256: str,
        size: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        if self.read_only:
            raise PermissionError("Store is read only")
        path = self._path(key)

        def operation() -> None:
            if path.exists():
                if file_identity(path) != (sha256, size):
                    raise ValueError("Existing object identity mismatch")
                return
            with source.open("rb") as stream:
                copy_verified(stream, path, sha256=sha256, size=size)

        await asyncio.to_thread(operation)
        return key

    async def put_json(self, key: str, document: dict[str, Any]) -> str:
        if self.read_only:
            raise PermissionError("Store is read only")
        await asyncio.to_thread(atomic_json, self._path(key), document)
        return key

    async def read_json(self, key: str) -> dict[str, Any]:
        path = self._path(key)

        def operation() -> dict[str, Any]:
            if path.stat().st_size > 32 * 1024 * 1024:
                raise ValueError("Checkpoint is too large")
            document = json.loads(path.read_text())
            if not isinstance(document, dict):
                raise ValueError("Invalid checkpoint document")
            return document

        return await asyncio.to_thread(operation)

    async def delete(self, key: str) -> None:
        if self.read_only:
            raise PermissionError("Store is read only")
        await asyncio.to_thread(self._path(key).unlink, missing_ok=True)


class S3ObjectStore:
    """S3 adapter using explicit credentials and a fixed bucket.

    Pass region="auto" with an account R2 endpoint. The adapter never creates a
    bucket or changes its policy. A source store can be read-only while result
    storage uses a separate bucket and write credential.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: str | None = None,
        read_only: bool = False,
        client: Any = None,
    ):
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("S3 endpoint must be an HTTP(S) origin")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("S3 endpoint must not include a bucket path or credentials")
        if not bucket or "/" in bucket:
            raise ValueError("Invalid bucket")
        if client is None:
            import certifi
            import urllib3
            from minio import Minio

            proxies = getproxies_environment()
            proxy = proxies.get(parsed.scheme) or proxies.get("all")
            timeout = urllib3.Timeout(connect=10, read=60)
            ca_certs = os.environ.get("SSL_CERT_FILE") or certifi.where()
            transport = (
                urllib3.ProxyManager(
                    proxy,
                    timeout=timeout,
                    retries=False,
                    cert_reqs="CERT_REQUIRED",
                    ca_certs=ca_certs,
                )
                if proxy and not proxy_bypass(parsed.netloc)
                else urllib3.PoolManager(
                    timeout=timeout,
                    retries=False,
                    cert_reqs="CERT_REQUIRED",
                    ca_certs=ca_certs,
                )
            )
            client = Minio(
                parsed.netloc,
                access_key=access_key,
                secret_key=secret_key,
                secure=parsed.scheme == "https",
                region=region,
                http_client=transport,
            )
        self.client = client
        self.bucket = bucket
        self.read_only = read_only

    async def fetch(self, key: str, destination: Path, *, sha256: str, size: int) -> Path:
        validate_key(key)

        def operation() -> Path:
            response = self.client.get_object(self.bucket, key)
            try:
                return copy_verified(response, destination, sha256=sha256, size=size)
            finally:
                response.close()
                response.release_conn()

        return await asyncio.to_thread(operation)

    async def put_file(
        self,
        key: str,
        source: Path,
        *,
        sha256: str,
        size: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        if self.read_only:
            raise PermissionError("Store is read only")
        validate_key(key)
        if await asyncio.to_thread(file_identity, source) != (sha256, size):
            raise ValueError("Artifact identity mismatch")
        await asyncio.to_thread(
            self.client.fput_object,
            self.bucket,
            key,
            str(source),
            content_type=content_type,
            metadata={"sha256": sha256},
        )
        return key

    async def put_json(self, key: str, document: dict[str, Any]) -> str:
        if self.read_only:
            raise PermissionError("Store is read only")
        validate_key(key)
        from io import BytesIO

        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True).encode()
        await asyncio.to_thread(
            self.client.put_object,
            self.bucket,
            key,
            BytesIO(encoded),
            len(encoded),
            content_type="application/json",
        )
        return key

    async def read_json(self, key: str) -> dict[str, Any]:
        validate_key(key)

        def operation() -> dict[str, Any]:
            response = self.client.get_object(self.bucket, key)
            try:
                encoded = response.read(32 * 1024 * 1024 + 1)
                if len(encoded) > 32 * 1024 * 1024:
                    raise ValueError("Checkpoint is too large")
                document = json.loads(encoded)
                if not isinstance(document, dict):
                    raise ValueError("Invalid checkpoint document")
                return document
            finally:
                response.close()
                response.release_conn()

        return await asyncio.to_thread(operation)

    async def delete(self, key: str) -> None:
        if self.read_only:
            raise PermissionError("Store is read only")
        validate_key(key)
        await asyncio.to_thread(self.client.remove_object, self.bucket, key)
