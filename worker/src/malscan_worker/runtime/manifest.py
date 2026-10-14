"""Validated, non-secret input contract for a portable root analysis."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid4

SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")


def validate_key(key: str) -> str:
    if not isinstance(key, str) or not key or len(key) > 1024:
        raise ValueError("Invalid object key")
    if key.startswith("/") or "\\" in key or "\x00" in key:
        raise ValueError("Invalid object key")
    if any(part in {"", ".", ".."} for part in key.split("/")):
        raise ValueError("Invalid object key")
    # Keep keys relative for both the filesystem and S3 adapters.
    if PurePosixPath(key).is_absolute():
        raise ValueError("Invalid object key")
    return key


def file_identity(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Source must be a regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class SourceReference:
    key: str
    sha256: str
    size: int
    filename: str

    def __post_init__(self) -> None:
        validate_key(self.key)
        if not isinstance(self.sha256, str) or not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("Invalid source SHA256")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("Invalid source size")
        if not isinstance(self.filename, str) or not self.filename or len(self.filename) > 1024:
            raise ValueError("Invalid source filename")
        if "\x00" in self.filename:
            raise ValueError("Invalid source filename")


@dataclass(frozen=True)
class AnalysisManifest:
    root_job_id: str
    attempt_id: str
    source: SourceReference
    report_key: str
    manifest_version: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.manifest_version, bool)
            or not isinstance(self.manifest_version, int)
            or self.manifest_version != 1
        ):
            raise ValueError("Unsupported manifest version")
        for value in (self.root_job_id, self.attempt_id):
            if str(UUID(value)) != value:
                raise ValueError("Identifiers must be canonical UUIDs")
        validate_key(self.report_key)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisManifest:
        expected = {"manifest_version", "root_job_id", "attempt_id", "source", "report_key"}
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError("Invalid analysis manifest fields")
        source = data["source"]
        if not isinstance(source, dict) or set(source) != {"key", "sha256", "size", "filename"}:
            raise ValueError("Invalid source reference fields")
        return cls(
            root_job_id=data["root_job_id"],
            attempt_id=data["attempt_id"],
            source=SourceReference(**source),
            report_key=data["report_key"],
            manifest_version=data["manifest_version"],
        )

    @classmethod
    def for_local_file(cls, path: Path, *, root_job_id: str | None = None) -> AnalysisManifest:
        sha256, size = file_identity(path)
        return cls(
            root_job_id=root_job_id or str(uuid4()),
            attempt_id=str(uuid4()),
            source=SourceReference(path.name, sha256, size, path.name),
            report_key="report.json",
        )
