"""Small ports used by the executable root-batch adapter."""

from pathlib import Path
from typing import Any, Protocol


class ObjectStore(Protocol):
    async def fetch(self, key: str, destination: Path, *, sha256: str, size: int) -> Path:
        """Fetch and verify an immutable artifact into a private local file."""
        ...

    async def put_file(
        self,
        key: str,
        source: Path,
        *,
        sha256: str,
        size: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        ...

    async def put_json(self, key: str, document: dict[str, Any]) -> str:
        ...

    async def read_json(self, key: str) -> dict[str, Any]:
        ...

    async def delete(self, key: str) -> None:
        ...


class ChildAnalysisServices(Protocol):
    async def submit_child(
        self,
        *,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job_id: str,
        parent_job_depth: int,
        artifact_id: str | None = None,
        root_artifact_id: str | None = None,
        root_job_id: str | None = None,
        ancestor_hashes: set[str] | None = None,
        origin_path: str | None = None,
        extraction_source: str | None = None,
        archive_type: str | None = None,
        occurrence_index: int | None = None,
    ) -> str | None:
        ...
