"""Base classes for pipeline stages."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from malscan.models.job import Job
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class StageContext:
    """Context passed to each stage."""

    job_id: str
    file_id: str
    storage_key: str
    sha256: str
    original_filename: str
    file_path: Path | None
    archive_password: str | None = None
    previous_results: list["StageResult"] = field(default_factory=list)
    job: Job | None = field(default=None)
    db: AsyncSession | None = field(default=None)
    artifact_id: str | None = None
    root_artifact_id: str | None = None
    root_job_id: str | None = None
    ancestor_hashes: set[str] = field(default_factory=set)
    skip_artifact_submission: bool = False
    # Optional ports allow the same stages to run with persistent self-hosted
    # adapters or a portable runtime without an ORM session.
    analysis_services: Any | None = None
    root_budget: Any | None = None
    depth: int = 0
    reserve_output: Callable[[str, int, int], None] | None = field(default=None, repr=False)


@dataclass
class StageResult:
    """Result from a stage execution."""

    stage_name: str
    status: str  # "ok", "failed", "skipped"
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    findings: dict[str, Any]
    artifacts: list[str]
    error: str | None = None
    tool_version: str | None = None
    rules_version: str | None = None


class Stage(ABC):
    """Abstract base class for analysis stages."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stage name identifier."""
        pass

    @abstractmethod
    async def execute(self, ctx: StageContext) -> StageResult:
        """
        Execute the stage.

        Args:
            ctx: Stage context with job info and file path.

        Returns:
            StageResult with findings and status.
        """
        pass
