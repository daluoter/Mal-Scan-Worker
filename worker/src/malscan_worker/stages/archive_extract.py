"""Archive extraction stage for processing compressed files.

Uses the pluggable handler registry to detect and extract archives,
creates artifact records for extracted files, and submits sub-jobs.
"""

import hashlib
import os
from collections.abc import Mapping
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import structlog

from malscan_worker.budget import BudgetExceeded
from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
)
from malscan_worker.extractors import (
    ExtractionLimits,
    get_default_registry,
)
from malscan_worker.extractors.process import extract_bounded
from malscan_worker.extractors.safety import remove_symlinks
from malscan_worker.heuristics.archive import (
    build_archive_heuristics,
    build_archive_summary,
)
from malscan_worker.heuristics.models import HeuristicHit
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

logger = structlog.get_logger()


class ArchiveExtractStage(Stage):
    """Extract files from archives and submit them as sub-jobs.

    Uses the handler registry to detect archive formats and delegates
    extraction to the appropriate format handler.  Creates artifact
    records for every extracted file and submits sub-jobs via MQ.
    """

    def __init__(self) -> None:
        self._registry = get_default_registry()

    @property
    def name(self) -> str:
        return "archive-extract"

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = getattr(ctx, "analysis_settings", None) or get_settings()

        # --- Skip checks ---------------------------------------------------
        if not ctx.file_path or not os.path.exists(ctx.file_path):
            return self._skip_result(started_at, "File not found")

        max_depth = getattr(
            ctx.analysis_services, "max_depth", getattr(settings, "max_job_depth", 3)
        )
        depth = ctx.job.depth if ctx.job else ctx.depth
        # --- Detect format --------------------------------------------------
        mime = self._get_mime(ctx)
        handler = self._registry.detect(ctx.file_path, mime)
        if handler is None:
            return self._skip_result(started_at, "Not an archive")
        if depth >= max_depth:
            return self._limited_result(started_at, f"Max depth {max_depth} reached", handler.name)

        logger.info(
            "archive_format_detected",
            job_id=ctx.job_id,
            format=handler.name,
            file=str(ctx.file_path),
        )

        # --- Build limits ---------------------------------------------------
        limits = ExtractionLimits(
            max_files=settings.extraction_max_files,
            max_extracted_bytes=settings.extraction_max_bytes,
            max_single_file_bytes=settings.extraction_max_single_bytes,
            max_expansion_ratio=settings.extraction_max_ratio,
            timeout_seconds=settings.extraction_timeout,
        )

        # --- Create root artifact if depth-0 and no artifact context yet ----
        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id
        root_job_id = ctx.root_job_id or ctx.job_id

        if not root_artifact_id and ctx.job:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,  # will self-reference after creation
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path),
                original_filename=ctx.original_filename,
                extraction_source="archive-extract",
                archive_type=handler.name,
                root_job_id=root_job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id
            ctx.root_artifact_id = root_artifact_id
            ctx.artifact_id = root_artifact_id

        # --- Extract with timeout -------------------------------------------
        extract_dir = Path(f"/tmp/{ctx.job_id}/extract")
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = await extract_bounded(
                handler,
                ctx.file_path,
                extract_dir,
                limits,
                ctx.archive_password,
                ctx.root_budget,
                ctx.job_id,
            )
        except BudgetExceeded as exc:
            return self._limited_result(started_at, exc.reason, handler.name)
        except NotImplementedError:
            unsupported = self._skip_result(
                started_at, "Archive format is not supported by the extractor"
            )
            unsupported.status = "unsupported"
            return unsupported
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as exc:
            logger.error(
                "archive_extraction_failed",
                job_id=ctx.job_id,
                error=str(exc),
                exc_info=True,
            )
            return self._error_result(started_at, f"Extraction failed: {exc!s}")

        # --- Zip bomb check -------------------------------------------------
        if result.malicious:
            return self._malicious_result(
                started_at, result.reason or "Malicious archive", handler.name
            )

        # Local extractor limits also make coverage incomplete, even when the
        # shared root still has capacity. Configuration limits imply no verdict.
        if any(
            "limit" in warning.lower()
            or "too large" in warning.lower()
            or "max total" in warning.lower()
            for warning in result.warnings
        ):
            result.resource_limited = True
            result.limit_reason = result.limit_reason or "extraction_limit"

        # --- Remove symlinks for safety -------------------------------------
        remove_symlinks(str(extract_dir))

        # --- Process extracted files ----------------------------------------
        seen_hashes: set[str] = set()
        created_artifacts: list[str] = []
        sub_jobs_created = 0
        ancestor_hashes = ctx.ancestor_hashes or set()

        # Only initialise submitter when we have a real job context
        job = ctx.job
        services = ctx.analysis_services
        submitter = await InternalJobSubmitter.get_instance() if job and not services else None

        for ef in result.files:
            # Compute SHA256
            file_sha256 = _file_sha256(ef.path)

            # Every occurrence keeps provenance, including duplicate/cycle nodes.
            cycle = file_sha256 in ancestor_hashes or file_sha256 == ctx.sha256
            duplicate = file_sha256 in seen_hashes
            skip = cycle or duplicate
            seen_hashes.add(file_sha256)

            if services:
                child = await services.submit_child(
                    file_path=ef.path,
                    filename=ef.original_name,
                    content_type="application/octet-stream",
                    sha256_hash=file_sha256,
                    file_size=ef.size,
                    parent_job_id=ctx.job_id,
                    parent_job_depth=depth,
                    artifact_id=None,
                    root_artifact_id=root_artifact_id,
                    root_job_id=root_job_id,
                    ancestor_hashes=ancestor_hashes | {ctx.sha256},
                    origin_path=ef.origin_path,
                    occurrence_index=ef.occurrence_index,
                    extraction_source="archive-extract",
                    archive_type=handler.name,
                )
                if isinstance(child, dict):
                    if child.get("artifact_id"):
                        created_artifacts.append(child["artifact_id"])
                    sub_jobs_created += bool(child.get("job_id"))
                elif child:
                    created_artifacts.append(str(child))
                    sub_jobs_created += not skip
                continue

            # Create artifact record and submit sub-job only with a real job
            if job:
                art = await create_artifact(
                    parent_id=parent_artifact_id,
                    root_id=root_artifact_id,
                    depth=job.depth + 1,
                    sha256=file_sha256,
                    size=ef.size,
                    original_filename=ef.original_name,
                    origin_path=ef.origin_path,
                    occurrence_index=ef.occurrence_index,
                    extraction_source="archive-extract",
                    archive_type=handler.name,
                    root_job_id=root_job_id if root_job_id else ctx.job_id,
                    verdict="skipped" if skip else None,
                    extraction_note=(
                        "ancestor_cycle"
                        if cycle
                        else "duplicate_within_extraction"
                        if duplicate
                        else None
                    ),
                )
                created_artifacts.append(art["id"])

            if skip:
                continue

            # Submit sub-job
            if submitter and job:
                try:
                    sub_job_id = await submitter.submit_subjob(
                        file_path=ef.path,
                        filename=ef.original_name,
                        content_type="application/octet-stream",
                        sha256_hash=file_sha256,
                        file_size=ef.size,
                        parent_job_id=str(job.id),
                        parent_job_depth=job.depth,
                        artifact_id=art["id"],
                        root_artifact_id=root_artifact_id,
                        root_job_id=root_job_id,
                        ancestor_hashes=ancestor_hashes | {ctx.sha256},
                    )
                    if sub_job_id:
                        sub_jobs_created += 1
                except Exception as exc:
                    result.warnings.append(f"Sub-job submission failed: {type(exc).__name__}")
                    logger.error(
                        "subjob_submission_failed",
                        job_id=ctx.job_id,
                        filename=ef.original_name,
                        error=str(exc),
                    )

        archive_summary = build_archive_summary(
            files=result.files,
            warnings=result.warnings,
            password_protected=result.password_protected,
        )
        heuristics = build_archive_heuristics(archive_summary)

        # --- Build final result ---------------------------------------------
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="partial" if result.resource_limited or result.warnings else "ok",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "archive_type": handler.name,
                "resource_limited": result.resource_limited,
                "limit_reason": result.limit_reason,
                "reason": result.limit_reason or (result.warnings[0] if result.warnings else None),
                "extracted_count": len(result.files),
                "sub_jobs_created": sub_jobs_created,
                "artifacts_created": len(created_artifacts),
                "warnings": result.warnings,
                "total_extracted_bytes": sum(ef.size for ef in result.files),
                "archive_summary": archive_summary,
                "heuristics": [_serialize_heuristic(hit) for hit in heuristics],
            },
            artifacts=created_artifacts,
        )

    # ------------------------------------------------------------------
    # MIME helper — extracts MIME from previous file-type stage results
    # ------------------------------------------------------------------

    def _get_mime(self, ctx: StageContext) -> str:
        """Get MIME type from the file-type stage in previous results."""
        for res in ctx.previous_results:
            if res.stage_name == "file-type":
                return (res.findings.get("mime_type") or "").lower()
        return ""

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _skip_result(self, started_at: datetime, reason: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="skipped",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={"reason": reason},
            artifacts=[],
        )

    def _limited_result(self, started_at: datetime, reason: str, archive_type: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="partial",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "resource_limited": True,
                "limit_reason": reason,
                "reason": reason,
                "archive_type": archive_type,
            },
            artifacts=[],
        )

    def _error_result(self, started_at: datetime, reason: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="error",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={"reason": reason},
            artifacts=[],
        )

    def _malicious_result(
        self, started_at: datetime, reason: str, archive_type: str
    ) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="malicious",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "malicious": True,
                "reason": reason,
                "archive_type": archive_type,
            },
            artifacts=[],
        )


def _serialize_heuristic(hit: HeuristicHit) -> dict[str, Any]:
    return {field.name: _to_jsonable(getattr(hit, field.name)) for field in fields(hit)}


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, MappingProxyType | Mapping):
        return {str(key): _to_jsonable(item) for key, item in value.items()}

    if isinstance(value, tuple):
        return [_to_jsonable(item) for item in value]

    return value


def _file_sha256(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
