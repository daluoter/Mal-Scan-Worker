"""API routes for file upload, job status, and reports."""

import asyncio
import hashlib
import os
import tempfile
import uuid
from collections.abc import AsyncGenerator
from copy import deepcopy
from datetime import datetime
from typing import Any, TypeAlias

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from sse_starlette.sse import EventSourceResponse

from malscan.analysis_contract import (
    REPORT_SCHEMA_VERSION,
    analysis_from_report,
    summarize_static_artifacts,
)
from malscan.artifact_references import resolve_artifact_analysis_references
from malscan.config import get_settings
from malscan.db import get_db, get_session_factory
from malscan.models import File, Job, JobStatus
from malscan.models.artifact import Artifact
from malscan.models.budget import AnalysisBudget
from malscan.queue import publish_job
from malscan.report_explainability import build_explainability, ensure_artifact_tree_root
from malscan.schemas.requests import (
    JobProgress,
    JobStatusLiteral,
    JobStatusResponse,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    ReportResponse,
    UploadResponse,
)
from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.policy import POLICY_VERSION
from malscan.scoring.tree import merge_with_descendants
from malscan.storage import upload_file_path as upload_to_minio

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()

CHUNK_SIZE = 1024 * 1024  # 1MB chunks

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


def _response_job_status(status: str) -> JobStatusLiteral:
    if status == "queued":
        return "queued"
    if status == "scanning":
        return "scanning"
    if status == "password_required":
        return "password_required"
    if status == "done":
        return "done"
    if status == "failed":
        return "failed"
    raise ValueError(f"Unsupported job status: {status}")


def _risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "malicious"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def _infer_level_from_legacy(verdict: str | None, score: int) -> str:
    if verdict == "malicious":
        return "malicious"
    if verdict == "clean":
        return "clean" if score == 0 else _risk_level_from_score(score)
    if verdict == "suspicious":
        return _risk_level_from_score(score) if score > 0 else "medium"
    return _risk_level_from_score(score)


def _normalize_risk_collection(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalize_risk_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ensure_report_risk_shape(report: dict[str, Any]) -> dict[str, Any]:
    """Backfill risk fields for legacy stored reports."""
    score = int(report.get("score") or 0)
    verdict = str(report.get("verdict") or "clean")
    risk = report.get("risk")

    if isinstance(risk, dict):
        risk_score = int(risk.get("risk_score") or score)
        legacy_verdict = str(risk.get("legacy_verdict") or verdict)
        risk_level = str(
            risk.get("risk_level")
            or report.get("risk_level")
            or _infer_level_from_legacy(legacy_verdict, risk_score)
        )
        breakdown = risk.get("breakdown")
        if not isinstance(breakdown, dict):
            breakdown = {}
        risk["policy_version"] = str(risk.get("policy_version") or POLICY_VERSION)
        risk["risk_score"] = risk_score
        risk["risk_level"] = risk_level
        risk["legacy_verdict"] = legacy_verdict
        risk["malicious_gate_open"] = bool(
            risk.get("malicious_gate_open", risk_level == "malicious")
        )
        risk["high_gate_open"] = bool(
            risk.get("high_gate_open", risk_level in {"high", "malicious"})
        )
        risk["independent_source_count"] = int(risk.get("independent_source_count") or 0)
        breakdown.setdefault("local_score", risk_score)
        breakdown.setdefault("inherited_score", 0)
        breakdown.setdefault("synergy_bonus", 0)
        breakdown.setdefault("dampener", 0)
        breakdown.setdefault("final_score", risk_score)
        risk["breakdown"] = breakdown
        risk["evidence"] = _normalize_risk_collection(risk.get("evidence"))
        risk["top_evidence"] = _normalize_risk_collection(risk.get("top_evidence"))
        risk["descendant_summary"] = _normalize_risk_mapping(risk.get("descendant_summary"))
        risk["score_trace"] = _normalize_risk_mapping(risk.get("score_trace"))
        report["risk_level"] = risk_level
        report["risk"] = risk
        return report

    risk_level = str(report.get("risk_level") or _infer_level_from_legacy(verdict, score))
    report["risk_level"] = risk_level
    report["risk"] = {
        "policy_version": POLICY_VERSION,
        "risk_score": score,
        "risk_level": risk_level,
        "legacy_verdict": verdict,
        "malicious_gate_open": risk_level == "malicious",
        "high_gate_open": risk_level in {"high", "malicious"},
        "independent_source_count": 0,
        "breakdown": {
            "local_score": score,
            "inherited_score": 0,
            "synergy_bonus": 0,
            "dampener": 0,
            "final_score": score,
        },
        "evidence": [],
        "top_evidence": [],
        "descendant_summary": {},
        "score_trace": {},
    }
    return report


def _public_report_value(value: Any) -> Any:
    """Remove password values from extensible/raw report dictionaries."""
    if isinstance(value, dict):
        return {
            key: _public_report_value(item)
            for key, item in value.items()
            if str(key).lower()
            not in {"password", "archive_password", "password_value", "passwords"}
        }
    if isinstance(value, list):
        return [_public_report_value(item) for item in value]
    return value


def _empty_explainability() -> dict[str, Any]:
    return {
        "summary": {
            "headline": "",
            "primary_artifact_id": None,
            "primary_artifact_path": None,
            "top_findings": [],
            "final_verdict_explainer": "",
        },
        "artifacts": [],
        "findings": [],
        "evidence": [],
        "iocs": [],
        "decoded_strings": [],
        "uncertainties": [],
        "timeline": [],
        "failure_diagnostics": {
            "status": "none",
            "headline": "",
            "diagnostics": [],
            "suspected_miss_stages": [],
        },
    }


def _ensure_report_explainability_shape(report: dict[str, Any]) -> dict[str, Any]:
    report["report_schema_version"] = REPORT_SCHEMA_VERSION
    if not isinstance(report.get("explainability"), dict):
        report["explainability"] = _empty_explainability()
    else:
        explainability = report["explainability"]
        empty = _empty_explainability()
        for key, value in empty.items():
            if key not in explainability or not isinstance(explainability.get(key), type(value)):
                explainability[key] = value
        summary = explainability.get("summary")
        if isinstance(summary, dict):
            for key, value in empty["summary"].items():
                summary.setdefault(key, value)
        failure = explainability.get("failure_diagnostics")
        if isinstance(failure, dict):
            for key, value in empty["failure_diagnostics"].items():
                failure.setdefault(key, value)
    return report


def _empty_sandbox_result() -> dict[str, Any]:
    return {
        "executed": False,
        "provider": None,
        "task_id": None,
        "is_mock": False,
        "verdict_hint": None,
        "behaviors": [],
        "network_connections": [],
        "processes": [],
        "files": [],
        "registry": [],
        "mutexes": [],
        "dns": [],
        "http": [],
        "tcp_udp": [],
        "dropped_files": [],
        "screenshots": [],
        "pcap": {"available": False, "url": None},
        "memory_dump": {"available": False, "url": None},
        "iocs": {"domains": [], "ips": [], "urls": []},
        "errors": [],
        "raw_report_ref": None,
    }


def _ensure_report_results_shape(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results")
    if not isinstance(results, dict):
        report["results"] = {"sandbox": _empty_sandbox_result()}
        return report

    sandbox = results.get("sandbox")
    empty = _empty_sandbox_result()
    if not isinstance(sandbox, dict):
        results["sandbox"] = empty
        return report

    for key, value in empty.items():
        if key not in sandbox:
            sandbox[key] = value

    network_connections = sandbox.get("network_connections")
    tcp_udp = sandbox.get("tcp_udp")
    if not isinstance(network_connections, list) and isinstance(tcp_udp, list):
        sandbox["network_connections"] = list(sandbox["tcp_udp"])
    if not isinstance(sandbox.get("tcp_udp"), list):
        sandbox["tcp_udp"] = list(sandbox.get("network_connections") or [])

    return report


def _should_preserve_stored_explainability(report: dict[str, Any]) -> bool:
    explainability = report.get("explainability")
    if not isinstance(explainability, dict):
        return False
    failure = explainability.get("failure_diagnostics")
    if not isinstance(failure, dict):
        return False
    return str(failure.get("status") or "") == "blocked"


def _synthesize_root_artifact_tree(report: dict[str, Any]) -> dict[str, Any]:
    return ensure_artifact_tree_root(report, None)


def _artifact_level(node: dict[str, Any]) -> str:
    level = node.get("risk_level")
    if isinstance(level, str) and level:
        return level

    score = int(node.get("score") or 0)
    verdict = node.get("verdict")
    return _infer_level_from_legacy(str(verdict) if verdict is not None else None, score)


def _sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filename to prevent path traversal and other attacks.

    - Strips path components (../../etc/passwd -> passwd)
    - Handles Windows path separators
    - Removes null bytes
    - Truncates to 255 characters
    - Falls back to 'unnamed' if result is empty
    """
    # Replace Windows path separators with Unix ones, then get basename
    filename = filename.replace(chr(92), "/")
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Truncate to 255 characters (common filesystem limit)
    if len(filename) > 255:
        filename = filename[:255]

    # Fallback for empty/whitespace-only names
    if not filename.strip():
        filename = "unnamed"

    return filename


@router.post(
    "/files",
    response_model=UploadResponse,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "file": {
                                "type": "string",
                                "format": "binary",
                                "description": "File to upload for malware analysis",
                            },
                            "parent_job_id": {
                                "type": "string",
                                "description": "Optional parent job ID",
                            },
                        },
                        "required": ["file"],
                    }
                }
            }
        }
    },
)
async def upload_file(request: Request, db: AsyncSession = Depends(get_db)) -> UploadResponse:
    """
    Upload a file for malware analysis.

    - Uses streaming to handle large files efficiently
    - Calculates SHA256 hash incrementally
    - Stores file in MinIO
    - Creates file and job records in database
    - Publishes job to RabbitMQ
    - Returns job_id immediately (async processing)
    """
    try:
        # Parse multipart form
        form = await request.form()
        file = form.get("file")
        parent_job_id_str = form.get("parent_job_id")

        if file is None or isinstance(file, str):
            raise HTTPException(
                status_code=422,
                detail="No file field in form data or field is not a file",
            )

        # Validate parent_job_id if provided
        parent_job = None
        new_depth = 0
        if parent_job_id_str and isinstance(parent_job_id_str, str):
            try:
                parent_job_uuid = uuid.UUID(parent_job_id_str)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail="Invalid parent_job_id format"
                ) from None

            stmt = select(Job).where(Job.id == parent_job_uuid)
            result = await db.execute(stmt)
            parent_job = result.scalar_one_or_none()

            if not parent_job:
                raise HTTPException(status_code=400, detail="Parent job not found")

            max_depth = getattr(settings, "max_job_depth", 3)
            if parent_job.depth >= max_depth:
                raise HTTPException(
                    status_code=400,
                    detail=f"Maximum recursion depth ({max_depth}) reached",
                )

            new_depth = parent_job.depth + 1

        filename = getattr(file, "filename", "unknown")
        filename = _sanitize_filename(filename)
        content_type = getattr(file, "content_type", "application/octet-stream")

        log.info(
            "file_upload_started",
            filename=filename,
            content_type=content_type,
        )

        # Process file using streaming
        hasher = hashlib.sha256()
        file_size = 0

        # Create a temporary file to hold the upload
        fd, temp_path = tempfile.mkstemp()

        try:
            with os.fdopen(fd, "wb") as temp_file:
                while True:
                    chunk = await file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    file_size += len(chunk)

                    # Check size limit dynamically to avoid writing huge files
                    if file_size > settings.max_file_size:
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": {
                                    "code": "FILE_TOO_LARGE",
                                    "message": "File size exceeds limit",
                                    "details": {
                                        "max_size_bytes": settings.max_file_size,
                                        "actual_size_bytes": file_size,
                                    },
                                }
                            },
                        )

                    hasher.update(chunk)
                    temp_file.write(chunk)

            sha256_hash = hasher.hexdigest()

            # Store file in MinIO (use SHA256 as storage key)
            try:
                await upload_to_minio(temp_path, sha256_hash, content_type)
            except Exception as e:
                log.error("minio_upload_failed", sha256=sha256_hash, error=str(e))
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": {
                            "code": "STORAGE_ERROR",
                            "message": f"Failed to store file: {e}",
                        }
                    },
                ) from e

        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # Check for existing file by SHA256 (deduplication)
        file_stmt = select(File).where(File.sha256 == sha256_hash)
        file_result = await db.execute(file_stmt)
        existing_file = file_result.scalar_one_or_none()

        if existing_file:
            file_record = existing_file
            log.info("file_exists", file_id=str(file_record.id), sha256=sha256_hash)
        else:
            # Create new file record
            file_record = File(
                sha256=sha256_hash,
                size=file_size,
                filename=filename,
                content_type=content_type,
            )
            db.add(file_record)
            await db.flush()  # Get the file ID
            log.info("file_created", file_id=str(file_record.id), sha256=sha256_hash)

        # Create job record
        job_record = Job(
            file_id=file_record.id,
            status=JobStatus.QUEUED.value,
            stages_total=settings.stages_total,
            parent_job_id=parent_job.id if parent_job else None,
            depth=new_depth,
        )
        db.add(job_record)
        await db.commit()

        log.info(
            "job_created",
            job_id=str(job_record.id),
            file_id=str(file_record.id),
            sha256=sha256_hash,
            size=file_size,
            filename=filename,
        )

        # Publish job to RabbitMQ
        job_message = {
            "job_id": str(job_record.id),
            "file_id": str(file_record.id),
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
        }
        try:
            await publish_job(job_message)
        except Exception as e:
            log.error("rabbitmq_publish_failed", job_id=str(job_record.id), error=str(e))
            # Mark job as failed so it won't be stuck in QUEUED forever
            job_record.status = JobStatus.FAILED.value
            job_record.error_message = f"Failed to publish to queue: {e}"
            await db.commit()
            raise HTTPException(
                status_code=503,
                detail={
                    "error": {
                        "code": "QUEUE_PUBLISH_FAILED",
                        "message": "Failed to submit job to processing queue. Please try again.",
                        "job_id": str(job_record.id),
                    }
                },
            ) from e

        return UploadResponse(
            job_id=str(job_record.id),
            file_id=str(file_record.id),
            sha256=sha256_hash,
            status="queued",
            created_at=job_record.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        log.error("file_upload_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e),
                }
            },
        ) from e


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str, db: AsyncSession = Depends(get_db)) -> JobStatusResponse:
    """
    Get the status of a job.

    Returns current stage, progress, and any error message.
    """
    log.info("job_status_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Query job from database
    stmt = select(Job).where(Job.id == job_uuid)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # Calculate progress percent
    percent = int((job.stages_done / job.stages_total) * 100) if job.stages_total > 0 else 0

    return JobStatusResponse(
        job_id=str(job.id),
        parent_job_id=str(job.parent_job_id) if job.parent_job_id else None,
        depth=job.depth,
        status=_response_job_status(job.status),
        password_attempts=job.password_attempts,
        password_attempts_remaining=max(0, 3 - job.password_attempts),
        progress=JobProgress(
            current_stage=job.current_stage,
            stages_done=job.stages_done,
            stages_total=job.stages_total,
            percent=percent,
        ),
        updated_at=job.updated_at,
        error_message=job.error_message,
        total_sub=job.total_sub,
        completed_sub=job.completed_sub,
        malicious_sub=job.malicious_sub,
        report_available=isinstance(job.result, dict),
    )


async def _password_retry_context(job: Job, file_sha256: str, db: AsyncSession) -> dict[str, Any]:
    """Recover retry provenance from trusted database links, never request fields."""
    root_job_id = job.id
    ancestor_hashes: set[str] = set()
    visited_jobs = {job.id}
    parent_id = job.parent_job_id
    while parent_id is not None:
        if parent_id in visited_jobs or len(visited_jobs) >= 128:
            raise HTTPException(status_code=409, detail="Job lineage is inconsistent")
        visited_jobs.add(parent_id)
        parent_result = await db.execute(
            select(Job).where(Job.id == parent_id).options(joinedload(Job.file))
        )
        parent = parent_result.scalar_one_or_none()
        if parent is None:
            raise HTTPException(status_code=409, detail="Job lineage is unavailable")
        root_job_id = parent.id
        if parent.file and isinstance(parent.file.sha256, str):
            ancestor_hashes.add(parent.file.sha256)
        parent_id = parent.parent_job_id

    artifact_stmt = select(Artifact).where(
        Artifact.job_id == job.id, Artifact.sha256 == file_sha256
    )
    if isinstance(job.artifact_id, uuid.UUID):
        artifact_stmt = artifact_stmt.where(Artifact.id == job.artifact_id)
    artifact_result = await db.execute(artifact_stmt.order_by(Artifact.created_at).limit(1))
    artifact = artifact_result.scalar_one_or_none()
    context: dict[str, Any] = {
        "root_job_id": str(root_job_id),
        "ancestor_hashes": sorted(ancestor_hashes),
    }
    if artifact is None:
        if isinstance(job.artifact_id, uuid.UUID):
            raise HTTPException(status_code=409, detail="Artifact lineage is unavailable")
        return context
    if artifact.root_job_id is not None and artifact.root_job_id != root_job_id:
        raise HTTPException(status_code=409, detail="Artifact lineage is inconsistent")
    context["artifact_id"] = str(artifact.id)
    context["original_filename"] = artifact.original_filename
    root_artifact = artifact
    visited_artifacts = {artifact.id}
    while root_artifact.parent_id is not None:
        parent_id = root_artifact.parent_id
        if parent_id in visited_artifacts or len(visited_artifacts) >= 128:
            raise HTTPException(status_code=409, detail="Artifact lineage is inconsistent")
        visited_artifacts.add(parent_id)
        parent_artifact_result = await db.execute(select(Artifact).where(Artifact.id == parent_id))
        parent_artifact = parent_artifact_result.scalar_one_or_none()
        if parent_artifact is None:
            raise HTTPException(status_code=409, detail="Artifact lineage is unavailable")
        if parent_artifact.root_job_id not in (None, root_job_id):
            raise HTTPException(status_code=409, detail="Artifact lineage is inconsistent")
        ancestor_hashes.add(parent_artifact.sha256)
        root_artifact = parent_artifact
    if artifact.root_id is not None and artifact.root_id != root_artifact.id:
        raise HTTPException(status_code=409, detail="Artifact root is inconsistent")
    context["root_artifact_id"] = str(root_artifact.id)
    context["ancestor_hashes"] = sorted(ancestor_hashes)
    return context


@router.post("/jobs/{job_id}/password", response_model=PasswordSubmitResponse)
async def submit_job_password(
    job_id: str,
    payload: PasswordSubmitRequest,
    db: AsyncSession = Depends(get_db),
) -> PasswordSubmitResponse:
    """Submit password for a supported password-protected file job and requeue it."""
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    stmt = select(Job).where(Job.id == job_uuid).with_for_update()
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status != JobStatus.PASSWORD_REQUIRED.value:
        raise HTTPException(
            status_code=409,
            detail=f"Job not in password_required status. Current status: {job.status}",
        )

    if job.password_attempts >= 3:
        raise HTTPException(status_code=409, detail="Password attempts exhausted")

    file_stmt = select(File).where(File.id == job.file_id)
    file_result = await db.execute(file_stmt)
    file_obj = file_result.scalar_one_or_none()

    if not file_obj:
        raise HTTPException(status_code=500, detail="Job file metadata not found")

    retry_context = await _password_retry_context(job, file_obj.sha256, db)

    attempts_used = job.password_attempts
    attempts_remaining = max(0, 3 - job.password_attempts)

    try:
        await publish_job(
            {
                "job_id": str(job.id),
                "file_id": str(file_obj.id),
                "storage_key": file_obj.sha256,
                "sha256": file_obj.sha256,
                "original_filename": file_obj.filename,
                "archive_password": payload.password,
                **retry_context,
            }
        )
    except Exception as e:
        log.error("password_submit_publish_failed", job_id=str(job.id), error_type=type(e).__name__)
        raise HTTPException(
            status_code=503,
            detail="Failed to submit password retry job",
        ) from e

    job.status = JobStatus.QUEUED.value
    job.current_stage = None
    job.error_message = None
    await db.commit()

    return PasswordSubmitResponse(
        job_id=str(job.id),
        status=JobStatus.QUEUED.value,
        message="Password accepted. Job requeued for analysis.",
        attempts_used=attempts_used,
        attempts_remaining=attempts_remaining,
    )


@router.get("/jobs/{job_id}/stream")
async def stream_job_status(job_id: str, request: Request) -> EventSourceResponse:
    """
    Stream the status of a job using Server-Sent Events (SSE).
    """
    log.info("job_status_stream_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Check if job exists first
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(Job).where(Job.id == job_uuid)
        result = await session.execute(stmt)
        if result.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        last_updated_at: datetime | None = None
        last_status: str | None = None
        session_factory = get_session_factory()

        try:
            while True:
                # If client disconnected, stop
                if await request.is_disconnected():
                    log.info("client_disconnected", job_id=job_id)
                    break

                # Create a new session per iteration
                async with session_factory() as session:
                    stmt = select(Job).where(Job.id == job_uuid)
                    result = await session.execute(stmt)
                    job = result.scalar_one_or_none()

                    if not job:
                        break

                    # Only yield if something changed
                    if job.updated_at != last_updated_at or job.status != last_status:
                        last_updated_at = job.updated_at
                        last_status = job.status

                        percent = (
                            int((job.stages_done / job.stages_total) * 100)
                            if job.stages_total > 0
                            else 0
                        )

                        data = JobStatusResponse(
                            job_id=str(job.id),
                            parent_job_id=str(job.parent_job_id) if job.parent_job_id else None,
                            depth=job.depth,
                            status=_response_job_status(job.status),
                            password_attempts=job.password_attempts,
                            password_attempts_remaining=max(0, 3 - job.password_attempts),
                            progress=JobProgress(
                                current_stage=job.current_stage,
                                stages_done=job.stages_done,
                                stages_total=job.stages_total,
                                percent=percent,
                            ),
                            updated_at=job.updated_at,
                            error_message=job.error_message,
                            total_sub=job.total_sub,
                            completed_sub=job.completed_sub,
                            malicious_sub=job.malicious_sub,
                            report_available=isinstance(job.result, dict),
                        )

                        yield {"event": "message", "data": data.model_dump_json()}

                        # Stop if job is done or failed
                        if job.status in (JobStatus.DONE.value, JobStatus.FAILED.value):
                            break

                # Sleep a bit before checking again to avoid hammering the DB
                await asyncio.sleep(1.0)

        except asyncio.CancelledError:
            log.info("client_disconnected_via_cancel", job_id=job_id)

    return EventSourceResponse(event_generator())


async def _build_artifact_tree(
    root_job_id: str,
    db: AsyncSession,
    reports_by_artifact: dict[str, dict[str, Any]] | None = None,
) -> JsonObject | None:
    """Build hierarchical artifact tree from flat records."""
    from uuid import UUID

    stmt = (
        select(Artifact)
        .where(Artifact.root_job_id == UUID(root_job_id))
        .options(joinedload(Artifact.job))
        .order_by(Artifact.depth, Artifact.created_at)
    )
    result = await db.execute(stmt)
    artifacts = result.scalars().all()

    if not artifacts:
        return None

    nodes: dict[str, JsonObject] = {}
    if reports_by_artifact is None:
        reports_by_artifact = {}
    root: JsonObject | None = None
    extra_roots: list[JsonObject] = []
    for art in artifacts:
        linked_job = art.job
        linked_status = getattr(linked_job, "status", None)
        linked_status = linked_status if isinstance(linked_status, str) else None
        linked_report = getattr(linked_job, "result", None)
        linked_report = linked_report if isinstance(linked_report, dict) else {}
        analysis = analysis_from_report(linked_report, linked_status)
        reports_by_artifact[str(art.id)] = linked_report
        root_artifact_id = getattr(art, "root_id", None)
        root_artifact_id = (
            str(root_artifact_id)
            if isinstance(root_artifact_id, (UUID, str))
            else str(art.id)
            if art.depth == 0
            else None
        )
        node: JsonObject = {
            "id": str(art.id),
            "root_artifact_id": root_artifact_id,
            "root_job_id": root_job_id,
            "filename": art.original_filename,
            "sha256": art.sha256,
            "mime": art.mime,
            "size": art.size,
            "depth": art.depth,
            "origin_path": art.origin_path,
            "extraction_source": art.extraction_source,
            "archive_type": art.archive_type,
            "extraction_note": art.extraction_note,
            "verdict": art.verdict,
            "score": art.score,
            "risk_level": art.risk_level,
            "policy_version": art.policy_version,
            "job_id": str(art.job_id) if art.job_id else None,
            "job_status": linked_status,
            "analysis_status": analysis["static"]["status"],
            "analysis": analysis,
            "synthetic_root": False,
            "children": [],
        }
        nodes[str(art.id)] = node
        if art.parent_id and str(art.parent_id) in nodes:
            children = nodes[str(art.parent_id)]["children"]
            assert isinstance(children, list)
            children.append(node)
        if art.depth == 0:
            if root is None:
                root = node
            else:
                node["synthetic_root"] = True
                extra_roots.append(node)

    if root is not None and extra_roots:
        children = root["children"]
        assert isinstance(children, list)
        children.extend(extra_roots)

    if root is not None:
        resolve_artifact_analysis_references(root, reports_by_artifact)
    return root


def _apply_tree_risk_rollup(
    report: dict[str, Any],
    artifact_tree: dict[str, Any] | None,
) -> dict[str, Any]:
    """Apply canonical descendant rollup to a stored local-risk report."""
    report = _ensure_report_risk_shape(report)
    risk = report.get("risk")
    if not artifact_tree or not isinstance(risk, dict):
        return report

    breakdown = risk.get("breakdown")
    if not isinstance(breakdown, dict):
        return report

    local = RiskDecision(
        risk_score=int(risk.get("risk_score") or 0),
        risk_level=str(risk.get("risk_level") or "clean"),
        legacy_verdict=str(risk.get("legacy_verdict") or report.get("verdict") or "clean"),
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(
            local_score=int(breakdown.get("local_score") or 0),
            inherited_score=int(breakdown.get("inherited_score") or 0),
            synergy_bonus=int(breakdown.get("synergy_bonus") or 0),
            dampener=int(breakdown.get("dampener") or 0),
            final_score=int(breakdown.get("final_score") or 0),
            malicious_gate_open=bool(risk.get("malicious_gate_open", False)),
            high_gate_open=bool(risk.get("high_gate_open", False)),
            independent_source_count=int(risk.get("independent_source_count") or 0),
        ),
        policy_version=str(risk.get("policy_version") or POLICY_VERSION),
        score_trace=deepcopy(risk.get("score_trace") or {}),
    )

    descendants: list[dict[str, Any]] = []
    root_depth = int(artifact_tree.get("depth") or 0)

    def _collect(node: dict[str, Any]) -> None:
        for child in node.get("children", []):
            if child.get("synthetic_root"):
                continue
            if not child.get("synthetic_root"):
                descendants.append(
                    {
                        "artifact_id": child["id"],
                        "sha256": child["sha256"],
                        "relative_depth": max(1, int(child.get("depth") or 0) - root_depth),
                        "risk_level": _artifact_level(child),
                        "risk_score": int(child.get("score") or 0),
                        "origin_path": child.get("origin_path"),
                        "verdict": child.get("verdict"),
                        "extraction_note": child.get("extraction_note"),
                        "size": child.get("size"),
                        "job_status": child.get("job_status"),
                        "job_id": child.get("job_id"),
                        "analysis_status": child.get("analysis_status"),
                        "analysis_reference": child.get("analysis_reference"),
                        "display_path": child.get("display_path")
                        or child.get("origin_path")
                        or child.get("filename"),
                    }
                )
            _collect(child)

    _collect(artifact_tree)
    final = merge_with_descendants(local=local, descendants=descendants)

    report["score"] = final.risk_score
    report["verdict"] = final.legacy_verdict
    report["risk_level"] = final.risk_level
    risk["risk_score"] = final.risk_score
    risk["risk_level"] = final.risk_level
    risk["legacy_verdict"] = final.legacy_verdict
    risk["malicious_gate_open"] = final.breakdown.malicious_gate_open
    risk["high_gate_open"] = final.breakdown.high_gate_open
    risk["independent_source_count"] = final.breakdown.independent_source_count
    breakdown["inherited_score"] = final.breakdown.inherited_score
    breakdown["final_score"] = final.breakdown.final_score
    breakdown["malicious_gate_open"] = final.breakdown.malicious_gate_open
    breakdown["high_gate_open"] = final.breakdown.high_gate_open
    breakdown["independent_source_count"] = final.breakdown.independent_source_count
    risk["descendant_summary"] = final.descendant_summary
    risk["score_trace"] = final.score_trace
    artifact_tree["score"] = final.risk_score
    artifact_tree["verdict"] = final.legacy_verdict
    artifact_tree["risk_level"] = final.risk_level
    artifact_tree["policy_version"] = final.policy_version
    return report


async def _count_pending_descendants(root_job_id: str, db: AsyncSession) -> int:
    """Count descendant jobs that are not in terminal status."""
    from uuid import UUID

    stmt = text(
        """
        WITH RECURSIVE descendants AS (
            SELECT id, status
            FROM jobs
            WHERE parent_job_id = :root_job_id
            UNION ALL
            SELECT j.id, j.status
            FROM jobs j
            JOIN descendants d ON j.parent_job_id = d.id
        )
        SELECT COUNT(*) AS pending_count
        FROM descendants
        WHERE status NOT IN ('done', 'failed')
        """
    )
    result = await db.execute(stmt, {"root_job_id": UUID(root_job_id)})
    return int(result.scalar() or 0)


async def _refresh_report_budget(report: dict[str, Any], job: Job, db: AsyncSession) -> None:
    """Overlay durable tree totals, preserving this report's static attempt deadline."""
    snapshot = report.get("execution_budget")
    if not isinstance(snapshot, dict):
        return
    lineage = (
        select(Job.id, Job.parent_job_id)
        .where(Job.id == job.id)
        .cte("budget_lineage", recursive=True)
    )
    # UNION bounds a corrupt cyclic lineage rather than recursing forever.
    lineage = lineage.union(
        select(Job.id, Job.parent_job_id).join(lineage, Job.id == lineage.c.parent_job_id)
    )
    result = await db.execute(
        select(AnalysisBudget)
        .join(lineage, AnalysisBudget.root_job_id == lineage.c.id)
        .where(lineage.c.parent_job_id.is_(None))
    )
    budget = result.scalar_one_or_none()
    if budget is None:
        return
    snapshot.update(
        limits={
            "max_files": budget.max_files,
            "max_bytes": budget.max_bytes,
            "timeout_seconds": budget.timeout_seconds,
        },
        used_files=budget.used_files,
        used_bytes=budget.used_bytes,
        accounting_scope="root_artifact_tree",
        accounting_source="durable_root_budget",
        # A root can finish before descendants spend their shared allocation.
        # Its previous deadline must not become a fresh descendant time window.
        deadline_active=job.status == JobStatus.SCANNING.value
        and job.current_stage not in {"sandbox", "sandbox_pending"},
    )


@router.get("/reports/{job_id}", response_model=ReportResponse)
async def get_report(job_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """
    Get the available report, including partial static results while work continues.

    Execution completion and coverage are reported separately from risk.
    """
    log.info("report_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Query job from database including its file and sub-jobs
    stmt = (
        select(Job)
        .where(Job.id == job_uuid)
        .options(joinedload(Job.file), joinedload(Job.sub_jobs).joinedload(Job.file))
    )
    result = await db.execute(stmt)
    job = result.unique().scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # A stored report is useful even while awaiting a password, descendants,
    # or the independent sandbox worker. No report yet remains a 404.
    if not isinstance(job.result, dict):
        raise HTTPException(status_code=404, detail="Report not available yet")

    pending_descendants = await _count_pending_descendants(str(job.id), db)

    # Format child jobs summary
    child_jobs = []
    for sub in job.sub_jobs:
        # We need to get verdict from sub.result if it exists
        sub_verdict = "unknown"
        if sub.result and isinstance(sub.result, dict):
            sub_verdict = sub.result.get("verdict", "unknown")

        child_jobs.append(
            {
                "job_id": str(sub.id),
                "filename": sub.file.filename if sub.file else "unknown",
                "sha256": sub.file.sha256 if sub.file else "unknown",
                "status": sub.status,
                "verdict": sub_verdict,
                "password_attempts": sub.password_attempts
                if isinstance(sub.password_attempts, int)
                else 0,
                "password_attempts_remaining": max(0, 3 - sub.password_attempts)
                if isinstance(sub.password_attempts, int)
                else 3,
            }
        )

    # Return stored result with created_at and child_jobs
    report = _public_report_value(deepcopy(job.result))
    report["job_status"] = job.status
    report["pending_descendants"] = pending_descendants
    report["analysis"] = analysis_from_report(report, job.status)
    report["report_complete"] = (
        job.status in {JobStatus.DONE.value, JobStatus.FAILED.value}
        and pending_descendants == 0
        and report["analysis"]["dynamic"]["status"] not in {"queued", "running"}
    )
    report = _ensure_report_risk_shape(report)
    report = _ensure_report_results_shape(report)
    report = _ensure_report_explainability_shape(report)
    report["created_at"] = job.created_at.isoformat()
    report["parent_job_id"] = str(job.parent_job_id) if job.parent_job_id else None
    report["child_jobs"] = child_jobs

    # Build artifact tree (returns None for non-archive files)
    artifact_reports: dict[str, dict[str, Any]] = {}
    report["artifact_tree"] = await _build_artifact_tree(str(job.id), db, artifact_reports)
    report = _apply_tree_risk_rollup(report, report["artifact_tree"])
    report["artifact_tree"] = ensure_artifact_tree_root(report, report["artifact_tree"])
    descendant_statuses: list[str] = []

    def collect_coverage(node: dict[str, Any]) -> None:
        for child in node.get("children", []):
            descendant_statuses.append(str(child.get("analysis_status") or "unknown"))
            collect_coverage(child)

    collect_coverage(report["artifact_tree"])
    await _refresh_report_budget(report, job, db)
    report["analysis"]["static"]["status"] = summarize_static_artifacts(
        report["analysis"]["static"]["status"], descendant_statuses
    )
    report["artifact_tree"]["analysis"] = deepcopy(report["analysis"])
    report["artifact_tree"]["analysis_status"] = report["analysis"]["static"]["status"]
    synthesized_explainability = build_explainability(
        report=report,
        artifact_tree=report["artifact_tree"],
        artifact_reports=artifact_reports,
    )
    if _should_preserve_stored_explainability(report):
        report_explainability = report.get("explainability")
        if isinstance(report_explainability, dict):
            synthesized_explainability["summary"] = report_explainability.get(
                "summary", synthesized_explainability["summary"]
            )
            synthesized_explainability["failure_diagnostics"] = report_explainability.get(
                "failure_diagnostics", synthesized_explainability["failure_diagnostics"]
            )
            synthesized_explainability["timeline"] = report_explainability.get(
                "timeline", synthesized_explainability["timeline"]
            )
    report["explainability"] = synthesized_explainability

    return report
