"""Pipeline orchestrator for running analysis stages."""

import asyncio
import shutil
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import structlog
from malscan.analysis_contract import REPORT_SCHEMA_VERSION, build_analysis
from malscan.scoring.adapters import build_direct_evidence
from malscan.scoring.engine import score_direct_evidence
from sqlalchemy.ext.asyncio import AsyncSession

from malscan_worker.budget import BudgetLimits, PostgresRootBudget
from malscan_worker.config import get_settings
from malscan_worker.db import (
    StaleAnalysisAttempt,
    _engine,
    ensure_root_artifact,
    get_job_for_context,
    update_artifact_risk,
    update_job_result_strict,
    update_job_stage,
    update_job_status,
)
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
    DocumentPasswordRequiredError,
    DocumentWrongPasswordError,
)
from malscan_worker.metrics import stage_latency
from malscan_worker.sandbox import build_empty_sandbox_result
from malscan_worker.sandbox.providers import ProviderCheckpointError
from malscan_worker.sandbox.publisher import publish_sandbox_job
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.deobfuscation import DeobfuscationStage
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.sandbox import SandboxStage, execute_sandbox_analysis
from malscan_worker.stages.yara_scan import YaraStage
from malscan_worker.storage import download_file

log = structlog.get_logger()
settings = get_settings()


def _public_value(value: Any) -> Any:
    """Serialize findings without copying credentials into a report checkpoint."""
    private_keys = {"archive_password", "password", "api_token", "access_token", "authorization"}
    if isinstance(value, Mapping):
        return {
            str(key): _public_value(item)
            for key, item in value.items()
            if str(key).lower() not in private_keys
        }
    if isinstance(value, (list, tuple)):
        return [_public_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _stage_record(result: StageResult, *, password: str | None = None) -> dict[str, Any]:
    error = result.error
    if error and password:
        error = error.replace(password, "[redacted]")
    findings = _public_value(result.findings)
    return {
        "stage_name": result.stage_name,
        "status": result.status,
        "started_at": result.started_at.isoformat(),
        "ended_at": result.ended_at.isoformat(),
        "duration_ms": result.duration_ms,
        "findings": findings,
        "artifacts": list(result.artifacts),
        "error": error,
        "tool_version": result.tool_version or findings.get("tool_version"),
        "rules_version": result.rules_version or findings.get("rules_version"),
    }


def _stage_timing(result: StageResult) -> dict[str, Any]:
    record = _stage_record(result)
    timing = {
        "name": result.stage_name,
        **{key: record[key] for key in ("status", "duration_ms", "started_at", "ended_at")},
    }
    reason = result.findings.get("reason")
    if reason:
        timing["reason"] = reason
    elif result.error:
        # Public coverage explains the class of failure without exposing raw errors.
        timing["reason"] = "Stage execution failed"
    for key in ("tool_version", "rules_version"):
        if record[key]:
            timing[key] = record[key]
    return timing


def _restore_checkpoint(report: Any, ctx: StageContext) -> list[StageResult]:
    """Restore only completed stages from an exact file/job checkpoint."""
    if not isinstance(report, dict):
        return []
    checkpoint = report.get("pipeline_checkpoint")
    if not isinstance(checkpoint, dict) or checkpoint.get("version") != 1:
        return []
    for key in ("job_id", "file_id", "sha256", "original_filename"):
        if checkpoint.get(key) != getattr(ctx, key):
            return []
    # Reusing a stage that creates artifacts is safe only in its original lineage.
    if checkpoint.get("artifact_id") != ctx.artifact_id:
        return []
    if checkpoint.get("root_artifact_id") != ctx.root_artifact_id:
        return []
    records = report.get("stages")
    if not isinstance(records, list):
        return []
    restored: list[StageResult] = []
    for item in records:
        if not isinstance(item, dict) or item.get("stage_name") == "sandbox":
            continue
        if item.get("status") != "ok" and not (
            item.get("status") == "skipped"
            and item.get("findings", {}).get("reason")
            in {"Not an archive", "Not a supported document", "No supported analyzer"}
        ):
            continue
        try:
            restored.append(
                StageResult(
                    stage_name=item["stage_name"],
                    status=item["status"],
                    started_at=datetime.fromisoformat(item["started_at"]),
                    ended_at=datetime.fromisoformat(item["ended_at"]),
                    duration_ms=int(item["duration_ms"]),
                    findings=deepcopy(item["findings"]),
                    artifacts=list(item["artifacts"]),
                    error=item.get("error"),
                    tool_version=item.get("tool_version"),
                    rules_version=item.get("rules_version"),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return restored


class _PipelineStage(Protocol):
    @property
    def name(self) -> str:
        ...

    async def execute(self, ctx: StageContext) -> StageResult:
        ...


# Stages that can run in parallel (Strictly no database writers here!)
PARALLEL_STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),
    IocExtractStage(),
    DeobfuscationStage(),
]

FORMAT_ANALYSIS_STAGE = FormatAnalysisStage()

# Stages that should run sequentially
# ArchiveExtractStage MUST be here because it writes to the DB,
# and AsyncSession is not concurrency-safe.
# DocumentAnalysisStage also creates sub-jobs for extracted artifacts.
SEQUENTIAL_STAGES = [
    ArchiveExtractStage(),
    DocumentAnalysisStage(),
    SandboxStage(),
]


def _cleanup_temp_dir(job_id: str) -> None:
    """Clean up temporary directory for a job."""
    temp_dir = Path(f"/tmp/{job_id}")
    if temp_dir.exists():
        try:
            shutil.rmtree(temp_dir)
            log.info("temp_dir_cleaned", job_id=job_id, path=str(temp_dir))
        except Exception as e:
            log.warning("temp_dir_cleanup_failed", job_id=job_id, error=str(e))


def _normalize_ioc_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _merge_unique(primary: list[str], secondary: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value in primary + secondary:
        if value and value not in seen:
            seen.add(value)
            merged.append(value)
    return merged


def _prepare_scorer_stage_findings(stage_findings: dict[str, Any]) -> dict[str, Any]:
    scorer_stage_findings = dict(stage_findings)
    if isinstance(scorer_stage_findings.get("ioc-extract"), dict):
        scorer_ioc = dict(scorer_stage_findings["ioc-extract"])
        for key in ("urls", "domains", "ips", "ip_addresses"):
            if scorer_ioc.get(key) is None:
                scorer_ioc[key] = []
        scorer_stage_findings["ioc-extract"] = scorer_ioc
    if isinstance(scorer_stage_findings.get("deobfuscation"), dict):
        scorer_deob = dict(scorer_stage_findings["deobfuscation"])
        extracted_iocs = scorer_deob.get("extracted_iocs")
        if isinstance(extracted_iocs, dict):
            scorer_deob_iocs = dict(extracted_iocs)
            for key in ("urls", "domains", "ips", "ip_addresses"):
                if scorer_deob_iocs.get(key) is None:
                    scorer_deob_iocs[key] = []
            scorer_deob["extracted_iocs"] = scorer_deob_iocs
        scorer_stage_findings["deobfuscation"] = scorer_deob
    if isinstance(scorer_stage_findings.get("sandbox"), dict):
        scorer_sandbox = dict(scorer_stage_findings["sandbox"])
        if scorer_sandbox.get("network_connections") is None and isinstance(
            scorer_sandbox.get("tcp_udp"), list
        ):
            scorer_sandbox["network_connections"] = list(scorer_sandbox["tcp_udp"])
        scorer_stage_findings["sandbox"] = scorer_sandbox
    return scorer_stage_findings


def _serialize_evidence_entry(entry: Any) -> dict[str, Any]:
    return {
        "id": entry.evidence_id,
        "source": entry.source,
        "kind": entry.kind,
        "tier": entry.tier,
        "severity": entry.severity,
        "confidence": entry.confidence,
        "points": entry.points,
        "scope": entry.scope,
        "depth": entry.depth,
        "artifact_id": entry.artifact_id,
        "related_artifact_id": entry.related_artifact_id,
        "stage": entry.stage,
        "analyzer": entry.analyzer,
        "reason": entry.reason,
        "raw": dict(entry.raw),
        "finding_ids": [],
        "ioc_ids": [],
        "decoded_ids": [],
        "score_contribution": dict(entry.score_contribution),
    }


def _build_risk_summary(
    *,
    stage_findings: dict[str, Any],
    artifact_id: str | None,
) -> tuple[Any, dict[str, Any]]:
    scorer_stage_findings = _prepare_scorer_stage_findings(stage_findings)
    direct_evidence = build_direct_evidence(
        artifact_id=artifact_id,
        stage_findings=scorer_stage_findings,
    )
    decision = score_direct_evidence(direct_evidence=direct_evidence)
    risk = {
        "policy_version": decision.policy_version,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "legacy_verdict": decision.legacy_verdict,
        "malicious_gate_open": decision.breakdown.malicious_gate_open,
        "high_gate_open": decision.breakdown.high_gate_open,
        "independent_source_count": decision.breakdown.independent_source_count,
        "breakdown": {
            "local_score": decision.breakdown.local_score,
            "inherited_score": decision.breakdown.inherited_score,
            "synergy_bonus": decision.breakdown.synergy_bonus,
            "dampener": decision.breakdown.dampener,
            "final_score": decision.breakdown.final_score,
        },
        "evidence": [_serialize_evidence_entry(entry) for entry in decision.evidence],
        "top_evidence": [_serialize_evidence_entry(entry) for entry in decision.top_evidence],
        "descendant_summary": {},
        "score_trace": dict(decision.score_trace),
    }
    return decision, risk


def _extract_stage_findings_from_report(report: dict[str, Any]) -> dict[str, Any]:
    results_value = report.get("results")
    results = results_value if isinstance(results_value, dict) else {}
    iocs_value = results.get("iocs")
    iocs = iocs_value if isinstance(iocs_value, dict) else {}
    hashes_value = iocs.get("hashes")
    hashes = hashes_value if isinstance(hashes_value, dict) else {}
    file_value = report.get("file")
    file_info = file_value if isinstance(file_value, dict) else {}
    findings: dict[str, Any] = {}

    av_result = results.get("av_result")
    if isinstance(av_result, dict):
        findings["clamav"] = {
            "infected": bool(av_result.get("infected", False)),
            "threat_name": av_result.get("threat_name"),
            "result": av_result.get("threat_name"),
        }

    yara_hits = results.get("yara_hits")
    if isinstance(yara_hits, list):
        findings["yara"] = {"matches": yara_hits}

    if isinstance(iocs, dict):
        findings["ioc-extract"] = {
            "urls": list(iocs.get("urls") or []),
            "domains": list(iocs.get("domains") or []),
            "ips": list(iocs.get("ips") or []),
            "ip_addresses": list(iocs.get("ips") or []),
            "ioc_items": list(iocs.get("ioc_items") or []),
            "md5": hashes.get("md5", ""),
            "sha1": hashes.get("sha1", ""),
            "sha256": hashes.get("sha256", file_info.get("sha256", "")),
        }

    for key, stage_name in (
        ("format_analysis", "format-analysis"),
        ("deobfuscation", "deobfuscation"),
        ("document_analysis", "document-analysis"),
        ("sandbox", "sandbox"),
        ("archive_extract", "archive-extract"),
    ):
        value = results.get(key)
        if isinstance(value, dict):
            findings[stage_name] = value

    return findings


def _apply_direct_risk_to_report(
    report: dict[str, Any],
    *,
    artifact_id: str | None,
) -> dict[str, Any]:
    decision, risk = _build_risk_summary(
        stage_findings=_extract_stage_findings_from_report(report),
        artifact_id=artifact_id,
    )
    report["verdict"] = decision.legacy_verdict
    report["score"] = decision.risk_score
    report["risk_level"] = decision.risk_level
    report["risk"] = risk
    return report


def _upsert_stage_timing(report: dict[str, Any], stage_timing: dict[str, Any]) -> None:
    timings = report.setdefault("timings", {"total_ms": 0, "stages": []})
    stages = timings.setdefault("stages", [])
    new_duration = int(stage_timing.get("duration_ms", 0) or 0)
    previous_duration = 0
    for index, existing in enumerate(stages):
        if existing.get("name") == stage_timing.get("name"):
            previous_duration = int(existing.get("duration_ms", 0) or 0)
            stages[index] = stage_timing
            break
    else:
        stages.append(stage_timing)
    timings["total_ms"] = max(
        0,
        int(timings.get("total_ms", 0) or 0) - previous_duration + new_duration,
    )


def _is_deferred_sandbox_result(findings: Any) -> bool:
    return isinstance(findings, dict) and str(findings.get("status") or "") == "deferred"


def _should_finalize_after_static_pipeline(results: list[StageResult]) -> bool:
    for result in results:
        if result.stage_name == "sandbox":
            return not _is_deferred_sandbox_result(result.findings)
    return True


def _build_sandbox_job_payload(job_data: dict[str, Any], ctx: StageContext) -> dict[str, Any]:
    return {
        "job_id": job_data["job_id"],
        "file_id": job_data["file_id"],
        "storage_key": job_data.get("storage_key", ""),
        "sha256": job_data.get("sha256", ""),
        "original_filename": job_data.get("original_filename", "unknown"),
        "artifact_id": ctx.artifact_id,
        "root_artifact_id": ctx.root_artifact_id,
        "root_job_id": ctx.root_job_id or ctx.job_id,
        "ancestor_hashes": list(ctx.ancestor_hashes),
        "deferred_stage": "sandbox",
    }


async def finalize_deferred_sandbox_job(job_data: dict[str, Any]) -> dict[str, Any]:
    """Run sandbox detonation and finalize a previously deferred job."""
    settings.require_service_configuration()
    job_id = job_data["job_id"]
    work_dir = Path(f"/tmp/{job_id}-sandbox")
    sandbox_started = datetime.now(timezone.utc)
    file_path: Path | None = None

    try:
        async with AsyncSession(_engine) as session:
            job_instance = await get_job_for_context(job_id, session=session)
            if job_instance is None:
                raise ValueError(f"Job not found: {job_id}")
            stored_result = job_instance.result
            if not isinstance(stored_result, dict):
                raise RuntimeError(f"Partial report not available for job {job_id}")
            artifact_id = job_data.get("artifact_id")
            if artifact_id is None and getattr(job_instance, "artifact_id", None) is not None:
                artifact_id = str(job_instance.artifact_id)

        existing_sandbox = stored_result.get("results", {}).get("sandbox")
        if isinstance(existing_sandbox, dict) and (
            bool(existing_sandbox.get("executed"))
            or existing_sandbox.get("status")
            in {
                "completed",
                "complete",
                "disabled",
                "synthetic",
                "failed",
                "unavailable",
                "unsupported",
            }
        ):
            report = dict(stored_result)
            # A completed provider result may precede a crash before Job.done.
            # Re-persist under this delivery's current server attempt before
            # finalizing; a replaced attempt must stop before touching risk.
            await update_job_result_strict(job_id, report)
            if artifact_id:
                try:
                    await update_artifact_risk(
                        artifact_id=artifact_id,
                        verdict=report["verdict"],
                        score=report["score"],
                        risk_level=report["risk_level"],
                        policy_version=report["risk"]["policy_version"],
                    )
                except StaleAnalysisAttempt:
                    raise
                except Exception:
                    log.exception(
                        "failed_to_update_artifact_risk_after_sandbox_finalize",
                        artifact_id=artifact_id,
                        job_id=job_id,
                    )

            await update_job_status(
                job_id,
                "done",
                current_stage=None,
                stages_done=settings.stages_total,
            )
            return {
                "job_id": job_id,
                "status": "done",
                "verdict": report["verdict"],
                "score": report["score"],
            }

        report = deepcopy(stored_result)
        previous_sandbox = existing_sandbox if isinstance(existing_sandbox, dict) else None
        # Polling a retained task and reconciling an uncertain submission require
        # no re-upload. The source object may already have reached its retention.
        if not previous_sandbox or (
            not previous_sandbox.get("task_id") and previous_sandbox.get("status") != "submitting"
        ):
            file_path = await download_file(job_data.get("storage_key", ""), work_dir)

        async def save_sandbox_checkpoint(state: dict[str, Any]) -> None:
            checkpoint_at = datetime.now(timezone.utc)
            report.setdefault("results", {})["sandbox"] = deepcopy(state)
            stage = StageResult(
                stage_name="sandbox",
                status="running",
                started_at=sandbox_started,
                ended_at=checkpoint_at,
                duration_ms=int((checkpoint_at - sandbox_started).total_seconds() * 1000),
                findings=state,
                artifacts=[],
            )
            report["stages"] = [
                item for item in report.get("stages", []) if item.get("stage_name") != "sandbox"
            ] + [_stage_record(stage)]
            _upsert_stage_timing(report, _stage_timing(stage))
            report["analysis"] = build_analysis(
                stages=report["timings"]["stages"],
                sandbox=state,
            )
            await update_job_result_strict(job_id, report)

        try:
            sandbox_result = await execute_sandbox_analysis(
                file_path=file_path,
                sha256=job_data.get("sha256", ""),
                filename=job_data.get("original_filename", "unknown"),
                previous_result=previous_sandbox,
                on_checkpoint=save_sandbox_checkpoint,
            )
        except ProviderCheckpointError as exc:
            if isinstance(exc.__cause__, StaleAnalysisAttempt):
                raise exc.__cause__ from None
            raise
        sandbox_ended = datetime.now(timezone.utc)

        results = report.setdefault("results", {})
        results["sandbox"] = sandbox_result
        sandbox_status = "ok" if sandbox_result.get("executed") else "failed"
        if sandbox_result.get("status") in {"disabled", "synthetic"}:
            sandbox_status = "skipped"
        report["stages"] = [
            item for item in report.get("stages", []) if item.get("stage_name") != "sandbox"
        ]
        report["stages"].append(
            _stage_record(
                StageResult(
                    stage_name="sandbox",
                    status=sandbox_status,
                    started_at=sandbox_started,
                    ended_at=sandbox_ended,
                    duration_ms=int((sandbox_ended - sandbox_started).total_seconds() * 1000),
                    findings=sandbox_result,
                    artifacts=[],
                )
            )
        )
        _upsert_stage_timing(
            report,
            {
                "name": "sandbox",
                "status": sandbox_status,
                "duration_ms": int((sandbox_ended - sandbox_started).total_seconds() * 1000),
                "started_at": sandbox_started.isoformat(),
                "ended_at": sandbox_ended.isoformat(),
            },
        )
        report["analysis"] = build_analysis(
            stages=report["timings"]["stages"],
            sandbox=sandbox_result,
        )
        report = _apply_direct_risk_to_report(report, artifact_id=artifact_id)

        await update_job_result_strict(job_id, report)

        if artifact_id:
            try:
                await update_artifact_risk(
                    artifact_id=artifact_id,
                    verdict=report["verdict"],
                    score=report["score"],
                    risk_level=report["risk_level"],
                    policy_version=report["risk"]["policy_version"],
                )
            except StaleAnalysisAttempt:
                raise
            except Exception:
                log.exception(
                    "failed_to_update_artifact_risk_after_sandbox_finalize",
                    artifact_id=artifact_id,
                    job_id=job_id,
                )

        await update_job_status(
            job_id,
            "done",
            current_stage=None,
            stages_done=settings.stages_total,
        )
        return {
            "job_id": job_id,
            "status": "done",
            "verdict": report["verdict"],
            "score": report["score"],
        }
    finally:
        _cleanup_temp_dir(f"{job_id}-sandbox")


def _build_analysis_result(
    job_id: str,
    file_id: str,
    ctx: StageContext,
    results: list[StageResult],
    total_ms: int,
) -> dict[str, Any]:
    """Build complete analysis result for storage."""

    # Extract key findings from stage results
    stage_findings = {r.stage_name: _public_value(r.findings) for r in results}
    if not settings.sandbox_enabled and "sandbox" not in stage_findings:
        # Disabled is known profile metadata even before a password-blocked
        # archive reaches the final stage; no execution or stage is invented.
        stage_findings["sandbox"] = build_empty_sandbox_result(status="disabled")

    # Check ClamAV result
    clamav = stage_findings.get("clamav", {})

    # Check YARA result
    yara = stage_findings.get("yara", {})
    yara_matches = yara.get("matches", [])

    # ------------------------------------------------------------------
    # Document analysis scoring
    # ------------------------------------------------------------------
    doc = stage_findings.get("document-analysis", {})
    exploit_indicators = doc.get("exploit_indicators", [])
    macros = doc.get("macros", {})
    embedded_objects = doc.get("embedded_objects", [])
    suspicious_keywords = doc.get("suspicious_keywords", [])

    fmt = stage_findings.get("format-analysis", {})
    fmt_risk_score = int(fmt.get("risk_score", 0) or 0)
    fmt_indicators = fmt.get("indicators", [])

    # Build file info
    filetype = stage_findings.get("file-type", {})
    file_info = {
        "file_id": file_id,
        "sha256": ctx.sha256,
        "mime": filetype.get("mime_type", "application/octet-stream"),
        "size": filetype.get("file_size", 0),
        "original_filename": ctx.original_filename,
    }

    # Build IOC info
    ioc_findings = stage_findings.get("ioc-extract", {})
    deobfuscation = stage_findings.get("deobfuscation", {})
    deob_iocs = deobfuscation.get("extracted_iocs", {}) if isinstance(deobfuscation, dict) else {}

    raw_urls = _normalize_ioc_list(ioc_findings.get("urls"))
    raw_domains = _normalize_ioc_list(ioc_findings.get("domains"))
    raw_ips = _merge_unique(
        _normalize_ioc_list(ioc_findings.get("ip_addresses")),
        _normalize_ioc_list(ioc_findings.get("ips")),
    )

    deob_urls = _normalize_ioc_list(deob_iocs.get("urls"))
    deob_domains = _normalize_ioc_list(deob_iocs.get("domains"))
    deob_ips = _merge_unique(
        _normalize_ioc_list(deob_iocs.get("ips")),
        _normalize_ioc_list(deob_iocs.get("ip_addresses")),
    )

    merged_urls = _merge_unique(raw_urls, deob_urls)
    merged_domains = _merge_unique(raw_domains, deob_domains)
    merged_ips = _merge_unique(raw_ips, deob_ips)

    iocs = {
        "urls": merged_urls,
        "domains": merged_domains,
        "ips": merged_ips,
        "ioc_items": list(ioc_findings.get("ioc_items") or []),
        "hashes": {
            "md5": ioc_findings.get("md5", ""),
            "sha1": ioc_findings.get("sha1", ""),
            "sha256": ctx.sha256,
        },
    }

    # Build document analysis summary for report
    doc_analysis: dict[str, Any] = {}
    if doc:
        doc_analysis = {
            **doc,
            "document_type": doc.get("document_type"),
            "exploit_indicators": exploit_indicators,
            "macros": macros,
            "embedded_objects_count": len(embedded_objects),
            "embedded_objects": embedded_objects[:20],  # cap for report size
            "extracted_artifacts_count": len(doc.get("extracted_artifacts", [])),
            "extracted_artifacts": [
                {
                    "filename": a.get("filename"),
                    "sha256": a.get("sha256"),
                    "size": a.get("size"),
                    "source": a.get("source"),
                }
                for a in doc.get("extracted_artifacts", [])
            ],
            "suspicious_keywords": suspicious_keywords,
            "sub_jobs_created": doc.get("sub_jobs_created", 0),
            "parser_findings": doc.get("parser_findings", [])[:50],
            "errors": doc.get("errors", []),
        }

    # Build timing info
    timings = {
        "total_ms": total_ms,
        "stages": [_stage_timing(result) for result in results],
    }

    artifact_id = getattr(ctx, "artifact_id", None)
    decision, risk = _build_risk_summary(stage_findings=stage_findings, artifact_id=artifact_id)

    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "job_id": job_id,
        "file": file_info,
        "verdict": decision.legacy_verdict,
        "score": decision.risk_score,
        "risk_level": decision.risk_level,
        "risk": risk,
        "results": {
            "av_result": {
                **clamav,
                "engine": "ClamAV",
                "infected": clamav.get("infected", False),
                "threat_name": clamav.get("threat_name"),
            },
            "yara_hits": yara_matches,
            "yara_rule_provenance": stage_findings.get("yara", {}).get("rule_provenance"),
            "iocs": iocs,
            "format_analysis": {
                **fmt,
                "analyzer": fmt.get("analyzer"),
                "format_type": fmt.get("format_type"),
                "risk_score": fmt_risk_score,
                "risk_factors": fmt.get("risk_factors", []),
                "indicators": fmt_indicators,
                "heuristics": fmt.get("heuristics", []),
                "features": fmt.get("features", {}),
            },
            "deobfuscation": deobfuscation,
            "document_analysis": doc_analysis,
            "sandbox": stage_findings.get("sandbox", {}),
            "archive_extract": {
                **stage_findings.get("archive-extract", {}),
                "heuristics": stage_findings.get("archive-extract", {}).get("heuristics", []),
            },
        },
        "timings": timings,
        "stages": [
            _stage_record(result, password=getattr(ctx, "archive_password", None))
            for result in results
        ],
        "analysis": build_analysis(stages=timings["stages"], sandbox=stage_findings.get("sandbox")),
        "pipeline_checkpoint": {
            "version": 1,
            "job_id": job_id,
            "file_id": file_id,
            "sha256": ctx.sha256,
            "original_filename": ctx.original_filename,
            "artifact_id": artifact_id,
            "root_artifact_id": getattr(ctx, "root_artifact_id", None),
            "root_job_id": getattr(ctx, "root_job_id", None),
        },
    }


# Public core entry points are shared by self-hosted and portable runtimes.
build_analysis_result = _build_analysis_result


async def attach_execution_budget(report: dict[str, Any], ctx: StageContext) -> None:
    """Publish limits and measured accounting without internal reservation keys."""
    if ctx.root_budget is None:
        return
    snapshot = (await ctx.root_budget.snapshot()).to_dict()
    report["execution_budget"] = {
        key: snapshot[key]
        for key in (
            "limits",
            "used_files",
            "used_bytes",
            "deadline_at",
            "time_scope",
            "accounting_scope",
        )
    }


async def execute_analysis_stages(
    ctx: StageContext,
    *,
    initial_results: list[StageResult] | None = None,
    on_progress: Callable[[str, int], Awaitable[None]] | None = None,
    on_checkpoint: Callable[[list[StageResult]], Awaitable[None]] | None = None,
    parallel_stages: list[_PipelineStage] | None = None,
    format_stage: _PipelineStage | None = None,
    sequential_stages: list[_PipelineStage] | None = None,
) -> list[StageResult]:
    """Execute the analysis core; storage, progress and checkpointing use ports.

    Only completed, validated checkpoint results should be supplied by callers.
    Artifact-writing stages run sequentially and are checkpointed immediately.
    Password blocking preserves completed results before propagating its exception.
    """
    parallel = PARALLEL_STAGES if parallel_stages is None else parallel_stages
    sequential = SEQUENTIAL_STAGES if sequential_stages is None else sequential_stages
    formatter = format_stage or FORMAT_ANALYSIS_STAGE
    restored = {result.stage_name: result for result in initial_results or []}
    results: list[StageResult] = []
    ctx.previous_results = []

    async def checkpoint() -> None:
        if on_checkpoint:
            await on_checkpoint(list(results))

    async def check_budget() -> None:
        if ctx.root_budget:
            await ctx.root_budget.check_deadline()

    await check_budget()
    if on_progress:
        await on_progress("static_analysis", 0)
    missing = [stage for stage in parallel if stage.name not in restored]
    executed = await asyncio.gather(*[_run_stage(stage, ctx) for stage in missing])
    by_name = {result.stage_name: result for result in executed}
    for stage in parallel:
        results.append(restored.get(stage.name) or by_name[stage.name])
    ctx.previous_results.extend(results)
    await checkpoint()

    for stage in [formatter, *sequential]:
        await check_budget()
        if stage is not formatter and on_progress and stage is sequential[0]:
            await on_progress("recursive_analysis", len(results))
        result = restored.get(stage.name)
        if result is None:
            try:
                result = await _run_stage(stage, ctx)
            except (ArchivePasswordRequiredError, ArchiveWrongPasswordError) as exc:
                document_password = isinstance(
                    exc, (DocumentPasswordRequiredError, DocumentWrongPasswordError)
                )
                wrong_password = isinstance(exc, ArchiveWrongPasswordError)
                kind = "PDF" if document_password else "Archive"
                findings: dict[str, Any] = {
                    "reason": f"{kind} password was rejected"
                    if wrong_password
                    else f"{kind} password is required"
                }
                if document_password:
                    # Persist only the class of the password block. Exception
                    # text, the credential and decrypted bytes never belong in
                    # a stage checkpoint; the existing per-artifact transport
                    # supplies the password again for a later attempt.
                    findings.update(
                        analyzer="pdf",
                        format_type="PDF",
                        features={
                            "encrypted": True,
                            "content_access": "wrong_password"
                            if wrong_password
                            else "password_required",
                        },
                        password_kind="pdf",
                    )
                now = datetime.now(timezone.utc)
                blocked = StageResult(
                    stage_name=stage.name,
                    status="password_required",
                    started_at=now,
                    ended_at=now,
                    duration_ms=0,
                    findings=findings,
                    artifacts=[],
                )
                results.append(blocked)
                ctx.previous_results.append(blocked)
                await checkpoint()
                exc.completed_results = list(results)
                raise
        results.append(result)
        ctx.previous_results.append(result)
        await checkpoint()
    if not sequential and on_progress:
        await on_progress("recursive_analysis", len(results))
    return results


async def _run_stage(stage: _PipelineStage, ctx: StageContext) -> StageResult:
    """Run a single stage with error handling and timeout."""
    stage_name = stage.name
    job_id = ctx.job_id

    log.info("stage_starting", job_id=job_id, stage=stage_name)
    start_time = datetime.now(timezone.utc)

    try:
        # Run stage with timeout
        timeout = getattr(settings, "stage_timeout_seconds", 300)

        result = await asyncio.wait_for(
            stage.execute(ctx),
            timeout=timeout,
        )

        # Record metrics
        stage_latency.labels(stage=stage_name, status=result.status).observe(
            result.duration_ms / 1000
        )

        log.info(
            "stage_completed",
            job_id=job_id,
            stage=stage_name,
            status=result.status,
            duration_ms=result.duration_ms,
        )
        return result

    except asyncio.TimeoutError:
        log.error("stage_timeout", job_id=job_id, stage=stage_name)
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=f"Stage timeout after {timeout}s",
        )
    except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
        raise
    except Exception as e:
        log.error("stage_error", job_id=job_id, stage=stage_name, error=str(e), exc_info=True)
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=str(e),
        )


async def run_pipeline(job_data: dict[str, Any]) -> dict[str, Any]:
    """Run the analysis pipeline with high resilience."""
    settings.require_service_configuration()
    job_id = job_data["job_id"]
    file_id = job_data["file_id"]
    storage_key = job_data.get("storage_key", "")

    total_stages = len(PARALLEL_STAGES) + 1 + len(SEQUENTIAL_STAGES)

    log.info(
        "pipeline_started",
        job_id=job_id,
        file_id=file_id,
        storage_key=storage_key,
        stages_total=total_stages,
    )

    # Create work directory
    work_dir = Path(f"/tmp/{job_id}")

    try:
        # Download file from MinIO
        try:
            file_path = await download_file(storage_key, work_dir)
            log.info("file_downloaded", job_id=job_id, file_path=str(file_path))
        except Exception as e:
            log.error("file_download_failed", job_id=job_id, storage_key=storage_key, error=str(e))
            await update_job_status(job_id, "failed", error_message=f"Failed to download file: {e}")
            raise RuntimeError(f"Failed to download file from MinIO: {e}") from e

        results: list[StageResult] = []
        total_start = datetime.now(timezone.utc)

        # Create context inside a single DB session that spans the entire pipeline.
        async with AsyncSession(_engine) as session:
            # Fetch job instance INSIDE the session
            job_instance = await get_job_for_context(job_id, session=session)

            ctx = StageContext(
                job_id=job_id,
                file_id=file_id,
                storage_key=storage_key,
                sha256=job_data.get("sha256", ""),
                original_filename=job_data.get("original_filename", "unknown"),
                file_path=file_path,
                archive_password=job_data.get("archive_password"),
                previous_results=[],
                job=job_instance,
                db=session,
                artifact_id=job_data.get("artifact_id"),
                root_artifact_id=job_data.get("root_artifact_id"),
                root_job_id=job_data.get("root_job_id") or job_id,
                ancestor_hashes=set(job_data.get("ancestor_hashes", [])),
            )

            root_artifact = await ensure_root_artifact(
                job_id=job_id,
                root_job_id=ctx.root_job_id or job_id,
                sha256=ctx.sha256,
                size=file_path.stat().st_size,
                original_filename=ctx.original_filename,
                existing_artifact_id=ctx.root_artifact_id or ctx.artifact_id,
            )
            ctx.root_artifact_id = root_artifact["root_id"]
            ctx.artifact_id = ctx.artifact_id or root_artifact["id"]
            ctx.depth = int(getattr(job_instance, "depth", 0) or 0)
            if job_instance is not None:
                ctx.root_budget = await PostgresRootBudget.initialize(
                    _engine,
                    ctx.root_job_id or job_id,
                    BudgetLimits(
                        max_files=settings.root_budget_max_files,
                        max_bytes=settings.root_budget_max_bytes,
                        timeout_seconds=settings.root_budget_timeout_seconds,
                    ),
                )
            previous = getattr(job_instance, "result", None)
            resumed = _restore_checkpoint(previous, ctx)
            planned = [*PARALLEL_STAGES, FORMAT_ANALYSIS_STAGE, *SEQUENTIAL_STAGES]
            latest_checkpoint: dict[str, Any] | None = None

            async def save_checkpoint(completed: list[StageResult]) -> None:
                nonlocal latest_checkpoint
                completed_names = {result.stage_name for result in completed}
                checkpoint_results = list(completed)
                now = datetime.now(timezone.utc)
                for stage in planned:
                    if stage.name not in completed_names:
                        checkpoint_results.append(
                            StageResult(
                                stage_name=stage.name,
                                status="pending",
                                started_at=now,
                                ended_at=now,
                                duration_ms=0,
                                findings={"status": "not_requested"}
                                if stage.name == "sandbox"
                                else {},
                                artifacts=[],
                            )
                        )
                report = _build_analysis_result(
                    job_id,
                    file_id,
                    ctx,
                    checkpoint_results,
                    int((now - total_start).total_seconds() * 1000),
                )
                await attach_execution_budget(report, ctx)
                await update_job_result_strict(job_id, report)
                latest_checkpoint = report

            try:
                results = await execute_analysis_stages(
                    ctx,
                    initial_results=resumed,
                    on_progress=lambda stage, done: update_job_stage(job_id, stage, done),
                    on_checkpoint=save_checkpoint,
                )
            except (ArchivePasswordRequiredError, ArchiveWrongPasswordError) as exc:
                # Consumers can finalize exhausted attempts without discarding the
                # findings that were persisted immediately before this exception.
                exc.partial_report = latest_checkpoint
                raise

        total_end = datetime.now(timezone.utc)
        total_ms = int((total_end - total_start).total_seconds() * 1000)

        log.info("pipeline_completed_saving_report", job_id=job_id, total_ms=total_ms)

        # Build complete result for storage
        # Even if some stages failed, this will contain what we HAVE.
        analysis_result = _build_analysis_result(
            job_id=job_id,
            file_id=file_id,
            ctx=ctx,
            results=results,
            total_ms=total_ms,
        )
        await attach_execution_budget(analysis_result, ctx)

        should_finalize = _should_finalize_after_static_pipeline(results)
        artifact_id = job_data.get("artifact_id") or getattr(ctx, "artifact_id", None)

        if should_finalize:
            await update_job_result_strict(job_id, analysis_result)
            if artifact_id:
                try:
                    await update_artifact_risk(
                        artifact_id=artifact_id,
                        verdict=analysis_result["verdict"],
                        score=analysis_result["score"],
                        risk_level=analysis_result["risk_level"],
                        policy_version=analysis_result["risk"]["policy_version"],
                    )
                except Exception:
                    log.exception("failed_to_update_artifact_risk", artifact_id=artifact_id)

            await update_job_status(
                job_id,
                "done",
                current_stage=None,
                stages_done=total_stages,
            )
            final_status = "done"
        else:
            await update_job_result_strict(job_id, analysis_result)
            try:
                await publish_sandbox_job(_build_sandbox_job_payload(job_data, ctx))
                if artifact_id:
                    try:
                        await update_artifact_risk(
                            artifact_id=artifact_id,
                            verdict=analysis_result["verdict"],
                            score=analysis_result["score"],
                            risk_level=analysis_result["risk_level"],
                            policy_version=analysis_result["risk"]["policy_version"],
                        )
                    except Exception:
                        log.exception(
                            "failed_to_update_partial_artifact_risk",
                            artifact_id=artifact_id,
                        )
                await update_job_status(
                    job_id,
                    "scanning",
                    current_stage="sandbox_pending",
                    stages_done=total_stages - 1,
                )
                final_status = "scanning"
            except Exception as exc:  # noqa: BLE001
                log.warning("sandbox_publish_failed", job_id=job_id, error_type=type(exc).__name__)
                prior_sandbox = analysis_result.setdefault("results", {}).get("sandbox", {})
                unavailable = {
                    "status": "unavailable",
                    "executed": False,
                    "is_mock": False,
                    "provider": prior_sandbox.get("provider"),
                    "error_code": "sandbox_dispatch_failed",
                    "reason": "Dynamic analysis queue is unavailable",
                    "errors": ["sandbox_dispatch_failed"],
                    "behaviors": [],
                    "network_connections": [],
                }
                analysis_result["results"]["sandbox"] = unavailable
                failed_at = datetime.now(timezone.utc)
                dispatch_failure = StageResult(
                    stage_name="sandbox",
                    status="failed",
                    started_at=failed_at,
                    ended_at=failed_at,
                    duration_ms=0,
                    findings=unavailable,
                    artifacts=[],
                    error="Dynamic analysis queue is unavailable",
                )
                results = [result for result in results if result.stage_name != "sandbox"]
                results.append(dispatch_failure)
                analysis_result["stages"] = [
                    record
                    for record in analysis_result["stages"]
                    if record.get("stage_name") != "sandbox"
                ] + [_stage_record(dispatch_failure)]
                _upsert_stage_timing(analysis_result, _stage_timing(dispatch_failure))
                analysis_result["analysis"] = build_analysis(
                    stages=analysis_result["timings"]["stages"],
                    sandbox=unavailable,
                )
                analysis_result = _apply_direct_risk_to_report(
                    analysis_result,
                    artifact_id=artifact_id,
                )
                await update_job_result_strict(job_id, analysis_result)
                if artifact_id:
                    try:
                        await update_artifact_risk(
                            artifact_id=artifact_id,
                            verdict=analysis_result["verdict"],
                            score=analysis_result["score"],
                            risk_level=analysis_result["risk_level"],
                            policy_version=analysis_result["risk"]["policy_version"],
                        )
                    except Exception:
                        log.exception("failed_to_update_artifact_risk", artifact_id=artifact_id)
                await update_job_status(
                    job_id,
                    "done",
                    current_stage=None,
                    stages_done=total_stages,
                )
                final_status = "done"

        return {
            "job_id": job_id,
            "stages": [r.__dict__ for r in results],
            "total_ms": total_ms,
            "verdict": analysis_result["verdict"],
            "status": final_status,
        }

    finally:
        # Always clean up temp directory
        _cleanup_temp_dir(job_id)
