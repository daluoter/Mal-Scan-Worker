"""Versioned, deployment-independent analysis coverage contract.

Completion describes execution coverage, independently from a malware verdict.
Legacy reports without stage evidence remain unknown rather than claiming success.
Only public stage metadata is copied; findings and credentials are never copied.
"""

from __future__ import annotations

from typing import Any

REPORT_SCHEMA_VERSION = "mswr-report-v3"
ANALYSIS_SCHEMA_VERSION = "mswr-analysis-v1"

STATIC_STATUSES = {
    "complete",
    "partial",
    "running",
    "queued",
    "password_required",
    "failed",
    "unknown",
}
DYNAMIC_STATUSES = STATIC_STATUSES | {
    "disabled",
    "not_requested",
    "unavailable",
    "unsupported",
    "timeout",
    "mock",
}


def stage_coverage(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep recorded stage status and allowlisted public provenance."""
    coverage: list[dict[str, Any]] = []
    for item in stages:
        if not isinstance(item, dict):
            continue
        stage = item.get("stage") or item.get("stage_name") or item.get("name")
        if not isinstance(stage, str) or stage in {"sandbox", "dynamic-analysis"}:
            continue
        entry: dict[str, Any] = {
            "stage": stage,
            "status": str(item.get("status") or "unknown"),
        }
        for field in ("reason", "duration_ms", "tool_version", "rules_version"):
            value = item.get(field)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                entry[field] = value
        coverage.append(entry)
    return coverage


def _static_status(coverage: list[dict[str, Any]], job_status: str | None) -> str:
    statuses = {item["status"] for item in coverage}
    if job_status == "password_required" or "password_required" in statuses:
        return "password_required"
    if job_status == "failed":
        return "partial" if coverage else "failed"
    if job_status == "queued":
        return "queued"
    if statuses & {"queued", "pending", "running", "scanning"}:
        return "running"
    if statuses & {
        "error",
        "failed",
        "timeout",
        "unavailable",
        "unsupported",
        "blocked",
        "partial",
    }:
        return "partial"
    if "unknown" in statuses or not coverage:
        return "running" if job_status == "scanning" else "unknown"
    if statuses <= {"ok", "complete", "completed", "skipped", "not_applicable"}:
        return "complete"
    return "unknown"


def _dynamic_status(sandbox: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(sandbox, dict):
        return {"status": "unknown"}
    status = sandbox.get("status")
    if sandbox.get("is_mock") or sandbox.get("synthetic") or sandbox.get("provider") == "mock":
        status = "mock"
    elif status not in DYNAMIC_STATUSES:
        if status in {"ok", "completed", "done"}:
            status = "complete"
        elif status in {"pending", "submitted", "deferred"} or sandbox.get("pending"):
            status = "queued"
        elif status == "submitting":
            status = "running"
        elif status == "synthetic":
            status = "mock"
        elif sandbox.get("errors"):
            status = "failed"
        elif sandbox.get("executed") is True:
            status = "complete"
        else:
            status = "unknown"
    if status == "complete" and sandbox.get("executed") is False:
        status = "unavailable"
    result: dict[str, Any] = {"status": status}
    for field in ("provider", "reason"):
        if isinstance(sandbox.get(field), str):
            result[field] = sandbox[field]
    return result


def build_analysis(
    *,
    stages: list[dict[str, Any]],
    job_status: str | None = None,
    sandbox: dict[str, Any] | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build separate static and dynamic states from persisted execution evidence."""
    existing = existing if isinstance(existing, dict) else {}
    static = existing.get("static")
    static = static if isinstance(static, dict) else {}
    recorded = static.get("stage_coverage")
    coverage = stage_coverage(recorded if isinstance(recorded, list) else stages)
    limited_skip = any(
        item["status"] == "skipped"
        and any(
            marker in str(item.get("reason") or "").lower()
            for marker in (
                "no yara rules",
                "no rules",
                "disabled",
                "size limit",
                "depth limit",
                "max depth",
                "budget",
                "unavailable",
                "not configured",
                "too large",
            )
        )
        for item in coverage
    )
    status = _static_status(coverage, job_status)
    if status == "complete" and limited_skip:
        status = "partial"
    # Explicit worker state supplies missing execution evidence, but live queue /
    # password / failed transitions must override stale stored completion.
    if status == "unknown" and static.get("status") in STATIC_STATUSES:
        status = static["status"]
    dynamic = _dynamic_status(sandbox)
    saved_dynamic = existing.get("dynamic")
    if (
        dynamic["status"] == "unknown"
        and isinstance(saved_dynamic, dict)
        and saved_dynamic.get("status") in DYNAMIC_STATUSES
    ):
        dynamic = {
            key: value
            for key, value in saved_dynamic.items()
            if key in {"status", "provider", "reason"} and isinstance(value, str)
        }
    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "static": {"status": status, "stage_coverage": coverage},
        "dynamic": dynamic,
    }


def analysis_from_report(report: dict[str, Any], job_status: str | None = None) -> dict[str, Any]:
    """Backfill the additive contract without changing stored findings or scores."""
    timings = report.get("timings")
    timings = timings if isinstance(timings, dict) else {}
    stages = timings.get("stages")
    results = report.get("results")
    results = results if isinstance(results, dict) else {}
    return build_analysis(
        stages=stages if isinstance(stages, list) else [],
        job_status=job_status,
        sandbox=results.get("sandbox"),
        existing=report.get("analysis"),
    )


def summarize_static_artifacts(local_status: str, descendant_statuses: list[str]) -> str:
    """Aggregate tree coverage without altering the root's recorded stage evidence."""
    if not descendant_statuses:
        return local_status
    statuses = {local_status, *descendant_statuses}
    if "password_required" in statuses:
        return "password_required"
    if statuses & {"running", "queued", "pending", "scanning"}:
        return "running"
    if statuses == {"complete"}:
        return "complete"
    if statuses == {"unknown"}:
        return "unknown"
    return "partial"
