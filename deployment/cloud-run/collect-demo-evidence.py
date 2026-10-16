#!/usr/bin/env python3
"""Collect sanitized, read-only GCP demo inventory; never estimate an invoice.

Run in an authenticated Cloud Shell. No credentials, environment values,
unstructured log messages, or Secret Manager payloads are read. Optional job
correlation reads only allowlisted structured success-log fields. The report
does not verify R2 object deletion, Cloudflare limits, or actual billed usage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import uuid
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

PROJECT = "malscan-v2-poc"
REGION = "us-central1"
JOB = "malscan-v2-static-demo"
DISPATCHER = "malscan-v2-dispatcher"
REPOSITORY = "malscan-v2-poc"
SECRETS = (
    "malscan-v2-r2-read",
    "malscan-v2-r2-results",
    "malscan-v2-control-hmac",
)
RELEVANT_APIS = {
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudscheduler.googleapis.com",
}
Runner = Callable[[list[str]], dict[str, Any]]


def stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except ValueError:
        return None


def error_category(stderr: str) -> str:
    text = stderr.lower()
    if any(term in text for term in ("permission_denied", "permission denied", "403")):
        return "permission_denied"
    if any(term in text for term in ("not found", "not_found", "404")):
        return "not_found"
    if any(term in text for term in ("unauthenticated", "no active account", "login")):
        return "authentication_required"
    return "gcloud_command_failed"


def run_gcloud(arguments: list[str]) -> dict[str, Any]:
    env = dict(os.environ)
    env.update(
        CLOUDSDK_CORE_LOG_HTTP="false",
        CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
        CLOUDSDK_CORE_DISABLE_PROMPTS="true",
    )
    try:
        result = subprocess.run(
            ["gcloud", *arguments, f"--project={PROJECT}", "--quiet"],
            capture_output=True,
            text=True,
            timeout=45,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        return {"observed": False, "reason": "gcloud_not_installed"}
    except subprocess.TimeoutExpired:
        return {"observed": False, "reason": "read_request_timed_out"}
    if result.returncode:
        # Neither stdout nor stderr is copied to the report or terminal.
        return {"observed": False, "reason": error_category(result.stderr)}
    try:
        return {"observed": True, "data": json.loads(result.stdout)}
    except (ValueError, TypeError):
        return {"observed": False, "reason": "invalid_gcloud_json"}


def conditions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {
            key: item[key]
            for key in ("type", "status", "lastTransitionTime")
            if key in item
        }
        for item in value
        if isinstance(item, dict)
    ]


def containers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    clean = []
    for item in value:
        if not isinstance(item, dict):
            continue
        limits = item.get("resources", {}).get("limits", {})
        clean.append(
            {
                "image": item.get("image"),
                "limits": {
                    key: limits[key] for key in ("cpu", "memory") if key in limits
                },
            }
        )
    return clean


def sanitize_job(data: Any) -> dict[str, Any]:
    spec = data.get("spec", {}).get("template", {}).get("spec", {})
    task = spec.get("template", {}).get("spec", {})
    return {
        "name": data.get("metadata", {}).get("name"),
        "task_count": spec.get("taskCount"),
        "parallelism": spec.get("parallelism"),
        "service_account": task.get("serviceAccountName"),
        "timeout_seconds": task.get("timeoutSeconds"),
        "max_retries": task.get("maxRetries"),
        "containers": containers(task.get("containers")),
        "conditions": conditions(data.get("status", {}).get("conditions")),
    }


def sanitize_dispatcher(data: Any) -> dict[str, Any]:
    template = data.get("spec", {}).get("template", {})
    spec = template.get("spec", {})
    annotations = template.get("metadata", {}).get("annotations", {})
    return {
        "name": data.get("metadata", {}).get("name"),
        "service_account": spec.get("serviceAccountName"),
        "concurrency": spec.get("containerConcurrency"),
        "timeout_seconds": spec.get("timeoutSeconds"),
        "containers": containers(spec.get("containers")),
        "scaling": {
            key: annotations[key]
            for key in (
                "autoscaling.knative.dev/minScale",
                "autoscaling.knative.dev/maxScale",
                "run.googleapis.com/cpu-throttling",
            )
            if key in annotations
        },
        "conditions": conditions(data.get("status", {}).get("conditions")),
    }


def sanitize_repository(rows: Any) -> dict[str, Any]:
    expected = f"projects/{PROJECT}/locations/{REGION}/repositories/{REPOSITORY}"
    if (
        not isinstance(rows, list)
        or len(rows) != 1
        or not isinstance(rows[0], dict)
        or rows[0].get("name") != expected
    ):
        raise ValueError("Expected exactly the configured Artifact Registry repository")
    row = rows[0]
    result = {
        key: row[key]
        for key in ("name", "format", "cleanupPolicies", "cleanupPolicyDryRun")
        if key in row
    }
    size = row.get("sizeBytes")
    result["size_bytes_observed"] = (
        isinstance(size, int) and not isinstance(size, bool) and size >= 0
    ) or (isinstance(size, str) and re.fullmatch(r"[0-9]+", size) is not None)
    if result["size_bytes_observed"]:
        result["sizeBytes"] = size
    return result


def quantity(value: Any, kind: str) -> Decimal | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    text = str(value)
    if kind == "cpu":
        pattern, units = r"(\d+(?:\.\d+)?)(m?)", {"": 1, "m": Decimal("0.001")}
    else:
        pattern = r"(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|T|)?"
        units = {
            "": 1,
            "Ki": 1024,
            "Mi": 1024**2,
            "Gi": 1024**3,
            "Ti": 1024**4,
            "K": 1000,
            "M": 1000**2,
            "G": 1000**3,
            "T": 1000**4,
        }
    match = re.fullmatch(pattern, text)
    if not match:
        return None
    try:
        number = Decimal(match.group(1)) * units[match.group(2) or ""]
        return number if number > 0 else None
    except InvalidOperation:
        return None


def summarize_executions(data: Any, limit: int) -> dict[str, Any]:
    executions = []
    cpu_seconds = Decimal(0)
    gib_seconds = Decimal(0)
    envelopes = 0
    for item in data:
        status, spec = item.get("status", {}), item.get("spec", {})
        start = parse_time(status.get("startTime"))
        end = parse_time(status.get("completionTime"))
        created = parse_time(item.get("metadata", {}).get("creationTimestamp"))
        duration = (
            (end - start).total_seconds() if start and end and end >= start else None
        )
        task_containers = containers(
            spec.get("template", {}).get("spec", {}).get("containers")
        )
        record = {
            "name": item.get("metadata", {}).get("name"),
            "created_at": stamp(created) if created else None,
            "start_time": stamp(start) if start else None,
            "completion_time": stamp(end) if end else None,
            "elapsed_start_to_completion_seconds": duration,
            "elapsed_created_to_completion_seconds": (
                (end - created).total_seconds()
                if end and created and end >= created
                else None
            ),
            "task_count": spec.get("taskCount"),
            "succeeded_count": status.get("succeededCount", 0),
            "failed_count": status.get("failedCount", 0),
            "cancelled_count": status.get("cancelledCount", 0),
            "conditions": conditions(status.get("conditions")),
            "containers": task_containers,
        }
        # Only an execution's own resource snapshot is suitable here. Do not
        # backfill old executions with today's possibly different Job limits.
        tasks = spec.get("taskCount")
        cpus = [quantity(c["limits"].get("cpu"), "cpu") for c in task_containers]
        memories = [
            quantity(c["limits"].get("memory"), "memory") for c in task_containers
        ]
        if (
            duration is not None
            and isinstance(tasks, int)
            and not isinstance(tasks, bool)
            and tasks > 0
            and task_containers
            and all(v is not None for v in cpus + memories)
        ):
            seconds = Decimal(str(duration)) * tasks
            cpu_seconds += seconds * sum(cpus)
            gib_seconds += seconds * sum(memories) / Decimal(1024**3)
            envelopes += 1
        executions.append(record)
    return {
        "returned_count": len(data),
        "possibly_truncated": len(data) >= limit,
        "executions": executions,
        "resource_time_envelope": {
            "included_completed_executions": envelopes,
            "excluded_executions": len(data) - envelopes,
            "vcpu_seconds": float(cpu_seconds) if envelopes or not data else None,
            "gib_seconds": float(gib_seconds) if envelopes or not data else None,
            "coverage": (
                "no_executions"
                if not data
                else "complete"
                if envelopes == len(data)
                else "partial"
                if envelopes
                else "unavailable"
            ),
            "is_billable_usage": False,
            "method": "Execution start-to-completion wall time multiplied by task count and that execution's resource limits. Includes platform waiting; does not model attempts, billing minimums, or service/build usage. Not an invoice or free-tier calculation.",
        },
    }


def validate_job_ids(values: list[str]) -> list[str]:
    if len(values) > 4:
        raise ValueError("Use at most four --job-id arguments")
    for value in values:
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError):
            raise ValueError(
                "Each --job-id must be a canonical lowercase UUID4"
            ) from None
        if (
            str(parsed) != value
            or parsed.version != 4
            or parsed.variant != uuid.RFC_4122
        ):
            raise ValueError("Each --job-id must be a canonical lowercase UUID4")
    return list(dict.fromkeys(values))


def summarize_job_logs(
    rows: Any, job_ids: list[str], limit: int, cutoff: str, observed_at: str
) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise ValueError("Expected structured log list")
    by_root: dict[str, dict[str, Any]] = {
        job_id: {
            "job_id": job_id,
            "successful_entrypoint_log_count": 0,
            "execution_names": set(),
            "dispatch_ids": set(),
            "batch_analysis_statuses": set(),
            "timestamps": [],
            "records_without_execution_name": 0,
        }
        for job_id in job_ids
    }
    ignored = 0
    for row in rows:
        if not isinstance(row, dict):
            ignored += 1
            continue
        payload = row.get("jsonPayload", {})
        if not isinstance(payload, dict):
            ignored += 1
            continue
        root = payload.get("job_id")
        if root not in by_root or payload.get("success") is not True:
            ignored += 1
            continue
        target = by_root[root]
        target["successful_entrypoint_log_count"] += 1
        labels = row.get("labels", {})
        name = (
            labels.get("run.googleapis.com/execution_name")
            if isinstance(labels, dict)
            else None
        )
        if isinstance(name, str) and re.fullmatch(
            rf"{re.escape(JOB)}-[a-z0-9-]+", name
        ):
            target["execution_names"].add(name)
        else:
            target["records_without_execution_name"] += 1
        dispatch_id = payload.get("dispatch_id")
        try:
            if validate_job_ids([dispatch_id]):
                target["dispatch_ids"].add(dispatch_id)
        except ValueError:
            pass
        batch = payload.get("batch_analysis", {})
        status = batch.get("status") if isinstance(batch, dict) else None
        if status in {"complete", "partial"}:
            target["batch_analysis_statuses"].add(status)
        timestamp = parse_time(row.get("timestamp"))
        if timestamp:
            target["timestamps"].append(timestamp)
    roots = []
    for item in by_root.values():
        times = sorted(item.pop("timestamps"))
        for key in ("execution_names", "dispatch_ids", "batch_analysis_statuses"):
            item[key] = sorted(item[key])
        item["observed_unique_execution_count"] = len(item["execution_names"])
        item["first_success_log_at"] = stamp(times[0]) if times else None
        item["last_success_log_at"] = stamp(times[-1]) if times else None
        roots.append(item)
    return {
        "observed_at_utc": observed_at,
        "timestamp_window_utc": {"from": cutoff, "through": observed_at},
        "returned_log_count": len(rows),
        "ignored_records": ignored,
        "possibly_truncated": len(rows) >= limit,
        "roots": roots,
        "proves_no_extra_execution": False,
        "limitations": "Only successful entrypoint summaries contain job/dispatch IDs. A successful summary can still describe partial analysis. Missing logs do not prove no execution; failed or interrupted executions, delayed/dropped logs, access restrictions, and records outside this window may be absent. Distinct observed execution names alone cannot prove replay caused no extra execution. No billing usage is inferred.",
    }


def collect(
    *,
    days: int,
    limit: int,
    now: dt.datetime,
    runner: Runner = run_gcloud,
    job_ids: list[str] | None = None,
) -> dict[str, Any]:
    job_ids = validate_job_ids(job_ids or [])
    cutoff = stamp(now - dt.timedelta(days=days))
    observations: dict[str, Any] = {}

    def read(name: str, args: list[str], sanitize: Callable[[Any], Any]) -> None:
        result = runner(args)
        if result.get("observed"):
            try:
                observations[name] = {
                    "observed": True,
                    "data": sanitize(result["data"]),
                }
            except (AttributeError, KeyError, TypeError, ValueError):
                observations[name] = {
                    "observed": False,
                    "reason": "unexpected_gcloud_schema",
                }
        else:
            observations[name] = {
                "observed": False,
                "reason": result.get("reason", "read_failed"),
            }

    read(
        "enabled_relevant_apis",
        ["services", "list", "--enabled", "--format=json(config.name)"],
        lambda rows: sorted(
            row["config"]["name"]
            for row in rows
            if row.get("config", {}).get("name") in RELEVANT_APIS
        ),
    )
    read(
        "billing_status",
        ["billing", "projects", "describe", PROJECT, "--format=json(billingEnabled)"],
        lambda row: {"billing_enabled": row.get("billingEnabled")},
    )
    read(
        "runner_job",
        [
            "run",
            "jobs",
            "describe",
            JOB,
            f"--region={REGION}",
            "--format=json(metadata.name,spec.template.spec.taskCount,spec.template.spec.parallelism,spec.template.spec.template.spec.serviceAccountName,spec.template.spec.template.spec.timeoutSeconds,spec.template.spec.template.spec.maxRetries,spec.template.spec.template.spec.containers[].image,spec.template.spec.template.spec.containers[].resources,status.conditions)",
        ],
        sanitize_job,
    )
    read(
        "dispatcher_service",
        [
            "run",
            "services",
            "describe",
            DISPATCHER,
            f"--region={REGION}",
            "--format=json(metadata.name,spec.template.spec.serviceAccountName,spec.template.spec.containerConcurrency,spec.template.spec.timeoutSeconds,spec.template.spec.containers[].image,spec.template.spec.containers[].resources,spec.template.metadata.annotations,status.conditions)",
        ],
        sanitize_dispatcher,
    )
    read(
        "runner_executions",
        [
            "run",
            "jobs",
            "executions",
            "list",
            f"--job={JOB}",
            f"--region={REGION}",
            f"--filter=metadata.creationTimestamp>={cutoff}",
            f"--limit={limit}",
            "--sort-by=~metadata.creationTimestamp",
            "--format=json(metadata.name,metadata.creationTimestamp,status.startTime,status.completionTime,status.conditions,status.succeededCount,status.failedCount,status.cancelledCount,spec.taskCount,spec.template.spec.containers[].image,spec.template.spec.containers[].resources)",
        ],
        lambda rows: summarize_executions(rows, limit),
    )
    read(
        "recent_builds",
        [
            "builds",
            "list",
            f"--region={REGION}",
            f"--filter=createTime>={cutoff}",
            f"--limit={limit}",
            "--sort-by=~createTime",
            "--format=json(id,status,createTime,startTime,finishTime,options.machineType,results.images[].name,results.images[].digest)",
        ],
        lambda rows: {
            "returned_count": len(rows),
            "possibly_truncated": len(rows) >= limit,
            "builds": [
                {
                    **{
                        k: row[k]
                        for k in (
                            "id",
                            "status",
                            "createTime",
                            "startTime",
                            "finishTime",
                        )
                        if k in row
                    },
                    "machine_type": row.get("options", {}).get("machineType"),
                    "images": [
                        {k: image[k] for k in ("name", "digest") if k in image}
                        for image in row.get("results", {}).get("images", [])
                    ],
                }
                for row in rows
            ],
        },
    )
    read(
        "artifact_repository",
        [
            "artifacts",
            "repositories",
            "list",
            f"--location={REGION}",
            f'--filter=name="projects/{PROJECT}/locations/{REGION}/repositories/{REPOSITORY}"',
            "--limit=2",
            "--format=json(name,format,sizeBytes,cleanupPolicies,cleanupPolicyDryRun)",
        ],
        # The gcloud describe command's presentation hook clears sizeBytes.
        # A fixed, exact-name list retains the API's byte value without parsing
        # rounded human-readable messages or reading another repository.
        sanitize_repository,
    )
    read(
        "registry_image_versions",
        [
            "artifacts",
            "docker",
            "images",
            "list",
            f"{REGION}-docker.pkg.dev/{PROJECT}/{REPOSITORY}",
            f"--limit={limit}",
            "--format=json(package,version,createTime,updateTime)",
        ],
        lambda rows: {
            "returned_version_count": len(rows),
            "possibly_truncated": len(rows) >= limit,
            "versions": [
                {
                    k: row[k]
                    for k in ("package", "version", "createTime", "updateTime")
                    if k in row
                }
                for row in rows
            ],
        },
    )
    read(
        "cloud_build_source_bucket",
        [
            "storage",
            "buckets",
            "describe",
            f"gs://{PROJECT}_cloudbuild",
            "--format=json(name,location,storage_class,lifecycle_config,soft_delete_policy,retention_policy)",
        ],
        lambda row: {
            k: row[k]
            for k in (
                "name",
                "location",
                "storage_class",
                "lifecycle_config",
                "soft_delete_policy",
                "retention_policy",
            )
            if k in row
        },
    )
    for secret in SECRETS:
        read(
            f"secret_versions/{secret}",
            [
                "secrets",
                "versions",
                "list",
                secret,
                f"--limit={limit}",
                "--format=json(name,state,createTime,destroyTime)",
            ],
            lambda rows: {
                "returned_version_count": len(rows),
                "possibly_truncated": len(rows) >= limit,
                "states": dict(Counter(row.get("state", "UNKNOWN") for row in rows)),
            },
        )
    if job_ids:
        roots_filter = " OR ".join(
            f'jsonPayload.job_id="{job_id}"' for job_id in job_ids
        )
        query = (
            'resource.type="cloud_run_job" '
            f'AND resource.labels.job_name="{JOB}" '
            f'AND resource.labels.location="{REGION}" '
            'AND jsonPayload.scope="shared_cloud_static_analysis" '
            "AND jsonPayload.success=true "
            f"AND ({roots_filter}) "
            f'AND timestamp>="{cutoff}" AND timestamp<="{stamp(now)}"'
        )
        read(
            "acceptance_job_correlation",
            [
                "logging",
                "read",
                query,
                f"--limit={limit}",
                "--order=asc",
                "--format=json(timestamp,labels,jsonPayload.job_id,jsonPayload.dispatch_id,jsonPayload.success,jsonPayload.batch_analysis.status)",
            ],
            lambda rows: summarize_job_logs(rows, job_ids, limit, cutoff, stamp(now)),
        )
    return {
        "schema_version": 2,
        "scope": "read_only_cloud_demo_inventory",
        "collected_at_utc": stamp(now),
        "project_id": PROJECT,
        "region": REGION,
        "window": {"created_since_utc": cutoff, "days": days, "per_list_limit": limit},
        "remote_mutations": False,
        "credential_payloads_read": False,
        "collection_complete": all(item["observed"] for item in observations.values()),
        "observations": observations,
        "unverified": {
            "actual_billed_cost": {
                "observed": False,
                "reason": "Billing-enabled status and resource durations do not establish invoice cost. Inspect Billing Reports, credits, and data freshness in the billing account; costs can arrive later.",
                "console_url": f"https://console.cloud.google.com/billing?project={PROJECT}",
            },
            "cloudflare_usage_and_quotas": {
                "observed": False,
                "reason": "This GCP-only helper does not read Cloudflare CPU/request/storage usage or live Durable Object quota counters.",
            },
            "r2_physical_cleanup_and_lifecycle": {
                "observed": False,
                "reason": "Application expiry alone does not prove physical R2 deletion. Verify both private buckets' lifecycle rules and absence of the test job's source/control/status/report/checkpoint objects using separate bucket-scoped read access.",
            },
            "logging_and_dispatcher_billable_usage": {
                "observed": False,
                "reason": "No unstructured log messages, Monitoring time series, or billing exports are read; optional structured success-log correlation is not billed usage. Execution envelopes exclude service requests, logs, build/storage charges and other projects sharing allowances.",
            },
        },
        "acceptance_complete": False,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--days", type=int, default=30, help="Creation-time lookback, 1–90 days"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Per-list cap, 1–1000; reaching it is reported",
    )
    parser.add_argument(
        "--output", type=Path, help="New local JSON file; never overwrite an old report"
    )
    parser.add_argument(
        "--job-id",
        action="append",
        default=[],
        help="Optional canonical UUID4 to correlate structured success logs; repeat up to four times",
    )
    args = parser.parse_args()
    if not 1 <= args.days <= 90 or not 1 <= args.limit <= 1000:
        parser.error("Use --days 1..90 and --limit 1..1000")
    try:
        job_ids = validate_job_ids(args.job_id)
    except ValueError as error:
        parser.error(str(error))
    now = dt.datetime.now(dt.timezone.utc)
    output = args.output or Path(f"demo-cloud-evidence-{now:%Y%m%dT%H%M%SZ}.json")
    if output.exists() or output.is_symlink():
        parser.error("Output exists; choose a new path to preserve previous evidence")
    report = collect(days=args.days, limit=args.limit, now=now, job_ids=job_ids)
    write_report(output, report)
    print(
        json.dumps(
            {
                "scope": report["scope"],
                "report_file": str(output),
                "collection_complete": report["collection_complete"],
                "resource_envelope_coverage": report["observations"]
                .get("runner_executions", {})
                .get("data", {})
                .get("resource_time_envelope", {})
                .get("coverage", "not_observed"),
                "acceptance_complete": False,
                "actual_cost_verified": False,
                "remote_mutations": False,
                "failed_reads": [
                    key
                    for key, value in report["observations"].items()
                    if not value["observed"]
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
