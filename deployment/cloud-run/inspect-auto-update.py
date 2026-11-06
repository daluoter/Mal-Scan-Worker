#!/usr/bin/env python3
"""Read private updater metadata and Monitoring points without changing resources.

The report excludes notification labels, provider bodies and private checkpoints.
A healthy GCS checkpoint is separate from a Monitoring point and email delivery.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

SPEC = importlib.util.spec_from_file_location(
    "observability_setup", Path(__file__).with_name("setup-auto-update.py")
)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)
PROJECT = setup.PROJECT
MAX_PAGES = 3
MAX_POINTS = 3000
METRIC = "logging.googleapis.com/user/malscan_db_update_healthy"


class ObservationError(RuntimeError):
    """Fixed safe category; provider text is never included."""


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        raise ObservationError("invalid_timestamp") from None


def safe_time(value):
    return timestamp(value).isoformat() if value is not None else None


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def healthy_points(rest, build_id, start, end):
    """Read (start,end] for the exact healthy controller, with bounded pagination."""
    if not canonical_uuid(build_id) or start >= end:
        raise ObservationError("invalid_metric_query_boundary")
    query = {
        "filter": (
            f'metric.type="{METRIC}" AND resource.type="build" AND '
            f'resource.labels.project_id="{PROJECT}" AND '
            f'resource.labels.build_id="{build_id}"'
        ),
        "interval.startTime": start.isoformat(),
        "interval.endTime": end.isoformat(),
        "view": "FULL",
        "pageSize": 1000,
    }
    token = None
    seen_tokens = set()
    points = []
    count = 0
    for _ in range(MAX_PAGES):
        if token is not None:
            query["pageToken"] = token
        result = rest.request(
            "GET",
            f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/timeSeries?"
            + urlencode(query),
        )
        if (
            not isinstance(result, dict)
            or result.get("executionErrors")
            or result.get("unreachable")
        ):
            raise ObservationError("metric_response_incomplete")
        series = result.get("timeSeries", [])
        if not isinstance(series, list):
            raise ObservationError("metric_response_invalid")
        for row in series:
            if (
                not isinstance(row, dict)
                or row.get("metric", {}).get("type") != METRIC
                or row.get("resource", {}).get("type") != "build"
                or row["resource"].get("labels", {}).get("project_id") != PROJECT
                or row["resource"].get("labels", {}).get("build_id") != build_id
                or row.get("metricKind") != "DELTA"
                or row.get("valueType") != "INT64"
                or not isinstance(row.get("points"), list)
            ):
                raise ObservationError("metric_series_scope_or_shape_invalid")
            for point in row["points"]:
                count += 1
                if count > MAX_POINTS:
                    raise ObservationError("metric_point_limit_reached")
                if not isinstance(point, dict):
                    raise ObservationError("metric_point_invalid")
                value = point.get("value", {}).get("int64Value")
                if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,19}", value):
                    raise ObservationError("metric_counter_invalid")
                if int(value) > 2**63 - 1:
                    raise ObservationError("metric_counter_invalid")
                ended = timestamp(point.get("interval", {}).get("endTime"))
                started = timestamp(point.get("interval", {}).get("startTime"))
                if started >= ended:
                    raise ObservationError("metric_delta_interval_invalid")
                if start < ended <= end and int(value) > 0:
                    points.append(ended)
        token = result.get("nextPageToken")
        if token is None or token == "":
            return {
                "read_complete": True,
                "post_activation_point_observed": bool(points),
                "positive_samples": len(points),
                "latest_positive_point_at": max(points).isoformat() if points else None,
            }
        if not isinstance(token, str) or len(token) > 8192 or token in seen_tokens:
            raise ObservationError("metric_pagination_invalid")
        seen_tokens.add(token)
    raise ObservationError("metric_pagination_incomplete")


def current_release_controls(tool, saved):
    """Read only the exact candidate Build's emitted controls, without exporting logs."""
    maintenance = setup.module("observability_release_controls", "maintain-demo.py")
    return maintenance.Maintenance(tool.directory, setup.ROOT).controls_report(saved)


def current_release_steps(build, saved, image):
    tag = image + ":" + saved["release"]
    expected = [
        {
            "name": "gcr.io/cloud-builders/docker",
            "env": ["DOCKER_BUILDKIT=1"],
            "args": [
                "build",
                "--target=cloud-job",
                "--build-arg=SIGNATURE_REFRESH=" + saved["release"],
                "-f",
                "worker/Dockerfile",
                "-t",
                tag,
                ".",
            ],
        },
        {
            "id": "engine-controls",
            "name": "gcr.io/cloud-builders/docker",
            "args": [
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--tmpfs=/tmp:rw,size=128m",
                "--entrypoint=python",
                tag,
                "-m",
                "malscan_worker.runtime.engine_controls",
            ],
        },
    ]
    steps = build.get("steps")
    options = build.get("options", {})
    if (
        not isinstance(steps, list)
        or len(steps) != 2
        or not isinstance(options, dict)
        or any(options.get(key) for key in ("env", "secretEnv", "volumes"))
    ):
        raise ObservationError("current_release_build_steps_invalid")
    for desired, actual in zip(expected, steps):
        if (
            not isinstance(actual, dict)
            or actual.get("status") != "SUCCESS"
            or not setup.subset(desired, actual)
            or actual.get("env", []) != desired.get("env", [])
            or actual.get("dir", "") not in {"", "."}
            or any(
                actual.get(key)
                for key in (
                    "entrypoint",
                    "script",
                    "secretEnv",
                    "volumes",
                    "allowFailure",
                    "allowExitCodes",
                )
            )
        ):
            raise ObservationError("current_release_build_steps_invalid")


def current_release(tool, state, generation, now):
    """Verify the current release; this does not classify its Scheduler trigger."""
    approved, observed_generation = tool._approved_state()
    if observed_generation != generation or approved != state:
        raise ObservationError("current_release_snapshot_changed")
    auto = setup.module("observability_release_controller", "auto_update.py")
    files = approved["current"]["files"]
    saved, _, daily = auto._approved_files(files)
    build_id = saved.get("build_id")
    if not canonical_uuid(build_id):
        raise ObservationError("current_release_build_id_invalid")
    build = tool.get(
        f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{setup.REGION}"
        f"/builds/{build_id}"
    )
    if (
        not isinstance(build, dict)
        or build.get("id") != build_id
        or build.get("status") != "SUCCESS"
        or build.get("serviceAccount") != auto.BUILDER_ACCOUNT
    ):
        raise ObservationError("current_release_build_identity_invalid")
    actual_files = {**files, "build.json": build}
    try:
        auto._approved_files(actual_files)
    except Exception:
        raise ObservationError("current_release_build_result_differs") from None
    current_release_steps(build, saved, auto.maintenance.IMAGE)
    source = build.get("source", {}).get("storageSource", {})
    object_name = source.get("object") if isinstance(source, dict) else None
    if (
        not isinstance(source, dict)
        or source.get("bucket") != tool.plan["bucket"]
        or not isinstance(object_name, str)
        or not re.fullmatch(r"build-sources/[A-Za-z0-9._/-]{1,1024}", object_name)
        or any(part in {"", ".", ".."} for part in object_name.split("/"))
    ):
        raise ObservationError("current_release_build_source_invalid")
    created, finished = timestamp(build.get("createTime")), timestamp(build.get("finishTime"))
    if created > finished or finished > now:
        raise ObservationError("current_release_build_time_invalid")
    if current_release_controls(tool, saved) != files["engine-controls.json"]:
        raise ObservationError("current_release_controls_differ")
    version = daily.get("version")
    age = int(now.timestamp()) - daily["created_at_epoch"]
    candidate_age = int(finished.timestamp()) - daily["created_at_epoch"]
    if (
        not setup.integer(version)
        or version < 1
        or not 0 <= age <= 604800
        or not 0 <= candidate_age <= auto.POLICY["max_candidate_age_seconds"]
    ):
        raise ObservationError("current_release_daily_invalid")
    controls = files["engine-controls.json"]
    return {
        "read_only": True,
        "current_image": approved["current"]["image"],
        "rollback_image": approved["current"]["rollback_image"],
        "release": saved["release"],
        "phase": saved["phase"],
        "build_id": build_id,
        "build_status": "SUCCESS",
        "build_created_at": created.isoformat(),
        "build_finished_at": finished.isoformat(),
        "registered_source_and_live_job_configuration_verified": True,
        "provider_build_result_and_builder_identity_verified": True,
        "provider_build_steps_match_expected_offline_controls": True,
        "provider_build_source_in_operations_staging_prefix": True,
        "provider_controls_match_saved_controls": True,
        "daily_database": {
            "version": version,
            "created_at": datetime.fromtimestamp(
                daily["created_at_epoch"], timezone.utc
            ).isoformat(),
            "age_seconds": age,
            "age_at_build_finish_seconds": candidate_age,
            "candidate_age_limit_seconds": auto.POLICY["max_candidate_age_seconds"],
        },
        "controls": {name: True for name in sorted(controls["controls"])},
        "all_three_database_signatures_verified": True,
        "cron_execution_not_classified": True,
        "new_build_submitted": False,
        "cloud_run_executed": False,
    }


def inspect(tool, *, now=None, include_current_release=False):
    now = now or datetime.now(timezone.utc)
    report = {
        "schema_version": 1,
        "scope": "read_only_auto_update_observability",
        "read_only": True,
        "observed_at": now.isoformat(),
        "errors": [],
        "notification_delivery_verified": False,
        "real_scheduled_refresh_verified": False,
        "billed_cost_verified": False,
        "cloud_run_executed": False,
        "remote_mutations": False,
        "raw_payloads_exported": False,
    }

    def attempt(check, action):
        try:
            return action()
        except Exception as error:
            code = str(error) if isinstance(error, ObservationError) else "read_unavailable"
            report["errors"].append({"check": check, "error": code})
            return None

    def state_snapshot():
        state, generation = tool.store.load_json("state.json")
        auto = setup.module("observability_controller", "auto_update.py")
        return auto.validate_state(state), generation, auto.status_summary(state)

    snapshot = attempt("controller_state", state_snapshot)
    state, generation, summary = snapshot if snapshot else (None, None, None)
    report["controller"] = summary
    owner = state.get("last_controller_build_id") if state else None
    report["healthy_controller_build_id"] = owner if canonical_uuid(owner) else None
    source_matches = bool(
        state
        and state["source"]
        == {
            "commit": tool.plan["source_commit"],
            "sha256": tool.plan["source_sha256"],
            "bundle_sha256": tool.plan["bundle_sha256"],
            "storage_source": tool.journal.get("storage_source"),
        }
    )
    report["registered_source_matches"] = source_matches
    if state is not None and not source_matches:
        report["errors"].append({"check": "registered_source", "error": "source_mismatch"})
    activated = attempt("activation_time", lambda: timestamp(tool.journal.get("activated_at")))
    if activated is not None and activated >= now:
        report["errors"].append({"check": "activation_time", "error": "activation_not_in_past"})
        activated = None
    report["activated_at"] = activated.isoformat() if activated else None
    report["activation_heartbeat_verified"] = bool(
        state
        and source_matches
        and activated
        and tool._post_intent_healthy(state, activated.isoformat())
    )

    def scheduler_readback():
        expected = tool.scheduler_document()
        actual = tool.get("https://cloudscheduler.googleapis.com/v1/" + expected["name"])
        if not isinstance(actual, dict):
            raise ObservationError("scheduler_not_observed")
        return {
            "state": actual.get("state")
            if actual.get("state") in {"ENABLED", "PAUSED", "DISABLED", "UPDATE_FAILED"}
            else "unrecognized",
            "configuration_matches": setup.subset(expected, setup.normalized_scheduler(actual)),
            "last_attempt_at": safe_time(actual.get("lastAttemptTime")),
            "next_schedule_at": safe_time(actual.get("scheduleTime")),
            "manual_or_cron_execution_not_classified": True,
        }

    report["scheduler"] = attempt("scheduler", scheduler_readback)
    report["log_metrics"] = []
    for expected in tool.plan["monitoring"]["log_metrics"]:

        def metric_readback(expected=expected):
            actual = tool.get(
                f"https://logging.googleapis.com/v2/projects/{PROJECT}/metrics/" + expected["name"]
            )
            if not isinstance(actual, dict):
                raise ObservationError("log_metric_not_observed")
            return {
                "name": expected["name"],
                "configuration_matches": setup.subset(expected, setup.normalized_metric(actual)),
            }

        value = attempt("log_metric:" + expected["name"], metric_readback)
        report["log_metrics"].append(
            value or {"name": expected["name"], "configuration_matches": None}
        )

    def policy_readbacks():
        references = tool.journal.get("policies")
        expected_policies = tool.plan["monitoring"]["alert_policies"]
        if (
            not isinstance(references, list)
            or len(references) != len(expected_policies)
            or len(set(references)) != len(references)
            or any(
                not isinstance(name, str)
                or not re.fullmatch(f"projects/{PROJECT}/alertPolicies/[0-9]+", name)
                for name in references
            )
        ):
            raise ObservationError("policy_references_invalid")
        result = []
        for name, desired in zip(references, expected_policies):
            actual = tool.get("https://monitoring.googleapis.com/v3/" + name)
            if not isinstance(actual, dict) or actual.get("name") != name:
                raise ObservationError("policy_not_observed")
            expected = copy.deepcopy(desired)
            expected["enabled"] = True
            result.append(
                {
                    "kind": desired["userLabels"]["alert-kind"],
                    "enabled": actual.get("enabled") is True,
                    "matches_enabled_plan": setup.subset(expected, setup.normalized_policy(actual)),
                }
            )
        return result

    report["alert_policies"] = attempt("alert_policies", policy_readbacks)

    def channel_readback():
        name = tool.plan["notification_channel"]
        actual = tool.get("https://monitoring.googleapis.com/v3/" + name)
        if not isinstance(actual, dict) or actual.get("name") != name:
            raise ObservationError("notification_channel_not_observed")
        return {
            "metadata_ready": actual.get("enabled") is True
            and actual.get("verificationStatus") != "UNVERIFIED",
            "delivery_verified": False,
        }

    report["notification_channel"] = attempt("notification_channel", channel_readback)
    report["healthy_metric"] = {
        "read_complete": False,
        "post_activation_point_observed": None,
    }
    if state and source_matches and activated:
        value = attempt(
            "healthy_metric_points",
            lambda: healthy_points(
                tool.rest, state.get("last_controller_build_id"), activated, now
            ),
        )
        if value is not None:
            report["healthy_metric"] = value

    if include_current_release:
        report["current_release"] = (
            attempt("current_release", lambda: current_release(tool, state, generation, now))
            if snapshot and source_matches
            else None
        )

    if snapshot:

        def unchanged():
            _, observed = tool.store.load_json("state.json")
            if observed != generation:
                raise ObservationError("controller_changed_during_observation")
            return True

        attempt("snapshot_consistency", unchanged)
    report["read_complete"] = not report["errors"]
    report["enabled_monitoring_metadata_matches_plan"] = bool(
        state
        and state["enabled"]
        and source_matches
        and report["scheduler"]
        and report["scheduler"]["state"] == "ENABLED"
        and report["scheduler"]["configuration_matches"]
        and all(m["configuration_matches"] is True for m in report["log_metrics"])
        and report["alert_policies"]
        and all(p["matches_enabled_plan"] for p in report["alert_policies"])
        and report["notification_channel"]
        and report["notification_channel"]["metadata_ready"]
    )
    healthy_config = next(
        (m for m in report["log_metrics"] if m["name"] == "malscan_db_update_healthy"), {}
    )
    report["healthy_metric_ingestion_verified"] = bool(
        report["read_complete"]
        and report["activation_heartbeat_verified"]
        and healthy_config.get("configuration_matches") is True
        and report["healthy_metric"]["post_activation_point_observed"] is True
    )
    if include_current_release:
        report["cloud_release_evidence_verified"] = bool(
            report["read_complete"] and report["current_release"] is not None
        )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--current-release",
        action="store_true",
        help="Also read the current candidate Build, live Job and emitted offline controls",
    )
    args = parser.parse_args()
    try:
        if args.output and (
            setup.ROOT == args.output.resolve() or setup.ROOT in args.output.resolve().parents
        ):
            raise ObservationError("report_must_be_outside_checkout")
        report = inspect(
            setup.Provisioner(args.plan_dir), include_current_release=args.current_release
        )
        if args.output:
            maintenance = setup.module("observability_private_output", "maintain-demo.py")
            maintenance.write_private(args.output, report, exclusive=True)
        print(json.dumps(report, indent=2))
    except Exception as error:
        code = str(error) if isinstance(error, ObservationError) else "observation_not_verified"
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": "read_only_auto_update_observability",
                    "error": code,
                    "read_only": True,
                    "remote_mutations": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
