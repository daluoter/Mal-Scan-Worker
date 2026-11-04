"""Reviewable Logging/Monitoring payloads; this module makes no cloud calls.

Cloud Build creates a new build_id time series for each invocation. Reduce those
series before evaluating either condition; retaining build_id would alert on
every historical build after it stopped emitting data.
"""

from __future__ import annotations

import re
from typing import Any

PROJECT = "malscan-v2-poc"
CONTROLLER_TAG = "malscan-db-controller"
FAILURE_MARKER = "MALSCAN_DB_UPDATE_FAILURE"
HEALTHY_MARKER = "MALSCAN_DB_UPDATE_HEALTHY"
FAILURE_METRIC = "malscan_db_update_failure"
HEALTHY_METRIC = "malscan_db_update_healthy"
HEALTHY_ABSENCE_SECONDS = 82_800  # 23 hours; provider maximum is 23.5 hours.
ALIGNMENT_SECONDS = 600

REFERENCES = (
    "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics",
    "https://cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.alertPolicies",
    "https://cloud.google.com/monitoring/alerts/metric-absence",
    "https://cloud.google.com/logging/docs/logs-based-metrics",
)


class MonitoringError(ValueError):
    """A fixed-scope monitoring configuration could not be established."""


def _aggregation() -> dict[str, Any]:
    return {
        "alignmentPeriod": f"{ALIGNMENT_SECONDS}s",
        "perSeriesAligner": "ALIGN_SUM",
        "crossSeriesReducer": "REDUCE_SUM",
        "groupByFields": [],
    }


def _metric(name: str, marker: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "disabled": False,
        "filter": (
            'resource.type="build"\n'
            f'resource.labels.project_id="{PROJECT}"\n'
            f'(textPayload:"{marker}" OR jsonPayload.marker="{marker}")'
        ),
        "metricDescriptor": {
            "metricKind": "DELTA",
            "valueType": "INT64",
            "unit": "1",
        },
    }


def _metric_filter(name: str) -> str:
    return (
        f'metric.type="logging.googleapis.com/user/{name}" AND '
        'resource.type="build" AND '
        f'resource.labels.project_id="{PROJECT}"'
    )


def _policy(
    title: str,
    kind: str,
    condition: dict[str, Any],
    channel: str,
    documentation: str,
) -> dict[str, Any]:
    return {
        "displayName": title,
        "enabled": False,
        "combiner": "OR",
        "notificationChannels": [channel],
        "userLabels": {"component": CONTROLLER_TAG, "alert-kind": kind},
        "conditions": [condition],
        "documentation": {"content": documentation, "mimeType": "text/markdown"},
        "alertStrategy": {"autoClose": "604800s"},
    }


def monitoring_plan(
    project: str,
    notification_channel: str,
    controller_tag: str = CONTROLLER_TAG,
) -> dict[str, Any]:
    """Return provider REST payloads, initially disabled until reviewed activation.

    Counter LogMetric payloads go to projects.metrics.create/update. AlertPolicy
    payloads go to projects.alertPolicies.create/update; their output-only names,
    IDs, creation records and ETags are deliberately absent.

    This fixed demo uses two daily ticks. A 23-hour absence window is compatible
    with the provider's 23.5-hour maximum and leaves room for one delayed tick.
    Absence evaluation starts only after the first data point following policy
    creation or modification; activation must seed and verify that data point.
    """
    if project != PROJECT:
        raise MonitoringError("unexpected_monitoring_project")
    if controller_tag != CONTROLLER_TAG:
        raise MonitoringError("unexpected_controller_tag")
    if not isinstance(notification_channel, str) or not re.fullmatch(
        re.escape(f"projects/{PROJECT}/notificationChannels/") + r"[1-9][0-9]{0,31}",
        notification_channel,
    ):
        raise MonitoringError("existing_same_project_notification_channel_required")

    failure_metric = _metric(
        FAILURE_METRIC,
        FAILURE_MARKER,
        "Count safe failure markers emitted by the MalScan database controller.",
    )
    healthy_metric = _metric(
        HEALTHY_METRIC,
        HEALTHY_MARKER,
        "Count verified healthy ticks from the MalScan database controller.",
    )
    failure = _policy(
        "MalScan database update failed",
        "failure",
        {
            "displayName": "Controller reported a database maintenance failure",
            "conditionThreshold": {
                "filter": _metric_filter(FAILURE_METRIC),
                "aggregations": [_aggregation()],
                "comparison": "COMPARISON_GT",
                "thresholdValue": 0,
                "duration": "60s",
                "evaluationMissingData": "EVALUATION_MISSING_DATA_INACTIVE",
                "trigger": {"count": 1},
            },
        },
        notification_channel,
        "The database updater reported a failure. Inspect its safe Cloud Build "
        "summary and durable campaign state. Preserve the current image and "
        "checkpoint; do not resubmit uncertain builds or updates. A Scheduler "
        "HTTP success only acknowledges controller submission, not maintenance "
        "success. Sparse counter gaps evaluate as inactive after the one-minute "
        "retest window so a later failure can open a new incident. This payload "
        "does not verify incident transitions or notification delivery.",
    )
    missing = _policy(
        "MalScan database controller heartbeat missing",
        "missing-heartbeat",
        {
            "displayName": "No verified healthy controller tick for 23 hours",
            "conditionAbsent": {
                "filter": _metric_filter(HEALTHY_METRIC),
                "aggregations": [_aggregation()],
                "duration": f"{HEALTHY_ABSENCE_SECONDS}s",
                "trigger": {"count": 1},
            },
        },
        notification_channel,
        "No verified healthy tick was observed for 23 hours despite a 12-hour "
        "schedule. Check Scheduler, source-bundle fetch, controller startup, "
        "IAM and the private campaign state. The failure-marker policy cannot "
        "see failures before Python starts; this absence policy covers that "
        "gap after it has received its first point. After creating or modifying "
        "this policy, immediately run a controller tick and verify that a "
        "healthy metric point is visible. Do not count the policy as operational "
        "until initial metric ingestion and notification delivery are checked.",
    )
    return {
        "schema_version": 1,
        "project": PROJECT,
        "controller_tag": CONTROLLER_TAG,
        "log_metrics": [failure_metric, healthy_metric],
        "alert_policies": [failure, missing],
        "activation_requirements": [
            "Use an enabled, owned notification channel in this project; verify actual delivery.",
            "Review the payloads and enable both alert policies during activation.",
            "Immediately run a controller tick after policy creation or modification.",
            "Verify the first healthy log metric point; metrics are not populated retroactively.",
            "Keep the controller on the 12-hour schedule; do not use this window for daily ticks.",
            "Plan intentional pauses with the absence policy; do not emit a fake healthy marker.",
        ],
        "references": list(REFERENCES),
        "remote_mutations": False,
        "notification_sent": False,
    }
