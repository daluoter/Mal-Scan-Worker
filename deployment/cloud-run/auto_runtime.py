"""Repair the exact pre-Python controller startup failure without replacing source.

The original private plan remains immutable. An exact, journal-bound runtime
override becomes effective only after its paused Scheduler body is read back.
Unknown writes are reconciled by reads and are never sent again.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = "malscan-v2-poc"
REGION = "us-central1"
SCHEDULER = "malscan-v2-database-updates"
SDK_IMAGE = (
    "gcr.io/google.com/cloudsdktool/google-cloud-cli@"
    "sha256:18d8c484aaef27d7ef7b54dfb018f73712503d254a16f0a76b2626b4f6003af2"
)
PYTHON = "/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin/python3"
CA_ENV = "SSL_CERT_FILE=/usr/lib/google-cloud-sdk/lib/third_party/certifi/cacert.pem"
READBACK_DELAYS = (1, 2, 4, 8, 15, 15, 15)
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
PROBE_TAG = re.compile(r"malscan-db-probe-[a-f0-9]{32}\Z")
LEGACY_TEMPLATE = {
    "steps": [
        {
            "id": "database-update-controller",
            "name": "gcr.io/google.com/cloudsdktool/google-cloud-cli:stable",
            "entrypoint": "python3",
            "args": [
                "deployment/cloud-run/auto_update.py",
                "run",
                "--bucket",
                "$_OPS_BUCKET",
                "--owner-build-id",
                "$BUILD_ID",
            ],
        }
    ],
    "substitutions": {"_OPS_BUCKET": "REPLACE_OPS_BUCKET"},
    "tags": ["malscan-db-controller"],
    "timeout": "1800s",
    "options": {"logging": "CLOUD_LOGGING_ONLY"},
}


class RuntimeRepairError(RuntimeError):
    """A fixed public error category, never a provider body or private value."""


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def current_template() -> dict:
    expected = copy.deepcopy(LEGACY_TEMPLATE)
    expected["steps"][0].update(name=SDK_IMAGE, entrypoint=PYTHON, env=[CA_ENV])
    actual = json.loads(Path(__file__).with_name("cloudbuild-auto-update.json").read_text())
    if actual != expected:
        raise RuntimeRepairError("runtime_current_template_invalid")
    return expected


def supported_template(template: Any) -> bool:
    return template == LEGACY_TEMPLATE or template == current_template()


def _probe_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "confirmed"
        and isinstance(value.get("build_id"), str)
        and UUID.fullmatch(value["build_id"]) is not None
        and isinstance(value.get("intent_tag"), str)
        and PROBE_TAG.fullmatch(value["intent_tag"]) is not None
    )


def _record(plan: dict, journal: dict) -> dict | None:
    value = journal.get("runtime_repair")
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("version"), int)
        or isinstance(value["version"], bool)
        or value["version"] != 1
        or value.get("status") not in {"pending", "confirmed"}
        or value.get("plan_sha256") != _digest(plan)
        or value.get("old_template_sha256") != _digest(LEGACY_TEMPLATE)
        or value.get("new_template_sha256") != _digest(current_template())
        or plan.get("controller_build_template") != LEGACY_TEMPLATE
        or not _probe_valid(value.get("original_probe"))
        or value.get("failed_probe_build_id") != value["original_probe"]["build_id"]
        or not isinstance(value.get("scheduler_configuration_sha256"), str)
        or re.fullmatch(r"[a-f0-9]{64}", value["scheduler_configuration_sha256"]) is None
        or not isinstance(value.get("state_generation"), int)
        or isinstance(value["state_generation"], bool)
        or value["state_generation"] < 1
    ):
        raise RuntimeRepairError("runtime_repair_checkpoint_invalid")
    return value


def effective_template(plan: dict, journal: dict) -> dict:
    template = plan.get("controller_build_template")
    if not supported_template(template):
        raise RuntimeRepairError("runtime_plan_template_invalid")
    record = _record(plan, journal)
    return copy.deepcopy(
        current_template() if record and record["status"] == "confirmed" else template
    )


def _subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _subset(child, actual[key]) for key, child in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(_subset(left, right) for left, right in zip(expected, actual))
        )
    return expected == actual


def build_matches(request: dict, build: Any) -> bool:
    """Match fixed request fields against raw or provider-resolved substitutions."""
    if not isinstance(build, dict) or not isinstance(build.get("id"), str):
        return False
    if UUID.fullmatch(build["id"]) is None:
        return False
    raw = copy.deepcopy(request)
    actual = copy.deepcopy(build)
    for value in (raw, actual):
        tags = value.get("tags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            return False
        value["tags"] = sorted(tags)
    bucket = request.get("substitutions", {}).get("_OPS_BUCKET")
    if not isinstance(bucket, str):
        return False

    def resolved(value):
        if isinstance(value, str):
            return (
                value.replace("${_OPS_BUCKET}", bucket)
                .replace("$_OPS_BUCKET", bucket)
                .replace("${BUILD_ID}", build["id"])
                .replace("$BUILD_ID", build["id"])
            )
        if isinstance(value, list):
            return [resolved(child) for child in value]
        if isinstance(value, dict):
            return {key: resolved(child) for key, child in value.items()}
        return value

    return _subset(raw, actual) or _subset(resolved(raw), actual)


def _scheduler_hash(value: dict) -> str:
    configuration = _normalized_scheduler(value)
    for name in ("status", "scheduleTime", "lastAttemptTime", "userUpdateTime", "satisfiesPzs"):
        configuration.pop(name, None)
    configuration.get("httpTarget", {}).pop("body", None)
    return _digest(configuration)


def _scheduler_matches(expected: dict, actual: Any) -> bool:
    return (
        isinstance(actual, dict)
        and actual.get("state") == "PAUSED"
        and _subset(expected, _normalized_scheduler(actual))
    )


def _normalized_scheduler(value: dict) -> dict:
    result = copy.deepcopy(value)
    retry = result.setdefault("retryConfig", {})
    if isinstance(retry, dict):
        retry.setdefault("retryCount", 0)
    return result


def _idle(tool, *, expected_generation=None):
    state, generation = tool._approved_state()
    lease, _ = tool.store.load_json("lease.json")
    if state.get("enabled") is not False or state.get("active") is not None or lease is not None:
        raise RuntimeRepairError("runtime_repair_requires_disabled_idle_state")
    if expected_generation is not None and generation != expected_generation:
        raise RuntimeRepairError("runtime_repair_state_generation_changed")
    return state, generation


def _failed_probe(tool, probe: dict):
    build_id = probe["build_id"]
    request = tool.build_request(template=LEGACY_TEMPLATE)
    request["tags"].append(probe["intent_tag"])
    build = tool.get(
        f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/builds/{build_id}"
    )
    if not build_matches(request, build) or build.get("id") != build_id:
        raise RuntimeRepairError("runtime_failed_probe_request_differs")
    info = build.get("failureInfo", {})
    if not isinstance(info, dict):
        raise RuntimeRepairError("runtime_failed_probe_not_pre_python_failure")
    detail = info.get("detail", "")
    if (
        build.get("status") != "FAILURE"
        or info.get("type") != "USER_BUILD_STEP"
        or not isinstance(detail, str)
        or 'exec: "python3": executable file not found' not in detail
        or "starting step container failed" not in detail
    ):
        raise RuntimeRepairError("runtime_failed_probe_not_pre_python_failure")


def _summary(tool, status: str) -> dict:
    return {
        "scope": "controller_runtime_repair",
        "status": status,
        "scheduler_state": "PAUSED",
        "automatic_updates_enabled": False,
        "approved_source_preserved": True,
        "probe_submitted": False,
        "probe_intent_present": "initial-probe" in tool.journal["operations"],
        "cloud_run_executed": False,
    }


def repair(tool) -> dict:
    """Repair only the recorded failed initial probe; never launch a new probe."""
    if tool.journal.get("phase") != "installed_paused":
        raise RuntimeRepairError("runtime_repair_requires_paused_installation")
    if tool.journal.get("plan_sha256") != _digest(tool.plan):
        raise RuntimeRepairError("runtime_repair_plan_changed")
    state, generation = _idle(tool)
    template = tool.plan.get("controller_build_template")
    url = f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
    scheduler = tool.get(url)
    if template == current_template() and _record(tool.plan, tool.journal) is None:
        if not _scheduler_matches(tool.scheduler_document(template=current_template()), scheduler):
            raise RuntimeRepairError("runtime_repair_scheduler_changed")
        return _summary(tool, "not_required")
    if template != LEGACY_TEMPLATE:
        raise RuntimeRepairError("runtime_plan_template_invalid")
    old = tool.scheduler_document(template=LEGACY_TEMPLATE)
    new = tool.scheduler_document(template=current_template())
    record = _record(tool.plan, tool.journal)
    if record and record["status"] == "confirmed":
        if (
            not _scheduler_matches(new, scheduler)
            or _scheduler_hash(scheduler) != record["scheduler_configuration_sha256"]
        ):
            raise RuntimeRepairError("runtime_repair_scheduler_changed")
        return _summary(tool, "confirmed")
    if state.get("last_healthy_at") is not None:
        raise RuntimeRepairError("runtime_repair_requires_failed_initial_probe")
    probe = record["original_probe"] if record else tool.journal["operations"].get("initial-probe")
    if not _probe_valid(probe) or tool.journal["operations"].get("initial-probe") != probe:
        raise RuntimeRepairError("runtime_failed_probe_identity_invalid")
    _failed_probe(tool, probe)
    if record is None:
        if not _scheduler_matches(old, scheduler):
            raise RuntimeRepairError("runtime_repair_scheduler_changed")
        record = {
            "version": 1,
            "status": "pending",
            "plan_sha256": _digest(tool.plan),
            "old_template_sha256": _digest(LEGACY_TEMPLATE),
            "new_template_sha256": _digest(current_template()),
            "failed_probe_build_id": probe["build_id"],
            "original_probe": copy.deepcopy(probe),
            "scheduler_configuration_sha256": _scheduler_hash(scheduler),
            "state_generation": generation,
            "intent_at": datetime.now(timezone.utc).isoformat(),
        }
        tool.journal["runtime_repair"] = record
        tool.save()  # Durable intent before the one allowed PATCH.
        _idle(tool, expected_generation=generation)
        scheduler = tool.get(url)
        if (
            not _scheduler_matches(old, scheduler)
            or _scheduler_hash(scheduler) != record["scheduler_configuration_sha256"]
        ):
            raise RuntimeRepairError("runtime_repair_scheduler_changed")
        try:
            tool.rest.request(
                "PATCH",
                url + "?updateMask=httpTarget.body",
                {"name": new["name"], "httpTarget": {"body": new["httpTarget"]["body"]}},
            )
        except Exception:
            raise RuntimeRepairError("runtime_patch_response_unknown") from None
        scheduler = tool.get(url)
    sleep = getattr(tool, "readback_sleep", time.sleep)
    for delay in READBACK_DELAYS:
        if _scheduler_matches(new, scheduler):
            break
        if (
            not _scheduler_matches(old, scheduler)
            or _scheduler_hash(scheduler) != record["scheduler_configuration_sha256"]
        ):
            raise RuntimeRepairError("runtime_repair_scheduler_changed")
        sleep(delay)
        scheduler = tool.get(url)
    if not _scheduler_matches(new, scheduler):
        raise RuntimeRepairError("runtime_patch_requires_reconciliation")
    if _scheduler_hash(scheduler) != record["scheduler_configuration_sha256"]:
        raise RuntimeRepairError("runtime_repair_scheduler_changed")
    _idle(tool, expected_generation=record["state_generation"])
    completed = copy.deepcopy(tool.journal)
    completed["runtime_repair"]["status"] = "confirmed"
    completed["runtime_repair"]["confirmed_at"] = datetime.now(timezone.utc).isoformat()
    history = completed.setdefault("failed_probes", [])
    if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
        raise RuntimeRepairError("runtime_failed_probe_history_invalid")
    if not any(item.get("build_id") == probe["build_id"] for item in history):
        history.append(copy.deepcopy(probe))
    del completed["operations"]["initial-probe"]
    tool.journal = completed
    tool.save()  # Override confirmation and old-probe archival are one atomic save.
    return _summary(tool, "confirmed")
