"""Durable, opt-in signed database maintenance; public output is summary-only.

The controller never executes an analysis Job. Every build/update/delete intent
is committed to private generation-conditional storage before the remote write.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import auto_retention
from auto_state import Lease, StateError, Store


def module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


maintenance = module("scheduled_maintenance", "maintain-demo.py")
inventory = module("scheduled_inventory", "cleanup-registry.py")
PROJECT = maintenance.PROJECT
REGION = maintenance.REGION
JOB = maintenance.JOB
CONTROLLER_ACCOUNT = (
    f"projects/{PROJECT}/serviceAccounts/malscan-v2-db-updater@{PROJECT}.iam.gserviceaccount.com"
)
BUILDER_ACCOUNT = (
    f"projects/{PROJECT}/serviceAccounts/malscan-v2-db-builder@{PROJECT}.iam.gserviceaccount.com"
)
CONTROLLER_TAG = "malscan-db-controller"
FAILURE_MARKER = "MALSCAN_DB_UPDATE_FAILURE"
HEALTHY_MARKER = "MALSCAN_DB_UPDATE_HEALTHY"
FILES = {"state.json", "job-before.json", "build.json", "engine-controls.json"}
POLICY = {
    "refresh_after_seconds": 259200,
    "max_candidate_age_seconds": 172800,
    "monthly_build_limit": 12,
    "max_live_owned": 4,
}
TERMINAL = {"SUCCESS", "FAILURE", "CANCELLED", "TIMEOUT", "EXPIRED", "INTERNAL_ERROR"}
PHASES = {
    "prepared",
    "submission_pending",
    "submission_unknown",
    "build_submitted",
    "build_verified",
    "build_failed",
    "promotion_pending",
    "promoted",
}
HEALTH_STATUSES = {"paused_healthy", "healthy_no_update_due", "updated", "reconciled"}
PUBLIC_UPDATE_CODES = {
    "approved_controls_invalid",
    "approved_signatures_invalid",
    "approved_daily_timestamp_invalid",
    "approved_daily_version_invalid",
    "approved_checkpoint_incomplete",
    "approved_checkpoint_invalid",
    "approved_rollback_must_differ",
    "approved_build_identity_invalid",
    "approved_source_identity_invalid",
    "approved_notification_channel_invalid",
    "approved_source_fingerprint_differs",
    "coordinator_state_invalid",
    "coordinator_current_pointer_invalid",
    "coordinator_source_invalid",
    "coordinator_source_changed",
    "coordinator_bundle_generation_invalid",
    "coordinator_attempts_invalid",
    "coordinator_active_checkpoint_invalid",
    "checkpoint_timestamp_invalid",
    "coordinator_generation_changed",
    "lease_owner_build_invalid",
    "lease_owner_build_unknown",
    "controller_bucket_differs",
    "controller_build_identity_invalid",
    "approved_application_source_changed",
    "live_job_changed_requires_approved_adoption",
    "current_database_future_dated",
    "checkpoint_file_name_invalid",
    "candidate_database_not_fresh_enough",
    "candidate_database_regressed",
    "image_build_failed",
    "submission_unknown_manual_reconciliation_required",
    "promotion_pending_requires_reconciliation",
    "active_campaign_phase_unsupported",
    "build_still_running_checkpoint_preserved",
    "current_database_stale",
    "owned_image_limit_reached",
    "daily_build_limit_reached",
    "monthly_build_limit_reached",
    "controller_build_id_required",
    "mutation_intent_missing",
    "unreconciled_cleanup_preserved",
    "ownership_ledger_limit_reached",
    "submission_reservation_period_changed",
    "image_publication_outcome_unknown",
}
PUBLIC_STATE_CODES = {
    "storage_generation_conflict",
    "storage_write_response_unknown",
    "storage_delete_response_unknown",
    "lease_not_owned",
    "lease_ownership_changed",
    "lease_owner_state_unknown",
    "storage_auth_unavailable",
    "storage_endpoint_invalid",
    "storage_generation_invalid",
    "storage_object_name_invalid",
    "storage_json_invalid",
    "storage_bucket_invalid",
    "storage_read_failed",
    "storage_object_size_invalid",
    "storage_exact_generation_unavailable",
    "storage_write_failed",
    "storage_delete_failed",
    "lease_owner_invalid",
    "lease_marker_invalid",
}
PUBLIC_RETENTION_CODES = {
    "ownership_ledger_invalid",
    "ownership_release_has_conflicting_digests",
    "inventory_not_fully_verified",
    "inventory_stale_or_future_dated",
    "protected_digests_invalid",
    "protected_digests_do_not_match_inventory",
    "cleanup_candidate_count_exceeds_bound",
    "cleanup_state_identity_invalid",
    "cleanup_state_time_bounds_invalid",
    "cleanup_state_baseline_invalid",
    "cleanup_state_selection_invalid",
    "cleanup_state_progress_invalid",
    "cleanup_state_invalid",
    "inventory_read_failed",
    "inventory_drift_before_further_deletion",
    "pending_digest_present_no_automatic_retry",
    "cleanup_plan_expired",
    "delete_outcome_uncertain",
}


class UpdateError(RuntimeError):
    """A fixed source-controlled public failure category."""


def public_failure_code(error: Exception) -> str:
    code = str(error)
    if isinstance(error, UpdateError) and code in PUBLIC_UPDATE_CODES:
        return code
    if isinstance(error, StateError):
        return code if code in PUBLIC_STATE_CODES else "private_state_guard_failed"
    if isinstance(error, auto_retention.RetentionError):
        return code if code in PUBLIC_RETENTION_CODES else "retention_guard_failed"
    if isinstance(error, maintenance.MaintenanceError):
        return "maintenance_protocol_guard_failed"
    return "controller_internal_failure"


def timestamp(value: Any) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        raise UpdateError("checkpoint_timestamp_invalid") from None


def integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _daily(controls: Any, module_sha: str) -> dict:
    expected_controls = {
        "clamav_clean",
        "clamav_eicar_detected",
        "yara_clean",
        "yara_eicar_detected",
    }
    if (
        not isinstance(controls, dict)
        or controls.get("success") is not True
        or controls.get("scope") != "offline_engine_controls"
        or not integer(controls.get("uid"))
        or controls["uid"] <= 0
        or controls.get("module_sha256") != module_sha
        or not isinstance(controls.get("controls"), dict)
        or set(controls["controls"]) != expected_controls
        or any(value is not True for value in controls["controls"].values())
    ):
        raise UpdateError("approved_controls_invalid")
    databases = controls.get("signed_databases")
    if (
        not isinstance(databases, list)
        or len(databases) != 3
        or {item.get("name") for item in databases} != {"main.cvd", "daily.cvd", "bytecode.cvd"}
        or any(item.get("signature_verified") is not True for item in databases)
    ):
        raise UpdateError("approved_signatures_invalid")
    daily = next(item for item in databases if item["name"] == "daily.cvd")
    if not integer(daily.get("created_at_epoch")) or daily["created_at_epoch"] <= 0:
        raise UpdateError("approved_daily_timestamp_invalid")
    if "version" in daily and (not integer(daily["version"]) or daily["version"] < 1):
        raise UpdateError("approved_daily_version_invalid")
    return daily


def _approved_files(files: Any) -> tuple[dict, dict, dict]:
    if (
        not isinstance(files, dict)
        or set(files) != FILES
        or not all(isinstance(v, dict) for v in files.values())
    ):
        raise UpdateError("approved_checkpoint_incomplete")
    state, baseline, build = files["state.json"], files["job-before.json"], files["build.json"]
    if (
        not integer(state.get("version"))
        or state["version"] != 1
        or state.get("project") != PROJECT
        or state.get("region") != REGION
        or state.get("job") != JOB
        or state.get("phase") != "promoted"
        or not re.fullmatch(maintenance.RELEASE_PATTERN, state.get("release", ""))
        or maintenance.fingerprint(maintenance.job_configuration(baseline))
        != state.get("baseline_fingerprint")
    ):
        raise UpdateError("approved_checkpoint_invalid")
    current = maintenance.immutable_image(state["candidate_image"])
    previous = maintenance.immutable_image(state["previous_image"])
    if current == previous:
        raise UpdateError("approved_rollback_must_differ")
    tag = maintenance.IMAGE + ":" + state["release"]
    images = build.get("results", {}).get("images", [])
    if (
        build.get("status") != "SUCCESS"
        or len(images) != 1
        or images[0].get("name") != tag
        or maintenance.IMAGE + "@" + str(images[0].get("digest")) != current
        or build.get("substitutions", {}).get("_RELEASE") != state["release"]
        or files["engine-controls.json"] != state.get("candidate_controls")
    ):
        raise UpdateError("approved_build_identity_invalid")
    daily = _daily(files["engine-controls.json"], state["controls_module_sha256"])
    return (
        state,
        maintenance.expected_configuration(maintenance.job_configuration(baseline), current),
        daily,
    )


def initial_state(
    maintenance_files: dict,
    source_commit: str,
    source_sha256: str,
    bundle_sha256: str,
    notification_channel: str,
) -> dict:
    """Create an unenabled registration from an already approved manual release."""
    for value, pattern in (
        (source_commit, r"[a-f0-9]{40}"),
        (source_sha256, r"[a-f0-9]{64}"),
        (bundle_sha256, r"[a-f0-9]{64}"),
    ):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise UpdateError("approved_source_identity_invalid")
    if not re.fullmatch(
        re.escape(f"projects/{PROJECT}/notificationChannels/") + r"[1-9][0-9]{0,31}",
        notification_channel,
    ):
        raise UpdateError("approved_notification_channel_invalid")
    saved, configuration, daily = _approved_files(maintenance_files)
    if saved.get("source_sha256") != source_sha256:
        raise UpdateError("approved_source_fingerprint_differs")
    return {
        "version": 1,
        "project": PROJECT,
        "region": REGION,
        "job": JOB,
        "enabled": False,
        "source": {
            "commit": source_commit,
            "sha256": source_sha256,
            "bundle_sha256": bundle_sha256,
        },
        "notification_channel": notification_channel,
        "policy": copy.deepcopy(POLICY),
        "current": {
            "image": saved["candidate_image"],
            "rollback_image": saved["previous_image"],
            "configuration": configuration,
            "files": copy.deepcopy(maintenance_files),
            "daily_created_at_epoch": daily["created_at_epoch"],
        },
        "active": None,
        "owned": [],
        "cleanup": None,
        "attempts": [],
        "last_healthy_at": None,
        "last_failure": None,
    }


def validate_state(value: Any, now: datetime | None = None) -> dict:
    if (
        not isinstance(value, dict)
        or not integer(value.get("version"))
        or value["version"] != 1
        or value.get("project") != PROJECT
        or value.get("region") != REGION
        or value.get("job") != JOB
        or not isinstance(value.get("enabled"), bool)
        or value.get("policy") != POLICY
    ):
        raise UpdateError("coordinator_state_invalid")
    current = value.get("current", {})
    saved, configuration, daily = _approved_files(current.get("files"))
    if (
        current.get("image") != saved["candidate_image"]
        or current.get("rollback_image") != saved["previous_image"]
        or current.get("configuration") != configuration
        or current.get("daily_created_at_epoch") != daily["created_at_epoch"]
    ):
        raise UpdateError("coordinator_current_pointer_invalid")
    source = value.get("source", {})
    for name, pattern in (
        ("commit", r"[a-f0-9]{40}"),
        ("sha256", r"[a-f0-9]{64}"),
        ("bundle_sha256", r"[a-f0-9]{64}"),
    ):
        if not isinstance(source.get(name), str) or not re.fullmatch(pattern, source[name]):
            raise UpdateError("coordinator_source_invalid")
    if source["sha256"] != saved.get("source_sha256"):
        raise UpdateError("coordinator_source_changed")
    stored = source.get("storage_source", {})
    if (
        set(stored) != {"bucket", "object", "generation"}
        or not isinstance(stored.get("bucket"), str)
        or stored.get("object") != f"bundles/{source['commit']}.tar.gz"
        or not isinstance(stored.get("generation"), str)
        or not re.fullmatch(r"[1-9][0-9]{0,18}", stored["generation"])
    ):
        raise UpdateError("coordinator_bundle_generation_invalid")
    auto_retention._ownership(value.get("owned"))
    attempts = value.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > 100:
        raise UpdateError("coordinator_attempts_invalid")
    releases = set()
    now = now or datetime.now(timezone.utc)
    for attempt in attempts:
        if (
            not isinstance(attempt, dict)
            or set(attempt) != {"release", "started_at"}
            or not re.fullmatch(maintenance.RELEASE_PATTERN, attempt["release"])
        ):
            raise UpdateError("coordinator_attempts_invalid")
        if attempt["release"] in releases or timestamp(attempt["started_at"]) > now:
            raise UpdateError("coordinator_attempts_invalid")
        releases.add(attempt["release"])
    if value.get("active") is not None:
        active = value["active"]
        if (
            not isinstance(active, dict)
            or set(active) != {"release", "files"}
            or not re.fullmatch(maintenance.RELEASE_PATTERN, active["release"])
            or not isinstance(active["files"], dict)
            or not {"state.json", "job-before.json"} <= set(active["files"]) <= FILES
            or not all(isinstance(item, dict) for item in active["files"].values())
            or active["files"]["state.json"].get("release") != active["release"]
            or active["files"]["state.json"].get("phase") not in PHASES
        ):
            raise UpdateError("coordinator_active_checkpoint_invalid")
    if value.get("last_healthy_at") is not None:
        timestamp(value["last_healthy_at"])
    if value.get("last_status") is not None and value["last_status"] not in HEALTH_STATUSES:
        raise UpdateError("coordinator_state_invalid")
    return value


def status_summary(state: dict) -> dict:
    current = state["current"]
    active = state.get("active")
    return {
        "scope": "scheduled_database_update",
        "enabled": state["enabled"],
        "current_image": current["image"],
        "rollback_image": current["rollback_image"],
        "phase": active["files"]["state.json"]["phase"] if active else "idle",
        "last_healthy_at": (
            timestamp(state["last_healthy_at"]).isoformat()
            if state.get("last_healthy_at")
            else None
        ),
        "last_status": state.get("last_status"),
        "cloud_run_executed": False,
    }


class _GuardedCloud:
    def __init__(self, controller):
        self.controller = controller

    def job(self):
        return self.controller.raw_cloud.job()

    def call(self, arguments, *, cwd=None):
        arguments = list(arguments)
        if arguments[:2] == ["builds", "submit"]:
            self.controller.before_write()
            active = self.controller.state.get("active")
            if (
                not active
                or active["files"]["state.json"].get("phase") != "submission_pending"
                or f"--substitutions=_RELEASE={active['release']}" not in arguments
            ):
                raise UpdateError("mutation_intent_missing")
            reservation = [
                item
                for item in self.controller.state["attempts"]
                if item["release"] == active["release"]
            ]
            if (
                len(reservation) != 1
                or timestamp(reservation[0]["started_at"]).date() != self.controller.now().date()
            ):
                raise UpdateError("submission_reservation_period_changed")
            arguments += [
                f"--service-account={BUILDER_ACCOUNT}",
                f"--gcs-source-staging-dir=gs://{self.controller.store.bucket}/build-sources",
            ]
        elif arguments[:3] == ["run", "jobs", "update"]:
            self.controller.before_write()
            active = self.controller.state.get("active")
            intent = active["files"]["state.json"] if active else {}
            if intent.get("phase") != "promotion_pending" or arguments != [
                "run",
                "jobs",
                "update",
                JOB,
                f"--region={REGION}",
                f"--image={intent.get('candidate_image')}",
            ]:
                raise UpdateError("mutation_intent_missing")
        return self.controller.raw_cloud.call(arguments, cwd=cwd)


class Controller:
    def __init__(
        self,
        store,
        owner_build_id: str,
        repository: Path,
        *,
        cloud=None,
        now=None,
        sleep=None,
        deadline_seconds=1500,
        inspect=None,
        delete=None,
    ):
        self.store = store
        self.owner_build_id = owner_build_id
        self.repository = repository.resolve()
        self.raw_cloud = cloud or maintenance.Gcloud()
        self.cloud = _GuardedCloud(self)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep or time.sleep
        self.deadline_seconds = deadline_seconds
        self.inspect_callback = inspect
        self.delete_callback = delete
        self.lease = Lease(store, owner_build_id)
        self.state = None
        self.generation = 0

    def before_write(self):
        self.lease.assert_owned()
        _, generation = self.store.load_json("state.json")
        if generation != self.generation:
            raise UpdateError("coordinator_generation_changed")

    def persist(self):
        self.before_write()
        self.generation = self.store.put_json("state.json", self.state, self.generation)

    def owner_terminal(self, owner):
        build = self.raw_cloud.call(["builds", "describe", owner, f"--region={REGION}"])
        if build.get("id") != owner:
            raise UpdateError("lease_owner_build_invalid")
        status = build.get("status")
        if status in TERMINAL:
            return True
        if status in {"QUEUED", "PENDING", "WORKING"}:
            return False
        raise UpdateError("lease_owner_build_unknown")

    def verify_parent(self):
        source = self.state["source"]["storage_source"]
        if source["bucket"] != self.store.bucket:
            raise UpdateError("controller_bucket_differs")
        build = self.raw_cloud.call(
            ["builds", "describe", self.owner_build_id, f"--region={REGION}"]
        )
        actual = build.get("source", {}).get("storageSource")
        resolved = build.get("sourceProvenance", {}).get("resolvedStorageSource")
        if (
            build.get("id") != self.owner_build_id
            or build.get("status") != "WORKING"
            or build.get("serviceAccount") != CONTROLLER_ACCOUNT
            or CONTROLLER_TAG not in build.get("tags", [])
            or actual != source
            or (resolved is not None and resolved != source)
        ):
            raise UpdateError("controller_build_identity_invalid")
        if maintenance.source_fingerprint(self.repository) != self.state["source"]["sha256"]:
            raise UpdateError("approved_application_source_changed")

    def live_current(self):
        job = self.raw_cloud.job()
        if not maintenance.job_ready(job) or not maintenance.configurations_equal(
            maintenance.job_configuration(job), self.state["current"]["configuration"]
        ):
            raise UpdateError("live_job_changed_requires_approved_adoption")
        return job

    def current_age(self):
        age = self.now().timestamp() - self.state["current"]["daily_created_at_epoch"]
        if age < 0:
            raise UpdateError("current_database_future_dated")
        return age

    def _capture(self, directory):
        return {
            name: maintenance.read_private(directory / name)
            for name in FILES
            if (directory / name).exists()
        }

    def _restore(self, directory, files):
        directory.mkdir(parents=True, mode=0o700)
        for name, value in files.items():
            if name not in FILES:
                raise UpdateError("checkpoint_file_name_invalid")
            maintenance.write_private(directory / name, value, exclusive=True)

    def _tool(self, root):
        active = self.state["active"]
        directory = root / active["release"]
        self._restore(directory, active["files"])
        controller = self

        class DurableMaintenance(maintenance.Maintenance):
            def save(self, state):
                if state.get("phase") == "submission_pending":
                    controller.reserve_submission(state["release"])
                super().save(state)
                controller.state["active"]["files"] = controller._capture(self.directory)
                controller.persist()

        return DurableMaintenance(directory, self.repository, self.cloud)

    def build_budget(self, attempts, now):
        if any(timestamp(item["started_at"]).date() == now.date() for item in attempts):
            raise UpdateError("daily_build_limit_reached")
        if (
            sum(
                timestamp(item["started_at"]).strftime("%Y-%m") == now.strftime("%Y-%m")
                for item in attempts
            )
            >= POLICY["monthly_build_limit"]
        ):
            raise UpdateError("monthly_build_limit_reached")

    def reserve_submission(self, release):
        """Move a prepared reservation to this UTC day before persisting intent.

        A saved pending submission is reconciled without moving its reservation;
        only prepared campaigns can arrive here again after interruption.
        """
        now = self.now()
        others = [
            item
            for item in self.state["attempts"]
            if item["release"] != release
            and now - timestamp(item["started_at"]) <= timedelta(days=35)
        ]
        self.build_budget(others, now)
        self.state["attempts"] = others + [{"release": release, "started_at": now.isoformat()}]

    def _inventory(self, root):
        if self.inspect_callback is not None:
            return self.inspect_callback()
        home = root / "inventory-home"
        files = self.state["current"]["files"]
        directory = home / ".malscan-v2-operations" / "maintenance" / files["state.json"]["release"]
        self._restore(directory, files)
        return inventory.Inspector(home=home).inspect()

    def cleanup(self, root):
        def inspect():
            # Inspector restores only one matching promoted checkpoint each time.
            with tempfile.TemporaryDirectory(prefix="malscan-auto-inventory-") as tmp:
                return self._inventory(Path(tmp))

        def delete(uri):
            self.before_write()
            intent = self.state.get("cleanup") or {}
            if intent.get("phase") != "deletion_pending" or intent.get("pending") != uri:
                raise UpdateError("mutation_intent_missing")
            if self.delete_callback is not None:
                return self.delete_callback(uri)
            return auto_retention.prune.delete_image(uri)

        def save(state):
            self.state["cleanup"] = state
            self.persist()

        if self.state["cleanup"] and self.state["cleanup"].get("phase") == "completed":
            self.state["cleanup"] = None
            self.persist()
        result = auto_retention.run(
            inspect,
            delete,
            save,
            self.state["owned"],
            self.state["current"]["image"],
            self.state["current"]["rollback_image"],
            state=self.state["cleanup"],
        )
        self.state["last_cleanup_summary"] = result["summary"]
        self.persist()
        return auto_retention.live_owned_count(inspect(), self.state["owned"])

    def _owned(self, candidate, release):
        item = {"digest": candidate, "release": release}
        if item not in self.state["owned"]:
            if self.state["cleanup"]:
                if self.state["cleanup"].get("phase") != "completed":
                    raise UpdateError("unreconciled_cleanup_preserved")
                # A plan binds the whole ledger. Only a completed plan may be
                # retired before this newly verified ownership changes it.
                self.state["cleanup"] = None
            if len(self.state["owned"]) >= auto_retention.MAX_OWNERSHIP_RECORDS:
                raise UpdateError("ownership_ledger_limit_reached")
            self.state["owned"].append(item)
            self.persist()

    def _finish(self, tool):
        saved = tool.load()
        controls = saved["candidate_controls"]
        daily = _daily(controls, saved["controls_module_sha256"])
        if (
            not 0
            <= self.now().timestamp() - daily["created_at_epoch"]
            <= POLICY["max_candidate_age_seconds"]
        ):
            raise UpdateError("candidate_database_not_fresh_enough")
        previous_daily = _daily(
            self.state["current"]["files"]["engine-controls.json"], saved["controls_module_sha256"]
        )
        if daily["created_at_epoch"] < previous_daily["created_at_epoch"] or (
            "version" in daily
            and "version" in previous_daily
            and daily["version"] < previous_daily["version"]
        ):
            raise UpdateError("candidate_database_regressed")
        if self.state["cleanup"] and self.state["cleanup"].get("phase") != "completed":
            raise UpdateError("unreconciled_cleanup_preserved")
        if saved["candidate_image"] != self.state["current"]["image"]:
            _, configuration, _ = _approved_files(self._capture(tool.directory))
            self.state["current"] = {
                "image": saved["candidate_image"],
                "rollback_image": saved["previous_image"],
                "configuration": configuration,
                "files": self._capture(tool.directory),
                "daily_created_at_epoch": daily["created_at_epoch"],
            }
        # Same immutable digest retains the genuine previous rollback checkpoint.
        self.state["active"] = None
        self.state["cleanup"] = None
        self.persist()

    def process(self, root):
        tool = self._tool(root)
        started = time.monotonic()
        while True:
            saved = tool.load()
            phase = saved["phase"]
            if phase == "prepared":
                self.live_current()
                tool.submit()
                continue
            if phase in {
                "submission_pending",
                "submission_unknown",
                "build_submitted",
                "promotion_pending",
            }:
                saved = tool.status()
                phase = saved["phase"]
            if phase == "build_failed":
                build = self._capture(tool.directory).get("build.json", {})
                steps = build.get("steps", [])
                # The images publication phase runs after both offline steps.
                # A terminal overall failure after both steps succeeded can
                # still have published an image; preserve its campaign rather
                # than losing ownership and spending another build tomorrow.
                failed_before_publication = len(steps) == 2 and any(
                    item.get("status") in {"FAILURE", "CANCELLED", "TIMEOUT", "INTERNAL_ERROR"}
                    for item in steps
                )
                if not failed_before_publication:
                    raise UpdateError("image_publication_outcome_unknown")
                self.state["last_failure"] = {
                    "code": "image_build_failed",
                    "release": saved["release"],
                    "at": self.now().isoformat(),
                }
                self.state["active"] = None
                self.persist()
                raise UpdateError("image_build_failed")
            if phase == "submission_unknown":
                raise UpdateError("submission_unknown_manual_reconciliation_required")
            if phase == "build_verified":
                self._owned(saved["candidate_image"], saved["release"])
                daily = _daily(saved["candidate_controls"], saved["controls_module_sha256"])
                if (
                    not 0
                    <= self.now().timestamp() - daily["created_at_epoch"]
                    <= POLICY["max_candidate_age_seconds"]
                ):
                    raise UpdateError("candidate_database_not_fresh_enough")
                previous = _daily(
                    self.state["current"]["files"]["engine-controls.json"],
                    saved["controls_module_sha256"],
                )
                if daily["created_at_epoch"] < previous["created_at_epoch"] or daily.get(
                    "version", 0
                ) < previous.get("version", 0):
                    raise UpdateError("candidate_database_regressed")
                if saved["candidate_image"] == self.state["current"]["image"]:
                    self.state["active"] = None
                    self.persist()
                    return
                self.live_current()
                tool.update_image()
                continue
            if phase == "promoted":
                self._finish(tool)
                return
            if phase == "promotion_pending":
                raise UpdateError("promotion_pending_requires_reconciliation")
            if phase != "build_submitted":
                raise UpdateError("active_campaign_phase_unsupported")
            if time.monotonic() - started >= self.deadline_seconds:
                raise UpdateError("build_still_running_checkpoint_preserved")
            self.sleep(15)

    def healthy(self, status):
        self.live_current()
        if self.current_age() > 604800:
            raise UpdateError("current_database_stale")
        self.state["last_healthy_at"] = self.now().isoformat()
        self.state["last_controller_build_id"] = self.owner_build_id
        self.state["last_status"] = status
        self.state["last_failure"] = None
        self.persist()
        return {**status_summary(self.state), "status": status, "marker": HEALTHY_MARKER}

    def run(self):
        value, self.generation = self.store.load_json("state.json")
        self.state = validate_state(value, self.now())
        self.verify_parent()
        if not self.lease.acquire(self.owner_terminal):
            return {
                "scope": "scheduled_database_update",
                "status": "busy",
                "cloud_run_executed": False,
            }
        try:
            # Reload after acquiring ownership; another terminal owner may have
            # completed its last save between our initial read and acquisition.
            value, self.generation = self.store.load_json("state.json")
            self.state = validate_state(value, self.now())
            self.verify_parent()
            if not self.state["enabled"]:
                if self.state["active"]:
                    return {**status_summary(self.state), "status": "paused_campaign_preserved"}
                return self.healthy("paused_healthy")
            with tempfile.TemporaryDirectory(prefix="malscan-auto-maintenance-") as temporary:
                root = Path(temporary)
                resumed = bool(self.state["active"])
                if resumed:
                    self.process(root)
                self.live_current()
                live_count = self.cleanup(root)
                if resumed:
                    return self.healthy("reconciled")
                if self.current_age() < POLICY["refresh_after_seconds"]:
                    return self.healthy("healthy_no_update_due")
                if live_count >= POLICY["max_live_owned"]:
                    raise UpdateError("owned_image_limit_reached")
                now = self.now()
                attempts = [
                    a
                    for a in self.state["attempts"]
                    if now - timestamp(a["started_at"]) <= timedelta(days=35)
                ]
                self.build_budget(attempts, now)
                release = "db-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
                directory = root / release
                tool = maintenance.Maintenance(directory, self.repository, self.cloud)
                tool.prepare()
                self.state["attempts"] = attempts + [
                    {"release": release, "started_at": now.isoformat()}
                ]
                self.state["active"] = {"release": release, "files": self._capture(directory)}
                self.persist()
                # Recreate through the durable subclass outside the upload tree.
                with tempfile.TemporaryDirectory(prefix="malscan-auto-campaign-") as active_root:
                    self.process(Path(active_root))
                self.cleanup(root)
                return self.healthy("updated")
        except Exception as error:
            # Lost CAS/lease responses must not be overwritten by error handling.
            try:
                self.before_write()
                self.state["last_failure"] = {
                    "code": public_failure_code(error),
                    "at": self.now().isoformat(),
                }
                self.persist()
            except Exception:
                pass
            raise
        finally:
            self.lease.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "status"))
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--owner-build-id")
    args = parser.parse_args()
    try:
        store = Store(args.bucket)
        if args.operation == "status":
            state, _ = store.load_json("state.json")
            result = status_summary(validate_state(state))
        else:
            if not args.owner_build_id:
                raise UpdateError("controller_build_id_required")
            result = Controller(
                store, args.owner_build_id, Path(__file__).resolve().parents[2]
            ).run()
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # Provider messages and checkpoint values must never reach public logs.
        print(
            json.dumps(
                {
                    "scope": "scheduled_database_update",
                    "status": "failed",
                    "code": public_failure_code(error),
                    "reason_code": public_failure_code(error),
                    "marker": FAILURE_MARKER,
                    "cloud_run_executed": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
