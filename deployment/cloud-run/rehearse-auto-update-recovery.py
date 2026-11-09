#!/usr/bin/env python3
"""Guard one natural update interruption and resume its existing candidate.

Prepare writes only a private local sidecar. Watch can cancel one precisely bound
maintenance controller; resume can create one original-source controller. Neither
operation edits coordinator state, leases, Scheduler settings or the source bundle.
Unknown writes are read back, never repeated. The resumed controller performs its
normal guarded maintenance, including its existing bounded cleanup policy.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


setup = module("recovery_setup", "setup-auto-update.py")
runtime = module("recovery_runtime", "auto_runtime.py")
observation = module("recovery_observation", "inspect-auto-update.py")
notification = module("recovery_source_proof", "test-auto-update-notification.py")
private = module("recovery_private", "maintain-demo.py")
auto = module("recovery_controller", "auto_update.py")
PROJECT, REGION = setup.PROJECT, setup.REGION
BASE = f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/builds"
SCOPE = "guarded_update_recovery_rehearsal"
PHASES = {
    "prepared",
    "armed",
    "cancel_pending",
    "interrupted",
    "resume_pending",
    "resume_submitted",
    "recovered",
    "missed_window",
}
MAX_WAIT_SECONDS = 900
POLL_SECONDS = 5
MAX_CANDIDATE_AGE_SECONDS = 90
ACTIVE_PHASES = {"build_submitted", "build_verified", "promotion_pending", "promoted"}


class RehearsalError(RuntimeError):
    """Fixed public categories; provider text and private payloads stay private."""


def require(condition, code):
    if not condition:
        raise RehearsalError(code)


def utc_now():
    return datetime.now(timezone.utc)


def valid_id(value):
    return observation.canonical_uuid(value) and uuid.UUID(value).int != 0


def next_tick(after):
    for day in range(5):
        date = after + timedelta(days=day)
        for hour in (3, 15):
            candidate = date.replace(hour=hour, minute=23, second=0, microsecond=0)
            if candidate >= after:
                return candidate
    raise RehearsalError("recovery_target_tick_unavailable")


class Rehearsal:
    def __init__(self, tool, *, now=None, sleep=None, progress=None):
        self.tool = tool
        self.path = tool.directory / "recovery-rehearsal.json"
        self.now = now or utc_now
        self.sleep = sleep or time.sleep
        self.progress = progress or (lambda report: None)

    def request(self, tag):
        result = self.tool.build_request()
        result["tags"].append(tag)
        result["queueTtl"] = "300s"
        return result

    def source_proof(self):
        try:
            notification.NotificationTest(self.tool).source_proof()
        except Exception:
            raise RehearsalError("recovery_approved_source_not_verified") from None

    def save(self, record, *, exclusive=False):
        record["updated_at"] = self.now().isoformat()
        private.write_private(self.path, record, exclusive=exclusive)

    def load(self):
        try:
            record = private.read_private(self.path)
            require(isinstance(record, dict), "recovery_checkpoint_invalid")
            tag = record.get("request_tag")
            require(
                setup.integer(record.get("version"))
                and record["version"] == 1
                and record.get("scope") == SCOPE
                and record.get("plan_sha256") == setup.digest(self.tool.plan)
                and record.get("phase") in PHASES
                and isinstance(tag, str)
                and re.fullmatch(r"malscan-db-recovery-[a-f0-9]{32}", tag)
                and record.get("request") == self.request(tag)
                and record.get("request_sha256") == setup.digest(record["request"]),
                "recovery_checkpoint_invalid",
            )
            baseline = record["baseline"]
            require(
                isinstance(baseline, dict)
                and set(baseline)
                == {
                    "image",
                    "rollback_image",
                    "configuration_sha256",
                    "source_sha256",
                    "daily_epoch",
                },
                "recovery_checkpoint_invalid",
            )
            for key in ("image", "rollback_image"):
                private.immutable_image(baseline[key])
            require(baseline["image"] != baseline["rollback_image"], "recovery_checkpoint_invalid")
            for key in ("configuration_sha256", "source_sha256"):
                require(
                    isinstance(baseline[key], str) and re.fullmatch(r"[a-f0-9]{64}", baseline[key]),
                    "recovery_checkpoint_invalid",
                )
            require(
                setup.integer(baseline["daily_epoch"]) and baseline["daily_epoch"] > 0,
                "recovery_checkpoint_invalid",
            )
            prepared = observation.timestamp(record["prepared_at"])
            updated = observation.timestamp(record["updated_at"])
            require(
                baseline["daily_epoch"] <= prepared.timestamp()
                and prepared <= updated <= self.now() + timedelta(minutes=5),
                "recovery_checkpoint_invalid",
            )
            target = next_tick(
                max(
                    prepared,
                    datetime.fromtimestamp(baseline["daily_epoch"], timezone.utc)
                    + timedelta(seconds=auto.POLICY["refresh_after_seconds"]),
                )
            )
            require(target >= prepared + timedelta(minutes=5), "recovery_checkpoint_invalid")
            for key, expected in (
                ("target_tick_at", target),
                ("window_start_at", target - timedelta(minutes=5)),
                ("window_end_at", target + timedelta(minutes=20)),
            ):
                require(
                    observation.timestamp(record[key]) == expected, "recovery_checkpoint_invalid"
                )
                record[key] = expected.isoformat()
            for key in (
                "armed_at",
                "cancel_intent_at",
                "resume_intent_at",
                "user_reconnected_at",
                "recovered_at",
            ):
                if key in record:
                    record[key] = observation.timestamp(record[key]).isoformat()
                    require(
                        prepared <= observation.timestamp(record[key]) <= updated,
                        "recovery_checkpoint_invalid",
                    )
            require(prepared <= self.now() + timedelta(minutes=5), "recovery_checkpoint_invalid")
            if record["phase"] == "prepared":
                require(
                    not any(
                        key in record
                        for key in (
                            "armed_at",
                            "cancel_intent_at",
                            "resume_intent_at",
                            "parent_build_id",
                            "candidate_build_id",
                            "resume_build_id",
                            "release",
                            "candidate_image",
                            "user_reconnected_at",
                            "recovered_at",
                        )
                    ),
                    "recovery_checkpoint_invalid",
                )
            else:
                require("armed_at" in record, "recovery_checkpoint_invalid")
                armed = observation.timestamp(record["armed_at"])
                require(
                    prepared <= armed
                    and target - timedelta(minutes=5) <= armed < target + timedelta(minutes=20),
                    "recovery_checkpoint_invalid",
                )
            if record["phase"] == "armed":
                require(
                    not any(
                        key in record
                        for key in (
                            "cancel_intent_at",
                            "resume_intent_at",
                            "parent_build_id",
                            "candidate_build_id",
                            "resume_build_id",
                            "release",
                            "candidate_image",
                            "user_reconnected_at",
                            "recovered_at",
                        )
                    ),
                    "recovery_checkpoint_invalid",
                )
            for key in ("parent_build_id", "candidate_build_id", "resume_build_id"):
                if key in record:
                    require(valid_id(record[key]), "recovery_checkpoint_invalid")
            if "release" in record:
                require(
                    isinstance(record["release"], str)
                    and re.fullmatch(private.RELEASE_PATTERN, record["release"]),
                    "recovery_checkpoint_invalid",
                )
            if record["phase"] not in {"prepared", "armed"}:
                require(
                    all(
                        key in record
                        for key in (
                            "armed_at",
                            "cancel_intent_at",
                            "parent_build_id",
                            "candidate_build_id",
                            "release",
                        )
                    )
                    and record["parent_build_id"] != record["candidate_build_id"],
                    "recovery_checkpoint_invalid",
                )
            if record["phase"] in {"resume_pending", "resume_submitted", "recovered"}:
                require(
                    "resume_intent_at" in record and "user_reconnected_at" in record,
                    "recovery_checkpoint_invalid",
                )
            else:
                require(
                    not any(
                        key in record
                        for key in ("resume_intent_at", "resume_build_id", "user_reconnected_at")
                    ),
                    "recovery_checkpoint_invalid",
                )
            if record["phase"] == "resume_pending":
                require("resume_build_id" not in record, "recovery_checkpoint_invalid")
            if record["phase"] != "recovered":
                require(
                    "candidate_image" not in record and "recovered_at" not in record,
                    "recovery_checkpoint_invalid",
                )
            if record["phase"] in {"resume_submitted", "recovered"}:
                require("resume_build_id" in record, "recovery_checkpoint_invalid")
            if "cancel_intent_at" in record:
                cancelled = observation.timestamp(record["cancel_intent_at"])
                require(
                    armed <= cancelled < target + timedelta(minutes=20),
                    "recovery_checkpoint_invalid",
                )
            if "resume_intent_at" in record:
                require(
                    cancelled
                    <= observation.timestamp(record["user_reconnected_at"])
                    <= observation.timestamp(record["resume_intent_at"]),
                    "recovery_checkpoint_invalid",
                )
            ids = [
                record[key]
                for key in ("parent_build_id", "candidate_build_id", "resume_build_id")
                if key in record
            ]
            require(len(ids) == len(set(ids)), "recovery_checkpoint_invalid")
            if "candidate_image" in record:
                private.immutable_image(record["candidate_image"])
            if record["phase"] == "recovered":
                require(
                    "candidate_image" in record
                    and "recovered_at" in record
                    and observation.timestamp(record["recovered_at"])
                    >= observation.timestamp(record["resume_intent_at"]),
                    "recovery_checkpoint_invalid",
                )
            return record
        except RehearsalError:
            raise
        except Exception:
            raise RehearsalError("recovery_checkpoint_invalid") from None

    def summary(self, record):
        target = observation.timestamp(record["target_tick_at"])
        taipei = timezone(timedelta(hours=8))
        return {
            "scope": SCOPE,
            "phase": record["phase"],
            "target_tick_at": record["target_tick_at"],
            "target_tick_at_taipei": target.astimezone(taipei).isoformat(),
            "recommended_watch_at_taipei": (target - timedelta(minutes=3))
            .astimezone(taipei)
            .isoformat(),
            "window_start_at": record["window_start_at"],
            "window_end_at": record["window_end_at"],
            "window_has_passed": self.now() >= observation.timestamp(record["window_end_at"]),
            "parent_build_id": record.get("parent_build_id"),
            "candidate_build_id": record.get("candidate_build_id"),
            "resume_build_id": record.get("resume_build_id"),
            "release": record.get("release"),
            "baseline_image": record["baseline"]["image"],
            "baseline_rollback_image": record["baseline"]["rollback_image"],
            "candidate_image": record.get("candidate_image"),
            "recovered_at": record.get("recovered_at"),
            "recovery_verified": record["phase"] == "recovered",
            "user_reconnected_at": record.get("user_reconnected_at"),
            "reconnect_evidence": "explicit_user_confirmation"
            if record.get("user_reconnected_at")
            else "not_observed",
            "candidate_build_reused": record["phase"] == "recovered",
            "automatic_write_resubmission": False,
            "cloud_run_executed": False,
            "coordinator_state_or_lease_mutated_directly_by_tool": False,
            "scheduler_or_alerts_changed_by_tool": False,
            "original_plan_source_or_journal_changed_by_tool": False,
            "maximum_extra_controller_builds": 1,
            "resumed_controller_runs_normal_maintenance_and_bounded_cleanup": True,
        }

    def state(self, *, current=False):
        try:
            return self.tool._approved_state(check_current=current)
        except Exception:
            raise RehearsalError("recovery_registered_state_not_verified") from None

    def scheduler(self, *, quiet=False):
        expected = self.tool.scheduler_document()
        actual = self.tool.get("https://cloudscheduler.googleapis.com/v1/" + expected["name"])
        require(
            isinstance(actual, dict)
            and actual.get("state") == "ENABLED"
            and setup.subset(expected, setup.normalized_scheduler(actual)),
            "recovery_scheduler_not_verified",
        )
        if quiet:
            require(
                observation.timestamp(actual.get("scheduleTime"))
                > self.now() + timedelta(minutes=30),
                "recovery_resume_scheduler_window_too_close",
            )

    def baseline_matches(self, record, state):
        baseline = record["baseline"]
        require(
            state["enabled"]
            and state["current"]["image"] == baseline["image"]
            and state["current"]["rollback_image"] == baseline["rollback_image"]
            and setup.digest(
                private.configuration_for_comparison(state["current"]["configuration"])
            )
            == baseline["configuration_sha256"]
            and setup.digest(state["source"]) == baseline["source_sha256"],
            "recovery_baseline_changed",
        )
        require(
            state["current"]["daily_created_at_epoch"] == baseline["daily_epoch"],
            "recovery_baseline_changed",
        )

    def prepare(self):
        with private.operation_lock(self.tool.directory):
            if self.path.exists():
                return self.summary(self.load())
            self.source_proof()
            report = observation.inspect(self.tool, now=self.now())
            require(
                report["read_complete"]
                and report["enabled_monitoring_metadata_matches_plan"]
                and report["healthy_metric_ingestion_verified"],
                "recovery_monitoring_not_ready",
            )
            state, _ = self.state(current=True)
            require(
                0
                <= (
                    self.now() - observation.timestamp(state.get("last_healthy_at"))
                ).total_seconds()
                <= 82800,
                "recovery_recent_health_not_verified",
            )
            lease, _ = self.tool.store.load_json("lease.json")
            require(
                state["enabled"] and state["active"] is None and lease is None,
                "recovery_prepare_requires_idle_state",
            )
            prepared = self.now()
            epoch = state["current"]["daily_created_at_epoch"]
            target = next_tick(
                max(
                    prepared,
                    datetime.fromtimestamp(epoch, timezone.utc)
                    + timedelta(seconds=auto.POLICY["refresh_after_seconds"]),
                )
            )
            require(
                target >= prepared + timedelta(minutes=5),
                "recovery_prepare_too_close_to_due_tick",
            )
            tag = "malscan-db-recovery-" + uuid.uuid4().hex
            request = self.request(tag)
            record = {
                "version": 1,
                "scope": SCOPE,
                "phase": "prepared",
                "plan_sha256": setup.digest(self.tool.plan),
                "prepared_at": prepared.isoformat(),
                "target_tick_at": target.isoformat(),
                "window_start_at": (target - timedelta(minutes=5)).isoformat(),
                "window_end_at": (target + timedelta(minutes=20)).isoformat(),
                "request_tag": tag,
                "request": request,
                "request_sha256": setup.digest(request),
                "baseline": {
                    "image": state["current"]["image"],
                    "rollback_image": state["current"]["rollback_image"],
                    "configuration_sha256": setup.digest(
                        private.configuration_for_comparison(state["current"]["configuration"])
                    ),
                    "source_sha256": setup.digest(state["source"]),
                    "daily_epoch": epoch,
                },
            }
            self.save(record, exclusive=True)
            return self.summary(record)

    def build(self, build_id):
        require(valid_id(build_id), "recovery_build_id_invalid")
        result = self.tool.get(BASE + "/" + build_id)
        require(
            isinstance(result, dict) and result.get("id") == build_id,
            "recovery_build_not_observed",
        )
        return result

    def parent(self, record):
        result = self.build(record["parent_build_id"])
        require(
            runtime.build_matches(self.tool.build_request(), result),
            "recovery_parent_request_differs",
        )
        return result

    def candidate(self, record):
        result = self.build(record["candidate_build_id"])
        require(
            result.get("serviceAccount") == auto.BUILDER_ACCOUNT
            and result.get("substitutions", {}).get("_RELEASE") == record["release"],
            "recovery_candidate_identity_differs",
        )
        source = result.get("source", {}).get("storageSource", {})
        name = source.get("object") if isinstance(source, dict) else None
        require(
            isinstance(source, dict)
            and source.get("bucket") == self.tool.plan["bucket"]
            and isinstance(name, str)
            and re.fullmatch(r"build-sources/[A-Za-z0-9._/-]{1,1024}", name)
            and all(part not in {"", ".", ".."} for part in name.split("/")),
            "recovery_candidate_source_differs",
        )

        # BuildStep.status is only populated at completion, so use overall status
        # for progress and reuse the pure exact-definition validator with a copy.
        def resolve(value):
            if isinstance(value, str):
                replacements = {"_RELEASE": record["release"], "PROJECT_ID": PROJECT}
                return re.sub(
                    r"\$\{(_RELEASE|PROJECT_ID)\}|\$(_RELEASE|PROJECT_ID)(?![A-Za-z0-9_])",
                    lambda match: replacements[match.group(1) or match.group(2)],
                    value,
                )
            if isinstance(value, list):
                return [resolve(child) for child in value]
            if isinstance(value, dict):
                return {key: resolve(child) for key, child in value.items()}
            return value

        definition = resolve(copy.deepcopy(result))
        if result.get("status") != "SUCCESS":
            for step in definition.get("steps", []):
                if isinstance(step, dict):
                    step["status"] = "SUCCESS"
        try:
            observation.current_release_steps(
                definition, {"release": record["release"]}, private.IMAGE
            )
        except Exception:
            raise RehearsalError("recovery_candidate_steps_differ") from None
        return result

    def active(self, record, state):
        self.baseline_matches(record, state)
        active = state.get("active")
        require(
            isinstance(active, dict) and active.get("release") == record["release"],
            "recovery_active_campaign_changed",
        )
        files = active["files"]
        saved = files["state.json"]
        require(
            saved.get("phase") in ACTIVE_PHASES
            and saved.get("build_id") == record["candidate_build_id"]
            and saved.get("source_sha256") == self.tool.plan["source_sha256"]
            and saved.get("previous_image") == record["baseline"]["image"]
            and saved.get("baseline_fingerprint")
            == private.fingerprint(private.job_configuration(files["job-before.json"]))
            and private.configurations_equal(
                state["current"]["configuration"],
                private.job_configuration(files["job-before.json"]),
            ),
            "recovery_active_checkpoint_differs",
        )
        return saved

    def lease(self, parent_id):
        value, _ = self.tool.store.load_json("lease.json")
        if value is not None:
            require(
                isinstance(value, dict)
                and setup.integer(value.get("schema_version"))
                and value == {"schema_version": 1, "owner_build_id": parent_id},
                "recovery_competing_controller_lease",
            )
        return value

    def capture(self, record):
        state, _ = self.state(current=True)
        self.baseline_matches(record, state)
        active = state.get("active")
        if active is None:
            return None
        saved = active["files"]["state.json"]
        if saved.get("phase") != "build_submitted":
            return None
        lease, _ = self.tool.store.load_json("lease.json")
        require(isinstance(lease, dict), "recovery_controller_lease_not_observed")
        parent_id = lease.get("owner_build_id")
        require(
            setup.integer(lease.get("schema_version"))
            and lease == {"schema_version": 1, "owner_build_id": parent_id},
            "recovery_controller_lease_not_verified",
        )
        candidate_id = saved.get("build_id")
        require(
            valid_id(parent_id) and valid_id(candidate_id) and parent_id != candidate_id,
            "recovery_candidate_or_parent_identity_invalid",
        )
        bound = {
            **record,
            "parent_build_id": parent_id,
            "candidate_build_id": candidate_id,
            "release": active["release"],
        }
        self.active(bound, state)
        parent, candidate = self.parent(bound), self.candidate(bound)
        armed = observation.timestamp(record["armed_at"])
        created = observation.timestamp(candidate.get("createTime"))
        require(
            parent.get("status") == "WORKING"
            and armed <= observation.timestamp(parent.get("createTime")) <= self.now()
            and created >= armed
            and 0 <= (self.now() - created).total_seconds() <= MAX_CANDIDATE_AGE_SECONDS,
            "recovery_candidate_not_in_interrupt_window",
        )
        if candidate.get("status") in {"QUEUED", "PENDING"}:
            return None
        require(candidate.get("status") == "WORKING", "recovery_candidate_not_in_interrupt_window")
        return bound

    def watch_and_interrupt(self, *, wait_seconds=MAX_WAIT_SECONDS):
        require(
            setup.integer(wait_seconds) and 0 <= wait_seconds <= MAX_WAIT_SECONDS,
            "recovery_watch_duration_invalid",
        )
        with private.operation_lock(self.tool.directory):
            record = self.load()
            if record["phase"] not in {"prepared", "armed"}:
                return self._status(record)
            now = self.now()
            require(
                observation.timestamp(record["window_start_at"])
                <= now
                < observation.timestamp(record["window_end_at"]),
                "recovery_watch_outside_planned_window",
            )
            self.source_proof()
            self.scheduler()
            if record["phase"] == "prepared":
                record.update(phase="armed", armed_at=now.isoformat())
                self.save(record)
            self.progress(
                {
                    "scope": SCOPE,
                    "phase": "armed",
                    "waiting_for_natural_candidate": True,
                    "polling_wait_limit_seconds": wait_seconds,
                    "cancel_intent_saved": False,
                }
            )
            deadline = time.monotonic() + wait_seconds
            while True:
                require(
                    self.now() < observation.timestamp(record["window_end_at"]),
                    "recovery_watch_window_expired",
                )
                bound = self.capture(record)
                if bound:
                    # Repeat critical reads immediately before the one cancellation.
                    self.source_proof()
                    self.scheduler()
                    require(self.capture(record) == bound, "recovery_capture_changed")
                    require(
                        self.now() < observation.timestamp(record["window_end_at"]),
                        "recovery_watch_window_expired",
                    )
                    record = bound
                    record.update(phase="cancel_pending", cancel_intent_at=self.now().isoformat())
                    self.save(record)
                    name = (
                        f"projects/{PROJECT}/locations/{REGION}/builds/{record['parent_build_id']}"
                    )
                    try:
                        self.tool.rest.request(
                            "POST",
                            BASE + "/" + record["parent_build_id"] + ":cancel",
                            {"name": name, "projectId": PROJECT, "id": record["parent_build_id"]},
                        )
                    except Exception:
                        raise RehearsalError("recovery_cancel_outcome_unknown") from None
                    return self._status(record)
                if time.monotonic() >= deadline:
                    return self.summary(record)
                self.sleep(min(POLL_SECONDS, max(0, deadline - time.monotonic())))

    def allowed_live_job(self, record, state, candidate):
        expected = state["current"]["configuration"]
        job = self.tool.live_job()
        require(private.job_ready(job), "recovery_live_job_not_ready")
        actual = private.job_configuration(job)
        if private.configurations_equal(expected, actual):
            return
        saved = self.active(record, state)
        require(
            saved["phase"] in {"promotion_pending", "promoted"}
            and candidate.get("status") == "SUCCESS",
            "recovery_live_job_configuration_changed",
        )
        images = candidate.get("results", {}).get("images", [])
        require(len(images) == 1, "recovery_candidate_result_invalid")
        image = private.immutable_image(private.IMAGE + "@" + str(images[0].get("digest")))
        require(
            saved.get("candidate_image") == image
            and private.configurations_equal(
                private.expected_configuration(expected, image), actual
            ),
            "recovery_live_job_configuration_changed",
        )

    def _resolve_resume(self, record):
        if not record.get("resume_build_id"):
            found = self.tool.get(
                BASE + "?" + urlencode({"filter": "tags=" + record["request_tag"], "pageSize": 100})
            )
            require(
                isinstance(found, dict) and not found.get("nextPageToken"),
                "recovery_resume_lookup_incomplete",
            )
            matches = [
                b for b in found.get("builds", []) if record["request_tag"] in b.get("tags", [])
            ]
            require(
                len(matches) == 1 and runtime.build_matches(record["request"], matches[0]),
                "recovery_resume_unknown_no_resubmit",
            )
            record.update(resume_build_id=matches[0]["id"], phase="resume_submitted")
            self.save(record)
        result = self.build(record["resume_build_id"])
        require(runtime.build_matches(record["request"], result), "recovery_resume_request_differs")
        return result

    def healthy_marker(self, record, image):
        start = observation.timestamp(record["resume_intent_at"]) - timedelta(minutes=5)
        end = self.now() + timedelta(minutes=5)
        query = {
            "resourceNames": ["projects/" + PROJECT],
            "pageSize": 100,
            "orderBy": "timestamp desc",
            "filter": (
                f'resource.type="build" AND resource.labels.project_id="{PROJECT}" '
                f'AND resource.labels.build_id="{record["resume_build_id"]}" '
                f'AND timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" '
                f'AND (textPayload:"{auto.HEALTHY_MARKER}" '
                f'OR jsonPayload.marker="{auto.HEALTHY_MARKER}")'
            ),
        }
        tokens = set()
        for _ in range(5):
            data = self.tool.rest.request(
                "POST", "https://logging.googleapis.com/v2/entries:list", query
            )
            require(isinstance(data, dict), "recovery_marker_read_incomplete")
            entries = data.get("entries", [])
            require(
                isinstance(entries, list) and len(entries) <= 100,
                "recovery_marker_response_invalid",
            )
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                resource = entry.get("resource", {})
                if not isinstance(resource, dict) or resource.get("type") != "build":
                    continue
                labels = resource.get("labels", {})
                if (
                    not isinstance(labels, dict)
                    or labels.get("project_id") != PROJECT
                    or labels.get("build_id") != record["resume_build_id"]
                ):
                    continue
                try:
                    if not start <= observation.timestamp(entry.get("timestamp")) <= end:
                        continue
                except Exception:
                    continue
                payloads = [entry.get("jsonPayload")]
                text = entry.get("textPayload")
                for line in text.splitlines() if isinstance(text, str) else []:
                    try:
                        payloads.append(json.loads(line[line.index("{") :]))
                    except (ValueError, json.JSONDecodeError):
                        pass
                for value in payloads:
                    if (
                        isinstance(value, dict)
                        and all(
                            value.get(k) == v
                            for k, v in {
                                "scope": "scheduled_database_update",
                                "status": "reconciled",
                                "marker": auto.HEALTHY_MARKER,
                                "current_image": image,
                                "rollback_image": record["baseline"]["image"],
                                "cloud_run_executed": False,
                            }.items()
                        )
                        and value.get("cloud_run_executed") is False
                    ):
                        return True
            token = data.get("nextPageToken")
            if token is None or token == "":
                return False
            require(
                isinstance(token, str) and len(token) <= 8192 and token not in tokens,
                "recovery_marker_pagination_invalid",
            )
            tokens.add(token)
            query["pageToken"] = token
        raise RehearsalError("recovery_marker_read_incomplete")

    def candidate_controls(self, saved):
        try:
            report = observation.current_release_controls(self.tool, saved)
            daily = auto._daily(report, saved["controls_module_sha256"])
            require(
                0
                <= self.now().timestamp() - daily["created_at_epoch"]
                <= auto.POLICY["max_candidate_age_seconds"],
                "recovery_candidate_database_stale",
            )
            return report
        except RehearsalError:
            raise
        except Exception:
            raise RehearsalError("recovery_candidate_controls_not_verified") from None

    def verify_recovered(self, record):
        state, generation = self.state(current=True)
        require(state["active"] is None, "recovery_campaign_still_active")
        saved = state["current"]["files"]["state.json"]
        require(
            state["enabled"]
            and setup.digest(state["source"]) == record["baseline"]["source_sha256"]
            and saved.get("release") == record["release"]
            and saved.get("build_id") == record["candidate_build_id"]
            and saved.get("phase") == "promoted"
            and state["current"]["rollback_image"] == record["baseline"]["image"],
            "recovery_promoted_checkpoint_differs",
        )
        restored = private.expected_configuration(
            state["current"]["configuration"], record["baseline"]["image"]
        )
        require(
            setup.digest(private.configuration_for_comparison(restored))
            == record["baseline"]["configuration_sha256"],
            "recovery_promoted_configuration_differs",
        )
        candidate = self.candidate(record)
        require(candidate.get("status") == "SUCCESS", "recovery_candidate_not_successful")
        auto._approved_files({**state["current"]["files"], "build.json": candidate})
        require(
            self.candidate_controls(saved) == state["current"]["files"]["engine-controls.json"],
            "recovery_candidate_controls_differ",
        )
        found = self.tool.get(
            BASE
            + "?"
            + urlencode(
                {
                    "filter": "substitutions._RELEASE=" + record["release"],
                    "pageSize": 100,
                }
            )
        )
        require(
            isinstance(found, dict) and not found.get("nextPageToken"),
            "recovery_candidate_lookup_incomplete",
        )
        builds = found.get("builds", [])
        require(
            isinstance(builds, list)
            and len(builds) == 1
            and builds[0].get("id") == record["candidate_build_id"],
            "recovery_duplicate_candidate_or_lookup_unknown",
        )
        require(
            self.healthy_marker(record, state["current"]["image"]),
            "recovery_resume_marker_not_observed",
        )
        _, latest = self.tool.store.load_json("state.json")
        require(latest == generation, "recovery_state_changed_during_verification")
        record.update(
            phase="recovered",
            recovered_at=self.now().isoformat(),
            candidate_image=state["current"]["image"],
        )
        self.save(record)

    def _status(self, record):
        if record["phase"] in {"prepared", "armed", "missed_window", "recovered"}:
            return self.summary(record)
        parent = self.parent(record)
        if record["phase"] == "cancel_pending":
            if parent.get("status") in {"QUEUED", "PENDING", "WORKING"}:
                return self.summary(record)
            if parent.get("status") != "CANCELLED":
                record["phase"] = "missed_window"
                self.save(record)
                return self.summary(record)
            state, _ = self.state()
            if state["active"] is None:
                record["phase"] = "missed_window"
                self.save(record)
                return self.summary(record)
            self.active(record, state)
            self.lease(record["parent_build_id"])
            record["phase"] = "interrupted"
            self.save(record)
        if record["phase"] == "interrupted":
            require(parent.get("status") == "CANCELLED", "recovery_parent_not_cancelled")
            state, _ = self.state()
            self.active(record, state)
            self.lease(record["parent_build_id"])
            candidate = self.candidate(record)
            require(
                candidate.get("status") in {"WORKING", "SUCCESS"},
                "recovery_candidate_not_resumable",
            )
            self.allowed_live_job(record, state, candidate)
        if record["phase"] in {"resume_pending", "resume_submitted"}:
            require(parent.get("status") == "CANCELLED", "recovery_parent_not_cancelled")
            resumed = self._resolve_resume(record)
            if resumed.get("status") in {"QUEUED", "PENDING", "WORKING"}:
                return self.summary(record)
            require(resumed.get("status") == "SUCCESS", "recovery_resume_not_successful")
            self.verify_recovered(record)
        return self.summary(record)

    def status(self):
        with private.operation_lock(self.tool.directory):
            return self._status(self.load())

    def resume(self, *, confirm_reconnected=False):
        with private.operation_lock(self.tool.directory):
            record = self.load()
            if record["phase"] in {"resume_pending", "resume_submitted", "recovered"}:
                return self._status(record)
            require(confirm_reconnected is True, "recovery_reconnect_confirmation_required")
            record = self.load()
            self._status(record)
            require(record["phase"] == "interrupted", "recovery_not_interrupted")
            self.source_proof()
            self.scheduler(quiet=True)
            require(
                self.parent(record).get("status") == "CANCELLED", "recovery_parent_not_cancelled"
            )
            self.lease(record["parent_build_id"])
            state, _ = self.state()
            saved = self.active(record, state)
            candidate = self.candidate(record)
            require(
                candidate.get("status") in {"WORKING", "SUCCESS"},
                "recovery_candidate_not_resumable",
            )
            self.allowed_live_job(record, state, candidate)
            if candidate["status"] == "SUCCESS":
                report = self.candidate_controls(saved)
                previous = state["current"]["files"]["engine-controls.json"]
                current_daily = auto._daily(previous, saved["controls_module_sha256"])
                candidate_daily = auto._daily(report, saved["controls_module_sha256"])
                require(
                    candidate_daily["created_at_epoch"] >= current_daily["created_at_epoch"]
                    and candidate_daily.get("version", 0) >= current_daily.get("version", 0),
                    "recovery_candidate_database_regressed",
                )
            record.update(
                phase="resume_pending",
                user_reconnected_at=self.now().isoformat(),
                resume_intent_at=self.now().isoformat(),
            )
            self.save(record)
            try:
                response = self.tool.rest.request("POST", BASE, record["request"])
            except Exception:
                raise RehearsalError("recovery_resume_outcome_unknown") from None
            build_id = response.get("metadata", {}).get("build", {}).get("id")
            require(valid_id(build_id), "recovery_resume_outcome_unknown")
            record.update(phase="resume_submitted", resume_build_id=build_id)
            self.save(record)
            return self.summary(record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "status", "watch-and-interrupt", "resume"))
    parser.add_argument("--plan-dir", required=True, type=Path)
    parser.add_argument("--wait-seconds", type=int, default=MAX_WAIT_SECONDS)
    parser.add_argument("--confirm-reconnected", action="store_true")
    args = parser.parse_args()
    try:
        test = Rehearsal(
            setup.Provisioner(args.plan_dir),
            progress=lambda report: print(json.dumps(report), flush=True),
        )
        if args.operation == "watch-and-interrupt":
            result = test.watch_and_interrupt(wait_seconds=args.wait_seconds)
        elif args.operation == "resume":
            result = test.resume(confirm_reconnected=args.confirm_reconnected)
        else:
            result = getattr(test, args.operation)()
        print(json.dumps(result, indent=2))
    except Exception as error:
        code = (
            str(error) if isinstance(error, RehearsalError) else "recovery_rehearsal_not_verified"
        )
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": SCOPE,
                    "error": code,
                    "automatic_write_resubmission": False,
                    "cloud_run_executed": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
