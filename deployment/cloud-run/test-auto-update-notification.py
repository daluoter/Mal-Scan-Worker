#!/usr/bin/env python3
"""Opt-in acceptance of the existing failure alert, using one deliberate failure.

An invalid owner stops the frozen controller before state or Job I/O. The test
creates one Cloud Build and targets the existing failure policy. Actual receipt
is recorded only after an explicit user confirmation; marker presence is not
delivery proof. Unknown submissions are discovered, never sent again.
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import io
import json
import re
import tarfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


setup = module("notification_setup", "setup-auto-update.py")
runtime = module("notification_runtime", "auto_runtime.py")
observation = module("notification_observation", "inspect-auto-update.py")
private = module("notification_private", "maintain-demo.py")
PROJECT = setup.PROJECT
REGION = setup.REGION
BASE = f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/builds"
POLICY_TITLE = "MalScan database update failed"
INVALID_OWNER = "notification-acceptance"
EXPECTED_CODE = "lease_owner_invalid"
MARKER = "MALSCAN_DB_UPDATE_FAILURE"
MAX_LOG_PAGES = 5
LOG_PAGE_SIZE = 100
DEPENDENCIES = (
    "auto_update.py",
    "auto_state.py",
    "auto_retention.py",
    "maintain-demo.py",
    "cleanup-registry.py",
    "prune-registry.py",
)
PHASES = {"prepared", "submission_pending", "submitted", "failure_verified", "delivery_recorded"}
BUILD_STATES = {
    "QUEUED",
    "PENDING",
    "WORKING",
    "SUCCESS",
    "FAILURE",
    "CANCELLED",
    "TIMEOUT",
    "EXPIRED",
    "INTERNAL_ERROR",
    "unrecognized",
}


class NotificationError(RuntimeError):
    """A source-controlled public category without provider text or recipients."""


def now_utc():
    return datetime.now(timezone.utc)


class NotificationTest:
    def __init__(self, tool, *, now=None):
        self.tool = tool
        self.path = tool.directory / "notification-test.json"
        self.now = now or now_utc

    def request(self, tag):
        request = self.tool.build_request()
        step = request["steps"][0]
        args = step["args"]
        if args.count("--owner-build-id") != 1 or args[-1] != "$BUILD_ID":
            raise NotificationError("notification_controller_arguments_invalid")
        args[args.index("--owner-build-id") + 1] = INVALID_OWNER
        request["tags"].append(tag)
        request.update(timeout="300s", queueTtl="300s")
        return request

    def load(self):
        state = private.read_private(self.path)
        if not isinstance(state, dict):
            raise NotificationError("notification_test_checkpoint_invalid")
        tag = state.get("request_tag")
        if (
            not setup.integer(state.get("version"))
            or state["version"] != 1
            or state.get("scope") != "controlled_updater_notification_test"
            or state.get("plan_sha256") != setup.digest(self.tool.plan)
            or not isinstance(state.get("phase"), str)
            or state["phase"] not in PHASES
            or not isinstance(tag, str)
            or not re.fullmatch(r"malscan-db-notification-test-[a-f0-9]{32}", tag)
            or state.get("request") != self.request(tag)
            or state.get("request_sha256") != setup.digest(state["request"])
        ):
            raise NotificationError("notification_test_checkpoint_invalid")
        if state.get("build_id") is not None and not self.tool._build_id(state["build_id"]):
            raise NotificationError("notification_build_identity_invalid")
        if state.get("build_status") is not None and (
            not isinstance(state["build_status"], str) or state["build_status"] not in BUILD_STATES
        ):
            raise NotificationError("notification_test_checkpoint_invalid")
        if any(
            not isinstance(state[key], bool)
            for key in ("failure_marker_verified", "failure_marker_currently_observed")
            if key in state
        ):
            raise NotificationError("notification_test_checkpoint_invalid")
        if state.get("user_confirmed_at") is not None:
            try:
                state["user_confirmed_at"] = observation.timestamp(
                    state["user_confirmed_at"]
                ).isoformat()
            except Exception:
                raise NotificationError("notification_test_checkpoint_invalid") from None
        if state["phase"] in {"failure_verified", "delivery_recorded"} and (
            state.get("failure_marker_verified") is not True
            or not state.get("build_id")
            or state.get("build_status") != "FAILURE"
        ):
            raise NotificationError("notification_test_checkpoint_invalid")
        if state["phase"] == "delivery_recorded" and state.get("user_confirmed_at") is None:
            raise NotificationError("notification_test_checkpoint_invalid")
        if state.get("user_confirmed_at") is not None and state["phase"] != "delivery_recorded":
            raise NotificationError("notification_test_checkpoint_invalid")
        if state.get("failure_marker_verified") is True and state["phase"] not in {
            "failure_verified",
            "delivery_recorded",
        }:
            raise NotificationError("notification_test_checkpoint_invalid")
        if state["phase"] == "prepared":
            if any(
                key in state
                for key in ("build_id", "build_status", "submission_intent_at", "pre_submit_images")
            ):
                raise NotificationError("notification_test_checkpoint_invalid")
        else:
            try:
                observation.timestamp(state.get("submission_intent_at"))
                pointers = state["pre_submit_images"]
                if not isinstance(pointers, dict) or set(pointers) != {"image", "rollback_image"}:
                    raise ValueError
                for image in pointers.values():
                    private.immutable_image(image)
                if state["phase"] != "submission_pending" and not state.get("build_id"):
                    raise ValueError
            except Exception:
                raise NotificationError("notification_test_checkpoint_invalid") from None
        return state

    def save(self, state, *, exclusive=False):
        state["updated_at"] = self.now().isoformat()
        private.write_private(self.path, state, exclusive=exclusive)

    def source_proof(self):
        """Bind the test's early-exit proof to the actual approved source archive."""
        self.tool.require_current_runtime()
        blob = (self.tool.directory / "source.tar.gz").read_bytes()
        if setup.hashlib.sha256(blob).hexdigest() != self.tool.plan["bundle_sha256"]:
            raise NotificationError("notification_source_archive_changed")
        try:
            raw = gzip.GzipFile(fileobj=io.BytesIO(blob)).read(setup.MAX_BUNDLE_BYTES + 1)
            if len(raw) > setup.MAX_BUNDLE_BYTES:
                raise ValueError
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                members = archive.getmembers()
                for filename in DEPENDENCIES:
                    name = "deployment/cloud-run/" + filename
                    selected = [m for m in members if m.name == name]
                    if len(selected) != 1 or not selected[0].isfile() or selected[0].size > 131072:
                        raise ValueError
                    stream = archive.extractfile(selected[0])
                    if (
                        stream is None
                        or stream.read(131073) != Path(__file__).with_name(filename).read_bytes()
                    ):
                        raise ValueError
        except (OSError, ValueError, tarfile.TarError, EOFError):
            raise NotificationError("notification_early_exit_source_not_verified") from None
        previous = self.tool._verify_only
        self.tool._verify_only = True
        try:
            generation = self.tool._bundle()
        finally:
            self.tool._verify_only = previous
        if generation != self.tool.journal["storage_source"]["generation"]:
            raise NotificationError("notification_source_generation_changed")

    def preflight(self):
        self.source_proof()
        now = self.now()
        report = observation.inspect(self.tool, now=now)
        try:
            next_schedule = observation.timestamp(report["scheduler"]["next_schedule_at"])
        except Exception:
            raise NotificationError("notification_scheduler_next_time_not_verified") from None
        if next_schedule <= now + timedelta(minutes=30):
            raise NotificationError("notification_scheduler_quiet_window_required")
        if (
            report.get("read_complete") is not True
            or report.get("enabled_monitoring_metadata_matches_plan") is not True
            or report.get("healthy_metric_ingestion_verified") is not True
        ):
            raise NotificationError("notification_monitoring_preflight_not_ready")
        state, _ = self.tool._approved_state()
        lease, _ = self.tool.store.load_json("lease.json")
        if not state["enabled"] or state.get("active") is not None or lease is not None:
            raise NotificationError("notification_requires_enabled_idle_state")
        return {key: state["current"][key] for key in ("image", "rollback_image")}

    def summary(self, state, *, pointers=None):
        return {
            "scope": "controlled_updater_notification_test",
            "phase": state["phase"],
            "build_id": state.get("build_id"),
            "build_status": state.get("build_status"),
            "expected_build_status": "FAILURE",
            "expected_failure_code": EXPECTED_CODE,
            "failure_marker_verified": state.get("failure_marker_verified", False),
            "failure_marker_currently_observed": state.get("failure_marker_currently_observed"),
            "targets_existing_failure_alert": True,
            "expected_policy_title": POLICY_TITLE,
            "notification_delivery_verified": state["phase"] == "delivery_recorded",
            "delivery_evidence": "explicit_user_confirmation"
            if state["phase"] == "delivery_recorded"
            else "not_observed",
            "user_confirmed_at": state.get("user_confirmed_at"),
            "independent_mailbox_access": False,
            "image_pointers_match_pre_submit": pointers,
            "new_build_submission_required": state["phase"] == "prepared",
            "resubmitted": False,
            "cloud_run_executed": False,
            "original_plan_state_and_journal_mutated_by_this_tool": False,
        }

    def prepare(self):
        with private.operation_lock(self.tool.directory):
            if self.path.exists():
                return self.summary(self.load())
            pointers = self.preflight()
            tag = "malscan-db-notification-test-" + uuid.uuid4().hex
            request = self.request(tag)
            state = {
                "version": 1,
                "scope": "controlled_updater_notification_test",
                "plan_sha256": setup.digest(self.tool.plan),
                "phase": "prepared",
                "request_tag": tag,
                "request": request,
                "request_sha256": setup.digest(request),
                "prepared_at": self.now().isoformat(),
                "prepared_images": pointers,
            }
            self.save(state, exclusive=True)
            return self.summary(state)

    def submit(self):
        with private.operation_lock(self.tool.directory):
            state = self.load()
            if state["phase"] != "prepared":
                return self._status(state)
            pointers = self.preflight()
            state.update(
                phase="submission_pending",
                pre_submit_images=pointers,
                submission_intent_at=self.now().isoformat(),
            )
            self.save(state)  # Intent is durable before the single create request.
            try:
                response = self.tool.rest.request("POST", BASE, state["request"])
            except Exception:
                raise NotificationError("notification_submission_outcome_unknown") from None
            build_id = response.get("metadata", {}).get("build", {}).get("id")
            if not self.tool._build_id(build_id):
                raise NotificationError("notification_submission_outcome_unknown")
            state.update(build_id=build_id, phase="submitted")
            self.save(state)
            return self.summary(state)

    def _build(self, state):
        if not state.get("build_id"):
            found = self.tool.rest.request(
                "GET",
                BASE
                + "?"
                + urlencode(
                    {
                        "filter": "tags=" + state["request_tag"],
                        "pageSize": 100,
                    }
                ),
            )
            if not isinstance(found, dict) or found.get("nextPageToken"):
                raise NotificationError("notification_build_lookup_incomplete")
            matches = [
                b for b in found.get("builds", []) if state["request_tag"] in b.get("tags", [])
            ]
            if len(matches) != 1 or not runtime.build_matches(state["request"], matches[0]):
                raise NotificationError("notification_submission_unknown_no_resubmit")
            state["build_id"] = matches[0]["id"]
            state["phase"] = "submitted"
            self.save(state)
        build = self.tool.get(BASE + "/" + state["build_id"])
        if (
            not runtime.build_matches(state["request"], build)
            or build.get("id") != state["build_id"]
        ):
            raise NotificationError("notification_build_request_differs")
        return build

    def marker(self, state):
        # Logging can return an empty page with a token while its search continues.
        # Keep every parameter fixed across pages and allow five minutes of clock skew.
        start = observation.timestamp(state["submission_intent_at"]) - timedelta(minutes=5)
        end = self.now() + timedelta(minutes=5)
        if start >= end:
            raise NotificationError("notification_marker_query_time_invalid")
        query = {
            "resourceNames": ["projects/" + PROJECT],
            "pageSize": LOG_PAGE_SIZE,
            "orderBy": "timestamp desc",
            "filter": (
                f'resource.type="build" AND resource.labels.project_id="{PROJECT}" '
                f'AND resource.labels.build_id="{state["build_id"]}" '
                f'AND timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" '
                f'AND (textPayload:"{MARKER}" OR jsonPayload.marker="{MARKER}")'
            ),
        }
        seen_tokens = set()
        for _ in range(MAX_LOG_PAGES):
            data = self.tool.rest.request(
                "POST", "https://logging.googleapis.com/v2/entries:list", query
            )
            if not isinstance(data, dict):
                raise NotificationError("notification_marker_read_incomplete")
            entries = data.get("entries", [])
            if not isinstance(entries, list) or len(entries) > LOG_PAGE_SIZE:
                raise NotificationError("notification_marker_response_invalid")
            for entry in entries:
                resource = entry.get("resource") if isinstance(entry, dict) else None
                labels = resource.get("labels") if isinstance(resource, dict) else None
                if (
                    not isinstance(labels, dict)
                    or resource.get("type") != "build"
                    or labels.get("project_id") != PROJECT
                    or labels.get("build_id") != state["build_id"]
                ):
                    continue
                payloads = [entry.get("jsonPayload")]
                text_payload = entry.get("textPayload")
                for line in text_payload.splitlines() if isinstance(text_payload, str) else []:
                    try:
                        payloads.append(json.loads(line[line.index("{") :]))
                    except (ValueError, json.JSONDecodeError):
                        continue
                for payload in payloads:
                    if (
                        isinstance(payload, dict)
                        and payload.get("marker") == MARKER
                        and payload.get("scope") == "scheduled_database_update"
                        and payload.get("status") == "failed"
                        and payload.get("code") == EXPECTED_CODE
                        and payload.get("cloud_run_executed") is False
                    ):
                        return True  # An exact positive marker is sufficient evidence.
            token = data.get("nextPageToken")
            if token is None or token == "":
                return False
            if not isinstance(token, str) or len(token) > 8192 or token in seen_tokens:
                raise NotificationError("notification_marker_pagination_invalid")
            seen_tokens.add(token)
            query["pageToken"] = token
        raise NotificationError("notification_marker_read_incomplete")

    def _status(self, state):
        if state["phase"] == "prepared":
            return self.summary(state)
        build = self._build(state)
        status = build.get("status")
        state["build_status"] = status if status in BUILD_STATES else "unrecognized"
        if status in {"QUEUED", "PENDING", "WORKING"}:
            self.save(state)
            return self.summary(state)
        if status != "FAILURE":
            self.save(state)
            raise NotificationError("notification_expected_failure_not_observed")
        verified = self.marker(state)
        state["failure_marker_currently_observed"] = verified
        if verified:
            state["failure_marker_verified"] = True
            state.setdefault("failure_marker_verified_at", self.now().isoformat())
        if verified and state["phase"] != "delivery_recorded":
            state["phase"] = "failure_verified"
        current, _ = self.tool._approved_state(check_current=False)
        pointers = {key: current["current"][key] for key in ("image", "rollback_image")}
        same = pointers == state["pre_submit_images"]
        self.save(state)
        return self.summary(state, pointers=same)

    def status(self):
        with private.operation_lock(self.tool.directory):
            return self._status(self.load())

    def received(self, *, policy_title):
        with private.operation_lock(self.tool.directory):
            if policy_title != POLICY_TITLE:
                raise NotificationError("notification_matching_policy_confirmation_required")
            state = self.load()
            result = self._status(state)
            if not result["failure_marker_verified"]:
                raise NotificationError("notification_expected_failure_marker_required")
            if state["phase"] != "delivery_recorded":
                state.update(
                    phase="delivery_recorded",
                    user_confirmed_at=self.now().isoformat(),
                    delivery_evidence="explicit_user_confirmation",
                )
                self.save(state)
            return self.summary(state, pointers=result["image_pointers_match_pre_submit"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "submit", "status", "received"))
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--policy-title")
    args = parser.parse_args()
    try:
        test = NotificationTest(setup.Provisioner(args.plan_dir))
        result = (
            test.received(policy_title=args.policy_title)
            if args.operation == "received"
            else getattr(test, args.operation)()
        )
        print(json.dumps(result, indent=2))
    except Exception as error:
        code = (
            str(error) if isinstance(error, NotificationError) else "notification_test_not_verified"
        )
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": "controlled_updater_notification_test",
                    "error": code,
                    "cloud_run_executed": False,
                    "automatic_resubmission": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
