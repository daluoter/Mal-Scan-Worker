"""Offline safety tests for the deliberately interrupted maintenance rehearsal."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


recovery = module("recovery_rehearsal", "rehearse-auto-update-recovery.py")
fixture = module("recovery_fixture", "test_auto_update_notification.py")
maintenance_fixture = module("recovery_maintenance_fixture", "test_maintain_demo.py")
PARENT = "22345678-1234-4234-8234-123456789abc"
CANDIDATE = "32345678-1234-4234-8234-123456789abc"
RESUME = "42345678-1234-4234-8234-123456789abc"
OTHER = "52345678-1234-4234-8234-123456789abc"
PRIVATE = "PRIVATE_PROVIDER_OR_CHECKPOINT_VALUE"
NEXT = maintenance_fixture.maintenance.IMAGE + "@sha256:" + "d" * 64


class RecoveryREST(fixture.TestREST):
    def __init__(self, previous):
        super().__init__(previous)
        self.builds = copy.deepcopy(previous.builds)
        self.pages = copy.deepcopy(previous.pages)
        self.lose_cancel = False
        self.cancel_stays_working = False
        self.cancel_finishes_successfully = False
        self.lose_resume = False
        self.cancel_without_effect = False
        self.resume_without_effect = False
        self.marker_mode = "reconciled"
        self.before_cancel = None
        self.before_resume = None
        self.after_cancel = None

    def request(self, method, url, payload=None, **kwargs):
        base = url.split("?", 1)[0]
        if method == "POST" and base.endswith(":cancel"):
            self.calls.append((method, url, copy.deepcopy(payload), None))
            if self.before_cancel:
                self.before_cancel()
            if self.cancel_without_effect:
                raise RuntimeError(PRIVATE)
            build = next(b for b in self.builds if b["id"] == base.rsplit("/", 1)[1][:-7])
            if not self.cancel_stays_working:
                build["status"] = "SUCCESS" if self.cancel_finishes_successfully else "CANCELLED"
            if self.after_cancel:
                self.after_cancel()
            if self.lose_cancel:
                self.lose_cancel = False
                raise RuntimeError(PRIVATE)
            return copy.deepcopy(build)
        if method == "POST" and base == recovery.BASE:
            self.calls.append((method, url, copy.deepcopy(payload), None))
            if self.before_resume:
                self.before_resume()
            if self.resume_without_effect:
                raise RuntimeError(PRIVATE)
            build = {
                **copy.deepcopy(payload),
                "id": RESUME,
                "status": "WORKING",
                "createTime": self.now().isoformat(),
                "startTime": self.now().isoformat(),
            }
            self.builds.append(build)
            if self.lose_resume:
                self.lose_resume = False
                raise RuntimeError(PRIVATE)
            return {"metadata": {"build": {"id": RESUME}}}
        if method == "GET" and base == recovery.BASE:
            self.calls.append((method, url, copy.deepcopy(payload), None))
            query = parse_qs(urlsplit(url).query).get("filter", [""])[0]
            if "tags=" in query:
                tag = query.split("tags=", 1)[1].strip('"')
                builds = [b for b in self.builds if tag in b.get("tags", [])]
            elif "_RELEASE" in query:
                builds = [b for b in self.builds if "_RELEASE" in b.get("substitutions", {})]
            else:
                builds = self.builds
            result = {"builds": copy.deepcopy(builds)}
            if self.list_truncated:
                result["nextPageToken"] = PRIVATE
            return result
        if method == "POST" and base == "https://logging.googleapis.com/v2/entries:list":
            self.calls.append((method, url, copy.deepcopy(payload), None))
            if self.log_pages is not None:
                token = payload.get("pageToken")
                if token is None:
                    return copy.deepcopy(self.log_pages[0])
                for index, page in enumerate(self.log_pages[:-1]):
                    if page.get("nextPageToken") == token:
                        return copy.deepcopy(self.log_pages[index + 1])
                raise AssertionError("Unexpected logging token")
            return {"entries": [] if self.marker_mode == "none" else [self.marker_entry()]}
        return super().request(method, url, payload, **kwargs)

    def marker_entry(self):
        return {
            "timestamp": self.now().isoformat(),
            "resource": {
                "type": "build",
                "labels": {"project_id": recovery.PROJECT, "build_id": RESUME},
            },
            "jsonPayload": {
                "scope": "scheduled_database_update",
                "status": self.marker_mode,
                "marker": "MALSCAN_DB_UPDATE_HEALTHY",
                "current_image": NEXT,
                "rollback_image": self.baseline_image,
                "cloud_run_executed": False,
                "enabled": True,
                "phase": "idle",
                "last_status": "reconciled",
                "last_healthy_at": self.now().isoformat(),
            },
        }


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = fixture.NotificationTests()
        self.base.setUp()
        self.tool = self.base.tool
        self.clock = self.base.base.now
        self.time_patch = patch.object(recovery.setup.time, "time", lambda: self.clock.timestamp())
        self.time_patch.start()
        state, _ = self.tool.store.load_json("state.json")
        created = int(self.clock.timestamp()) - 86400
        for report in (
            state["current"]["files"]["engine-controls.json"],
            state["current"]["files"]["state.json"]["candidate_controls"],
        ):
            next(d for d in report["signed_databases"] if d["name"] == "daily.cvd")[
                "created_at_epoch"
            ] = created
        state["current"]["daily_created_at_epoch"] = created
        self.set_state(state)
        self.rest = RecoveryREST(self.tool.rest)
        self.rest.now = lambda: self.clock
        self.rest.baseline_image = state["current"]["image"]
        self.tool.rest = self.rest
        self.scheduler = self.rest.resources[
            "https://cloudscheduler.googleapis.com/v1/" + self.tool.scheduler_document()["name"]
        ]
        self.scheduler["scheduleTime"] = (self.clock + timedelta(hours=2)).isoformat()
        self.test = recovery.Rehearsal(self.tool, now=lambda: self.clock, sleep=self.sleep)
        self.baseline = copy.deepcopy(state)
        self.before_files = {
            name: (self.tool.directory / name).read_bytes()
            for name in ("plan.json", "source.tar.gz", "apply-state.json")
        }
        self.before_journal = copy.deepcopy(self.tool.journal)
        self.tool.store.writes.clear()
        self.record_external_changes()
        self.provider_controls = copy.deepcopy(state["current"]["files"]["engine-controls.json"])
        self.control_reads = []
        controls_patch = patch.object(
            recovery.observation, "current_release_controls", self.read_provider_controls
        )
        controls_patch.start()
        self.addCleanup(controls_patch.stop)
        # All cloud reads use RecoveryREST; these guards catch accidental fallthrough.
        for target in ("subprocess.run", "socket.create_connection"):
            guard = patch(target, side_effect=AssertionError("offline test attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def tearDown(self):
        self.time_patch.stop()
        self.base.tearDown()

    def set_state(self, state):
        self.tool.store.generation += 1
        self.tool.store.values["state.json"] = (copy.deepcopy(state), self.tool.store.generation)

    def sleep(self, seconds):
        self.clock += timedelta(seconds=seconds)

    def read_provider_controls(self, tool, saved):
        self.assertIs(tool, self.tool)
        self.assertEqual(saved["build_id"], CANDIDATE)
        self.control_reads.append(copy.deepcopy(saved))
        return copy.deepcopy(self.provider_controls)

    def cancelled_posts(self):
        return [c for c in self.rest.calls if c[0] == "POST" and c[1].endswith(":cancel")]

    def created_posts(self):
        return [c for c in self.rest.calls if c[0] == "POST" and c[1] == recovery.BASE]

    def record_external_changes(self):
        """Only fixtures simulate the real controllers' coordinator changes."""
        self.expected_values = copy.deepcopy(self.tool.store.values)
        self.expected_resources = copy.deepcopy(self.rest.resources)
        self.expected_job = copy.deepcopy(self.base.base.fixture.job)

    def unchanged_private_registration(self):
        self.assertEqual(self.tool.journal, self.before_journal)
        for name, contents in self.before_files.items():
            self.assertEqual((self.tool.directory / name).read_bytes(), contents)
        self.assertEqual(self.tool.store.writes, [])
        self.assertEqual(self.tool.store.values, self.expected_values)
        self.assertEqual(self.rest.resources, self.expected_resources)
        self.assertEqual(self.base.base.fixture.job, self.expected_job)
        self.assertTrue(
            all(
                method == "GET"
                or (
                    method == "POST"
                    and (
                        url == recovery.BASE
                        or url == "https://logging.googleapis.com/v2/entries:list"
                        or url == recovery.BASE + "/" + PARENT + ":cancel"
                    )
                )
                for method, url, _, _ in self.rest.calls
            )
        )

    def arm(self):
        self.test.prepare()
        checkpoint = self.test.load()
        self.clock = recovery.observation.timestamp(checkpoint["target_tick_at"])
        self.scheduler["scheduleTime"] = (self.clock + timedelta(hours=12)).isoformat()
        self.record_external_changes()
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(self.test.load()["phase"], "armed")
        self.clock += timedelta(seconds=90)

    def active_campaign(self):
        state = copy.deepcopy(self.baseline)
        self.release = "db-" + self.clock.strftime("%Y%m%dT%H%M%SZ") + "-abcdef123456"
        self.job_before = copy.deepcopy(self.base.base.fixture.job)
        self.saved = copy.deepcopy(state["current"]["files"]["state.json"])
        self.saved.update(
            phase="build_submitted",
            release=self.release,
            build_id=CANDIDATE,
            previous_image=state["current"]["image"],
            baseline_fingerprint=recovery.private.fingerprint(
                recovery.private.job_configuration(self.job_before)
            ),
            prepared_at=self.clock.isoformat(),
        )
        self.saved.pop("candidate_image", None)
        self.saved.pop("candidate_controls", None)
        state["active"] = {
            "release": self.release,
            "files": {
                "state.json": self.saved,
                "job-before.json": self.job_before,
            },
        }
        self.set_state(state)
        self.tool.store.generation += 1
        self.tool.store.values["lease.json"] = (
            {"schema_version": 1, "owner_build_id": PARENT},
            self.tool.store.generation,
        )
        parent = self.tool.build_request()
        parent.update(
            id=PARENT,
            status="WORKING",
            createTime=(self.clock - timedelta(seconds=70)).isoformat(),
            startTime=(self.clock - timedelta(seconds=60)).isoformat(),
        )
        candidate = maintenance_fixture.successful_build()
        candidate = json.loads(
            json.dumps(candidate)
            .replace(maintenance_fixture.RELEASE, self.release)
            .replace(maintenance_fixture.BUILD_ID, CANDIDATE)
        )
        candidate.update(
            status="WORKING",
            serviceAccount=recovery.auto.BUILDER_ACCOUNT,
            source={
                "storageSource": {
                    "bucket": self.tool.plan["bucket"],
                    "object": "build-sources/source.tgz",
                }
            },
            createTime=self.clock.isoformat(),
            options={"logging": "CLOUD_LOGGING_ONLY"},
        )
        candidate["steps"][0].update(
            status="WORKING", name="gcr.io/cloud-builders/docker", env=["DOCKER_BUILDKIT=1"]
        )
        candidate["steps"][1]["status"] = "QUEUED"
        candidate.pop("results", None)
        self.rest.builds.extend([parent, candidate])
        self.record_external_changes()
        return parent, candidate

    def interrupt(self):
        self.arm()
        parent, candidate = self.active_campaign()
        self.test.watch_and_interrupt(wait_seconds=0)
        return parent, candidate

    def finish_recovery(self):
        self.clock += timedelta(minutes=3)
        candidate = next(b for b in self.rest.builds if b["id"] == CANDIDATE)
        candidate.update(
            status="SUCCESS",
            finishTime=self.clock.isoformat(),
            results={
                "images": [
                    {
                        "name": recovery.private.IMAGE + ":" + self.release,
                        "digest": NEXT.split("@", 1)[1],
                    }
                ]
            },
        )
        for step in candidate["steps"]:
            step["status"] = "SUCCESS"
        controls = copy.deepcopy(self.baseline["current"]["files"]["engine-controls.json"])
        daily = next(d for d in controls["signed_databases"] if d["name"] == "daily.cvd")
        daily["created_at_epoch"] = int(self.clock.timestamp()) - 3600
        daily["version"] = daily.get("version", 1) + 1
        self.provider_controls = copy.deepcopy(controls)
        promoted = {
            **copy.deepcopy(self.saved),
            "phase": "promoted",
            "candidate_image": NEXT,
            "candidate_controls": controls,
        }
        state, _ = self.tool.store.load_json("state.json")
        state.update(
            active=None,
            last_status="reconciled",
            last_healthy_at=self.clock.isoformat(),
            last_controller_build_id=RESUME,
        )
        state["current"] = {
            "image": NEXT,
            "rollback_image": self.baseline["current"]["image"],
            "configuration": recovery.private.expected_configuration(
                recovery.private.job_configuration(self.job_before), NEXT
            ),
            "daily_created_at_epoch": daily["created_at_epoch"],
            "files": {
                "state.json": promoted,
                "build.json": copy.deepcopy(candidate),
                "job-before.json": self.job_before,
                "engine-controls.json": controls,
            },
        }
        self.set_state(state)
        recovery.private.container(self.base.base.fixture.job)["image"] = NEXT
        self.tool.store.values.pop("lease.json", None)
        resume = next(b for b in self.rest.builds if b["id"] == RESUME)
        resume.update(status="SUCCESS", finishTime=self.clock.isoformat())
        self.record_external_changes()
        return state

    def test_prepare_is_readonly_and_pins_original_registration(self):
        result = self.test.prepare()
        self.assertEqual(result["phase"], "prepared")
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.assertTrue(all(c[0] == "GET" for c in self.rest.calls))
        state = self.test.load()
        self.assertGreater(
            recovery.observation.timestamp(state["target_tick_at"]),
            recovery.observation.timestamp(state["prepared_at"]),
        )
        before = self.test.path.read_bytes()
        self.test.prepare()
        self.assertEqual(self.test.path.read_bytes(), before)
        self.assertEqual(self.test.path.stat().st_mode & 0o777, 0o600)
        self.unchanged_private_registration()

    def test_watch_outside_window_cannot_cancel_or_create(self):
        self.test.prepare()
        with self.assertRaises(recovery.RehearsalError):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())

    def test_prepare_computes_a_future_tick_from_current_state(self):
        self.clock += timedelta(days=8)
        state, _ = self.tool.store.load_json("state.json")
        epoch = int((self.clock - timedelta(days=1)).timestamp())
        for report in (
            state["current"]["files"]["engine-controls.json"],
            state["current"]["files"]["state.json"]["candidate_controls"],
        ):
            next(d for d in report["signed_databases"] if d["name"] == "daily.cvd")[
                "created_at_epoch"
            ] = epoch
        state["current"]["daily_created_at_epoch"] = epoch
        state["last_healthy_at"] = (self.clock - timedelta(minutes=2)).isoformat()
        self.set_state(state)
        self.baseline = copy.deepcopy(state)
        self.record_external_changes()
        self.rest.pages = [{"timeSeries": [self.base.base.series(ended=self.clock)]}]
        with patch.object(self.tool, "_post_intent_healthy", return_value=True):
            report = self.test.prepare()
        target = recovery.observation.timestamp(report["target_tick_at"])
        self.assertGreater(target, self.clock)
        self.assertGreaterEqual(
            target.timestamp(),
            self.baseline["current"]["daily_created_at_epoch"]
            + recovery.auto.POLICY["refresh_after_seconds"],
        )
        self.assertIn(target.hour, (3, 15))
        self.assertEqual(target.minute, 23)
        self.unchanged_private_registration()

    def test_checkpoint_tampering_is_rejected_before_remote_calls(self):
        self.test.prepare()
        original = self.test.load()
        for key, changed in (
            ("version", True),
            ("phase", PRIVATE),
            ("phase", "recovered"),
            ("prepared_at", PRIVATE),
            ("updated_at", PRIVATE),
            ("target_tick_at", self.clock.isoformat()),
            ("parent_build_id", "00000000-0000-0000-0000-000000000000"),
            ("candidate_build_id", PRIVATE),
            ("resume_build_id", 123),
        ):
            with self.subTest(key=key, value=changed):
                record = {**copy.deepcopy(original), key: changed}
                recovery.private.write_private(self.test.path, record)
                count = len(self.rest.calls)
                with self.assertRaisesRegex(
                    recovery.RehearsalError, "^recovery_checkpoint_invalid$"
                ):
                    self.test.status()
                self.assertEqual(len(self.rest.calls), count)
        recovery.private.write_private(self.test.path, original)
        self.unchanged_private_registration()

    def test_checkpoint_boolean_daily_epoch_is_invalid(self):
        self.test.prepare()
        record = self.test.load()
        record["baseline"]["daily_epoch"] = True
        recovery.private.write_private(self.test.path, record)
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_checkpoint_invalid$"):
            self.test.status()
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())

    def test_only_exact_running_controller_is_cancelled_once(self):
        self.interrupt()
        report = self.test.status()
        self.assertEqual(report["phase"], "interrupted")
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.assertIn(PARENT + ":cancel", self.cancelled_posts()[0][1])
        self.assertNotIn(CANDIDATE + ":cancel", self.cancelled_posts()[0][1])
        self.test.watch_and_interrupt(wait_seconds=0)
        self.test.status()
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.assertEqual(self.created_posts(), [])
        self.unchanged_private_registration()

    def test_unknown_cancel_reconciles_without_another_cancel(self):
        self.arm()
        self.active_campaign()
        self.rest.lose_cancel = True
        with self.assertRaises(recovery.RehearsalError) as error:
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertNotIn(PRIVATE, str(error.exception))
        self.assertEqual(self.test.status()["phase"], "interrupted")
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.unchanged_private_registration()

    def test_unknown_cancel_without_observed_effect_is_never_reissued(self):
        self.arm()
        self.active_campaign()
        self.rest.cancel_without_effect = True
        self.rest.before_cancel = lambda: self.assertEqual(
            self.test.load()["phase"], "cancel_pending"
        )
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_cancel_outcome_unknown$"):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(self.test.load()["phase"], "cancel_pending")
        self.assertEqual(self.test.status()["phase"], "cancel_pending")
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_cancel_outcome_working_remains_pending_without_repetition(self):
        self.arm()
        self.active_campaign()
        self.rest.cancel_stays_working = True
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(self.test.status()["phase"], "cancel_pending")
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(len(self.cancelled_posts()), 1)

    def test_source_parent_candidate_and_lease_changes_block_cancel(self):
        self.arm()
        parent, candidate = self.active_campaign()
        original_parent, original_candidate = copy.deepcopy(parent), copy.deepcopy(candidate)
        for item, key, changed in (
            (parent, "serviceAccount", PRIVATE),
            (parent, "source", {}),
            (candidate, "serviceAccount", PRIVATE),
            (
                candidate,
                "source",
                {"storageSource": {"bucket": PRIVATE, "object": "build-sources/source.tgz"}},
            ),
        ):
            with self.subTest(key=key):
                item[key] = changed
                with self.assertRaises(recovery.RehearsalError):
                    self.test.watch_and_interrupt(wait_seconds=0)
                parent.clear()
                parent.update(copy.deepcopy(original_parent))
                candidate.clear()
                candidate.update(copy.deepcopy(original_candidate))
                self.assertEqual(self.cancelled_posts(), [])
        self.unchanged_private_registration()

    def test_exact_lease_schema_is_required_before_cancel(self):
        self.arm()
        self.active_campaign()
        lease, generation = self.tool.store.values["lease.json"]
        lease["unexpected"] = True
        self.tool.store.values["lease.json"] = (lease, generation)
        self.record_external_changes()
        with self.assertRaises(recovery.RehearsalError):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_baseline_daily_epoch_change_blocks_cancel(self):
        self.arm()
        self.active_campaign()
        state, _ = self.tool.store.load_json("state.json")
        changed = state["current"]["daily_created_at_epoch"] - 60
        for report in (
            state["current"]["files"]["engine-controls.json"],
            state["current"]["files"]["state.json"]["candidate_controls"],
        ):
            next(d for d in report["signed_databases"] if d["name"] == "daily.cvd")[
                "created_at_epoch"
            ] = changed
        state["current"]["daily_created_at_epoch"] = changed
        self.set_state(state)
        self.record_external_changes()
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_baseline_changed$"):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_future_or_stale_candidate_cannot_be_cancelled(self):
        self.arm()
        _, candidate = self.active_campaign()
        for delta in (timedelta(seconds=1), timedelta(seconds=-91)):
            with self.subTest(delta=delta):
                candidate["createTime"] = (self.clock + delta).isoformat()
                with self.assertRaises(recovery.RehearsalError):
                    self.test.watch_and_interrupt(wait_seconds=0)
                self.assertFalse(self.cancelled_posts())
        self.unchanged_private_registration()

    def test_queued_candidate_is_observed_without_cancel(self):
        self.arm()
        _, candidate = self.active_campaign()
        candidate["status"] = "QUEUED"
        report = self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(report["phase"], "armed")
        self.assertFalse(self.cancelled_posts())
        candidate["status"] = "WORKING"
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.unchanged_private_registration()

    def test_window_is_rechecked_immediately_before_cancel(self):
        self.arm()
        self.clock = recovery.observation.timestamp(self.test.load()["window_end_at"]) - timedelta(
            seconds=1
        )
        self.active_campaign()
        source_proof = self.test.source_proof
        calls = 0

        def advance_after_final_source_proof():
            nonlocal calls
            source_proof()
            calls += 1
            if calls == 2:
                self.clock += timedelta(seconds=2)

        with patch.object(self.test, "source_proof", advance_after_final_source_proof):
            with self.assertRaises(recovery.RehearsalError):
                self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        self.unchanged_private_registration()

    def test_parent_success_race_marks_missed_without_resume(self):
        self.arm()
        self.active_campaign()
        self.rest.cancel_finishes_successfully = True
        self.assertEqual(self.test.watch_and_interrupt(wait_seconds=0)["phase"], "missed_window")
        with self.assertRaises(recovery.RehearsalError):
            self.test.resume(confirm_reconnected=True)
        self.assertFalse(self.created_posts())
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.unchanged_private_registration()

    def test_cancelled_parent_with_no_active_campaign_is_missed(self):
        self.arm()
        self.active_campaign()

        def controller_finished():
            state, _ = self.tool.store.load_json("state.json")
            state["active"] = None
            self.set_state(state)
            self.record_external_changes()

        self.rest.after_cancel = controller_finished
        self.assertEqual(self.test.watch_and_interrupt(wait_seconds=0)["phase"], "missed_window")
        with self.assertRaises(recovery.RehearsalError):
            self.test.resume(confirm_reconnected=True)
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_resume_requires_explicit_reconnection_confirmation(self):
        self.interrupt()
        with self.assertRaises(recovery.RehearsalError):
            self.test.resume()
        self.assertEqual(self.created_posts(), [])

    def test_resume_submission_is_once_and_unknown_response_is_not_reissued(self):
        self.interrupt()
        self.rest.lose_resume = True
        with self.assertRaises(recovery.RehearsalError):
            self.test.resume(confirm_reconnected=True)
        self.test.status()
        self.test.resume(confirm_reconnected=True)
        self.assertEqual(len(self.created_posts()), 1)
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.unchanged_private_registration()

    def test_unknown_resume_without_observed_build_is_never_reissued(self):
        self.interrupt()
        self.rest.resume_without_effect = True
        self.rest.before_resume = lambda: self.assertEqual(
            self.test.load()["phase"], "resume_pending"
        )
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_resume_outcome_unknown$"):
            self.test.resume(confirm_reconnected=True)
        for operation in (self.test.status, lambda: self.test.resume(confirm_reconnected=True)):
            with self.assertRaisesRegex(
                recovery.RehearsalError, "^recovery_resume_unknown_no_resubmit$"
            ):
                operation()
        self.assertEqual(self.test.load()["phase"], "resume_pending")
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_submitted_checkpoint_cannot_rewind_phase_or_forge_timing(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        original = self.test.load()
        for key, changed in (
            ("phase", "interrupted"),
            ("resume_build_id", PARENT),
            ("armed_at", (self.clock + timedelta(days=1)).isoformat()),
            ("cancel_intent_at", (self.clock - timedelta(days=1)).isoformat()),
            ("resume_intent_at", (self.clock - timedelta(days=1)).isoformat()),
            ("resume_intent_at", (self.clock + timedelta(days=1)).isoformat()),
        ):
            with self.subTest(key=key, value=changed):
                record = {**copy.deepcopy(original), key: changed}
                recovery.private.write_private(self.test.path, record)
                count = len(self.rest.calls)
                with self.assertRaisesRegex(
                    recovery.RehearsalError, "^recovery_checkpoint_invalid$"
                ):
                    self.test.resume(confirm_reconnected=True)
                self.assertEqual(len(self.rest.calls), count)
        recovery.private.write_private(self.test.path, original)
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_resume_rejects_live_job_drift_and_near_scheduler_tick(self):
        self.interrupt()
        image = recovery.private.container(self.base.base.fixture.job)["image"]
        recovery.private.container(self.base.base.fixture.job)["image"] = NEXT
        with self.assertRaises(recovery.RehearsalError):
            self.test.resume(confirm_reconnected=True)
        recovery.private.container(self.base.base.fixture.job)["image"] = image
        self.scheduler["scheduleTime"] = (self.clock + timedelta(minutes=10)).isoformat()
        self.record_external_changes()
        with self.assertRaisesRegex(
            recovery.RehearsalError, "^recovery_resume_scheduler_window_too_close$"
        ):
            self.test.resume(confirm_reconnected=True)
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_running_candidate_does_not_need_completed_step_statuses(self):
        self.arm()
        _, candidate = self.active_campaign()
        for step in candidate["steps"]:
            step.pop("status", None)
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(self.test.status()["phase"], "interrupted")
        self.assertEqual(len(self.cancelled_posts()), 1)

    def test_working_candidate_accepts_only_known_cloud_build_substitutions(self):
        self.arm()
        _, candidate = self.active_campaign()
        for step in candidate["steps"]:
            step["args"] = [
                arg.replace(self.release, "$_RELEASE").replace(recovery.PROJECT, "$PROJECT_ID")
                for arg in step["args"]
            ]
        known = copy.deepcopy(candidate["steps"])
        candidate["steps"][0]["args"] = [
            arg.replace("$_RELEASE", "$_RELEASE_OTHER") for arg in candidate["steps"][0]["args"]
        ]
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_candidate_steps_differ$"):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        candidate["steps"] = known
        self.test.watch_and_interrupt(wait_seconds=0)
        self.assertEqual(self.test.status()["phase"], "interrupted")
        self.assertEqual(len(self.cancelled_posts()), 1)
        self.unchanged_private_registration()

    def test_successful_candidate_requires_completed_step_statuses_before_resume(self):
        self.interrupt()
        candidate = next(b for b in self.rest.builds if b["id"] == CANDIDATE)
        candidate["status"] = "SUCCESS"
        for step in candidate["steps"]:
            step.pop("status", None)
        with self.assertRaisesRegex(recovery.RehearsalError, "^recovery_candidate_steps_differ$"):
            self.test.resume(confirm_reconnected=True)
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_ready_candidate_requires_valid_fresh_provider_controls_before_resume(self):
        self.interrupt()
        candidate = next(b for b in self.rest.builds if b["id"] == CANDIDATE)
        candidate["status"] = "SUCCESS"
        for step in candidate["steps"]:
            step["status"] = "SUCCESS"
        fresh = copy.deepcopy(self.provider_controls)
        daily = next(d for d in fresh["signed_databases"] if d["name"] == "daily.cvd")
        daily["created_at_epoch"] = int(self.clock.timestamp()) - 3600
        for failure in ("signature", "stale"):
            with self.subTest(failure=failure):
                self.provider_controls = copy.deepcopy(fresh)
                if failure == "signature":
                    self.provider_controls["signed_databases"][0]["signature_verified"] = False
                else:
                    daily = next(
                        d
                        for d in self.provider_controls["signed_databases"]
                        if d["name"] == "daily.cvd"
                    )
                    daily["created_at_epoch"] = (
                        int(self.clock.timestamp())
                        - recovery.auto.POLICY["max_candidate_age_seconds"]
                        - 1
                    )
                with self.assertRaises(recovery.RehearsalError):
                    self.test.resume(confirm_reconnected=True)
                self.assertFalse(self.created_posts())
        self.provider_controls = fresh
        self.test.resume(confirm_reconnected=True)
        self.assertEqual(len(self.created_posts()), 1)
        self.assertGreaterEqual(len(self.control_reads), 3)
        self.unchanged_private_registration()

    def test_successful_resume_reuses_candidate_and_preserves_rollback(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        self.finish_recovery()
        report = self.test.status()
        self.assertTrue(report["recovery_verified"])
        self.assertEqual(len(self.created_posts()), 1)
        self.assertEqual(len(self.cancelled_posts()), 1)
        request = self.created_posts()[0][2]
        approved = self.tool.build_request()
        for field in ("source", "serviceAccount", "steps", "timeout", "options"):
            self.assertEqual(request[field], approved[field])
        self.assertEqual(request["queueTtl"], "300s")
        self.assertEqual(request["tags"], approved["tags"] + [self.test.load()["request_tag"]])
        self.assertEqual(
            len([b for b in self.rest.builds if "_RELEASE" in b.get("substitutions", {})]), 1
        )
        state, _ = self.tool.store.load_json("state.json")
        self.assertEqual(state["current"]["image"], NEXT)
        self.assertEqual(state["current"]["rollback_image"], self.baseline["current"]["image"])
        self.assertTrue(
            recovery.private.configurations_equal(
                state["current"]["configuration"],
                recovery.private.expected_configuration(
                    self.baseline["current"]["configuration"], NEXT
                ),
            )
        )
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.test.resume(confirm_reconnected=True)
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_duplicate_candidate_build_does_not_pass_recovery_acceptance(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        self.finish_recovery()
        duplicate = copy.deepcopy(next(b for b in self.rest.builds if b["id"] == CANDIDATE))
        duplicate["id"] = OTHER
        self.rest.builds.append(duplicate)
        with self.assertRaises(recovery.RehearsalError):
            self.test.status()
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_missing_resume_marker_is_not_recovery_acceptance(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        self.finish_recovery()
        self.rest.marker_mode = "none"
        with self.assertRaisesRegex(
            recovery.RehearsalError, "^recovery_resume_marker_not_observed$"
        ):
            self.test.status()
        self.assertEqual(self.test.load()["phase"], "resume_submitted")
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_recovered_candidate_controls_must_match_provider_and_be_fresh(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        self.finish_recovery()
        fresh = copy.deepcopy(self.provider_controls)
        for failure, code in (
            ("different", "recovery_candidate_controls_differ"),
            ("stale", "recovery_candidate_database_stale"),
        ):
            with self.subTest(failure=failure):
                self.provider_controls = copy.deepcopy(fresh)
                if failure == "different":
                    self.provider_controls["clamav_version"] = PRIVATE
                else:
                    daily = next(
                        d
                        for d in self.provider_controls["signed_databases"]
                        if d["name"] == "daily.cvd"
                    )
                    daily["created_at_epoch"] = (
                        int(self.clock.timestamp())
                        - recovery.auto.POLICY["max_candidate_age_seconds"]
                        - 1
                    )
                with self.assertRaisesRegex(recovery.RehearsalError, "^" + code + "$"):
                    self.test.status()
                self.assertEqual(self.test.load()["phase"], "resume_submitted")
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_recovered_configuration_must_preserve_frozen_baseline(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        state = self.finish_recovery()
        files = state["current"]["files"]
        job_before = files["job-before.json"]
        recovery.private.container(job_before).setdefault("env", []).append(
            {"name": "UNEXPECTED", "value": PRIVATE}
        )
        configuration = recovery.private.job_configuration(job_before)
        files["state.json"]["baseline_fingerprint"] = recovery.private.fingerprint(configuration)
        state["current"]["configuration"] = recovery.private.expected_configuration(
            configuration, NEXT
        )
        recovery.private.container(self.base.base.fixture.job).setdefault("env", []).append(
            {"name": "UNEXPECTED", "value": PRIVATE}
        )
        self.set_state(state)
        self.record_external_changes()
        with self.assertRaisesRegex(
            recovery.RehearsalError, "^recovery_promoted_configuration_differs$"
        ):
            self.test.status()
        self.assertEqual(self.test.load()["phase"], "resume_submitted")
        self.assertEqual(len(self.created_posts()), 1)
        self.unchanged_private_registration()

    def test_prepare_near_due_tick_stops_instead_of_planning_a_stale_baseline(self):
        tick = recovery.next_tick(self.clock + timedelta(minutes=10))
        self.clock = tick - timedelta(minutes=2)
        state, _ = self.tool.store.load_json("state.json")
        epoch = int(self.clock.timestamp()) - recovery.auto.POLICY["refresh_after_seconds"] - 1
        for report in (
            state["current"]["files"]["engine-controls.json"],
            state["current"]["files"]["state.json"]["candidate_controls"],
        ):
            next(item for item in report["signed_databases"] if item["name"] == "daily.cvd")[
                "created_at_epoch"
            ] = epoch
        state["current"]["daily_created_at_epoch"] = epoch
        self.set_state(state)
        self.record_external_changes()
        with self.assertRaisesRegex(
            recovery.RehearsalError, "^recovery_prepare_too_close_to_due_tick$"
        ):
            self.test.prepare()
        self.assertFalse(self.test.path.exists())
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_old_healthy_checkpoint_cannot_prepare_even_when_metric_exists(self):
        state, _ = self.tool.store.load_json("state.json")
        state["last_healthy_at"] = (self.clock - timedelta(hours=24)).isoformat()
        self.set_state(state)
        self.record_external_changes()
        ready = {
            "read_complete": True,
            "enabled_monitoring_metadata_matches_plan": True,
            "healthy_metric_ingestion_verified": True,
        }
        with patch.object(recovery.observation, "inspect", return_value=ready):
            with self.assertRaisesRegex(
                recovery.RehearsalError, "^recovery_recent_health_not_verified$"
            ):
                self.test.prepare()
        self.assertFalse(self.test.path.exists())
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_boolean_lease_version_cannot_authorize_cancellation(self):
        self.arm()
        self.active_campaign()
        lease, generation = self.tool.store.load_json("lease.json")
        lease["schema_version"] = True
        self.tool.store.values["lease.json"] = (lease, generation)
        self.record_external_changes()
        with self.assertRaisesRegex(
            recovery.RehearsalError, "^recovery_controller_lease_not_verified$"
        ):
            self.test.watch_and_interrupt(wait_seconds=0)
        self.assertFalse(self.cancelled_posts())
        self.assertFalse(self.created_posts())
        self.unchanged_private_registration()

    def test_historical_or_wrong_identity_marker_is_not_recovery_acceptance(self):
        self.interrupt()
        self.test.resume(confirm_reconnected=True)
        self.finish_recovery()
        entry = self.rest.marker_entry()
        wrong_build = copy.deepcopy(entry)
        wrong_build["resource"]["labels"]["build_id"] = OTHER
        wrong_digest = copy.deepcopy(entry)
        wrong_digest["jsonPayload"]["current_image"] = self.baseline["current"]["image"]
        historical = copy.deepcopy(entry)
        historical["timestamp"] = (self.clock - timedelta(days=1)).isoformat()
        for marker in (wrong_build, wrong_digest, historical):
            with self.subTest(marker=marker):
                self.rest.log_pages = [{"entries": [marker]}]
                with self.assertRaisesRegex(
                    recovery.RehearsalError, "^recovery_resume_marker_not_observed$"
                ):
                    self.test.status()
                self.assertEqual(self.test.load()["phase"], "resume_submitted")
        self.unchanged_private_registration()


if __name__ == "__main__":
    unittest.main()
