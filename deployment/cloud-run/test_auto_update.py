"""Offline scheduled-controller transactions, recovery and budget boundaries."""

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import auto_state
import auto_update as auto

SPEC = importlib.util.spec_from_file_location(
    "controller_fixtures", Path(__file__).with_name("test_maintain_demo.py")
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
OWNER = "12345678-1234-4234-8234-123456789abc"
OTHER = "22345678-1234-4234-8234-123456789abc"
CHILD = "32345678-1234-4234-8234-123456789abc"
NEXT = auto.maintenance.IMAGE + "@sha256:" + "d" * 64
CHANNEL = f"projects/{auto.PROJECT}/notificationChannels/123"


class MemoryStore:
    bucket = "malscan-v2-poc-db-operations"

    def __init__(self, value):
        self.objects = {"state.json": (copy.deepcopy(value), 1)}
        self.serial = 1
        self.puts = []
        self.fail_phase = None
        self.uncertain_phase = None

    @property
    def state(self):
        return copy.deepcopy(self.objects["state.json"][0])

    def load_json(self, name):
        return copy.deepcopy(self.objects.get(name, (None, 0)))

    def put_json(self, name, value, expected_generation):
        current = self.objects.get(name, (None, 0))[1]
        if current != expected_generation:
            raise auto_state.ConflictError("storage_generation_conflict")
        active = value.get("active")
        phase = active["files"]["state.json"]["phase"] if active else None
        if name == "state.json" and phase and phase == self.fail_phase:
            raise auto_state.ConflictError("storage_generation_conflict")
        self.serial += 1
        self.objects[name] = (copy.deepcopy(value), self.serial)
        self.puts.append((name, copy.deepcopy(value)))
        if name == "state.json" and phase and phase == self.uncertain_phase:
            self.uncertain_phase = None
            raise auto_state.UncertainWriteError("storage_write_response_unknown")
        return self.serial

    def delete(self, name, expected_generation):
        if self.objects.get(name, (None, 0))[1] != expected_generation:
            raise auto_state.ConflictError("storage_generation_conflict")
        del self.objects[name]


class Cloud:
    def __init__(self, current, controls, store):
        self.current = copy.deepcopy(current)
        self.controls = copy.deepcopy(controls)
        self.store = store
        self.build = None
        self.calls = []
        self.writes = []
        self.fail_submit_after_accept = False
        self.fail_update_after_accept = False
        self.build_status = "SUCCESS"
        self.failed_step = None
        self.other_terminal = True
        self.candidate = NEXT
        self.parent_source_override = None
        self.parent_tags = [auto.CONTROLLER_TAG]

    def job(self):
        return copy.deepcopy(self.current)

    def call(self, args, **kwargs):
        self.calls.append(copy.deepcopy(args))
        if args[:2] == ["builds", "describe"]:
            if args[2] in (OWNER, OTHER):
                if args[2] == OTHER:
                    return {"id": OTHER, "status": "SUCCESS" if self.other_terminal else "WORKING"}
                return {
                    "id": OWNER,
                    "status": "WORKING",
                    "serviceAccount": auto.CONTROLLER_ACCOUNT,
                    "tags": self.parent_tags,
                    "source": {
                        "storageSource": self.parent_source_override
                        or self.store.state["source"]["storage_source"]
                    },
                }
            return copy.deepcopy(self.build)
        if args[:2] == ["builds", "submit"]:
            state = self.store.state
            intent = state["active"]["files"]["state.json"]
            assert intent["phase"] == "submission_pending"
            release = next(a.split("=", 2)[2] for a in args if a.startswith("--substitutions="))
            assert release == state["active"]["release"]
            self.writes.append("build")
            original = fixture.successful_build()
            text = (
                json.dumps(original)
                .replace(fixture.RELEASE, release)
                .replace(fixture.BUILD_ID, CHILD)
            )
            self.build = json.loads(text)
            self.build["results"]["images"][0]["digest"] = self.candidate.split("@", 1)[1]
            self.build["status"] = self.build_status
            if self.failed_step is not None:
                self.build["steps"][self.failed_step]["status"] = "FAILURE"
            if self.fail_submit_after_accept:
                self.fail_submit_after_accept = False
                raise auto.maintenance.MaintenanceError("submission response lost")
            return {"id": CHILD}
        if args[:2] == ["builds", "list"]:
            return [copy.deepcopy(self.build)] if self.build else []
        if args[:3] == ["artifacts", "docker", "images"]:
            return {"image_summary": {"fully_qualified_digest": self.candidate}}
        if args[:2] == ["logging", "read"]:
            return [{"jsonPayload": copy.deepcopy(self.controls)}]
        if args[:3] == ["run", "jobs", "update"]:
            intent = self.store.state["active"]["files"]["state.json"]
            assert intent["phase"] == "promotion_pending"
            assert args[-1] == "--image=" + intent["candidate_image"]
            self.writes.append("update")
            auto.maintenance.container(self.current)["image"] = intent["candidate_image"]
            if self.fail_update_after_accept:
                self.fail_update_after_accept = False
                raise auto.maintenance.MaintenanceError("update response lost")
            return copy.deepcopy(self.current)
        raise AssertionError(args)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "deployment/cloud-run").mkdir(parents=True)
        (self.repo / "worker/src/malscan_worker/runtime").mkdir(parents=True)
        (self.repo / "backend").mkdir()
        for name in (auto.maintenance.CONFIG, ".gcloudignore", ".dockerignore"):
            (self.repo / name).write_text("test input")
        (self.repo / "worker/src/malscan_worker/runtime/engine_controls.py").write_bytes(
            b"controls"
        )
        self.now = datetime.now(timezone.utc)
        approved_cloud = fixture.FakeCloud()
        for item in approved_cloud.report["signed_databases"]:
            item["created_at_epoch"] = int(self.now.timestamp()) - 4 * 86400
            item["version"] = 1
        directory = self.root / fixture.RELEASE
        tool = auto.maintenance.Maintenance(directory, self.repo, approved_cloud)
        tool.prepare()
        tool.submit()
        tool.status()
        tool.update_image()
        self.files = {name: auto.maintenance.read_private(directory / name) for name in auto.FILES}
        value = auto.initial_state(
            self.files, "a" * 40, tool.load()["source_sha256"], "b" * 64, CHANNEL
        )
        value["source"]["storage_source"] = {
            "bucket": MemoryStore.bucket,
            "object": "bundles/" + "a" * 40 + ".tar.gz",
            "generation": "42",
        }
        self.store = MemoryStore(value)
        controls = copy.deepcopy(approved_cloud.report)
        for item in controls["signed_databases"]:
            item["created_at_epoch"] = int(self.now.timestamp()) - 3600
            item["version"] = 2
        self.cloud = Cloud(approved_cloud.current, controls, self.store)
        self.live_count = 0
        self.cleanup_calls = 0

    def tearDown(self):
        self.temporary.cleanup()

    def change(self, edit):
        value, generation = self.store.load_json("state.json")
        edit(value)
        self.store.put_json("state.json", value, generation)

    def enabled(self):
        self.change(lambda state: state.update(enabled=True))

    def controller(self):
        c = auto.Controller(
            self.store,
            OWNER,
            self.repo,
            cloud=self.cloud,
            now=lambda: self.now,
            sleep=lambda _: None,
            deadline_seconds=0,
        )

        def cleanup(root):
            self.cleanup_calls += 1
            return self.live_count

        c.cleanup = cleanup
        return c

    def test_paused_probe_only_reads_and_seeds_verified_heartbeat(self):
        result = self.controller().run()
        self.assertEqual(result["status"], "paused_healthy")
        self.assertEqual(result["marker"], auto.HEALTHY_MARKER)
        self.assertEqual(self.store.state["last_controller_build_id"], OWNER)
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.cleanup_calls, 0)

    def test_due_update_persists_intents_and_advances_real_rollback(self):
        self.enabled()
        previous = self.store.state["current"]["image"]
        result = self.controller().run()
        self.assertEqual(result["status"], "updated")
        self.assertEqual(self.cloud.writes, ["build", "update"])
        self.assertEqual(self.store.state["current"]["image"], NEXT)
        self.assertEqual(self.store.state["current"]["rollback_image"], previous)
        self.assertIsNone(self.store.state["active"])
        self.assertEqual(len(self.store.state["attempts"]), 1)
        submit = next(args for args in self.cloud.calls if args[:2] == ["builds", "submit"])
        self.assertIn("--service-account=" + auto.BUILDER_ACCOUNT, submit)
        self.assertIn(
            "--gcs-source-staging-dir=gs://" + self.store.bucket + "/build-sources", submit
        )

    def test_not_due_does_not_spend_a_build(self):
        self.enabled()

        def fresh(state):
            epoch = int(self.now.timestamp()) - 3600
            state["current"]["daily_created_at_epoch"] = epoch
            for item in state["current"]["files"]["engine-controls.json"]["signed_databases"]:
                item["created_at_epoch"] = epoch
            state["current"]["files"]["state.json"]["candidate_controls"] = copy.deepcopy(
                state["current"]["files"]["engine-controls.json"]
            )

        self.change(fresh)
        self.assertEqual(self.controller().run()["status"], "healthy_no_update_due")
        self.assertEqual(self.cloud.writes, [])

    def test_source_and_manual_job_drift_stop_before_any_remote_write(self):
        self.enabled()
        (self.repo / "worker/changed.py").write_text("changed")
        with self.assertRaisesRegex(auto.UpdateError, "approved_application_source_changed"):
            self.controller().run()
        (self.repo / "worker/changed.py").unlink()
        auto.maintenance.container(self.cloud.current)["env"][0]["value"] = "private-other"
        with self.assertRaisesRegex(auto.UpdateError, "live_job_changed"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])

    def test_wrong_parent_generation_account_or_source_is_not_trusted(self):
        source = copy.deepcopy(self.store.state["source"]["storage_source"])
        source["generation"] = "43"
        self.cloud.parent_source_override = source
        with self.assertRaisesRegex(auto.UpdateError, "controller_build_identity_invalid"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])

    def test_parent_allows_setup_probe_tag_alongside_required_controller_tag(self):
        self.cloud.parent_tags.append("malscan-db-probe-123456789abc")
        self.assertEqual(self.controller().run()["status"], "paused_healthy")

    def test_busy_nonterminal_owner_does_not_steal_lock(self):
        self.store.put_json("lease.json", {"schema_version": 1, "owner_build_id": OTHER}, 0)
        self.cloud.other_terminal = False
        result = self.controller().run()
        self.assertEqual(result["status"], "busy")
        self.assertEqual(self.store.load_json("lease.json")[0]["owner_build_id"], OTHER)
        self.assertEqual(self.cloud.writes, [])

    def test_terminal_owner_can_be_reconciled_without_time_expiry(self):
        self.store.put_json("lease.json", {"schema_version": 1, "owner_build_id": OTHER}, 0)
        self.assertEqual(self.controller().run()["status"], "paused_healthy")
        self.assertEqual(self.store.load_json("lease.json"), (None, 0))

    def test_submission_response_loss_reconciles_one_existing_build(self):
        self.enabled()
        self.cloud.fail_submit_after_accept = True
        with self.assertRaises(auto.maintenance.MaintenanceError):
            self.controller().run()
        self.assertEqual(
            self.store.state["active"]["files"]["state.json"]["phase"], "submission_pending"
        )
        self.assertEqual(self.controller().run()["status"], "reconciled")
        self.assertEqual(self.cloud.writes, ["build", "update"])

    def test_lost_intent_write_never_sends_an_unconfirmed_build(self):
        self.enabled()
        self.store.uncertain_phase = "submission_pending"
        with self.assertRaises(auto_state.UncertainWriteError):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])
        with self.assertRaisesRegex(auto.UpdateError, "submission_unknown"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])

    def test_failed_intent_cas_blocks_build_and_preserves_prepared_campaign(self):
        self.enabled()
        self.store.fail_phase = "submission_pending"
        with self.assertRaises(auto_state.ConflictError):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.store.state["active"]["files"]["state.json"]["phase"], "prepared")

    def test_update_response_loss_is_reconciled_without_another_update(self):
        self.enabled()
        self.cloud.fail_update_after_accept = True
        with self.assertRaises(auto.maintenance.MaintenanceError):
            self.controller().run()
        self.assertEqual(
            self.store.state["active"]["files"]["state.json"]["phase"], "promotion_pending"
        )
        self.assertEqual(self.controller().run()["status"], "reconciled")
        self.assertEqual(self.cloud.writes, ["build", "update"])

    def test_failed_build_keeps_current_and_allows_only_later_day_retry(self):
        self.enabled()
        self.cloud.build_status = "FAILURE"
        self.cloud.failed_step = 0
        current = self.store.state["current"]
        with self.assertRaisesRegex(auto.UpdateError, "image_build_failed"):
            self.controller().run()
        self.assertEqual(self.store.state["current"], current)
        self.assertIsNone(self.store.state["active"])
        with self.assertRaisesRegex(auto.UpdateError, "daily_build_limit_reached"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, ["build"])

    def test_controls_failure_and_old_or_future_candidate_never_promote(self):
        self.enabled()
        self.cloud.controls["controls"]["clamav_eicar_detected"] = False
        with self.assertRaises(auto.maintenance.MaintenanceError):
            self.controller().run()
        self.assertEqual(self.cloud.writes, ["build"])
        self.assertEqual(self.store.state["current"]["image"], fixture.NEW)

    def test_owned_image_cap_blocks_new_build(self):
        self.enabled()
        self.live_count = 4
        with self.assertRaisesRegex(auto.UpdateError, "owned_image_limit_reached"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])

    def test_same_image_noop_preserves_original_rollback_and_checkpoint(self):
        self.enabled()
        before = self.store.state["current"]
        self.cloud.candidate = before["image"]
        self.assertEqual(self.controller().run()["status"], "updated")
        self.assertEqual(self.cloud.writes, ["build"])
        self.assertEqual(self.store.state["current"], before)
        self.assertIsNone(self.store.state["active"])
        self.assertEqual(len(self.store.state["owned"]), 1)

    def test_monthly_counter_blocks_thirteenth_build_before_submission(self):
        self.enabled()
        # Distinct earlier UTC days in this month, independent of today's date.
        self.now = self.now.replace(day=20)
        attempts = [
            {
                "release": f"db-202611{i:02d}T010000Z-123456789abc",
                "started_at": self.now.replace(day=i).isoformat(),
            }
            for i in range(1, 13)
        ]
        self.change(lambda value: value.update(attempts=attempts))
        with self.assertRaisesRegex(auto.UpdateError, "monthly_build_limit_reached"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])

    def test_resumed_campaign_does_not_use_second_attempt_or_apply_daily_gate(self):
        self.enabled()
        self.cloud.build_status = "WORKING"
        with self.assertRaisesRegex(auto.UpdateError, "build_still_running"):
            self.controller().run()
        attempts = self.store.state["attempts"]
        self.cloud.build["status"] = "SUCCESS"
        self.assertEqual(self.controller().run()["status"], "reconciled")
        self.assertEqual(self.store.state["attempts"], attempts)
        self.assertEqual(self.cloud.writes, ["build", "update"])

    def test_candidate_future_old_and_regressing_database_never_updates_job(self):
        initial = self.store.state
        current_job = self.cloud.job()
        initial_controls = copy.deepcopy(self.cloud.controls)
        for age, version, code in (
            (-60, 2, "not_fresh_enough"),
            (3 * 86400, 2, "not_fresh_enough"),
            (3600, 2, "candidate_database_regressed"),
        ):
            with self.subTest(age=age, version=version):
                self.store = MemoryStore(initial)
                self.cloud = Cloud(current_job, initial_controls, self.store)
                self.enabled()
                if code == "candidate_database_regressed":

                    def version_three(state):
                        files = state["current"]["files"]
                        for item in files["engine-controls.json"]["signed_databases"]:
                            if item["name"] == "daily.cvd":
                                item["version"] = 3
                        files["state.json"]["candidate_controls"] = copy.deepcopy(
                            files["engine-controls.json"]
                        )

                    self.change(version_three)
                for item in self.cloud.controls["signed_databases"]:
                    if item["name"] == "daily.cvd":
                        item.update(
                            created_at_epoch=int(self.now.timestamp()) - age, version=version
                        )
                if age < 0:
                    # The reused maintenance verifier already rejects a future
                    # timestamp before the controller's stricter 2-day guard.
                    with self.assertRaises(auto.maintenance.MaintenanceError):
                        self.controller().run()
                else:
                    with self.assertRaisesRegex(auto.UpdateError, code):
                        self.controller().run()
                self.assertEqual(self.cloud.writes, ["build"])

    def test_missing_or_wrong_mutation_intent_blocks_update_and_submit(self):
        controller = self.controller()
        controller.state, controller.generation = self.store.load_json("state.json")
        self.assertTrue(controller.lease.acquire(controller.owner_terminal))
        for args in (
            ["builds", "submit", "."],
            ["run", "jobs", "update", auto.JOB, f"--region={auto.REGION}", f"--image={NEXT}"],
        ):
            with self.assertRaisesRegex(auto.UpdateError, "mutation_intent_missing"):
                controller.cloud.call(args)
        controller.state["active"] = {
            "release": fixture.RELEASE,
            "files": {"state.json": {"phase": "promotion_pending", "candidate_image": NEXT}},
        }
        controller.persist()
        with self.assertRaisesRegex(auto.UpdateError, "mutation_intent_missing"):
            controller.cloud.call(
                [
                    "run",
                    "jobs",
                    "update",
                    auto.JOB,
                    f"--region={auto.REGION}",
                    f"--image={fixture.NEW}",
                ]
            )
        self.assertEqual(self.cloud.writes, [])
        controller.lease.release()

    def test_retention_adapter_requires_durable_matching_delete_intent(self):
        removed = []
        controller = auto.Controller(
            self.store,
            OWNER,
            self.repo,
            cloud=self.cloud,
            now=lambda: self.now,
            delete=removed.append,
            inspect=lambda: {},
        )
        controller.state, controller.generation = self.store.load_json("state.json")
        self.assertTrue(controller.lease.acquire(controller.owner_terminal))

        def without_intent(inspect, delete, save, *args, **kwargs):
            delete(NEXT)

        with patch.object(auto.auto_retention, "run", side_effect=without_intent):
            with self.assertRaisesRegex(auto.UpdateError, "mutation_intent_missing"):
                controller.cleanup(self.root)
        self.assertEqual(removed, [])

        def with_intent(inspect, delete, save, *args, **kwargs):
            save({"phase": "deletion_pending", "pending": NEXT})
            self.assertEqual(self.store.state["cleanup"]["pending"], NEXT)
            with self.assertRaisesRegex(auto.UpdateError, "mutation_intent_missing"):
                delete(fixture.NEW)
            delete(NEXT)
            save({"phase": "completed", "pending": None})
            return {"summary": {"removed": 1}}

        with patch.object(auto.auto_retention, "run", side_effect=with_intent), patch.object(
            auto.auto_retention, "live_owned_count", return_value=0
        ):
            self.assertEqual(controller.cleanup(self.root), 0)
        self.assertEqual(removed, [NEXT])
        controller.lease.release()

    def test_unreconciled_cleanup_is_never_discarded_by_new_owned_image_or_finish(self):
        self.enabled()
        self.cloud.fail_update_after_accept = True
        with self.assertRaises(auto.maintenance.MaintenanceError):
            self.controller().run()
        unknown = {"phase": "uncertain", "pending": fixture.OLD}
        self.change(lambda state: state.update(cleanup=copy.deepcopy(unknown)))
        before = self.store.state["current"]
        with self.assertRaisesRegex(auto.UpdateError, "unreconciled_cleanup_preserved"):
            self.controller().run()
        self.assertEqual(self.store.state["cleanup"], unknown)
        self.assertEqual(self.store.state["current"], before)
        self.assertIsNotNone(self.store.state["active"])
        self.assertEqual(self.cloud.writes, ["build", "update"])

    def test_pending_promotion_rechecks_future_database_before_committing_current(self):
        self.enabled()
        self.cloud.fail_update_after_accept = True
        with self.assertRaises(auto.maintenance.MaintenanceError):
            self.controller().run()
        # Cloud readback succeeded later, but its supplied daily timestamp is
        # now future-dated relative to the controller; do not adopt it silently.
        self.now -= timedelta(hours=2)
        self.change(
            lambda value: value["attempts"][0].update(
                started_at=(self.now - timedelta(hours=1)).isoformat()
            )
        )
        before = self.store.state["current"]
        with self.assertRaisesRegex(auto.UpdateError, "candidate_database_not_fresh_enough"):
            self.controller().run()
        self.assertEqual(self.store.state["current"], before)
        self.assertEqual(self.store.state["active"]["files"]["state.json"]["phase"], "promoted")

    def test_failed_publication_after_successful_controls_preserves_campaign(self):
        self.enabled()
        self.cloud.build_status = "FAILURE"
        with self.assertRaisesRegex(auto.UpdateError, "image_publication_outcome_unknown"):
            self.controller().run()
        self.now += timedelta(days=1)
        with self.assertRaisesRegex(auto.UpdateError, "image_publication_outcome_unknown"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, ["build"])
        self.assertEqual(self.store.state["active"]["files"]["state.json"]["phase"], "build_failed")

    def test_prepared_campaign_checks_and_moves_actual_submission_day_reservation(self):
        self.enabled()
        self.store.fail_phase = "submission_pending"
        with self.assertRaises(auto_state.ConflictError):
            self.controller().run()
        release = self.store.state["active"]["release"]
        self.store.fail_phase = None
        self.now += timedelta(days=1)
        # A separate reservation today must prevent this old prepared campaign
        # from issuing the day's second build even though its old count differs.
        today = {"release": "db-20261101T010000Z-abcdef012345", "started_at": self.now.isoformat()}
        self.change(lambda state: state["attempts"].append(today))
        with self.assertRaisesRegex(auto.UpdateError, "daily_build_limit_reached"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.store.state["active"]["files"]["state.json"]["phase"], "prepared")
        self.change(
            lambda state: state.update(
                attempts=[a for a in state["attempts"] if a["release"] == release]
            )
        )
        self.assertEqual(self.controller().run()["status"], "reconciled")
        self.assertEqual(self.cloud.writes, ["build", "update"])
        self.assertEqual(
            auto.timestamp(self.store.state["attempts"][0]["started_at"]).date(), self.now.date()
        )

    def test_prepared_campaign_crossing_month_still_obeys_new_month_cap(self):
        self.enabled()
        self.store.fail_phase = "submission_pending"
        with self.assertRaises(auto_state.ConflictError):
            self.controller().run()
        self.store.fail_phase = None
        self.now = (self.now.replace(day=1) + timedelta(days=32)).replace(day=20)
        month = self.now.strftime("%Y%m")
        attempts = [
            {
                "release": f"db-{month}{day:02d}T010000Z-123456789abc",
                "started_at": self.now.replace(day=day).isoformat(),
            }
            for day in range(1, 13)
        ]
        self.change(lambda state: state["attempts"].extend(attempts))
        with self.assertRaisesRegex(auto.UpdateError, "monthly_build_limit_reached"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.store.state["active"]["files"]["state.json"]["phase"], "prepared")

    def test_completed_cleanup_retired_before_owned_ledger_changes(self):
        controller = self.controller()
        controller.state, controller.generation = self.store.load_json("state.json")
        self.assertTrue(controller.lease.acquire(controller.owner_terminal))
        controller.state["cleanup"] = {"phase": "completed"}
        controller.persist()
        controller._owned(NEXT, fixture.RELEASE)
        self.assertIsNone(self.store.state["cleanup"])
        controller.state["cleanup"] = {"phase": "uncertain", "pending": fixture.OLD}
        controller.persist()
        before = self.store.state["owned"]
        with self.assertRaisesRegex(auto.UpdateError, "unreconciled_cleanup_preserved"):
            controller._owned(fixture.OLD, "db-20261102T000000Z-123456789abc")
        self.assertEqual(self.store.state["owned"], before)
        controller.lease.release()

    def test_working_build_checkpoint_is_preserved_without_second_submit(self):
        self.enabled()
        self.cloud.build_status = "WORKING"
        with self.assertRaisesRegex(auto.UpdateError, "build_still_running"):
            self.controller().run()
        self.assertEqual(self.cloud.writes, ["build"])
        self.cloud.build_status = "SUCCESS"
        self.cloud.build["status"] = "SUCCESS"
        self.assertEqual(self.controller().run()["status"], "reconciled")
        self.assertEqual(self.cloud.writes, ["build", "update"])

    def test_state_validation_rejects_future_and_duplicate_attempts_and_boolean_version(self):
        value = self.store.state
        attempt = {
            "release": fixture.RELEASE,
            "started_at": (self.now + timedelta(seconds=1)).isoformat(),
        }
        value["attempts"] = [attempt]
        with self.assertRaisesRegex(auto.UpdateError, "attempts_invalid"):
            auto.validate_state(value, self.now)
        attempt["started_at"] = self.now.isoformat()
        value["attempts"] = [attempt, attempt]
        with self.assertRaisesRegex(auto.UpdateError, "attempts_invalid"):
            auto.validate_state(value, self.now)
        value["attempts"] = []
        value["current"]["files"]["state.json"]["version"] = True
        with self.assertRaisesRegex(auto.UpdateError, "approved_checkpoint_invalid"):
            auto.validate_state(value, self.now)

    def test_public_failure_codes_never_echo_arbitrary_provider_or_checkpoint_values(self):
        secret = "private-provider-secret-value"
        for error in (
            RuntimeError(secret),
            auto.UpdateError(secret),
            auto_state.StateError(secret),
            auto.maintenance.MaintenanceError(secret),
        ):
            self.assertNotIn(secret, auto.public_failure_code(error))
        self.assertEqual(
            auto.public_failure_code(auto.UpdateError("monthly_build_limit_reached")),
            "monthly_build_limit_reached",
        )

    def test_public_status_rejects_arbitrary_private_phase_or_status_values(self):
        value = self.store.state
        value["last_status"] = "private-provider-secret-value"
        with self.assertRaisesRegex(auto.UpdateError, "coordinator_state_invalid"):
            auto.validate_state(value, self.now)
        value["last_status"] = None
        value["active"] = {
            "release": fixture.RELEASE,
            "files": {
                "state.json": {"release": fixture.RELEASE, "phase": "private-secret"},
                "job-before.json": {},
            },
        }
        with self.assertRaisesRegex(auto.UpdateError, "coordinator_active_checkpoint_invalid"):
            auto.validate_state(value, self.now)

    def test_numeric_control_boolean_is_not_a_successful_engine_control(self):
        controls = copy.deepcopy(self.cloud.controls)
        controls["controls"]["clamav_eicar_detected"] = 1
        with self.assertRaisesRegex(auto.UpdateError, "approved_controls_invalid"):
            auto._daily(controls, controls["module_sha256"])


if __name__ == "__main__":
    unittest.main()
