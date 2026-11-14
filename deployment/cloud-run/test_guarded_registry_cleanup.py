"""Paused updater guards and deletion recovery, without authenticated cloud calls."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = load("guarded_cleanup_test_module", "guarded-registry-cleanup.py")
fixtures = load("guarded_cleanup_prune_fixtures", "test_prune_registry.py")


class ReadOnlyStore:
    def __init__(self):
        self.lease = (None, 0)
        self.reads = []

    def load_json(self, name):
        self.reads.append(name)
        if name != "lease.json":
            raise AssertionError("Unexpected coordinator read")
        return copy.deepcopy(self.lease)


class ReadOnlyProvisioner:
    """The wrapper must call the real Provisioner's full approval validation."""

    def __init__(self):
        self.plan = {
            "source_commit": "1" * 40,
            "source_sha256": "2" * 64,
            "bundle_sha256": "3" * 64,
            "bucket": mod.prune.PROJECT + "-db-operations",
        }
        self.state = {
            "enabled": False,
            "active": None,
            "current": {
                "image": fixtures.image("a"),
                "rollback_image": fixtures.image("b"),
                "configuration": {},
                "files": {
                    "state.json": {
                        "release": fixtures.RELEASE,
                        "marker": "REMOTE_CURRENT",
                    }
                },
            },
        }
        self.generation = 7
        self.journal = {"storage_source": {"generation": "9"}}
        self.store = ReadOnlyStore()
        self.scheduler = {**self.scheduler_document(), "state": "PAUSED"}
        self.approval_calls = []
        self.scheduler_reads = []
        self.before_approval = None
        self.approval_failure = None

    def scheduler_document(self):
        return {
            "name": (
                f"projects/{mod.prune.PROJECT}/locations/{mod.prune.REGION}"
                "/jobs/malscan-v2-database-updates"
            ),
            "schedule": "23 3,15 * * *",
            "timeZone": "UTC",
            "retryConfig": {"retryCount": 0},
        }

    def get(self, url):
        self.scheduler_reads.append(url)
        return copy.deepcopy(self.scheduler)

    def _approved_state(self, *, check_current=True):
        self.approval_calls.append(check_current)
        if self.before_approval:
            self.before_approval()
        if self.approval_failure:
            raise mod.setup.SetupError(self.approval_failure)
        return copy.deepcopy(self.state), self.generation


class GuardedCleanupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name)
        self.plan_dir = self.home / "original-plan"
        self.plan_dir.mkdir(mode=0o700)
        self.output = self.home / "cleanup-operation"
        self.report = fixtures.fixture()
        self.cloud = fixtures.FakeCloud(self.report)
        self.provider = ReadOnlyProvisioner()
        self.inventory = self.home / "registry-inventory.json"
        self.inspector_homes = []
        self.save_review()

    def save_review(self):
        payload = json.dumps(self.report, indent=2).encode()
        self.inventory.write_bytes(payload)
        self.inventory.chmod(0o600)
        self.review_hash = hashlib.sha256(payload).hexdigest()

    def inspect(self, temporary_home):
        temporary_home = Path(temporary_home)
        self.inspector_homes.append(temporary_home)
        self.assertNotEqual(temporary_home, self.home)
        checkpoint = (
            temporary_home / ".malscan-v2-operations/maintenance" / fixtures.RELEASE / "state.json"
        )
        self.assertEqual(json.loads(checkpoint.read_text())["marker"], "REMOTE_CURRENT")
        self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)
        return self.cloud.inspect()

    def prepare(self, **kwargs):
        return mod.prepare(
            self.plan_dir,
            self.inventory,
            self.review_hash,
            self.output,
            home=self.home,
            provisioner=self.provider,
            inspector=self.inspect,
            **kwargs,
        )

    def operation(self, *, delete=None):
        return mod.Operation(
            self.output,
            self.plan_dir,
            home=self.home,
            provisioner=self.provider,
            inspector=self.inspect,
            delete=delete or self.cloud.delete,
        )

    def journal(self):
        return json.loads((self.output / "state/state.json").read_text())

    def test_prepare_is_read_only_and_uses_current_checkpoint_in_fresh_private_home(self):
        stale = self.home / ".malscan-v2-operations/maintenance" / fixtures.RELEASE
        stale.mkdir(parents=True, mode=0o700)
        (stale / "state.json").write_text('{"marker":"STALE_MANUAL_CHECKPOINT"}')
        self.prepare()
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(
            (self.output / "guarded-registry-operation.json").stat().st_mode & 0o777, 0o600
        )
        self.assertTrue(self.provider.approval_calls)
        self.assertTrue(all(self.provider.approval_calls))
        self.assertTrue(self.provider.scheduler_reads)
        self.assertTrue(self.provider.store.reads)
        self.assertEqual(self.provider.state["enabled"], False)
        self.assertEqual(self.provider.state["active"], None)
        self.assertEqual(self.provider.store.lease, (None, 0))
        self.assertTrue(self.inspector_homes)
        self.assertTrue(all(not path.exists() for path in self.inspector_homes))

    def test_sha_mismatch_stops_before_provider_inventory_and_deletion(self):
        self.review_hash = "0" * 64
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.assertEqual(self.cloud.reads, 0)
        self.assertEqual(self.cloud.deleted, [])

    def test_stale_review_cannot_be_refreshed_into_a_new_approval(self):
        self.report["observed_at"] = (mod.prune.now() - timedelta(hours=25)).isoformat()
        self.save_review()
        with self.assertRaisesRegex(mod.prune.GuardError, "inventory_is_stale"):
            self.prepare()
        self.assertEqual(self.cloud.reads, 0)
        self.assertEqual(self.cloud.deleted, [])

    def test_enabled_active_scheduler_lease_and_read_errors_fail_closed(self):
        cases = {
            "enabled": lambda: self.provider.state.update(enabled=True),
            "active": lambda: self.provider.state.update(active={"release": "in-flight"}),
            "scheduler-enabled": lambda: self.provider.scheduler.update(state="ENABLED"),
            "scheduler-config": lambda: self.provider.scheduler.update(schedule="0 0 * * *"),
            "scheduler-missing": lambda: setattr(self.provider, "scheduler", None),
            "lease": lambda: setattr(self.provider.store, "lease", ({"owner": "active"}, 2)),
            "deleted-lease-generation": lambda: setattr(self.provider.store, "lease", (None, 2)),
            "source-rejected": lambda: setattr(
                self.provider, "approval_failure", "setup_registered_state_differs"
            ),
            "live-job-rejected": lambda: setattr(
                self.provider, "approval_failure", "setup_current_job_or_database_differs"
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.provider = ReadOnlyProvisioner()
                mutate()
                with self.assertRaises(mod.prune.GuardError):
                    self.prepare()
                self.assertEqual(self.cloud.deleted, [])
        self.assertFalse(self.output.exists())

    def test_paused_inventory_candidate_expansion_and_new_reference_are_rejected(self):
        original = copy.deepcopy(self.cloud.report)
        extra = copy.deepcopy(self.cloud.report["images"][2])
        extra["image"] = fixtures.image("2")
        self.cloud.report["images"].append(extra)
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.cloud.report = copy.deepcopy(original)
        row = self.cloud.report["images"][2]
        row.update(classification="protected_reference", protection_reasons=["new-reference"])
        self.cloud.report["references"].append(
            {
                "kind": "job",
                "resource": "another-consumer",
                "region": mod.prune.REGION,
                "image": row["image"],
            }
        )
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.assertEqual(self.cloud.deleted, [])

    def test_reviewed_worker_oci_manifest_or_protected_candidate_cannot_enter_plan(self):
        self.report["images"][2][
            "reported_media_type"
        ] = "application/vnd.oci.image.manifest.v1+json"
        self.save_review()
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.assertEqual(self.cloud.deleted, [])

    def test_generation_change_during_inventory_aborts_prepare(self):
        def changed(home):
            value = self.inspect(home)
            self.provider.generation += 1
            return value

        with self.assertRaises(mod.prune.GuardError):
            mod.prepare(
                self.plan_dir,
                self.inventory,
                self.review_hash,
                self.output,
                home=self.home,
                provisioner=self.provider,
                inspector=changed,
            )
        self.assertEqual(self.cloud.deleted, [])

    def test_apply_requires_original_coordinator_generation_source_and_current_pair(self):
        self.prepare()
        cases = {
            "generation": lambda: setattr(self.provider, "generation", 8),
            "source": lambda: self.provider.plan.update(source_sha256="4" * 64),
            "current": lambda: self.provider.state["current"].update(image=fixtures.image("9")),
            "rollback": lambda: self.provider.state["current"].update(
                rollback_image=fixtures.image("9")
            ),
            "configuration": lambda: self.provider.state["current"].update(
                configuration={"changed": True}
            ),
            "checkpoint": lambda: self.provider.state["current"]["files"]["state.json"].update(
                marker="CHANGED_CHECKPOINT"
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.provider = ReadOnlyProvisioner()
                mutate()
                with self.assertRaises(mod.prune.GuardError):
                    self.operation().run(apply=True)
                self.assertEqual(self.cloud.deleted, [])

    def test_apply_only_deletes_reviewed_worker_digests_and_repeated_apply_is_idempotent(self):
        self.prepare()
        result = self.operation().run(apply=True)
        self.assertEqual(result["phase"], "completed")
        self.assertEqual(self.cloud.deleted, [fixtures.image("c"), fixtures.image("d")])
        self.assertFalse(result["cloud_run_executed"])
        self.assertEqual(self.journal()["phase"], "completed")
        self.assertEqual(self.operation().run(apply=True)["phase"], "completed")
        self.assertEqual(len(self.cloud.deleted), 2)
        present = {row["image"] for row in self.cloud.report["images"]}
        self.assertIn(fixtures.image("a"), present)
        self.assertIn(fixtures.image("b"), present)
        self.assertIn(fixtures.image("1", "engine-poc"), present)
        self.assertEqual(len(self.inspector_homes), len(set(self.inspector_homes)))

    def test_uncertain_delete_that_remains_present_is_never_resubmitted(self):
        self.prepare()

        def fail_before(uri):
            raise mod.prune.GuardError("delete_request_outcome_uncertain")

        with self.assertRaises(mod.prune.GuardError):
            self.operation(delete=fail_before).run(apply=True)
        for apply in (False, True):
            with self.assertRaisesRegex(mod.prune.GuardError, "no_automatic_retry"):
                self.operation().run(apply=apply)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(self.journal()["phase"], "uncertain")
        self.assertEqual(self.journal()["pending"], fixtures.image("c"))

    def test_new_operation_cannot_reset_an_uncertain_existing_campaign(self):
        self.prepare()

        def fail_before(uri):
            raise mod.prune.GuardError("delete_request_outcome_uncertain")

        with self.assertRaises(mod.prune.GuardError):
            self.operation(delete=fail_before).run(apply=True)
        original_journal = self.output / "state/state.json"
        self.output = self.home / "another-cleanup-operation"
        self.prepare()
        with self.assertRaisesRegex(mod.prune.GuardError, "requires_reconciliation"):
            self.operation().run(apply=True)
        self.assertEqual(json.loads(original_journal.read_text())["pending"], fixtures.image("c"))
        self.assertEqual(self.cloud.deleted, [])

    def test_uncertain_absent_digest_reconciles_without_repeating_delete(self):
        self.prepare()

        def fail_after(uri):
            self.cloud.delete(uri)
            raise mod.prune.GuardError("delete_request_outcome_uncertain")

        with self.assertRaises(mod.prune.GuardError):
            self.operation(delete=fail_after).run(apply=True)
        checked = self.operation().run(apply=False)
        self.assertEqual(checked["removed_count"], 1)
        self.assertEqual(self.cloud.deleted, [fixtures.image("c")])
        self.assertEqual(self.operation().run(apply=True)["phase"], "completed")
        self.assertEqual(self.cloud.deleted, [fixtures.image("c"), fixtures.image("d")])

    def test_last_guard_failure_keeps_pending_journal_without_provider_delete(self):
        self.prepare()

        def stop_on_persisted_delete_intent():
            path = self.output / "state/state.json"
            if path.exists() and json.loads(path.read_text()).get("pending"):
                self.provider.approval_failure = "setup_current_job_or_database_differs"

        self.provider.before_approval = stop_on_persisted_delete_intent
        with self.assertRaises(mod.prune.GuardError):
            self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(self.journal()["phase"], "uncertain")
        self.assertEqual(self.journal()["pending"], fixtures.image("c"))
        self.assertFalse(self.provider.state["enabled"])

    def test_post_delete_guard_failure_stops_before_second_candidate(self):
        self.prepare()

        def enable_after_first_delete(cloud):
            if cloud.deleted:
                self.provider.state["enabled"] = True

        self.cloud.before_read = enable_after_first_delete
        with self.assertRaises(mod.prune.GuardError):
            self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [fixtures.image("c")])
        self.assertEqual(self.journal()["phase"], "uncertain")
        self.assertEqual(self.journal()["pending"], fixtures.image("c"))

    def test_delete_callback_requires_persisted_exact_candidate_intent(self):
        self.prepare()
        operation = self.operation()
        operation.run(apply=False)
        for uri in (fixtures.image("c"), fixtures.image("a"), fixtures.image("1", "engine-poc")):
            with self.subTest(uri=uri), self.assertRaisesRegex(
                mod.prune.GuardError, "persisted_delete_intent_not_verified"
            ):
                operation.delete(uri)
        self.assertEqual(self.cloud.deleted, [])

    def test_operation_wrapper_tamper_and_duplicate_prepare_are_rejected(self):
        self.prepare()
        with self.assertRaises((mod.prune.GuardError, OSError)):
            self.prepare()
        path = self.output / "guarded-registry-operation.json"
        wrapped = json.loads(path.read_text())
        wrapped["unreviewed-change"] = True
        path.write_text(json.dumps(wrapped))
        with self.assertRaises(mod.prune.GuardError):
            self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [])

    def test_private_paths_cannot_escape_home_follow_symlinks_or_use_public_permissions(self):
        self.output.mkdir(mode=0o755)
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.output.rmdir()
        actual = self.home / "actual"
        actual.mkdir(mode=0o700)
        self.output.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(mod.prune.GuardError):
            self.prepare()
        self.assertEqual(self.cloud.deleted, [])


if __name__ == "__main__":
    unittest.main()
