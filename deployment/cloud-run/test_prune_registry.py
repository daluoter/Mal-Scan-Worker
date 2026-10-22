"""Offline deletion guards; no authenticated cloud command runs in this suite."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "prune_registry", Path(__file__).with_name("prune-registry.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
RELEASE = "db-20261020T082329Z-b01014151255"


def image(letter, package="full-worker"):
    return mod.inventory.PREFIX + package + "@sha256:" + letter * 64


def fixture():
    created = mod.now() - timedelta(days=3)
    rows = []
    for letter, package, protected in [
        ("a", "full-worker", True),
        ("b", "full-worker", True),
        ("c", "full-worker", False),
        ("d", "full-worker", False),
        ("e", "demo-dispatcher", True),
        ("f", "engine-poc", True),
        ("1", "engine-poc", False),
    ]:
        rows.append(
            {
                "image": image(letter, package),
                "classification": "protected_reference" if protected else "unclassified",
                "protection_reasons": ["preserved-reference"] if protected else [],
                "tags": ["release-" + letter],
                "createTime": (created + timedelta(days=1) if protected else created).isoformat(),
                "updateTime": created.isoformat(),
                "reported_image_size_bytes": 100,
                "reported_media_type": mod.MANIFEST
                if package != "engine-poc"
                else "application/vnd.oci.image.index.v1+json",
            }
        )
    return {
        "schema_version": 1,
        "scope": "read_only_registry_cleanup_inventory",
        "project": mod.PROJECT,
        "repository_region": mod.REGION,
        "observed_at": mod.now().isoformat(),
        "readiness_issues": [],
        "protected_versions_not_listed": [],
        "remote_mutations": False,
        "cloud_run_executed": False,
        "cloud_run_list_scope": "all project regions with command-scoped run/region cleared",
        "repository": {
            "name": f"projects/{mod.PROJECT}/locations/{mod.REGION}/repositories/{mod.REPOSITORY}",
            "format": "DOCKER",
            "sizeBytes": 1000,
        },
        "rollback_checkpoint": {"status": "matched", "matching_releases": [RELEASE]},
        "images": rows,
        "references": [
            {
                "kind": "job",
                "resource": "malscan-v2-static-demo",
                "region": mod.REGION,
                "image": image("a"),
            },
            {
                "kind": "rollback_checkpoint",
                "resource": RELEASE,
                "region": mod.REGION,
                "image": image("b"),
            },
            {
                "kind": "service",
                "resource": "dispatcher",
                "region": mod.REGION,
                "image": image("e", "demo-dispatcher"),
            },
            {
                "kind": "job",
                "resource": "engine-poc",
                "region": mod.REGION,
                "image": image("f", "engine-poc"),
            },
        ],
    }


class FakeCloud:
    def __init__(self, report):
        self.report = copy.deepcopy(report)
        self.deleted = []
        self.reads = 0
        self.failure = None
        self.before_read = None

    def inspect(self):
        self.reads += 1
        if self.before_read:
            self.before_read(self)
        value = copy.deepcopy(self.report)
        value["observed_at"] = mod.now().isoformat()
        return value

    def delete(self, uri):
        if self.failure == "before":
            raise mod.GuardError("delete_request_outcome_uncertain")
        self.deleted.append(uri)
        self.report["images"] = [row for row in self.report["images"] if row["image"] != uri]
        if self.failure == "after":
            raise mod.GuardError("delete_request_outcome_uncertain")


class PruneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.report = fixture()
        self.plan = mod.make_plan(self.report)
        self.cloud = FakeCloud(self.report)

    def operation(self, name="state"):
        return mod.Cleanup(
            self.plan,
            self.home / name,
            home=self.home,
            inspect=self.cloud.inspect,
            delete=self.cloud.delete,
        )

    def test_plan_binds_exact_candidates_and_preserves_other_packages(self):
        self.assertEqual(self.plan["candidates"], [image("c"), image("d")])
        self.assertEqual(mod.validate_plan(self.plan), self.plan)
        self.assertNotIn(image("1", "engine-poc"), self.plan["candidates"])
        changed = copy.deepcopy(self.plan)
        changed["candidates"].append(image("a"))
        with self.assertRaisesRegex(mod.GuardError, "plan_identity_changed"):
            mod.validate_plan(changed)
        changed["plan_sha256"] = mod.digest(
            {key: value for key, value in changed.items() if key != "plan_sha256"}
        )
        with self.assertRaisesRegex(mod.GuardError, "plan_candidates_changed"):
            mod.validate_plan(changed)

    def test_rejects_partial_scope_missing_metadata_or_worker_index(self):
        cases = [
            lambda d: d.update(readiness_issues=[{"reason": "read_failed"}]),
            lambda d: d.pop("references"),
            lambda d: d["images"][2].pop("createTime"),
            lambda d: d["images"][2].update(tags=[{}]),
            lambda d: d["images"][0].update(
                reported_media_type="application/vnd.oci.image.index.v1+json"
            ),
            lambda d: d["rollback_checkpoint"].update(status="not_observed"),
        ]
        for mutate in cases:
            with self.subTest(case=cases.index(mutate)):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(mod.GuardError):
                    mod.make_plan(report)

    def test_plan_and_inventory_age_are_bounded_without_force_override(self):
        report = copy.deepcopy(self.report)
        report["observed_at"] = (mod.now() - timedelta(hours=25)).isoformat()
        with self.assertRaisesRegex(mod.GuardError, "inventory_is_stale"):
            mod.make_plan(report)
        with patch.object(
            mod, "now", return_value=mod.timestamp(self.plan["expires_at"]) + timedelta(seconds=1)
        ):
            with self.assertRaisesRegex(mod.GuardError, "plan_expired"):
                mod.validate_plan(self.plan)
            self.assertEqual(mod.validate_plan(self.plan, expired_ok=True), self.plan)

    def test_original_inventory_bytes_are_pinned_before_preparation(self):
        path = self.home / "inventory.json"
        payload = json.dumps(self.report, indent=2).encode()
        path.write_bytes(payload)
        source_hash = hashlib.sha256(payload).hexdigest()
        self.assertEqual(mod.read_inventory(path, source_hash), self.report)
        plan = mod.make_plan(mod.read_inventory(path, source_hash), source_sha256=source_hash)
        self.assertEqual(plan["source_inventory_sha256"], source_hash)
        with self.assertRaisesRegex(mod.GuardError, "inventory_sha256_mismatch"):
            mod.read_inventory(path, "0" * 64)

    def test_apply_deletes_only_selected_digests_and_records_verified_completion(self):
        result = self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [image("c"), image("d")])
        self.assertEqual(result["phase"], "completed")
        self.assertEqual(result["removed"], self.plan["candidates"])
        self.assertFalse(result["cloud_run_executed"])
        state = self.home / "state/state.json"
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        again = self.operation().run(apply=True)
        self.assertEqual(again["phase"], "completed")
        self.assertEqual(len(self.cloud.deleted), 2)

    def test_new_version_tag_change_reference_or_partial_read_halts_before_delete(self):
        def version_change(d):
            row = copy.deepcopy(d["images"][2])
            row["image"] = image("2")
            d["images"].append(row)

        def reference_change(d):
            d["references"].append(
                {
                    "kind": "job",
                    "resource": "new-consumer",
                    "region": mod.REGION,
                    "image": image("c"),
                }
            )
            d["images"][2].update(
                classification="protected_reference", protection_reasons=["new-consumer"]
            )

        cases = [
            version_change,
            reference_change,
            lambda d: d["images"][2].update(tags=["moved-tag"]),
            lambda d: d["images"][2].update(reported_media_type=None),
            lambda d: d.update(readiness_issues=[{"reason": "read_failed"}]),
        ]
        for n, mutate in enumerate(cases):
            with self.subTest(case=n):
                self.cloud = FakeCloud(self.report)
                mutate(self.cloud.report)
                with self.assertRaises(mod.GuardError):
                    self.operation("case-" + str(n)).run(apply=True)
                self.assertEqual(self.cloud.deleted, [])

    def test_rechecks_fresh_inventory_before_each_new_delete(self):
        def mutate(cloud):
            if cloud.reads == 4:
                cloud.report["images"][0]["tags"] = ["changed"]

        self.cloud.before_read = mutate
        with self.assertRaisesRegex(mod.GuardError, "live_inventory_changed"):
            self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [image("c")])

    def test_uncertain_present_digest_is_not_automatically_deleted_again(self):
        self.cloud.failure = "before"
        with self.assertRaisesRegex(mod.GuardError, "outcome_uncertain"):
            self.operation().run(apply=True)
        self.cloud.failure = None
        for apply in (False, True):
            with self.assertRaisesRegex(mod.GuardError, "no_automatic_retry"):
                self.operation().run(apply=apply)
        self.assertEqual(self.cloud.deleted, [])
        state = json.loads((self.home / "state/state.json").read_text())
        self.assertEqual(state["pending"], image("c"))
        self.assertEqual(state["phase"], "uncertain")

    def test_uncertain_absent_digest_can_be_reconciled_read_only_then_resume(self):
        self.cloud.failure = "after"
        with self.assertRaisesRegex(mod.GuardError, "outcome_uncertain"):
            self.operation().run(apply=True)
        self.cloud.failure = None
        result = self.operation().run(apply=False)
        self.assertEqual(result["removed"], [image("c")])
        self.assertEqual(self.cloud.deleted, [image("c")])
        self.assertEqual(self.operation().run(apply=True)["phase"], "completed")
        self.assertEqual(self.cloud.deleted, [image("c"), image("d")])

    def test_active_campaign_binds_plan_and_state_and_blocks_duplicate_campaign(self):
        self.cloud.failure = "before"
        with self.assertRaises(mod.GuardError):
            self.operation().run(apply=True)
        with self.assertRaisesRegex(mod.GuardError, "bound_to_another_state_directory"):
            self.operation("alternate").run(apply=True)
        different = mod.make_plan(self.report, at_time=mod.now() + timedelta(seconds=1))
        operation = mod.Cleanup(
            different,
            self.home / "different",
            home=self.home,
            inspect=self.cloud.inspect,
            delete=self.cloud.delete,
        )
        with self.assertRaisesRegex(
            mod.GuardError, "another_cleanup_campaign_requires_reconciliation"
        ):
            operation.run(apply=True)
        self.assertEqual(self.cloud.deleted, [])

    def test_claimed_campaign_cannot_reinitialize_a_missing_uncertain_ledger(self):
        self.cloud.failure = "before"
        with self.assertRaises(mod.GuardError):
            self.operation().run(apply=True)
        (self.home / "state/state.json").unlink()
        self.cloud.failure = None
        for apply in (False, True):
            with self.assertRaisesRegex(mod.GuardError, "checkpoint_missing_for_claimed_campaign"):
                self.operation().run(apply=apply)
        self.assertEqual(self.cloud.deleted, [])

    def test_package_lock_excludes_another_state_directory(self):
        root = self.home / ".malscan-v2-operations/registry-cleanup"
        mod.ensure_directory(root, self.home)
        with mod.locked(root), self.assertRaisesRegex(mod.GuardError, "another_cleanup_is_using"):
            self.operation().run(apply=True)
        self.assertEqual(self.cloud.deleted, [])

    def test_completed_campaign_allows_a_fresh_verified_plan(self):
        self.operation().run(apply=True)
        added = copy.deepcopy(self.report["images"][2])
        added["image"] = image("2")
        self.cloud.report["images"].append(added)
        different = mod.make_plan(self.cloud.inspect())
        operation = mod.Cleanup(
            different,
            self.home / "second",
            home=self.home,
            inspect=self.cloud.inspect,
            delete=self.cloud.delete,
        )
        self.assertEqual(operation.run(apply=True)["phase"], "completed")
        self.assertEqual(self.cloud.deleted, [image("c"), image("d"), image("2")])

    def test_directory_publication_is_synced_before_mutation(self):
        published = []
        real_sync = mod.fsync_directory
        real_delete = self.cloud.delete

        def sync(path):
            real_sync(path)
            published.append(path)

        def delete(uri):
            self.assertEqual(published[-1], self.home / "state")
            state = json.loads((self.home / "state/state.json").read_text())
            self.assertEqual(state["pending"], uri)
            real_delete(uri)

        with patch.object(mod, "fsync_directory", side_effect=sync):
            operation = self.operation()
            operation.delete = delete
            operation.run(apply=True)

    def test_private_paths_reject_symlinks_and_output_is_exclusive(self):
        path = self.home / "plan.json"
        mod.write_private(path, self.plan, exclusive=True)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            mod.write_private(path, {}, exclusive=True)
        alias = self.home / "alias.json"
        alias.symlink_to(path)
        with self.assertRaises(mod.GuardError):
            mod.private_location(alias, self.home)
        with self.assertRaises(mod.GuardError):
            mod.private_location(self.home.parent / "outside.json", self.home)
        self.assertEqual(mod.private_location(self.home / "unused/../plan.json", self.home), path)
        os.chmod(path, 0o644)
        with self.assertRaises(mod.GuardError):
            mod.read_json(path, home=self.home)


class DeleteCommandTests(unittest.TestCase):
    def test_exact_digest_only_command_and_no_raw_output_exposure(self):
        result = subprocess.CompletedProcess([], 0, "PRIVATE_RESPONSE", "")
        with patch.object(mod.subprocess, "run", return_value=result) as run:
            mod.delete_image(image("c"))
        self.assertEqual(
            run.call_args.args[0],
            [
                "gcloud",
                "artifacts",
                "docker",
                "images",
                "delete",
                image("c"),
                "--delete-tags",
                "--project=" + mod.PROJECT,
                "--quiet",
            ],
        )
        for uri in (mod.PACKAGE, mod.PACKAGE + ":latest", image("c", "engine-poc")):
            with self.assertRaises(mod.GuardError):
                mod.delete_image(uri)
        result = subprocess.CompletedProcess([], 1, "PRIVATE_RESPONSE", "PRIVATE_ERROR")
        with patch.object(mod.subprocess, "run", return_value=result), self.assertRaisesRegex(
            mod.GuardError, "^delete_request_outcome_uncertain$"
        ):
            mod.delete_image(image("c"))


if __name__ == "__main__":
    unittest.main()
