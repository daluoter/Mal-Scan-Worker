"""Offline safety tests: no authenticated gcloud command is ever executed."""

import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "maintenance", Path(__file__).with_name("maintain-demo.py")
)
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)
RELEASE = "db-20261015T010000Z-123456789abc"
OLD = maintenance.IMAGE + "@sha256:" + "a" * 64
NEW = maintenance.IMAGE + "@sha256:" + "b" * 64
BUILD_ID = "12345678-1234-1234-1234-123456789abc"


def job():
    return {
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        "metadata": {
            "name": maintenance.JOB,
            "annotations": {"owner-note": "preserve"},
            "labels": {
                "run.googleapis.com/lastUpdatedTime": "2026-10-15T01:00:00Z",
                "user-label": "preserve",
            },
        },
        "spec": {
            "template": {
                "metadata": {
                    "labels": {
                        "client.knative.dev/nonce": "before-update",
                        "user-template-label": "preserve",
                    }
                },
                "spec": {
                    "parallelism": 1,
                    "taskCount": 1,
                    "template": {
                        "spec": {
                            "serviceAccountName": "runner@example.invalid",
                            "maxRetries": 0,
                            "containers": [
                                {
                                    "image": OLD,
                                    "env": [{"name": "SECRET_PATH", "value": "/secrets/key"}],
                                    "resources": {"limits": {"memory": "4Gi", "cpu": "2"}},
                                }
                            ],
                            "volumes": [{"name": "key", "secret": {"secretName": "private-ref"}}],
                        }
                    },
                },
            }
        },
    }


def successful_build():
    tag = maintenance.IMAGE + ":" + RELEASE
    return {
        "id": BUILD_ID,
        "status": "SUCCESS",
        "substitutions": {"_RELEASE": RELEASE},
        "steps": [
            {
                "status": "SUCCESS",
                "args": [
                    "build",
                    "--target=cloud-job",
                    f"--build-arg=SIGNATURE_REFRESH={RELEASE}",
                    "-f",
                    "worker/Dockerfile",
                    "-t",
                    tag,
                    ".",
                ],
            },
            {
                "id": "engine-controls",
                "status": "SUCCESS",
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
        ],
        "results": {"images": [{"name": tag, "digest": "sha256:" + "b" * 64}]},
    }


class FakeCloud:
    def __init__(self):
        self.current = job()
        self.build = successful_build()
        self.calls = []
        self.job_reads = 0
        self.updates = 0
        self.report = {
            "scope": "offline_engine_controls",
            "success": True,
            "uid": 10001,
            "module_sha256": maintenance.hashlib.sha256(b"controls").hexdigest(),
            "clamav_version": "ClamAV test",
            "yara_version": "4.test",
            "yara_rules_sha256": "c" * 64,
            "controls": {
                "clamav_clean": True,
                "clamav_eicar_detected": True,
                "yara_clean": True,
                "yara_eicar_detected": True,
            },
            "signed_databases": [
                {
                    "name": name + ".cvd",
                    "signature_verified": True,
                    "created_at_epoch": int(time.time()),
                }
                for name in ("main", "daily", "bytecode")
            ],
        }

    def job(self):
        self.job_reads += 1
        return copy.deepcopy(self.current)

    def call(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["builds", "submit"]:
            return {"id": BUILD_ID}
        if args[:2] == ["builds", "list"]:
            return [self.build]
        if args[:2] == ["builds", "describe"]:
            return copy.deepcopy(self.build)
        if args[:3] == ["artifacts", "docker", "images"]:
            return {"image_summary": {"fully_qualified_digest": NEW}}
        if args[:2] == ["logging", "read"]:
            return [{"textPayload": json.dumps(self.report)}]
        if args[:3] == ["run", "jobs", "update"]:
            self.updates += 1
            maintenance.container(self.current)["image"] = next(
                arg[8:] for arg in args if arg.startswith("--image=")
            )
            self.current["metadata"].setdefault("labels", {})[
                "run.googleapis.com/lastUpdatedTime"
            ] = f"2026-10-15T01:00:0{self.updates}Z"
            self.current["spec"]["template"].setdefault("metadata", {}).setdefault("labels", {})[
                "client.knative.dev/nonce"
            ] = f"after-update-{self.updates}"
            return copy.deepcopy(self.current)
        raise AssertionError(args)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        (self.repository / "deployment/cloud-run").mkdir(parents=True)
        (self.repository / "worker/src/malscan_worker/runtime").mkdir(parents=True)
        (self.repository / "backend").mkdir()
        for name in (maintenance.CONFIG, ".gcloudignore", ".dockerignore"):
            (self.repository / name).write_text("test input")
        (self.repository / "worker/src/malscan_worker/runtime/engine_controls.py").write_bytes(
            b"controls"
        )
        self.cloud = FakeCloud()
        self.tool = maintenance.Maintenance(self.root / RELEASE, self.repository, self.cloud)
        self.tool.prepare()

    def tearDown(self):
        self.temporary.cleanup()

    def verified(self):
        self.tool.submit()
        self.assertEqual(self.tool.status()["phase"], "build_verified")

    def test_full_workflow_and_guarded_image_only_rollback(self):
        before = copy.deepcopy(maintenance.job_configuration(self.cloud.current))
        self.verified()
        state = self.tool.update_image()
        self.assertEqual(state["phase"], "promoted")
        self.assertTrue(
            maintenance.configurations_equal(
                maintenance.job_configuration(self.cloud.current),
                maintenance.expected_configuration(before, NEW),
            )
        )
        self.assertNotEqual(maintenance.job_configuration(self.cloud.current), before)
        self.assertEqual(self.tool.update_image(rollback=True)["phase"], "rolled_back")
        self.assertTrue(
            maintenance.configurations_equal(
                maintenance.job_configuration(self.cloud.current), before
            )
        )
        self.assertNotEqual(maintenance.job_configuration(self.cloud.current), before)
        writes = [args for args in self.cloud.calls if args[:3] == ["run", "jobs", "update"]]
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(len(args) == 6 and args[-1].startswith("--image=") for args in writes))
        self.assertFalse(any("execute" in args for args in self.cloud.calls))
        self.assertFalse(any("secrets" in args for args in self.cloud.calls))
        self.assertTrue(
            all(
                (path.stat().st_mode & 0o777) == 0o600
                for path in self.tool.directory.glob("*.json")
            )
        )

    def test_concurrent_configuration_edit_blocks_promotion(self):
        self.verified()
        maintenance.container(self.cloud.current)["env"].append({"name": "changed", "value": "yes"})
        with self.assertRaisesRegex(maintenance.MaintenanceError, "Job changed"):
            self.tool.update_image()
        self.assertFalse(any(args[:3] == ["run", "jobs", "update"] for args in self.cloud.calls))

    def test_concurrent_edit_blocks_rollback(self):
        self.verified()
        self.tool.update_image()
        self.cloud.current["metadata"]["annotations"]["owner-note"] = "new value"
        with self.assertRaisesRegex(maintenance.MaintenanceError, "Job changed"):
            self.tool.update_image(rollback=True)

    def test_failed_and_nonterminal_builds_never_promote(self):
        for status in (
            "QUEUED",
            "WORKING",
            "FAILURE",
            "CANCELLED",
            "TIMEOUT",
            "INTERNAL_ERROR",
        ):
            with self.subTest(status=status):
                state = self.tool.load()
                state.update(phase="build_submitted", build_id=BUILD_ID)
                self.tool.save(state)
                self.cloud.build["status"] = status
                result = self.tool.status()
                self.assertNotEqual(result["phase"], "build_verified")
                with self.assertRaises(maintenance.MaintenanceError):
                    self.tool.update_image()

    def test_missing_offline_controls_never_promote(self):
        self.tool.submit()
        del self.cloud.build["steps"][1]
        with self.assertRaisesRegex(maintenance.MaintenanceError, "expected release controls"):
            self.tool.status()

    def test_cloud_build_prefixed_log_and_structured_report_formats(self):
        self.tool.submit()
        original = self.cloud.call
        for prefix in ('Step #1 - "engine-controls": ', "Step #1: ", ""):
            with self.subTest(prefix=prefix):

                def prefixed(args, **kwargs):
                    if args[:2] == ["logging", "read"]:
                        return [{"textPayload": prefix + json.dumps(self.cloud.report)}]
                    return original(args, **kwargs)

                self.cloud.call = prefixed
                self.assertEqual(self.tool.status()["phase"], "build_verified")

        def structured(args, **kwargs):
            if args[:2] == ["logging", "read"]:
                return [{"jsonPayload": self.cloud.report}]
            return original(args, **kwargs)

        self.cloud.call = structured
        self.assertEqual(self.tool.status()["phase"], "build_verified")

    def test_other_step_cannot_supply_control_evidence(self):
        self.tool.submit()
        original = self.cloud.call

        def wrong_step(args, **kwargs):
            if args[:2] == ["logging", "read"]:
                return [{"textPayload": "Step #0: " + json.dumps(self.cloud.report)}]
            return original(args, **kwargs)

        self.cloud.call = wrong_step
        with self.assertRaisesRegex(maintenance.MaintenanceError, "report unavailable"):
            self.tool.status()

    def test_uncertain_image_update_reconciles_without_another_write(self):
        self.verified()
        original = self.cloud.call

        def interrupted(args, **kwargs):
            result = original(args, **kwargs)
            if args[:3] == ["run", "jobs", "update"]:
                raise maintenance.MaintenanceError("response lost")
            return result

        self.cloud.call = interrupted
        with self.assertRaisesRegex(maintenance.MaintenanceError, "response lost"):
            self.tool.update_image()
        self.assertEqual(self.tool.load()["phase"], "promotion_pending")
        calls_before_status = len(self.cloud.calls)
        reads_before_status = self.cloud.job_reads
        self.assertEqual(self.tool.status()["phase"], "promoted")
        self.assertEqual(len(self.cloud.calls), calls_before_status)
        self.assertEqual(self.cloud.job_reads, reads_before_status + 1)
        self.assertEqual(self.tool.status()["phase"], "promoted")
        self.assertEqual(
            len([args for args in self.cloud.calls if args[:3] == ["run", "jobs", "update"]]),
            1,
        )

    def test_comparison_ignores_only_observed_paths_without_mutating_checkpoint(self):
        before = copy.deepcopy(maintenance.job_configuration(self.cloud.current))
        after = copy.deepcopy(before)
        after["labels"]["run.googleapis.com/lastUpdatedTime"] = "new-server-time"
        after["spec"]["template"]["metadata"]["labels"][
            "client.knative.dev/nonce"
        ] = "new-client-nonce"
        frozen_before, frozen_after = copy.deepcopy(before), copy.deepcopy(after)
        self.assertTrue(maintenance.configurations_equal(before, after))
        self.assertEqual(before, frozen_before)
        self.assertEqual(after, frozen_after)
        self.assertNotEqual(maintenance.fingerprint(before), maintenance.fingerprint(after))

    def test_legacy_baseline_fingerprint_and_metadata_tamper_guard_are_preserved(self):
        # Captured using maintain-demo.py from commit 8685393, before the fix.
        legacy_fingerprint = "f2a30a1a46b654e32f5ece282d75b1c5226bd23e8cdbc5c5917c4c15dddfe97e"
        self.assertEqual(self.tool.load()["baseline_fingerprint"], legacy_fingerprint)
        baseline_path = self.tool.directory / "job-before.json"
        baseline = maintenance.read_private(baseline_path)
        original_bytes = baseline_path.read_bytes()
        self.verified()
        self.assertEqual(self.tool.update_image()["phase"], "promoted")
        self.assertEqual(baseline_path.read_bytes(), original_bytes)
        self.assertEqual(self.tool.load()["baseline_fingerprint"], legacy_fingerprint)

        for path in (
            ("metadata", "labels", "run.googleapis.com/lastUpdatedTime"),
            ("spec", "template", "metadata", "labels", "client.knative.dev/nonce"),
        ):
            with self.subTest(path=path):
                tampered = copy.deepcopy(baseline)
                target = tampered
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = "tampered-checkpoint"
                maintenance.write_private(baseline_path, tampered)
                with self.assertRaisesRegex(maintenance.MaintenanceError, "fingerprint changed"):
                    self.tool.load()
                maintenance.write_private(baseline_path, baseline)

    def test_added_nonce_only_metadata_does_not_block_image_update(self):
        for index, baseline_metadata in enumerate(
            ({}, {"annotations": {"user-note": "preserve"}}, None)
        ):
            with self.subTest(metadata=baseline_metadata):
                self.cloud.current = job()
                template = self.cloud.current["spec"]["template"]
                if baseline_metadata is None:
                    del template["metadata"]
                else:
                    template["metadata"] = copy.deepcopy(baseline_metadata)
                directory = self.root / f"nonce-{index}" / RELEASE
                tool = maintenance.Maintenance(directory, self.repository, self.cloud)
                tool.prepare()
                tool.submit()
                self.assertEqual(tool.status()["phase"], "build_verified")
                self.assertEqual(tool.update_image()["phase"], "promoted")
                self.assertEqual(tool.update_image(rollback=True)["phase"], "rolled_back")

    def test_meaningful_drift_still_blocks_promotion_and_rollback(self):
        self.verified()
        task_spec = ("spec", "template", "spec", "template", "spec")
        changes = [
            (("spec", "template", "spec", "taskCount"), 2),
            (task_spec + ("serviceAccountName",), "different@example.invalid"),
            (task_spec + ("containers", 0, "env", 0, "value"), "/different/secret"),
            (task_spec + ("volumes", 0, "secret", "secretName"), "different-secret"),
            (task_spec + ("containers", 0, "resources", "limits", "cpu"), "4"),
            (("metadata", "labels", "user-label"), "changed"),
            (("metadata", "annotations", "owner-note"), "changed"),
            (
                ("spec", "template", "metadata", "labels", "user-template-label"),
                "changed",
            ),
            (("metadata", "labels", "client.knative.dev/nonce"), "not-ignored-here"),
            (
                (
                    "spec",
                    "template",
                    "metadata",
                    "labels",
                    "run.googleapis.com/lastUpdatedTime",
                ),
                "not-ignored-here",
            ),
            (
                ("spec", "template", "spec", "template", "metadata", "labels"),
                {"client.knative.dev/nonce": "not-ignored-in-task-template"},
            ),
        ]
        for rollback in (False, True):
            if rollback:
                self.assertEqual(self.tool.update_image()["phase"], "promoted")
            frozen_job = copy.deepcopy(self.cloud.current)
            frozen_state = self.tool.load()
            for path, value in changes:
                with self.subTest(rollback=rollback, path=path):
                    self.cloud.current = copy.deepcopy(frozen_job)
                    self.cloud.current["metadata"]["labels"][
                        "run.googleapis.com/lastUpdatedTime"
                    ] = "different-time"
                    self.cloud.current["spec"]["template"]["metadata"]["labels"][
                        "client.knative.dev/nonce"
                    ] = "different-nonce"
                    target = self.cloud.current
                    for key in path[:-1]:
                        if isinstance(target, dict):
                            target = target.setdefault(key, {})
                        else:
                            target = target[key]
                    target[path[-1]] = value
                    updates_before = self.cloud.updates
                    with self.assertRaisesRegex(maintenance.MaintenanceError, "Job changed"):
                        self.tool.update_image(rollback=rollback)
                    self.assertEqual(self.cloud.updates, updates_before)
                    self.assertEqual(self.tool.load()["phase"], frozen_state["phase"])
            self.cloud.current = frozen_job

    def test_pending_recovery_preserves_real_drift_and_requires_ready(self):
        self.verified()
        original = self.cloud.call

        def interrupted(args, **kwargs):
            result = original(args, **kwargs)
            if args[:3] == ["run", "jobs", "update"]:
                raise maintenance.MaintenanceError("response lost")
            return result

        self.cloud.call = interrupted
        with self.assertRaisesRegex(maintenance.MaintenanceError, "response lost"):
            self.tool.update_image()
        promoted_job = copy.deepcopy(self.cloud.current)
        self.cloud.current["spec"]["template"]["spec"]["template"]["spec"][
            "serviceAccountName"
        ] = "unexpected@example.invalid"
        calls_before = len(self.cloud.calls)
        self.assertEqual(self.tool.status()["phase"], "promotion_pending")
        self.cloud.current = copy.deepcopy(promoted_job)
        self.cloud.current["status"]["conditions"][0]["status"] = "False"
        self.assertEqual(self.tool.status()["phase"], "promotion_pending")
        self.assertEqual(len(self.cloud.calls), calls_before)
        self.cloud.current = promoted_job
        self.assertEqual(self.tool.status()["phase"], "promoted")
        self.assertEqual(self.cloud.updates, 1)
        self.assertEqual(len(self.cloud.calls), calls_before)

    def test_interrupted_rollback_reconciles_new_server_metadata_without_another_write(
        self,
    ):
        self.verified()
        self.tool.update_image()
        original = self.cloud.call

        def interrupted(args, **kwargs):
            result = original(args, **kwargs)
            if args[:3] == ["run", "jobs", "update"]:
                raise maintenance.MaintenanceError("rollback response lost")
            return result

        self.cloud.call = interrupted
        with self.assertRaisesRegex(maintenance.MaintenanceError, "rollback response lost"):
            self.tool.update_image(rollback=True)
        self.assertEqual(self.tool.load()["phase"], "rollback_pending")
        calls_before = len(self.cloud.calls)
        self.assertEqual(self.tool.status()["phase"], "rolled_back")
        self.assertEqual(self.cloud.updates, 2)
        self.assertEqual(len(self.cloud.calls), calls_before)

    def test_failed_control_or_missing_negative_is_rejected(self):
        self.tool.submit()
        self.cloud.report["controls"]["clamav_clean"] = False
        with self.assertRaisesRegex(maintenance.MaintenanceError, "evidence did not verify"):
            self.tool.status()

    def test_delayed_promotion_rechecks_database_age(self):
        self.verified()
        self.cloud.report["signed_databases"][1]["created_at_epoch"] = int(time.time()) - 604801
        with self.assertRaisesRegex(maintenance.MaintenanceError, "now stale"):
            self.tool.update_image()

    def test_submission_unknown_recovers_by_unique_release_without_resubmitting(self):
        state = self.tool.load()
        state["phase"] = "submission_pending"
        self.tool.save(state)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "already attempted"):
            self.tool.submit()
        self.assertEqual(self.tool.status()["phase"], "build_verified")
        self.assertFalse(any(args[:2] == ["builds", "submit"] for args in self.cloud.calls))

    def test_source_edit_after_prepare_requires_new_checkpoint(self):
        (self.repository / "worker/source.py").write_text("edited")
        with self.assertRaisesRegex(maintenance.MaintenanceError, "Build inputs changed"):
            self.tool.submit()

    def test_registry_digest_mismatch_is_rejected(self):
        self.tool.submit()
        self.cloud.build["results"]["images"][0]["digest"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(maintenance.MaintenanceError, "readback"):
            self.tool.status()

    def test_failed_submit_persists_intent_before_command(self):
        def failure(args, **kwargs):
            self.assertEqual(self.tool.load()["phase"], "submission_pending")
            raise maintenance.MaintenanceError("network ended")

        self.cloud.call = failure
        with self.assertRaisesRegex(maintenance.MaintenanceError, "network ended"):
            self.tool.submit()
        self.assertEqual(self.tool.load()["phase"], "submission_pending")

    def test_no_state_default_is_inert(self):
        with patch.object(maintenance.sys, "argv", ["maintain-demo.py"]), patch.object(
            maintenance.subprocess, "run"
        ) as run:
            maintenance.main()
        run.assert_not_called()

    def test_private_checkpoint_and_outside_source_guards(self):
        with self.assertRaisesRegex(maintenance.MaintenanceError, "outside"):
            maintenance.Maintenance(self.repository / RELEASE, self.repository, self.cloud)
        os.chmod(self.tool.state_file, 0o644)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "private"):
            self.tool.load()

    def test_gcloud_wrapper_uses_explicit_project_no_shell(self):
        result = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
        with patch.object(maintenance.subprocess, "run", return_value=result) as run:
            maintenance.Gcloud().call(
                ["run", "jobs", "describe", maintenance.JOB, "--region=us-central1"]
            )
        args, kwargs = run.call_args
        self.assertIn("--project=malscan-v2-poc", args[0])
        self.assertNotIn("shell", kwargs)
        self.assertTrue(kwargs["capture_output"])


if __name__ == "__main__":
    unittest.main()
