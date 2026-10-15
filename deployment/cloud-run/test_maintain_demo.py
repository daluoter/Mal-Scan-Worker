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
        },
        "spec": {
            "template": {
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
                }
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
            maintenance.container(self.current)["image"] = next(
                arg[8:] for arg in args if arg.startswith("--image=")
            )
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
        before = maintenance.job_configuration(self.cloud.current)
        self.verified()
        state = self.tool.update_image()
        self.assertEqual(state["phase"], "promoted")
        self.assertEqual(
            maintenance.job_configuration(self.cloud.current),
            maintenance.expected_configuration(before, NEW),
        )
        self.assertEqual(self.tool.update_image(rollback=True)["phase"], "rolled_back")
        self.assertEqual(maintenance.job_configuration(self.cloud.current), before)
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
        self.assertEqual(self.tool.status()["phase"], "promoted")
        self.assertEqual(
            len([args for args in self.cloud.calls if args[:3] == ["run", "jobs", "update"]]), 1
        )

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
