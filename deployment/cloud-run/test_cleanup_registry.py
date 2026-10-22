"""Offline guards for the read-only Cloud Shell registry inspector."""

import copy
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "cleanup_registry", Path(__file__).with_name("cleanup-registry.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def image(digit, package="full-worker"):
    return mod.PREFIX + package + "@sha256:" + digit * 64


def resource(name, region="us-central1"):
    return {"metadata": {"name": name, "labels": {"cloud.googleapis.com/location": region}}}


class FakeCloud:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.job_rows = [
            resource("malscan-v2-static-demo"),
            resource("other-region", "europe-west12"),
        ]
        self.service_rows = [resource("dispatcher")]
        self.versions = [
            dict(
                package=mod.PREFIX + package,
                version="sha256:" + digit * 64,
                tags=["release-" + digit],
                metadata={"imageSizeBytes": "1024"},
                secret="NEVER_OUTPUT_RAW_SECRET",
            )
            for digit, package in [
                ("a", "full-worker"),
                ("b", "full-worker"),
                ("c", "full-worker"),
                ("d", "demo-dispatcher"),
                ("e", "demo-dispatcher"),
                ("f", "full-worker"),
                ("1", "full-worker"),
                ("2", "full-worker"),
            ]
        ]

    def read(self, args):
        self.calls.append(args)
        key = tuple(args[:3])
        if self.fail == key:
            raise mod.ReadError("gcloud_read_failed")
        if key == ("artifacts", "repositories", "list"):
            return [
                {
                    "name": (
                        f"projects/{mod.PROJECT}/locations/{mod.REGION}"
                        f"/repositories/{mod.REPOSITORY}"
                    ),
                    "format": "DOCKER",
                    "sizeBytes": "5000",
                    "password": "NEVER_OUTPUT_RAW_SECRET",
                    "cleanupPolicies": {
                        "keep": {
                            "action": "KEEP",
                            "secret": "NEVER_OUTPUT_RAW_SECRET",
                            "mostRecentVersions": {
                                "keepCount": 2,
                                "password": "NEVER_OUTPUT_RAW_SECRET",
                            },
                        }
                    },
                }
            ]
        if tuple(args[:4]) == ("artifacts", "docker", "images", "list"):
            return copy.deepcopy(self.versions)
        if key == ("run", "jobs", "list"):
            return copy.deepcopy(self.job_rows)
        if key == ("run", "jobs", "describe"):
            value = image("a") if args[3] == "malscan-v2-static-demo" else image("f")
            return {
                "spec": {
                    "template": {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "image": value,
                                            "env": [{"value": "NEVER_OUTPUT_RAW_SECRET"}],
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        if tuple(args[:4]) == ("run", "jobs", "executions", "list"):
            return [
                {
                    "metadata": {"name": "pending"},
                    "spec": {"template": {"spec": {"containers": [{"image": image("1")}]}}},
                },
                {
                    "metadata": {"name": "completed"},
                    "status": {"completionTime": "2026-10-22T00:00:00Z"},
                    "spec": {"template": {"spec": {"containers": [{"image": image("2")}]}}},
                },
            ]
        if key == ("run", "services", "list"):
            return copy.deepcopy(self.service_rows)
        if key == ("run", "services", "describe"):
            return {
                "spec": {
                    "template": {"spec": {"containers": [{"image": image("d", "demo-dispatcher")}]}}
                }
            }
        if key == ("run", "revisions", "list"):
            return [
                {
                    "metadata": {"name": "dispatcher-old"},
                    "spec": {"containers": [{"image": image("e", "demo-dispatcher")}]},
                    "status": {"imageDigest": image("e", "demo-dispatcher")},
                }
            ]
        raise AssertionError(args)


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.cloud = FakeCloud()

    def checkpoint(self, release, candidate, previous):
        path = self.home / ".malscan-v2-operations/maintenance" / release / "state.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "project": mod.PROJECT,
                    "region": mod.REGION,
                    "job": "malscan-v2-static-demo",
                    "phase": "promoted",
                    "release": release,
                    "candidate_image": candidate,
                    "previous_image": previous,
                    "secret": "NEVER_OUTPUT_RAW_SECRET",
                }
            )
        )
        return path

    def test_references_and_matching_rollback_are_kept_not_old_history(self):
        self.checkpoint("db-20261022T000000Z-aaaaaaaaaaaa", image("a"), image("b"))
        self.checkpoint("db-20261020T000000Z-bbbbbbbbbbbb", image("b"), image("c"))
        report = mod.Inspector(self.cloud, self.home).inspect()
        classified = {row["image"]: row["classification"] for row in report["images"]}
        for ref in (
            image("a"),
            image("b"),
            image("d", "demo-dispatcher"),
            image("e", "demo-dispatcher"),
            image("f"),
            image("1"),
        ):
            self.assertEqual(classified[ref], "protected_reference")
        for ref in (image("c"), image("2")):
            self.assertEqual(classified[ref], "unclassified")
        self.assertEqual(report["rollback_checkpoint"]["status"], "matched")
        self.assertFalse(report["oci_manifest_graph_verified"])
        self.assertFalse(report["deletion_plan_ready"])
        self.assertFalse(report["remote_mutations"])
        self.assertNotIn("NEVER_OUTPUT_RAW_SECRET", json.dumps(report))
        for args in self.cloud.calls:
            self.assertTrue(
                any(tuple(args[: len(prefix)]) == prefix for prefix in mod.READ_COMMANDS)
            )
            if tuple(args[:3]) in (("run", "jobs", "list"), ("run", "services", "list")):
                self.assertFalse(any(arg.startswith("--region") for arg in args))

    def test_partial_reads_and_missing_region_are_explicit(self):
        self.cloud.fail = ("run", "services", "describe")
        self.cloud.job_rows.append({"metadata": {"name": "missing-region"}})
        report = mod.Inspector(self.cloud, self.home).inspect()
        reasons = {row["reason"] for row in report["readiness_issues"]}
        self.assertIn("gcloud_read_failed", reasons)
        self.assertIn("resource_region_not_observed", reasons)
        self.assertIn("no_promoted_checkpoint_matches_current_job", reasons)
        self.assertFalse(report["deletion_plan_ready"])

    def test_bad_completion_time_keeps_execution_image_and_reports_issue(self):
        original = self.cloud.read

        def read(args):
            result = original(args)
            if tuple(args[:4]) == ("run", "jobs", "executions", "list"):
                result[1]["status"]["completionTime"] = "not-a-timestamp"
            return result

        self.cloud.read = read
        self.cloud.versions[0]["metadata"]["mediaType"] = "application/vnd.oci.image.index.v1+json"
        report = mod.Inspector(self.cloud, self.home).inspect()
        classified = {row["image"]: row for row in report["images"]}
        self.assertEqual(classified[image("2")]["classification"], "protected_reference")
        self.assertEqual(
            classified[image("a")]["reported_media_type"], "application/vnd.oci.image.index.v1+json"
        )
        self.assertIn(
            "completion_timestamp_invalid", {row["reason"] for row in report["readiness_issues"]}
        )

    def test_list_bound_and_tag_bound_are_not_claimed_complete(self):
        self.cloud.versions = [
            dict(self.cloud.versions[0], tags=["tag" + str(n) for n in range(100)])
        ]
        with patch.object(mod, "LIMIT", 1):
            report = mod.Inspector(self.cloud, self.home).inspect()
        reasons = {row["reason"] for row in report["readiness_issues"]}
        self.assertIn("list_may_be_truncated", reasons)
        self.assertIn("tag_list_may_be_truncated", reasons)

    def test_unresolved_tag_conservatively_protects_package_and_canonical_digest(self):
        inspector = mod.Inspector(self.cloud, self.home)
        inspector.reference(mod.PREFIX + "full-worker:latest", "job", "tag-job", mod.REGION)
        inspector.reference(
            mod.PREFIX + "full-worker:tag@sha256:" + "a" * 64, "job", "pinned", mod.REGION
        )
        self.assertIn(mod.PREFIX + "full-worker", inspector.protected_packages)
        self.assertIn(image("a"), inspector.protected)
        self.assertEqual(inspector.issues[0]["reason"], "tag_reference_requires_digest_resolution")

    def test_malformed_nested_fields_are_reported_not_crashed(self):
        self.cloud.job_rows = [{"metadata": None}, {"metadata": {"name": "bad", "labels": None}}]
        self.cloud.versions = [None, {"package": "foreign/repo", "version": "bad"}]
        report = mod.Inspector(self.cloud, self.home).inspect()
        reasons = {row["reason"] for row in report["readiness_issues"]}
        self.assertIn("resource_name_not_observed", reasons)
        self.assertIn("resource_region_not_observed", reasons)
        self.assertIn("unsupported_image_version", reasons)

    def test_malformed_checkpoint_candidate_and_non_utf8_are_issues(self):
        self.checkpoint("db-20261022T000000Z-aaaaaaaaaaaa", [], image("b"))
        path = self.checkpoint("db-20261020T000000Z-bbbbbbbbbbbb", image("b"), image("c"))
        path.write_bytes(b"\xff\xfe\xff")
        report = mod.Inspector(self.cloud, self.home).inspect()
        reasons = {row["reason"] for row in report["readiness_issues"]}
        self.assertIn("checkpoint_candidate_image_invalid", reasons)
        self.assertIn("checkpoint_unreadable", reasons)
        self.assertFalse(report["deletion_plan_ready"])

    def test_private_output_is_exclusive_and_rejects_symlinks_or_outside_home(self):
        path = self.home / "report.json"
        mod.write_report(path, {"safe": True}, self.home)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            mod.write_report(path, {"overwritten": True}, self.home)
        self.assertEqual(json.loads(path.read_text()), {"safe": True})
        alias = self.home / "alias.json"
        alias.symlink_to(path)
        with self.assertRaises(FileExistsError):
            mod.write_report(alias, {}, self.home)
        with self.assertRaises(ValueError):
            mod.write_report(self.home.parent / "outside.json", {}, self.home)

    def test_invalid_output_stops_before_cloud_reads(self):
        existing = self.home / "existing.json"
        existing.write_text("unchanged")
        with patch.object(mod.Path, "home", return_value=self.home), patch.object(
            mod, "Inspector"
        ) as inspector, patch(
            "sys.argv", ["cleanup-registry.py", "inspect", "--output", str(existing)]
        ), redirect_stderr(
            io.StringIO()
        ), self.assertRaises(
            SystemExit
        ):
            mod.main()
        inspector.assert_not_called()
        self.assertEqual(existing.read_text(), "unchanged")


class GcloudTests(unittest.TestCase):
    def test_mutations_are_rejected_before_spawning(self):
        with patch.object(mod.subprocess, "run") as run:
            for args in (
                ["run", "jobs", "execute", "job"],
                ["artifacts", "docker", "images", "delete", "image"],
                ["secrets", "versions", "access", "latest"],
            ):
                with self.assertRaisesRegex(mod.ReadError, "command_not_in_read_only_allowlist"):
                    mod.Gcloud().read(args)
        run.assert_not_called()

    def test_region_override_and_no_raw_cloud_error(self):
        result = subprocess.CompletedProcess([], 0, "[]", "")
        with patch.dict(os.environ, {"CLOUDSDK_RUN_REGION": "asia-east1"}), patch.object(
            mod.subprocess, "run", return_value=result
        ) as run:
            self.assertEqual(mod.Gcloud().read(["run", "jobs", "list"]), [])
            self.assertEqual(run.call_args.kwargs["env"]["CLOUDSDK_RUN_REGION"], "")
            self.assertEqual(run.call_args.kwargs["env"]["CLOUDSDK_CORE_LOG_HTTP"], "false")
            self.assertEqual(os.environ["CLOUDSDK_RUN_REGION"], "asia-east1")
        result = subprocess.CompletedProcess(
            [], 1, "NEVER_OUTPUT_RAW_SECRET", "Authorization: NEVER_OUTPUT_RAW_SECRET"
        )
        with patch.object(mod.subprocess, "run", return_value=result), self.assertRaisesRegex(
            mod.ReadError, "^gcloud_read_failed$"
        ):
            mod.Gcloud().read(["run", "jobs", "list"])

    def test_unreachable_locations_are_a_failed_read(self):
        result = subprocess.CompletedProcess([], 0, "[]", "WARNING: unreachable locations")
        with patch.object(mod.subprocess, "run", return_value=result), self.assertRaisesRegex(
            mod.ReadError, "unreachable_locations"
        ):
            mod.Gcloud().read(["run", "services", "list"])


if __name__ == "__main__":
    unittest.main()
