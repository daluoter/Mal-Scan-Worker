"""Offline evidence-collector checks; no Google identity or network is used."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "collect_demo_evidence", Path(__file__).with_name("collect-demo-evidence.py")
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
NOW = dt.datetime(2026, 10, 15, 4, 0, tzinfo=dt.timezone.utc)
JOB_IDS = [
    "6a0910bf-ed13-4de9-b6bf-e0d7ff9cd2a0",
    "04cfe4ec-4f30-4ad9-9b1b-d2dc8f0f3687",
    "192e3653-2995-4b10-b9fe-e34a1d453dfe",
]
DISPATCH_ID = "aac5ef07-8612-42fe-bfad-d81175704d77"


def execution(*, with_resources=True):
    value = {
        "metadata": {
            "name": "malscan-v2-static-demo-hrcmh",
            "creationTimestamp": "2026-10-14T15:08:02.491454Z",
        },
        "spec": {"taskCount": 1, "template": {"spec": {"containers": []}}},
        "status": {
            "startTime": "2026-10-14T15:08:25.458499Z",
            "completionTime": "2026-10-14T15:12:00.566362Z",
            "succeededCount": 1,
            "conditions": [
                {"type": "Completed", "status": "True", "message": "not exported"}
            ],
        },
    }
    if with_resources:
        value["spec"]["template"]["spec"]["containers"] = [
            {"resources": {"limits": {"cpu": "2", "memory": "4Gi"}}}
        ]
    return value


class InventoryTests(unittest.TestCase):
    def test_read_only_fixed_targets_and_no_raw_secret_or_log_access(self):
        calls = []

        def runner(args):
            calls.append(args)
            if args[:2] in (["services", "list"], ["builds", "list"]):
                return {"observed": True, "data": []}
            if args[:3] in (
                ["run", "jobs", "executions"],
                ["artifacts", "docker", "images"],
                ["secrets", "versions", "list"],
            ):
                return {"observed": True, "data": []}
            return {"observed": True, "data": {}}

        report = collector.collect(days=30, limit=200, now=NOW, runner=runner)
        self.assertEqual(len(calls), 12)
        for args in calls:
            self.assertTrue("list" in args or "describe" in args)
            self.assertFalse(
                set(args)
                & {
                    "create",
                    "delete",
                    "update",
                    "execute",
                    "access",
                    "read",
                    "add-iam-policy-binding",
                }
            )
            self.assertTrue(any(arg.startswith("--format=json(") for arg in args))
            self.assertFalse(any(".env" in arg or ".volumes" in arg for arg in args))
        self.assertTrue(report["collection_complete"])
        self.assertFalse(report["acceptance_complete"])
        self.assertFalse(report["remote_mutations"])
        self.assertFalse(report["credential_payloads_read"])
        self.assertFalse(report["unverified"]["actual_billed_cost"]["observed"])
        self.assertFalse(
            report["unverified"]["r2_physical_cleanup_and_lifecycle"]["observed"]
        )
        self.assertEqual(report["window"]["created_since_utc"], "2026-09-15T04:00:00Z")

    def test_job_sanitization_discards_environment_secrets_and_error_messages(self):
        raw = {
            "metadata": {"name": collector.JOB},
            "spec": {
                "template": {
                    "spec": {
                        "taskCount": 1,
                        "parallelism": 1,
                        "template": {
                            "spec": {
                                "serviceAccountName": "runner@example.iam.gserviceaccount.com",
                                "timeoutSeconds": "900",
                                "maxRetries": 0,
                                "volumes": [{"secret": "do not expose"}],
                                "containers": [
                                    {
                                        "image": "image@sha256:123",
                                        "resources": {
                                            "limits": {"cpu": "2", "memory": "4Gi"}
                                        },
                                        "env": [
                                            {
                                                "name": "PRIVATE",
                                                "value": "private-environment-value",
                                            }
                                        ],
                                    }
                                ],
                            }
                        },
                    }
                }
            },
            "status": {
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "message": "secret failure text",
                    }
                ]
            },
        }
        clean = collector.sanitize_job(raw)
        self.assertEqual(clean["containers"][0]["limits"]["memory"], "4Gi")
        self.assertNotIn("private-environment-value", json.dumps(clean))
        self.assertNotIn("do not expose", json.dumps(clean))
        self.assertNotIn("secret failure text", json.dumps(clean))

    def test_dispatcher_only_allowlisted_scaling_annotations_are_exported(self):
        clean = collector.sanitize_dispatcher(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "autoscaling.knative.dev/maxScale": "1",
                                "run.googleapis.com/cpu-throttling": "true",
                                "unknown": "sensitive annotation",
                            }
                        },
                        "spec": {"containers": [], "containerConcurrency": 1},
                    }
                },
            }
        )
        self.assertEqual(clean["scaling"]["autoscaling.knative.dev/maxScale"], "1")
        self.assertNotIn("sensitive annotation", json.dumps(clean))

    def test_execution_real_milestone_times_and_non_billing_resource_envelope(self):
        result = collector.summarize_executions([execution()], 200)
        item = result["executions"][0]
        self.assertAlmostEqual(item["elapsed_start_to_completion_seconds"], 215.107863)
        self.assertAlmostEqual(
            item["elapsed_created_to_completion_seconds"], 238.074908
        )
        envelope = result["resource_time_envelope"]
        self.assertAlmostEqual(envelope["vcpu_seconds"], 430.215726)
        self.assertAlmostEqual(envelope["gib_seconds"], 860.431452)
        self.assertEqual(envelope["included_completed_executions"], 1)
        self.assertFalse(envelope["is_billable_usage"])
        self.assertNotIn("not exported", json.dumps(result))

    def test_missing_historic_resources_not_filled_from_current_job(self):
        result = collector.summarize_executions([execution(with_resources=False)], 200)
        envelope = result["resource_time_envelope"]
        self.assertEqual(envelope["included_completed_executions"], 0)
        self.assertEqual(envelope["excluded_executions"], 1)
        self.assertEqual(envelope["vcpu_seconds"], 0)

    def test_unfinished_and_invalid_durations_excluded_and_limit_reported(self):
        first, second = execution(), execution()
        first["status"].pop("completionTime")
        second["status"]["completionTime"] = "2026-10-14T15:00:00Z"
        result = collector.summarize_executions([first, second], 2)
        self.assertTrue(result["possibly_truncated"])
        self.assertEqual(result["resource_time_envelope"]["excluded_executions"], 2)
        self.assertIsNone(
            result["executions"][0]["elapsed_start_to_completion_seconds"]
        )

    def test_units_milli_cpu_binary_and_decimal_memory(self):
        self.assertEqual(collector.quantity("500m", "cpu"), collector.Decimal("0.5"))
        self.assertEqual(collector.quantity("512Mi", "memory"), 512 * 1024**2)
        self.assertEqual(collector.quantity("4G", "memory"), 4 * 1000**3)
        for value in ("-1", "NaN", "0", "unknown", True, None):
            self.assertIsNone(collector.quantity(value, "cpu"))

    def test_partial_permission_failure_and_schema_failure_do_not_claim_acceptance(
        self,
    ):
        def runner(args):
            if args[:3] == ["billing", "projects", "describe"]:
                return {"observed": True, "data": None}
            return {
                "observed": False,
                "reason": "permission_denied",
                "raw": "private stderr",
            }

        report = collector.collect(days=1, limit=2, now=NOW, runner=runner)
        self.assertFalse(report["collection_complete"])
        self.assertFalse(report["acceptance_complete"])
        self.assertEqual(
            report["observations"]["billing_status"]["reason"],
            "unexpected_gcloud_schema",
        )
        self.assertNotIn("private stderr", json.dumps(report))

    def test_secret_versions_only_state_counts_and_no_raw_response(self):
        def runner(args):
            if args[:3] == ["secrets", "versions", "list"]:
                return {
                    "observed": True,
                    "data": [
                        {"name": "1", "state": "ENABLED", "payload": "secret-value"},
                        {"name": "2", "state": "DISABLED"},
                    ],
                }
            return {"observed": False, "reason": "permission_denied"}

        report = collector.collect(days=30, limit=2, now=NOW, runner=runner)
        record = report["observations"]["secret_versions/malscan-v2-r2-read"]["data"]
        self.assertEqual(record["states"], {"ENABLED": 1, "DISABLED": 1})
        self.assertTrue(record["possibly_truncated"])
        self.assertNotIn("secret-value", json.dumps(report))

    def test_opt_in_correlation_query_is_fixed_scoped_and_only_projected_fields(self):
        calls = []

        def runner(args):
            calls.append(args)
            return (
                {"observed": True, "data": []}
                if args[:2] == ["logging", "read"]
                else {"observed": False, "reason": "permission_denied"}
            )

        report = collector.collect(
            days=30, limit=200, now=NOW, runner=runner, job_ids=JOB_IDS
        )
        self.assertEqual(len(calls), 13)
        args = calls[-1]
        self.assertEqual(args[:2], ["logging", "read"])
        query = args[2]
        self.assertIn('resource.type="cloud_run_job"', query)
        self.assertIn('resource.labels.job_name="malscan-v2-static-demo"', query)
        self.assertIn('resource.labels.location="us-central1"', query)
        self.assertIn('jsonPayload.scope="shared_cloud_static_analysis"', query)
        self.assertIn("jsonPayload.success=true", query)
        for job_id in JOB_IDS:
            self.assertIn(f'jsonPayload.job_id="{job_id}"', query)
        self.assertIn('timestamp>="2026-09-15T04:00:00Z"', query)
        self.assertIn('timestamp<="2026-10-15T04:00:00Z"', query)
        self.assertEqual(
            args[-1],
            "--format=json(timestamp,labels,jsonPayload.job_id,jsonPayload.dispatch_id,jsonPayload.success,jsonPayload.batch_analysis.status)",
        )
        correlation = report["observations"]["acceptance_job_correlation"]["data"]
        self.assertEqual(correlation["returned_log_count"], 0)
        self.assertEqual(len(correlation["roots"]), 3)
        self.assertTrue(
            all(
                root["observed_unique_execution_count"] == 0
                for root in correlation["roots"]
            )
        )
        self.assertFalse(correlation["proves_no_extra_execution"])
        self.assertIn(
            "Missing logs do not prove no execution", correlation["limitations"]
        )

    def test_correlation_deduplicates_executions_dispatches_without_leaking_other_fields(
        self,
    ):
        rows = []
        for execution_name, dispatch_id, timestamp in [
            ("malscan-v2-static-demo-first", DISPATCH_ID, "2026-10-15T03:00:00Z"),
            ("malscan-v2-static-demo-first", DISPATCH_ID, "2026-10-15T03:00:00.1Z"),
            ("malscan-v2-static-demo-second", JOB_IDS[1], "2026-10-15T03:01:00Z"),
        ]:
            rows.append(
                {
                    "timestamp": timestamp,
                    "textPayload": "SECRET LOG TEXT",
                    "labels": {
                        "run.googleapis.com/execution_name": execution_name,
                        "unknown": "SECRET LABEL",
                    },
                    "jsonPayload": {
                        "job_id": JOB_IDS[0],
                        "dispatch_id": dispatch_id,
                        "success": True,
                        "batch_analysis": {
                            "status": "partial",
                            "password": "SECRET PASSWORD",
                        },
                    },
                }
            )
        result = collector.summarize_job_logs(
            rows, JOB_IDS, 3, "2026-10-14T00:00:00Z", "2026-10-15T04:00:00Z"
        )
        root = result["roots"][0]
        self.assertEqual(root["successful_entrypoint_log_count"], 3)
        self.assertEqual(root["observed_unique_execution_count"], 2)
        self.assertEqual(root["dispatch_ids"], sorted([DISPATCH_ID, JOB_IDS[1]]))
        self.assertEqual(root["batch_analysis_statuses"], ["partial"])
        self.assertEqual(root["first_success_log_at"], "2026-10-15T03:00:00Z")
        self.assertEqual(root["last_success_log_at"], "2026-10-15T03:01:00Z")
        self.assertTrue(result["possibly_truncated"])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertFalse(result["proves_no_extra_execution"])

    def test_missing_execution_label_is_not_counted_as_an_execution(self):
        rows = [
            {"jsonPayload": {"job_id": JOB_IDS[0], "success": True}},
            {"jsonPayload": {"job_id": JOB_IDS[0], "success": False}},
            {"jsonPayload": {"job_id": DISPATCH_ID, "success": True}},
            "malformed",
        ]
        result = collector.summarize_job_logs(rows, JOB_IDS, 20, "from", "through")
        root = result["roots"][0]
        self.assertEqual(root["successful_entrypoint_log_count"], 1)
        self.assertEqual(root["records_without_execution_name"], 1)
        self.assertEqual(root["observed_unique_execution_count"], 0)
        self.assertEqual(root["dispatch_ids"], [])
        self.assertEqual(result["ignored_records"], 3)

    def test_job_id_validation_precedes_all_cloud_reads(self):
        for job_ids in (
            ["not-a-uuid"],
            [JOB_IDS[0].upper()],
            ["6a0910bf-ed13-1de9-b6bf-e0d7ff9cd2a0"],
            [JOB_IDS[0] + '" OR true'],
            [None],
            JOB_IDS + [DISPATCH_ID],
        ):
            with self.subTest(job_ids=job_ids), patch.object(
                collector, "run_gcloud"
            ) as run:
                with self.assertRaises(ValueError):
                    collector.collect(
                        days=1, limit=20, now=NOW, runner=run, job_ids=job_ids
                    )
                run.assert_not_called()
        self.assertEqual(
            collector.validate_job_ids([JOB_IDS[0], JOB_IDS[0]]), [JOB_IDS[0]]
        )


class ProcessAndFileTests(unittest.TestCase):
    @patch.object(collector.subprocess, "run")
    def test_process_uses_no_shell_fixed_project_and_disables_http_logging(self, run):
        run.return_value = subprocess.CompletedProcess(
            [], 0, '{"billingEnabled": true}', ""
        )
        result = collector.run_gcloud(
            [
                "billing",
                "projects",
                "describe",
                collector.PROJECT,
                "--format=json(billingEnabled)",
            ]
        )
        self.assertTrue(result["observed"])
        args, kwargs = run.call_args
        self.assertIn("--project=malscan-v2-poc", args[0])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"]["CLOUDSDK_CORE_LOG_HTTP"], "false")
        self.assertEqual(kwargs["timeout"], 45)

    @patch.object(collector.subprocess, "run")
    def test_errors_and_timeouts_never_copy_diagnostic_contents(self, run):
        run.return_value = subprocess.CompletedProcess(
            [], 1, "access-token-in-stdout", "PERMISSION_DENIED private-details"
        )
        result = collector.run_gcloud(["services", "list"])
        self.assertEqual(result, {"observed": False, "reason": "permission_denied"})
        run.side_effect = subprocess.TimeoutExpired("gcloud", 45, output="secret-token")
        self.assertEqual(collector.run_gcloud([])["reason"], "read_request_timed_out")
        run.side_effect = FileNotFoundError
        self.assertEqual(collector.run_gcloud([])["reason"], "gcloud_not_installed")

    @patch.object(collector.subprocess, "run")
    def test_bad_json_is_categorized_without_echoing_output(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "secret-token", "")
        self.assertEqual(
            collector.run_gcloud([]),
            {"observed": False, "reason": "invalid_gcloud_json"},
        )

    def test_file_is_private_and_exclusive_including_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            collector.write_report(path, {"read_only": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), {"read_only": True})
            with self.assertRaises(FileExistsError):
                collector.write_report(path, {"overwritten": True})
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                collector.write_report(link, {})
            self.assertEqual(json.loads(path.read_text()), {"read_only": True})


if __name__ == "__main__":
    unittest.main()
