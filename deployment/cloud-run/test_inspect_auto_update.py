"""Offline evidence boundaries and privacy of the read-only observability tool."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

SPEC = importlib.util.spec_from_file_location(
    "observe", Path(__file__).with_name("inspect-auto-update.py")
)
observe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observe)
FIXTURE = importlib.util.spec_from_file_location(
    "observe_fixture", Path(__file__).with_name("test_setup_auto_update.py")
)
fixtures = importlib.util.module_from_spec(FIXTURE)
FIXTURE.loader.exec_module(fixtures)
OWNER = "00000000-0000-4000-8000-000000000001"
PRIVATE = "PRIVATE_PROVIDER_OR_NOTIFICATION_VALUE"


class PointsREST(fixtures.FakeREST):
    def __init__(self, previous):
        super().__init__()
        self.resources = copy.deepcopy(previous.resources)
        self.channel = {
            **copy.deepcopy(previous.channel),
            "labels": {"email_address": PRIVATE},
            "displayName": PRIVATE,
        }
        self.pages = [{}]
        self.point_calls = 0
        self.fail_points = False
        self.on_points = None

    def request(self, method, url, payload=None, **kwargs):
        if "/timeSeries?" in url:
            self.calls.append((method, url, payload, None))
            if self.on_points:
                self.on_points()
            if self.fail_points:
                raise RuntimeError(PRIVATE)
            result = self.pages[min(self.point_calls, len(self.pages) - 1)]
            self.point_calls += 1
            return copy.deepcopy(result)
        return super().request(method, url, payload, **kwargs)


class ObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProvisioningTests()
        self.fixture.setUp()
        self.tool = self.fixture.provisioner()
        self.tool.apply()
        self.fixture.healthy()
        self.tool.enable()
        self.now = datetime.now(timezone.utc)
        self.activated = self.now - timedelta(minutes=5)
        self.healthy = self.now - timedelta(minutes=2)
        self.tool.journal["activated_at"] = self.activated.isoformat()
        self.tool.save()
        state, generation = self.tool.store.load_json("state.json")
        state.update(
            last_healthy_at=self.healthy.isoformat(),
            last_status="healthy_no_update_due",
            last_controller_build_id=OWNER,
        )
        self.tool.store.put_json("state.json", state, generation)
        self.rest = PointsREST(self.tool.rest)
        self.tool.rest = self.rest
        self.tool.store.writes.clear()
        self.original_state = copy.deepcopy(self.tool.store.values)
        self.original_journal = copy.deepcopy(self.tool.journal)
        self.rest.pages = [{"timeSeries": [self.series()]}]

    def tearDown(self):
        self.fixture.tearDown()

    def series(self, *, value="1", ended=None):
        ended = ended or self.healthy + timedelta(seconds=30)
        return {
            "metric": {"type": observe.METRIC},
            "resource": {
                "type": "build",
                "labels": {"project_id": observe.PROJECT, "build_id": OWNER},
            },
            "metricKind": "DELTA",
            "valueType": "INT64",
            "points": [
                {
                    "interval": {
                        "endTime": ended.isoformat(),
                        "startTime": (ended - timedelta(minutes=1)).isoformat(),
                    },
                    "value": {"int64Value": value},
                }
            ],
        }

    def report(self):
        return observe.inspect(self.tool, now=self.now)

    def test_verified_point_is_separate_from_checkpoint_and_delivery_without_writes(self):
        report = self.report()
        self.assertTrue(report["read_complete"])
        self.assertTrue(report["activation_heartbeat_verified"])
        self.assertTrue(report["healthy_metric_ingestion_verified"])
        self.assertEqual(report["healthy_controller_build_id"], OWNER)
        self.assertTrue(report["enabled_monitoring_metadata_matches_plan"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertFalse(report["real_scheduled_refresh_verified"])
        self.assertTrue(all(call[0] == "GET" for call in self.rest.calls))
        self.assertEqual(self.tool.store.values, self.original_state)
        self.assertEqual(self.tool.journal, self.original_journal)
        self.assertEqual(self.tool.store.writes, [])
        self.assertNotIn(PRIVATE, json.dumps(report))
        query = parse_qs(
            urlsplit(next(c[1] for c in self.rest.calls if "/timeSeries?" in c[1])).query
        )
        self.assertIn('resource.labels.build_id="' + OWNER + '"', query["filter"][0])
        self.assertEqual(query["interval.startTime"], [self.activated.isoformat()])
        self.assertEqual(query["view"], ["FULL"])

    def test_checkpoint_without_metric_is_not_monitoring_proof(self):
        self.rest.pages = [{}]
        report = self.report()
        self.assertTrue(report["activation_heartbeat_verified"])
        self.assertTrue(report["read_complete"])
        self.assertFalse(report["healthy_metric"]["post_activation_point_observed"])
        self.assertFalse(report["healthy_metric_ingestion_verified"])

    def test_only_positive_points_inside_exclusive_start_inclusive_end_count(self):
        for value, ended, expected in (
            ("0", self.healthy, False),
            ("1", self.activated, False),
            ("1", self.activated - timedelta(seconds=1), False),
            ("1", self.now + timedelta(seconds=1), False),
            ("1", self.now, True),
        ):
            with self.subTest(value=value, ended=ended):
                self.rest.point_calls = 0
                self.rest.pages = [{"timeSeries": [self.series(value=value, ended=ended)]}]
                report = self.report()
                self.assertTrue(report["read_complete"])
                self.assertEqual(report["healthy_metric_ingestion_verified"], expected)

    def test_wrong_build_metric_project_or_type_is_unknown_not_absent(self):
        for mutate in (
            lambda row: row["resource"]["labels"].update(build_id="other-build"),
            lambda row: row["resource"]["labels"].update(project_id="other-project"),
            lambda row: row["metric"].update(type="other-metric"),
            lambda row: row.update(metricKind="GAUGE"),
        ):
            row = self.series()
            mutate(row)
            self.rest.point_calls = 0
            self.rest.pages = [{"timeSeries": [row]}]
            report = self.report()
            self.assertFalse(report["read_complete"])
            self.assertIsNone(report["healthy_metric"]["post_activation_point_observed"])

    def test_invalid_counter_timestamp_or_response_cannot_claim_success(self):
        for value in (True, "-1", "2.1", str(2**63)):
            self.rest.point_calls = 0
            self.rest.pages = [{"timeSeries": [self.series(value=value)]}]
            self.assertFalse(self.report()["read_complete"])
        row = self.series()
        row["points"][0]["interval"]["endTime"] = PRIVATE
        self.rest.point_calls = 0
        self.rest.pages = [{"timeSeries": [row]}]
        report = self.report()
        self.assertFalse(report["read_complete"])
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_pagination_finishes_before_reporting_point(self):
        self.rest.pages = [
            {"nextPageToken": "opaque-private-cursor"},
            {"timeSeries": [self.series()]},
        ]
        report = self.report()
        self.assertTrue(report["healthy_metric_ingestion_verified"])
        self.assertEqual(self.rest.point_calls, 2)
        self.assertNotIn("opaque-private-cursor", json.dumps(report))

    def test_truncated_or_partially_failed_query_is_unknown_even_with_a_point(self):
        for extra in (
            {"executionErrors": [{"message": PRIVATE}]},
            {"unreachable": [PRIVATE]},
        ):
            self.rest.point_calls = 0
            self.rest.pages = [{"timeSeries": [self.series()], **extra}]
            report = self.report()
            self.assertFalse(report["read_complete"])
            self.assertIsNone(report["healthy_metric"]["post_activation_point_observed"])
            self.assertNotIn(PRIVATE, json.dumps(report))
        self.rest.point_calls = 0
        self.rest.pages = [
            {"nextPageToken": str(i), "timeSeries": [self.series()]} for i in range(3)
        ]
        self.assertFalse(self.report()["read_complete"])
        self.assertEqual(self.rest.point_calls, 3)

    def test_permission_failure_is_redacted_and_distinct_from_no_points(self):
        self.rest.fail_points = True
        report = self.report()
        self.assertFalse(report["read_complete"])
        self.assertIsNone(report["healthy_metric"]["post_activation_point_observed"])
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.assertIn(
            {"check": "healthy_metric_points", "error": "read_unavailable"}, report["errors"]
        )

    def test_disabled_policy_or_unverified_channel_is_not_ready(self):
        policy = self.tool.journal["policies"][0]
        self.rest.resources["https://monitoring.googleapis.com/v3/" + policy]["enabled"] = False
        self.rest.channel["verificationStatus"] = "UNVERIFIED"
        report = self.report()
        self.assertTrue(report["read_complete"])
        self.assertFalse(report["enabled_monitoring_metadata_matches_plan"])
        self.assertFalse(report["notification_channel"]["metadata_ready"])

    def test_email_without_verification_status_is_metadata_only(self):
        self.rest.channel.pop("verificationStatus")
        report = self.report()
        self.assertTrue(report["notification_channel"]["metadata_ready"])
        self.assertFalse(report["notification_channel"]["delivery_verified"])

    def test_concurrent_controller_state_change_invalidates_observation(self):
        def update():
            state, generation = self.tool.store.load_json("state.json")
            self.tool.store.put_json("state.json", state, generation)

        self.rest.on_points = update
        report = self.report()
        self.assertFalse(report["read_complete"])
        self.assertFalse(report["healthy_metric_ingestion_verified"])
        self.assertIn(
            {"check": "snapshot_consistency", "error": "controller_changed_during_observation"},
            report["errors"],
        )

    def test_registered_source_mismatch_cannot_claim_heartbeat_or_complete_read(self):
        state, generation = self.tool.store.load_json("state.json")
        state["source"]["bundle_sha256"] = "c" * 64
        self.tool.store.put_json("state.json", state, generation)
        report = self.report()
        self.assertFalse(report["registered_source_matches"])
        self.assertFalse(report["activation_heartbeat_verified"])
        self.assertFalse(report["read_complete"])
        self.assertEqual(self.rest.point_calls, 0)

    def test_invalid_falsy_page_tokens_and_delta_metadata_are_not_complete(self):
        for token in (0, False, []):
            self.rest.point_calls = 0
            self.rest.pages = [{"nextPageToken": token}]
            self.assertFalse(self.report()["read_complete"])
        for missing in ("metricKind", "valueType"):
            row = self.series()
            row.pop(missing)
            self.rest.point_calls = 0
            self.rest.pages = [{"timeSeries": [row]}]
            self.assertFalse(self.report()["read_complete"])
        row = self.series()
        row["points"][0]["interval"]["startTime"] = row["points"][0]["interval"]["endTime"]
        self.rest.point_calls = 0
        self.rest.pages = [{"timeSeries": [row]}]
        self.assertFalse(self.report()["read_complete"])

    def test_cli_cannot_overwrite_existing_private_file(self):
        path = self.fixture.directory / "existing-private-file.json"
        path.write_text("keep existing private file")
        output = io.StringIO()
        with patch.object(observe.setup, "Provisioner", return_value=self.tool), patch.object(
            observe, "inspect", return_value={"read_only": True}
        ), patch(
            "sys.argv",
            [
                "inspect-auto-update.py",
                "--plan-dir",
                str(self.fixture.directory),
                "--output",
                str(path),
            ],
        ), redirect_stdout(
            output
        ), self.assertRaises(
            SystemExit
        ) as result:
            observe.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(path.read_text(), "keep existing private file")


if __name__ == "__main__":
    unittest.main()
