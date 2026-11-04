"""Monitoring payload contracts; no API request or notification is sent."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "auto_monitoring", Path(__file__).with_name("auto_monitoring.py")
)
monitoring = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitoring)
CHANNEL = "projects/malscan-v2-poc/notificationChannels/123456789"


class MonitoringPlanTests(unittest.TestCase):
    def plan(self):
        return monitoring.monitoring_plan("malscan-v2-poc", CHANNEL)

    def test_configuration_is_reviewable_serializable_and_initially_disabled(self):
        plan = self.plan()
        self.assertEqual(plan["schema_version"], 1)
        self.assertFalse(plan["remote_mutations"])
        self.assertFalse(plan["notification_sent"])
        self.assertEqual(len(plan["log_metrics"]), 2)
        self.assertEqual(len(plan["alert_policies"]), 2)
        self.assertEqual(json.loads(json.dumps(plan)), plan)
        for policy in plan["alert_policies"]:
            self.assertFalse(policy["enabled"])
            self.assertEqual(policy["notificationChannels"], [CHANNEL])
            self.assertNotIn("name", policy)
            self.assertNotIn("creationRecord", policy)

    def test_project_and_controller_scope_cannot_be_changed(self):
        for project in (None, "other-project", "malscan-v2-poc\nOR resource.type=global"):
            with self.subTest(project=project), self.assertRaises(monitoring.MonitoringError):
                monitoring.monitoring_plan(project, CHANNEL)
        for tag in (None, "another-controller", "malscan-db-controller\nOR true"):
            with self.subTest(tag=tag), self.assertRaises(monitoring.MonitoringError):
                monitoring.monitoring_plan("malscan-v2-poc", CHANNEL, tag)

    def test_channel_must_be_an_existing_resource_name_in_this_project(self):
        for channel in (
            None,
            "",
            "owner@example.invalid",
            "projects/other-project/notificationChannels/123",
            "projects/malscan-v2-poc/notificationChannels/0",
            "projects/malscan-v2-poc/notificationChannels/-1",
            "projects/malscan-v2-poc/notificationChannels/123/extra",
            "projects/malscan-v2-poc/notificationChannels/123\n",
            [CHANNEL],
        ):
            with self.subTest(channel=channel), self.assertRaises(monitoring.MonitoringError):
                monitoring.monitoring_plan("malscan-v2-poc", channel)

    def test_metrics_match_only_project_build_controller_markers(self):
        plan = self.plan()
        expected = {
            monitoring.FAILURE_METRIC: monitoring.FAILURE_MARKER,
            monitoring.HEALTHY_METRIC: monitoring.HEALTHY_MARKER,
        }
        for metric in plan["log_metrics"]:
            self.assertIn('resource.type="build"', metric["filter"])
            self.assertIn('resource.labels.project_id="malscan-v2-poc"', metric["filter"])
            marker = expected[metric["name"]]
            self.assertIn(f'textPayload:"{marker}"', metric["filter"])
            self.assertIn(f'jsonPayload.marker="{marker}"', metric["filter"])
            self.assertEqual(
                metric["metricDescriptor"],
                {"metricKind": "DELTA", "valueType": "INT64", "unit": "1"},
            )
            self.assertNotIn("labelExtractors", metric)
            self.assertNotIn("valueExtractor", metric)
            self.assertNotIn("type", metric["metricDescriptor"])
            other = next(value for key, value in expected.items() if key != metric["name"])
            self.assertNotIn(other, metric["filter"])

    def test_failure_is_positive_count_and_sparse_gaps_reset_the_condition(self):
        policy = self.plan()["alert_policies"][0]
        condition = policy["conditions"][0]["conditionThreshold"]
        self.assertEqual(condition["comparison"], "COMPARISON_GT")
        self.assertEqual(condition["thresholdValue"], 0)
        self.assertEqual(condition["duration"], "60s")
        self.assertEqual(condition["evaluationMissingData"], "EVALUATION_MISSING_DATA_INACTIVE")
        self.assertEqual(condition["trigger"], {"count": 1})
        self.assertIn(monitoring.FAILURE_METRIC, condition["filter"])

    def test_absence_window_fits_provider_limit_and_twelve_hour_ticks(self):
        condition = self.plan()["alert_policies"][1]["conditions"][0]["conditionAbsent"]
        seconds = int(condition["duration"][:-1])
        self.assertEqual(seconds, 23 * 3600)
        self.assertGreater(seconds, 12 * 3600)
        self.assertLessEqual(seconds, int(23.5 * 3600))
        self.assertEqual(seconds % 60, 0)
        self.assertIn(monitoring.HEALTHY_METRIC, condition["filter"])
        self.assertNotIn("172800s", json.dumps(self.plan()))

    def test_every_build_series_is_reduced_before_threshold_or_absence(self):
        for policy in self.plan()["alert_policies"]:
            wrapper = policy["conditions"][0]
            condition = wrapper.get("conditionThreshold") or wrapper["conditionAbsent"]
            self.assertIn('resource.type="build"', condition["filter"])
            self.assertIn('resource.labels.project_id="malscan-v2-poc"', condition["filter"])
            self.assertEqual(len(condition["aggregations"]), 1)
            aggregation = condition["aggregations"][0]
            self.assertEqual(aggregation["perSeriesAligner"], "ALIGN_SUM")
            self.assertEqual(aggregation["crossSeriesReducer"], "REDUCE_SUM")
            self.assertEqual(aggregation["groupByFields"], [])
            self.assertGreaterEqual(int(aggregation["alignmentPeriod"][:-1]), 600)
            self.assertNotIn("build_id", json.dumps(condition))

    def test_initial_point_delivery_and_pre_python_failure_gap_are_explicit(self):
        plan = self.plan()
        requirements = "\n".join(plan["activation_requirements"])
        docs = "\n".join(p["documentation"]["content"] for p in plan["alert_policies"])
        self.assertIn("first healthy", requirements)
        self.assertIn("not populated retroactively", requirements)
        self.assertIn("verify actual delivery", requirements)
        self.assertIn("before Python starts", docs)
        self.assertIn("After creating or modifying", docs)

    def test_independent_plans_do_not_share_mutable_payloads(self):
        before = self.plan()
        expected = copy.deepcopy(before)
        second = self.plan()
        second["log_metrics"][0]["metricDescriptor"]["unit"] = "changed"
        second["alert_policies"][1]["conditions"][0]["conditionAbsent"]["duration"] = "120s"
        second["activation_requirements"].clear()
        self.assertEqual(before, expected)
        self.assertEqual(self.plan(), expected)


if __name__ == "__main__":
    unittest.main()
