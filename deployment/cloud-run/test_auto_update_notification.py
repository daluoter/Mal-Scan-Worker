"""Offline one-Build notification acceptance and durable no-resubmit safety."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import unittest
from datetime import timedelta
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "notification", Path(__file__).with_name("test-auto-update-notification.py")
)
notification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notification)
FIXTURE = importlib.util.spec_from_file_location(
    "notification_fixture", Path(__file__).with_name("test_inspect_auto_update.py")
)
fixture = importlib.util.module_from_spec(FIXTURE)
FIXTURE.loader.exec_module(fixture)
PRIVATE = "PRIVATE_PROVIDER_OR_RECIPIENT_VALUE"


def source_archive(replacement=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name in notification.DEPENDENCIES:
            content = Path(__file__).with_name(name).read_bytes()
            if replacement and name == replacement:
                content = b"unapproved controller dependency"
            member = tarfile.TarInfo("deployment/cloud-run/" + name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return gzip.compress(stream.getvalue(), mtime=0)


class TestREST(fixture.PointsREST):
    def __init__(self, previous):
        super().__init__(previous)
        self.lose_create_response = False
        self.create_without_id = False
        self.marker_mode = "expected"
        self.log_pages = None
        self.list_truncated = False

    def request(self, method, url, payload=None, **kwargs):
        base = url.split("?", 1)[0]
        if method == "POST" and url == notification.BASE:
            result = super().request(method, url, payload, **kwargs)
            if self.lose_create_response:
                self.lose_create_response = False
                raise RuntimeError(PRIVATE)
            return {} if self.create_without_id else result
        if method == "GET" and base == notification.BASE:
            result = super().request(method, url, payload, **kwargs)
            if self.list_truncated:
                result["nextPageToken"] = PRIVATE
            return result
        if method == "GET" and base.startswith(notification.BASE + "/"):
            self.calls.append((method, url, payload, None))
            return copy.deepcopy(
                next((b for b in self.builds if b["id"] == base.rsplit("/", 1)[1]), None)
            )
        if method == "POST" and url == "https://logging.googleapis.com/v2/entries:list":
            self.calls.append((method, url, copy.deepcopy(payload), None))
            if self.log_pages is not None:
                token = payload.get("pageToken")
                if token is None:
                    return copy.deepcopy(self.log_pages[0])
                for index, page in enumerate(self.log_pages[:-1]):
                    if isinstance(page, dict) and page.get("nextPageToken") == token:
                        return copy.deepcopy(self.log_pages[index + 1])
                raise AssertionError("Unexpected logging page token")
            return {"entries": [] if self.marker_mode == "none" else [self.marker_entry()]}
        return super().request(method, url, payload, **kwargs)

    def marker_entry(self):
        marker = {
            "scope": "scheduled_database_update",
            "status": "failed",
            "code": PRIVATE if self.marker_mode == "wrong_code" else notification.EXPECTED_CODE,
            "marker": notification.MARKER,
            "cloud_run_executed": False,
        }
        return {
            "resource": {
                "type": "build",
                "labels": {
                    "project_id": notification.PROJECT,
                    "build_id": "other-build"
                    if self.marker_mode == "wrong_build"
                    else self.builds[0]["id"],
                },
            },
            "textPayload": 'Step #0 - "database-update-controller": ' + json.dumps(marker),
        }


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.base = fixture.ObservabilityTests()
        self.base.setUp()
        self.tool = self.base.tool
        blob = source_archive()
        digest = hashlib.sha256(blob).hexdigest()
        self.tool.plan["bundle_sha256"] = digest
        self.tool.plan["initial_state"]["source"]["bundle_sha256"] = digest
        (self.tool.directory / "source.tar.gz").write_bytes(blob)
        self.tool.journal["plan_sha256"] = notification.setup.digest(self.tool.plan)
        self.tool.save()
        notification.setup.write_private(
            self.tool.directory / "plan.json",
            {
                "sha256": notification.setup.digest(self.tool.plan),
                "plan": self.tool.plan,
            },
        )
        state, generation = self.tool.store.load_json("state.json")
        state["source"]["bundle_sha256"] = digest
        self.tool.store.put_json("state.json", state, generation)
        self.rest = TestREST(self.tool.rest)
        self.rest.pages = [{"timeSeries": [self.base.series()]}]
        self.tool.rest = self.rest
        self.scheduler = self.rest.resources[
            "https://cloudscheduler.googleapis.com/v1/" + self.tool.scheduler_document()["name"]
        ]
        self.scheduler["scheduleTime"] = (self.base.now + timedelta(hours=2)).isoformat()
        metadata_url = (
            f"https://storage.googleapis.com/storage/v1/b/{self.tool.plan['bucket']}/o/"
            + notification.setup.quote(self.tool.plan["bundle_object"], safe="")
        )
        metadata = self.rest.resources[metadata_url]
        metadata.update(
            size=str(len(blob)),
            md5Hash=notification.setup.base64.b64encode(
                hashlib.md5(blob, usedforsecurity=False).digest()
            ).decode(),
            metadata={"sha256": digest, "source_commit": self.tool.plan["source_commit"]},
        )
        self.test = notification.NotificationTest(self.tool, now=lambda: self.base.now)
        self.before_state = copy.deepcopy(self.tool.store.values)
        self.before_journal = copy.deepcopy(self.tool.journal)
        self.before_files = {
            name: (self.tool.directory / name).read_bytes()
            for name in ("plan.json", "source.tar.gz", "apply-state.json")
        }
        self.tool.store.writes.clear()

    def tearDown(self):
        self.base.tearDown()

    def build_posts(self):
        return [c for c in self.rest.calls if c[0] == "POST" and c[1] == notification.BASE]

    def failed(self):
        self.rest.builds[0]["status"] = "FAILURE"
        self.rest.builds[0]["steps"][0]["status"] = "FAILURE"

    def test_prepare_is_preview_and_changes_only_private_sidecar(self):
        report = self.test.prepare()
        self.assertEqual(report["phase"], "prepared")
        self.assertTrue(report["targets_existing_failure_alert"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertEqual(self.build_posts(), [])
        self.assertTrue(all(c[0] == "GET" for c in self.rest.calls))
        self.assertEqual(self.tool.store.values, self.before_state)
        self.assertEqual(self.tool.journal, self.before_journal)
        for name, data in self.before_files.items():
            self.assertEqual((self.tool.directory / name).read_bytes(), data)
        self.assertEqual(self.test.path.stat().st_mode & 0o777, 0o600)
        before = self.test.path.read_bytes()
        self.test.prepare()
        self.assertEqual(self.test.path.read_bytes(), before)

    def test_submit_one_intent_build_uses_invalid_owner_and_exact_source(self):
        self.test.prepare()
        result = self.test.submit()
        self.assertEqual(result["phase"], "submitted")
        self.assertEqual(len(self.build_posts()), 1)
        request = self.build_posts()[0][2]
        self.assertEqual(request["steps"][0]["args"][-1], notification.INVALID_OWNER)
        self.assertEqual(request["timeout"], "300s")
        self.assertEqual(request["queueTtl"], "300s")
        self.assertEqual(request["source"]["storageSource"], self.tool.journal["storage_source"])
        self.assertEqual(
            request["serviceAccount"],
            notification.setup.account_resource(notification.setup.ACCOUNTS["controller"]),
        )
        for _ in range(2):
            self.test.submit()
            self.test.status()
        self.assertEqual(len(self.build_posts()), 1)
        self.assertEqual(self.tool.store.values, self.before_state)

    def test_unknown_create_reconciles_by_tag_without_second_create(self):
        self.test.prepare()
        self.rest.lose_create_response = True
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_submission_outcome_unknown"
        ):
            self.test.submit()
        state = self.test.load()
        self.assertEqual(state["phase"], "submission_pending")
        self.assertNotIn("build_id", state)
        report = self.test.status()
        self.assertEqual(report["phase"], "submitted")
        self.assertEqual(report["build_id"], self.rest.builds[0]["id"])
        self.test.submit()
        self.assertEqual(len(self.build_posts()), 1)

    def test_unknown_submission_with_no_or_duplicate_match_stays_blocked(self):
        self.test.prepare()
        self.rest.create_without_id = True
        with self.assertRaises(notification.NotificationError):
            self.test.submit()
        accepted = copy.deepcopy(self.rest.builds[0])
        for builds in ([], [accepted, accepted]):
            self.rest.builds = builds
            with self.assertRaisesRegex(
                notification.NotificationError, "notification_submission_unknown_no_resubmit"
            ):
                self.test.submit()
            self.assertEqual(len(self.build_posts()), 1)

    def test_failure_marker_is_not_email_receipt_and_received_is_explicit(self):
        self.test.prepare()
        self.test.submit()
        self.failed()
        report = self.test.status()
        self.assertTrue(report["failure_marker_verified"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertTrue(report["image_pointers_match_pre_submit"])
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_matching_policy_confirmation_required"
        ):
            self.test.received(policy_title="Budget warning")
        result = self.test.received(policy_title=notification.POLICY_TITLE)
        self.assertTrue(result["notification_delivery_verified"])
        self.assertFalse(result["independent_mailbox_access"])
        self.assertEqual(result["user_confirmed_at"], self.base.now.isoformat())
        self.rest.marker_mode = "none"
        self.assertTrue(self.test.status()["notification_delivery_verified"])
        self.test.received(policy_title=notification.POLICY_TITLE)
        self.assertEqual(len(self.build_posts()), 1)
        self.assertEqual(self.tool.store.values, self.before_state)

    def test_wrong_status_marker_scope_or_code_cannot_confirm_delivery(self):
        self.test.prepare()
        self.test.submit()
        self.rest.builds[0]["status"] = "SUCCESS"
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_expected_failure_not_observed"
        ):
            self.test.status()
        self.failed()
        for mode in ("none", "wrong_code", "wrong_build"):
            self.rest.marker_mode = mode
            report = self.test.status()
            self.assertFalse(report["failure_marker_verified"])
            with self.assertRaisesRegex(
                notification.NotificationError, "notification_expected_failure_marker_required"
            ):
                self.test.received(policy_title=notification.POLICY_TITLE)
            self.assertNotIn(PRIVATE, json.dumps(report))

    def test_modified_build_source_or_service_account_is_rejected(self):
        self.test.prepare()
        self.test.submit()
        for key, value in (
            ("source", {}),
            ("serviceAccount", "other-account"),
            ("timeout", "301s"),
            ("queueTtl", "301s"),
        ):
            before = self.rest.builds[0][key]
            self.rest.builds[0][key] = value
            with self.assertRaisesRegex(
                notification.NotificationError, "notification_build_request_differs"
            ):
                self.test.status()
            self.rest.builds[0][key] = before
        self.assertEqual(len(self.build_posts()), 1)

    def test_changed_source_dependency_is_not_approved_for_test(self):
        path = self.tool.directory / "source.tar.gz"
        content = path.read_bytes()
        path.write_bytes(content + b"changed")
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_source_archive_changed"
        ):
            self.test.prepare()
        self.assertFalse(self.test.path.exists())
        self.assertEqual(self.build_posts(), [])

    def test_matching_archive_hash_does_not_approve_different_controller_code(self):
        blob = source_archive(replacement="auto_state.py")
        (self.tool.directory / "source.tar.gz").write_bytes(blob)
        self.tool.plan["bundle_sha256"] = hashlib.sha256(blob).hexdigest()
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_early_exit_source_not_verified"
        ):
            self.test.source_proof()
        self.assertEqual(self.build_posts(), [])

    def test_same_source_bytes_at_different_gcs_generation_are_not_used(self):
        url = (
            f"https://storage.googleapis.com/storage/v1/b/{self.tool.plan['bucket']}/o/"
            + notification.setup.quote(self.tool.plan["bundle_object"], safe="")
        )
        self.rest.resources[url]["generation"] = "8"
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_source_generation_changed"
        ):
            self.test.prepare()
        self.assertEqual(self.build_posts(), [])

    def test_busy_controller_lease_blocks_new_acceptance_build(self):
        self.tool.store.put_json(
            "lease.json", {"schema_version": 1, "owner_build_id": fixture.OWNER}, 0
        )
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_requires_enabled_idle_state"
        ):
            self.test.prepare()
        self.assertEqual(self.build_posts(), [])

    def test_near_or_unknown_scheduler_tick_blocks_prepare_and_submit(self):
        for time, error in (
            (None, "notification_scheduler_next_time_not_verified"),
            ("invalid", "notification_scheduler_next_time_not_verified"),
            (
                (self.base.now + timedelta(minutes=30)).isoformat(),
                "notification_scheduler_quiet_window_required",
            ),
            (
                (self.base.now - timedelta(minutes=1)).isoformat(),
                "notification_scheduler_quiet_window_required",
            ),
        ):
            with self.subTest(time=time):
                self.scheduler["scheduleTime"] = time
                with self.assertRaisesRegex(notification.NotificationError, error):
                    self.test.prepare()
                self.assertFalse(self.test.path.exists())
                self.assertEqual(self.build_posts(), [])
        self.scheduler["scheduleTime"] = (self.base.now + timedelta(hours=2)).isoformat()
        self.test.prepare()
        self.scheduler["scheduleTime"] = (self.base.now + timedelta(minutes=29)).isoformat()
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_scheduler_quiet_window_required"
        ):
            self.test.submit()
        self.assertEqual(self.test.load()["phase"], "prepared")
        self.assertEqual(self.build_posts(), [])

    def test_concurrent_local_operation_lock_blocks_submission(self):
        self.test.prepare()
        with notification.private.operation_lock(self.tool.directory):
            with self.assertRaises(notification.private.MaintenanceError):
                self.test.submit()
        self.assertEqual(self.test.load()["phase"], "prepared")
        self.assertEqual(self.build_posts(), [])

    def test_preflight_disabled_or_busy_prevents_submission(self):
        self.test.prepare()
        state, generation = self.tool.store.load_json("state.json")
        state["enabled"] = False
        self.tool.store.put_json("state.json", state, generation)
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_monitoring_preflight_not_ready"
        ):
            self.test.submit()
        self.assertEqual(self.test.load()["phase"], "prepared")
        self.assertEqual(self.build_posts(), [])

    def test_partial_build_lookup_never_claims_verification_or_resubmits(self):
        self.test.prepare()
        self.rest.create_without_id = True
        with self.assertRaises(notification.NotificationError):
            self.test.submit()
        self.rest.list_truncated = True
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_build_lookup_incomplete"
        ):
            self.test.status()
        self.assertFalse(self.test.load().get("failure_marker_verified", False))
        self.assertEqual(len(self.build_posts()), 1)

    def logging_calls(self):
        return [
            c
            for c in self.rest.calls
            if c[0] == "POST" and c[1] == "https://logging.googleapis.com/v2/entries:list"
        ]

    def start_failed_test(self):
        self.test.prepare()
        self.test.submit()
        self.failed()
        return self.test.path.read_bytes()

    def test_empty_search_page_continues_to_exact_marker_with_fixed_query(self):
        self.start_failed_test()
        original = self.test.load()
        self.rest.log_pages = [
            {"nextPageToken": PRIVATE},
            {"entries": [self.rest.marker_entry()]},
        ]
        result = self.test.status()
        self.assertTrue(result["failure_marker_verified"])
        self.assertFalse(result["notification_delivery_verified"])
        calls = self.logging_calls()
        self.assertEqual(len(calls), 2)
        first, second = calls[0][2], calls[1][2]
        self.assertNotIn("pageToken", first)
        self.assertEqual(second["pageToken"], PRIVATE)
        self.assertEqual(first, {k: v for k, v in second.items() if k != "pageToken"})
        self.assertEqual(first["resourceNames"], ["projects/" + notification.PROJECT])
        self.assertEqual(first["pageSize"], notification.LOG_PAGE_SIZE)
        self.assertEqual(first["orderBy"], "timestamp desc")
        query = first["filter"]
        self.assertIn('resource.type="build"', query)
        self.assertIn('resource.labels.project_id="' + notification.PROJECT + '"', query)
        self.assertIn('resource.labels.build_id="' + original["build_id"] + '"', query)
        self.assertIn(
            'timestamp>="' + (self.base.now - timedelta(minutes=5)).isoformat() + '"', query
        )
        self.assertIn(
            'timestamp<="' + (self.base.now + timedelta(minutes=5)).isoformat() + '"', query
        )
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertEqual(len(self.build_posts()), 1)
        after = self.test.load()
        for key in ("build_id", "request", "request_tag", "submission_intent_at"):
            self.assertEqual(after[key], original[key])
        self.assertEqual(self.tool.store.values, self.before_state)
        self.assertEqual(self.tool.journal, self.before_journal)
        for name, data in self.before_files.items():
            self.assertEqual((self.tool.directory / name).read_bytes(), data)

    def test_foreign_or_malformed_entries_do_not_hide_later_exact_marker(self):
        self.start_failed_test()
        self.rest.marker_mode = "wrong_build"
        foreign = self.rest.marker_entry()
        self.rest.marker_mode = "expected"
        exact = self.rest.marker_entry()
        payload = json.loads(exact.pop("textPayload").split(": ", 1)[1])
        exact["jsonPayload"] = payload
        self.rest.log_pages = [
            {"entries": [None, PRIVATE, {"resource": []}, foreign], "nextPageToken": PRIVATE},
            {"entries": [exact]},
        ]
        result = self.test.status()
        self.assertTrue(result["failure_marker_verified"])
        self.assertEqual(len(self.logging_calls()), 2)
        self.assertEqual(len(self.build_posts()), 1)

    def test_matching_marker_is_sufficient_even_if_positive_page_has_token(self):
        self.start_failed_test()
        self.rest.log_pages = [{"entries": [self.rest.marker_entry()], "nextPageToken": PRIVATE}]
        report = self.test.status()
        self.assertTrue(report["failure_marker_verified"])
        self.assertEqual(len(self.logging_calls()), 1)
        self.assertFalse(report["notification_delivery_verified"])

    def test_complete_empty_paginated_search_remains_unverified(self):
        self.start_failed_test()
        self.rest.log_pages = [{"entries": [], "nextPageToken": PRIVATE}, {}]
        report = self.test.status()
        self.assertFalse(report["failure_marker_verified"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertEqual(len(self.logging_calls()), 2)
        self.assertEqual(len(self.build_posts()), 1)

    def test_repeated_or_malformed_token_stays_unknown_and_private(self):
        original = self.start_failed_test()
        for pages in (
            [{"nextPageToken": PRIVATE}, {"nextPageToken": PRIVATE}],
            [{"nextPageToken": 123}],
            [{"nextPageToken": PRIVATE * 1000}],
        ):
            with self.subTest(pages=len(pages)):
                self.rest.log_pages = pages
                with self.assertRaisesRegex(
                    notification.NotificationError, "notification_marker_pagination_invalid"
                ) as raised:
                    self.test.status()
                self.assertNotIn(PRIVATE, str(raised.exception))
                self.assertEqual(self.test.path.read_bytes(), original)
        self.assertEqual(len(self.build_posts()), 1)

    def test_search_page_budget_is_bounded_and_cannot_claim_absence(self):
        original = self.start_failed_test()
        self.rest.log_pages = [
            {"entries": [], "nextPageToken": PRIVATE + str(i)}
            for i in range(notification.MAX_LOG_PAGES + 1)
        ]
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_marker_read_incomplete"
        ):
            self.test.status()
        self.assertEqual(len(self.logging_calls()), notification.MAX_LOG_PAGES)
        self.assertEqual(self.test.path.read_bytes(), original)
        self.assertFalse(self.test.load().get("failure_marker_verified", False))
        self.assertEqual(len(self.build_posts()), 1)

    def test_exact_marker_on_last_allowed_page_is_verified(self):
        self.start_failed_test()
        self.rest.log_pages = [
            {"entries": [], "nextPageToken": PRIVATE + str(i)}
            for i in range(notification.MAX_LOG_PAGES - 1)
        ] + [{"entries": [self.rest.marker_entry()]}]
        report = self.test.status()
        self.assertTrue(report["failure_marker_verified"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertEqual(len(self.logging_calls()), notification.MAX_LOG_PAGES)
        self.assertEqual(len(self.build_posts()), 1)

    def test_invalid_query_time_is_rejected_before_logging_read(self):
        original = self.start_failed_test()
        self.test.now = lambda: self.base.now - timedelta(minutes=11)
        with self.assertRaisesRegex(
            notification.NotificationError, "notification_marker_query_time_invalid"
        ):
            self.test.status()
        self.assertEqual(self.logging_calls(), [])
        self.assertEqual(self.test.path.read_bytes(), original)
        self.assertEqual(len(self.build_posts()), 1)

    def test_malformed_or_oversized_page_is_not_verification(self):
        original = self.start_failed_test()
        for response, error in (
            ([], "notification_marker_read_incomplete"),
            ({"entries": None}, "notification_marker_response_invalid"),
            ({"entries": PRIVATE}, "notification_marker_response_invalid"),
            (
                {"entries": [None] * (notification.LOG_PAGE_SIZE + 1)},
                "notification_marker_response_invalid",
            ),
        ):
            with self.subTest(error=error):
                self.rest.log_pages = [response]
                with self.assertRaisesRegex(notification.NotificationError, error):
                    self.test.status()
                self.assertEqual(self.test.path.read_bytes(), original)
        self.assertEqual(len(self.build_posts()), 1)

    def test_private_checkpoint_fields_are_validated_before_public_summary(self):
        self.test.prepare()
        for field, value in (
            ("build_status", PRIVATE),
            ("failure_marker_verified", PRIVATE),
            ("user_confirmed_at", PRIVATE),
        ):
            state = self.test.load()
            state[field] = value
            notification.private.write_private(self.test.path, state)
            with self.assertRaisesRegex(
                notification.NotificationError, "notification_test_checkpoint_invalid"
            ):
                self.test.prepare()
            state.pop(field)
            notification.private.write_private(self.test.path, state)


if __name__ == "__main__":
    unittest.main()
