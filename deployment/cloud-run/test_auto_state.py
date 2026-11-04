"""Offline storage and lease tests; no credentials or cloud requests are used."""

import copy
import io
import json
import subprocess
import traceback
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import auto_state as state

OWNER = "12345678-1234-4234-8234-123456789abc"
OTHER = "22345678-1234-4234-8234-123456789abc"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class ScriptedTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class MemoryStore:
    def __init__(self):
        self.value = None
        self.generation = 0
        self.serial = 0
        self.puts = []
        self.deletes = []
        self.put_failure = None
        self.delete_failure = None

    def load_json(self, name):
        return copy.deepcopy(self.value), self.generation

    def put_json(self, name, value, expected_generation):
        self.puts.append((name, copy.deepcopy(value), expected_generation))
        if self.put_failure == "conflict":
            raise state.ConflictError("storage_generation_conflict")
        if self.generation != expected_generation:
            raise state.ConflictError("storage_generation_conflict")
        self.serial += 1
        self.generation = self.serial
        self.value = copy.deepcopy(value)
        if self.put_failure == "unknown_after_write":
            raise state.UncertainWriteError("storage_write_response_unknown")
        return self.generation

    def delete(self, name, expected_generation):
        self.deletes.append((name, expected_generation))
        if self.generation != expected_generation:
            raise state.ConflictError("storage_generation_conflict")
        self.generation = 0
        self.value = None
        if self.delete_failure:
            raise state.UncertainWriteError("storage_delete_response_unknown")


class StoreTests(unittest.TestCase):
    def store(self, *responses):
        transport = ScriptedTransport(*responses)
        return state.Store("malscan-private-operations", transport=transport), transport

    def test_missing_object_is_zero_generation_without_a_media_request(self):
        store, transport = self.store((404, b"arbitrary provider error"))
        self.assertEqual(store.load_json("controller.json"), (None, 0))
        self.assertEqual(len(transport.calls), 1)

    def test_body_read_is_bound_to_the_metadata_generation_and_exact_size(self):
        payload = encoded({"phase": "submission_pending", "release": "test"})
        store, transport = self.store(
            (200, encoded({"generation": "42", "size": str(len(payload))})),
            (200, payload),
        )
        self.assertEqual(
            store.load_json("campaigns/release/state.json"),
            ({"phase": "submission_pending", "release": "test"}, 42),
        )
        for method, url, _, body in transport.calls:
            self.assertEqual(method, "GET")
            self.assertIsNone(body)
            self.assertEqual(urlsplit(url).netloc, "storage.googleapis.com")
            self.assertIn("database-updates%2Fcampaigns%2Frelease%2Fstate.json", url)
        self.assertEqual(
            parse_qs(urlsplit(transport.calls[1][1]).query),
            {"alt": ["media"], "generation": ["42"]},
        )

    def test_generation_change_or_disappearance_never_becomes_an_unbound_read(self):
        for response in ((404, b""), (412, b""), (200, b"{} ")):
            with self.subTest(response=response):
                store, transport = self.store(
                    (200, encoded({"generation": "42", "size": "2"})), response
                )
                with self.assertRaisesRegex(state.StateError, "exact_generation"):
                    store.load_json("state.json")
                self.assertEqual(len(transport.calls), 2)

    def test_upload_and_delete_always_use_explicit_generation_preconditions(self):
        store, transport = self.store(
            (200, encoded({"generation": "51"})),
            (200, encoded({"generation": "52"})),
            (204, b""),
        )
        self.assertEqual(store.put_json("state.json", {"phase": "prepared"}, 0), 51)
        self.assertEqual(store.put_json("state.json", {"phase": "pending"}, 51), 52)
        store.delete("state.json", 52)
        self.assertEqual([call[0] for call in transport.calls], ["POST", "POST", "DELETE"])
        self.assertEqual(
            [parse_qs(urlsplit(call[1]).query)["ifGenerationMatch"] for call in transport.calls],
            [["0"], ["51"], ["52"]],
        )
        self.assertEqual(json.loads(transport.calls[0][3]), {"phase": "prepared"})

    def test_generation_validation_precedes_network_writes(self):
        for value in (True, False, -1, 1.0, "1", None, state.MAX_GENERATION + 1):
            with self.subTest(value=value):
                store, transport = self.store()
                with self.assertRaisesRegex(state.StateError, "generation_invalid"):
                    store.put_json("state.json", {}, value)
                with self.assertRaisesRegex(state.StateError, "generation_invalid"):
                    store.delete("state.json", value)
                self.assertEqual(transport.calls, [])
        store, transport = self.store()
        with self.assertRaisesRegex(state.StateError, "generation_invalid"):
            store.delete("state.json", 0)
        self.assertEqual(transport.calls, [])

    def test_malformed_generation_and_oversized_metadata_are_rejected(self):
        for generation in (True, 0, "0", "01", "-1", "1.0", "9" * 100, None):
            with self.subTest(generation=generation):
                store, transport = self.store(
                    (200, encoded({"generation": generation, "size": "2"}))
                )
                with self.assertRaisesRegex(state.StateError, "generation_invalid"):
                    store.load_json("state.json")
                self.assertEqual(len(transport.calls), 1)
        store, transport = self.store((200, b" " * (state.MAX_METADATA_BYTES + 1)))
        with self.assertRaisesRegex(state.StateError, "json_invalid"):
            store.load_json("state.json")

    def test_state_size_is_bounded_before_download_or_upload(self):
        store, transport = self.store(
            (200, encoded({"generation": "1", "size": str(state.MAX_JSON_BYTES + 1)}))
        )
        with self.assertRaisesRegex(state.StateError, "size_invalid"):
            store.load_json("state.json")
        self.assertEqual(len(transport.calls), 1)
        store, transport = self.store()
        with self.assertRaisesRegex(state.StateError, "size_invalid"):
            store.put_json("state.json", {"large": "x" * state.MAX_JSON_BYTES}, 0)
        self.assertEqual(transport.calls, [])

    def test_json_requires_a_finite_unique_bounded_object(self):
        for body in (b"[]", b"null", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            with self.subTest(body=body):
                store, _ = self.store(
                    (200, encoded({"generation": "42", "size": str(len(body))})),
                    (200, body),
                )
                with self.assertRaisesRegex(state.StateError, "json_invalid"):
                    store.load_json("state.json")
        deep = {}
        for _ in range(state.MAX_JSON_DEPTH + 1):
            deep = {"x": deep}
        for value in ([], {"x": float("nan")}, {"x": float("inf")}, {1: "bad"}, deep):
            with self.subTest(value_type=type(value)):
                store, transport = self.store()
                with self.assertRaisesRegex(state.StateError, "json_invalid"):
                    store.put_json("state.json", value, 0)
                self.assertEqual(transport.calls, [])

    def test_lost_or_invalid_write_response_is_uncertain_and_not_retried(self):
        for response in (
            TimeoutError("private provider detail"),
            (500, b"private provider detail"),
            (200, b"not JSON"),
            (200, encoded({"generation": "0"})),
            (200, encoded({"generation": "9"})),
        ):
            with self.subTest(response=response):
                store, transport = self.store(response)
                with self.assertRaises(state.UncertainWriteError) as caught:
                    store.put_json("state.json", {}, 9)
                self.assertNotIn("private provider detail", str(caught.exception))
                self.assertEqual(len(transport.calls), 1)

    def test_precondition_conflicts_and_delete_unknowns_are_distinct(self):
        store, transport = self.store((412, b"provider detail"))
        with self.assertRaises(state.ConflictError):
            store.put_json("state.json", {}, 0)
        self.assertEqual(len(transport.calls), 1)
        for response, kind in (
            ((412, b""), state.ConflictError),
            ((404, b""), state.ConflictError),
            ((503, b""), state.UncertainWriteError),
            (TimeoutError(), state.UncertainWriteError),
            ((403, b""), state.StateError),
        ):
            with self.subTest(response=response):
                store, transport = self.store(response)
                with self.assertRaises(kind):
                    store.delete("state.json", 7)
                self.assertEqual(len(transport.calls), 1)

    def test_provider_errors_do_not_print_sensitive_payloads_or_trace_context(self):
        sensitive = uuid.uuid4().hex
        for response in (RuntimeError(sensitive), (403, sensitive.encode())):
            with self.subTest(response_type=type(response)):
                store, _ = self.store(response)
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    try:
                        store.load_json("state.json")
                    except state.StateError:
                        trace = traceback.format_exc()
                self.assertNotIn(sensitive, trace)
                self.assertEqual(output.getvalue(), "")

    def test_names_cannot_change_the_bucket_host_or_escape_the_namespace(self):
        for bucket in ("https://evil.invalid", "bucket/other", "ABC", "a", "x?alt=media"):
            with self.subTest(bucket=bucket), self.assertRaises(state.StateError):
                state.Store(bucket)
        for name in ("../x", "/x", "x//y", "x/../y", "x?x=y", "x#fragment", "x\\y"):
            with self.subTest(name=name):
                store, transport = self.store()
                with self.assertRaises(state.StateError):
                    store.load_json(name)
                self.assertEqual(transport.calls, [])


class TransportTests(unittest.TestCase):
    def test_gcloud_identity_is_used_privately_and_auth_headers_are_never_forwarded(self):
        token = uuid.uuid4().hex
        response = Mock()
        response.status = 200
        response.read.return_value = b"{}"
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        transport = state._HTTPTransport()
        transport.opener = Mock()
        transport.opener.open.return_value = context
        with patch.object(
            state.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, token + "\n", ""),
        ) as command:
            self.assertEqual(
                transport.request("GET", "https://storage.googleapis.com/storage/v1/b/x", {}, None),
                (200, b"{}"),
            )
        request = transport.opener.open.call_args.args[0]
        self.assertEqual(request.headers["Authorization"], "Bearer " + token)
        self.assertIn("print-access-token", command.call_args.args[0])
        self.assertTrue(command.call_args.kwargs["capture_output"])
        self.assertEqual(command.call_args.kwargs["env"]["CLOUDSDK_CORE_LOG_HTTP"], "false")
        self.assertIsNone(
            state._NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.invalid")
        )

    def test_token_failure_and_redirect_error_body_remain_redacted(self):
        sensitive = uuid.uuid4().hex
        transport = state._HTTPTransport()
        with patch.object(
            state.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", sensitive),
        ):
            with self.assertRaisesRegex(state.StateError, "^storage_auth_unavailable$"):
                transport.request("GET", "https://storage.googleapis.com/storage/v1/b/x", {}, None)
        with patch.object(state.subprocess, "run") as command:
            with self.assertRaises(state.StateError):
                transport.request("GET", "https://storage.googleapis.com.evil.invalid/x", {}, None)
            command.assert_not_called()
        error = HTTPError("https://storage.googleapis.com/x", 302, sensitive, {}, None)
        error.read = Mock(side_effect=AssertionError("must not read error body"))
        transport.opener = Mock()
        transport.opener.open.side_effect = error
        with patch.object(
            state.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, uuid.uuid4().hex, ""),
        ):
            self.assertEqual(
                transport.request("GET", "https://storage.googleapis.com/x", {}, None), (302, b"")
            )
        error.read.assert_not_called()


class LeaseTests(unittest.TestCase):
    def test_first_acquisition_and_same_owner_reentry_do_not_require_a_terminal_probe(self):
        store = MemoryStore()
        terminal = Mock(side_effect=AssertionError("no previous owner"))
        lease = state.Lease(store, OWNER)
        self.assertTrue(lease.acquire(terminal))
        self.assertTrue(lease.acquire(terminal))
        self.assertTrue(state.Lease(store, OWNER).acquire(terminal))
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(store.puts[0][2], 0)
        lease.assert_owned()
        terminal.assert_not_called()

    def test_foreign_active_or_unknown_owner_is_never_replaced_by_age(self):
        store = MemoryStore()
        self.assertTrue(state.Lease(store, OWNER).acquire(lambda _: None))
        for result in (False, None, "terminal", 1):
            with self.subTest(result=result):
                lease = state.Lease(store, OTHER)
                if result is False:
                    self.assertFalse(lease.acquire(lambda _, result=result: result))
                else:
                    with self.assertRaisesRegex(state.StateError, "owner_state_unknown"):
                        lease.acquire(lambda _, result=result: result)
                self.assertEqual(store.value["owner_build_id"], OWNER)
                self.assertEqual(len(store.puts), 1)
        probe = Mock(side_effect=RuntimeError(uuid.uuid4().hex))
        with self.assertRaisesRegex(state.StateError, "^lease_owner_state_unknown$"):
            state.Lease(store, OTHER).acquire(probe)

    def test_terminal_takeover_is_generation_conditional_and_fences_the_old_owner(self):
        store = MemoryStore()
        first = state.Lease(store, OWNER)
        self.assertTrue(first.acquire(lambda _: None))
        previous_generation = store.generation
        terminal = Mock(return_value=True)
        second = state.Lease(store, OTHER)
        self.assertTrue(second.acquire(terminal))
        terminal.assert_called_once_with(OWNER)
        self.assertEqual(store.puts[-1][2], previous_generation)
        for operation in (first.assert_owned, first.release, lambda: first.acquire(terminal)):
            with self.assertRaises(state.StateError):
                operation()
        self.assertEqual(store.deletes, [])
        second.assert_owned()
        second.release()
        second.release()
        self.assertEqual(len(store.deletes), 1)
        self.assertEqual(store.load_json("lease.json"), (None, 0))

    def test_cas_collision_does_not_retry_or_claim_ownership(self):
        store = MemoryStore()
        store.put_failure = "conflict"
        lease = state.Lease(store, OWNER)
        self.assertFalse(lease.acquire(lambda _: None))
        self.assertEqual(len(store.puts), 1)
        with self.assertRaisesRegex(state.StateError, "lease_not_owned"):
            lease.assert_owned()

    def test_lost_acquire_response_never_grants_permission_for_following_mutations(self):
        store = MemoryStore()
        store.put_failure = "unknown_after_write"
        lease = state.Lease(store, OWNER)
        with self.assertRaises(state.UncertainWriteError):
            lease.acquire(lambda _: None)
        self.assertEqual(len(store.puts), 1)
        with self.assertRaisesRegex(state.StateError, "lease_not_owned"):
            lease.assert_owned()
        store.put_failure = None
        resumed = state.Lease(store, OWNER)
        self.assertTrue(resumed.acquire(lambda _: None))
        self.assertEqual(len(store.puts), 1)

    def test_a_lost_delete_response_is_not_blindly_repeated(self):
        store = MemoryStore()
        lease = state.Lease(store, OWNER)
        self.assertTrue(lease.acquire(lambda _: None))
        store.delete_failure = True
        with self.assertRaises(state.UncertainWriteError):
            lease.release()
        with self.assertRaisesRegex(state.StateError, "lease_not_owned"):
            lease.release()
        self.assertEqual(len(store.deletes), 1)

    def test_malformed_markers_and_invalid_owner_generations_fail_closed(self):
        for owner in (
            "not-a-build",
            OWNER.upper(),
            "0" * 32,
            "00000000-0000-0000-0000-000000000000",
        ):
            with self.subTest(owner=owner), self.assertRaises(state.StateError):
                state.Lease(MemoryStore(), owner)
        for value, generation in (
            (None, 4),
            ({"schema_version": 1, "owner_build_id": OWNER}, 0),
            ({"schema_version": True, "owner_build_id": OWNER}, 4),
            ({"schema_version": 1, "owner_build_id": OTHER, "expires_at": "old"}, 4),
            ({"owner_build_id": OWNER}, 4),
        ):
            with self.subTest(value=value, generation=generation):
                store = MemoryStore()
                store.value, store.generation = value, generation
                with self.assertRaises(state.StateError):
                    state.Lease(store, OWNER).acquire(lambda _: True)
                self.assertEqual(store.puts, [])

    def test_replaced_or_removed_marker_is_detected_before_remote_mutations(self):
        for replacement in (None, {"schema_version": 1, "owner_build_id": OWNER}):
            with self.subTest(replacement=replacement):
                store = MemoryStore()
                lease = state.Lease(store, OWNER)
                self.assertTrue(lease.acquire(lambda _: None))
                store.value, store.generation = replacement, 0 if replacement is None else 99
                with self.assertRaises(state.StateError):
                    lease.assert_owned()
                with self.assertRaises(state.StateError):
                    lease.acquire(lambda _: True)
                with self.assertRaises(state.StateError):
                    lease.release()
                self.assertEqual(store.deletes, [])


if __name__ == "__main__":
    unittest.main()
