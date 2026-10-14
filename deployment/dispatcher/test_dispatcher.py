"""Offline protocol tests: no Google, Cloudflare, Docker, or real credentials."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from server import (
    CLAIM_DOMAIN,
    DISPATCH_DOMAIN,
    MAX_BYTES,
    METADATA_URL,
    Config,
    DispatchError,
    Dispatcher,
    Reply,
    Transport,
    document,
    encoded,
    handler_for,
)

NOW = 1_800_000_000_000
KEY = bytes.fromhex("12" * 32)
CONFIG = Config(
    "malscan-v2-poc",
    "us-central1",
    "malscan-v2-static-demo",
    "https://malscan-v2-demo-control.daluoter.workers.dev",
    KEY,
)
ROOT = "e2add173-87f9-47d5-a2dc-c57ba8a3478e"
ATTEMPT = "7d65cd6b-22f1-449f-8ed5-a1968c830f9e"
DISPATCH = "a3ffef0e-3f07-458a-a18c-f2ad6b5683cb"
OPERATION = "projects/malscan-v2-poc/locations/us-central1/operations/run-123"


def payload() -> dict[str, object]:
    return {
        "dispatch_version": 1,
        "job_name": CONFIG.job_name,
        "issued_at": NOW,
        "expires_at": NOW + 120_000,
        "job_id": ROOT,
        "attempt_id": ATTEMPT,
        "dispatch_id": DISPATCH,
        "sequence": 1,
        "manifest_key": f"manifests/{ROOT}/{ATTEMPT}.json",
        "control_key": f"controls/{ROOT}/{DISPATCH}.json",
        "status_key": f"statuses/{ROOT}/{DISPATCH}.json",
        "report_key": f"reports/{ROOT}/{ATTEMPT}.json",
    }


def request(
    value: dict[str, object] | None = None, domain: bytes = DISPATCH_DOMAIN
) -> bytes:
    text = json.dumps(
        payload() if value is None else value, sort_keys=True, separators=(",", ":")
    )
    return encoded(
        {
            "payload": text,
            "hmac_sha256": hmac.new(
                KEY, domain + text.encode(), hashlib.sha256
            ).hexdigest(),
        }
    )


class FakeTransport:
    def __init__(self, replies: list[Reply | Exception]):
        self.replies = replies
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "timeout": timeout,
            }
        )
        response = self.replies[len(self.calls) - 1]
        if isinstance(response, Exception):
            raise response
        return response


def success_replies(raw: bytes | None = None) -> list[Reply]:
    text = json.loads(raw if raw is not None else request())["payload"]
    return [
        Reply(200, encoded({"access_token": "test-metadata-access-token"})),
        Reply(
            200,
            encoded(
                {
                    "claimed": True,
                    "dispatch_id": DISPATCH,
                    "request_sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
            ),
        ),
        Reply(200, encoded({"name": OPERATION})),
    ]


class ProtocolTests(unittest.TestCase):
    def dispatcher(self, responses=None):
        transport = FakeTransport(success_replies() if responses is None else responses)
        return Dispatcher(CONFIG, transport, lambda: NOW), transport

    def assert_preflight_rejected(self, raw: bytes):
        dispatcher, transport = self.dispatcher()
        with self.assertRaises(DispatchError):
            dispatcher.dispatch(raw)
        self.assertEqual([], transport.calls)

    def test_success_and_fixed_target_headers_timeouts_and_only_eight_overrides(self):
        dispatcher, transport = self.dispatcher()
        self.assertEqual(dispatcher.dispatch(request()), {"name": OPERATION})
        metadata, claim, google = transport.calls
        self.assertEqual(
            metadata,
            {
                "method": "GET",
                "url": METADATA_URL,
                "headers": {"Metadata-Flavor": "Google"},
                "body": None,
                "timeout": 5,
            },
        )
        self.assertEqual(
            claim["url"], CONFIG.control_origin + "/internal/dispatch/claim"
        )
        self.assertEqual(claim["timeout"], 10)
        claim_document = json.loads(claim["body"])
        original_text = json.loads(request())["payload"]
        self.assertEqual(claim_document["payload"], original_text)
        self.assertEqual(
            claim_document["hmac_sha256"],
            hmac.new(
                KEY, CLAIM_DOMAIN + original_text.encode(), hashlib.sha256
            ).hexdigest(),
        )
        self.assertEqual(
            google["url"], "https://run.googleapis.com/v2/" + CONFIG.job_name + ":run"
        )
        self.assertEqual(google["timeout"], 20)
        self.assertEqual(
            google["headers"],
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer test-metadata-access-token",
            },
        )
        override = json.loads(google["body"])
        self.assertEqual(set(override), {"overrides"})
        self.assertEqual(
            set(override["overrides"]), {"taskCount", "containerOverrides"}
        )
        self.assertEqual(override["overrides"]["taskCount"], 1)
        containers = override["overrides"]["containerOverrides"]
        self.assertEqual(len(containers), 1)
        self.assertEqual(set(containers[0]), {"env"})
        values = {entry["name"]: entry["value"] for entry in containers[0]["env"]}
        self.assertEqual(
            values,
            {
                "MALSCAN_MANIFEST_KEY": f"manifests/{ROOT}/{ATTEMPT}.json",
                "MALSCAN_CONTROL_KEY": f"controls/{ROOT}/{DISPATCH}.json",
                "MALSCAN_STATUS_KEY": f"statuses/{ROOT}/{DISPATCH}.json",
                "MALSCAN_DISPATCH_ID": DISPATCH,
                "MALSCAN_ROOT_JOB_ID": ROOT,
                "MALSCAN_ATTEMPT_ID": ATTEMPT,
                "MALSCAN_REPORT_KEY": f"reports/{ROOT}/{ATTEMPT}.json",
                "MALSCAN_SEQUENCE": "1",
            },
        )

    def test_invalid_signature_and_cross_domain_replay_do_not_call_anything(self):
        envelope = json.loads(request())
        envelope["hmac_sha256"] = "00" * 32
        self.assert_preflight_rejected(encoded(envelope))
        self.assert_preflight_rejected(request(domain=CLAIM_DOMAIN))
        self.assert_preflight_rejected(request(domain=b""))

    def test_request_tampering_does_not_call_anything(self):
        envelope = json.loads(request())
        envelope["payload"] = envelope["payload"].replace(
            '"sequence":1', '"sequence":2'
        )
        self.assert_preflight_rejected(encoded(envelope))

    def test_invalid_targets_refs_and_arbitrary_overrides_are_rejected_before_metadata(
        self,
    ):
        cases = {
            "job_name": "projects/other-project/locations/us-central1/jobs/other",
            "job_id": "../other-job",
            "attempt_id": True,
            "dispatch_id": ROOT.upper(),
            "sequence": 0,
            "manifest_key": f"manifests/{ROOT}/../secret.json",
            "control_key": f"controls/{ROOT}/{ATTEMPT}.json",
            "status_key": f"statuses/{ATTEMPT}/{DISPATCH}.json",
            "report_key": "https://example.com/capture",
            "dispatch_version": True,
            "overrides": {"taskCount": 999},
            "callback_url": "http://metadata.google.internal/",
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                changed = payload()
                changed[key] = value
                self.assert_preflight_rejected(request(changed))

    def test_expired_future_oversized_or_bool_time_windows_rejected(self):
        for change in (
            {"expires_at": NOW},
            {"issued_at": NOW + 5_001},
            {"expires_at": NOW + 120_001},
            {"issued_at": True},
            {"expires_at": float(NOW + 10_000)},
            {"sequence": True},
            {"sequence": 1_000_000_000},
        ):
            with self.subTest(change=change):
                changed = payload()
                changed.update(change)
                self.assert_preflight_rejected(request(changed))

    def test_malformed_envelopes_and_oversize_never_make_network_calls(self):
        for raw in (
            b"{}",
            b"not-json",
            b"x" * (MAX_BYTES + 1),
            b'{"payload":"x","payload":"y","hmac_sha256":"z"}',
            b'{"payload":"\\ud800","hmac_sha256":"' + b"0" * 64 + b'"}',
        ):
            with self.subTest(raw=raw[:50]):
                self.assert_preflight_rejected(raw)

    def test_maximum_sequence_and_five_second_clock_skew_are_accepted(self):
        value = payload()
        value["sequence"] = 999_999_999
        value["issued_at"] = NOW + 5_000
        raw = request(value)
        dispatcher, transport = self.dispatcher(success_replies(raw))
        self.assertEqual(dispatcher.dispatch(raw), {"name": OPERATION})
        self.assertEqual(len(transport.calls), 3)

    def test_signed_payload_duplicate_keys_rejected(self):
        text = json.loads(request())["payload"].replace(
            '"sequence":1', '"sequence":1,"sequence":1'
        )
        signature = hmac.new(
            KEY, DISPATCH_DOMAIN + text.encode(), hashlib.sha256
        ).hexdigest()
        self.assert_preflight_rejected(
            encoded({"payload": text, "hmac_sha256": signature})
        )

    def test_metadata_failure_does_not_claim_or_run(self):
        for response in (
            Reply(403, b"{}"),
            Reply(200, encoded({"access_token": "x\r\nInjected: y"})),
            socket.timeout("private network error"),
            Reply(200, b"x" * (MAX_BYTES + 1)),
        ):
            with self.subTest(response=type(response).__name__):
                dispatcher, transport = self.dispatcher([response])
                with self.assertRaisesRegex(
                    DispatchError, "dispatcher_identity_unavailable"
                ):
                    dispatcher.dispatch(request())
                self.assertEqual(len(transport.calls), 1)

    def test_claim_conflict_timeout_bad_hash_or_bad_identity_never_run(self):
        for reply in (
            Reply(409, b"{}"),
            socket.timeout("claim accepted but response lost"),
            Reply(
                200,
                encoded(
                    {
                        "claimed": True,
                        "dispatch_id": DISPATCH,
                        "request_sha256": "00" * 32,
                    }
                ),
            ),
            Reply(
                200,
                encoded(
                    {"claimed": True, "dispatch_id": ROOT, "request_sha256": "00" * 32}
                ),
            ),
            Reply(
                200,
                encoded(
                    {"claimed": 1, "dispatch_id": DISPATCH, "request_sha256": "00" * 32}
                ),
            ),
            Reply(302, b"{}"),
        ):
            with self.subTest(reply=type(reply).__name__):
                responses = success_replies()
                responses[1] = reply
                dispatcher, transport = self.dispatcher(responses)
                with self.assertRaisesRegex(
                    DispatchError, "dispatch_claim_unavailable"
                ):
                    dispatcher.dispatch(request())
                self.assertEqual(len(transport.calls), 2)

    def test_google_timeout_rejection_redirect_or_wrong_operation_never_retry(self):
        for reply in (
            socket.timeout("Google may have accepted"),
            Reply(403, b"{}"),
            Reply(302, b"{}"),
            Reply(
                200,
                encoded({"name": OPERATION.replace("malscan-v2-poc", "other-project")}),
            ),
            Reply(200, encoded({"name": OPERATION + "/../../other"})),
        ):
            with self.subTest(reply=type(reply).__name__):
                responses = success_replies()
                responses[2] = reply
                dispatcher, transport = self.dispatcher(responses)
                with self.assertRaisesRegex(DispatchError, "job_dispatch_uncertain"):
                    dispatcher.dispatch(request())
                self.assertEqual(len(transport.calls), 3)

    def test_request_expiring_after_claim_never_runs(self):
        dispatcher, transport = self.dispatcher()
        ticks = iter((NOW, NOW + 120_001))
        dispatcher.clock_ms = lambda: next(ticks)
        with self.assertRaisesRegex(DispatchError, "dispatch_request_expired"):
            dispatcher.dispatch(request())
        self.assertEqual(len(transport.calls), 2)

    def test_replayed_request_relies_on_durable_one_time_claim_not_process_memory(self):
        first, first_transport = self.dispatcher()
        self.assertEqual(first.dispatch(request()), {"name": OPERATION})
        responses = success_replies()
        responses[1] = Reply(409, encoded({"error": "dispatch_already_claimed"}))
        second, second_transport = self.dispatcher(responses)
        with self.assertRaisesRegex(DispatchError, "dispatch_claim_unavailable"):
            second.dispatch(request())
        self.assertEqual(len(first_transport.calls), 3)
        self.assertEqual(len(second_transport.calls), 2)

    def test_config_rejects_credentials_queries_ports_and_non_https_control_origin(
        self,
    ):
        for origin in (
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com:443",
            "https://example.com/path",
            "https://example.com?target=metadata",
            "https://127.0.0.1",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    Config(CONFIG.project, CONFIG.region, CONFIG.job, origin, KEY)


class LocalHTTPTests(unittest.TestCase):
    def start(self, handler):
        server = HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_transport_identifies_client_and_preserves_required_headers(self):
        received = []

        class Capture(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        server = self.start(Capture)
        reply = Transport().request(
            "GET",
            f"http://127.0.0.1:{server.server_port}/client-check",
            {"Metadata-Flavor": "Google"},
            None,
            1,
        )
        self.assertEqual(reply.status, 200)
        self.assertEqual(received[0]["User-Agent"], "MalScanWorker-dispatcher/1.0")
        self.assertEqual(received[0]["Metadata-Flavor"], "Google")

    def test_redirect_transport_never_follows_location(self):
        visited = []

        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                visited.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.end_headers()

        server = self.start(Redirect)
        result = Transport().request(
            "GET", f"http://127.0.0.1:{server.server_port}/first", {}, None, 1
        )
        self.assertEqual(result.status, 302)
        self.assertEqual(visited, ["/first"])

    def test_http_health_malformed_and_large_requests(self):
        transport = FakeTransport(success_replies())
        dispatcher = Dispatcher(CONFIG, transport, lambda: NOW)
        server = self.start(handler_for(dispatcher))
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=2
        )
        self.addCleanup(connection.close)
        connection.request("GET", "/health")
        reply = connection.getresponse()
        self.assertEqual(reply.status, 200)
        self.assertEqual(document(reply.read())["scope"], "keyless_job_dispatcher")
        for raw, expected in ((b"{}", 400), (b"x" * (MAX_BYTES + 1), 413)):
            connection.request(
                "POST", "/dispatch", raw, {"Content-Type": "application/json"}
            )
            reply = connection.getresponse()
            self.assertEqual(reply.status, expected)
            reply.read()
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
