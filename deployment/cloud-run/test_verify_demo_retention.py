"""Offline retention verification tests; every HTTP request stays on loopback."""

import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from xml.sax.saxutils import escape

SPEC = importlib.util.spec_from_file_location(
    "malscan_verify_demo_retention",
    Path(__file__).with_name("verify-demo-retention.py"),
)
RETENTION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RETENTION
SPEC.loader.exec_module(RETENTION)

JOB = "f9e7d95c-1c74-4624-8b15-ffab0ba533b1"
NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
EXPIRY = NOW - RETENTION.GRACE
CREDS = RETENTION.Credentials(
    "R2ACCESSKEYFORTEST0001", "a-secret-value-used-only-in-unit-tests"
)


def listing(bucket, prefix, present=False, **overrides):
    fields = {
        "Name": bucket,
        "Prefix": prefix,
        "KeyCount": "1" if present else "0",
        "MaxKeys": "1",
        "IsTruncated": "false",
    }
    fields.update(overrides)
    contents = (
        "<Contents><Key>" + escape(prefix + "private-name.bin") + "</Key></Contents>"
        if present
        else ""
    )
    return (
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        + "".join(f"<{key}>{escape(value)}</{key}>" for key, value in fields.items())
        + contents
        + "</ListBucketResult>"
    ).encode()


@contextlib.contextmanager
def local_server(responder):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path, dict(self.headers)))
            status, headers, body = responder(self.path)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def local_transport(server):
    """Production signing stays fixed; only this test forwards the wire locally."""

    def send(request):
        parts = urllib.parse.urlsplit(request.full_url)
        forwarded = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}{parts.path}?{parts.query}",
            headers=dict(request.header_items()),
            method=request.method,
        )
        return RETENTION.request_remote(forwarded)

    return send


class RetentionVerificationTests(unittest.TestCase):
    def test_before_grace_never_reads_credentials_or_makes_requests(self):
        read, transport = mock.Mock(), mock.Mock()
        report = RETENTION.verify(
            JOB,
            EXPIRY,
            now=NOW - dt.timedelta(microseconds=1),
            credential_reader=read,
            transport=transport,
        )
        self.assertEqual(report["status"], "not_due")
        self.assertFalse(report["r2_absence_confirmed"])
        self.assertEqual(len(report["prefixes"]), 7)
        self.assertTrue(
            all(row["objects_present"] is None for row in report["prefixes"])
        )
        read.assert_not_called()
        transport.assert_not_called()

    def test_all_seven_prefixes_listed_and_absent_exactly_at_grace_boundary(self):
        def respond(path):
            parts = urllib.parse.urlsplit(path)
            query = urllib.parse.parse_qs(parts.query)
            return 200, {}, listing(parts.path[1:], query["prefix"][0])

        read = mock.Mock(return_value=CREDS)
        with local_server(respond) as (server, requests):
            report = RETENTION.verify(
                JOB,
                EXPIRY,
                now=NOW,
                credential_reader=read,
                transport=local_transport(server),
            )
        self.assertEqual(report["status"], "verified_absent")
        self.assertTrue(report["r2_absence_confirmed"])
        self.assertEqual(
            read.call_args_list,
            [mock.call(value[0]) for value in RETENTION.BUCKETS.values()],
        )
        self.assertEqual(len(requests), 7)
        expected = {
            (bucket, f"{root}/{JOB}/")
            for bucket, (_, roots) in RETENTION.BUCKETS.items()
            for root in roots
        }
        seen = set()
        for method, path, headers in requests:
            self.assertEqual(method, "GET")
            parts = urllib.parse.urlsplit(path)
            query = urllib.parse.parse_qs(parts.query)
            self.assertEqual(set(query), {"prefix", "max-keys", "list-type"})
            self.assertEqual(query["max-keys"], ["1"])
            self.assertEqual(query["list-type"], ["2"])
            seen.add((parts.path[1:], query["prefix"][0]))
            self.assertEqual(headers["User-Agent"], RETENTION.USER_AGENT)
            self.assertEqual(headers["Host"], RETENTION.HOST)
            self.assertEqual(headers["X-Amz-Date"], "20261015T000000Z")
            self.assertIn(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                headers["Authorization"],
            )
        self.assertEqual(seen, expected)
        self.assertEqual(report["durable_object_row_deletion"], "not_observed")
        self.assertEqual(report["bucket_lifecycle_configuration"], "not_observed")
        self.assertEqual(report["billed_usage"], "not_observed")
        self.assertFalse(report["public_api_withdrawal_is_physical_deletion_proof"])
        encoded = json.dumps(report)
        self.assertNotIn(CREDS.access_key_id, encoded)
        self.assertNotIn(CREDS.secret_access_key, encoded)

    def test_early_observation_absence_cannot_pass(self):
        def send(request):
            parts = urllib.parse.urlsplit(request.full_url)
            prefix = urllib.parse.parse_qs(parts.query)["prefix"][0]
            return listing(parts.path[1:], prefix)

        report = RETENTION.verify(
            JOB,
            EXPIRY,
            observe=True,
            now=NOW - dt.timedelta(seconds=1),
            credential_reader=lambda _: CREDS,
            transport=send,
        )
        self.assertEqual(report["status"], "not_due")
        self.assertFalse(report["r2_absence_confirmed"])
        self.assertTrue(all(row["observed"] for row in report["prefixes"]))

    def test_one_remaining_object_prevents_clean_result_without_leaking_key(self):
        def send(request):
            parts = urllib.parse.urlsplit(request.full_url)
            prefix = urllib.parse.parse_qs(parts.query)["prefix"][0]
            return listing(parts.path[1:], prefix, prefix.startswith("checkpoints/"))

        report = RETENTION.verify(
            JOB, EXPIRY, now=NOW, credential_reader=lambda _: CREDS, transport=send
        )
        self.assertEqual(report["status"], "objects_present")
        self.assertFalse(report["r2_absence_confirmed"])
        self.assertEqual(
            sum(row["objects_present"] is True for row in report["prefixes"]), 1
        )
        self.assertNotIn("private-name.bin", json.dumps(report))

    def test_permission_denial_and_404_are_unknown_not_absence(self):
        for status in (403, 404):
            with self.subTest(status=status):
                with local_server(
                    lambda _: (status, {}, b"private service details")
                ) as (server, _):
                    report = RETENTION.verify(
                        JOB,
                        EXPIRY,
                        now=NOW,
                        credential_reader=lambda _: CREDS,
                        transport=local_transport(server),
                    )
                self.assertEqual(report["status"], "unknown")
                self.assertFalse(report["r2_absence_confirmed"])
                self.assertTrue(
                    all(row["http_status"] == status for row in report["prefixes"])
                )
                self.assertNotIn("private service details", json.dumps(report))

    def test_redirects_are_not_followed(self):
        with local_server(
            lambda _: (302, {"Location": "/must-not-be-requested"}, b"")
        ) as (server, requests):
            with self.assertRaises(RETENTION.ObservationError) as raised:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/initial"
                )
                RETENTION.request_remote(request)
        self.assertEqual(raised.exception.http_status, 302)
        self.assertEqual(len(requests), 1)

    def test_network_failure_is_unknown(self):
        def fail(_):
            raise RETENTION.ObservationError("listing_network_error")

        report = RETENTION.verify(
            JOB, EXPIRY, now=NOW, credential_reader=lambda _: CREDS, transport=fail
        )
        self.assertEqual(report["status"], "unknown")
        self.assertTrue(
            all(row["objects_present"] is None for row in report["prefixes"])
        )

    def test_secret_read_failure_does_not_attempt_listing_or_expose_stderr(self):
        transport = mock.Mock()
        result = subprocess.CompletedProcess(
            [], 1, b"private credential", b"sensitive stderr"
        )
        captured = io.StringIO()
        with mock.patch.object(
            RETENTION.subprocess, "run", return_value=result
        ), contextlib.redirect_stdout(captured):
            report = RETENTION.verify(JOB, EXPIRY, now=NOW, transport=transport)
        transport.assert_not_called()
        self.assertEqual(captured.getvalue(), "")
        self.assertEqual(report["status"], "unknown")
        self.assertNotIn("private credential", json.dumps(report))
        self.assertNotIn("sensitive stderr", json.dumps(report))

    def test_secret_read_is_pinned_to_existing_version_and_captured_in_memory(self):
        payload = json.dumps(
            {
                "access_key_id": CREDS.access_key_id,
                "secret_access_key": CREDS.secret_access_key,
            }
        ).encode()
        result = subprocess.CompletedProcess([], 0, payload, b"")
        captured = io.StringIO()
        with mock.patch.object(
            RETENTION.subprocess, "run", return_value=result
        ) as run, contextlib.redirect_stdout(captured):
            credentials = RETENTION.read_credentials("malscan-v2-r2-read")
        self.assertEqual(credentials.access_key_id, CREDS.access_key_id)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:5], ["gcloud", "secrets", "versions", "access", "1"])
        self.assertIn("--secret=malscan-v2-r2-read", args[0])
        self.assertIn("--project=malscan-v2-poc", args[0])
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"]["CLOUDSDK_CORE_LOG_HTTP"], "false")
        self.assertEqual(kwargs["env"]["CLOUDSDK_CORE_DISABLE_FILE_LOGGING"], "true")
        self.assertEqual(captured.getvalue(), "")
        self.assertNotIn(CREDS.secret_access_key, repr(credentials))

    def test_invalid_secret_format_and_unapproved_secret_fail_closed(self):
        for payload in (
            b"null",
            b"{}",
            b"not json",
            b'{"access_key_id": [], "secret_access_key": "x"}',
        ):
            with self.subTest(payload=payload), mock.patch.object(
                RETENTION.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, payload, b""),
            ):
                with self.assertRaises(RETENTION.ObservationError) as raised:
                    RETENTION.read_credentials("malscan-v2-r2-results")
                self.assertEqual(raised.exception.reason, "credential_format_invalid")
        with mock.patch.object(RETENTION.subprocess, "run") as run:
            with self.assertRaises(RETENTION.ObservationError):
                RETENTION.read_credentials("malscan-v2-control-hmac")
            run.assert_not_called()

    def test_sigv4_exact_request_fixture(self):
        # This fixture was independently matched against MinIO's SigV4 signer;
        # the verifier and this test need only the Python standard library.
        request = RETENTION.signed_listing_request(
            RETENTION.SOURCE_BUCKET, f"uploads/{JOB}/", CREDS, NOW
        )
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertEqual(
            request.full_url,
            f"https://{RETENTION.HOST}/{RETENTION.SOURCE_BUCKET}?list-type=2&max-keys=1&prefix=uploads%2F{JOB}%2F",
        )
        self.assertEqual(
            request.get_header("Authorization"),
            "AWS4-HMAC-SHA256 Credential=R2ACCESSKEYFORTEST0001/20261015/auto/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
            "Signature=8ed887a53c0a536162e78f5e49b71403da0375b73a333213e988f5160b2f1ced",
        )
        self.assertNotIn(CREDS.secret_access_key, request.full_url)

    def test_signing_cannot_target_other_buckets_or_prefixes(self):
        for bucket, prefix in (
            ("other-bucket", f"uploads/{JOB}/"),
            (RETENTION.SOURCE_BUCKET, f"reports/{JOB}/"),
            (RETENTION.RESULT_BUCKET, f"uploads/{JOB}/"),
            (RETENTION.SOURCE_BUCKET, f"uploads/{JOB}/../"),
            (RETENTION.SOURCE_BUCKET, "uploads/not-a-job/"),
            (RETENTION.SOURCE_BUCKET, f"uploads/{JOB}"),
        ):
            with self.subTest(bucket=bucket, prefix=prefix), self.assertRaises(
                ValueError
            ):
                RETENTION.signed_listing_request(bucket, prefix, CREDS, NOW)

    def test_malformed_or_inconsistent_listings_cannot_prove_absence(self):
        bucket, prefix = RETENTION.SOURCE_BUCKET, f"uploads/{JOB}/"
        cases = [
            b"",
            b"not xml",
            b"<Error><Code>AccessDenied</Code></Error>",
            listing(bucket, prefix, IsTruncated="true"),
            listing(bucket, prefix, KeyCount="1"),
            listing(bucket, prefix, MaxKeys="1000"),
            listing("other-bucket", prefix),
            listing(bucket, "uploads/other-job/"),
            b'<!DOCTYPE x [<!ENTITY x "private">]><ListBucketResult/>',
            '<!DOCTYPE x [<!ENTITY x "private">]><ListBucketResult/>'.encode("utf-16"),
            b"x" * (RETENTION.MAX_RESPONSE_BYTES + 1),
            listing(bucket, prefix).replace(
                b"</ListBucketResult>", b"<KeyCount>0</KeyCount></ListBucketResult>"
            ),
        ]
        for body in cases:
            with self.subTest(body_length=len(body)), self.assertRaises(
                RETENTION.ObservationError
            ):
                RETENTION.listing_presence(body, bucket, prefix)

    def test_bounded_http_response(self):
        with local_server(
            lambda _: (200, {}, b"x" * (RETENTION.MAX_RESPONSE_BYTES + 1))
        ) as (server, _):
            with self.assertRaises(RETENTION.ObservationError) as raised:
                RETENTION.request_remote(
                    urllib.request.Request(f"http://127.0.0.1:{server.server_port}/")
                )
        self.assertEqual(raised.exception.reason, "listing_response_too_large")

    def test_input_requires_canonical_uuid4_and_aware_timestamp(self):
        for value in (
            JOB.upper(),
            "../" + JOB,
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RETENTION.validate_job_id(value)
        self.assertEqual(RETENTION.parse_expiry("2026-10-15T08:00:00+08:00"), NOW)
        for value in ("2026-10-15T00:00:00", "not-a-date", "9999-12-31T23:59:59Z"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RETENTION.parse_expiry(value)

    def test_cli_creates_private_evidence_and_refuses_overwrite(self):
        report = {"status": "verified_absent", "r2_absence_confirmed": True}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            args = [
                "--job-id",
                JOB,
                "--retention-expires-at",
                "2026-10-14T00:00:00Z",
                "--output",
                str(path),
            ]
            captured = io.StringIO()
            with mock.patch.object(
                RETENTION, "verify", return_value=report
            ), contextlib.redirect_stdout(captured):
                self.assertEqual(RETENTION.main(args), 0)
                self.assertEqual(RETENTION.main(args), 2)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertIn("report_write_failed", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
