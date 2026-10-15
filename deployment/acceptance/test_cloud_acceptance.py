"""Stdlib HTTP contract tests; never contact the deployed demo."""

import contextlib
import copy
import importlib.util
import io
import json
import socket
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "cloud_acceptance", Path(__file__).with_name("cloud_acceptance.py")
)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class ContractServer:
    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.requests = []
        self.executions = 0
        self.jobs = {}
        self.drop_upload_response = False
        self.drop_ticket_response = False
        self.redirect = False
        self.quota_reject = False
        self.passwords = False
        self.oversize_error_code = "invalid_upload_metadata"
        self.replay_error_code = "upload_credential_used"
        self.cors = client.ORIGIN
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, body):
                data = client.encode(body)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Access-Control-Allow-Origin", owner.cors)
                self.end_headers()
                self.wfile.write(data)

            def error(self, code, status):
                self.answer(status, {"error": {"code": code, "message": code}})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                owner.requests.append(("POST", self.path, dict(self.headers), body))
                # Verify durable intent was visible to another process before
                # this real server received any mutation.
                state = json.loads((owner.state_dir / "campaign.json").read_text())
                if self.path == "/api/v1/upload-tickets":
                    payload = json.loads(body)
                    if payload["bytes"] > client.MAX_BYTES:
                        assert "oversize" in state["guards"]["operations"]
                        return self.error(owner.oversize_error_code, 400)
                    assert any(
                        "ticket" in case["operations"]
                        for case in state["cases"].values()
                    )
                    if owner.redirect:
                        self.send_response(307)
                        self.send_header("Location", owner.url + "/redirected")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if owner.quota_reject:
                        return self.error("daily_demo_limit_reached", 429)
                    ticket = {
                        "token": uuid.uuid4().hex * 2,
                        "capability_token": uuid.uuid4().hex * 2,
                        "job_id": str(uuid.uuid4()),
                        "max_bytes": payload["bytes"],
                        "expires_at": int(datetime.now(timezone.utc).timestamp() * 1000)
                        + 300000,
                    }
                    owner.jobs[ticket["job_id"]] = {
                        "ticket": ticket,
                        "metadata": payload,
                        "consumed": False,
                        "password_phase": 0,
                    }
                    if owner.drop_ticket_response:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    return self.answer(201, ticket)
                if self.path == "/api/v1/files":
                    token = self.headers.get("Authorization", "").removeprefix(
                        "Bearer "
                    )
                    job = next(
                        (
                            job
                            for job in owner.jobs.values()
                            if job["ticket"]["token"] == token
                        ),
                        None,
                    )
                    if job is None:
                        return self.error("upload_credential_invalid", 401)
                    if job["consumed"]:
                        return self.error(owner.replay_error_code, 409)
                    case = next(
                        case
                        for case in state["cases"].values()
                        if case.get("ticket", {}).get("job_id")
                        == job["ticket"]["job_id"]
                    )
                    assert (
                        case["ticket"]["capability_token"]
                        == job["ticket"]["capability_token"]
                    )
                    assert case["operations"]["upload"]["phase"] == "uncertain"
                    assert case["fixture"]["bytes"] == length
                    assert client.digest(body) == case["fixture"]["sha256"]
                    job["consumed"] = True
                    owner.executions += 1
                    if owner.drop_upload_response:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    return self.answer(
                        201,
                        {
                            "job_id": job["ticket"]["job_id"],
                            "sha256": job["metadata"]["sha256"],
                            "status": "queued",
                            "dispatch_uncertain": False,
                        },
                    )
                if self.path.endswith("/password"):
                    job = next(iter(owner.jobs.values()))
                    assert (
                        self.headers.get("Authorization")
                        == "Bearer " + job["ticket"]["capability_token"]
                    )
                    step = ("wrong", "outer", "inner")[job["password_phase"]]
                    assert json.loads(body) == {"password": client.PASSWORDS[step]}
                    case = state["cases"]["passwords"]
                    assert (
                        case["operations"]["password_" + step]["phase"] == "uncertain"
                    )
                    expected_artifact = password_report(case, job["password_phase"])[
                        "password_required_artifacts"
                    ][0]
                    assert (
                        self.path == "/api/v1/jobs/" + expected_artifact + "/password"
                    )
                    job["password_phase"] += 1
                    owner.executions += 1
                    return self.answer(
                        200,
                        {
                            "job_id": expected_artifact,
                            "status": "queued",
                            "password_attempts": job["password_phase"],
                        },
                    )
                return self.error("not_found", 404)

            def do_GET(self):
                owner.requests.append(("GET", self.path, dict(self.headers), b""))
                identifier = self.path.rsplit("/", 1)[-1]
                job = owner.jobs.get(identifier)
                if (
                    not job
                    or self.headers.get("Authorization")
                    != "Bearer " + job["ticket"]["capability_token"]
                    or job.get("expired")
                ):
                    return self.error("job_not_found", 404)
                if "/reports/" in self.path:
                    state = json.loads((owner.state_dir / "campaign.json").read_text())
                    case = next(
                        item
                        for item in state["cases"].values()
                        if item.get("ticket", {}).get("job_id") == identifier
                    )
                    return self.answer(
                        200,
                        password_report(case, job["password_phase"])
                        if owner.passwords
                        else valid_report(case),
                    )
                if owner.passwords:
                    state = json.loads((owner.state_dir / "campaign.json").read_text())
                    case = state["cases"]["passwords"]
                    report = password_report(case, job["password_phase"])
                    return self.answer(
                        200,
                        {
                            "job_id": identifier,
                            "status": report["job_status"],
                            "dispatch_uncertain": False,
                            "report_available": True,
                            "password_attempts": job["password_phase"],
                            "password_required_artifacts": report[
                                "password_required_artifacts"
                            ],
                        },
                    )
                return self.answer(
                    200,
                    {
                        "job_id": identifier,
                        "status": "done",
                        "dispatch_uncertain": False,
                        "report_available": True,
                        "password_attempts": 0,
                        "retention_expires_at": (
                            datetime.now(timezone.utc) + timedelta(days=1)
                        ).isoformat(),
                    },
                )

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.http.server_port}"
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()


def fixture_coverage(archive=False):
    return [
        *[
            {"stage": name, "status": "ok"}
            for name in ("file-type", "clamav", "yara", "ioc-extract", "deobfuscation")
        ],
        {
            "stage": "format-analysis",
            "status": "skipped",
            "reason": "No analyzer matched",
        },
        {"stage": "archive-extract", "status": "ok"}
        if archive
        else {
            "stage": "archive-extract",
            "status": "skipped",
            "reason": "Not an archive",
        },
        {
            "stage": "document-analysis",
            "status": "skipped",
            "reason": "Not a supported document format",
        },
    ]


def valid_report(item):
    root = item["ticket"]["job_id"]
    artifact = {
        "artifact_id": root,
        "parent_id": None,
        "depth": 0,
        "sha256": item["fixture"]["sha256"],
        "size": item["fixture"]["bytes"],
        "status": "done",
        "report": {
            "analysis": {
                "static": {
                    "status": "complete",
                    "stage_coverage": fixture_coverage(),
                },
                "dynamic": {"status": "disabled"},
            },
            "results": {"sandbox": {"status": "disabled", "executed": False}},
        },
    }
    return {
        "job_id": root,
        "job_status": "done",
        "report_schema_version": "mswr-report-v3",
        "analysis_attempt_id": str(uuid.uuid5(uuid.UUID(root), "analysis-attempt")),
        "attempt_id": str(uuid.uuid5(uuid.UUID(root), "analysis-attempt")),
        "report_complete": True,
        "analysis": {
            "static": {"status": "complete"},
            "dynamic": {"status": "disabled"},
        },
        "file": {"size": artifact["size"], "sha256": artifact["sha256"]},
        "artifacts": [artifact],
        "artifact_tree": {"job_id": root, "children": []},
        "execution_budget": {
            "used_files": 0,
            "used_bytes": 0,
            "accounting_scope": "root_artifact_tree",
        },
    }


def password_report(item, phase):
    report = valid_report(item)
    root = item["ticket"]["job_id"]
    nodes = []
    paths = {(): root}
    for expected in item["expected_nodes"]:
        chain = tuple(expected["chain"])
        paths[chain] = (
            root if not chain else str(uuid.uuid5(uuid.UUID(root), "/".join(chain)))
        )
    for expected in item["expected_nodes"]:
        chain = tuple(expected["chain"])
        if len(chain) > (0 if phase < 2 else 1 if phase == 2 else 2):
            continue
        waiting = len(chain) == (0 if phase < 2 else 1) and phase < 3
        status = "password_required" if waiting else "done"
        nodes.append(
            {
                "artifact_id": paths[chain],
                "parent_id": paths[chain[:-1]] if chain else None,
                "depth": len(chain),
                "origin_path": chain[-1] if chain else None,
                "status": status,
                "size": expected["size"],
                "sha256": expected["sha256"],
                "reason": "wrong_password" if waiting and phase == 1 else None,
                "report": {
                    "analysis": {
                        "static": {
                            "status": "password_required" if waiting else "complete",
                            "stage_coverage": fixture_coverage(archive=len(chain) < 2),
                        },
                        "dynamic": {"status": "disabled"},
                    },
                    "results": {"sandbox": {"status": "disabled", "executed": False}},
                    "timings": {
                        "stages": [
                            {
                                "name": name,
                                "status": "ok",
                                "duration_ms": 1,
                                "started_at": "2026-01-01T00:00:00Z",
                                "ended_at": "2026-01-01T00:00:00.001Z",
                            }
                            for name in (
                                "file-type",
                                "clamav",
                                "yara",
                                "ioc-extract",
                                "deobfuscation",
                            )
                        ]
                    },
                },
            }
        )
    tree = {
        node["artifact_id"]: {"job_id": node["artifact_id"], "children": []}
        for node in nodes
    }
    for node in nodes:
        if node["parent_id"]:
            tree[node["parent_id"]]["children"].append(tree[node["artifact_id"]])
    report.update(
        artifacts=nodes,
        artifact_tree=tree[root],
        job_status="done" if phase == 3 else "password_required",
        report_complete=phase == 3,
        password_required_artifacts=[
            node["artifact_id"]
            for node in nodes
            if node["status"] == "password_required"
        ],
    )
    report["analysis"]["static"]["status"] = (
        "complete" if phase == 3 else "password_required"
    )
    children = [node for node in nodes if node["parent_id"]]
    report["execution_budget"].update(
        used_files=len(children), used_bytes=sum(node["size"] for node in children)
    )
    return report


def seed_campaign(path):
    client.private_directory(path)
    client.private_directory(path / "fixtures")
    client.private_directory(path / "reports")
    cases = {}
    for name in client.CASES:
        data = (name + " benign text\n").encode()
        client.write_private(path / "fixtures" / (name + ".txt"), data)
        cases[name] = {
            "fixture": {
                "filename": name + ".txt",
                "bytes": len(data),
                "sha256": client.digest(data),
            },
            "expected_nodes": [
                {"chain": [], "sha256": client.digest(data), "size": len(data)}
            ],
            "operations": {},
            "snapshots": [],
            "round": "initial",
        }
    state = {
        "version": 1,
        "base_url": client.BASE_URL,
        "origin": client.ORIGIN,
        "cases": cases,
        "guards": {"operations": {}},
        "job_intents": 0,
        "execution_intents": 0,
    }
    client.write_private(path / "campaign.json", client.encode(state))


class AcceptanceContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "campaign"
        seed_campaign(self.path)

    def tearDown(self):
        self.temporary.cleanup()

    @contextlib.contextmanager
    def campaign(self, server):
        with client.Campaign(
            self.path, client.Transport(server.url)
        ).locked() as campaign:
            yield campaign

    def test_success_durable_ownership_reconnect_and_negative_guards(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                summary = campaign.start("nested")
                self.assertNotIn("token", json.dumps(summary))
                self.assertEqual(campaign.guards("nested")["replay_http"], 409)
            # A new object reloads ownership from disk, without a new ticket.
            with self.campaign(server) as campaign:
                self.assertEqual(campaign.inspect("nested")["status"], "done")
                self.assertTrue(campaign.verify("nested")["success"])
                with self.assertRaises(client.AcceptanceError):
                    campaign.start("nested")
            self.assertEqual(server.executions, 1)
            self.assertEqual(len(server.jobs), 1)
            for _, _, headers, _ in server.requests:
                normalized = {key.lower(): value for key, value in headers.items()}
                self.assertEqual(normalized["user-agent"], client.USER_AGENT)
                self.assertEqual(normalized["origin"], client.ORIGIN)
            self.assertEqual(
                (self.path / "campaign.json").stat().st_mode & 0o777, 0o600
            )
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
            self.assertTrue(
                all(
                    path.stat().st_mode & 0o777 == 0o600
                    for path in (self.path / "reports").iterdir()
                )
            )

    def test_lost_upload_response_never_resubmits_and_status_recovers(self):
        with ContractServer(self.path) as server:
            server.drop_upload_response = True
            with self.campaign(server) as campaign:
                with self.assertRaises(
                    (client.AcceptanceError, ConnectionError, OSError)
                ):
                    campaign.start("nested")
            with self.campaign(server) as campaign:
                self.assertEqual(
                    campaign.state["cases"]["nested"]["operations"]["upload"]["phase"],
                    "uncertain",
                )
                self.assertEqual(campaign.inspect("nested")["status"], "done")
                with self.assertRaises(client.AcceptanceError):
                    campaign.start("nested")
            self.assertEqual(server.executions, 1)
            self.assertEqual(
                sum(path == "/api/v1/files" for _, path, _, _ in server.requests), 1
            )

    def test_lost_ticket_response_never_allocates_replacement_job(self):
        with ContractServer(self.path) as server:
            server.drop_ticket_response = True
            for _ in range(2):
                with self.campaign(server) as campaign:
                    with self.assertRaises(client.AcceptanceError):
                        campaign.start("nested")
            self.assertEqual(len(server.jobs), 1)
            self.assertEqual(len(server.requests), 1)
            saved = json.loads((self.path / "campaign.json").read_text())
            self.assertNotIn("ticket", saved["cases"]["nested"])
            self.assertEqual(
                saved["cases"]["nested"]["operations"]["ticket"]["phase"], "uncertain"
            )

    def test_quota_rejection_preserves_intent_and_never_issues_second_ticket(self):
        with ContractServer(self.path) as server:
            server.quota_reject = True
            for _ in range(2):
                with self.campaign(server) as campaign:
                    with self.assertRaises(client.AcceptanceError):
                        campaign.start("nested")
            self.assertEqual(len(server.requests), 1)
            self.assertEqual(server.executions, 0)

    def test_redirect_is_not_followed(self):
        with ContractServer(self.path) as server:
            server.redirect = True
            with self.campaign(server) as campaign:
                with self.assertRaises(client.AcceptanceError):
                    campaign.start("nested")
            self.assertEqual(len(server.requests), 1)

    def test_cors_failure_saves_ticket_but_never_uploads_on_reconnect(self):
        with ContractServer(self.path) as server:
            server.cors = "https://wrong.invalid"
            for _ in range(2):
                with self.campaign(server) as campaign:
                    with self.assertRaises(client.AcceptanceError):
                        campaign.start("nested")
            self.assertEqual(len(server.requests), 1)
            saved = json.loads((self.path / "campaign.json").read_text())
            self.assertIn("capability_token", saved["cases"]["nested"]["ticket"])

    def test_changed_fixture_stops_before_network(self):
        (self.path / "fixtures" / "nested.txt").write_bytes(b"changed")
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                with self.assertRaises(client.AcceptanceError):
                    campaign.start("nested")
            self.assertEqual(server.requests, [])

    def test_campaign_limits_and_concurrent_lock(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                campaign.state["job_intents"] = 3
                with self.assertRaises(client.AcceptanceError):
                    campaign.start("nested")
                campaign.state["execution_intents"] = 8
                with self.assertRaises(client.AcceptanceError):
                    campaign.intent(
                        campaign.state["guards"], "forbidden", execution=True
                    )
                with self.assertRaises(client.AcceptanceError):
                    with self.campaign(server):
                        pass
            self.assertEqual(server.requests, [])

    def test_expired_ticket_never_claimed_as_replay_success(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                campaign.start("nested")
                campaign.state["cases"]["nested"]["ticket"]["expires_at"] = 1
                campaign.save()
                with self.assertRaisesRegex(client.AcceptanceError, "Ticket expired"):
                    campaign.guards("nested")
            self.assertEqual(server.executions, 1)
            self.assertEqual(
                sum(path == "/api/v1/files" for _, path, _, _ in server.requests), 1
            )

    def test_expiry_is_access_evidence_only_not_r2_cleanup(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                campaign.start("nested")
                campaign.inspect("nested")
                campaign.state["cases"]["nested"]["last_status"][
                    "retention_expires_at"
                ] = "2020-01-01T00:00:00Z"
                server.jobs[next(iter(server.jobs))]["expired"] = True
                proof = campaign.expiry("nested")
                self.assertTrue(proof["public_access_withdrawn"])
                self.assertFalse(proof["r2_deleted_verified"])

    def test_semantically_wrong_guard_errors_stay_failed_across_reconnect(self):
        for failing_guard in ("oversize", "replay"):
            with self.subTest(guard=failing_guard):
                self.temporary.cleanup()
                self.setUp()
                with ContractServer(self.path) as server:
                    setattr(server, failing_guard + "_error_code", "unexpected_error")
                    with self.campaign(server) as campaign:
                        campaign.start("nested")
                    for _ in range(2):
                        with self.campaign(server) as campaign:
                            with self.assertRaises(client.AcceptanceError):
                                campaign.guards("nested")
                    posts = [
                        (path, body)
                        for method, path, _, body in server.requests
                        if method == "POST"
                    ]
                    oversize = sum(
                        path == "/api/v1/upload-tickets"
                        and json.loads(body)["bytes"] > client.MAX_BYTES
                        for path, body in posts
                    )
                    self.assertEqual(oversize, 1)
                    self.assertEqual(
                        sum(path == "/api/v1/files" for path, _ in posts),
                        2 if failing_guard == "replay" else 1,
                    )
                    self.assertEqual(server.executions, 1)

    def test_verify_rejects_partial_hash_budget_and_tree_regressions(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                campaign.start("nested")
                item = campaign.state["cases"]["nested"]
                good = valid_report(item)
                self.assertEqual(client.verify_report(good, item), [])
                for change, failure in [
                    (
                        lambda report: report.update(
                            analysis_attempt_id="not-an-attempt"
                        ),
                        "analysis_attempt_identity_invalid",
                    ),
                    (
                        lambda report: report["artifacts"][0]["report"]["analysis"][
                            "static"
                        ].update(
                            stage_coverage=[
                                {"stage": "irrelevant", "status": "skipped"}
                            ]
                        ),
                        "required_stage_coverage_missing_or_duplicated",
                    ),
                    (
                        lambda report: report["analysis"]["static"].update(
                            status="partial"
                        ),
                        "static_analysis_status_mismatch",
                    ),
                    (
                        lambda report: report["file"].update(sha256="0" * 64),
                        "source_identity_mismatch",
                    ),
                    (
                        lambda report: report["execution_budget"].update(used_files=1),
                        "cumulative_budget_mismatch",
                    ),
                    (
                        lambda report: report["artifact_tree"].update(
                            children=[{"job_id": str(uuid.uuid4())}]
                        ),
                        "artifact_tree_mismatch",
                    ),
                ]:
                    broken = copy.deepcopy(good)
                    change(broken)
                    self.assertIn(failure, client.verify_report(broken, item))

    def test_large_fixture_accepts_only_declared_bounded_partial_coverage(self):
        item = copy.deepcopy(
            json.loads((self.path / "campaign.json").read_text())["cases"]["20mb"]
        )
        item["ticket"] = {"job_id": str(uuid.uuid4())}
        item["fixture"]["bytes"] = client.MAX_BYTES
        item["expected_nodes"][0]["size"] = client.MAX_BYTES
        report = valid_report(item)
        report["analysis"]["static"]["status"] = "partial"
        static = report["artifacts"][0]["report"]["analysis"]["static"]
        static["status"] = "partial"
        next(
            stage
            for stage in static["stage_coverage"]
            if stage["stage"] == "deobfuscation"
        ).update(
            status="skipped", reason="File too large for deobfuscation (20000000 bytes)"
        )
        self.assertEqual(client.verify_report(report, item), [])
        static["stage_coverage"] = [
            stage for stage in static["stage_coverage"] if stage["stage"] != "clamav"
        ]
        self.assertIn("required_scan_stage_not_ok", client.verify_report(report, item))

    def test_valid_but_changed_attempt_between_snapshots_is_rejected(self):
        with ContractServer(self.path) as server:
            with self.campaign(server) as campaign:
                campaign.start("nested")
                campaign.inspect("nested")
                item = campaign.state["cases"]["nested"]
                report = campaign.load_report(item["snapshots"][0])
                changed = str(uuid.uuid4())
                report.update(analysis_attempt_id=changed, attempt_id=changed)
                data = client.encode(report)
                client.write_private(
                    self.path / "reports" / "changed-attempt.json", data
                )
                item["snapshots"].append(
                    {
                        "file": "changed-attempt.json",
                        "sha256": client.digest(data),
                        "round": "initial",
                        "status": "done",
                    }
                )
                self.assertIn(
                    "analysis_attempt_changed_between_snapshots",
                    campaign.verify("nested")["failures"],
                )

    def test_mutating_cli_without_run_is_offline(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                client.main(
                    ["start", "--state-dir", str(self.path), "--case", "nested"]
                ),
                0,
            )
        self.assertTrue(json.loads(output.getvalue())["dry_run"])

    def test_password_rounds_keep_completed_timestamps_and_detect_rerun(self):
        with ContractServer(self.path) as server:
            server.passwords = True
            with self.campaign(server) as campaign:
                item = campaign.state["cases"]["passwords"]
                item["expected_nodes"].extend(
                    [
                        {"chain": ["inner.7z"], "sha256": "1" * 64, "size": 200},
                        {
                            "chain": ["inner.7z", "payload.txt"],
                            "sha256": "2" * 64,
                            "size": 30,
                        },
                    ]
                )
                campaign.save()
                campaign.start("passwords")
                self.assertEqual(
                    campaign.inspect("passwords")["status"], "password_required"
                )
            # Deliberately reconnect between each step. No password is printed
            # and each POST has a different persisted intent and pending target.
            for step in ("wrong", "outer", "inner"):
                with self.campaign(server) as campaign:
                    campaign.password(step)
                    campaign.inspect("passwords")
            with self.campaign(server) as campaign:
                self.assertTrue(campaign.verify("passwords")["success"])
                item = campaign.state["cases"]["passwords"]
                snapshot = item["snapshots"][-1]
                report = campaign.load_report(snapshot)
                report["artifacts"][0]["report"]["timings"]["stages"][0][
                    "started_at"
                ] = "2026-01-02T00:00:00Z"
                data = client.encode(report)
                client.write_private(self.path / "reports" / snapshot["file"], data)
                snapshot["sha256"] = client.digest(data)
                campaign.save()
                self.assertIn(
                    "completed_stage_reran", campaign.verify("passwords")["failures"]
                )
                before = len(server.requests)
                with self.assertRaises(client.AcceptanceError):
                    campaign.password("inner")
                self.assertEqual(
                    sum(
                        method == "POST" for method, _, _, _ in server.requests[before:]
                    ),
                    0,
                )
            self.assertEqual(server.executions, 4)

    def test_credentials_cannot_be_sent_to_arbitrary_origin(self):
        with self.assertRaises(client.AcceptanceError):
            client.Transport("https://example.invalid")


if __name__ == "__main__":
    unittest.main()
