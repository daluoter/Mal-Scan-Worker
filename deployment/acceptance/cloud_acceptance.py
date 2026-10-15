#!/usr/bin/env python3
"""Small, resumable acceptance campaign for the public static cloud demo.

Preparation and verification are offline. Mutating commands require --run;
every mutation writes a durable intent before opening a connection. Repeating
an interrupted command never repeats its POST. See README.md before use.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import io
import json
import os
import re
import secrets
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

BASE_URL = "https://malscan-v2-demo-control.daluoter.workers.dev"
ORIGIN = "https://malscan-v2-demo.pages.dev"
USER_AGENT = "MalScanWorker-acceptance/1.0"
MAX_BYTES = 20_000_000
CASES = ("nested", "passwords", "20mb")
PASSWORDS = {
    "wrong": "malscan-public-fixture-wrong",
    "outer": "malscan-public-fixture-outer",
    "inner": "malscan-public-fixture-inner",
}
UUID = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[45][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)
TOKEN = re.compile(r"^[a-f0-9]{64}$")
PATH = re.compile(
    r"^/api/v1/(?:upload-tickets|files|(?:jobs|reports)/[a-f0-9-]{36}(?:/password)?)$"
)


class AcceptanceError(Exception):
    """Predictable, non-sensitive operator error."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(path: Path) -> tuple[int, str]:
    result = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
            size += len(chunk)
    return size, result.hexdigest()


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise AcceptanceError("State directories must not be symbolic links.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise AcceptanceError("State directory must belong to the current user.")
    path.chmod(0o700)


def write_private(path: Path, data: bytes) -> None:
    """Persist first, then atomically publish; never follow an existing symlink."""
    if path.is_symlink():
        raise AcceptanceError("State files must not be symbolic links.")
    fd, temporary = tempfile.mkstemp(prefix=".acceptance-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def encode(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2).encode() + b"\n"
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self, base_url: str = BASE_URL):
        # CLI never accepts a URL. Loopback HTTP is only for the local contract
        # tests; an authenticated request cannot be redirected elsewhere.
        if base_url != BASE_URL and not re.fullmatch(
            r"http://127\.0\.0\.1:[0-9]+", base_url
        ):
            raise AcceptanceError(
                "Only the production demo or a loopback test server is allowed."
            )
        self.base_url = base_url
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            NoRedirect(),
        )
        self.opener.addheaders = [("User-Agent", USER_AGENT)]

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload: Any = None,
        source: BinaryIO | None = None,
        size: int = 0,
    ) -> dict:
        if not PATH.fullmatch(path) or method not in {"GET", "POST"}:
            raise AcceptanceError("Unexpected acceptance API request.")
        headers = {"Origin": ORIGIN, "Cache-Control": "no-store"}
        if token is not None:
            if not TOKEN.fullmatch(token):
                raise AcceptanceError("Invalid saved credential format.")
            headers["Authorization"] = "Bearer " + token
        if source is not None:
            body = source
            headers.update(
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                }
            )
        elif payload is not None:
            body = encode(payload)
            headers.update(
                {"Content-Type": "application/json", "Content-Length": str(len(body))}
            )
        else:
            body = None
        request = urllib.request.Request(
            self.base_url + path, method=method, data=body, headers=headers
        )
        try:
            try:
                response = self.opener.open(request, timeout=90)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise AcceptanceError("Response exceeds the bounded report size.")
                status = response.status
                try:
                    value = json.loads(raw)
                except (UnicodeError, ValueError):
                    value = None
                # Do not persist arbitrary response text or raw transport errors.
                return {
                    "status": status,
                    "body": value,
                    "json": isinstance(value, dict),
                    "allow_origin": response.headers.get("Access-Control-Allow-Origin"),
                }
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.HTTPException,
        ):
            raise AcceptanceError(
                "Connection failed; any saved POST intent remains uncertain. Inspect before continuing."
            ) from None


class Campaign:
    def __init__(self, directory: Path, transport: Transport | None = None):
        self.directory = directory
        self.transport = transport or Transport()
        self.state_path = directory / "campaign.json"
        self.state: dict[str, Any] = {}

    @contextlib.contextmanager
    def locked(self):
        private_directory(self.directory)
        lock_path = self.directory / ".lock"
        if lock_path.is_symlink():
            raise AcceptanceError("Lock must not be a symbolic link.")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AcceptanceError(
                    "Another acceptance command is using this campaign."
                ) from None
            if self.state_path.exists():
                if self.state_path.is_symlink():
                    raise AcceptanceError("State must not be a symbolic link.")
                self.state = json.loads(self.state_path.read_text())
                if (
                    self.state.get("version") != 1
                    or self.state.get("base_url") != BASE_URL
                    or self.state.get("origin") != ORIGIN
                ):
                    raise AcceptanceError(
                        "Saved campaign identity does not match this client."
                    )
            yield self
        finally:
            os.close(fd)

    def save(self):
        write_private(self.state_path, encode(self.state))

    def prepared(self):
        if not self.state or set(self.state.get("cases", {})) != set(CASES):
            raise AcceptanceError("Run offline prepare first.")

    def fixture(self, case: str) -> tuple[dict, Path]:
        self.prepared()
        item = self.state["cases"][case]
        path = self.directory / "fixtures" / item["fixture"]["filename"]
        if path.is_symlink() or identity(path) != (
            item["fixture"]["bytes"],
            item["fixture"]["sha256"],
        ):
            raise AcceptanceError(
                "Fixture changed; saved campaign will not be submitted."
            )
        return item, path

    def intent(
        self,
        item: dict,
        name: str,
        *,
        execution: bool = False,
        job: bool = False,
        **details,
    ):
        operations = item.setdefault("operations", {})
        if name in operations:
            raise AcceptanceError(
                "This POST already has a durable intent. Inspect existing state; do not resubmit."
            )
        if execution and self.state["execution_intents"] >= 8:
            raise AcceptanceError(
                "Campaign limit of eight potential execution intents reached."
            )
        if job and self.state["job_intents"] >= 3:
            raise AcceptanceError("Campaign limit of three new job intents reached.")
        self.state["execution_intents"] += int(execution)
        self.state["job_intents"] += int(job)
        operations[name] = {"phase": "uncertain", "intent_at": now(), **details}
        self.save()
        return operations[name]

    def finish(self, operation: dict, response: dict, expected: int):
        # Successful credentials are saved separately after strict validation.
        body = response.get("body")
        code = (
            body.get("error", {}).get("code")
            if isinstance(body, dict) and isinstance(body.get("error"), dict)
            else None
        )
        operation.update(http_status=response["status"], error_code=code)
        if (
            response["status"] == expected
            and response["json"]
            and response["allow_origin"] == ORIGIN
        ):
            operation["phase"] = "received"
            operation["received_at"] = now()
            self.save()
            return body
        self.save()
        raise AcceptanceError(
            "Unexpected API response; the POST will not be retried. Inspect campaign state."
        )

    def prepare(self):
        if self.state:
            raise AcceptanceError(
                "Campaign already exists; preparation never overwrites it."
            )
        fixtures = self.directory / "fixtures"
        private_directory(fixtures)
        private_directory(self.directory / "reports")
        # The fixed public fixture passwords are synthetic test inputs, not keys.
        try:
            import py7zr
            import pyzipper
        except ImportError:
            raise AcceptanceError(
                "Offline fixture preparation needs py7zr and pyzipper; use the existing worker virtualenv."
            ) from None
        leaf = b"Hello MalScan nested acceptance\n"
        inner_stream = io.BytesIO()
        with zipfile.ZipFile(
            inner_stream, "w", compression=zipfile.ZIP_STORED
        ) as archive:
            archive.writestr(
                zipfile.ZipInfo("payload.txt", (2026, 1, 1, 0, 0, 0)), leaf
            )
        inner_zip = inner_stream.getvalue()
        outer_stream = io.BytesIO()
        with zipfile.ZipFile(
            outer_stream, "w", compression=zipfile.ZIP_STORED
        ) as archive:
            for name in ("one/inner.zip", "two/inner.zip"):
                archive.writestr(
                    zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), inner_zip
                )
        inner_7z = io.BytesIO()
        with py7zr.SevenZipFile(
            inner_7z, "w", password=PASSWORDS["inner"], header_encryption=True
        ) as archive:
            archive.writestr(leaf, "payload.txt")
        encrypted_inner = inner_7z.getvalue()
        encrypted_outer = io.BytesIO()
        with pyzipper.AESZipFile(
            encrypted_outer,
            "w",
            encryption=pyzipper.WZ_AES,
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.setpassword(PASSWORDS["outer"].encode())
            archive.writestr("inner.7z", encrypted_inner)
        contents = {
            "nested": ("nested.zip", outer_stream.getvalue()),
            "passwords": ("passwords.zip", encrypted_outer.getvalue()),
            "20mb": (
                "twenty-million.txt",
                (b"MalScan acceptance benign fixture.\n" * 600000)[:MAX_BYTES],
            ),
        }
        if len(contents["20mb"][1]) != MAX_BYTES:
            raise AcceptanceError(
                "Fixture generation did not produce exactly 20,000,000 bytes."
            )
        cases = {}
        for name, (filename, data) in contents.items():
            write_private(fixtures / filename, data)
            nodes = [{"chain": [], "sha256": digest(data), "size": len(data)}]
            if name == "nested":
                for origin in ("one/inner.zip", "two/inner.zip"):
                    nodes.extend(
                        [
                            {
                                "chain": [origin],
                                "sha256": digest(inner_zip),
                                "size": len(inner_zip),
                            },
                            {
                                "chain": [origin, "payload.txt"],
                                "sha256": digest(leaf),
                                "size": len(leaf),
                            },
                        ]
                    )
            if name == "passwords":
                nodes.extend(
                    [
                        {
                            "chain": ["inner.7z"],
                            "sha256": digest(encrypted_inner),
                            "size": len(encrypted_inner),
                        },
                        {
                            "chain": ["inner.7z", "payload.txt"],
                            "sha256": digest(leaf),
                            "size": len(leaf),
                        },
                    ]
                )
            cases[name] = {
                "fixture": {
                    "filename": filename,
                    "bytes": len(data),
                    "sha256": digest(data),
                },
                "expected_nodes": nodes,
                "operations": {},
                "snapshots": [],
                "round": "initial",
            }
        self.state = {
            "version": 1,
            "base_url": BASE_URL,
            "origin": ORIGIN,
            "campaign_id": str(uuid.uuid4()),
            "created_at": now(),
            "job_intents": 0,
            "execution_intents": 0,
            "cases": cases,
            "guards": {"operations": {}},
        }
        self.save()
        return {
            "prepared": True,
            "network_requests": 0,
            "cases": list(CASES),
            "planned_positive_jobs": 3,
            "planned_positive_executions": 6,
        }

    def start(self, case: str):
        item, path = self.fixture(case)
        if "upload" in item["operations"]:
            raise AcceptanceError(
                "Upload has already been attempted. Use inspect; do not resubmit."
            )
        if "ticket" not in item:
            operation = self.intent(item, "ticket", job=True, metadata=item["fixture"])
            metadata = {
                "filename": path.name,
                "bytes": item["fixture"]["bytes"],
                "sha256": item["fixture"]["sha256"],
            }
            response = self.transport.request(
                "POST", "/api/v1/upload-tickets", payload=metadata
            )
            # Save the complete successful ticket before any file upload, even if
            # CORS or response validation then fails. It is private local state.
            body = response.get("body")
            if response["status"] == 201 and isinstance(body, dict):
                item["ticket"] = body
                self.save()
            body = self.finish(operation, response, 201)
            if not valid_ticket(body, item["fixture"]["bytes"]):
                raise AcceptanceError(
                    "Invalid ticket response saved privately; do not upload."
                )
        if item["operations"].get("ticket", {}).get("phase") != "received":
            raise AcceptanceError(
                "Ticket response was uncertain; inspect existing state before any upload."
            )
        ticket = item["ticket"]
        if not valid_ticket(ticket, item["fixture"]["bytes"]):
            raise AcceptanceError(
                "Saved ticket is invalid or expired; do not request another ticket."
            )
        operation = self.intent(
            item,
            "upload",
            execution=True,
            fixture_sha256=item["fixture"]["sha256"],
            job_id=ticket["job_id"],
        )
        with path.open("rb") as source:
            response = self.transport.request(
                "POST",
                "/api/v1/files",
                token=ticket["token"],
                source=source,
                size=item["fixture"]["bytes"],
            )
        body = self.finish(operation, response, 201)
        if (
            body.get("job_id") != ticket["job_id"]
            or body.get("sha256") != item["fixture"]["sha256"]
        ):
            raise AcceptanceError("Upload identity mismatch; inspect the saved job.")
        item["upload_received"] = {
            key: body.get(key)
            for key in (
                "job_id",
                "sha256",
                "status",
                "dispatch_uncertain",
                "created_at",
            )
        }
        self.save()
        return self.summary(case)

    def owned(self, case: str) -> tuple[dict, dict]:
        self.prepared()
        item = self.state["cases"][case]
        ticket = item.get("ticket", {})
        if not UUID.fullmatch(str(ticket.get("job_id", ""))) or not TOKEN.fullmatch(
            str(ticket.get("capability_token", ""))
        ):
            raise AcceptanceError(
                "No recoverable job capability is saved; do not reissue its ticket."
            )
        return item, ticket

    def inspect(self, case: str):
        item, ticket = self.owned(case)
        response = self.transport.request(
            "GET", "/api/v1/jobs/" + ticket["job_id"], token=ticket["capability_token"]
        )
        item["last_status_http"] = response["status"]
        if (
            response["status"] != 200
            or not response["json"]
            or response["allow_origin"] != ORIGIN
        ):
            self.save()
            raise AcceptanceError(
                "Job status is unavailable; inspect cannot create or retry any execution."
            )
        body = response["body"]
        if body.get("job_id") != ticket["job_id"]:
            raise AcceptanceError("Job status identity does not match saved ownership.")
        item["last_status"] = body
        item["status_checked_at"] = now()
        self.save()
        if body.get("report_available"):
            report_response = self.transport.request(
                "GET",
                "/api/v1/reports/" + ticket["job_id"],
                token=ticket["capability_token"],
            )
            report = report_response["body"]
            if (
                report_response["status"] != 200
                or not report_response["json"]
                or report_response["allow_origin"] != ORIGIN
                or report.get("job_id") != ticket["job_id"]
            ):
                raise AcceptanceError(
                    "Report could not be validated; status and capability are preserved."
                )
            content = encode(report)
            if (
                not item["snapshots"]
                or item["snapshots"][-1]["sha256"] != digest(content)
                or item["snapshots"][-1]["round"] != item["round"]
            ):
                filename = f"{case}-{len(item['snapshots']) + 1:03d}.json"
                write_private(self.directory / "reports" / filename, content)
                item["snapshots"].append(
                    {
                        "file": filename,
                        "sha256": digest(content),
                        "round": item["round"],
                        "status": body["status"],
                        "saved_at": now(),
                    }
                )
                self.save()
        return self.summary(case)

    def password(self, value: str):
        self.inspect("passwords")  # Fresh, read-only status; capture previous round.
        item, ticket = self.owned("passwords")
        status = item["last_status"]
        if status.get("status") != "password_required" or status.get(
            "dispatch_uncertain"
        ):
            raise AcceptanceError(
                "The existing job is not safely waiting for a password."
            )
        required = status.get("password_required_artifacts", [])
        if len(required) != 1 or not UUID.fullmatch(str(required[0])):
            raise AcceptanceError("Expected exactly one pending fixture artifact.")
        sequence = {"wrong": "initial", "outer": "wrong", "inner": "outer"}
        if item["round"] != sequence[value]:
            raise AcceptanceError(
                "Password campaign order is wrong: wrong, outer, then inner."
            )
        if not status.get("report_available") or not item["snapshots"]:
            raise AcceptanceError(
                "A verified partial report is required before a password mutation."
            )
        if (
            status.get("password_attempts")
            != {"wrong": 0, "outer": 1, "inner": 2}[value]
        ):
            raise AcceptanceError(
                "Password attempt count has not reconciled; preserve state and inspect again."
            )
        latest = self.load_report(item["snapshots"][-1])
        pending = next(
            (
                node
                for node in latest.get("artifacts", [])
                if node["artifact_id"] == required[0]
            ),
            {},
        )
        if pending.get("depth") != (1 if value == "inner" else 0):
            raise AcceptanceError(
                "Pending artifact depth does not match this password step."
            )
        operation = self.intent(
            item, "password_" + value, execution=True, artifact_id=required[0]
        )
        # Persist the phase before POST so reconnect inspect can label its result.
        item["round"] = value
        self.save()
        response = self.transport.request(
            "POST",
            "/api/v1/jobs/" + required[0] + "/password",
            token=ticket["capability_token"],
            payload={"password": PASSWORDS[value]},
        )
        result = self.finish(operation, response, 200)
        if result.get("job_id") != required[0]:
            raise AcceptanceError("Password response identity mismatch; do not retry.")
        receipt = self.summary("passwords")
        receipt.update(
            mutation_accepted=True,
            status_source="password_post_receipt",
            status=result.get("status"),
            password_attempts=result.get("password_attempts"),
            dispatch_uncertain=None,
            note="Acceptance is not scan completion; use inspect before the next step.",
        )
        return receipt

    def guards(self, case: str):
        item, ticket = self.owned(case)
        if "upload" not in item["operations"]:
            raise AcceptanceError("Replay check requires a prior upload attempt.")
        guards = self.state["guards"]
        if "oversize" not in guards["operations"]:
            operation = self.intent(
                guards, "oversize", metadata={"bytes": MAX_BYTES + 1}
            )
            response = self.transport.request(
                "POST",
                "/api/v1/upload-tickets",
                payload={
                    "filename": "oversize.txt",
                    "bytes": MAX_BYTES + 1,
                    "sha256": "0" * 64,
                },
            )
            body = self.finish(operation, response, 400)
            if body.get("error", {}).get("code") != "invalid_upload_metadata":
                raise AcceptanceError(
                    "Oversize response did not prove metadata rejection."
                )
        elif (
            guards["operations"]["oversize"]["phase"] != "received"
            or guards["operations"]["oversize"].get("error_code")
            != "invalid_upload_metadata"
        ):
            raise AcceptanceError(
                "Oversize POST was uncertain or semantically invalid; it will not be repeated."
            )
        wrong = secrets.token_hex(32)
        while wrong == ticket["capability_token"]:
            wrong = secrets.token_hex(32)
        response = self.transport.request(
            "GET", "/api/v1/jobs/" + ticket["job_id"], token=wrong
        )
        if response["status"] != 404 or response["body"] != {
            "error": {"code": "job_not_found", "message": "job_not_found"}
        }:
            raise AcceptanceError(
                "Wrong capability did not produce the expected ownership failure."
            )
        guards["wrong_capability"] = {
            "http_status": 404,
            "checked_at": now(),
            "job_id": ticket["job_id"],
        }
        self.save()
        if "replay" not in item["operations"]:
            if ticket["expires_at"] <= int(
                datetime.now(timezone.utc).timestamp() * 1000
            ):
                raise AcceptanceError(
                    "Ticket expired; replay proof must be obtained within its original five-minute lifetime. No replacement job will be created."
                )
            # One byte is enough: consumed credentials are checked before size.
            # No accepted upload body or second fixture is sent by this guard.
            operation = self.intent(item, "replay", execution=True, bytes_sent=1)
            response = self.transport.request(
                "POST",
                "/api/v1/files",
                token=ticket["token"],
                source=io.BytesIO(b"x"),
                size=1,
            )
            body = self.finish(operation, response, 409)
            if body.get("error", {}).get("code") != "upload_credential_used":
                raise AcceptanceError(
                    "Replay response does not prove single-use rejection."
                )
        elif (
            item["operations"]["replay"]["phase"] != "received"
            or item["operations"]["replay"].get("error_code")
            != "upload_credential_used"
        ):
            raise AcceptanceError(
                "Replay POST was uncertain or semantically invalid; it will not be repeated."
            )
        return {
            "oversize_http": 400,
            "wrong_capability_http": 404,
            "replay_http": 409,
            "new_job_created_by_guards": False,
            "extra_cloud_execution_verified": False,
            "note": "Use GCP execution inventory to independently prove no extra execution.",
        }

    def expiry(self, case: str):
        item, ticket = self.owned(case)
        previous = item.get("last_status", {}).get("retention_expires_at")
        if not previous or datetime.fromisoformat(
            previous.replace("Z", "+00:00")
        ) > datetime.now(timezone.utc):
            raise AcceptanceError(
                "Retention has not expired, or a prior status did not establish the deadline."
            )
        checks = {}
        for route in ("jobs", "reports"):
            response = self.transport.request(
                "GET",
                f"/api/v1/{route}/{ticket['job_id']}",
                token=ticket["capability_token"],
            )
            # Current ownership gates return 404 after expiry, deliberately
            # indistinguishable from nonexistent ownership, not an R2 inventory.
            if (
                response["status"] != 404
                or not response["json"]
                or response["body"].get("error", {}).get("code") != "job_not_found"
            ):
                raise AcceptanceError("Expired access was not withdrawn as expected.")
            checks[route] = response["status"]
        item["expiry"] = {
            "checks": checks,
            "checked_at": now(),
            "retention_expires_at": previous,
            "r2_deleted_verified": False,
        }
        self.save()
        return {
            "case": case,
            "public_access_withdrawn": True,
            "r2_deleted_verified": False,
            "note": "R2 prefix inventory and Durable Object cleanup evidence are still required.",
        }

    def load_report(self, snapshot: dict) -> dict:
        path = self.directory / "reports" / snapshot["file"]
        if path.is_symlink() or digest(path.read_bytes()) != snapshot["sha256"]:
            raise AcceptanceError("Saved report snapshot has changed.")
        return json.loads(path.read_text())

    def verify(self, case: str, *, require_full_pipeline: bool = True):
        item, _ = self.fixture(case)
        if not item["snapshots"]:
            raise AcceptanceError("No saved report; run inspect first.")
        reports = [
            (snapshot, self.load_report(snapshot)) for snapshot in item["snapshots"]
        ]
        report = reports[-1][1]
        failures = verify_report(
            report, item, require_full_pipeline=require_full_pipeline
        )
        attempts = {previous.get("analysis_attempt_id") for _, previous in reports}
        if len(attempts) != 1 or any(
            previous.get("analysis_attempt_id") != previous.get("attempt_id")
            for _, previous in reports
        ):
            failures.append("analysis_attempt_changed_between_snapshots")
        if case == "passwords":
            stable = {}
            wrong_proved = False
            phases = set()
            previous_budget = (0, 0)
            for snapshot, previous in reports:
                current_completed = set()
                if snapshot["status"] in {"done", "password_required"}:
                    phases.add(snapshot["round"])
                    if require_full_pipeline:
                        root = next(
                            (
                                node
                                for node in previous.get("artifacts", [])
                                if node.get("artifact_id") == previous.get("job_id")
                            ),
                            {},
                        )
                        timings = {
                            stage.get("name"): stage
                            for stage in (root.get("report") or {})
                            .get("timings", {})
                            .get("stages", [])
                        }
                        if any(
                            timings.get(name, {}).get("status") != "ok"
                            for name in (
                                "file-type",
                                "clamav",
                                "yara",
                                "ioc-extract",
                                "deobfuscation",
                            )
                        ):
                            failures.append("password_checkpoint_stage_timings_missing")
                if (
                    snapshot["round"] == "wrong"
                    and snapshot["status"] == "password_required"
                ):
                    wrong_proved |= any(
                        node.get("reason") == "wrong_password"
                        for node in previous.get("artifacts", [])
                    )
                budget = previous.get("execution_budget", {})
                counts = (budget.get("used_files", 0), budget.get("used_bytes", 0))
                if any(new < old for new, old in zip(counts, previous_budget)):
                    failures.append("cumulative_budget_decreased")
                previous_budget = counts
                for node in previous.get("artifacts", []):
                    for stage in (
                        (node.get("report") or {}).get("timings", {}).get("stages", [])
                    ):
                        if stage.get("name") == "sandbox" or stage.get(
                            "status"
                        ) not in {"ok", "skipped"}:
                            continue
                        key = (node["artifact_id"], stage["name"])
                        current_completed.add(key)
                        value = tuple(
                            stage.get(field)
                            for field in (
                                "started_at",
                                "ended_at",
                                "duration_ms",
                                "status",
                            )
                        )
                        if value[0] is None or value[1] is None:
                            failures.append("missing_completed_stage_timestamps")
                        if key in stable and stable[key] != value:
                            failures.append("completed_stage_reran")
                        stable.setdefault(key, value)
                if snapshot["status"] in {"done", "password_required"} and not set(
                    stable
                ).issubset(current_completed):
                    failures.append("completed_stage_evidence_disappeared")
            if not stable:
                failures.append("completed_stage_timing_evidence_missing")
            if not wrong_proved:
                failures.append("wrong_password_not_proved")
            if phases != {"initial", "wrong", "outer", "inner"}:
                failures.append("password_resume_phases_missing")
            if item.get("last_status", {}).get("password_attempts") != 3:
                failures.append("password_attempt_accounting_mismatch")
        result = {
            "case": case,
            "success": not failures,
            "failures": sorted(set(failures)),
            "artifact_count": len(report.get("artifacts", [])),
            "report_sha256": item["snapshots"][-1]["sha256"],
            "execution_intents": self.state["execution_intents"],
            "job_intents": self.state["job_intents"],
            "r2_cleanup_verified": False,
            "cost_verified": False,
            "verification_scope": "upload_integrity_and_declared_scan_coverage"
            if require_full_pipeline
            else "offline_recursive_archive_adapter",
            "analysis_static_status": report.get("analysis", {})
            .get("static", {})
            .get("status"),
            "full_static_analysis_verified": not failures
            and not is_large_fixture(item)
            and require_full_pipeline,
            "known_limitations": ["deobfuscation_skipped_size_limit"]
            if is_large_fixture(item)
            else [],
        }
        item["verification"] = result
        self.save()
        return result

    def summary(self, case: str) -> dict:
        item = self.state["cases"][case]
        status = item.get("last_status", item.get("upload_received", {}))
        return {
            "case": case,
            "job_id": item.get("ticket", {}).get("job_id"),
            "status": status.get("status", "not_observed"),
            "status_source": "job_status_get"
            if "last_status" in item
            else "upload_post_receipt",
            "round": item["round"],
            "dispatch_uncertain": status.get("dispatch_uncertain"),
            "password_attempts": status.get("password_attempts"),
            "report_snapshots": len(item["snapshots"]),
            "retention_expires_at": status.get("retention_expires_at"),
            "job_intents": self.state["job_intents"],
            "execution_intents": self.state["execution_intents"],
        }


def valid_ticket(ticket: dict, size: int) -> bool:
    return (
        UUID.fullmatch(str(ticket.get("job_id", ""))) is not None
        and all(
            TOKEN.fullmatch(str(ticket.get(key, "")))
            for key in ("token", "capability_token")
        )
        and ticket.get("max_bytes") == size
        and isinstance(ticket.get("expires_at"), int)
        and not isinstance(ticket.get("expires_at"), bool)
        and ticket["expires_at"] > int(datetime.now(timezone.utc).timestamp() * 1000)
    )


def is_large_fixture(item: dict) -> bool:
    return item["fixture"]["bytes"] == MAX_BYTES and len(item["expected_nodes"]) == 1


def verify_report(
    report: dict, item: dict, *, require_full_pipeline: bool = True
) -> list[str]:
    failures = []
    if report.get("job_status") != "done" or report.get("report_complete") is not True:
        failures.append("report_not_complete")
    if report.get("report_schema_version") != "mswr-report-v3":
        failures.append("report_schema_mismatch")
    if report.get("job_id") != item.get("ticket", {}).get("job_id"):
        failures.append("root_identity_mismatch")
    attempt = report.get("analysis_attempt_id")
    if not UUID.fullmatch(str(attempt)) or report.get("attempt_id") != attempt:
        failures.append("analysis_attempt_identity_invalid")
    expected_static = "partial" if is_large_fixture(item) else "complete"
    if report.get("analysis", {}).get("static", {}).get("status") != expected_static:
        failures.append("static_analysis_status_mismatch")
    if report.get("analysis", {}).get("dynamic", {}).get("status") != "disabled":
        failures.append("dynamic_analysis_unexpected")
    file = report.get("file", {})
    if (file.get("size"), file.get("sha256")) != (
        item["fixture"]["bytes"],
        item["fixture"]["sha256"],
    ):
        failures.append("source_identity_mismatch")
    artifacts = report.get("artifacts", [])
    ids = [node.get("artifact_id") for node in artifacts]
    if len(set(ids)) != len(ids):
        failures.append("artifact_identity_collision")
    by_id = {node.get("artifact_id"): node for node in artifacts}
    actual = []
    for node in artifacts:
        static = (node.get("report") or {}).get("analysis", {}).get("static", {})
        coverage = static.get("stage_coverage", [])
        if not coverage or static.get("status") != expected_static:
            failures.append("artifact_coverage_missing_or_incomplete")
        if any(
            stage.get("status")
            in {
                "failed",
                "error",
                "limited",
                "partial",
                "timeout",
                "unavailable",
                "unknown",
                "password_required",
            }
            for stage in coverage
        ):
            failures.append("artifact_stage_incomplete")
        chain, cursor, seen = [], node, set()
        while cursor.get("parent_id"):
            if cursor.get("artifact_id") in seen or cursor["parent_id"] not in by_id:
                failures.append("artifact_parent_chain_invalid")
                break
            seen.add(cursor["artifact_id"])
            chain.insert(0, cursor.get("origin_path"))
            cursor = by_id[cursor["parent_id"]]
        if node.get("depth") != len(chain) or node.get("status") != "done":
            failures.append("artifact_depth_or_status_mismatch")
        if require_full_pipeline:
            stages = {stage.get("stage"): stage for stage in coverage}
            needed = {
                "file-type",
                "clamav",
                "yara",
                "ioc-extract",
                "deobfuscation",
                "format-analysis",
                "archive-extract",
                "document-analysis",
            }
            if len(stages) != len(coverage) or not needed.issubset(stages):
                failures.append("required_stage_coverage_missing_or_duplicated")
            if any(
                stages.get(name, {}).get("status") != "ok"
                for name in ("file-type", "clamav", "yara", "ioc-extract")
            ):
                failures.append("required_scan_stage_not_ok")
            deobfuscation = stages.get("deobfuscation", {})
            if is_large_fixture(item):
                if (
                    deobfuscation.get("status") != "skipped"
                    or deobfuscation.get("reason")
                    != "File too large for deobfuscation (20000000 bytes)"
                ):
                    failures.append("large_fixture_limit_not_declared")
            elif deobfuscation.get("status") != "ok":
                failures.append("deobfuscation_not_ok")
            for name, reason in (
                ("format-analysis", "No analyzer matched"),
                ("document-analysis", "Not a supported document format"),
            ):
                stage = stages.get(name, {})
                if stage.get("status") != "skipped" or stage.get("reason") != reason:
                    failures.append("fixture_skip_reason_unexpected")
            archive = stages.get("archive-extract", {})
            has_children = any(
                candidate["chain"][:-1] == chain
                and len(candidate["chain"]) == len(chain) + 1
                for candidate in item["expected_nodes"]
            )
            if (has_children and archive.get("status") != "ok") or (
                not has_children
                and (
                    archive.get("status") != "skipped"
                    or archive.get("reason") != "Not an archive"
                )
            ):
                failures.append("archive_coverage_unexpected")
            embedded = node.get("report") or {}
            sandbox = embedded.get("results", {}).get("sandbox", {})
            if (
                embedded.get("analysis", {}).get("dynamic", {}).get("status")
                != "disabled"
                or sandbox.get("status") != "disabled"
                or sandbox.get("executed") is not False
            ):
                failures.append("artifact_dynamic_execution_unexpected")
        actual.append(
            {"chain": chain, "sha256": node.get("sha256"), "size": node.get("size")}
        )
    if sorted(actual, key=encode) != sorted(item["expected_nodes"], key=encode):
        failures.append("artifact_paths_hashes_or_counts_mismatch")
    expected = item["expected_nodes"]
    budget = report.get("execution_budget", {})
    if (budget.get("used_files"), budget.get("used_bytes")) != (
        len(expected) - 1,
        sum(node["size"] for node in expected if node["chain"]),
    ):
        failures.append("cumulative_budget_mismatch")
    if budget.get("accounting_scope") != "root_artifact_tree":
        failures.append("budget_scope_mismatch")
    tree_ids = []

    def visit(node):
        if not isinstance(node, dict):
            return
        tree_ids.append(node.get("job_id"))
        for child in node.get("children", []):
            visit(child)

    visit(report.get("artifact_tree"))
    if sorted(tree_ids) != sorted(ids):
        failures.append("artifact_tree_mismatch")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "prepare",
            "start",
            "inspect",
            "password",
            "guards",
            "verify",
            "expiry",
        ),
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        required=True,
        help="private state outside the repository; keep it across reconnects",
    )
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--value", choices=tuple(PASSWORDS))
    parser.add_argument(
        "--run",
        action="store_true",
        help="explicitly permit the selected bounded mutating command",
    )
    args = parser.parse_args(argv)
    if args.command in {"start", "password", "guards"} and not args.run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "network_requests": 0,
                    "command": args.command,
                    "note": "Pass --run only after reviewing the fixed campaign and limits.",
                }
            )
        )
        return 0
    if (
        args.command in {"start", "inspect", "guards", "verify", "expiry"}
        and not args.case
    ):
        parser.error("--case is required for this command")
    if args.command == "password" and not args.value:
        parser.error("password requires --value wrong|outer|inner")
    directory = args.state_dir.expanduser().resolve()
    repository = Path(__file__).resolve().parents[2]
    if directory.is_relative_to(repository):
        parser.error("Keep private campaign state outside the repository.")
    try:
        with Campaign(directory).locked() as campaign:
            if args.command == "prepare":
                result = campaign.prepare()
            elif args.command == "password":
                result = campaign.password(args.value)
            else:
                result = getattr(campaign, args.command)(args.case)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result.get("success") is False else 0
    except AcceptanceError as error:
        print(
            json.dumps({"success": False, "error": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print(
            json.dumps(
                {
                    "success": False,
                    "error": "Local state or response is invalid. Preserve the campaign directory; no automatic POST retry.",
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
