#!/usr/bin/env python3
"""Keyless, single-attempt Cloud Run Job dispatcher for the closed demo control."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

MAX_BYTES = 16_384
DISPATCH_DOMAIN = b"malscan:v2:dispatch\n"
CLAIM_DOMAIN = b"malscan:v2:dispatch-claim\n"
METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)
UUID = re.compile(
    r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
)
HEX = re.compile(r"[a-f0-9]{64}")
PAYLOAD_KEYS = {
    "dispatch_version",
    "job_name",
    "issued_at",
    "expires_at",
    "job_id",
    "attempt_id",
    "dispatch_id",
    "sequence",
    "manifest_key",
    "control_key",
    "status_key",
    "report_key",
}


class DispatchError(Exception):
    """Only fixed, nonsecret error codes may reach the HTTP response."""

    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(_: str) -> object:
    raise ValueError("nonfinite_json_number")


def document(raw: bytes) -> object:
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("invalid_document_size")
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant
    )


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Config:
    project: str
    region: str
    job: str
    control_origin: str
    key: bytes

    def __post_init__(self) -> None:
        origin = urlsplit(self.control_origin)
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", self.project)
            or not re.fullmatch(r"[a-z]+-[a-z]+[0-9]", self.region)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.job)
            or origin.scheme != "https"
            or origin.netloc != origin.hostname
            or not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", origin.hostname or "")
            or origin.path
            or origin.query
            or origin.fragment
            or len(self.key) != 32
        ):
            raise ValueError("invalid_dispatcher_configuration")

    @property
    def job_name(self) -> str:
        return f"projects/{self.project}/locations/{self.region}/jobs/{self.job}"

    @classmethod
    def from_env(cls) -> Config:
        secret = Path(
            os.environ.get("CONTROL_HMAC_SECRET_FILE", "/secrets/control/key")
        )
        # Bound reads even if an operator accidentally mounts an unrelated file.
        with secret.open("rb") as stream:
            raw_key = stream.read(129).strip()
        if not HEX.fullmatch(raw_key.decode("ascii")):
            raise ValueError("invalid_dispatcher_configuration")
        return cls(
            os.environ["GCP_PROJECT"],
            os.environ["GCP_REGION"],
            os.environ["GCP_JOB"],
            os.environ["CONTROL_ORIGIN"],
            bytes.fromhex(raw_key.decode("ascii")),
        )


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    """Single HTTP attempt, fixed configured targets, no redirects or proxy."""

    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )
        self.opener.addheaders = [("User-Agent", "MalScanWorker-dispatcher/1.0")]

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: int,
    ) -> Reply:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("upstream_response_too_large")
            return Reply(response.status, raw)


class Dispatcher:
    def __init__(
        self,
        config: Config,
        transport: Transport | None = None,
        clock_ms: Callable[[], int] | None = None,
    ):
        self.config = config
        self.transport = transport or Transport()
        self.clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def validated(self, raw: bytes) -> tuple[str, dict[str, object]]:
        try:
            envelope = document(raw)
            if not isinstance(envelope, dict) or set(envelope) != {
                "payload",
                "hmac_sha256",
            }:
                raise ValueError("invalid_envelope")
            payload_text = envelope["payload"]
            signature = envelope["hmac_sha256"]
            if (
                not isinstance(payload_text, str)
                or not isinstance(signature, str)
                or not HEX.fullmatch(signature)
            ):
                raise ValueError("invalid_envelope")
            expected = hmac.new(
                self.config.key,
                DISPATCH_DOMAIN + payload_text.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise DispatchError("dispatch_authentication_failed", 401)
            payload = document(payload_text.encode("utf-8"))
            if not isinstance(payload, dict) or set(payload) != PAYLOAD_KEYS:
                raise ValueError("invalid_payload")
            if (
                not isinstance(payload["dispatch_version"], int)
                or isinstance(payload["dispatch_version"], bool)
                or payload["dispatch_version"] != 1
            ):
                raise ValueError("invalid_version")
            if payload["job_name"] != self.config.job_name:
                raise ValueError("invalid_target")
            for field in ("job_id", "attempt_id", "dispatch_id"):
                if not isinstance(payload[field], str) or not UUID.fullmatch(
                    payload[field]
                ):
                    raise ValueError("invalid_identity")
            for field in ("issued_at", "expires_at", "sequence"):
                if (
                    not isinstance(payload[field], int)
                    or isinstance(payload[field], bool)
                    or not 0 < payload[field] <= 9_007_199_254_740_991
                ):
                    raise ValueError("invalid_integer")
            if payload["sequence"] > 999_999_999:
                raise ValueError("invalid_sequence")
            now = self.clock_ms()
            issued, expires = payload["issued_at"], payload["expires_at"]
            if not (
                issued <= now + 5_000
                and now < expires
                and issued < expires <= issued + 120_000
            ):
                raise ValueError("invalid_dispatch_window")
            root, attempt, dispatch = (
                payload["job_id"],
                payload["attempt_id"],
                payload["dispatch_id"],
            )
            refs = {
                "manifest_key": f"manifests/{root}/{attempt}.json",
                "control_key": f"controls/{root}/{dispatch}.json",
                "status_key": f"statuses/{root}/{dispatch}.json",
                "report_key": f"reports/{root}/{attempt}.json",
            }
            if any(payload[field] != value for field, value in refs.items()):
                raise ValueError("invalid_reference")
            return payload_text, payload
        except DispatchError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise DispatchError("invalid_dispatch_request") from None

    def dispatch(self, raw: bytes) -> dict[str, str]:
        payload_text, payload = self.validated(raw)
        try:
            token_reply = self.transport.request(
                "GET",
                METADATA_URL,
                {"Metadata-Flavor": "Google"},
                None,
                5,
            )
            token_document = document(token_reply.body)
            token = (
                token_document.get("access_token")
                if isinstance(token_document, dict)
                else None
            )
            if (
                token_reply.status != 200
                or not isinstance(token, str)
                or not re.fullmatch(r"[\x21-\x7e]{1,8192}", token)
            ):
                raise ValueError("metadata_token_invalid")
        except Exception:
            raise DispatchError("dispatcher_identity_unavailable", 503) from None

        claim_signature = hmac.new(
            self.config.key,
            CLAIM_DOMAIN + payload_text.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        try:
            claim = self.transport.request(
                "POST",
                self.config.control_origin + "/internal/dispatch/claim",
                {"Content-Type": "application/json"},
                encoded({"payload": payload_text, "hmac_sha256": claim_signature}),
                10,
            )
            result = document(claim.body)
            if (
                claim.status != 200
                or not isinstance(result, dict)
                or set(result) != {"claimed", "dispatch_id", "request_sha256"}
            ):
                raise ValueError("claim_rejected")
            if (
                result["claimed"] is not True
                or result["dispatch_id"] != payload["dispatch_id"]
                or result["request_sha256"]
                != hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
            ):
                raise ValueError("claim_invalid")
        except Exception:
            # Never run after an uncertain claim, even if its request was accepted.
            raise DispatchError("dispatch_claim_unavailable", 409) from None

        if self.clock_ms() >= payload["expires_at"]:
            raise DispatchError("dispatch_request_expired", 409)
        overrides = {
            "overrides": {
                "taskCount": 1,
                "containerOverrides": [
                    {
                        "env": [
                            {
                                "name": "MALSCAN_MANIFEST_KEY",
                                "value": payload["manifest_key"],
                            },
                            {
                                "name": "MALSCAN_CONTROL_KEY",
                                "value": payload["control_key"],
                            },
                            {
                                "name": "MALSCAN_STATUS_KEY",
                                "value": payload["status_key"],
                            },
                            {
                                "name": "MALSCAN_DISPATCH_ID",
                                "value": payload["dispatch_id"],
                            },
                            {"name": "MALSCAN_ROOT_JOB_ID", "value": payload["job_id"]},
                            {
                                "name": "MALSCAN_ATTEMPT_ID",
                                "value": payload["attempt_id"],
                            },
                            {
                                "name": "MALSCAN_REPORT_KEY",
                                "value": payload["report_key"],
                            },
                            {
                                "name": "MALSCAN_SEQUENCE",
                                "value": str(payload["sequence"]),
                            },
                        ]
                    }
                ],
            },
        }
        try:
            run = self.transport.request(
                "POST",
                f"https://run.googleapis.com/v2/{self.config.job_name}:run",
                {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                encoded(overrides),
                20,
            )
            operation = document(run.body)
            prefix = f"projects/{self.config.project}/locations/{self.config.region}/operations/"
            name = operation.get("name") if isinstance(operation, dict) else None
            if (
                not 200 <= run.status < 300
                or not isinstance(name, str)
                or not re.fullmatch(re.escape(prefix) + r"[a-zA-Z0-9_-]{1,256}", name)
            ):
                raise ValueError("dispatch_response_invalid")
            return {"name": name}
        except Exception:
            # Cloud Run may have accepted the request. No transport-level retry.
            raise DispatchError("job_dispatch_uncertain", 503) from None


def handler_for(dispatcher: Dispatcher) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format: str, *args: object) -> None:
            # BaseHTTPRequestHandler logs user-controlled URLs by default.
            pass

        def reply(self, status: int, body: object) -> None:
            raw = encoded(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path == "/health":
                self.reply(200, {"status": "ok", "scope": "keyless_job_dispatcher"})
            else:
                self.reply(404, {"error": "not_found"})

        def do_POST(self) -> None:
            try:
                if self.path != "/dispatch":
                    raise DispatchError("not_found", 404)
                lengths = self.headers.get_all("Content-Length", [])
                if (
                    len(lengths) != 1
                    or not re.fullmatch(r"[0-9]+", lengths[0])
                    or self.headers.get("Transfer-Encoding")
                ):
                    raise DispatchError("content_length_required", 411)
                length = int(lengths[0])
                if not 0 < length <= MAX_BYTES:
                    raise DispatchError("request_too_large", 413)
                if (
                    self.headers.get("Content-Type", "")
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                    != "application/json"
                ):
                    raise DispatchError("json_required", 415)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise DispatchError("invalid_dispatch_request")
                self.reply(200, dispatcher.dispatch(raw))
            except DispatchError as error:
                self.reply(error.status, {"error": error.code})
            except (socket.timeout, ConnectionError, OSError):
                # The caller may already have disconnected; no execution retry.
                self.close_connection = True
            except Exception:
                self.reply(500, {"error": "dispatcher_internal_error"})

    return Handler


def main() -> None:
    try:
        config = Config.from_env()
        port = int(os.environ.get("PORT", "8080"))
        if not 1 <= port <= 65535:
            raise ValueError("invalid_port")
    except Exception:
        raise SystemExit("invalid_dispatcher_configuration") from None
    HTTPServer(("0.0.0.0", port), handler_for(Dispatcher(config))).serve_forever()


if __name__ == "__main__":
    main()
