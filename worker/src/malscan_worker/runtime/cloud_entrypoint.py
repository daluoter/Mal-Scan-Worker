"""Authenticated R2 control envelopes for the shared Cloud Run static runner.

The control plane sends object references and immutable identifiers in env vars.
Passwords are consumed from a private signed control object, then deleted. Each
report revision has a separate immutable key; signed status selects the revision
for the current dispatch, so stale executions cannot replace its visible report.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from malscan_worker.budget import BudgetLimits
from malscan_worker.config import get_settings
from malscan_worker.runtime.batch import RootBatchRunner
from malscan_worker.runtime.manifest import AnalysisManifest, validate_key
from malscan_worker.runtime.store import S3ObjectStore


def canonical(document: Any) -> bytes:
    """The stored report's exact encoding; status contains its SHA256."""
    return json.dumps(document, ensure_ascii=False, sort_keys=True).encode()


def seal(document: dict[str, Any], key: bytes) -> dict[str, str]:
    payload = canonical(document).decode()
    return {
        "payload": payload,
        "hmac_sha256": hmac.new(key, payload.encode(), hashlib.sha256).hexdigest(),
    }


def open_envelope(envelope: Any, key: bytes) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "hmac_sha256"}:
        raise ValueError("Invalid control envelope")
    payload, supplied = envelope["payload"], envelope["hmac_sha256"]
    if not isinstance(payload, str) or len(payload.encode()) > 131072:
        raise ValueError("Invalid control size")
    if not isinstance(supplied, str) or not re.fullmatch(r"[a-f0-9]{64}", supplied):
        raise ValueError("Invalid control signature")
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise ValueError("Invalid control signature")
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("Invalid control document")
    return document


@dataclass(frozen=True)
class CloudConfiguration:
    root_job_id: str
    attempt_id: str
    dispatch_id: str
    sequence: int
    manifest_key: str
    control_key: str
    status_key: str
    report_key: str
    endpoint: str
    upload_bucket: str
    result_bucket: str
    read_secret_file: Path
    result_secret_file: Path
    hmac_secret_file: Path
    state_dir: Path

    @classmethod
    def from_environment(cls) -> CloudConfiguration:
        def required(name: str) -> str:
            value = os.environ.get("MALSCAN_" + name)
            if not value:
                raise ValueError("Missing MALSCAN_" + name)
            return value

        root, attempt, dispatch = (
            required(name)
            for name in (
                "ROOT_JOB_ID",
                "ATTEMPT_ID",
                "DISPATCH_ID",
            )
        )
        for identifier in (root, attempt, dispatch):
            if str(UUID(identifier)) != identifier:
                raise ValueError("Invalid dispatch identity")
        sequence_raw = required("SEQUENCE")
        if not re.fullmatch(r"[1-9][0-9]{0,8}", sequence_raw):
            raise ValueError("Invalid dispatch sequence")
        manifest, control, status, report = (
            validate_key(required(name))
            for name in (
                "MANIFEST_KEY",
                "CONTROL_KEY",
                "STATUS_KEY",
                "REPORT_KEY",
            )
        )
        if manifest != f"manifests/{root}/{attempt}.json":
            raise ValueError("Invalid manifest scope")
        if control != f"controls/{root}/{dispatch}.json":
            raise ValueError("Invalid control scope")
        if status != f"statuses/{root}/{dispatch}.json":
            raise ValueError("Invalid status scope")
        if report != f"reports/{root}/{attempt}.json":
            raise ValueError("Invalid report scope")
        return cls(
            root,
            attempt,
            dispatch,
            int(sequence_raw),
            manifest,
            control,
            status,
            report,
            required("R2_ENDPOINT"),
            required("UPLOAD_BUCKET"),
            required("RESULT_BUCKET"),
            Path(os.environ.get("MALSCAN_R2_READ_SECRET_FILE", "/secrets/r2-read.json")),
            Path(os.environ.get("MALSCAN_R2_RESULT_SECRET_FILE", "/secrets/r2-result.json")),
            Path(os.environ.get("MALSCAN_HMAC_SECRET_FILE", "/secrets/control-hmac")),
            Path(os.environ.get("MALSCAN_STATE_DIR", "/tmp/malscan-batch")),
        )


def _credentials(path: Path) -> tuple[str, str]:
    if path.stat().st_size > 16384:
        raise ValueError("Invalid credential file")
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError("Invalid credential file")
    access_key, secret_key = document.get("access_key_id"), document.get("secret_access_key")
    if (
        not isinstance(access_key, str)
        or not access_key
        or not isinstance(secret_key, str)
        or not secret_key
    ):
        raise ValueError("Invalid credential file")
    return access_key, secret_key


def _hmac_key(path: Path) -> bytes:
    if path.stat().st_size > 256:
        raise ValueError("Invalid signing key")
    value = path.read_text().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Signing key must contain 64 lowercase hex digits")
    return bytes.fromhex(value)


def validate_control(
    control: dict[str, Any], config: CloudConfiguration, manifest: AnalysisManifest
) -> dict[str, str]:
    expected = {
        "control_version": 1,
        "manifest_sha256": manifest.fingerprint,
        "dispatch_id": config.dispatch_id,
        "sequence": config.sequence,
        "status_key": config.status_key,
    }
    for name, value in expected.items():
        if control.get(name) != value:
            raise ValueError("Control identity mismatch")
    expires_at = control.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        raise ValueError("Invalid control expiry")
    if (
        control.get("checkpoint_key")
        != f"checkpoints/{config.root_job_id}/{config.attempt_id}.json"
    ):
        raise ValueError("Invalid checkpoint scope")
    if not isinstance(control.get("resume"), bool):
        raise ValueError("Invalid resume flag")
    passwords = control.get("passwords")
    if not isinstance(passwords, dict) or len(passwords) > 100:
        raise ValueError("Invalid password challenges")
    for artifact_id, password in passwords.items():
        if (
            str(UUID(artifact_id)) != artifact_id
            or not isinstance(password, str)
            or not 1 <= len(password) <= 512
        ):
            raise ValueError("Invalid password challenge")
    policy_fields = {
        "password_attempts_by_artifact",
        "password_attempt_limit",
        "password_attempts_scope",
    }
    if policy_fields & control.keys():
        counts = control.get("password_attempts_by_artifact")
        if (
            control.get("password_attempts_scope") != "artifact"
            or not isinstance(control.get("password_attempt_limit"), int)
            or control.get("password_attempt_limit") != 3
            or not isinstance(counts, dict)
            or len(counts) > 100
        ):
            raise ValueError("Invalid per-file password attempt policy")
        for artifact_id, count in counts.items():
            if (
                not isinstance(artifact_id, str)
                or str(UUID(artifact_id)) != artifact_id
                or not isinstance(count, int)
                or isinstance(count, bool)
                or not 0 <= count <= 3
            ):
                raise ValueError("Invalid per-file password attempt count")
        if any(not 1 <= counts.get(artifact_id, 0) <= 3 for artifact_id in passwords):
            raise ValueError("Password submission is missing its attempt count")
    return passwords


class JobExpiredError(RuntimeError):
    """A demo job's retention window ended; no new persistent writes are allowed."""


class ExpiringResultStore:
    """Guard all persistent writes, including private runtime checkpoints."""

    def __init__(self, store: Any, expires_at: int) -> None:
        self.store = store
        self.expires_at = expires_at

    def check(self) -> None:
        if int(time.time() * 1000) >= self.expires_at:
            raise JobExpiredError("Job retention window ended")

    async def fetch(self, *args: Any, **kwargs: Any) -> Path:
        self.check()
        path: Path = await self.store.fetch(*args, **kwargs)
        self.check()
        return path

    async def read_json(self, key: str) -> dict[str, Any]:
        self.check()
        document: dict[str, Any] = await self.store.read_json(key)
        self.check()
        return document

    async def put_file(self, *args: Any, **kwargs: Any) -> str:
        self.check()
        result: str = await self.store.put_file(*args, **kwargs)
        self.check()
        return result

    async def put_json(self, key: str, document: dict[str, Any]) -> str:
        self.check()
        result: str = await self.store.put_json(key, document)
        self.check()
        return result

    async def delete(self, key: str) -> None:
        # Control cleanup remains permitted after expiry.
        await self.store.delete(key)


def demo_limits() -> tuple[BudgetLimits, int]:
    """Fail closed on an accidental unlimited cloud-demo configuration."""
    files = int(os.environ.get("MALSCAN_MAX_FILES", "20"))
    bytes_limit = int(os.environ.get("MALSCAN_MAX_EXPANDED_BYTES", "100000000"))
    timeout = float(os.environ.get("MALSCAN_ATTEMPT_TIMEOUT", "840"))
    depth = int(os.environ.get("MALSCAN_MAX_DEPTH", "3"))
    limits = BudgetLimits(files, bytes_limit, timeout)
    if files > 20 or bytes_limit > 100_000_000 or timeout > 840 or not 0 <= depth <= 3:
        raise ValueError("Cloud demo limits exceed its configured profile")
    return limits, depth


async def execute_cloud(
    config: CloudConfiguration,
    *,
    source_store: Any = None,
    result_store: Any = None,
    key: bytes | None = None,
    runner_type: Any = RootBatchRunner,
) -> dict[str, Any]:
    """Run with injectable real-store boundaries for integration verification."""
    if get_settings().sandbox_enabled:
        raise ValueError("Cloud demo supports static analysis only")
    key = key if key is not None else _hmac_key(config.hmac_secret_file)
    if source_store is None:
        access, secret = _credentials(config.read_secret_file)
        source_store = S3ObjectStore(
            endpoint=config.endpoint,
            bucket=config.upload_bucket,
            access_key=access,
            secret_key=secret,
            region="auto",
            read_only=True,
        )
    if result_store is None:
        access, secret = _credentials(config.result_secret_file)
        result_store = S3ObjectStore(
            endpoint=config.endpoint,
            bucket=config.result_bucket,
            access_key=access,
            secret_key=secret,
            region="auto",
        )
    limits, depth = demo_limits()
    manifest = AnalysisManifest.from_dict(await source_store.read_json(config.manifest_key))
    if (manifest.root_job_id, manifest.attempt_id, manifest.report_key) != (
        config.root_job_id,
        config.attempt_id,
        config.report_key,
    ) or not 1 <= manifest.source.size <= 20_000_000:
        raise ValueError("Manifest identity or demo size mismatch")
    if manifest.source.key != f"uploads/{config.root_job_id}/source":
        raise ValueError("Manifest source is outside this job")
    control = open_envelope(await result_store.read_json(config.control_key), key)
    passwords = validate_control(control, config, manifest)
    # Controls are transient secrets. Checkpoints and reports never contain them.
    await result_store.delete(config.control_key)
    result_store = ExpiringResultStore(result_store, control["expires_at"])
    result_store.check()
    limits = BudgetLimits(
        limits.max_files,
        limits.max_bytes,
        min(limits.timeout_seconds, (control["expires_at"] / 1000) - time.time()),
    )
    latest_report_key: str | None = None
    latest_report_sha256: str | None = None
    latest_waiting: list[str] = []

    async def publish_status(status: str, error_code: str | None = None) -> None:
        document = {
            "status_version": 1,
            "job_id": config.root_job_id,
            "attempt_id": config.attempt_id,
            "manifest_sha256": manifest.fingerprint,
            "dispatch_id": config.dispatch_id,
            "sequence": config.sequence,
            "status": status,
            "report_key": latest_report_key,
            "report_sha256": latest_report_sha256,
            "password_required_artifacts": latest_waiting,
            "error_code": error_code,
        }
        await result_store.put_json(config.status_key, seal(document, key))

    async def publish(
        report: dict[str, Any], *, final: bool = False, error_code: str | None = None
    ) -> None:
        nonlocal latest_report_key, latest_report_sha256, latest_waiting
        revision = report.get("report_revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("Invalid report revision")
        report_key = (
            f"reports/{config.root_job_id}/{config.attempt_id}/{config.dispatch_id}/{revision}.json"
        )
        await result_store.put_json(report_key, report)
        waiting = sorted(
            item["artifact_id"]
            for item in report.get("artifacts", [])
            if item.get("status") == "password_required"
        )
        latest_report_key = report_key
        latest_report_sha256 = hashlib.sha256(canonical(report)).hexdigest()
        latest_waiting = waiting
        status = (
            "failed"
            if error_code
            else "password_required"
            if final and waiting
            else "done"
            if final
            else "scanning"
        )
        await publish_status(status, error_code)

    try:
        # The initial signed state also proves startup before the first report.
        await publish_status("scanning")
        runner = runner_type(
            manifest=manifest,
            source_store=source_store,
            result_store=result_store,
            state_dir=config.state_dir,
            limits=limits,
            max_depth=depth,
            passwords=passwords,
            password_attempts_by_artifact=control.get("password_attempts_by_artifact"),
            password_attempt_limit=control.get("password_attempt_limit"),
            checkpoint_key=control["checkpoint_key"],
            checkpoint_secret=key,
            on_report=publish,
        )
        report = await runner.run(resume=control["resume"])
        await publish(report, final=True)
    except (Exception, asyncio.CancelledError) as exc:
        try:
            # Preserve the last immutable partial snapshot. Never persist the
            # exception message, which may contain a password or provider URL.
            await publish_status("failed", type(exc).__name__)
        except (Exception, asyncio.CancelledError):
            # Expired/unreachable storage remains an uncertain execution. The
            # controller's bounded timeout and reconciliation handle that case.
            pass
        raise
    return {
        "success": True,
        "scope": "shared_cloud_static_analysis",
        "job_id": config.root_job_id,
        "dispatch_id": config.dispatch_id,
        "batch_analysis": report.get("batch_analysis"),
    }


async def _run_with_signals() -> dict[str, Any]:
    task = asyncio.create_task(execute_cloud(CloudConfiguration.from_environment()))
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        return await task
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


def main() -> int:
    try:
        result = asyncio.run(_run_with_signals())
    except (Exception, asyncio.CancelledError) as exc:
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": "shared_cloud_static_analysis",
                    "error_code": type(exc).__name__,
                }
            )
        )
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
