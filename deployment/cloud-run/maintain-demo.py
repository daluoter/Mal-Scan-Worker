#!/usr/bin/env python3
"""Checkpointed, opt-in Cloud Shell maintenance; inspect is read-only by default.

No operation executes an analysis Job or reads Secret Manager values. All remote
commands use the authenticated gcloud account and the fixed demo project/region.
Keep the private state directory in persistent Cloud Shell HOME, outside source.
"""

import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

PROJECT = "malscan-v2-poc"
REGION = "us-central1"
JOB = "malscan-v2-static-demo"
IMAGE = f"{REGION}-docker.pkg.dev/{PROJECT}/malscan-v2-poc/full-worker"
CONFIG = "deployment/cloud-run/cloudbuild.yaml"
DEFAULT_ROOT = Path.home() / ".malscan-v2-operations" / "maintenance"
RELEASE_PATTERN = r"db-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}"
DIGEST_PATTERN = r"sha256:[a-f0-9]{64}"
IGNORED_ANNOTATIONS = {
    "run.googleapis.com/client-name",
    "run.googleapis.com/client-version",
    "run.googleapis.com/operation-id",
    "run.googleapis.com/creator",
    "run.googleapis.com/lastModifier",
    "serving.knative.dev/creator",
    "serving.knative.dev/lastModifier",
}


class MaintenanceError(RuntimeError):
    """A guard stopped the operation before an unsafe continuation."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fingerprint(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write_private(path: Path, value, *, exclusive: bool = False) -> None:
    if path.is_symlink():
        raise MaintenanceError("Refusing a symlink checkpoint")
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with os.fdopen(
            os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_private(path: Path):
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise MaintenanceError("Checkpoint must be a private regular file (0600)")
    return json.loads(path.read_text())


@contextmanager
def operation_lock(directory: Path):
    lock = directory / "operation.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceError("Another operation is using this checkpoint") from None
        yield
    finally:
        os.close(descriptor)


class Gcloud:
    def call(self, arguments: list[str], *, cwd: Path | None = None):
        try:
            result = subprocess.run(
                [
                    "gcloud",
                    *arguments,
                    f"--project={PROJECT}",
                    "--quiet",
                    "--format=json",
                ],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise MaintenanceError("gcloud command did not return a verified response") from error
        if result.returncode:
            # Do not echo arbitrary command output: Job configuration is private.
            raise MaintenanceError("gcloud command failed; inspect Cloud Console before retrying")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise MaintenanceError("gcloud returned an unverifiable response") from error

    def job(self):
        return self.call(["run", "jobs", "describe", JOB, f"--region={REGION}"])


def container(job: dict) -> dict:
    try:
        containers = job["spec"]["template"]["spec"]["template"]["spec"]["containers"]
    except (KeyError, TypeError) as error:
        raise MaintenanceError("Unexpected Cloud Run v1 Job structure") from error
    if len(containers) != 1:
        raise MaintenanceError("Maintenance requires exactly one configured container")
    return containers[0]


def immutable_image(value: str) -> str:
    if not re.fullmatch(re.escape(IMAGE) + "@" + DIGEST_PATTERN, value):
        raise MaintenanceError("Expected this demo's full-worker immutable image digest")
    return value


def job_configuration(job: dict) -> dict:
    """Include spec, user labels and annotations; omit only server/client metadata."""
    container(job)
    metadata = job.get("metadata", {})
    if metadata.get("name") != JOB:
        raise MaintenanceError("Unexpected Job name")
    return {
        "spec": job["spec"],
        "labels": metadata.get("labels", {}),
        "annotations": {
            key: value
            for key, value in metadata.get("annotations", {}).items()
            if key not in IGNORED_ANNOTATIONS
        },
    }


def job_ready(job: dict) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in job.get("status", {}).get("conditions", [])
    )


def expected_configuration(base: dict, image: str) -> dict:
    result = copy.deepcopy(base)
    container({"spec": result["spec"]})["image"] = image
    return result


def source_fingerprint(repository: Path) -> str:
    """Hash build inputs without venv/cache/operational directories or credentials."""
    ignored = {".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    digest = hashlib.sha256()
    files = [
        repository / CONFIG,
        repository / ".gcloudignore",
        repository / ".dockerignore",
    ]
    for root in ("worker", "backend"):
        for path in (repository / root).rglob("*"):
            relative = path.relative_to(repository)
            if any(part in ignored for part in relative.parts) or "tests" in relative.parts:
                continue
            if (
                path.is_file()
                and not path.name.startswith(".env")
                and not path.name.endswith(".log")
            ):
                files.append(path)
    for path in sorted(files):
        if path.is_symlink():
            raise MaintenanceError("Symlink build input is not supported")
        digest.update(str(path.relative_to(repository)).encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class Maintenance:
    def __init__(self, directory: Path, repository: Path, cloud=None):
        self.directory = directory.resolve()
        self.repository = repository.resolve()
        if self.directory == self.repository or self.repository in self.directory.parents:
            raise MaintenanceError("State must be outside the source checkout/upload context")
        self.cloud = cloud or Gcloud()

    @property
    def state_file(self):
        return self.directory / "state.json"

    def load(self) -> dict:
        state = read_private(self.state_file)
        if (
            state.get("version") != 1
            or state.get("project") != PROJECT
            or state.get("region") != REGION
            or state.get("job") != JOB
            or not re.fullmatch(RELEASE_PATTERN, state.get("release", ""))
        ):
            raise MaintenanceError("Unrecognized maintenance checkpoint")
        immutable_image(state["previous_image"])
        baseline = read_private(self.directory / "job-before.json")
        if fingerprint(job_configuration(baseline)) != state["baseline_fingerprint"]:
            raise MaintenanceError("Baseline checkpoint fingerprint changed")
        return state

    def save(self, state: dict) -> None:
        state["updated_at"] = utc_now()
        write_private(self.state_file, state)

    def prepare(self) -> dict:
        if self.directory.exists():
            raise MaintenanceError("Checkpoint already exists; use inspect/status, not prepare")
        release = self.directory.name
        if not re.fullmatch(RELEASE_PATTERN, release):
            raise MaintenanceError("State directory name must be the generated db release ID")
        job = self.cloud.job()
        if not job_ready(job):
            raise MaintenanceError("Capture requires a healthy Ready Job baseline")
        image = immutable_image(container(job)["image"])
        configuration = job_configuration(job)
        source = source_fingerprint(self.repository)
        self.directory.mkdir(parents=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        write_private(self.directory / "job-before.json", job, exclusive=True)
        state = {
            "version": 1,
            "project": PROJECT,
            "region": REGION,
            "job": JOB,
            "release": release,
            "phase": "prepared",
            "prepared_at": utc_now(),
            "previous_image": image,
            "baseline_fingerprint": fingerprint(configuration),
            "source_sha256": source,
            "controls_module_sha256": hashlib.sha256(
                (
                    self.repository / "worker/src/malscan_worker/runtime/engine_controls.py"
                ).read_bytes()
            ).hexdigest(),
            "cloud_run_executed": False,
        }
        write_private(self.state_file, state, exclusive=True)
        return state

    def submit(self) -> dict:
        state = self.load()
        if state["phase"] != "prepared":
            raise MaintenanceError("Submission already attempted; use status to reconcile it")
        if state["source_sha256"] != source_fingerprint(self.repository):
            raise MaintenanceError("Build inputs changed after prepare; start a new checkpoint")
        state["phase"] = "submission_pending"
        self.save(state)  # Persist intent BEFORE a possible remote write.
        build = self.cloud.call(
            [
                "builds",
                "submit",
                ".",
                f"--region={REGION}",
                f"--config={CONFIG}",
                f"--substitutions=_RELEASE={state['release']}",
                "--async",
            ],
            cwd=self.repository,
        )
        if isinstance(build, list) and len(build) == 1:
            build = build[0]
        if not isinstance(build, dict) or not re.fullmatch(r"[a-f0-9-]{36}", build.get("id", "")):
            raise MaintenanceError("Submission response unknown; use status, do not resubmit")
        state.update(phase="build_submitted", build_id=build["id"])
        state["source_unchanged_after_submission"] = state["source_sha256"] == source_fingerprint(
            self.repository
        )
        self.save(state)
        return state

    def find_build(self, state: dict) -> dict | None:
        if not state.get("build_id"):
            builds = self.cloud.call(
                [
                    "builds",
                    "list",
                    f"--region={REGION}",
                    f"--filter=substitutions._RELEASE={state['release']}",
                    "--limit=20",
                ]
            )
            matches = [
                b for b in builds if b.get("substitutions", {}).get("_RELEASE") == state["release"]
            ]
            if not matches:
                return None
            if len(matches) != 1:
                raise MaintenanceError("Multiple matching builds; manual reconciliation required")
            state["build_id"] = matches[0]["id"]
        build = self.cloud.call(["builds", "describe", state["build_id"], f"--region={REGION}"])
        if build.get("substitutions", {}).get("_RELEASE") != state["release"]:
            raise MaintenanceError("Build release does not match this checkpoint")
        return build

    def controls_report(self, state: dict) -> dict:
        """Read only this build's emitted evidence; never print arbitrary logs."""
        entries = self.cloud.call(
            [
                "logging",
                "read",
                f'resource.type="build" AND resource.labels.build_id="{state["build_id"]}"',
                "--limit=1000",
                "--order=desc",
                "--freshness=30d",
            ]
        )
        reports = {}
        for entry in entries:
            candidates = [entry.get("jsonPayload")]
            for line in entry.get("textPayload", "").splitlines():
                line = re.sub(r'^Step #1(?: - "engine-controls")?: ', "", line, count=1)
                try:
                    candidates.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            for report in candidates:
                if isinstance(report, dict) and report.get("scope") == "offline_engine_controls":
                    reports[fingerprint(report)] = report
        if len(reports) != 1:
            raise MaintenanceError(
                "Offline controls report unavailable/ambiguous; retry status after logs arrive"
            )
        report = next(iter(reports.values()))
        if (
            report.get("success") is not True
            or not isinstance(report.get("uid"), int)
            or report["uid"] <= 0
            or report.get("module_sha256") != state["controls_module_sha256"]
            or report.get("controls")
            != {
                "clamav_clean": True,
                "clamav_eicar_detected": True,
                "yara_clean": True,
                "yara_eicar_detected": True,
            }
            or not report.get("clamav_version")
            or not report.get("yara_version")
            or not re.fullmatch(r"[a-f0-9]{64}", report.get("yara_rules_sha256", ""))
        ):
            raise MaintenanceError("Offline controls evidence did not verify")
        databases = report.get("signed_databases", [])
        if {item.get("name") for item in databases} != {
            "main.cvd",
            "daily.cvd",
            "bytecode.cvd",
        } or len(databases) != 3:
            raise MaintenanceError("Signed database provenance is incomplete")
        for item in databases:
            if item.get("signature_verified") is not True:
                raise MaintenanceError("Signed database verification did not pass")
            if (
                item["name"] == "daily.cvd"
                and not 0
                <= datetime.now(timezone.utc).timestamp() - item["created_at_epoch"]
                <= 604800
            ):
                raise MaintenanceError(
                    "Candidate daily database is now stale or future-dated; rebuild"
                )
        return report

    def verified_candidate(self, state: dict, build: dict) -> str:
        if state.get("source_unchanged_after_submission") is False:
            raise MaintenanceError("Build inputs changed during submission; use a fresh checkpoint")
        tag = IMAGE + ":" + state["release"]
        steps = build.get("steps", [])
        if build.get("status") != "SUCCESS" or len(steps) != 2:
            raise MaintenanceError("Build has not completed the expected release controls")
        controls = steps[1]
        expected = [
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs=/tmp:rw,size=128m",
            "--entrypoint=python",
            tag,
            "-m",
            "malscan_worker.runtime.engine_controls",
        ]
        if (
            controls.get("id") != "engine-controls"
            or controls.get("status") != "SUCCESS"
            or controls.get("name") != "gcr.io/cloud-builders/docker"
            or controls.get("args") != expected
            or steps[0].get("status") != "SUCCESS"
            or steps[0].get("args")
            != [
                "build",
                "--target=cloud-job",
                f"--build-arg=SIGNATURE_REFRESH={state['release']}",
                "-f",
                "worker/Dockerfile",
                "-t",
                tag,
                ".",
            ]
        ):
            raise MaintenanceError("Fresh image offline controls are absent or do not match")
        images = build.get("results", {}).get("images", [])
        if len(images) != 1 or images[0].get("name") != tag:
            raise MaintenanceError("Build publication did not return the expected image")
        digest = images[0].get("digest", "")
        if not re.fullmatch(DIGEST_PATTERN, digest):
            raise MaintenanceError("Build returned no immutable digest")
        description = self.cloud.call(["artifacts", "docker", "images", "describe", tag])
        candidate = IMAGE + "@" + digest
        if description.get("image_summary", {}).get("fully_qualified_digest") != candidate:
            raise MaintenanceError("Registry readback does not match the successful build digest")
        report = self.controls_report(state)
        write_private(self.directory / "engine-controls.json", report)
        state["candidate_controls"] = report
        return candidate

    def status(self) -> dict:
        state = self.load()
        if state["phase"] == "prepared":
            return state
        if state["phase"] in {"promotion_pending", "rollback_pending"}:
            job = self.cloud.job()
            current = job_configuration(job)
            target = (
                state["candidate_image"]
                if state["phase"] == "promotion_pending"
                else state["previous_image"]
            )
            baseline = job_configuration(read_private(self.directory / "job-before.json"))
            if current == expected_configuration(baseline, target) and job_ready(job):
                state["phase"] = (
                    "promoted" if state["phase"] == "promotion_pending" else "rolled_back"
                )
                state["active_fingerprint"] = fingerprint(current)
                self.save(state)
            return state
        if state["phase"] in {"promoted", "rolled_back"}:
            return state
        build = self.find_build(state)
        if build is None:
            state["phase"] = "submission_unknown"
        else:
            write_private(self.directory / "build.json", build)
            state["build_status"] = build.get("status")
            if build.get("status") == "SUCCESS":
                state["candidate_image"] = self.verified_candidate(state, build)
                state["phase"] = "build_verified"
            elif build.get("status") in {
                "FAILURE",
                "CANCELLED",
                "TIMEOUT",
                "EXPIRED",
                "INTERNAL_ERROR",
            }:
                state["phase"] = "build_failed"
            else:
                state["phase"] = "build_submitted"
        self.save(state)
        return state

    def update_image(self, *, rollback: bool = False) -> dict:
        state = self.load()
        required = "promoted" if rollback else "build_verified"
        if state["phase"] != required:
            raise MaintenanceError(
                f"Expected {required}; run status, never blindly repeat an update"
            )
        if not rollback:
            # Re-read build and registry even if a previous status already passed.
            build = self.find_build(state)
            if not build or self.verified_candidate(state, build) != state["candidate_image"]:
                raise MaintenanceError("Candidate no longer matches the verified build")
        baseline = job_configuration(read_private(self.directory / "job-before.json"))
        before = (
            expected_configuration(baseline, state["candidate_image"]) if rollback else baseline
        )
        current = job_configuration(self.cloud.job())
        if current != before:
            raise MaintenanceError("Job changed since capture/promotion; refusing to overwrite it")
        image = state["previous_image"] if rollback else immutable_image(state["candidate_image"])
        state["phase"] = "rollback_pending" if rollback else "promotion_pending"
        self.save(state)
        self.cloud.call(["run", "jobs", "update", JOB, f"--region={REGION}", f"--image={image}"])
        job = self.cloud.job()
        current = job_configuration(job)
        if current != expected_configuration(baseline, image):
            raise MaintenanceError(
                "Post-update configuration differs; inspect before any further action"
            )
        if not job_ready(job):
            raise MaintenanceError("Image update is not Ready; retain checkpoint and use status")
        state["phase"] = "rolled_back" if rollback else "promoted"
        state["active_fingerprint"] = fingerprint(current)
        self.save(state)
        return state


def summary(state: dict, directory: Path) -> dict:
    return {
        key: state[key]
        for key in (
            "release",
            "phase",
            "build_id",
            "build_status",
            "previous_image",
            "candidate_image",
            "cloud_run_executed",
            "candidate_controls",
        )
        if key in state
    } | {"state_dir": str(directory)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        nargs="?",
        default="inspect",
        choices=("inspect", "prepare", "submit", "status", "promote", "rollback"),
    )
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    directory = args.state_dir
    if args.operation == "prepare" and directory is None:
        release = (
            "db-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid.uuid4().hex[:12]
        )
        directory = DEFAULT_ROOT / release
    if directory is None:
        if args.operation != "inspect":
            parser.error("This operation requires --state-dir from prepare output")
        # Default invocation does not even call gcloud or create state.
        print(
            json.dumps(
                {
                    "scope": "read_only_instructions",
                    "state_root": str(DEFAULT_ROOT),
                    "next": "prepare",
                    "cloud_run_executed": False,
                }
            )
        )
        return
    try:
        maintenance = Maintenance(directory, args.repository)
        if args.operation == "prepare":
            result = maintenance.prepare()
        elif args.operation == "inspect":
            result = maintenance.load()
        else:
            with operation_lock(maintenance.directory):
                if args.operation in {"submit", "status"}:
                    result = getattr(maintenance, args.operation)()
                else:
                    result = maintenance.update_image(rollback=args.operation == "rollback")
        print(json.dumps(summary(result, maintenance.directory), indent=2))
    except (MaintenanceError, OSError, ValueError, KeyError, TypeError) as error:
        print(
            json.dumps({"success": False, "error": str(error), "cloud_run_executed": False}),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
