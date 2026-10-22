#!/usr/bin/env python3
"""Prepare and apply a bounded full-worker digest cleanup in Cloud Shell.

Keep deployments/builds/tag writers paused throughout apply. Each delete is
preceded and followed by fresh read-only inventory, but provider reads and
deletion are not atomic. Other packages, including OCI indexes, are untouched.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SPEC = importlib.util.spec_from_file_location(
    "registry_inventory", Path(__file__).with_name("cleanup-registry.py")
)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
PROJECT = inventory.PROJECT
REGION = inventory.REGION
REPOSITORY = inventory.REPOSITORY
PACKAGE = inventory.PREFIX + "full-worker"
IMAGE = re.compile(re.escape(inventory.PREFIX) + r"[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}\Z")
WORKER_IMAGE = re.compile(re.escape(PACKAGE) + r"@sha256:[a-f0-9]{64}\Z")
RELEASE = re.compile(r"db-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
MAX_CANDIDATES = 20
MAX_AGE = timedelta(hours=24)


class GuardError(RuntimeError):
    """A bounded cleanup guard stopped the operation."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError) as error:
        raise GuardError("invalid_timestamp") from error


def now() -> datetime:
    return datetime.now(timezone.utc)


def normalize(report: Any) -> dict[str, Any]:
    """Validate a complete inventory; never infer completeness from issues alone."""
    expected = f"projects/{PROJECT}/locations/{REGION}/repositories/{REPOSITORY}"
    if not isinstance(report, dict) or any(
        report.get(key) != value
        for key, value in {
            "schema_version": 1,
            "scope": "read_only_registry_cleanup_inventory",
            "project": PROJECT,
            "repository_region": REGION,
            "readiness_issues": [],
            "protected_versions_not_listed": [],
            "remote_mutations": False,
            "cloud_run_executed": False,
            "cloud_run_list_scope": "all project regions with command-scoped run/region cleared",
        }.items()
    ):
        raise GuardError("inventory_incomplete_or_wrong_scope")
    if report.get("remote_mutations") is not False or report.get("cloud_run_executed") is not False:
        raise GuardError("inventory_mutation_flags_invalid")
    timestamp(report.get("observed_at"))
    repository = report.get("repository")
    if not isinstance(repository, dict) or (repository.get("name"), repository.get("format")) != (
        expected,
        "DOCKER",
    ):
        raise GuardError("repository_identity_not_verified")
    if repository.get("cleanupPolicies"):
        raise GuardError("existing_cleanup_policy_requires_separate_review")
    metadata = {
        key: repository[key]
        for key in ("name", "format", "cleanupPolicies", "cleanupPolicyDryRun")
        if key in repository
    }
    rollback = report.get("rollback_checkpoint")
    if not isinstance(rollback, dict) or rollback.get("status") != "matched":
        raise GuardError("rollback_checkpoint_not_matched")
    releases = rollback.get("matching_releases")
    if not isinstance(releases, list) or len(releases) != 1 or not isinstance(releases[0], str):
        raise GuardError("rollback_checkpoint_not_unique")
    if not RELEASE.fullmatch(releases[0]):
        raise GuardError("rollback_checkpoint_invalid")
    rows = report.get("images")
    if not isinstance(rows, list) or not 0 < len(rows) < inventory.LIMIT:
        raise GuardError("image_inventory_not_complete")
    images = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("image"), str):
            raise GuardError("invalid_image_row")
        uri = row["image"]
        if not IMAGE.fullmatch(uri) or uri in images:
            raise GuardError("invalid_or_duplicate_image_identity")
        classification = row.get("classification")
        reasons = row.get("protection_reasons")
        tags = row.get("tags")
        if classification not in ("protected_reference", "unclassified") or (
            not isinstance(reasons, list)
            or any(not isinstance(reason, str) for reason in reasons)
            or bool(reasons) != (classification == "protected_reference")
            or not isinstance(tags, list)
            or len(tags) >= 100
            or any(
                not isinstance(tag, str)
                or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag)
                for tag in tags
            )
            or len(set(tags)) != len(tags)
        ):
            raise GuardError("image_tags_or_protection_not_verified")
        timestamp(row.get("createTime"))
        timestamp(row.get("updateTime"))
        size = row.get("reported_image_size_bytes")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise GuardError("invalid_image_size_metadata")
        media = row.get("reported_media_type")
        if media is not None and not isinstance(media, str):
            raise GuardError("invalid_media_type_metadata")
        if uri.startswith(PACKAGE + "@") and media != MANIFEST:
            raise GuardError("full_worker_package_contains_index_or_unknown_manifest")
        images[uri] = {
            "image": uri,
            "classification": classification,
            "protection_reasons": sorted(reasons),
            "tags": sorted(tags),
            "createTime": row["createTime"],
            "updateTime": row["updateTime"],
            "reported_image_size_bytes": size,
            "reported_media_type": media,
        }
    references = report.get("references")
    if not isinstance(references, list) or not references:
        raise GuardError("deployment_references_not_observed")
    clean_refs = {}
    for ref in references:
        if not isinstance(ref, dict) or set(ref) != {"kind", "resource", "region", "image"}:
            raise GuardError("invalid_reference_row")
        if any(not isinstance(value, str) for value in ref.values()) or (
            ref["kind"]
            not in {
                "job",
                "service",
                "revision",
                "revision_resolved",
                "unfinished_execution",
                "rollback_checkpoint",
            }
            or not (RELEASE if ref["kind"] == "rollback_checkpoint" else inventory.NAME).fullmatch(
                ref["resource"]
            )
            or not inventory.REGION_NAME.fullmatch(ref["region"])
            or not inventory.IMAGE.fullmatch(ref["image"])
        ):
            raise GuardError("invalid_reference_identity")
        if ref["image"].startswith(inventory.PREFIX) and "@" in ref["image"]:
            base, sha = ref["image"].split("@")
            base = base.rsplit(":", 1)[0] if ":" in base else base
            resolved = base + "@" + sha
            if (
                resolved not in images
                or images[resolved]["classification"] != "protected_reference"
            ):
                raise GuardError("referenced_image_not_protected")
        clean_refs[canonical(ref)] = ref
    primary = {
        ref["image"]
        for ref in references
        if ref["kind"] == "job"
        and ref["resource"] == "malscan-v2-static-demo"
        and ref["region"] == REGION
    }
    previous = {
        ref["image"]
        for ref in references
        if ref["kind"] == "rollback_checkpoint"
        and ref["resource"] == releases[0]
        and ref["region"] == REGION
    }
    if (
        len(primary) != 1
        or len(previous) != 1
        or primary == previous
        or not all(
            WORKER_IMAGE.fullmatch(uri)
            and uri in images
            and images[uri]["classification"] == "protected_reference"
            for uri in primary | previous
        )
    ):
        raise GuardError("current_and_rollback_images_not_verified")
    return {
        "repository": metadata,
        "images": [images[key] for key in sorted(images)],
        "references": [clean_refs[key] for key in sorted(clean_refs)],
        "rollback_checkpoint": {"status": "matched", "matching_releases": releases},
    }


def candidates(baseline: dict[str, Any]) -> list[str]:
    rows = baseline["images"]
    keep_times = [
        timestamp(row["createTime"])
        for row in rows
        if row["image"].startswith(PACKAGE + "@") and row["classification"] == "protected_reference"
    ]
    if len(keep_times) < 2:
        raise GuardError("protected_worker_versions_missing")
    cutoff = min(keep_times)
    return [
        row["image"]
        for row in rows
        if row["image"].startswith(PACKAGE + "@")
        and row["classification"] == "unclassified"
        and row["reported_media_type"] == MANIFEST
        and timestamp(row["createTime"]) < cutoff
    ]


def make_plan(
    report: dict[str, Any], at_time: datetime | None = None, *, source_sha256: str | None = None
) -> dict[str, Any]:
    current_time = at_time or now()
    if not isinstance(report, dict):
        raise GuardError("inventory_incomplete_or_wrong_scope")
    observed = timestamp(report.get("observed_at"))
    if observed > current_time + timedelta(minutes=5) or current_time - observed > MAX_AGE:
        raise GuardError("inventory_is_stale_or_from_future")
    baseline = normalize(report)
    selected = candidates(baseline)
    if not 0 < len(selected) <= MAX_CANDIDATES:
        raise GuardError("candidate_count_outside_bounded_batch")
    payload = {
        "version": 1,
        "scope": "bounded_full_worker_digest_cleanup",
        "project": PROJECT,
        "region": REGION,
        "package": PACKAGE,
        "created_at": current_time.isoformat(),
        "inventory_observed_at": observed.isoformat(),
        "expires_at": min(current_time + MAX_AGE, observed + MAX_AGE).isoformat(),
        "baseline": baseline,
        "candidates": selected,
        "repository_size_bytes_at_inventory": report["repository"].get("sizeBytes"),
        "source_inventory_sha256": source_sha256 or digest(report),
    }
    return {**payload, "plan_sha256": digest(payload)}


def report_for_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        **plan["baseline"],
        "schema_version": 1,
        "scope": "read_only_registry_cleanup_inventory",
        "project": PROJECT,
        "repository_region": REGION,
        "readiness_issues": [],
        "protected_versions_not_listed": [],
        "remote_mutations": False,
        "cloud_run_executed": False,
        "cloud_run_list_scope": "all project regions with command-scoped run/region cleared",
        "observed_at": plan["inventory_observed_at"],
    }


def validate_plan(value: Any, *, expired_ok: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardError("invalid_plan")
    payload = {key: child for key, child in value.items() if key != "plan_sha256"}
    if value.get("plan_sha256") != digest(payload) or any(
        value.get(key) != expected
        for key, expected in {
            "version": 1,
            "scope": "bounded_full_worker_digest_cleanup",
            "project": PROJECT,
            "region": REGION,
            "package": PACKAGE,
        }.items()
    ):
        raise GuardError("plan_identity_changed")
    if not isinstance(value.get("source_inventory_sha256"), str) or not re.fullmatch(
        r"[a-f0-9]{64}", value["source_inventory_sha256"]
    ):
        raise GuardError("plan_source_identity_invalid")
    try:
        created, observed, expires = (
            timestamp(value[key]) for key in ("created_at", "inventory_observed_at", "expires_at")
        )
        baseline = normalize(report_for_plan(value))
        selected = candidates(baseline)
        if (
            baseline != value["baseline"]
            or selected != value["candidates"]
            or not (0 < len(selected) <= MAX_CANDIDATES)
        ):
            raise GuardError("plan_candidates_changed")
    except (KeyError, TypeError) as error:
        raise GuardError("invalid_plan_schema") from error
    if expires != min(created + MAX_AGE, observed + MAX_AGE) or (
        created > now() + timedelta(minutes=5)
        or observed > created + timedelta(minutes=5)
        or created - observed > MAX_AGE
    ):
        raise GuardError("plan_time_bounds_invalid")
    if not expired_ok and now() >= expires:
        raise GuardError("plan_expired_prepare_fresh_inventory")
    return value


def private_location(path: Path, home: Path, *, directory: bool = False) -> Path:
    path = path.expanduser().absolute()
    resolved_home = home.resolve()
    source = Path(__file__).resolve().parents[2]
    resolved = path.resolve()
    if resolved_home not in resolved.parents or source == resolved or source in resolved.parents:
        raise GuardError("private_path_must_be_in_home_outside_source")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise GuardError("private_path_must_not_use_symlinks")
        if parent == resolved_home:
            break
    if path.exists():
        info = path.stat()
        if info.st_mode & 0o077 or not (
            stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        ):
            raise GuardError("private_path_permissions_or_type_invalid")
    return resolved


def read_inventory(path: Path, expected_sha256: str) -> Any:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise GuardError("inventory_sha256_invalid")
    path = path.expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise GuardError("invalid_inventory_file")
    try:
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise GuardError("inventory_sha256_mismatch")
        return json.loads(payload)
    except (OSError, ValueError) as error:
        raise GuardError("inventory_file_unreadable") from error


def read_json(path: Path, *, private: bool = True, home: Path | None = None) -> Any:
    if private:
        path = private_location(path, home or Path.home())
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise GuardError("invalid_json_file")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise GuardError("json_file_unreadable") from error


def write_private(path: Path, value: Any, *, exclusive: bool = False) -> None:
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with os.fdopen(
            os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as out:
            out.write(canonical(value) + b"\n")
            out.flush()
            os.fsync(out.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory(path: Path, home: Path) -> None:
    current = home.resolve()
    for component in path.relative_to(current).parts:
        parent = current
        current /= component
        if not current.exists():
            current.mkdir(mode=0o700)
            fsync_directory(parent)
            fsync_directory(current)
        if current.is_symlink() or not current.is_dir():
            raise GuardError("state_directory_invalid")


@contextmanager
def locked(directory: Path):
    descriptor = os.open(
        directory / "operation.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GuardError("another_cleanup_is_using_state_directory") from error
        yield
    finally:
        os.close(descriptor)


def delete_image(uri: str) -> None:
    if not WORKER_IMAGE.fullmatch(uri):
        raise GuardError("delete_target_is_not_full_worker_digest")
    environment = dict(os.environ)
    environment.update(
        CLOUDSDK_CORE_LOG_HTTP="false",
        CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
        CLOUDSDK_CORE_DISABLE_PROMPTS="true",
    )
    try:
        result = subprocess.run(
            [
                "gcloud",
                "artifacts",
                "docker",
                "images",
                "delete",
                uri,
                "--delete-tags",
                f"--project={PROJECT}",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GuardError("delete_request_outcome_uncertain") from error
    if result.returncode:
        raise GuardError("delete_request_outcome_uncertain")


class Cleanup:
    def __init__(
        self,
        plan: dict[str, Any],
        directory: Path,
        *,
        home: Path | None = None,
        inspect=None,
        delete=None,
    ):
        self.plan = plan
        self.home = home or Path.home()
        self.directory = private_location(directory, self.home, directory=True)
        self.inspect = inspect or (lambda: inventory.Inspector().inspect())
        self.delete = delete or delete_image
        self.campaign_directory = private_location(
            self.home / ".malscan-v2-operations/registry-cleanup", self.home, directory=True
        )

    def campaign(self) -> dict[str, Any] | None:
        path = self.campaign_directory / "active-campaign.json"
        if path.is_symlink():
            raise GuardError("campaign_checkpoint_must_not_be_symlink")
        if not path.exists():
            return None
        value = read_json(path, home=self.home)
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or (
                value.get("package") != PACKAGE
                or value.get("phase") not in {"active", "completed"}
                or not isinstance(value.get("plan_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["plan_sha256"])
                or not isinstance(value.get("state_dir"), str)
                or not isinstance(value.get("candidates"), list)
                or not 0 < len(value["candidates"]) <= MAX_CANDIDATES
                or any(
                    not isinstance(uri, str) or not WORKER_IMAGE.fullmatch(uri)
                    for uri in value["candidates"]
                )
                or len(set(value["candidates"])) != len(value["candidates"])
            )
        ):
            raise GuardError("campaign_checkpoint_invalid")
        same_plan = value["plan_sha256"] == self.plan["plan_sha256"]
        same_state = value["state_dir"] == str(self.directory)
        if same_plan and not same_state:
            raise GuardError("plan_is_bound_to_another_state_directory")
        if not same_plan or not same_state:
            if value["phase"] != "completed":
                raise GuardError("another_cleanup_campaign_requires_reconciliation")
            previous = read_json(Path(value["state_dir"]) / "state.json", home=self.home)
            if (
                not isinstance(previous, dict)
                or previous.get("phase") != "completed"
                or (
                    previous.get("plan_sha256") != value["plan_sha256"]
                    or previous.get("pending") is not None
                    or previous.get("removed") != sorted(value["candidates"])
                )
            ):
                raise GuardError("previous_campaign_completion_not_verified")
        return value

    def claim_campaign(self, phase: str) -> None:
        write_private(
            self.campaign_directory / "active-campaign.json",
            {
                "version": 1,
                "package": PACKAGE,
                "plan_sha256": self.plan["plan_sha256"],
                "state_dir": str(self.directory),
                "candidates": self.plan["candidates"],
                "phase": phase,
            },
        )

    def save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = now().isoformat()
        write_private(self.directory / "state.json", state)

    def load(self, *, allow_initialize: bool = True) -> dict[str, Any]:
        path = self.directory / "state.json"
        if not path.exists():
            if not allow_initialize:
                raise GuardError("checkpoint_missing_for_claimed_campaign")
            state = {
                "version": 1,
                "plan_sha256": self.plan["plan_sha256"],
                "removed": [],
                "pending": None,
                "phase": "prepared",
                "remote_mutations_attempted": False,
            }
            write_private(path, state, exclusive=True)
            return state
        state = read_json(path, home=self.home)
        if (
            not isinstance(state, dict)
            or state.get("version") != 1
            or (state.get("plan_sha256") != self.plan["plan_sha256"])
        ):
            raise GuardError("checkpoint_does_not_match_plan")
        removed, pending = state.get("removed"), state.get("pending")
        if (
            not isinstance(removed, list)
            or any(not isinstance(uri, str) for uri in removed)
            or (
                len(set(removed)) != len(removed)
                or not set(removed) <= set(self.plan["candidates"])
                or (
                    pending is not None
                    and (
                        not isinstance(pending, str)
                        or pending not in self.plan["candidates"]
                        or pending in removed
                    )
                )
            )
        ):
            raise GuardError("checkpoint_candidate_state_invalid")
        phase = state.get("phase")
        if phase not in {"prepared", "partial", "completed", "deletion_pending", "uncertain"} or (
            not isinstance(state.get("remote_mutations_attempted"), bool)
            or bool(pending) != (phase in {"deletion_pending", "uncertain"})
            or (phase == "completed" and set(removed) != set(self.plan["candidates"]))
            or ((removed or pending) and not state["remote_mutations_attempted"])
        ):
            raise GuardError("checkpoint_phase_invalid")
        return state

    def refresh(self, state: dict[str, Any]) -> dict[str, Any]:
        report = self.inspect()
        fresh = normalize(report)
        removed = set(state["removed"])
        present = {row["image"] for row in fresh["images"]}
        pending = state["pending"]
        if pending and pending not in present:
            removed.add(pending)
        expected = copy.deepcopy(self.plan["baseline"])
        expected["images"] = [row for row in expected["images"] if row["image"] not in removed]
        if fresh != expected:
            raise GuardError("live_inventory_changed_stop_before_further_deletion")
        if pending:
            if pending in present:
                state["phase"] = "uncertain"
                self.save(state)
                raise GuardError("pending_digest_still_present_no_automatic_retry")
            state["removed"] = sorted(removed)
            state["pending"] = None
            state["phase"] = "partial"
            self.save(state)
        size = report["repository"].get("sizeBytes")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            state["observed_repository_size_bytes"] = size
        state["observed_version_count"] = len(report["images"])
        return report

    def run(self, *, apply: bool) -> dict[str, Any]:
        validate_plan(self.plan, expired_ok=not apply)
        ensure_directory(self.campaign_directory, self.home)
        with locked(self.campaign_directory):
            campaign = self.campaign()
            claimed = campaign is not None and (
                campaign["plan_sha256"] == self.plan["plan_sha256"]
                and campaign["state_dir"] == str(self.directory)
            )
            return self.run_locked(apply=apply, claimed=claimed)

    def run_locked(self, *, apply: bool, claimed: bool) -> dict[str, Any]:
        ensure_directory(self.directory, self.home)
        with locked(self.directory):
            state = self.load(allow_initialize=not claimed)
            self.refresh(state)
            if apply or state.get("remote_mutations_attempted"):
                self.claim_campaign("active")
            if apply:
                for uri in self.plan["candidates"]:
                    if uri in state["removed"]:
                        continue
                    validate_plan(self.plan)
                    self.refresh(state)
                    state.update(
                        pending=uri, phase="deletion_pending", remote_mutations_attempted=True
                    )
                    self.save(state)
                    try:
                        self.delete(uri)
                        self.refresh(state)
                    except GuardError:
                        state["phase"] = "uncertain"
                        self.save(state)
                        raise
            state["phase"] = (
                "completed" if set(state["removed"]) == set(self.plan["candidates"]) else "partial"
            )
            self.save(state)
            if state.get("remote_mutations_attempted") and state["phase"] == "completed":
                self.claim_campaign("completed")
            return {
                "scope": "bounded_full_worker_digest_cleanup",
                "phase": state["phase"],
                "plan_sha256": self.plan["plan_sha256"],
                "candidate_count": len(self.plan["candidates"]),
                "removed": state["removed"],
                "pending": state["pending"],
                "removed_count": len(state["removed"]),
                "state_dir": str(self.directory),
                "observed_repository_size_bytes": state.get("observed_repository_size_bytes"),
                "observed_version_count": state.get("observed_version_count"),
                "cloud_run_executed": False,
                "billed_savings_verified": False,
            }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare = commands.add_parser("prepare", help="create a private plan; no cloud calls")
    prepare.add_argument("--inventory", type=Path, required=True)
    prepare.add_argument("--inventory-sha256", required=True)
    prepare.add_argument("--plan", type=Path, required=True)
    for operation in ("apply", "check"):
        command = commands.add_parser(operation)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            path = private_location(args.plan, Path.home())
            plan = make_plan(
                read_inventory(args.inventory, args.inventory_sha256),
                source_sha256=args.inventory_sha256,
            )
            write_private(path, plan, exclusive=True)
            result = {
                "scope": plan["scope"],
                "plan_file": str(path),
                "plan_sha256": plan["plan_sha256"],
                "candidates": plan["candidates"],
                "expires_at": plan["expires_at"],
                "remote_mutations": False,
            }
        else:
            plan = validate_plan(read_json(args.plan), expired_ok=args.operation == "check")
            result = Cleanup(plan, args.state_dir).run(apply=args.operation == "apply")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (GuardError, OSError, ValueError):
        # Never echo arbitrary cloud output or JSON values. The named GuardError
        # categories contain only source-controlled labels and no credentials.
        error = sys.exc_info()[1]
        reason = str(error) if isinstance(error, GuardError) else "local_file_operation_failed"
        print(
            json.dumps(
                {
                    "success": False,
                    "error": reason,
                    "cloud_run_executed": False,
                    "automatic_delete_retry": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
