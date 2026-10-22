#!/usr/bin/env python3
"""Inspect demo images and deployment references without deleting anything.

Run in authenticated Cloud Shell. This first-stage inventory is not a deletion
plan: OCI manifest relationships and consumers outside Cloud Run are not checked.
No builds, executions, configuration updates, tokens or Secret payloads are read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = "malscan-v2-poc"
REGION = "us-central1"
REPOSITORY = "malscan-v2-poc"
PREFIX = f"{REGION}-docker.pkg.dev/{PROJECT}/{REPOSITORY}/"
LIMIT = 1000
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
REGION_NAME = re.compile(r"[a-z]+-[a-z]+[0-9]+\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
IMAGE = re.compile(
    r"[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+(?::[A-Za-z0-9_.-]+)?(?:@sha256:[a-f0-9]{64})?\Z"
)
READ_COMMANDS = (
    ("run", "jobs", "list"),
    ("run", "jobs", "describe"),
    ("run", "jobs", "executions", "list"),
    ("run", "services", "list"),
    ("run", "services", "describe"),
    ("run", "revisions", "list"),
    ("artifacts", "repositories", "list"),
    ("artifacts", "docker", "images", "list"),
)


class ReadError(RuntimeError):
    """A read could not be established; raw cloud output is never echoed."""


def at(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def cleanup_policies(value: Any) -> dict[str, Any] | None:
    """Keep only documented non-credential cleanup-policy fields."""
    if not isinstance(value, dict):
        return None
    policies = {}
    for name, policy in value.items():
        if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(policy, dict):
            continue
        item = {}
        if policy.get("action") in ("DELETE", "KEEP"):
            item["action"] = policy["action"]
        condition = policy.get("condition")
        if isinstance(condition, dict):
            item["condition"] = {}
            for key in ("tagState", "olderThan", "newerThan"):
                candidate = condition.get(key)
                if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9.]+", candidate):
                    item["condition"][key] = candidate
            for key in ("tagPrefixes", "versionNamePrefixes", "packageNamePrefixes"):
                candidate = condition.get(key)
                if isinstance(candidate, list) and all(
                    isinstance(part, str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", part)
                    for part in candidate
                ):
                    item["condition"][key] = candidate
        recent = policy.get("mostRecentVersions")
        if isinstance(recent, dict):
            item["mostRecentVersions"] = {}
            if (
                isinstance(recent.get("keepCount"), int)
                and not isinstance(recent["keepCount"], bool)
                and recent["keepCount"] > 0
            ):
                item["mostRecentVersions"]["keepCount"] = recent["keepCount"]
            prefixes = recent.get("packageNamePrefixes")
            if isinstance(prefixes, list) and all(
                isinstance(part, str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", part)
                for part in prefixes
            ):
                item["mostRecentVersions"]["packageNamePrefixes"] = prefixes
        policies[name] = item
    return policies


class Gcloud:
    def read(self, arguments: list[str]) -> Any:
        if not any(tuple(arguments[: len(prefix)]) == prefix for prefix in READ_COMMANDS):
            raise ReadError("command_not_in_read_only_allowlist")
        # Empty command-scoped overrides prevent a saved run/region property
        # from silently narrowing the project-wide jobs/services list.
        env = dict(os.environ)
        env.update(
            CLOUDSDK_RUN_REGION="",
            CLOUDSDK_RUN_PLATFORM="managed",
            CLOUDSDK_CORE_LOG_HTTP="false",
            CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
            CLOUDSDK_CORE_DISABLE_PROMPTS="true",
        )
        try:
            result = subprocess.run(
                ["gcloud", *arguments, f"--project={PROJECT}", "--quiet"],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env=env,
            )
        except FileNotFoundError as error:
            raise ReadError("gcloud_not_installed") from error
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReadError("read_did_not_complete") from error
        if result.returncode:
            raise ReadError("gcloud_read_failed")
        if "unreachable" in result.stderr.lower():
            raise ReadError("unreachable_locations")
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise ReadError("invalid_gcloud_json") from error


class Inspector:
    def __init__(self, cloud=None, home: Path | None = None):
        self.cloud = cloud or Gcloud()
        self.home = home or Path.home()
        self.issues: list[dict[str, str]] = []
        self.references: list[dict[str, str]] = []
        self.protected: dict[str, set[str]] = {}
        self.protected_packages: set[str] = set()

    def issue(self, scope: str, reason: str) -> None:
        self.issues.append({"scope": scope, "reason": reason})

    def read(self, scope: str, arguments: list[str], kind: type) -> Any:
        try:
            value = self.cloud.read(arguments)
            if not isinstance(value, kind):
                raise ReadError("unexpected_gcloud_schema")
            if kind is list and len(value) >= LIMIT:
                self.issue(scope, "list_may_be_truncated")
            return value
        except ReadError as error:
            self.issue(scope, str(error))
            return None

    def reference(self, image: Any, reason: str, resource: str, region: str) -> None:
        if not isinstance(image, str) or not IMAGE.fullmatch(image):
            self.issue(reason, "missing_or_unsupported_image_reference")
            return
        self.references.append(
            {"kind": reason, "resource": resource, "region": region, "image": image}
        )
        if not image.startswith(PREFIX):
            return
        package, separator, digest = image.partition("@")
        if separator and DIGEST.fullmatch(digest):
            package = package.rsplit(":", 1)[0] if ":" in package else package
            self.protected.setdefault(package + "@" + digest, set()).add(reason + ":" + resource)
        else:
            # A tag cannot establish the image resolved at deployment time.
            package = image.rsplit(":", 1)[0] if ":" in image else image
            self.protected_packages.add(package)
            self.issue(reason, "tag_reference_requires_digest_resolution")

    def images(self, containers: Any, reason: str, resource: str, region: str) -> None:
        if not isinstance(containers, list) or not containers:
            self.issue(reason, "container_images_not_observed")
            return
        for container in containers:
            self.reference(
                container.get("image") if isinstance(container, dict) else None,
                reason,
                resource,
                region,
            )

    def resources(self, plural: str) -> list[tuple[str, str]]:
        rows = self.read(
            plural,
            [
                "run",
                plural,
                "list",
                f"--limit={LIMIT}",
                "--format=json(metadata.name,metadata.labels)",
            ],
            list,
        )
        result = []
        for row in rows or []:
            name = at(row, "metadata", "name")
            region = at(row, "metadata", "labels", "cloud.googleapis.com/location")
            if not isinstance(name, str) or not NAME.fullmatch(name):
                self.issue(plural, "resource_name_not_observed")
            elif not isinstance(region, str) or not REGION_NAME.fullmatch(region):
                self.issue(plural, "resource_region_not_observed")
            else:
                result.append((name, region))
        if len(set(result)) != len(result):
            self.issue(plural, "duplicate_resource_identity")
        return sorted(set(result))

    def jobs(self) -> None:
        for name, region in self.resources("jobs"):
            args = [
                "run",
                "jobs",
                "describe",
                name,
                f"--region={region}",
                "--format=json(metadata.name,spec.template.spec.template.spec.containers[].image)",
            ]
            data = self.read("job:" + name, args, dict)
            if data is not None:
                containers = at(data, "spec", "template", "spec", "template", "spec", "containers")
                self.images(containers, "job", name, region)
            executions = self.read(
                "executions:" + name,
                [
                    "run",
                    "jobs",
                    "executions",
                    "list",
                    f"--job={name}",
                    f"--region={region}",
                    f"--limit={LIMIT}",
                    "--format=json(metadata.name,status.completionTime,spec.template.spec.containers[].image)",
                ],
                list,
            )
            for execution in executions or []:
                if not isinstance(execution, dict):
                    self.issue("executions:" + name, "unexpected_execution_schema")
                    continue
                completion = at(execution, "status", "completionTime")
                if completion is not None:
                    try:
                        parsed = datetime.fromisoformat(completion.replace("Z", "+00:00"))
                        if parsed.tzinfo is None:
                            raise ValueError
                    except (ValueError, TypeError, AttributeError):
                        self.issue("executions:" + name, "completion_timestamp_invalid")
                    else:
                        continue
                execution_name = at(execution, "metadata", "name")
                if not isinstance(execution_name, str) or not NAME.fullmatch(execution_name):
                    self.issue("executions:" + name, "execution_name_not_observed")
                    continue
                # Conservatively retain failed/cancelled records without a
                # completion timestamp as well as pending/running executions.
                containers = at(execution, "spec", "template", "spec", "containers")
                self.images(containers, "unfinished_execution", execution_name, region)

    def services(self) -> None:
        for name, region in self.resources("services"):
            data = self.read(
                "service:" + name,
                [
                    "run",
                    "services",
                    "describe",
                    name,
                    f"--region={region}",
                    "--format=json(metadata.name,spec.template.spec.containers[].image)",
                ],
                dict,
            )
            if data is not None:
                self.images(
                    at(data, "spec", "template", "spec", "containers"), "service", name, region
                )
            revisions = self.read(
                "revisions:" + name,
                [
                    "run",
                    "revisions",
                    "list",
                    f"--service={name}",
                    f"--region={region}",
                    f"--limit={LIMIT}",
                    "--format=json(metadata.name,spec.containers[].image,status.imageDigest)",
                ],
                list,
            )
            for revision in revisions or []:
                if not isinstance(revision, dict):
                    self.issue("revisions:" + name, "unexpected_revision_schema")
                    continue
                revision_name = at(revision, "metadata", "name")
                if not isinstance(revision_name, str) or not NAME.fullmatch(revision_name):
                    self.issue("revisions:" + name, "revision_name_not_observed")
                    continue
                self.images(at(revision, "spec", "containers"), "revision", revision_name, region)
                resolved = at(revision, "status", "imageDigest")
                if resolved:
                    self.reference(resolved, "revision_resolved", revision_name, region)

    def rollback(self) -> dict[str, Any]:
        current = {
            row["image"]
            for row in self.references
            if row["kind"] == "job"
            and row["resource"] == "malscan-v2-static-demo"
            and row["region"] == REGION
        }
        if len(current) != 1:
            self.issue("rollback", "primary_job_image_not_uniquely_observed")
            return {"status": "not_observed", "matching_releases": []}
        matches = []
        root = self.home / ".malscan-v2-operations/maintenance"
        for path in sorted(root.glob("db-*/state.json")):
            try:
                if path.is_symlink() or path.parent.is_symlink() or path.stat().st_size > 131072:
                    raise ValueError
                state = json.loads(path.read_text())
                if not isinstance(state, dict):
                    raise ValueError
            except (OSError, ValueError):
                self.issue("rollback", "checkpoint_unreadable")
                continue
            if (
                state.get("version") != 1
                or state.get("project") != PROJECT
                or state.get("region") != REGION
                or state.get("job") != "malscan-v2-static-demo"
                or state.get("phase") != "promoted"
            ):
                continue
            candidate = state.get("candidate_image")
            if not isinstance(candidate, str):
                self.issue("rollback", "checkpoint_candidate_image_invalid")
                continue
            if candidate not in current:
                continue
            release = state.get("release")
            previous = state.get("previous_image")
            if (
                not isinstance(release, str)
                or not re.fullmatch(r"db-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}", release)
                or not isinstance(previous, str)
                or not re.fullmatch(
                    re.escape(PREFIX + "full-worker@") + r"sha256:[a-f0-9]{64}", previous
                )
            ):
                self.issue("rollback", "matching_checkpoint_image_invalid")
                continue
            self.reference(previous, "rollback_checkpoint", release, REGION)
            matches.append(release)
        if not matches:
            self.issue("rollback", "no_promoted_checkpoint_matches_current_job")
        if len(matches) > 1:
            self.issue("rollback", "multiple_matching_checkpoints_retained")
        return {
            "status": "matched" if matches else "not_observed",
            "matching_releases": matches,
            "scope": (
                "Only promoted checkpoints matching the currently observed primary Job; "
                "no rollback was executed."
            ),
        }

    def inspect(self) -> dict[str, Any]:
        repository = self.read(
            "repository",
            [
                "artifacts",
                "repositories",
                "list",
                f"--location={REGION}",
                f'--filter=name="projects/{PROJECT}/locations/{REGION}/repositories/{REPOSITORY}"',
                "--limit=2",
                "--format=json(name,format,sizeBytes,cleanupPolicies,cleanupPolicyDryRun)",
            ],
            list,
        )
        metadata = None
        expected = f"projects/{PROJECT}/locations/{REGION}/repositories/{REPOSITORY}"
        if repository is not None:
            if (
                len(repository) != 1
                or not isinstance(repository[0], dict)
                or repository[0].get("name") != expected
                or repository[0].get("format") != "DOCKER"
            ):
                self.issue("repository", "repository_identity_or_type_not_verified")
            else:
                metadata = {
                    key: repository[0][key] for key in ("name", "format") if key in repository[0]
                }
                size = repository[0].get("sizeBytes")
                if (
                    isinstance(size, (str, int))
                    and not isinstance(size, bool)
                    and re.fullmatch(r"[0-9]+", str(size))
                ):
                    metadata["sizeBytes"] = int(size)
                if isinstance(repository[0].get("cleanupPolicyDryRun"), bool):
                    metadata["cleanupPolicyDryRun"] = repository[0]["cleanupPolicyDryRun"]
                if "cleanupPolicies" in repository[0]:
                    metadata["cleanupPolicies"] = cleanup_policies(repository[0]["cleanupPolicies"])
        versions = self.read(
            "versions",
            [
                "artifacts",
                "docker",
                "images",
                "list",
                PREFIX[:-1],
                "--include-tags",
                f"--limit={LIMIT}",
                "--format=json(package,version,createTime,updateTime,tags,metadata.imageSizeBytes,metadata.mediaType)",
            ],
            list,
        )
        self.jobs()
        self.services()
        rollback = self.rollback()
        images = []
        seen = set()
        for row in versions or []:
            package = row.get("package") if isinstance(row, dict) else None
            digest = row.get("version") if isinstance(row, dict) else None
            if (
                not isinstance(package, str)
                or not package.startswith(PREFIX)
                or not IMAGE.fullmatch(package)
                or "@" in package
                or ":" in package
                or not isinstance(digest, str)
                or not DIGEST.fullmatch(digest)
            ):
                self.issue("versions", "unsupported_image_version")
                continue
            uri = package + "@" + digest
            if uri in seen:
                self.issue("versions", "duplicate_image_version")
                continue
            seen.add(uri)
            item = {
                "image": uri,
                "classification": "protected_reference"
                if uri in self.protected or package in self.protected_packages
                else "unclassified",
                "protection_reasons": sorted(self.protected.get(uri, set())),
            }
            if package in self.protected_packages:
                item["protection_reasons"].append("unresolved_tag_in_package")
            for key in ("createTime", "updateTime"):
                if isinstance(row.get(key), str) and re.fullmatch(r"[0-9TZ:.+-]+", row[key]):
                    item[key] = row[key]
            tags = row.get("tags")
            if isinstance(tags, str):
                tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
            if isinstance(tags, list) and all(
                isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag)
                for tag in tags
            ):
                item["tags"] = sorted(tags)
                if len(tags) >= 100:
                    self.issue("versions", "tag_list_may_be_truncated")
            else:
                item["tags"] = None
                self.issue("versions", "tags_not_observed")
            details = row.get("metadata", {})
            size = details.get("imageSizeBytes") if isinstance(details, dict) else None
            item["reported_image_size_bytes"] = (
                int(size)
                if isinstance(size, (str, int))
                and not isinstance(size, bool)
                and re.fullmatch(r"[0-9]+", str(size))
                else None
            )
            media_type = details.get("mediaType") if isinstance(details, dict) else None
            item["reported_media_type"] = (
                media_type
                if media_type
                in (
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                else None
            )
            images.append(item)
        missing = sorted(set(self.protected) - seen)
        if missing:
            self.issue("versions", "protected_versions_missing_from_registry_inventory")
        return {
            "schema_version": 1,
            "scope": "read_only_registry_cleanup_inventory",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "project": PROJECT,
            "repository_region": REGION,
            "cloud_run_list_scope": "all project regions with command-scoped run/region cleared",
            "repository": metadata,
            "references": self.references,
            "rollback_checkpoint": rollback,
            "images": sorted(images, key=lambda row: row["image"]),
            "protected_versions_not_listed": missing,
            "readiness_issues": self.issues,
            "oci_manifest_graph_verified": False,
            "deletion_plan_ready": False,
            "remote_mutations": False,
            "cloud_run_executed": False,
            "limitations": [
                "Unclassified does not mean unused or safe to delete.",
                "OCI index children, attestations, shared layers and "
                "non-Cloud-Run consumers are not verified.",
                "Image size sums are not repository billed storage or predicted savings.",
                "Deployment reads are not atomic; re-read before any future deletion.",
                "No image, tag, cleanup policy, build, execution or service was changed.",
            ],
        }


def validate_output(path: Path, home: Path) -> None:
    resolved = path.expanduser().resolve()
    repository = Path(__file__).resolve().parents[2]
    if home.resolve() not in resolved.parents or repository in resolved.parents:
        raise ValueError("Output must be in private HOME, outside the source checkout")
    if path.expanduser().exists() or path.expanduser().is_symlink():
        raise FileExistsError("Output already exists")
    if not path.expanduser().parent.is_dir():
        raise FileNotFoundError("Output parent must exist")


def write_report(path: Path, report: dict[str, Any], home: Path) -> None:
    validate_output(path, home)
    payload = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
    descriptor = os.open(path.expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_output(args.output, Path.home())
    except (OSError, ValueError):
        parser.exit(1, "Use a new private HOME filename outside the source checkout.\n")
    report = Inspector().inspect()
    try:
        write_report(args.output, report, Path.home())
    except (OSError, ValueError):
        parser.exit(1, "Report not saved: use a new private HOME filename outside source.\n")
    counts = {
        name: sum(row["classification"] == name for row in report["images"])
        for name in ("protected_reference", "unclassified")
    }
    print(
        json.dumps(
            {
                "scope": report["scope"],
                "report_file": str(args.output),
                "version_counts": counts,
                "readiness_issues": report["readiness_issues"],
                "rollback_checkpoint": report["rollback_checkpoint"]["status"],
                "deletion_plan_ready": False,
                "remote_mutations": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
