#!/usr/bin/env python3
"""Prepare and provision private, opt-in P0-12 update infrastructure.

Prepare is local-only. Apply creates only the reviewed resources and leaves the
schedule paused and coordinator disabled. Every provider write has a private
intent journal; an unknown response is reconciled by reads, never blindly sent
again. No secret payload or analysis execution permission is used.
"""

from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROJECT = "malscan-v2-poc"
REGION = "us-central1"
JOB = "malscan-v2-static-demo"
PURPOSE = "MalScan P0-12 private database update infrastructure"
SCHEDULE = "23 3,15 * * *"
SCHEDULER = "malscan-v2-database-updates"
TAG = "malscan-db-controller"
ACCOUNT_IDS = {
    "scheduler": "malscan-v2-db-scheduler",
    "controller": "malscan-v2-db-updater",
    "builder": "malscan-v2-db-builder",
}
ACCOUNTS = {key: f"{name}@{PROJECT}.iam.gserviceaccount.com" for key, name in ACCOUNT_IDS.items()}
ROOT = Path(__file__).resolve().parents[2]
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
HOSTS = {
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "storage.googleapis.com",
    "cloudscheduler.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "cloudbuild.googleapis.com",
    "serviceusage.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
}
APIS = (
    "cloudbuild.googleapis.com",
    "cloudscheduler.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
)


class SetupError(RuntimeError):
    """A fixed safe error code; provider bodies and credentials are excluded."""


def module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def write_private(path: Path, value: Any) -> None:
    maintenance = module("setup_maintenance", "maintain-demo.py")
    maintenance.write_private(path, value)


def read_private(path: Path) -> Any:
    maintenance = module("setup_maintenance", "maintain-demo.py")
    return maintenance.read_private(path)


def account_resource(email: str) -> str:
    return f"projects/{PROJECT}/serviceAccounts/{email}"


def operator_member(value: str | None) -> str:
    if value is None:
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "account"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError("operator_identity_unavailable") from None
        if result.returncode:
            raise SetupError("operator_identity_unavailable")
        email = result.stdout.strip()
        value = ("serviceAccount:" if email.endswith(".gserviceaccount.com") else "user:") + email
    if not re.fullmatch(r"(?:user|serviceAccount):[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+", value):
        raise SetupError("operator_identity_invalid")
    return value


def role_documents() -> dict[str, dict]:
    permissions = {
        "malscanDbSchedule": ["cloudbuild.builds.create", "serviceusage.services.use"],
        "malscanDbControl": [
            "artifactregistry.repositories.list",
            "cloudbuild.builds.create",
            "cloudbuild.builds.get",
            "cloudbuild.builds.list",
            "logging.logEntries.list",
            "logging.logs.list",
            "resourcemanager.projects.get",
            "serviceusage.services.use",
        ],
        "malscanDbJobUpdate": ["run.jobs.update"],
        "malscanDbVersionDelete": [
            "artifactregistry.tags.delete",
            "artifactregistry.versions.delete",
        ],
        "malscanDbBucketGet": ["storage.buckets.get"],
    }
    return {
        name: {
            "title": name,
            "description": PURPOSE,
            "stage": "GA",
            "includedPermissions": sorted(values),
        }
        for name, values in permissions.items()
    }


def bucket_document(bucket: str) -> dict:
    return {
        "name": bucket,
        "location": REGION,
        "storageClass": "STANDARD",
        "labels": {"malscan-p012": "database-updates"},
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced",
        },
        "versioning": {"enabled": False},
        "softDeletePolicy": {"retentionDurationSeconds": "0"},
        "lifecycle": {
            "rule": [
                {
                    "action": {"type": "Delete"},
                    "condition": {"age": 7, "matchesPrefix": ["build-sources/"]},
                }
            ]
        },
    }


def checkpoint_files(directory: Path, repository: Path) -> dict[str, dict]:
    maintenance = module("setup_maintenance", "maintain-demo.py")
    tool = maintenance.Maintenance(directory, repository)
    state = tool.load()
    if state.get("phase") != "promoted":
        raise SetupError("approved_maintenance_must_be_promoted")
    if state.get("source_sha256") != maintenance.source_fingerprint(repository):
        raise SetupError("approved_application_source_differs")
    files = {}
    for name in ("state.json", "job-before.json", "build.json", "engine-controls.json"):
        path = directory / name
        if not path.exists():
            raise SetupError("approved_checkpoint_incomplete")
        files[name] = read_private(path)
    return files


def archive_source(repository: Path) -> tuple[str, bytes]:
    try:
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=repository, text=True
        )
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        raw = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=repository)
    except (OSError, subprocess.CalledProcessError):
        raise SetupError("approved_git_archive_unavailable") from None
    if dirty or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise SetupError("approved_worktree_must_be_clean")
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        names = {member.name for member in archive.getmembers()}
        required = {
            "deployment/cloud-run/auto_update.py",
            "deployment/cloud-run/auto_state.py",
            "deployment/cloud-run/auto_retention.py",
            "deployment/cloud-run/auto_monitoring.py",
            "deployment/cloud-run/cloudbuild-auto-update.json",
        }
        if not required <= names:
            raise SetupError("approved_bundle_missing_update_controller")
        if any(
            m.issym() or m.islnk() or m.name.startswith("/") or ".." in Path(m.name).parts
            for m in archive.getmembers()
        ):
            raise SetupError("approved_archive_contains_links_or_unsafe_paths")
    bundle = gzip.compress(raw, mtime=0)
    if len(raw) > MAX_BUNDLE_BYTES or len(bundle) > MAX_BUNDLE_BYTES:
        raise SetupError("approved_bundle_too_large")
    return revision, bundle


def verify_archive_source(bundle: bytes, expected_source_sha256: str) -> None:
    """Verify the archive actually contains the approved application inputs."""
    maintenance = module("setup_archive_maintenance", "maintain-demo.py")
    try:
        raw = gzip.GzipFile(fileobj=io.BytesIO(bundle)).read(MAX_BUNDLE_BYTES + 1)
        if len(raw) > MAX_BUNDLE_BYTES:
            raise ValueError
        with tempfile.TemporaryDirectory(prefix="malscan-approved-source-") as directory:
            root = Path(directory)
            seen = set()
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                for member in archive:
                    parts = member.name.rstrip("/").split("/")
                    if (
                        member.name.startswith("/")
                        or "\\" in member.name
                        or any(part in {"", ".", ".."} for part in parts)
                        or member.name in seen
                        or not (member.isdir() or member.isfile())
                    ):
                        raise ValueError
                    seen.add(member.name)
                    target = root.joinpath(*parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is None or member.size > MAX_BUNDLE_BYTES:
                            raise ValueError
                        with target.open("xb") as stream:
                            stream.write(source.read(MAX_BUNDLE_BYTES + 1))
                        if target.stat().st_size != member.size:
                            raise ValueError
            if maintenance.source_fingerprint(root) != expected_source_sha256:
                raise ValueError
    except (OSError, ValueError, tarfile.TarError, EOFError):
        raise SetupError("approved_archive_source_differs") from None


def normalized_metric(value: dict) -> dict:
    result = copy.deepcopy(value)
    result.setdefault("disabled", False)
    return result


def normalized_policy(value: dict) -> dict:
    result = copy.deepcopy(value)
    for condition in result.get("conditions", []):
        condition.pop("name", None)  # Monitoring adds this output-only identity.
        if "conditionThreshold" in condition:
            condition["conditionThreshold"].setdefault("thresholdValue", 0)
        for kind in ("conditionThreshold", "conditionAbsent"):
            for aggregation in condition.get(kind, {}).get("aggregations", []):
                aggregation.setdefault("groupByFields", [])
    return result


def normalized_scheduler(value: dict) -> dict:
    result = copy.deepcopy(value)
    result.setdefault("retryConfig", {}).setdefault("retryCount", 0)
    return result


def prepare(
    repository: Path,
    maintenance_directory: Path,
    channel: str,
    output: Path,
    *,
    bucket: str = PROJECT + "-db-operations",
    operator: str | None = None,
) -> dict:
    repository, output = repository.resolve(), output.resolve()
    if output == repository or repository in output.parents or output.exists():
        raise SetupError("plan_must_be_new_and_outside_checkout")
    if not re.fullmatch(re.escape(PROJECT) + r"-[a-z0-9-]{3,35}", bucket):
        raise SetupError("private_operations_bucket_invalid")
    monitoring = module("setup_monitoring", "auto_monitoring.py").monitoring_plan(PROJECT, channel)
    files = checkpoint_files(maintenance_directory, repository)
    revision, bundle = archive_source(repository)
    verify_archive_source(bundle, files["state.json"]["source_sha256"])
    bundle_sha = hashlib.sha256(bundle).hexdigest()
    auto = module("setup_controller", "auto_update.py")
    initial = auto.initial_state(
        files, revision, files["state.json"]["source_sha256"], bundle_sha, channel
    )
    template = json.loads(
        (repository / "deployment/cloud-run/cloudbuild-auto-update.json").read_text()
    )
    plan = {
        "schema_version": 1,
        "scope": "reviewed_private_database_update_setup",
        "project": PROJECT,
        "region": REGION,
        "job": JOB,
        "bucket": bucket,
        "source_commit": revision,
        "source_sha256": files["state.json"]["source_sha256"],
        "bundle_sha256": bundle_sha,
        "bundle_object": f"bundles/{revision}.tar.gz",
        "notification_channel": channel,
        "operator_member": operator_member(operator),
        "service_accounts": ACCOUNTS,
        "custom_roles": role_documents(),
        "bucket_configuration": bucket_document(bucket),
        "controller_build_template": template,
        "scheduler": {"name": SCHEDULER, "schedule": SCHEDULE, "time_zone": "UTC"},
        "monitoring": monitoring,
        "initial_state": initial,
        "activation": (
            "apply leaves disabled state and paused scheduler; probe then explicit enable"
        ),
        "source_retention": (
            "Only build-sources/ expires after seven days; bundles and state do not"
        ),
        "cost_boundary": (
            "New bucket has soft delete disabled; existing buckets are never changed; "
            "not a zero-cost guarantee"
        ),
    }
    output.mkdir(mode=0o700, parents=True)
    bundle_path = output / "source.tar.gz"
    with bundle_path.open("xb") as stream:
        os.chmod(bundle_path, 0o600)
        stream.write(bundle)
    write_private(output / "plan.json", {"sha256": digest(plan), "plan": plan})
    return {
        "scope": "local_setup_plan_only",
        "plan_dir": str(output),
        "source_commit": revision,
        "bundle_sha256": bundle_sha,
        "remote_mutations": False,
        "automatic_updates_enabled": False,
    }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class REST:
    def __init__(self):
        self.opener = build_opener(ProxyHandler(), _NoRedirect())

    def request(
        self,
        method: str,
        url: str,
        payload: Any = None,
        *,
        raw: bytes | None = None,
        content_type: str = "application/json",
        missing_ok: bool = False,
    ):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc not in HOSTS or parsed.fragment:
            raise SetupError("setup_endpoint_invalid")
        env = dict(
            os.environ,
            CLOUDSDK_CORE_LOG_HTTP="false",
            CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
            CLOUDSDK_CORE_DISABLE_PROMPTS="true",
        )
        try:
            token = subprocess.run(
                ["gcloud", "auth", "print-access-token", f"--project={PROJECT}", "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError("setup_auth_unavailable") from None
        value = token.stdout.strip()
        if token.returncode or not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,8192}={0,2}", value):
            raise SetupError("setup_auth_unavailable")
        body = raw if raw is not None else canonical(payload) if payload is not None else None
        request = Request(
            url,
            method=method,
            data=body,
            headers={"Authorization": "Bearer " + value, "Content-Type": content_type},
        )
        try:
            with self.opener.open(request, timeout=90) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError
            return json.loads(data) if data else {}
        except HTTPError as error:
            if error.code == 404 and missing_ok and method == "GET":
                return None
            raise SetupError("setup_provider_request_failed") from None
        except Exception:
            raise SetupError("setup_provider_response_unknown") from None


def subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and subset(v, actual[k]) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(subset(left, right) for left, right in zip(expected, actual))
        )
    return expected == actual


class Provisioner:
    def __init__(self, directory: Path, *, rest=None, store=None, live_job=None):
        if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077:
            raise SetupError("setup_plan_directory_must_be_private")
        self.directory = directory.resolve()
        wrapped = read_private(self.directory / "plan.json")
        self.plan = wrapped["plan"]
        if (
            wrapped.get("sha256") != digest(self.plan)
            or self.plan.get("project") != PROJECT
            or self.plan.get("region") != REGION
            or self.plan.get("schema_version") != 1
        ):
            raise SetupError("setup_plan_changed_or_invalid")
        p = self.plan
        expected_monitoring = module(
            "setup_validated_monitoring", "auto_monitoring.py"
        ).monitoring_plan(PROJECT, p.get("notification_channel", ""))
        template = json.loads(
            (ROOT / "deployment/cloud-run/cloudbuild-auto-update.json").read_text()
        )
        if (
            p.get("scope") != "reviewed_private_database_update_setup"
            or p.get("job") != JOB
            or not re.fullmatch(re.escape(PROJECT) + r"-[a-z0-9-]{3,35}", str(p.get("bucket", "")))
            or not re.fullmatch(r"[a-f0-9]{40}", str(p.get("source_commit", "")))
            or any(
                not re.fullmatch(r"[a-f0-9]{64}", str(p.get(k, "")))
                for k in ("source_sha256", "bundle_sha256")
            )
            or p.get("bundle_object") != "bundles/" + p["source_commit"] + ".tar.gz"
            or p.get("service_accounts") != ACCOUNTS
            or p.get("custom_roles") != role_documents()
            or p.get("bucket_configuration") != bucket_document(p["bucket"])
            or p.get("controller_build_template") != template
            or p.get("scheduler") != {"name": SCHEDULER, "schedule": SCHEDULE, "time_zone": "UTC"}
            or p.get("monitoring") != expected_monitoring
        ):
            raise SetupError("setup_plan_fixed_scope_invalid")
        operator_member(p.get("operator_member", "invalid"))
        initial = p.get("initial_state", {})
        if (
            initial.get("version") != 1
            or initial.get("project") != PROJECT
            or initial.get("region") != REGION
            or initial.get("job") != JOB
            or initial.get("enabled") is not False
            or initial.get("active") is not None
            or initial.get("source")
            != {
                "commit": p["source_commit"],
                "sha256": p["source_sha256"],
                "bundle_sha256": p["bundle_sha256"],
            }
        ):
            raise SetupError("setup_plan_initial_state_invalid")
        registered = copy.deepcopy(initial)
        registered["source"]["storage_source"] = {
            "bucket": p["bucket"],
            "object": p["bundle_object"],
            "generation": "1",
        }
        module("setup_plan_controller", "auto_update.py").validate_state(registered)
        blob = self.directory / "source.tar.gz"
        if (
            blob.is_symlink()
            or not blob.is_file()
            or blob.stat().st_mode & 0o077
            or blob.stat().st_size > MAX_BUNDLE_BYTES
            or hashlib.sha256(blob.read_bytes()).hexdigest() != self.plan["bundle_sha256"]
        ):
            raise SetupError("setup_source_bundle_changed")
        self.rest = rest or REST()
        self.store = store or module("setup_state", "auto_state.py").Store(self.plan["bucket"])
        self.live_job = live_job or module("setup_maintenance", "maintain-demo.py").Gcloud().job
        self._verify_only = False
        self.journal_path = self.directory / "apply-state.json"
        self.journal = (
            read_private(self.journal_path)
            if self.journal_path.exists()
            else {
                "version": 1,
                "plan_sha256": wrapped["sha256"],
                "operations": {},
                "phase": "prepared",
            }
        )
        if (
            self.journal.get("version") != 1
            or self.journal.get("plan_sha256") != wrapped["sha256"]
            or not isinstance(self.journal.get("operations"), dict)
            or self.journal.get("phase")
            not in {"prepared", "installed_paused", "activation_submitted", "pausing"}
            or any(
                not isinstance(e, dict) or e.get("status") not in {"pending", "confirmed"}
                for e in self.journal["operations"].values()
            )
        ):
            raise SetupError("setup_journal_plan_changed")

    def save(self):
        write_private(self.journal_path, self.journal)

    def ensure(self, name, read, matches, write, *, permit_existing=False):
        entry = self.journal["operations"].get(name)
        current = read()
        if self._verify_only:
            if entry is None or current is None or not matches(current):
                raise SetupError("setup_installation_drift")
            return current
        if current is not None and matches(current):
            if entry is None and not permit_existing:
                raise SetupError("setup_existing_resource_requires_review")
            self.journal["operations"][name] = {"status": "confirmed"}
            self.save()
            return current
        if current is not None:
            raise SetupError("setup_resource_differs_from_plan")
        if entry is not None:
            raise SetupError("setup_pending_write_requires_reconciliation")
        self.journal["operations"][name] = {
            "status": "pending",
            "intent_at": datetime.now(timezone.utc).isoformat(),
        }
        self.save()
        write()
        self.journal["operations"][name]["provider_accepted"] = True
        self.save()
        current = read()
        if current is None or not matches(current):
            raise SetupError("setup_write_not_verified")
        self.journal["operations"][name] = {"status": "confirmed"}
        self.save()
        return current

    def get(self, url):
        return self.rest.request("GET", url, missing_ok=True)

    def _apis(self):
        project = self.rest.request(
            "GET", f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}"
        )
        number = project.get("projectNumber")
        if project.get("projectId") != PROJECT or not re.fullmatch(r"[0-9]+", str(number)):
            raise SetupError("setup_project_identity_invalid")
        self.journal["project_number"] = str(number)
        self.save()
        for api in APIS:
            url = f"https://serviceusage.googleapis.com/v1/projects/{number}/services/{api}"

            def read_service(url=url):
                value = self.get(url)
                return value if value and value.get("state") == "ENABLED" else None

            def enable_service(url=url):
                self.rest.request("POST", url + ":enable", {})
                for _ in range(20):
                    if read_service(url):
                        return
                    time.sleep(2)

            self.ensure(
                "api:" + api,
                read_service,
                lambda v: v["state"] == "ENABLED",
                enable_service,
                permit_existing=True,
            )

    def _managed_agents(self):
        number = self.journal["project_number"]
        policy = self.rest.request(
            "POST",
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
        )
        for service, role in (
            ("cloudscheduler", "roles/cloudscheduler.serviceAgent"),
            ("cloudbuild", "roles/cloudbuild.serviceAgent"),
        ):
            member = f"serviceAccount:service-{number}@gcp-sa-{service}.iam.gserviceaccount.com"
            if not any(
                b.get("role") == role and not b.get("condition") and member in b.get("members", [])
                for b in policy.get("bindings", [])
            ):
                raise SetupError("setup_managed_service_agent_role_missing")

    def _accounts_and_roles(self):
        for key, account_id in ACCOUNT_IDS.items():
            email = ACCOUNTS[key]
            url = "https://iam.googleapis.com/v1/" + account_resource(email)
            desired = {"email": email, "displayName": account_id, "description": PURPOSE}
            self.ensure(
                "account:" + key,
                lambda url=url: self.get(url),
                lambda value, desired=desired: subset(desired, value) and not value.get("disabled"),
                lambda account_id=account_id: self.rest.request(
                    "POST",
                    f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts",
                    {
                        "accountId": account_id,
                        "serviceAccount": {"displayName": account_id, "description": PURPOSE},
                    },
                ),
            )
        for name, role in self.plan["custom_roles"].items():
            url = f"https://iam.googleapis.com/v1/projects/{PROJECT}/roles/{name}"
            self.ensure(
                "role:" + name,
                lambda url=url: self.get(url),
                lambda value, role=role: subset(role, value) and not value.get("deleted"),
                lambda name=name, role=role: self.rest.request(
                    "POST",
                    f"https://iam.googleapis.com/v1/projects/{PROJECT}/roles",
                    {"roleId": name, "role": role},
                ),
            )

    def _bucket(self):
        bucket = self.plan["bucket"]
        expected = copy.deepcopy(self.plan["bucket_configuration"])
        expected["location"] = expected["location"].lower()

        def matches(value):
            value = copy.deepcopy(value)
            value["location"] = str(value.get("location", "")).lower()
            value["versioning"] = {"enabled": value.get("versioning", {}).get("enabled", False)}
            value["softDeletePolicy"] = {
                "retentionDurationSeconds": str(
                    value.get("softDeletePolicy", {}).get("retentionDurationSeconds", "0")
                )
            }
            return (
                subset(expected, value)
                and value.get("lifecycle") == expected["lifecycle"]
                and str(value.get("projectNumber")) == self.journal["project_number"]
                and not value.get("retentionPolicy")
            )

        self.ensure(
            "operations-bucket",
            lambda: self.get(f"https://storage.googleapis.com/storage/v1/b/{bucket}"),
            matches,
            lambda: self.rest.request(
                "POST",
                "https://storage.googleapis.com/storage/v1/b?" + urlencode({"project": PROJECT}),
                self.plan["bucket_configuration"],
            ),
        )

    def _binding(
        self,
        name,
        get_url,
        set_url,
        role,
        member,
        *,
        get_method="GET",
        set_method="POST",
        condition=None,
        get_body_options=True,
    ):
        def read():
            policy = self.rest.request(
                get_method,
                get_url,
                {"options": {"requestedPolicyVersion": 3}}
                if get_method == "POST" and get_body_options
                else None,
            )
            if not isinstance(policy, dict):
                raise SetupError("setup_iam_policy_invalid")
            for binding in policy.get("bindings", []):
                if (
                    binding.get("role") == role
                    and binding.get("condition") == condition
                    and member in binding.get("members", [])
                ):
                    return policy
            return None

        def write():
            policy = self.rest.request(
                get_method,
                get_url,
                {"options": {"requestedPolicyVersion": 3}}
                if get_method == "POST" and get_body_options
                else None,
            )
            if not policy.get("etag"):
                raise SetupError("setup_iam_etag_unavailable")
            policy = copy.deepcopy(policy)
            if condition:
                policy["version"] = 3
            for binding in policy.setdefault("bindings", []):
                if binding.get("role") == role and binding.get("condition") == condition:
                    binding["members"] = sorted(set(binding.get("members", [])) | {member})
                    break
            else:
                binding = {"role": role, "members": [member]}
                if condition:
                    binding["condition"] = condition
                policy["bindings"].append(binding)
            self.rest.request(
                set_method, set_url, policy if set_method == "PUT" else {"policy": policy}
            )

        self.ensure("binding:" + name, read, lambda v: True, write, permit_existing=True)

    def _iam(self):
        project = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}"

        def project_binding(name, role, account):
            self._binding(
                name,
                project + ":getIamPolicy",
                project + ":setIamPolicy",
                role,
                "serviceAccount:" + account,
                get_method="POST",
            )

        for name, role, account in (
            (
                "scheduler-build",
                f"projects/{PROJECT}/roles/malscanDbSchedule",
                ACCOUNTS["scheduler"],
            ),
            (
                "controller-build-read",
                f"projects/{PROJECT}/roles/malscanDbControl",
                ACCOUNTS["controller"],
            ),
            ("controller-run-read", "roles/run.viewer", ACCOUNTS["controller"]),
            ("controller-log-write", "roles/logging.logWriter", ACCOUNTS["controller"]),
            ("builder-log-write", "roles/logging.logWriter", ACCOUNTS["builder"]),
        ):
            project_binding(name, role, account)
        for name, target, member in (
            (
                "scheduler-act-controller",
                ACCOUNTS["controller"],
                "serviceAccount:" + ACCOUNTS["scheduler"],
            ),
            (
                "controller-act-builder",
                ACCOUNTS["builder"],
                "serviceAccount:" + ACCOUNTS["controller"],
            ),
            (
                "controller-act-runtime",
                f"malscan-v2-static-demo@{PROJECT}.iam.gserviceaccount.com",
                "serviceAccount:" + ACCOUNTS["controller"],
            ),
            ("operator-act-controller", ACCOUNTS["controller"], self.plan["operator_member"]),
            ("operator-act-scheduler", ACCOUNTS["scheduler"], self.plan["operator_member"]),
        ):
            url = "https://iam.googleapis.com/v1/" + account_resource(target)
            self._binding(
                name,
                url + ":getIamPolicy?options.requestedPolicyVersion=3",
                url + ":setIamPolicy",
                "roles/iam.serviceAccountUser",
                member,
                get_method="POST",
                get_body_options=False,
            )
        job = f"https://run.googleapis.com/v2/projects/{PROJECT}/locations/{REGION}/jobs/{JOB}"
        self._binding(
            "controller-job-update",
            job + ":getIamPolicy?options.requestedPolicyVersion=3",
            job + ":setIamPolicy",
            f"projects/{PROJECT}/roles/malscanDbJobUpdate",
            "serviceAccount:" + ACCOUNTS["controller"],
        )
        repository = f"https://artifactregistry.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/repositories/malscan-v2-poc"
        for name, role, account in (
            ("controller-registry-read", "roles/artifactregistry.reader", ACCOUNTS["controller"]),
            (
                "controller-registry-delete",
                f"projects/{PROJECT}/roles/malscanDbVersionDelete",
                ACCOUNTS["controller"],
            ),
            ("builder-registry-write", "roles/artifactregistry.writer", ACCOUNTS["builder"]),
        ):
            self._binding(
                name,
                repository + ":getIamPolicy?options.requestedPolicyVersion=3",
                repository + ":setIamPolicy",
                role,
                "serviceAccount:" + account,
            )
        bucket = self.plan["bucket"]
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/iam"
        self._binding(
            "controller-bucket-metadata",
            url + "?optionsRequestedPolicyVersion=3",
            url,
            f"projects/{PROJECT}/roles/malscanDbBucketGet",
            "serviceAccount:" + ACCOUNTS["controller"],
            set_method="PUT",
        )
        self._binding(
            "controller-private-state",
            url + "?optionsRequestedPolicyVersion=3",
            url,
            "roles/storage.objectAdmin",
            "serviceAccount:" + ACCOUNTS["controller"],
            set_method="PUT",
        )
        self._binding(
            "builder-sources-only",
            url + "?optionsRequestedPolicyVersion=3",
            url,
            "roles/storage.objectViewer",
            "serviceAccount:" + ACCOUNTS["builder"],
            set_method="PUT",
            condition={
                "title": "OnlyBuildSourceArchives",
                "expression": (
                    f'resource.name.startsWith("projects/_/buckets/{bucket}/objects/'
                    'build-sources/")'
                ),
            },
        )

    def _bundle(self):
        p = self.plan
        url = f"https://storage.googleapis.com/storage/v1/b/{p['bucket']}/o/" + quote(
            p["bundle_object"], safe=""
        )
        blob = (self.directory / "source.tar.gz").read_bytes()
        md5 = base64.b64encode(hashlib.md5(blob, usedforsecurity=False).digest()).decode()

        def matches(value):
            return (
                value.get("metadata")
                == {"sha256": p["bundle_sha256"], "source_commit": p["source_commit"]}
                and value.get("md5Hash") == md5
                and str(value.get("size")) == str(len(blob))
                and value.get("contentType") == "application/gzip"
                and re.fullmatch(r"[1-9][0-9]*", str(value.get("generation", ""))) is not None
            )

        def write():
            metadata = {
                "name": p["bundle_object"],
                "contentType": "application/gzip",
                "md5Hash": md5,
                "metadata": {"sha256": p["bundle_sha256"], "source_commit": p["source_commit"]},
            }
            boundary = "malscan-" + p["bundle_sha256"]
            data = (
                f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode()
                + canonical(metadata)
                + f"\r\n--{boundary}\r\nContent-Type: application/gzip\r\n\r\n".encode()
                + (self.directory / "source.tar.gz").read_bytes()
                + f"\r\n--{boundary}--\r\n".encode()
            )
            upload = f"https://storage.googleapis.com/upload/storage/v1/b/{p['bucket']}/o?uploadType=multipart&ifGenerationMatch=0"
            self.rest.request(
                "POST", upload, raw=data, content_type="multipart/related; boundary=" + boundary
            )

        result = self.ensure("approved-bundle", lambda: self.get(url), matches, write)
        return str(result["generation"])

    def _current(self):
        maintenance = module("setup_maintenance", "maintain-demo.py")
        job = self.live_job()
        expected = self.plan["initial_state"]["current"]["configuration"]
        if not maintenance.job_ready(job) or not maintenance.configurations_equal(
            expected, maintenance.job_configuration(job)
        ):
            raise SetupError("setup_current_job_changed")
        created = self.plan["initial_state"]["current"]["daily_created_at_epoch"]
        if not integer(created) or not 0 <= time.time() - created <= 604800:
            raise SetupError("setup_approved_database_stale")

    def _state(self, generation):
        self._current()
        initial = copy.deepcopy(self.plan["initial_state"])
        initial["source"]["storage_source"] = {
            "bucket": self.plan["bucket"],
            "object": self.plan["bundle_object"],
            "generation": generation,
        }
        module("setup_registered_controller", "auto_update.py").validate_state(initial)
        current, _ = self.store.load_json("state.json")
        existing = self.journal["operations"].get("initial-state")
        if current is not None:
            if (
                not existing
                or current.get("source") != initial["source"]
                or any(
                    current.get(k) != initial.get(k)
                    for k in ("version", "project", "region", "job", "current")
                )
                or current.get("enabled") is not False
                or current.get("active") is not None
            ):
                raise SetupError("setup_existing_state_requires_review")
        else:
            if existing:
                raise SetupError("setup_state_write_requires_reconciliation")
            self.journal["operations"]["initial-state"] = {"status": "pending"}
            self.save()
            self.store.put_json("state.json", initial, 0)
        self.journal["operations"]["initial-state"] = {"status": "confirmed"}
        self.save()

    def build_request(self):
        source = self.journal.get("storage_source")
        if not source:
            raise SetupError("setup_bundle_generation_unavailable")
        request = copy.deepcopy(self.plan["controller_build_template"])
        request["source"] = {"storageSource": source}
        request["serviceAccount"] = account_resource(ACCOUNTS["controller"])
        request.setdefault("substitutions", {})["_OPS_BUCKET"] = self.plan["bucket"]
        request["tags"] = [TAG]
        return request

    def scheduler_document(self):
        return {
            "name": f"projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}",
            "description": PURPOSE,
            "schedule": self.plan["scheduler"]["schedule"],
            "timeZone": "UTC",
            "attemptDeadline": "30s",
            "retryConfig": {"retryCount": 0},
            "httpTarget": {
                "uri": f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/builds",
                "httpMethod": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": base64.b64encode(canonical(self.build_request())).decode(),
                "oauthToken": {
                    "serviceAccountEmail": ACCOUNTS["scheduler"],
                    "scope": "https://www.googleapis.com/auth/cloud-platform",
                },
            },
        }

    def _monitoring(self):
        channel = self.rest.request(
            "GET", "https://monitoring.googleapis.com/v3/" + self.plan["notification_channel"]
        )
        if (
            channel.get("name") != self.plan["notification_channel"]
            or channel.get("enabled") is not True
            or channel.get("verificationStatus") == "UNVERIFIED"
        ):
            raise SetupError("setup_notification_channel_not_ready")
        for metric in self.plan["monitoring"]["log_metrics"]:
            base = f"https://logging.googleapis.com/v2/projects/{PROJECT}/metrics"
            name = metric["name"]
            self.ensure(
                "metric:" + name,
                lambda base=base, name=name: self.get(base + "/" + name),
                lambda value, metric=metric: subset(metric, normalized_metric(value)),
                lambda base=base, metric=metric: self.rest.request("POST", base, metric),
            )
        policies = []
        for index, desired in enumerate(self.plan["monitoring"]["alert_policies"]):
            base = f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/alertPolicies"

            def read_policy(desired=desired, base=base):
                listed = self.rest.request("GET", base + "?pageSize=100")
                if listed.get("nextPageToken"):
                    raise SetupError("setup_policy_list_truncated")
                matches = [
                    p
                    for p in listed.get("alertPolicies", [])
                    if p.get("displayName") == desired["displayName"]
                ]
                if len(matches) > 1:
                    raise SetupError("setup_monitoring_policy_ambiguous")
                return matches[0] if matches else None

            comparison = copy.deepcopy(desired)
            if self._verify_only:
                comparison.pop("enabled", None)
            policy = self.ensure(
                "policy:" + str(index),
                read_policy,
                lambda value, desired=comparison: subset(desired, normalized_policy(value)),
                lambda base=base, desired=desired: self.rest.request("POST", base, desired),
            )
            if not re.fullmatch(
                r"projects/" + PROJECT + r"/alertPolicies/[0-9]+", policy.get("name", "")
            ):
                raise SetupError("setup_monitoring_policy_identity_invalid")
            policies.append(policy["name"])
        if self._verify_only and self.journal.get("policies") != policies:
            raise SetupError("setup_monitoring_policy_identity_changed")
        self.journal["policies"] = policies
        self.save()

    def _approved_state(self, *, check_current=True):
        state, generation = self.store.load_json("state.json")
        expected_source = {
            "commit": self.plan["source_commit"],
            "sha256": self.plan["source_sha256"],
            "bundle_sha256": self.plan["bundle_sha256"],
            "storage_source": self.journal.get("storage_source"),
        }
        if (
            not isinstance(state, dict)
            or not integer(state.get("version"))
            or state["version"] != 1
            or state.get("project") != PROJECT
            or state.get("region") != REGION
            or state.get("job") != JOB
            or not isinstance(state.get("enabled"), bool)
            or not subset(expected_source, state.get("source"))
        ):
            raise SetupError("setup_registered_state_differs")
        module("setup_live_controller", "auto_update.py").validate_state(state)
        maintenance = module("setup_current_maintenance", "maintain-demo.py")
        try:
            current = state["current"]
            maintenance.immutable_image(current["image"])
            maintenance.immutable_image(current["rollback_image"])
            if current["image"] == current["rollback_image"]:
                raise ValueError
            if check_current:
                observed = self.live_job()
                if not maintenance.job_ready(observed) or not maintenance.configurations_equal(
                    current["configuration"], maintenance.job_configuration(observed)
                ):
                    raise ValueError
                created = current["daily_created_at_epoch"]
                if not integer(created) or not 0 <= time.time() - created <= 604800:
                    raise ValueError
        except (KeyError, TypeError, ValueError):
            raise SetupError("setup_current_job_or_database_differs") from None
        return state, generation

    def _verify_installation(self):
        self._verify_only = True
        try:
            self._managed_agents()
            self._accounts_and_roles()
            self._bucket()
            self._iam()
            generation = self._bundle()
            if generation != self.journal["storage_source"]["generation"]:
                raise SetupError("setup_source_generation_changed")
            self._monitoring()
            url = f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
            scheduler = self.get(url)
            if scheduler is None or not subset(
                self.scheduler_document(), normalized_scheduler(scheduler)
            ):
                raise SetupError("setup_scheduler_configuration_changed")
            if scheduler.get("state") not in {"PAUSED", "ENABLED"}:
                raise SetupError("setup_scheduler_state_invalid")
            if scheduler["state"] == "ENABLED" and not self.journal["operations"].get(
                "resume-scheduler"
            ):
                raise SetupError("setup_scheduler_enabled_outside_activation")
        finally:
            self._verify_only = False

    def _post_intent_healthy(self, state, intent_at):
        if not intent_at or not state.get("last_healthy_at"):
            return False
        try:
            after = datetime.fromisoformat(intent_at.replace("Z", "+00:00"))
            healthy = datetime.fromisoformat(state["last_healthy_at"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if after.tzinfo is None or healthy.tzinfo is None:
                return False
            owner = state.get("last_controller_build_id")
            return (
                healthy >= after
                and 0 <= (now - healthy).total_seconds() <= 86400
                and self._build_id(owner)
            )
        except (TypeError, ValueError):
            return False

    def apply(self):
        if self.journal.get("phase") in {"installed_paused", "activation_submitted"}:
            return self.status()
        self._apis()
        self._managed_agents()
        self._accounts_and_roles()
        self._bucket()
        self._iam()
        generation = self._bundle()
        self.journal["storage_source"] = {
            "bucket": self.plan["bucket"],
            "object": self.plan["bundle_object"],
            "generation": generation,
        }
        self.save()
        self._state(generation)
        self._monitoring()
        desired = self.scheduler_document()
        base = (
            f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs"
        )
        url = base + "/" + SCHEDULER
        self.ensure(
            "scheduler",
            lambda: self.get(url),
            lambda value: subset(desired, normalized_scheduler(value)),
            lambda: self.rest.request("POST", base, desired),
        )
        self.ensure(
            "scheduler-paused",
            lambda: self.get(url) if self.get(url).get("state") == "PAUSED" else None,
            lambda v: v["state"] == "PAUSED",
            lambda: self.rest.request("POST", url + ":pause", {}),
            permit_existing=True,
        )
        self.journal["phase"] = "installed_paused"
        self.save()
        return self.status()

    def probe(self):
        if self.journal.get("phase") != "installed_paused":
            raise SetupError("setup_probe_requires_paused_installation")
        self._verify_installation()
        state, _ = self._approved_state()
        if state.get("enabled") is not False or state.get("active") is not None:
            raise SetupError("setup_probe_requires_disabled_idle_state")
        entry = self.journal["operations"].get("initial-probe")
        base = f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/builds"
        if entry:
            if entry.get("status") != "confirmed":
                # An unknown create is never repeated. Discover only our unique
                # intent tag, then validate the entire immutable request.
                listed = self.rest.request(
                    "GET",
                    base
                    + "?"
                    + urlencode(
                        {
                            "filter": "tags=" + entry["intent_tag"],
                            "pageSize": 100,
                        }
                    ),
                )
                if listed.get("nextPageToken"):
                    raise SetupError("setup_probe_build_list_truncated")
                desired = self.build_request()
                desired["tags"].append(entry["intent_tag"])
                matches = [
                    b for b in listed.get("builds", []) if entry["intent_tag"] in b.get("tags", [])
                ]
                if len(matches) != 1 or not subset(desired, matches[0]):
                    raise SetupError("setup_probe_submission_requires_reconciliation")
                entry["build_id"] = matches[0].get("id")
                if not self._build_id(entry["build_id"]):
                    raise SetupError("setup_probe_build_identity_unknown")
                entry["status"] = "confirmed"
                self.save()
            return {
                "scope": "initial_paused_health_probe",
                "build_id": entry["build_id"],
                "resubmitted": False,
                "controller_health_verified": self._post_intent_healthy(state, entry["intent_at"]),
            }
        entry = {
            "status": "pending",
            "intent_at": datetime.now(timezone.utc).isoformat(),
            "intent_tag": "malscan-db-probe-" + uuid.uuid4().hex,
        }
        self.journal["operations"]["initial-probe"] = entry
        self.save()
        request = self.build_request()
        request["tags"].append(entry["intent_tag"])
        result = self.rest.request("POST", base, request)
        build_id = result.get("metadata", {}).get("build", {}).get("id")
        if not self._build_id(build_id):
            raise SetupError("setup_probe_build_identity_unknown")
        entry.update(status="confirmed", build_id=build_id)
        self.save()
        return {
            "scope": "initial_paused_health_probe",
            "build_id": build_id,
            "resubmitted": False,
            "controller_health_verified": False,
        }

    @staticmethod
    def _build_id(value):
        try:
            return str(uuid.UUID(value)) == value
        except (TypeError, ValueError, AttributeError):
            return False

    def enable(self):
        if self.journal.get("phase") not in {"installed_paused", "activation_submitted"}:
            raise SetupError("setup_enable_requires_completed_installation")
        self._verify_installation()
        state, generation = self._approved_state()
        lease, _ = self.store.load_json("lease.json")
        if state.get("active") is not None or lease is not None:
            raise SetupError("setup_enable_requires_idle_state")
        entry = self.journal["operations"].get("activation-tick")
        if entry:
            scheduler_url = f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
            if state["enabled"] is not True or self.get(scheduler_url).get("state") != "ENABLED":
                raise SetupError("setup_activation_configuration_drift")
            for name in self.journal["policies"]:
                if (
                    self.get("https://monitoring.googleapis.com/v3/" + name).get("enabled")
                    is not True
                ):
                    raise SetupError("setup_activation_configuration_drift")
            # Scheduler's HTTP acceptance is not a controller heartbeat. A
            # later matching healthy state proves a lost tick was effective.
            if entry["status"] == "pending":
                if not self._post_intent_healthy(state, entry["intent_at"]):
                    raise SetupError("setup_activation_tick_requires_reconciliation")
                entry["status"] = "confirmed"
                entry["healthy_after_intent"] = True
                self.save()
            self.journal["phase"] = "activation_submitted"
            self.save()
            return self.status()
        try:
            healthy = datetime.fromisoformat(state["last_healthy_at"].replace("Z", "+00:00"))
            if healthy.tzinfo is None:
                raise ValueError
            age = (datetime.now(timezone.utc) - healthy).total_seconds()
        except (AttributeError, KeyError, ValueError, TypeError):
            raise SetupError("setup_initial_health_probe_required") from None
        if not 0 <= age <= 86400:
            raise SetupError("setup_initial_health_probe_stale")
        if not self._build_id(state.get("last_controller_build_id")):
            raise SetupError("setup_initial_health_probe_identity_missing")
        for name in self.journal["policies"]:
            url = "https://monitoring.googleapis.com/v3/" + name
            self.ensure(
                "enable-policy:" + name,
                lambda url=url: self.get(url) if self.get(url).get("enabled") is True else None,
                lambda v: v["enabled"] is True,
                lambda url=url, name=name: self.rest.request(
                    "PATCH", url + "?updateMask=enabled", {"name": name, "enabled": True}
                ),
                permit_existing=True,
            )
        if state.get("enabled") is not True:
            if self.journal["operations"].get("enable-state"):
                raise SetupError("setup_enable_state_requires_reconciliation")
            self.journal["operations"]["enable-state"] = {"status": "pending"}
            self.save()
            state["enabled"] = True
            self.store.put_json("state.json", state, generation)
        self.journal["operations"]["enable-state"] = {"status": "confirmed"}
        self.save()
        url = f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
        self.ensure(
            "resume-scheduler",
            lambda: self.get(url) if self.get(url).get("state") == "ENABLED" else None,
            lambda v: v["state"] == "ENABLED",
            lambda: self.rest.request("POST", url + ":resume", {}),
            permit_existing=True,
        )
        # A data point after the final policy edit is required to arm absence
        # detection; record the boundary before the one allowed run request.
        self.journal["operations"]["activation-tick"] = {
            "status": "pending",
            "intent_at": datetime.now(timezone.utc).isoformat(),
        }
        self.journal["activated_at"] = self.journal["operations"]["activation-tick"]["intent_at"]
        self.save()
        self.rest.request("POST", url + ":run", {})
        self.journal["operations"]["activation-tick"]["status"] = "confirmed"
        self.journal["phase"] = "activation_submitted"
        self.save()
        return self.status()

    def pause(self):
        if self.journal.get("phase") not in {"installed_paused", "activation_submitted", "pausing"}:
            raise SetupError("setup_pause_requires_completed_installation")
        # Pausing must remain possible when a notification channel or an
        # unrelated IAM binding drifts. Stop our recorded Scheduler resource
        # first; disabling state still requires its exact approved source.
        url = f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
        scheduler = self.get(url)
        if (
            self.journal["operations"].get("scheduler", {}).get("status") != "confirmed"
            or not scheduler
            or scheduler.get("name") != f"projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
            or scheduler.get("state") not in {"PAUSED", "ENABLED"}
        ):
            raise SetupError("setup_pause_scheduler_identity_invalid")
        self.journal["phase"] = "pausing"
        self.save()
        self.ensure(
            "pause-scheduler",
            lambda: self.get(url) if self.get(url).get("state") == "PAUSED" else None,
            lambda v: v["state"] == "PAUSED",
            lambda: self.rest.request("POST", url + ":pause", {}),
            permit_existing=True,
        )
        state, generation = self._approved_state(check_current=False)
        if state["enabled"]:
            if self.journal["operations"].get("pause-state"):
                raise SetupError("setup_pause_state_requires_reconciliation")
            self.journal["operations"]["pause-state"] = {"status": "pending"}
            self.save()
            state["enabled"] = False
            self.store.put_json("state.json", state, generation)
        self.journal["operations"]["pause-state"] = {"status": "confirmed"}
        self.save()
        for name in self.journal["policies"]:
            url = "https://monitoring.googleapis.com/v3/" + name
            self.ensure(
                "pause-policy:" + name,
                lambda url=url: self.get(url) if self.get(url).get("enabled") is False else None,
                lambda v: v["enabled"] is False,
                lambda url=url, name=name: self.rest.request(
                    "PATCH", url + "?updateMask=enabled", {"name": name, "enabled": False}
                ),
                permit_existing=True,
            )
        # Preserve completed cycles for diagnosis; a future explicit enable
        # creates new policy/state/tick intents and a fresh heartbeat boundary.
        prefixes = ("enable-policy:", "pause-policy:")
        keys = {
            "enable-state",
            "resume-scheduler",
            "activation-tick",
            "pause-state",
            "pause-scheduler",
        }
        archived = {
            k: self.journal["operations"].pop(k)
            for k in list(self.journal["operations"])
            if k in keys or k.startswith(prefixes)
        }
        self.journal.setdefault("paused_cycles", []).append(archived)
        self.journal["phase"] = "installed_paused"
        self.save()
        result = self.status()
        lease, _ = self.store.load_json("lease.json")
        result["controller_in_flight"] = state.get("active") is not None or lease is not None
        result["controller_lease_present"] = lease is not None
        return result

    def status(self):
        state, _ = self.store.load_json("state.json")
        safe_state = {}
        if state is not None:
            auto = module("setup_status_controller", "auto_update.py")
            safe_state = auto.status_summary(auto.validate_state(state))
        scheduler = self.get(
            f"https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}/jobs/{SCHEDULER}"
        )
        lease, _ = self.store.load_json("lease.json")
        same_source = bool(
            state
            and state.get("project") == PROJECT
            and state.get("source", {}).get("sha256") == self.plan["source_sha256"]
            and state.get("source", {}).get("bundle_sha256") == self.plan["bundle_sha256"]
            and state.get("source", {}).get("storage_source") == self.journal.get("storage_source")
        )
        return {
            "scope": "private_database_update_setup_status",
            "phase": self.journal["phase"],
            "source_commit": self.plan["source_commit"],
            "operations_bucket": self.plan["bucket"],
            "scheduler_state": scheduler.get("state") if scheduler else "not_observed",
            "automatic_updates_enabled": safe_state.get("enabled", False),
            "last_healthy_at": safe_state.get("last_healthy_at"),
            "registered_source_matches": same_source,
            "controller_in_flight": bool(
                (state and state.get("active") is not None) or lease is not None
            ),
            "controller_lease_present": lease is not None,
            "activation_heartbeat_verified": bool(
                same_source and self._post_intent_healthy(state, self.journal.get("activated_at"))
            ),
            "new_cloud_scan_executed": False,
            "live_automatic_update_or_notification_delivery_verified": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("prepare", "apply", "probe", "enable", "pause", "status")
    )
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--maintenance-state-dir", type=Path)
    parser.add_argument("--notification-channel")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bucket", default=PROJECT + "-db-operations")
    parser.add_argument("--operator-member")
    parser.add_argument("--plan-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            if not args.maintenance_state_dir or not args.notification_channel or not args.output:
                raise SetupError("setup_prepare_arguments_required")
            result = prepare(
                args.repository,
                args.maintenance_state_dir,
                args.notification_channel,
                args.output,
                bucket=args.bucket,
                operator=args.operator_member,
            )
        else:
            if not args.plan_dir:
                raise SetupError("setup_plan_directory_required")
            result = getattr(Provisioner(args.plan_dir), args.operation)()
        print(json.dumps(result, indent=2))
    except Exception as error:
        code = str(error) if isinstance(error, SetupError) else "setup_operation_not_verified"
        print(
            json.dumps(
                {"success": False, "error": code, "automatic_updates_enabled_verified": False}
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
