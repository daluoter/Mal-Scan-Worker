"""Offline provisioning, activation and private-plan safety checks."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

SPEC = importlib.util.spec_from_file_location(
    "setup_auto", Path(__file__).with_name("setup-auto-update.py")
)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)
MAINT_SPEC = importlib.util.spec_from_file_location(
    "setup_maintenance_test", Path(__file__).with_name("test_maintain_demo.py")
)
fixtures = importlib.util.module_from_spec(MAINT_SPEC)
MAINT_SPEC.loader.exec_module(fixtures)
maintenance = fixtures.maintenance
CHANNEL = f"projects/{setup.PROJECT}/notificationChannels/123"


class FakeStore:
    def __init__(self):
        self.values = {}
        self.generation = 0
        self.writes = []
        self.lose_next_write = False

    def load_json(self, name):
        return copy.deepcopy(self.values.get(name, (None, 0)))

    def put_json(self, name, value, expected_generation):
        current = self.values.get(name, (None, 0))[1]
        if current != expected_generation:
            raise setup.SetupError("test_generation_conflict")
        self.generation += 1
        self.values[name] = (copy.deepcopy(value), self.generation)
        self.writes.append((name, copy.deepcopy(value), expected_generation))
        if self.lose_next_write:
            self.lose_next_write = False
            raise setup.SetupError("test_response_unknown")
        return self.generation


class FakeREST:
    def __init__(self):
        self.resources = {}
        self.policies = {}
        self.calls = []
        self.builds = []
        self.lose_after = set()
        self.omit_defaults = True
        self.channel = {"name": CHANNEL, "enabled": True, "verificationStatus": "VERIFIED"}
        self.policies[
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{setup.PROJECT}"
        ] = {
            "etag": "project-etag",
            "version": 1,
            "bindings": [
                {
                    "role": "roles/cloudscheduler.serviceAgent",
                    "members": [
                        "serviceAccount:service-371636043543@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
                    ],
                },
                {
                    "role": "roles/cloudbuild.serviceAgent",
                    "members": [
                        "serviceAccount:service-371636043543@gcp-sa-cloudbuild.iam.gserviceaccount.com"
                    ],
                },
            ],
        }

    def _response(self, method, url, value):
        key = (method, url)
        if key in self.lose_after:
            self.lose_after.remove(key)
            raise setup.SetupError("test_provider_response_unknown")
        return copy.deepcopy(value)

    def request(self, method, url, payload=None, *, raw=None, content_type=None, missing_ok=False):
        self.calls.append((method, url, copy.deepcopy(payload), raw))
        base = url.split("?", 1)[0]
        if base.endswith(":getIamPolicy") or (base.endswith("/iam") and method == "GET"):
            resource = base.removesuffix(":getIamPolicy").removesuffix("/iam")
            return copy.deepcopy(
                self.policies.setdefault(
                    resource,
                    {
                        "version": 1,
                        "etag": "original-etag",
                        "bindings": [
                            {"role": "roles/viewer", "members": ["user:owner@example.invalid"]}
                        ],
                    },
                )
            )
        if base.endswith(":setIamPolicy") or (base.endswith("/iam") and method == "PUT"):
            resource = base.removesuffix(":setIamPolicy").removesuffix("/iam")
            value = copy.deepcopy(payload if method == "PUT" else payload["policy"])
            self.policies[resource] = value
            return self._response(method, url, value)
        if method == "GET":
            if base == f"https://cloudresourcemanager.googleapis.com/v1/projects/{setup.PROJECT}":
                return {"projectId": setup.PROJECT, "projectNumber": "371636043543"}
            if "/services/" in base:
                return {"state": "ENABLED"}
            if base == "https://monitoring.googleapis.com/v3/" + CHANNEL:
                return copy.deepcopy(self.channel)
            if base.endswith("/alertPolicies"):
                return {
                    "alertPolicies": [
                        copy.deepcopy(v)
                        for k, v in self.resources.items()
                        if k.startswith(base + "/")
                    ]
                }
            if base.endswith("/builds"):
                return {"builds": copy.deepcopy(self.builds)}
            return copy.deepcopy(self.resources.get(base))
        if method == "POST" and base.endswith("/serviceAccounts"):
            email = payload["accountId"] + f"@{setup.PROJECT}.iam.gserviceaccount.com"
            value = {"email": email, **payload["serviceAccount"]}
            target = base + "/" + email
        elif method == "POST" and base.endswith("/roles"):
            value = copy.deepcopy(payload["role"])
            target = base + "/" + payload["roleId"]
            value["name"] = f"projects/{setup.PROJECT}/roles/{payload['roleId']}"
        elif method == "POST" and base == "https://storage.googleapis.com/storage/v1/b":
            value = copy.deepcopy(payload)
            value["location"] = value["location"].upper()
            value["projectNumber"] = "371636043543"
            target = base + "/" + payload["name"]
        elif method == "POST" and base.startswith("https://storage.googleapis.com/upload/"):
            start = raw.index(b"\r\n\r\n") + 4
            end = raw.index(b"\r\n--", start)
            value = json.loads(raw[start:end])
            value["generation"] = "7"
            content_start = raw.index(b"\r\n\r\n", end + 4) + 4
            content_end = raw.index(b"\r\n--", content_start)
            value["size"] = str(content_end - content_start)
            bucket = base.split("/b/", 1)[1].split("/", 1)[0]
            target = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/" + setup.quote(
                value["name"], safe=""
            )
        elif method == "POST" and base.endswith("/metrics"):
            value = copy.deepcopy(payload)
            if self.omit_defaults:
                value.pop("disabled", None)
            target = base + "/" + payload["name"]
        elif method == "POST" and base.endswith("/alertPolicies"):
            value = copy.deepcopy(payload)
            value["name"] = f"projects/{setup.PROJECT}/alertPolicies/{100 + len(self.resources)}"
            if self.omit_defaults:
                for index, c in enumerate(value["conditions"]):
                    c["name"] = value["name"] + "/conditions/" + str(index + 1)
                    if "conditionThreshold" in c and c["conditionThreshold"]["thresholdValue"] == 0:
                        c["conditionThreshold"].pop("thresholdValue")
                    for field in ("conditionThreshold", "conditionAbsent"):
                        for a in c.get(field, {}).get("aggregations", []):
                            a.pop("groupByFields", None)
            target = "https://monitoring.googleapis.com/v3/" + value["name"]
        elif method == "POST" and base.endswith("/jobs"):
            value = {**copy.deepcopy(payload), "state": "ENABLED"}
            target = "https://cloudscheduler.googleapis.com/v1/" + value["name"]
        elif method == "POST" and base.endswith((":pause", ":resume")):
            target = base.rsplit(":", 1)[0]
            value = copy.deepcopy(self.resources[target])
            value["state"] = "PAUSED" if base.endswith(":pause") else "ENABLED"
        elif method == "POST" and base.endswith(":run"):
            return self._response(method, url, {})
        elif method == "POST" and base.endswith("/builds"):
            build_id = f"00000000-0000-4000-8000-{len(self.builds) + 1:012d}"
            value = {"id": build_id, "status": "WORKING", **copy.deepcopy(payload)}
            for step in value["steps"]:
                step.update(
                    status="WORKING", timing={"startTime": "2026-11-04T00:00:00Z"}, pullTiming={}
                )
            self.builds.append(value)
            return self._response(method, url, {"metadata": {"build": value}})
        elif method == "PATCH":
            target = base
            value = {**copy.deepcopy(self.resources[base]), **copy.deepcopy(payload)}
        else:
            raise AssertionError((method, url))
        self.resources[target] = copy.deepcopy(value)
        return self._response(method, url, value)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "plan"
        self.directory.mkdir(mode=0o700)
        blob = b"approved immutable source bytes"
        (self.directory / "source.tar.gz").write_bytes(blob)
        (self.directory / "source.tar.gz").chmod(0o600)
        repository = Path(self.temp.name) / "approved-repository"
        (repository / "deployment/cloud-run").mkdir(parents=True)
        (repository / "worker/src/malscan_worker/runtime").mkdir(parents=True)
        (repository / "backend").mkdir()
        for name in (maintenance.CONFIG, ".gcloudignore", ".dockerignore"):
            (repository / name).write_text("test input")
        (repository / "worker/src/malscan_worker/runtime/engine_controls.py").write_bytes(
            b"controls"
        )
        cloud = fixtures.FakeCloud()
        for database in cloud.report["signed_databases"]:
            database["created_at_epoch"] = int(time.time()) - 1000
        campaign = Path(self.temp.name) / fixtures.RELEASE
        approved = maintenance.Maintenance(campaign, repository, cloud)
        approved.prepare()
        approved.submit()
        approved.status()
        approved.update_image()
        files = {
            name: maintenance.read_private(campaign / name)
            for name in ("state.json", "job-before.json", "build.json", "engine-controls.json")
        }
        self.job = cloud.current
        self.store = FakeStore()
        self.rest = FakeREST()
        root = Path(__file__).parents[2]
        monitoring = setup.module("setup_monitoring_test", "auto_monitoring.py").monitoring_plan(
            setup.PROJECT, CHANNEL
        )
        source_sha = files["state.json"]["source_sha256"]
        bundle_sha = hashlib.sha256(blob).hexdigest()
        initial = setup.module("setup_test_controller", "auto_update.py").initial_state(
            files, "a" * 40, source_sha, bundle_sha, CHANNEL
        )
        self.plan = {
            "schema_version": 1,
            "scope": "reviewed_private_database_update_setup",
            "project": setup.PROJECT,
            "region": setup.REGION,
            "job": setup.JOB,
            "bucket": setup.PROJECT + "-db-operations",
            "source_commit": "a" * 40,
            "source_sha256": source_sha,
            "bundle_sha256": bundle_sha,
            "bundle_object": "bundles/" + "a" * 40 + ".tar.gz",
            "notification_channel": CHANNEL,
            "operator_member": "user:operator@example.invalid",
            "service_accounts": setup.ACCOUNTS,
            "custom_roles": setup.role_documents(),
            "bucket_configuration": setup.bucket_document(setup.PROJECT + "-db-operations"),
            "controller_build_template": json.loads(
                (root / "deployment/cloud-run/cloudbuild-auto-update.json").read_text()
            ),
            "scheduler": {"name": setup.SCHEDULER, "schedule": setup.SCHEDULE, "time_zone": "UTC"},
            "monitoring": monitoring,
            "initial_state": initial,
        }
        self.write_plan()

    def tearDown(self):
        self.temp.cleanup()

    def write_plan(self):
        setup.write_private(
            self.directory / "plan.json", {"sha256": setup.digest(self.plan), "plan": self.plan}
        )

    def provisioner(self):
        return setup.Provisioner(
            self.directory,
            rest=self.rest,
            store=self.store,
            live_job=lambda: copy.deepcopy(self.job),
        )

    def test_initial_apply_is_paused_disabled_and_repeat_has_no_writes(self):
        tool = self.provisioner()
        result = tool.apply()
        self.assertEqual(result["phase"], "installed_paused")
        self.assertFalse(result["automatic_updates_enabled"])
        self.assertEqual(result["scheduler_state"], "PAUSED")
        self.assertTrue(
            all(
                not self.rest.resources["https://monitoring.googleapis.com/v3/" + p]["enabled"]
                for p in tool.journal["policies"]
            )
        )
        calls = len(
            [
                c
                for c in self.rest.calls
                if c[0] != "GET" and not c[1].split("?", 1)[0].endswith(":getIamPolicy")
            ]
        )
        self.provisioner().apply()
        self.assertEqual(
            len(
                [
                    c
                    for c in self.rest.calls
                    if c[0] != "GET" and not c[1].split("?", 1)[0].endswith(":getIamPolicy")
                ]
            ),
            calls,
        )
        self.assertEqual(len(self.store.writes), 1)

    def healthy(self):
        state, generation = self.store.load_json("state.json")
        state["last_healthy_at"] = datetime.now(timezone.utc).isoformat()
        state["last_controller_build_id"] = "00000000-0000-4000-8000-000000000001"
        self.store.put_json("state.json", state, generation)

    def scheduler_url(self):
        return f"https://cloudscheduler.googleapis.com/v1/projects/{setup.PROJECT}/locations/{setup.REGION}/jobs/{setup.SCHEDULER}"

    def writes(self, suffix):
        return [c for c in self.rest.calls if c[0] != "GET" and c[1].endswith(suffix)]

    def test_missing_managed_agent_role_fails_before_resource_creation(self):
        self.rest.policies[
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{setup.PROJECT}"
        ]["bindings"] = []
        with self.assertRaisesRegex(setup.SetupError, "managed_service_agent_role_missing"):
            self.provisioner().apply()
        self.assertFalse(self.rest.resources)

    def test_status_rejects_arbitrary_private_checkpoint_text(self):
        tool = self.provisioner()
        tool.apply()
        state, generation = self.store.load_json("state.json")
        state["last_healthy_at"] = "unexpected-private-checkpoint-text"
        self.store.put_json("state.json", state, generation)
        with self.assertRaisesRegex(Exception, "^checkpoint_timestamp_invalid$"):
            tool.status()

    def test_same_role_members_are_merged_and_service_account_policy_has_no_body(self):
        self.provisioner().apply()
        project = self.rest.policies[
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{setup.PROJECT}"
        ]
        writers = [b for b in project["bindings"] if b["role"] == "roles/logging.logWriter"]
        self.assertEqual(len(writers), 1)
        self.assertEqual(len(writers[0]["members"]), 2)
        self.assertEqual(project["etag"], "project-etag")
        calls = [
            c
            for c in self.rest.calls
            if "iam.googleapis.com/v1/projects/" in c[1] and ":getIamPolicy" in c[1]
        ]
        self.assertTrue(calls)
        self.assertTrue(
            all(
                c[0] == "POST" and c[2] is None and "options.requestedPolicyVersion=3" in c[1]
                for c in calls
            )
        )

    def test_apply_lost_state_write_is_reconciled_without_duplicate(self):
        self.store.lose_next_write = True
        with self.assertRaisesRegex(setup.SetupError, "test_response_unknown"):
            self.provisioner().apply()
        self.provisioner().apply()
        self.assertEqual(len(self.store.writes), 1)

    def test_apply_lost_create_is_reconciled_without_duplicate(self):
        endpoint = f"https://iam.googleapis.com/v1/projects/{setup.PROJECT}/serviceAccounts"
        self.rest.lose_after.add(("POST", endpoint))
        with self.assertRaises(setup.SetupError):
            self.provisioner().apply()
        self.provisioner().apply()
        creates = [c for c in self.rest.calls if c[0] == "POST" and c[1] == endpoint]
        self.assertEqual(len(creates), 3)  # Three distinct accounts, no repeated first account.

    def test_probe_unknown_response_reads_unique_build_without_resubmitting(self):
        self.provisioner().apply()
        base = f"https://cloudbuild.googleapis.com/v1/projects/{setup.PROJECT}/locations/{setup.REGION}/builds"
        self.rest.lose_after.add(("POST", base))
        with self.assertRaises(setup.SetupError):
            self.provisioner().probe()
        result = self.provisioner().probe()
        self.assertEqual(result["build_id"], self.rest.builds[0]["id"])
        self.assertFalse(result["controller_health_verified"])
        self.assertEqual(len([c for c in self.rest.calls if c[0] == "POST" and c[1] == base]), 1)
        self.provisioner().probe()
        self.assertEqual(len(self.rest.builds), 1)

    def test_probe_unknown_without_match_stays_pending(self):
        self.provisioner().apply()
        tool = self.provisioner()
        tool.journal["operations"]["initial-probe"] = {
            "status": "pending",
            "intent_tag": "malscan-db-probe-" + "1" * 32,
            "intent_at": datetime.now(timezone.utc).isoformat(),
        }
        tool.save()
        with self.assertRaisesRegex(setup.SetupError, "requires_reconciliation"):
            self.provisioner().probe()
        self.assertFalse(self.rest.builds)

    def test_enable_requires_recent_health_and_does_not_execute_scan(self):
        self.provisioner().apply()
        with self.assertRaisesRegex(setup.SetupError, "initial_health_probe_required"):
            self.provisioner().enable()
        self.healthy()
        result = self.provisioner().enable()
        self.assertEqual(result["phase"], "activation_submitted")
        self.assertTrue(result["automatic_updates_enabled"])
        self.assertFalse(result["activation_heartbeat_verified"])
        self.assertFalse(result["live_automatic_update_or_notification_delivery_verified"])
        self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 1)
        self.assertFalse(
            any("run.googleapis.com" in c[1] and c[1].endswith(":run") for c in self.rest.calls)
        )

    def test_lost_activation_tick_reconciles_only_after_matching_health(self):
        self.provisioner().apply()
        self.healthy()
        self.rest.lose_after.add(("POST", self.scheduler_url() + ":run"))
        with self.assertRaises(setup.SetupError):
            self.provisioner().enable()
        with self.assertRaisesRegex(setup.SetupError, "activation_tick_requires_reconciliation"):
            self.provisioner().enable()
        self.healthy()
        result = self.provisioner().enable()
        self.assertTrue(result["activation_heartbeat_verified"])
        self.assertEqual(len(self.writes(":run")), 1)

    def test_lost_enable_state_cas_recovers_without_rewriting_snapshot(self):
        self.provisioner().apply()
        self.healthy()
        self.store.lose_next_write = True
        with self.assertRaises(setup.SetupError):
            self.provisioner().enable()
        count = len(self.store.writes)
        self.provisioner().enable()
        self.assertEqual(len(self.store.writes), count)
        self.assertEqual(len(self.writes(":run")), 1)

    def test_lost_policy_edit_recovers_then_emits_single_post_edit_tick(self):
        tool = self.provisioner()
        tool.apply()
        self.healthy()
        name = tool.journal["policies"][0]
        self.rest.lose_after.add(
            ("PATCH", "https://monitoring.googleapis.com/v3/" + name + "?updateMask=enabled")
        )
        with self.assertRaises(setup.SetupError):
            self.provisioner().enable()
        self.provisioner().enable()
        edits = [
            c for c in self.rest.calls if c[0] == "PATCH" and c[1].endswith("?updateMask=enabled")
        ]
        self.assertEqual(len(edits), 2)
        self.assertEqual(len(self.writes(":run")), 1)

    def test_enable_refuses_bucket_iam_channel_source_and_scheduler_drift(self):
        self.provisioner().apply()
        self.healthy()
        snapshot = copy.deepcopy(self.rest.resources)
        bucket_url = f"https://storage.googleapis.com/storage/v1/b/{self.plan['bucket']}"
        self.rest.resources[bucket_url]["iamConfiguration"]["publicAccessPrevention"] = "inherited"
        with self.assertRaisesRegex(setup.SetupError, "installation_drift"):
            self.provisioner().enable()
        self.rest.resources = copy.deepcopy(snapshot)
        self.rest.channel["enabled"] = False
        with self.assertRaisesRegex(setup.SetupError, "channel_not_ready"):
            self.provisioner().enable()
        self.rest.channel["enabled"] = True
        self.rest.resources[self.scheduler_url()]["httpTarget"]["uri"] = "https://example.invalid"
        with self.assertRaisesRegex(setup.SetupError, "scheduler_configuration_changed"):
            self.provisioner().enable()
        self.rest.resources = copy.deepcopy(snapshot)
        state, generation = self.store.load_json("state.json")
        state["source"]["sha256"] = "c" * 64
        self.store.put_json("state.json", state, generation)
        with self.assertRaisesRegex(setup.SetupError, "registered_state_differs"):
            self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 0)

    def test_pause_and_reenable_rearm_with_new_single_tick(self):
        self.provisioner().apply()
        self.healthy()
        self.provisioner().enable()
        result = self.provisioner().pause()
        self.assertEqual(result["scheduler_state"], "PAUSED")
        self.assertFalse(result["automatic_updates_enabled"])
        self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 2)
        self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 2)

    def test_pause_reports_held_lease_even_without_active_campaign(self):
        self.provisioner().apply()
        self.healthy()
        self.provisioner().enable()
        self.store.put_json(
            "lease.json", {"owner_build_id": "00000000-0000-4000-8000-000000000001"}, 0
        )
        result = self.provisioner().pause()
        self.assertTrue(result["controller_in_flight"])
        self.assertTrue(result["controller_lease_present"])
        with self.assertRaisesRegex(setup.SetupError, "enable_requires_idle_state"):
            self.provisioner().enable()

    def test_pause_recovers_lost_state_and_scheduler_writes(self):
        self.provisioner().apply()
        self.healthy()
        self.provisioner().enable()
        self.rest.lose_after.add(("POST", self.scheduler_url() + ":pause"))
        with self.assertRaises(setup.SetupError):
            self.provisioner().pause()
        self.store.lose_next_write = True
        with self.assertRaises(setup.SetupError):
            self.provisioner().pause()
        result = self.provisioner().pause()
        self.assertFalse(result["automatic_updates_enabled"])
        self.assertEqual(result["scheduler_state"], "PAUSED")
        self.assertEqual(len(self.writes(":pause")), 2)  # initial apply plus explicit pause
        self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 2)

    def test_pause_remains_available_when_channel_or_iam_drifts(self):
        self.provisioner().apply()
        self.healthy()
        self.provisioner().enable()
        self.rest.channel["enabled"] = False
        self.rest.policies[
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{setup.PROJECT}"
        ]["bindings"] = []
        result = self.provisioner().pause()
        self.assertEqual(result["scheduler_state"], "PAUSED")
        self.assertFalse(result["automatic_updates_enabled"])

    def test_enabled_policy_drift_is_not_silently_repaired(self):
        tool = self.provisioner()
        tool.apply()
        self.healthy()
        self.provisioner().enable()
        name = tool.journal["policies"][0]
        self.rest.resources["https://monitoring.googleapis.com/v3/" + name]["enabled"] = False
        with self.assertRaisesRegex(setup.SetupError, "activation_configuration_drift"):
            self.provisioner().enable()
        self.assertEqual(len(self.writes(":run")), 1)

    def test_new_ops_bucket_iam_stays_conditional_for_builder(self):
        self.provisioner().apply()
        resource = f"https://storage.googleapis.com/storage/v1/b/{self.plan['bucket']}"
        policy = self.rest.policies[resource]
        builders = [
            b
            for b in policy["bindings"]
            if "serviceAccount:" + setup.ACCOUNTS["builder"] in b["members"]
        ]
        self.assertEqual(len(builders), 1)
        self.assertEqual(builders[0]["role"], "roles/storage.objectViewer")
        self.assertIn("/objects/build-sources/", builders[0]["condition"]["expression"])
        self.assertEqual(policy["version"], 3)
        self.assertFalse(
            any(
                p in setup.canonical(self.plan["custom_roles"]).decode()
                for p in (
                    "run.jobs.run",
                    "secretmanager.versions.access",
                    "iam.serviceAccountKeys.create",
                )
            )
        )

    def test_plan_self_hash_cannot_expand_permissions(self):
        self.plan["custom_roles"]["malscanDbJobUpdate"]["includedPermissions"].append(
            "run.jobs.run"
        )
        self.write_plan()
        with self.assertRaisesRegex(setup.SetupError, "fixed_scope_invalid"):
            self.provisioner()

    def test_bundle_replacement_is_detected_locally(self):
        (self.directory / "source.tar.gz").write_bytes(b"changed bundle")
        with self.assertRaisesRegex(setup.SetupError, "source_bundle_changed"):
            self.provisioner()


class ArchiveTests(unittest.TestCase):
    def test_git_archive_exactly_matches_approved_source_and_rejects_untracked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            required = [
                "auto_update.py",
                "auto_state.py",
                "auto_retention.py",
                "auto_monitoring.py",
                "cloudbuild-auto-update.json",
            ]
            for name in required:
                target = root / "deployment/cloud-run" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}" if name.endswith("json") else "# fixture\n")
            for name in (maintenance.CONFIG, ".gcloudignore", ".dockerignore"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# fixture\n")
            (root / "worker").mkdir()
            (root / "worker/Dockerfile").write_text("FROM scratch\n")
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            expected = maintenance.source_fingerprint(root)
            revision, bundle = setup.archive_source(root)
            self.assertEqual(len(revision), 40)
            setup.verify_archive_source(bundle, expected)
            (root / "worker/untracked.py").write_text("# not approved\n")
            with self.assertRaisesRegex(setup.SetupError, "archive_source_differs"):
                setup.verify_archive_source(bundle, maintenance.source_fingerprint(root))
            (root / "worker/Dockerfile").write_text("FROM changed\n")
            with self.assertRaisesRegex(setup.SetupError, "worktree_must_be_clean"):
                setup.archive_source(root)

    def test_unsafe_archive_paths_links_and_duplicates_are_rejected(self):
        for kind in ("traversal", "symlink", "duplicate"):
            with self.subTest(kind=kind):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w") as archive:
                    item = tarfile.TarInfo("../escape" if kind == "traversal" else "worker/example")
                    if kind == "symlink":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "/etc/passwd"
                    archive.addfile(item)
                    if kind == "duplicate":
                        archive.addfile(item)
                with self.assertRaisesRegex(setup.SetupError, "archive_source_differs"):
                    setup.verify_archive_source(gzip.compress(raw.getvalue()), "b" * 64)

    def test_rest_provider_errors_do_not_expose_payload_or_token(self):
        client = setup.REST()
        secret = "do-not-print-this-secret"
        with patch.object(
            setup.subprocess,
            "run",
            return_value=type("Result", (), {"returncode": 0, "stdout": "safe-token"})(),
        ), patch.object(client.opener, "open", side_effect=RuntimeError(secret)):
            with self.assertRaises(setup.SetupError) as raised:
                client.request(
                    "POST",
                    "https://cloudbuild.googleapis.com/v1/projects/malscan-v2-poc/locations/us-central1/builds",
                    {"sensitive": secret},
                )
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
