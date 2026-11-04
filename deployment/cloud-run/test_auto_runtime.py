"""Offline runtime repair, exact request proof and unknown-response recovery."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

import auto_runtime as runtime

SPEC = importlib.util.spec_from_file_location(
    "runtime_setup_fixtures", Path(__file__).with_name("test_setup_auto_update.py")
)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
setup = fixtures.setup
FAILED = "11111111-1111-4111-8111-111111111111"
NEXT = "22222222-2222-4222-8222-222222222222"
SCHEDULER_URL = (
    f"https://cloudscheduler.googleapis.com/v1/projects/{runtime.PROJECT}/locations/"
    f"{runtime.REGION}/jobs/{runtime.SCHEDULER}"
)
BUILD_URL = (
    f"https://cloudbuild.googleapis.com/v1/projects/{runtime.PROJECT}/locations/"
    f"{runtime.REGION}/builds/{FAILED}"
)


class MaskedREST(fixtures.FakeREST):
    def __init__(self):
        super().__init__()
        self.lose_patch_response = False
        self.ignore_patch = False
        self.scheduler_reads = []
        self.after_patch = None

    def request(self, method, url, payload=None, **kwargs):
        if method == "GET" and url == SCHEDULER_URL and self.scheduler_reads:
            self.calls.append((method, url, None, None))
            return copy.deepcopy(self.scheduler_reads.pop(0))
        if method == "PATCH" and url == SCHEDULER_URL + "?updateMask=httpTarget.body":
            self.calls.append((method, url, copy.deepcopy(payload), None))
            if not self.ignore_patch:
                self.resources[SCHEDULER_URL]["httpTarget"]["body"] = payload["httpTarget"]["body"]
                self.resources[SCHEDULER_URL]["userUpdateTime"] = "2026-11-04T10:00:00Z"
            if self.after_patch:
                self.after_patch()
            if self.lose_patch_response:
                self.lose_patch_response = False
                raise RuntimeError("unexpected-private-provider-body")
            return copy.deepcopy(self.resources[SCHEDULER_URL])
        return super().request(method, url, payload, **kwargs)


class Harness(setup.Provisioner):
    """Actual setup helpers and a valid promoted checkpoint; all APIs are fake."""

    def __init__(self, fixture):
        self.plan = copy.deepcopy(fixture.plan)
        self.plan["controller_build_template"] = copy.deepcopy(runtime.LEGACY_TEMPLATE)
        self.store = fixtures.FakeStore()
        self.rest = MaskedREST()
        self.live_job = lambda: copy.deepcopy(fixture.job)
        self.readback_delays = []
        self.readback_sleep = self.readback_delays.append
        self.saved = []
        self.on_save = None
        self.journal = {
            "version": 1,
            "phase": "installed_paused",
            "plan_sha256": setup.digest(self.plan),
            "storage_source": {
                "bucket": self.plan["bucket"],
                "object": self.plan["bundle_object"],
                "generation": "7",
            },
            "operations": {
                "scheduler": {"status": "confirmed"},
                "initial-probe": {
                    "status": "confirmed",
                    "build_id": FAILED,
                    "intent_tag": "malscan-db-probe-" + "a" * 32,
                    "intent_at": "2026-11-04T09:00:00Z",
                },
            },
        }
        state = copy.deepcopy(self.plan["initial_state"])
        state["source"]["storage_source"] = copy.deepcopy(self.journal["storage_source"])
        self.store.put_json("state.json", state, 0)
        self.rest.resources[SCHEDULER_URL] = {
            **self.scheduler_document(template=runtime.LEGACY_TEMPLATE),
            "state": "PAUSED",
            "userUpdateTime": "2026-11-04T09:00:00Z",
        }
        request = self.build_request(template=runtime.LEGACY_TEMPLATE)
        request["tags"].append(self.journal["operations"]["initial-probe"]["intent_tag"])
        build = copy.deepcopy(request)
        build.update(
            id=FAILED,
            status="FAILURE",
            failureInfo={
                "type": "USER_BUILD_STEP",
                "detail": (
                    'starting step container failed: exec: "python3": '
                    "executable file not found in $PATH"
                ),
            },
        )
        build["steps"][0]["args"] = [
            item.replace("$_OPS_BUCKET", self.plan["bucket"]).replace("$BUILD_ID", FAILED)
            for item in build["steps"][0]["args"]
        ]
        build["steps"][0].update(status="FAILURE", timing={"endTime": "2026-11-04T09:01:00Z"})
        self.rest.resources[BUILD_URL] = build

    def save(self):
        self.saved.append(copy.deepcopy(self.journal))
        if self.on_save:
            self.on_save()

    def patches(self):
        return [c for c in self.rest.calls if c[0] == "PATCH"]


class RuntimeRepairTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProvisioningTests()
        self.fixture.setUp()
        self.tool = Harness(self.fixture)

    def tearDown(self):
        self.fixture.tearDown()

    def test_repair_patches_only_body_and_keeps_original_source_and_state(self):
        before_plan = copy.deepcopy(self.tool.plan)
        before_state = self.tool.store.load_json("state.json")
        before_scheduler = copy.deepcopy(self.tool.rest.resources[SCHEDULER_URL])
        result = runtime.repair(self.tool)
        self.assertEqual(result["status"], "confirmed")
        self.assertFalse(result["probe_submitted"])
        self.assertFalse(result["automatic_updates_enabled"])
        self.assertEqual(self.tool.plan, before_plan)
        self.assertEqual(self.tool.store.load_json("state.json"), before_state)
        patch = self.tool.patches()
        self.assertEqual(len(patch), 1)
        self.assertEqual(set(patch[0][2]), {"name", "httpTarget"})
        self.assertEqual(set(patch[0][2]["httpTarget"]), {"body"})
        self.assertEqual(self.tool.saved[0]["runtime_repair"]["status"], "pending")
        self.assertIn("initial-probe", self.tool.saved[0]["operations"])
        self.assertNotIn("initial-probe", self.tool.journal["operations"])
        self.assertEqual(self.tool.journal["failed_probes"][0]["build_id"], FAILED)
        self.assertEqual(
            runtime.effective_template(self.tool.plan, self.tool.journal),
            runtime.current_template(),
        )
        self.assertEqual(
            runtime._scheduler_hash(before_scheduler),
            runtime._scheduler_hash(self.tool.rest.resources[SCHEDULER_URL]),
        )

    def test_lost_patch_response_reconciles_without_a_second_patch(self):
        self.tool.rest.lose_patch_response = True
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "^runtime_patch_response_unknown$"):
            runtime.repair(self.tool)
        self.assertEqual(self.tool.journal["runtime_repair"]["status"], "pending")
        self.assertEqual(runtime.repair(self.tool)["status"], "confirmed")
        self.assertEqual(len(self.tool.patches()), 1)

    def test_still_old_after_unknown_patch_is_not_written_again(self):
        self.tool.rest.ignore_patch = True
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "requires_reconciliation"):
            runtime.repair(self.tool)
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "requires_reconciliation"):
            runtime.repair(self.tool)
        self.assertEqual(len(self.tool.patches()), 1)
        self.assertEqual(self.tool.journal["runtime_repair"]["status"], "pending")
        self.assertIn("initial-probe", self.tool.journal["operations"])

    def test_completed_repair_does_not_clear_a_new_probe(self):
        runtime.repair(self.tool)
        next_probe = {
            "status": "confirmed",
            "build_id": NEXT,
            "intent_tag": "malscan-db-probe-" + "b" * 32,
            "intent_at": "2026-11-04T10:02:00Z",
        }
        self.tool.journal["operations"]["initial-probe"] = next_probe
        self.assertEqual(runtime.repair(self.tool)["status"], "confirmed")
        self.assertEqual(self.tool.journal["operations"]["initial-probe"], next_probe)
        self.assertEqual(len(self.tool.journal["failed_probes"]), 1)
        self.assertEqual(len(self.tool.patches()), 1)

    def test_wrong_or_nonterminal_failed_probe_is_rejected_without_patch(self):
        original = copy.deepcopy(self.tool.rest.resources[BUILD_URL])
        variants = []
        for status in ("WORKING", "SUCCESS", "TIMEOUT"):
            build = copy.deepcopy(original)
            build["status"] = status
            variants.append(build)
        for name in ("source", "serviceAccount", "tags"):
            build = copy.deepcopy(original)
            build[name] = {} if name == "source" else "wrong" if name == "serviceAccount" else []
            variants.append(build)
        build = copy.deepcopy(original)
        build["failureInfo"]["detail"] = "unexpected-private-error"
        variants.append(build)
        for build in variants:
            with self.subTest(status=build.get("status")):
                self.tool.rest.resources[BUILD_URL] = build
                with self.assertRaises(runtime.RuntimeRepairError):
                    runtime.repair(self.tool)
                self.assertEqual(self.tool.patches(), [])

    def test_enabled_active_lease_and_scheduler_drift_block_repair(self):
        for field in ("enabled", "active", "lease", "schedule"):
            tool = Harness(self.fixture)
            if field in {"enabled", "active"}:
                state, generation = tool.store.load_json("state.json")
                state[field] = True if field == "enabled" else {"unapproved": True}
                tool.store.put_json("state.json", state, generation)
            elif field == "lease":
                tool.store.put_json("lease.json", {"owner": NEXT}, 0)
            else:
                tool.rest.resources[SCHEDULER_URL]["schedule"] = "* * * * *"
            with self.subTest(field=field):
                with self.assertRaises(RuntimeError):
                    runtime.repair(tool)
                self.assertEqual(tool.patches(), [])

    def test_generation_change_after_intent_blocks_patch(self):
        def change_state():
            state, generation = self.tool.store.load_json("state.json")
            self.tool.store.put_json("state.json", state, generation)

        self.tool.on_save = change_state
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "state_generation_changed"):
            runtime.repair(self.tool)
        self.assertEqual(self.tool.patches(), [])

    def test_generation_change_after_patch_keeps_pending_checkpoint(self):
        def change_state():
            state, generation = self.tool.store.load_json("state.json")
            self.tool.store.put_json("state.json", state, generation)

        self.tool.rest.after_patch = change_state
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "state_generation_changed"):
            runtime.repair(self.tool)
        self.assertEqual(self.tool.journal["runtime_repair"]["status"], "pending")
        self.assertIn("initial-probe", self.tool.journal["operations"])

    def test_scheduler_omitted_zero_retry_count_is_accepted(self):
        self.tool.rest.resources[SCHEDULER_URL]["retryConfig"] = {}
        self.assertEqual(runtime.repair(self.tool)["status"], "confirmed")

    def test_current_runtime_noop_still_requires_paused_matching_scheduler(self):
        self.tool.plan["controller_build_template"] = runtime.current_template()
        self.tool.journal["plan_sha256"] = setup.digest(self.tool.plan)
        self.tool.rest.resources[SCHEDULER_URL] = {
            **self.tool.scheduler_document(template=runtime.current_template()),
            "state": "PAUSED",
        }
        self.assertEqual(runtime.repair(self.tool)["status"], "not_required")
        self.tool.rest.resources[SCHEDULER_URL]["state"] = "ENABLED"
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "scheduler_changed"):
            runtime.repair(self.tool)
        self.assertEqual(self.tool.patches(), [])

    def test_build_proof_accepts_raw_or_resolved_args_and_generated_metadata(self):
        request = self.tool.build_request(template=runtime.LEGACY_TEMPLATE)
        request["tags"].append(self.tool.journal["operations"]["initial-probe"]["intent_tag"])
        actual = self.tool.rest.resources[BUILD_URL]
        self.assertTrue(runtime.build_matches(request, actual))
        raw = copy.deepcopy(actual)
        raw["steps"][0]["args"] = request["steps"][0]["args"]
        self.assertTrue(runtime.build_matches(request, raw))
        changed = copy.deepcopy(actual)
        changed["steps"][0]["args"][-1] = NEXT
        self.assertFalse(runtime.build_matches(request, changed))

    def test_unapproved_runtime_and_record_tampering_are_rejected(self):
        bad = copy.deepcopy(runtime.current_template())
        bad["steps"][0]["entrypoint"] = "/unapproved/python"
        self.assertFalse(runtime.supported_template(bad))
        runtime.repair(self.tool)
        self.tool.journal["runtime_repair"]["version"] = True
        with self.assertRaisesRegex(runtime.RuntimeRepairError, "checkpoint_invalid"):
            runtime.effective_template(self.tool.plan, self.tool.journal)

    def test_failure_context_never_contains_private_provider_values(self):
        self.tool.rest.lose_patch_response = True
        with self.assertRaises(runtime.RuntimeRepairError) as caught:
            runtime.repair(self.tool)
        self.assertEqual(str(caught.exception), "runtime_patch_response_unknown")
        self.assertNotIn("private", str(caught.exception))
        json.dumps(self.tool.journal, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
