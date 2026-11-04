"""Offline scheduled-image retention ownership and uncertainty controls."""

import copy
import importlib.util
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "auto_retention", Path(__file__).with_name("auto_retention.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "prune_fixture", Path(__file__).with_name("test_prune_registry.py")
)
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixtures)
CURRENT = fixtures.image("a")
ROLLBACK = fixtures.image("b")


def release(index):
    return f"db-20261101T000000Z-{index:012x}"


def fixture():
    value = fixtures.fixture()
    owned = []
    for index, letter in enumerate(("c", "d"), 1):
        tag = release(index)
        next(row for row in value["images"] if row["image"] == fixtures.image(letter))["tags"] = [
            tag
        ]
        owned.append({"digest": fixtures.image(letter), "release": tag})
    return value, owned


class SavedState:
    def __init__(self):
        self.states = []
        self.interrupt = None

    @property
    def latest(self):
        return copy.deepcopy(self.states[-1])

    def persist(self, state):
        self.states.append(copy.deepcopy(state))
        if self.interrupt == state["phase"]:
            raise KeyboardInterrupt()


class FakeCloud(fixtures.FakeCloud):
    def inspect(self):
        value = super().inspect()
        value["observed_at"] = mod.now().isoformat()
        return value


class AutoRetentionTests(unittest.TestCase):
    def setUp(self):
        self.snapshot, self.owned = fixture()
        self.cloud = FakeCloud(self.snapshot)
        self.saved = SavedState()

    def run_cleanup(self, state=None, *, owned=None, pending=None, persist=None):
        return mod.run(
            self.cloud.inspect,
            self.cloud.delete,
            persist or self.saved.persist,
            self.owned if owned is None else owned,
            CURRENT,
            ROLLBACK,
            pending,
            state,
        )

    def prepared(self):
        self.saved.interrupt = "prepared"
        with self.assertRaises(KeyboardInterrupt):
            self.run_cleanup()
        self.saved.interrupt = None
        return self.saved.latest

    def test_only_exact_ledger_owned_tag_sets_are_selected(self):
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK),
            [fixtures.image("c"), fixtures.image("d")],
        )
        # A manually produced db-* version is not automatically owned.
        row = copy.deepcopy(self.snapshot["images"][2])
        row.update(image=fixtures.image("2"), tags=[release(9)])
        self.snapshot["images"].append(row)
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK),
            [fixtures.image("c"), fixtures.image("d")],
        )
        self.snapshot["images"][2]["tags"].append(release(999))
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK), [fixtures.image("d")]
        )
        self.snapshot["images"][3]["tags"] = []
        self.assertEqual(mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK), [])

    def test_multiple_owned_tags_same_digest_and_duplicate_ledger_entries_are_idempotent(self):
        self.owned.append({"digest": fixtures.image("c"), "release": release(3)})
        self.owned.append(copy.deepcopy(self.owned[0]))
        self.snapshot["images"][2]["tags"].append(release(3))
        self.assertEqual(mod.live_owned_count(self.snapshot, self.owned), 2)
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK),
            [fixtures.image("c"), fixtures.image("d")],
        )

    def test_wrong_or_conflicting_ownership_never_creates_delete_plan(self):
        bad_ledgers = [
            [{"digest": fixtures.image("c", "engine-poc"), "release": release(1)}],
            [{"digest": fixtures.image("c"), "release": "unreviewed-prefix"}],
            [{"digest": fixtures.image("c"), "release": release(1), "ignored": True}],
            [
                {"digest": fixtures.image("c"), "release": release(1)},
                {"digest": fixtures.image("d"), "release": release(1)},
            ],
        ]
        for owned in bad_ledgers:
            with self.subTest(owned=owned), self.assertRaises(mod.RetentionError):
                self.run_cleanup(owned=owned)
        self.assertEqual(self.saved.states, [])
        self.assertEqual(self.cloud.deleted, [])

    def test_current_rollback_and_pending_are_never_selected(self):
        for uri in (CURRENT, ROLLBACK):
            self.owned.append({"digest": uri, "release": release(len(self.owned) + 1)})
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK, fixtures.image("c")),
            [fixtures.image("d")],
        )
        for current, rollback in ((ROLLBACK, CURRENT), (CURRENT, CURRENT)):
            with self.subTest(current=current, rollback=rollback):
                with self.assertRaises(mod.RetentionError):
                    mod.selection(self.snapshot, self.owned, current, rollback)

    def test_all_cloud_run_reference_kinds_and_regions_protect_owned_version(self):
        for kind in ("job", "service", "revision", "revision_resolved", "unfinished_execution"):
            with self.subTest(kind=kind):
                snapshot = copy.deepcopy(self.snapshot)
                snapshot["references"].append(
                    {
                        "kind": kind,
                        "resource": "other-consumer",
                        "region": "europe-west12",
                        "image": fixtures.image("c"),
                    }
                )
                snapshot["images"][2].update(
                    classification="protected_reference", protection_reasons=["other-consumer"]
                )
                self.assertEqual(
                    mod.selection(snapshot, self.owned, CURRENT, ROLLBACK), [fixtures.image("d")]
                )

    def test_newer_owned_version_is_retained_and_all_existing_owned_versions_count(self):
        self.snapshot["images"][2]["createTime"] = mod.now().isoformat()
        self.assertEqual(
            mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK), [fixtures.image("d")]
        )
        self.assertEqual(mod.live_owned_count(self.snapshot, self.owned), 2)
        self.assertEqual(mod.MAX_LIVE_OWNED, 4)

    def test_incomplete_inventory_missing_rollback_and_worker_index_halt(self):
        mutations = [
            lambda s: s.update(readiness_issues=[{"reason": "permission_denied"}]),
            lambda s: s["rollback_checkpoint"].update(status="not_observed"),
            lambda s: s["images"][2].update(reported_media_type=None),
            lambda s: s["images"][2].update(
                reported_media_type="application/vnd.oci.image.index.v1+json"
            ),
            lambda s: s["images"][2].pop("updateTime"),
            lambda s: s["repository"].update(cleanupPolicies={"unreviewed": {}}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                snapshot = copy.deepcopy(self.snapshot)
                mutation(snapshot)
                with self.assertRaises(mod.RetentionError):
                    mod.selection(snapshot, self.owned, CURRENT, ROLLBACK)
        self.assertEqual(self.cloud.deleted, [])

    def test_stale_and_future_inventory_never_authorize_mutation(self):
        for observed in (mod.now() - timedelta(hours=25), mod.now() + timedelta(minutes=6)):
            with self.subTest(observed=observed):
                snapshot = copy.deepcopy(self.snapshot)
                snapshot["observed_at"] = observed.isoformat()
                with self.assertRaisesRegex(mod.RetentionError, "stale_or_future"):
                    mod.selection(snapshot, self.owned, CURRENT, ROLLBACK)

    def test_batch_over_twenty_is_rejected_before_persistence(self):
        for index in range(21):
            row = copy.deepcopy(self.snapshot["images"][2])
            uri = mod.prune.PACKAGE + "@sha256:" + f"{index + 30:064x}"
            row.update(image=uri, tags=[release(index + 30)])
            self.cloud.report["images"].append(row)
            self.owned.append({"digest": uri, "release": release(index + 30)})
        with self.assertRaisesRegex(mod.RetentionError, "exceeds_bound"):
            self.run_cleanup()
        self.assertEqual(self.saved.states, [])
        self.assertEqual(self.cloud.deleted, [])

    def test_apply_rechecks_full_snapshot_and_persists_pending_before_each_delete(self):
        original_delete = self.cloud.delete

        def delete(uri):
            self.assertEqual(self.saved.latest["pending"], uri)
            self.assertEqual(self.saved.latest["phase"], "deletion_pending")
            original_delete(uri)

        self.cloud.delete = delete
        result = self.run_cleanup()
        self.assertEqual(self.cloud.deleted, [fixtures.image("c"), fixtures.image("d")])
        self.assertEqual(result["state"]["phase"], "completed")
        self.assertIsNone(result["state"]["pending"])
        self.assertEqual(result["summary"]["observed_version_count"], 5)
        self.assertFalse(result["summary"]["billed_savings_verified"])
        self.assertFalse(result["summary"]["cloud_run_executed"])
        self.assertGreaterEqual(self.cloud.reads, 6)
        again = self.run_cleanup(state=self.saved.latest)
        self.assertEqual(again["summary"]["removed_count"], 2)
        self.assertEqual(len(self.cloud.deleted), 2)

    def test_empty_owned_set_completes_without_mutation(self):
        result = self.run_cleanup(owned=[])
        self.assertEqual(result["summary"]["candidate_count"], 0)
        self.assertEqual(result["state"]["phase"], "completed")
        self.assertEqual(self.cloud.deleted, [])

    def test_complete_snapshot_drift_stops_before_first_delete(self):
        mutations = [
            lambda s: s["images"][2]["tags"].append("manual-tag"),
            lambda s: s["images"][4].update(updateTime=mod.now().isoformat()),
            lambda s: s["images"].append({**s["images"][2], "image": fixtures.image("2")}),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.setUp()

                def before_read(cloud, change=mutation):
                    if cloud.reads == 3:
                        change(cloud.report)

                self.cloud.before_read = before_read
                with self.assertRaisesRegex(mod.RetentionError, "inventory_drift"):
                    self.run_cleanup()
                self.assertEqual(self.cloud.deleted, [])

    def test_lease_or_cas_failure_prevents_any_next_delete(self):
        for fail_phase in ("prepared", "deletion_pending"):
            with self.subTest(phase=fail_phase):
                self.setUp()

                def persist(state, blocked=fail_phase):
                    if state["phase"] == blocked:
                        raise RuntimeError("lease_lost")
                    self.saved.persist(state)

                with self.assertRaisesRegex(RuntimeError, "lease_lost"):
                    self.run_cleanup(persist=persist)
                self.assertEqual(self.cloud.deleted, [])

    def test_cancelled_runner_after_pending_save_does_not_send_a_delete_on_resume(self):
        self.saved.interrupt = "deletion_pending"
        with self.assertRaises(KeyboardInterrupt):
            self.run_cleanup()
        self.saved.interrupt = None
        self.assertEqual(self.saved.latest["phase"], "deletion_pending")
        with self.assertRaisesRegex(mod.RetentionError, "no_automatic_retry"):
            self.run_cleanup(state=self.saved.latest)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(self.saved.latest["phase"], "uncertain")

    def test_uncertain_existing_digest_never_retries_request(self):
        self.cloud.failure = "before"
        with self.assertRaisesRegex(mod.RetentionError, "delete_outcome_uncertain"):
            self.run_cleanup()
        self.cloud.failure = None
        with self.assertRaisesRegex(mod.RetentionError, "no_automatic_retry"):
            self.run_cleanup(state=self.saved.latest)
        self.assertEqual(self.cloud.deleted, [])

    def test_absent_after_lost_delete_response_is_confirmed_without_duplicate_request(self):
        self.cloud.failure = "after"
        with self.assertRaisesRegex(mod.RetentionError, "delete_outcome_uncertain"):
            self.run_cleanup()
        self.cloud.failure = None
        result = self.run_cleanup(state=self.saved.latest)
        self.assertEqual(self.cloud.deleted, [fixtures.image("c"), fixtures.image("d")])
        self.assertEqual(result["summary"]["removed_count"], 2)
        self.assertEqual(result["state"]["phase"], "completed")

    def test_drift_after_delete_is_retained_as_pending_and_blocks_remaining_deletes(self):
        def before_read(cloud):
            if cloud.reads == 4:
                cloud.report["images"][4]["tags"].append("external-tag")

        self.cloud.before_read = before_read
        with self.assertRaisesRegex(mod.RetentionError, "inventory_drift"):
            self.run_cleanup()
        self.assertEqual(self.cloud.deleted, [fixtures.image("c")])
        self.assertEqual(self.saved.latest["pending"], fixtures.image("c"))
        with self.assertRaisesRegex(mod.RetentionError, "inventory_drift"):
            self.run_cleanup(state=self.saved.latest)
        self.assertEqual(self.cloud.deleted, [fixtures.image("c")])

    def test_persisted_campaign_binds_ownership_protection_and_exact_selection(self):
        prepared = self.prepared()
        malformed = copy.deepcopy(prepared)
        malformed["version"] = True
        malformed["plan_sha256"] = mod.prune.digest(mod._plan_payload(malformed))
        with self.assertRaisesRegex(mod.RetentionError, "identity_invalid"):
            self.run_cleanup(state=malformed)
        changed = copy.deepcopy(prepared)
        changed["selected"].append(CURRENT)
        changed["plan_sha256"] = mod.prune.digest(mod._plan_payload(changed))
        with self.assertRaisesRegex(mod.RetentionError, "selection_invalid"):
            self.run_cleanup(state=changed)
        changed_owned = [*self.owned, {"digest": CURRENT, "release": release(99)}]
        with self.assertRaisesRegex(mod.RetentionError, "identity_invalid"):
            self.run_cleanup(state=prepared, owned=changed_owned)
        with self.assertRaisesRegex(mod.RetentionError, "identity_invalid"):
            self.run_cleanup(state=prepared, pending=fixtures.image("c"))
        self.assertEqual(self.cloud.deleted, [])

    def test_expired_campaign_never_issues_a_new_delete(self):
        prepared = self.prepared()
        with patch.object(
            mod,
            "now",
            return_value=mod.prune.timestamp(prepared["expires_at"]) + timedelta(seconds=1),
        ):
            with self.assertRaisesRegex(mod.RetentionError, "plan_expired"):
                self.run_cleanup(state=prepared)
        self.assertEqual(self.cloud.deleted, [])

    def test_snapshot_inputs_and_callback_saved_states_do_not_mutate_in_place(self):
        original = copy.deepcopy(self.snapshot)
        mod.selection(self.snapshot, self.owned, CURRENT, ROLLBACK)
        self.assertEqual(self.snapshot, original)
        held = []
        self.run_cleanup(persist=lambda state: held.append(state))
        self.assertEqual(held[0]["phase"], "prepared")
        self.assertEqual(held[0]["removed"], [])
        self.assertTrue(any(state["phase"] == "deletion_pending" for state in held))
        self.assertEqual(held[-1]["phase"], "completed")


if __name__ == "__main__":
    unittest.main()
