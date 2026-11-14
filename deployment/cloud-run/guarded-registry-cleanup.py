#!/usr/bin/env python3
"""Bound a legacy-image cleanup to a paused, unchanged approved updater.

This local adapter performs fresh provider reads around the frozen cleanup
journal. Pause/enable remain explicit operations of setup-auto-update.py.
Provider reads and deletion are not atomic; other operators must avoid writes.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prune = module("guarded_cleanup_prune", "prune-registry.py")
setup = module("guarded_cleanup_setup", "setup-auto-update.py")
auto = module("guarded_cleanup_auto", "auto_update.py")
SCOPE = "guarded_paused_full_worker_cleanup"
SCHEDULER_URL = (
    "https://cloudscheduler.googleapis.com/v1/projects/"
    f"{setup.PROJECT}/locations/{setup.REGION}/jobs/{setup.SCHEDULER}"
)


def private(path, home, *, directory=False):
    """Use private nonsymlink paths under the real home, outside the checkout."""
    result = prune.private_location(path, home, directory=directory)
    for ancestor in result.parents:
        if ancestor == home.resolve():
            break
        if ancestor.exists() and ancestor.stat().st_mode & 0o077:
            raise prune.GuardError("operation_parent_directory_must_be_private")
    return result


class Adapter:
    def __init__(self, plan_dir, *, home=None, provisioner=None, inspector=None, delete=None):
        self.home = (home or Path.home()).resolve()
        self.plan_dir = private(plan_dir, self.home, directory=True)
        self.provided = provisioner
        self.inspector = inspector or (lambda home: prune.inventory.Inspector(home=home).inspect())
        self.delete = delete or prune.delete_image
        self.binding = None

    def guard(self, binding=None):
        """Read the approved setup, scheduler, current job and absent lease each time."""
        try:
            tool = self.provided or setup.Provisioner(self.plan_dir)
            state, generation = tool._approved_state(check_current=True)
            scheduler = tool.get(SCHEDULER_URL)
            if (
                not isinstance(scheduler, dict)
                or scheduler.get("state") != "PAUSED"
                or not setup.subset(
                    tool.scheduler_document(), setup.normalized_scheduler(scheduler)
                )
            ):
                raise prune.GuardError("scheduler_not_paused_or_configuration_changed")
            lease, lease_generation = tool.store.load_json("lease.json")
            if (
                state.get("enabled") is not False
                or state.get("active") is not None
                or lease is not None
                or lease_generation != 0
            ):
                raise prune.GuardError("coordinator_not_disabled_idle_and_lease_free")
            if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
                raise prune.GuardError("coordinator_generation_invalid")
            current = state["current"]
            observed = {
                "setup_plan_sha256": setup.digest(tool.plan),
                "setup_plan_dir": str(self.plan_dir),
                "coordinator_generation": generation,
                "current_image": current["image"],
                "rollback_image": current["rollback_image"],
                "current_checkpoint_sha256": setup.digest(current),
                "scheduler_configuration_sha256": setup.digest(tool.scheduler_document()),
            }
            expected = binding if binding is not None else self.binding
            if expected is not None and observed != expected:
                raise prune.GuardError("paused_cleanup_binding_changed")
            return copy.deepcopy(state), observed
        except prune.GuardError:
            raise
        except Exception:
            raise prune.GuardError("approved_updater_readback_failed") from None

    def inspect(self):
        state, observed = self.guard()
        if self.binding is None:
            self.binding = observed
        try:
            with tempfile.TemporaryDirectory(
                prefix=".malscan-registry-inspection-", dir=self.home
            ) as directory:
                temporary_home = Path(directory)
                files = state["current"]["files"]
                release = files["state.json"]["release"]
                if not isinstance(release, str) or not prune.RELEASE.fullmatch(release):
                    raise prune.GuardError("current_checkpoint_release_invalid")
                checkpoint = temporary_home / ".malscan-v2-operations/maintenance" / release
                auto.Controller._restore(None, checkpoint, files)
                report = self.inspector(temporary_home)
            self.guard()
            return report
        except prune.GuardError:
            raise
        except Exception:
            raise prune.GuardError("current_registry_inventory_failed") from None


def prepare(
    plan_dir,
    inventory_path,
    inventory_sha256,
    output,
    *,
    home=None,
    provisioner=None,
    inspector=None,
):
    adapter = Adapter(plan_dir, home=home, provisioner=provisioner, inspector=inspector)
    output = private(output, adapter.home, directory=True)
    if output.exists():
        raise prune.GuardError("operation_directory_must_be_new")
    inventory_path = private(inventory_path, adapter.home)
    reviewed = prune.read_inventory(inventory_path, inventory_sha256)
    review_plan = prune.make_plan(reviewed, source_sha256=inventory_sha256)
    fresh = adapter.inspect()
    fresh_plan = prune.make_plan(fresh, source_sha256=inventory_sha256)
    if fresh_plan["candidates"] != review_plan["candidates"]:
        raise prune.GuardError("fresh_candidates_differ_from_reviewed_set")
    if fresh_plan["baseline"] != review_plan["baseline"]:
        raise prune.GuardError("fresh_inventory_differs_from_reviewed_inventory")
    payload = {
        "version": 1,
        "scope": SCOPE,
        "operation_dir": str(output),
        "reviewed_inventory_sha256": inventory_sha256,
        "binding": adapter.binding,
        "cleanup_plan": fresh_plan,
    }
    wrapped = {**payload, "sha256": setup.digest(payload)}
    prune.ensure_directory(output, adapter.home)
    private(output, adapter.home, directory=True)
    prune.write_private(output / "guarded-registry-operation.json", wrapped, exclusive=True)
    return {
        "scope": SCOPE,
        "phase": "prepared",
        "candidate_count": len(fresh_plan["candidates"]),
        "operation_dir": str(output),
        "cleanup_expires_at": fresh_plan["expires_at"],
        "remote_mutations": False,
        "cloud_run_executed": False,
        "scheduler_or_controller_changed": False,
    }


class Operation:
    def __init__(
        self,
        operation_dir,
        plan_dir,
        *,
        home=None,
        provisioner=None,
        inspector=None,
        delete=None,
    ):
        self.adapter = Adapter(
            plan_dir, home=home, provisioner=provisioner, inspector=inspector, delete=delete
        )
        self.directory = private(operation_dir, self.adapter.home, directory=True)
        path = self.directory / "guarded-registry-operation.json"
        wrapped = prune.read_json(path, home=self.adapter.home)
        if not isinstance(wrapped, dict):
            raise prune.GuardError("operation_record_invalid")
        payload = {key: value for key, value in wrapped.items() if key != "sha256"}
        if (
            wrapped.get("sha256") != setup.digest(payload)
            or set(payload)
            != {
                "version",
                "scope",
                "operation_dir",
                "reviewed_inventory_sha256",
                "binding",
                "cleanup_plan",
            }
            or payload.get("version") != 1
            or payload.get("scope") != SCOPE
            or payload.get("operation_dir") != str(self.directory)
            or not isinstance(payload.get("binding"), dict)
            or not isinstance(payload.get("reviewed_inventory_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", payload["reviewed_inventory_sha256"])
        ):
            raise prune.GuardError("operation_record_changed_or_invalid")
        self.plan = prune.validate_plan(payload["cleanup_plan"], expired_ok=True)
        if self.plan["source_inventory_sha256"] != payload["reviewed_inventory_sha256"]:
            raise prune.GuardError("operation_review_identity_changed")
        self.adapter.binding = payload["binding"]
        self.cleanup = prune.Cleanup(
            self.plan,
            self.directory / "state",
            home=self.adapter.home,
            inspect=self.adapter.inspect,
            delete=self.delete,
        )

    def delete(self, uri):
        self.adapter.guard()
        state = self.cleanup.load(allow_initialize=False)
        if (
            uri not in self.plan["candidates"]
            or state["pending"] != uri
            or state["phase"] != "deletion_pending"
            or state["remote_mutations_attempted"] is not True
        ):
            raise prune.GuardError("persisted_delete_intent_not_verified")
        self.adapter.delete(uri)

    def run(self, *, apply):
        result = self.cleanup.run(apply=apply)
        return {
            "scope": SCOPE,
            "phase": result["phase"],
            "candidate_count": result["candidate_count"],
            "removed_count": result["removed_count"],
            "pending_intent_present": result["pending"] is not None,
            "observed_version_count": result["observed_version_count"],
            "cloud_run_executed": False,
            "scheduler_or_controller_changed": False,
            "automatic_delete_retry": False,
            "billed_savings_verified": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    command = commands.add_parser("prepare")
    command.add_argument("--plan-dir", type=Path, required=True)
    command.add_argument("--inventory", type=Path, required=True)
    command.add_argument("--inventory-sha256", required=True)
    command.add_argument("--output", type=Path, required=True)
    for name in ("apply", "check"):
        command = commands.add_parser(name)
        command.add_argument("--plan-dir", type=Path, required=True)
        command.add_argument("--operation-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            result = prepare(args.plan_dir, args.inventory, args.inventory_sha256, args.output)
        else:
            result = Operation(args.operation_dir, args.plan_dir).run(
                apply=args.operation == "apply"
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as error:
        # Do not disclose provider payloads, filesystem names or credential values.
        reason = str(error) if isinstance(error, prune.GuardError) else "guarded_cleanup_failed"
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": SCOPE,
                    "error": reason,
                    "cloud_run_executed": False,
                    "automatic_delete_retry": False,
                    "scheduler_or_controller_changed": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
