"""Bounded deletion of ledger-owned scheduled-update images.

The caller supplies the private ownership ledger, durable compare-and-swap
checkpoint persistence and a maintenance lease. No cloud command runs at import
time. Inventory is the complete read-only Inspector report, including a verified
rollback checkpoint, rather than a list filtered to the automatic releases.
"""

from __future__ import annotations

import copy
import importlib.util
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_SPEC = importlib.util.spec_from_file_location(
    "scheduled_registry_prune", Path(__file__).with_name("prune-registry.py")
)
prune = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prune)

SCOPE = "scheduled_owned_full_worker_retention"
MAX_CANDIDATES = 20
MAX_LIVE_OWNED = 4
MAX_OWNERSHIP_RECORDS = 1000
MAX_AGE = timedelta(hours=24)


class RetentionError(RuntimeError):
    """A source-controlled failure category safe for public operator logs."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def _ownership(owned: Any) -> list[dict[str, str]]:
    if not isinstance(owned, list) or len(owned) > MAX_OWNERSHIP_RECORDS:
        raise RetentionError("ownership_ledger_invalid")
    releases: dict[str, str] = {}
    pairs: set[tuple[str, str]] = set()
    for item in owned:
        if (
            not isinstance(item, dict)
            or set(item) != {"digest", "release"}
            or not isinstance(item["digest"], str)
            or not prune.WORKER_IMAGE.fullmatch(item["digest"])
            or not isinstance(item["release"], str)
            or not prune.RELEASE.fullmatch(item["release"])
        ):
            raise RetentionError("ownership_ledger_invalid")
        previous = releases.setdefault(item["release"], item["digest"])
        if previous != item["digest"]:
            raise RetentionError("ownership_release_has_conflicting_digests")
        pairs.add((item["digest"], item["release"]))
    return [{"digest": digest, "release": release} for digest, release in sorted(pairs)]


def _snapshot(snapshot: Any) -> dict[str, Any]:
    try:
        normalized = prune.normalize(snapshot)
        observed = prune.timestamp(snapshot["observed_at"])
    except (prune.GuardError, KeyError, TypeError, ValueError):
        raise RetentionError("inventory_not_fully_verified") from None
    if observed > now() + timedelta(minutes=5) or now() - observed > MAX_AGE:
        raise RetentionError("inventory_stale_or_future_dated")
    return normalized


def _protection(
    baseline: dict[str, Any], current: str, rollback: str, pending: str | None
) -> dict[str, str | None]:
    if (
        not isinstance(current, str)
        or not prune.WORKER_IMAGE.fullmatch(current)
        or not isinstance(rollback, str)
        or not prune.WORKER_IMAGE.fullmatch(rollback)
        or current == rollback
        or (
            pending is not None
            and (not isinstance(pending, str) or not prune.WORKER_IMAGE.fullmatch(pending))
        )
    ):
        raise RetentionError("protected_digests_invalid")
    current_refs = {
        row["image"]
        for row in baseline["references"]
        if row["kind"] == "job"
        and row["resource"] == "malscan-v2-static-demo"
        and row["region"] == prune.REGION
    }
    rollback_refs = {
        row["image"]
        for row in baseline["references"]
        if row["kind"] == "rollback_checkpoint" and row["region"] == prune.REGION
    }
    if current_refs != {current} or rollback_refs != {rollback}:
        raise RetentionError("protected_digests_do_not_match_inventory")
    return {"current": current, "rollback": rollback, "pending": pending}


def _select(
    baseline: dict[str, Any],
    owned: list[dict[str, str]],
    protection: dict[str, str | None],
) -> list[str]:
    tags_by_digest: dict[str, set[str]] = {}
    for item in owned:
        tags_by_digest.setdefault(item["digest"], set()).add(item["release"])
    rows = {row["image"]: row for row in baseline["images"]}
    protected = set(protection.values()) - {None}
    cutoff = min(
        prune.timestamp(rows[str(protection[name])]["createTime"])
        for name in ("current", "rollback")
    )
    selected = [
        row
        for row in baseline["images"]
        if row["image"] in tags_by_digest
        and row["image"] not in protected
        and row["classification"] == "unclassified"
        and row["reported_media_type"] == prune.MANIFEST
        and row["tags"]
        and set(row["tags"]) <= tags_by_digest[row["image"]]
        and prune.timestamp(row["createTime"]) < cutoff
    ]
    if len(selected) > MAX_CANDIDATES:
        raise RetentionError("cleanup_candidate_count_exceeds_bound")
    selected.sort(key=lambda row: (prune.timestamp(row["createTime"]), row["image"]))
    return [row["image"] for row in selected]


def selection(
    snapshot: Any,
    owned: Any,
    current: str,
    rollback: str,
    pending: str | None = None,
) -> list[str]:
    """Select only exact ledger-owned, older, unreferenced Docker image versions."""
    baseline = _snapshot(snapshot)
    protection = _protection(baseline, current, rollback, pending)
    return _select(baseline, _ownership(owned), protection)


def live_owned_count(snapshot: Any, owned: Any) -> int:
    """Count actual existing owned digests; displayed sizes do not predict savings."""
    baseline = _snapshot(snapshot)
    ledger = _ownership(owned)
    present = {row["image"] for row in baseline["images"]}
    return len({item["digest"] for item in ledger} & present)


def _plan_payload(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: state[key]
        for key in (
            "version",
            "scope",
            "created_at",
            "observed_at",
            "expires_at",
            "baseline",
            "ownership_sha256",
            "protection",
            "selected",
        )
    }


def _report_for_baseline(state: dict[str, Any]) -> dict[str, Any]:
    return {
        **state["baseline"],
        "schema_version": 1,
        "scope": "read_only_registry_cleanup_inventory",
        "project": prune.PROJECT,
        "repository_region": prune.REGION,
        "observed_at": state["observed_at"],
        "readiness_issues": [],
        "protected_versions_not_listed": [],
        "remote_mutations": False,
        "cloud_run_executed": False,
        "cloud_run_list_scope": "all project regions with command-scoped run/region cleared",
    }


def _validate_state(
    state: Any, owned: list[dict[str, str]], protection: dict[str, str | None]
) -> dict[str, Any]:
    try:
        if (
            not isinstance(state, dict)
            or not isinstance(state.get("version"), int)
            or isinstance(state["version"], bool)
            or state["version"] != 1
            or (
                state.get("scope") != SCOPE
                or state.get("plan_sha256") != prune.digest(_plan_payload(state))
                or state.get("ownership_sha256") != prune.digest(owned)
                or state.get("protection") != protection
            )
        ):
            raise RetentionError("cleanup_state_identity_invalid")
        created = prune.timestamp(state["created_at"])
        observed = prune.timestamp(state["observed_at"])
        expires = prune.timestamp(state["expires_at"])
        if (
            expires != min(created + MAX_AGE, observed + MAX_AGE)
            or observed > created + timedelta(minutes=5)
            or created - observed > MAX_AGE
            or created > now() + timedelta(minutes=5)
        ):
            raise RetentionError("cleanup_state_time_bounds_invalid")
        baseline = prune.normalize(_report_for_baseline(state))
        if (
            baseline != state["baseline"]
            or _protection(
                baseline,
                str(protection["current"]),
                str(protection["rollback"]),
                protection["pending"],
            )
            != protection
        ):
            raise RetentionError("cleanup_state_baseline_invalid")
        if state["selected"] != _select(baseline, owned, protection):
            raise RetentionError("cleanup_state_selection_invalid")
        removed = state["removed"]
        pending = state["pending"]
        phase = state["phase"]
        if (
            not isinstance(removed, list)
            or len(set(removed)) != len(removed)
            or not set(removed) <= set(state["selected"])
            or pending is not None
            and (pending not in state["selected"] or pending in removed)
            or phase not in {"prepared", "partial", "deletion_pending", "uncertain", "completed"}
            or bool(pending) != (phase in {"deletion_pending", "uncertain"})
            or phase == "completed"
            and set(removed) != set(state["selected"])
        ):
            raise RetentionError("cleanup_state_progress_invalid")
    except (prune.GuardError, KeyError, TypeError, ValueError):
        raise RetentionError("cleanup_state_invalid") from None
    return copy.deepcopy(state)


def run(
    inspect: Callable[[], dict[str, Any]],
    delete: Callable[[str], Any],
    persist: Callable[[dict[str, Any]], Any],
    owned: Any,
    current: str,
    rollback: str,
    pending: str | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconcile/apply one campaign under the caller's durable maintenance lease.

    persist must perform a durable compare-and-swap before returning. A failed
    persist propagates before any next mutation. Callers must preserve the saved
    pending state on cancellation, and may not silently reset uncertain campaigns.
    Only a completed campaign may be discarded before preparing a later baseline.
    """
    ledger = _ownership(owned)

    def fresh() -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            report = inspect()
        except Exception:
            raise RetentionError("inventory_read_failed") from None
        normalized = _snapshot(report)
        _protection(normalized, current, rollback, pending)
        return report, normalized

    report, baseline = fresh()
    protection = _protection(baseline, current, rollback, pending)

    def save(value: dict[str, Any]) -> None:
        # Never let a callback retain a mutable reference to a later state.
        persist(copy.deepcopy(value))

    if state is None:
        created = now()
        state = {
            "version": 1,
            "scope": SCOPE,
            "created_at": created.isoformat(),
            "observed_at": report["observed_at"],
            "expires_at": min(
                created + MAX_AGE, prune.timestamp(report["observed_at"]) + MAX_AGE
            ).isoformat(),
            "baseline": baseline,
            "ownership_sha256": prune.digest(ledger),
            "protection": protection,
            "selected": _select(baseline, ledger, protection),
            "removed": [],
            "pending": None,
            "phase": "prepared",
        }
        state["plan_sha256"] = prune.digest(_plan_payload(state))
        save(state)
    else:
        state = _validate_state(state, ledger, protection)

    def refresh() -> None:
        report, observed = fresh()
        removed = set(state["removed"])
        in_flight = state["pending"]
        present = {row["image"] for row in observed["images"]}
        if in_flight and in_flight not in present:
            removed.add(in_flight)
        expected = copy.deepcopy(state["baseline"])
        expected["images"] = [row for row in expected["images"] if row["image"] not in removed]
        if observed != expected:
            raise RetentionError("inventory_drift_before_further_deletion")
        if in_flight:
            if in_flight in present:
                state["phase"] = "uncertain"
                save(state)
                raise RetentionError("pending_digest_present_no_automatic_retry")
            state["removed"] = sorted(removed)
            state["pending"] = None
            state["phase"] = "partial"
            save(state)
        state["observed_version_count"] = len(observed["images"])
        size = report["repository"].get("sizeBytes")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            state["observed_repository_size_bytes"] = size

    refresh()
    for uri in state["selected"]:
        if uri in state["removed"]:
            continue
        if now() >= prune.timestamp(state["expires_at"]):
            raise RetentionError("cleanup_plan_expired")
        refresh()
        state.update(pending=uri, phase="deletion_pending")
        save(state)
        try:
            delete(uri)
        except Exception:
            state["phase"] = "uncertain"
            save(state)
            raise RetentionError("delete_outcome_uncertain") from None
        refresh()
    state["phase"] = "completed"
    save(state)
    return {
        "state": state,
        "summary": {
            "scope": SCOPE,
            "phase": state["phase"],
            "candidate_count": len(state["selected"]),
            "removed_count": len(state["removed"]),
            "pending": state["pending"],
            "observed_version_count": state.get("observed_version_count"),
            "observed_repository_size_bytes": state.get("observed_repository_size_bytes"),
            "cloud_run_executed": False,
            "billed_savings_verified": False,
        },
    }
