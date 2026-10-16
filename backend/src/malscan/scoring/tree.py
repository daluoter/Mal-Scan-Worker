"""Tree-aware descendant rollup scoring helpers."""

from __future__ import annotations

import re
from math import floor
from typing import Any

from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.policy import (
    DEPTH_DECAY,
    INHERITANCE_BASE,
    INHERITED_SCORE_CAP,
    LEGACY_VERDICT_MAP,
)


def _level_from_score(score: int) -> str:
    if score >= 85:
        return "malicious"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def merge_with_descendants(
    *,
    local: RiskDecision,
    descendants: list[dict[str, Any]],
) -> RiskDecision:
    candidates: list[dict[str, Any]] = []
    source_nodes = {str(item.get("artifact_id")): item for item in descendants}
    for descendant in descendants:
        reference = descendant.get("analysis_reference") or {}
        source = source_nodes.get(str(reference.get("source_artifact_id")))
        source_reference = (source or {}).get("analysis_reference") or {}
        inherited = (
            reference.get("mode") == "inherited"
            and reference.get("status") == "verified"
            and source is not None
            and source_reference.get("mode") == "direct"
            and source_reference.get("status") == "verified"
            and source.get("job_status") == "done"
            and source.get("analysis_status") == "complete"
            and source.get("sha256") == descendant.get("sha256")
            and source.get("size") == descendant.get("size")
            and reference.get("source_sha256") == source.get("sha256")
            and reference.get("source_size") == source.get("size")
            and reference.get("source_job_id") == source.get("job_id")
            and source_reference.get("source_root_artifact_id")
            == reference.get("source_root_artifact_id")
            and source_reference.get("source_root_job_id") == reference.get("source_root_job_id")
        )
        if descendant.get("verdict") == "skipped" and not inherited:
            continue
        if descendant.get("extraction_note") == "duplicate_within_extraction" and not inherited:
            continue
        candidate = dict(descendant)
        if inherited:
            risk = reference.get("risk") or {}
            if (
                not isinstance(risk.get("score"), int)
                or isinstance(risk.get("score"), bool)
                or not 0 <= risk["score"] <= 100
                or risk.get("risk_level") not in INHERITANCE_BASE
            ):
                continue
            candidate.update(
                risk_score=risk["score"],
                risk_level=risk["risk_level"],
                verdict=risk.get("verdict"),
            )
        candidates.append(candidate)

    # Pick the strongest, nearest occurrence before hash deduplication. Traversal
    # order must not suppress a direct malicious child behind a deeper copy.
    candidates.sort(
        key=lambda item: (
            -INHERITANCE_BASE.get(str(item.get("risk_level")), -1),
            int(item.get("relative_depth") or 0),
            -int(item.get("risk_score") or 0),
            str(item.get("artifact_id") or ""),
            str(item.get("display_path") or item.get("origin_path") or ""),
        )
    )
    content_groups: dict[str, list[dict[str, Any]]] = {}
    for index, item in enumerate(candidates):
        digest = item.get("sha256")
        key = (
            digest.lower()
            if isinstance(digest, str) and re.fullmatch(r"[a-fA-F0-9]{64}", digest)
            else f"unverified-content::{index}"
        )
        content_groups.setdefault(key, []).append(item)
    top_descendants: list[dict[str, Any]] = []
    branch_scores: list[int] = []
    descendant_components: list[dict[str, Any]] = []
    malicious_descendants = 0
    high_descendants = 0
    direct_child_malicious = False
    any_nearby_high_or_malicious = False

    for occurrences in content_groups.values():
        descendant = occurrences[0]
        level = descendant.get("risk_level", "clean")
        depth = descendant.get("relative_depth") or 0
        base = INHERITANCE_BASE.get(level, 0)
        multiplier = DEPTH_DECAY.get(depth, 0.35)
        inherited_points = floor(base * multiplier)

        descendant_copy = dict(descendant)
        descendant_copy["inherited_points"] = inherited_points
        descendant_copy["occurrences"] = [
            {
                "artifact_id": item.get("artifact_id"),
                "display_path": item.get("display_path") or item.get("origin_path"),
                "relative_depth": item.get("relative_depth"),
                "analysis_mode": (item.get("analysis_reference") or {}).get("mode", "direct"),
                "source_artifact_id": (item.get("analysis_reference") or {}).get(
                    "source_artifact_id"
                ),
            }
            for item in occurrences
        ]
        top_descendants.append(descendant_copy)
        branch_scores.append(inherited_points)
        descendant_components.append(
            {
                "type": "descendant_inheritance",
                "artifact_id": local.evidence[0].artifact_id if local.evidence else None,
                "related_artifact_id": descendant.get("artifact_id"),
                "relative_depth": depth,
                "source_score": int(descendant.get("risk_score") or 0),
                "applied_points": inherited_points,
                "reason": (
                    "direct malicious child artifact inherited into root report"
                    if depth == 1 and level == "malicious"
                    else "descendant risk inherited into root report"
                ),
            }
        )

        if level == "malicious":
            malicious_descendants += 1
            if depth == 1:
                direct_child_malicious = True
        if level == "high":
            high_descendants += 1
        if level in {"high", "malicious"}:
            if depth <= 2:
                any_nearby_high_or_malicious = True

    top_descendants.sort(key=lambda item: item.get("inherited_points", 0), reverse=True)
    branch_scores.sort(reverse=True)
    inherited_score = min(INHERITED_SCORE_CAP, sum(branch_scores[:3]))
    final_score = min(100, local.risk_score + inherited_score)

    malicious_gate_open = local.breakdown.malicious_gate_open
    high_gate_open = local.breakdown.high_gate_open

    if direct_child_malicious:
        final_score = max(final_score, 60)
        high_gate_open = True
    if any_nearby_high_or_malicious:
        high_gate_open = True

    if malicious_descendants >= 2:
        malicious_gate_open = True
        final_score = max(final_score, 85)
    elif direct_child_malicious and local.breakdown.local_score >= 20:
        malicious_gate_open = True
        final_score = max(final_score, 85)

    if not malicious_gate_open:
        final_score = min(final_score, 84)
    if not high_gate_open:
        final_score = min(final_score, 59)

    final_level = _level_from_score(final_score)
    breakdown = ScoreBreakdown(
        local_score=local.breakdown.local_score,
        inherited_score=inherited_score,
        synergy_bonus=local.breakdown.synergy_bonus,
        dampener=local.breakdown.dampener,
        final_score=final_score,
        malicious_gate_open=malicious_gate_open,
        high_gate_open=high_gate_open,
        independent_source_count=local.breakdown.independent_source_count,
    )
    return RiskDecision(
        risk_score=final_score,
        risk_level=final_level,
        legacy_verdict=LEGACY_VERDICT_MAP[final_level],
        evidence=local.evidence,
        top_evidence=local.top_evidence,
        breakdown=breakdown,
        descendant_summary={
            "total_descendants": len(top_descendants),
            "total_occurrences": len(candidates),
            "duplicate_occurrences": len(candidates) - len(top_descendants),
            "malicious_descendants": malicious_descendants,
            "high_descendants": high_descendants,
            "top_descendants": top_descendants[:3],
        },
        policy_version=local.policy_version,
        score_trace={
            "formula": local.score_trace.get("formula", ""),
            "components": [*list(local.score_trace.get("components", [])), *descendant_components],
            "gates": {
                **dict(local.score_trace.get("gates", {})),
                "local_capped_by": local.score_trace.get("gates", {}).get("capped_by"),
                "malicious_gate_open": malicious_gate_open,
                "high_gate_open": high_gate_open,
                "capped_by": (
                    "no_high_gate"
                    if not high_gate_open
                    else "no_malicious_gate"
                    if not malicious_gate_open
                    else None
                ),
            },
            "breakdown": {
                "local_score": local.breakdown.local_score,
                "inherited_score": inherited_score,
                "synergy_bonus": local.breakdown.synergy_bonus,
                "dampener": local.breakdown.dampener,
                "final_score": final_score,
            },
        },
    )
