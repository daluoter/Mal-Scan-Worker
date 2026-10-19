"""Verified references for occurrences whose identical content was analyzed once.

References are assembled from trusted persisted reports, never from a filename or
hash alone. Referenced stages remain separate from an occurrence's direct stages.
"""

from __future__ import annotations

import re
from pathlib import PurePath
from typing import Any

from malscan.analysis_contract import analysis_from_report, build_analysis

REFERENCE_SCHEMA_VERSION = "mswr-artifact-reference-v1"
_BASIC_STAGES = {"file-type", "clamav", "yara", "ioc-extract", "deobfuscation"}
_OPTIONAL_STAGE_REASONS = {
    "format-analysis": "No analyzer matched",
    "archive-extract": "Not an archive",
    "document-analysis": "Not a supported document format",
}
_SUCCESS = {"ok", "complete", "completed"}


def _complete_source(reference: dict[str, Any]) -> bool:
    coverage = reference["source_stage_coverage"]
    names = [item["stage"] for item in coverage]
    if (
        reference["source_analysis_status"] != "complete"
        or not reference["source_coverage_consistent"]
        or len(names) != len(set(names))
        or set(names) != _BASIC_STAGES | set(_OPTIONAL_STAGE_REASONS)
    ):
        return False
    for stage in coverage:
        if stage["status"] in _SUCCESS:
            continue
        if (
            stage["stage"] not in _OPTIONAL_STAGE_REASONS
            or stage["status"] not in {"skipped", "not_applicable"}
            or stage.get("reason") != _OPTIONAL_STAGE_REASONS[stage["stage"]]
        ):
            return False
    return True


def _direct_reference(
    node: dict[str, Any], report: dict[str, Any], root_id: str, root_job_id: str | None
) -> dict[str, Any] | None:
    file_info = report.get("file")
    file_info = file_info if isinstance(file_info, dict) else {}
    sha256 = node.get("sha256")
    size = node.get("size")
    if (
        not isinstance(sha256, str)
        or re.fullmatch(r"[a-f0-9]{64}", sha256) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(file_info.get("size"), int)
        or isinstance(file_info.get("size"), bool)
        or file_info.get("sha256") != sha256
        or file_info.get("size") != size
        or file_info.get("original_filename") != node.get("filename")
        or not isinstance(node.get("job_id"), str)
        or report.get("job_id") != node["job_id"]
        or node.get("root_artifact_id", root_id) != root_id
        or node.get("root_job_id", root_job_id) != root_job_id
    ):
        return None
    analysis = analysis_from_report(report, node.get("job_status"))
    timings = report.get("timings")
    timings = timings if isinstance(timings, dict) else {}
    stages = timings.get("stages")
    recorded_analysis = build_analysis(
        stages=stages if isinstance(stages, list) else [],
        job_status=node.get("job_status"),
    )
    coverage = recorded_analysis["static"]["stage_coverage"]

    def coverage_identity(items: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
        return sorted(
            (str(item["stage"]), str(item["status"]), str(item.get("reason") or ""))
            for item in items
        )

    risk = report.get("risk")
    risk = risk if isinstance(risk, dict) else {}
    evidence = risk.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else []
    return {
        "schema_version": REFERENCE_SCHEMA_VERSION,
        "mode": "direct",
        "status": "verified",
        "source_artifact_id": str(node["id"]),
        "source_job_id": node["job_id"],
        "source_root_artifact_id": root_id,
        "source_root_job_id": root_job_id,
        "source_sha256": sha256,
        "source_size": size,
        "source_filename": node.get("filename"),
        "source_analysis_status": recorded_analysis["static"]["status"],
        "source_coverage_consistent": (
            analysis["static"]["status"] == recorded_analysis["static"]["status"]
            and coverage_identity(analysis["static"]["stage_coverage"])
            == coverage_identity(coverage)
        ),
        "source_stage_coverage": coverage,
        "source_evidence_ids": [
            str(item.get("id") or item.get("evidence_id"))
            for item in evidence
            if isinstance(item, dict) and (item.get("id") or item.get("evidence_id"))
        ],
        "source_finding_ids": [
            f"finding::{node['id']}::{index}"
            for index, item in enumerate(evidence, start=1)
            if isinstance(item, dict)
        ],
        "risk": {key: report.get(key) for key in ("score", "risk_level", "verdict")},
    }


def resolve_artifact_analysis_references(
    tree: dict[str, Any], reports_by_artifact: dict[str, dict[str, Any]]
) -> None:
    """Attach direct or verified one-hop references without persisting new rows.

    Only un-dispatched extraction duplicates can inherit. Missing, incomplete,
    cyclic, cross-root, and mismatched references remain unknown. A source must
    have a completed job and actual successful stage evidence; an explicit stored
    ``complete`` flag without stages cannot authorize a duplicate's coverage.
    """
    # A nested report can show only its requested subtree while retaining the
    # authoritative enclosing-root binding from persisted artifact records.
    root_id = str(tree.get("root_artifact_id") or tree["id"])
    root_job_id = tree.get("root_job_id") or tree.get("job_id")
    nodes: dict[str, dict[str, Any]] = {}

    def collect(node: dict[str, Any]) -> None:
        artifact_id = str(node["id"])
        if artifact_id in nodes:
            return
        nodes[artifact_id] = node
        for child in node.get("children", []):
            collect(child)

    collect(tree)

    def subtree_complete(node: dict[str, Any], seen: set[str] | None = None) -> bool:
        seen = set() if seen is None else seen
        artifact_id = str(node["id"])
        if artifact_id in seen:
            return False
        seen.add(artifact_id)
        reference = node.get("analysis_reference") or {}
        return (
            node.get("analysis_status") == "complete"
            and reference.get("status") == "verified"
            and all(subtree_complete(child, seen) for child in node.get("children", []))
        )

    direct: dict[str, dict[str, Any]] = {}
    requested_sources: dict[str, str] = {}
    for artifact_id, node in nodes.items():
        previous = node.get("analysis_reference")
        if isinstance(previous, dict) and previous.get("mode") == "inherited":
            requested_sources[artifact_id] = str(previous.get("source_artifact_id") or "")
        report = reports_by_artifact.get(artifact_id)
        reference = (
            _direct_reference(node, report, root_id, root_job_id)
            if isinstance(report, dict)
            else None
        )
        if reference is not None:
            direct[artifact_id] = reference
            node["analysis_reference"] = reference
            node["analysis_status"] = reference["source_analysis_status"]
            analysis = analysis_from_report(report or {}, node.get("job_status"))
            analysis["static"] = {
                "status": reference["source_analysis_status"],
                "stage_coverage": reference["source_stage_coverage"],
            }
            node["analysis"] = analysis
        else:
            node["analysis_reference"] = {
                "schema_version": REFERENCE_SCHEMA_VERSION,
                "mode": "unresolved",
                "status": "unresolved",
                "reason": "direct_report_unverified",
            }

    for artifact_id, node in nodes.items():
        if node.get("extraction_note") != "duplicate_within_extraction" or node.get("job_id"):
            continue
        eligible = [
            source_id
            for source_id, reference in direct.items()
            if source_id != artifact_id
            and reference["source_sha256"] == node.get("sha256")
            and reference["source_size"] == node.get("size")
            # Format selection can depend on the suffix even for identical bytes.
            # A .txt scan cannot complete the coverage of a .ps1 occurrence.
            and isinstance(reference["source_filename"], str)
            and isinstance(node.get("filename"), str)
            and PurePath(reference["source_filename"]).suffix.lower()
            == PurePath(node["filename"]).suffix.lower()
            and nodes[source_id].get("job_status") == "done"
            and _complete_source(reference)
            and subtree_complete(nodes[source_id])
            and node.get("root_artifact_id", root_id) == root_id
            and node.get("root_job_id", root_job_id) == root_job_id
        ]
        requested = requested_sources.get(artifact_id)
        source_id = requested if requested in eligible else None
        if requested is None and eligible:
            source_id = sorted(eligible)[0]
        if source_id is None:
            node["analysis_reference"]["reason"] = "completed_identical_source_unverified"
            node["analysis_status"] = "unknown"
            node["analysis"] = analysis_from_report({})
            continue
        reference = {**direct[source_id], "mode": "inherited"}
        node["analysis_reference"] = reference
        node["analysis_status"] = "complete"
        # The occurrence did not run these stages. Their evidence is exclusively
        # available under source_stage_coverage and the explicit source identity.
        node["analysis"] = analysis_from_report({})
        node["analysis"]["static"]["status"] = "complete"
