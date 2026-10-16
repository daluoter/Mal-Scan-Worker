"""Helpers for assembling additive report explainability payloads."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from malscan.analysis_contract import analysis_from_report
from malscan.artifact_references import resolve_artifact_analysis_references


def ensure_artifact_tree_root(
    report: dict[str, Any], artifact_tree: dict[str, Any] | None
) -> dict[str, Any]:
    if artifact_tree is not None:
        return artifact_tree

    file_info = report["file"]
    filename = str(file_info["original_filename"])
    return {
        "id": f"root::{report['job_id']}",
        "filename": filename,
        "sha256": file_info["sha256"],
        "mime": file_info.get("mime"),
        "size": file_info.get("size", 0),
        "depth": 0,
        "origin_path": None,
        "extraction_source": "upload",
        "archive_type": None,
        "extraction_note": None,
        "verdict": report.get("verdict"),
        "score": report.get("score"),
        "risk_level": report.get("risk_level"),
        "policy_version": report.get("risk", {}).get("policy_version"),
        "job_id": report["job_id"],
        "display_path": filename,
        "archive_layer": 0,
        "analysis_status": analysis_from_report(report, report.get("job_status"))["static"][
            "status"
        ],
        "job_status": report.get("job_status"),
        "analysis": analysis_from_report(report, report.get("job_status")),
        "primary_analyzer": None,
        "finding_ids": [],
        "uncertainty_ids": [],
        "diagnostic_ids": [],
        "top_finding_titles": [],
        "children": [],
    }


def build_explainability(
    *,
    report: dict[str, Any],
    artifact_tree: dict[str, Any] | None,
    artifact_reports: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tree = ensure_artifact_tree_root(report, artifact_tree)
    root_aggregate = {
        key: deepcopy(tree[key]) for key in ("analysis", "analysis_status") if key in tree
    }
    if artifact_reports is None:
        artifact_reports = {
            str(item["artifact_id"]): item["report"]
            for item in report.get("artifacts", [])
            if isinstance(item, dict)
            and isinstance(item.get("artifact_id"), str)
            and isinstance(item.get("report"), dict)
        }
    if artifact_reports:
        resolve_artifact_analysis_references(tree, artifact_reports)
        # The root's visible coverage is the complete tree aggregate. Resolving
        # its direct reference must not replace that aggregate with local stages.
        tree.update(root_aggregate)
    artifacts = _flatten_artifacts(tree)
    evidence: list[dict[str, Any]] = []
    for item in report.get("risk", {}).get("evidence", []):
        scoped_item = dict(item)
        artifact_id = str(item.get("artifact_id") or artifacts[0]["artifact_id"])
        raw_id = item.get("id") or item.get("evidence_id") or f"ev-{len(evidence) + 1}"
        scoped_item.update(
            id=(
                raw_id
                if str(raw_id).startswith(f"evidence::{artifact_id}::")
                else f"evidence::{artifact_id}::{raw_id}"
            ),
            artifact_id=artifact_id,
            source_evidence_id=item.get("source_evidence_id") or raw_id,
        )
        evidence.append(scoped_item)
    root_view = {**report, "risk": {**report.get("risk", {}), "evidence": evidence}}
    findings = _build_finding_groups(root_view, artifacts)
    iocs = _build_ioc_records(report, findings, artifacts)
    decoded = _build_decoded_records(report, findings, artifacts)
    for artifact in artifacts[1:]:
        reference = artifact.get("analysis_reference") or {}
        local_report = artifact_reports.get(artifact["artifact_id"])
        if (
            not isinstance(local_report, dict)
            or reference.get("mode") != "direct"
            or reference.get("status") != "verified"
            or not reference.get("source_stage_coverage")
        ):
            continue
        scoped = _scope_artifact_report(local_report, artifact["artifact_id"])
        ordered = [artifact, *[item for item in artifacts if item is not artifact]]
        local_findings = _build_finding_groups(scoped, ordered)
        for finding in local_findings:
            finding["source_report_job_id"] = reference.get("source_job_id")
        findings.extend(local_findings)
        evidence.extend(scoped.get("risk", {}).get("evidence", []))
        iocs.extend(_build_ioc_records(scoped, local_findings, ordered))
        decoded.extend(_build_decoded_records(scoped, local_findings, ordered))
    findings.sort(key=lambda item: -int(item.get("score_impact") or 0))
    findings = _attach_finding_refs(findings, iocs, decoded)
    _attach_analysis_reference_ids(artifacts, findings, evidence)
    uncertainties = _build_uncertainties(report, artifacts)
    diagnostics = _build_failure_diagnostics(report, artifacts)
    timeline = _build_timeline(report, findings, iocs, decoded, artifacts)
    _enrich_tree(tree, findings, uncertainties, diagnostics, artifacts)
    return {
        "summary": _build_summary(report, artifacts, findings),
        "artifacts": artifacts,
        "findings": findings,
        "evidence": evidence,
        "iocs": iocs,
        "decoded_strings": decoded,
        "uncertainties": uncertainties,
        "timeline": timeline,
        "failure_diagnostics": diagnostics,
        "artifact_coverage": {
            "occurrences": len(artifacts),
            "direct": sum(
                item.get("analysis_reference", {}).get("mode") == "direct" for item in artifacts
            ),
            "inherited": sum(
                item.get("analysis_reference", {}).get("mode") == "inherited" for item in artifacts
            ),
            "unresolved": sum(
                item.get("analysis_reference", {}).get("mode") not in {"direct", "inherited"}
                for item in artifacts
            ),
        },
    }


def _scope_artifact_report(report: dict[str, Any], artifact_id: str) -> dict[str, Any]:
    """Scope local identifiers while leaving the scored report unchanged."""
    scoped = deepcopy(report)

    def scoped_id(kind: str, value: Any) -> str:
        prefix = f"{kind}::{artifact_id}::"
        return str(value) if str(value).startswith(prefix) else f"{prefix}{value}"

    for item in scoped.get("risk", {}).get("evidence", []):
        item["artifact_id"] = artifact_id
        raw_id = item.get("id") or item.get("evidence_id")
        if raw_id:
            item["source_evidence_id"] = raw_id
            item["id"] = scoped_id("evidence", raw_id)
        item["decoded_ids"] = [scoped_id("decoded", value) for value in item.get("decoded_ids", [])]
    results = scoped.get("results", {})
    for item in results.get("iocs", {}).get("ioc_items", []) or []:
        item["artifact_id"] = artifact_id
        if item.get("ioc_id"):
            item["ioc_id"] = scoped_id("ioc", item["ioc_id"])
        if item.get("decoded_id"):
            item["decoded_id"] = scoped_id("decoded", item["decoded_id"])
    for item in (results.get("deobfuscation") or {}).get("candidates", []):
        item["artifact_id"] = artifact_id
        if item.get("decoded_id"):
            item["decoded_id"] = scoped_id("decoded", item["decoded_id"])
    return scoped


def _attach_analysis_reference_ids(
    artifacts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> None:
    by_artifact = {item["artifact_id"]: item for item in artifacts}
    for artifact in artifacts:
        reference = artifact.get("analysis_reference") or {}
        if reference.get("mode") == "direct" and reference.get("status") == "verified":
            reference["source_finding_ids"] = [
                item["finding_id"]
                for item in findings
                if item.get("artifact_id") == artifact["artifact_id"]
            ]
            reference["source_evidence_ids"] = [
                item.get("id") or item.get("evidence_id")
                for item in evidence
                if item.get("artifact_id") == artifact["artifact_id"]
                and (item.get("id") or item.get("evidence_id"))
            ]
    for artifact in artifacts:
        reference = artifact.get("analysis_reference")
        reference = reference if isinstance(reference, dict) else {}
        artifact["analysis_reference"] = reference
        direct = reference.get("status") == "verified" and reference.get("mode") == "direct"
        inherited = reference.get("status") == "verified" and reference.get("mode") == "inherited"
        if inherited:
            source = by_artifact.get(reference.get("source_artifact_id"), {})
            source_reference = source.get("analysis_reference") or {}
            for kind in ("finding", "evidence"):
                reference[f"source_{kind}_ids"] = source_reference.get(f"source_{kind}_ids", [])
        for kind in ("finding", "evidence"):
            ids = list(reference.get(f"source_{kind}_ids") or [])
            artifact[f"direct_{kind}_ids"] = ids if direct else []
            artifact[f"inherited_{kind}_ids"] = ids if inherited else []


def _flatten_artifacts(tree: dict[str, Any]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    root_id = str(tree["id"])

    def _walk(
        node: dict[str, Any],
        *,
        parent_id: str | None,
        archive_layer: int,
        path_prefix: str,
        chain: list[dict[str, Any]],
    ) -> None:
        filename = str(node.get("filename") or node.get("origin_path") or node.get("id"))
        origin = node.get("origin_path")
        display_path = filename if not path_prefix else f"{path_prefix}!/{origin or filename}"
        relation = "root" if not chain else "archive_member"
        container_chain = [
            *chain,
            {
                "artifact_id": str(node["id"]),
                "filename": filename,
                "relation": relation,
            },
        ]
        current = dict(node)
        current["artifact_id"] = str(node["id"])
        current["parent_artifact_id"] = parent_id
        current["root_artifact_id"] = root_id
        current["display_path"] = display_path
        current["archive_layer"] = archive_layer
        current["analysis_status"] = current.get("analysis_status") or "unknown"
        current["primary_analyzer"] = current.get("primary_analyzer")
        current["finding_ids"] = list(current.get("finding_ids") or [])
        current["uncertainty_ids"] = list(current.get("uncertainty_ids") or [])
        current["diagnostic_ids"] = list(current.get("diagnostic_ids") or [])
        current["top_finding_titles"] = list(current.get("top_finding_titles") or [])
        current["lineage"] = {
            "depth": int(current.get("depth") or 0),
            "archive_layer": archive_layer,
            "display_path": display_path,
            "origin_path": origin,
            "container_chain": container_chain,
        }
        analysis = current.get("analysis")
        analysis = analysis if isinstance(analysis, dict) else analysis_from_report({})
        # Keep legacy per-artifact fields while adding the shared v1 contract.
        current["analysis"] = {
            **analysis,
            "status": current["analysis_status"],
            "primary_analyzer": current["primary_analyzer"],
            "stage_coverage": analysis.get("static", {}).get("stage_coverage", []),
        }
        current.pop("children", None)
        nodes.append(current)

        child_layer = archive_layer + (1 if node.get("archive_type") else 0)
        for child in node.get("children", []):
            _walk(
                child,
                parent_id=str(node["id"]),
                archive_layer=child_layer,
                path_prefix=display_path,
                chain=container_chain,
            )

    _walk(tree, parent_id=None, archive_layer=0, path_prefix="", chain=[])
    return nodes


def _build_finding_groups(
    report: dict[str, Any], artifacts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    artifact_lookup = {item["artifact_id"]: item for item in artifacts}
    root_artifact_id = artifacts[0]["artifact_id"]
    findings: list[dict[str, Any]] = []
    for index, evidence in enumerate(report.get("risk", {}).get("evidence", []), start=1):
        artifact_id = str(evidence.get("artifact_id") or root_artifact_id)
        artifact = artifact_lookup.get(artifact_id, artifacts[0])
        findings.append(
            {
                "finding_id": f"finding::{artifact_id}::{index}",
                "artifact_id": artifact_id,
                "title": str(evidence.get("reason") or evidence.get("kind") or "finding"),
                "summary": str(evidence.get("reason") or evidence.get("kind") or "finding"),
                "severity": str(evidence.get("severity") or "low"),
                "confidence": (
                    "high" if float(evidence.get("confidence", 0.0) or 0.0) >= 0.85 else "medium"
                ),
                "kind": str(evidence.get("kind") or "generic"),
                "primary": index == 1,
                "score_impact": int(
                    evidence.get("score_contribution", {}).get("applied_points")
                    or evidence.get("points")
                    or 0
                ),
                "found_by": [
                    {
                        "stage": evidence.get("stage") or evidence.get("source"),
                        "analyzer": evidence.get("analyzer"),
                    }
                ],
                "evidence_ids": [evidence.get("id") or evidence.get("evidence_id")],
                "ioc_ids": [],
                "decoded_ids": list(evidence.get("decoded_ids") or []),
                "uncertainty_ids": [],
                "timeline_event_ids": [],
                "artifact_path": artifact.get("display_path") or artifact.get("filename"),
                "archive_layer": int(artifact.get("archive_layer") or 0),
            }
        )
    return findings


def _artifact_lookup(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["artifact_id"]: item for item in artifacts}


def _artifact_id_for_decoded(
    candidate: dict[str, Any], artifact_lookup: dict[str, dict[str, Any]]
) -> str | None:
    artifact_id = candidate.get("artifact_id")
    if artifact_id is not None:
        return str(artifact_id)

    decoded_id = candidate.get("decoded_id")
    if isinstance(decoded_id, str):
        parts = decoded_id.split("::")
        if len(parts) >= 3 and parts[1] in artifact_lookup:
            return parts[1]
    return None


def _related_finding_ids(
    artifact_id: str,
    findings: list[dict[str, Any]],
    *,
    decoded_id: str | None = None,
) -> list[str]:
    matches: list[str] = []
    for finding in findings:
        if finding.get("artifact_id") != artifact_id:
            continue
        if decoded_id is not None:
            decoded_ids = finding.get("decoded_ids") or []
            if decoded_id not in decoded_ids:
                continue
        matches.append(str(finding["finding_id"]))
    return matches


def _build_ioc_records(
    report: dict[str, Any],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifact_lookup = _artifact_lookup(artifacts)
    records: list[dict[str, Any]] = []
    ioc_items = report.get("results", {}).get("iocs", {}).get("ioc_items")
    if isinstance(ioc_items, list) and ioc_items:
        for item in ioc_items:
            if not isinstance(item, dict):
                continue
            artifact_id = str(item.get("artifact_id") or artifacts[0]["artifact_id"])
            if artifact_id not in artifact_lookup:
                artifact_id = artifacts[0]["artifact_id"]
            records.append(
                {
                    "ioc_id": item.get("ioc_id")
                    or f"ioc::{artifact_id}::{item.get('type') or 'ioc'}::{len(records) + 1}",
                    "artifact_id": artifact_id,
                    "type": str(item.get("type") or "ioc"),
                    "value": item.get("value"),
                    "source_stage": item.get("source_stage") or "ioc-extract",
                    "source_kind": item.get("source_kind") or "raw_regex",
                    "decoder": item.get("decoder"),
                    "decoded_id": item.get("decoded_id"),
                    "first_seen_in": None,
                    "finding_ids": _related_finding_ids(
                        artifact_id,
                        findings,
                        decoded_id=str(item.get("decoded_id"))
                        if item.get("decoded_id") is not None
                        else None,
                    ),
                }
            )
        return records

    artifact_id = findings[0]["artifact_id"] if findings else artifacts[0]["artifact_id"]
    primary_finding_id = findings[0]["finding_id"] if findings else None
    results_iocs = report.get("results", {}).get("iocs", {})
    flattened: list[tuple[str, str]] = []
    for ioc_type in ("url", "domain", "ip"):
        field = "ips" if ioc_type == "ip" else f"{ioc_type}s"
        for value in list(results_iocs.get(field, [])):
            flattened.append((ioc_type, value))

    for index, (ioc_type, value) in enumerate(flattened, start=1):
        records.append(
            {
                "ioc_id": f"ioc::{artifact_id}::{ioc_type}::{index}",
                "artifact_id": artifact_id,
                "type": ioc_type,
                "value": value,
                "source_stage": "ioc-extract",
                "source_kind": "report_merge",
                "decoder": None,
                "decoded_id": None,
                "first_seen_in": f"timeline::{index + 1}",
                "finding_ids": [primary_finding_id] if primary_finding_id else [],
            }
        )
    return records


def _build_decoded_records(
    report: dict[str, Any],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifact_lookup = _artifact_lookup(artifacts)
    records: list[dict[str, Any]] = []
    for index, candidate in enumerate(
        report.get("results", {}).get("deobfuscation", {}).get("candidates", []),
        start=1,
    ):
        artifact_id = _artifact_id_for_decoded(candidate, artifact_lookup) or (
            findings[0]["artifact_id"] if findings else artifacts[0]["artifact_id"]
        )
        decoded_id = candidate.get("decoded_id") or f"decoded::{artifact_id}::{index}"
        records.append(
            {
                "decoded_id": decoded_id,
                "artifact_id": artifact_id,
                "source_stage": candidate.get("source_stage") or "deobfuscation",
                "decoder": candidate.get("provenance", {}).get("decoder"),
                "technique": candidate.get("technique"),
                "confidence": candidate.get("confidence", 0.0),
                "content_preview": candidate.get("content", ""),
                "content_encoding": candidate.get("content_encoding"),
                "content_truncated": candidate.get("content_truncated", False),
                "provenance": candidate.get("provenance", {}),
                "ioc_ids": [],
                "finding_ids": _related_finding_ids(
                    artifact_id, findings, decoded_id=str(decoded_id)
                ),
            }
        )
    return records


def _attach_finding_refs(
    findings: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    decoded: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not findings:
        return findings

    finding_by_id = {str(item["finding_id"]): item for item in findings}
    for item in iocs:
        for finding_id in item.get("finding_ids", []):
            finding = finding_by_id.get(str(finding_id))
            if finding is not None and item["ioc_id"] not in finding["ioc_ids"]:
                finding["ioc_ids"].append(item["ioc_id"])
    for item in decoded:
        if not item.get("finding_ids"):
            item["finding_ids"] = _related_finding_ids(
                item["artifact_id"], findings, decoded_id=item["decoded_id"]
            )
        matching_iocs = [
            ioc["ioc_id"]
            for ioc in iocs
            if ioc.get("artifact_id") == item.get("artifact_id")
            or ioc.get("decoded_id") == item.get("decoded_id")
        ]
        item["ioc_ids"] = matching_iocs
        for finding_id in item.get("finding_ids", []):
            finding = finding_by_id.get(str(finding_id))
            if finding is None:
                continue
            if item["decoded_id"] not in finding["decoded_ids"]:
                finding["decoded_ids"].append(item["decoded_id"])
            for ioc_id in matching_iocs:
                if ioc_id not in finding["ioc_ids"]:
                    finding["ioc_ids"].append(ioc_id)
    return findings


def _build_uncertainties(
    report: dict[str, Any], artifacts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    uncertainties: list[dict[str, Any]] = []
    if int(report.get("risk", {}).get("breakdown", {}).get("inherited_score") or 0) > 0:
        uncertainties.append(
            {
                "uncertainty_id": f"uncertainty::{artifacts[0]['artifact_id']}::1",
                "artifact_id": artifacts[0]["artifact_id"],
                "kind": "tree_inheritance_elevated_root",
                "severity": "low",
                "direction": "context_only",
                "message": "最外層檔案的判定是由子層檔案風險繼承所抬升。",
                "finding_ids": [],
            }
        )
    return uncertainties


def _build_failure_diagnostics(
    report: dict[str, Any], artifacts: list[dict[str, Any]]
) -> dict[str, Any]:
    archive_extract = report.get("results", {}).get("archive_extract") or {}
    if archive_extract.get("extraction_failed"):
        return {
            "status": "blocked",
            "headline": "內層封存內容因密碼耗盡而無法分析。",
            "diagnostics": [
                {
                    "diagnostic_id": f"diag::{artifacts[0]['artifact_id']}::archive-extract::1",
                    "artifact_id": artifacts[0]["artifact_id"],
                    "stage": "archive-extract",
                    "code": "password_attempts_exhausted",
                    "category": "blocked",
                    "severity": "high",
                    "likely_effect": "possible_false_negative",
                    "confidence": "high",
                    "message": (
                        archive_extract.get("reason") or "連續 3 次密碼錯誤，封存檔解壓失敗。"
                    ),
                    "recommended_action": "請取得正確密碼後重新提交分析。",
                }
            ],
            "suspected_miss_stages": [
                {
                    "artifact_id": artifacts[0]["artifact_id"],
                    "stage": "archive-extract",
                    "reason": "內層檔案未曾被解壓，因此未進入分析流程。",
                    "confidence": "high",
                }
            ],
        }
    diagnostics: list[dict[str, Any]] = []
    for artifact in artifacts:
        state = artifact.get("analysis_status") or "unknown"
        coverage = artifact.get("analysis", {}).get("static", {}).get("stage_coverage", [])
        for stage in coverage:
            if stage.get("status") in {"ok", "complete", "completed", "not_applicable"}:
                continue
            if stage.get("status") == "skipped" and state == "complete":
                continue
            diagnostics.append(
                {
                    "diagnostic_id": (
                        f"diag::{artifact['artifact_id']}::{stage['stage']}::"
                        f"{len(diagnostics) + 1}"
                    ),
                    "artifact_id": artifact["artifact_id"],
                    "stage": stage["stage"],
                    "code": stage.get("status") or "unknown",
                    "category": "coverage",
                    "severity": "medium",
                    "likely_effect": "incomplete_analysis",
                    "confidence": "high",
                    "message": stage.get("reason") or "此分析階段尚未完成或未執行。",
                    "recommended_action": "查看分析狀態與限制後再評估檔案風險。",
                }
            )
        if state in {"unknown", "password_required", "queued", "running", "failed"}:
            diagnostics.append(
                {
                    "diagnostic_id": (
                        f"diag::{artifact['artifact_id']}::coverage::{len(diagnostics) + 1}"
                    ),
                    "artifact_id": artifact["artifact_id"],
                    "stage": "analysis",
                    "code": state,
                    "category": "coverage",
                    "severity": "medium",
                    "likely_effect": "incomplete_analysis",
                    "confidence": "high",
                    "message": "此檔案的分析覆蓋尚未確認完成。",
                    "recommended_action": "等待分析完成，或為等待密碼的檔案補交密碼。",
                }
            )
    return {
        "status": "degraded" if diagnostics else "none",
        "headline": (
            "部分檔案或階段尚未完成分析。" if diagnostics else "未偵測到會阻斷分析覆蓋率的問題。"
        ),
        "diagnostics": diagnostics,
        "suspected_miss_stages": [
            {
                "artifact_id": item["artifact_id"],
                "stage": item["stage"],
                "reason": item["message"],
                "confidence": "high",
            }
            for item in diagnostics
        ],
    }


def _build_timeline(
    report: dict[str, Any],
    findings: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    decoded: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifact_id = findings[0]["artifact_id"] if findings else artifacts[0]["artifact_id"]
    finding_ids = [findings[0]["finding_id"]] if findings else []
    events: list[dict[str, Any]] = [
        {
            "timeline_event_id": "timeline::1",
            "seq": 1,
            "artifact_id": artifact_id,
            "kind": "artifact_registered",
            "stage": "upload",
            "analyzer": None,
            "status": "ok",
            "summary": "已將檔案建立為分析節點。",
            "refs": {"finding_ids": [], "evidence_ids": [], "ioc_ids": [], "decoded_ids": []},
        }
    ]
    if decoded:
        events.append(
            {
                "timeline_event_id": "timeline::2",
                "seq": 2,
                "artifact_id": artifact_id,
                "kind": "decoded_string_extracted",
                "stage": "deobfuscation",
                "analyzer": None,
                "status": "ok",
                "summary": "在去混淆階段擷取到解碼內容。",
                "refs": {
                    "finding_ids": finding_ids,
                    "evidence_ids": [],
                    "ioc_ids": [item["ioc_id"] for item in iocs],
                    "decoded_ids": [item["decoded_id"] for item in decoded],
                },
            }
        )
    if findings:
        findings[0]["timeline_event_ids"] = [event["timeline_event_id"] for event in events[1:]]
    return events


def _build_summary(
    report: dict[str, Any], artifacts: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    risk = report.get("risk", {})
    components = list(risk.get("score_trace", {}).get("components", []))
    primary_artifact_id = None
    if findings:
        primary_artifact_id = findings[0]["artifact_id"]
    else:
        for component in components:
            related = component.get("related_artifact_id")
            if related:
                primary_artifact_id = str(related)
                break
    if primary_artifact_id is None:
        primary_artifact_id = artifacts[0]["artifact_id"]
    artifact_lookup = {item["artifact_id"]: item for item in artifacts}
    primary_artifact = artifact_lookup.get(primary_artifact_id, artifacts[0])
    top_findings = [
        {
            "finding_id": item["finding_id"],
            "artifact_id": item["artifact_id"],
            "artifact_path": item["artifact_path"],
            "archive_layer": item["archive_layer"],
            "title": item["title"],
            "score_impact": item["score_impact"],
            "why_flagged": item["summary"],
        }
        for item in findings[:10]
    ]
    return {
        "headline": (
            "一個巢狀內層檔案主導了最終的可疑判定。"
            if primary_artifact_id != artifacts[0]["artifact_id"]
            else "最外層檔案主導了最終判定。"
        ),
        "primary_artifact_id": primary_artifact_id,
        "primary_artifact_path": primary_artifact.get("display_path"),
        "top_findings": top_findings,
        "final_verdict_explainer": (
            "最外層檔案的判定是由子層檔案風險繼承所抬升。"
            if int(risk.get("breakdown", {}).get("inherited_score") or 0) > 0
            else "最終判定來自目前計分檔案上的直接證據。"
        ),
    }


def _enrich_tree(
    tree: dict[str, Any],
    findings: list[dict[str, Any]],
    uncertainties: list[dict[str, Any]],
    diagnostics: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> None:
    artifact_lookup = {item["artifact_id"]: item for item in artifacts}
    findings_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        findings_by_artifact.setdefault(finding["artifact_id"], []).append(finding)
    uncertainty_by_artifact: dict[str, list[str]] = {}
    for uncertainty in uncertainties:
        uncertainty_by_artifact.setdefault(uncertainty["artifact_id"], []).append(
            uncertainty["uncertainty_id"]
        )
    diagnostic_by_artifact: dict[str, list[str]] = {}
    for diagnostic in diagnostics.get("diagnostics", []):
        diagnostic_by_artifact.setdefault(diagnostic["artifact_id"], []).append(
            diagnostic["diagnostic_id"]
        )

    def _walk(node: dict[str, Any]) -> None:
        artifact = artifact_lookup.get(str(node["id"]))
        if artifact is not None:
            node["display_path"] = artifact.get("display_path")
            node["archive_layer"] = artifact.get("archive_layer")
            node["analysis_status"] = artifact.get("analysis_status")
            node["primary_analyzer"] = artifact.get("primary_analyzer")
            for kind in ("finding", "evidence"):
                for mode in ("direct", "inherited"):
                    field = f"{mode}_{kind}_ids"
                    node[field] = artifact.get(field, [])
        node_findings = findings_by_artifact.get(str(node["id"]), [])
        node["finding_ids"] = [item["finding_id"] for item in node_findings]
        node["uncertainty_ids"] = uncertainty_by_artifact.get(str(node["id"]), [])
        node["diagnostic_ids"] = diagnostic_by_artifact.get(str(node["id"]), [])
        node["top_finding_titles"] = [item["title"] for item in node_findings[:3]]
        for child in node.get("children", []):
            _walk(child)

    _walk(tree)
