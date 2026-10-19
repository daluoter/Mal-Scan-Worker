"""Content references preserve occurrence provenance and fail closed."""

from copy import deepcopy
from itertools import permutations

import pytest
from malscan.api.routes import _apply_tree_risk_rollup
from malscan.artifact_references import resolve_artifact_analysis_references
from malscan.report_explainability import build_explainability
from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.tree import merge_with_descendants


def _node(artifact_id: str, *, duplicate: bool = False) -> dict:
    return {
        "id": artifact_id,
        "filename": f"{artifact_id}.txt",
        "sha256": "a" * 64,
        "size": 68,
        "depth": 1,
        "root_artifact_id": "root",
        "root_job_id": "root-job",
        "origin_path": f"{artifact_id}/eicar.txt",
        "job_id": None if duplicate else f"job-{artifact_id}",
        "job_status": None if duplicate else "done",
        "analysis_status": "unknown" if duplicate else "complete",
        "extraction_note": "duplicate_within_extraction" if duplicate else None,
        "verdict": "skipped" if duplicate else "malicious",
        "score": None if duplicate else 95,
        "risk_level": None if duplicate else "malicious",
        "children": [],
    }


def _report(node: dict) -> dict:
    return {
        "job_id": node["job_id"],
        "file": {
            "sha256": node["sha256"],
            "size": node["size"],
            "original_filename": node["filename"],
        },
        "score": 95,
        "risk_level": "malicious",
        "verdict": "malicious",
        "risk": {
            "evidence": [
                {
                    "evidence_id": "ev-1",
                    "artifact_id": node["id"],
                    "source": "clamav",
                    "reason": "EICAR test signature",
                    "severity": "critical",
                    "points": 95,
                }
            ]
        },
        "timings": {
            "stages": [
                {"name": name, "status": "ok", "duration_ms": 5}
                for name in ("file-type", "clamav", "yara", "ioc-extract", "deobfuscation")
            ]
            + [
                {"name": name, "status": "skipped", "reason": reason}
                for name, reason in (
                    ("format-analysis", "No analyzer matched"),
                    ("archive-extract", "Not an archive"),
                    ("document-analysis", "Not a supported document format"),
                )
            ]
        },
        "results": {"iocs": {}, "deobfuscation": {"candidates": []}},
    }


def _tree() -> dict:
    return {
        **_node("root"),
        "job_id": "root-job",
        "sha256": "b" * 64,
        "depth": 0,
        "children": [_node("source"), _node("copy", duplicate=True)],
    }


def test_duplicate_references_source_without_claiming_direct_scan() -> None:
    tree = _tree()
    source, duplicate = tree["children"]
    resolve_artifact_analysis_references(tree, {"source": _report(source)})

    reference = duplicate["analysis_reference"]
    assert reference["mode"] == "inherited"
    assert reference["source_artifact_id"] == "source"
    assert reference["source_job_id"] == "job-source"
    assert reference["source_stage_coverage"][1]["stage"] == "clamav"
    assert len(reference["source_stage_coverage"]) == 8
    assert duplicate["analysis_status"] == "complete"
    assert duplicate["analysis"]["static"]["stage_coverage"] == []
    assert duplicate["job_id"] is None
    assert duplicate["verdict"] == "skipped"
    assert len(tree["children"]) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "report_hash",
        "report_size",
        "report_job",
        "report_filename",
        "different_extension",
        "root_artifact",
        "root_job",
        "missing",
        "failed",
        "partial",
        "empty_stages",
        "self_reference",
        "cyclic_reference",
        "only_filetype",
        "only_av",
        "missing_detector",
        "duplicate_stages",
        "stale_complete_failed_timings",
        "undocumented_skip",
    ],
)
def test_invalid_reference_never_completes_duplicate(mutation: str) -> None:
    tree = _tree()
    source, duplicate = tree["children"]
    report = _report(source)
    reports = {"source": report}
    if mutation == "report_hash":
        report["file"]["sha256"] = "c" * 64
    elif mutation == "report_size":
        report["file"]["size"] += 1
    elif mutation == "report_job":
        report["job_id"] = "other-job"
    elif mutation == "report_filename":
        report["file"]["original_filename"] = "other.ps1"
    elif mutation == "different_extension":
        duplicate["filename"] = "copy.ps1"
    elif mutation == "root_artifact":
        source["root_artifact_id"] = "other-root"
    elif mutation == "root_job":
        source["root_job_id"] = "other-root-job"
    elif mutation == "missing":
        reports.clear()
    elif mutation == "failed":
        source["job_status"] = "failed"
    elif mutation == "partial":
        report["timings"]["stages"][0]["status"] = "error"
    elif mutation == "empty_stages":
        report["timings"]["stages"] = []
        report["analysis"] = {"static": {"status": "complete"}}
    elif mutation == "self_reference":
        duplicate["analysis_reference"] = {"mode": "inherited", "source_artifact_id": "copy"}
    elif mutation == "cyclic_reference":
        source["job_id"] = None
        source["extraction_note"] = "duplicate_within_extraction"
        source["analysis_reference"] = {"mode": "inherited", "source_artifact_id": "copy"}
        duplicate["analysis_reference"] = {"mode": "inherited", "source_artifact_id": "source"}
    elif mutation == "only_filetype":
        report["timings"]["stages"] = report["timings"]["stages"][:1]
    elif mutation == "only_av":
        report["timings"]["stages"] = report["timings"]["stages"][1:2]
    elif mutation == "missing_detector":
        report["timings"]["stages"].pop(2)
    elif mutation == "duplicate_stages":
        report["timings"]["stages"].append(dict(report["timings"]["stages"][0]))
    elif mutation == "stale_complete_failed_timings":
        report["analysis"] = {
            "static": {
                "status": "complete",
                "stage_coverage": [
                    {
                        "stage": item["name"],
                        **{key: value for key, value in item.items() if key != "name"},
                    }
                    for item in deepcopy(report["timings"]["stages"])
                ],
            }
        }
        report["timings"]["stages"][1]["status"] = "error"
    elif mutation == "undocumented_skip":
        report["timings"]["stages"][-1]["reason"] = "Parser disabled by owner"
    resolve_artifact_analysis_references(tree, reports)
    assert duplicate["analysis_status"] == "unknown"
    assert duplicate["analysis_reference"]["mode"] == "unresolved"
    assert duplicate["analysis"]["static"]["stage_coverage"] == []


def test_child_evidence_is_scoped_and_duplicate_refers_to_original_finding() -> None:
    tree = _tree()
    root_report = _report(tree)
    source_report = _report(tree["children"][0])
    original = deepcopy(source_report)
    explanation = build_explainability(
        report=root_report,
        artifact_tree=tree,
        artifact_reports={"root": root_report, "source": source_report},
    )
    by_id = {item["artifact_id"]: item for item in explanation["artifacts"]}
    assert source_report == original
    assert len(explanation["evidence"]) == 2
    assert explanation["evidence"][1]["id"] == "evidence::source::ev-1"
    assert explanation["evidence"][0]["evidence_id"] == "ev-1"
    assert by_id["source"]["direct_finding_ids"] == ["finding::source::1"]
    assert by_id["copy"]["inherited_finding_ids"] == ["finding::source::1"]
    assert by_id["copy"]["inherited_evidence_ids"] == ["evidence::source::ev-1"]
    assert by_id["copy"]["direct_finding_ids"] == []
    assert tree["children"][1]["finding_ids"] == []
    assert explanation["artifact_coverage"] == {
        "occurrences": 3,
        "direct": 2,
        "inherited": 1,
        "unresolved": 0,
    }


def test_portable_child_only_hit_controls_primary_summary() -> None:
    tree = _tree()
    tree["children"].pop()
    root_report = _report(tree)
    root_report.update(score=0, risk_level="clean", verdict="clean")
    root_report["risk"]["evidence"] = []
    root_report["artifacts"] = [
        {"artifact_id": "root", "report": deepcopy(root_report)},
        {"artifact_id": "source", "report": _report(tree["children"][0])},
    ]
    explanation = build_explainability(report=root_report, artifact_tree=tree)
    assert explanation["summary"]["primary_artifact_id"] == "source"
    assert explanation["findings"][0]["artifact_path"].endswith("!/source/eicar.txt")
    assert explanation["evidence"][0]["artifact_id"] == "source"
    assert root_report["risk"]["evidence"] == []


def test_risk_inheritance_is_order_independent_and_keeps_both_occurrences() -> None:
    nodes = [
        {"artifact_id": "deep", "sha256": "a" * 64, "risk_level": "malicious", "relative_depth": 3},
        {"artifact_id": "near", "sha256": "a" * 64, "risk_level": "malicious", "relative_depth": 1},
    ]
    for ordered in permutations(nodes):
        result = merge_with_descendants(
            local=RiskDecision(0, "clean", "clean", [], [], ScoreBreakdown()),
            descendants=list(ordered),
        )
        assert result.risk_score == 60
        assert result.descendant_summary["total_descendants"] == 1
        assert result.descendant_summary["total_occurrences"] == 2
        assert result.descendant_summary["top_descendants"][0]["artifact_id"] == "near"
        assert result.score_trace["gates"]["high_gate_open"] is True
        assert result.score_trace["gates"]["capped_by"] == "no_malicious_gate"


@pytest.mark.parametrize("digest", [None, "", "invalid"])
def test_unverified_hashes_do_not_collapse_unrelated_descendants(digest: str | None) -> None:
    result = merge_with_descendants(
        local=RiskDecision(0, "clean", "clean", [], [], ScoreBreakdown()),
        descendants=[
            {"artifact_id": "a", "sha256": digest, "risk_level": "malicious", "relative_depth": 1},
            {"artifact_id": "b", "sha256": digest, "risk_level": "malicious", "relative_depth": 1},
        ],
    )
    assert result.descendant_summary["total_descendants"] == 2
    assert result.breakdown.malicious_gate_open is True
    assert result.score_trace["gates"]["malicious_gate_open"] is True
    assert result.score_trace["gates"]["capped_by"] is None


def test_verified_duplicate_counts_risk_once_but_retains_inherited_occurrence() -> None:
    tree = _tree()
    source, duplicate = tree["children"]
    resolve_artifact_analysis_references(tree, {"source": _report(source)})
    descendants = [
        {
            **item,
            "artifact_id": item["id"],
            "risk_score": item["score"],
            "relative_depth": item["depth"],
        }
        for item in tree["children"]
    ]
    result = merge_with_descendants(
        local=RiskDecision(0, "clean", "clean", [], [], ScoreBreakdown()),
        descendants=descendants,
    )
    assert result.risk_score == 60
    assert result.descendant_summary["total_descendants"] == 1
    assert result.descendant_summary["total_occurrences"] == 2
    occurrences = result.descendant_summary["top_descendants"][0]["occurrences"]
    assert {item["analysis_mode"] for item in occurrences} == {"direct", "inherited"}
    assert {item["display_path"] for item in occurrences} == {"source/eicar.txt", "copy/eicar.txt"}


def test_unverified_child_report_does_not_inject_findings_into_root() -> None:
    tree = _tree()
    root_report = _report(tree)
    root_report["risk"]["evidence"] = []
    child_report = _report(tree["children"][0])
    child_report["file"]["sha256"] = "f" * 64
    explanation = build_explainability(
        report=root_report,
        artifact_tree=tree,
        artifact_reports={"source": child_report},
    )
    assert explanation["findings"] == []
    assert explanation["evidence"] == []
    assert tree["children"][1]["analysis_status"] == "unknown"


def test_completed_archive_with_unverified_inner_content_cannot_complete_duplicate() -> None:
    tree = _tree()
    source, duplicate = tree["children"]
    source["children"] = [{**_node("unverified-inner"), "analysis_status": "unknown"}]
    resolve_artifact_analysis_references(tree, {"source": _report(source)})
    assert source["analysis_status"] == "complete"
    assert duplicate["analysis_status"] == "unknown"
    assert duplicate["analysis_reference"]["mode"] == "unresolved"


def test_root_keeps_partial_tree_coverage_while_direct_source_is_complete() -> None:
    tree = _tree()
    tree["analysis_status"] = "partial"
    tree["analysis"] = {
        "static": {"status": "partial", "stage_coverage": []},
        "dynamic": {"status": "disabled"},
    }
    root_report = _report(tree)
    source_report = _report(tree["children"][0])
    source_report["timings"]["stages"][1]["status"] = "error"
    explanation = build_explainability(
        report=root_report,
        artifact_tree=tree,
        artifact_reports={"root": root_report, "source": source_report},
    )
    assert tree["analysis_status"] == "partial"
    assert tree["analysis"]["static"]["status"] == "partial"
    assert tree["analysis_reference"]["source_analysis_status"] == "complete"
    assert explanation["artifacts"][0]["analysis"]["status"] == "partial"
    assert explanation["artifacts"][1]["analysis_status"] == "partial"


@pytest.mark.parametrize("second_malicious", [False, True])
def test_api_rollup_publishes_combined_trace_and_keeps_local_components(
    second_malicious: bool,
) -> None:
    tree = _tree()
    resolve_artifact_analysis_references(tree, {"source": _report(tree["children"][0])})
    if second_malicious:
        tree["children"].append({**_node("second-malicious"), "sha256": "c" * 64})
    report = _report(tree)
    report.update(score=0, verdict="clean", risk_level="clean")
    report["risk"] = {
        "risk_score": 0,
        "risk_level": "clean",
        "legacy_verdict": "clean",
        "independent_source_count": 2,
        "breakdown": {
            "local_score": 0,
            "inherited_score": 0,
            "final_score": 0,
            "high_gate_open": False,
            "malicious_gate_open": False,
            "independent_source_count": 0,
        },
        "score_trace": {
            "components": [{"type": "local_marker", "applied_points": 0}],
            "gates": {
                "high_gate_open": False,
                "malicious_gate_open": False,
                "capped_by": "weak_only",
            },
        },
    }
    rolled = _apply_tree_risk_rollup(report, tree)
    assert rolled["score"] == 95
    risk = rolled["risk"]
    assert risk["breakdown"]["high_gate_open"] == risk["high_gate_open"] is True
    assert risk["breakdown"]["malicious_gate_open"] == risk["malicious_gate_open"]
    assert risk["malicious_gate_open"] is True
    assert risk["breakdown"]["independent_source_count"] == risk["independent_source_count"] == 2
    trace = rolled["risk"]["score_trace"]
    assert trace["gates"]["high_gate_open"] is True
    assert trace["gates"]["local_capped_by"] == "weak_only"
    assert trace["gates"]["capped_by"] is None
    assert trace["components"][0]["type"] == "local_marker"
    assert trace["components"][1]["type"] == "descendant_inheritance"
