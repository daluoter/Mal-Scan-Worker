"""Effective risk retains verified dangerous content without inflating sources."""

from copy import deepcopy

import pytest
from malscan.api.routes import _apply_tree_risk_rollup
from malscan.artifact_references import resolve_artifact_analysis_references
from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.tree import apply_descendant_risk, local_decision_from_report


def _local() -> RiskDecision:
    return RiskDecision(
        risk_score=4,
        risk_level="clean",
        legacy_verdict="clean",
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(local_score=4, final_score=4, independent_source_count=1),
        score_trace={"components": [{"type": "local_marker", "applied_points": 4}]},
    )


def _child(**changes) -> dict:
    return {
        "artifact_id": "decrypted-child",
        "sha256": "a" * 64,
        "size": 2048,
        "relative_depth": 2,
        "display_path": "locked.pdf!/pdf-decrypted",
        "risk_score": 84,
        "risk_level": "high",
        "verdict": "suspicious",
        "risk_verified": True,
        **changes,
    }


@pytest.mark.parametrize("depth", [1, 2, 5])
@pytest.mark.parametrize(
    "score,level,verdict",
    [(60, "high", "suspicious"), (84, "high", "suspicious"), (95, "malicious", "malicious")],
)
def test_verified_high_risk_content_survives_all_enclosing_layers(depth, score, level, verdict):
    local = _local()
    report = {"score": 4, "risk_level": "clean", "verdict": "clean", "risk": {}}
    result = apply_descendant_risk(
        report,
        local=local,
        descendants=[
            _child(relative_depth=depth, risk_score=score, risk_level=level, verdict=verdict)
        ],
    )
    assert result["score"] == result["risk"]["risk_score"] == score
    assert result["risk_level"] == result["risk"]["risk_level"] == level
    assert result["verdict"] == result["risk"]["legacy_verdict"] == verdict
    assert result["risk"]["local_risk"]["score"] == 4
    assert result["risk"]["independent_source_count"] == 1
    assert "evidence" not in result["risk"]
    breakdown = result["risk"]["breakdown"]
    assert breakdown["descendant_floor"] > 0
    assert breakdown["final_score"] == score
    assert breakdown["inherited_score"] <= 40
    assert (
        result["risk"]["descendant_summary"]["strongest_verified_descendant"]["artifact_id"]
        == "decrypted-child"
    )
    component = result["risk"]["score_trace"]["components"][-1]
    assert component["type"] == "descendant_risk_floor"
    assert component["related_artifact_id"] == "decrypted-child"
    assert component["display_path"] == "locked.pdf!/pdf-decrypted"


@pytest.mark.parametrize(
    "changes",
    [
        {"risk_verified": False},
        {"risk_score": True},
        {"risk_score": 101},
        {"risk_score": "84"},
        {"risk_level": "malicious"},
        {"verdict": "clean"},
        {"sha256": "bad"},
        {"size": True},
        {"size": -1},
        {"verdict": "skipped"},
        {"extraction_note": "duplicate_within_extraction"},
    ],
)
def test_unverified_or_inconsistent_descendant_never_authorizes_a_risk_floor(changes):
    result = apply_descendant_risk({}, local=_local(), descendants=[_child(**changes)])
    assert result["risk"]["breakdown"]["descendant_floor"] == 0
    assert result["risk"]["descendant_summary"]["strongest_verified_descendant"] is None


def test_duplicate_dangerous_occurrences_do_not_multiply_evidence_or_score():
    report = apply_descendant_risk(
        {},
        local=_local(),
        descendants=[_child(), _child(artifact_id="duplicate", relative_depth=1)],
    )
    assert report["score"] == 84
    assert report["risk"]["independent_source_count"] == 1
    assert report["risk"]["descendant_summary"]["duplicate_occurrences"] == 1
    assert report["risk"]["breakdown"]["inherited_score"] == 25


def test_reapplying_rollup_restores_direct_decision_instead_of_reinheriting():
    initial = apply_descendant_risk({}, local=_local(), descendants=[_child()])
    unchanged = deepcopy(initial)
    local = local_decision_from_report(initial)
    assert local.risk_score == 4
    repeated = apply_descendant_risk(initial, local=local, descendants=[_child()])
    assert repeated == unchanged


def _api_tree():
    def node(identifier, depth, score, *, children=None):
        return {
            "id": identifier,
            "job_id": "job-" + identifier,
            "root_artifact_id": "root",
            "root_job_id": "job-root",
            "filename": {0: "outer.zip", 1: "locked.pdf", 2: "decrypted.pdf"}[depth],
            "origin_path": {0: None, 1: "nested/locked.pdf", 2: "pdf-decrypted"}[depth],
            "sha256": str(depth + 1) * 64,
            "size": 2048 + depth,
            "depth": depth,
            "score": score,
            "risk_level": "high" if score == 84 else "clean",
            "verdict": "suspicious" if score == 84 else "clean",
            "job_status": "done",
            "analysis_status": "complete",
            "children": children or [],
        }

    leaf = node("plaintext", 2, 84)
    parent = node("locked", 1, 4, children=[leaf])
    tree = node("root", 0, 0, children=[parent])
    reports = {}
    for item in (tree, parent, leaf):
        reports[item["id"]] = {
            "job_id": item["job_id"],
            "file": {
                "sha256": item["sha256"],
                "size": item["size"],
                "original_filename": item["filename"],
            },
            "score": item["score"],
            "risk_level": item["risk_level"],
            "verdict": item["verdict"],
            "timings": {"stages": [{"name": "format-analysis", "status": "ok"}]},
            "risk": {
                "risk_score": item["score"],
                "risk_level": item["risk_level"],
                "legacy_verdict": item["verdict"],
                "high_gate_open": item["risk_level"] == "high",
                "malicious_gate_open": False,
                "independent_source_count": 1,
                "breakdown": {"local_score": item["score"], "final_score": item["score"]},
            },
        }
    return tree, reports


def test_api_tree_effective_risk_and_direct_scores_remain_distinct_for_every_parent():
    tree, reports = _api_tree()
    original = deepcopy(reports)
    resolve_artifact_analysis_references(tree, reports)
    root_report = deepcopy(reports["root"])
    root_report["child_jobs"] = [{"job_id": "job-locked", "verdict": "clean"}]
    report = _apply_tree_risk_rollup(root_report, tree, reports)
    assert report["score"] == report["risk"]["risk_score"] == 84
    assert report["risk"]["local_risk"]["score"] == 0
    parent, leaf = tree["children"][0], tree["children"][0]["children"][0]
    assert tree["score"] == parent["score"] == leaf["score"] == 84
    assert tree["local_score"] == 0
    assert parent["local_score"] == 4
    assert leaf["local_score"] == 84
    assert report["child_jobs"][0]["verdict"] == "suspicious"
    assert reports == original
    repeated = _apply_tree_risk_rollup(deepcopy(report), tree, reports)
    assert repeated == report


@pytest.mark.parametrize("change", ["foreign_job", "bad_hash", "score_string", "bool_size"])
def test_api_risk_floor_rejects_foreign_and_malformed_direct_reports(change):
    tree, reports = _api_tree()
    leaf_report = reports["plaintext"]
    if change == "foreign_job":
        leaf_report["job_id"] = "foreign-job"
    elif change == "bad_hash":
        leaf_report["file"]["sha256"] = "f" * 64
    elif change == "score_string":
        leaf_report["score"] = "84"
    else:
        leaf_report["file"]["size"] = True
    resolve_artifact_analysis_references(tree, reports)
    report = _apply_tree_risk_rollup(deepcopy(reports["root"]), tree, reports)
    assert report["risk"]["breakdown"]["descendant_floor"] == 0
    assert report["risk"]["descendant_summary"]["strongest_verified_descendant"] is None
