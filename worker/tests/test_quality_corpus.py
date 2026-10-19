"""A pinned quality baseline detects lost coverage, identities and detector evidence."""

import copy
import json
from pathlib import Path

import pytest
from malscan.scoring.policy import POLICY_VERSION
from malscan_worker.quality.corpus import (
    REQUIRED_STAGES,
    evaluate_report,
    fixture_bytes,
    load_corpus,
)
from malscan_worker.rule_provenance import load_rule_bundle

CORPUS = Path(__file__).parents[1] / "quality" / "corpus-v4.json"
RULES = Path(__file__).parents[1] / "rules"


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(CORPUS)


@pytest.mark.parametrize("case_id", [case["id"] for case in load_corpus(CORPUS)["cases"]])
def test_every_case_has_reproducible_pinned_input(corpus, case_id):
    case = next(case for case in corpus["cases"] if case["id"] == case_id)
    assert fixture_bytes(corpus["fixtures"], case["fixture"]) == fixture_bytes(
        corpus["fixtures"], case["fixture"]
    )


def test_pinned_rule_baseline_measures_real_clean_hits_and_benign_rule_hits(corpus):
    bundle = load_rule_bundle(RULES)
    benign_hits = []
    checked = 0
    for case in corpus["cases"]:
        spec = corpus["fixtures"][case["fixture"]]
        if (
            case["label"] == "failure"
            or case["scenario"] != "normal"
            or spec["kind"] not in {"text", "eicar"}
        ):
            continue
        data = fixture_bytes(corpus["fixtures"], case["fixture"])
        actual = sorted(match.rule for match in bundle.rules.match(data=data))
        assert actual == sorted(case["expect"]["yara_rules"])
        checked += 1
        if case["label"] == "benign" and actual:
            assert case["known_limitations"]
            benign_hits.append(case["id"])
    assert checked == 9
    assert benign_hits == ["benign-documentation-url"]
    assert bundle.rules_sha256 == corpus["rules_sha256"]


def test_historical_v1_fixture_bytes_remain_reproducible():
    historical = load_corpus(CORPUS.with_name("corpus-v1.json"))
    assert historical["corpus_version"] == "static-quality-v1.0.0"
    for name in historical["fixtures"]:
        assert fixture_bytes(historical["fixtures"], name)


@pytest.mark.parametrize(
    "mutation",
    [
        "changed_bytes",
        "cyclic_recipe",
        "duplicate_case",
        "path_escape",
        "unknown_check",
        "ambiguous_check",
        "bad_check_path",
        "bad_rules_hash",
    ],
)
def test_invalid_corpus_cannot_silently_rebaseline(corpus, tmp_path, mutation):
    data = copy.deepcopy(corpus)
    if mutation == "changed_bytes":
        data["fixtures"]["clean"]["text"] += "changed"
    elif mutation == "cyclic_recipe":
        data["fixtures"]["inner-zip"]["entries"][0]["fixture"] = "inner-zip"
    elif mutation == "duplicate_case":
        data["cases"].append(data["cases"][0])
    elif mutation == "path_escape":
        data["cases"][0]["filename"] = "../escape.txt"
    elif mutation == "unknown_check":
        data["cases"][0]["expect"]["checks"] = [{"path": ["score"], "ignore": True}]
    elif mutation == "ambiguous_check":
        data["cases"][0]["expect"]["checks"] = [{"path": ["score"], "equals": 0, "min_length": 1}]
    elif mutation == "bad_check_path":
        data["cases"][0]["expect"]["checks"] = [{"path": [True], "equals": 0}]
    else:
        data["rules_sha256"] = "wrong-version"
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_corpus(path)


def _report():
    stages = [{"stage": name, "status": "ok"} for name in sorted(REQUIRED_STAGES)]
    next(stage for stage in stages if stage["stage"] == "yara").update(
        tool_version="4.5", rules_version="a" * 64
    )
    risk = {
        "policy_version": POLICY_VERSION,
        "risk_score": 0,
        "risk_level": "clean",
        "legacy_verdict": "clean",
        "high_gate_open": False,
        "malicious_gate_open": False,
        "independent_source_count": 0,
        "breakdown": {
            "high_gate_open": False,
            "malicious_gate_open": False,
            "independent_source_count": 0,
        },
    }
    child = {
        "file": {"sha256": "a" * 64, "size": 31},
        "analysis": {"static": {"status": "complete", "stage_coverage": stages}},
        "results": {"av_result": {"infected": False}, "yara_hits": []},
    }
    return {
        "report_complete": True,
        "job_status": "done",
        "root_artifact_id": "root",
        "job_id": "root",
        "file": {"sha256": "a" * 64, "size": 31},
        "analysis": {"static": {"status": "complete"}, "dynamic": {"status": "disabled"}},
        "artifacts": [
            {
                "artifact_id": "root",
                "root_id": "root",
                "parent_id": None,
                "sha256": "a" * 64,
                "size": 31,
                "report": child,
            }
        ],
        "risk": risk,
        "score": 0,
        "risk_level": "clean",
        "verdict": "clean",
        "explainability": {"evidence": []},
        "artifact_tree": {"analysis_status": "complete"},
    }


@pytest.mark.parametrize(
    "corruption",
    [
        "none",
        "failed_av_empty_result",
        "lost_yara_stage",
        "wrong_content",
        "stale_verdict",
        "colliding_evidence",
        "optional_stage_failed",
        "coherent_wrong_content",
        "ghost_root",
        "duplicate_stage",
        "coherent_wrong_verdict",
        "wrong_policy_version",
    ],
)
def test_clean_fields_cannot_hide_failed_coverage_or_invalid_evidence(corpus, corruption):
    report = _report()
    node = report["artifacts"][0]
    stages = node["report"]["analysis"]["static"]["stage_coverage"]
    if corruption == "failed_av_empty_result":
        next(stage for stage in stages if stage["stage"] == "clamav")["status"] = "failed"
    elif corruption == "lost_yara_stage":
        stages[:] = [stage for stage in stages if stage["stage"] != "yara"]
    elif corruption == "wrong_content":
        node["sha256"] = "b" * 64
    elif corruption == "stale_verdict":
        report["risk"]["legacy_verdict"] = "malicious"
    elif corruption == "colliding_evidence":
        report["explainability"]["evidence"] = [{"id": "ev-1"}, {"id": "ev-1"}]
    elif corruption == "optional_stage_failed":
        next(stage for stage in stages if stage["stage"] == "format-analysis").update(
            status="failed", reason="parser crashed"
        )
    elif corruption == "coherent_wrong_content":
        node["sha256"] = "b" * 64
        node["report"]["file"]["sha256"] = "b" * 64
    elif corruption == "ghost_root":
        report["root_artifact_id"] = node["root_id"] = "missing-root"
    elif corruption == "duplicate_stage":
        stages.append(dict(stages[0]))
    elif corruption == "coherent_wrong_verdict":
        report.update(score=100, risk_level="malicious", verdict="malicious")
        report["risk"].update(risk_score=100, risk_level="malicious", legacy_verdict="malicious")
    elif corruption == "wrong_policy_version":
        report["risk"]["policy_version"] = "old-policy"
    result = evaluate_report(corpus["cases"][0], report, source_sha256="a" * 64, source_size=31)
    assert result["passed"] is (corruption == "none")
    assert bool(result["errors"]) is (corruption != "none")


@pytest.mark.parametrize("score", [29, 100])
def test_encoded_url_keeps_its_heuristic_baseline_without_unexplained_promotion(corpus, score):
    case = next(item for item in corpus["cases"] if item["id"] == "encoded-url")
    report = _report()
    child = report["artifacts"][0]["report"]
    child["results"]["yara_hits"] = [{"rule": "base64_url"}]
    child["risk"] = {
        "evidence": [
            {"source": "yara", "raw": {"rule": "base64_url"}, "tier": "weak", "points": 25}
        ]
    }
    level, verdict = ("low", "suspicious") if score == 29 else ("malicious", "malicious")
    report.update(score=score, risk_level=level, verdict=verdict)
    report["risk"].update(risk_score=score, risk_level=level, legacy_verdict=verdict)
    result = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert result["passed"] is (score == 29)


def test_successful_process_cannot_hide_missing_or_incorrect_format_evidence(corpus):
    case = copy.deepcopy(corpus["cases"][0])
    case["expect"]["checks"] = [
        {"path": ["results", "format_analysis", "features", "encrypted"], "equals": True}
    ]
    report = _report()
    missing = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert missing["passed"] is False
    report["results"] = {"format_analysis": {"features": {"encrypted": False}}}
    incorrect = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert incorrect["passed"] is False
    assert any("format evidence differs" in error for error in incorrect["errors"])


def test_successful_scan_with_different_rule_bytes_is_rejected(corpus):
    result = evaluate_report(
        corpus["cases"][0], _report(), source_sha256="a" * 64, source_size=31, rules_sha256="b" * 64
    )
    assert result["passed"] is False
    assert "YARA rules differ from the versioned corpus" in result["errors"]


@pytest.mark.parametrize(
    ("corruption", "error"),
    [
        ("none", None),
        ("self_cycle", "artifact parent graph contains a cycle"),
        ("multiple_node_cycle", "artifact parent graph contains a cycle"),
        ("detached_parent", "artifact occurrence cannot reach the root"),
        ("detached_root", "artifact occurrence cannot reach the root"),
    ],
)
def test_every_artifact_ancestry_reaches_the_root_without_cycles(corpus, corruption, error):
    report = _report()
    root = report["artifacts"][0]
    for identifier in ("child-a", "child-b"):
        child = copy.deepcopy(root)
        child.update(artifact_id=identifier, parent_id="root")
        report["artifacts"].append(child)
    if corruption == "self_cycle":
        report["artifacts"][1]["parent_id"] = "child-a"
    elif corruption == "multiple_node_cycle":
        report["artifacts"][1]["parent_id"] = "child-b"
        report["artifacts"][2]["parent_id"] = "child-a"
    elif corruption == "detached_parent":
        report["artifacts"][1]["parent_id"] = "missing-parent"
    elif corruption == "detached_root":
        report["artifacts"][1]["parent_id"] = None
    case = copy.deepcopy(corpus["cases"][0])
    case["expect"]["artifact_count"] = 3
    result = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert result["passed"] is (corruption == "none")
    if error is not None:
        assert error in result["errors"]


def test_waiting_quality_case_cannot_be_reported_as_completed(corpus):
    case = copy.deepcopy(corpus["cases"][0])
    case["expect"].update(job_status="password_required", report_complete=False)
    report = _report()
    completed = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert completed["passed"] is False
    assert "execution completion state differs" in completed["errors"]
    case["expect"].update(
        static_status="password_required",
        not_run_stages=["archive-extract", "document-analysis"],
        root_stages={"format-analysis": "password_required"},
    )
    report.update(job_status="password_required", report_complete=False)
    report["analysis"]["static"]["status"] = "password_required"
    report["artifact_tree"]["analysis_status"] = "password_required"
    child_static = report["artifacts"][0]["report"]["analysis"]["static"]
    child_static["status"] = "password_required"
    child_static["stage_coverage"] = [
        item
        for item in child_static["stage_coverage"]
        if item["stage"] not in {"archive-extract", "document-analysis"}
    ]
    next(
        item for item in child_static["stage_coverage"] if item["stage"] == "format-analysis"
    ).update(status="password_required", reason="PDF password is required")
    waiting = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert waiting["passed"] is True
    child_static["stage_coverage"] = [
        item for item in child_static["stage_coverage"] if item["stage"] != "clamav"
    ]
    lost_detector = evaluate_report(case, report, source_sha256="a" * 64, source_size=31)
    assert lost_detector["passed"] is False


def test_historical_v2_retains_locked_pdf_partial_expectation():
    historical = load_corpus(CORPUS.with_name("corpus-v2.json"))
    assert historical["corpus_version"] == "static-quality-v2.0.0"
    locked = next(case for case in historical["cases"] if case["id"] == "pdf-encrypted")
    assert locked["expect"]["static_status"] == "partial"
    assert "job_status" not in locked["expect"]
