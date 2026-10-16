"""A pinned quality baseline detects lost coverage, identities and detector evidence."""

import copy
import json
from pathlib import Path

import pytest
from malscan_worker.quality.corpus import (
    REQUIRED_STAGES,
    evaluate_report,
    fixture_bytes,
    load_corpus,
)
from malscan_worker.rule_provenance import load_rule_bundle

CORPUS = Path(__file__).parents[1] / "quality" / "corpus-v1.json"
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
    assert checked == 7
    assert benign_hits == ["benign-documentation-url", "benign-java-api"]


@pytest.mark.parametrize(
    "mutation", ["changed_bytes", "cyclic_recipe", "duplicate_case", "path_escape"]
)
def test_invalid_corpus_cannot_silently_rebaseline(corpus, tmp_path, mutation):
    data = copy.deepcopy(corpus)
    if mutation == "changed_bytes":
        data["fixtures"]["clean"]["text"] += "changed"
    elif mutation == "cyclic_recipe":
        data["fixtures"]["inner-zip"]["entries"][0]["fixture"] = "inner-zip"
    elif mutation == "duplicate_case":
        data["cases"].append(data["cases"][0])
    else:
        data["cases"][0]["filename"] = "../escape.txt"
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
    result = evaluate_report(corpus["cases"][0], report, source_sha256="a" * 64, source_size=31)
    assert result["passed"] is (corruption == "none")
    assert bool(result["errors"]) is (corruption != "none")
