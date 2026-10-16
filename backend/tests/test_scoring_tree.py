"""Tests for tree-aware descendant rollup scoring."""

from malscan.scoring import RiskDecision, ScoreBreakdown
from malscan.scoring.tree import merge_with_descendants


def _decision(score: int, level: str) -> RiskDecision:
    legacy_verdict = (
        "malicious" if level == "malicious" else "clean" if level == "clean" else "suspicious"
    )
    return RiskDecision(
        risk_score=score,
        risk_level=level,
        legacy_verdict=legacy_verdict,
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(local_score=score, final_score=score),
    )


def test_direct_malicious_child_promotes_clean_parent_to_high() -> None:
    decision = merge_with_descendants(
        local=_decision(5, "clean"),
        descendants=[{"sha256": "child-1", "risk_level": "malicious", "relative_depth": 1}],
    )

    assert decision.risk_score == 60
    assert decision.risk_level == "high"


def test_deep_single_malicious_descendant_only_adds_decayed_score() -> None:
    decision = merge_with_descendants(
        local=_decision(0, "clean"),
        descendants=[{"sha256": "child-1", "risk_level": "malicious", "relative_depth": 3}],
    )

    assert decision.risk_score == 17
    assert decision.risk_level == "low"


def test_two_malicious_descendants_open_malicious_gate() -> None:
    decision = merge_with_descendants(
        local=_decision(25, "low"),
        descendants=[
            {"sha256": "child-1", "risk_level": "malicious", "relative_depth": 1},
            {"sha256": "child-2", "risk_level": "malicious", "relative_depth": 1},
        ],
    )

    assert decision.breakdown.malicious_gate_open is True
    assert decision.risk_level == "malicious"


def test_duplicate_descendant_hash_only_counts_once() -> None:
    decision = merge_with_descendants(
        local=_decision(15, "low"),
        descendants=[
            {"sha256": "a" * 64, "risk_level": "high", "relative_depth": 1},
            {"sha256": "a" * 64, "risk_level": "high", "relative_depth": 1},
        ],
    )

    assert decision.breakdown.inherited_score == 25
    assert decision.risk_score == 40


def test_descendant_summary_counts_high_and_malicious_separately() -> None:
    decision = merge_with_descendants(
        local=_decision(0, "clean"),
        descendants=[
            {"sha256": "mal-1", "risk_level": "malicious", "relative_depth": 1},
            {"sha256": "high-1", "risk_level": "high", "relative_depth": 1},
        ],
    )

    assert decision.descendant_summary["malicious_descendants"] == 1
    assert decision.descendant_summary["high_descendants"] == 1


def test_inherited_score_still_respects_no_high_gate_cap() -> None:
    decision = merge_with_descendants(
        local=_decision(55, "medium"),
        descendants=[{"sha256": "child-1", "risk_level": "medium", "relative_depth": 1}],
    )

    assert decision.breakdown.high_gate_open is False
    assert decision.breakdown.inherited_score == 15
    assert decision.risk_score == 59
    assert decision.risk_level == "medium"


def test_skipped_descendant_does_not_contribute_to_scoring_or_summary() -> None:
    decision = merge_with_descendants(
        local=_decision(0, "clean"),
        descendants=[
            {
                "sha256": "skipped-1",
                "risk_level": "malicious",
                "relative_depth": 1,
                "verdict": "skipped",
            },
        ],
    )

    assert decision.breakdown.inherited_score == 0
    assert decision.risk_score == 0
    assert decision.descendant_summary["total_descendants"] == 0
    assert decision.descendant_summary["malicious_descendants"] == 0
    assert decision.descendant_summary["top_descendants"] == []


def test_duplicate_within_extraction_descendant_does_not_contribute_to_scoring_or_summary() -> None:
    decision = merge_with_descendants(
        local=_decision(0, "clean"),
        descendants=[
            {
                "sha256": "dup-1",
                "risk_level": "high",
                "relative_depth": 1,
                "extraction_note": "duplicate_within_extraction",
            },
        ],
    )

    assert decision.breakdown.inherited_score == 0
    assert decision.risk_score == 0
    assert decision.descendant_summary["total_descendants"] == 0
    assert decision.descendant_summary["high_descendants"] == 0
    assert decision.descendant_summary["top_descendants"] == []
