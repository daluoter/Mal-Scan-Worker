"""Contextual YARA observations remain visible without changing malware risk."""

from typing import Any

import pytest
from malscan.scoring.adapters import build_direct_evidence
from malscan.scoring.engine import score_direct_evidence


def _records(match: dict[str, Any]):
    return build_direct_evidence(
        artifact_id="root-artifact", stage_findings={"yara": {"matches": [match]}}
    )


def _context(**changes: Any) -> dict[str, Any]:
    return {
        "rule": "network_iocs",
        "namespace": "network",
        "classification": "informational",
        "severity": "info",
        "provenance": {"status": "verified", "category": "context"},
        **changes,
    }


def test_context_observation_is_retained_with_zero_risk_and_no_open_gates() -> None:
    records = _records(_context())
    assert len(records) == 1
    evidence = records[0]
    assert evidence.kind == "yara_context_observation"
    assert evidence.tier == "benign_context"
    assert evidence.severity == "info"
    assert evidence.points == 0
    assert evidence.raw["rule"] == "network_iocs"
    decision = score_direct_evidence(direct_evidence=records)
    assert evidence in decision.evidence
    assert decision.risk_score == 0
    assert decision.risk_level == "clean"
    assert decision.breakdown.independent_source_count == 0
    assert decision.breakdown.high_gate_open is False
    assert decision.breakdown.malicious_gate_open is False
    assert decision.score_trace["components"] == []


def test_context_adds_neither_score_nor_deobfuscation_synergy() -> None:
    direct = build_direct_evidence(
        artifact_id="root-artifact",
        stage_findings={
            "deobfuscation": {
                "techniques_found": ["base64"],
                "decoded_strings_preview": ["cmd.exe /c echo test"],
            },
            "ioc-extract": {"urls": ["https://example.org/"]},
        },
    )
    assert any(record.kind == "deobfuscated_payload_execution" for record in direct)
    baseline = score_direct_evidence(direct_evidence=direct)
    observed = score_direct_evidence(direct_evidence=[*direct, *_records(_context())])
    assert observed.risk_score == baseline.risk_score
    assert observed.breakdown == baseline.breakdown


@pytest.mark.parametrize("classification", ["malicious_family", "exploit", "suspicious"])
def test_verified_context_only_reduces_a_conflicting_classification(classification: str) -> None:
    record = _records(_context(classification=classification, severity="critical"))[0]
    assert record.kind == "yara_context_observation"
    assert record.tier == "benign_context"
    assert record.points == 0
    assert record.severity == "info"


@pytest.mark.parametrize(
    "provenance",
    [
        {"status": "unverified", "category": "malicious_family"},
        {"status": "unverified", "category": "confirmed"},
        {"status": "verified", "category": "malicious_family"},
        {"category": "context"},
        None,
        "malicious_family",
    ],
)
def test_author_supplied_category_never_promotes_metadata(provenance: Any) -> None:
    # A manifest category is not a classification or an accuracy/trust decision.
    record = _records({"rule": "custom", "classification": "generic", "provenance": provenance})[0]
    assert record.kind == "yara_generic_heuristic"
    assert record.tier == "weak"
    assert record.points == 25


def test_informational_metadata_can_only_lower_unverified_rule_risk() -> None:
    record = _records(_context(provenance={"status": "unverified"}))[0]
    assert record.tier == "benign_context"
    assert record.points == 0


def test_unverified_context_does_not_relabel_a_generic_match() -> None:
    record = _records(
        _context(
            classification="generic", provenance={"status": "unverified", "category": "context"}
        )
    )[0]
    assert record.kind == "yara_generic_heuristic"
    assert record.tier == "weak"
    assert record.points == 25
