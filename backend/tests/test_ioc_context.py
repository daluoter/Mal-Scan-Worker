"""Raw extracted network-looking strings are observations, not reputation evidence."""

from typing import Any

import pytest
from malscan.scoring.adapters import build_direct_evidence
from malscan.scoring.engine import score_direct_evidence
from malscan.scoring.policy import POLICY_VERSION


def _office_observations() -> dict[str, list[str]]:
    # Inputs include normal OOXML schema URLs and values a broad domain regex can
    # mistake for hosts. This tests scoring, not the extractor.
    return {
        "urls": [
            "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
            "http://schemas.openxmlformats.org/package/2006/relationships",
            "http://schemas.openxmlformats.org/package/2006/content-types",
            "http://www.w3.org/XML/1998/namespace",
            "https://example.org/documentation",
        ],
        "domains": [
            "schemas.openxmlformats.org",
            "document.xml",
            "settings.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "example.org",
        ],
        "ips": ["192.0.2.1", "198.51.100.2", "203.0.113.3", "203.0.113.4"],
    }


def _records(findings: dict[str, Any]):
    return build_direct_evidence(artifact_id="root-artifact", stage_findings=findings)


def test_many_normal_schema_and_file_like_values_remain_visible_at_zero_risk() -> None:
    observations = _office_observations()
    records = _records({"ioc-extract": observations})
    assert len(records) == 12  # Existing 4 URLs, 4 domains, 3 IPs, one summary bound.
    assert {record.tier for record in records} == {"benign_context"}
    assert {record.severity for record in records} == {"info"}
    assert {record.points for record in records} == {0}
    assert {record.raw["value"] for record in records if record.kind == "raw_url_ioc"} == set(
        observations["urls"][:4]
    )
    assert {record.raw["value"] for record in records if record.kind == "raw_domain_ioc"} == set(
        observations["domains"][:4]
    )
    summary = next(record for record in records if record.kind == "ioc_multiple_types_observation")
    assert summary.raw["types_present"] == 3
    decision = score_direct_evidence(direct_evidence=records)
    assert len(decision.evidence) == len(records)
    assert decision.risk_score == 0
    assert decision.risk_level == "clean"
    assert decision.breakdown.independent_source_count == 0
    assert decision.breakdown.synergy_bonus == 0
    assert decision.breakdown.high_gate_open is False
    assert decision.breakdown.malicious_gate_open is False
    assert decision.score_trace["components"] == []
    assert decision.policy_version == POLICY_VERSION == "msrs-v1.2"


@pytest.mark.parametrize(
    "observations",
    [
        {"urls": ["https://example.org/"]},
        {"domains": ["document.xml"]},
        {"ips": ["192.0.2.1"]},
        {"ip_addresses": ["192.0.2.1"]},
        {"urls": ["https://example.org/"], "domains": ["example.org"]},
        {"domains": ["example.org"], "ips": ["192.0.2.1"]},
    ],
)
def test_each_raw_type_and_type_combination_is_unscored(observations: dict[str, Any]) -> None:
    records = _records({"ioc-extract": observations})
    assert records
    assert all(record.tier == "benign_context" and record.points == 0 for record in records)
    decision = score_direct_evidence(direct_evidence=records)
    assert decision.risk_score == 0
    assert decision.breakdown.independent_source_count == 0


@pytest.mark.parametrize(
    "other_findings, expected_score",
    [
        ({"deobfuscation": {"techniques_found": ["base64"]}}, 4),
        ({"deobfuscation": {"decoded_strings_preview": ["cmd.exe /c echo test"]}}, 12),
        ({"clamav": {"infected": True, "result": "Win.Test.EICAR_HDB-1"}}, 95),
        (
            {
                "yara": {
                    "matches": [
                        {"rule": "jsp_webshell", "classification": "generic", "severity": "high"}
                    ]
                }
            },
            25,
        ),
        (
            {
                "yara": {
                    "matches": [{"rule": "custom_family", "classification": "malicious_family"}]
                }
            },
            85,
        ),
        (
            {
                "format-analysis": {
                    "heuristics": [
                        {
                            "key": "office.external_template_execution",
                            "confidence": 0.9,
                            "summary": "Execution-oriented external template reference",
                        }
                    ]
                }
            },
            20,  # Existing heuristic_structure cap remains unchanged.
        ),
        (
            {
                "format-analysis": {
                    "indicators": [
                        {
                            "type": "pe_section_anomaly",
                            "severity": "critical",
                            "detail": "Suspicious executable structure",
                        }
                    ]
                }
            },
            70,
        ),
    ],
)
def test_context_cannot_change_other_findings_scores_sources_gates_or_synergy(
    other_findings: dict[str, Any], expected_score: int
) -> None:
    baseline = score_direct_evidence(direct_evidence=_records(other_findings))
    observed = _records({**other_findings, "ioc-extract": _office_observations()})
    combined = score_direct_evidence(direct_evidence=observed)
    assert baseline.risk_score == expected_score
    assert combined.risk_score == baseline.risk_score
    assert combined.risk_level == baseline.risk_level
    assert combined.legacy_verdict == baseline.legacy_verdict
    assert combined.breakdown == baseline.breakdown
    assert len(combined.evidence) > len(baseline.evidence)
