"""Tests for adapting direct stage outputs into evidence records."""

import pytest
from malscan.scoring.adapters import build_direct_evidence


def test_clamav_infected_hit_becomes_confirmed_signature_evidence() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {
                "infected": True,
                "result": "Win.Test.EICAR_HDB-1",
            }
        },
    )

    assert len(records) == 1
    record = records[0]
    assert record.source == "clamav"
    assert record.scope == "direct"
    assert record.kind == "confirmed_malware_signature"
    assert record.tier == "confirmed"
    assert record.confidence == 1.0
    assert record.cap_group == "signature"
    assert record.points == 95
    assert record.raw["signature"] == "Win.Test.EICAR_HDB-1"


def test_yara_classification_comes_from_metadata_not_rule_name() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "yara": {
                "matches": [
                    {
                        "rule": "generic_suspicious_name",
                        "classification": "MALICIOUS_FAMILY",
                        "confidence": "HIGH",
                        "family": "TrickBot",
                        "severity": "HIGH",
                    }
                ]
            }
        },
    )

    assert len(records) == 1
    record = records[0]
    assert record.kind == "yara_malicious_family"
    assert record.tier == "confirmed"
    assert record.points == 85
    assert record.confidence == 0.95
    assert record.scope == "direct"
    assert record.severity == "high"
    assert record.cap_group == "yara"
    assert record.raw == {
        "rule": "generic_suspicious_name",
        "classification": "MALICIOUS_FAMILY",
        "confidence": "HIGH",
        "family": "TrickBot",
        "severity": "HIGH",
    }


def test_raw_iocs_are_emitted_as_unscored_context() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "ioc-extract": {
                "urls": ["https://a.test", "https://b.test"],
                "domains": ["a.test"],
                "ips": ["1.2.3.4"],
            }
        },
    )

    ioc_records = [record for record in records if record.source == "ioc"]

    assert len(ioc_records) == 5
    assert {record.tier for record in ioc_records} == {"benign_context"}
    assert {record.severity for record in ioc_records} == {"info"}
    assert {record.points for record in ioc_records} == {0}
    assert {record.scope for record in ioc_records} == {"direct"}
    assert {record.cap_group for record in ioc_records} == {"ioc_raw"}
    assert {record.kind for record in ioc_records} >= {
        "raw_url_ioc",
        "raw_domain_ioc",
        "raw_ip_ioc",
        "ioc_multiple_types_observation",
    }


def test_raw_ioc_ip_addresses_alias_is_used_when_ips_is_none() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "ioc-extract": {
                "urls": [],
                "domains": [],
                "ips": None,
                "ip_addresses": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            }
        },
    )

    ip_records = [record for record in records if record.kind == "raw_ip_ioc"]

    assert len(ip_records) == 3
    assert {record.raw["value"] for record in ip_records} == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}


def test_format_analysis_uses_indicators_without_risk_score_support_when_two_or_more() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "indicators": [
                    {
                        "type": "pe_section_anomaly",
                        "severity": "critical",
                        "detail": "Entry point jumps into suspicious section",
                    },
                    {
                        "type": "header_inconsistency",
                        "severity": "medium",
                        "detail": "Section sizes do not align cleanly",
                    },
                ],
                "risk_score": 88,
            }
        },
    )

    format_records = [record for record in records if record.source == "format-analysis"]
    kinds = {record.kind for record in format_records}

    assert "format_execution_or_exploit_critical" in kinds
    assert "format_structural_anomaly_medium" in kinds
    assert "format_risk_score_support" not in kinds
    assert {record.scope for record in format_records} == {"direct"}
    assert {record.cap_group for record in format_records} == {"format_structural"}
    assert {record.confidence for record in format_records} == {0.8, 0.6}
    assert any(
        record.kind == "format_execution_or_exploit_critical"
        and record.reason == "Entry point jumps into suspicious section"
        for record in format_records
    )


def test_format_analysis_fallback_support_uses_plan_scoring() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "indicators": [
                    {
                        "type": "unknown_structure_issue",
                        "severity": "low",
                        "detail": "Minor packing indicators",
                    }
                ],
                "risk_score": 22,
                "risk_factors": ["overlay", "entropy"],
            }
        },
    )

    support_records = [record for record in records if record.kind == "format_risk_score_support"]

    assert len(support_records) == 1
    record = support_records[0]
    assert record.cap_group == "format_structural"
    assert record.points == 5
    assert record.confidence == 0.4
    assert record.raw == {"risk_score": 22, "risk_factors": ["overlay", "entropy"]}


def test_format_heuristics_are_normalized_before_legacy_indicator_fallback() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {
                "heuristics": [
                    {
                        "key": "api.process_injection_cluster",
                        "category": "api_pattern",
                        "scope": "pe",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Process injection API cluster detected",
                        "evidence": {
                            "matched": [
                                "VirtualAllocEx",
                                "WriteProcessMemory",
                                "CreateRemoteThread",
                            ]
                        },
                        "tags": ["injection"],
                    }
                ],
                "risk_score": 0,
                "indicators": [
                    {
                        "type": "header_inconsistency",
                        "severity": "medium",
                        "detail": "Section sizes do not align cleanly",
                    }
                ],
            },
            "deobfuscation": {},
            "archive-extract": {},
            "sandbox": {},
        },
    )

    heuristic_record = next(
        record for record in records if record.kind == "api.process_injection_cluster"
    )

    assert heuristic_record.source == "format-analysis"
    assert heuristic_record.tier == "strong"
    assert heuristic_record.severity == "high"
    assert heuristic_record.points == 40
    assert heuristic_record.cap_group == "heuristic_api"
    assert heuristic_record.reason == "Process injection API cluster detected"


def test_format_heuristics_disable_risk_score_support_without_skipping_indicators() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "heuristics": [
                    {
                        "key": "packer.known_section_name",
                        "category": "packer",
                        "scope": "pe",
                        "role": "corroborating",
                        "severity": "low",
                        "confidence": 0.7,
                        "summary": "Known packer section name present",
                    }
                ],
                "indicators": [
                    {
                        "type": "unknown_structure_issue",
                        "severity": "low",
                        "detail": "Minor packing indicators",
                    }
                ],
                "risk_score": 40,
                "risk_factors": ["overlay", "entropy"],
            }
        },
    )

    kinds = {record.kind for record in records if record.source == "format-analysis"}

    assert "packer.known_section_name" in kinds
    assert "format_structural_anomaly_low" in kinds
    assert "format_risk_score_support" not in kinds


def test_archive_heuristics_are_normalized_to_archive_cap_group() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {},
            "deobfuscation": {},
            "archive-extract": {
                "heuristics": [
                    {
                        "key": "archive.executable_concentration",
                        "category": "archive",
                        "scope": "archive",
                        "role": "corroborating",
                        "severity": "medium",
                        "confidence": 0.8,
                        "summary": "Archive contains multiple executable-like members",
                        "evidence": {"executable_member_count": 3},
                        "tags": ["archive"],
                    }
                ]
            },
            "sandbox": {},
        },
    )

    record = next(item for item in records if item.kind == "archive.executable_concentration")

    assert record.source == "archive-extract"
    assert record.cap_group == "heuristic_archive"
    assert record.points == 18
    assert record.tier == "medium"


def test_null_heuristics_are_ignored_without_breaking_adapter() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "heuristics": None,
                "indicators": [
                    {
                        "type": "unknown_structure_issue",
                        "severity": "low",
                        "detail": "Minor packing indicators",
                    }
                ],
                "risk_score": 12,
            },
            "archive-extract": {
                "heuristics": None,
            },
        },
    )

    assert {record.kind for record in records} == {
        "format_structural_anomaly_low",
        "format_risk_score_support",
    }


def test_format_analysis_macro_presence_maps_to_low_risk_loader_signal() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "indicators": [
                    {
                        "type": "macro_presence",
                        "severity": "low",
                        "detail": "Office document contains macros",
                    }
                ],
                "risk_score": 3,
                "risk_factors": ["macro_presence"],
            }
        },
    )

    format_records = [record for record in records if record.source == "format-analysis"]

    assert len(format_records) == 1
    record = format_records[0]
    assert record.kind == "format_structural_anomaly_medium"
    assert record.tier == "medium"
    assert record.points == 12
    assert record.reason == "Office document contains macros"


def test_deobfuscation_emits_technique_and_payload_execution_evidence() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "deobfuscation": {
                "techniques_found": ["base64", "string_concat"],
                "decoded_strings_preview": [
                    "powershell -nop -w hidden -enc AAAA",
                    "cmd.exe /c whoami",
                    "other string",
                ],
            }
        },
    )

    deobfuscation_records = [record for record in records if record.source == "deobfuscation"]

    assert len(deobfuscation_records) >= 2
    assert {record.tier for record in deobfuscation_records} <= {"weak", "medium"}
    assert {record.scope for record in deobfuscation_records} == {"direct"}
    assert {record.cap_group for record in deobfuscation_records} == {"deob"}
    execution_records = [
        record
        for record in deobfuscation_records
        if record.kind == "deobfuscated_payload_execution"
    ]
    assert len(execution_records) == 2
    assert {record.reason for record in execution_records} == {
        "Decoded content reveals execution-oriented payload"
    }
    assert {record.raw["preview"] for record in execution_records} == {
        "powershell -nop -w hidden -enc AAAA",
        "cmd.exe /c whoami",
    }


def test_sandbox_reads_behavior_dicts_and_uses_dynamic_cap_group() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "sandbox": {
                "behaviors": [
                    {"type": "process_injection"},
                    {"type": "benign_child_process"},
                ],
                "network_connections": [{"dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "tcp"}],
            }
        },
    )

    assert len(records) == 1
    record = records[0]
    assert record.source == "sandbox"
    assert record.scope == "direct"
    assert record.kind == "sandbox_confirmed_malicious_behavior"
    assert record.cap_group == "dynamic"
    assert record.confidence == 1.0
    assert record.raw == {
        "behaviors": [
            {"type": "process_injection"},
            {"type": "benign_child_process"},
        ],
        "network_connections": [{"dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "tcp"}],
    }


def test_sandbox_scoring_reads_additive_network_shape_too() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "sandbox": {
                "behaviors": [{"type": "credential_theft"}],
                "tcp_udp": [{"dst_ip": "10.0.0.8", "dst_port": 8443, "protocol": "tcp"}],
                "provider": "capev2",
                "task_id": "42",
            }
        },
    )

    assert len(records) == 1
    record = records[0]
    assert record.kind == "sandbox_confirmed_malicious_behavior"
    assert record.raw == {
        "behaviors": [{"type": "credential_theft"}],
        "network_connections": [{"dst_ip": "10.0.0.8", "dst_port": 8443, "protocol": "tcp"}],
        "provider": "capev2",
        "task_id": "42",
    }


@pytest.mark.parametrize(
    "metadata",
    [
        {"provider": "mock"},
        {"is_mock": True},
        {"synthetic": True},
        {"executed": False},
        *[
            {"status": status}
            for status in (
                "synthetic",
                "mock",
                "disabled",
                "not_requested",
                "deferred",
                "queued",
                "unavailable",
                "failed",
                "timeout",
                "unsupported",
            )
        ],
    ],
)
def test_sandbox_mock_or_incomplete_results_cannot_be_malicious_evidence(metadata):
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "sandbox": {
                "behaviors": [{"type": "process_injection"}],
                **metadata,
            }
        },
    )
    assert records == []


def test_completed_real_sandbox_still_contributes_dynamic_evidence():
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "sandbox": {
                "status": "completed",
                "executed": True,
                "is_mock": False,
                "provider": "capev2",
                "task_id": "42",
                "behaviors": [{"type": "process_injection"}],
            }
        },
    )
    assert len(records) == 1
    assert records[0].cap_group == "dynamic"


def test_build_direct_evidence_preserves_artifact_and_analyzer_provenance() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "analyzer": "script",
                "heuristics": [
                    {
                        "key": "script.encoded_command_execution",
                        "category": "script_token",
                        "scope": "script",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Encoded payload and execution primitives appear together",
                        "evidence": {"exec_operations": ["powershell", "iex"]},
                    }
                ],
            }
        },
    )

    record = next(item for item in records if item.kind == "script.encoded_command_execution")

    assert record.artifact_id == "artifact-1"
    assert record.stage == "format-analysis"
    assert record.analyzer == "script"
