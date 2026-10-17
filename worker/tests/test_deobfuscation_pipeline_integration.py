"""Integration-oriented tests for deobfuscation in pipeline result building."""

from datetime import datetime, timezone

import pytest
from malscan_worker.metrics import CONTENT_TYPE_LATEST, metrics_handler
from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageContext, StageResult


def _stage_result(stage_name: str, findings: dict) -> StageResult:
    now = datetime.now(timezone.utc)
    return StageResult(
        stage_name=stage_name,
        status="ok",
        started_at=now,
        ended_at=now,
        duration_ms=1,
        findings=findings,
        artifacts=[],
    )


def _build_report(results: list[StageResult]) -> dict:
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key-1",
        sha256="a" * 64,
        original_filename="sample.bin",
        file_path=None,
    )
    return _build_analysis_result("job-1", "file-1", ctx, results, total_ms=100)


def test_deobfuscation_iocs_are_merged_into_report_iocs_with_dedupe() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": ["http://a.test", "http://shared.test/path"],
                    "domains": ["a.test", "shared.test"],
                    "ip_addresses": ["1.1.1.1", "2.2.2.2"],
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": ["http://shared.test/path", "http://b.test"],
                        "domains": ["shared.test", "b.test"],
                        "ips": ["2.2.2.2", "3.3.3.3"],
                    }
                },
            ),
        ]
    )

    iocs = report["results"]["iocs"]
    assert iocs["urls"] == ["http://a.test", "http://shared.test/path", "http://b.test"]
    assert iocs["domains"] == ["a.test", "shared.test", "b.test"]
    assert iocs["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_deobfuscation_report_section_exists() -> None:
    deob_findings = {
        "candidates": [
            {
                "content": "http://evil.test",
                "content_encoding": "utf-8",
                "content_byte_length": 16,
                "confidence": 0.91,
                "technique": "base64",
                "truncated": False,
                "tags": [],
                "provenance": {
                    "decoder": "base64",
                    "offset": 10,
                    "length": 24,
                    "key": None,
                    "meta": {},
                },
            }
        ],
        "extracted_iocs": {
            "urls": ["http://evil.test"],
            "domains": ["evil.test"],
            "ips": [],
            "commands": [],
        },
        "techniques_found": ["base64"],
        "total_decoded_bytes": 16,
        "stats": {"final_candidate_count": 1},
    }
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result("deobfuscation", deob_findings),
        ]
    )

    assert "deobfuscation" in report["results"]
    assert report["results"]["deobfuscation"] == deob_findings


def test_deobfuscation_candidates_keep_structured_ids_and_source_stage() -> None:
    deob_findings = {
        "candidates": [
            {
                "decoded_id": "decoded::artifact-1::1",
                "content": "http://evil.test",
                "content_encoding": "utf-8",
                "content_byte_length": 16,
                "serialized_content_byte_length": 16,
                "content_truncated": False,
                "confidence": 0.91,
                "technique": "base64",
                "truncated": False,
                "tags": [],
                "source_stage": "deobfuscation",
                "provenance": {
                    "decoder": "base64",
                    "offset": 10,
                    "length": 24,
                    "key": None,
                    "meta": {},
                },
            }
        ],
        "extracted_iocs": {
            "urls": ["http://evil.test"],
            "domains": ["evil.test"],
            "ips": [],
            "commands": [],
        },
        "techniques_found": ["base64"],
        "total_decoded_bytes": 16,
        "stats": {"final_candidate_count": 1},
    }
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": [],
                    "domains": [],
                    "ips": [],
                    "ioc_items": [],
                },
            ),
            _stage_result("deobfuscation", deob_findings),
        ]
    )

    candidate = report["results"]["deobfuscation"]["candidates"][0]
    assert candidate["decoded_id"] == "decoded::artifact-1::1"
    assert candidate["source_stage"] == "deobfuscation"


def test_pure_deobfuscation_with_raw_ioc_stays_low_risk() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {"urls": ["http://a.test"], "domains": [], "ip_addresses": []},
            ),
            _stage_result(
                "deobfuscation",
                {
                    "techniques_found": ["base64"],
                    "decoded_strings_preview": ["powershell -nop -w hidden -enc AAAA"],
                    "extracted_iocs": {
                        "urls": ["http://a.test"],
                        "domains": [],
                        "ips": [],
                    },
                },
            ),
        ]
    )

    # The decoded execution marker still contributes; its raw URL is context.
    assert report["score"] == 16
    assert report["risk_level"] == "low"
    assert report["verdict"] == "suspicious"


def test_deobfuscation_plus_confirmed_yara_is_malicious() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result(
                "yara",
                {
                    "matches": [
                        {
                            "rule": "malware_family_rule",
                            "classification": "malicious_family",
                            "confidence": "high",
                            "severity": "high",
                        }
                    ]
                },
            ),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {
                    "decoded_strings_preview": ["powershell -nop -w hidden -enc AAAA"],
                },
            ),
        ]
    )

    assert report["score"] == 100
    assert report["risk_level"] == "malicious"
    assert report["verdict"] == "malicious"


def test_no_deobfuscation_evidence_remains_clean() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {"extracted_iocs": {"urls": [], "domains": [], "ips": []}},
            ),
        ]
    )

    assert report["score"] == 0
    assert report["risk_level"] == "clean"
    assert report["verdict"] == "clean"


def test_deobfuscation_decoded_iocs_are_reported_without_affecting_local_score() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": [
                            "http://dup.test/a",
                            "http://dup.test/a",
                            "http://uniq.test/b",
                        ],
                        "domains": ["dup.test", "dup.test"],
                        "ips": ["9.9.9.9", "9.9.9.9"],
                    }
                },
            ),
        ]
    )

    assert report["score"] == 0
    assert report["risk_level"] == "clean"
    assert report["verdict"] == "clean"


def test_none_ioc_fields_are_treated_as_empty_lists() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": None,
                    "domains": None,
                    "ip_addresses": None,
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": None,
                        "domains": None,
                        "ips": None,
                        "ip_addresses": None,
                    }
                },
            ),
        ]
    )

    assert report["score"] == 0
    assert report["verdict"] == "clean"
    assert report["results"]["iocs"]["urls"] == []
    assert report["results"]["iocs"]["domains"] == []
    assert report["results"]["iocs"]["ips"] == []


def test_ip_addresses_alias_is_preserved_as_context_when_ips_is_none() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": [],
                    "domains": [],
                    "ips": None,
                    "ip_addresses": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                },
            ),
        ]
    )

    assert report["results"]["iocs"]["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert report["score"] == 0
    assert report["risk_level"] == "clean"
    assert report["verdict"] == "clean"
    ip_evidence = [item for item in report["risk"]["evidence"] if item["kind"] == "raw_ip_ioc"]
    assert len(ip_evidence) == 3
    assert all(item["tier"] == "benign_context" and item["points"] == 0 for item in ip_evidence)


def test_mixed_ips_and_ip_addresses_fields_are_merged_correctly() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": [],
                    "domains": [],
                    "ips": ["1.1.1.1", "2.2.2.2"],
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": [],
                        "domains": [],
                        "ip_addresses": ["2.2.2.2", "3.3.3.3"],
                    }
                },
            ),
        ]
    )

    assert report["results"]["iocs"]["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


@pytest.mark.asyncio
async def test_metrics_handler_sets_prometheus_content_type_header() -> None:
    response = await metrics_handler(None)  # type: ignore[arg-type]

    assert response.headers["Content-Type"] == CONTENT_TYPE_LATEST
