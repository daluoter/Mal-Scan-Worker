"""Tests for worker pipeline local risk scoring integration."""

from datetime import datetime, timezone

from malscan.scoring.policy import POLICY_VERSION
from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageResult


def _stage(stage_name: str, findings: dict) -> StageResult:
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


def test_pipeline_builds_risk_block_and_legacy_fields_from_local_scorer() -> None:
    ctx = type(
        "Ctx",
        (),
        {
            "sha256": "abc123",
            "original_filename": "sample.bin",
            "artifact_id": "artifact-1",
        },
    )()
    report = _build_analysis_result(
        "job-1",
        "file-1",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/octet-stream", "file_size": 10}),
            _stage("clamav", {"infected": False, "threat_name": None}),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage(
                "format-analysis",
                {
                    "analyzer": "pe",
                    "format_type": "PE",
                    "risk_score": 37,
                    "risk_factors": ["packed"],
                    "indicators": [
                        {"type": "suspicious_import", "severity": "high", "detail": "packed"}
                    ],
                    "features": {"entrypoint": 4096},
                },
            ),
        ],
        123,
    )

    assert report["score"] == report["risk"]["risk_score"]
    assert report["risk_level"] == "medium"
    assert report["verdict"] == "suspicious"
    assert report["risk"]["legacy_verdict"] == "suspicious"
    assert report["risk"]["policy_version"] == POLICY_VERSION
    assert report["risk"]["evidence"]
    assert report["risk"]["top_evidence"]
    assert set(report["risk"]["evidence"][0]) >= {
        "source",
        "kind",
        "tier",
        "severity",
        "points",
        "scope",
        "depth",
        "reason",
        "raw",
    }


def test_confirmed_clamav_hit_produces_malicious_local_risk() -> None:
    ctx = type(
        "Ctx",
        (),
        {
            "sha256": "def456",
            "original_filename": "sample.bin",
            "artifact_id": "artifact-2",
        },
    )()
    report = _build_analysis_result(
        "job-2",
        "file-2",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/octet-stream", "file_size": 10}),
            _stage(
                "clamav",
                {"infected": True, "threat_name": "Win.Test.EICAR_HDB-1"},
            ),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
        ],
        123,
    )

    assert report["score"] == 95
    assert report["risk_level"] == "malicious"
    assert report["verdict"] == "malicious"


def test_office_macro_autoexec_and_keywords_still_influence_local_risk() -> None:
    ctx = type(
        "Ctx",
        (),
        {
            "sha256": "office-1",
            "original_filename": "invoice.docm",
            "artifact_id": "artifact-office-1",
        },
    )()
    report = _build_analysis_result(
        "job-office-1",
        "file-office-1",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/msword", "file_size": 10}),
            _stage("clamav", {"infected": False, "threat_name": None}),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage(
                "format-analysis",
                {
                    "analyzer": "office",
                    "format_type": "OLE",
                    "risk_score": 11,
                    "risk_factors": ["macro_auto_exec"],
                    "indicators": [
                        {
                            "type": "macro_auto_exec",
                            "severity": "medium",
                            "detail": (
                                "Office document contains auto-exec macros " "with suspicious APIs"
                            ),
                        }
                    ],
                    "features": {
                        "document_type": "ole",
                        "macros": {
                            "found": True,
                            "auto_exec": True,
                            "suspicious": True,
                            "sources": [{"module": "Module1", "auto_exec": True}],
                        },
                        "embedded_objects": [],
                        "parser_findings": [],
                    },
                    "extracted_strings": ["Shell", "CreateObject", "WScript.Shell"],
                },
            ),
        ],
        123,
    )

    assert report["verdict"] == "suspicious"
    assert report["risk_level"] == "medium"
    assert report["score"] == 37


def test_office_benign_macros_keep_clean_verdict_but_nonzero_score() -> None:
    ctx = type(
        "Ctx",
        (),
        {
            "sha256": "office-2",
            "original_filename": "macro.doc",
            "artifact_id": "artifact-office-2",
        },
    )()
    report = _build_analysis_result(
        "job-office-2",
        "file-office-2",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/msword", "file_size": 10}),
            _stage("clamav", {"infected": False, "threat_name": None}),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage(
                "format-analysis",
                {
                    "analyzer": "office",
                    "format_type": "OLE",
                    "risk_score": 3,
                    "risk_factors": ["macro_presence"],
                    "indicators": [
                        {
                            "type": "macro_presence",
                            "severity": "low",
                            "detail": "Office document contains macros",
                        }
                    ],
                    "features": {
                        "document_type": "ole",
                        "macros": {
                            "found": True,
                            "auto_exec": False,
                            "suspicious": False,
                            "sources": [{"module": "Module1", "auto_exec": False}],
                        },
                        "embedded_objects": [],
                        "parser_findings": [],
                    },
                    "extracted_strings": [],
                },
            ),
        ],
        123,
    )

    assert report["verdict"] == "suspicious"
    assert report["risk_level"] == "low"
    assert report["score"] >= 10
