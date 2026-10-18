"""Helpers for building worker report payloads."""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from malscan.analysis_contract import REPORT_SCHEMA_VERSION, build_analysis
from malscan.scoring.policy import POLICY_VERSION


def build_password_attempts_exhausted_report(
    job_data: dict[str, Any],
    existing_report: dict[str, Any] | None = None,
    *,
    password_kind: str | None = None,
) -> dict[str, Any]:
    """Preserve available detections when file password attempts are exhausted."""
    previous_format = (existing_report or {}).get("results", {}).get("format_analysis", {})
    pdf_password = password_kind == "pdf" or previous_format.get("password_kind") == "pdf"
    blocked_stage_name = "format-analysis" if pdf_password else "archive-extract"
    result_key = "format_analysis" if pdf_password else "archive_extract"
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "job_id": job_data["job_id"],
        "file": {
            "file_id": job_data["file_id"],
            "sha256": job_data.get("sha256", ""),
            "mime": "application/octet-stream",
            "size": 0,
            "original_filename": job_data.get("original_filename", "unknown"),
        },
        "verdict": "unknown",
        "score": 0,
        "risk_level": "clean",
        "risk": {
            "policy_version": POLICY_VERSION,
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
            "av_result": {
                "engine": "ClamAV",
                "infected": False,
                "threat_name": None,
            },
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {
                    "md5": "",
                    "sha1": "",
                    "sha256": job_data.get("sha256", ""),
                },
            },
            "sandbox": {
                "status": "not_requested",
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "provider": None,
                "task_id": None,
                "is_mock": False,
                "verdict_hint": None,
                "processes": [],
                "files": [],
                "registry": [],
                "mutexes": [],
                "dns": [],
                "http": [],
                "tcp_udp": [],
                "dropped_files": [],
                "screenshots": [],
                "pcap": {"available": False, "url": None},
                "memory_dump": {"available": False, "url": None},
                "iocs": {"domains": [], "ips": [], "urls": []},
                "errors": [],
                "raw_report_ref": None,
            },
            result_key: {
                "archive_type": None,
                "extracted_count": 0,
                "sub_jobs_created": 0,
                "total_extracted_bytes": 0,
                "reason": "連續 3 次密碼錯誤，封存檔解壓失敗。",
                "extraction_failed": True,
            },
        },
        "timings": {
            "total_ms": 0,
            "stages": [],
        },
        "explainability": {
            "summary": {
                "headline": "因密碼嘗試次數耗盡，封存內容未被分析。",
                "primary_artifact_id": None,
                "primary_artifact_path": None,
                "top_findings": [],
                "final_verdict_explainer": "此報告僅反映最外層檔案的分析結果。",
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
                "headline": "內層封存內容因密碼耗盡而無法分析。",
                "diagnostics": [
                    {
                        "stage": blocked_stage_name,
                        "code": "password_attempts_exhausted",
                        "category": "blocked",
                        "severity": "high",
                        "likely_effect": "possible_false_negative",
                        "confidence": "high",
                        "message": "連續 3 次密碼錯誤，封存檔解壓失敗。",
                        "recommended_action": "請取得正確密碼後重新提交分析。",
                    }
                ],
                "suspected_miss_stages": [
                    {
                        "stage": blocked_stage_name,
                        "reason": "內層檔案未曾被解壓，因此未進入分析流程。",
                        "confidence": "high",
                    }
                ],
            },
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if pdf_password:
        report["results"][result_key] = {
            "analyzer": "pdf",
            "format_type": "PDF",
            "features": {"encrypted": True, "content_access": "password_attempts_exhausted"},
            "password_kind": "pdf",
            "reason": "連續 3 次密碼錯誤，PDF 解密失敗。",
            "decryption_failed": True,
        }
        summary = report["explainability"]["summary"]
        summary["headline"] = "因密碼嘗試次數耗盡，PDF 加密內容未被分析。"
        diagnostics = report["explainability"]["failure_diagnostics"]
        diagnostics["headline"] = "PDF 加密內容因密碼耗盡而無法分析。"
        diagnostics["diagnostics"][0]["message"] = report["results"][result_key]["reason"]
        diagnostics["suspected_miss_stages"][0][
            "reason"
        ] = "PDF 內容未曾被解密，因此未進入明文分析流程。"
    if isinstance(existing_report, dict):
        # Exhausting the password budget blocks descendants; it must not erase
        # detections and evidence obtained from the outer file.
        merged = deepcopy(existing_report)
        merged["report_schema_version"] = REPORT_SCHEMA_VERSION
        merged.setdefault("results", {})[result_key] = {
            **merged.get("results", {}).get(result_key, {}),
            **report["results"][result_key],
        }
        explainability = merged.setdefault("explainability", {})
        explainability["failure_diagnostics"] = report["explainability"]["failure_diagnostics"]
        summary = explainability.setdefault("summary", {})
        summary["headline"] = report["explainability"]["summary"]["headline"]
        summary["final_verdict_explainer"] = report["explainability"]["summary"][
            "final_verdict_explainer"
        ]
        report = merged
    now = datetime.now(timezone.utc).isoformat()
    blocked_stage = {
        "stage_name": blocked_stage_name,
        "status": "blocked",
        "duration_ms": 0,
        "started_at": now,
        "ended_at": now,
        "findings": report["results"][result_key],
        "artifacts": [],
        "error": "File password attempts exhausted",
    }
    stages = [
        stage for stage in report.get("stages", []) if stage.get("stage_name") != blocked_stage_name
    ]
    stages.append(blocked_stage)
    report["stages"] = stages
    for stage in stages:
        if stage.get("status") == "pending":
            stage["status"] = "blocked"
            stage["findings"] = {"reason": "Not executed after file password attempts exhausted"}
    sandbox = report["results"].get("sandbox")
    if not isinstance(sandbox, dict) or not sandbox.get("status"):
        report["results"]["sandbox"] = {
            "status": "not_requested",
            "executed": False,
            "reason": "File password attempts exhausted",
        }
    timings = report.setdefault("timings", {"total_ms": 0, "stages": []})
    timings["stages"] = [
        stage for stage in timings.get("stages", []) if stage.get("name") != blocked_stage_name
    ] + [
        {
            "name": blocked_stage_name,
            "status": "blocked",
            "duration_ms": 0,
            "reason": "File password attempts exhausted",
            "started_at": now,
            "ended_at": now,
        }
    ]
    # Pending stages after a permanent password block were not executed.
    for stage in timings["stages"]:
        if stage.get("status") == "pending":
            stage["status"] = "blocked"
            stage["reason"] = "Not executed after file password attempts exhausted"
    report["analysis"] = build_analysis(
        stages=timings["stages"],
        sandbox=report["results"].get("sandbox"),
    )
    return report
