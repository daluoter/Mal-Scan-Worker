"""Adapters that normalize direct stage outputs into evidence records."""

from typing import Any

from malscan.scoring.models import EvidenceRecord

YARA_CLASSIFICATION_MAP = {
    "informational": ("yara_context_observation", "benign_context", 0),
    "malicious_family": ("yara_malicious_family", "confirmed", 85),
    "exploit": ("yara_exploit_rule", "strong", 75),
    "suspicious": ("yara_suspicious_behavior", "strong", 55),
}

YARA_CONFIDENCE_MAP = {
    "low": 0.4,
    "medium": 0.7,
    "high": 0.95,
}

FORMAT_SEVERITY_MAP = {
    "critical": ("format_execution_or_exploit_critical", "strong", 70),
    "high": ("format_execution_or_exploit_high", "strong", 50),
    "medium": ("format_structural_anomaly_medium", "medium", 20),
}

HEURISTIC_MAP = {
    "entropy.high_region_cluster": ("weak", 8, "heuristic_entropy"),
    "packer.known_section_name": ("weak", 10, "heuristic_packer"),
    "packer.sparse_imports_high_entropy": ("medium", 18, "heuristic_packer"),
    "api.process_injection_cluster": ("strong", 40, "heuristic_api"),
    "structure.overlay_anomaly": ("weak", 10, "heuristic_structure"),
    "resource.embedded_executable": ("medium", 22, "heuristic_resource"),
    "script.encoded_command_execution": ("strong", 45, "heuristic_script"),
    "script.download_execute_chain": ("medium", 20, "heuristic_script"),
    "script.amsi_bypass": ("medium", 18, "heuristic_script"),
    "script.long_line_entropy_cluster": ("weak", 8, "heuristic_script"),
    "lolbin.reference_only": ("weak", 6, "heuristic_lolbin"),
    "lolbin.execution_chain": ("medium", 18, "heuristic_lolbin"),
    "archive.password_protected": ("weak", 6, "heuristic_archive"),
    "archive.executable_concentration": ("medium", 18, "heuristic_archive"),
    "archive.path_traversal_member": ("weak", 10, "heuristic_archive"),
    "archive.deep_nesting": ("weak", 8, "heuristic_archive"),
    "office.external_template_execution": ("strong", 45, "heuristic_structure"),
    "office.macro_autoexec_launcher": ("medium", 20, "heuristic_script"),
    "pdf.launch_action_executable": ("strong", 45, "heuristic_structure"),
}

FORMAT_OVERRIDE_INDICATORS = {"macro_auto_exec", "embedded_executable", "suspicious_launcher"}
PAYLOAD_EXECUTION_MARKERS = ("powershell", "cmd.exe", "rundll32", "regsvr32")
SANDBOX_CONFIRMED_BEHAVIORS = {"process_injection", "credential_theft", "ransomware"}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _append(records: list[EvidenceRecord], **kwargs: Any) -> None:
    records.append(
        EvidenceRecord(
            evidence_id=f"ev-{len(records) + 1}",
            scope="direct",
            related_artifact_id=None,
            depth=0,
            tags=(),
            score_contribution={},
            **kwargs,
        )
    )


def _severity_for_tier(tier: str) -> str:
    if tier == "confirmed":
        return "critical"
    if tier == "strong":
        return "high"
    if tier == "medium":
        return "medium"
    return "low"


def _append_clamav(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    if not finding.get("infected"):
        return

    signature = finding.get("result") or finding.get("threat_name") or ""
    _append(
        records,
        source="clamav",
        kind="confirmed_malware_signature",
        tier="confirmed",
        severity="critical",
        confidence=1.0,
        points=95,
        cap_group="signature",
        artifact_id=artifact_id,
        reason=f"ClamAV reported malware signature {signature or 'match'}",
        raw={"signature": signature},
    )


def _append_yara(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    for match in finding.get("matches", []):
        classification = str(match.get("classification", "generic") or "generic").lower()
        # A local provenance check only verifies bytes/inventory, never detection
        # accuracy. Its context category can reduce risk, not promote a claim.
        provenance = match.get("provenance")
        if (
            isinstance(provenance, dict)
            and provenance.get("status") == "verified"
            and provenance.get("category") == "context"
        ):
            classification = "informational"
        confidence_name = str(match.get("confidence", "medium") or "medium").lower()
        kind, tier, points = YARA_CLASSIFICATION_MAP.get(
            classification,
            ("yara_generic_heuristic", "weak", 25),
        )
        _append(
            records,
            source="yara",
            kind=kind,
            tier=tier,
            severity=(
                "info" if tier == "benign_context" else str(match.get("severity", "medium")).lower()
            ),
            confidence=YARA_CONFIDENCE_MAP.get(confidence_name, 0.7),
            points=points,
            cap_group="yara",
            artifact_id=artifact_id,
            reason=(
                f"YARA classification {classification} matched rule " f"{match.get('rule', '')}"
            ).strip(),
            raw=dict(match),
        )


def _append_iocs(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    # Extracted strings have neither destination reputation nor behavior context.
    # Keep their observed values in reports without treating lexical matches as
    # malicious evidence; independently established findings are scored elsewhere.
    urls = _string_list(finding.get("urls"))
    domains = _string_list(finding.get("domains"))
    ips: list[str] = []
    seen_ips: set[str] = set()
    for value in _string_list(finding.get("ips")) + _string_list(finding.get("ip_addresses")):
        if value in seen_ips:
            continue
        seen_ips.add(value)
        ips.append(value)

    for url in urls[:4]:
        _append(
            records,
            source="ioc",
            kind="raw_url_ioc",
            tier="benign_context",
            severity="info",
            confidence=0.6,
            points=0,
            cap_group="ioc_raw",
            artifact_id=artifact_id,
            reason=f"Observed URL IOC {url}",
            raw={"type": "url", "value": url},
        )

    for domain in domains[:4]:
        _append(
            records,
            source="ioc",
            kind="raw_domain_ioc",
            tier="benign_context",
            severity="info",
            confidence=0.6,
            points=0,
            cap_group="ioc_raw",
            artifact_id=artifact_id,
            reason=f"Observed domain IOC {domain}",
            raw={"type": "domain", "value": domain},
        )

    for ip in ips[:3]:
        _append(
            records,
            source="ioc",
            kind="raw_ip_ioc",
            tier="benign_context",
            severity="info",
            confidence=0.6,
            points=0,
            cap_group="ioc_raw",
            artifact_id=artifact_id,
            reason=f"Observed IP IOC {ip}",
            raw={"type": "ip", "value": ip},
        )

    non_empty_types = sum(1 for values in (urls, domains, ips) if values)
    if non_empty_types >= 2:
        _append(
            records,
            source="ioc",
            kind="ioc_multiple_types_observation",
            tier="benign_context",
            severity="info",
            confidence=0.7,
            points=0,
            cap_group="ioc_raw",
            artifact_id=artifact_id,
            reason="Observed multiple raw network indicator types; reputation is not assessed",
            raw={"types_present": non_empty_types},
        )


def _append_heuristic_records(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    source: str,
    heuristics: list[Any],
    *,
    analyzer: str | None = None,
) -> None:
    for hit in heuristics:
        if not isinstance(hit, dict):
            continue
        key = str(hit.get("key", "")).strip()
        if not key:
            continue
        tier, points, cap_group = HEURISTIC_MAP.get(
            key,
            ("weak", 5, "heuristic_structure"),
        )
        severity = "high" if tier == "strong" else ("medium" if tier == "medium" else "low")
        _append(
            records,
            source=source,
            stage=source,
            analyzer=analyzer,
            kind=key,
            tier=tier,
            severity=severity,
            confidence=float(hit.get("confidence", 0.5) or 0.5),
            points=points,
            cap_group=cap_group,
            artifact_id=artifact_id,
            reason=str(hit.get("summary", key)),
            raw=dict(hit),
        )


def _append_format_analysis(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    analyzer = str(finding.get("analyzer") or "") or None
    indicators = list(finding.get("indicators", []))
    heuristics = _dict_list(finding.get("heuristics"))

    for indicator in indicators:
        indicator_type = str(indicator.get("type", ""))
        indicator_severity = str(indicator.get("severity", "")).lower()

        if indicator_type in FORMAT_OVERRIDE_INDICATORS:
            confidence = 0.6
            _append(
                records,
                source="format-analysis",
                stage="format-analysis",
                analyzer=analyzer,
                kind="format_loader_or_dropper_pattern",
                tier="medium",
                severity="medium",
                confidence=confidence,
                points=35,
                cap_group="format_structural",
                artifact_id=artifact_id,
                reason=str(indicator.get("detail") or indicator_type),
                raw=dict(indicator),
            )
            continue

        if indicator_type == "macro_presence":
            _append(
                records,
                source="format-analysis",
                stage="format-analysis",
                analyzer=analyzer,
                kind="format_structural_anomaly_medium",
                tier="medium",
                severity="medium",
                confidence=0.6,
                points=12,
                cap_group="format_structural",
                artifact_id=artifact_id,
                reason=str(indicator.get("detail") or indicator_type),
                raw=dict(indicator),
            )
            continue

        kind, tier, points = FORMAT_SEVERITY_MAP.get(
            indicator_severity,
            ("format_structural_anomaly_low", "weak", 8),
        )
        _append(
            records,
            source="format-analysis",
            stage="format-analysis",
            analyzer=analyzer,
            kind=kind,
            tier=tier,
            severity=_severity_for_tier(tier),
            confidence=0.8 if tier in {"strong", "confirmed"} else 0.6,
            points=points,
            cap_group="format_structural",
            artifact_id=artifact_id,
            reason=str(indicator.get("detail") or indicator_type),
            raw=dict(indicator),
        )

    risk_score = int(finding.get("risk_score", 0) or 0)
    support_points = min(15, risk_score // 4)
    if not heuristics and len(indicators) < 2 and support_points > 0:
        _append(
            records,
            source="format-analysis",
            stage="format-analysis",
            analyzer=analyzer,
            kind="format_risk_score_support",
            tier="weak",
            severity="low",
            confidence=0.4,
            points=support_points,
            cap_group="format_structural",
            artifact_id=artifact_id,
            reason="Format analysis risk score provided supporting evidence",
            raw={
                "risk_score": risk_score,
                "risk_factors": finding.get("risk_factors", []),
            },
        )


def _append_deobfuscation(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    for technique in list(finding.get("techniques_found", []))[:3]:
        _append(
            records,
            source="deobfuscation",
            kind="deobfuscation_technique_found",
            tier="weak",
            severity="low",
            confidence=0.6,
            points=4,
            cap_group="deob",
            artifact_id=artifact_id,
            reason=f"Deobfuscation detected technique {technique}",
            raw={"technique": technique},
        )

    for preview in finding.get("decoded_strings_preview", []):
        lowered_preview = str(preview).lower()
        if any(marker in lowered_preview for marker in PAYLOAD_EXECUTION_MARKERS):
            _append(
                records,
                source="deobfuscation",
                kind="deobfuscated_payload_execution",
                tier="medium",
                severity="medium",
                confidence=0.75,
                points=12,
                cap_group="deob",
                artifact_id=artifact_id,
                reason="Decoded content reveals execution-oriented payload",
                raw={"preview": preview},
            )


def _append_sandbox(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    # Synthetic development data and incomplete provider attempts are not
    # evidence of a real detonation. Older real reports may omit these fields.
    if (
        finding.get("is_mock")
        or finding.get("synthetic")
        or finding.get("provider") == "mock"
        or finding.get("executed") is False
        or finding.get("status")
        in {
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
        }
    ):
        return
    behaviors = list(finding.get("behaviors", []))
    network_connections = list(finding.get("network_connections", []))
    if not network_connections:
        network_connections = list(finding.get("tcp_udp", []))
    behavior_types = {str(behavior.get("type", "")) for behavior in behaviors}
    if behavior_types & SANDBOX_CONFIRMED_BEHAVIORS:
        raw_payload: dict[str, object] = {
            "behaviors": behaviors,
            "network_connections": network_connections,
        }
        if finding.get("provider") is not None:
            raw_payload["provider"] = finding.get("provider")
        if finding.get("task_id") is not None:
            raw_payload["task_id"] = finding.get("task_id")
        _append(
            records,
            source="sandbox",
            kind="sandbox_confirmed_malicious_behavior",
            tier="confirmed",
            severity="critical",
            confidence=1.0,
            points=95,
            cap_group="dynamic",
            artifact_id=artifact_id,
            reason="Sandbox confirmed malicious behavior",
            raw=raw_payload,
        )


def build_direct_evidence(
    *, artifact_id: str | None, stage_findings: dict[str, Any]
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []

    clamav = stage_findings.get("clamav")
    if isinstance(clamav, dict):
        _append_clamav(records, artifact_id, clamav)

    yara = stage_findings.get("yara")
    if isinstance(yara, dict):
        _append_yara(records, artifact_id, yara)

    ioc = stage_findings.get("ioc-extract")
    if isinstance(ioc, dict):
        _append_iocs(records, artifact_id, ioc)

    format_analysis = stage_findings.get("format-analysis")
    if isinstance(format_analysis, dict):
        _append_heuristic_records(
            records,
            artifact_id,
            "format-analysis",
            _dict_list(format_analysis.get("heuristics")),
            analyzer=str(format_analysis.get("analyzer") or "") or None,
        )
        _append_format_analysis(records, artifact_id, format_analysis)

    archive_extract = stage_findings.get("archive-extract")
    if isinstance(archive_extract, dict):
        _append_heuristic_records(
            records,
            artifact_id,
            "archive-extract",
            _dict_list(archive_extract.get("heuristics")),
        )

    deobfuscation = stage_findings.get("deobfuscation")
    if isinstance(deobfuscation, dict):
        _append_deobfuscation(records, artifact_id, deobfuscation)

    sandbox = stage_findings.get("sandbox")
    if isinstance(sandbox, dict):
        _append_sandbox(records, artifact_id, sandbox)

    return records
