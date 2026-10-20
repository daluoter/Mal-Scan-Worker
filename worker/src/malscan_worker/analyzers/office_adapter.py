"""Office document analyzer adapter over DocumentAnalysisStage."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from malscan_worker.analyzers.base import AnalyzerIndicator, AnalyzerResult, FormatAnalyzer
from malscan_worker.analyzers.office_decryption import analyze_encrypted_office
from malscan_worker.heuristics.models import HeuristicHit, make_hit
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.document_analysis import DocumentAnalysisStage, detect_document_type

_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


class OfficeAnalyzerAdapter(FormatAnalyzer):
    """Bridge DocumentAnalysisStage output into AnalyzerResult."""

    @property
    def name(self) -> str:
        return "office"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        del magic
        doc_type = detect_document_type(file_path, mime)
        if doc_type is None:
            return False
        # libmagic can report a valid OOXML package as application/zip. The
        # document detector already requires an Office extension or package parts;
        # a generic ZIP alone does not satisfy that identification.
        return True

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        encrypted_result = await analyze_encrypted_office(file_path, ctx)
        if encrypted_result is not None:
            return encrypted_result
        stage_ctx = replace(ctx, file_path=file_path, skip_artifact_submission=True)
        stage_result = await DocumentAnalysisStage().execute(stage_ctx)
        findings = stage_result.findings

        raw_indicators = findings.get("exploit_indicators", [])
        indicators = self._convert_indicators(raw_indicators)
        indicators.extend(self._macro_indicators(findings))
        indicators.extend(self._embedded_object_indicators(findings))

        document_type = findings.get("document_type")
        if isinstance(document_type, str):
            format_type = document_type.upper()
        else:
            format_type = "OFFICE"

        errors = findings.get("errors", [])
        if not isinstance(errors, list):
            errors = []
        if stage_result.error:
            errors = [*errors, stage_result.error]
        if findings.get("resource_limited"):
            errors = [*errors, str(findings.get("limit_reason", "document_resource_limit"))]
        errors = self._unique_strings(errors)

        extracted_artifacts = findings.get("extracted_artifacts", [])
        if not isinstance(extracted_artifacts, list):
            extracted_artifacts = []

        suspicious_keywords = findings.get("suspicious_keywords", [])
        if not isinstance(suspicious_keywords, list):
            suspicious_keywords = []

        parser_findings = findings.get("parser_findings", [])
        if not isinstance(parser_findings, list):
            parser_findings = []

        embedded_objects = findings.get("embedded_objects", [])
        if not isinstance(embedded_objects, list):
            embedded_objects = []

        features = {
            "document_type": document_type if isinstance(document_type, str) else None,
            "macros": findings.get("macros", {}),
            "embedded_objects": embedded_objects,
            "embedded_extraction": findings.get("embedded_extraction", {}),
            "parser_findings": parser_findings,
            "resource_limited": bool(findings.get("resource_limited")),
            "limit_reason": findings.get("limit_reason"),
        }
        heuristics = self._build_heuristics(findings, indicators)

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type=format_type,
            indicators=indicators,
            features=features,
            extracted_strings=[str(item) for item in suspicious_keywords],
            risk_score=self._calculate_risk_score(indicators),
            risk_factors=[
                factor
                for factor in (str(indicator.get("type", "")) for indicator in indicators)
                if factor
            ],
            heuristics=heuristics,
            errors=errors,
            extracted_artifacts=extracted_artifacts,
        )

    @staticmethod
    def _unique_strings(values: list[object]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for value in values:
            item = str(value)
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _convert_indicators(self, raw_indicators: object) -> list[AnalyzerIndicator]:
        if not isinstance(raw_indicators, list):
            return []

        indicators: list[AnalyzerIndicator] = []
        for item in raw_indicators:
            if not isinstance(item, dict):
                continue

            indicator_type = str(item.get("type", ""))
            detail = item.get("detail")
            severity = self._map_severity(indicator_type, item)
            converted: AnalyzerIndicator = {
                "type": indicator_type,
                "severity": severity,
            }
            if isinstance(detail, str):
                converted["detail"] = detail
            converted["evidence"] = item
            indicators.append(converted)

        return indicators

    def _macro_indicators(self, findings: dict[str, Any]) -> list[AnalyzerIndicator]:
        macros = findings.get("macros")
        if not isinstance(macros, dict) or not macros.get("found"):
            return []

        suspicious_keywords = findings.get("suspicious_keywords")
        if not isinstance(suspicious_keywords, list):
            suspicious_keywords = []

        indicators: list[AnalyzerIndicator] = []
        if macros.get("auto_exec") and (macros.get("suspicious") or suspicious_keywords):
            indicators.append(
                {
                    "type": "macro_auto_exec",
                    "severity": "medium",
                    "detail": "Office document contains auto-exec macros with suspicious APIs",
                    "evidence": {
                        "macros": macros,
                        "suspicious_keywords": suspicious_keywords[:10],
                    },
                }
            )
            return indicators

        if macros.get("auto_exec"):
            indicators.append(
                {
                    "type": "macro_auto_exec",
                    "severity": "medium",
                    "detail": "Office document contains auto-exec macros",
                    "evidence": {"macros": macros},
                }
            )
            return indicators

        if macros.get("suspicious") or suspicious_keywords:
            indicators.append(
                {
                    "type": "suspicious_launcher",
                    "severity": "medium",
                    "detail": "Office document macros use suspicious execution keywords",
                    "evidence": {
                        "macros": macros,
                        "suspicious_keywords": suspicious_keywords[:10],
                    },
                }
            )
            return indicators

        indicators.append(
            {
                "type": "macro_presence",
                "severity": "low",
                "detail": "Office document contains macros",
                "evidence": {"macros": macros},
            }
        )
        return indicators

    def _embedded_object_indicators(self, findings: dict[str, Any]) -> list[AnalyzerIndicator]:
        embedded_objects = findings.get("embedded_objects")
        if not isinstance(embedded_objects, list) or not embedded_objects:
            return []

        for obj in embedded_objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("is_pe"):
                return [
                    {
                        "type": "embedded_executable",
                        "severity": "medium",
                        "detail": "Office document embeds an executable object",
                        "evidence": {"embedded_object": obj},
                    }
                ]

        return []

    def _build_heuristics(
        self,
        findings: dict[str, Any],
        indicators: list[AnalyzerIndicator],
    ) -> list[HeuristicHit]:
        heuristics: list[HeuristicHit] = []

        macros = findings.get("macros")
        suspicious_keywords = findings.get("suspicious_keywords")
        if not isinstance(suspicious_keywords, list):
            suspicious_keywords = []
        if (
            isinstance(macros, dict)
            and macros.get("auto_exec")
            and (macros.get("suspicious") or suspicious_keywords)
        ):
            heuristics.append(
                make_hit(
                    key="office.macro_autoexec_launcher",
                    category="behavior",
                    scope="office",
                    role="detection",
                    severity="high",
                    confidence=0.84,
                    summary=(
                        "Office macros combine auto-exec behavior with suspicious launcher "
                        "keywords"
                    ),
                    evidence={
                        "macros": macros,
                        "suspicious_keywords": suspicious_keywords[:10],
                    },
                    tags=("office", "macro", "autoexec"),
                )
            )

        parser_findings = findings.get("parser_findings")
        if not isinstance(parser_findings, list):
            parser_findings = []

        external_types = sorted(
            {
                str(indicator.get("type", ""))
                for indicator in indicators
                if str(indicator.get("type", "")) == "external_template"
            }
        )
        if not external_types and self._has_attached_template_relationship(
            indicators, parser_findings
        ):
            external_types = ["external_relationship"]
        if external_types:
            heuristics.append(
                make_hit(
                    key="office.external_template_execution",
                    category="behavior",
                    scope="office",
                    role="detection",
                    severity="high",
                    confidence=0.83,
                    summary=(
                        "Office document references external template relationships for "
                        "execution"
                    ),
                    evidence={"indicator_types": external_types},
                    tags=("office", "external-template", "relationship"),
                )
            )

        return heuristics

    @staticmethod
    def _has_attached_template_relationship(
        indicators: list[AnalyzerIndicator],
        parser_findings: list[object],
    ) -> bool:
        has_external_relationship = any(
            str(indicator.get("type", "")) == "external_relationship" for indicator in indicators
        )
        if not has_external_relationship:
            return False

        for finding in parser_findings:
            if not isinstance(finding, dict):
                continue
            finding_type = str(finding.get("type", "")).lower()
            finding_value = str(finding.get("value", "")).lower()
            if finding_type == "attachedtemplate":
                return True
            if finding_type == "ooxml_rel_type" and "attachedtemplate" in finding_value:
                return True
        return False

    def _map_severity(self, indicator_type: str, item: dict[str, Any]) -> str:
        indicator_type_l = indicator_type.lower()

        if indicator_type_l.startswith("equation_editor_"):
            return "critical"

        if indicator_type_l in {"external_template", "external_relationship", "dde_field"}:
            return "high"

        if indicator_type_l == "dangerous_ole_class":
            return "high"

        if indicator_type_l == "oleid_risk":
            risk_value = self._extract_oleid_risk(item)
            if risk_value == "high":
                return "high"
            if risk_value == "medium":
                return "medium"

        return "medium"

    @staticmethod
    def _extract_oleid_risk(item: dict[str, Any]) -> str:
        risk = item.get("risk")
        if isinstance(risk, str):
            risk_l = risk.lower()
            if risk_l in {"high", "medium"}:
                return risk_l

        detail = item.get("detail")
        if isinstance(detail, str):
            detail_l = detail.lower()
            if "risk: high" in detail_l:
                return "high"
            if "risk: medium" in detail_l:
                return "medium"

        return ""

    def _calculate_risk_score(self, indicators: list[AnalyzerIndicator]) -> int:
        score = 0
        for indicator in indicators:
            severity = str(indicator.get("severity", ""))
            score += _SEVERITY_WEIGHTS.get(severity, 0)
        return min(score, 100)
