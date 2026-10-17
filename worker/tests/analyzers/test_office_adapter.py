"""Tests for OfficeAnalyzerAdapter behavior."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from malscan_worker.analyzers.office_adapter import OfficeAnalyzerAdapter
from malscan_worker.stages.base import StageContext, StageResult


def _ctx(file_path: Path) -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="0" * 64,
        original_filename=file_path.name,
        file_path=file_path,
    )


def _stage_result(status: str, findings: dict[str, Any]) -> StageResult:
    now = datetime.now(timezone.utc)
    return StageResult(
        stage_name="document-analysis",
        status=status,
        started_at=now,
        ended_at=now,
        duration_ms=0,
        findings=findings,
        artifacts=[],
    )


@pytest.mark.parametrize(
    ("data", "mime"),
    [
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest", "application/octet-stream"),
        (
            b"PK\x03\x04fake-office",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (b"{\\rtf1\\ansi", "application/octet-stream"),
        (b"not-a-doc", "application/msword"),
    ],
)
def test_can_handle_supported_office_variants(tmp_path: Path, data: bytes, mime: str) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(data)

    analyzer = OfficeAnalyzerAdapter()

    assert analyzer.can_handle(file_path, mime, data[:32]) is True


@pytest.mark.parametrize(
    ("data", "mime"),
    [
        (b"just-text", "text/plain"),
        (b"PK\x03\x04plain-zip", "application/zip"),
    ],
)
def test_can_handle_rejects_non_office_and_plain_zip(
    tmp_path: Path,
    data: bytes,
    mime: str,
) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(data)

    analyzer = OfficeAnalyzerAdapter()

    assert analyzer.can_handle(file_path, mime, data[:32]) is False


@pytest.mark.parametrize("suffix", [".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"])
def test_can_handle_office_extension_when_libmagic_returns_zip(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / ("claimed-office" + suffix)
    path.write_bytes(b"PK\x03\x04broken-package")
    # A claimed Office package still needs the analyzer to report parse errors.
    assert OfficeAnalyzerAdapter().can_handle(path, "application/zip", b"PK\x03\x04")


@pytest.mark.asyncio
async def test_analyze_rtf_returns_structured_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.rtf"
    file_path.write_bytes(b"{\\rtf1\\ansi}")

    findings = {
        "document_type": "rtf",
        "parser_findings": [{"type": "rtf_control", "value": "\\objdata"}],
        "exploit_indicators": [
            {"type": "external_template", "detail": "template injection"},
        ],
        "embedded_objects": [{"index": 0, "size": 123}],
        "extracted_artifacts": [
            {
                "filename": "blob.bin",
                "sha256": "a" * 64,
                "size": 10,
                "path": "/tmp/blob.bin",
                "source": "rtf_object_0",
            }
        ],
        "suspicious_keywords": ["IEX", "Powershell"],
        "macros": {
            "found": False,
            "auto_exec": False,
            "suspicious": False,
            "sources": [],
        },
        "errors": ["minor parser warning"],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "office"
    assert result.format_type == "RTF"
    assert result.features["document_type"] == "rtf"
    assert result.features["embedded_objects"] == findings["embedded_objects"]
    assert result.features["parser_findings"] == findings["parser_findings"]
    assert result.extracted_strings == ["IEX", "Powershell"]
    assert result.extracted_artifacts == findings["extracted_artifacts"]
    assert result.errors == ["minor parser warning"]
    assert result.indicators[0]["severity"] == "high"
    assert result.risk_score == 15


@pytest.mark.asyncio
async def test_analyze_non_document_returns_low_risk_emptyish_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "not-doc.bin"
    file_path.write_bytes(b"not-a-doc")

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("skipped", {"reason": "Not a supported document format"})

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "office"
    assert result.risk_score == 0
    assert result.indicators == []
    assert result.extracted_strings == []
    assert result.extracted_artifacts == []
    assert result.features["document_type"] is None


@pytest.mark.asyncio
async def test_indicator_severity_mapping_and_risk_score(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.doc"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ole",
        "parser_findings": [],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {
            "found": True,
            "auto_exec": True,
            "suspicious": True,
            "sources": [{"module": "Module1"}],
        },
        "errors": [],
        "exploit_indicators": [
            {"type": "equation_editor_clsid_binary", "detail": "eq"},
            {"type": "external_template", "detail": "ext"},
            {"type": "external_relationship", "detail": "ext-rel"},
            {"type": "dde_field", "detail": "dde"},
            {"type": "dangerous_ole_class", "detail": "class"},
            {"type": "oleid_risk", "detail": "foo (risk: high)"},
            {"type": "oleid_risk", "detail": "bar (risk: medium)"},
            {"type": "unknown_indicator", "detail": "default-medium"},
        ],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    severities = {str(ind["type"]): str(ind["severity"]) for ind in result.indicators}
    assert severities["equation_editor_clsid_binary"] == "critical"
    assert severities["external_template"] == "high"
    assert severities["external_relationship"] == "high"
    assert severities["dde_field"] == "high"
    assert severities["dangerous_ole_class"] == "high"

    oleid_severities = [
        str(ind["severity"]) for ind in result.indicators if str(ind["type"]) == "oleid_risk"
    ]
    assert sorted(oleid_severities) == ["high", "medium"]

    assert severities["unknown_indicator"] == "medium"
    assert result.risk_score == 100


@pytest.mark.asyncio
async def test_analyze_adds_macro_and_embedded_object_indicators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.doc"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ole",
        "parser_findings": [],
        "embedded_objects": [{"index": 0, "is_pe": True, "size": 321}],
        "extracted_artifacts": [],
        "suspicious_keywords": ["Shell", "CreateObject", "WScript.Shell"],
        "macros": {
            "found": True,
            "auto_exec": True,
            "suspicious": True,
            "sources": [{"module": "Module1", "auto_exec": True}],
        },
        "errors": [],
        "exploit_indicators": [],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "macro_auto_exec" in indicator_types
    assert "embedded_executable" in indicator_types
    assert result.risk_score == 16
    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "office.macro_autoexec_launcher" in heuristic_map
    assert heuristic_map["office.macro_autoexec_launcher"].evidence["suspicious_keywords"] == (
        "Shell",
        "CreateObject",
        "WScript.Shell",
    )


@pytest.mark.asyncio
async def test_macro_autoexec_launcher_heuristic_matches_suspicious_macro_without_keywords(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "macro-suspicious.doc"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ole",
        "parser_findings": [],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {
            "found": True,
            "auto_exec": True,
            "suspicious": True,
            "sources": [{"module": "Module1", "auto_exec": True}],
        },
        "errors": [],
        "exploit_indicators": [],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "office.macro_autoexec_launcher" in heuristic_map
    assert heuristic_map["office.macro_autoexec_launcher"].evidence["suspicious_keywords"] == ()


@pytest.mark.asyncio
async def test_analyze_adds_external_template_execution_heuristic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "template.docx"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ooxml",
        "parser_findings": [],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
        "errors": [],
        "exploit_indicators": [
            {"type": "external_template", "detail": "remote template"},
            {"type": "external_relationship", "detail": "remote relationship"},
        ],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "office.external_template_execution" in heuristic_map
    assert heuristic_map["office.external_template_execution"].scope == "office"


@pytest.mark.asyncio
async def test_external_relationship_alone_does_not_emit_external_template_execution_heuristic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "relationship-only.docx"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ooxml",
        "parser_findings": [],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
        "errors": [],
        "exploit_indicators": [
            {"type": "external_relationship", "detail": "generic remote relationship"},
        ],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    heuristic_keys = {heuristic.key for heuristic in result.heuristics}
    assert "office.external_template_execution" not in heuristic_keys


@pytest.mark.asyncio
async def test_attached_template_parser_finding_enables_external_template_execution_heuristic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "attached-template.docx"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ooxml",
        "parser_findings": [
            {"type": "attachedTemplate", "value": "https://example.test/template.dotm"},
            {
                "type": "ooxml_rel_type",
                "value": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
            },
        ],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
        "errors": [],
        "exploit_indicators": [
            {"type": "external_relationship", "detail": "attached template relationship"},
        ],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "office.external_template_execution" in heuristic_map


@pytest.mark.asyncio
async def test_analyze_adds_low_severity_indicator_for_benign_macros(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.doc"
    file_path.write_bytes(b"stub")

    findings = {
        "document_type": "ole",
        "parser_findings": [],
        "embedded_objects": [],
        "extracted_artifacts": [],
        "suspicious_keywords": [],
        "macros": {
            "found": True,
            "auto_exec": False,
            "suspicious": False,
            "sources": [{"module": "Module1", "auto_exec": False}],
        },
        "errors": [],
        "exploit_indicators": [],
    }

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        del self, ctx
        return _stage_result("ok", findings)

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    result = await adapter.analyze(file_path, _ctx(file_path))

    assert result.indicators == [
        {
            "type": "macro_presence",
            "severity": "low",
            "detail": "Office document contains macros",
            "evidence": {"macros": findings["macros"]},
        }
    ]
    assert result.risk_score == 3


@pytest.mark.asyncio
async def test_analyze_uses_passed_file_path_over_ctx_file_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provided_file = tmp_path / "provided.doc"
    ctx_file = tmp_path / "ctx.doc"
    provided_file.write_bytes(b"doc")
    ctx_file.write_bytes(b"doc")

    seen_file_path: Path | None = None

    async def _fake_execute(self: object, ctx: StageContext) -> StageResult:
        nonlocal seen_file_path
        del self
        seen_file_path = ctx.file_path
        return _stage_result("ok", {"document_type": "ole"})

    monkeypatch.setattr(
        "malscan_worker.analyzers.office_adapter.DocumentAnalysisStage.execute",
        _fake_execute,
    )

    adapter = OfficeAnalyzerAdapter()
    ctx = _ctx(ctx_file)
    await adapter.analyze(provided_file, ctx)

    assert seen_file_path == provided_file
