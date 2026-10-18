"""Real document parser controls built from small deterministic inert structures."""

from __future__ import annotations

import hashlib
import io
import uuid
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
from malscan_worker.exceptions import DocumentPasswordRequiredError
from malscan_worker.quality.document_fixtures import (
    DOCUMENT_PROFILES,
    PDF_TEST_PASSWORD,
    build_document_fixture,
)
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from pypdf import PdfReader

_SHA256 = {
    "office-normal": "110c70e2b485144ee5941197e4773a64c45c2400754c1da8d2e798a7988f3e03",
    "office-external-references": (
        "8d9af4f5f324360f2bb68c72bdddc950c7080fa1a8334d184add45c5d28f09da"
    ),
    "office-macro-flag": "d8960cec626502168aeda9d36cb02f943d070bc1f0900c6c94ad9e2dd70539fb",
    "office-malformed": "2a60a859dcd50c3577afd9897dc749f98b3a3a81e16e9cf7a41436a8a7602a95",
    "office-metadata-limit": "e6e802ce2577194761f1d13aa3780d0548f839cd609b8180975a8ac68b2ba78a",
    "pdf-normal": "d93949d0eff53eb91a3cd28d5d52f3efbb0caca2e876f9c56c1a934a3be46f1b",
    "pdf-active-actions": "a4e757baf0605cdd63fe30fa27c00869e03a2797ba1380f44650c5b600accff2",
    "pdf-malformed": "9cd7cf199d804501d42bdac4121fab7239452011cc3d994be69cf5078218cad1",
    "pdf-encrypted": "fa0bf7e45e78acd212e7d3269468474e47cbea1f52546894de7d4a744f203d1b",
}


def _context(tmp_path: Path, profile: str) -> StageContext:
    suffix = ".docm" if profile == "office-macro-flag" else ".docx"
    if profile.startswith("pdf-"):
        suffix = ".pdf"
    path = tmp_path / (profile + suffix)
    payload = build_document_fixture(profile)
    path.write_bytes(payload)
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id="fixture",
        storage_key="quality-fixture",
        sha256=hashlib.sha256(payload).hexdigest(),
        original_filename=path.name,
        file_path=path,
        skip_artifact_submission=True,
    )


@pytest.mark.parametrize("profile", DOCUMENT_PROFILES)
def test_document_fixture_bytes_are_small_and_pinned(profile: str) -> None:
    first = build_document_fixture(profile)
    assert first == build_document_fixture(profile)
    assert len(first) < 1_000_000
    assert hashlib.sha256(first).hexdigest() == _SHA256[profile]


def test_document_fixture_recipes_reject_unknown_profiles_and_versions() -> None:
    with pytest.raises(ValueError, match="profile"):
        build_document_fixture("not-a-document")
    with pytest.raises(ValueError, match="version"):
        build_document_fixture("pdf-normal", recipe_version=2)


def test_benign_office_is_a_complete_ooxml_package() -> None:
    with zipfile.ZipFile(io.BytesIO(build_document_fixture("office-normal"))) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        assert names == {
            "[Content_Types].xml",
            "_rels/.rels",
            "word/document.xml",
            "word/_rels/document.xml.rels",
        }
        for name in names:
            ElementTree.fromstring(archive.read(name))
        document = ElementTree.fromstring(archive.read("word/document.xml"))
        assert "Inert quality fixture document." in "".join(document.itertext())
        assert sum(item.file_size for item in archive.infolist()) == 1018


@pytest.mark.asyncio
async def test_benign_office_has_no_structural_risk_signals(tmp_path: Path) -> None:
    ctx = _context(tmp_path, "office-normal")
    ctx.previous_results = [await FileTypeStage().execute(ctx)]
    result = await FormatAnalysisStage().execute(ctx)
    assert result.status == "ok"
    assert result.findings["analyzer"] == "office"
    assert result.findings["errors"] == []
    assert result.findings["risk_factors"] == []
    assert result.findings["features"]["macros"]["found"] is False
    assert result.findings["extracted_artifacts_count"] == 0


@pytest.mark.asyncio
async def test_office_external_references_retain_both_actual_targets(tmp_path: Path) -> None:
    ctx = _context(tmp_path, "office-external-references")
    ctx.previous_results = [await FileTypeStage().execute(ctx)]
    result = await FormatAnalysisStage().execute(ctx)
    assert result.status == "ok"
    indicators = result.findings["indicators"]
    external = [item for item in indicators if item["type"] == "external_relationship"]
    assert len(external) == 2
    assert {item["detail"] for item in external} == {
        "OOXML external target: https://quality.invalid/inert-template.dotx",
        "OOXML external target: https://quality.invalid/inert-reference.txt",
    }
    assert result.findings["features"]["macros"]["found"] is False
    assert result.findings["extracted_artifacts_count"] == 0


@pytest.mark.parametrize(
    "attributes",
    [
        'Target="https://quality.invalid/a.dotx" TargetMode="External"',
        'TargetMode="External" Target="https://quality.invalid/a.dotx"',
        "TargetMode='External' Target='https://quality.invalid/a.dotx'",
    ],
)
def test_office_relationship_detection_uses_xml_attribute_semantics(attributes: str) -> None:
    findings: dict[str, Any] = {"errors": [], "exploit_indicators": [], "parser_findings": []}
    targets: list[dict[str, str]] = []
    DocumentAnalysisStage()._scan_rels_xml(
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" {attributes}/></Relationships>',
        targets,
        findings,
    )
    assert targets == [{"target": "https://quality.invalid/a.dotx", "mode": "External"}]
    assert len(findings["exploit_indicators"]) == 1
    assert findings["errors"] == []


def test_office_relationship_comments_and_internal_links_are_not_external() -> None:
    findings: dict[str, Any] = {"errors": [], "exploit_indicators": [], "parser_findings": []}
    targets: list[dict[str, str]] = []
    DocumentAnalysisStage()._scan_rels_xml(
        "<Relationships>"
        '<!-- <Relationship Target="https://quality.invalid/comment.dotx" '
        'TargetMode="External"/> -->'
        '<Relationship Target="word/styles.xml" TargetMode="Internal"/>'
        '<NotRelationship Target="https://quality.invalid/other.dotx" TargetMode="External"/>'
        "</Relationships>",
        targets,
        findings,
    )
    assert targets == []
    assert findings["exploit_indicators"] == []
    assert findings["errors"] == []


def test_office_invalid_relationship_xml_keeps_a_parser_diagnostic() -> None:
    findings: dict[str, Any] = {"errors": [], "exploit_indicators": [], "parser_findings": []}
    DocumentAnalysisStage()._scan_rels_xml("<Relationships><", [], findings)
    assert findings["errors"][0].startswith("Relationship XML parse error:")
    assert findings["exploit_indicators"] == []


@pytest.mark.asyncio
async def test_office_macro_part_only_proves_structural_presence(tmp_path: Path) -> None:
    ctx = _context(tmp_path, "office-macro-flag")
    ctx.previous_results = [await FileTypeStage().execute(ctx)]
    result = await FormatAnalysisStage().execute(ctx)
    macros = result.findings["features"]["macros"]
    assert macros["found"] is True
    assert macros["project_present"] is True
    assert macros["source_status"] == "unavailable"
    assert macros["auto_exec"] is False
    assert macros["sources"] == []
    assert result.findings["risk_factors"] == ["macro_presence"]
    assert result.status == "partial"
    assert any("VBA" in item for item in result.findings["errors"])


@pytest.mark.asyncio
async def test_malformed_office_is_partial_with_parse_diagnostics(tmp_path: Path) -> None:
    ctx = _context(tmp_path, "office-malformed")
    ctx.previous_results = [await FileTypeStage().execute(ctx)]
    result = await FormatAnalysisStage().execute(ctx)
    assert result.status == "partial"
    assert result.findings["analyzer"] == "office"
    assert "OOXML file failed ZIP validation" in result.findings["errors"]
    assert result.findings["risk_factors"] == []


@pytest.mark.asyncio
async def test_office_metadata_limit_is_partial_in_both_document_paths(tmp_path: Path) -> None:
    ctx = _context(tmp_path, "office-metadata-limit")
    ctx.previous_results = [await FileTypeStage().execute(ctx)]
    document = await DocumentAnalysisStage().execute(ctx)
    result = await FormatAnalysisStage().execute(ctx)
    assert document.status == result.status == "partial"
    assert document.findings["resource_limited"] is True
    assert document.findings["limit_reason"] == "document_metadata_bytes_limit"
    assert result.findings["features"]["limit_reason"] == "document_metadata_bytes_limit"
    assert result.findings["features"]["resource_limited"] is True
    assert any("exceeds parse limit" in item for item in result.findings["errors"])


@pytest.mark.asyncio
async def test_real_benign_pdf_has_one_page_and_no_active_content(tmp_path: Path) -> None:
    result = await FormatAnalysisStage().execute(_context(tmp_path, "pdf-normal"))
    assert result.status == "ok"
    assert result.findings["analyzer"] == "pdf"
    assert result.findings["features"]["page_count"] == 1
    assert result.findings["features"]["encrypted"] is False
    assert result.findings["risk_factors"] == []
    assert result.findings["errors"] == []


@pytest.mark.asyncio
async def test_pdf_active_actions_are_detected_from_real_object_graph(tmp_path: Path) -> None:
    result = await FormatAnalysisStage().execute(_context(tmp_path, "pdf-active-actions"))
    assert result.status == "ok"
    features = result.findings["features"]
    assert features["page_count"] == 1
    assert features["js_code"] == ["void 0;"]
    assert features["launch_actions"] == ["quality-fixture-never-execute.txt"]
    assert set(features["open_actions"]) == {"/JavaScript", "/Launch"}
    assert set(result.findings["risk_factors"]) == {
        "launch_action",
        "embedded_javascript",
        "auto_open_action",
    }
    assert result.findings["errors"] == []


@pytest.mark.asyncio
async def test_malformed_pdf_cannot_claim_complete_content_analysis(tmp_path: Path) -> None:
    result = await FormatAnalysisStage().execute(_context(tmp_path, "pdf-malformed"))
    assert result.status == "partial"
    assert result.findings["errors"][0].startswith("failed to parse PDF file:")
    assert result.findings["features"]["page_count"] == 0


def test_encrypted_pdf_has_real_deterministic_password_protection() -> None:
    reader = PdfReader(io.BytesIO(build_document_fixture("pdf-encrypted")))
    assert reader.is_encrypted is True
    assert reader.decrypt("incorrect-password") == 0
    with pytest.raises(Exception, match="decrypted"):
        list(reader.pages)
    assert reader.decrypt(PDF_TEST_PASSWORD) != 0
    assert len(reader.pages) == 1


@pytest.mark.asyncio
async def test_locked_pdf_requests_a_password_without_modifying_the_original(
    tmp_path: Path,
) -> None:
    ctx = _context(tmp_path, "pdf-encrypted")
    assert ctx.file_path is not None
    original = ctx.file_path.read_bytes()
    with pytest.raises(DocumentPasswordRequiredError, match="^pdf$"):
        await FormatAnalysisStage().execute(ctx)
    assert ctx.file_path.read_bytes() == original
