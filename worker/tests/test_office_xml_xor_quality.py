"""Exercise XOR scoring on actual OOXML members and a nonzero-key control."""

import hashlib
import io
from pathlib import Path
from zipfile import ZipFile

import pytest
from malscan_worker.pipeline import build_analysis_result
from malscan_worker.quality.document_embedded_fixtures import build_document_embedded_fixture
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.deobfuscation import DeobfuscationStage
from malscan_worker.stages.ioc_extract import IocExtractStage


def _stage_context(tmp_path: Path, filename: str, content: bytes) -> StageContext:
    path = tmp_path / Path(filename).name
    path.write_bytes(content)
    return StageContext(
        job_id="xor-quality-job",
        file_id="xor-quality-file",
        storage_key="xor-quality-file",
        sha256=hashlib.sha256(content).hexdigest(),
        original_filename=filename,
        file_path=path,
        artifact_id="xor-quality-artifact",
        skip_artifact_submission=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("member", "namespace"),
    [
        ("[Content_Types].xml", "http://schemas.openxmlformats.org/package/2006/content-types"),
        ("_rels/.rels", "http://schemas.openxmlformats.org/package/2006/relationships"),
        (
            "word/_rels/document.xml.rels",
            "http://schemas.openxmlformats.org/package/2006/relationships",
        ),
    ],
)
async def test_ooxml_metadata_namespace_is_raw_ioc_without_xor_score(
    tmp_path: Path, member: str, namespace: str
) -> None:
    fixture = build_document_embedded_fixture("office-embedded-pdf")
    with ZipFile(io.BytesIO(fixture)) as archive:
        content = archive.read(member)

    ctx = _stage_context(tmp_path, member, content)
    deob = await DeobfuscationStage().execute(ctx)
    ioc = await IocExtractStage().execute(ctx)
    assert deob.status == ioc.status == "ok"
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [deob, ioc], 0)

    assert report["score"] == 0
    assert "xor" not in report["results"]["deobfuscation"]["observed_techniques"]
    assert not any(
        record["kind"] == "deobfuscation_technique_found" and record["raw"]["technique"] == "xor"
        for record in report["risk"]["evidence"]
    )
    assert namespace in report["results"]["iocs"]["urls"]
    assert any(
        item["value"] == namespace
        and item["source_kind"] == "raw_regex"
        and item["offset"] == content.index(namespace.encode())
        for item in report["results"]["iocs"]["ioc_items"]
    )


@pytest.mark.asyncio
async def test_nonzero_xor_url_contributes_evidence_even_with_xml_filename(tmp_path: Path) -> None:
    plaintext = b"https://quality.invalid/inert"
    key = 0x23
    encoded = bytes(byte ^ key for byte in plaintext)
    ctx = _stage_context(tmp_path, "encoded.xml", encoded)
    deob = await DeobfuscationStage().execute(ctx)
    ioc = await IocExtractStage().execute(ctx)
    assert deob.status == ioc.status == "ok"
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [deob, ioc], 0)

    evidence = [
        record
        for record in report["risk"]["evidence"]
        if record["kind"] == "deobfuscation_technique_found" and record["raw"]["technique"] == "xor"
    ]
    assert [record["points"] for record in evidence] == [4]
    candidate = next(
        candidate
        for candidate in report["results"]["deobfuscation"]["candidates"]
        if candidate["technique"] == "xor" and candidate["content"] == plaintext.decode()
    )
    assert candidate["provenance"]["key"] == f"0x{key:02x}"
    assert candidate["score_eligible"] is True
    assert plaintext.decode() not in ioc.findings["urls"]
    assert plaintext.decode() in report["results"]["iocs"]["urls"]
