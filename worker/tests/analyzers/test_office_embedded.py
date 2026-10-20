"""Byte restoration, provenance and hostile metadata controls for F-03 Office."""
from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest
from malscan_worker.analyzers.office_embedded import (
    _native_payload,
    embedded_filename,
    extract_ole_payloads,
    ooxml_embedding_candidates,
)
from malscan_worker.budget import BudgetExceeded
from malscan_worker.quality.document_embedded_fixtures import (
    _cfb_stream,
    build_document_embedded_fixture,
    embedded_fixture_payloads,
)
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.document_analysis import DocumentAnalysisStage


def _native(payload=b"safe bytes", name=b"note.txt"):
    rest = struct.pack("<H", 2) + name + b"\0source\0" + b"\0" * 8
    rest += b"temporary\0" + struct.pack("<I", len(payload)) + payload
    return struct.pack("<I", len(rest)) + rest


def _zip(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return zipfile.ZipFile(io.BytesIO(output.getvalue()))


def _relationship(target, mode="Internal", kind="package"):
    return (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="x" Type="https://schemas.invalid/{kind}" Target="{target}" '
        f'TargetMode="{mode}"/></Relationships>'
    ).encode()


@pytest.mark.parametrize(
    "profile,source", [("ole-native-text", "ole-native/0"), ("ole-package-pdf", "ole-package/0")]
)
def test_real_cfb_stream_restoration(profile, source, tmp_path):
    path = tmp_path / "wrapper.bin"
    path.write_bytes(build_document_embedded_fixture(profile))
    emitted = []
    reserved = []
    coverage = extract_ole_payloads(
        path,
        maximum_bytes=1_000_000,
        maximum_objects=30,
        reserve=lambda *args: reserved.append(args),
        emit=lambda *args: emitted.append(args),
    )
    assert coverage["status"] == "complete"
    assert coverage["candidates"] == coverage["extracted"] == 1
    assert coverage["unavailable"] == 0
    assert len(emitted) == 1
    data, name, origin, _ = emitted[0]
    assert data in embedded_fixture_payloads(profile)
    assert origin == source
    assert (source, 1, len(data)) in reserved
    assert Path(name).suffix in {".txt", ".pdf"}
    assert coverage["items"][0]["sha256"]


def test_corrupt_native_does_not_emit_or_echo_metadata(tmp_path):
    path = tmp_path / "wrapper.bin"
    path.write_bytes(build_document_embedded_fixture("ole-native-truncated"))
    emitted = []
    coverage = extract_ole_payloads(
        path,
        maximum_bytes=1_000_000,
        maximum_objects=30,
        reserve=None,
        emit=lambda *args: emitted.append(args),
    )
    assert coverage["status"] == "partial"
    assert coverage["items"][0]["reason"] == "ole_native_size_mismatch"
    assert not emitted


@pytest.mark.parametrize(
    "raw", [_native()[:-1], b"\0" * 5, _native(name=b"a" * 4097), _native() + b"unexpected"]
)
def test_native_truncation_ambiguity_and_metadata_bounds(raw):
    with pytest.raises(ValueError):
        _native_payload(raw, 1000)


def test_native_link_not_followed():
    raw = _native()
    payload_end = raw.index(b"temporary\0") + len(b"temporary\0")
    linked = raw[4:payload_end]
    linked = struct.pack("<I", len(linked)) + linked
    with pytest.raises(ValueError, match="linked_not_embedded"):
        _native_payload(linked, 1000)


def test_native_payload_limit():
    with pytest.raises(BudgetExceeded, match="document_embedded_bytes_limit"):
        _native_payload(_native(b"12345"), 4)


def test_shared_budget_rejection_prevents_emit(tmp_path):
    path = tmp_path / "wrapper.bin"
    path.write_bytes(build_document_embedded_fixture("ole-native-text"))
    emitted = []

    def rejected(*args):
        raise BudgetExceeded("root_expanded_bytes_limit")

    coverage = extract_ole_payloads(
        path,
        maximum_bytes=1000,
        maximum_objects=30,
        reserve=rejected,
        emit=lambda *args: emitted.append(args),
    )
    assert coverage["status"] == "partial"
    assert coverage["items"][0]["reason"] == "root_expanded_bytes_limit"
    assert not emitted


def test_no_object_budget_prevents_emit(tmp_path):
    path = tmp_path / "wrapper.bin"
    path.write_bytes(build_document_embedded_fixture("ole-native-text"))
    emitted = []
    coverage = extract_ole_payloads(
        path,
        maximum_bytes=1000,
        maximum_objects=0,
        reserve=None,
        emit=lambda *args: emitted.append(args),
    )
    assert coverage["status"] == "partial"
    assert coverage["items"][0]["reason"] == "document_embedded_object_count_limit"
    assert not emitted


@pytest.mark.parametrize(
    "profile,target",
    [
        ("office-embedded-pdf", "word/embeddings/attachment.pdf"),
        ("office-relationship-package", "custom/payload.pdf"),
    ],
)
def test_ooxml_non_bin_and_relationship_target(profile, target):
    with zipfile.ZipFile(io.BytesIO(build_document_embedded_fixture(profile))) as archive:
        candidates, coverage = ooxml_embedding_candidates(archive)
    assert coverage["status"] == "complete"
    assert target in [info.filename for info, _ in candidates]


def test_ooxml_repeated_relationship_target_is_one_occurrence():
    rels = _relationship("embeddings/note.pdf")
    rels = rels.replace(
        b"</Relationships>",
        b'<Relationship Id="y" Type="x/package" Target="embeddings/note.pdf"/></Relationships>',
    )
    with _zip(
        [("word/embeddings/note.pdf", b"%PDF-data"), ("word/_rels/document.xml.rels", rels)]
    ) as archive:
        candidates, coverage = ooxml_embedding_candidates(archive)
    assert coverage["candidates"] == 1
    assert len(candidates[0][1]) == 2


@pytest.mark.parametrize(
    "members,reason",
    [
        (
            [("word/embeddings/a.bin", b"a"), ("word/embeddings/A.bin", b"b")],
            "document_zip_member_names_ambiguous",
        ),
        ([("../escape", b"a")], "document_zip_member_path_invalid"),
        (
            [("word/_rels/document.xml.rels", _relationship("../../../escape"))],
            "document_embedded_relationship_invalid",
        ),
        (
            [
                (
                    "word/_rels/document.xml.rels",
                    _relationship("https://example.invalid/x", "External"),
                )
            ],
            "office_embedded_external_not_fetched",
        ),
        (
            [("word/_rels/document.xml.rels", _relationship("missing.pdf"))],
            "office_embedded_target_missing",
        ),
        (
            [("word/_rels/document.xml.rels", b"<!DOCTYPE x [<!ENTITY x 'a'>]><x/>")],
            "document_relationships_invalid",
        ),
    ],
)
def test_ooxml_ambiguous_missing_external_or_unsafe_is_partial(members, reason):
    with _zip(members) as archive:
        _, coverage = ooxml_embedding_candidates(archive)
    assert coverage["status"] == "partial"
    assert reason in coverage["errors"]


def test_ooxml_metadata_limit_precedes_decompression():
    with _zip([("word/_rels/document.xml.rels", b"a" * 1_000_001)]) as archive:
        _, coverage = ooxml_embedding_candidates(archive)
    assert "document_metadata_bytes_limit" in coverage["errors"]


def test_filenames_never_use_native_paths_or_overwrite_by_path():
    assert embedded_filename("../../secret.txt", b"ok", 0) == "secret.txt"
    assert embedded_filename("..\\payload.dat", b"%PDF-1.7", 0) == "payload.pdf"
    assert embedded_filename("\0\r\n", b"ok", 0) == "___.bin"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "profile",
    ["office-embedded-pdf", "office-relationship-package", "ole-native-text", "ole-package-pdf"],
)
async def test_document_stage_emits_real_bytes_and_coverage(profile, tmp_path):
    path = tmp_path / ("input.docx" if profile.startswith("office") else "input.bin")
    path.write_bytes(build_document_embedded_fixture(profile))
    ctx = StageContext(
        job_id="f03-office-" + profile,
        file_id="file",
        storage_key="test",
        sha256="a" * 64,
        original_filename=path.name,
        file_path=path,
    )
    result = await DocumentAnalysisStage().execute(ctx)
    coverage = result.findings["embedded_extraction"]
    assert coverage["status"] == "complete"
    assert coverage["extracted"] == 1
    records = result.findings["extracted_artifacts"]
    assert len(records) == 1
    assert Path(records[0]["path"]).read_bytes() in embedded_fixture_payloads(profile)
    assert records[0]["budget_key"]


@pytest.mark.parametrize(
    "xml",
    [
        b'<NotRelationships><Relationship Type="x/package" '
        b'Target="embedded.pdf"/></NotRelationships>',
        b'<Relationships><Relationship Type="x/package" Target="embedded.pdf"/></Relationships>',
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<x><Relationship Type="x/package" Target="embedded.pdf"/></x></Relationships>',
    ],
)
def test_non_opc_or_nested_relationships_cannot_extract_payload(xml):
    with _zip(
        [("word/_rels/document.xml.rels", xml), ("word/embedded.pdf", b"%PDF-1.7")]
    ) as archive:
        candidates, coverage = ooxml_embedding_candidates(archive)
    assert not candidates
    assert coverage["status"] == "partial"
    assert "document_relationships_invalid" in coverage["errors"]


def test_relationship_tree_depth_is_bounded():
    xml = (
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + b"<x>" * 33
        + b"</x>" * 33
        + b"</Relationships>"
    )
    with _zip([("word/_rels/document.xml.rels", xml)]) as archive:
        _, coverage = ooxml_embedding_candidates(archive)
    assert "document_relationship_count_limit" in coverage["errors"]


def test_zip_member_count_bound_prevents_iteration(monkeypatch):
    import malscan_worker.analyzers.office_embedded as module

    monkeypatch.setattr(module, "MAX_STREAMS", 1)
    with _zip(
        [("word/embeddings/one.pdf", b"one"), ("word/embeddings/two.pdf", b"two")]
    ) as archive:
        candidates, coverage = ooxml_embedding_candidates(archive)
    assert not candidates
    assert "document_zip_member_count_limit" in coverage["errors"]


def _findings():
    return {
        "macros": {},
        "errors": [],
        "extracted_artifacts": [],
        "embedded_objects": [],
        "exploit_indicators": [],
        "parser_findings": [],
    }


def _stage_ctx(path, reserve=None):
    ctx = StageContext(
        job_id="f03-unit",
        file_id="file",
        storage_key="test",
        sha256="a" * 64,
        original_filename=path.name,
        file_path=path,
    )
    ctx.reserve_output = reserve
    return ctx


def test_reservation_rejection_precedes_embedded_zip_open(tmp_path, monkeypatch):
    path = tmp_path / "office.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/embeddings/note.pdf", b"%PDF-1.7")
    opened = []
    original = zipfile.ZipFile.open

    def observed(self, name, *args, **kwargs):
        opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", observed)

    def rejected(*args):
        raise BudgetExceeded("root_expanded_bytes_limit")

    findings = _findings()
    artifacts = []
    DocumentAnalysisStage()._analyse_ooxml(
        _stage_ctx(path, rejected), findings, artifacts, tmp_path
    )
    assert "word/embeddings/note.pdf" not in opened
    assert not artifacts
    assert findings["embedded_extraction"]["status"] == "partial"


def test_duplicate_basenames_have_distinct_disk_paths_and_origins(tmp_path):
    path = tmp_path / "office.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/embeddings/first/note.pdf", b"%PDF-first")
        archive.writestr("word/embeddings/second/note.pdf", b"%PDF-second")
    findings = _findings()
    artifacts = []
    DocumentAnalysisStage()._analyse_ooxml(_stage_ctx(path), findings, artifacts, tmp_path)
    assert len(artifacts) == 2
    assert artifacts[0]["filename"] == artifacts[1]["filename"] == "note.pdf"
    assert len({artifact["path"] for artifact in artifacts}) == 2
    assert len({artifact["source"] for artifact in artifacts}) == 2
    assert {Path(artifact["path"]).read_bytes() for artifact in artifacts} == {
        b"%PDF-first",
        b"%PDF-second",
    }


def test_late_corrupt_embedding_keeps_earlier_valid_bytes(tmp_path):
    path = tmp_path / "office.docx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/embeddings/first.pdf", b"%PDF-first")
        archive.writestr("word/embeddings/broken.pdf", b"%PDF-broken")
    data = path.read_bytes().replace(b"%PDF-broken", b"%PDF-BROKEN", 1)
    path.write_bytes(data)
    findings = _findings()
    artifacts = []
    DocumentAnalysisStage()._analyse_ooxml(_stage_ctx(path), findings, artifacts, tmp_path)
    assert len(artifacts) == 1
    assert Path(artifacts[0]["path"]).read_bytes() == b"%PDF-first"
    assert findings["embedded_extraction"]["status"] == "partial"
    assert findings["embedded_extraction"]["unavailable"] == 1
    assert "document_embedded_unavailable" in findings["errors"]


@pytest.mark.parametrize(
    "stream,reason",
    [
        ("ApplicationData", "ole_payload_layout_unsupported"),
        ("CONTENTS", "ole_application_payload_unsupported"),
    ],
)
def test_unknown_cfb_payload_layout_is_explicitly_unavailable(stream, reason, tmp_path):
    path = tmp_path / "wrapper.bin"
    path.write_bytes(_cfb_stream(stream, b"opaque application payload"))
    emitted = []
    coverage = extract_ole_payloads(
        path,
        maximum_bytes=1000,
        maximum_objects=30,
        reserve=None,
        emit=lambda *args: emitted.append(args),
    )
    assert coverage["status"] == "partial"
    assert coverage.get("reason") == reason or coverage["items"][0]["reason"] == reason
    assert not emitted


def test_unicode_embedded_name_fits_filesystem_byte_limit(tmp_path):
    name = embedded_filename("附" * 120 + ".dat", b"%PDF-1.7", 0)
    assert len(name.encode("utf-8")) <= 164
    output = tmp_path / ("ooxml-000-" + name)
    output.write_bytes(b"%PDF-1.7")
    assert output.read_bytes() == b"%PDF-1.7"


def test_document_output_never_overwrites_existing_file_or_symlink(tmp_path):
    target = tmp_path / "original"
    target.write_bytes(b"keep original bytes")
    existing = tmp_path / "output"
    existing.symlink_to(target)
    with pytest.raises(FileExistsError):
        DocumentAnalysisStage._write_artifact(None, existing, b"replacement")
    assert existing.is_symlink()
    assert target.read_bytes() == b"keep original bytes"


@pytest.mark.asyncio
async def test_document_repeated_parse_uses_distinct_private_output_directories(tmp_path):
    path = tmp_path / "input.docx"
    path.write_bytes(build_document_embedded_fixture("office-embedded-pdf"))
    ctx = StageContext(
        job_id="f03-repeat-parse",
        file_id="file",
        storage_key="test",
        sha256="a" * 64,
        original_filename=path.name,
        file_path=path,
    )
    first = await DocumentAnalysisStage().execute(ctx)
    second = await DocumentAnalysisStage().execute(ctx)
    outputs = [
        Path(result.findings["extracted_artifacts"][0]["path"]) for result in (first, second)
    ]
    assert outputs[0].parent != outputs[1].parent
    for output in outputs:
        assert output.read_bytes() == embedded_fixture_payloads("office-embedded-pdf")[0]
        assert output.parent.stat().st_mode & 0o077 == 0
