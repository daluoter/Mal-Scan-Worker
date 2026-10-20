"""Exact-byte PDF attachment extraction and hostile input controls."""
from __future__ import annotations

import hashlib
import io
import stat
import zlib
from pathlib import Path

import pytest
from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
from malscan_worker.analyzers.pdf_attachments import extract_pdf_attachments
from malscan_worker.budget import BudgetExceeded, reservation_key
from malscan_worker.quality.document_embedded_fixtures import (
    build_document_embedded_fixture,
    embedded_fixture_payloads,
)
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject, StreamObject


def _stream(payload: bytes, *, compress: bool = False) -> StreamObject:
    result = StreamObject()
    result._data = zlib.compress(payload) if compress else payload
    if compress:
        result[NameObject("/Filter")] = NameObject("/FlateDecode")
    return result


def _spec(stream: object, name: str = "test.txt") -> dict:
    return {"/Type": "/Filespec", "/F": name, "/EF": {"/F": stream}}


def _reader(specs: list[object], *, root_extra: dict | None = None):
    class Reader:
        trailer = {"/Root": {"/AF": specs, **(root_extra or {})}}
        pages = []

    return Reader()


def _extract(reader, tmp_path: Path, **kwargs):
    reservations = []
    output = tmp_path / "output"
    output.mkdir(exist_ok=True)
    result = extract_pdf_attachments(
        reader,
        output_dir=output,
        reserve=kwargs.pop("reserve", lambda *args: reservations.append(args)),
        maximum_bytes=kwargs.pop("maximum_bytes", 1024 * 1024),
        maximum_files=kwargs.pop("maximum_files", 30),
        job_id="pdf-attachments-test",
        depth_limited=kwargs.pop("depth_limited", False),
        **kwargs,
    )
    return result, reservations


@pytest.mark.parametrize(
    "profile",
    [
        "pdf-name-tree-text",
        "pdf-flate-eicar",
        "pdf-alias-and-duplicate-names",
        "pdf-associated-and-annotation",
        "pdf-password-child",
    ],
)
def test_frozen_fixtures_restore_each_payload_exactly(profile, tmp_path):
    payload = build_document_embedded_fixture(profile)
    expected = embedded_fixture_payloads(profile)
    result, reservations = _extract(PdfReader(io.BytesIO(payload)), tmp_path)
    assert result.errors == []
    actual = [Path(artifact["path"]).read_bytes() for artifact in result.artifacts]
    assert sorted(actual) == sorted(expected)
    assert len(reservations) == len(actual)
    for artifact in result.artifacts:
        path = Path(artifact["path"])
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert artifact["size"] == len(path.read_bytes())
        assert artifact["budget_key"] == reservation_key(
            "pdf-attachments-test", "format-analysis", artifact["source"]
        )
        assert (artifact["source"], 1, artifact["size"]) in reservations
    assert "path" not in repr(result.entries)


def test_alias_reference_keeps_one_occurrence_but_distinct_stream_is_preserved(tmp_path):
    stream = _stream(b"same payload")
    same_spec = _spec(stream)
    distinct_spec_alias = _spec(stream, "alias.txt")
    identical_distinct_stream = _spec(_stream(b"same payload"))
    result, reservations = _extract(
        _reader([same_spec, same_spec, distinct_spec_alias, identical_distinct_stream]), tmp_path
    )
    assert result.errors == []
    assert len(result.artifacts) == len(reservations) == 2
    assert len(result.entries[0]["references"]) == 3
    assert result.artifacts[0]["sha256"] == result.artifacts[1]["sha256"]
    assert result.artifacts[0]["source"] != result.artifacts[1]["source"]
    assert result.artifacts[0]["path"] != result.artifacts[1]["path"]


def test_same_filename_does_not_overwrite_and_traversal_name_stays_leaf(tmp_path):
    result, _ = _extract(
        _reader(
            [
                _spec(_stream(b"a"), "../../one.txt"),
                _spec(_stream(b"b"), "..\\..\\one.txt"),
            ]
        ),
        tmp_path,
    )
    assert [art["filename"] for art in result.artifacts] == ["one.txt", "one.txt"]
    assert [Path(art["path"]).read_bytes() for art in result.artifacts] == [b"a", b"b"]
    assert all(Path(art["path"]).parent == tmp_path / "output" for art in result.artifacts)


def test_no_eager_stream_get_data_or_decoded_self_is_used(tmp_path, monkeypatch):
    payload = b"bounded decoder" * 100
    stream = _stream(payload, compress=True)
    monkeypatch.setattr(StreamObject, "get_data", lambda *_: pytest.fail("eager decode"))
    result, _ = _extract(_reader([_spec(stream)]), tmp_path)
    assert result.errors == []
    assert Path(result.artifacts[0]["path"]).read_bytes() == payload


def test_exact_reservation_precedes_output_and_not_rounded_buffer_count(tmp_path):
    called = []

    def reserve(*args):
        assert not list((tmp_path / "output").iterdir())
        called.append(args)

    result, _ = _extract(
        _reader([_spec(_stream(b"tiny", compress=True))]), tmp_path, reserve=reserve
    )
    assert result.errors == []
    assert called == [("pdf-attachment/0000", 1, 4)]


def test_flate_bomb_is_bounded_without_reservation_or_output(tmp_path):
    result, reservations = _extract(
        _reader([_spec(_stream(b"X" * 100_000, compress=True))]), tmp_path, maximum_bytes=1024
    )
    assert result.limited
    assert result.limit_reason == "pdf_attachment_bytes_limit"
    assert result.artifacts == [] and reservations == []
    assert not list((tmp_path / "output").iterdir())
    assert result.entries[0]["extraction_status"] == "resource_limited"


def test_valid_earlier_attachment_survives_later_invalid_stream(tmp_path):
    broken = _stream(b"not-zlib")
    broken[NameObject("/Filter")] = NameObject("/FlateDecode")
    result, _ = _extract(_reader([_spec(_stream(b"keep")), _spec(broken)]), tmp_path)
    assert result.errors
    assert len(result.artifacts) == 1
    assert Path(result.artifacts[0]["path"]).read_bytes() == b"keep"
    assert result.entries[1]["extraction_status"] == "malformed"


@pytest.mark.parametrize("mode", ["unsupported", "chain", "predictor", "truncated", "trailing"])
def test_unsupported_or_broken_filters_never_publish_partial_payload(mode, tmp_path):
    stream = _stream(b"payload", compress=True)
    if mode == "unsupported":
        stream[NameObject("/Filter")] = NameObject("/LZWDecode")
    elif mode == "chain":
        stream[NameObject("/Filter")] = ArrayObject(
            [NameObject("/ASCII85Decode"), NameObject("/FlateDecode")]
        )
    elif mode == "predictor":
        stream[NameObject("/DecodeParms")] = DictionaryObject(
            {NameObject("/Predictor"): NumberObject(12)}
        )
    elif mode == "truncated":
        stream._data = stream._data[:-2]
    elif mode == "trailing":
        stream._data += b"unexpected trailing data"
    result, reservations = _extract(_reader([_spec(stream)]), tmp_path)
    assert result.errors and not result.artifacts and not reservations
    assert not list((tmp_path / "output").iterdir())


def test_unsupported_attachment_does_not_hide_other_valid_payload(tmp_path):
    stream = _stream(b"payload")
    stream[NameObject("/Filter")] = NameObject("/Crypt")
    result, _ = _extract(_reader([_spec(stream), _spec(_stream(b"second"))]), tmp_path)
    assert len(result.artifacts) == 1
    assert Path(result.artifacts[0]["path"]).read_bytes() == b"second"
    assert result.summary(100, 30)["status"] == "partial"


@pytest.mark.parametrize(
    "spec",
    [
        {"/F": "missing.exe"},
        {"/FS": "/URL", "/F": "https://example.invalid/never-fetch"},
        "https://example.invalid/never-fetch",
    ],
)
def test_nonembedded_filespec_is_explicit_incomplete_and_never_fetched(spec, tmp_path):
    result, reservations = _extract(_reader([spec]), tmp_path)
    assert result.errors and not result.artifacts and not reservations
    assert result.entries[0]["extraction_status"] in {"missing_stream", "external_reference"}


def test_external_stream_dictionary_is_never_dereferenced(tmp_path):
    stream = _stream(b"data")
    stream[NameObject("/F")] = NameObject("/external")
    result, reservations = _extract(_reader([_spec(stream)]), tmp_path)
    assert result.entries[0]["extraction_status"] == "external_reference"
    assert not reservations and not result.artifacts


def test_budget_rejection_preserves_previous_artifact_and_stops_new_outputs(tmp_path):
    calls = []

    def reserve(*args):
        calls.append(args)
        if len(calls) > 1:
            raise BudgetExceeded("root_file_limit")

    result, _ = _extract(
        _reader([_spec(_stream(b"one")), _spec(_stream(b"two")), _spec(_stream(b"three"))]),
        tmp_path,
        reserve=reserve,
    )
    assert len(result.artifacts) == 1
    assert result.limit_reason == "root_file_limit"
    assert len(list((tmp_path / "output").iterdir())) == 1
    assert len(calls) == 2


def test_count_limit_is_reported_instead_of_silent_truncation(tmp_path):
    result, _ = _extract(
        _reader([_spec(_stream(b"a")), _spec(_stream(b"b"))]), tmp_path, maximum_files=1
    )
    assert len(result.artifacts) == 1
    assert result.limit_reason == "pdf_attachment_count_limit"


def test_depth_limit_keeps_descriptors_without_extracting(tmp_path):
    result, reservations = _extract(
        _reader([_spec(_stream(b"data"))]), tmp_path, depth_limited=True
    )
    assert not result.artifacts and not reservations
    assert result.limit_reason == "max_depth"
    assert result.entries[0]["extraction_status"] == "resource_limited"


def test_cycle_and_odd_name_array_are_explicit_partial(tmp_path):
    tree = {"/Names": ["only-name"]}
    tree["/Kids"] = [tree]
    result, _ = _extract(_reader([], root_extra={"/Names": {"/EmbeddedFiles": tree}}), tmp_path)
    assert any("cyclic_name_tree" in error for error in result.errors)
    assert any("malformed_name_tree" in error for error in result.errors)


def test_deep_name_tree_has_independent_depth_guard(tmp_path):
    tree = {"/Names": ["test", _spec(_stream(b"data"))]}
    for _ in range(33):
        tree = {"/Kids": [tree]}
    result, reservations = _extract(
        _reader([], root_extra={"/Names": {"/EmbeddedFiles": tree}}), tmp_path
    )
    assert result.limit_reason == "pdf_attachment_name_tree_depth_limit"
    assert not result.artifacts and not reservations


def test_huge_metadata_array_hits_traversal_cap_before_extraction(tmp_path):
    result, reservations = _extract(_reader([{}] * 4097), tmp_path)
    assert result.limit_reason == "pdf_attachment_traversal_limit"
    assert not result.artifacts and not reservations


def test_file_write_error_removes_output_and_does_not_publish_metadata(tmp_path, monkeypatch):
    original = __import__("os").fsync

    def fail(_):
        raise OSError("hidden path or credential must not escape")

    monkeypatch.setattr("malscan_worker.analyzers.pdf_attachments.os.fsync", fail)
    result, _ = _extract(_reader([_spec(_stream(b"data"))]), tmp_path)
    monkeypatch.setattr("malscan_worker.analyzers.pdf_attachments.os.fsync", original)
    assert result.errors and not result.artifacts
    assert "hidden path" not in repr(result)
    assert not list((tmp_path / "output").iterdir())


def test_analyzer_sync_exposes_bytes_metadata_and_partial_coverage(tmp_path):
    path = tmp_path / "sample.pdf"
    path.write_bytes(build_document_embedded_fixture("pdf-flate-eicar"))
    result = PDFAnalyzer()._analyze_sync(
        path,
        password=None,
        output_path=tmp_path / "decrypted.pdf",
        reserve=lambda *_: None,
        maximum_bytes=1_000_000,
        maximum_files=30,
        job_id="pdf-attachment-test",
        depth_limited=False,
    )
    assert result.errors == []
    assert result.features["attachment_extraction"]["status"] == "complete"
    assert result.features["embedded_files"][0]["extraction_status"] == "extracted"
    assert result.extracted_artifacts[0]["size"] == 68


def test_unicode_filename_fits_filesystem_byte_limit(tmp_path):
    result, _ = _extract(_reader([_spec(_stream(b"payload"), "附件" * 100 + ".txt")]), tmp_path)
    assert result.errors == []
    assert len(result.artifacts[0]["filename"].encode("utf-8")) <= 180
    assert Path(result.artifacts[0]["path"]).read_bytes() == b"payload"


@pytest.mark.parametrize("annots", [{}, None, [None]])
def test_malformed_annotation_container_is_explicit_partial(annots, tmp_path):
    reader = _reader([])
    reader.pages = [{"/Annots": annots}]
    result, _ = _extract(reader, tmp_path)
    assert result.errors and result.summary(100, 30)["status"] == "partial"


def test_distinct_unicode_and_legacy_ef_stream_variants_are_both_scanned(tmp_path):
    spec = {
        "/UF": "說明.txt",
        "/F": "readme.txt",
        "/EF": {
            "/UF": _stream(b"unicode variant"),
            "/F": _stream(b"legacy variant"),
        },
    }
    result, _ = _extract(_reader([spec]), tmp_path)
    assert result.errors == [] and len(result.artifacts) == 2
    assert {Path(art["path"]).read_bytes() for art in result.artifacts} == {
        b"unicode variant",
        b"legacy variant",
    }
    assert {entry["stream_key"] for entry in result.entries} == {"/UF", "/F"}


def test_uf_f_alias_does_not_duplicate_same_stream(tmp_path):
    stream = _stream(b"same stream")
    spec = {"/UF": "說明.txt", "/F": "readme.txt", "/EF": {"/UF": stream, "/F": stream}}
    result, reservations = _extract(_reader([spec]), tmp_path)
    assert result.errors == [] and len(result.artifacts) == len(reservations) == 1
