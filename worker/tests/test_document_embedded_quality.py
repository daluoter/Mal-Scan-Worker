"""Freeze embedded bytes and reject false acceptance/provenance evidence."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path
from typing import Any

import olefile
import pytest
from malscan_worker.quality import document_embedded_acceptance as acceptance
from malscan_worker.quality.document_embedded_fixtures import (
    DOCUMENT_EMBEDDED_PROFILES,
    build_document_embedded_fixture,
    embedded_fixture_payloads,
    fixture_identity,
)
from malscan_worker.quality.pdf_password_fixtures import PDF_PASSWORD, WRONG_PASSWORD
from pypdf import PdfReader

_MANIFEST = Path(__file__).parents[1] / "quality" / "document-embedded-v1.json"


@pytest.mark.parametrize("profile", DOCUMENT_EMBEDDED_PROFILES)
def test_real_container_recipe_is_deterministic_and_manifest_pinned(profile: str) -> None:
    source = build_document_embedded_fixture(profile)
    assert source == build_document_embedded_fixture(profile)
    assert len(source) < 10_000
    suite = acceptance.load_manifest(_MANIFEST)
    case = next(case for case in suite["cases"] if case["profile"] == profile)
    assert fixture_identity(profile) == (case["sha256"], case["bytes"])
    assert hashlib.sha256(source).hexdigest() == case["sha256"]
    assert case["direct_inventory"] == acceptance.expected_inventory(profile)


@pytest.mark.parametrize("version", [0, 2, True, "1", 1.0])
def test_recipe_rejects_unknown_or_ambiguous_versions(version: Any) -> None:
    with pytest.raises(ValueError, match="version"):
        build_document_embedded_fixture("pdf-name-tree-text", version)


def test_recipe_rejects_unknown_profile() -> None:
    with pytest.raises(ValueError, match="profile"):
        build_document_embedded_fixture("missing-profile")
    with pytest.raises(ValueError, match="profile"):
        embedded_fixture_payloads("missing-profile")


def test_pdf_aliases_and_same_name_distinct_streams_are_real_pdf_objects() -> None:
    reader = PdfReader(io.BytesIO(build_document_embedded_fixture("pdf-alias-and-duplicate-names")))
    catalog = reader.trailer["/Root"]
    entries = catalog["/Names"]["/EmbeddedFiles"]["/Kids"][0].get_object()["/Names"]
    specs = [entries[index].get_object() for index in (1, 3, 5)]
    assert [str(spec["/F"]) for spec in specs] == ["same-name.txt"] * 3
    streams = [spec["/EF"]["/F"] for spec in specs]
    assert tuple(stream.get_data() for stream in streams) == embedded_fixture_payloads(
        "pdf-alias-and-duplicate-names"
    )
    assert streams[0].indirect_reference != streams[2].indirect_reference
    assert specs[0].indirect_reference == catalog["/AF"][0]
    page = reader.pages[0]
    assert page["/AF"][0] == specs[0].indirect_reference
    assert page["/Annots"][0].get_object().raw_get("/FS") == specs[0].indirect_reference


def test_compressed_eicar_is_not_literal_source_but_decodes_to_standard_control() -> None:
    payload = build_document_embedded_fixture("pdf-flate-eicar")
    (expected,) = embedded_fixture_payloads("pdf-flate-eicar")
    assert expected not in payload
    reader = PdfReader(io.BytesIO(payload))
    spec = reader.trailer["/Root"]["/Names"]["/EmbeddedFiles"]["/Names"][1].get_object()
    stream = spec["/EF"]["/F"]
    assert stream["/Filter"] == "/FlateDecode"
    assert stream.get_data() == expected


def test_embedded_encrypted_pdf_really_requires_its_separate_password() -> None:
    (payload,) = embedded_fixture_payloads("pdf-password-child")
    reader = PdfReader(io.BytesIO(payload))
    assert reader.is_encrypted
    assert reader.decrypt(WRONG_PASSWORD) == 0
    assert reader.decrypt(PDF_PASSWORD) == 1
    assert len(reader.pages) == 1
    outer = PdfReader(io.BytesIO(build_document_embedded_fixture("pdf-password-child")))
    spec = outer.trailer["/Root"]["/Names"]["/EmbeddedFiles"]["/Names"][1].get_object()
    assert spec["/EF"]["/F"].get_data() == payload


@pytest.mark.parametrize("profile", ["office-embedded-pdf", "office-relationship-package"])
def test_ooxml_parts_really_contain_non_bin_pdf_and_declared_internal_relationship(
    profile: str,
) -> None:
    with zipfile.ZipFile(io.BytesIO(build_document_embedded_fixture(profile))) as archive:
        member = (
            "word/embeddings/attachment.pdf"
            if profile == "office-embedded-pdf"
            else "custom/payload.pdf"
        )
        assert archive.read(member) == embedded_fixture_payloads(profile)[0]
        assert len(archive.namelist()) == 5
        assert member.endswith(".pdf")
        assert b"TargetMode" not in archive.read("word/_rels/document.xml.rels")
        assert b"officeDocument/2006/relationships/" in archive.read("word/_rels/document.xml.rels")


@pytest.mark.parametrize("profile", ["ole-native-text", "ole-package-pdf", "ole-native-truncated"])
def test_cfb_has_exact_size_stream_in_real_minifat(profile: str) -> None:
    with olefile.OleFileIO(io.BytesIO(build_document_embedded_fixture(profile))) as container:
        assert container.listdir() == [
            ["Package" if profile == "ole-package-pdf" else "\x01Ole10Native"]
        ]
        stream = container.openstream(container.listdir()[0]).read()
        if profile == "ole-package-pdf":
            assert stream == embedded_fixture_payloads(profile)[0]
        elif profile == "ole-native-text":
            assert struct.unpack_from("<I", stream)[0] == len(stream) - 4
            assert stream.endswith(embedded_fixture_payloads(profile)[0])
        else:
            assert struct.unpack_from("<I", stream)[0] > len(stream) - 4


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "bool_schema",
        "recipe",
        "suite",
        "scope",
        "policy",
        "rules",
        "cases",
        "duplicate",
        "profile",
        "hash",
        "size",
        "bool_size",
        "inventory",
        "scenario",
        "false_complete",
        "missing_scan",
        "missing_child",
        "invented_rule",
        "case_type",
    ],
)
def test_manifest_rejects_stale_bytes_and_relaxed_contracts(tmp_path: Path, mutation: str) -> None:
    suite = json.loads(_MANIFEST.read_text())
    case = suite["cases"][0]
    if mutation == "schema":
        suite["schema_version"] = 2
    elif mutation == "bool_schema":
        suite["schema_version"] = True
    elif mutation == "recipe":
        suite["recipe_version"] = "1"
    elif mutation == "suite":
        suite["suite_version"] = "unfrozen"
    elif mutation == "scope":
        suite["scope"] = "other"
    elif mutation == "policy":
        suite["policy_version"] = None
    elif mutation == "rules":
        suite["rules_sha256"] = "not-pinned"
    elif mutation == "cases":
        suite["cases"] = []
    elif mutation == "duplicate":
        suite["cases"].append(copy.deepcopy(case))
    elif mutation == "profile":
        case["profile"] = "unknown"
    elif mutation == "hash":
        case["sha256"] = "0" * 64
    elif mutation == "size":
        case["bytes"] += 1
    elif mutation == "bool_size":
        case["bytes"] = True
    elif mutation == "inventory":
        case["direct_inventory"][0]["origin_path"] = "metadata-only-not-a-child"
    elif mutation == "scenario":
        case["scenario"] = "partial"
    elif mutation == "false_complete":
        suite["cases"][5]["expect"]["static_status"] = "complete"
    elif mutation == "missing_scan":
        case["expect"]["root_stages"] = {"yara": "skipped"}
    elif mutation == "missing_child":
        case["expect"]["artifact_count"] = 1
    elif mutation == "invented_rule":
        case["expect"]["yara_rules"] = ["invented"]
    else:
        suite["cases"][0] = None
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(suite))
    with pytest.raises(ValueError):
        acceptance.load_manifest(path)


def _simple_report(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    case = acceptance.load_manifest(_MANIFEST)["cases"][0]
    expected = case["direct_inventory"][0]
    path = tmp_path / "child"
    path.write_bytes(embedded_fixture_payloads(case["profile"])[0])
    node = {
        **expected,
        "artifact_id": "child",
        "parent_id": "root",
        "depth": 1,
        "storage_key": "child",
        "report": {},
    }
    root = {
        "artifact_id": "root",
        "parent_id": None,
        "report": {
            "results": {
                "format_analysis": {
                    "features": {
                        "attachment_extraction": {"status": "complete", "extracted_files": 1},
                        "embedded_files": [
                            {
                                "source": expected["origin_path"],
                                "sha256": expected["sha256"],
                                "size": expected["size"],
                                "extraction_status": "extracted",
                            }
                        ],
                    }
                }
            }
        },
    }
    return case, {"root_artifact_id": "root", "artifacts": [root, node]}


def test_inventory_reads_actual_stored_child_and_exact_origin(tmp_path: Path) -> None:
    case, report = _simple_report(tmp_path)
    assert acceptance.verify_inventory(case, report, tmp_path)["stored_children_verified"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "hash",
        "origin",
        "source",
        "size",
        "parent",
        "bytes",
        "missing",
        "summary",
        "metadata",
        "storage_escape",
        "symlink",
    ],
)
def test_inventory_rejects_claimed_extraction_without_matching_child_bytes(
    tmp_path: Path, mutation: str
) -> None:
    case, report = _simple_report(tmp_path)
    node = report["artifacts"][1]
    features = report["artifacts"][0]["report"]["results"]["format_analysis"]["features"]
    if mutation == "hash":
        node["sha256"] = "0" * 64
    elif mutation == "origin":
        node["origin_path"] = "pdf-attachment/9999"
    elif mutation == "source":
        node["extraction_source"] = "archive-extract"
    elif mutation == "size":
        node["size"] += 1
    elif mutation == "parent":
        node["parent_id"] = "missing"
    elif mutation == "bytes":
        (tmp_path / "child").write_bytes(b"changed")
    elif mutation == "missing":
        (tmp_path / "child").unlink()
    elif mutation == "summary":
        features["attachment_extraction"]["extracted_files"] = 0
    elif mutation == "metadata":
        features["embedded_files"][0]["sha256"] = "0" * 64
    elif mutation == "storage_escape":
        node["storage_key"] = "../outside"
    else:
        (tmp_path / "different").write_bytes((tmp_path / "child").read_bytes())
        (tmp_path / "child").unlink()
        (tmp_path / "child").symlink_to(tmp_path / "different")
    with pytest.raises((ValueError, FileNotFoundError)):
        acceptance.verify_inventory(case, report, tmp_path)


@pytest.mark.parametrize("password", [PDF_PASSWORD, WRONG_PASSWORD])
@pytest.mark.parametrize("filename", ["report.json", "checkpoint.json", "case.log"])
def test_report_and_log_secret_guard_preserves_password_boundary(
    tmp_path: Path, password: str, filename: str
) -> None:
    (tmp_path / "source.pdf").write_bytes(password.encode())
    acceptance._check_secrets(tmp_path)
    (tmp_path / filename).write_text(json.dumps({"accidental": password}))
    with pytest.raises(ValueError, match="leaked"):
        acceptance._check_secrets(tmp_path)


def test_general_v6_preserves_inputs_and_only_changes_external_embed_coverage():
    from malscan_worker.quality.corpus import load_corpus

    before = load_corpus(_MANIFEST.with_name("corpus-v5.json"))
    after = load_corpus(_MANIFEST.with_name("corpus-v6.json"))
    assert before["fixtures"] == after["fixtures"]
    assert before["rules_sha256"] == after["rules_sha256"]
    assert before["policy_version"] == after["policy_version"]
    assert len(after["cases"]) == len(before["cases"]) == 40
    changed = [
        old["id"] for old, new in zip(before["cases"], after["cases"], strict=True) if old != new
    ]
    assert changed == ["office-external-references"]
    case = next(case for case in after["cases"] if case["id"] == changed[0])
    assert case["expect"]["static_status"] == "partial"
    assert case["expect"]["root_stages"] == {
        "format-analysis": "partial",
        "document-analysis": "partial",
    }
    assert case["expect"]["yara_risk_rules"] == []
    assert case["expect"]["artifact_count"] == 5
