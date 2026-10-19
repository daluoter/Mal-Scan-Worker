"""Frozen inert Office fixtures exercise real crypto using public test passwords."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError

import olefile
import pytest
import pyzipper
from malscan_worker.quality import office_password_fixtures as fixtures
from malscan_worker.quality.office_password_fixtures import (
    ARCHIVE_PASSWORD,
    NESTED_OFFICE_PROFILES,
    OFFICE_PASSWORD,
    OFFICE_PASSWORD_PROFILES,
    OFFICE_PLAINTEXT_PROFILES,
    SECOND_OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_password_fixture,
    build_office_plaintext_fixture,
)
from msoffcrypto import exceptions
from msoffcrypto.format.ooxml import OOXMLFile

_DECRYPTABLE = tuple(
    profile for profile in OFFICE_PASSWORD_PROFILES if profile.startswith(("agile-", "standard-"))
)
_MANIFEST = Path(__file__).resolve().parents[1] / "quality" / "office-password-v1.json"


@pytest.mark.parametrize("profile", OFFICE_PASSWORD_PROFILES)
def test_frozen_encrypted_fixture_matches_manifest_and_stays_small(profile: str) -> None:
    payload = build_office_password_fixture(profile=profile)
    manifest = json.loads(_MANIFEST.read_text())
    case = next(case for case in manifest["cases"] if case["profile"] == profile)
    assert payload == build_office_password_fixture(profile=profile)
    assert case["sha256"] == hashlib.sha256(payload).hexdigest()
    assert case["bytes"] == len(payload) < 20_000
    for password in (OFFICE_PASSWORD, SECOND_OFFICE_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD):
        assert password.encode() not in payload


def test_fixture_manifest_covers_exact_public_recipe_and_current_policy() -> None:
    manifest = json.loads(_MANIFEST.read_text())
    assert manifest["schema_version"] == manifest["recipe_version"] == 1
    assert manifest["suite_version"] == "office-password-v1.0.0"
    assert manifest["policy_version"] == "msrs-v1.2"
    assert manifest["rules_sha256"] == (
        "52cc7df2f9732941bce0f079bb70b36f01f04008b0a458398ef3ee58679a7dcc"
    )
    assert "Public test-only" in manifest["password_notice"]
    assert manifest["generator_versions"]["msoffcrypto-tool"] == "6.0.0"
    assert {case["profile"] for case in manifest["cases"]} == set(OFFICE_PASSWORD_PROFILES)
    assert len(manifest["cases"]) == len(OFFICE_PASSWORD_PROFILES)


def test_fixture_api_rejects_unknown_recipes_and_detects_damaged_frozen_data(monkeypatch) -> None:
    for builder in (build_office_password_fixture, build_office_plaintext_fixture):
        with pytest.raises(ValueError, match="profile"):
            builder(profile="unknown")
        with pytest.raises(ValueError, match="version"):
            builder(profile="agile-aes256-docx", recipe_version=2)
    sha256, size, encoded = fixtures._FIXTURES["agile-aes256-docx"]
    monkeypatch.setitem(fixtures._FIXTURES, "agile-aes256-docx", (sha256, size + 1, encoded))
    with pytest.raises(ValueError, match="checksum"):
        build_office_password_fixture(profile="agile-aes256-docx")


@pytest.mark.parametrize("profile", _DECRYPTABLE)
def test_real_office_crypto_requires_password_and_recovers_exact_plaintext(profile: str) -> None:
    payload = build_office_password_fixture(profile=profile)
    expected = build_office_plaintext_fixture(profile=profile)
    assert olefile.isOleFile(io.BytesIO(payload))
    office = OOXMLFile(io.BytesIO(payload))
    assert office.is_encrypted()
    with pytest.raises(exceptions.InvalidKeyError):
        office.load_key(password=WRONG_PASSWORD, verify_password=True)
    with pytest.raises(exceptions.InvalidKeyError):
        office.load_key(password=ARCHIVE_PASSWORD, verify_password=True)
    password = SECOND_OFFICE_PASSWORD if profile.endswith("second-password") else OFFICE_PASSWORD
    other = OFFICE_PASSWORD if profile.endswith("second-password") else SECOND_OFFICE_PASSWORD
    with pytest.raises(exceptions.InvalidKeyError):
        office.load_key(password=other, verify_password=True)
    office.load_key(password=password, verify_password=True)
    clear = io.BytesIO()
    office.decrypt(clear, verify_integrity=True)
    assert clear.getvalue() == expected
    with olefile.OleFileIO(io.BytesIO(payload)) as ole:
        assert struct.unpack("<Q", ole.openstream("EncryptedPackage").read(8))[0] == len(expected)
    if profile.startswith("agile-"):
        assert office.type == "agile"
        assert office.info["passwordKeyBits"] == 256
        assert office.info["passwordHashAlgorithm"] == "SHA512"
        assert office.info["spinValue"] == 100_000
    else:
        assert office.type == "standard"
        assert office.info["header"]["algId"] == 0x660E
        assert office.info["header"]["keySize"] == 128
    manifest = json.loads(_MANIFEST.read_text())
    case = next(case for case in manifest["cases"] if case["profile"] == profile)
    assert case["plaintext_sha256"] == hashlib.sha256(expected).hexdigest()
    assert case["plaintext_bytes"] == len(expected)


@pytest.mark.parametrize("kind", OFFICE_PLAINTEXT_PROFILES)
def test_plaintext_ooxml_has_real_main_parts_and_preserves_inert_binary_flags(kind: str) -> None:
    payload = build_office_plaintext_fixture(profile=kind)
    assert payload == build_office_plaintext_fixture(profile=f"agile-aes256-{kind}")
    assert not OOXMLFile(io.BytesIO(payload)).is_encrypted()
    macro = kind in {"docm", "xlsm", "pptm"}
    family = (
        "word"
        if kind.startswith("doc") or kind == "external-template-docx"
        else ("xl" if kind.startswith("xl") else "ppt")
    )
    main = {"word": "word/document.xml", "xl": "xl/workbook.xml", "ppt": "ppt/presentation.xml"}[
        family
    ]
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert archive.testzip() is None
        assert archive.read("customXml/opaque.bin") == bytes(range(256)) * 12
        assert b"inert binary preservation" in archive.read("customXml/item1.xml")
        root_rels = ElementTree.fromstring(archive.read("_rels/.rels"))
        assert next(iter(root_rels)).attrib["Target"] == main
        main_types = [
            node.attrib["ContentType"]
            for node in ElementTree.fromstring(archive.read("[Content_Types].xml"))
            if node.attrib.get("PartName") == f"/{main}"
        ]
        assert len(main_types) == 1
        assert ("macroEnabled" in main_types[0]) is macro
        ElementTree.fromstring(archive.read(main))
        if family == "xl":
            ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        if family == "ppt":
            ElementTree.fromstring(archive.read("ppt/slides/slide1.xml"))
        macro_parts = [name for name in archive.namelist() if name.endswith("/vbaProject.bin")]
        assert bool(macro_parts) is macro
        if macro:
            assert archive.read(macro_parts[0]) == bytes.fromhex("d0cf11e0a1b11ae1") + bytes(504)
            assert archive.read(f"{family}/embeddings/oleObject1.bin") == (
                b"Inert fixture embedding\x00\xff\x80\x01"
            )
        if kind == "external-template-docx":
            rels = ElementTree.fromstring(archive.read("word/_rels/settings.xml.rels"))
            attached = next(iter(rels))
            assert attached.attrib["Type"].endswith("/attachedTemplate")
            assert attached.attrib["TargetMode"] == "External"
            assert attached.attrib["Target"] == "https://quality.invalid/inert-template.dotx"


@pytest.mark.parametrize("profile", tuple(NESTED_OFFICE_PROFILES))
def test_real_nested_zip_has_distinct_outer_password_and_independent_office_bytes(
    profile: str,
) -> None:
    payload = build_office_password_fixture(profile=profile)
    manifest = json.loads(_MANIFEST.read_text())
    case = next(case for case in manifest["cases"] if case["profile"] == profile)
    children = case["nested_children"]
    assert tuple(child["profile"] for child in children) == NESTED_OFFICE_PROFILES[profile]
    with pyzipper.AESZipFile(io.BytesIO(payload)) as archive:
        assert archive.namelist() == [child["filename"] for child in children]
        for child in children:
            filename = child["filename"]
            with pytest.raises(RuntimeError):
                archive.read(filename, pwd=OFFICE_PASSWORD.encode())
            inner = archive.read(filename, pwd=ARCHIVE_PASSWORD.encode())
            assert inner == build_office_password_fixture(profile=child["profile"])
            office = OOXMLFile(io.BytesIO(inner))
            with pytest.raises(exceptions.InvalidKeyError):
                office.load_key(password=ARCHIVE_PASSWORD, verify_password=True)
            office.load_key(password=OFFICE_PASSWORD, verify_password=True)
            clear = io.BytesIO()
            office.decrypt(clear, verify_integrity=True)
            expected = build_office_plaintext_fixture(profile=child["profile"])
            assert clear.getvalue() == expected
            assert child["plaintext_sha256"] == hashlib.sha256(expected).hexdigest()
            assert child["plaintext_bytes"] == len(expected)


def test_corrupt_ciphertext_has_valid_password_but_fails_real_integrity_check() -> None:
    office = OOXMLFile(
        io.BytesIO(build_office_password_fixture(profile="corrupt-encrypted-package"))
    )
    office.load_key(password=OFFICE_PASSWORD, verify_password=True)
    clear = io.BytesIO()
    with pytest.raises(exceptions.InvalidKeyError, match="integrity"):
        office.decrypt(clear, verify_integrity=True)
    assert clear.getvalue() == b""


def test_unsupported_and_malformed_controls_fail_real_parser_without_decrypting() -> None:
    with pytest.raises(exceptions.DecryptionError, match="Unsupported.*Extensible"):
        OOXMLFile(io.BytesIO(build_office_password_fixture(profile="unsupported-encryption")))
    with pytest.raises(ExpatError):
        OOXMLFile(io.BytesIO(build_office_password_fixture(profile="malformed-agile-xml")))
