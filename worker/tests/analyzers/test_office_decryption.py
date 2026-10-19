"""Real Office crypto, exact package preservation and bounded failure controls."""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import io
import json
import logging
import shutil
import stat
import struct
import time
import uuid
import zipfile
from pathlib import Path

import olefile
import pytest
from malscan_worker.analyzers import office_decryption
from malscan_worker.analyzers.office_adapter import OfficeAnalyzerAdapter
from malscan_worker.analyzers.office_decryption import (
    _analyze_sync,
    _ReservedOutput,
    _validate_package,
    analyze_encrypted_office,
)
from malscan_worker.budget import BudgetExceeded, BudgetLimits, InMemoryRootBudget, reservation_key
from malscan_worker.config import get_settings
from malscan_worker.exceptions import DocumentPasswordRequiredError, DocumentWrongPasswordError
from malscan_worker.quality.office_password_fixtures import (
    OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_password_fixture,
    build_office_plaintext_fixture,
)
from malscan_worker.stages.base import StageContext
from msoffcrypto.method.container.ecma376_encrypted import DSPos, ECMA376Encrypted
from msoffcrypto.method.ecma376_agile import ECMA376Agile


@pytest.fixture(autouse=True)
def restore_logging():
    previous = logging.root.manager.disable
    yield
    logging.disable(previous)


@pytest.fixture
def office_context(tmp_path):
    contexts = []

    def create(profile="agile-aes256-docx", password=OFFICE_PASSWORD, payload=None):
        identifier = str(uuid.uuid4())
        path = tmp_path / (identifier + ".bin")
        payload = payload if payload is not None else build_office_password_fixture(profile)
        path.write_bytes(payload)
        context = StageContext(
            job_id=identifier,
            file_id=identifier,
            storage_key="encrypted-office-source",
            sha256=hashlib.sha256(payload).hexdigest(),
            original_filename="misleading.bin",
            file_path=path,
            archive_password=password,
        )
        contexts.append(context)
        return context

    yield create
    for context in contexts:
        shutil.rmtree(Path("/tmp") / context.job_id, ignore_errors=True)


def _streams(profile="agile-aes256-docx"):
    with olefile.OleFileIO(io.BytesIO(build_office_password_fixture(profile))) as ole:
        return ole.openstream("EncryptionInfo").read(), ole.openstream("EncryptedPackage").read()


def _container(info, package):
    output = io.BytesIO()
    ECMA376Encrypted(package, info).write_to(output)
    return output.getvalue()


def _sync(tmp_path, payload, password=OFFICE_PASSWORD, **overrides):
    path = tmp_path / "input.bin"
    path.write_bytes(payload)
    arguments = {
        "password": password,
        "output_path": tmp_path / "decrypted.package",
        "reserve": lambda *args: None,
        "maximum_bytes": 50_000_000,
        "maximum_expanded": 100_000_000,
        "job_id": "unit",
        "depth_limited": False,
    }
    arguments.update(overrides)
    return _analyze_sync(path, **arguments)


@pytest.mark.parametrize(
    "profile",
    [
        "agile-aes256-docx",
        "agile-aes256-xlsx",
        "agile-aes256-pptx",
        "agile-aes256-docm",
        "agile-aes256-xlsm",
        "agile-aes256-pptm",
        "agile-aes256-external-template-docx",
        "standard-aes128-docx",
    ],
)
@pytest.mark.asyncio
async def test_real_encrypted_office_emits_exact_plaintext_with_shared_budget(
    office_context, profile
):
    context = office_context(profile)
    original = context.file_path.read_bytes()
    context.root_budget = InMemoryRootBudget(BudgetLimits(5, 1_000_000, 60))
    analyzer = OfficeAnalyzerAdapter()
    assert analyzer.can_handle(context.file_path, "application/octet-stream", original[:8])
    result = await analyzer.analyze(context.file_path, context)
    assert result.errors == []
    assert result.features["encrypted"] is True
    assert result.features["content_access"] == "decrypted_child"
    (child,) = result.extracted_artifacts
    extension = profile.rsplit("-", 1)[1]
    assert child["filename"] == "decrypted." + extension
    assert child["source"] == "office-decrypted"
    assert child["budget_key"] == reservation_key(
        context.job_id, "format-analysis", "office-decrypted"
    )
    path = Path(child["path"])
    plaintext = path.read_bytes()
    assert plaintext == build_office_plaintext_fixture(profile)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert child["size"] == len(plaintext)
    assert child["sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert context.file_path.read_bytes() == original
    assert OFFICE_PASSWORD not in repr(result)
    assert "path" not in json.dumps(result.features)
    expected_integrity = (
        "zip_crc_only_no_authenticated_integrity"
        if profile.startswith("standard")
        else "hmac_verified"
    )
    assert result.features["encryption"]["integrity"] == expected_integrity
    snapshot = await context.root_budget.snapshot()
    assert snapshot.used_files == 1
    assert snapshot.used_bytes == child["size"]


@pytest.mark.parametrize("profile", ["agile-aes256-docx", "standard-aes128-docx"])
@pytest.mark.parametrize(
    ("password", "error"),
    [
        (None, DocumentPasswordRequiredError),
        (WRONG_PASSWORD, DocumentWrongPasswordError),
    ],
)
@pytest.mark.asyncio
async def test_password_wait_is_only_explicit_retry_control_flow(
    office_context, profile, password, error
):
    context = office_context(profile, password=password)
    with pytest.raises(error) as raised:
        await OfficeAnalyzerAdapter().analyze(context.file_path, context)
    assert raised.value.args == ("office",)
    assert OFFICE_PASSWORD not in str(raised.value)
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.*"))


@pytest.mark.parametrize(
    "profile",
    [
        "unsupported-encryption",
        "malformed-agile-xml",
    ],
)
@pytest.mark.parametrize("password", [None, WRONG_PASSWORD, OFFICE_PASSWORD])
@pytest.mark.asyncio
async def test_unsupported_and_malformed_encryption_are_partial_not_password_waits(
    office_context,
    profile,
    password,
):
    context = office_context(profile, password=password)
    result = await analyze_encrypted_office(context.file_path, context)
    assert result.errors
    assert result.extracted_artifacts == []
    assert result.features["content_access"] in {"unsupported", "unavailable"}
    assert OFFICE_PASSWORD not in repr(result)
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.*"))


@pytest.mark.asyncio
async def test_hmac_failure_is_corruption_after_password_verification(office_context):
    context = office_context("corrupt-encrypted-package")
    result = await analyze_encrypted_office(context.file_path, context)
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert result.features["content_access"] == "unavailable"
    assert result.features["encryption"]["integrity"] == "hmac_required"
    assert result.extracted_artifacts == []


def test_ole_encryption_stream_names_are_case_insensitive(tmp_path):
    payload = build_office_password_fixture("agile-aes256-docx")
    payload = payload.replace(
        "EncryptionInfo".encode("utf-16le"), "encryptioninfo".encode("utf-16le")
    )
    payload = payload.replace(
        "EncryptedPackage".encode("utf-16le"), "encryptedpackage".encode("utf-16le")
    )
    result = _sync(tmp_path, payload)
    assert result.features["content_access"] == "decrypted_child"
    assert result.errors == []


@pytest.mark.parametrize(
    ("name", "header"),
    [
        ("WordDocument", b"\0" * 10 + struct.pack("<H", 0x100)),
        ("Workbook", struct.pack("<HH", 0x002F, 0)),
        ("Book", struct.pack("<HH", 0x002F, 0)),
        ("Current User", b"\0" * 12 + struct.pack("<I", 0xF3D1C4DF)),
        ("DRMContent", b"unsupported-rights-management"),
    ],
)
def test_legacy_password_and_irm_containers_are_explicitly_unsupported(tmp_path, name, header):
    container = ECMA376Encrypted(b"x" * 4096, header)
    container._dirs[DSPos.iEncryptionInfo].Name = name.lower()
    container._dirs[DSPos.iEncryptionPackage].Name = "OtherPackage"
    output = io.BytesIO()
    container.write_to(output)
    result = _sync(tmp_path, output.getvalue(), password=None)
    assert result.features["encrypted"] is True
    assert result.features["content_access"] == "unsupported"
    assert result.errors == ["Office encryption or package type unsupported"]
    assert result.extracted_artifacts == []


def test_ordinary_unencrypted_ole_is_delegated_to_existing_analyzer(tmp_path):
    container = ECMA376Encrypted(b"x" * 4096, b"\0" * 32)
    container._dirs[DSPos.iEncryptionInfo].Name = "WordDocument"
    container._dirs[DSPos.iEncryptionPackage].Name = "OtherPackage"
    output = io.BytesIO()
    container.write_to(output)
    assert _sync(tmp_path, output.getvalue(), password=None) is None


@pytest.mark.parametrize("offset", [40, 44, 64, 72])
def test_cfb_allocation_counts_are_rejected_before_ole_parser(tmp_path, monkeypatch, offset):
    payload = bytearray(build_office_password_fixture("agile-aes256-docx"))
    struct.pack_into("<I", payload, offset, 0xFFFFFFFF)
    calls = []
    monkeypatch.setattr(olefile, "OleFileIO", lambda *args, **kwargs: calls.append(True))
    result = _sync(tmp_path, bytes(payload))
    assert calls == []
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert result.extracted_artifacts == []


def test_empty_password_can_unlock_without_prompting(tmp_path):
    plaintext = build_office_plaintext_fixture("docm")
    encrypted = ECMA376Agile.encrypt("", io.BytesIO(plaintext), spin_count=1000)
    result = _sync(tmp_path, encrypted, password=None)
    assert result.errors == []
    assert result.features["content_access"] == "decrypted_child"
    assert Path(result.extracted_artifacts[0]["path"]).read_bytes() == plaintext


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        (b'spinCount="100000"', b'spinCount="4294967295"', "office_spin_count_limit"),
        (b'cipherAlgorithm="AES"', b'cipherAlgorithm="RC4"', "unsupported"),
        (b"ChainingModeCBC", b"ChainingModeCFB", "unsupported"),
        (b'hashAlgorithm="SHA512"', b'hashAlgorithm="SHA1"', "unsupported"),
        (b'blockSize="16"', b'blockSize="8"', "unsupported"),
        (b'saltSize="16"', b'saltSize="8"', "unsupported"),
        (b'keyBits="256"', b'keyBits="192"', "unsupported"),
        (b'hashSize="64"', b'hashSize="48"', "unsupported"),
    ],
)
def test_agile_metadata_rejected_before_password_derivation(
    tmp_path, monkeypatch, old, new, reason
):
    info, package = _streams()
    called = []
    monkeypatch.setattr(office_decryption, "_load_password_key", lambda *args: called.append(True))
    result = _sync(tmp_path, _container(info.replace(old, new), package))
    assert called == []
    assert result.extracted_artifacts == []
    assert result.errors
    assert result.features["content_access"] == (
        "unsupported" if reason == "unsupported" else "unavailable"
    )
    if reason != "unsupported":
        assert result.features["limit_reason"] == reason


@pytest.mark.parametrize(
    ("offset", "value"), [(20, 0x660F), (24, 0x800C), (28, 256), (32, 1), (12, 0)]
)
def test_standard_parameters_must_match_pinned_aes_handler(tmp_path, monkeypatch, offset, value):
    info, package = _streams("standard-aes128-docx")
    changed = bytearray(info)
    struct.pack_into("<I", changed, offset, value)
    called = []
    monkeypatch.setattr(office_decryption, "_load_password_key", lambda *args: called.append(True))
    result = _sync(tmp_path, _container(bytes(changed), package))
    assert called == []
    assert result.features["content_access"] == "unsupported"
    assert result.extracted_artifacts == []


@pytest.mark.parametrize("size", [0, 21, 2**32 + 4831, 100_000_000])
def test_declared_package_length_cannot_bypass_output_bound(tmp_path, monkeypatch, size):
    info, package = _streams()
    called = []
    monkeypatch.setattr(office_decryption, "_load_password_key", lambda *args: called.append(True))
    result = _sync(tmp_path, _container(info, struct.pack("<Q", size) + package[8:]))
    assert called == []
    assert result.errors
    assert result.extracted_artifacts == []


@pytest.mark.parametrize("payload", [b"<!DOCTYPE x [<!ENTITY x 'attack'>]><x>&x;</x>", b"<bad/>"])
def test_xml_metadata_is_bounded_and_rejects_dtd(tmp_path, payload):
    info, package = _streams()
    result = _sync(tmp_path, _container(info[:8] + payload, package), password=None)
    assert result.errors
    assert result.features["content_access"] in {"unsupported", "unavailable"}


def test_zip_crc_is_checked_after_successful_hmac(tmp_path):
    plaintext = bytearray(build_office_plaintext_fixture("docx"))
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        member = archive.getinfo("customXml/opaque.bin")
        offset = member.header_offset
        name_size, extra_size = struct.unpack_from("<HH", plaintext, offset + 26)
        plaintext[offset + 30 + name_size + extra_size] ^= 1
    encrypted = ECMA376Agile.encrypt(OFFICE_PASSWORD, io.BytesIO(plaintext), spin_count=1000)
    result = _sync(tmp_path, encrypted)
    assert result.features["content_access"] == "unavailable"
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert result.extracted_artifacts == []
    assert result.features["encryption"]["integrity"] == "hmac_required"


def test_standard_ciphertext_corruption_requires_full_zip_crc_verification(tmp_path):
    info, package = _streams("standard-aes128-docx")
    damaged = bytearray(package)
    damaged[8 + 2048] ^= 1
    result = _sync(tmp_path, _container(info, bytes(damaged)))
    assert result.features["content_access"] == "unavailable"
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert result.extracted_artifacts == []


@pytest.mark.parametrize("main_xml", [b"not XML", b"<wrong/>", b"<document>", b"<!DOCTYPE x><x/>"])
def test_authenticated_zip_must_contain_actual_well_formed_office_main_xml(tmp_path, main_xml):
    original = build_office_plaintext_fixture("docx")
    modified = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(modified, "w") as target:
        for member in source.infolist():
            target.writestr(
                member.filename,
                main_xml if member.filename == "word/document.xml" else source.read(member),
            )
    encrypted = ECMA376Agile.encrypt(
        OFFICE_PASSWORD, io.BytesIO(modified.getvalue()), spin_count=1000
    )
    result = _sync(tmp_path, encrypted)
    assert result.features["content_access"] == "unavailable"
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert result.extracted_artifacts == []


def test_zip_expansion_is_bounded_even_for_authenticated_plaintext(tmp_path):
    result = _sync(
        tmp_path,
        build_office_password_fixture("agile-aes256-docx"),
        maximum_expanded=100,
    )
    assert result.features["limit_reason"] == "office_zip_expanded_bytes_limit"
    assert result.extracted_artifacts == []


def test_package_main_part_must_be_a_file_and_use_real_relationship_tag(tmp_path):
    for index, relation_tag in enumerate(("Relationship", "Unrecognized")):
        path = tmp_path / f"invalid-{index}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("word/", b"")
            archive.writestr(
                "[Content_Types].xml",
                (
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Override PartName="/word" ContentType="application/vnd.openxmlformats-'
                    'officedocument.wordprocessingml.document.main+xml"/></Types>'
                ),
            )
            archive.writestr(
                "_rels/.rels",
                (
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    f'<{relation_tag} Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                    'relationships/officeDocument" Target="word"/></Relationships>'
                ),
            )
        with pytest.raises(ValueError):
            _validate_package(path, 100_000)


@pytest.mark.asyncio
async def test_root_output_budget_rejects_before_plaintext_write(office_context):
    context = office_context()
    context.root_budget = InMemoryRootBudget(BudgetLimits(5, 100, 60))
    result = await analyze_encrypted_office(context.file_path, context)
    assert result.errors == ["root_expanded_bytes_limit"]
    assert result.features["resource_limited"] is True
    assert result.extracted_artifacts == []
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.*"))
    snapshot = await context.root_budget.snapshot()
    assert snapshot.used_bytes == 0


def test_reserved_output_charges_high_water_before_each_write():
    stream = io.BytesIO()
    charges = []
    target = _ReservedOutput(stream, lambda *args: charges.append(args), 5)
    assert target.write(b"abc") == 3
    stream.seek(0)
    assert target.write(b"xy") == 2
    assert charges == [("office-decrypted", 1, 3), ("office-decrypted", 1, 3)]
    with pytest.raises(BudgetExceeded, match="document_output_bytes_limit"):
        target.write(b"long")
    assert stream.getvalue() == b"xyc"


def _slow_password(heartbeat):
    def wait_forever(*args):
        while True:
            with heartbeat.open("ab") as stream:
                stream.write(b"x")
            time.sleep(0.01)

    return wait_forever


@pytest.mark.asyncio
async def test_timeout_kills_password_work_and_removes_private_output(
    office_context, tmp_path, monkeypatch
):
    heartbeat = tmp_path / "timeout-heartbeat"
    monkeypatch.setattr(office_decryption, "_load_password_key", _slow_password(heartbeat))
    context = office_context()
    context.analysis_settings = get_settings().model_copy(update={"extraction_timeout": 0.3})
    result = await analyze_encrypted_office(context.file_path, context)
    assert result.errors == ["parser_deadline"]
    assert heartbeat.exists()
    last_size = heartbeat.stat().st_size
    await asyncio.sleep(0.05)
    assert heartbeat.stat().st_size == last_size
    assert not list((Path("/tmp") / context.job_id).rglob("decrypt-*"))


@pytest.mark.asyncio
async def test_cancellation_kills_password_work_and_removes_private_output(
    office_context, tmp_path, monkeypatch
):
    heartbeat = tmp_path / "cancel-heartbeat"
    monkeypatch.setattr(office_decryption, "_load_password_key", _slow_password(heartbeat))
    context = office_context()
    task = asyncio.create_task(analyze_encrypted_office(context.file_path, context))
    async with asyncio.timeout(2):
        while not heartbeat.exists():
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    last_size = heartbeat.stat().st_size
    await asyncio.sleep(0.05)
    assert heartbeat.stat().st_size == last_size
    assert not list((Path("/tmp") / context.job_id).rglob("decrypt-*"))


@pytest.mark.asyncio
async def test_dependency_and_parser_diagnostics_are_sanitized(office_context, monkeypatch, capfd):
    def unsafe_failure(*args):
        print(OFFICE_PASSWORD)
        raise RuntimeError(OFFICE_PASSWORD)

    monkeypatch.setattr(office_decryption, "_load_password_key", unsafe_failure)
    context = office_context()
    result = await analyze_encrypted_office(context.file_path, context)
    assert result.errors == ["Office encrypted package corrupt or unavailable"]
    assert OFFICE_PASSWORD not in repr(result)
    assert OFFICE_PASSWORD not in "".join(capfd.readouterr())


def test_missing_optional_crypto_dependency_is_partial(tmp_path, monkeypatch):
    original_import = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "msoffcrypto.format.ooxml":
            raise ImportError("private diagnostic")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    result = _sync(tmp_path, build_office_password_fixture("agile-aes256-docx"))
    assert result.errors == ["Office decryption dependency unavailable"]
    assert result.features["content_access"] == "unavailable"


@pytest.mark.asyncio
async def test_untrusted_job_identifier_cannot_select_output_directory(office_context):
    context = office_context()
    safe_identifier = context.job_id
    context.job_id = "../escape"
    try:
        result = await analyze_encrypted_office(context.file_path, context)
        assert result.errors == ["Office working directory unavailable"]
    finally:
        context.job_id = safe_identifier
