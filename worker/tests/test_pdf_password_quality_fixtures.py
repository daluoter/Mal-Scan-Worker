"""Real PDF encryption controls use fixed public fixture passwords, never mocks."""

from __future__ import annotations

import hashlib
import io

import pytest
import pyzipper
from malscan_worker.quality.pdf_password_fixtures import (
    ARCHIVE_PASSWORD,
    PDF_OWNER_PASSWORD,
    PDF_PASSWORD,
    PDF_PASSWORD_PROFILES,
    WRONG_PASSWORD,
    build_pdf_password_fixture,
)
from pypdf import PdfReader
from pypdf.errors import FileNotDecryptedError


@pytest.mark.parametrize("profile", PDF_PASSWORD_PROFILES)
def test_password_fixture_is_stable_small_and_pinned(profile: str) -> None:
    first = build_pdf_password_fixture(profile)
    assert first == build_pdf_password_fixture(profile)
    assert len(first) < 10_000
    assert len(hashlib.sha256(first).hexdigest()) == 64
    for password in (PDF_PASSWORD, PDF_OWNER_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD):
        assert password.encode() not in first


def test_password_fixture_rejects_unknown_recipe() -> None:
    with pytest.raises(ValueError, match="profile"):
        build_pdf_password_fixture("unknown")
    with pytest.raises(ValueError, match="version"):
        build_pdf_password_fixture("aes-128-normal", recipe_version=2)


@pytest.mark.parametrize("profile", [p for p in PDF_PASSWORD_PROFILES if not p.startswith("zip-")])
def test_actual_pdf_encryption_requires_and_accepts_expected_password(profile: str) -> None:
    payload = build_pdf_password_fixture(profile)
    reader = PdfReader(io.BytesIO(payload))
    assert reader.is_encrypted
    assert reader.decrypt(WRONG_PASSWORD) == 0
    if not profile.endswith("empty-user"):
        with pytest.raises(FileNotDecryptedError):
            len(reader.pages)
    password = "" if profile.endswith("empty-user") else PDF_PASSWORD
    assert reader.decrypt(password) == 1
    assert len(reader.pages) == 1
    root = reader.trailer["/Root"]
    if "active-actions" in profile:
        assert root["/OpenAction"]["/JS"] == "void 0;"
        assert root["/AA"]["/O"]["/F"] == "quality-fixture-never-execute.txt"
        assert b"void 0;" not in payload
    else:
        assert "/OpenAction" not in root
        assert "/AA" not in root
    owner_reader = PdfReader(io.BytesIO(payload))
    assert owner_reader.decrypt(PDF_OWNER_PASSWORD) == 2
    assert len(owner_reader.pages) == 1
    encryption = reader.trailer["/Encrypt"]
    if profile.startswith("rc4"):
        assert (encryption["/V"], encryption["/R"], encryption["/Length"]) == (1, 2, 40)
    elif profile.startswith("aes-128"):
        assert (encryption["/V"], encryption["/R"], encryption["/Length"]) == (4, 4, 128)
    else:
        revision = 5 if profile.startswith("aes-256-r5") else 6
        assert (encryption["/V"], encryption["/R"], encryption["/Length"]) == (5, revision, 256)


def test_nested_archive_and_pdf_require_distinct_real_passwords() -> None:
    payload = build_pdf_password_fixture("zip-aes-pdf-aes-128")
    with pyzipper.AESZipFile(io.BytesIO(payload)) as archive:
        assert archive.namelist() == ["nested/locked.pdf"]
        with pytest.raises(RuntimeError):
            archive.read("nested/locked.pdf", pwd=PDF_PASSWORD.encode())
        inner = archive.read("nested/locked.pdf", pwd=ARCHIVE_PASSWORD.encode())
    assert inner == build_pdf_password_fixture("aes-128-active-actions")
    reader = PdfReader(io.BytesIO(inner))
    assert reader.decrypt(ARCHIVE_PASSWORD) == 0
    assert reader.decrypt(PDF_PASSWORD) == 1
    assert reader.trailer["/Root"]["/OpenAction"]["/JS"] == "void 0;"
