"""Real-crypto PDF decryption and killable writer boundary regression controls."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import shutil
import stat
import time
import uuid
from pathlib import Path

import pytest
from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
from malscan_worker.analyzers.pdf_decryption import _preserve_xref_objects, _ReservedOutput
from malscan_worker.budget import BudgetLimits, InMemoryRootBudget, reservation_key
from malscan_worker.config import get_settings
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
    DocumentPasswordRequiredError,
    DocumentWrongPasswordError,
)
from malscan_worker.quality.pdf_password_fixtures import (
    PDF_OWNER_PASSWORD,
    PDF_PASSWORD,
    WRONG_PASSWORD,
    build_pdf_password_fixture,
)
from malscan_worker.stages.base import StageContext
from pypdf import PdfReader, PdfWriter
from pypdf.errors import DependencyError


@pytest.fixture
def pdf_context(tmp_path):
    contexts = []

    def create(profile="rc4-40-normal", password=PDF_PASSWORD):
        identifier = str(uuid.uuid4())
        path = tmp_path / (identifier + ".pdf")
        payload = build_pdf_password_fixture(profile)
        path.write_bytes(payload)
        context = StageContext(
            job_id=identifier,
            file_id=identifier,
            storage_key="encrypted-source",
            sha256=hashlib.sha256(payload).hexdigest(),
            original_filename="encrypted.pdf",
            file_path=path,
            archive_password=password,
        )
        contexts.append(context)
        return context

    yield create
    for context in contexts:
        shutil.rmtree(Path("/tmp") / context.job_id, ignore_errors=True)


@pytest.mark.parametrize(
    ("profile", "revision"),
    [
        ("rc4-40-active-actions", 2),
        ("aes-128-active-actions", 4),
        ("aes-256-r5-active-actions", 5),
        ("aes-256-active-actions", 6),
    ],
)
@pytest.mark.asyncio
async def test_real_pdf_decryption_preserves_actions_and_original_identity(
    pdf_context, profile, revision
):
    context = pdf_context(profile)
    original = context.file_path.read_bytes()
    context.root_budget = InMemoryRootBudget(BudgetLimits(5, 1_000_000, 60))
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == []
    assert result.features["encrypted"] is True
    assert result.features["content_access"] == "decrypted_child"
    assert result.features["encryption"]["revision"] == revision
    assert len(result.extracted_artifacts) == 1
    child = result.extracted_artifacts[0]
    assert child["filename"] == "decrypted.pdf"
    assert child["source"] == "pdf-decrypted"
    assert child["budget_key"] == reservation_key(
        context.job_id, "format-analysis", "pdf-decrypted"
    )
    path = Path(child["path"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert hashlib.sha256(path.read_bytes()).hexdigest() == child["sha256"]
    assert path.stat().st_size == child["size"]
    reader = PdfReader(path)
    assert reader.is_encrypted is False
    assert len(reader.pages) == 1
    catalog = reader.trailer["/Root"]
    assert catalog["/OpenAction"]["/S"] == "/JavaScript"
    assert catalog["/AA"]["/O"]["/S"] == "/Launch"
    assert context.file_path.read_bytes() == original
    assert PDF_PASSWORD not in repr(result)
    assert PDF_OWNER_PASSWORD not in repr(result)
    assert "path" not in json.dumps(result.features)
    snapshot = await context.root_budget.snapshot()
    assert snapshot.used_files == 1
    assert snapshot.used_bytes == child["size"]


@pytest.mark.parametrize("profile", ["rc4-40-normal", "aes-128-normal", "aes-256-normal"])
@pytest.mark.parametrize(
    ("password", "exception"),
    [(None, DocumentPasswordRequiredError), (WRONG_PASSWORD, DocumentWrongPasswordError)],
)
@pytest.mark.asyncio
async def test_missing_and_wrong_pdf_passwords_are_explicit_retry_control_flow(
    pdf_context, profile, password, exception
):
    context = pdf_context(profile, password=password)
    with pytest.raises(exception) as raised:
        await PDFAnalyzer().analyze(context.file_path, context)
    assert isinstance(raised.value, (ArchivePasswordRequiredError, ArchiveWrongPasswordError))
    assert raised.value.args == ("pdf",)
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


@pytest.mark.parametrize("profile", ["rc4-40-empty-user", "aes-256-empty-user"])
@pytest.mark.asyncio
async def test_empty_user_password_emits_a_child_without_prompting(pdf_context, profile):
    context = pdf_context(profile, password=None)
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.features["content_access"] == "decrypted_child"
    assert len(result.extracted_artifacts) == 1
    assert PdfReader(result.extracted_artifacts[0]["path"]).is_encrypted is False


@pytest.mark.asyncio
async def test_owner_password_can_unlock_document_content(pdf_context):
    context = pdf_context("aes-128-normal", password=PDF_OWNER_PASSWORD)
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == []
    assert result.features["content_access"] == "decrypted_child"


@pytest.mark.asyncio
async def test_unreferenced_encrypted_stream_survives_for_child_scanners(pdf_context):
    context = pdf_context("aes-128-orphan-stream")
    original = context.file_path.read_bytes()
    assert b"xmrig" not in original
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == []
    coverage = result.features["decryption_object_coverage"]
    assert coverage["status"] == "complete"
    assert coverage["structural_objects_omitted"] == 1
    child_path = Path(result.extracted_artifacts[0]["path"])
    assert b"xmrig synthetic orphan-object review control" in child_path.read_bytes()
    child = PdfReader(child_path)
    assert not child.is_encrypted
    assert "/Encrypt" not in child.trailer
    assert len(child.pages) == 1
    assert context.file_path.read_bytes() == original


@pytest.mark.asyncio
async def test_unreadable_xref_object_retains_available_child_with_partial_coverage(
    pdf_context, monkeypatch
):
    original = PdfReader.get_object

    def unreadable_orphan(self, reference):
        obj = original(self, reference)
        if hasattr(obj, "get_data") and b"xmrig" in obj.get_data():
            raise ValueError("unreadable-" + PDF_PASSWORD)
        return obj

    monkeypatch.setattr(PdfReader, "get_object", unreadable_orphan)
    context = pdf_context("aes-128-orphan-stream")
    result = await PDFAnalyzer().analyze(context.file_path, context)
    coverage = result.features["decryption_object_coverage"]
    assert coverage["status"] == "partial"
    assert coverage["unreadable_or_ambiguous_objects"] == 1
    assert result.errors == [
        "PDF object preservation incomplete: unreadable or ambiguous xref objects"
    ]
    assert len(result.extracted_artifacts) == 1
    assert PDF_PASSWORD not in repr(result)


@pytest.mark.asyncio
async def test_pdf_object_count_limit_cleans_plaintext_output(pdf_context, monkeypatch):
    monkeypatch.setattr("malscan_worker.analyzers.pdf_decryption._MAX_OBJECTS", 2)
    context = pdf_context("aes-128-orphan-stream")
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["pdf_object_count_limit"]
    assert result.features["resource_limited"] is True
    assert result.extracted_artifacts == []
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


def test_compressed_object_index_is_included_in_preservation():
    reader = PdfReader(io.BytesIO(build_pdf_password_fixture("rc4-40-normal")))
    assert reader.decrypt(PDF_PASSWORD)
    # Model pypdf's separate index for an object that came from an ObjStm.
    number = next(iter(reader.xref[0]))
    reader.get_object(number)
    del reader.xref[0][number]
    reader.xref_objStm[number] = (100, 0)
    writer = PdfWriter()
    coverage = _preserve_xref_objects(reader, writer)
    assert coverage["status"] == "complete"
    assert number in writer._id_translated[id(reader)]


def test_conflicting_xref_generations_are_explicitly_incomplete():
    reader = PdfReader(io.BytesIO(build_pdf_password_fixture("rc4-40-normal")))
    assert reader.decrypt(PDF_PASSWORD)
    number = next(iter(reader.xref[0]))
    reader.xref[1] = {number: reader.xref[0][number]}
    coverage = _preserve_xref_objects(reader, PdfWriter())
    assert coverage["status"] == "partial"
    assert coverage["unreadable_or_ambiguous_objects"] == 1


@pytest.mark.parametrize("failure", [NotImplementedError, DependencyError, ValueError])
@pytest.mark.asyncio
async def test_unsupported_crypto_missing_backend_and_corrupt_parser_are_sanitized(
    pdf_context, monkeypatch, capfd, failure
):
    context = pdf_context(password="credential-that-must-not-escape")

    def broken_reader(*args, **kwargs):
        print(context.archive_password)
        raise failure(context.archive_password)

    monkeypatch.setattr("malscan_worker.analyzers.pdf_analyzer.PdfReader", broken_reader)
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["failed to parse PDF file: corrupt or unsupported PDF data"]
    assert result.features["content_access"] == "unavailable"
    assert result.features["encrypted"] is None
    assert result.extracted_artifacts == []
    captured = capfd.readouterr()
    assert context.archive_password not in captured.out + captured.err + repr(result)


@pytest.mark.asyncio
async def test_actual_corrupt_pdf_is_incomplete_without_a_password_prompt(pdf_context):
    context = pdf_context()
    context.file_path.write_bytes(b"%PDF-1.7\nnot-a-PDF\n")
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors
    assert result.extracted_artifacts == []
    assert result.features["content_access"] == "unavailable"
    assert result.features["encrypted"] is None


@pytest.mark.asyncio
async def test_decrypted_output_respects_local_output_byte_limit(pdf_context):
    context = pdf_context()
    context.analysis_settings = get_settings().model_copy(
        update={"extraction_max_single_bytes": 100}
    )
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["document_output_bytes_limit"]
    assert result.features["resource_limited"] is True
    assert result.features["encrypted"] is True
    assert result.extracted_artifacts == []
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


@pytest.mark.asyncio
async def test_shared_root_byte_budget_rejects_before_more_output_is_written(pdf_context):
    context = pdf_context()
    context.root_budget = InMemoryRootBudget(BudgetLimits(5, 30, 60))
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.features["resource_limited"] is True
    assert result.errors == ["root_expanded_bytes_limit"]
    assert result.extracted_artifacts == []
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))
    snapshot = await context.root_budget.snapshot()
    assert snapshot.used_bytes <= 30


@pytest.mark.asyncio
async def test_shared_root_file_budget_rejects_before_plaintext_file_creation(pdf_context):
    context = pdf_context()
    context.root_budget = InMemoryRootBudget(BudgetLimits(1, 100_000, 60))
    await context.root_budget.reserve("previous-child", 1, 1)
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["root_file_limit"]
    assert result.extracted_artifacts == []
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


@pytest.mark.asyncio
async def test_depth_limit_prevents_password_prompt_and_plaintext_output(pdf_context):
    context = pdf_context(password=None)
    context.depth = 3
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["max_depth"]
    assert result.features["resource_limited"] is True
    assert result.extracted_artifacts == []


def test_writer_reserves_high_water_bytes_before_each_write():
    stream = io.BytesIO()
    reservations = []

    def reserve(origin, files, size):
        reservations.append((origin, files, size, stream.getvalue()))

    writer = _ReservedOutput(stream, reserve, 100)
    writer.write(b"PDF")
    writer.write(b"bytes")
    assert reservations == [
        ("pdf-decrypted", 1, 3, b""),
        ("pdf-decrypted", 1, 8, b"PDF"),
    ]
    assert stream.getvalue() == b"PDFbytes"


def _slow_writer(heartbeat):
    def write(self, stream):
        del self
        while True:
            stream.write(b"plaintext-output")
            stream.flush()
            with heartbeat.open("ab") as pulse:
                pulse.write(b".")
            time.sleep(0.01)

    return write


@pytest.mark.asyncio
async def test_timeout_kills_pdf_writer_and_removes_partial_plaintext(
    pdf_context, tmp_path, monkeypatch
):
    heartbeat = tmp_path / "timeout-writer-heartbeat"
    monkeypatch.setattr(
        "malscan_worker.analyzers.pdf_decryption.PdfWriter.write", _slow_writer(heartbeat)
    )
    context = pdf_context()
    context.analysis_settings = get_settings().model_copy(update={"extraction_timeout": 0.2})
    result = await PDFAnalyzer().analyze(context.file_path, context)
    assert result.errors == ["parser_deadline"]
    assert heartbeat.exists()
    last_size = heartbeat.stat().st_size
    await asyncio.sleep(0.05)
    assert heartbeat.stat().st_size == last_size
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


@pytest.mark.asyncio
async def test_cancellation_kills_pdf_writer_and_removes_partial_plaintext(
    pdf_context, tmp_path, monkeypatch
):
    heartbeat = tmp_path / "cancel-writer-heartbeat"
    monkeypatch.setattr(
        "malscan_worker.analyzers.pdf_decryption.PdfWriter.write", _slow_writer(heartbeat)
    )
    context = pdf_context()
    task = asyncio.create_task(PDFAnalyzer().analyze(context.file_path, context))
    async with asyncio.timeout(2):
        while not heartbeat.exists():
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    last_size = heartbeat.stat().st_size
    await asyncio.sleep(0.05)
    assert heartbeat.stat().st_size == last_size
    assert not list((Path("/tmp") / context.job_id).rglob("decrypted.pdf"))


@pytest.mark.asyncio
async def test_untrusted_job_identifier_cannot_select_a_working_directory(pdf_context):
    context = pdf_context()
    safe_identifier = context.job_id
    context.job_id = "../unsafe-path"
    try:
        result = await PDFAnalyzer().analyze(context.file_path, context)
        assert result.errors == ["PDF working directory unavailable"]
        assert result.extracted_artifacts == []
    finally:
        context.job_id = safe_identifier
