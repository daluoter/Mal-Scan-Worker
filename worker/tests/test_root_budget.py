"""Root-tree accounting, resumable reservations, and killable parser boundaries."""
from __future__ import annotations

import asyncio
import io
import os
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from malscan_worker.budget import BudgetExceeded, BudgetLimits, InMemoryRootBudget
from malscan_worker.extractors.base import ExtractionLimits
from malscan_worker.extractors.process import extract_bounded
from malscan_worker.extractors.sevenz_handler import SevenZipHandler
from malscan_worker.extractors.zip_handler import ZipHandler


@pytest.mark.asyncio
async def test_concurrent_descendants_cannot_overspend_root_file_budget():
    budget = InMemoryRootBudget(BudgetLimits(max_files=3, max_bytes=100))
    results = await asyncio.gather(
        *(budget.reserve(f"child-{index}", 1, 10) for index in range(10)),
        return_exceptions=True,
    )
    assert sum(not isinstance(value, Exception) for value in results) == 3
    assert all(
        isinstance(value, BudgetExceeded) for value in results if isinstance(value, Exception)
    )
    snapshot = await budget.snapshot()
    assert (snapshot.used_files, snapshot.used_bytes) == (3, 30)


@pytest.mark.asyncio
async def test_concurrent_byte_limit_rejection_does_not_spend_file_count():
    budget = InMemoryRootBudget(BudgetLimits(max_files=10, max_bytes=25))
    results = await asyncio.gather(
        *(budget.reserve(f"child-{index}", 1, 10) for index in range(5)),
        return_exceptions=True,
    )
    assert sum(not isinstance(value, Exception) for value in results) == 2
    snapshot = await budget.snapshot()
    assert (snapshot.used_files, snapshot.used_bytes) == (2, 20)


@pytest.mark.asyncio
async def test_retry_and_stream_high_water_marks_are_idempotent():
    budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=100))
    await budget.reserve("one-origin", 1, 30)
    await asyncio.gather(*(budget.reserve("one-origin", 1, 30) for _ in range(10)))
    await budget.reserve("one-origin", 1, 10)
    await budget.reserve("one-origin", 1, 40)
    snapshot = await budget.snapshot()
    assert (snapshot.used_files, snapshot.used_bytes) == (1, 40)
    await budget.reserve("second-origin-identical-content", 1, 40)
    assert (await budget.snapshot()).used_files == 2


@pytest.mark.asyncio
async def test_password_resume_opens_time_window_without_resetting_root_counts():
    expired = datetime.now(timezone.utc) - timedelta(seconds=1)
    budget = InMemoryRootBudget(BudgetLimits(max_files=1, max_bytes=100))
    await budget.reserve("existing-output", 1, 50)
    budget.deadline_at = expired
    stored = (await budget.snapshot()).to_dict()
    old_attempt = InMemoryRootBudget.from_snapshot(stored)
    new_attempt = InMemoryRootBudget.from_snapshot(stored, new_attempt=True)
    with pytest.raises(BudgetExceeded, match="analysis_attempt_deadline"):
        await old_attempt.check_deadline()
    await new_attempt.check_deadline()
    await new_attempt.reserve("existing-output", 1, 50)
    with pytest.raises(BudgetExceeded, match="root_file_limit"):
        await new_attempt.reserve("new-child", 1, 1)
    assert (await new_attempt.snapshot()).used_bytes == 50
    with pytest.raises(BudgetExceeded, match="analysis_attempt_deadline"):
        await old_attempt.check_deadline()


@pytest.mark.asyncio
async def test_nested_zip_uses_same_root_bytes_before_writing_child(tmp_path):
    inner_data = io.BytesIO()
    with zipfile.ZipFile(inner_data, "w") as archive:
        archive.writestr("payload.txt", b"payload!")
    inner_bytes = inner_data.getvalue()
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner_bytes)
    budget = InMemoryRootBudget(BudgetLimits(max_files=10, max_bytes=len(inner_bytes) + 4))
    outer_dir, inner_dir = tmp_path / "outer-output", tmp_path / "inner-output"
    outer_dir.mkdir()
    inner_dir.mkdir()
    first = await extract_bounded(
        ZipHandler(), outer, outer_dir, ExtractionLimits(), None, budget, "root-job"
    )
    assert len(first.files) == 1
    second = await extract_bounded(
        ZipHandler(),
        Path(first.files[0].path),
        inner_dir,
        ExtractionLimits(),
        None,
        budget,
        "child-job",
    )
    assert second.resource_limited
    assert second.limit_reason == "root_expanded_bytes_limit"
    assert not list(inner_dir.rglob("payload.txt"))
    snapshot = await budget.snapshot()
    assert (snapshot.used_files, snapshot.used_bytes) == (1, len(inner_bytes))


@pytest.mark.asyncio
async def test_real_7z_writer_accounts_outputs_before_writing(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "sample.7z"
    with py7zr.SevenZipFile(path, "w") as archive:
        archive.writestr(b"one payload", "one.txt")
        archive.writestr(b"two payload", "two.txt")
    output = tmp_path / "out"
    output.mkdir()
    budget = InMemoryRootBudget(BudgetLimits(max_files=1, max_bytes=1000))
    result = await extract_bounded(
        SevenZipHandler(), path, output, ExtractionLimits(), None, budget, "7z-job"
    )
    assert result.resource_limited
    assert result.limit_reason == "root_file_limit"
    assert len(result.files) == 1
    assert Path(result.files[0].path).read_bytes() == b"one payload"
    assert not (output / "two.txt").exists()
    snapshot = await budget.snapshot()
    assert (snapshot.used_files, snapshot.used_bytes) == (1, 11)


class HangingHandler:
    name = "hanging-test"

    def extract(self, path, output, limits, password):
        # A decoder helper in the parser's process group also needs to stop.
        code = """import pathlib, sys, time
p = pathlib.Path(sys.argv[1])
while True:
    with p.open("ab") as handle:
        handle.write(b"x")
    time.sleep(.01)
"""
        subprocess.Popen([sys.executable, "-c", code, str(output / "helper-heartbeat")])
        while True:
            with (output / "parser-heartbeat").open("ab") as handle:
                handle.write(b"x")
            time.sleep(0.01)


@pytest.mark.asyncio
async def test_deadline_stops_parser_and_its_helper_process(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    started = time.monotonic()
    with pytest.raises(BudgetExceeded, match="extraction_deadline"):
        await extract_bounded(
            HangingHandler(),
            tmp_path / "unused",
            output,
            ExtractionLimits(timeout_seconds=0.15),
            None,
            None,
            "hanging-job",
        )
    assert time.monotonic() - started < 1
    sizes = {path.name: path.stat().st_size for path in output.iterdir()}
    assert set(sizes) == {"parser-heartbeat", "helper-heartbeat"}
    await asyncio.sleep(0.08)
    assert {path.name: path.stat().st_size for path in output.iterdir()} == sizes


@pytest.mark.asyncio
async def test_cancellation_stops_extractor_after_task_returns(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    task = asyncio.create_task(
        extract_bounded(
            HangingHandler(),
            tmp_path / "unused",
            output,
            ExtractionLimits(),
            None,
            None,
            "cancelled-job",
        )
    )
    await asyncio.sleep(0.06)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    sizes = {path.name: path.stat().st_size for path in output.iterdir()}
    await asyncio.sleep(0.08)
    assert {path.name: path.stat().st_size for path in output.iterdir()} == sizes


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("MALSCAN_TEST_POSTGRES_URL"), reason="isolated Postgres required")
async def test_postgres_root_accounting_is_atomic_and_persistent():
    from malscan.models.budget import AnalysisBudget, BudgetReservation
    from malscan_worker.budget import PostgresRootBudget
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(os.environ["MALSCAN_TEST_POSTGRES_URL"])
    root_id = uuid.uuid4()
    try:
        async with engine.begin() as connection:
            # This test uses its own disposable database, with only the FK identity table.
            await connection.execute(text("CREATE TABLE IF NOT EXISTS jobs (id UUID PRIMARY KEY)"))
            await connection.run_sync(AnalysisBudget.__table__.create, checkfirst=True)
            await connection.run_sync(BudgetReservation.__table__.create, checkfirst=True)
            await connection.execute(text("INSERT INTO jobs (id) VALUES (:id)"), {"id": root_id})
        limits = BudgetLimits(max_files=3, max_bytes=30)
        handles = await asyncio.gather(
            *(PostgresRootBudget.initialize(engine, str(root_id), limits) for _ in range(5))
        )
        results = await asyncio.gather(
            *(
                handles[index % len(handles)].reserve(f"output-{index}", 1, 10)
                for index in range(10)
            ),
            return_exceptions=True,
        )
        assert sum(not isinstance(value, Exception) for value in results) == 3
        snapshot = await handles[0].snapshot()
        assert (snapshot.used_files, snapshot.used_bytes) == (3, 30)
        resumed = await PostgresRootBudget.initialize(
            engine, str(root_id), BudgetLimits(max_files=100, max_bytes=1000)
        )
        assert resumed.limits == limits
        existing = next(iter(snapshot.reservations))
        await asyncio.gather(*(resumed.reserve(existing, 1, 10) for _ in range(5)))
        assert (await resumed.snapshot()).used_bytes == 30
        with pytest.raises(BudgetExceeded):
            await resumed.reserve("fourth-file", 1, 0)
        async with engine.begin() as connection:
            await connection.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": root_id})
            count = await connection.execute(text("SELECT count(*) FROM budget_reservations"))
            assert count.scalar_one() == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_duplicate_zip_names_preserve_all_content_occurrences(tmp_path):
    path = tmp_path / "duplicate-names.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("same-name.txt", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("same-name.txt", b"second")
        archive.writestr("other-name.txt", b"first")
    output = tmp_path / "out"
    output.mkdir()
    budget = InMemoryRootBudget(BudgetLimits(max_files=3, max_bytes=100))
    result = await extract_bounded(
        ZipHandler(), path, output, ExtractionLimits(), None, budget, "duplicate-zip-job"
    )
    assert [Path(item.path).read_bytes() for item in result.files] == [
        b"first",
        b"second",
        b"first",
    ]
    assert len({item.path for item in result.files}) == 3
    assert [item.origin_path for item in result.files] == [
        "same-name.txt",
        "same-name.txt",
        "other-name.txt",
    ]
    assert (await budget.snapshot()).used_bytes == 16


@pytest.mark.asyncio
async def test_duplicate_7z_names_preserve_content_occurrences(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "duplicate-names.7z"
    with py7zr.SevenZipFile(path, "w") as archive:
        archive.writestr(b"first", "same-name.txt")
        archive.writestr(b"second", "same-name.txt")
    output = tmp_path / "out"
    output.mkdir()
    budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=100))
    result = await extract_bounded(
        SevenZipHandler(), path, output, ExtractionLimits(), None, budget, "duplicate-7z-job"
    )
    assert [Path(item.path).read_bytes() for item in result.files] == [b"first", b"second"]
    assert len({item.path for item in result.files}) == 2
    assert [item.origin_path for item in result.files] == ["same-name.txt", "same-name.txt"]
    assert (await budget.snapshot()).used_bytes == 11


@pytest.mark.asyncio
async def test_real_7z_encrypted_headers_require_password_and_resume(tmp_path):
    from malscan_worker.exceptions import ArchivePasswordRequiredError

    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "encrypted.7z"
    with py7zr.SevenZipFile(
        path, "w", password="fixture-password", header_encryption=True
    ) as archive:
        archive.writestr(b"encrypted payload", "payload.txt")
    output = tmp_path / "out"
    output.mkdir()
    budget = InMemoryRootBudget(BudgetLimits())
    with pytest.raises(ArchivePasswordRequiredError):
        await extract_bounded(
            SevenZipHandler(), path, output, ExtractionLimits(), None, budget, "encrypted-job"
        )
    assert (await budget.snapshot()).used_files == 0
    result = await extract_bounded(
        SevenZipHandler(),
        path,
        output,
        ExtractionLimits(),
        "fixture-password",
        budget,
        "encrypted-job",
    )
    assert len(result.files) == 1
    assert Path(result.files[0].path).read_bytes() == b"encrypted payload"
    assert (await budget.snapshot()).used_files == 1


@pytest.mark.asyncio
async def test_archive_depth_limit_marks_only_archive_coverage_partial(tmp_path):
    from malscan_worker.stages.archive_extract import ArchiveExtractStage
    from malscan_worker.stages.base import StageContext

    archive_path = tmp_path / "nested.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("child.txt", "payload")
    context = StageContext(
        job_id=str(uuid.uuid4()),
        file_id="file",
        storage_key="key",
        sha256="hash",
        original_filename="nested.zip",
        file_path=archive_path,
        depth=3,
    )
    result = await ArchiveExtractStage().execute(context)
    assert result.status == "partial"
    assert result.findings["resource_limited"]
    context.file_path = tmp_path / "leaf.txt"
    context.file_path.write_text("ordinary leaf")
    leaf = await ArchiveExtractStage().execute(context)
    assert leaf.status == "skipped"
    assert leaf.findings["reason"] == "Not an archive"


@pytest.mark.asyncio
async def test_corrupt_zip_never_claims_complete_archive_extraction(tmp_path):
    from malscan_worker.stages.archive_extract import ArchiveExtractStage
    from malscan_worker.stages.base import StageContext

    archive_path = tmp_path / "broken.zip"
    archive_path.write_bytes(b"PK\x03\x04broken content")
    context = StageContext(
        job_id=str(uuid.uuid4()),
        file_id="file",
        storage_key="key",
        sha256="hash",
        original_filename="broken.zip",
        file_path=archive_path,
    )
    result = await ArchiveExtractStage().execute(context)
    assert result.status == "partial"
    assert result.findings["warnings"]
    assert result.findings["sub_jobs_created"] == 0


@pytest.mark.asyncio
async def test_ordinary_zip_is_not_misreported_as_partial_office_document(tmp_path):
    from malscan_worker.stages.base import StageContext
    from malscan_worker.stages.document_analysis import DocumentAnalysisStage, detect_document_type

    archive_path = tmp_path / "ordinary.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.txt", "ordinary archive")
    assert detect_document_type(archive_path, "application/zip") is None
    context = StageContext(
        job_id=str(uuid.uuid4()),
        file_id="file",
        storage_key="key",
        sha256="hash",
        original_filename="ordinary.zip",
        file_path=archive_path,
    )
    result = await DocumentAnalysisStage().execute(context)
    assert result.status == "skipped"
    assert result.findings["reason"] == "Not a supported document format"


@pytest.mark.asyncio
async def test_declared_office_zip_without_package_markers_is_partial(tmp_path):
    from malscan_worker.stages.base import StageContext
    from malscan_worker.stages.document_analysis import DocumentAnalysisStage

    archive_path = tmp_path / "broken.docx"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.txt", "ordinary archive")
    context = StageContext(
        job_id=str(uuid.uuid4()),
        file_id="file",
        storage_key="key",
        sha256="hash",
        original_filename="broken.docx",
        file_path=archive_path,
    )
    result = await DocumentAnalysisStage().execute(context)
    assert result.status == "partial"
    assert any("missing [Content_Types].xml" in error for error in result.findings["errors"])
