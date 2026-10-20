"""Embedded bytes must have verified identities and real child submission evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from malscan_worker.budget import BudgetLimits, InMemoryRootBudget, reservation_key
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from pypdf import PdfWriter


def _context(source: Path, *, services=None, with_job=False) -> StageContext:
    identifier = str(uuid4())
    return StageContext(
        identifier,
        identifier,
        "source",
        hashlib.sha256(source.read_bytes()).hexdigest(),
        source.name,
        source,
        analysis_services=services,
        job=SimpleNamespace(id=identifier, depth=0) if with_job else None,
        artifact_id="parent-occurrence",
        root_artifact_id="root-occurrence",
        root_job_id=identifier,
    )


def _artifact(path: Path, source: str, data: bytes = b"embedded fixture bytes") -> dict:
    path.write_bytes(data)
    return {
        "filename": "attachment.bin",
        "source": source,
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "analysis_state": "not_submitted",
    }


class _Services:
    max_depth = 3

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    async def submit_child(self, **kwargs):
        # The port consumes immutable bytes before the stage clears its temporary output.
        self.calls.append({**kwargs, "observed_bytes": Path(kwargs["file_path"]).read_bytes()})
        response = self.responses.pop(0) if self.responses else str(uuid4())
        if isinstance(response, BaseException):
            raise response
        return response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("analyzer", "origin"),
    [
        ("pdf", "pdf-attachment/0"),
        ("office", "ooxml_embed_word/embeddings/payload.pdf"),
        ("office", "ole-native/0"),
    ],
)
@pytest.mark.parametrize(
    "failure", ["none", "hash", "size", "no_hash", "no_size", "symlink", "source", "missing"]
)
async def test_submission_rejects_unverified_document_bytes(tmp_path, analyzer, origin, failure):
    source = tmp_path / "source.bin"
    source.write_bytes(b"original document bytes")
    output = tmp_path / "output.bin"
    artifact = _artifact(output, origin)
    if failure == "hash":
        artifact["sha256"] = "0" * 64
    elif failure == "size":
        artifact["size"] += 1
    elif failure == "no_hash":
        artifact.pop("sha256")
    elif failure == "no_size":
        artifact.pop("size")
    elif failure == "symlink":
        output.unlink()
        output.symlink_to(source)
        artifact.update(
            size=source.stat().st_size, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
        )
    elif failure == "source":
        artifact.update(
            path=str(source),
            size=source.stat().st_size,
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )
    elif failure == "missing":
        output.unlink()
    services = _Services("child-id")
    ctx = _context(source, services=services)
    submitted, identifiers, errors = await FormatAnalysisStage()._submit_artifacts(
        ctx, [artifact], analyzer
    )
    assert source.read_bytes() == b"original document bytes"
    if failure == "none":
        assert (submitted, identifiers, errors) == (1, ["child-id"], [])
        assert artifact["analysis_state"] == "submitted"
        assert artifact["artifact_id"] == "child-id"
        assert services.calls[0]["origin_path"] == origin
        assert services.calls[0]["observed_bytes"] == b"embedded fixture bytes"
    else:
        assert submitted == 0 and identifiers == []
        assert not services.calls
        assert artifact["analysis_state"] == "not_submitted"


@pytest.mark.asyncio
async def test_shared_reservation_and_distinct_same_byte_occurrences(tmp_path):
    source = tmp_path / "source.pdf"
    source.write_bytes(b"source")
    services = _Services("child-0", "child-1")
    ctx = _context(source, services=services)
    ctx.root_budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=1000))
    artifacts = [
        _artifact(tmp_path / f"output-{index}.bin", f"pdf-attachment/{index}") for index in range(2)
    ]
    for artifact in artifacts:
        key = reservation_key(ctx.job_id, "format-analysis", artifact["source"])
        artifact["budget_key"] = key
        await ctx.root_budget.reserve(key, 1, artifact["size"])
    submitted, identifiers, errors = await FormatAnalysisStage()._submit_artifacts(
        ctx, artifacts, "pdf"
    )
    assert (submitted, identifiers, errors) == (2, ["child-0", "child-1"], [])
    assert [artifact["analysis_state"] for artifact in artifacts] == ["submitted", "submitted"]
    assert [call["origin_path"] for call in services.calls] == [
        "pdf-attachment/0",
        "pdf-attachment/1",
    ]
    snapshot = await ctx.root_budget.snapshot()
    assert snapshot.used_files == 2
    assert snapshot.used_bytes == sum(artifact["size"] for artifact in artifacts)


@pytest.mark.asyncio
async def test_service_failure_preserves_good_siblings_and_sanitizes_error(tmp_path, caplog):
    source = tmp_path / "source.pdf"
    source.write_bytes(b"source")
    secret_message = "private-password-not-for-report"
    services = _Services("first-child", RuntimeError(secret_message), "last-child")
    ctx = _context(source, services=services)
    artifacts = [
        _artifact(tmp_path / f"output-{index}.bin", f"pdf-attachment/{index}", bytes([index]))
        for index in range(3)
    ]
    submitted, identifiers, errors = await FormatAnalysisStage()._submit_artifacts(
        ctx, artifacts, "pdf"
    )
    assert submitted == 2 and identifiers == ["first-child", "last-child"]
    assert len(services.calls) == 3
    assert [artifact["analysis_state"] for artifact in artifacts] == [
        "submitted",
        "not_submitted",
        "submitted",
    ]
    assert errors and secret_message not in json.dumps(errors)
    assert secret_message not in caplog.text


@pytest.mark.asyncio
async def test_database_records_keep_duplicate_occurrences_without_double_queue(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    ctx = _context(source, with_job=True)
    records, queued = [], []

    async def create(**kwargs):
        records.append(kwargs)
        return {"id": f"record-{len(records)}"}

    class Submitter:
        async def submit_subjob(self, **kwargs):
            queued.append(kwargs)
            return f"queue-{len(queued)}"

    async def submitter():
        return Submitter()

    monkeypatch.setattr("malscan_worker.stages.format_analysis.create_artifact", create)
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance", submitter
    )
    artifacts = [
        _artifact(tmp_path / f"output-{index}.bin", f"ole-native/{index}") for index in range(2)
    ]
    submitted, identifiers, errors = await FormatAnalysisStage()._submit_artifacts(
        ctx, artifacts, "office"
    )
    assert (submitted, identifiers, errors) == (1, ["record-1", "record-2"], [])
    assert len(queued) == 1
    assert records[0]["parent_id"] == records[1]["parent_id"] == "parent-occurrence"
    assert records[0]["origin_path"] != records[1]["origin_path"]
    assert records[1]["verdict"] == "skipped"
    assert records[1]["extraction_note"] == "duplicate_within_extraction"
    assert artifacts[1]["analysis_state"] == "skipped_duplicate"


@pytest.mark.asyncio
@pytest.mark.parametrize("first_failure", ["wrong_size", "queue_none", "queue_error"])
async def test_unanalyzed_first_output_cannot_suppress_identical_valid_sibling(
    tmp_path, monkeypatch, first_failure
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    ctx = _context(source, with_job=True)
    artifacts = [
        _artifact(tmp_path / f"output-{index}.bin", f"ole-native/{index}") for index in range(2)
    ]
    if first_failure == "wrong_size":
        artifacts[0]["size"] += 1
    records, queued = [], []

    async def create(**kwargs):
        records.append(kwargs)
        return {"id": f"record-{len(records)}"}

    class Submitter:
        async def submit_subjob(self, **kwargs):
            queued.append(kwargs)
            if len(queued) == 1 and first_failure == "queue_none":
                return None
            if len(queued) == 1 and first_failure == "queue_error":
                raise RuntimeError("private queue details")
            return "valid-child"

    async def submitter():
        return Submitter()

    monkeypatch.setattr("malscan_worker.stages.format_analysis.create_artifact", create)
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance", submitter
    )
    submitted, _, _ = await FormatAnalysisStage()._submit_artifacts(ctx, artifacts, "office")
    assert submitted == 1
    assert artifacts[0]["analysis_state"] == "not_submitted"
    assert artifacts[1]["analysis_state"] == "submitted"
    assert records[-1]["origin_path"] == "ole-native/1"
    assert records[-1]["verdict"] is None


def _pdf_with_attachment(path, data=b"harmless embedded text"):
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.add_attachment("receipt.txt", data)
    with path.open("wb") as handle:
        writer.write(handle)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response", ["child-id", None, RuntimeError("private port detail"), "no-context"]
)
async def test_real_pdf_extraction_public_submission_evidence_and_cleanup(tmp_path, response):
    source = tmp_path / "source.pdf"
    _pdf_with_attachment(source)
    original = source.read_bytes()
    services = None if response == "no-context" else _Services(response)
    ctx = _context(source, services=services)
    outcome = await FormatAnalysisStage().execute(ctx)
    assert source.read_bytes() == original
    outputs = outcome.findings["extracted_outputs"]
    assert len(outputs) == 1
    assert outputs[0]["source"] == "pdf-attachment/0000"
    assert outputs[0]["sha256"] == hashlib.sha256(b"harmless embedded text").hexdigest()
    assert outputs[0]["size"] == len(b"harmless embedded text")
    assert "path" not in outputs[0]
    assert "private port detail" not in json.dumps(outcome.findings)
    attachment = outcome.findings["features"]["embedded_files"][0]
    if response == "child-id":
        assert outcome.status == "ok"
        assert outcome.artifacts == ["child-id"]
        assert outputs[0]["artifact_id"] == attachment["artifact_id"] == "child-id"
        assert outputs[0]["analysis_state"] == attachment["analysis_state"] == "submitted"
    else:
        assert outcome.status == "partial"
        assert outcome.artifacts == []
        assert outputs[0]["analysis_state"] == attachment["analysis_state"] == "not_submitted"
    assert not any(
        item.is_file() or item.is_symlink()
        for item in (Path("/tmp") / ctx.job_id / "pdf_artifacts").rglob("*")
    )
    if services and services.calls:
        assert services.calls[0]["observed_bytes"] == b"harmless embedded text"
        assert not Path(services.calls[0]["file_path"]).exists()


@pytest.mark.asyncio
async def test_real_pdf_cancellation_removes_all_extracted_outputs(tmp_path):
    source = tmp_path / "source.pdf"
    _pdf_with_attachment(source)
    original = source.read_bytes()
    services = _Services(asyncio.CancelledError())
    ctx = _context(source, services=services)
    with pytest.raises(asyncio.CancelledError):
        await FormatAnalysisStage().execute(ctx)
    assert services.calls and not Path(services.calls[0]["file_path"]).exists()
    assert source.read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("file_limit", [1, 2])
async def test_format_and_document_occurrences_have_separate_root_budget_grants(
    tmp_path, file_limit
):
    from malscan_worker.quality.document_embedded_fixtures import (
        build_document_embedded_fixture,
        embedded_fixture_payloads,
    )
    from malscan_worker.stages.document_analysis import DocumentAnalysisStage

    source = tmp_path / "embedded.docx"
    source.write_bytes(build_document_embedded_fixture("office-embedded-pdf"))
    services = _Services()
    ctx = _context(source, services=services)
    ctx.root_budget = InMemoryRootBudget(BudgetLimits(max_files=file_limit, max_bytes=10_000))
    first = await FormatAnalysisStage().execute(ctx)
    assert first.status == "ok"
    ctx.previous_results = [first]
    second = await DocumentAnalysisStage().execute(ctx)
    snapshot = await ctx.root_budget.snapshot()
    expected_size = len(embedded_fixture_payloads("office-embedded-pdf")[0])
    if file_limit == 1:
        assert second.status == "partial"
        assert "root_file_limit" in second.findings["errors"]
        assert len(services.calls) == 1
    else:
        assert second.status == "ok"
        assert len(services.calls) == 2
    assert (snapshot.used_files, snapshot.used_bytes) == (file_limit, file_limit * expected_size)
