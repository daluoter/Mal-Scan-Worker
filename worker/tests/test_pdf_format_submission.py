"""Unlocking cannot masquerade as scanning when plaintext submission fails."""

import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from malscan_worker.analyzers.base import AnalyzerResult
from malscan_worker.budget import BudgetLimits, InMemoryRootBudget, reservation_key
from malscan_worker.exceptions import DocumentPasswordRequiredError, DocumentWrongPasswordError
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.format_analysis import FormatAnalysisStage


class Services:
    max_depth = 3

    def __init__(self, response):
        self.response = response
        self.calls = []

    async def submit_child(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["no_context", "no_child", "wrong_hash", "wrong_size", "missing", "port_error", "none"],
)
async def test_plaintext_requires_a_valid_linked_analysis_child(
    tmp_path, monkeypatch, caplog, failure
):
    job_id = str(uuid4())
    password = "private-pdf-password-do-not-publish"
    source = tmp_path / "encrypted.pdf"
    source.write_bytes(b"encrypted placeholder")
    output = tmp_path / "decrypted.pdf"
    data = b"%PDF-1.4 plaintext"
    output.write_bytes(data)
    key = reservation_key(job_id, "format-analysis", "pdf-decrypted")
    artifact = {
        "path": str(output),
        "filename": "decrypted.pdf",
        "source": "pdf-decrypted",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "budget_key": key,
    }
    if failure == "wrong_hash":
        artifact["sha256"] = "0" * 64
    elif failure == "wrong_size":
        artifact["size"] += 1
    elif failure == "missing":
        output.unlink()
    result = AnalyzerResult(
        analyzer_name="pdf",
        format_type="PDF",
        extracted_artifacts=[artifact],
        features={
            "encrypted": True,
            "content_access": "decrypted_child",
            "decrypted_child": {"sha256": artifact["sha256"], "size": artifact["size"]},
        },
    )

    class Analyzer:
        name = "pdf"

        async def analyze(self, path, context):
            return result

    stage = FormatAnalysisStage()
    monkeypatch.setattr(stage, "_registry", SimpleNamespace(detect=lambda *args: Analyzer()))
    expected_child = str(uuid4())
    response = (
        None
        if failure == "no_child"
        else RuntimeError(password)
        if failure == "port_error"
        else expected_child
    )
    services = Services(response)
    budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=1000))
    # The bounded writer and submission share a single high-water reservation.
    await budget.reserve(key, 1, len(data))
    ctx = StageContext(
        job_id=job_id,
        file_id=job_id,
        storage_key="source",
        sha256="a" * 64,
        original_filename="encrypted.pdf",
        file_path=source,
        archive_password=password,
        artifact_id=job_id,
        root_artifact_id=job_id,
        root_job_id=job_id,
        root_budget=budget,
        analysis_services=None if failure == "no_context" else services,
    )
    outcome = await stage.execute(ctx)
    assert password not in json.dumps(outcome.findings)
    assert password not in caplog.text
    child = outcome.findings["features"]["decrypted_child"]
    if failure == "none":
        assert outcome.status == "ok"
        assert outcome.artifacts == child["artifact_ids"] == [expected_child]
        assert child["analysis_state"] == "submitted"
        assert services.calls[0]["sha256_hash"] == hashlib.sha256(data).hexdigest()
        assert services.calls[0]["origin_path"] == "pdf-decrypted"
        snapshot = await budget.snapshot()
        assert snapshot.used_files == 1
        assert snapshot.used_bytes == len(data)
    else:
        assert outcome.status == "partial"
        assert not outcome.artifacts
        assert child["analysis_state"] == "not_submitted"
        assert "decrypted_pdf_child_not_submitted" in outcome.findings["errors"]
        if failure in {"no_context", "wrong_hash", "wrong_size", "missing"}:
            assert not services.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_type", [DocumentPasswordRequiredError, DocumentWrongPasswordError]
)
async def test_pdf_password_challenge_reaches_the_checkpointing_pipeline(
    tmp_path, monkeypatch, exception_type
):
    source = tmp_path / "locked.pdf"
    source.write_bytes(b"%PDF-1.4 locked")

    class Analyzer:
        name = "pdf"

        async def analyze(self, path, ctx):
            raise exception_type("pdf")

    stage = FormatAnalysisStage()
    monkeypatch.setattr(stage, "_registry", SimpleNamespace(detect=lambda *args: Analyzer()))
    ctx = StageContext("job", "file", "source", "a" * 64, "locked.pdf", source)
    with pytest.raises(exception_type):
        await stage.execute(ctx)


@pytest.mark.asyncio
async def test_database_artifact_without_queued_plaintext_job_is_incomplete(tmp_path, monkeypatch):
    source = tmp_path / "encrypted.pdf"
    source.write_bytes(b"ciphertext")
    output = tmp_path / "decrypted.pdf"
    data = b"%PDF-1.4 plaintext"
    output.write_bytes(data)
    artifact_id = str(uuid4())

    class Analyzer:
        name = "pdf"

        async def analyze(self, path, ctx):
            return AnalyzerResult(
                analyzer_name="pdf",
                format_type="PDF",
                features={
                    "encrypted": True,
                    "content_access": "decrypted_child",
                    "decrypted_child": {"sha256": hashlib.sha256(data).hexdigest()},
                },
                extracted_artifacts=[
                    {
                        "path": str(output),
                        "filename": "decrypted.pdf",
                        "source": "pdf-decrypted",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                ],
            )

    async def create(**kwargs):
        return {"id": artifact_id}

    class Submitter:
        async def submit_subjob(self, **kwargs):
            return None

    async def submitter():
        return Submitter()

    stage = FormatAnalysisStage()
    monkeypatch.setattr(stage, "_registry", SimpleNamespace(detect=lambda *args: Analyzer()))
    monkeypatch.setattr("malscan_worker.stages.format_analysis.create_artifact", create)
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance", submitter
    )
    ctx = StageContext(
        "job",
        "file",
        "source",
        "a" * 64,
        "locked.pdf",
        source,
        job=SimpleNamespace(id=uuid4(), depth=0, created_at=datetime.now(timezone.utc)),
        artifact_id="parent",
        root_artifact_id="root",
        root_job_id="job",
    )
    result = await stage.execute(ctx)
    assert result.status == "partial"
    assert result.artifacts == [artifact_id]
    assert result.findings["sub_jobs_created"] == 0
    assert "decrypted_pdf_child_not_submitted" in result.findings["errors"]
    assert result.findings["features"]["decrypted_child"]["analysis_state"] == "submission_failed"
