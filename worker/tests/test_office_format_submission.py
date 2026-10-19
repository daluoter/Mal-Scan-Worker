"""Office plaintext is available only after verified child submission."""

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from malscan_worker.analyzers.base import AnalyzerResult
from malscan_worker.budget import BudgetLimits, InMemoryRootBudget, reservation_key
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.format_analysis import FormatAnalysisStage


class Services:
    max_depth = 3

    def __init__(self, response):
        self.response = response
        self.calls = []

    async def submit_child(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def _office_analysis(output, data):
    digest = hashlib.sha256(data).hexdigest()
    return AnalyzerResult(
        analyzer_name="office",
        format_type="OFFICE",
        extracted_artifacts=[
            {
                "path": str(output),
                "filename": "decrypted.docx",
                "source": "office-decrypted",
                "sha256": digest,
                "size": len(data),
            }
        ],
        features={
            "encrypted": True,
            "content_access": "decrypted_child",
            "decrypted_child": {"sha256": digest, "size": len(data)},
        },
    )


def _stage(monkeypatch, analysis):
    class Analyzer:
        name = "office"

        async def analyze(self, path, ctx):
            return analysis

    stage = FormatAnalysisStage()
    monkeypatch.setattr(stage, "_registry", SimpleNamespace(detect=lambda *args: Analyzer()))
    return stage


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "none",
        "no_context",
        "no_child",
        "missing",
        "wrong_hash",
        "wrong_size",
        "missing_hash",
        "child_identity",
        "port_error",
        "no_artifact",
        "source_identity",
        "symlink",
        "wrong_source",
        "cancelled",
    ],
)
async def test_office_plaintext_submission_verifies_identity_and_cleans_local_bytes(
    tmp_path, monkeypatch, caplog, failure
):
    password = "office-private-credential"
    source = tmp_path / "encrypted.bin"
    ciphertext = b"encrypted immutable fixture"
    source.write_bytes(ciphertext)
    output = tmp_path / "decrypted.docx"
    data = b"PK plaintext fixture"
    output.write_bytes(data)
    analysis = _office_analysis(output, data)
    artifact = analysis.extracted_artifacts[0]
    if failure == "missing":
        output.unlink()
    elif failure == "wrong_hash":
        artifact["sha256"] = analysis.features["decrypted_child"]["sha256"] = "0" * 64
    elif failure == "wrong_size":
        artifact["size"] = analysis.features["decrypted_child"]["size"] = len(data) + 1
    elif failure == "missing_hash":
        artifact.pop("sha256")
        analysis.features["decrypted_child"].pop("sha256")
    elif failure == "child_identity":
        analysis.features["decrypted_child"]["sha256"] = "0" * 64
    elif failure == "no_artifact":
        output.unlink()
        analysis.extracted_artifacts = []
    elif failure == "source_identity":
        output.unlink()
        artifact.update(
            path=str(source), sha256=hashlib.sha256(ciphertext).hexdigest(), size=len(ciphertext)
        )
        analysis.features["decrypted_child"] = {
            "sha256": artifact["sha256"],
            "size": len(ciphertext),
        }
    elif failure == "symlink":
        output.unlink()
        output.symlink_to(source)
    elif failure == "wrong_source":
        artifact["source"] = "unverified-child"
        output.unlink()
    child_id = str(uuid4())
    response = (
        None
        if failure == "no_child"
        else RuntimeError(password)
        if failure == "port_error"
        else asyncio.CancelledError()
        if failure == "cancelled"
        else child_id
    )
    services = Services(response)
    job_id = str(uuid4())
    budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=1000))
    key = reservation_key(job_id, "format-analysis", "office-decrypted")
    await budget.reserve(key, 1, len(data))
    # The submit path must use the same canonical reservation as the writer.
    artifact["budget_key"] = "analyzer-metadata-cannot-charge-a-second-reservation"
    ctx = StageContext(
        job_id,
        job_id,
        "source",
        hashlib.sha256(ciphertext).hexdigest(),
        source.name,
        source,
        archive_password=password,
        artifact_id=job_id,
        root_artifact_id=job_id,
        root_job_id=job_id,
        root_budget=budget,
        analysis_services=None if failure == "no_context" else services,
    )
    stage = _stage(monkeypatch, analysis)
    if failure == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await stage.execute(ctx)
    else:
        outcome = await stage.execute(ctx)
        assert password not in json.dumps(outcome.findings)
        child = outcome.findings["features"]["decrypted_child"]
        if failure == "none":
            assert outcome.status == "ok"
            assert outcome.findings["features"]["content_access"] == "decrypted_child"
            assert child["artifact_ids"] == outcome.artifacts == [child_id]
            assert child["analysis_state"] == "submitted"
            assert services.calls[0]["origin_path"] == "office-decrypted"
            assert services.calls[0]["sha256_hash"] == hashlib.sha256(data).hexdigest()
            snapshot = await budget.snapshot()
            assert (snapshot.used_files, snapshot.used_bytes) == (1, len(data))
        else:
            assert outcome.status == "partial"
            assert outcome.findings["features"]["content_access"] == "unavailable"
            assert not outcome.artifacts
            assert child["analysis_state"] == "not_submitted"
            assert "decrypted_office_child_not_submitted" in outcome.findings["errors"]
        if failure not in {"none", "no_child", "port_error"}:
            assert not services.calls
    assert password not in caplog.text
    assert source.read_bytes() == ciphertext
    assert not output.exists() and not output.is_symlink()


@pytest.mark.asyncio
async def test_office_database_record_requires_a_queued_plaintext_job(tmp_path, monkeypatch):
    source = tmp_path / "encrypted.docx"
    source.write_bytes(b"ciphertext")
    output = tmp_path / "decrypted.docx"
    data = b"PK plaintext"
    output.write_bytes(data)
    analysis = _office_analysis(output, data)
    artifact_id = str(uuid4())

    async def create(**kwargs):
        return {"id": artifact_id}

    class Submitter:
        async def submit_subjob(self, **kwargs):
            return None

    async def submitter():
        return Submitter()

    monkeypatch.setattr("malscan_worker.stages.format_analysis.create_artifact", create)
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance", submitter
    )
    ctx = StageContext(
        "job",
        "file",
        "source",
        "a" * 64,
        source.name,
        source,
        job=SimpleNamespace(id=uuid4(), depth=0, created_at=datetime.now(timezone.utc)),
        artifact_id="parent",
        root_artifact_id="root",
        root_job_id="job",
    )
    outcome = await _stage(monkeypatch, analysis).execute(ctx)
    assert outcome.status == "partial"
    assert outcome.artifacts == [artifact_id]
    assert outcome.findings["sub_jobs_created"] == 0
    assert outcome.findings["features"]["content_access"] == "unavailable"
    child = outcome.findings["features"]["decrypted_child"]
    assert child["analysis_state"] == "submission_failed"
    assert "decrypted_office_child_not_submitted" in outcome.findings["errors"]
    assert not output.exists()
