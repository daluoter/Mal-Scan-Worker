"""Regression tests for IOC-derived recursive submissions."""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, create_autospec

import pytest
from malscan_worker.budget import BudgetLimits, InMemoryRootBudget
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.utils.submission import InternalJobSubmitter


@pytest.mark.parametrize("caller_db_session", [None, object()], ids=["no-db", "with-db"])
@pytest.mark.asyncio
async def test_ioc_url_subjob_uses_current_submitter_signature(
    caller_db_session: object | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    embedded_url = "https://malicious.example/payload.bin"
    file_path = tmp_path / "sample.txt"
    file_path.write_text(f"Embedded content references {embedded_url}")

    parent_job_id = uuid.uuid4()
    root_artifact_id = str(uuid.uuid4())
    root_job_id = str(uuid.uuid4())
    submitter = create_autospec(InternalJobSubmitter, instance=True, spec_set=True)
    submitter.submit_subjob.return_value = str(uuid.uuid4())
    get_instance = AsyncMock(return_value=submitter)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.InternalJobSubmitter.get_instance",
        get_instance,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )

    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.create_artifact",
        AsyncMock(return_value={"id": str(uuid.uuid4())}),
    )
    context = StageContext(
        job_id=str(parent_job_id),
        file_id=str(uuid.uuid4()),
        storage_key="sample-key",
        sha256="parent-sha256",
        original_filename=file_path.name,
        file_path=file_path,
        job=SimpleNamespace(id=parent_job_id, depth=1),
        db=caller_db_session,
        root_artifact_id=root_artifact_id,
        root_job_id=root_job_id,
        ancestor_hashes={"ancestor-sha256"},
        root_budget=InMemoryRootBudget(BudgetLimits()),
    )

    result = await IocExtractStage().execute(context)

    assert result.status == "ok"
    assert embedded_url in result.findings["urls"]
    assert result.findings["sub_jobs_created"] == 1
    get_instance.assert_awaited_once_with()
    submitter.submit_subjob.assert_awaited_once()

    submitted = submitter.submit_subjob.await_args
    assert submitted is not None
    assert submitted.kwargs["filename"].endswith(".url")
    assert submitted.kwargs["content_type"] == "application/internet-shortcut"
    assert submitted.kwargs["parent_job_id"] == str(parent_job_id)
    assert submitted.kwargs["parent_job_depth"] == 1
    assert submitted.kwargs["root_artifact_id"] == root_artifact_id
    assert submitted.kwargs["root_job_id"] == root_job_id
    assert submitted.kwargs["ancestor_hashes"] == {"ancestor-sha256", "parent-sha256"}
    assert "db" not in submitted.kwargs
    assert "parent_job" not in submitted.kwargs
    assert not Path(submitted.kwargs["file_path"]).exists()


def _context(tmp_path: Path, payload: bytes | None = None) -> StageContext:
    import hashlib

    file_path = tmp_path / "fixture.txt"
    file_path.write_bytes(payload or b"Harmless text references https://payload.invalid/object")
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="fixture",
        sha256=hashlib.sha256(file_path.read_bytes()).hexdigest(),
        original_filename="fixture.txt",
        file_path=file_path,
        root_budget=InMemoryRootBudget(BudgetLimits()),
    )


@pytest.mark.asyncio
async def test_url_observations_do_not_require_synthetic_submissions(tmp_path, monkeypatch):
    context = _context(tmp_path)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.InternalJobSubmitter.get_instance",
        AsyncMock(side_effect=AssertionError("MQ must not be used for static IOC extraction")),
    )
    result = await IocExtractStage().execute(context)
    assert result.status == "ok"
    assert result.findings["urls"] == ["https://payload.invalid/object"]
    assert result.findings["sub_jobs_created"] == 0
    assert result.findings["url_artifact_submission"]["status"] == "disabled"
    assert (await context.root_budget.snapshot()).used_files == 0


@pytest.mark.asyncio
async def test_portable_url_artifact_uses_shared_budget_and_stable_provenance(
    tmp_path, monkeypatch
):
    import hashlib

    context = _context(tmp_path)
    observed = []

    async def submit_child(**kwargs):
        payload = Path(kwargs["file_path"]).read_bytes()
        assert (await context.root_budget.snapshot()).used_files == 1
        assert hashlib.sha256(payload).hexdigest() == kwargs["sha256_hash"]
        assert kwargs["origin_path"].startswith("ioc-url:")
        assert kwargs["extraction_source"] == "ioc-extract"
        assert kwargs["occurrence_index"] == 0
        assert kwargs["parent_job_id"] == context.job_id
        assert kwargs["ancestor_hashes"] == {context.sha256}
        observed.append(kwargs)
        return "derived-artifact"

    context.analysis_services = SimpleNamespace(max_depth=3, submit_child=submit_child)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )
    first = await IocExtractStage().execute(context)
    second = await IocExtractStage().execute(context)
    assert first.status == second.status == "ok"
    assert first.artifacts == ["derived-artifact"]
    assert len(observed) == 2
    assert observed[0]["origin_path"] == observed[1]["origin_path"]
    snapshot = await context.root_budget.snapshot()
    assert snapshot.used_files == 1
    assert snapshot.used_bytes == observed[0]["file_size"]
    assert all(not Path(item["file_path"]).exists() for item in observed)


@pytest.mark.asyncio
async def test_url_budget_rejection_happens_before_temporary_file_creation(tmp_path, monkeypatch):
    context = _context(tmp_path)
    context.root_budget = InMemoryRootBudget(BudgetLimits(max_files=1))
    await context.root_budget.reserve("already-spent", 1, 1)
    submit_child = AsyncMock()
    context.analysis_services = SimpleNamespace(max_depth=3, submit_child=submit_child)
    mkstemp = AsyncMock(side_effect=AssertionError("Must reserve before creating a file"))
    monkeypatch.setattr("malscan_worker.stages.ioc_extract.tempfile.mkstemp", mkstemp)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )
    result = await IocExtractStage().execute(context)
    assert result.status == "partial"
    assert result.findings["reason"] == "root_file_limit"
    assert result.findings["urls"] == ["https://payload.invalid/object"]
    assert "sha256" in result.findings["hashes"]
    assert result.findings["ioc_items"]
    mkstemp.assert_not_called()
    submit_child.assert_not_awaited()


@pytest.mark.asyncio
async def test_shortcut_self_cycle_preserves_ioc_without_more_jobs(tmp_path, monkeypatch):
    payload = b"[InternetShortcut]\nURL=https://payload.invalid/object\n"
    context = _context(tmp_path, payload)
    submit_child = AsyncMock()
    context.analysis_services = SimpleNamespace(max_depth=3, submit_child=submit_child)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )
    result = await IocExtractStage().execute(context)
    assert result.status == "ok"
    assert result.findings["urls"] == ["https://payload.invalid/object"]
    assert result.findings["url_artifact_submission"]["skipped_cycles"] == 1
    assert result.findings["sub_jobs_created"] == 0
    assert (await context.root_budget.snapshot()).used_files == 0
    submit_child.assert_not_awaited()


@pytest.mark.asyncio
async def test_portable_url_submission_failure_keeps_extracted_findings(tmp_path, monkeypatch):
    context = _context(tmp_path)
    failed = AsyncMock(
        side_effect=RuntimeError("provider diagnostic must not replace IOC evidence")
    )
    context.analysis_services = SimpleNamespace(max_depth=3, submit_child=failed)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )
    result = await IocExtractStage().execute(context)
    assert result.status == "partial"
    assert result.findings["urls"]
    assert result.findings["hashes"]["sha256"] == context.sha256
    assert result.findings["reason"] == "url_artifact_submission_failed:RuntimeError"
    temporary = failed.await_args.kwargs["file_path"]
    assert not Path(temporary).exists()


@pytest.mark.asyncio
async def test_url_generation_fails_closed_when_root_budget_is_missing(tmp_path, monkeypatch):
    context = _context(tmp_path)
    context.root_budget = None
    submit_child = AsyncMock()
    context.analysis_services = SimpleNamespace(max_depth=3, submit_child=submit_child)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3, sandbox_enable_url_submission=True),
    )
    result = await IocExtractStage().execute(context)
    assert result.status == "partial"
    assert result.findings["reason"] == "root_budget_unavailable"
    assert result.findings["urls"]
    submit_child.assert_not_awaited()


def test_fresh_standalone_ioc_process_needs_no_backend_credentials(tmp_path):
    import os
    import subprocess
    import sys

    environment = os.environ.copy()
    for key in (
        "DATABASE_URL",
        "RABBITMQ_URL",
        "MINIO_ENDPOINT",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
    ):
        environment.pop(key, None)
    code = """import asyncio, json, tempfile
from pathlib import Path
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.ioc_extract import IocExtractStage
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'fixture.txt'
    path.write_text('Harmless https://payload.invalid/object 1.2.3.4')
    context = StageContext(job_id='local', file_id='fixture', storage_key='fixture',
        sha256='fixture', original_filename='fixture.txt', file_path=path)
    result = asyncio.run(IocExtractStage().execute(context))
    assert result.status == 'ok'
    assert result.findings['urls'] == ['https://payload.invalid/object']
    assert result.findings['ips'] == ['1.2.3.4']
    assert result.findings['url_artifact_submission']['status'] == 'disabled'
print('standalone_ioc_passed')
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, "Standalone IOC extraction needs no DB/MQ/MinIO credentials"
    assert "standalone_ioc_passed" in result.stdout
