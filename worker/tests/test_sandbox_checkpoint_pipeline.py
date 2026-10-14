"""Persist CAPE lifecycle transitions alongside the completed static report."""

import json
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker.db import StaleAnalysisAttempt
from malscan_worker.pipeline import finalize_deferred_sandbox_job
from malscan_worker.sandbox.providers import ProviderCheckpointError


class Session:
    def __init__(self, *_args, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


def prepare_case(mocker, tmp_path, sandbox):
    report = {
        "verdict": "malicious",
        "score": 95,
        "risk_level": "malicious",
        "risk": {"policy_version": "msrs-v1", "evidence": [{"source": "clamav"}]},
        "results": {
            "sandbox": deepcopy(sandbox),
            "av_result": {"infected": True, "threat_name": "Test.Signature"},
        },
        "timings": {
            "total_ms": 20,
            "stages": [{"name": "clamav", "status": "ok", "duration_ms": 20}],
        },
        "stages": [],
    }
    mocker.patch("malscan_worker.pipeline.AsyncSession", Session)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(result=report, artifact_id=None),
    )
    fixture = tmp_path / "sample.bin"
    fixture.write_bytes(b"sample")
    download = mocker.patch(
        "malscan_worker.pipeline.download_file", new_callable=AsyncMock, return_value=fixture
    )
    persist = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock
    )
    status = mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    return report, download, persist, status


DATA = {"job_id": "job-id", "file_id": "file-id", "storage_key": "source-key", "sha256": "sha"}


@pytest.mark.asyncio
async def test_cape_submission_and_task_identity_are_saved_before_the_next_action(mocker, tmp_path):
    original, _, persist, status = prepare_case(
        mocker,
        tmp_path,
        {
            "status": "deferred",
            "provider": "capev2",
            "executed": False,
        },
    )
    saved = []

    async def save(_job_id, report):
        saved.append(deepcopy(report))

    persist.side_effect = save

    async def analyze(*, previous_result, on_checkpoint, **_kwargs):
        assert previous_result["status"] == "deferred"
        await on_checkpoint({"status": "submitting", "provider": "capev2", "task_id": None})
        assert saved[-1]["results"]["sandbox"]["status"] == "submitting"
        # A provider may only submit after this confirmed durable checkpoint.
        await on_checkpoint({"status": "running", "provider": "capev2", "task_id": "42"})
        assert saved[-1]["results"]["sandbox"]["task_id"] == "42"
        return {"status": "completed", "provider": "capev2", "task_id": "42", "executed": True}

    mocker.patch("malscan_worker.pipeline.execute_sandbox_analysis", side_effect=analyze)
    await finalize_deferred_sandbox_job(DATA)
    assert [item["results"]["sandbox"]["status"] for item in saved] == [
        "submitting",
        "running",
        "completed",
    ]
    assert saved[0]["analysis"]["dynamic"]["status"] == "running"
    assert saved[1]["analysis"]["static"]["status"] == "complete"
    assert saved[-1]["results"]["av_result"]["infected"] is True
    assert original["results"]["sandbox"]["status"] == "deferred"
    status.assert_awaited_once()


@pytest.mark.asyncio
async def test_retained_task_is_polled_without_redownloading_source(mocker, tmp_path):
    _, download, persist, _ = prepare_case(
        mocker,
        tmp_path,
        {
            "status": "running",
            "provider": "capev2",
            "task_id": "42",
            "executed": False,
        },
    )
    analyze = mocker.patch(
        "malscan_worker.pipeline.execute_sandbox_analysis",
        new_callable=AsyncMock,
        return_value={
            "status": "completed",
            "executed": True,
            "task_id": "42",
            "provider": "capev2",
        },
    )
    await finalize_deferred_sandbox_job(DATA)
    download.assert_not_awaited()
    assert analyze.await_args.kwargs["file_path"] is None
    assert analyze.await_args.kwargs["previous_result"]["task_id"] == "42"
    assert callable(analyze.await_args.kwargs["on_checkpoint"])
    assert persist.await_args.args[1]["analysis"]["dynamic"]["status"] == "complete"


@pytest.mark.asyncio
async def test_uncertain_submission_does_not_require_source_or_claim_completion(mocker, tmp_path):
    _, download, persist, _ = prepare_case(
        mocker,
        tmp_path,
        {
            "status": "submitting",
            "provider": "capev2",
            "task_id": None,
            "executed": False,
        },
    )
    mocker.patch(
        "malscan_worker.pipeline.execute_sandbox_analysis",
        new_callable=AsyncMock,
        return_value={
            "status": "unavailable",
            "executed": False,
            "error_code": "provider_submission_unknown",
            "reconcile_required": True,
        },
    )
    await finalize_deferred_sandbox_job(DATA)
    download.assert_not_awaited()
    assert persist.await_args.args[1]["analysis"]["dynamic"]["status"] == "unavailable"
    assert persist.await_args.args[1]["results"]["sandbox"]["reconcile_required"] is True


@pytest.mark.asyncio
async def test_stale_checkpoint_cause_is_preserved_for_consumer_ack(mocker, tmp_path):
    _, _, persist, status = prepare_case(mocker, tmp_path, {"status": "deferred"})
    persist.side_effect = StaleAnalysisAttempt("Replaced attempt")

    async def analyze(*, on_checkpoint, **_kwargs):
        try:
            await on_checkpoint({"status": "submitting", "task_id": None})
        except Exception as exc:
            raise ProviderCheckpointError("Checkpoint not confirmed") from exc

    mocker.patch("malscan_worker.pipeline.execute_sandbox_analysis", side_effect=analyze)
    with pytest.raises(StaleAnalysisAttempt):
        await finalize_deferred_sandbox_job(DATA)
    status.assert_not_awaited()


@pytest.mark.asyncio
async def test_stale_cape_checkpoint_acknowledges_old_delivery_without_retry_or_finalization(
    mocker, tmp_path
):
    from malscan_worker import consumer

    _, _, persist, finalize_status = prepare_case(mocker, tmp_path, {"status": "deferred"})
    persist.side_effect = StaleAnalysisAttempt("Replaced attempt")

    @asynccontextmanager
    async def scope(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", scope)
    mocker.patch("malscan_worker.consumer.job_analysis_attempt", scope)
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(status="scanning", current_stage="sandbox_pending"),
    )
    consumer_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    retry = mocker.patch("malscan_worker.consumer._retry_or_dead_letter", new_callable=AsyncMock)

    async def analyze(*, on_checkpoint, **_kwargs):
        try:
            await on_checkpoint({"status": "submitting", "task_id": None})
        except Exception as exc:
            raise ProviderCheckpointError("Checkpoint not confirmed") from exc

    mocker.patch("malscan_worker.pipeline.execute_sandbox_analysis", side_effect=analyze)
    message = SimpleNamespace(
        body=json.dumps(DATA).encode(),
        headers={},
        ack=AsyncMock(),
        reject=AsyncMock(),
        processed=False,
    )
    await consumer.process_sandbox_message(message)
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()
    retry.assert_not_awaited()
    assert [call.args[1] for call in consumer_status.await_args_list] == ["scanning"]
    finalize_status.assert_not_awaited()


@pytest.mark.asyncio
async def test_terminal_provider_result_is_refenced_before_retry_marks_done(mocker, tmp_path):
    original, download, persist, status = prepare_case(
        mocker, tmp_path, {"status": "completed", "executed": True, "task_id": "42"}
    )
    persist.side_effect = StaleAnalysisAttempt("Replaced attempt")
    provider = mocker.patch(
        "malscan_worker.pipeline.execute_sandbox_analysis", new_callable=AsyncMock
    )
    with pytest.raises(StaleAnalysisAttempt):
        await finalize_deferred_sandbox_job(DATA)
    persist.assert_awaited_once_with(DATA["job_id"], original)
    download.assert_not_awaited()
    provider.assert_not_awaited()
    status.assert_not_awaited()
