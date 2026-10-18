"""Tests for worker password-control flow across pipeline and consumer."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from malscan.scoring.policy import POLICY_VERSION
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
    DocumentPasswordRequiredError,
    DocumentWrongPasswordError,
)
from malscan_worker.stages.base import StageContext


@pytest.fixture(autouse=True)
def mock_message_execution_lock(mocker):
    @asynccontextmanager
    async def unlocked(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", unlocked)
    mocker.patch("malscan_worker.consumer.job_analysis_attempt", unlocked)
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    # Existing password control-flow tests cover failure of the report store;
    # retain the original when retry publication is unavailable.
    mocker.patch(
        "malscan_worker.consumer.publish_retry",
        new_callable=AsyncMock,
        side_effect=ConnectionError("Retry publisher unavailable"),
    )
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context", new_callable=AsyncMock, return_value=None
    )


class _StageRaisesPasswordRequired:
    name = "archive-extract"

    async def execute(self, _ctx):
        raise ArchivePasswordRequiredError("zip")


class _FakeMessage:
    def __init__(self, body: dict, headers: dict | None = None):
        import json

        self.body = json.dumps(body).encode()
        self.headers = headers or {}
        self.ack = AsyncMock()
        self.reject = AsyncMock()


@pytest.mark.asyncio
async def test_run_stage_reraises_password_exception(tmp_path):
    from malscan_worker.pipeline import _run_stage

    stage = _StageRaisesPasswordRequired()
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="archive.zip",
        file_path=tmp_path / "archive.zip",
    )

    with pytest.raises(ArchivePasswordRequiredError):
        await _run_stage(stage, ctx)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type", [ArchivePasswordRequiredError, DocumentPasswordRequiredError]
)
async def test_consumer_password_required_updates_status_and_ack(mocker, error_type):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "11111111-1111-1111-1111-111111111111",
            "file_id": "22222222-2222-2222-2222-222222222222",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=error_type("pdf" if error_type.__name__.startswith("Document") else "zip"),
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    assert update_status.await_count == 2
    update_status.assert_any_await("11111111-1111-1111-1111-111111111111", "scanning")
    update_status.assert_any_await(
        "11111111-1111-1111-1111-111111111111",
        "password_required",
        error_message="File is password-protected. Please provide a password to continue.",
    )
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_deferred_sandbox_does_not_increment_done_metric(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "10101010-1010-1010-1010-101010101010",
            "file_id": "20202020-2020-2020-2020-202020202020",
        }
    )

    scanning_counter = MagicMock()
    done_counter = MagicMock()

    def _labels(*, status: str):
        if status == "scanning":
            return scanning_counter
        if status == "done":
            return done_counter
        return MagicMock()

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        return_value={"status": "scanning"},
    )
    mocker.patch(
        "malscan_worker.consumer.job_total.labels",
        side_effect=_labels,
    )
    mocker.patch("malscan_worker.consumer.worker_active_jobs.inc")
    mocker.patch("malscan_worker.consumer.worker_active_jobs.dec")
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status",
        new_callable=AsyncMock,
    )

    await consumer.process_message(message)

    update_status.assert_awaited_once_with(
        "10101010-1010-1010-1010-101010101010",
        "scanning",
    )
    scanning_counter.inc.assert_called_once_with()
    done_counter.inc.assert_not_called()
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_sandbox_consumer_preserves_progress_while_detonation_runs(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "30303030-3030-3030-3030-303030303030",
            "file_id": "40404040-4040-4040-4040-404040404040",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.finalize_deferred_sandbox_job",
        new_callable=AsyncMock,
        return_value={"status": "done"},
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status",
        new_callable=AsyncMock,
    )

    await consumer.process_sandbox_message(message)

    update_status.assert_awaited_once_with(
        "30303030-3030-3030-3030-303030303030",
        "scanning",
        current_stage="sandbox",
        stages_done=consumer.settings.stages_total - 1,
    )
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


def test_build_password_attempts_exhausted_report_has_zero_risk_block() -> None:
    from malscan_worker.reporting import build_password_attempts_exhausted_report

    report = build_password_attempts_exhausted_report(
        {
            "job_id": "33333333-3333-3333-3333-333333333333",
            "file_id": "44444444-4444-4444-4444-444444444444",
            "sha256": "deadbeef",
            "original_filename": "secret.zip",
        }
    )

    assert report["verdict"] == "unknown"
    assert report["score"] == 0
    assert report["risk_level"] == "clean"
    assert report["risk"] == {
        "policy_version": POLICY_VERSION,
        "risk_score": 0,
        "risk_level": "clean",
        "legacy_verdict": "unknown",
        "malicious_gate_open": False,
        "high_gate_open": False,
        "independent_source_count": 0,
        "breakdown": {
            "local_score": 0,
            "inherited_score": 0,
            "synergy_bonus": 0,
            "dampener": 0,
            "final_score": 0,
        },
        "evidence": [],
        "top_evidence": [],
        "descendant_summary": {},
        "score_trace": {},
    }
    assert report["report_schema_version"] == "mswr-report-v3"
    assert report["explainability"]["failure_diagnostics"]["status"] == "blocked"
    assert (
        report["explainability"]["failure_diagnostics"]["diagnostics"][0]["code"]
        == "password_attempts_exhausted"
    )
    assert report["results"]["archive_extract"]["reason"] == "連續 3 次密碼錯誤，封存檔解壓失敗。"
    summary = report["explainability"]["summary"]
    diagnostics = report["explainability"]["failure_diagnostics"]
    assert summary["headline"] == "因密碼嘗試次數耗盡，封存內容未被分析。"
    assert summary["final_verdict_explainer"] == "此報告僅反映最外層檔案的分析結果。"
    assert diagnostics["headline"] == "內層封存內容因密碼耗盡而無法分析。"


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [ArchiveWrongPasswordError, DocumentWrongPasswordError])
async def test_consumer_wrong_password_exhausted_stores_report_sets_done_and_ack(
    mocker, error_type
):
    from malscan_worker import consumer

    artifact_id = "99999999-0000-0000-0000-000000000000"
    message = _FakeMessage(
        {
            "job_id": "33333333-3333-3333-3333-333333333333",
            "file_id": "44444444-4444-4444-4444-444444444444",
            "artifact_id": artifact_id,
            "sha256": "deadbeef",
            "original_filename": "secret.zip",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=error_type("pdf" if error_type.__name__.startswith("Document") else "zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=3,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    update_result = mocker.patch(
        "malscan_worker.consumer.update_job_result_strict", new_callable=AsyncMock
    )
    update_artifact_risk = mocker.patch(
        "malscan_worker.consumer.update_artifact_risk", new_callable=AsyncMock, create=True
    )

    await consumer.process_message(message)

    update_result.assert_awaited_once()
    saved_result = update_result.await_args.args[1]
    assert saved_result["verdict"] == "unknown"
    assert saved_result["risk_level"] == "clean"
    assert saved_result["risk"] == {
        "policy_version": POLICY_VERSION,
        "risk_score": 0,
        "risk_level": "clean",
        "legacy_verdict": "unknown",
        "malicious_gate_open": False,
        "high_gate_open": False,
        "independent_source_count": 0,
        "breakdown": {
            "local_score": 0,
            "inherited_score": 0,
            "synergy_bonus": 0,
            "dampener": 0,
            "final_score": 0,
        },
        "evidence": [],
        "top_evidence": [],
        "descendant_summary": {},
        "score_trace": {},
    }
    if error_type is DocumentWrongPasswordError:
        pdf_result = saved_result["results"]["format_analysis"]
        assert pdf_result["decryption_failed"] is True
        assert pdf_result["features"]["content_access"] == "password_attempts_exhausted"
        assert "archive_extract" not in saved_result["results"]
        assert saved_result["stages"][-1]["stage_name"] == "format-analysis"
    else:
        archive_result = saved_result["results"]["archive_extract"]
        assert archive_result["reason"] == "連續 3 次密碼錯誤，封存檔解壓失敗。"
        assert saved_result["results"]["archive_extract"]["extraction_failed"] is True
    assert saved_result["explainability"]["failure_diagnostics"]["status"] == "blocked"
    update_artifact_risk.assert_awaited_once_with(
        artifact_id=artifact_id,
        verdict="unknown",
        score=0,
        risk_level="clean",
        policy_version=POLICY_VERSION,
    )

    update_status.assert_any_await(
        "33333333-3333-3333-3333-333333333333",
        "done",
    )
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [ArchiveWrongPasswordError, DocumentWrongPasswordError])
async def test_consumer_wrong_password_under_limit_sets_password_required_and_ack(
    mocker, error_type
):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "55555555-5555-5555-5555-555555555555",
            "file_id": "66666666-6666-6666-6666-666666666666",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=error_type("pdf" if error_type.__name__.startswith("Document") else "zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=2,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    update_result = mocker.patch(
        "malscan_worker.consumer.update_job_result_strict", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    update_status.assert_any_await(
        "55555555-5555-5555-5555-555555555555",
        "password_required",
        error_message="Wrong file password. Please try again.",
    )
    update_result.assert_not_awaited()
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_wrong_password_over_limit_treated_as_exhausted(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "77777777-7777-7777-7777-777777777777",
            "file_id": "88888888-8888-8888-8888-888888888888",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=4,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    update_result = mocker.patch(
        "malscan_worker.consumer.update_job_result_strict", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    update_result.assert_awaited_once()
    update_status.assert_any_await("77777777-7777-7777-7777-777777777777", "done")
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_wrong_password_increment_failure_rejects_for_retry(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "99999999-9999-9999-9999-999999999999",
            "file_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        }
    )

    pipeline = mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    increment = mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        side_effect=RuntimeError("db unavailable"),
    )
    status = mocker.patch("malscan_worker.consumer.update_job_status", new_callable=AsyncMock)

    await consumer.process_message(message)

    pipeline.assert_awaited_once()
    increment.assert_awaited_once_with("99999999-9999-9999-9999-999999999999")
    status.assert_awaited_once_with("99999999-9999-9999-9999-999999999999", "scanning")
    message.ack.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=True)


@pytest.mark.asyncio
async def test_consumer_exhausted_report_write_failure_not_done_and_requeues(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "file_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=3,
    )
    mocker.patch(
        "malscan_worker.consumer.update_job_result_strict",
        new_callable=AsyncMock,
        side_effect=RuntimeError("write failed"),
        create=True,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    update_status.assert_any_await(
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "scanning",
    )
    for call in update_status.await_args_list:
        assert not (
            call.args[0] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" and call.args[1] == "done"
        )
    message.ack.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=True)


@pytest.mark.asyncio
async def test_consumer_exhausted_artifact_risk_failure_still_marks_done_and_acks(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "abababab-abab-abab-abab-abababababab",
            "file_id": "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
            "artifact_id": "efefefef-efef-efef-efef-efefefefefef",
            "sha256": "deadbeef",
            "original_filename": "secret.zip",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=3,
    )
    mocker.patch("malscan_worker.consumer.update_job_result_strict", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.consumer.update_artifact_risk",
        new_callable=AsyncMock,
        side_effect=RuntimeError("artifact update failed"),
        create=True,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    update_status.assert_any_await("abababab-abab-abab-abab-abababababab", "done")
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_exhausted_report_write_failure_goes_dlq_after_max_retries(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "file_id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        },
        headers={"x-death": [{"count": 3}]},
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=3,
    )
    mocker.patch(
        "malscan_worker.consumer.update_job_result_strict",
        new_callable=AsyncMock,
        side_effect=RuntimeError("write failed"),
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    message.ack.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=False)

    failed_call_found = False
    for call in update_status.await_args_list:
        if (
            call.args[0] == "dddddddd-dddd-dddd-dddd-dddddddddddd"
            and call.args[1] == "failed"
            and "Max retries exceeded" in call.kwargs.get("error_message", "")
        ):
            failed_call_found = True
        assert not (
            call.args[0] == "dddddddd-dddd-dddd-dddd-dddddddddddd" and call.args[1] == "done"
        )

    assert failed_call_found
