"""Coverage, password checkpoints and truthful dynamic failure regressions."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError
from malscan_worker.pipeline import (
    _restore_checkpoint,
    attach_execution_budget,
    build_analysis_result,
    execute_analysis_stages,
    run_pipeline,
)
from malscan_worker.reporting import build_password_attempts_exhausted_report
from malscan_worker.stages.base import StageContext, StageResult


def stage_result(name, *, status="ok", findings=None, error=None):
    now = datetime.now(timezone.utc)
    return StageResult(name, status, now, now, 7, findings or {}, [], error)


class CountingStage:
    def __init__(self, name, *, findings=None, password=False):
        self.name = name
        self.calls = 0
        self.findings = findings or {}
        self.password = password

    async def execute(self, ctx):
        self.calls += 1
        if self.password and not ctx.archive_password:
            raise ArchivePasswordRequiredError("zip")
        return stage_result(self.name, findings=self.findings)


@pytest.fixture
def ctx(tmp_path):
    sample = tmp_path / "sample.zip"
    sample.write_bytes(b"outer archive bytes")
    return StageContext(
        job_id="11111111-1111-4111-8111-111111111111",
        file_id="22222222-2222-4222-8222-222222222222",
        storage_key="source",
        sha256="a" * 64,
        original_filename="sample.zip",
        file_path=sample,
        artifact_id="artifact-root",
        root_artifact_id="artifact-root",
    )


def test_report_preserves_stage_failure_and_versions(ctx):
    results = [
        stage_result("clamav", status="failed", error="Connection refused"),
        stage_result("yara", status="skipped", findings={"reason": "No YARA rules configured"}),
        stage_result(
            "format-analysis",
            findings={"features": {"sections": [".text"]}, "warnings": ["truncated"]},
        ),
    ]
    results[1].tool_version = "4.5.7"
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, results, 21)
    assert report["analysis"]["static"]["status"] == "partial"
    assert report["stages"][0]["error"] == "Connection refused"
    assert report["analysis"]["static"]["stage_coverage"][1]["tool_version"] == "4.5.7"
    assert report["results"]["format_analysis"]["warnings"] == ["truncated"]


def test_early_partial_report_knows_dynamic_profile_is_disabled(ctx, monkeypatch):
    from malscan_worker import pipeline

    monkeypatch.setattr(pipeline.settings, "sandbox_enabled", False)
    report = build_analysis_result(
        ctx.job_id,
        ctx.file_id,
        ctx,
        [stage_result("clamav", findings={"infected": False})],
        7,
    )
    assert report["analysis"]["dynamic"]["status"] == "disabled"
    assert report["results"]["sandbox"]["executed"] is False
    assert all(stage["name"] != "sandbox" for stage in report["timings"]["stages"])


@pytest.mark.asyncio
async def test_yara_missing_rules_is_skipped_not_clean(ctx, monkeypatch):
    from malscan_worker.stages import yara_scan

    monkeypatch.setattr(yara_scan, "_rules_loaded", True)
    monkeypatch.setattr(yara_scan, "_compiled_rules", None)
    monkeypatch.setattr(yara_scan, "_rules_load_error", None)
    result = await yara_scan.YaraStage().execute(ctx)
    assert result.status == "skipped"
    assert result.findings["reason"] == "No YARA rules configured"
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [result], 1)
    assert report["analysis"]["static"]["status"] == "partial"


@pytest.mark.asyncio
async def test_yara_invalid_rules_are_failed(ctx, monkeypatch):
    from malscan_worker.stages import yara_scan

    monkeypatch.setattr(yara_scan, "_rules_loaded", True)
    monkeypatch.setattr(yara_scan, "_compiled_rules", None)
    monkeypatch.setattr(yara_scan, "_rules_load_error", "YARA rule compilation failed")
    result = await yara_scan.YaraStage().execute(ctx)
    assert result.status == "failed"
    assert result.error == "YARA rule compilation failed"


@pytest.mark.asyncio
async def test_core_password_checkpoint_resumes_without_repeating_artifact_writer(ctx):
    av = CountingStage("clamav", findings={"infected": True, "threat_name": "Test.Signature"})
    fmt = CountingStage("format-analysis", findings={"child_artifacts": ["existing-child"]})
    archive = CountingStage("archive-extract", password=True)
    checkpoints = []

    async def save(results):
        checkpoints.append(build_analysis_result(ctx.job_id, ctx.file_id, ctx, results, 21))

    with pytest.raises(ArchivePasswordRequiredError):
        await execute_analysis_stages(
            ctx,
            parallel_stages=[av],
            format_stage=fmt,
            sequential_stages=[archive],
            on_checkpoint=save,
        )
    partial = checkpoints[-1]
    assert partial["verdict"] == "malicious"
    assert partial["analysis"]["static"]["status"] == "password_required"
    assert partial["stages"][-1]["status"] == "password_required"
    ctx.archive_password = "correct secret"
    resumed = _restore_checkpoint(partial, ctx)
    final = await execute_analysis_stages(
        ctx,
        parallel_stages=[av],
        format_stage=fmt,
        sequential_stages=[archive],
        initial_results=resumed,
    )
    assert av.calls == 1
    assert fmt.calls == 1
    assert archive.calls == 2
    assert len(final) == 3
    assert final[1].findings["child_artifacts"] == ["existing-child"]


def test_checkpoint_rejects_changed_file_or_artifact_lineage(ctx):
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [stage_result("clamav")], 1)
    assert len(_restore_checkpoint(report, ctx)) == 1
    ctx.sha256 = "b" * 64
    assert _restore_checkpoint(report, ctx) == []
    ctx.sha256 = "a" * 64
    ctx.artifact_id = "different-artifact"
    assert _restore_checkpoint(report, ctx) == []


def test_exhausting_password_attempts_keeps_static_detection_and_evidence(ctx):
    partial = build_analysis_result(
        ctx.job_id,
        ctx.file_id,
        ctx,
        [
            stage_result("clamav", findings={"infected": True, "threat_name": "Test.Signature"}),
            stage_result("archive-extract", status="password_required"),
        ],
        7,
    )
    final = build_password_attempts_exhausted_report(
        {
            "job_id": ctx.job_id,
            "file_id": ctx.file_id,
            "sha256": ctx.sha256,
            "original_filename": ctx.original_filename,
        },
        existing_report=partial,
    )
    assert final["verdict"] == "malicious"
    assert final["score"] == partial["score"]
    assert final["risk"]["evidence"] == partial["risk"]["evidence"]
    assert final["analysis"]["static"]["status"] == "partial"
    assert final["results"]["av_result"]["infected"] is True
    assert final["results"]["sandbox"]["status"] == "disabled"
    assert partial["stages"][-1]["status"] == "password_required"


def test_report_checkpoint_does_not_store_password_fields(ctx):
    ctx.archive_password = "secret-archive-credential"
    result = stage_result(
        "archive-extract",
        findings={
            "archive_password": ctx.archive_password,
            "metadata": {"password": ctx.archive_password, "password_protected": True},
        },
        error=f"Failed with {ctx.archive_password}",
    )
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [result], 1)
    assert "archive_password" not in report["results"]["archive_extract"]
    assert report["results"]["archive_extract"]["metadata"] == {"password_protected": True}
    assert ctx.archive_password not in report["stages"][0]["error"]


def patch_pipeline(mocker, ctx, *, job=None):
    mocker.patch(
        "malscan_worker.pipeline.download_file", new_callable=AsyncMock, return_value=ctx.file_path
    )
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context", new_callable=AsyncMock, return_value=job
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": ctx.artifact_id, "root_id": ctx.root_artifact_id},
    )
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    status = mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    persist = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock
    )
    mocker.patch("malscan_worker.pipeline.update_artifact_risk", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.PostgresRootBudget.initialize",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(check_deadline=AsyncMock()),
    )
    return status, persist


def job_data(ctx):
    return {
        key: getattr(ctx, key)
        for key in (
            "job_id",
            "file_id",
            "storage_key",
            "sha256",
            "original_filename",
            "artifact_id",
            "root_artifact_id",
        )
    }


@pytest.mark.asyncio
async def test_real_pipeline_persists_partial_report_before_password_exception(mocker, ctx):
    status, persist = patch_pipeline(mocker, ctx)
    mocker.patch(
        "malscan_worker.pipeline.PARALLEL_STAGES",
        [CountingStage("clamav", findings={"infected": True})],
    )
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", CountingStage("format-analysis"))
    mocker.patch(
        "malscan_worker.pipeline.SEQUENTIAL_STAGES",
        [CountingStage("archive-extract", password=True)],
    )
    with pytest.raises(ArchivePasswordRequiredError) as caught:
        await run_pipeline(job_data(ctx))
    report = persist.await_args.args[1]
    assert caught.value.partial_report == report
    assert report["analysis"]["static"]["status"] == "password_required"
    assert report["results"]["av_result"]["infected"] is True
    assert not any(call.args[1] == "done" for call in status.await_args_list)


@pytest.mark.asyncio
async def test_dynamic_dispatch_failure_keeps_static_without_synthetic_findings(mocker, ctx):
    _, persist = patch_pipeline(mocker, ctx)
    mocker.patch(
        "malscan_worker.pipeline.PARALLEL_STAGES",
        [CountingStage("clamav", findings={"infected": True})],
    )
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", CountingStage("format-analysis"))
    mocker.patch(
        "malscan_worker.pipeline.SEQUENTIAL_STAGES",
        [
            CountingStage(
                "sandbox",
                findings={
                    "status": "deferred",
                    "provider": "capev2",
                    "executed": False,
                },
            )
        ],
    )
    mocker.patch(
        "malscan_worker.pipeline.publish_sandbox_job",
        new_callable=AsyncMock,
        side_effect=OSError("queue down"),
    )
    result = await run_pipeline(job_data(ctx))
    final = persist.await_args.args[1]
    assert result["status"] == "done"
    assert final["analysis"]["dynamic"]["status"] == "unavailable"
    assert final["analysis"]["static"]["status"] == "complete"
    assert final["verdict"] == "malicious"
    assert final["results"]["sandbox"]["executed"] is False
    assert final["results"]["sandbox"]["is_mock"] is False
    assert final["results"]["sandbox"]["behaviors"] == []


@pytest.mark.asyncio
async def test_checkpoint_write_failure_prevents_done(mocker, ctx):
    status, persist = patch_pipeline(mocker, ctx)
    persist.side_effect = RuntimeError("checkpoint write failed")
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", [CountingStage("clamav")])
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", CountingStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])
    with pytest.raises(RuntimeError, match="checkpoint write failed"):
        await run_pipeline(job_data(ctx))
    assert not any(call.args[1] == "done" for call in status.await_args_list)


@pytest.mark.asyncio
async def test_report_budget_exposes_limits_and_counts_without_private_reservations(ctx):
    from malscan_worker.budget import BudgetLimits, InMemoryRootBudget

    ctx.root_budget = InMemoryRootBudget(BudgetLimits(max_files=2, max_bytes=100))
    await ctx.root_budget.reserve("internal-origin-key", 1, 40)
    report = {}
    await attach_execution_budget(report, ctx)
    assert report["execution_budget"]["used_files"] == 1
    assert report["execution_budget"]["used_bytes"] == 40
    assert report["execution_budget"]["limits"]["max_bytes"] == 100
    assert report["execution_budget"]["time_scope"] == "analysis_attempt"
    assert "reservations" not in report["execution_budget"]


@pytest.mark.asyncio
async def test_consumer_done_duplicate_is_acked_without_reanalysis(mocker):
    import json

    from malscan_worker import consumer

    @asynccontextmanager
    async def unlocked(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", unlocked)
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(status="done", current_stage=None),
    )
    analyze = mocker.patch("malscan_worker.consumer.run_pipeline", new_callable=AsyncMock)
    message = SimpleNamespace(
        body=json.dumps({"job_id": "job-id"}).encode(),
        headers={},
        ack=AsyncMock(),
        reject=AsyncMock(),
    )
    await consumer.process_message(message)
    analyze.assert_not_awaited()
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_busy_duplicate_is_requeued_without_reanalysis(mocker):
    import json

    from malscan_worker import consumer

    @asynccontextmanager
    async def busy(_job_id):
        yield False

    mocker.patch("malscan_worker.consumer.job_execution_lock", busy)
    mocker.patch("malscan_worker.consumer.asyncio.sleep", new_callable=AsyncMock)
    analyze = mocker.patch("malscan_worker.consumer.run_pipeline", new_callable=AsyncMock)
    message = SimpleNamespace(
        body=json.dumps({"job_id": "job-id"}).encode(),
        headers={},
        ack=AsyncMock(),
        reject=AsyncMock(),
    )
    await consumer.process_message(message)
    analyze.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=True)
    message.ack.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("sandbox", [False, True])
async def test_superseded_consumer_attempt_is_acked_without_failed_status(mocker, sandbox):
    import json

    from malscan_worker import consumer
    from malscan_worker.db import StaleAnalysisAttempt

    @asynccontextmanager
    async def unlocked(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", unlocked)
    mocker.patch("malscan_worker.consumer.job_analysis_attempt", unlocked)
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context",
        new_callable=AsyncMock,
        return_value=SimpleNamespace(status="scanning", current_stage=None),
    )
    status = mocker.patch("malscan_worker.consumer.update_job_status", new_callable=AsyncMock)
    handler = "finalize_deferred_sandbox_job" if sandbox else "run_pipeline"
    mocker.patch(
        f"malscan_worker.consumer.{handler}",
        new_callable=AsyncMock,
        side_effect=StaleAnalysisAttempt("Newer attempt owns the job"),
    )
    message = SimpleNamespace(
        body=json.dumps({"job_id": "job-id"}).encode(),
        headers={},
        ack=AsyncMock(),
        reject=AsyncMock(),
    )
    process = consumer.process_sandbox_message if sandbox else consumer.process_message
    await process(message)
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()
    assert not any(call.args[1] == "failed" for call in status.await_args_list)
