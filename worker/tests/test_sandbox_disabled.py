"""Tests for the default-disabled dynamic sandbox flow."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
from malscan_worker.config import Settings
from malscan_worker.stages.base import Stage, StageContext, StageResult


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "postgresql+asyncpg://test:test@localhost:5432/test",
        "minio_endpoint": "localhost:9000",
        "minio_access_key": "test",
        "minio_secret_key": "test",
        "rabbitmq_url": "amqp://guest:guest@localhost:5672/",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


class _SuccessfulStage(Stage):
    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, _ctx: StageContext) -> StageResult:
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={},
            artifacts=[],
        )


class _DummySession:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    async def __aenter__(self) -> _DummySession:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False


class _FakeMessage:
    def __init__(self, body: dict[str, str]) -> None:
        self.body = json.dumps(body).encode()
        self.headers: dict[str, object] = {}
        self.ack = AsyncMock()
        self.reject = AsyncMock()


def test_sandbox_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SANDBOX_ENABLED",
        "sandbox_enabled",
        "SANDBOX_PROVIDER",
        "sandbox_provider",
        "SANDBOX_MOCK",
        "sandbox_mock",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = _settings()

    assert settings.sandbox_enabled is False
    assert settings.sandbox_provider == "capev2"
    assert settings.sandbox_mock is False


def test_explicit_false_sandbox_enabled_env_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SANDBOX_ENABLED", "sandbox_enabled"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SANDBOX_ENABLED", "false")

    settings = _settings()

    assert settings.sandbox_enabled is False
    assert "sandbox_enabled" in settings.model_fields_set


@pytest.mark.asyncio
async def test_sandbox_stage_is_skipped_when_disabled(mocker, stage_context: StageContext) -> None:
    from malscan_worker.stages.sandbox import SandboxStage

    mocker.patch(
        "malscan_worker.stages.sandbox.get_settings",
        return_value=_settings(sandbox_enabled=False),
    )

    result = await SandboxStage().execute(stage_context)

    assert result.stage_name == "sandbox"
    assert result.status == "skipped"
    assert result.findings["executed"] is False
    assert result.findings["provider"] == "capev2"
    assert result.findings["is_mock"] is False
    assert result.findings["status"] == "disabled"
    for key in (
        "behaviors",
        "network_connections",
        "processes",
        "files",
        "registry",
        "mutexes",
        "dns",
        "http",
        "tcp_udp",
        "dropped_files",
        "screenshots",
    ):
        assert result.findings[key] == []
    assert result.findings["errors"] == []


@pytest.mark.asyncio
async def test_explicit_sandbox_opt_in_keeps_deferred_provider_flow(
    mocker, stage_context: StageContext
) -> None:
    from malscan_worker.stages.sandbox import SandboxStage

    mocker.patch(
        "malscan_worker.stages.sandbox.get_settings",
        return_value=_settings(sandbox_enabled=True, sandbox_provider="capev2"),
    )

    result = await SandboxStage().execute(stage_context)

    assert result.status == "ok"
    assert result.findings["status"] == "deferred"
    assert result.findings["executed"] is False
    assert result.findings["provider"] == "capev2"
    assert result.findings["behaviors"] == []


@pytest.mark.asyncio
async def test_disabled_sandbox_job_finalizes_without_sandbox_queue_or_findings(
    mocker, tmp_path
) -> None:
    from malscan_worker import consumer
    from malscan_worker.pipeline import run_pipeline
    from malscan_worker.stages.sandbox import SandboxStage

    job_id = "11111111-1111-1111-1111-111111111111"
    file_id = "22222222-2222-2222-2222-222222222222"
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"static test sample")

    @asynccontextmanager
    async def unlocked(_job_id):
        yield True

    mocker.patch("malscan_worker.consumer.job_execution_lock", unlocked)
    mocker.patch("malscan_worker.consumer.job_analysis_attempt", unlocked)
    mocker.patch(
        "malscan_worker.consumer.get_job_for_context", new_callable=AsyncMock, return_value=None
    )

    mocker.patch(
        "malscan_worker.stages.sandbox.get_settings",
        return_value=_settings(sandbox_enabled=False),
    )
    mocker.patch("malscan_worker.pipeline.AsyncSession", _DummySession)
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-1", "root_id": "artifact-1"},
    )
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    pipeline_update_status = mocker.patch(
        "malscan_worker.pipeline.update_job_status", new_callable=AsyncMock
    )
    consumer_update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    update_result_strict = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock
    )
    mocker.patch("malscan_worker.pipeline.update_artifact_risk", new_callable=AsyncMock)
    publish_sandbox_job = mocker.patch(
        "malscan_worker.pipeline.publish_sandbox_job", new_callable=AsyncMock
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", [_SuccessfulStage("file-type")])
    mocker.patch(
        "malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", _SuccessfulStage("format-analysis")
    )
    mocker.patch(
        "malscan_worker.pipeline.SEQUENTIAL_STAGES",
        [
            _SuccessfulStage("archive-extract"),
            _SuccessfulStage("document-analysis"),
            SandboxStage(),
        ],
    )

    message = _FakeMessage(
        {
            "job_id": job_id,
            "file_id": file_id,
            "storage_key": "sample-key",
            "sha256": "deadbeef",
            "original_filename": "sample.bin",
        }
    )

    # process_message uses the real pipeline, including its actual SandboxStage.
    mocker.patch("malscan_worker.consumer.run_pipeline", side_effect=run_pipeline)
    await consumer.process_message(message)

    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()
    consumer_update_status.assert_awaited_once_with(job_id, "scanning")
    pipeline_update_status.assert_awaited_once_with(
        job_id, "done", current_stage=None, stages_done=5
    )
    assert update_result_strict.await_count == 6
    publish_sandbox_job.assert_not_awaited()

    report = update_result_strict.await_args.args[1]
    sandbox = report["results"]["sandbox"]
    assert report["job_id"] == job_id
    assert sandbox["executed"] is False
    assert sandbox["provider"] == "capev2"
    for key in (
        "behaviors",
        "network_connections",
        "processes",
        "files",
        "registry",
        "mutexes",
        "dns",
        "http",
        "tcp_udp",
        "dropped_files",
        "screenshots",
    ):
        assert sandbox[key] == []
    assert sandbox["iocs"] == {"domains": [], "ips": [], "urls": []}
    assert sandbox["pcap"] == {"available": False, "url": None}
    assert sandbox["memory_dump"] == {"available": False, "url": None}
    assert sandbox["verdict_hint"] is None
    assert sandbox["status"] == "disabled"
    sandbox_timing = next(
        stage for stage in report["timings"]["stages"] if stage["name"] == "sandbox"
    )
    assert sandbox_timing["status"] == "skipped"
