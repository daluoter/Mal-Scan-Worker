"""Unit tests for the analysis pipeline."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from malscan.scoring.policy import POLICY_VERSION
from malscan_worker.stages.base import Stage, StageResult


class MockStage(Stage):
    """Mock stage for testing pipeline flow."""

    def __init__(self, name: str, should_fail: bool = False):
        self._name = name
        self.should_fail = should_fail

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, ctx):
        now = datetime.now(timezone.utc)
        if self.should_fail:
            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=now,
                ended_at=now,
                duration_ms=10,
                findings={},
                artifacts=[],
                error="Mock failure",
            )
        return StageResult(
            stage_name=self.name,
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=10,
            findings={"test": "data"},
            artifacts=[],
            error=None,
        )


@pytest.mark.asyncio
async def test_run_pipeline_success(mocker, tmp_path):
    """Test successful pipeline execution."""
    from malscan_worker.pipeline import run_pipeline

    # Create temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock all external dependencies
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    update_job_stage = mocker.patch(
        "malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock
    )
    mocker.patch("malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-root-1", "root_id": "artifact-root-1"},
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Replace STAGES with mock stages
    mock_stages = [MockStage("stage1"), MockStage("stage2")]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "file_id": file_id,
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)

    assert result["job_id"] == job_id
    assert len(result["stages"]) == 3
    assert [stage["stage_name"] for stage in result["stages"]] == [
        "stage1",
        "stage2",
        "format-analysis",
    ]

    assert update_job_stage.await_args_list[1].args == (job_id, "recursive_analysis", 3)


@pytest.mark.asyncio
async def test_run_pipeline_stage_failure(mocker, tmp_path):
    """Test pipeline continues and records failed stage."""
    from malscan_worker.pipeline import run_pipeline

    # Create temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock dependencies
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-root-1", "root_id": "artifact-root-1"},
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Mock STAGES (second stage fails)
    mock_stages = [MockStage("stage1"), MockStage("stage2", should_fail=True)]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "file_id": file_id,
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)

    assert result["job_id"] == job_id
    assert any(
        stage["stage_name"] == "stage2" and stage["status"] == "failed"
        for stage in result["stages"]
    )


@pytest.mark.asyncio
async def test_run_pipeline_sets_root_artifact_context_before_stage_execution(mocker, tmp_path):
    from malscan_worker.pipeline import run_pipeline

    captured: dict[str, str | None] = {}

    class CaptureStage(MockStage):
        async def execute(self, ctx):
            captured["artifact_id"] = ctx.artifact_id
            captured["root_artifact_id"] = ctx.root_artifact_id
            return await super().execute(ctx)

    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    ensure_root_artifact = mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-root-1", "root_id": "artifact-root-1"},
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", [CaptureStage("stage1")])
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    await run_pipeline(
        {
            "job_id": str(uuid.uuid4()),
            "file_id": str(uuid.uuid4()),
            "storage_key": "test-key",
            "sha256": "test-sha256",
            "original_filename": "test.txt",
        }
    )

    ensure_root_artifact.assert_awaited_once()
    assert captured["artifact_id"] == "artifact-root-1"
    assert captured["root_artifact_id"] == "artifact-root-1"


def test_build_analysis_result_applies_format_scoring_and_reporting():
    from malscan_worker.pipeline import _build_analysis_result

    now = datetime.now(timezone.utc)
    ctx = type(
        "Ctx",
        (),
        {"sha256": "abc123", "original_filename": "sample.bin", "artifact_id": "artifact-1"},
    )()
    results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"mime_type": "application/octet-stream", "file_size": 10},
            artifacts=[],
        ),
        StageResult(
            stage_name="clamav",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"infected": False, "threat_name": None},
            artifacts=[],
        ),
        StageResult(
            stage_name="yara",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"matches": []},
            artifacts=[],
        ),
        StageResult(
            stage_name="format-analysis",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={
                "analyzer": "pe",
                "format_type": "PE",
                "risk_score": 37,
                "risk_factors": ["packed"],
                "indicators": [{"type": "suspicious_import", "severity": "high"}],
                "heuristics": [
                    {
                        "key": "script.encoded_command_execution",
                        "category": "script_token",
                        "scope": "script",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Encoded payload and execution primitives appear together",
                        "evidence": {},
                        "tags": (),
                    }
                ],
                "features": {"entrypoint": 4096},
            },
            artifacts=[],
        ),
        StageResult(
            stage_name="archive-extract",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={
                "archive_type": "zip",
                "heuristics": [
                    {
                        "key": "archive.executable_concentration",
                        "category": "archive",
                        "scope": "archive",
                        "role": "corroborating",
                        "severity": "medium",
                        "confidence": 0.8,
                        "summary": "Archive contains multiple executable-like members",
                        "evidence": {"executable_members": 2},
                        "tags": ("archive", "embedded-executable"),
                    }
                ],
            },
            artifacts=[],
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", ctx, results, 123)

    assert report["verdict"] == "suspicious"
    assert report["risk_level"] == "high"
    assert report["score"] == 84
    assert report["risk"]["policy_version"] == "msrs-v1"
    assert report["risk"]["breakdown"]["local_score"] >= 0

    format_report = report["results"]["format_analysis"]
    assert format_report["analyzer"] == "pe"
    assert format_report["format_type"] == "PE"
    assert format_report["risk_score"] == 37
    assert format_report["risk_factors"] == ["packed"]
    assert format_report["indicators"][0]["severity"] == "high"
    assert format_report["heuristics"][0]["key"] == "script.encoded_command_execution"
    assert format_report["features"] == {"entrypoint": 4096}

    archive_report = report["results"]["archive_extract"]
    assert archive_report["archive_type"] == "zip"
    assert archive_report["heuristics"][0]["key"] == "archive.executable_concentration"


def test_build_analysis_result_adds_score_trace_and_report_version():
    from malscan_worker.pipeline import _build_analysis_result

    now = datetime.now(timezone.utc)
    ctx = type(
        "Ctx",
        (),
        {
            "sha256": "abc123",
            "original_filename": "sample.bin",
            "artifact_id": "artifact-1",
            "root_artifact_id": "artifact-1",
        },
    )()
    results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"mime_type": "application/octet-stream", "file_size": 10},
            artifacts=[],
        ),
        StageResult(
            stage_name="clamav",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"infected": True, "threat_name": "Win.Test.EICAR_HDB-1"},
            artifacts=[],
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", ctx, results, 123)

    assert report["report_schema_version"] == "mswr-report-v3"
    assert report["risk"]["policy_version"] == POLICY_VERSION
    assert report["risk"]["score_trace"]["components"][0]["type"] == "evidence"
    evidence = report["risk"]["evidence"][0]
    assert evidence["id"] == "ev-1"
    assert evidence["artifact_id"] == "artifact-1"
    assert evidence["stage"] is None
    assert evidence["analyzer"] is None
    assert evidence["confidence"] == 1.0
    assert evidence["score_contribution"] == {}


def test_build_analysis_result_keeps_additive_and_legacy_sandbox_fields() -> None:
    from malscan_worker.pipeline import _build_analysis_result

    now = datetime.now(timezone.utc)
    ctx = type(
        "Ctx",
        (),
        {"sha256": "abc123", "original_filename": "sample.bin", "artifact_id": "artifact-1"},
    )()
    results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"mime_type": "application/octet-stream", "file_size": 10},
            artifacts=[],
        ),
        StageResult(
            stage_name="sandbox",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={
                "executed": True,
                "provider": "capev2",
                "task_id": "42",
                "is_mock": False,
                "verdict_hint": "malicious",
                "behaviors": [{"type": "process_injection"}],
                "network_connections": [{"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp"}],
                "processes": [{"pid": 100, "name": "sample.exe"}],
                "files": [{"path": "C:\\temp\\dropper.dll", "action": "write"}],
                "registry": [{"key": "HKCU\\Run", "action": "modify"}],
                "mutexes": [{"name": "Global\\abc123"}],
                "dns": [{"query": "evil.example", "answers": ["8.8.8.8"]}],
                "http": [{"url": "http://evil.example/payload", "method": "GET"}],
                "tcp_udp": [{"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp"}],
                "dropped_files": [{"name": "dropper.dll", "sha256": "abc123"}],
                "screenshots": [{"name": "0001.jpg"}],
                "pcap": {"available": True},
                "memory_dump": {"available": False},
                "iocs": {"domains": ["evil.example"], "ips": ["8.8.8.8"], "urls": []},
                "errors": [],
                "raw_report_ref": "https://cape.local/apiv2/tasks/report/42/?format=json",
            },
            artifacts=[],
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", ctx, results, 123)

    sandbox = report["results"]["sandbox"]
    assert sandbox["provider"] == "capev2"
    assert sandbox["task_id"] == "42"
    assert sandbox["behaviors"] == [{"type": "process_injection"}]
    assert sandbox["network_connections"][0]["protocol"] == "tcp"
    assert sandbox["dropped_files"][0]["name"] == "dropper.dll"
    assert sandbox["raw_report_ref"] == "https://cape.local/apiv2/tasks/report/42/?format=json"


@pytest.mark.asyncio
async def test_run_pipeline_defers_sandbox_and_keeps_job_scanning(mocker, tmp_path) -> None:
    from malscan_worker.pipeline import run_pipeline

    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    update_status = mocker.patch(
        "malscan_worker.pipeline.update_job_status",
        new_callable=AsyncMock,
    )
    update_stage = mocker.patch(
        "malscan_worker.pipeline.update_job_stage",
        new_callable=AsyncMock,
    )
    update_result_strict = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict", new_callable=AsyncMock
    )
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-root-1", "root_id": "artifact-root-1"},
    )
    mocker.patch(
        "malscan_worker.pipeline.update_artifact_risk",
        new_callable=AsyncMock,
        create=True,
    )
    mocker.patch("malscan_worker.pipeline.publish_sandbox_job", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.stage_latency")
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", [MockStage("stage1")])
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch(
        "malscan_worker.pipeline.SEQUENTIAL_STAGES",
        [
            MockStage("archive-extract"),
            MockStage("document-analysis"),
            MockStage("sandbox"),
        ],
    )
    mocker.patch(
        "malscan_worker.pipeline._should_finalize_after_static_pipeline",
        return_value=False,
    )

    job_id = str(uuid.uuid4())
    result = await run_pipeline(
        {
            "job_id": job_id,
            "file_id": str(uuid.uuid4()),
            "storage_key": "test-key",
            "sha256": "test-sha256",
            "original_filename": "test.txt",
        }
    )

    assert result["job_id"] == job_id
    # Every completed phase is persisted, followed by the final static report.
    assert update_result_strict.await_count == 6
    update_status.assert_any_await(
        job_id,
        "scanning",
        current_stage="sandbox_pending",
        stages_done=4,
    )
    assert update_status.await_args_list[-1].args[1] == "scanning"
    assert update_stage.await_args_list[-1].args == (job_id, "recursive_analysis", 2)


@pytest.mark.asyncio
async def test_finalize_deferred_sandbox_job_reuses_persisted_sandbox_result(mocker) -> None:
    from malscan_worker.pipeline import finalize_deferred_sandbox_job, settings

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    stored_report = {
        "verdict": "suspicious",
        "score": 55,
        "risk_level": "medium",
        "risk": {"policy_version": POLICY_VERSION},
        "results": {
            "sandbox": {
                "executed": True,
                "provider": "capev2",
                "task_id": "42",
                "is_mock": False,
                "behaviors": [],
                "network_connections": [],
            }
        },
    }
    job_instance = type(
        "Job",
        (),
        {"result": stored_report, "artifact_id": "artifact-1"},
    )()

    mocker.patch("malscan_worker.pipeline.AsyncSession", DummySession)
    download_file = mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
    )
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=job_instance,
    )
    execute_sandbox = mocker.patch(
        "malscan_worker.pipeline.execute_sandbox_analysis",
        new_callable=AsyncMock,
    )
    update_result = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict",
        new_callable=AsyncMock,
    )
    update_artifact_risk = mocker.patch(
        "malscan_worker.pipeline.update_artifact_risk",
        new_callable=AsyncMock,
    )
    update_status = mocker.patch(
        "malscan_worker.pipeline.update_job_status",
        new_callable=AsyncMock,
    )

    result = await finalize_deferred_sandbox_job(
        {
            "job_id": "job-1",
            "file_id": "file-1",
            "storage_key": "upload-key",
            "sha256": "sha256",
            "original_filename": "sample.bin",
        }
    )

    download_file.assert_not_awaited()
    execute_sandbox.assert_not_awaited()
    update_result.assert_awaited_once_with("job-1", stored_report)
    update_artifact_risk.assert_awaited_once_with(
        artifact_id="artifact-1",
        verdict="suspicious",
        score=55,
        risk_level="medium",
        policy_version=POLICY_VERSION,
    )
    update_status.assert_awaited_once_with(
        "job-1",
        "done",
        current_stage=None,
        stages_done=settings.stages_total,
    )
    assert result == {
        "job_id": "job-1",
        "status": "done",
        "verdict": "suspicious",
        "score": 55,
    }


@pytest.mark.asyncio
async def test_finalize_deferred_sandbox_job_tolerates_artifact_risk_failure(
    mocker,
    tmp_path,
) -> None:
    from malscan_worker.pipeline import finalize_deferred_sandbox_job, settings

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"sample")
    partial_report = {
        "results": {
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": False,
            }
        }
    }
    final_report = {
        "results": {
            "sandbox": {
                "executed": True,
                "provider": "capev2",
                "task_id": "42",
                "behaviors": [],
                "network_connections": [],
                "is_mock": False,
            }
        },
        "verdict": "suspicious",
        "score": 55,
        "risk_level": "medium",
        "risk": {"policy_version": POLICY_VERSION},
    }
    job_instance = type(
        "Job",
        (),
        {"result": partial_report, "artifact_id": "artifact-1"},
    )()

    mocker.patch("malscan_worker.pipeline.AsyncSession", DummySession)
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=sample_file,
    )
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=job_instance,
    )
    mocker.patch(
        "malscan_worker.pipeline.execute_sandbox_analysis",
        new_callable=AsyncMock,
        return_value=final_report["results"]["sandbox"],
    )
    mocker.patch(
        "malscan_worker.pipeline._apply_direct_risk_to_report",
        return_value=final_report,
    )
    update_result = mocker.patch(
        "malscan_worker.pipeline.update_job_result_strict",
        new_callable=AsyncMock,
    )
    mocker.patch(
        "malscan_worker.pipeline.update_artifact_risk",
        new_callable=AsyncMock,
        side_effect=RuntimeError("artifact update failed"),
    )
    update_status = mocker.patch(
        "malscan_worker.pipeline.update_job_status",
        new_callable=AsyncMock,
    )

    result = await finalize_deferred_sandbox_job(
        {
            "job_id": "job-2",
            "file_id": "file-2",
            "storage_key": "upload-key",
            "sha256": "sha256",
            "original_filename": "sample.bin",
        }
    )

    update_result.assert_awaited_once_with("job-2", final_report)
    update_status.assert_awaited_once_with(
        "job-2",
        "done",
        current_stage=None,
        stages_done=settings.stages_total,
    )
    assert result == {
        "job_id": "job-2",
        "status": "done",
        "verdict": "suspicious",
        "score": 55,
    }
