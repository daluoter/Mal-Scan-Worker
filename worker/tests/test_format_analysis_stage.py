"""Tests for format analysis stage dispatch and result shaping."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from malscan_worker.analyzers.base import AnalyzerResult
from malscan_worker.heuristics.models import make_hit
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.format_analysis import FormatAnalysisStage


class _FakeRegistry:
    def __init__(self, analyzer: Any) -> None:
        self._analyzer = analyzer

    def detect(self, file_path: Path, mime: str) -> Any:
        del file_path, mime
        return self._analyzer


class _FakeSubmitter:
    def __init__(self) -> None:
        self.calls = 0
        self.raise_on_submit = False

    async def submit_subjob(self, **kwargs: Any) -> str:
        del kwargs
        if self.raise_on_submit:
            raise RuntimeError("submit boom")
        self.calls += 1
        return f"subjob-{self.calls}"


def _ctx(tmp_path: Path, *, with_file: bool = True, with_job: bool = False) -> StageContext:
    file_path: Path | None = tmp_path / "sample.bin"
    if with_file:
        assert file_path is not None
        file_path.write_bytes(b"MZ test payload")
    else:
        file_path = None

    previous = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": "application/x-dosexec"},
            artifacts=[],
        )
    ]

    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="key",
        sha256="a" * 64,
        original_filename="sample.bin",
        file_path=file_path,
        previous_results=previous,
    )

    if with_job:
        ctx.job = SimpleNamespace(id=uuid.uuid4(), depth=0)

    return ctx


@pytest.mark.asyncio
async def test_name_property() -> None:
    stage = FormatAnalysisStage()
    assert stage.name == "format-analysis"


@pytest.mark.asyncio
async def test_skip_when_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(None),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path, with_file=False))

    assert result.status == "skipped"
    assert "reason" in result.findings


@pytest.mark.asyncio
async def test_skip_when_no_analyzer_matched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(None),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    assert result.status == "skipped"
    assert result.findings["reason"] == "No analyzer matched"


@pytest.mark.asyncio
async def test_dispatch_to_analyzer_and_returns_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                risk_score=42,
                risk_factors=["high_entropy_section"],
                indicators=[{"type": "test", "severity": "low", "detail": "ok"}],
                features={"entrypoint": 4096},
                extracted_strings=[str(i) for i in range(250)],
                extracted_artifacts=[
                    {"path": str(artifact_path), "filename": "child.bin", "size": 13}
                ],
                errors=[],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        del kwargs
        return {"id": str(uuid.uuid4())}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path, with_job=True))

    assert result.status == "ok"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["format_type"] == "PE"
    assert result.findings["sub_jobs_created"] == 1
    assert result.findings["extracted_artifacts_count"] == 1
    assert len(result.findings["extracted_strings"]) == 200


@pytest.mark.asyncio
async def test_findings_include_expected_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analyzer:
        name = "script"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="script",
                format_type="SCRIPT",
                risk_score=0,
                risk_factors=[],
                indicators=[],
                features={"script_type": "batch"},
                extracted_strings=["one"],
                extracted_artifacts=[],
                errors=[],
            )

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    expected = {
        "analyzer",
        "format_type",
        "risk_score",
        "risk_factors",
        "indicators",
        "features",
        "extracted_strings",
        "extracted_artifacts_count",
        "sub_jobs_created",
        "errors",
    }
    assert result.status == "ok"
    assert expected.issubset(result.findings.keys())


@pytest.mark.asyncio
async def test_analyzer_exception_returns_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    assert result.status == "failed"
    assert result.error is not None
    assert "boom" in result.error


@pytest.mark.asyncio
async def test_submit_subjob_exception_preserves_partial_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[{"path": str(artifact_path), "filename": "child.bin"}],
            )

    fake_submitter = _FakeSubmitter()
    fake_submitter.raise_on_submit = True

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        del kwargs
        return {"id": "artifact-1"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path, with_job=True))

    assert result.status == "partial"
    assert result.findings["sub_jobs_created"] == 0
    assert any("sub-job submit failed" in e for e in result.findings["errors"])


@pytest.mark.asyncio
async def test_create_artifact_exception_preserves_partial_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[{"path": str(artifact_path), "filename": "child.bin"}],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        del kwargs
        raise RuntimeError("artifact create boom")

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)
    ctx.root_artifact_id = "root-id"
    ctx.artifact_id = "parent-id"

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "partial"
    assert any("artifact create boom" in e for e in result.findings["errors"])


@pytest.mark.asyncio
async def test_cycle_detected_artifact_skipped_no_subjob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")
    artifact_sha = "b" * 64

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[
                    {"path": str(artifact_path), "filename": "child.bin", "sha256": artifact_sha}
                ],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    created: list[dict[str, Any]] = []

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        created.append(kwargs)
        return {"id": "artifact-1"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)
    ctx.root_artifact_id = "root-id"
    ctx.artifact_id = "parent-id"
    ctx.ancestor_hashes = {artifact_sha}

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert result.findings["sub_jobs_created"] == 0
    assert fake_submitter.calls == 0
    assert len(created) == 1
    assert created[0]["extraction_note"] == "ancestor_cycle"


@pytest.mark.asyncio
async def test_duplicate_within_extraction_skips_second_duplicate_subjob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_one = tmp_path / "child-1.bin"
    artifact_two = tmp_path / "child-2.bin"
    artifact_one.write_bytes(b"same")
    artifact_two.write_bytes(b"same")
    shared_sha = "c" * 64

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[
                    {
                        "path": str(artifact_one),
                        "filename": "child-1.bin",
                        "sha256": shared_sha,
                    },
                    {
                        "path": str(artifact_two),
                        "filename": "child-2.bin",
                        "sha256": shared_sha,
                    },
                ],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    created: list[dict[str, Any]] = []

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        created.append(kwargs)
        return {"id": f"artifact-{len(created)}"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)
    ctx.root_artifact_id = "root-id"
    ctx.artifact_id = "parent-id"

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert result.findings["sub_jobs_created"] == 1
    assert fake_submitter.calls == 1
    assert len(created) == 2
    assert created[1]["verdict"] == "skipped"
    assert created[1]["extraction_note"] == "duplicate_within_extraction"


@pytest.mark.asyncio
async def test_root_artifact_ids_are_written_back_to_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[{"path": str(artifact_path), "filename": "child.bin"}],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    created: list[dict[str, Any]] = []

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        created.append(kwargs)
        return {"id": "root-artifact" if len(created) == 1 else "child-artifact"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert created[0]["parent_id"] is None
    assert created[1]["parent_id"] == "root-artifact"
    assert ctx.root_artifact_id == "root-artifact"
    assert ctx.artifact_id == "root-artifact"


@pytest.mark.asyncio
async def test_submitted_artifacts_keep_original_root_job_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[{"path": str(artifact_path), "filename": "child.bin"}],
            )

    submit_kwargs: list[dict[str, Any]] = []

    class _TrackingSubmitter:
        async def submit_subjob(self, **kwargs: Any) -> str:
            submit_kwargs.append(kwargs)
            return "subjob-1"

    async def _fake_get_submitter() -> _TrackingSubmitter:
        return _TrackingSubmitter()

    created: list[dict[str, Any]] = []

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        created.append(kwargs)
        return {"id": "artifact-root" if len(created) == 1 else "artifact-child"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)
    ctx.job_id = str(uuid.uuid4())
    original_root_job_id = str(uuid.uuid4())
    ctx.root_job_id = original_root_job_id  # type: ignore[attr-defined]

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert created[0]["root_job_id"] == original_root_job_id
    assert created[1]["root_job_id"] == original_root_job_id
    assert submit_kwargs[0]["root_job_id"] == original_root_job_id


@pytest.mark.asyncio
async def test_max_depth_guard_skips_artifact_creation_and_subjob_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                extracted_artifacts=[{"path": str(artifact_path), "filename": "child.bin"}],
            )

    submitter_calls = 0

    class _TrackingSubmitter:
        async def submit_subjob(self, **kwargs: Any) -> str:
            del kwargs
            nonlocal submitter_calls
            submitter_calls += 1
            return "subjob-1"

    get_instance_calls = 0

    async def _fake_get_submitter() -> _TrackingSubmitter:
        nonlocal get_instance_calls
        get_instance_calls += 1
        return _TrackingSubmitter()

    create_artifact_calls = 0

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        del kwargs
        nonlocal create_artifact_calls
        create_artifact_calls += 1
        return {"id": "artifact-1"}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_settings",
        lambda: SimpleNamespace(max_job_depth=3),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    ctx = _ctx(tmp_path, with_job=True)
    ctx.job = SimpleNamespace(id=uuid.uuid4(), depth=3)

    stage = FormatAnalysisStage()
    result = await stage.execute(ctx)

    assert result.status == "partial"
    assert result.findings["sub_jobs_created"] == 0
    assert create_artifact_calls == 0
    assert get_instance_calls == 0
    assert submitter_calls == 0


@pytest.mark.asyncio
async def test_format_stage_preserves_heuristics_in_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analyzer:
        name = "script"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="script",
                format_type="SCRIPT",
                heuristics=[
                    make_hit(
                        key="script.encoded_command_execution",
                        category="script_token",
                        scope="script",
                        role="gate_signal",
                        severity="high",
                        confidence=0.9,
                        summary="Encoded payload and execution primitives appear together",
                        evidence={"matched": ["powershell", "-enc"]},
                    )
                ],
            )

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    assert result.findings["heuristics"][0]["key"] == "script.encoded_command_execution"
    assert result.findings["heuristics"][0]["evidence"] == {"matched": ["powershell", "-enc"]}
    assert isinstance(result.findings["heuristics"][0]["evidence"], dict)
