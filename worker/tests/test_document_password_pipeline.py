"""Document password waits checkpoint safe findings and reuse original scan stages."""

import hashlib
import json
from datetime import datetime, timezone

import pytest
from malscan_worker.exceptions import (
    DocumentPasswordRequiredError,
    DocumentWrongPasswordError,
)
from malscan_worker.pipeline import (
    _restore_checkpoint,
    build_analysis_result,
    execute_analysis_stages,
)
from malscan_worker.stages.base import StageContext, StageResult


class _CountingStage:
    def __init__(self, name, findings=None):
        self.name = name
        self.calls = 0
        self.findings = findings or {}

    async def execute(self, ctx):
        self.calls += 1
        now = datetime.now(timezone.utc)
        return StageResult(self.name, "ok", now, now, 1, self.findings, [])


class _PasswordFormat(_CountingStage):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(
            "format-analysis",
            {"analyzer": kind, "features": {"content_access": "decrypted_child"}},
        )

    async def execute(self, ctx):
        self.calls += 1
        if ctx.archive_password is None:
            raise DocumentPasswordRequiredError(self.kind)
        if ctx.archive_password != f"correct-{self.kind}-test-credential":
            # Deliberately unsafe exception text verifies it is never persisted.
            raise DocumentWrongPasswordError(
                "office" if self.kind == "office" else f"reject {ctx.archive_password}"
            )
        now = datetime.now(timezone.utc)
        return StageResult(self.name, "ok", now, now, 1, self.findings, [])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["pdf", "office"])
async def test_required_wrong_and_correct_document_resume_keep_completed_scan_results(
    tmp_path, capsys, kind
):
    sample = tmp_path / f"encrypted.{kind}"
    sample.write_bytes(b"original immutable encrypted PDF fixture identity")
    original = sample.read_bytes()
    ctx = StageContext(
        job_id="11111111-1111-4111-8111-111111111111",
        file_id="11111111-1111-4111-8111-111111111111",
        storage_key="source",
        sha256=hashlib.sha256(original).hexdigest(),
        original_filename=sample.name,
        file_path=sample,
        artifact_id="11111111-1111-4111-8111-111111111111",
        root_artifact_id="11111111-1111-4111-8111-111111111111",
    )
    parallel = [
        _CountingStage("file-type", {"mime_type": "application/pdf"}),
        _CountingStage("clamav", {"infected": False}),
        _CountingStage("yara", {"matches": []}),
        _CountingStage("ioc-extract"),
        _CountingStage("deobfuscation"),
    ]
    formatter = _PasswordFormat(kind)
    sequential = [_CountingStage("archive-extract"), _CountingStage("document-analysis")]
    checkpoints = []

    async def save(results):
        checkpoints.append(build_analysis_result(ctx.job_id, ctx.file_id, ctx, results, 5))

    for password, error, content_access in (
        (None, DocumentPasswordRequiredError, "password_required"),
        (f"wrong-{kind}-test-credential", DocumentWrongPasswordError, "wrong_password"),
    ):
        ctx.archive_password = password
        initial = _restore_checkpoint(checkpoints[-1], ctx) if checkpoints else []
        with pytest.raises(error) as caught:
            await execute_analysis_stages(
                ctx,
                initial_results=initial,
                parallel_stages=parallel,
                format_stage=formatter,
                sequential_stages=sequential,
                on_checkpoint=save,
            )
        blocked = caught.value.completed_results[-1]
        assert blocked.stage_name == "format-analysis"
        assert blocked.status == "password_required"
        assert blocked.findings == {
            "analyzer": kind,
            "format_type": kind.upper(),
            "features": {"encrypted": True, "content_access": content_access},
            "password_kind": kind,
            "reason": ("Office" if kind == "office" else "PDF")
            + (" password was rejected" if password else " password is required"),
        }
        assert checkpoints[-1]["analysis"]["static"]["status"] == "password_required"
        assert all(stage.calls == 1 for stage in parallel)
        assert all(stage.calls == 0 for stage in sequential)

    ctx.archive_password = f"correct-{kind}-test-credential"
    final = await execute_analysis_stages(
        ctx,
        initial_results=_restore_checkpoint(checkpoints[-1], ctx),
        parallel_stages=parallel,
        format_stage=formatter,
        sequential_stages=sequential,
        on_checkpoint=save,
    )
    assert all(result.status == "ok" for result in final)
    assert all(stage.calls == 1 for stage in parallel)
    assert all(stage.calls == 1 for stage in sequential)
    assert formatter.calls == 3
    assert sample.read_bytes() == original
    captured = capsys.readouterr()
    serialized = json.dumps(checkpoints) + captured.out + captured.err
    assert f"correct-{kind}-test-credential" not in serialized
    assert f"wrong-{kind}-test-credential" not in serialized


@pytest.mark.parametrize("kind", ["pdf", "office"])
def test_document_password_exhaustion_blocks_format_without_erasing_existing_detections(
    tmp_path, kind
):
    from malscan_worker.reporting import build_password_attempts_exhausted_report

    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"encrypted identity")
    ctx = StageContext(
        job_id="11111111-1111-4111-8111-111111111111",
        file_id="11111111-1111-4111-8111-111111111111",
        storage_key="source",
        sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
        original_filename=sample.name,
        file_path=sample,
    )
    now = datetime.now(timezone.utc)
    partial = build_analysis_result(
        ctx.job_id,
        ctx.file_id,
        ctx,
        [
            StageResult(
                "clamav", "ok", now, now, 1, {"infected": True, "threat_name": "Test.Marker"}, []
            ),
            StageResult(
                "format-analysis",
                "password_required",
                now,
                now,
                0,
                {
                    "analyzer": kind,
                    "format_type": kind.upper(),
                    "password_kind": kind,
                    "features": {"encrypted": True, "content_access": "wrong_password"},
                },
                [],
            ),
            StageResult("archive-extract", "pending", now, now, 0, {}, []),
        ],
        1,
    )
    final = build_password_attempts_exhausted_report(
        {"job_id": ctx.job_id, "file_id": ctx.file_id},
        existing_report=partial,
    )
    assert final["score"] == partial["score"] == 95
    assert final["risk"]["evidence"] == partial["risk"]["evidence"]
    assert final["results"]["av_result"]["infected"] is True
    assert final["results"]["format_analysis"]["decryption_failed"] is True
    assert "extraction_failed" not in final["results"]["archive_extract"]
    format_stage = next(
        stage for stage in final["stages"] if stage["stage_name"] == "format-analysis"
    )
    assert format_stage["status"] == "blocked"
    assert format_stage["findings"]["password_kind"] == kind
    assert not any(stage["status"] == "password_required" for stage in final["stages"])
    assert final["analysis"]["static"]["status"] == "partial"
    diagnostics = final["explainability"]["failure_diagnostics"]
    assert diagnostics["diagnostics"][0]["stage"] == "format-analysis"
    assert diagnostics["diagnostics"][0]["code"] == "password_attempts_exhausted"
    assert partial["stages"][1]["status"] == "password_required"
