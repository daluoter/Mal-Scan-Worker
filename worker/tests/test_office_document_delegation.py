"""The Office envelope is not sent back through legacy document parsers."""

from datetime import datetime, timezone

import pytest
from malscan_worker.pipeline import build_analysis_result, execute_analysis_stages
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.document_analysis import DocumentAnalysisStage


@pytest.mark.asyncio
@pytest.mark.parametrize("access", ["decrypted_child", "unsupported", "unavailable"])
async def test_pipeline_delegates_encrypted_envelope_before_legacy_parser(
    tmp_path, monkeypatch, access
):
    source = tmp_path / "encrypted.docx"
    source.write_bytes(b"encrypted fixture envelope")
    ctx = StageContext("job", "file", "source", "a" * 64, source.name, source)

    def detect(*args):
        pytest.fail("The encrypted envelope reached the legacy document parser")

    monkeypatch.setattr("malscan_worker.stages.document_analysis.detect_document_type", detect)

    class Formatter:
        name = "format-analysis"

        async def execute(self, ctx):
            now = datetime.now(timezone.utc)
            return StageResult(
                self.name,
                "ok" if access == "decrypted_child" else "partial",
                now,
                now,
                0,
                {"analyzer": "office", "features": {"encrypted": True, "content_access": access}},
                ["already-verified-and-submitted-child"] if access == "decrypted_child" else [],
            )

    results = await execute_analysis_stages(
        ctx,
        parallel_stages=[],
        format_stage=Formatter(),
        sequential_stages=[DocumentAnalysisStage()],
    )
    assert results[-1].status == "skipped"
    assert results[-1].findings["content_access"] == access
    assert ("delegated" if access == "decrypted_child" else "unavailable") in results[-1].findings[
        "reason"
    ]
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, results, 0)
    if access != "decrypted_child":
        assert report["analysis"]["static"]["status"] == "partial"


@pytest.mark.asyncio
@pytest.mark.parametrize("analyzer, encrypted", [("office", False), ("pdf", True)])
async def test_delegation_does_not_suppress_other_document_analysis(
    tmp_path, monkeypatch, analyzer, encrypted
):
    source = tmp_path / "ordinary.docx"
    source.write_bytes(b"ordinary fixture")
    now = datetime.now(timezone.utc)
    ctx = StageContext("job", "file", "source", "a" * 64, source.name, source)
    ctx.previous_results = [
        StageResult(
            "format-analysis",
            "ok",
            now,
            now,
            0,
            {
                "analyzer": analyzer,
                "features": {"encrypted": encrypted, "content_access": "decrypted_child"},
            },
            [],
        )
    ]
    calls = []

    def detect(*args):
        calls.append(args)
        return None

    monkeypatch.setattr("malscan_worker.stages.document_analysis.detect_document_type", detect)
    result = await DocumentAnalysisStage().execute(ctx)
    assert len(calls) == 1
    assert result.findings["reason"] == "Not a supported document format"
