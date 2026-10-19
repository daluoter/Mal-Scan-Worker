"""Real encrypted ZIP/PDF content keeps its risk across every enclosing layer."""

from datetime import datetime, timezone

import pytest
from malscan_worker.quality.pdf_password_fixtures import (
    ARCHIVE_PASSWORD,
    PDF_PASSWORD,
    build_pdf_password_fixture,
)
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageResult
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage


class CleanAV:
    name = "clamav"

    async def execute(self, ctx):
        now = datetime.now(timezone.utc)
        return StageResult(self.name, "ok", now, now, 0, {"infected": False}, [])


def _runner(directory, manifest, passwords=None):
    return RootBatchRunner(
        manifest=manifest,
        source_store=LocalObjectStore(directory, read_only=True),
        result_store=LocalObjectStore(directory / "results"),
        state_dir=directory / "state",
        passwords=passwords,
        parallel_stages=[FileTypeStage(), CleanAV()],
        format_stage=FormatAnalysisStage(),
        sequential_stages=[ArchiveExtractStage(), DocumentAnalysisStage()],
    )


async def _unlocked_nested(directory):
    source = directory / "outer.zip"
    source.write_bytes(build_pdf_password_fixture("zip-aes-pdf-aes-128"))
    manifest = AnalysisManifest.for_local_file(source)
    first = await _runner(directory, manifest).run()
    assert first["job_status"] == "password_required"
    second = await _runner(directory, manifest, {manifest.root_job_id: ARCHIVE_PASSWORD}).run(
        resume=True
    )
    inner = second["password_required_artifacts"][0]
    final = await _runner(directory, manifest, {inner: PDF_PASSWORD}).run(resume=True)
    return manifest, final


@pytest.mark.asyncio
async def test_decrypted_pdf_sets_effective_parent_and_root_risk_without_faking_local_evidence(
    tmp_path,
):
    manifest, report = await _unlocked_nested(tmp_path)
    assert report["score"] == report["risk"]["risk_score"] == 84
    assert report["risk_level"] == report["risk"]["risk_level"] == "high"
    assert report["verdict"] == report["risk"]["legacy_verdict"] == "suspicious"
    assert report["risk"]["local_risk"]["score"] == 6
    assert report["risk"]["independent_source_count"] == 1
    assert report["results"]["av_result"]["infected"] is False
    parent = next(node for node in report["artifacts"] if node["depth"] == 1)
    child = next(node for node in report["artifacts"] if node["depth"] == 2)
    assert child["original_filename"] == "decrypted.pdf"
    assert parent["original_filename"] == "locked.pdf"
    assert parent["report"]["score"] == child["report"]["score"] == 84
    assert parent["report"]["risk"]["local_risk"]["score"] == 0
    assert child["report"]["risk"]["local_risk"]["score"] == 84
    assert parent["report"]["risk"]["independent_source_count"] == 0
    tree = report["artifact_tree"]
    for node in (tree, tree["children"][0], tree["children"][0]["children"][0]):
        assert node["score"] == 84
        assert node["risk_level"] == "high"
    assert tree["local_score"] == 6
    assert tree["children"][0]["local_score"] == 0
    assert tree["children"][0]["children"][0]["local_score"] == 84
    # Direct checkpoints remain immutable and a completed replay does not add
    # the effective parent as another independent dangerous descendant.
    runner = _runner(tmp_path, manifest)
    repeated = await runner.run(resume=True)
    assert runner.artifacts[parent["artifact_id"]]["report"]["score"] == 0
    assert repeated["score"] == 84
    assert repeated["risk"]["breakdown"]["inherited_score"] == 17
    assert repeated["risk"]["descendant_summary"]["high_descendants"] == 1
    assert (
        repeated["risk"]["descendant_summary"]["strongest_verified_descendant"]["artifact_id"]
        == child["artifact_id"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("identity_field", ["sha256", "size", "original_filename", "job_id"])
async def test_foreign_or_mismatched_child_report_cannot_authorize_effective_risk_floor(
    tmp_path, identity_field
):
    manifest, final = await _unlocked_nested(tmp_path)
    child_id = next(node["artifact_id"] for node in final["artifacts"] if node["depth"] == 2)
    runner = _runner(tmp_path, manifest)
    await runner._load(resume=True)
    direct = runner.artifacts[child_id]["report"]
    if identity_field == "job_id":
        direct["job_id"] = "foreign-job"
    else:
        direct["file"][identity_field] = 9999 if identity_field == "size" else "foreign-value"
    report = runner._report()
    assert report["risk"]["breakdown"]["descendant_floor"] == 0
    assert report["risk"]["descendant_summary"]["strongest_verified_descendant"] is None
    parent = next(node for node in report["artifacts"] if node["depth"] == 1)
    assert parent["report"]["risk"]["breakdown"]["descendant_floor"] == 0


@pytest.mark.asyncio
async def test_known_dangerous_plaintext_retains_risk_while_another_pdf_still_needs_password(
    tmp_path,
):
    import zipfile

    source = tmp_path / "two-pdfs.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("active.pdf", build_pdf_password_fixture("aes-128-active-actions"))
        archive.writestr("other.pdf", build_pdf_password_fixture("aes-128-normal"))
    manifest = AnalysisManifest.for_local_file(source)
    waiting = await _runner(tmp_path, manifest).run()
    active = next(
        node for node in waiting["artifacts"] if node["original_filename"] == "active.pdf"
    )
    report = await _runner(tmp_path, manifest, {active["artifact_id"]: PDF_PASSWORD}).run(
        resume=True
    )
    assert report["report_complete"] is False
    assert report["job_status"] == "password_required"
    assert report["analysis"]["static"]["status"] == "password_required"
    assert report["score"] == 84
    assert report["risk_level"] == "high"
    assert report["risk"]["breakdown"]["descendant_floor"] > 0
    assert len(report["password_required_artifacts"]) == 1
