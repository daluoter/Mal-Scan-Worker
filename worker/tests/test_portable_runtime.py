"""Executable portable runtime acceptance: recursion, password waits and recovery."""

import asyncio
import bz2
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pyzipper
from malscan_worker.budget import BudgetLimits
from malscan_worker.runtime import (
    AnalysisManifest,
    LocalObjectStore,
    RootBatchRunner,
    S3ObjectStore,
)
from malscan_worker.runtime.manifest import SourceReference, file_identity
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageResult
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from malscan_worker.stages.ioc_extract import IocExtractStage


class CountingStage:
    name = "clamav"

    def __init__(self):
        self.calls = []

    async def execute(self, ctx):
        from datetime import datetime, timezone

        self.calls.append(ctx.artifact_id)
        assert ctx.file_path.stat().st_mode & 0o222 == 0
        now = datetime.now(timezone.utc)
        return StageResult(self.name, "ok", now, now, 0, {"infected": False}, [])


def _runner(tmp_path, manifest, *, passwords=None, counter=None, **kwargs):
    return RootBatchRunner(
        manifest=manifest,
        source_store=LocalObjectStore(tmp_path, read_only=True),
        result_store=LocalObjectStore(tmp_path / "results"),
        state_dir=tmp_path / "state",
        passwords=passwords,
        parallel_stages=[FileTypeStage(), IocExtractStage(), counter or CountingStage()],
        format_stage=FormatAnalysisStage(),
        sequential_stages=[ArchiveExtractStage(), DocumentAnalysisStage()],
        **kwargs,
    )


def _zip(path, files, password=None):
    if password:
        with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(password.encode())
            for name, data in files.items():
                archive.writestr(name, data)
    else:
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)


@pytest.mark.asyncio
async def test_real_nested_archives_preserve_duplicate_paths_and_scan_every_node(tmp_path):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"payload.ps1": b"Write-Output 'https://nested.example/path'"})
    outer = tmp_path / "outer.zip"
    _zip(outer, {"one/inner.zip": inner.read_bytes(), "two/inner.zip": inner.read_bytes()})
    original = file_identity(outer)
    manifest = AnalysisManifest.for_local_file(outer)
    counter = CountingStage()
    report = await _runner(tmp_path, manifest, counter=counter).run()
    nodes = report["artifacts"]
    assert len(nodes) == 5
    assert len(counter.calls) == 5
    assert len({node["artifact_id"] for node in nodes}) == 5
    assert len({node["sha256"] for node in nodes}) == 3
    assert {node["origin_path"] for node in nodes if node["depth"] == 1} == {
        "one/inner.zip",
        "two/inner.zip",
    }
    scripts = [node for node in nodes if node["depth"] == 2]
    assert all(
        node["report"]["results"]["format_analysis"]["format_type"] == "SCRIPT" for node in scripts
    )
    assert all(
        "https://nested.example/path" in node["report"]["results"]["iocs"]["urls"]
        for node in scripts
    )
    assert file_identity(outer) == original
    assert report["report_complete"] is True
    assert report["job_status"] == "done"
    assert report["execution_budget"]["used_files"] == 4
    assert json.loads((tmp_path / "results" / "report.json").read_text())["artifacts"] == nodes
    assert not list((tmp_path / "state" / "work").glob("*/input.*"))


@pytest.mark.asyncio
async def test_real_archive_duplicate_entries_keep_occurrences_and_accounting(tmp_path):
    source = tmp_path / "duplicates.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("same.txt", b"same child bytes")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("same.txt", b"same child bytes")
    counter = CountingStage()
    report = await _runner(tmp_path, AnalysisManifest.for_local_file(source), counter=counter).run()
    children = [node for node in report["artifacts"] if node["depth"] == 1]
    assert len(children) == 2
    assert len({node["artifact_id"] for node in children}) == 2
    assert {node["occurrence_index"] for node in children} == {0, 1}
    assert {node["origin_path"] for node in children} == {"same.txt"}
    assert len({node["storage_key"] for node in children}) == 1
    assert len(counter.calls) == 3
    assert report["execution_budget"]["used_files"] == 2
    assert report["execution_budget"]["used_bytes"] == 2 * len(b"same child bytes")


@pytest.mark.asyncio
@pytest.mark.parametrize("child_count,expected_level", [(1, "high"), (2, "malicious")])
async def test_child_detection_rollup_keeps_public_risk_verdict_and_gates_consistent(
    tmp_path, child_count, expected_level
):
    class ChildDetectionStage(CountingStage):
        async def execute(self, ctx):
            now = datetime.now(timezone.utc)
            findings = {"infected": ctx.depth > 0}
            if findings["infected"]:
                findings["threat_name"] = "Contract-Test-Signature"
            return StageResult(self.name, "ok", now, now, 0, findings, [])

    source = tmp_path / "child-detections.zip"
    _zip(
        source,
        {f"child-{index}": f"unique child {index}".encode() for index in range(child_count)},
    )

    report = await _runner(
        tmp_path, AnalysisManifest.for_local_file(source), counter=ChildDetectionStage()
    ).run()

    assert report["report_complete"] is True
    assert report["risk_level"] == expected_level
    assert report["risk"]["risk_level"] == report["risk_level"]
    assert report["risk"]["risk_score"] == report["score"]
    expected_verdict = "malicious" if child_count == 2 else "suspicious"
    assert report["verdict"] == report["risk"]["legacy_verdict"] == expected_verdict
    assert report["risk"]["high_gate_open"] is True
    assert report["risk"]["malicious_gate_open"] is (child_count == 2)
    breakdown = report["risk"]["breakdown"]
    assert breakdown["high_gate_open"] == report["risk"]["high_gate_open"]
    assert breakdown["malicious_gate_open"] == report["risk"]["malicious_gate_open"]
    assert breakdown["local_score"] == 0
    assert breakdown["inherited_score"] > 0
    assert report["results"]["av_result"]["infected"] is False
    assert all(
        node["report"]["results"]["av_result"]["infected"] is True
        for node in report["artifacts"]
        if node["depth"] == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix,compress", [("gz", gzip.compress), ("bz2", bz2.compress)])
async def test_single_stream_archives_use_default_occurrence(tmp_path, suffix, compress):
    source = tmp_path / f"payload.txt.{suffix}"
    source.write_bytes(compress(b"same child bytes"))
    counter = CountingStage()
    report = await _runner(tmp_path, AnalysisManifest.for_local_file(source), counter=counter).run()
    children = [node for node in report["artifacts"] if node["depth"] == 1]
    assert len(children) == 1 and children[0]["occurrence_index"] == 0
    assert len(counter.calls) == 2
    assert children[0]["status"] == "done"
    assert report["execution_budget"]["used_files"] == 1
    assert report["execution_budget"]["used_bytes"] == len(b"same child bytes")


@pytest.mark.asyncio
async def test_nested_different_passwords_resume_same_tree_without_rescanning(tmp_path):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"payload.txt": b"https://password.example/file"}, "inner-test-secret")
    outer = tmp_path / "outer.zip"
    _zip(outer, {"inner.zip": inner.read_bytes()}, "outer-test-secret")
    manifest = AnalysisManifest.for_local_file(outer)
    counter = CountingStage()
    first = await _runner(
        tmp_path, manifest, counter=counter, passwords={manifest.root_job_id: "outer-test-secret"}
    ).run()
    waiting = next(node for node in first["artifacts"] if node["status"] == "password_required")
    assert waiting["depth"] == 1
    assert first["analysis"]["static"]["status"] == "password_required"
    assert first["artifact_tree"]["analysis_status"] == "password_required"
    assert len(counter.calls) == 2
    counters_before = first["execution_budget"]["used_files"]
    wrong = await _runner(
        tmp_path,
        manifest,
        counter=counter,
        passwords={waiting["artifact_id"]: "incorrect-test-secret"},
    ).run(resume=True)
    assert (
        next(node for node in wrong["artifacts"] if node["artifact_id"] == waiting["artifact_id"])[
            "reason"
        ]
        == "wrong_password"
    )
    assert len(counter.calls) == 2
    final = await _runner(
        tmp_path, manifest, counter=counter, passwords={waiting["artifact_id"]: "inner-test-secret"}
    ).run(resume=True)
    assert len(counter.calls) == 3
    assert final["report_complete"] is True
    assert final["job_status"] == "done"
    assert len(final["artifacts"]) == 3
    assert final["execution_budget"]["used_files"] == counters_before + 1
    assert final["artifacts"][1]["artifact_id"] == waiting["artifact_id"]
    persisted = (tmp_path / "state" / "checkpoint.json").read_text()
    for secret in ("outer-test-secret", "inner-test-secret", "incorrect-test-secret"):
        assert secret not in persisted
        assert secret not in json.dumps(final)


@pytest.mark.asyncio
async def test_checkpoint_recovers_from_persistent_store_after_local_state_loss(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"https://resume.example/path")
    manifest = AnalysisManifest.for_local_file(source)
    counter = CountingStage()
    first = await _runner(tmp_path, manifest, counter=counter).run()
    (tmp_path / "state" / "checkpoint.json").unlink()
    source.unlink()
    restored = await _runner(tmp_path, manifest, counter=counter).run(resume=True)
    assert len(counter.calls) == 1
    assert restored["artifacts"] == first["artifacts"]
    assert restored["report_revision"] > first["report_revision"]


@pytest.mark.asyncio
async def test_root_budget_spans_nested_extractions_and_retains_partial_report(tmp_path):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"first.txt": b"first", "second.txt": b"second"})
    outer = tmp_path / "outer.zip"
    _zip(outer, {"inner.zip": inner.read_bytes()})
    report = await _runner(
        tmp_path,
        AnalysisManifest.for_local_file(outer),
        limits=BudgetLimits(max_files=2, max_bytes=10000),
    ).run()
    assert report["execution_budget"]["used_files"] == 2
    assert report["batch_analysis"]["status"] == "partial"
    assert report["analysis"]["static"]["status"] == "partial"
    assert report["artifact_tree"]["analysis_status"] == "partial"
    inner_node = next(node for node in report["artifacts"] if node["depth"] == 1)
    coverage = inner_node["report"]["analysis"]["static"]["stage_coverage"]
    assert any(
        item["stage"] == "archive-extract" and item["status"] == "partial" for item in coverage
    )


@pytest.mark.asyncio
async def test_resume_keeps_new_retention_deadline_and_durable_expansion_counts(tmp_path):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"payload.txt": b"payload"}, "inner-test-secret")
    outer = tmp_path / "outer.zip"
    _zip(outer, {"inner.zip": inner.read_bytes()})
    manifest = AnalysisManifest.for_local_file(outer)
    counter = CountingStage()
    first = await _runner(tmp_path, manifest, counter=counter).run()
    waiting = next(node for node in first["artifacts"] if node["status"] == "password_required")
    resumed = _runner(
        tmp_path,
        manifest,
        counter=counter,
        passwords={waiting["artifact_id"]: "inner-test-secret"},
        limits=BudgetLimits(max_files=2, max_bytes=20000, timeout_seconds=10),
    )
    # A retention deadline can pass while a checkpoint is being downloaded.
    incoming_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    resumed.budget.deadline_at = incoming_deadline
    final = await resumed.run(resume=True)
    assert resumed.budget.deadline_at == incoming_deadline
    assert resumed.budget.limits == BudgetLimits(2, 20000, 10)
    assert final["execution_budget"]["used_files"] == first["execution_budget"]["used_files"]
    assert final["execution_budget"]["used_bytes"] == first["execution_budget"]["used_bytes"]
    assert len(counter.calls) == 2
    limited = next(
        node for node in final["artifacts"] if node["artifact_id"] == waiting["artifact_id"]
    )
    assert limited["status"] == "limited" and limited["reason"] == "analysis_attempt_deadline"
    assert final["analysis"]["static"]["status"] == "partial"


@pytest.mark.asyncio
async def test_resume_lower_depth_cannot_reopen_waiting_child(tmp_path):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"payload.txt": b"payload"}, "inner-test-secret")
    outer = tmp_path / "outer.zip"
    _zip(outer, {"inner.zip": inner.read_bytes()})
    manifest = AnalysisManifest.for_local_file(outer)
    counter = CountingStage()
    first = await _runner(tmp_path, manifest, counter=counter).run()
    waiting = next(node for node in first["artifacts"] if node["status"] == "password_required")
    final = await _runner(
        tmp_path,
        manifest,
        counter=counter,
        passwords={waiting["artifact_id"]: "inner-test-secret"},
        max_depth=0,
    ).run(resume=True)
    assert len(counter.calls) == 2
    child = next(
        node for node in final["artifacts"] if node["artifact_id"] == waiting["artifact_id"]
    )
    assert child["status"] == "limited" and child["reason"] == "max_depth"
    assert final["execution_budget"]["used_files"] == first["execution_budget"]["used_files"]
    assert final["analysis"]["static"]["status"] == "partial"


@pytest.mark.asyncio
async def test_child_occurrences_keep_distinct_ids_and_retry_identity(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"root sample")
    child = tmp_path / "duplicate.txt"
    child.write_bytes(b"same child bytes")
    manifest = AnalysisManifest.for_local_file(source)
    runner = _runner(tmp_path, manifest)
    await runner.run()
    sha256, size = file_identity(child)
    arguments = {
        "file_path": str(child),
        "filename": "duplicate.txt",
        "content_type": "text/plain",
        "sha256_hash": sha256,
        "file_size": size,
        "parent_job_id": manifest.root_job_id,
        "parent_job_depth": 0,
        "origin_path": "duplicate.txt",
        "extraction_source": "archive",
    }
    first = await runner.submit_child(**arguments, occurrence_index=0)
    second = await runner.submit_child(**arguments, occurrence_index=1)
    retry = await runner.submit_child(**arguments, occurrence_index=0)
    assert first != second and retry == first
    assert len(runner.artifacts) == 3
    assert runner.artifacts[first]["storage_key"] == runner.artifacts[second]["storage_key"]
    for invalid in (-1, True, "1"):
        with pytest.raises(ValueError, match="occurrence index"):
            await runner.submit_child(**arguments, occurrence_index=invalid)


@pytest.mark.asyncio
async def test_resume_rejects_different_manifest_and_does_not_replace_checkpoint(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"sample")
    manifest = AnalysisManifest.for_local_file(source)
    await _runner(tmp_path, manifest).run()
    before = (tmp_path / "state" / "checkpoint.json").read_bytes()
    other = AnalysisManifest.for_local_file(source)
    with pytest.raises(ValueError, match="different source or attempt"):
        await _runner(tmp_path, other).run(resume=True)
    assert (tmp_path / "state" / "checkpoint.json").read_bytes() == before


@pytest.mark.asyncio
async def test_cancelled_attempt_resumes_completed_stage_checkpoint(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"source")
    manifest = AnalysisManifest.for_local_file(source)
    counter = CountingStage()

    class Interrupt(CountingStage):
        name = "continuation"

        async def execute(self, ctx):
            raise asyncio.CancelledError()

    first = _runner(tmp_path, manifest, counter=counter)
    first.sequential_stages = [Interrupt()]
    with pytest.raises(asyncio.CancelledError):
        await first.run()
    resumed = _runner(tmp_path, manifest, counter=counter)
    continuation = CountingStage()
    continuation.name = "continuation"
    resumed.sequential_stages = [continuation]
    await resumed.run(resume=True)
    assert len(counter.calls) == 1
    assert len(continuation.calls) == 1


@pytest.mark.asyncio
async def test_source_integrity_failure_does_not_publish_a_successful_report(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"sample")
    manifest = AnalysisManifest.for_local_file(source)
    source.write_bytes(b"changed")
    with pytest.raises(ValueError, match="identity mismatch|declared size"):
        await _runner(tmp_path, manifest).run()
    assert not (tmp_path / "results" / "report.json").exists()


@pytest.mark.asyncio
async def test_local_store_confines_keys_and_rejects_corrupt_existing_blob(tmp_path):
    store = LocalObjectStore(tmp_path / "store")
    source = tmp_path / "sample"
    source.write_bytes(b"sample")
    sha256, size = file_identity(source)
    for key in ("../outside", "/absolute", "a/../outside", "a\\outside", "a//b"):
        with pytest.raises(ValueError):
            await store.put_file(key, source, sha256=sha256, size=size)
    (tmp_path / "store" / "escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        await store.put_json("escape/outside.json", {})
    await store.put_file("blob", source, sha256=sha256, size=size)
    blob = tmp_path / "store" / "blob"
    blob.chmod(0o600)
    blob.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="Existing object identity mismatch"):
        await store.put_file("blob", source, sha256=sha256, size=size)


@pytest.mark.asyncio
async def test_s3_read_only_source_is_stream_verified_and_connection_released(tmp_path):
    class Response(io.BytesIO):
        released = False

        def release_conn(self):
            self.released = True

    response = Response(b"remote sample")
    client = MagicMock()
    client.get_object.return_value = response
    source = S3ObjectStore(
        endpoint="https://account.r2.cloudflarestorage.com",
        bucket="uploads",
        access_key="test",
        secret_key="test",
        region="auto",
        read_only=True,
        client=client,
    )
    path = await source.fetch(
        "poc/source",
        tmp_path / "input",
        size=13,
        sha256=hashlib.sha256(b"remote sample").hexdigest(),
    )
    assert path.read_bytes() == b"remote sample"
    assert response.closed and response.released
    with pytest.raises(PermissionError):
        await source.put_json("report.json", {})
    client.put_object.assert_not_called()


@pytest.mark.asyncio
async def test_s3_mismatched_object_is_not_adopted(tmp_path):
    response = MagicMock(wraps=io.BytesIO(b"oversized"))
    response.release_conn = MagicMock()
    client = MagicMock()
    client.get_object.return_value = response
    store = S3ObjectStore(
        endpoint="https://s3.example",
        bucket="uploads",
        access_key="test",
        secret_key="test",
        client=client,
    )
    with pytest.raises(ValueError):
        await store.fetch("source", tmp_path / "input", size=3, sha256="a" * 64)
    assert not (tmp_path / "input").exists()
    response.close.assert_called_once()
    response.release_conn.assert_called_once()


def test_default_cli_runs_all_stages_without_service_configuration(tmp_path):
    source = tmp_path / "sample.ps1"
    source.write_bytes(b"Write-Output 'https://cli.example/file'")
    environment = dict(os.environ)
    # Keep this independent of whichever daemon the host happens to expose.
    # A missing optional scanner must preserve functioning IOC analysis and
    # produce explicit partial coverage instead of fake all-stage completion.
    environment["CLAMAV_MODE"] = "cli"
    environment["CLAMAV_CLI_PATH"] = str(tmp_path / "missing-clamscan")
    for name in (
        "DATABASE_URL",
        "MINIO_ENDPOINT",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
        "RABBITMQ_URL",
    ):
        environment.pop(name, None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "malscan_worker.runtime",
            "--file",
            str(source),
            "--output-dir",
            str(tmp_path / "output"),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout.splitlines()[-1])
    assert summary["success"] is True
    report = json.loads((tmp_path / "output" / "report.json").read_text())
    assert {stage["name"] for stage in report["timings"]["stages"]} == {
        "file-type",
        "clamav",
        "yara",
        "ioc-extract",
        "deobfuscation",
        "format-analysis",
        "archive-extract",
        "document-analysis",
        "sandbox",
    }
    assert report["results"]["format_analysis"]["format_type"] == "SCRIPT"
    assert "https://cli.example/file" in report["results"]["iocs"]["urls"]
    statuses = {stage["name"]: stage["status"] for stage in report["timings"]["stages"]}
    assert statuses["ioc-extract"] == "ok"
    assert statuses["clamav"] == "failed"
    assert report["analysis"]["static"]["status"] == "partial"
    assert report["analysis"]["dynamic"]["status"] == "disabled"
    assert file_identity(source) == (
        hashlib.sha256(source.read_bytes()).hexdigest(),
        source.stat().st_size,
    )


def test_manifest_rejects_secret_or_unexpected_fields(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"sample")
    data = AnalysisManifest.for_local_file(source).to_dict()
    data["password"] = "not-allowed"
    with pytest.raises(ValueError, match="fields"):
        AnalysisManifest.from_dict(data)
    with pytest.raises(ValueError):
        SourceReference("source", "a" * 64, True, "sample")


@pytest.mark.asyncio
async def test_checkpoint_stage_mutation_is_rejected_before_any_scan(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"sample")
    manifest = AnalysisManifest.for_local_file(source)
    counter = CountingStage()
    await _runner(tmp_path, manifest, counter=counter).run()
    path = tmp_path / "state" / "checkpoint.json"
    changed = json.loads(path.read_text())
    changed["artifacts"][manifest.root_job_id]["stage_results"][0]["findings"] = {"forged": True}
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="authentication failed"):
        await _runner(tmp_path, manifest, counter=counter).run(resume=True)
    assert len(counter.calls) == 1


@pytest.mark.asyncio
async def test_persistent_checkpoint_tampering_is_rejected_after_cache_loss(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"sample")
    manifest = AnalysisManifest.for_local_file(source)
    await _runner(tmp_path, manifest).run()
    (tmp_path / "state" / "checkpoint.json").unlink()
    path = (
        tmp_path
        / "results"
        / "checkpoints"
        / manifest.root_job_id
        / (manifest.attempt_id + ".json")
    )
    changed = json.loads(path.read_text())
    changed["artifacts"][manifest.root_job_id]["status"] = "done"
    changed["artifacts"][manifest.root_job_id]["stage_results"] = []
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="authentication failed"):
        await _runner(tmp_path, manifest).run(resume=True)


@pytest.mark.asyncio
async def test_report_contract_nested_tree_callback_and_public_budget(tmp_path):
    source = tmp_path / "root.zip"
    _zip(source, {"child.txt": b"https://child.example/file"})
    manifest = AnalysisManifest.for_local_file(source)
    callback = AsyncMock()
    report = await _runner(tmp_path, manifest, on_report=callback).run()
    assert callback.await_count > 0
    assert callback.await_args.args[0] == report
    assert report["report_schema_version"] == "mswr-report-v3"
    assert report["analysis_attempt_id"] == manifest.attempt_id
    assert report["artifact_tree"]["id"] == manifest.root_job_id
    assert report["artifact_tree"]["children"][0]["filename"] == "child.txt"
    assert (
        report["artifact_tree"]["children"][0]["analysis"]["schema_version"] == "mswr-analysis-v1"
    )
    assert report["report_complete"] is True and report["pending_descendants"] == 0
    assert report["job_status"] == "done"
    assert "reservations" not in report["execution_budget"]
    assert "checkpoint_hmac" not in json.dumps(report)
    assert all(
        node["storage_key"].startswith("artifacts/" + manifest.root_job_id + "/")
        for node in report["artifacts"]
    )
    assert report["artifacts"][1]["report"]["results"]["iocs"]["urls"] == [
        "https://child.example/file"
    ]


@pytest.mark.asyncio
async def test_runtime_deadline_cancels_stage_and_clears_workspace(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"sample")
    manifest = AnalysisManifest.for_local_file(source)

    class Slow(CountingStage):
        async def execute(self, ctx):
            await asyncio.sleep(1)
            return await super().execute(ctx)

    report = await _runner(
        tmp_path, manifest, counter=Slow(), limits=BudgetLimits(timeout_seconds=0.08)
    ).run()
    assert report["batch_analysis"]["status"] == "partial"
    assert report["artifacts"][0]["reason"] == "analysis_attempt_deadline"
    assert not list((tmp_path / "state" / "work").glob("*/input.*"))


@pytest.mark.asyncio
async def test_store_delete_and_readonly_guards(tmp_path):
    local = LocalObjectStore(tmp_path / "results")
    await local.put_json("control.json", {"password": "transient-test"})
    await local.delete("control.json")
    assert not (tmp_path / "results" / "control.json").exists()
    readonly = LocalObjectStore(tmp_path / "results", read_only=True)
    with pytest.raises(PermissionError):
        await readonly.delete("control.json")
    client = MagicMock()
    remote = S3ObjectStore(
        endpoint="https://s3.example",
        bucket="results",
        access_key="test",
        secret_key="test",
        client=client,
    )
    await remote.delete("private/control.json")
    client.remove_object.assert_called_once_with("results", "private/control.json")
    remote.read_only = True
    with pytest.raises(PermissionError):
        await remote.delete("private/control.json")


@pytest.mark.parametrize("bypass", [False, True])
def test_s3_transport_preserves_environment_proxy_and_trusted_ca(monkeypatch, bypass):
    import urllib3

    proxy = MagicMock()
    pool = MagicMock()
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:8080")
    monkeypatch.setenv("https_proxy", "http://proxy.test:8080")
    monkeypatch.setenv("SSL_CERT_FILE", "/trusted/custom-ca.pem")
    monkeypatch.setenv("NO_PROXY", "s3.example" if bypass else "127.0.0.1")
    monkeypatch.setenv("no_proxy", "s3.example" if bypass else "127.0.0.1")
    monkeypatch.setattr(urllib3, "ProxyManager", proxy)
    monkeypatch.setattr(urllib3, "PoolManager", pool)
    minio = MagicMock()
    monkeypatch.setattr("minio.Minio", minio)
    S3ObjectStore(
        endpoint="https://s3.example", bucket="uploads", access_key="test", secret_key="test"
    )
    transport = pool if bypass else proxy
    transport.assert_called_once()
    assert transport.call_args.kwargs["cert_reqs"] == "CERT_REQUIRED"
    assert transport.call_args.kwargs["ca_certs"] == "/trusted/custom-ca.pem"
    if not bypass:
        assert proxy.call_args.args[0] == "http://proxy.test:8080"
        pool.assert_not_called()
    else:
        proxy.assert_not_called()
    assert minio.call_args.kwargs["http_client"] is transport.return_value
