"""Real encrypted PDFs and native YARA across portable password checkpoints.

The ClamAV stage uses a local transport stub: these tests verify stage scheduling,
not antivirus detection accuracy. Native YARA and PDF/archive parsing are real.
"""

import io
import json
from collections import Counter
from pathlib import Path

import pytest
import pyzipper
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.runtime.manifest import file_identity
from malscan_worker.stages import clamav, yara_scan
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.deobfuscation import DeobfuscationStage
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.sandbox import SandboxStage
from malscan_worker.stages.yara_scan import YaraStage
from pypdf import PdfReader, PdfWriter


class _RecordedStage:
    def __init__(self, delegate):
        self.delegate = delegate
        self.calls = Counter()

    @property
    def name(self):
        return self.delegate.name

    async def execute(self, ctx):
        self.calls[ctx.artifact_id] += 1
        return await self.delegate.execute(ctx)


@pytest.fixture
def scans(monkeypatch):
    monkeypatch.setattr(clamav.settings, "clamav_mode", "daemon")
    monkeypatch.setattr(clamav, "_scan_stream_sync", lambda _: None)
    monkeypatch.setattr(clamav, "_daemon_version", lambda: "ClamAV local-transport-test")
    monkeypatch.setattr(
        yara_scan.settings, "yara_rules_path", str(Path(__file__).parents[1] / "rules")
    )
    for name, value in (
        ("_rules_loaded", False),
        ("_compiled_rules", None),
        ("_rules_load_error", None),
        ("_rules_version", None),
        ("_rule_bundle", None),
    ):
        monkeypatch.setattr(yara_scan, name, value)
    return _RecordedStage(ClamAVStage()), _RecordedStage(YaraStage())


def _encrypted_pdf(password, *, title="Ordinary document"):
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_metadata({"/Title": title})
    writer.encrypt(password, owner_password="unrelated-owner-test-credential", algorithm="RC4-40")
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def _runner(tmp_path, manifest, scans, *, passwords=None):
    av, yara = scans
    return RootBatchRunner(
        manifest=manifest,
        source_store=LocalObjectStore(tmp_path, read_only=True),
        result_store=LocalObjectStore(tmp_path / "results"),
        state_dir=tmp_path / "state",
        passwords=passwords,
        parallel_stages=[FileTypeStage(), av, yara, IocExtractStage(), DeobfuscationStage()],
        format_stage=FormatAnalysisStage(),
        sequential_stages=[ArchiveExtractStage(), DocumentAnalysisStage(), SandboxStage()],
    )


def _counts(report):
    return tuple(report["execution_budget"][key] for key in ("used_files", "used_bytes"))


def _assert_no_credentials(tmp_path, report, *credentials):
    documents = json.dumps(report)
    for path in (
        tmp_path / "state" / "checkpoint.json",
        *list((tmp_path / "results").rglob("*.json")),
    ):
        documents += path.read_text()
    for credential in credentials:
        assert credential not in documents


@pytest.mark.asyncio
async def test_pdf_root_resumes_wrong_then_correct_without_rescanning_ciphertext(
    tmp_path, scans, capsys
):
    password = "root-pdf-test-credential"
    wrong_password = "wrong-root-pdf-test-credential"
    source = tmp_path / "encrypted.pdf"
    # An inert miner-name marker is encrypted at rest and should appear to native
    # YARA only after the clear child goes through its own scan stages.
    source.write_bytes(_encrypted_pdf(password, title="xmrig synthetic string control"))
    original = file_identity(source)
    assert b"xmrig" not in source.read_bytes()
    manifest = AnalysisManifest.for_local_file(source)
    first = await _runner(tmp_path, manifest, scans).run()
    root_id = manifest.root_job_id
    assert first["job_status"] == "password_required"
    assert first["report_complete"] is False
    assert first["analysis"]["static"]["status"] == "password_required"
    assert len(first["artifacts"]) == 1
    assert first["results"]["format_analysis"]["password_kind"] == "pdf"
    assert first["results"]["format_analysis"]["features"]["content_access"] == "password_required"
    assert _counts(first) == (0, 0)
    original_scans = [
        next(stage for stage in first["stages"] if stage["stage_name"] == name)
        for name in ("clamav", "yara")
    ]
    wrong = await _runner(tmp_path, manifest, scans, passwords={root_id: wrong_password}).run(
        resume=True
    )
    assert wrong["job_status"] == "password_required"
    assert wrong["artifacts"][0]["reason"] == "wrong_password"
    assert wrong["results"]["format_analysis"]["features"]["content_access"] == "wrong_password"
    assert _counts(wrong) == _counts(first)
    assert all(scanner.calls == {root_id: 1} for scanner in scans)
    (tmp_path / "state" / "checkpoint.json").unlink()
    final = await _runner(tmp_path, manifest, scans, passwords={root_id: password}).run(resume=True)
    assert final["job_status"] == "done" and final["report_complete"] is True
    assert final["analysis"]["static"]["status"] == "complete"
    assert final["root_artifact_id"] == root_id
    assert final["analysis_attempt_id"] == first["analysis_attempt_id"]
    assert len(final["artifacts"]) == 2
    child = next(artifact for artifact in final["artifacts"] if artifact["parent_id"] == root_id)
    assert child["status"] == "done"
    assert child["sha256"] != original[0]
    assert child["extraction_source"] == "format-analysis"
    assert child["archive_type"] == "pdf"
    assert child["origin_path"] == "pdf-decrypted"
    clear = tmp_path / "results" / child["storage_key"]
    assert file_identity(clear) == (child["sha256"], child["size"])
    assert PdfReader(clear).is_encrypted is False
    assert all(scanner.calls == {root_id: 1, child["artifact_id"]: 1} for scanner in scans)
    assert any(
        hit["rule"] == "crypto_miner_binary" for hit in child["report"]["results"]["yara_hits"]
    )
    assert not final["results"]["yara_hits"]
    assert {stage["stage_name"] for stage in child["report"]["stages"]} == {
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
    assert all(stage in final["stages"] for stage in original_scans)
    assert _counts(final) == (1, child["size"])
    repeat = await _runner(tmp_path, manifest, scans).run(resume=True)
    assert _counts(repeat) == _counts(final)
    assert all(
        scanner.calls[root_id] == scanner.calls[child["artifact_id"]] == 1 for scanner in scans
    )
    assert file_identity(source) == original
    _assert_no_credentials(tmp_path, repeat, password, wrong_password)
    captured = capsys.readouterr()
    assert password not in captured.out + captured.err
    assert wrong_password not in captured.out + captured.err


@pytest.mark.asyncio
async def test_zip_and_two_nested_pdfs_keep_distinct_passwords_and_monotonic_budget(
    tmp_path, scans
):
    outer_password, first_password, second_password = (
        "outer-archive-test-credential",
        "first-document-test-credential",
        "second-document-test-credential",
    )
    first_pdf = _encrypted_pdf(first_password)
    second_pdf = _encrypted_pdf(second_password, title="Other document")
    source = tmp_path / "outer.zip"
    with pyzipper.AESZipFile(source, "w", encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(outer_password.encode())
        archive.writestr("one/first.pdf", first_pdf)
        archive.writestr("two/second.pdf", second_pdf)
    original = file_identity(source)
    manifest = AnalysisManifest.for_local_file(source)
    first = await _runner(
        tmp_path, manifest, scans, passwords={manifest.root_job_id: outer_password}
    ).run()
    waiting = {
        node["origin_path"]: node
        for node in first["artifacts"]
        if node["status"] == "password_required"
    }
    assert set(waiting) == {"one/first.pdf", "two/second.pdf"}
    assert _counts(first) == (2, len(first_pdf) + len(second_pdf))
    one, two = waiting["one/first.pdf"], waiting["two/second.pdf"]
    wrong = await _runner(
        tmp_path, manifest, scans, passwords={one["artifact_id"]: second_password}
    ).run(resume=True)
    assert _counts(wrong) == _counts(first)
    assert all(sum(scanner.calls.values()) == 3 for scanner in scans)
    next_report = await _runner(
        tmp_path, manifest, scans, passwords={one["artifact_id"]: first_password}
    ).run(resume=True)
    assert next_report["job_status"] == "password_required"
    assert next_report["password_required_artifacts"] == [two["artifact_id"]]
    assert _counts(next_report)[0] == 3
    assert all(sum(scanner.calls.values()) == 4 for scanner in scans)
    final = await _runner(
        tmp_path, manifest, scans, passwords={two["artifact_id"]: second_password}
    ).run(resume=True)
    assert final["job_status"] == "done" and final["report_complete"] is True
    assert final["analysis"]["static"]["status"] == "complete"
    assert len(final["artifacts"]) == 5
    clear_children = [
        node for node in final["artifacts"] if node["extraction_source"] == "format-analysis"
    ]
    assert {node["parent_id"] for node in clear_children} == {
        one["artifact_id"],
        two["artifact_id"],
    }
    assert _counts(final) == (
        4,
        len(first_pdf) + len(second_pdf) + sum(node["size"] for node in clear_children),
    )
    assert all(
        sum(scanner.calls.values()) == 5 and set(scanner.calls.values()) == {1} for scanner in scans
    )
    assert {node["artifact_id"] for node in first["artifacts"]}.issubset(
        {node["artifact_id"] for node in final["artifacts"]}
    )
    assert final["analysis_attempt_id"] == first["analysis_attempt_id"]
    assert file_identity(source) == original
    _assert_no_credentials(tmp_path, final, outer_password, first_password, second_password)
