"""Real Office decryption and native scan stages through durable password resume.

ClamAV transport is stubbed to verify scheduling; Office, ZIP, and YARA are real.
"""

import hashlib
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

import pytest
from malscan_worker.quality.office_password_fixtures import (
    ARCHIVE_PASSWORD,
    OFFICE_PASSWORD,
    SECOND_OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_password_fixture,
    build_office_plaintext_fixture,
)
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


class RecordedStage:
    def __init__(self, stage):
        self.stage = stage
        self.calls = Counter()

    @property
    def name(self):
        return self.stage.name

    async def execute(self, ctx):
        self.calls[ctx.artifact_id] += 1
        return await self.stage.execute(ctx)


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
    return RecordedStage(ClamAVStage()), RecordedStage(YaraStage())


def runner(tmp_path, manifest, scans, *, passwords=None, attempts=None):
    return RootBatchRunner(
        manifest=manifest,
        source_store=LocalObjectStore(tmp_path, read_only=True),
        result_store=LocalObjectStore(tmp_path / "results"),
        state_dir=tmp_path / "state",
        passwords=passwords,
        password_attempts_by_artifact=attempts,
        password_attempt_limit=3 if attempts is not None else None,
        parallel_stages=[FileTypeStage(), *scans, IocExtractStage(), DeobfuscationStage()],
        format_stage=FormatAnalysisStage(),
        sequential_stages=[ArchiveExtractStage(), DocumentAnalysisStage(), SandboxStage()],
    )


def counts(report):
    return tuple(report["execution_budget"][key] for key in ("used_files", "used_bytes"))


def assert_private(tmp_path, report):
    serialized = json.dumps(report)
    for path in (tmp_path / "state" / "checkpoint.json", *(tmp_path / "results").rglob("*.json")):
        serialized += path.read_text()
    for password in (OFFICE_PASSWORD, SECOND_OFFICE_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD):
        assert password not in serialized


def assert_package_parts(tmp_path, report, child, payload):
    # Expected content comes from the pinned fixture, independently of extraction.
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        expected = {info.filename: archive.read(info) for info in archive.infolist()}
    parts = [node for node in report["artifacts"] if node["parent_id"] == child["artifact_id"]]
    assert len(parts) == len(expected)
    assert {node["origin_path"] for node in parts} == set(expected)
    for node in parts:
        content = expected[node["origin_path"]]
        assert node["extraction_source"] == "archive-extract"
        assert node["sha256"] == hashlib.sha256(content).hexdigest()
        assert (tmp_path / "results" / node["storage_key"]).read_bytes() == content
    return len(parts), sum(len(content) for content in expected.values())


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["agile-aes256-docx", "standard-aes128-docx"])
async def test_office_root_resume_reuses_ciphertext_scans_and_analyzes_exact_child(
    tmp_path, scans, capsys, profile
):
    source = tmp_path / "encrypted.bin"
    source.write_bytes(build_office_password_fixture(profile))
    original = file_identity(source)
    manifest = AnalysisManifest.for_local_file(source)
    root_id = manifest.root_job_id
    first = await runner(tmp_path, manifest, scans).run()
    assert first["job_status"] == "password_required"
    assert first["analysis"]["static"]["status"] == "password_required"
    waiting = first["results"]["format_analysis"]
    assert waiting["analyzer"] == waiting["password_kind"] == "office"
    assert waiting["format_type"] == "OFFICE"
    assert waiting["features"]["content_access"] == "password_required"
    assert len(first["artifacts"]) == 1 and counts(first) == (0, 0)
    completed = [stage for stage in first["stages"] if stage["status"] in {"ok", "skipped"}]
    wrong = await runner(tmp_path, manifest, scans, passwords={root_id: WRONG_PASSWORD}).run(
        resume=True
    )
    assert wrong["job_status"] == "password_required"
    assert wrong["results"]["format_analysis"]["features"]["content_access"] == "wrong_password"
    assert counts(wrong) == counts(first)
    assert all(scan.calls == {root_id: 1} for scan in scans)
    # The final resume must recover from the durable object-store checkpoint.
    (tmp_path / "state" / "checkpoint.json").unlink()
    final = await runner(tmp_path, manifest, scans, passwords={root_id: OFFICE_PASSWORD}).run(
        resume=True
    )
    assert final["job_status"] == "done" and final["report_complete"] is True
    assert final["analysis"]["static"]["status"] == "complete"
    child = next(node for node in final["artifacts"] if node["parent_id"] == root_id)
    clear = tmp_path / "results" / child["storage_key"]
    assert clear.read_bytes() == build_office_plaintext_fixture(profile)
    assert file_identity(clear) == (child["sha256"], child["size"])
    assert child["original_filename"].endswith(".docx")
    assert child["origin_path"] == "office-decrypted" and child["archive_type"] == "office"
    assert child["status"] == "done"
    assert final["results"]["format_analysis"]["features"]["content_access"] == "decrypted_child"
    assert final["results"]["document_analysis"]["content_access"] == "decrypted_child"
    assert child["report"]["results"]["document_analysis"]["document_type"] == "ooxml"
    assert all(stage in final["stages"] for stage in completed)
    part_count, part_bytes = assert_package_parts(
        tmp_path, final, child, build_office_plaintext_fixture(profile)
    )
    assert len(final["artifacts"]) == 2 + part_count
    assert counts(final) == (1 + part_count, child["size"] + part_bytes)
    identifiers = {node["artifact_id"] for node in final["artifacts"]}
    assert all(scan.calls == dict.fromkeys(identifiers, 1) for scan in scans)
    repeat = await runner(tmp_path, manifest, scans).run(resume=True)
    assert counts(repeat) == counts(final)
    assert all(set(scan.calls.values()) == {1} for scan in scans)
    assert file_identity(source) == original
    assert_private(tmp_path, repeat)
    captured = capsys.readouterr()
    for password in (OFFICE_PASSWORD, WRONG_PASSWORD):
        assert password not in captured.out + captured.err


@pytest.mark.asyncio
async def test_office_sibling_exhaustion_is_per_file_and_outer_zip_password_does_not_propagate(
    tmp_path, scans
):
    source = tmp_path / "outer.zip"
    source.write_bytes(build_office_password_fixture("zip-aes-office-two-siblings"))
    manifest = AnalysisManifest.for_local_file(source)
    root_id = manifest.root_job_id
    first = await runner(
        tmp_path, manifest, scans, passwords={root_id: ARCHIVE_PASSWORD}, attempts={root_id: 1}
    ).run()
    waiting = [node for node in first["artifacts"] if node["status"] == "password_required"]
    assert len(waiting) == 2
    assert all(node["reason"] == "password_required" for node in waiting)
    one, two = waiting
    assert counts(first)[0] == 2
    for used in range(1, 4):
        report = await runner(
            tmp_path,
            manifest,
            scans,
            passwords={one["artifact_id"]: WRONG_PASSWORD},
            attempts={root_id: 1, one["artifact_id"]: used},
        ).run(resume=True)
        blocked = next(
            node for node in report["artifacts"] if node["artifact_id"] == one["artifact_id"]
        )
        assert blocked["status"] == ("failed" if used == 3 else "password_required")
        assert blocked["reason"] == (
            "password_attempts_exhausted" if used == 3 else "wrong_password"
        )
        assert two["artifact_id"] in report["password_required_artifacts"]
        assert counts(report) == counts(first)
    blocked_format = blocked["report"]["results"]["format_analysis"]
    assert blocked_format["password_kind"] == "office"
    assert blocked_format["features"]["content_access"] == "password_attempts_exhausted"
    assert blocked_format["decryption_failed"] is True
    (tmp_path / "state" / "checkpoint.json").unlink()
    final = await runner(
        tmp_path,
        manifest,
        scans,
        passwords={two["artifact_id"]: OFFICE_PASSWORD},
        attempts={root_id: 1, one["artifact_id"]: 3, two["artifact_id"]: 1},
    ).run(resume=True)
    assert final["job_status"] == "done" and final["report_complete"] is True
    assert final["analysis"]["static"]["status"] == "partial"
    children = [node for node in final["artifacts"] if node["origin_path"] == "office-decrypted"]
    assert len(children) == 1 and children[0]["parent_id"] == two["artifact_id"]
    plaintext_profile = "xlsx" if two["original_filename"].endswith(".xlsx") else "docx"
    part_count, part_bytes = assert_package_parts(
        tmp_path, final, children[0], build_office_plaintext_fixture(plaintext_profile)
    )
    assert counts(final) == (3 + part_count, counts(first)[1] + children[0]["size"] + part_bytes)
    identifiers = {node["artifact_id"] for node in final["artifacts"]}
    assert all(scan.calls == dict.fromkeys(identifiers, 1) for scan in scans)
    assert_private(tmp_path, final)
