"""An extracted EICAR marker cannot stand in for an unavailable antivirus scan."""

import hashlib
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from malscan_worker.quality import document_embedded_acceptance as acceptance
from malscan_worker.quality.document_embedded_fixtures import (
    build_document_embedded_fixture,
    embedded_fixture_payloads,
)
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.stages import clamav, yara_scan
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage


@pytest.mark.asyncio
async def test_recovered_eicar_with_stale_database_remains_partial_and_fails_acceptance(
    tmp_path, monkeypatch
):
    source = tmp_path / "pdf-flate-eicar.pdf"
    source.write_bytes(build_document_embedded_fixture("pdf-flate-eicar"))
    manifest = AnalysisManifest.for_local_file(source)

    database = tmp_path / "database"
    database.mkdir()
    header = f"ClamAV-VDB:date:1:1:1:hash:sig:builder:{int(time.time()) - 604801}"
    (database / "daily.cvd").write_bytes(header.encode().ljust(512, b" "))
    monkeypatch.setattr(clamav.settings, "clamav_mode", "cli")
    monkeypatch.setattr(clamav.settings, "clamav_database_path", str(database))
    monkeypatch.setattr(clamav.settings, "clamav_max_database_age_seconds", 604800)
    scanner_command = AsyncMock()
    monkeypatch.setattr(clamav, "_command", scanner_command)

    # Use the repository's real native rules and parser. Only the database header
    # and command boundary are controlled; no scanner success is fabricated.
    monkeypatch.setattr(
        yara_scan.settings, "yara_rules_path", str(Path(__file__).parents[1] / "rules")
    )
    for name, value in (
        ("_compiled_rules", None),
        ("_rules_loaded", False),
        ("_rules_load_error", None),
        ("_rules_version", None),
        ("_rule_bundle", None),
    ):
        monkeypatch.setattr(yara_scan, name, value)

    results = tmp_path / "results"
    runner = RootBatchRunner(
        manifest=manifest,
        source_store=LocalObjectStore(tmp_path, read_only=True),
        result_store=LocalObjectStore(results),
        state_dir=tmp_path / "state",
        parallel_stages=[FileTypeStage(), clamav.ClamAVStage(), yara_scan.YaraStage()],
        format_stage=FormatAnalysisStage(),
        sequential_stages=[ArchiveExtractStage(), DocumentAnalysisStage()],
    )
    report = await runner.run()

    assert report["job_status"] == "done"
    assert report["report_complete"] is True  # The work ended; coverage is separate.
    assert report["analysis"]["static"]["status"] == "partial"
    assert len(report["artifacts"]) == 2
    child = next(node for node in report["artifacts"] if node["depth"] == 1)
    (expected,) = embedded_fixture_payloads("pdf-flate-eicar")
    assert child["sha256"] == hashlib.sha256(expected).hexdigest()
    assert child["size"] == 68
    assert results.joinpath(*child["storage_key"].split("/")).read_bytes() == expected
    assert {hit["rule"] for hit in child["report"]["results"]["yara_hits"]} == {"eicar"}

    for node in report["artifacts"]:
        direct = node["report"]
        assert direct["analysis"]["static"]["status"] == "partial"
        av = next(stage for stage in direct["stages"] if stage["stage_name"] == "clamav")
        assert av["status"] == "failed"
        assert "stale" in av["error"]
        assert "infected" not in av["findings"]
        assert not any(item["source"] == "clamav" for item in direct["risk"]["evidence"])
    scanner_command.assert_not_called()

    suite = acceptance.load_manifest(
        Path(__file__).parents[1] / "quality" / "document-embedded-v1.json"
    )
    case = next(case for case in suite["cases"] if case["profile"] == "pdf-flate-eicar")
    with pytest.raises(ValueError, match="Native antivirus did not detect"):
        acceptance.verify_inventory(case, report, results)
