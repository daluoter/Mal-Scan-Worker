"""Real pefile and format-stage checks for inert, reproducible PE layouts."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pefile
import pytest
from malscan_worker.analyzers.pe_analyzer import _MAX_FILE_SIZE_BYTES
from malscan_worker.quality.pe_fixtures import build_pe_fixture
from malscan_worker.rule_provenance import load_rule_bundle
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.format_analysis import FormatAnalysisStage


def _context(path: Path) -> StageContext:
    return StageContext(
        job_id="pe-quality",
        file_id="pe-fixture",
        storage_key="synthetic",
        sha256="0" * 64,
        original_filename=path.name,
        file_path=path,
    )


@pytest.mark.parametrize("profile", ["benign", "suspicious", "truncated"])
def test_pe_fixture_is_reproducible_and_has_fixed_identity(profile):
    data = build_pe_fixture(profile)
    assert data == build_pe_fixture(profile, recipe_version=1)
    assert data[:2] == b"MZ"
    assert data[0x80:0x84] == b"PE\x00\x00"
    assert len(data) < 1_000_000
    assert (
        hashlib.sha256(data).hexdigest()
        == {
            "benign": "bf726088669d975c1b057c39b57a4a533592f2dee576221fb55c5b74500b465d",
            "suspicious": "24330cc942afffef3cb1e392ea91348041aa5cc784f75eb2efa605a1bf33adf0",
            "truncated": "d05415154be7a960dc77a0844a97d131d8e6e65dcf2c0f3a17371ca194bdc14b",
        }[profile]
    )


@pytest.mark.parametrize("profile", ["benign", "suspicious"])
def test_real_pefile_reads_only_inert_headers_and_import_metadata(profile):
    with pefile.PE(data=build_pe_fixture(profile)) as image:
        assert image.FILE_HEADER.Machine == 0x14C
        assert image.FILE_HEADER.TimeDateStamp == 1577836800
        assert image.OPTIONAL_HEADER.Magic == 0x10B
        assert image.OPTIONAL_HEADER.AddressOfEntryPoint == 0
        assert image.OPTIONAL_HEADER.SizeOfImage == 0x2000
        assert len(image.sections) == 1
        section = image.sections[0]
        assert section.Characteristics & 0x20000000 == 0  # No executable section.
        assert section.Characteristics & 0x40000000
        assert image.DIRECTORY_ENTRY_IMPORT[0].dll == b"KERNEL32.dll"
        assert [symbol.name for symbol in image.DIRECTORY_ENTRY_IMPORT[0].imports] == (
            [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"]
            if profile == "suspicious"
            else [b"GetCurrentProcessId"]
        )


@pytest.mark.asyncio
async def test_benign_pe_stage_retains_real_features_without_false_indicators(tmp_path):
    path = tmp_path / "benign.exe"
    path.write_bytes(build_pe_fixture("benign"))
    result = await FormatAnalysisStage().execute(_context(path))
    assert result.status == "ok"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["format_type"] == "PE"
    features = result.findings["features"]
    assert features["headers"] == {
        "machine": 0x14C,
        "timestamp": 1577836800,
        "characteristics": 0x0102,
        "optional_magic": 0x10B,
        "subsystem": 3,
    }
    assert features["imports"] == [{"dll": "KERNEL32.dll", "functions": ["GetCurrentProcessId"]}]
    assert features["sections"][0]["name"] == ".rdata"
    assert features["overlay"] == {
        "present": False,
        "offset": None,
        "size": 0,
        "file_size": 1024,
    }
    assert result.findings["indicators"] == []
    assert result.findings["heuristics"] == []
    assert result.findings["risk_score"] == 0
    assert result.findings["errors"] == []


@pytest.mark.asyncio
async def test_suspicious_pe_stage_binds_indicators_to_actual_structure_and_imports(tmp_path):
    path = tmp_path / "suspicious.exe"
    path.write_bytes(build_pe_fixture("suspicious"))
    result = await FormatAnalysisStage().execute(_context(path))
    assert result.status == "ok"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["features"]["sections"][0]["name"] == "UPX1"
    indicators = {item["type"]: item for item in result.findings["indicators"]}
    assert set(indicators) == {
        "suspicious_imports",
        "suspicious_section_name",
        "packer_detected",
        "overlay_data",
    }
    assert indicators["suspicious_section_name"]["evidence"] == {"section": "UPX1"}
    assert indicators["suspicious_imports"]["evidence"] == [
        {"dll": "KERNEL32.dll", "function": name}
        for name in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    ]
    assert indicators["overlay_data"]["evidence"] == {
        "present": True,
        "offset": 1024,
        "size": 1360,
        "file_size": 2384,
    }
    heuristics = {item["key"]: item for item in result.findings["heuristics"]}
    assert set(heuristics) == {
        "api.process_injection_cluster",
        "packer.known_section_name",
        "structure.overlay_anomaly",
    }
    assert heuristics["api.process_injection_cluster"]["evidence"] == {
        "apis": ["createremotethread", "virtualallocex", "writeprocessmemory"]
    }
    assert result.findings["risk_score"] == 34
    assert result.findings["errors"] == []


@pytest.mark.asyncio
async def test_truncated_pe_is_incomplete_instead_of_a_clean_empty_success(tmp_path):
    path = tmp_path / "truncated.exe"
    path.write_bytes(build_pe_fixture("truncated"))
    with pytest.raises(pefile.PEFormatError, match="No Optional Header"):
        pefile.PE(str(path))
    result = await FormatAnalysisStage().execute(_context(path))
    assert result.status == "partial"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["features"] == {}
    assert result.findings["errors"][0].startswith("failed to parse PE file:")
    assert "No Optional Header" in result.findings["reason"]


@pytest.mark.asyncio
async def test_real_pe_size_limit_is_reported_without_loading_large_file(tmp_path):
    path = tmp_path / "size-limited.exe"
    path.write_bytes(build_pe_fixture("benign"))
    # A sparse file reaches the real production boundary without a 100 MiB blob.
    with path.open("r+b") as handle:
        handle.truncate(_MAX_FILE_SIZE_BYTES + 1)
    result = await FormatAnalysisStage().execute(_context(path))
    assert result.status == "partial"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["features"] == {}
    assert result.findings["errors"] == ["PE analysis skipped: file exceeds 100MB limit"]
    assert "100MB limit" in result.findings["reason"]


def test_real_bundled_yara_keeps_normal_pe_clean_and_detects_control_import_cluster():
    rules = load_rule_bundle(Path(__file__).parents[1] / "rules").rules
    assert rules.match(data=build_pe_fixture("benign")) == []
    assert rules.match(data=build_pe_fixture("truncated")) == []
    assert sorted(match.rule for match in rules.match(data=build_pe_fixture("suspicious"))) == [
        "suspicious_api_calls"
    ]


@pytest.mark.parametrize("profile,version", [("unknown", 1), ("benign", 2), ("benign", 0)])
def test_unknown_pe_recipe_cannot_silently_rebaseline(profile, version):
    with pytest.raises(ValueError, match="Unknown PE fixture recipe"):
        build_pe_fixture(profile, recipe_version=version)
