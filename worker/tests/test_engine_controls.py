"""Release controls must reject stale, unsigned or nonfunctional engines."""

import subprocess
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker.runtime import engine_controls as controls


def signed_headers(directory, epoch=None):
    for name in ("main", "daily", "bytecode"):
        header = f"ClamAV-VDB:date:28153:355000:90:hash:sig:builder:{epoch or int(time.time())}"
        (directory / (name + ".cvd")).write_bytes(header.encode().ljust(512, b" "))


def test_requires_successful_signature_verification(tmp_path, monkeypatch):
    signed_headers(tmp_path)
    monkeypatch.setattr(
        controls.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "Verification FAILED.\n", ""),
    )
    with pytest.raises(RuntimeError, match="signature verification failed"):
        controls.verified_databases(tmp_path, time.time())


@pytest.mark.parametrize("offset", [-604801, 3600])
def test_database_freshness_rejects_stale_and_future(tmp_path, monkeypatch, offset):
    signed_headers(tmp_path, int(time.time()) + offset)
    monkeypatch.setattr(
        controls.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "Verification OK.\n", ""),
    )
    with pytest.raises(RuntimeError, match="stale or future"):
        controls.verified_databases(tmp_path, time.time())


@pytest.mark.asyncio
async def test_root_execution_is_rejected_before_scanner(monkeypatch):
    monkeypatch.setattr(controls.os, "geteuid", lambda: 0)
    scanner = AsyncMock()
    monkeypatch.setattr(controls.clamav, "_scan_cli", scanner)
    with pytest.raises(RuntimeError, match="unprivileged"):
        await controls.run_controls()
    scanner.assert_not_called()


@pytest.mark.asyncio
async def test_actual_yara_rules_and_scanner_control_contract(tmp_path, monkeypatch):
    """Use native installed YARA and real repository rules, stub only unavailable AV."""
    from pathlib import Path

    monkeypatch.setattr(controls.os, "geteuid", lambda: 10001)
    monkeypatch.setattr(controls.clamav.settings, "clamav_mode", "cli")
    monkeypatch.setattr(controls.clamav.settings, "clamav_database_path", str(tmp_path))
    monkeypatch.setattr(controls.clamav.settings, "clamav_max_database_age_seconds", 604800)
    monkeypatch.setattr(controls, "verified_databases", lambda *a: [{"test": "signed-fixture"}])
    monkeypatch.setattr(
        controls.clamav,
        "_scan_cli",
        AsyncMock(
            side_effect=[
                (False, None, "ClamAV test"),
                (True, "Eicar-Test-Signature", "ClamAV test"),
            ]
        ),
    )
    monkeypatch.setattr(
        controls.yara_scan.settings,
        "yara_rules_path",
        str(Path(__file__).parents[1] / "rules"),
    )
    for name, value in (
        ("_rules_loaded", False),
        ("_compiled_rules", None),
        ("_rules_load_error", None),
        ("_rules_version", None),
    ):
        monkeypatch.setattr(controls.yara_scan, name, value)
    report = await controls.run_controls()
    assert report["success"] is True
    assert report["controls"]["yara_eicar_detected"] is True
    assert len(report["yara_rules_sha256"]) == 64
    assert report["uid"] == 10001


@pytest.mark.asyncio
async def test_false_clean_or_missing_av_positive_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(controls.os, "geteuid", lambda: 10001)
    monkeypatch.setattr(controls.clamav.settings, "clamav_mode", "cli")
    monkeypatch.setattr(controls.clamav.settings, "clamav_database_path", str(tmp_path))
    monkeypatch.setattr(controls.clamav.settings, "clamav_max_database_age_seconds", 604800)
    monkeypatch.setattr(controls, "verified_databases", lambda *a: [])
    monkeypatch.setattr(controls.yara_scan, "YaraStage", lambda: SimpleNamespace())
    monkeypatch.setattr(
        controls.clamav,
        "_scan_cli",
        AsyncMock(side_effect=[(False, None, "v"), (False, None, "v")]),
    )
    with pytest.raises(RuntimeError, match="clean/EICAR controls failed"):
        await controls.run_controls()
