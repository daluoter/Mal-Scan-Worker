"""Scanner failures and findings retain distinct report semantics."""

import time
from unittest.mock import AsyncMock

import pytest
from malscan_worker.stages import clamav


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,stdout,stderr,status,infected",
    [
        (0, "sample: OK\n", "", "ok", False),
        (1, "sample: Eicar-Test-Signature FOUND\n", "", "ok", True),
        (2, "", "database missing", "failed", None),
        (1, "unreadable scanner output", "", "failed", None),
    ],
)
async def test_cli_scan_interprets_exit_codes(
    monkeypatch, stage_context, code, stdout, stderr, status, infected
):
    monkeypatch.setattr(clamav.settings, "clamav_mode", "cli")
    command = AsyncMock(side_effect=[(code, stdout, stderr), (0, "ClamAV 1.5/123/date", "")])
    monkeypatch.setattr(clamav, "_command", command)
    result = await clamav.ClamAVStage().execute(stage_context)
    assert result.status == status
    assert result.findings.get("infected") is infected
    if infected is not None:
        assert result.tool_version == "ClamAV 1.5/123/date"
    else:
        assert result.error
    assert "--scan-archive=no" in command.call_args_list[0].args


@pytest.mark.asyncio
async def test_daemon_stream_error_does_not_become_detection(monkeypatch, stage_context):
    monkeypatch.setattr(clamav.settings, "clamav_mode", "daemon")
    monkeypatch.setattr(
        clamav,
        "_scan_stream_sync",
        lambda data: {"stream": ("ERROR", "INSTREAM size limit exceeded")},
    )
    result = await clamav.ClamAVStage().execute(stage_context)
    assert result.status == "failed"
    assert "infected" not in result.findings
    assert "size limit" in result.error


@pytest.mark.asyncio
async def test_daemon_scan_records_actual_version(monkeypatch, stage_context):
    monkeypatch.setattr(clamav.settings, "clamav_mode", "daemon")
    monkeypatch.setattr(clamav, "_scan_stream_sync", lambda data: None)
    monkeypatch.setattr(clamav, "_daemon_version", lambda: "ClamAV 1.5/123/date")
    result = await clamav.ClamAVStage().execute(stage_context)
    assert result.status == "ok"
    assert result.findings["infected"] is False
    assert result.tool_version == "ClamAV 1.5/123/date"


@pytest.mark.asyncio
async def test_stale_cloud_database_is_a_coverage_failure(monkeypatch, stage_context, tmp_path):
    monkeypatch.setattr(clamav.settings, "clamav_mode", "cli")
    monkeypatch.setattr(clamav.settings, "clamav_database_path", str(tmp_path))
    monkeypatch.setattr(clamav.settings, "clamav_max_database_age_seconds", 604800)
    header = f"ClamAV-VDB:date:1:1:1:hash:sig:builder:{int(time.time()) - 604801}"
    (tmp_path / "daily.cvd").write_bytes(header.encode().ljust(512, b" "))
    command = AsyncMock()
    monkeypatch.setattr(clamav, "_command", command)
    result = await clamav.ClamAVStage().execute(stage_context)
    assert result.status == "failed"
    assert "stale" in result.error
    assert "infected" not in result.findings
    command.assert_not_called()
