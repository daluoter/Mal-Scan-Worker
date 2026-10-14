"""ClamAV stage with explicit daemon and standalone container adapters."""

import asyncio
import os
import re
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pyclamd

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()


def _get_clamd_client() -> pyclamd.ClamdNetworkSocket:
    """Connect to the configured self-hosted ClamAV daemon."""
    return pyclamd.ClamdNetworkSocket(
        host=settings.clamav_host,
        port=settings.clamav_port,
        timeout=settings.stage_timeout_seconds,
    )


def _scan_stream_sync(file_content: bytes) -> dict[str, tuple[str, str]] | None:
    """Scan using INSTREAM, independent of container volume mappings."""
    client = _get_clamd_client()
    if not client.ping():
        raise ConnectionError("ClamAV daemon is unavailable")
    return cast(dict[str, tuple[str, str]] | None, client.scan_stream(file_content))


def _daemon_version() -> str | None:
    value = _get_clamd_client().version()
    return value.strip() if isinstance(value, str) else None


async def _command(*arguments: str) -> tuple[int, str, str]:
    """Run a scanner command and terminate its process group on cancellation."""
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=settings.stage_timeout_seconds,
        )
        return (
            int(process.returncode or 0),
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )
    finally:
        if process.returncode is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


async def _scan_cli(path: Path) -> tuple[bool, str | None, str | None]:
    """Treat clamscan exit 1 as a detection, and exit 2 as an engine failure."""
    if settings.clamav_max_database_age_seconds is not None:
        if not settings.clamav_database_path:
            raise RuntimeError("ClamAV database directory is required for the freshness check")
        database = Path(settings.clamav_database_path) / "daily.cvd"
        with database.open("rb") as stream:
            fields = stream.read(512).decode("ascii").strip().split(":")
        if len(fields) < 9 or fields[0] != "ClamAV-VDB":
            raise RuntimeError("Invalid ClamAV daily database header")
        age = time.time() - int(fields[8])
        if not 0 <= age <= settings.clamav_max_database_age_seconds:
            raise RuntimeError("ClamAV daily database is stale; rebuild the signed database image")
    arguments = [settings.clamav_cli_path, "--stdout", "--no-summary", "--scan-archive=no"]
    if settings.clamav_database_path:
        arguments.append("--database=" + settings.clamav_database_path)
    arguments.append(str(path.resolve()))
    code, stdout, stderr = await _command(*arguments)
    if code not in {0, 1}:
        raise RuntimeError("ClamAV scanner failed: " + (stderr or stdout).strip()[:512])
    found = re.findall(r": (.+) FOUND\s*$", stdout, flags=re.MULTILINE)
    if code == 1 and not found:
        raise RuntimeError("ClamAV returned a detection without a readable finding")
    version_arguments = [settings.clamav_cli_path, "--version"]
    if settings.clamav_database_path:
        version_arguments.append("--database=" + settings.clamav_database_path)
    version_code, version, _ = await _command(*version_arguments)
    return (
        code == 1,
        "; ".join(found) if found else None,
        (version.strip() if version_code == 0 else None),
    )


class ClamAVStage(Stage):
    """Scan one artifact; recursive extraction belongs to the shared pipeline."""

    @property
    def name(self) -> str:
        return "clamav"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        tool_version = None
        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError("File not found")
            if settings.clamav_mode == "cli":
                infected, threat_name, tool_version = await _scan_cli(ctx.file_path)
            else:
                result = await asyncio.to_thread(_scan_stream_sync, ctx.file_path.read_bytes())
                infected = False
                names = []
                for state, name in (result or {}).values():
                    if state != "FOUND":
                        raise RuntimeError(
                            "ClamAV daemon could not scan the artifact: " + str(name)
                        )
                    infected = True
                    names.append(name)
                threat_name = "; ".join(names) if names else None
                try:
                    tool_version = await asyncio.to_thread(_daemon_version)
                except Exception:
                    pass
            status, error = "ok", None
            findings = {
                "engine": "ClamAV",
                "infected": infected,
                "threat_name": threat_name,
                "adapter": settings.clamav_mode,
            }
        except Exception as exc:
            status, findings = "failed", {}
            error = "ClamAV analysis timed out" if isinstance(exc, TimeoutError) else str(exc)
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=[],
            error=error,
            tool_version=tool_version,
        )
