"""Offline release controls for the actual cloud-job image, without cloud credentials.

Run as the image's default unprivileged user with Docker networking disabled.
Only a harmless clean fixture and the standard EICAR antivirus test string are used.
"""

import asyncio
import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malscan_worker.stages import clamav, yara_scan
from malscan_worker.stages.base import StageContext

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MAX_DATABASE_AGE = 604800


def verified_databases(directory: Path, now: float) -> list[dict[str, Any]]:
    """Reverify every signed database; only daily.cvd has a freshness requirement."""
    reports = []
    for name in ("main", "daily", "bytecode"):
        path = directory / (name + ".cvd")
        with path.open("rb") as stream:
            fields = stream.read(512).decode("ascii").strip().split(":")
        if len(fields) < 9 or fields[0] != "ClamAV-VDB":
            raise RuntimeError("Invalid signed database header: " + name)
        created = int(fields[8])
        age = now - created
        if name == "daily" and not 0 <= age <= MAX_DATABASE_AGE:
            raise RuntimeError("Daily database is stale or future-dated")
        result = subprocess.run(
            ["sigtool", "--info", str(path)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode != 0 or "Verification OK." not in result.stdout.splitlines():
            raise RuntimeError("Official database signature verification failed: " + name)
        reports.append(
            {
                "name": path.name,
                "version": int(fields[2]),
                "signatures": int(fields[3]),
                "created_at_epoch": created,
                "age_seconds": round(age),
                "signature_verified": True,
            }
        )
    return reports


async def run_controls() -> dict[str, Any]:
    """Fail closed if the real CLI adapter or the installed rules are unavailable."""
    if os.geteuid() == 0:
        raise RuntimeError("Release controls must run as the image's unprivileged user")
    settings = clamav.settings
    if settings.clamav_mode != "cli" or not settings.clamav_database_path:
        raise RuntimeError("Release controls require the cloud CLI adapter and signed databases")
    if settings.clamav_max_database_age_seconds != MAX_DATABASE_AGE:
        raise RuntimeError("Cloud database freshness enforcement must remain seven days")
    databases = verified_databases(Path(settings.clamav_database_path), time.time())
    stage = yara_scan.YaraStage()
    with tempfile.TemporaryDirectory(prefix="malscan-release-controls-") as temporary:
        clean = Path(temporary) / "clean.txt"
        eicar = Path(temporary) / "eicar.com"
        clean.write_bytes(b"Hello MalScan release control\n")
        eicar.write_bytes(EICAR)
        clean_infected, _, version = await clamav._scan_cli(clean)
        positive, threat, positive_version = await clamav._scan_cli(eicar)
        if clean_infected or not positive or not threat or "eicar" not in threat.lower():
            raise RuntimeError("ClamAV clean/EICAR controls failed")
        if not version or version != positive_version:
            raise RuntimeError("ClamAV did not report a consistent engine/database version")
        results = []
        for path in (clean, eicar):
            results.append(
                await stage.execute(
                    StageContext(
                        job_id="release-control",
                        file_id=path.name,
                        storage_key=path.name,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        original_filename=path.name,
                        file_path=path,
                    )
                )
            )
        clean_yara, positive_yara = results
        if any(result.status != "ok" for result in results):
            raise RuntimeError("YARA release controls did not complete")
        matched = [match["rule"] for match in positive_yara.findings["matches"]]
        if clean_yara.findings["matches"] or "eicar" not in matched:
            raise RuntimeError("YARA clean/EICAR controls failed")
        if not positive_yara.rules_version or not positive_yara.tool_version:
            raise RuntimeError("YARA rules/engine provenance is missing")
    return {
        "success": True,
        "scope": "offline_engine_controls",
        "cloud_run_executed": False,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "uid": os.geteuid(),
        "module_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "clamav_version": version,
        "signed_databases": databases,
        "yara_version": positive_yara.tool_version,
        "yara_rules_sha256": positive_yara.rules_version,
        "controls": {
            "clamav_clean": True,
            "clamav_eicar_detected": True,
            "yara_clean": True,
            "yara_eicar_detected": True,
        },
    }


def main() -> None:
    try:
        result = asyncio.run(run_controls())
    except Exception as error:
        print(
            json.dumps(
                {
                    "success": False,
                    "scope": "offline_engine_controls",
                    "error": str(error),
                }
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
