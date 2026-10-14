"""Read-only CAPE API/registered guest checks before enabling dynamic workers.

This verifies API access and an unlocked configured guest. It does not boot a
guest, submit a sample, or establish that a future detonation will succeed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
from dataclasses import dataclass
from typing import Any

import aiohttp

from malscan_worker.sandbox.providers import validate_cape_base_url


@dataclass(frozen=True)
class PreflightConfig:
    provider: str = "capev2"
    base_url: str = ""
    api_token: str | None = None
    timeout_seconds: float = 10.0
    platform: str | None = None


def _result(config: PreflightConfig, code: str, **extra: Any) -> dict[str, Any]:
    return {
        "scope": "sandbox_read_only_preflight",
        "success": code == "ready",
        "provider": config.provider,
        "status": code,
        "sample_submitted": False,
        "analysis_executed": False,
        "guest_boot_verified": False,
        **extra,
    }


async def check_sandbox_readiness(config: PreflightConfig) -> dict[str, Any]:
    """GET the official machines-list route; return sanitized readiness facts."""
    if config.provider != "capev2":
        return _result(config, "synthetic" if config.provider == "mock" else "unsupported_provider")
    try:
        base_url = validate_cape_base_url(config.base_url)
    except (ValueError, RuntimeError):
        return _result(config, "invalid_endpoint")
    if not math.isfinite(config.timeout_seconds) or not 0 < config.timeout_seconds <= 60:
        return _result(config, "invalid_timeout")

    endpoint = (
        f"{base_url}/machines/list/"
        if base_url.endswith("/apiv2")
        else f"{base_url}/apiv2/machines/list/"
    )
    headers = {"Authorization": f"Token {config.api_token}"} if config.api_token else {}
    try:
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.get(endpoint, allow_redirects=False) as response:
                if response.status in {401, 403}:
                    return _result(config, "authentication_failed", http_status=response.status)
                if not 200 <= response.status < 300:
                    return _result(config, "api_unavailable", http_status=response.status)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65_536):
                    raw.extend(chunk)
                    if len(raw) > 1_048_576:
                        return _result(config, "invalid_api_response")
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeError):
                    return _result(config, "invalid_api_response")
    except asyncio.TimeoutError:
        return _result(config, "api_timeout")
    except (aiohttp.ClientError, ValueError, TypeError, UnicodeError):
        return _result(config, "api_unavailable")

    if not isinstance(payload, dict):
        return _result(config, "invalid_api_response")
    if payload.get("error"):
        return _result(config, "api_rejected")
    machines = payload.get("data")
    if not isinstance(machines, list) or any(not isinstance(item, dict) for item in machines):
        return _result(config, "invalid_api_response")
    requested_platform = (config.platform or "").strip().lower()
    configured = [
        machine
        for machine in machines
        if isinstance(machine.get("platform"), str)
        and machine["platform"].strip()
        and (machine.get("name") or machine.get("label"))
        and (not requested_platform or machine["platform"].strip().lower() == requested_platform)
    ]
    available = [
        machine
        for machine in configured
        if "locked" in machine
        and machine["locked"] in (False, 0)
        and str(machine.get("status") or "").lower()
        not in {
            "error",
            "failed",
            "broken",
            "unavailable",
            "disabled",
        }
    ]
    return _result(
        config,
        "ready" if available else "no_available_guest",
        api_access_verified=True,
        authentication_header_configured=bool(config.api_token),
        configured_guests=len(configured),
        available_guests=len(available),
        requested_platform=requested_platform or None,
    )


def main() -> int:
    """Run without loading unrelated DB, storage, or broker configuration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", help="Require an unlocked guest for this OS")
    args = parser.parse_args()
    try:
        timeout = float(os.environ.get("SANDBOX_PREFLIGHT_TIMEOUT_SECONDS", "10"))
    except ValueError:
        timeout = 0
    config = PreflightConfig(
        provider=os.environ.get("SANDBOX_PROVIDER", "capev2").strip().lower() or "capev2",
        base_url=os.environ.get("SANDBOX_BASE_URL", ""),
        api_token=os.environ.get("SANDBOX_API_TOKEN") or None,
        timeout_seconds=timeout,
        platform=args.platform,
    )
    result = asyncio.run(check_sandbox_readiness(config))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
