"""Sandbox stage orchestration and deferred execution helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.config import Settings, get_settings
from malscan_worker.sandbox import (
    build_empty_sandbox_result,
    get_default_sandbox_provider_registry,
    resolve_sandbox_provider_name,
)
from malscan_worker.stages.base import Stage, StageContext, StageResult

log = structlog.get_logger()


def _duration_ms(started_at: datetime, ended_at: datetime) -> int:
    return int((ended_at - started_at).total_seconds() * 1000)


def build_deferred_sandbox_result(
    *,
    provider_name: str,
    reason: str = "Sandbox dispatched to dedicated queue",
) -> dict[str, Any]:
    result = build_empty_sandbox_result(
        provider=provider_name,
        executed=False,
        status="deferred",
    )
    result["reason"] = reason
    return result


def should_defer_sandbox(
    *,
    settings: Settings | None = None,
    force_inline: bool = False,
) -> bool:
    cfg = settings or get_settings()
    if not cfg.sandbox_enabled or force_inline:
        return False
    return True


def _provider_kwargs(settings: Settings) -> dict[str, Any]:
    return {
        "base_url": settings.sandbox_base_url,
        "api_token": settings.sandbox_api_token,
        "timeout_seconds": settings.sandbox_timeout_seconds,
        "poll_interval_seconds": settings.sandbox_poll_interval_seconds,
        "enable_url_submission": settings.sandbox_enable_url_submission,
    }


async def execute_sandbox_analysis(
    *,
    file_path: Path | None,
    sha256: str,
    filename: str,
    submission_url: str | None = None,
    settings: Settings | None = None,
    previous_result: dict[str, Any] | None = None,
    on_checkpoint: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Execute the selected provider without fabricating fallback observations."""
    cfg = settings or get_settings()
    provider_name = resolve_sandbox_provider_name(cfg)
    registry = get_default_sandbox_provider_registry()
    if not cfg.sandbox_enabled:
        return build_empty_sandbox_result(provider=provider_name, status="disabled")
    return await registry.analyze(
        provider_name=provider_name,
        file_path=file_path,
        sha256=sha256,
        filename=filename,
        submission_url=submission_url,
        provider_kwargs=_provider_kwargs(cfg),
        previous_result=previous_result,
        on_checkpoint=on_checkpoint,
    )


class SandboxStage(Stage):
    """Sandbox stage that defers dynamic detonation to a dedicated worker."""

    @property
    def name(self) -> str:
        return "sandbox"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = get_settings()

        if not settings.sandbox_enabled:
            ended_at = datetime.now(timezone.utc)
            return StageResult(
                stage_name=self.name,
                status="skipped",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=_duration_ms(started_at, ended_at),
                findings=build_empty_sandbox_result(
                    provider=resolve_sandbox_provider_name(settings),
                    executed=False,
                    status="disabled",
                ),
                artifacts=[],
                error=None,
            )

        provider_name = resolve_sandbox_provider_name(settings)

        if should_defer_sandbox(settings=settings):
            ended_at = datetime.now(timezone.utc)
            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=_duration_ms(started_at, ended_at),
                findings=build_deferred_sandbox_result(provider_name=provider_name),
                artifacts=[],
                error=None,
            )

        findings = await execute_sandbox_analysis(
            file_path=ctx.file_path,
            sha256=ctx.sha256,
            filename=ctx.original_filename,
            settings=settings,
        )
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="failed" if findings.get("status") in {"failed", "unavailable"} else "ok",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=_duration_ms(started_at, ended_at),
            findings=findings,
            artifacts=[],
            error=findings.get("error_code"),
        )
