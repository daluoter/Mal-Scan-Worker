"""Sandbox worker startup must be explicit and fail before consuming on errors."""

from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


def _settings(**overrides):
    values = {
        "sandbox_enabled": True,
        "sandbox_provider": "capev2",
        "sandbox_base_url": "https://cape.test",
        "sandbox_api_token": "test-only-token",
        "rabbitmq_sandbox_queue": "test.sandbox",
        "metrics_port": 9099,
        "require_service_configuration": Mock(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.asyncio
async def test_disabled_worker_does_not_check_or_consume(monkeypatch):
    from malscan_worker import sandbox_main

    settings = _settings(sandbox_enabled=False)
    monkeypatch.setattr(sandbox_main, "settings", settings)
    readiness = AsyncMock()
    consumer = AsyncMock()
    metrics = AsyncMock()
    monkeypatch.setattr(sandbox_main, "check_sandbox_readiness", readiness)
    monkeypatch.setattr(sandbox_main, "start_sandbox_consumer", consumer)
    monkeypatch.setattr(sandbox_main, "start_metrics_server", metrics)
    assert await sandbox_main.main() == 0
    settings.require_service_configuration.assert_not_called()
    readiness.assert_not_awaited()
    consumer.assert_not_awaited()
    metrics.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_provider_prevents_worker_consumption(monkeypatch):
    from malscan_worker import sandbox_main

    settings = _settings()
    monkeypatch.setattr(sandbox_main, "settings", settings)
    readiness = AsyncMock(return_value={"success": False, "status": "authentication_failed"})
    consumer = AsyncMock()
    metrics = AsyncMock()
    monkeypatch.setattr(sandbox_main, "check_sandbox_readiness", readiness)
    monkeypatch.setattr(sandbox_main, "start_sandbox_consumer", consumer)
    monkeypatch.setattr(sandbox_main, "start_metrics_server", metrics)
    assert await sandbox_main.main() == 1
    settings.require_service_configuration.assert_called_once()
    readiness.assert_awaited_once()
    consumer.assert_not_awaited()
    metrics.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["capev2", "mock"])
async def test_successful_or_explicit_mock_worker_starts_and_cleans_metrics(monkeypatch, provider):
    from malscan_worker import sandbox_main

    monkeypatch.setattr(sandbox_main, "settings", _settings(sandbox_provider=provider))
    readiness = AsyncMock(return_value={"success": True, "status": "ready"})
    consumer = AsyncMock()
    runner = SimpleNamespace(cleanup=AsyncMock())
    monkeypatch.setattr(sandbox_main, "check_sandbox_readiness", readiness)
    monkeypatch.setattr(sandbox_main, "start_sandbox_consumer", consumer)
    monkeypatch.setattr(sandbox_main, "start_metrics_server", AsyncMock(return_value=runner))
    assert await sandbox_main.main() == 0
    consumer.assert_awaited_once()
    runner.cleanup.assert_awaited_once()
    assert readiness.await_count == (1 if provider == "capev2" else 0)


def test_read_only_preflight_cli_requires_no_storage_or_broker_credentials(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-m", "malscan_worker.sandbox.preflight"],
        cwd=tmp_path,
        env={"SANDBOX_PROVIDER": "capev2", "SANDBOX_BASE_URL": ""},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["status"] == "invalid_endpoint"
    assert result["sample_submitted"] is False
    assert result["analysis_executed"] is False
