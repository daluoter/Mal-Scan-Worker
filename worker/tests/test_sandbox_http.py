"""Exercise the CAPE adapter and read-only preflight against local HTTP servers."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import pytest
from aiohttp import web
from malscan_worker.sandbox.preflight import PreflightConfig, check_sandbox_readiness
from malscan_worker.sandbox.providers import (
    CAPEv2SandboxProvider,
    ProviderCheckpointError,
    ProviderUnavailableError,
    SandboxProviderRegistry,
    resolve_sandbox_provider_name,
)


@asynccontextmanager
async def _server(handler) -> AsyncIterator[str]:
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def _provider(base_url: str, **overrides) -> CAPEv2SandboxProvider:
    values = {
        "base_url": base_url,
        "api_token": "test-only-token",
        "timeout_seconds": 2,
        "poll_interval_seconds": 0,
        "enable_url_submission": True,
    }
    values.update(overrides)
    return CAPEv2SandboxProvider(**values)


@pytest.mark.asyncio
async def test_cape_file_submission_polls_reported_and_preserves_real_evidence(
    tmp_path: Path,
):
    requests: list[tuple[str, str]] = []
    statuses = iter(["completed", "reported"])

    async def handler(request):
        requests.append((request.method, request.path))
        assert request.headers["Authorization"] == "Token test-only-token"
        if request.path == "/apiv2/tasks/create/file/":
            reader = await request.multipart()
            field = await reader.next()
            assert field.name == "file"
            assert await field.read() == b"harmless sample"
            return web.json_response({"error": False, "data": {"task_ids": [42]}})
        if request.path == "/apiv2/tasks/status/42/":
            return web.json_response({"error": False, "data": next(statuses)})
        if request.path == "/apiv2/tasks/get/report/42/json/":
            return web.json_response(
                {
                    "info": {"id": 42},
                    "signatures": [{"name": "process_injection", "description": "Injection"}],
                    "network": {"tcp": [{"dst": "192.0.2.7", "dport": 443}]},
                    "dropped": [{"name": "child.bin", "sha256": "abc"}],
                }
            )
        if request.path == "/apiv2/tasks/get/screenshot/42/":
            return web.Response(body=b"archive-placeholder", content_type="application/zip")
        if request.path == "/apiv2/tasks/get/pcap/42/":
            return web.json_response({"error": True, "error_value": "PCAP unavailable"})
        return web.Response(status=404)

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"harmless sample")
    async with _server(handler) as base_url:
        result = await _provider(base_url).analyze_file(
            file_path=sample, sha256="sample-hash", filename="sample.bin"
        )
    assert result["status"] == "completed"
    assert result["executed"] is True
    assert result["synthetic"] is False
    assert result["task_id"] == "42"
    assert result["verdict_hint"] == "malicious"
    assert result["dropped_files"][0]["url"].endswith("/tasks/get/dropped/42/")
    assert result["raw_report_ref"].endswith("/tasks/get/report/42/json/")
    assert result["screenshots"][0]["url"].endswith("/tasks/get/screenshot/42/")
    assert result["pcap"]["available"] is False
    assert requests.count(("POST", "/apiv2/tasks/create/file/")) == 1
    assert requests.count(("GET", "/apiv2/tasks/status/42/")) == 2
    assert ("GET", "/apiv2/tasks/get/screenshot/42/") in requests
    assert ("GET", "/apiv2/tasks/get/pcap/42/") in requests


@pytest.mark.asyncio
async def test_cape_submission_is_not_retried_or_replaced_on_http_failure(
    tmp_path: Path,
):
    calls = []

    async def handler(request):
        calls.append(request.method)
        return web.Response(status=503, text="private-token-in-response")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **kwargs: _provider(**kwargs))
    async with _server(handler) as base_url:
        result = await registry.analyze(
            provider_name="capev2",
            file_path=sample,
            sha256="hash",
            filename="sample.bin",
            submission_url=None,
            provider_kwargs={"base_url": base_url},
        )
    assert calls == ["POST"]
    assert result["status"] == "unavailable"
    assert result["provider"] == "capev2"
    assert result["executed"] is False
    assert result["behaviors"] == []
    assert "private-token-in-response" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["failed_analysis", "failed_processing", "failed_reporting"])
async def test_cape_task_failure_retains_task_id(failure: str, tmp_path: Path):
    async def handler(request):
        if request.method == "POST":
            await request.read()
            return web.json_response({"error": False, "data": {"task_ids": [7]}})
        return web.json_response({"error": False, "data": failure})

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **kwargs: _provider(**kwargs))
    async with _server(handler) as base_url:
        result = await registry.analyze(
            provider_name="capev2",
            file_path=sample,
            sha256="hash",
            filename="sample.bin",
            submission_url=None,
            provider_kwargs={"base_url": base_url},
        )
    assert result["status"] == "failed"
    assert result["error_code"] == "provider_task_failed"
    assert result["task_id"] == "7"
    assert result["executed"] is False
    assert result["behaviors"] == []


@pytest.mark.asyncio
async def test_cape_report_identity_is_required(tmp_path: Path):
    async def handler(request):
        if request.method == "POST":
            await request.read()
            return web.json_response({"error": False, "data": {"task_ids": [7]}})
        if "/status/" in request.path:
            return web.json_response({"error": False, "data": "reported"})
        return web.json_response({"info": {"id": 8}, "signatures": []})

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    async with _server(handler) as base_url:
        with pytest.raises(ProviderUnavailableError) as error:
            await _provider(base_url).analyze_file(
                file_path=sample, sha256="hash", filename="sample.bin"
            )
    assert error.value.code == "provider_report_invalid"
    assert error.value.task_id == "7"


@pytest.mark.asyncio
async def test_cape_real_poll_timeout_keeps_submitted_task_and_no_synthetic_data(tmp_path: Path):
    submissions = []

    async def handler(request):
        if request.method == "POST":
            submissions.append(request.path)
            await request.read()
            return web.json_response({"error": False, "data": {"task_ids": [9]}})
        return web.json_response({"error": False, "data": "running"})

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register(
        "capev2",
        lambda **kwargs: _provider(**kwargs, timeout_seconds=0.03, poll_interval_seconds=0.01),
    )
    async with _server(handler) as base_url:
        result = await registry.analyze(
            provider_name="capev2",
            file_path=sample,
            sha256="hash",
            filename="sample.bin",
            submission_url=None,
            provider_kwargs={"base_url": base_url},
        )
    assert submissions == ["/apiv2/tasks/create/file/"]
    assert result["status"] == "failed"
    assert result["error_code"] == "provider_timeout"
    assert result["task_id"] == "9"
    assert result["executed"] is False
    assert result["is_mock"] is False
    assert result["behaviors"] == []


@pytest.mark.asyncio
async def test_registry_circuit_and_timeout_never_build_mock():
    calls = []

    class TimedOutProvider:
        async def analyze_file(self, **_kwargs):
            calls.append("real")
            raise ProviderUnavailableError("secret exception", code="provider_timeout", task_id="3")

    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **_: TimedOutProvider())
    outcomes = []
    for _ in range(4):
        outcomes.append(
            await registry.analyze(
                provider_name="capev2",
                file_path=None,
                sha256="hash",
                filename="file",
                submission_url=None,
                provider_kwargs={},
            )
        )
    assert calls == ["real"] * 3
    assert [item["status"] for item in outcomes] == ["failed"] * 3 + ["unavailable"]
    assert outcomes[-1]["error_code"] == "provider_circuit_open"
    assert all(item["provider"] == "capev2" and not item["executed"] for item in outcomes)
    assert "secret exception" not in json.dumps(outcomes)
    interrupted = await registry.analyze(
        provider_name="capev2",
        file_path=None,
        sha256="hash",
        filename="file",
        submission_url=None,
        provider_kwargs={},
        previous_result={
            "status": "running",
            "task_id": "3",
            "provider": "capev2",
            "provider_endpoint_fingerprint": "retained-host",
        },
    )
    assert interrupted["task_id"] == "3"
    assert interrupted["reconcile_required"] is True
    assert interrupted["provider_endpoint_fingerprint"] == "retained-host"


@pytest.mark.asyncio
async def test_registry_cancellation_propagates():
    class CancelledProvider:
        async def analyze_file(self, **_kwargs):
            raise asyncio.CancelledError()

    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **_: CancelledProvider())
    with pytest.raises(asyncio.CancelledError):
        await registry.analyze(
            provider_name="capev2",
            file_path=None,
            sha256="hash",
            filename="file",
            submission_url=None,
            provider_kwargs={},
        )


@pytest.mark.asyncio
async def test_cape_accept_then_disconnect_resumes_known_task_without_second_post(tmp_path):
    requests = []
    retained = {}

    async def handler(request):
        requests.append((request.method, request.path))
        if request.method == "POST":
            await request.read()
            return web.json_response({"error": False, "data": {"task_ids": [27]}})
        if "/status/" in request.path:
            return web.json_response({"error": False, "data": "reported"})
        if "/report/" in request.path:
            return web.json_response({"info": {"id": 27}, "signatures": []})
        return web.Response(status=404)

    async def interrupted_checkpoint(state):
        retained.clear()
        retained.update(state)
        assert "test-only-token" not in json.dumps(state)
        if state["status"] == "running":
            # Model a process disconnect after the task identity was committed.
            raise asyncio.CancelledError()

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    async with _server(handler) as base_url:
        with pytest.raises(asyncio.CancelledError):
            await _provider(base_url).analyze_file(
                file_path=sample,
                filename="sample.bin",
                sha256="hash",
                on_checkpoint=interrupted_checkpoint,
            )
        assert retained["status"] == "running"
        assert retained["task_id"] == "27"
        result = await _provider(base_url).analyze_file(
            # A known task can resume even if the source fixture is gone.
            file_path=None,
            filename="sample.bin",
            sha256="hash",
            previous_result=retained,
        )
    assert result["status"] == "completed"
    assert result["task_id"] == "27"
    assert requests.count(("POST", "/apiv2/tasks/create/file/")) == 1
    assert requests.count(("GET", "/apiv2/tasks/status/27/")) == 1


@pytest.mark.asyncio
async def test_cape_submitting_checkpoint_without_task_id_never_resubmits(tmp_path):
    calls = []
    retained = {}

    async def handler(request):
        calls.append(request.method)
        return web.Response(status=500)

    async def crash_before_response(state):
        retained.update(state)
        raise asyncio.CancelledError()

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    async with _server(handler) as base_url:
        with pytest.raises(asyncio.CancelledError):
            await _provider(base_url).analyze_file(
                file_path=sample,
                filename="sample.bin",
                sha256="hash",
                on_checkpoint=crash_before_response,
            )
        assert retained["status"] == "submitting"
        assert retained["task_id"] is None
        result = await _provider(base_url).analyze_file(
            file_path=sample,
            filename="sample.bin",
            sha256="hash",
            previous_result=retained,
        )
    assert calls == []
    assert result["status"] == "unavailable"
    assert result["error_code"] == "provider_submission_unknown"
    assert result["reconcile_required"] is True
    assert result["executed"] is False


@pytest.mark.asyncio
async def test_cape_uncertain_post_response_requires_reconciliation_without_retry(tmp_path):
    submissions = []
    retained = {}

    async def handler(request):
        submissions.append(request.method)
        await request.read()
        # The request was received, but the response is lost before task identity.
        request.transport.close()
        return web.Response(status=200)

    async def checkpoint(state):
        retained.update(state)

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **kwargs: _provider(**kwargs))
    async with _server(handler) as base_url:
        values = {
            "provider_name": "capev2",
            "file_path": sample,
            "filename": "sample.bin",
            "sha256": "hash",
            "submission_url": None,
            "provider_kwargs": {"base_url": base_url},
        }
        failed = await registry.analyze(**values, on_checkpoint=checkpoint)
        resumed = await registry.analyze(**values, previous_result=retained)
    assert submissions == ["POST"]
    assert failed["error_code"] == resumed["error_code"] == "provider_submission_unknown"
    assert failed["reconcile_required"] is resumed["reconcile_required"] is True


@pytest.mark.asyncio
async def test_cape_failed_checkpoint_prevents_submission_and_is_not_terminal_mock(tmp_path):
    requests = []

    async def handler(request):
        requests.append(request.method)
        return web.Response(status=500)

    async def failed_checkpoint(_state):
        raise RuntimeError("simulated storage unavailable")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **kwargs: _provider(**kwargs))
    async with _server(handler) as base_url:
        with pytest.raises(ProviderCheckpointError):
            await registry.analyze(
                provider_name="capev2",
                file_path=sample,
                filename="sample.bin",
                sha256="hash",
                submission_url=None,
                provider_kwargs={"base_url": base_url},
                on_checkpoint=failed_checkpoint,
            )
    assert requests == []


@pytest.mark.asyncio
async def test_cape_changed_endpoint_never_polls_or_submits_retained_task():
    requests = []

    async def handler(request):
        requests.append(request.method)
        return web.Response(status=500)

    async with _server(handler) as base_url:
        result = await _provider(base_url).analyze_file(
            file_path=None,
            filename="sample",
            sha256="hash",
            previous_result={
                "status": "running",
                "provider": "capev2",
                "task_id": "27",
                "provider_endpoint_fingerprint": "different-endpoint",
            },
        )
    assert requests == []
    assert result["error_code"] == "provider_configuration_changed"
    assert result["reconcile_required"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("submission_kind", ["file", "url"])
async def test_cape_multiple_tasks_save_all_ids_and_never_complete_only_first(
    tmp_path, submission_kind
):
    requests = []
    checkpoints = []

    async def handler(request):
        requests.append((request.method, request.path))
        await request.read()
        return web.json_response({"error": False, "data": {"task_ids": [71, 72]}})

    async def checkpoint(state):
        checkpoints.append(dict(state))
        assert "test-only-token" not in json.dumps(state)

    sample = tmp_path / "sample.zip"
    sample.write_bytes(b"test")
    registry = SandboxProviderRegistry()
    registry.register("capev2", lambda **kwargs: _provider(**kwargs))
    async with _server(handler) as base_url:
        result = await registry.analyze(
            provider_name="capev2",
            file_path=sample,
            filename="sample.zip",
            sha256="hash",
            submission_url="https://example.invalid/test" if submission_kind == "url" else None,
            provider_kwargs={"base_url": base_url},
            on_checkpoint=checkpoint,
        )
        resumed = await registry.analyze(
            provider_name="capev2",
            file_path=None,
            filename="sample.zip",
            sha256="hash",
            submission_url=None,
            provider_kwargs={"base_url": base_url},
            previous_result=checkpoints[-1],
        )
    assert [state["status"] for state in checkpoints] == ["submitting", "running"]
    assert checkpoints[-1]["task_ids"] == ["71", "72"]
    assert checkpoints[-1]["task_id"] == "71"
    assert requests == [("POST", f"/apiv2/tasks/create/{submission_kind}/")]
    for outcome in (result, resumed):
        assert outcome["status"] == "unavailable"
        assert outcome["executed"] is False
        assert outcome["error_code"] == "provider_multiple_tasks"
        assert outcome["task_ids"] == ["71", "72"]
        assert outcome["reconcile_required"] is True


def test_provider_resolution_does_not_use_legacy_mock_fallback():
    from types import SimpleNamespace

    assert (
        resolve_sandbox_provider_name(SimpleNamespace(sandbox_provider="", sandbox_mock=True))
        == "capev2"
    )
    assert (
        resolve_sandbox_provider_name(SimpleNamespace(sandbox_provider="typo", sandbox_mock=True))
        == "typo"
    )
    assert (
        resolve_sandbox_provider_name(SimpleNamespace(sandbox_provider="mock", sandbox_mock=False))
        == "mock"
    )


@pytest.mark.asyncio
async def test_preflight_only_gets_machine_list_and_can_select_platform():
    calls = []

    async def handler(request):
        calls.append((request.method, request.path))
        assert request.headers["Authorization"] == "Token test-only-token"
        return web.json_response(
            {
                "error": [],
                "data": [
                    {
                        "name": "win",
                        "platform": "windows",
                        "locked": False,
                        "status": "poweroff",
                    },
                    {"name": "linux", "platform": "linux", "locked": True},
                ],
            }
        )

    async with _server(handler) as base_url:
        result = await check_sandbox_readiness(
            PreflightConfig(
                base_url=f"{base_url}/apiv2/",
                api_token="test-only-token",
                platform="windows",
            )
        )
    assert calls == [("GET", "/apiv2/machines/list/")]
    assert result["success"] is True
    assert result["configured_guests"] == 1
    assert result["available_guests"] == 1
    assert result["guest_boot_verified"] is False
    assert result["sample_submitted"] is False
    assert "test-only-token" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 302, 404, 503])
async def test_preflight_rejects_http_errors_and_redirects(status):
    calls = []

    async def handler(request):
        calls.append(request.path)
        return web.Response(status=status, text="private token", headers={"Location": "/other"})

    async with _server(handler) as base_url:
        result = await check_sandbox_readiness(PreflightConfig(base_url=base_url))
    assert result["success"] is False
    assert result["status"] == (
        "authentication_failed" if status in {401, 403} else "api_unavailable"
    )
    assert calls == ["/apiv2/machines/list/"]
    assert "private token" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"error": True, "error_value": "private body"}, "api_rejected"),
        ({"data": []}, "no_available_guest"),
        (
            {"data": [{"name": "busy", "platform": "windows", "locked": True}]},
            "no_available_guest",
        ),
        ({"data": [{"name": "unknown", "platform": "windows"}]}, "no_available_guest"),
        (
            {
                "data": [
                    {
                        "name": "bad",
                        "platform": "windows",
                        "locked": False,
                        "status": "error",
                    }
                ]
            },
            "no_available_guest",
        ),
        ({"data": {"name": "bad"}}, "invalid_api_response"),
        ({"data": ["bad"]}, "invalid_api_response"),
    ],
)
async def test_preflight_requires_real_registered_unlocked_guest(payload, expected):
    async def handler(_request):
        return web.json_response(payload)

    async with _server(handler) as base_url:
        result = await check_sandbox_readiness(PreflightConfig(base_url=base_url))
    assert result["success"] is False
    assert result["status"] == expected
    assert "private body" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "not-a-url",
        "ftp://cape",
        "https://user:password@cape",
        "https://cape/?token=secret",
    ],
)
async def test_preflight_rejects_invalid_or_credential_bearing_endpoints(base_url):
    result = await check_sandbox_readiness(PreflightConfig(base_url=base_url))
    assert result["status"] == "invalid_endpoint"
    assert "password" not in json.dumps(result)
    assert "secret" not in json.dumps(result)


@pytest.mark.asyncio
async def test_preflight_mock_is_explicit_synthetic_not_readiness():
    result = await check_sandbox_readiness(PreflightConfig(provider="mock"))
    assert result["status"] == "synthetic"
    assert result["success"] is False


@pytest.mark.asyncio
async def test_preflight_timeout_is_sanitized():
    async def handler(_request):
        await asyncio.sleep(0.1)
        return web.json_response({"data": []})

    async with _server(handler) as base_url:
        result = await check_sandbox_readiness(
            PreflightConfig(base_url=base_url, timeout_seconds=0.01)
        )
    assert result["status"] == "api_timeout"
    assert result["success"] is False
