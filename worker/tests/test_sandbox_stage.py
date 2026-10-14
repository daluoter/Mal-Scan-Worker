"""Tests for sandbox providers and truthful execution outcomes."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_sandbox_registry_exposes_mock_and_capev2() -> None:
    from malscan_worker.sandbox.providers import SandboxProviderRegistry

    registry = SandboxProviderRegistry.default()

    assert registry.names() == ["mock", "capev2"]


def test_mock_provider_normalizes_legacy_and_additive_fields(tmp_path: Path) -> None:
    from malscan_worker.sandbox.providers import MockSandboxProvider

    provider = MockSandboxProvider()
    result = provider.build_mock_result(
        file_path=tmp_path / "sample.bin",
        sha256="deadbeef",
        filename="sample.bin",
        reason="unit test",
    )

    assert result["executed"] is False
    assert result["provider"] == "mock"
    assert result["is_mock"] is True
    assert result["synthetic"] is True
    assert result["status"] == "synthetic"
    assert result["verdict_hint"] is None
    assert result["errors"] == ["unit test"]
    assert result["behaviors"][0]["type"] == "file_write"
    assert result["network_connections"][0]["protocol"] == "tcp"
    assert result["dns"]
    assert result["http"]
    assert result["tcp_udp"]
    assert result["raw_report_ref"] is None


def test_capev2_normalizer_maps_report_to_additive_schema() -> None:
    from malscan_worker.sandbox.providers import CAPEv2SandboxProvider

    provider = CAPEv2SandboxProvider(
        base_url="https://cape.local",
        api_token="token",
        timeout_seconds=30,
        poll_interval_seconds=1,
        enable_url_submission=True,
    )
    normalized = provider.normalize_report(
        task_id="42",
        report={
            "info": {"id": 42},
            "signatures": [
                {
                    "name": "process_injection",
                    "description": "Injected into another process",
                },
                {"name": "ransomware_files", "description": "Mass file encryption"},
            ],
            "behavior": {
                "summary": {
                    "files": ["C:\\temp\\dropper.dll"],
                    "write_files": ["C:\\temp\\dropper.dll"],
                    "keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                    "mutexes": ["Global\\abc123"],
                },
                "processes": [
                    {
                        "process_id": 100,
                        "parent_id": 4,
                        "process_name": "sample.exe",
                        "command_line": "sample.exe /q",
                    }
                ],
            },
            "network": {
                "dns": [
                    {
                        "request": "evil.example",
                        "answers": [{"type": "A", "data": "8.8.8.8"}],
                    }
                ],
                "http": [
                    {
                        "uri": "http://evil.example/payload",
                        "method": "GET",
                        "user-agent": "TestAgent",
                    }
                ],
                "tcp": [{"dst": "8.8.8.8", "dport": 443}],
                "udp": [{"dst": "1.1.1.1", "dport": 53}],
                "hosts": ["8.8.8.8", "1.1.1.1"],
            },
            "dropped": [
                {
                    "name": "dropper.dll",
                    "filepath": "C:\\temp\\dropper.dll",
                    "size": 1234,
                    "sha256": "abc123",
                    "type": "PE32 executable",
                }
            ],
            "procmemory": [{"path": "memory/100.dmp", "pid": 100}],
        },
        screenshot_refs=[
            {
                "name": "0001.jpg",
                "url": "https://cape.local/apiv2/tasks/screenshots/42/?screenshot=0001",
            }
        ],
        pcap_ref={"url": "https://cape.local/apiv2/pcap/get/42/", "available": True},
    )

    assert normalized["executed"] is True
    assert normalized["status"] == "completed"
    assert normalized["provider"] == "capev2"
    assert normalized["task_id"] == "42"
    assert normalized["is_mock"] is False
    assert normalized["verdict_hint"] == "malicious"
    assert normalized["behaviors"] == [
        {"type": "process_injection", "detail": "Injected into another process"},
        {"type": "ransomware", "detail": "Mass file encryption"},
    ]
    assert normalized["network_connections"] == [
        {"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp"},
        {"dst_ip": "1.1.1.1", "dst_port": 53, "protocol": "udp"},
    ]
    assert normalized["files"] == [{"path": "C:\\temp\\dropper.dll", "action": "write"}]
    assert normalized["registry"] == [
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "action": "modify",
        }
    ]
    assert normalized["mutexes"] == [{"name": "Global\\abc123"}]
    assert normalized["dns"][0]["query"] == "evil.example"
    assert normalized["http"][0]["url"] == "http://evil.example/payload"
    assert normalized["tcp_udp"] == [
        {"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp"},
        {"dst_ip": "1.1.1.1", "dst_port": 53, "protocol": "udp"},
    ]
    assert normalized["dropped_files"][0]["sha256"] == "abc123"
    assert normalized["screenshots"][0]["name"] == "0001.jpg"
    assert normalized["pcap"]["available"] is True
    assert normalized["memory_dump"]["available"] is True
    assert normalized["iocs"]["domains"] == ["evil.example"]
    assert normalized["raw_report_ref"] == "https://cape.local/apiv2/tasks/get/report/42/json/"


@pytest.mark.asyncio
async def test_registry_preserves_unavailability_without_mock(tmp_path: Path) -> None:
    from malscan_worker.sandbox.providers import SandboxProviderRegistry

    registry = SandboxProviderRegistry()
    from malscan_worker.sandbox.providers import CAPEv2SandboxProvider

    registry.register("capev2", lambda **kwargs: CAPEv2SandboxProvider(**kwargs))
    result = await registry.analyze_with_fallback(
        provider_name="capev2",
        file_path=tmp_path / "sample.bin",
        sha256="deadbeef",
        filename="sample.bin",
        submission_url=None,
        provider_kwargs={
            "base_url": "",
            "api_token": None,
            "timeout_seconds": 30,
            "poll_interval_seconds": 1,
            "enable_url_submission": False,
        },
    )

    assert result["provider"] == "capev2"
    assert result["is_mock"] is False
    assert result["status"] == "unavailable"
    assert result["executed"] is False
    assert result["behaviors"] == []
    assert result["errors"] == ["provider_unavailable"]
