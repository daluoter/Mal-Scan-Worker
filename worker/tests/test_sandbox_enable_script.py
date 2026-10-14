"""Validate the enable command with a fake Docker CLI, without starting services."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "enable-sandbox.sh"


def _run(tmp_path: Path, *, provider="capev2", preflight_status=0, args=()):
    docker = tmp_path / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['FAKE_DOCKER_LOG'], 'a') as handle:\n"
        "    handle.write(json.dumps({'args': sys.argv[1:], "
        "'enabled': os.environ.get('SANDBOX_ENABLED'), "
        "'provider': os.environ.get('SANDBOX_PROVIDER')}) + '\\n')\n"
        "if 'sandbox-preflight' in sys.argv:\n"
        "    raise SystemExit(int(os.environ['FAKE_PREFLIGHT_STATUS']))\n"
    )
    docker.chmod(0o755)
    log = tmp_path / "docker-log.jsonl"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{tmp_path}:{env.get('PATH', '')}",
            "SANDBOX_PROVIDER": provider,
            "SANDBOX_API_TOKEN": "test-only-secret-never-printed",
            "SANDBOX_ENABLED": "false",
            "FAKE_DOCKER_LOG": str(log),
            "FAKE_PREFLIGHT_STATUS": str(preflight_status),
        }
    )
    completed = subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    assert "test-only-secret-never-printed" not in completed.stdout + completed.stderr
    return completed, calls


def test_cape_preflight_failure_prevents_starting_dynamic_services(tmp_path):
    completed, calls = _run(tmp_path, preflight_status=1)
    assert completed.returncode == 1
    assert [call["args"] for call in calls] == [
        ["compose", "version"],
        ["compose", "run", "--build", "--rm", "--no-deps", "sandbox-preflight"],
    ]
    assert calls[-1]["enabled"] == "true"
    assert calls[-1]["provider"] == "capev2"


def test_cape_enable_checks_access_before_starting_both_workers(tmp_path):
    completed, calls = _run(tmp_path)
    assert completed.returncode == 0
    assert calls[-1]["args"] == [
        "compose",
        "--profile",
        "sandbox",
        "up",
        "--build",
        "-d",
        "worker",
        "sandbox-worker",
    ]
    assert calls[-1]["enabled"] == "true"
    assert calls[-1]["provider"] == "capev2"
    assert calls[-2]["args"][-1] == "sandbox-preflight"


def test_mock_is_rejected_without_explicit_development_flag(tmp_path):
    completed, calls = _run(tmp_path, provider="mock")
    assert completed.returncode == 2
    assert calls == []


def test_explicit_mock_enable_is_labeled_synthetic_and_skips_real_preflight(tmp_path):
    completed, calls = _run(tmp_path, provider="mock", args=("--allow-mock",))
    assert completed.returncode == 0
    assert "no real dynamic analysis" in completed.stderr
    assert all("sandbox-preflight" not in call["args"] for call in calls)
    assert calls[-1]["provider"] == "mock"


@pytest.mark.parametrize("provider", ["typo", "CAPE", "other"])
def test_unknown_provider_fails_before_running_compose(tmp_path, provider):
    completed, calls = _run(tmp_path, provider=provider)
    assert completed.returncode == 2
    assert calls == []
