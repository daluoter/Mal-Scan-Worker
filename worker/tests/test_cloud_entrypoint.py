"""Control-plane and shared-runner identities are checked before analysis."""

import copy
import hashlib
import json
import time
from pathlib import Path
from uuid import uuid4

import pytest
from malscan_worker.runtime.cloud_entrypoint import (
    CloudConfiguration,
    ExpiringResultStore,
    JobExpiredError,
    canonical,
    execute_cloud,
    open_envelope,
    seal,
)
from malscan_worker.runtime.manifest import AnalysisManifest, SourceReference


class MemoryStore:
    def __init__(self):
        self.documents = {}
        self.deleted = []

    async def read_json(self, key):
        return copy.deepcopy(self.documents[key])

    async def put_json(self, key, document):
        self.documents[key] = copy.deepcopy(document)
        return key

    async def delete(self, key):
        self.deleted.append(key)
        self.documents.pop(key, None)


def setup_control(tmp_path):
    root, attempt, dispatch = (str(uuid4()) for _ in range(3))
    config = CloudConfiguration(
        root,
        attempt,
        dispatch,
        1,
        f"manifests/{root}/{attempt}.json",
        f"controls/{root}/{dispatch}.json",
        f"statuses/{root}/{dispatch}.json",
        f"reports/{root}/{attempt}.json",
        "https://example.r2.cloudflarestorage.com",
        "uploads",
        "results",
        Path("unused-source-secret"),
        Path("unused-results-secret"),
        Path("unused-hmac"),
        tmp_path,
    )
    manifest = AnalysisManifest(
        root,
        attempt,
        SourceReference(
            f"uploads/{root}/source", hashlib.sha256(b"sample").hexdigest(), 6, "sample.txt"
        ),
        config.report_key,
    )
    control = {
        "control_version": 1,
        "manifest_sha256": manifest.fingerprint,
        "dispatch_id": dispatch,
        "sequence": 1,
        "expires_at": int(time.time() * 1000) + 86400000,
        "status_key": config.status_key,
        "checkpoint_key": f"checkpoints/{root}/{attempt}.json",
        "resume": False,
        "passwords": {root: "never-expose-this-password"},
    }
    key = bytes(range(32))
    source, result = MemoryStore(), MemoryStore()
    source.documents[config.manifest_key] = manifest.to_dict()
    result.documents[config.control_key] = seal(control, key)
    return config, manifest, control, key, source, result


@pytest.mark.asyncio
async def test_cloud_controls_are_consumed_and_reports_are_immutable(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_ENABLED", "false")
    config, manifest, control, key, source, result = setup_control(tmp_path)
    calls = []

    class Runner:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            self.callback = kwargs["on_report"]

        async def run(self, *, resume):
            assert resume is False
            report = {
                "report_revision": 1,
                "artifacts": [],
                "batch_analysis": {"status": "complete"},
            }
            await self.callback(report)
            report["report_revision"] = 2
            return report

    outcome = await execute_cloud(
        config, source_store=source, result_store=result, key=key, runner_type=Runner
    )
    assert outcome["success"]
    assert result.deleted == [config.control_key]
    assert calls[0]["passwords"] == control["passwords"]
    assert calls[0]["checkpoint_secret"] == key
    status = open_envelope(result.documents[config.status_key], key)
    assert status["status"] == "done"
    assert status["dispatch_id"] == config.dispatch_id
    assert status["manifest_sha256"] == manifest.fingerprint
    stored_report = result.documents[status["report_key"]]
    assert status["report_sha256"] == hashlib.sha256(canonical(stored_report)).hexdigest()
    assert status["report_key"].endswith(f"/{config.dispatch_id}/2.json")
    assert "never-expose-this-password" not in json.dumps(result.documents)
    assert any(name.endswith(f"/{config.dispatch_id}/1.json") for name in result.documents)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("sequence", 2),
        ("dispatch_id", str(uuid4())),
        ("manifest_sha256", "0" * 64),
        ("checkpoint_key", "checkpoints/other.json"),
    ],
)
async def test_mismatched_control_never_runs_or_deletes(tmp_path, field, value):
    config, _manifest, control, key, source, result = setup_control(tmp_path)
    control[field] = value
    result.documents[config.control_key] = seal(control, key)

    def unexpected_runner(**kwargs):
        pytest.fail("Untrusted control must not execute")

    with pytest.raises(ValueError):
        await execute_cloud(
            config, source_store=source, result_store=result, key=key, runner_type=unexpected_runner
        )
    assert not result.deleted


def test_control_signature_rejects_tampering_before_parsing_passwords():
    key = b"a" * 32
    envelope = seal({"passwords": {"root": "private"}}, key)
    envelope["payload"] = envelope["payload"].replace("private", "changed")
    with pytest.raises(ValueError, match="signature"):
        open_envelope(envelope, key)


@pytest.mark.asyncio
async def test_signed_per_file_attempt_policy_is_forwarded_to_runner(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_ENABLED", "false")
    config, _manifest, control, key, source, result = setup_control(tmp_path)
    control.update(
        password_attempts_scope="artifact",
        password_attempt_limit=3,
        password_attempts_by_artifact={config.root_job_id: 2},
    )
    result.documents[config.control_key] = seal(control, key)
    calls = []

    class Runner:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        async def run(self, *, resume):
            return {"report_revision": 1, "artifacts": [], "batch_analysis": {"status": "complete"}}

    await execute_cloud(
        config, source_store=source, result_store=result, key=key, runner_type=Runner
    )
    assert calls[0]["password_attempts_by_artifact"] == {config.root_job_id: 2}
    assert calls[0]["password_attempt_limit"] == 3
    assert "never-expose-this-password" not in json.dumps(result.documents)


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [True, -1, 4, "2", None])
async def test_malformed_signed_attempt_count_never_runs_or_consumes_control(tmp_path, invalid):
    config, _manifest, control, key, source, result = setup_control(tmp_path)
    control.update(
        password_attempts_scope="artifact",
        password_attempt_limit=3,
        password_attempts_by_artifact={config.root_job_id: invalid},
    )
    result.documents[config.control_key] = seal(control, key)
    with pytest.raises(ValueError, match="per-file password attempt"):
        await execute_cloud(
            config,
            source_store=source,
            result_store=result,
            key=key,
            runner_type=lambda **_: pytest.fail("Must not run"),
        )
    assert not result.deleted


@pytest.mark.asyncio
async def test_expired_control_is_consumed_without_analysis_or_persistent_writes(tmp_path):
    config, _manifest, control, key, source, result = setup_control(tmp_path)
    control["expires_at"] = int(time.time() * 1000) - 1
    result.documents[config.control_key] = seal(control, key)

    def unexpected_runner(**kwargs):
        pytest.fail("Expired control must not execute")

    with pytest.raises(JobExpiredError):
        await execute_cloud(
            config, source_store=source, result_store=result, key=key, runner_type=unexpected_runner
        )
    assert result.deleted == [config.control_key]
    assert not result.documents


@pytest.mark.asyncio
async def test_expiry_applies_to_private_checkpoint_writes_too():
    store = MemoryStore()
    wrapped = ExpiringResultStore(store, int(time.time() * 1000) - 1)
    with pytest.raises(JobExpiredError):
        await wrapped.put_json("checkpoints/root/attempt.json", {"stage": "complete"})
    assert not store.documents


@pytest.mark.asyncio
@pytest.mark.parametrize("snapshot", [False, True])
async def test_trusted_runner_failure_signs_state_and_preserves_snapshot(tmp_path, snapshot):
    config, _manifest, _control, key, source, result = setup_control(tmp_path)

    class Runner:
        def __init__(self, **kwargs):
            self.callback = kwargs["on_report"]

        async def run(self, *, resume):
            if snapshot:
                await self.callback({"report_revision": 1, "artifacts": []})
            raise RuntimeError("never-expose-this-password")

    with pytest.raises(RuntimeError):
        await execute_cloud(
            config, source_store=source, result_store=result, key=key, runner_type=Runner
        )
    status = open_envelope(result.documents[config.status_key], key)
    assert status["status"] == "failed"
    assert status["error_code"] == "RuntimeError"
    assert bool(status["report_key"]) is snapshot
    assert bool(status["report_sha256"]) is snapshot
    assert "never-expose-this-password" not in json.dumps(result.documents)


@pytest.mark.asyncio
async def test_current_attempt_deadline_is_bounded_by_root_retention(tmp_path):
    config, _manifest, control, key, source, result = setup_control(tmp_path)
    control["expires_at"] = int(time.time() * 1000) + 30000
    result.documents[config.control_key] = seal(control, key)

    class Runner:
        def __init__(self, **kwargs):
            assert 0 < kwargs["limits"].timeout_seconds <= 30

        async def run(self, *, resume):
            return {"report_revision": 1, "artifacts": []}

    await execute_cloud(
        config, source_store=source, result_store=result, key=key, runner_type=Runner
    )
