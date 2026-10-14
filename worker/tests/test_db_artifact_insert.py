"""Tests for artifact DB insert payload construction."""

import uuid

import pytest
from malscan_worker import db as worker_db


@pytest.mark.asyncio
async def test_create_artifact_includes_created_at_for_raw_insert(monkeypatch):
    """Raw INSERT payload must include created_at for DBs without server default."""

    captured: dict = {}

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, params):
            captured["params"] = params

            class Result:
                def scalar_one_or_none(self):
                    return params.get("id")

            return Result()

        async def commit(self):
            return None

        async def rollback(self):
            return None

    monkeypatch.setattr(worker_db, "AsyncSession", DummySession)

    await worker_db.create_artifact(
        parent_id=None,
        root_id=None,
        depth=0,
        sha256="a" * 64,
        size=123,
        original_filename="sample.zip",
        extraction_source="archive-extract",
        archive_type="zip",
        job_id=str(uuid.uuid4()),
        root_job_id=str(uuid.uuid4()),
    )

    assert "created_at" in captured["params"]
    assert captured["params"]["created_at"] is not None


@pytest.mark.asyncio
async def test_update_artifact_risk_includes_risk_level_and_policy_version(monkeypatch):
    captured: dict = {}

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, params):
            captured["params"] = params

            class Result:
                def scalar_one_or_none(self):
                    return params.get("id")

            return Result()

        async def commit(self):
            return None

        async def rollback(self):
            return None

    monkeypatch.setattr(worker_db, "AsyncSession", DummySession)

    await worker_db.update_artifact_risk(
        artifact_id=str(uuid.uuid4()),
        verdict="suspicious",
        score=65,
        risk_level="medium",
        policy_version="msrs-v1",
    )

    assert captured["params"]["risk_level"] == "medium"
    assert captured["params"]["policy_version"] == "msrs-v1"


@pytest.mark.asyncio
async def test_update_artifact_verdict_shim_preserves_verdict_and_score(monkeypatch):
    captured: dict = {}

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, params):
            captured["params"] = params

            class Result:
                def scalar_one_or_none(self):
                    return params.get("id")

            return Result()

        async def commit(self):
            return None

        async def rollback(self):
            return None

    monkeypatch.setattr(worker_db, "AsyncSession", DummySession)

    await worker_db.update_artifact_verdict(
        artifact_id=str(uuid.uuid4()),
        verdict="malicious",
        score=90,
    )

    assert captured["params"]["verdict"] == "malicious"
    assert captured["params"]["score"] == 90
