"""Recovery republishes linked queued children with durable identity and no password."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from malscan_worker import dispatch_recovery


@pytest.mark.asyncio
async def test_recovery_confirmed_publish_after_failed_round(monkeypatch):
    row = {
        name: uuid4()
        for name in (
            "job_id",
            "file_id",
            "artifact_id",
            "parent_id",
            "root_artifact_id",
            "root_job_id",
        )
    }
    row.update(sha256="a" * 64, original_filename="nested.txt")
    session = AsyncMock()
    session.__aenter__.return_value = session
    rows = MagicMock()
    rows.mappings.return_value.all.return_value = [row]
    ancestors = MagicMock()
    ancestors.scalars.return_value.all.return_value = ["b" * 64, "b" * 64]
    session.execute.side_effect = [rows, ancestors, rows, ancestors]
    monkeypatch.setattr(dispatch_recovery, "_engine", object())
    monkeypatch.setattr(dispatch_recovery, "AsyncSession", lambda *_: session)
    submitter = SimpleNamespace(
        publish_payload=AsyncMock(side_effect=[RuntimeError("temporarily unavailable"), None])
    )
    monkeypatch.setattr(
        dispatch_recovery.InternalJobSubmitter, "get_instance", AsyncMock(return_value=submitter)
    )
    assert await dispatch_recovery.reconcile_queued_children() == 0
    assert await dispatch_recovery.reconcile_queued_children() == 1
    first, second = (call.args[0] for call in submitter.publish_payload.await_args_list)
    assert first == second
    assert first["artifact_id"] == str(row["artifact_id"])
    assert first["root_job_id"] == str(row["root_job_id"])
    assert first["ancestor_hashes"] == ["b" * 64]
    assert not any("password" in key for key in first)
    assert "j.parent_job_id IS NOT NULL" in str(dispatch_recovery.QUEUED_CHILDREN)
    assert "j.status = 'queued'" in str(dispatch_recovery.QUEUED_CHILDREN)


@pytest.mark.asyncio
async def test_recovery_validates_scope_and_database(monkeypatch):
    with pytest.raises(ValueError, match="batch size"):
        await dispatch_recovery.reconcile_queued_children(0)
    monkeypatch.setattr(dispatch_recovery, "_engine", None)
    with pytest.raises(ValueError, match="configured database"):
        await dispatch_recovery.reconcile_queued_children()
