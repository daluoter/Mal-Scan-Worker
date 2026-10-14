"""Tests for internal sub-job submission storage behavior."""

import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker.utils.submission import InternalJobSubmitter


class _DummyScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_submit_subjob_reuploads_when_dedup_file_missing_in_storage(monkeypatch):
    """If dedup DB row exists but object is gone, submitter must re-upload."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="a" * 64)

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt):
            return _DummyScalarResult(existing_file)

        def add(self, obj):
            self._adds.append(obj)

        async def flush(self):
            for obj in self._adds:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid.uuid4()

        async def commit(self):
            return None

    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", DummySession)

    upload_mock = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", upload_mock)

    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._storage_object_exists = AsyncMock(return_value=False)
    submitter._exchange = SimpleNamespace(publish=AsyncMock())

    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="a" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
    )

    assert sub_job_id is not None
    upload_mock.assert_awaited_once_with("/tmp/sub.bin", "a" * 64, "application/octet-stream")


@pytest.mark.asyncio
async def test_submit_subjob_updates_artifact_job_id_when_artifact_id_provided(
    monkeypatch,
):
    """Successful sub-job submission should attach the new job id to the artifact row."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="b" * 64)
    artifact_id = str(uuid.uuid4())
    root_artifact_id = str(uuid.uuid4())
    root_job_id = str(uuid.uuid4())
    ancestor_hashes = {"ancestor-a", "ancestor-b"}
    captured_updates = []
    publish_mock = AsyncMock()

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, *args, **kwargs):
            if kwargs:
                captured_updates.append({"stmt": stmt, "args": args, "kwargs": kwargs})
                return None
            return _DummyScalarResult(existing_file)

        def add(self, obj):
            self._adds.append(obj)

        async def flush(self):
            for obj in self._adds:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid.uuid4()

        async def commit(self):
            return None

    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", DummySession)

    upload_mock = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", upload_mock)

    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._storage_object_exists = AsyncMock(return_value=True)
    submitter._exchange = SimpleNamespace(publish=publish_mock)

    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="b" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
        artifact_id=artifact_id,
        root_artifact_id=root_artifact_id,
        root_job_id=root_job_id,
        ancestor_hashes=ancestor_hashes,
    )

    assert sub_job_id is not None
    assert captured_updates
    update_call = captured_updates[0]
    update_params = update_call["args"][0]
    assert update_params["artifact_id"] == uuid.UUID(artifact_id)
    assert update_params["job_id"] == uuid.UUID(sub_job_id)

    publish_mock.assert_awaited_once()
    published_message = publish_mock.await_args.args[0]
    published_payload = json.loads(published_message.body.decode())
    assert published_payload["artifact_id"] == artifact_id
    assert published_payload["root_artifact_id"] == root_artifact_id
    assert published_payload["root_job_id"] == root_job_id
    assert set(published_payload["ancestor_hashes"]) == ancestor_hashes


@pytest.mark.asyncio
async def test_submit_subjob_rolls_back_when_artifact_job_link_update_fails(monkeypatch):
    """A failed durable artifact link must roll back before publishing a child."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="c" * 64)
    artifact_id = str(uuid.uuid4())

    events = []

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            if exc_type is not None:
                events.append("rollback")
            return False

        async def execute(self, stmt, *args, **kwargs):
            if kwargs:
                raise RuntimeError("artifact link failed")
            return _DummyScalarResult(existing_file)

        def add(self, obj):
            self._adds.append(obj)

        async def flush(self):
            for obj in self._adds:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid.uuid4()

        async def commit(self):
            events.append("commit")

    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", DummySession)

    publish_mock = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", AsyncMock())

    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._storage_object_exists = AsyncMock(return_value=True)
    submitter._exchange = SimpleNamespace(publish=publish_mock)

    with pytest.raises(RuntimeError, match="artifact link failed"):
        await submitter.submit_subjob(
            file_path="/tmp/sub.bin",
            filename="sub.bin",
            content_type="application/octet-stream",
            sha256_hash="c" * 64,
            file_size=12,
            parent_job_id=str(uuid.uuid4()),
            parent_job_depth=0,
            artifact_id=artifact_id,
        )

    assert events == ["rollback"]
    publish_mock.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status,publish_count", [("queued", 1), ("done", 0)])
async def test_existing_artifact_child_identity_is_reused(monkeypatch, status, publish_count):
    from unittest.mock import MagicMock

    linked_job = SimpleNamespace(id=uuid.uuid4(), file_id=uuid.uuid4(), status=status)
    artifact_id = str(uuid.uuid4())
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.execute.side_effect = [
        _DummyScalarResult(None),
        _DummyScalarResult(linked_job.id),
        _DummyScalarResult(linked_job),
    ]
    session.add = MagicMock()
    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", lambda *_: session)
    upload = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", upload)
    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter.publish_payload = AsyncMock()
    result = await submitter.submit_subjob(
        file_path="/tmp/file",
        filename="child",
        content_type="application/octet-stream",
        sha256_hash="a" * 64,
        file_size=4,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
        artifact_id=artifact_id,
    )
    assert result == str(linked_job.id)
    session.add.assert_not_called()
    upload.assert_not_awaited()
    assert submitter.publish_payload.await_count == publish_count
    if publish_count:
        assert submitter.publish_payload.await_args.args[0]["job_id"] == str(linked_job.id)


@pytest.mark.asyncio
async def test_submitter_requires_broker_confirmations_and_mandatory_route(monkeypatch):
    connection = AsyncMock()
    channel = AsyncMock()
    channel.default_exchange = AsyncMock()
    connection.is_closed = False
    connection.channel.return_value = channel
    factory = AsyncMock(return_value=connection)
    monkeypatch.setattr("malscan_worker.utils.submission.aio_pika.connect_robust", factory)
    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._connection = None
    await submitter.publish_payload({"job_id": "test-job"})
    connection.channel.assert_awaited_once_with(publisher_confirms=True, on_return_raises=True)
    assert channel.default_exchange.publish.await_args.kwargs["mandatory"] is True
    channel.default_exchange.publish.side_effect = RuntimeError("broker rejected delivery")
    with pytest.raises(RuntimeError, match="broker rejected"):
        await submitter.publish_payload({"job_id": "test-job"})
