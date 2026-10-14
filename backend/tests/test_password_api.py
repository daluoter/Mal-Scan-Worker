"""Tests for password submission API and related job status payloads."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient
from malscan.models import JobStatus


def test_submit_password_success(
    client: TestClient,
    mock_db_session: AsyncMock,
    mock_rabbitmq,
):
    """Submitting a password queues the job and republishes with password metadata."""
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()

    mock_file = MagicMock()
    mock_file.id = file_id
    mock_file.sha256 = "abc123"
    mock_file.filename = "secret.zip"

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.file_id = file_id
    mock_job.file = mock_file
    mock_job.status = JobStatus.PASSWORD_REQUIRED.value
    mock_job.password_attempts = 1
    mock_job.parent_job_id = None
    mock_job.current_stage = "archive_extract"
    mock_job.error_message = "Password required"

    job_result = MagicMock()
    job_result.scalar_one_or_none.return_value = mock_job
    file_result = MagicMock()
    file_result.scalar_one_or_none.return_value = mock_file
    artifact_result = MagicMock()
    artifact_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.side_effect = [job_result, file_result, artifact_result]
    mock_db_session.commit = AsyncMock()

    response = client.post(
        f"/api/v1/jobs/{job_id}/password",
        json={"password": "s3cr3t"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "job_id": str(job_id),
        "status": "queued",
        "message": "Password accepted. Job requeued for analysis.",
        "attempts_used": 1,
        "attempts_remaining": 2,
    }

    assert mock_job.status == JobStatus.QUEUED.value
    assert mock_job.current_stage is None
    assert mock_job.error_message is None
    mock_db_session.commit.assert_awaited_once()

    mock_rabbitmq.assert_awaited_once()
    published = mock_rabbitmq.await_args.args[0]
    assert published["job_id"] == str(job_id)
    assert published["file_id"] == str(file_id)
    assert published["storage_key"] == "abc123"
    assert published["sha256"] == "abc123"
    assert published["original_filename"] == "secret.zip"
    assert published["archive_password"] == "s3cr3t"
    assert published["root_job_id"] == str(job_id)
    assert published["ancestor_hashes"] == []

    submitted_stmt = mock_db_session.execute.await_args_list[0].args[0]
    assert getattr(submitted_stmt, "_for_update_arg", None) is not None


def test_submit_password_invalid_status_returns_409(
    client: TestClient,
    mock_db_session: AsyncMock,
):
    """Submitting password when job is not password_required returns conflict."""
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = JobStatus.SCANNING.value
    mock_job.password_attempts = 0

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.post(f"/api/v1/jobs/{job_id}/password", json={"password": "secret"})

    assert response.status_code == 409


def test_submit_password_not_found_returns_404(
    client: TestClient,
    mock_db_session: AsyncMock,
):
    """Submitting password for unknown job returns not found."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    response = client.post(
        f"/api/v1/jobs/{uuid.uuid4()}/password",
        json={"password": "secret"},
    )

    assert response.status_code == 404


def test_submit_password_invalid_payload_returns_422(client: TestClient):
    """Payload validation rejects empty passwords."""
    response = client.post(
        f"/api/v1/jobs/{uuid.uuid4()}/password",
        json={"password": ""},
    )

    assert response.status_code == 422


def test_submit_password_attempts_exhausted_returns_409(
    client: TestClient,
    mock_db_session: AsyncMock,
    mock_rabbitmq,
):
    """Submitting password after max attempts are used returns conflict."""
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = JobStatus.PASSWORD_REQUIRED.value
    mock_job.password_attempts = 3

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.post(f"/api/v1/jobs/{job_id}/password", json={"password": "secret"})

    assert response.status_code == 409
    mock_rabbitmq.assert_not_awaited()


def test_submit_password_publish_failure_returns_503_and_does_not_commit(
    client: TestClient,
    mock_db_session: AsyncMock,
    mock_rabbitmq,
):
    """Queue publish failures should not commit queued transition."""
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()

    mock_file = MagicMock()
    mock_file.id = file_id
    mock_file.sha256 = "abc123"
    mock_file.filename = "secret.zip"

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.file_id = file_id
    mock_job.file = mock_file
    mock_job.status = JobStatus.PASSWORD_REQUIRED.value
    mock_job.password_attempts = 1
    mock_job.parent_job_id = None
    mock_job.current_stage = "archive_extract"
    mock_job.error_message = "Password required"

    job_result = MagicMock()
    job_result.scalar_one_or_none.return_value = mock_job
    file_result = MagicMock()
    file_result.scalar_one_or_none.return_value = mock_file
    artifact_result = MagicMock()
    artifact_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.side_effect = [job_result, file_result, artifact_result]
    mock_db_session.commit = AsyncMock()

    mock_rabbitmq.side_effect = RuntimeError("broker down")

    response = client.post(f"/api/v1/jobs/{job_id}/password", json={"password": "secret"})

    assert response.status_code == 503
    assert response.json()["detail"] == "Failed to submit password retry job"
    mock_db_session.commit.assert_not_awaited()
    assert mock_job.status == JobStatus.PASSWORD_REQUIRED.value
    assert mock_job.current_stage == "archive_extract"
    assert mock_job.error_message == "Password required"


def test_get_job_status_includes_password_counters_and_required_status(
    client: TestClient,
    mock_db_session: AsyncMock,
):
    """GET /jobs/{job_id} should reflect password_required with live attempt counters."""
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = JobStatus.PASSWORD_REQUIRED.value
    mock_job.current_stage = None
    mock_job.stages_done = 1
    mock_job.stages_total = 5
    mock_job.error_message = "Archive is password-protected"
    mock_job.parent_job_id = None
    mock_job.depth = 0
    mock_job.total_sub = 0
    mock_job.completed_sub = 0
    mock_job.malicious_sub = 0
    mock_job.password_attempts = 2
    mock_job.updated_at = datetime.now(timezone.utc)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.get(f"/api/v1/jobs/{job_id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "password_required"
    assert payload["password_attempts"] == 2
    assert payload["password_attempts_remaining"] == 1
