"""Partial reports and password retries preserve real artifact identity."""

import json
import uuid
from datetime import datetime, timezone

import pytest
from malscan.models import File, Job
from malscan.models.artifact import Artifact
from malscan.models.budget import AnalysisBudget


class Result:
    def __init__(self, value):
        self.value = value

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.value

    def scalar(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


def file_record(name, hash_char):
    return File(
        id=uuid.uuid4(),
        filename=name,
        sha256=hash_char * 64,
        size=10,
        content_type="application/octet-stream",
    )


def report(job, *, sandbox_status="disabled"):
    return {
        "job_id": str(job.id),
        "file": {
            "file_id": str(job.file_id),
            "sha256": job.file.sha256,
            "mime": "application/octet-stream",
            "size": 10,
            "original_filename": job.file.filename,
        },
        "score": 0,
        "verdict": "clean",
        "results": {
            "av_result": {"engine": "clamav", "infected": False, "threat_name": None},
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": job.file.sha256},
            },
            "sandbox": {"executed": False, "is_mock": False, "status": sandbox_status},
        },
        "timings": {
            "total_ms": 2,
            "stages": [
                {
                    "name": "clamav",
                    "status": "ok",
                    "duration_ms": 2,
                    "tool_version": "test-version",
                }
            ],
        },
    }


def job_record(file, status, parent=None):
    now = datetime.now(timezone.utc)
    return Job(
        id=uuid.uuid4(),
        file_id=file.id,
        file=file,
        status=status,
        parent_job_id=parent.id if parent else None,
        depth=parent.depth + 1 if parent else 0,
        sub_jobs=[],
        password_attempts=1,
        created_at=now,
        updated_at=now,
    )


def artifact_record(job, root_job, parent=None):
    artifact = Artifact(
        id=uuid.uuid4(),
        job_id=job.id,
        job=job,
        root_job_id=root_job.id,
        parent_id=parent.id if parent else None,
        root_id=parent.root_id if parent else None,
        depth=job.depth,
        original_filename=job.file.filename,
        sha256=job.file.sha256,
        size=10,
        verdict="clean" if job.status == "done" else None,
        score=0 if job.status == "done" else None,
        mime="application/octet-stream",
        origin_path=job.file.filename if parent else None,
    )
    if parent is None:
        artifact.root_id = artifact.id
    return artifact


@pytest.mark.parametrize("status", ["scanning", "password_required", "failed"])
def test_existing_partial_report_is_readable_and_password_values_are_redacted(
    client, mock_db_session, status
):
    job = job_record(file_record("secret.zip", "a"), status)
    job.result = report(job)
    job.result["results"]["format_analysis"] = {
        "raw": {"archive_password": "private-value", "password_required": True}
    }
    mock_db_session.execute.side_effect = [Result(job), Result(0), Result([])]
    response = client.get(f"/api/v1/reports/{job.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["job_status"] == status
    assert data["report_complete"] is (status == "failed")
    assert (
        data["analysis"]["static"]["status"]
        == {
            "scanning": "complete",
            "password_required": "password_required",
            "failed": "partial",
        }[status]
    )
    assert "private-value" not in json.dumps(data)
    assert data["results"]["format_analysis"]["raw"]["password_required"] is True
    assert job.result["results"]["format_analysis"]["raw"]["archive_password"] == "private-value"


def test_dynamic_pending_does_not_hide_completed_static_report(client, mock_db_session):
    job = job_record(file_record("sample.exe", "a"), "scanning")
    job.result = report(job, sandbox_status="deferred")
    mock_db_session.execute.side_effect = [Result(job), Result(0), Result([])]
    data = client.get(f"/api/v1/reports/{job.id}").json()
    assert data["analysis"]["static"]["status"] == "complete"
    assert data["analysis"]["dynamic"]["status"] == "queued"
    assert data["report_complete"] is False
    assert data["results"]["sandbox"]["status"] == "deferred"


def test_artifact_states_and_coverage_come_from_each_linked_job(client, mock_db_session):
    root = job_record(file_record("outer.zip", "a"), "done")
    child = job_record(file_record("inner.zip", "b"), "password_required", root)
    root.sub_jobs = [child]
    root.result = report(root)
    root_artifact = artifact_record(root, root)
    child_artifact = artifact_record(child, root, root_artifact)
    orphan = Artifact(
        id=uuid.uuid4(),
        parent_id=root_artifact.id,
        root_id=root_artifact.id,
        root_job_id=root.id,
        job_id=None,
        sha256="c" * 64,
        size=1,
        original_filename="unassigned.bin",
        depth=1,
    )
    mock_db_session.execute.side_effect = [
        Result(root),
        Result(1),
        Result([root_artifact, child_artifact, orphan]),
    ]
    response = client.get(f"/api/v1/reports/{root.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["report_complete"] is False
    assert data["pending_descendants"] == 1
    assert data["analysis"]["static"]["status"] == "password_required"
    nodes = {item["artifact_id"]: item for item in data["explainability"]["artifacts"]}
    assert nodes[str(root_artifact.id)]["analysis"]["stage_coverage"][0]["stage"] == "clamav"
    assert nodes[str(child_artifact.id)]["job_status"] == "password_required"
    assert nodes[str(child_artifact.id)]["analysis_status"] == "password_required"
    assert nodes[str(orphan.id)]["analysis_status"] == "unknown"
    assert data["child_jobs"][0]["password_attempts_remaining"] == 2
    assert data["score"] == 0


def test_nested_password_retry_recovers_lineage_from_database(
    client, mock_db_session, mock_rabbitmq
):
    root = job_record(file_record("outer.zip", "a"), "done")
    parent = job_record(file_record("middle.zip", "b"), "done", root)
    child = job_record(file_record("inner.zip", "c"), "password_required", parent)
    root_artifact = artifact_record(root, root)
    parent_artifact = artifact_record(parent, root, root_artifact)
    child_artifact = artifact_record(child, root, parent_artifact)
    child_artifact.original_filename = "member-path/inner.zip"
    mock_db_session.execute.side_effect = [
        Result(child),
        Result(child.file),
        Result(parent),
        Result(root),
        Result(child_artifact),
        Result(parent_artifact),
        Result(root_artifact),
    ]
    response = client.post(
        f"/api/v1/jobs/{child.id}/password",
        json={
            "password": "new-inner-password",
            "root_job_id": str(uuid.uuid4()),
            "artifact_id": str(uuid.uuid4()),
            "ancestor_hashes": ["forged"],
        },
    )
    assert response.status_code == 200
    message = mock_rabbitmq.await_args.args[0]
    assert message["job_id"] == str(child.id)
    assert message["root_job_id"] == str(root.id)
    assert message["artifact_id"] == str(child_artifact.id)
    assert message["root_artifact_id"] == str(root_artifact.id)
    assert message["ancestor_hashes"] == ["a" * 64, "b" * 64]
    assert message["original_filename"] == "member-path/inner.zip"
    assert message["archive_password"] == "new-inner-password"
    assert "new-inner-password" not in response.text
    assert child.status == "queued"
    assert parent.status == root.status == "done"


def test_inconsistent_artifact_lineage_blocks_retry(client, mock_db_session, mock_rabbitmq):
    child = job_record(file_record("inner.zip", "c"), "password_required")
    artifact = artifact_record(child, child)
    artifact.root_job_id = uuid.uuid4()
    mock_db_session.execute.side_effect = [
        Result(child),
        Result(child.file),
        Result(artifact),
    ]
    response = client.post(f"/api/v1/jobs/{child.id}/password", json={"password": "private"})
    assert response.status_code == 409
    mock_rabbitmq.assert_not_awaited()


def test_execution_budget_exposes_only_public_accounting_fields(client, mock_db_session):
    job = job_record(file_record("outer.zip", "a"), "done")
    job.result = report(job)
    job.result["execution_budget"] = {
        "limits": {"max_files": 10, "max_bytes": 100, "timeout_seconds": 30},
        "used_files": 2,
        "used_bytes": 70,
        "deadline_at": "2026-10-13T01:00:00Z",
        "time_scope": "analysis_attempt",
        "accounting_scope": "root_artifact_tree",
        "reservations": {"internal-key": {"files": 2, "bytes": 70}},
        "billing": "not-a-billing-estimate",
        "password": "private",
    }
    mock_db_session.execute.side_effect = [Result(job), Result(0), Result([]), Result(None)]
    response = client.get(f"/api/v1/reports/{job.id}")
    assert response.status_code == 200
    budget = response.json()["execution_budget"]
    assert budget["used_files"] == 2 and budget["used_bytes"] == 70
    assert budget["limits"] == {
        "max_files": 10,
        "max_bytes": 100,
        "timeout_seconds": 30,
    }
    assert budget["time_scope"] == "analysis_attempt"
    assert "reservations" not in budget and "billing" not in budget and "password" not in budget


def test_report_refreshes_durable_root_accounting_without_renewing_attempt_deadline(
    client, mock_db_session
):
    job = job_record(file_record("outer.zip", "a"), "done")
    job.result = report(job)
    original_deadline = "2026-10-13T01:00:00Z"
    job.result["execution_budget"] = {
        "limits": {"max_files": 10, "max_bytes": 1000, "timeout_seconds": 30},
        "used_files": 1,
        "used_bytes": 234,
        "deadline_at": original_deadline,
        "time_scope": "analysis_attempt",
        "accounting_scope": "root_artifact_tree",
    }
    durable = AnalysisBudget(
        root_job_id=job.id,
        max_files=20,
        max_bytes=2000,
        timeout_seconds=60,
        used_files=2,
        used_bytes=304,
    )
    mock_db_session.execute.side_effect = [Result(job), Result(0), Result([]), Result(durable)]
    response = client.get(f"/api/v1/reports/{job.id}")
    assert response.status_code == 200
    budget = response.json()["execution_budget"]
    assert budget["used_files"] == 2 and budget["used_bytes"] == 304
    assert budget["limits"] == {"max_files": 20, "max_bytes": 2000, "timeout_seconds": 60}
    assert budget["deadline_at"] == original_deadline
    assert budget["deadline_active"] is False
    assert budget["accounting_source"] == "durable_root_budget"
    assert job.result["execution_budget"]["used_files"] == 1


def test_report_preserves_all_cape_task_identities_for_operator_reconciliation(
    client, mock_db_session
):
    job = job_record(file_record("sample.exe", "a"), "done")
    job.result = report(job)
    job.result["results"]["sandbox"].update(
        status="unavailable",
        task_ids=["42", "43"],
        error_code="provider_multiple_tasks",
        reconcile_required=True,
    )
    mock_db_session.execute.side_effect = [Result(job), Result(0), Result([])]
    response = client.get(f"/api/v1/reports/{job.id}")
    assert response.status_code == 200
    sandbox = response.json()["results"]["sandbox"]
    assert sandbox["task_ids"] == ["42", "43"]
    assert sandbox["reconcile_required"] is True
    assert sandbox["error_code"] == "provider_multiple_tasks"
    assert response.json()["analysis"]["dynamic"]["status"] == "unavailable"
