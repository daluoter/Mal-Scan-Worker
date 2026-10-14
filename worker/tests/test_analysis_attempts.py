"""A replaced delivery cannot overwrite new results, status, or password count."""

import asyncio
import json
from uuid import UUID, uuid4

import pytest
from malscan_worker import db


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


@pytest.fixture
def state(monkeypatch):
    job_id = uuid4()
    artifact_id = uuid4()
    state = {
        "job_id": job_id,
        "artifact_id": artifact_id,
        "attempt_id": None,
        "status": "scanning",
        "password_attempts": 0,
        "queries": [],
        "commits": 0,
        "rollbacks": 0,
    }

    class Session:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, statement, params):
            sql = str(statement)
            state["queries"].append((sql, params))
            if "SET analysis_attempt_id" in sql:
                if params["job_id"] != job_id or state["status"] == "done":
                    return Result(None)
                state["attempt_id"] = params["attempt_id"]
                return Result(job_id)
            if "UPDATE artifacts" in sql:
                if params.get("id") != artifact_id:
                    return Result(None)
                if params.get("active_attempt_id") != state["attempt_id"]:
                    return Result(None)
                if (
                    state["attempt_id"] is not None
                    and params.get("attempt_job_id") != job_id
                ):
                    return Result(None)
                state["artifact_score"] = params["score"]
                return Result(artifact_id)
            if (
                params["job_id"] != job_id
                or params.get("active_attempt_id") != state["attempt_id"]
            ):
                return Result(None)
            if "result = :result" in sql:
                state["result"] = json.loads(params["result"])
            if "status = :status" in sql:
                state["status"] = params["status"]
            if "stage" in params:
                state["stage"] = params["stage"]
            if "password_attempts = password_attempts + 1" in sql:
                state["password_attempts"] += 1
                return Result(state["password_attempts"])
            return Result(job_id)

        async def commit(self):
            state["commits"] += 1

        async def rollback(self):
            state["rollbacks"] += 1

    monkeypatch.setattr(db, "AsyncSession", Session)
    return state


@pytest.mark.asyncio
async def test_claim_generates_server_identity_and_restores_context_after_error(state):
    assert db.current_analysis_attempt() is None
    with pytest.raises(RuntimeError, match="test interruption"):
        async with db.job_analysis_attempt(str(state["job_id"])) as attempt_id:
            assert UUID(attempt_id) == state["attempt_id"]
            await db.update_job_result_strict(
                str(state["job_id"]), {"analysis_attempt_id": "forged", "score": 1}
            )
            assert state["result"]["analysis_attempt_id"] == attempt_id
            raise RuntimeError("test interruption")
    assert db.current_analysis_attempt() is None


@pytest.mark.asyncio
async def test_finalized_duplicate_cannot_claim_new_attempt(state):
    state["status"] = "done"
    with pytest.raises(db.StaleAnalysisAttempt):
        async with db.job_analysis_attempt(str(state["job_id"])):
            pytest.fail("Already finalized job must not execute")
    assert state["attempt_id"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["status", "stage", "result", "strict_result", "password", "artifact"]
)
async def test_each_write_is_fenced_when_a_new_delivery_replaces_the_attempt(
    state, kind
):
    job_id = str(state["job_id"])
    async with db.job_analysis_attempt(job_id):
        old_attempt = state["attempt_id"]
        state[
            "attempt_id"
        ] = uuid4()  # A replacement committed ownership after a lost connection.
        with pytest.raises(db.StaleAnalysisAttempt):
            if kind == "status":
                await db.update_job_status(job_id, "done")
            elif kind == "stage":
                await db.update_job_stage(job_id, "sandbox", 9)
            elif kind == "result":
                await db.update_job_result(job_id, {"score": 99})
            elif kind == "strict_result":
                await db.update_job_result_strict(job_id, {"score": 99})
            elif kind == "password":
                await db.increment_password_attempts(job_id)
            else:
                await db.update_artifact_risk(
                    str(state["artifact_id"]), "malicious", 99, "malicious", "test"
                )
        sql, params = state["queries"][-1]
        assert "analysis_attempt_id = :active_attempt_id" in sql
        assert params["active_attempt_id"] == old_attempt
        assert state["status"] == "scanning"
        assert state["password_attempts"] == 0
        assert "result" not in state and "artifact_score" not in state
        assert state["rollbacks"] == 1


@pytest.mark.asyncio
async def test_context_isolated_between_old_and_replacement_tasks(state):
    job_id = str(state["job_id"])
    old_claimed = asyncio.Event()
    replacement_finished = asyncio.Event()
    attempts = []

    async def old_delivery():
        async with db.job_analysis_attempt(job_id) as attempt:
            attempts.append(attempt)
            old_claimed.set()
            await replacement_finished.wait()
            with pytest.raises(db.StaleAnalysisAttempt):
                await db.update_job_result_strict(job_id, {"score": 99})
            with pytest.raises(db.StaleAnalysisAttempt):
                await db.update_job_status(job_id, "done")

    async def replacement():
        await old_claimed.wait()
        async with db.job_analysis_attempt(job_id) as attempt:
            attempts.append(attempt)
            await db.update_job_result_strict(job_id, {"score": 5})
            replacement_finished.set()

    await asyncio.gather(old_delivery(), replacement())
    assert attempts[0] != attempts[1]
    assert state["result"] == {"score": 5, "analysis_attempt_id": attempts[1]}
    assert state["status"] == "scanning"
    assert db.current_analysis_attempt() is None


@pytest.mark.asyncio
async def test_unscoped_writes_reject_jobs_already_claimed_by_worker(state):
    job_id = str(state["job_id"])
    async with db.job_analysis_attempt(job_id):
        pass
    with pytest.raises(db.StaleAnalysisAttempt):
        await db.update_job_status(job_id, "done")
    sql, _ = state["queries"][-1]
    assert "analysis_attempt_id IS NULL" in sql


@pytest.mark.asyncio
async def test_attempt_scope_cannot_write_another_job(state):
    async with db.job_analysis_attempt(str(state["job_id"])):
        with pytest.raises(db.StaleAnalysisAttempt):
            await db.update_job_status(str(uuid4()), "done")
