"""Tests for startup repairs of legacy database schemas."""

import pytest
from malscan.main import _ensure_schema_compatibility


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Connection:
    def __init__(self, password_attempts_needs_default, analysis_attempt_present=True):
        self.password_attempts_needs_default = password_attempts_needs_default
        self.analysis_attempt_present = analysis_attempt_present
        self.statements = []

    async def execute(self, statement, parameters=None):
        sql = str(statement)
        self.statements.append(sql)

        if "column_name = 'password_attempts'" in sql:
            return _Result(1 if self.password_attempts_needs_default else None)
        if "column_name = 'analysis_attempt_id'" in sql:
            return _Result(1 if self.analysis_attempt_present else None)
        if "column_name = :column_name" in sql:
            return _Result(1)
        if sql.lstrip().startswith("SELECT"):
            return _Result(1)
        return _Result(None)


@pytest.mark.asyncio
async def test_startup_sets_default_for_legacy_password_attempts_column():
    connection = _Connection(password_attempts_needs_default=True)

    await _ensure_schema_compatibility(connection)

    assert any(
        "ALTER TABLE public.jobs ALTER COLUMN password_attempts SET DEFAULT 0"
        in statement
        for statement in connection.statements
    )
    password_attempts_check = next(
        statement
        for statement in connection.statements
        if "column_name = 'password_attempts'" in statement
    )
    assert "table_schema = 'public'" in password_attempts_check
    assert "column_default IS NULL" in password_attempts_check
    assert not any("UPDATE jobs" in statement for statement in connection.statements)


@pytest.mark.asyncio
async def test_startup_does_not_alter_password_attempts_default_when_already_set():
    connection = _Connection(password_attempts_needs_default=False)

    await _ensure_schema_compatibility(connection)

    assert not any(
        "ALTER TABLE public.jobs ALTER COLUMN password_attempts SET DEFAULT 0"
        in statement
        for statement in connection.statements
    )


@pytest.mark.asyncio
async def test_startup_adds_nullable_attempt_identity_without_rewriting_existing_results():
    connection = _Connection(False, analysis_attempt_present=False)

    await _ensure_schema_compatibility(connection)

    assert (
        "ALTER TABLE public.jobs ADD COLUMN analysis_attempt_id UUID"
        in connection.statements
    )
    assert not any("UPDATE jobs" in statement for statement in connection.statements)


@pytest.mark.asyncio
async def test_startup_keeps_existing_attempt_column():
    connection = _Connection(False)

    await _ensure_schema_compatibility(connection)

    assert not any(
        "ADD COLUMN analysis_attempt_id" in statement
        for statement in connection.statements
    )
