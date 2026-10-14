"""Opt-in migration 007 DDL roundtrip in an isolated PostgreSQL schema."""

import importlib.util
import os
from pathlib import Path
from uuid import uuid4

import pytest
from malscan.db.engine import get_engine
from sqlalchemy import text

from alembic.migration import MigrationContext
from alembic.operations import Operations

pytestmark = pytest.mark.skipif(
    os.environ.get("MALSCAN_TEST_POSTGRES") != "1", reason="Opt-in development PostgreSQL test"
)


@pytest.mark.asyncio
async def test_attempt_migration_preserves_existing_job_and_roundtrips():
    migration_path = Path(__file__).parents[1] / "alembic/versions/007_add_job_analysis_attempt.py"
    spec = importlib.util.spec_from_file_location("attempt_migration", migration_path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    schema = "attempt_migration_" + uuid4().hex
    job_id = uuid4()

    def roundtrip(conn):
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
        conn.execute(text("CREATE TABLE jobs (id UUID PRIMARY KEY, status TEXT NOT NULL)"))
        conn.execute(text("INSERT INTO jobs (id, status) VALUES (:id, 'done')"), {"id": job_id})
        migration.op = Operations(MigrationContext.configure(conn))
        migration.upgrade()
        record = conn.execute(text("SELECT id, status, analysis_attempt_id FROM jobs")).one()
        assert record == (job_id, "done", None)
        column = conn.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = 'jobs' "
                "AND column_name = 'analysis_attempt_id'"
            ),
            {"schema": schema},
        ).one()
        assert column == ("uuid", "YES")
        migration.downgrade()
        assert conn.execute(text("SELECT id, status FROM jobs")).one() == (job_id, "done")
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))

    async with get_engine().begin() as connection:
        await connection.run_sync(roundtrip)
