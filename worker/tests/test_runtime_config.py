"""Configuration boundaries between portable and queue analysis entry points."""

import pytest
from malscan_worker.config import Settings
from pydantic import ValidationError


def test_portable_configuration_has_no_implicit_service_credentials(monkeypatch):
    for name in (
        "DATABASE_URL",
        "MINIO_ENDPOINT",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
        "RABBITMQ_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)
    assert settings.database_url is None
    assert settings.minio_secret_key is None
    assert settings.rabbitmq_url is None
    with pytest.raises(ValueError, match="DATABASE_URL"):
        settings.require_service_configuration()


def test_queue_worker_missing_configuration_error_exposes_names_only():
    settings = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://user:never-print-this@localhost/db",
        minio_endpoint=None,
        minio_access_key=None,
        minio_secret_key=None,
        rabbitmq_url=None,
    )
    with pytest.raises(ValueError) as error:
        settings.require_service_configuration()
    assert "MINIO_SECRET_KEY" in str(error.value)
    assert "never-print-this" not in str(error.value)


@pytest.mark.parametrize(
    "field", ["root_budget_max_files", "root_budget_max_bytes", "root_budget_timeout_seconds"]
)
def test_root_budget_configuration_rejects_unbounded_zero(field):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: 0})
