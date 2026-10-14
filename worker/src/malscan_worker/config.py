"""Worker configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Worker settings loaded from environment variables."""

    # Optional for the portable runner; queue workers validate these at startup.
    # Never substitute development credentials for missing service configuration.
    database_url: str | None = None

    # MinIO (required - no default to enforce security)
    minio_endpoint: str | None = None
    minio_access_key: str | None = None
    minio_secret_key: str | None = None
    minio_bucket_uploads: str = "uploads"
    minio_bucket_artifacts: str = "artifacts"
    minio_secure: bool = False

    # RabbitMQ (required - no default to enforce security)
    rabbitmq_url: str | None = None
    rabbitmq_queue: str = "malscan.jobs"
    rabbitmq_sandbox_queue: str = "malscan.jobs.sandbox"

    # Stage configuration
    stage_timeout_seconds: int = 300
    stages_total: int = 9

    # Deobfuscation
    deobfuscation_enabled: bool = True
    deobfuscation_max_file_size: int = 10_000_000
    deobfuscation_min_base64_length: int = 8
    deobfuscation_xor_min_decoded_length: int = 8
    deobfuscation_max_candidates: int = 100
    deobfuscation_per_decoder_limit: int = 25
    deobfuscation_confidence_threshold: float = 0.5
    deobfuscation_max_wall_time_seconds: float = 2.0
    deobfuscation_max_candidate_bytes: int = 4096

    # Extraction limits (depth controlled by existing max_job_depth)
    extraction_max_files: int = 100
    extraction_max_bytes: int = 500_000_000  # 500MB total
    extraction_max_single_bytes: int = 100_000_000  # 100MB per file
    extraction_max_ratio: float = 100.0
    extraction_timeout: int = 120  # seconds
    max_job_depth: int = Field(default=3, ge=0)

    # File/byte limits span the root tree; the deadline is per execution attempt.
    root_budget_max_files: int = Field(default=100, gt=0)
    root_budget_max_bytes: int = Field(default=500_000_000, gt=0)
    root_budget_timeout_seconds: int = Field(default=3600, gt=0)

    # YARA
    yara_rules_path: str = "/etc/yara/rules"

    # ClamAV
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_mode: Literal["daemon", "cli"] = "daemon"
    clamav_cli_path: str = "clamscan"
    clamav_database_path: str | None = None
    clamav_max_database_age_seconds: int | None = Field(default=None, ge=1)

    # Sandbox
    sandbox_enabled: bool = False
    sandbox_mock: bool = False
    sandbox_provider: str = "capev2"
    sandbox_base_url: str = ""
    sandbox_api_token: str | None = None
    sandbox_timeout_seconds: int = 900
    sandbox_poll_interval_seconds: int = 10
    sandbox_enable_url_submission: bool = False

    # Metrics
    metrics_port: int = 9090

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    def require_service_configuration(self) -> None:
        """Fail before starting a queue worker when required services are missing."""
        required = (
            "database_url",
            "minio_endpoint",
            "minio_access_key",
            "minio_secret_key",
            "rabbitmq_url",
        )
        missing = [name.upper() for name in required if not getattr(self, name)]
        if missing:
            raise ValueError("Missing queue worker configuration: " + ", ".join(missing))

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
