"""FastAPI application entry point."""

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from malscan.api.routes import router
from malscan.config import get_settings
from malscan.queue import close_rabbitmq, init_rabbitmq
from malscan.storage import init_buckets

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

settings = get_settings()
log = structlog.get_logger()

# Increase max request body size for file uploads (150MB to allow 100MB files + overhead)
MAX_REQUEST_BODY_SIZE = 150 * 1024 * 1024

app = FastAPI(
    title="MalScan API",
    description="惡意檔案分析 Pipeline API",
    version="0.1.0",
)

# CORS
if settings.cors_origins == "*":
    cors_origins = ["*"]
else:
    cors_origins = [origin.strip() for origin in settings.cors_origins.split(",")]

# Prometheus metrics (add BEFORE CORS so CORS middleware runs first)
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# CORS middleware (added last = runs first in middleware chain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,  # Must be False when allow_origins is ["*"]
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,  # Cache preflight for 10 minutes
)

# Routes
app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/ready")
async def readiness_check() -> dict[str, str]:
    """Readiness check endpoint."""
    # TODO: 檢查資料庫連線、MinIO、RabbitMQ
    return {"status": "ready"}


async def _ensure_schema_compatibility(conn: AsyncConnection) -> None:
    has_artifact_id = (
        await conn.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'jobs'
                  AND column_name = 'artifact_id'
                """
            )
        )
    ).scalar_one_or_none()

    if not has_artifact_id:
        await conn.execute(text("ALTER TABLE jobs ADD COLUMN artifact_id UUID"))
        log.warning("schema_repair_applied", change="jobs.artifact_id column added")

    has_analysis_attempt_id = (
        await conn.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'jobs'
                  AND column_name = 'analysis_attempt_id'
                """
            )
        )
    ).scalar_one_or_none()
    if not has_analysis_attempt_id:
        await conn.execute(
            text("ALTER TABLE public.jobs ADD COLUMN analysis_attempt_id UUID")
        )
        log.warning(
            "schema_repair_applied", change="jobs.analysis_attempt_id column added"
        )

    has_artifact_fk = (
        await conn.execute(
            text(
                """
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'jobs_artifact_id_fkey'
                  AND conrelid = 'jobs'::regclass
                """
            )
        )
    ).scalar_one_or_none()

    if not has_artifact_fk:
        await conn.execute(
            text(
                """
                ALTER TABLE jobs
                ADD CONSTRAINT jobs_artifact_id_fkey
                FOREIGN KEY (artifact_id)
                REFERENCES artifacts(id)
                ON DELETE SET NULL
                """
            )
        )
        log.warning("schema_repair_applied", change="jobs.artifact_id FK added")

    await conn.execute(
        text("CREATE INDEX IF NOT EXISTS ix_jobs_artifact_id ON jobs (artifact_id)")
    )

    needs_password_attempts_default = (
        await conn.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'jobs'
                  AND column_name = 'password_attempts'
                  AND column_default IS NULL
                """
            )
        )
    ).scalar_one_or_none()

    if needs_password_attempts_default:
        await conn.execute(
            text("ALTER TABLE public.jobs ALTER COLUMN password_attempts SET DEFAULT 0")
        )
        log.warning(
            "schema_repair_applied", change="jobs.password_attempts default set to 0"
        )

    for column_name in ("risk_level", "policy_version"):
        has_column = (
            await conn.execute(
                text(
                    """
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'artifacts'
                      AND column_name = :column_name
                    """
                ),
                {"column_name": column_name},
            )
        ).scalar_one_or_none()

        if not has_column:
            await conn.execute(
                text(f"ALTER TABLE artifacts ADD COLUMN {column_name} VARCHAR(20)")
            )
            log.warning(
                "schema_repair_applied", change=f"artifacts.{column_name} column added"
            )


@app.on_event("startup")
async def startup_event() -> None:
    """Application startup."""
    log.info("application_startup", cors_origins=cors_origins)

    # Initialize RabbitMQ connection
    try:
        await init_rabbitmq()
        log.info("rabbitmq_initialized")
    except Exception as e:
        log.error("rabbitmq_initialization_failed", error=str(e))
        raise

    # Initialize MinIO buckets
    try:
        # Run sync initialization in event loop's executor
        import asyncio

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, init_buckets)
        log.info("minio_buckets_initialized")
    except Exception as e:
        log.error("minio_initialization_failed", error=str(e))
        # Keep app running even if MinIO init fails, it might come back later

    # Auto-create database tables if they don't exist
    from malscan.db.engine import get_engine
    from malscan.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_schema_compatibility(conn)
    log.info("database_tables_ready")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Application shutdown."""
    log.info("application_shutdown")

    # Close RabbitMQ connection
    try:
        await close_rabbitmq()
    except Exception as e:
        log.error("rabbitmq_shutdown_failed", error=str(e))
