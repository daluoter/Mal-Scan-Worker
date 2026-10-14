"""IOC extraction stage using regex patterns."""

import hashlib
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malscan_worker.budget import BudgetExceeded, reservation_key
from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

# IOC patterns
URL_PATTERN = re.compile(
    rb'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+[^\s\x00-\x1f"\'<>]*',
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    rb"(?<![a-zA-Z0-9.-])(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9.-])",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

_COMMON_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "google.com",
    "example.com",
    "localhost",
    "w3.org",
}


def _is_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first = int(parts[0])
    second = int(parts[1])
    if first == 10:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first == 127:
        return False
    if first == 0 or first >= 224:
        return False
    return True


def extract_raw_iocs(
    content: bytes,
    *,
    max_urls: int = 100,
    max_domains: int = 100,
    max_ips: int = 50,
) -> dict[str, list[str]]:
    urls = list({match.decode("utf-8", errors="ignore") for match in URL_PATTERN.findall(content)})[
        :max_urls
    ]

    url_domains = set()
    for url in urls:
        parts = url.split("/")
        if len(parts) >= 3:
            url_domains.add(parts[2].lower())

    domains = list(
        {
            match.decode("utf-8", errors="ignore").lower()
            for match in DOMAIN_PATTERN.findall(content)
            if match.decode("utf-8", errors="ignore").lower() not in url_domains
        }
    )[:max_domains]
    domains = [d for d in domains if d not in _COMMON_DOMAINS]
    domains = [d for d in domains if len(d) >= 4 and "." in d[1:-1]]

    ips = list({match.decode("utf-8", errors="ignore") for match in IP_PATTERN.findall(content)})[
        :max_ips
    ]
    ips = [ip for ip in ips if _is_public_ip(ip)]

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
    }


def extract_raw_ioc_items(
    content: bytes,
    *,
    artifact_ref: str,
    max_urls: int = 100,
    max_domains: int = 100,
    max_ips: int = 50,
) -> list[dict[str, str | int | None]]:
    """Return structured IOC records with stable IDs and offsets."""

    items: list[dict[str, str | int | None]] = []
    seen: set[tuple[str, str]] = set()

    for index, match in enumerate(URL_PATTERN.finditer(content)):
        if index >= max_urls:
            break
        value = match.group().decode("utf-8", errors="ignore")
        key = ("url", value)
        if key in seen:
            continue
        seen.add(key)
        url_index = len([item for item in items if item["type"] == "url"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::url::{url_index}",
                "type": "url",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    url_domains = {
        item["value"].split("/")[2].lower()
        for item in items
        if item["type"] == "url" and isinstance(item["value"], str) and "/" in item["value"]
    }

    for match in DOMAIN_PATTERN.finditer(content):
        if len([item for item in items if item["type"] == "domain"]) >= max_domains:
            break
        value = match.group().decode("utf-8", errors="ignore").lower()
        if (
            value in _COMMON_DOMAINS
            or value in url_domains
            or len(value) < 4
            or "." not in value[1:-1]
        ):
            continue
        key = ("domain", value)
        if key in seen:
            continue
        seen.add(key)
        domain_index = len([item for item in items if item["type"] == "domain"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::domain::{domain_index}",
                "type": "domain",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    for match in IP_PATTERN.finditer(content):
        if len([item for item in items if item["type"] == "ip"]) >= max_ips:
            break
        value = match.group().decode("utf-8", errors="ignore")
        if not _is_public_ip(value):
            continue
        key = ("ip", value)
        if key in seen:
            continue
        seen.add(key)
        ip_index = len([item for item in items if item["type"] == "ip"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::ip::{ip_index}",
                "type": "ip",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    return items


class IocExtractStage(Stage):
    """Extract IOCs (URLs, domains, IPs, hashes) from file."""

    @property
    def name(self) -> str:
        return "ioc-extract"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            # Read file content
            content = ctx.file_path.read_bytes()

            extracted_iocs = extract_raw_iocs(content)
            urls = extracted_iocs["urls"]
            domains = extracted_iocs["domains"]
            ips = extracted_iocs["ips"]
            artifact_ref = ctx.artifact_id or ctx.root_artifact_id or ctx.job_id
            ioc_items = extract_raw_ioc_items(content, artifact_ref=artifact_ref)

            # Calculate file hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

            findings: dict[str, Any] = {
                "urls": urls,
                "domains": domains,
                "ips": ips,
                "hashes": {"md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash},
                "ioc_items": ioc_items,
                "sub_jobs_created": 0,
            }
            artifact_ids: list[str] = []
            submission_errors: list[str] = []
            settings = get_settings()
            enabled = bool(settings.sandbox_enable_url_submission)
            findings["url_artifact_submission"] = {
                "enabled": enabled,
                "status": "disabled" if not enabled else "complete",
                "reason": None if enabled else "sandbox_enable_url_submission_disabled",
                "skipped_cycles": 0,
                "max_artifacts": 50,
                "omitted_urls": max(0, len(urls) - 50) if enabled else 0,
            }
            if enabled and urls:
                if ctx.root_budget is None:
                    submission_errors.append("root_budget_unavailable")
                elif not ctx.analysis_services and not ctx.job:
                    submission_errors.append("artifact_submission_unavailable")
                else:
                    depth = ctx.job.depth if ctx.job else ctx.depth
                    max_depth = getattr(ctx.analysis_services, "max_depth", settings.max_job_depth)
                    if depth >= max_depth:
                        submission_errors.append("max_depth")
                    else:
                        artifact_ids, created, skipped, submission_errors = await self._submit_urls(
                            ctx,
                            sorted(urls)[:50],
                            depth,
                        )
                        findings["sub_jobs_created"] = created
                        findings["url_artifact_submission"]["skipped_cycles"] = skipped
            if enabled and len(urls) > 50:
                submission_errors.append("url_artifact_count_limit")
            if submission_errors:
                findings["url_artifact_submission"]["status"] = "partial"
                findings["url_artifact_submission"]["errors"] = submission_errors
                findings["reason"] = submission_errors[0]

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="partial" if submission_errors else "ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings=findings,
                artifacts=artifact_ids,
                error=None,
            )

        except Exception as e:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={},
                artifacts=[],
                error=str(e),
            )

    async def _submit_urls(
        self,
        ctx: StageContext,
        urls: list[str],
        depth: int,
    ) -> tuple[list[str], int, int, list[str]]:
        """Optional synthetic shortcuts; observations never require this extension.

        This writes text only. It never fetches or executes an extracted URL.
        Budget is reserved before creating/writing a temporary file. Stable URL
        identity and artifact ordinal make retries idempotent. A shortcut's IOC
        cannot recursively generate an identical shortcut or an ancestor.
        """
        artifact_ids: list[str] = []
        created = 0
        skipped_cycles = 0
        errors: list[str] = []
        submitter: InternalJobSubmitter | None = None
        assert ctx.root_budget is not None
        root_job_id = ctx.root_job_id or ctx.job_id
        ancestors = ctx.ancestor_hashes | {ctx.sha256}
        for url in urls:
            payload = f"[InternetShortcut]\nURL={url}\n".encode()
            sha256_hash = hashlib.sha256(payload).hexdigest()
            if sha256_hash in ancestors:
                skipped_cycles += 1
                continue
            identity = hashlib.sha256(url.encode()).hexdigest()
            origin = f"ioc-url:{identity}"
            filename = f"url_{identity[:16]}.url"
            temporary_path: str | None = None
            try:
                await ctx.root_budget.reserve(
                    reservation_key(ctx.job_id, "ioc-extract", origin),
                    1,
                    len(payload),
                )
                descriptor, temporary_path = tempfile.mkstemp(suffix=".url")
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                if ctx.analysis_services:
                    child = await ctx.analysis_services.submit_child(
                        file_path=temporary_path,
                        filename=filename,
                        content_type="application/internet-shortcut",
                        sha256_hash=sha256_hash,
                        file_size=len(payload),
                        parent_job_id=ctx.job_id,
                        parent_job_depth=depth,
                        root_artifact_id=ctx.root_artifact_id,
                        root_job_id=root_job_id,
                        ancestor_hashes=ancestors,
                        origin_path=origin,
                        extraction_source="ioc-extract",
                        archive_type=None,
                        occurrence_index=0,
                    )
                    if child:
                        artifact_ids.append(str(child))
                        created += 1
                    continue
                if not ctx.root_artifact_id:
                    root = await create_artifact(
                        parent_id=None,
                        root_id=None,
                        depth=0,
                        sha256=ctx.sha256,
                        size=Path(ctx.file_path).stat().st_size if ctx.file_path else 0,
                        original_filename=ctx.original_filename,
                        extraction_source="upload",
                        root_job_id=root_job_id,
                        job_id=ctx.job_id,
                    )
                    ctx.root_artifact_id = root["id"]
                    ctx.artifact_id = root["id"]
                record = await create_artifact(
                    parent_id=ctx.artifact_id or ctx.root_artifact_id,
                    root_id=ctx.root_artifact_id,
                    depth=depth + 1,
                    sha256=sha256_hash,
                    size=len(payload),
                    original_filename=filename,
                    origin_path=origin,
                    extraction_source="ioc-extract",
                    root_job_id=root_job_id,
                    occurrence_index=0,
                )
                artifact_ids.append(record["id"])
                if submitter is None:
                    submitter = await InternalJobSubmitter.get_instance()
                child = await submitter.submit_subjob(
                    file_path=temporary_path,
                    filename=filename,
                    content_type="application/internet-shortcut",
                    sha256_hash=sha256_hash,
                    file_size=len(payload),
                    parent_job_id=ctx.job_id,
                    parent_job_depth=depth,
                    artifact_id=record["id"],
                    root_artifact_id=ctx.root_artifact_id,
                    root_job_id=root_job_id,
                    ancestor_hashes=ancestors,
                )
                if child:
                    created += 1
            except BudgetExceeded as exc:
                errors.append(exc.reason)
                break
            except Exception as exc:
                errors.append(f"url_artifact_submission_failed:{type(exc).__name__}")
                break
            finally:
                if temporary_path is not None:
                    Path(temporary_path).unlink(missing_ok=True)
        return artifact_ids, created, skipped_cycles, errors
