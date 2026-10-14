"""RAR format handler."""

from __future__ import annotations

import os
from pathlib import Path

import structlog

try:
    import rarfile
except ImportError:  # pragma: no cover - optional dependency fallback
    rarfile = None

from malscan_worker.budget import BudgetExceeded
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
)
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    check_stream_size,
    reserve_output,
    safe_extract_path,
)

logger = structlog.get_logger(__name__)

RAR_MAGIC = b"Rar!\x1a\x07"


class RarHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "rar"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:7] == RAR_MAGIC:
            return True
        if mime in ("application/x-rar-compressed", "application/vnd.rar"):
            return True
        if file_path.suffix.lower() == ".rar":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        if rarfile is None:
            raise RuntimeError("rarfile not available")

        files: list[ExtractedFile] = []
        warnings: list[str] = []

        with rarfile.RarFile(file_path) as archive:
            members = [item for item in archive.infolist() if getattr(item, "filename", None)]
            password_protected = bool(archive.needs_password())

            reason = _preflight_reason(
                archive_size=file_path.stat().st_size,
                member_count=len(members),
                member_sizes=[int(getattr(item, "file_size", 0) or 0) for item in members],
                limits=limits,
            )
            if reason is not None:
                return ExtractionResult(
                    files=[],
                    malicious="Expansion ratio" in reason,
                    reason=reason,
                    resource_limited="Expansion ratio" not in reason,
                    limit_reason="extraction_limit" if "Expansion ratio" not in reason else None,
                    archive_type="rar",
                    password_protected=password_protected,
                )

            total_extracted_bytes = 0
            for member_index, member in enumerate(members):
                member_name = str(member.filename)

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached")
                    break

                target = safe_extract_path(str(extract_dir), member_name)
                if target is None:
                    warnings.append(f"Path traversal skipped: {member_name}")
                    continue

                member_size = int(getattr(member, "file_size", 0) or 0)
                target = safe_extract_path(str(extract_dir / str(member_index)), member_name)
                if target is None:
                    continue

                if member_size > limits.max_single_file_bytes:
                    warnings.append(f"File too large, skipped: {member_name} ({member_size} bytes)")
                    continue

                if total_extracted_bytes + member_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached")
                    break

                origin = f"{member_index}:{member_name}"
                try:
                    reserve_output(limits, origin, member_size)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with archive.open(member, pwd=password) as source, open(target, "wb") as handle:
                        written = 0
                        while True:
                            chunk = source.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            reason = _stream_limit_reason(
                                archive_size=file_path.stat().st_size,
                                current_total_extracted_bytes=total_extracted_bytes,
                                current_file_written=written,
                                limits=limits,
                            )
                            if reason is not None:
                                os.remove(target)
                                return ExtractionResult(
                                    files=files,
                                    malicious=True,
                                    reason=reason,
                                    archive_type="rar",
                                    password_protected=password_protected,
                                )
                            check_stream_size(
                                limits,
                                written=written,
                                total=total_extracted_bytes,
                                archive_size=file_path.stat().st_size,
                            )
                            reserve_output(limits, origin, written)
                            handle.write(chunk)
                except BudgetExceeded as exc:
                    if os.path.exists(target):
                        os.remove(target)
                    return ExtractionResult(
                        files=files,
                        warnings=[*warnings, exc.reason],
                        archive_type="rar",
                        password_protected=password_protected,
                        resource_limited=True,
                        limit_reason=exc.reason,
                    )
                except Exception as exc:
                    if _is_password_required_error(exc):
                        raise ArchivePasswordRequiredError("rar") from exc
                    if _is_wrong_password_error(exc):
                        raise ArchiveWrongPasswordError("rar") from exc
                    raise

                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(member_name),
                        size=written,
                        origin_path=member_name,
                        occurrence_index=member_index,
                    )
                )

        return ExtractionResult(
            files=files,
            warnings=warnings,
            archive_type="rar",
            password_protected=password_protected,
        )


def _preflight_reason(
    *,
    archive_size: int,
    member_count: int,
    member_sizes: list[int],
    limits: ExtractionLimits,
) -> str | None:
    if member_count > limits.max_files:
        return "Max files limit exceeded before extraction"

    if any(size > limits.max_single_file_bytes for size in member_sizes):
        return "Single file size limit exceeded before extraction"

    total_uncompressed = sum(member_sizes)
    if total_uncompressed > limits.max_extracted_bytes:
        return "Max total extracted bytes exceeded before extraction"

    if check_expansion_ratio(archive_size, total_uncompressed, limits) is not None:
        return "Expansion ratio exceeded before extraction"

    return None


def _is_password_required_error(exc: Exception) -> bool:
    if rarfile is not None and isinstance(exc, getattr(rarfile, "PasswordRequired", ())):
        return True
    return "password required" in str(exc).lower()


def _is_wrong_password_error(exc: Exception) -> bool:
    if rarfile is not None and isinstance(exc, getattr(rarfile, "RarWrongPassword", ())):
        return True
    return "wrong password" in str(exc).lower()


def _stream_limit_reason(
    *,
    archive_size: int,
    current_total_extracted_bytes: int,
    current_file_written: int,
    limits: ExtractionLimits,
) -> str | None:
    if current_file_written > limits.max_single_file_bytes:
        return "Zip bomb: single file bytes exceeded during extraction"

    cumulative_written = current_total_extracted_bytes + current_file_written
    if cumulative_written > limits.max_extracted_bytes:
        return "Zip bomb: total extracted bytes exceeded during extraction"

    if archive_size > 0 and cumulative_written / archive_size > limits.max_expansion_ratio:
        return "Zip bomb: expansion ratio exceeded during extraction"

    return None
