"""7z format handler."""

from __future__ import annotations

import io
import os
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    import py7zr
else:
    try:
        import py7zr
    except ImportError:  # pragma: no cover - optional dependency fallback
        py7zr = None

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

SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"


class SevenZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "7z"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:6] == SEVENZ_MAGIC:
            return True
        if mime in ("application/x-7z-compressed",):
            return True
        if file_path.suffix.lower() == ".7z":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        try:
            return self._extract(file_path, extract_dir, limits, password)
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as exc:
            # Encrypted headers fail while opening, before member iteration.
            if _is_password_required_error(exc):
                raise ArchivePasswordRequiredError("7z") from exc
            if password and "wrong password" in str(exc).lower():
                raise ArchiveWrongPasswordError("7z") from exc
            raise

    def _extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        if py7zr is None:
            raise RuntimeError("py7zr not available")

        files: list[ExtractedFile] = []
        warnings: list[str] = []
        with py7zr.SevenZipFile(file_path, mode="r", password=password) as archive:
            members = [
                item
                for item in archive.list()
                if getattr(item, "filename", None) and not getattr(item, "is_directory", False)
            ]
            password_protected = bool(archive.needs_password())

            reason = _preflight_reason(
                archive_size=file_path.stat().st_size,
                member_count=len(members),
                member_sizes=[int(getattr(item, "uncompressed", 0) or 0) for item in members],
                limits=limits,
            )
            if reason is not None:
                return ExtractionResult(
                    files=[],
                    malicious="Expansion ratio" in reason,
                    reason=reason,
                    resource_limited="Expansion ratio" not in reason,
                    limit_reason="extraction_limit" if "Expansion ratio" not in reason else None,
                    archive_type="7z",
                    password_protected=password_protected,
                )

            if limits.reserve_output is not None:
                return _extract_bounded_members(
                    archive, file_path, extract_dir, limits, password, password_protected
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

                member_size = int(getattr(member, "uncompressed", 0) or 0)
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
                    archive.extract(path=extract_dir, targets=[member_name])
                except BudgetExceeded as exc:
                    if os.path.exists(target):
                        os.remove(target)
                    return ExtractionResult(
                        files=files,
                        warnings=[*warnings, exc.reason],
                        archive_type="7z",
                        password_protected=password_protected,
                        resource_limited=True,
                        limit_reason=exc.reason,
                    )
                except Exception as exc:
                    if _is_password_required_error(exc):
                        raise ArchivePasswordRequiredError("7z") from exc
                    if _is_wrong_password_error(exc, password_protected, password):
                        raise ArchiveWrongPasswordError("7z") from exc
                    raise

                written = os.path.getsize(target)

                reason = _stream_limit_reason(
                    archive_size=file_path.stat().st_size,
                    current_total_extracted_bytes=total_extracted_bytes,
                    current_file_written=written,
                    limits=limits,
                )
                if reason is not None:
                    if os.path.exists(target):
                        os.remove(target)
                    archive.reset()
                    return ExtractionResult(
                        files=files,
                        malicious=True,
                        reason=reason,
                        archive_type="7z",
                        password_protected=password_protected,
                    )

                archive.reset()
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
            archive_type="7z",
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
    if py7zr is not None and isinstance(exc, getattr(py7zr, "PasswordRequired", ())):
        return True
    return "password required" in str(exc).lower()


def _is_wrong_password_error(
    exc: Exception, password_protected: bool, password: str | None
) -> bool:
    if not password_protected or not password:
        return False
    message = str(exc).lower()
    return "wrong password" in message or "corrupt input data" in message


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


def _extract_bounded_members(
    archive: Any,
    file_path: Path,
    extract_dir: Path,
    limits: ExtractionLimits,
    password: str | None,
    password_protected: bool,
) -> ExtractionResult:
    """Pinned py7zr 0.22 writer bridge, including duplicate-name provenance.

    This version predates public WriterFactory. Its worker accepts MemIO targets;
    each target writes bounded bytes directly to a separate on-disk file. No
    read-all buffers or unbounded filesystem extraction are used. Unsupported
    writer versions fail explicitly. The outer process boundary kills native
    decoding on deadline and protects other worker/parser instances.
    """
    if not str(getattr(py7zr, "__version__", "")).startswith("0.22."):
        return ExtractionResult(
            files=[],
            archive_type="7z",
            resource_limited=True,
            limit_reason="bounded_7z_writer_unavailable",
            warnings=["bounded_7z_writer_unavailable"],
        )
    from py7zr.helpers import MemIO

    files: list[ExtractedFile] = []
    warnings: list[str] = []
    total_written = 0
    archive_size = file_path.stat().st_size

    class BoundedDiskIO(MemIO):
        def __init__(self, target: Path, member_name: str, origin: str, declared: int):
            self.target = target
            self.member_name = member_name
            self.origin = origin
            self.occurrence_index = int(origin.split(":", 1)[0])
            self.declared = declared
            self.written = 0
            self._buf = io.BytesIO()

        @property
        def parent(self) -> Path:
            return self.target.parent

        def open(self, mode: str | None = None) -> BoundedDiskIO:
            reserve_output(limits, self.origin, self.declared)
            self.target.parent.mkdir(parents=True, exist_ok=True)
            self._buf = open(self.target, "w+b")
            return self

        def write(self, data: bytes) -> int:
            nonlocal total_written
            next_written = self.written + len(data)
            check_stream_size(
                limits,
                written=next_written,
                total=total_written - self.written,
                archive_size=archive_size,
            )
            reserve_output(limits, self.origin, next_written)
            result = self._buf.write(data)
            self.written += result
            total_written += result
            return result

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None:
            self._buf.close()
            if exc_type is not None:
                self.target.unlink(missing_ok=True)
            else:
                files.append(
                    ExtractedFile(
                        path=str(self.target),
                        original_name=Path(self.member_name).name,
                        size=self.written,
                        origin_path=self.member_name,
                        occurrence_index=self.occurrence_index,
                    )
                )

    worker = getattr(archive, "worker", None)
    if worker is None or not callable(getattr(worker, "register_filelike", None)):
        raise BudgetExceeded("bounded_7z_writer_unavailable")
    for index, member in enumerate(archive.files):
        name = str(member.filename)
        if member.is_directory or member.is_symlink or member.is_junction or member.is_socket:
            worker.register_filelike(member.id, None)
            if not member.is_directory:
                warnings.append(f"Special archive entry skipped: {name}")
            continue
        target = safe_extract_path(str(extract_dir / str(index)), name)
        if target is None:
            worker.register_filelike(member.id, None)
            warnings.append(f"Path traversal skipped: {name}")
            continue
        worker.register_filelike(
            member.id,
            BoundedDiskIO(
                Path(target),
                name,
                f"{index}:{name}",
                int(member.uncompressed or 0),
            ),
        )
    try:
        # Serial processing gives one ordered stream of output reservations.
        worker.extract(archive.fp, extract_dir, parallel=False, skip_notarget=True)
    except BudgetExceeded as exc:
        return ExtractionResult(
            files=files,
            archive_type="7z",
            password_protected=password_protected,
            warnings=[*warnings, exc.reason],
            resource_limited=True,
            limit_reason=exc.reason,
        )
    except Exception as exc:
        if _is_password_required_error(exc):
            raise ArchivePasswordRequiredError("7z") from exc
        if _is_wrong_password_error(exc, password_protected, password):
            raise ArchiveWrongPasswordError("7z") from exc
        raise
    return ExtractionResult(
        files=files,
        archive_type="7z",
        warnings=warnings,
        password_protected=password_protected,
    )
