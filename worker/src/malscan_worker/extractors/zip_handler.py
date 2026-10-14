# worker/src/malscan_worker/extractors/zip_handler.py
"""ZIP format handler.

Supports standard ZIP encryption and AES-256 encryption (via pyzipper fallback).
"""

import os
import zipfile
from pathlib import Path

import structlog

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

# Optional AES support via pyzipper
try:
    import pyzipper

    _HAS_PYZIPPER = True
except ImportError:
    _HAS_PYZIPPER = False


class ZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "zip"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:4] == b"PK\x03\x04":
            return True
        if mime in ("application/zip", "application/x-zip-compressed"):
            return True
        if file_path.suffix.lower() == ".zip":
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
            return self._extract_standard(file_path, extract_dir, limits, password)
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except zipfile.BadZipFile as e:
            return ExtractionResult(files=[], warnings=[f"Bad zip file: {e}"], archive_type="zip")
        except NotImplementedError:
            # Standard zipfile can't handle AES — try pyzipper fallback
            return self._try_pyzipper_fallback(file_path, extract_dir, limits, password)
        except Exception as e:
            # Check if this is an AES "compression method not supported" error
            if "compression method" in str(e).lower() and _HAS_PYZIPPER:
                return self._try_pyzipper_fallback(file_path, extract_dir, limits, password)
            logger.error("zip_extraction_error", error=str(e))
            return ExtractionResult(
                files=[], warnings=[f"Extraction error: {e}"], archive_type="zip"
            )

    def _try_pyzipper_fallback(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        """Attempt extraction with pyzipper for AES-encrypted zips."""
        if not _HAS_PYZIPPER:
            return ExtractionResult(
                files=[],
                warnings=["AES-encrypted zip requires pyzipper package"],
                archive_type="zip",
            )
        try:
            return self._extract_pyzipper(file_path, extract_dir, limits, password)
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as e:
            logger.error("zip_pyzipper_extraction_error", error=str(e))
            return ExtractionResult(
                files=[],
                warnings=[f"Extraction error (pyzipper): {e}"],
                archive_type="zip",
            )

    # ------------------------------------------------------------------
    # Standard zipfile extraction
    # ------------------------------------------------------------------

    def _extract_standard(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []
        password_protected = False

        with zipfile.ZipFile(str(file_path), "r") as zf:
            # Check for encryption
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # encrypted
                    password_protected = True
                    if not password:
                        raise ArchivePasswordRequiredError("zip")
                    break

            # Pre-check expansion ratio from declared sizes
            archive_size = os.path.getsize(file_path)
            total_uncompressed = sum(i.file_size for i in zf.infolist() if not i.is_dir())
            ratio_warning = check_expansion_ratio(archive_size, total_uncompressed, limits)
            if ratio_warning:
                return ExtractionResult(
                    files=[],
                    malicious=True,
                    reason=ratio_warning,
                    archive_type="zip",
                    password_protected=password_protected,
                )

            total_extracted_bytes = 0
            pwd = password.encode() if password else None

            for member_index, info in enumerate(zf.infolist()):
                if info.is_dir():
                    continue

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached, stopping")
                    break

                target = safe_extract_path(str(extract_dir), info.filename)
                if target is None:
                    warnings.append(f"Path traversal skipped: {info.filename}")
                    continue

                # Separate filesystem targets preserve duplicate-name entries.
                target = safe_extract_path(str(extract_dir / str(member_index)), info.filename)
                if target is None:
                    continue

                if info.file_size > limits.max_single_file_bytes:
                    warnings.append(
                        f"File too large, skipped: {info.filename} ({info.file_size} bytes)"
                    )
                    continue

                if total_extracted_bytes + info.file_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached, stopping")
                    break

                origin = f"{member_index}:{info.filename}"
                try:
                    reserve_output(limits, origin, info.file_size)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            reason = _stream_limit_reason(
                                archive_size=archive_size,
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
                                    archive_type="zip",
                                    password_protected=password_protected,
                                )
                            check_stream_size(
                                limits,
                                written=written,
                                total=total_extracted_bytes,
                                archive_size=archive_size,
                            )
                            reserve_output(limits, origin, written)
                            dst.write(chunk)
                except BudgetExceeded as exc:
                    if os.path.exists(target):
                        os.remove(target)
                    return ExtractionResult(
                        files=files,
                        warnings=[*warnings, exc.reason],
                        archive_type="zip",
                        password_protected=password_protected,
                        resource_limited=True,
                        limit_reason=exc.reason,
                    )
                except RuntimeError as e:
                    if _is_password_error(e):
                        raise ArchiveWrongPasswordError("zip") from e
                    raise

                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(info.filename),
                        size=written,
                        origin_path=info.filename,
                        occurrence_index=member_index,
                    )
                )

        return ExtractionResult(
            files=files,
            warnings=warnings,
            archive_type="zip",
            password_protected=password_protected,
        )

    # ------------------------------------------------------------------
    # pyzipper fallback for AES-encrypted zips
    # ------------------------------------------------------------------

    def _extract_pyzipper(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        if not _HAS_PYZIPPER:
            raise RuntimeError("pyzipper not available")

        files: list[ExtractedFile] = []
        warnings: list[str] = []
        password_protected = False

        with pyzipper.AESZipFile(str(file_path), "r") as zf:
            # Check for encryption
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # encrypted
                    password_protected = True
                    if not password:
                        raise ArchivePasswordRequiredError("zip")
                    break

            archive_size = os.path.getsize(file_path)
            total_uncompressed = sum(i.file_size for i in zf.infolist() if not i.is_dir())
            ratio_warning = check_expansion_ratio(archive_size, total_uncompressed, limits)
            if ratio_warning:
                return ExtractionResult(
                    files=[],
                    malicious=True,
                    reason=ratio_warning,
                    archive_type="zip",
                    password_protected=password_protected,
                )

            total_extracted_bytes = 0
            pwd = password.encode() if password else None
            if pwd:
                zf.setpassword(pwd)

            for member_index, info in enumerate(zf.infolist()):
                if info.is_dir():
                    continue

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached, stopping")
                    break

                target = safe_extract_path(str(extract_dir), info.filename)
                if target is None:
                    warnings.append(f"Path traversal skipped: {info.filename}")
                    continue

                # Separate filesystem targets preserve duplicate-name entries.
                target = safe_extract_path(str(extract_dir / str(member_index)), info.filename)
                if target is None:
                    continue

                if info.file_size > limits.max_single_file_bytes:
                    warnings.append(
                        f"File too large, skipped: {info.filename} ({info.file_size} bytes)"
                    )
                    continue

                if total_extracted_bytes + info.file_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached, stopping")
                    break

                origin = f"{member_index}:{info.filename}"
                try:
                    reserve_output(limits, origin, info.file_size)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            reason = _stream_limit_reason(
                                archive_size=archive_size,
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
                                    archive_type="zip",
                                    password_protected=password_protected,
                                )
                            check_stream_size(
                                limits,
                                written=written,
                                total=total_extracted_bytes,
                                archive_size=archive_size,
                            )
                            reserve_output(limits, origin, written)
                            dst.write(chunk)
                except BudgetExceeded as exc:
                    if os.path.exists(target):
                        os.remove(target)
                    return ExtractionResult(
                        files=files,
                        warnings=[*warnings, exc.reason],
                        archive_type="zip",
                        password_protected=password_protected,
                        resource_limited=True,
                        limit_reason=exc.reason,
                    )
                except RuntimeError as e:
                    if _is_password_error(e):
                        raise ArchiveWrongPasswordError("zip") from e
                    raise

                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(info.filename),
                        size=written,
                        origin_path=info.filename,
                        occurrence_index=member_index,
                    )
                )

        return ExtractionResult(
            files=files,
            warnings=warnings,
            archive_type="zip",
            password_protected=password_protected,
        )


def _stream_limit_reason(
    *,
    archive_size: int,
    current_total_extracted_bytes: int,
    current_file_written: int,
    limits: ExtractionLimits,
) -> str | None:
    cumulative_written = current_total_extracted_bytes + current_file_written
    if cumulative_written > limits.max_extracted_bytes:
        return "Zip bomb: total extracted bytes exceeded during extraction"

    if archive_size > 0 and cumulative_written / archive_size > limits.max_expansion_ratio:
        return "Zip bomb: expansion ratio exceeded during extraction"

    return None


def _is_password_error(error: RuntimeError) -> bool:
    message = str(error).lower()
    return "password" in message or "bad password" in message
