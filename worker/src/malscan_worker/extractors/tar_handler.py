# worker/src/malscan_worker/extractors/tar_handler.py
"""TAR format handler."""

import os
import tarfile
from pathlib import Path

import structlog

from malscan_worker.budget import BudgetExceeded
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import (
    check_stream_size,
    remove_symlinks,
    reserve_output,
    safe_extract_path,
)

logger = structlog.get_logger(__name__)

TAR_MAGIC = b"ustar"  # appears at offset 257


class TarHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "tar"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in ("application/x-tar",):
            return True
        if file_path.suffix.lower() == ".tar":
            return True
        # Check tar magic at offset 257
        try:
            with open(file_path, "rb") as f:
                f.seek(257)
                marker = f.read(5)
                if marker == TAR_MAGIC:
                    return True
        except OSError:
            pass
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        try:
            with tarfile.open(str(file_path), "r:*") as tf:
                total_bytes = 0
                for member_index, member in enumerate(tf):
                    if not member.isfile():
                        continue

                    if len(files) >= limits.max_files:
                        warnings.append(f"Max files limit ({limits.max_files}) reached")
                        break

                    target = safe_extract_path(str(extract_dir), member.name)
                    if target is None:
                        warnings.append(f"Path traversal skipped: {member.name}")
                        continue

                    target = safe_extract_path(str(extract_dir / str(member_index)), member.name)
                    if target is None:
                        continue

                    if member.size > limits.max_single_file_bytes:
                        warnings.append(
                            f"File too large, skipped: {member.name} ({member.size} bytes)"
                        )
                        continue

                    if total_bytes + member.size > limits.max_extracted_bytes:
                        warnings.append("Max total extracted bytes reached")
                        break

                    origin = f"{member_index}:{member.name}"
                    reserve_output(limits, origin, member.size)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            check_stream_size(
                                limits,
                                written=written,
                                total=total_bytes,
                                archive_size=file_path.stat().st_size,
                            )
                            reserve_output(limits, origin, written)
                            dst.write(chunk)

                    total_bytes += written
                    files.append(
                        ExtractedFile(
                            path=target,
                            original_name=os.path.basename(member.name),
                            size=written,
                            origin_path=member.name,
                            occurrence_index=member_index,
                        )
                    )

        except BudgetExceeded as exc:
            if "target" in locals() and target is not None and os.path.exists(target):
                os.remove(target)
            return ExtractionResult(
                files=files,
                warnings=[*warnings, exc.reason],
                archive_type="tar",
                resource_limited=True,
                limit_reason=exc.reason,
            )
        except tarfile.TarError as e:
            warnings.append(f"Tar error: {e}")
        except Exception as e:
            logger.error("tar_extraction_error", error=str(e))
            warnings.append(f"Extraction error: {e}")

        remove_symlinks(str(extract_dir))
        return ExtractionResult(files=files, warnings=warnings, archive_type="tar")
