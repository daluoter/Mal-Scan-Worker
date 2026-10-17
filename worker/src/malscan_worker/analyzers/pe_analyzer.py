"""Portable Executable (PE) format analyzer."""

from __future__ import annotations

import asyncio
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pefile

from malscan_worker.analyzers.base import (
    AnalyzerIndicator,
    AnalyzerResult,
    FormatAnalyzer,
    JsonValue,
)
from malscan_worker.heuristics.pe import build_pe_heuristics

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageContext


_PE_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
}

_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
_SPARSE_IMPORT_DLL_THRESHOLD = 1
_SPARSE_IMPORT_SYMBOL_THRESHOLD = 9

_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

_SUSPICIOUS_IMPORTS = {
    "createremotethread",
    "virtualallocex",
    "writeprocessmemory",
    "readprocessmemory",
    "setwindowshookex",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopena",
    "internetopenw",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
}

_SUSPICIOUS_SECTION_NAMES = {
    ".upx",
    "upx0",
    "upx1",
    ".aspack",
    ".packed",
    ".petite",
    ".themida",
    ".adata",
}


class PEAnalyzer(FormatAnalyzer):
    """Analyze PE files for suspicious structural patterns."""

    @property
    def name(self) -> str:
        return "pe"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in _PE_MIME_TYPES:
            return True

        if not magic.startswith(b"MZ"):
            return False

        return self._has_valid_pe_signature(file_path)

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        del ctx
        result = AnalyzerResult(analyzer_name=self.name, format_type="PE")

        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            result.errors.append(f"failed to stat PE file: {exc}")
            return result

        if file_size > _MAX_FILE_SIZE_BYTES:
            result.errors.append("PE analysis skipped: file exceeds 100MB limit")
            return result

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path, file_size)

    def _analyze_sync(self, file_path: Path, file_size: int) -> AnalyzerResult:
        result = AnalyzerResult(analyzer_name=self.name, format_type="PE")

        try:
            pe: Any = pefile.PE(str(file_path), fast_load=False)
        except pefile.PEFormatError as exc:
            result.errors.append(f"failed to parse PE file: {exc}")
            return result
        except OSError as exc:
            result.errors.append(f"failed to open PE file: {exc}")
            return result

        try:
            imports, suspicious_imports = self._extract_imports(pe)
            exports = self._extract_exports(pe)
            sections, section_indicators = self._extract_sections(pe)
            headers = self._extract_headers(pe)
            resources, resource_indicators = self._extract_resources(pe)
            tls_callbacks, tls_indicator = self._extract_tls_callbacks(pe)
            debug_info, debug_indicator = self._extract_debug_info(pe)
            overlay = self._extract_overlay(pe, file_size)
            packer_clues = self._derive_packer_clues(sections, imports)

            indicators: list[AnalyzerIndicator] = []
            if suspicious_imports:
                indicators.append(
                    {
                        "type": "suspicious_imports",
                        "severity": "high",
                        "detail": "Suspicious API imports detected",
                        "evidence": suspicious_imports,
                    }
                )
            if packer_clues:
                indicators.append(
                    {
                        "type": "packer_detected",
                        "severity": "medium",
                        "detail": "Packer-like characteristics observed",
                        "evidence": packer_clues,
                    }
                )
            if not imports:
                indicators.append(
                    {
                        "type": "no_imports",
                        "severity": "medium",
                        "detail": "No imports found",
                    }
                )

            indicators.extend(section_indicators)
            if tls_indicator is not None:
                indicators.append(tls_indicator)
            indicators.extend(resource_indicators)

            if overlay.get("present"):
                indicators.append(
                    {
                        "type": "overlay_data",
                        "severity": "low",
                        "detail": "Overlay data is present",
                        "evidence": overlay,
                    }
                )

            if self._is_timestamp_anomalous(headers):
                indicators.append(
                    {
                        "type": "timestamp_anomaly",
                        "severity": "low",
                        "detail": "PE timestamp appears implausible",
                        "evidence": {"timestamp": headers.get("timestamp")},
                    }
                )

            if debug_indicator is not None:
                indicators.append(debug_indicator)

            result.features = {
                "imports": imports,
                "exports": exports,
                "sections": sections,
                "headers": headers,
                "resources": resources,
                "packer_clues": packer_clues,
                "tls_callbacks": tls_callbacks,
                "debug_info": debug_info,
                "overlay": overlay,
                "is_dll": bool(getattr(pe, "is_dll", lambda: False)()),
                "is_64bit": self._is_64bit(pe),
            }
            result.indicators = indicators
            result.risk_score = self._calculate_risk_score(indicators)
            result.risk_factors = [str(indicator.get("type", "")) for indicator in indicators]
            result.heuristics = build_pe_heuristics(result.features)
            return result
        finally:
            close_method = getattr(pe, "close", None)
            if callable(close_method):
                close_method()

    @staticmethod
    def _has_valid_pe_signature(file_path: Path) -> bool:
        try:
            with file_path.open("rb") as handle:
                handle.seek(0x3C)
                e_lfanew_raw = handle.read(4)
                if len(e_lfanew_raw) != 4:
                    return False

                e_lfanew = int.from_bytes(e_lfanew_raw, "little")
                if e_lfanew < 0x40:
                    return False

                handle.seek(e_lfanew)
                return handle.read(4) == b"PE\x00\x00"
        except OSError:
            return False

    @staticmethod
    def _decode_ascii(value: bytes | None) -> str:
        if not value:
            return ""
        return value.decode("ascii", errors="ignore").strip("\x00").strip()

    def _extract_imports(self, pe: Any) -> tuple[list[JsonValue], list[JsonValue]]:
        imports: list[JsonValue] = []
        suspicious: list[JsonValue] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll_name = self._decode_ascii(getattr(entry, "dll", None))
            functions: list[JsonValue] = []
            for symbol in getattr(entry, "imports", []):
                function_name = self._decode_ascii(getattr(symbol, "name", None))
                if not function_name:
                    continue
                functions.append(function_name)
                if function_name.lower() in _SUSPICIOUS_IMPORTS:
                    suspicious.append({"dll": dll_name, "function": function_name})

            imports.append({"dll": dll_name, "functions": functions})
        return imports, suspicious

    def _extract_exports(self, pe: Any) -> list[JsonValue]:
        exports: list[JsonValue] = []
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is None:
            return exports

        for symbol in getattr(export_dir, "symbols", []):
            name = self._decode_ascii(getattr(symbol, "name", None))
            if name:
                exports.append(name)
        return exports

    def _extract_sections(self, pe: Any) -> tuple[list[JsonValue], list[AnalyzerIndicator]]:
        sections: list[JsonValue] = []
        indicators: list[AnalyzerIndicator] = []

        for section in getattr(pe, "sections", []):
            name = self._decode_ascii(getattr(section, "Name", b""))
            entropy = float(getattr(section, "get_entropy", lambda: 0.0)())
            item: dict[str, JsonValue] = {
                "name": name,
                "virtual_size": int(getattr(section, "Misc_VirtualSize", 0)),
                "raw_size": int(getattr(section, "SizeOfRawData", 0)),
                "entropy": round(entropy, 3),
            }
            sections.append(item)

            if name.lower() in _SUSPICIOUS_SECTION_NAMES:
                indicators.append(
                    {
                        "type": "suspicious_section_name",
                        "severity": "medium",
                        "detail": f"Suspicious section name: {name}",
                        "evidence": {"section": name},
                    }
                )

            if entropy >= 7.2:
                indicators.append(
                    {
                        "type": "high_entropy_section",
                        "severity": "medium",
                        "detail": f"High entropy section: {name}",
                        "evidence": {"section": name, "entropy": round(entropy, 3)},
                    }
                )

        return sections, indicators

    def _extract_headers(self, pe: Any) -> dict[str, JsonValue]:
        file_header = getattr(pe, "FILE_HEADER", None)
        optional_header = getattr(pe, "OPTIONAL_HEADER", None)
        return {
            "machine": int(getattr(file_header, "Machine", 0)),
            "timestamp": int(getattr(file_header, "TimeDateStamp", 0)),
            "characteristics": int(getattr(file_header, "Characteristics", 0)),
            "optional_magic": int(getattr(optional_header, "Magic", 0)),
            "subsystem": int(getattr(optional_header, "Subsystem", 0)),
        }

    def _extract_resources(self, pe: Any) -> tuple[list[JsonValue], list[AnalyzerIndicator]]:
        resources: list[JsonValue] = []
        indicators: list[AnalyzerIndicator] = []
        resource_dir = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if resource_dir is None:
            return resources, indicators

        for root_entry in getattr(resource_dir, "entries", []):
            resource_type = int(getattr(root_entry, "id", -1))
            type_directory = getattr(root_entry, "directory", None)
            if type_directory is None:
                continue

            for name_entry in getattr(type_directory, "entries", []):
                language_directory = getattr(name_entry, "directory", None)
                if language_directory is None:
                    continue

                for language_entry in getattr(language_directory, "entries", []):
                    data_entry = getattr(language_entry, "data", None)
                    if data_entry is None:
                        continue

                    data_struct = getattr(data_entry, "struct", None)
                    if data_struct is None:
                        continue

                    offset = int(getattr(data_struct, "OffsetToData", 0))
                    size = int(getattr(data_struct, "Size", 0))
                    blob = b""
                    if size > 0:
                        try:
                            blob = pe.get_data(offset, size)
                        except Exception:
                            blob = b""

                    entropy = self._estimate_entropy(blob)
                    resources.append(
                        {
                            "type": resource_type,
                            "size": size,
                            "entropy": round(entropy, 3),
                        }
                    )

                    if size >= 2048 and entropy >= 7.2:
                        indicators.append(
                            {
                                "type": "suspicious_resource",
                                "severity": "medium",
                                "detail": "High-entropy resource blob",
                                "evidence": {
                                    "type": resource_type,
                                    "size": size,
                                    "entropy": round(entropy, 3),
                                },
                            }
                        )

        return resources, indicators

    def _extract_tls_callbacks(self, pe: Any) -> tuple[list[JsonValue], AnalyzerIndicator | None]:
        tls_dir = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls_dir is None:
            return [], None

        tls_struct = getattr(tls_dir, "struct", None)
        callback_addr = int(getattr(tls_struct, "AddressOfCallBacks", 0) or 0)
        if callback_addr == 0:
            return [], None

        callbacks: list[JsonValue] = [callback_addr]
        return callbacks, {
            "type": "tls_callbacks",
            "severity": "medium",
            "detail": "TLS callbacks present",
            "evidence": callbacks,
        }

    def _extract_debug_info(self, pe: Any) -> tuple[list[JsonValue], AnalyzerIndicator | None]:
        debug_info: list[JsonValue] = []
        suspicious_paths: list[JsonValue] = []

        for debug_entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            debug_struct = getattr(debug_entry, "struct", None)
            entry_type = int(getattr(debug_struct, "Type", 0))
            entry_obj = getattr(debug_entry, "entry", None)
            path = self._decode_ascii(getattr(entry_obj, "PdbFileName", None))

            debug_info.append({"type": entry_type, "path": path})

            lowered = path.lower()
            if lowered and any(token in lowered for token in ("\\users\\", "\\temp\\", "appdata")):
                suspicious_paths.append(path)

        if not suspicious_paths:
            return debug_info, None

        return debug_info, {
            "type": "debug_path_suspicious",
            "severity": "low",
            "detail": "Debug path references user/temp profile",
            "evidence": suspicious_paths,
        }

    def _extract_overlay(self, pe: Any, file_size: int) -> dict[str, JsonValue]:
        # pefile returns None for the ordinary case with no trailing overlay.
        overlay_bytes = getattr(pe, "get_overlay", lambda: b"")() or b""
        overlay_offset = getattr(pe, "get_overlay_data_start_offset", lambda: None)()
        return {
            "present": bool(overlay_bytes),
            "offset": int(overlay_offset) if overlay_offset is not None else None,
            "size": len(overlay_bytes),
            "file_size": file_size,
        }

    @staticmethod
    def _is_64bit(pe: Any) -> bool:
        optional_header = getattr(pe, "OPTIONAL_HEADER", None)
        return int(getattr(optional_header, "Magic", 0)) == 0x20B

    @staticmethod
    def _is_timestamp_anomalous(headers: dict[str, JsonValue]) -> bool:
        timestamp = headers.get("timestamp")
        if not isinstance(timestamp, int):
            return False
        if timestamp <= 0:
            return True

        try:
            dt = datetime.fromtimestamp(timestamp, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return True

        current_year = datetime.now(tz=UTC).year
        return dt.year < 1995 or dt.year > current_year + 1

    def _derive_packer_clues(
        self, sections: list[JsonValue], imports: list[JsonValue]
    ) -> list[JsonValue]:
        clues: list[JsonValue] = []

        section_names = {
            str(section.get("name", "")).lower()
            for section in sections
            if isinstance(section, dict)
        }
        for suspicious_name in sorted(_SUSPICIOUS_SECTION_NAMES):
            if suspicious_name in section_names:
                clues.append({"type": "section_name", "value": suspicious_name})

        high_entropy_count = 0
        for section in sections:
            if not isinstance(section, dict):
                continue
            entropy = section.get("entropy")
            if isinstance(entropy, int | float) and float(entropy) >= 7.2:
                high_entropy_count += 1

        imported_symbol_count = self._count_imported_symbols(imports)
        imported_dll_count = self._count_imported_dlls(imports)
        if high_entropy_count > 0 and (
            imported_dll_count <= _SPARSE_IMPORT_DLL_THRESHOLD
            or imported_symbol_count <= _SPARSE_IMPORT_SYMBOL_THRESHOLD
        ):
            clues.append(
                {
                    "type": "high_entropy_with_sparse_imports",
                    "high_entropy_sections": high_entropy_count,
                    "import_dll_count": imported_dll_count,
                    "import_symbols": imported_symbol_count,
                }
            )

        return clues

    @staticmethod
    def _count_imported_symbols(imports: list[JsonValue]) -> int:
        normalized_functions: set[str] = set()
        for entry in imports:
            if not isinstance(entry, dict):
                continue
            functions = entry.get("functions")
            if not isinstance(functions, list):
                continue
            for function in functions:
                if isinstance(function, str) and function:
                    normalized_functions.add(function.lower())
        return len(normalized_functions)

    @staticmethod
    def _count_imported_dlls(imports: list[JsonValue]) -> int:
        return sum(1 for entry in imports if isinstance(entry, dict) and entry.get("functions"))

    def _calculate_risk_score(self, indicators: list[AnalyzerIndicator]) -> int:
        score = 0
        for indicator in indicators:
            severity = str(indicator.get("severity", ""))
            score += _SEVERITY_WEIGHTS.get(severity, 0)
        return min(score, 100)

    @staticmethod
    def _estimate_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        counts = [0] * 256
        for value in data:
            counts[value] += 1

        total = len(data)
        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy
