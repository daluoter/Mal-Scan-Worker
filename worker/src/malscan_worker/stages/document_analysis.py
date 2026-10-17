"""Document analysis stage for RTF, OLE, and Office file deep inspection.

Provides structural parsing, exploit indicator extraction, macro/script
detection, and embedded object extraction with sub-job submission for
recursive analysis.

Primary tools: oletools ecosystem (oleobj, rtfobj, olevba, oleid).
Fallback: raw binary heuristics when oletools is unavailable.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import structlog

from malscan_worker.budget import BudgetExceeded, reservation_key
from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.extractors.process import run_parser_bounded
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional dependency imports — graceful degradation
# ---------------------------------------------------------------------------
try:
    from oletools import oleid  # noqa: F401

    HAS_OLEID = True
except ImportError:
    HAS_OLEID = False

try:
    from oletools import rtfobj as _rtfobj  # noqa: F401

    HAS_RTFOBJ = True
except ImportError:
    HAS_RTFOBJ = False

try:
    from oletools.olevba import VBA_Parser  # noqa: F401

    HAS_OLEVBA = True
except ImportError:
    HAS_OLEVBA = False

try:
    from oletools import oleobj as _oleobj  # noqa: F401

    HAS_OLEOBJ = True
except ImportError:
    HAS_OLEOBJ = False

# ---------------------------------------------------------------------------
# Constants — size / depth guards
# ---------------------------------------------------------------------------
MAX_FILE_SIZE_FOR_PARSE = 50 * 1024 * 1024  # 50 MB — skip huge docs
MAX_EMBEDDED_OBJECTS = 30  # cap on objects we inspect per document
MAX_EXTRACTED_ARTIFACT_SIZE = 20 * 1024 * 1024  # 20 MB per artifact
MAX_MACRO_SOURCE_LEN = 256 * 1024  # 256 KB of VBA source kept in findings
PARSE_TIMEOUT_GUARD_BYTES = 100 * 1024 * 1024  # secondary guard

# Suspicious VBA / script keywords (case-insensitive matching)
SUSPICIOUS_VBA_KEYWORDS: list[str] = [
    "AutoOpen",
    "Auto_Open",
    "AutoClose",
    "Auto_Close",
    "AutoExec",
    "Document_Open",
    "Document_Close",
    "Workbook_Open",
    "Shell",
    "WScript.Shell",
    "Powershell",
    "cmd.exe",
    "CreateObject",
    "GetObject",
    "CallByName",
    "Environ",
    "URLDownloadToFile",
    "MSXML2.XMLHTTP",
    "ADODB.Stream",
    "Scripting.FileSystemObject",
    "VirtualAlloc",
    "RtlMoveMemory",
    "CreateThread",
    "NtAllocateVirtualMemory",
    "ShellExecute",
    "RegWrite",
    "FromBase64String",
    "certutil",
    "bitsadmin",
    "mshta",
    "regsvr32",
    "rundll32",
    "cmstp",
    "msiexec",
    "Invoke-Expression",
    "IEX(",
    "Net.WebClient",
    "DownloadString",
    "DownloadFile",
    "Start-Process",
    "New-Object",
]

# RTF control words commonly abused in exploits
RTF_SUSPICIOUS_CONTROLS: list[bytes] = [
    b"\\objdata",
    b"\\objemb",
    b"\\objocx",
    b"\\objhtml",
    b"\\objlink",
    b"\\objautlink",
    b"\\objupdate",
    b"\\pict",
    b"\\objclass Equation",
    b"\\objclass Package",
    b"\\datafield",
]

# OLE CLSID for Equation Editor (CVE-2017-11882 / CVE-2018-0802)
EQUATION_EDITOR_CLSIDS: list[str] = [
    "0002CE02-0000-0000-C000-000000000046",  # Equation 3.0
    "0002CE03-0000-0000-C000-000000000046",  # Equation 3.0 alt
]

# Known dangerous OLE class names
DANGEROUS_OLE_CLASSES: list[str] = [
    "equation",
    "package",
    "ole2link",
    "script",
    "shellbrowserwindow",
    "htmlfile",
]

# Extension → content-type mapping for extracted artifacts
ARTIFACT_CONTENT_TYPES: dict[str, str] = {
    ".exe": "application/x-dosexec",
    ".dll": "application/x-dosexec",
    ".scr": "application/x-dosexec",
    ".vbs": "text/vbscript",
    ".js": "application/javascript",
    ".ps1": "application/x-powershell",
    ".bat": "application/x-bat",
    ".cmd": "application/x-bat",
    ".hta": "application/hta",
    ".wsf": "text/xml",
    ".bin": "application/octet-stream",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_filename(name: str, index: int, ext: str = ".bin") -> str:
    """Produce a filesystem-safe artifact name — no path traversal."""
    # Strip directory separators and null bytes
    sanitised = re.sub(r"[/\\:\x00]", "_", name or "")
    sanitised = sanitised.strip(". ")[:80] or f"artifact_{index}"
    if not sanitised.endswith(ext):
        sanitised += ext
    return sanitised


def _looks_like_pe(data: bytes) -> bool:
    """Quick check for MZ header."""
    return data[:2] == b"MZ" and len(data) > 64


def _looks_like_shellcode(data: bytes) -> bool:
    """Heuristic: high entropy blob with common shellcode prologue bytes."""
    if len(data) < 16:
        return False
    # Common x86 shellcode starts
    prologues = [b"\xfc\xe8", b"\xe8\x00\x00\x00", b"\x60\xe8", b"\xeb\x10"]
    head = data[:8]
    for p in prologues:
        if head.startswith(p):
            return True
    # NOP sled
    if data[:16].count(b"\x90") > 10:
        return True
    return False


def _guess_artifact_ext(data: bytes, original_name: str) -> str:
    """Guess a reasonable file extension for an extracted blob."""
    if _looks_like_pe(data):
        return ".exe"
    lname = original_name.lower()
    for ext in ARTIFACT_CONTENT_TYPES:
        if lname.endswith(ext):
            return ext
    # VBS / JS sniff
    text_head = data[:512].lower()
    if b"<script" in text_head or b"wscript" in text_head:
        return ".js"
    if b"dim " in text_head or b"sub " in text_head or b"function " in text_head:
        return ".vbs"
    if b"powershell" in text_head or b"invoke-" in text_head:
        return ".ps1"
    if _looks_like_shellcode(data):
        return ".bin"
    return ".bin"


# ---------------------------------------------------------------------------
# Document type detection
# ---------------------------------------------------------------------------

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_OOXML_MAGIC = b"PK\x03\x04"

# RTF can start with {\rtf or have leading whitespace/BOM
_RTF_RE = re.compile(rb"^\s*(?:\xef\xbb\xbf)?\s*\{\\rtf", re.DOTALL)


def detect_document_type(file_path: Path, mime: str) -> str | None:
    """Return a document type tag or None if not a document we handle.

    Returns one of: "rtf", "ole", "ooxml", "ole+rtf_embedded", or None.
    """
    try:
        with open(file_path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None

    if _RTF_RE.match(head):
        return "rtf"
    if head[:8] == _OLE_MAGIC:
        return "ole"
    if head[:4] == _OOXML_MAGIC:
        office_extensions = {
            ".docx",
            ".docm",
            ".dotx",
            ".dotm",
            ".xlsx",
            ".xlsm",
            ".xltx",
            ".xltm",
            ".pptx",
            ".pptm",
            ".potx",
            ".potm",
        }
        if file_path.suffix.lower() in office_extensions:
            return "ooxml"
        try:
            with zipfile.ZipFile(file_path) as archive:
                names = set(archive.namelist())
            if "[Content_Types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            ):
                return "ooxml"
        except (OSError, zipfile.BadZipFile):
            pass

    # MIME fallback
    ml = mime.lower()
    if "rtf" in ml or "richtext" in ml:
        return "rtf"
    if "msword" in ml or "ms-word" in ml or "ole" in ml:
        return "ole"
    if (
        "officedocument" in ml
        or "vnd.openxmlformats" in ml
        or "vnd.ms-excel" in ml
        or "vnd.ms-powerpoint" in ml
    ):
        return "ooxml"
    return None


# ===================================================================
# Stage implementation
# ===================================================================


class DocumentAnalysisStage(Stage):
    """Deep-inspect RTF / OLE / Office documents for exploits, macros,
    embedded objects, and suspicious artefacts.

    Placement: SEQUENTIAL_STAGES (it creates sub-jobs via InternalJobSubmitter).
    """

    @property
    def name(self) -> str:
        return "document-analysis"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        if not ctx.file_path or not ctx.file_path.exists():
            return self._result(started_at, "skipped", {"reason": "File not found"})

        # Determine document type using magic bytes + MIME from earlier stage
        mime = self._get_mime(ctx)
        doc_type = detect_document_type(ctx.file_path, mime)

        if doc_type is None:
            return self._result(
                started_at,
                "skipped",
                {"reason": "Not a supported document format"},
            )

        file_size = ctx.file_path.stat().st_size
        if file_size > MAX_FILE_SIZE_FOR_PARSE:
            return self._result(
                started_at,
                "partial",
                {
                    "reason": f"File too large for document parsing ({file_size} bytes)",
                    "resource_limited": True,
                    "limit_reason": "document_input_bytes_limit",
                },
            )

        log.info(
            "document_analysis_start",
            job_id=ctx.job_id,
            doc_type=doc_type,
            file=str(ctx.file_path),
        )

        # Initialise output containers
        findings: dict[str, Any] = {
            "document_type": doc_type,
            "parser_findings": [],
            "exploit_indicators": [],
            "embedded_objects": [],
            "extracted_artifacts": [],
            "suspicious_keywords": [],
            "macros": {
                "found": False,
                "auto_exec": False,
                "suspicious": False,
                "sources": [],
            },
            "errors": [],
        }
        artifacts_on_disk: list[dict[str, Any]] = []

        extract_dir = Path(f"/tmp/{ctx.job_id}/doc_artifacts")
        extract_dir.mkdir(parents=True, exist_ok=True)

        def parse(
            reserve: Callable[[str, int, int], None],
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            parse_ctx = replace(ctx)

            def reserve_checked(origin: str, files: int, bytes: int) -> None:
                try:
                    reserve(origin, files, bytes)
                except BudgetExceeded as exc:
                    findings["resource_limited"] = True
                    findings["limit_reason"] = exc.reason
                    raise

            parse_ctx.reserve_output = reserve_checked
            # --- dispatch per doc type ---
            try:
                if doc_type == "rtf":
                    self._analyse_rtf(parse_ctx, findings, artifacts_on_disk, extract_dir)
                elif doc_type == "ole":
                    self._analyse_ole(parse_ctx, findings, artifacts_on_disk, extract_dir)
                elif doc_type == "ooxml":
                    self._analyse_ooxml(parse_ctx, findings, artifacts_on_disk, extract_dir)
            except Exception as exc:
                log.error(
                    "document_analysis_parse_error",
                    job_id=ctx.job_id,
                    error=str(exc),
                    exc_info=True,
                )
                findings["errors"].append(f"Parser error: {exc}")

            # --- VBA / macro analysis (works on OLE and OOXML) ---
            if doc_type in ("ole", "ooxml"):
                try:
                    self._analyse_vba(parse_ctx, findings)
                except Exception as exc:
                    log.error(
                        "document_vba_error",
                        job_id=ctx.job_id,
                        error=str(exc),
                        exc_info=True,
                    )
                    findings["errors"].append(f"VBA parser error: {exc}")
            return findings, artifacts_on_disk

        settings = getattr(ctx, "analysis_settings", None) or get_settings()
        try:
            findings, artifacts_on_disk = await run_parser_bounded(
                parse,
                root_budget=ctx.root_budget,
                job_id=ctx.job_id,
                source="document-analysis",
                timeout_seconds=settings.extraction_timeout,
            )
        except BudgetExceeded as exc:
            findings["resource_limited"] = True
            findings["limit_reason"] = exc.reason
            findings["errors"].append(exc.reason)
        except Exception as exc:
            findings["errors"].append(f"Document parser failed: {type(exc).__name__}")

        for artifact in artifacts_on_disk:
            artifact["budget_key"] = reservation_key(
                ctx.job_id,
                "document-analysis",
                artifact.get("budget_origin")
                or artifact.get("filename")
                or artifact.get("name")
                or Path(artifact["path"]).name,
            )

        # --- submit extracted artifacts as sub-jobs ---
        sub_jobs_created = 0
        if (
            artifacts_on_disk
            and (ctx.job or ctx.analysis_services)
            and not ctx.skip_artifact_submission
        ):
            depth = ctx.job.depth if ctx.job else ctx.depth
            max_depth = getattr(ctx.analysis_services, "max_depth", settings.max_job_depth)
            if depth >= max_depth:
                findings["resource_limited"] = True
                findings["limit_reason"] = "max_depth"
                findings["errors"].append(f"Max depth {max_depth} reached")
            else:
                try:
                    sub_jobs_created = await self._submit_artifacts(ctx, artifacts_on_disk)
                except Exception as exc:
                    findings["errors"].append(f"Artifact submission failed: {type(exc).__name__}")

        findings["sub_jobs_created"] = sub_jobs_created
        if findings.get("errors"):
            findings["reason"] = findings.get("limit_reason") or findings["errors"][0]

        # Truncate large lists to keep report manageable
        findings["suspicious_keywords"] = findings["suspicious_keywords"][:100]
        findings["parser_findings"] = findings["parser_findings"][:200]

        log.info(
            "document_analysis_done",
            job_id=ctx.job_id,
            doc_type=doc_type,
            exploit_indicators=len(findings["exploit_indicators"]),
            embedded_objects=len(findings["embedded_objects"]),
            artifacts_extracted=len(findings["extracted_artifacts"]),
            sub_jobs=sub_jobs_created,
        )

        return self._result(
            started_at,
            "partial" if findings.get("resource_limited") or findings["errors"] else "ok",
            findings,
        )

    # ------------------------------------------------------------------
    # RTF analysis
    # ------------------------------------------------------------------

    def _analyse_rtf(
        self,
        ctx: StageContext,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
    ) -> None:
        file_path = ctx.file_path
        if file_path is None:
            raise FileNotFoundError("File not found")
        raw = file_path.read_bytes()

        # 1. Structural scan for suspicious control words
        for ctrl in RTF_SUSPICIOUS_CONTROLS:
            if ctrl in raw:
                findings["parser_findings"].append(
                    {
                        "type": "rtf_control",
                        "value": ctrl.decode("ascii", errors="replace"),
                    }
                )

        # 2. oletools.rtfobj — extract embedded OLE objects from RTF
        # Isolated so that a parser crash does not prevent steps 3–4.
        try:
            if HAS_RTFOBJ:
                self._rtfobj_extract(ctx, raw, findings, artifacts, extract_dir)
            else:
                self._rtf_fallback_extract(raw, findings, artifacts, extract_dir, ctx=ctx)
        except Exception as exc:
            log.warning("rtfobj_extract_error", job_id=ctx.job_id, error=str(exc))
            findings["errors"].append(f"rtfobj extraction error: {exc}")

        # 3. Equation Editor detection
        if b"Equation" in raw or b"equation" in raw:
            findings["exploit_indicators"].append(
                {
                    "type": "equation_editor_reference",
                    "detail": "RTF contains Equation Editor class reference",
                    "cves": ["CVE-2017-11882", "CVE-2018-0802"],
                }
            )

        # 4. External template / URL moniker
        if b"\\*\\template " in raw or b"TEMPLATE" in raw.upper():
            findings["exploit_indicators"].append(
                {
                    "type": "external_template",
                    "detail": "RTF references an external template — possible template injection",
                }
            )

    def _rtfobj_extract(
        self,
        ctx: StageContext,
        raw: bytes,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
    ) -> None:
        """Use oletools.rtfobj to enumerate and extract embedded objects."""
        from oletools.rtfobj import RtfObjParser

        parser = RtfObjParser(raw)
        parser.parse()

        for idx, obj in enumerate(parser.objects):
            if idx >= MAX_EMBEDDED_OBJECTS:
                findings["errors"].append(
                    f"Truncated: more than {MAX_EMBEDDED_OBJECTS} objects in RTF"
                )
                break

            obj_info: dict[str, Any] = {
                "index": idx,
                "format_id": getattr(obj, "format_id", None),
                "class_name": getattr(obj, "class_name", "") or "",
                "size": getattr(obj, "oledata_size", 0)
                or len(getattr(obj, "oledata", None) or b""),
                "is_ole": getattr(obj, "is_ole", False),
                "is_package": getattr(obj, "is_package", False),
            }

            # Check for Equation Editor CLSID
            clsid = getattr(obj, "clsid", "") or ""
            clsid_upper = clsid.upper().replace("{", "").replace("}", "")
            obj_info["clsid"] = clsid_upper
            if clsid_upper in EQUATION_EDITOR_CLSIDS:
                obj_info["equation_editor"] = True
                findings["exploit_indicators"].append(
                    {
                        "type": "equation_editor_ole",
                        "detail": f"OLE object #{idx} has Equation Editor CLSID {clsid_upper}",
                        "cves": ["CVE-2017-11882", "CVE-2018-0802"],
                    }
                )

            class_lower = obj_info["class_name"].lower()
            if any(d in class_lower for d in DANGEROUS_OLE_CLASSES):
                obj_info["dangerous_class"] = True
                findings["exploit_indicators"].append(
                    {
                        "type": "dangerous_ole_class",
                        "detail": f"OLE object #{idx} class '{obj_info['class_name']}'",
                    }
                )

            findings["embedded_objects"].append(obj_info)

            # Extract data
            data = getattr(obj, "oledata", None) or b""
            if getattr(obj, "is_package", False):
                data = getattr(obj, "olepkgdata", None) or data
            if not data or len(data) > MAX_EXTRACTED_ARTIFACT_SIZE:
                continue

            orig_name = getattr(obj, "filename", "") or f"rtfobj_{idx}"
            ext = _guess_artifact_ext(data, orig_name)
            safe_name = _safe_filename(orig_name, idx, ext)
            out_path = extract_dir / safe_name

            self._write_artifact(ctx, out_path, data)

            art_record = {
                "filename": safe_name,
                "sha256": _sha256_bytes(data),
                "size": len(data),
                "source": f"rtf_object_{idx}",
                "path": str(out_path),
            }
            findings["extracted_artifacts"].append(art_record)
            artifacts.append(art_record)

    def _rtf_fallback_extract(
        self,
        raw: bytes,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
        *,
        ctx: StageContext | None = None,
    ) -> None:
        """Fallback: scan for hex-encoded OLE blobs (\\objdata hex dump)."""
        findings["errors"].append("oletools.rtfobj unavailable — using fallback hex extraction")

        # Pattern: \objdata followed by hex stream
        pattern = re.compile(rb"\\objdata\s+([0-9a-fA-F\s]{32,})", re.DOTALL)
        for idx, m in enumerate(pattern.finditer(raw)):
            if idx >= MAX_EMBEDDED_OBJECTS:
                break
            hex_str = re.sub(rb"\s+", b"", m.group(1))
            try:
                blob = bytes.fromhex(hex_str.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                continue

            if len(blob) < 8 or len(blob) > MAX_EXTRACTED_ARTIFACT_SIZE:
                continue

            # Check for OLE magic or PE header inside
            is_ole = blob[:8] == _OLE_MAGIC
            is_pe = _looks_like_pe(blob)

            obj_info: dict[str, Any] = {
                "index": idx,
                "size": len(blob),
                "is_ole": is_ole,
                "is_pe": is_pe,
                "source": "fallback_hex_extract",
            }
            findings["embedded_objects"].append(obj_info)

            # Check for Equation Editor signature in raw OLE header
            if is_ole and (b"Equation" in blob[:512] or b"equation" in blob[:512]):
                findings["exploit_indicators"].append(
                    {
                        "type": "equation_editor_blob",
                        "detail": f"Hex-extracted blob #{idx} contains Equation Editor reference",
                        "cves": ["CVE-2017-11882", "CVE-2018-0802"],
                    }
                )

            ext = ".exe" if is_pe else ".bin"
            safe_name = _safe_filename(f"rtf_hex_blob_{idx}", idx, ext)
            out_path = extract_dir / safe_name
            self._write_artifact(ctx, out_path, blob)

            art = {
                "filename": safe_name,
                "sha256": _sha256_bytes(blob),
                "size": len(blob),
                "source": f"rtf_hex_blob_{idx}",
                "path": str(out_path),
            }
            findings["extracted_artifacts"].append(art)
            artifacts.append(art)

    # ------------------------------------------------------------------
    # OLE analysis (legacy binary Office docs — .doc, .xls, .ppt)
    # ------------------------------------------------------------------

    def _analyse_ole(
        self,
        ctx: StageContext,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
    ) -> None:
        file_path = ctx.file_path
        if file_path is None:
            raise FileNotFoundError("File not found")
        raw = file_path.read_bytes()

        # 1. oleid indicators
        if HAS_OLEID:
            self._oleid_scan(ctx, findings)

        # 2. Embedded OLE objects via oleobj
        if HAS_OLEOBJ:
            self._oleobj_extract(ctx, findings, artifacts, extract_dir)

        # 3. Manual stream walk for Equation Editor / suspicious CLSIDs
        self._ole_stream_scan(raw, findings)

        # 4. Check for external link / template reference in binary doc
        if b"http://" in raw or b"https://" in raw or b"\\\\\\\\1" in raw:
            findings["parser_findings"].append(
                {
                    "type": "external_reference",
                    "detail": "OLE document contains URL/UNC reference",
                }
            )

    def _oleid_scan(self, ctx: StageContext, findings: dict[str, Any]) -> None:
        """Use oleid to get quick document risk indicators."""
        from oletools.oleid import OleID

        oid = OleID(str(ctx.file_path))
        try:
            indicators = oid.check()
        except Exception as exc:
            findings["errors"].append(f"oleid error: {exc}")
            return

        for ind in indicators:
            ind_name = getattr(ind, "name", str(ind))
            ind_value = getattr(ind, "value", None)
            ind_risk = getattr(ind, "risk", "none")

            entry = {
                "indicator": ind_name,
                "value": str(ind_value) if ind_value is not None else "",
                "risk": str(ind_risk),
            }
            findings["parser_findings"].append(entry)

            # Promote high-risk to exploit indicators
            risk_str = str(ind_risk).lower()
            if risk_str in ("high", "medium"):
                findings["exploit_indicators"].append(
                    {
                        "type": "oleid_risk",
                        "detail": f"{ind_name} = {ind_value} (risk: {ind_risk})",
                    }
                )

    def _oleobj_extract(
        self,
        ctx: StageContext,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
    ) -> None:
        """Extract embedded objects using oletools.oleobj."""
        from oletools.oleobj import OleNativeStream, OleObject

        idx = 0
        try:
            for ole_entry in _oleobj.find_ole(str(ctx.file_path)):
                if idx >= MAX_EMBEDDED_OBJECTS:
                    break

                # ole_entry is (storage_path, filename, ole_obj_or_native)
                # The API varies across oletools versions; handle both tuple and object forms.
                if isinstance(ole_entry, tuple) and len(ole_entry) >= 3:
                    obj = ole_entry[2]
                    source_path = str(ole_entry[0])
                else:
                    obj = ole_entry
                    source_path = str(idx)

                data = b""
                obj_class = ""

                if isinstance(obj, OleNativeStream):
                    data = getattr(obj, "data", b"") or b""
                    obj_class = getattr(obj, "class_name", "") or ""
                elif isinstance(obj, OleObject):
                    data = getattr(obj, "data", b"") or b""
                    obj_class = getattr(obj, "class_name", "") or ""
                elif hasattr(obj, "read"):
                    data = obj.read(MAX_EXTRACTED_ARTIFACT_SIZE + 1)
                elif isinstance(obj, bytes):
                    data = obj

                obj_info = {
                    "index": idx,
                    "class_name": obj_class,
                    "size": len(data),
                    "source_path": source_path,
                }

                class_lower = obj_class.lower()
                if any(d in class_lower for d in DANGEROUS_OLE_CLASSES):
                    obj_info["dangerous_class"] = True
                    findings["exploit_indicators"].append(
                        {
                            "type": "dangerous_ole_class",
                            "detail": f"Embedded object #{idx} class '{obj_class}'",
                        }
                    )

                findings["embedded_objects"].append(obj_info)

                if data and len(data) <= MAX_EXTRACTED_ARTIFACT_SIZE:
                    orig_name = getattr(obj, "filename", "") or f"oleobj_{idx}"
                    ext = _guess_artifact_ext(data, orig_name)
                    safe_name = _safe_filename(orig_name, idx, ext)
                    out_path = extract_dir / safe_name
                    self._write_artifact(ctx, out_path, data)

                    art = {
                        "filename": safe_name,
                        "sha256": _sha256_bytes(data),
                        "size": len(data),
                        "source": f"ole_object_{idx}",
                        "path": str(out_path),
                    }
                    findings["extracted_artifacts"].append(art)
                    artifacts.append(art)

                idx += 1
        except Exception as exc:
            findings["errors"].append(f"oleobj extraction error: {exc}")

    def _ole_stream_scan(self, raw: bytes, findings: dict[str, Any]) -> None:
        """Scan raw OLE bytes for Equation Editor CLSID and suspicious streams."""
        # Equation Editor CLSID in binary (little-endian)
        try:
            eq_bytes = (
                struct.pack(
                    "<IHH",
                    0x0002CE02,
                    0x0000,
                    0x0000,
                )
                + b"\xC0\x00\x00\x00\x00\x00\x00\x46"
            )
        except struct.error:
            eq_bytes = b""

        if eq_bytes and eq_bytes in raw:
            findings["exploit_indicators"].append(
                {
                    "type": "equation_editor_clsid_binary",
                    "detail": "Raw OLE stream contains Equation Editor CLSID bytes",
                    "cves": ["CVE-2017-11882", "CVE-2018-0802"],
                }
            )

        # Check for DDE field link
        if b"\x13 DDEAUTO" in raw or b"\x13 DDE " in raw:
            findings["exploit_indicators"].append(
                {
                    "type": "dde_field",
                    "detail": "Document contains DDE / DDEAUTO field code",
                }
            )

        # Check for OLE Package stream name
        if b"\x00P\x00a\x00c\x00k\x00a\x00g\x00e" in raw:
            findings["parser_findings"].append(
                {"type": "ole_package_stream", "detail": "OLE Package stream found"}
            )

    # ------------------------------------------------------------------
    # OOXML analysis (.docx, .xlsx, .pptx)
    # ------------------------------------------------------------------

    def _analyse_ooxml(
        self,
        ctx: StageContext,
        findings: dict[str, Any],
        artifacts: list[dict[str, Any]],
        extract_dir: Path,
    ) -> None:
        """Parse OOXML (ZIP-based Office) for external links, macros, embedded OLE."""
        import zipfile

        file_path = ctx.file_path
        if file_path is None:
            raise FileNotFoundError("File not found")

        if not zipfile.is_zipfile(file_path):
            findings["errors"].append("OOXML file failed ZIP validation")
            return

        dangerous_rels: list[dict[str, str]] = []
        embedded_bins: list[str] = []

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                if "[Content_Types].xml" not in names:
                    findings["errors"].append("OOXML package is missing [Content_Types].xml")
                    return

                # Check for vbaProject.bin → macros present
                for n in names:
                    nl = n.lower()
                    if "vbaproject.bin" in nl:
                        findings["macros"]["found"] = True
                        findings["macros"]["project_present"] = True
                        findings["macros"]["source_status"] = "unavailable"
                        findings["parser_findings"].append(
                            {"type": "ooxml_macro", "detail": f"VBA project found: {n}"}
                        )
                    if nl.endswith(".bin") and ("oleobject" in nl or "embedding" in nl):
                        embedded_bins.append(n)

                # Parse .rels files for external targets
                for n in names:
                    if n.endswith(".rels"):
                        try:
                            with zf.open(n) as rel_stream:
                                rel_bytes = rel_stream.read(1_000_001)
                            if len(rel_bytes) > 1_000_000:
                                findings["errors"].append(
                                    f"Relationship XML exceeds parse limit: {n}"
                                )
                                findings["resource_limited"] = True
                                findings["limit_reason"] = "document_metadata_bytes_limit"
                                continue
                            rels_data = rel_bytes.decode("utf-8", errors="replace")
                            self._scan_rels_xml(rels_data, dangerous_rels, findings)
                        except Exception:
                            pass

                # Extract embedded OLE objects (oleObject*.bin, embedding/*.bin)
                idx = 0
                for bin_name in embedded_bins:
                    if idx >= MAX_EMBEDDED_OBJECTS:
                        break
                    try:
                        info = zf.getinfo(bin_name)
                        if info.file_size > MAX_EXTRACTED_ARTIFACT_SIZE:
                            findings["errors"].append(
                                f"Embedded object exceeds size limit: {bin_name}"
                            )
                            findings["resource_limited"] = True
                            findings["limit_reason"] = "document_embedded_bytes_limit"
                            continue
                        # Reserve declared output before decompressing it into memory.
                        provisional_name = _safe_filename(os.path.basename(bin_name), idx, ".bin")
                        reserve = ctx.reserve_output if ctx else None
                        if reserve:
                            reserve(provisional_name, 1, info.file_size)
                        with zf.open(bin_name) as stream:
                            data = stream.read(MAX_EXTRACTED_ARTIFACT_SIZE + 1)
                    except BudgetExceeded:
                        break
                    except Exception:
                        continue

                    if len(data) > MAX_EXTRACTED_ARTIFACT_SIZE:
                        findings["resource_limited"] = True
                        findings["limit_reason"] = "document_embedded_bytes_limit"
                        continue

                    obj_info = {
                        "index": idx,
                        "zip_path": bin_name,
                        "size": len(data),
                        "is_ole": data[:8] == _OLE_MAGIC,
                    }
                    findings["embedded_objects"].append(obj_info)

                    # Check Equation Editor in embedded OLE
                    if data[:8] == _OLE_MAGIC and (
                        b"Equation" in data[:1024] or b"equation" in data[:1024]
                    ):
                        findings["exploit_indicators"].append(
                            {
                                "type": "equation_editor_ooxml_embed",
                                "detail": f"Embedded OLE '{bin_name}' references Equation Editor",
                                "cves": ["CVE-2017-11882", "CVE-2018-0802"],
                            }
                        )

                    ext = _guess_artifact_ext(data, bin_name)
                    safe_name = _safe_filename(os.path.basename(bin_name), idx, ext)
                    out_path = extract_dir / safe_name
                    self._write_artifact(ctx, out_path, data, budget_origin=provisional_name)

                    art = {
                        "filename": safe_name,
                        "sha256": _sha256_bytes(data),
                        "size": len(data),
                        "source": f"ooxml_embed_{bin_name}",
                        "path": str(out_path),
                        "budget_origin": provisional_name,
                    }
                    findings["extracted_artifacts"].append(art)
                    artifacts.append(art)
                    idx += 1

        except zipfile.BadZipFile as exc:
            findings["errors"].append(f"Bad OOXML ZIP: {exc}")
        except Exception as exc:
            findings["errors"].append(f"OOXML parse error: {exc}")

        if dangerous_rels:
            findings["parser_findings"].append(
                {"type": "dangerous_relationships", "items": dangerous_rels}
            )

    def _scan_rels_xml(
        self,
        rels_xml: str,
        dangerous_rels: list[dict[str, str]],
        findings: dict[str, Any],
    ) -> None:
        """Scan .rels XML for external Target URLs or dangerous types."""
        # Relationship attributes have no defined order. Parse the already bounded
        # XML rather than interpreting examples inside comments as active targets.
        try:
            relationships = ElementTree.fromstring(rels_xml)
        except ElementTree.ParseError as exc:
            findings["errors"].append(f"Relationship XML parse error: {exc}")
            return
        for relationship in relationships:
            if relationship.tag.rsplit("}", 1)[-1] != "Relationship":
                continue
            if relationship.get("TargetMode", "").lower() != "external":
                continue
            target = relationship.get("Target", "")
            if not target:
                continue
            dangerous_rels.append({"target": target, "mode": "External"})
            findings["exploit_indicators"].append(
                {
                    "type": "external_relationship",
                    "detail": f"OOXML external target: {target[:200]}",
                }
            )

        # OLE / ActiveX relationship types
        ole_types = [
            "oleObject",
            "control",
            "activeX",
            "frame",
            "attachedTemplate",
        ]
        for ot in ole_types:
            if ot.lower() in rels_xml.lower():
                findings["parser_findings"].append(
                    {
                        "type": "ooxml_rel_type",
                        "detail": f"Relationship type '{ot}' found",
                    }
                )

    # ------------------------------------------------------------------
    # VBA / macro analysis (OLE + OOXML)
    # ------------------------------------------------------------------

    def _analyse_vba(self, ctx: StageContext, findings: dict[str, Any]) -> None:
        """Extract and inspect VBA macros using olevba."""
        if not HAS_OLEVBA:
            findings["errors"].append("oletools.olevba unavailable — macro analysis skipped")
            return

        try:
            vba = VBA_Parser(str(ctx.file_path))
        except Exception as exc:
            findings["errors"].append(f"VBA_Parser init error: {exc}")
            return

        try:
            if not vba.detect_vba_macros():
                if findings["macros"].get("project_present"):
                    findings["errors"].append(
                        "VBA project part present but no parseable VBA source found"
                    )
                return

            findings["macros"]["found"] = True

            # Collect keyword hits across all modules
            keyword_hits: set[str] = set()

            for vba_filename, stream_path, vba_code_str in vba.extract_macros():
                source_entry: dict[str, Any] = {
                    "stream": stream_path or "",
                    "module": vba_filename or "",
                    "code_length": len(vba_code_str),
                }

                # Check for suspicious keywords
                code_lower = vba_code_str.lower() if vba_code_str else ""
                for kw in SUSPICIOUS_VBA_KEYWORDS:
                    if kw.lower() in code_lower:
                        keyword_hits.add(kw)

                # Auto-exec detection
                auto_exec_patterns = [
                    "autoopen",
                    "auto_open",
                    "autoclose",
                    "auto_close",
                    "autoexec",
                    "document_open",
                    "document_close",
                    "workbook_open",
                ]
                if any(p in code_lower for p in auto_exec_patterns):
                    findings["macros"]["auto_exec"] = True
                    source_entry["auto_exec"] = True

                # Truncate code for storage
                if vba_code_str:
                    source_entry["code_preview"] = vba_code_str[:MAX_MACRO_SOURCE_LEN]

                findings["macros"]["sources"].append(source_entry)

            if findings["macros"]["sources"]:
                findings["macros"]["source_status"] = "parsed"
            else:
                findings["macros"]["source_status"] = "unavailable"
                findings["errors"].append("VBA macros detected but no source could be extracted")

            if keyword_hits:
                findings["macros"]["suspicious"] = True
                findings["suspicious_keywords"] = list(keyword_hits)

            # Use olevba's own analysis for additional indicators
            try:
                results = vba.analyze_macros()
                for kw_type, keyword, description in results:
                    findings["parser_findings"].append(
                        {
                            "type": f"vba_{kw_type}",
                            "keyword": keyword,
                            "description": description,
                        }
                    )
            except Exception:
                pass  # analyze_macros can fail on malformed streams

        finally:
            try:
                vba.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Artifact submission
    # ------------------------------------------------------------------

    async def _submit_artifacts(
        self,
        ctx: StageContext,
        artifacts: list[dict[str, Any]],
    ) -> int:
        """Submit extracted artifacts as sub-jobs with artifact records."""
        settings = getattr(ctx, "analysis_settings", None) or get_settings()
        max_depth = getattr(
            ctx.analysis_services, "max_depth", getattr(settings, "max_job_depth", 3)
        )
        depth = ctx.job.depth if ctx.job else ctx.depth
        if depth >= max_depth:
            log.info("doc_analysis_max_depth_reached", depth=depth)
            return 0

        parent_job_id = str(ctx.job.id) if ctx.job else ctx.job_id
        parent_job_depth = depth
        root_job_id = ctx.root_job_id or ctx.job_id

        # Create root artifact if needed (depth=0 with embedded objects)
        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id

        if not root_artifact_id and ctx.job and artifacts:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path) if ctx.file_path else 0,
                original_filename=ctx.original_filename,
                extraction_source="document-analysis",
                root_job_id=root_job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id
            ctx.root_artifact_id = root_artifact_id
            ctx.artifact_id = root_artifact_id

        services = ctx.analysis_services
        submitter = await InternalJobSubmitter.get_instance() if not services else None
        submitted = 0
        seen_hashes: set[str] = set()
        ancestor_hashes = ctx.ancestor_hashes or set()

        for art_info in artifacts:
            art_path = art_info.get("path", "")
            if not art_path or not os.path.exists(art_path):
                continue

            file_size = os.path.getsize(art_path)
            digest = hashlib.sha256()
            with open(art_path, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    digest.update(chunk)
            file_sha256 = digest.hexdigest()

            original_name = art_info.get(
                "filename", art_info.get("name", os.path.basename(art_path))
            )
            origin_path = art_info.get("origin_path", art_info.get("source", original_name))
            if ctx.root_budget:
                await ctx.root_budget.reserve(
                    art_info.get("budget_key")
                    or reservation_key(ctx.job_id, "document-analysis", original_name),
                    1,
                    file_size,
                )
            cycle = file_sha256 in ancestor_hashes or file_sha256 == ctx.sha256
            duplicate = file_sha256 in seen_hashes
            skip = cycle or duplicate
            seen_hashes.add(file_sha256)

            if services:
                child = await services.submit_child(
                    file_path=art_path,
                    filename=original_name,
                    content_type="application/octet-stream",
                    sha256_hash=file_sha256,
                    file_size=file_size,
                    parent_job_id=parent_job_id,
                    parent_job_depth=parent_job_depth,
                    artifact_id=None,
                    root_artifact_id=root_artifact_id,
                    root_job_id=root_job_id,
                    ancestor_hashes=ancestor_hashes | {ctx.sha256},
                    origin_path=origin_path,
                    extraction_source="document-analysis",
                    archive_type=None,
                )
                if child and not skip:
                    submitted += 1
                continue

            artifact_record = await create_artifact(
                parent_id=parent_artifact_id,
                root_id=root_artifact_id,
                depth=parent_job_depth + 1,
                sha256=file_sha256,
                size=file_size,
                original_filename=original_name,
                origin_path=origin_path,
                extraction_source="document-analysis",
                root_job_id=root_job_id,
                verdict="skipped" if skip else None,
                extraction_note=(
                    "ancestor_cycle"
                    if cycle
                    else "duplicate_within_extraction"
                    if duplicate
                    else None
                ),
            )

            if skip:
                continue

            assert submitter is not None
            sub_job_id = await submitter.submit_subjob(
                file_path=art_path,
                filename=original_name,
                content_type="application/octet-stream",
                sha256_hash=file_sha256,
                file_size=file_size,
                parent_job_id=parent_job_id,
                parent_job_depth=parent_job_depth,
                artifact_id=artifact_record["id"],
                root_artifact_id=root_artifact_id,
                root_job_id=root_job_id,
                ancestor_hashes=ancestor_hashes | {ctx.sha256},
            )
            if sub_job_id:
                submitted += 1

        return submitted

    @staticmethod
    def _write_artifact(
        ctx: StageContext | None,
        path: Path,
        data: bytes,
        *,
        budget_origin: str | None = None,
    ) -> None:
        if len(data) > MAX_EXTRACTED_ARTIFACT_SIZE:
            raise BudgetExceeded("document_embedded_bytes_limit")
        reserve = ctx.reserve_output if ctx else None
        if reserve:
            reserve(budget_origin or path.name, 1, len(data))
        path.write_bytes(data)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _get_mime(ctx: StageContext) -> str:
        """Pull MIME from the file-type stage result."""
        for r in ctx.previous_results:
            if r.stage_name == "file-type":
                mime_type = r.findings.get("mime_type", "")
                return mime_type if isinstance(mime_type, str) else ""
        return ""

    def _result(self, started_at: datetime, status: str, findings: dict[str, Any]) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=[f["filename"] for f in findings.get("extracted_artifacts", [])],
        )
