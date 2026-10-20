"""PDF format analyzer."""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pypdf import PdfReader

from malscan_worker.analyzers.base import (
    AnalyzerIndicator,
    AnalyzerResult,
    FormatAnalyzer,
    JsonValue,
)
from malscan_worker.analyzers.pdf_attachments import extract_pdf_attachments
from malscan_worker.analyzers.pdf_decryption import decrypt_to_child
from malscan_worker.budget import BudgetExceeded
from malscan_worker.config import get_settings
from malscan_worker.exceptions import DocumentPasswordRequiredError, DocumentWrongPasswordError
from malscan_worker.extractors.process import run_parser_bounded
from malscan_worker.heuristics.pdf import build_pdf_heuristics

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageContext


_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024

_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

_PDF_MAGIC_RE = re.compile(rb"^(?:\xef\xbb\xbf)?[\t\n\r\f ]*%PDF-")
_OBJ_RE = re.compile(rb"\b\d+\s+\d+\s+obj\b")
_STREAM_RE = re.compile(rb"\bstream\b")
_OBFUSCATED_NAME_RE = re.compile(rb"/([A-Za-z0-9]+(?:#[0-9A-Fa-f]{2})+[A-Za-z0-9#]*)")
_FILTER_NAME_RE = re.compile(
    rb"/(FlateDecode|LZWDecode|ASCII85Decode|ASCIIHexDecode|RunLengthDecode|CCITTFaxDecode|DCTDecode|JPXDecode|JBIG2Decode|Crypt)\b",
    re.IGNORECASE,
)
_ACTION_JAVASCRIPT_RE = re.compile(rb"/S\s*/JavaScript\b")
_ACTION_LAUNCH_RE = re.compile(rb"/S\s*/Launch\b")
_OPEN_ACTION_RE = re.compile(rb"/OpenAction\b")
_WIN_LAUNCH_TARGET_RE = re.compile(r"/Win\s*<<\s*/F\s*\(([^)]*)\)\s*>>", re.IGNORECASE | re.DOTALL)
_FILESPEC_LAUNCH_TARGET_RE = re.compile(
    r"/F\s*<<\s*/F\s*\(([^)]*)\)\s*>>", re.IGNORECASE | re.DOTALL
)
_DIRECT_LAUNCH_TARGET_RE = re.compile(r"/F\s*\(([^)]*)\)", re.IGNORECASE | re.DOTALL)

_SUSPICIOUS_URI_PREFIXES = (
    "javascript:",
    "file:",
    "cmd:",
    "powershell:",
)

_EXECUTABLE_SUFFIXES = (
    ".exe",
    ".dll",
    ".com",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".scr",
    ".ps1",
    ".jar",
)


class PDFAnalyzer(FormatAnalyzer):
    """Analyze PDFs for active content and suspicious structures."""

    @property
    def name(self) -> str:
        return "pdf"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        del file_path
        if mime.lower() == "application/pdf":
            return True
        return _PDF_MAGIC_RE.match(magic) is not None

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        result = AnalyzerResult(analyzer_name=self.name, format_type="PDF")

        try:
            file_size = file_path.stat().st_size
        except OSError:
            result.errors.append("failed to stat PDF file")
            return result

        if file_size > _MAX_FILE_SIZE_BYTES:
            result.errors.append("PDF analysis skipped: file exceeds 50MB limit")
            return result

        settings = getattr(ctx, "analysis_settings", None) or get_settings()
        maximum_bytes = min(
            _MAX_FILE_SIZE_BYTES,
            settings.extraction_max_single_bytes,
            settings.extraction_max_bytes,
        )
        max_depth = getattr(ctx.analysis_services, "max_depth", settings.max_job_depth)
        depth = ctx.job.depth if ctx.job else ctx.depth
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ctx.job_id) is None:
            result.errors.append("PDF working directory unavailable")
            return result
        parent = Path("/tmp") / ctx.job_id / "pdf_artifacts"
        try:
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            work = Path(tempfile.mkdtemp(prefix="decrypt-", dir=parent))
        except OSError:
            result.errors.append("PDF working directory unavailable")
            return result
        retain = False
        try:

            def parse(reserve: Callable[[str, int, int], None]) -> AnalyzerResult:
                with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
                    return self._analyze_sync(
                        file_path,
                        password=ctx.archive_password,
                        output_path=work / "decrypted.pdf",
                        reserve=reserve,
                        maximum_bytes=maximum_bytes,
                        maximum_files=settings.extraction_max_files,
                        job_id=ctx.job_id,
                        depth_limited=depth >= max_depth,
                    )

            try:
                result = await run_parser_bounded(
                    parse,
                    root_budget=ctx.root_budget,
                    job_id=ctx.job_id,
                    source="format-analysis",
                    timeout_seconds=settings.extraction_timeout,
                )
            except BudgetExceeded as exc:
                result.features = {
                    "resource_limited": True,
                    "limit_reason": exc.reason,
                }
                result.errors = [exc.reason]
            except Exception:
                result.errors = ["PDF parser unavailable or failed"]
            access = result.features.get("content_access")
            if access == "password_required":
                raise DocumentPasswordRequiredError("pdf")
            if access == "wrong_password":
                raise DocumentWrongPasswordError("pdf")
            # HeuristicHit contains immutable mapping proxies. Build those from
            # the bounded parser's plain features after crossing the IPC boundary.
            result.heuristics = build_pdf_heuristics(result.features)
            retain = bool(result.extracted_artifacts)
            return result
        finally:
            if not retain:
                shutil.rmtree(work, ignore_errors=True)

    def _analyze_sync(
        self,
        file_path: Path,
        *,
        password: str | None,
        output_path: Path,
        reserve: Callable[[str, int, int], None],
        maximum_bytes: int,
        maximum_files: int,
        job_id: str,
        depth_limited: bool,
    ) -> AnalyzerResult:
        result = AnalyzerResult(analyzer_name=self.name, format_type="PDF")
        features = self._empty_features()

        # Hostile parser diagnostics can include file contents. Keep the parser
        # child's logging channel private and return only sanitized diagnostics.
        parser_log = logging.getLogger("pypdf")
        parser_log.handlers = [logging.NullHandler()]
        parser_log.propagate = False

        try:
            with file_path.open("rb") as source:
                raw = source.read(_MAX_FILE_SIZE_BYTES + 1)
            if len(raw) > _MAX_FILE_SIZE_BYTES:
                raise BudgetExceeded("document_input_bytes_limit")
        except OSError:
            result.errors.append("failed to read PDF file")
            result.features = features
            return result

        self._scan_raw_features(raw, features, include_action_tokens=False)

        parser_ok = False
        reader_available = False
        try:
            reader = PdfReader(io.BytesIO(raw))
            reader_available = True
            features["encrypted"] = bool(getattr(reader, "is_encrypted", False))
            if features["encrypted"]:
                decryption = decrypt_to_child(
                    reader,
                    password=password,
                    output_path=output_path,
                    reserve=reserve,
                    maximum_bytes=maximum_bytes,
                    job_id=job_id,
                    depth_limited=depth_limited,
                )
                features["content_access"] = decryption.access
                features["encryption"] = decryption.encryption
                if decryption.object_coverage:
                    features["decryption_object_coverage"] = decryption.object_coverage
                    if decryption.object_coverage.get("status") != "complete":
                        result.errors.append(
                            "PDF object preservation incomplete: "
                            "unreadable or ambiguous xref objects"
                        )
                if decryption.artifact is not None:
                    result.extracted_artifacts = [decryption.artifact]
                    features["decrypted_child"] = {
                        "sha256": decryption.artifact["sha256"],
                        "size": decryption.artifact["size"],
                    }
            else:
                self._scan_structured(reader, features)
                attachments = extract_pdf_attachments(
                    reader,
                    output_dir=output_path.parent,
                    reserve=reserve,
                    maximum_bytes=maximum_bytes,
                    maximum_files=maximum_files,
                    job_id=job_id,
                    depth_limited=depth_limited,
                )
                result.extracted_artifacts.extend(attachments.artifacts)
                features["embedded_files"] = attachments.entries
                features["attachment_extraction"] = attachments.summary(
                    maximum_bytes, maximum_files
                )
                result.errors.extend(attachments.errors)
                if attachments.limited:
                    features["resource_limited"] = True
                    features["limit_reason"] = attachments.limit_reason
            parser_ok = True
        except BudgetExceeded as exc:
            features["resource_limited"] = True
            features["limit_reason"] = exc.reason
            features["content_access"] = "unavailable"
            result.errors = [exc.reason]
        except Exception:
            if not reader_available:
                features["encrypted"] = None
            features["content_access"] = "unavailable"
            result.errors.append("failed to parse PDF file: corrupt or unsupported PDF data")
            self._scan_raw_features(raw, features, include_action_tokens=True)

        indicators = self._build_indicators(features)
        result.features = features
        result.indicators = indicators
        result.risk_score = self._calculate_risk_score(indicators)
        result.risk_factors = [str(ind.get("type", "")) for ind in indicators if ind.get("type")]

        if not parser_ok and not result.errors:
            result.errors.append("failed to parse PDF file")

        return result

    def _scan_structured(self, reader: PdfReader, features: dict[str, JsonValue]) -> None:
        header = str(getattr(reader, "pdf_header", ""))
        if header.startswith("%PDF-"):
            features["version"] = header.removeprefix("%PDF-")

        features["encrypted"] = bool(getattr(reader, "is_encrypted", False))
        pages = list(getattr(reader, "pages", []))
        features["page_count"] = len(pages)

        root = self._resolve_indirect(getattr(reader, "trailer", {}).get("/Root"))
        if isinstance(root, dict):
            self._scan_root(root, features)

        annotations = self._as_int(features.get("annotations"), default=0)
        for page in pages:
            page_obj = self._resolve_indirect(page)
            if not isinstance(page_obj, dict):
                continue

            annots = self._resolve_indirect(page_obj.get("/Annots"))
            if isinstance(annots, list):
                annotations += len(annots)
                for annot in annots:
                    annot_obj = self._resolve_indirect(annot)
                    if isinstance(annot_obj, dict):
                        self._scan_action_container(annot_obj, features)

            self._scan_action_container(page_obj, features)

        features["annotations"] = annotations

        try:
            fields = reader.get_fields()
            features["form_fields"] = len(fields) if isinstance(fields, dict) else 0
        except Exception:
            pass

    def _scan_root(self, root: dict[str, Any], features: dict[str, JsonValue]) -> None:
        self._scan_action_container(root, features)

    def _scan_action_container(
        self, container: dict[str, Any], features: dict[str, JsonValue]
    ) -> None:
        direct_action = self._resolve_indirect(container.get("/A"))
        if isinstance(direct_action, dict):
            self._scan_action_dict(direct_action, features, from_open=False)

        open_action = self._resolve_indirect(container.get("/OpenAction"))
        if isinstance(open_action, dict):
            self._scan_action_dict(open_action, features, from_open=True)

        additional = self._resolve_indirect(container.get("/AA"))
        if isinstance(additional, dict):
            for key in ("/O", "/OpenAction", "/E", "/X", "/D", "/U"):
                nested = self._resolve_indirect(additional.get(key))
                if isinstance(nested, dict):
                    self._scan_action_dict(
                        nested,
                        features,
                        from_open=key in {"/O", "/OpenAction"},
                    )

    def _scan_action_dict(
        self,
        action: dict[str, Any],
        features: dict[str, JsonValue],
        *,
        from_open: bool,
    ) -> None:
        action_type = self._stringify(action.get("/S"))
        if not action_type:
            return

        open_actions = self._as_list(features["open_actions"])
        if from_open:
            open_actions.append(action_type)
        features["open_actions"] = self._dedupe_strings(open_actions)

        if action_type == "/Launch":
            launch_target = self._extract_launch_target(action)
            launch_actions = self._as_list(features["launch_actions"])
            launch_actions.append(launch_target or "launch")
            features["launch_actions"] = self._dedupe_strings(launch_actions)

        if action_type == "/JavaScript":
            js_payload = self._stringify(action.get("/JS"))
            js_code = self._as_list(features["js_code"])
            if js_payload:
                js_code.append(js_payload)
            else:
                js_code.append("javascript-action")
            features["js_code"] = self._dedupe_strings(js_code)

        if action_type == "/URI":
            uri = self._stringify(action.get("/URI"))
            if uri:
                uri_actions = self._as_list(features["uri_actions"])
                uri_actions.append(uri)
                features["uri_actions"] = self._dedupe_strings(uri_actions)

        if action_type == "/GoToR":
            names = self._as_list(features["suspicious_names"])
            names.append("/GoToR")
            features["suspicious_names"] = self._dedupe_strings(names)

    def _scan_raw_features(
        self,
        raw: bytes,
        features: dict[str, JsonValue],
        *,
        include_action_tokens: bool,
    ) -> None:
        text_l = raw.decode("latin-1", errors="ignore")

        version_match = re.search(r"%PDF-(\d\.\d)", text_l)
        if version_match and not features.get("version"):
            features["version"] = version_match.group(1)

        features["object_count"] = len(_OBJ_RE.findall(raw))

        stream_count = len(_STREAM_RE.findall(raw))
        filter_names = [
            "/" + match.decode("ascii", errors="ignore") for match in _FILTER_NAME_RE.findall(raw)
        ]
        features["stream_info"] = {
            "stream_count": stream_count,
            "filter_count": len(filter_names),
            "filters": self._dedupe_strings(filter_names),
            "has_object_stream": "/ObjStm" in text_l,
        }

        if include_action_tokens:
            if _ACTION_JAVASCRIPT_RE.search(raw):
                js_code = self._as_list(features["js_code"])
                if not js_code:
                    js_code.append("javascript-action-token")
                features["js_code"] = self._dedupe_strings(js_code)

            if _ACTION_LAUNCH_RE.search(raw):
                launch_actions = self._as_list(features["launch_actions"])
                raw_targets: list[str] = []
                win_targets = [
                    target.strip()
                    for target in _WIN_LAUNCH_TARGET_RE.findall(text_l)
                    if target.strip()
                ]
                filespec_targets = [
                    target.strip()
                    for target in _FILESPEC_LAUNCH_TARGET_RE.findall(text_l)
                    if target.strip()
                ]
                direct_targets = [
                    target.strip()
                    for target in _DIRECT_LAUNCH_TARGET_RE.findall(text_l)
                    if target.strip()
                ]
                preferred_targets = win_targets or filespec_targets or direct_targets
                raw_targets.extend(preferred_targets)
                launch_actions.extend(raw_targets or ["/Launch"])
                features["launch_actions"] = self._dedupe_strings(launch_actions)

            if _OPEN_ACTION_RE.search(raw):
                open_actions = self._as_list(features["open_actions"])
                open_actions.append("/OpenAction")
                features["open_actions"] = self._dedupe_strings(open_actions)

            uri_actions = self._as_list(features["uri_actions"])
            uri_actions.extend(re.findall(r"/URI\s*\(([^)]*)\)", text_l))
            features["uri_actions"] = self._dedupe_strings(uri_actions)

        obfuscated_names = [
            "/" + match.decode("ascii", errors="ignore")
            for match in _OBFUSCATED_NAME_RE.findall(raw)
        ]
        suspicious_names = self._as_list(features["suspicious_names"])
        suspicious_names.extend(obfuscated_names)

        for token in ("/XFA", "/GoToR", "/ObjStm", "/URI", "/JavaScript", "/Launch"):
            if token in text_l:
                suspicious_names.append(token)

        features["suspicious_names"] = self._dedupe_strings(suspicious_names)

    def _build_indicators(self, features: dict[str, JsonValue]) -> list[AnalyzerIndicator]:
        indicators: list[AnalyzerIndicator] = []

        launch_actions = self._as_list(features["launch_actions"])
        if launch_actions:
            indicators.append(
                {
                    "type": "launch_action",
                    "severity": "critical",
                    "detail": "Launch action detected in PDF",
                    "evidence": launch_actions,
                }
            )

        js_code = self._as_list(features["js_code"])
        if js_code:
            indicators.append(
                {
                    "type": "embedded_javascript",
                    "severity": "high",
                    "detail": "Embedded JavaScript detected",
                    "evidence": js_code,
                }
            )

        open_actions = self._as_list(features["open_actions"])
        if open_actions:
            indicators.append(
                {
                    "type": "auto_open_action",
                    "severity": "high",
                    "detail": "Automatic open action detected",
                    "evidence": open_actions,
                }
            )

        embedded_files = self._as_list(features["embedded_files"])
        executable_embeds: list[JsonValue] = []
        for item in embedded_files:
            if not isinstance(item, dict):
                continue
            item_dict = item
            if bool(item_dict.get("executable")):
                executable_embeds.append(item_dict)
        if executable_embeds:
            indicators.append(
                {
                    "type": "embedded_file_executable",
                    "severity": "high",
                    "detail": "Embedded executable-like attachment found",
                    "evidence": executable_embeds,
                }
            )

        suspicious_names = self._as_list(features["suspicious_names"])
        obfuscated: list[JsonValue] = [str(name) for name in suspicious_names if "#" in str(name)]
        if obfuscated:
            indicators.append(
                {
                    "type": "name_obfuscation",
                    "severity": "medium",
                    "detail": "Obfuscated PDF name tokens detected",
                    "evidence": obfuscated,
                }
            )

        stream_info = features.get("stream_info")
        if isinstance(stream_info, dict):
            stream_count = self._as_int(stream_info.get("stream_count"), default=0)
            filter_count = self._as_int(stream_info.get("filter_count"), default=0)
            if filter_count >= 12 or (stream_count > 0 and filter_count > (stream_count * 2)):
                indicators.append(
                    {
                        "type": "excessive_stream_filters",
                        "severity": "medium",
                        "detail": "Unusually high stream filter usage",
                        "evidence": {
                            "stream_count": stream_count,
                            "filter_count": filter_count,
                        },
                    }
                )

            if (
                bool(stream_info.get("has_object_stream"))
                and self._as_int(features.get("object_count"), default=0) <= 1
            ):
                indicators.append(
                    {
                        "type": "object_stream_anomaly",
                        "severity": "low",
                        "detail": "Object stream token seen with very low object count",
                        "evidence": {
                            "object_count": self._as_int(features.get("object_count"), default=0),
                            "has_object_stream": True,
                        },
                    }
                )

        if any(name == "/XFA" for name in suspicious_names):
            indicators.append(
                {
                    "type": "xfa_form",
                    "severity": "medium",
                    "detail": "XFA form marker detected",
                    "evidence": ["/XFA"],
                }
            )

        if any(name == "/GoToR" for name in suspicious_names):
            indicators.append(
                {
                    "type": "goto_remote",
                    "severity": "medium",
                    "detail": "GoToR remote navigation action detected",
                    "evidence": ["/GoToR"],
                }
            )

        uri_actions = self._as_list(features["uri_actions"])
        suspicious_uris: list[JsonValue] = []
        for uri in uri_actions:
            uri_s = str(uri)
            uri_l = uri_s.lower()
            if uri_l.startswith(_SUSPICIOUS_URI_PREFIXES) or uri_l.endswith(_EXECUTABLE_SUFFIXES):
                suspicious_uris.append(uri_s)
        if suspicious_uris:
            indicators.append(
                {
                    "type": "suspicious_uri",
                    "severity": "medium",
                    "detail": "Suspicious URI scheme or target detected",
                    "evidence": self._dedupe_strings(suspicious_uris),
                }
            )

        return indicators

    def _calculate_risk_score(self, indicators: list[AnalyzerIndicator]) -> int:
        score = 0
        for indicator in indicators:
            severity = str(indicator.get("severity", ""))
            score += _SEVERITY_WEIGHTS.get(severity, 0)
        return min(score, 100)

    def _extract_launch_target(self, action: dict[str, Any]) -> str:
        nested_win = self._resolve_indirect(action.get("/Win"))
        if isinstance(nested_win, dict):
            win_target = self._stringify(nested_win.get("/F"))
            if win_target:
                return win_target

        launch_target = self._resolve_indirect(action.get("/F"))
        if isinstance(launch_target, dict):
            nested_target = self._stringify(launch_target.get("/F"))
            if nested_target:
                return nested_target

        return self._stringify(action.get("/F"))

    @staticmethod
    def _resolve_indirect(value: Any) -> Any:
        try:
            getter = getattr(value, "get_object", None)
            if callable(getter):
                return getter()
        except Exception:
            return value
        return value

    @staticmethod
    def _stringify(value: Any) -> str:
        resolved = PDFAnalyzer._resolve_indirect(value)
        if resolved is None:
            return ""
        if isinstance(resolved, bytes):
            return resolved.decode("latin-1", errors="ignore")
        return str(resolved)

    @staticmethod
    def _as_list(value: JsonValue) -> list[JsonValue]:
        if isinstance(value, list):
            return list(value)
        return []

    @staticmethod
    def _dedupe_strings(values: list[Any]) -> list[JsonValue]:
        seen: set[str] = set()
        result: list[JsonValue] = []
        for value in values:
            item = str(value)
            if item in seen:
                continue
            seen.add(item)
            result.append(item)
        return result

    @staticmethod
    def _as_int(value: JsonValue | None, *, default: int) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return default
        return default

    @staticmethod
    def _empty_features() -> dict[str, JsonValue]:
        return {
            "version": None,
            "page_count": 0,
            "encrypted": False,
            "object_count": 0,
            "js_code": [],
            "launch_actions": [],
            "open_actions": [],
            "uri_actions": [],
            "embedded_files": [],
            "annotations": 0,
            "form_fields": 0,
            "stream_info": {
                "stream_count": 0,
                "filter_count": 0,
                "filters": [],
                "has_object_stream": False,
            },
            "suspicious_names": [],
        }
