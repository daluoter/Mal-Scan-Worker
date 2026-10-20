"""Extract bounded PDF embedded-file streams without eager pypdf decoding.

Only catalog EmbeddedFiles name trees, catalog/page associated files and page
FileAttachment annotations are declared. External file references are observations,
never network requests. Unfiltered and single Flate streams without predictors
are supported; other encodings stay explicitly incomplete.
"""
from __future__ import annotations

import hashlib
import os
import re
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pypdf.generic import IndirectObject, NullObject, StreamObject

from malscan_worker.analyzers.base import AnalyzerArtifact, JsonValue
from malscan_worker.budget import BudgetExceeded, reservation_key

_MAX_ATTACHMENTS = 30
_MAX_OUTPUT_BYTES = 20 * 1024 * 1024
_MAX_NODES = 4096
_MAX_TREE_DEPTH = 32
_CHUNK_SIZE = 65536
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
_SCOPE = [
    "catalog_embedded_files_name_tree",
    "catalog_page_associated_files",
    "file_attachment_annotations",
]


class AttachmentError(ValueError):
    """A sanitized, non-secret extraction outcome."""


@dataclass
class AttachmentExtraction:
    artifacts: list[AnalyzerArtifact] = field(default_factory=list)
    entries: list[JsonValue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limited: bool = False
    limit_reason: str | None = None

    def summary(self, maximum_bytes: int, maximum_files: int) -> dict[str, JsonValue]:
        return {
            "status": "partial" if self.errors else "complete",
            "scope": list(_SCOPE),
            "discovered_files": len(self.entries),
            "extracted_files": len(self.artifacts),
            "limits": {
                "files": min(_MAX_ATTACHMENTS, maximum_files),
                "single_bytes": min(_MAX_OUTPUT_BYTES, maximum_bytes),
                "traversal_nodes": _MAX_NODES,
                "name_tree_depth": _MAX_TREE_DEPTH,
            },
        }


def _resolve(value: Any) -> Any:
    try:
        getter = getattr(value, "get_object", None)
        return getter() if callable(getter) else value
    except Exception as exc:
        raise AttachmentError("malformed") from exc


def _identity(value: Any) -> tuple[object, ...]:
    if isinstance(value, IndirectObject):
        return ("indirect", value.idnum, value.generation)
    resolved = _resolve(value)
    reference = getattr(resolved, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return ("indirect", reference.idnum, reference.generation)
    return ("direct", id(resolved))


def _name(value: Any, default: str) -> str:
    value = _resolve(value)
    if isinstance(value, bytes):
        value = value[:1024].decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return default
    return re.sub(r"[\x00-\x1f\x7f]", "_", value[:256]) or default


def _safe_filename(name: str, index: int) -> str:
    leaf = name.replace("\\", "/").split("/")[-1]
    leaf = re.sub(r"[\x00-\x1f\x7f/:]", "_", leaf).strip(". ")
    return (
        leaf.encode("utf-8")[:180].decode("utf-8", errors="ignore") or f"attachment-{index:04d}.bin"
    )


def _filters(stream: StreamObject) -> str:
    if any(key in stream for key in ("/F", "/FFilter", "/FDecodeParms")):
        raise AttachmentError("external_reference")
    filters = _resolve(stream.get("/Filter"))
    if filters is None or isinstance(filters, NullObject):
        filters = []
    elif not isinstance(filters, list):
        filters = [filters]
    if len(filters) > 1:
        raise AttachmentError("unsupported_filter")
    if not filters:
        return "identity"
    if _resolve(filters[0]) not in ("/FlateDecode", "/Fl"):
        raise AttachmentError("unsupported_filter")
    params = _resolve(stream.get("/DecodeParms"))
    if isinstance(params, list):
        if len(params) != 1:
            raise AttachmentError("unsupported_filter")
        params = _resolve(params[0])
    if params is not None and not isinstance(params, NullObject):
        if not isinstance(params, dict):
            raise AttachmentError("malformed")
        if _resolve(params.get("/Predictor", 1)) != 1:
            raise AttachmentError("unsupported_filter")
    return "flate"


def _decoded_chunks(raw: bytes, codec: str, maximum_bytes: int) -> Iterator[bytes]:
    """Never allocate more than one 64KiB decoded chunk at a time."""
    total = 0
    if codec == "identity":
        if len(raw) > maximum_bytes:
            raise BudgetExceeded("pdf_attachment_bytes_limit")
        for offset in range(0, len(raw), _CHUNK_SIZE):
            yield raw[offset : offset + _CHUNK_SIZE]
        return
    decoder = zlib.decompressobj()
    try:
        for offset in range(0, len(raw), _CHUNK_SIZE):
            pending = raw[offset : offset + _CHUNK_SIZE]
            while pending:
                chunk = decoder.decompress(pending, min(_CHUNK_SIZE, maximum_bytes - total + 1))
                total += len(chunk)
                if total > maximum_bytes:
                    raise BudgetExceeded("pdf_attachment_bytes_limit")
                if chunk:
                    yield chunk
                if decoder.eof:
                    trailing = decoder.unused_data + raw[offset + _CHUNK_SIZE :]
                    if trailing.strip(b"\x00\t\n\r\f "):
                        raise AttachmentError("malformed")
                    return
                pending = decoder.unconsumed_tail
        # zlib only buffers an incomplete terminal sequence here, never accept
        # its partial plaintext as a complete attachment.
        if not decoder.eof:
            raise AttachmentError("malformed")
    except zlib.error as exc:
        raise AttachmentError("malformed") from exc


class _Extractor:
    def __init__(
        self,
        output_dir: Path,
        reserve: Callable[[str, int, int], None],
        maximum_bytes: int,
        maximum_files: int,
        job_id: str,
        depth_limited: bool,
    ):
        self.output_dir = output_dir
        self.reserve = reserve
        self.maximum_bytes = min(maximum_bytes, _MAX_OUTPUT_BYTES)
        self.maximum_files = min(maximum_files, _MAX_ATTACHMENTS)
        self.job_id = job_id
        self.depth_limited = depth_limited
        self.result = AttachmentExtraction()
        self.nodes = 0
        self.streams: dict[tuple[object, ...], dict[str, JsonValue]] = {}
        self.specs: dict[tuple[object, ...], list[dict[str, JsonValue]]] = {}

    def error(self, reason: str, *, limited: bool = False) -> None:
        error = f"PDF attachment extraction incomplete: {reason}"
        if error not in self.result.errors:
            self.result.errors.append(error)
        if limited:
            self.result.limited = True
            self.result.limit_reason = reason

    def visit(self, size: int = 1) -> None:
        self.nodes += size
        if self.nodes > _MAX_NODES:
            raise BudgetExceeded("pdf_attachment_traversal_limit")

    def reference(self, entry: dict[str, JsonValue], reference: str) -> None:
        references = entry["references"]
        if isinstance(references, list) and reference not in references:
            if len(references) >= _MAX_NODES:
                raise BudgetExceeded("pdf_attachment_traversal_limit")
            references.append(reference)

    def spec(self, value: Any, reference: str, fallback: str = "") -> None:
        self.visit()
        identity = _identity(value)
        if identity in self.specs:
            for entry in self.specs[identity]:
                self.reference(entry, reference)
            return
        if len(self.result.entries) >= self.maximum_files:
            raise BudgetExceeded("pdf_attachment_count_limit")
        resolved = _resolve(value)
        name = fallback or f"attachment-{len(self.result.entries):04d}.bin"
        if isinstance(resolved, dict):
            name = _name(resolved.get("/UF", resolved.get("/F")), name)
        elif isinstance(resolved, (str, bytes)):
            name = _name(resolved, name)
        base: dict[str, JsonValue] = {
            "name": _safe_filename(name, len(self.result.entries)),
            "source": f"pdf-attachment/{len(self.result.entries):04d}",
            "references": [reference],
            "extraction_status": "missing_stream",
            "executable": name.lower().endswith(_EXECUTABLE_SUFFIXES),
        }
        if not isinstance(resolved, dict):
            self.specs[identity] = [base]
            self.result.entries.append(base)
            base["extraction_status"] = (
                "external_reference" if isinstance(resolved, str) else "malformed"
            )
            self.error(str(base["extraction_status"]))
            return
        ef = _resolve(resolved.get("/EF"))
        if not isinstance(ef, dict) or not ef:
            self.specs[identity] = [base]
            self.result.entries.append(base)
            base["extraction_status"] = (
                "external_reference" if resolved.get("/FS") == "/URL" else "missing_stream"
            )
            self.error(str(base["extraction_status"]))
            return
        if len(ef) > 8:
            raise BudgetExceeded("pdf_attachment_traversal_limit")
        entries: list[dict[str, JsonValue]] = []
        self.specs[identity] = entries
        keys = [key for key in ("/UF", "/F", "/DOS", "/Mac", "/Unix") if key in ef]
        keys += [key for key in ef if key not in keys]
        for key in keys:
            stream_ref = ef.get(key)
            stream_identity = _identity(stream_ref)
            if stream_identity in self.streams:
                entry = self.streams[stream_identity]
                self.reference(entry, reference)
                if entry not in entries:
                    entries.append(entry)
                continue
            if len(self.result.entries) >= self.maximum_files:
                raise BudgetExceeded("pdf_attachment_count_limit")
            entry = dict(base)
            entry["source"] = f"pdf-attachment/{len(self.result.entries):04d}"
            entry["references"] = [reference]
            entry["stream_key"] = _name(key, "/F")
            self.streams[stream_identity] = entry
            entries.append(entry)
            self.result.entries.append(entry)
            try:
                self.extract(stream_ref, entry)
            except BudgetExceeded as exc:
                entry["extraction_status"] = "resource_limited"
                entry["reason"] = exc.reason
                self.error(exc.reason, limited=True)
                if exc.reason.startswith("root_") or exc.reason == "analysis_attempt_deadline":
                    raise
            except AttachmentError as exc:
                entry["extraction_status"] = str(exc)
                self.error(str(exc))
            except Exception:
                entry["extraction_status"] = "malformed"
                self.error("malformed")

    def extract(self, reference: Any, entry: dict[str, JsonValue]) -> None:
        if self.depth_limited:
            raise BudgetExceeded("max_depth")
        stream = _resolve(reference)
        if not isinstance(stream, StreamObject):
            raise AttachmentError("missing_stream")
        codec = _filters(stream)
        raw = getattr(stream, "_data", None)
        if not isinstance(raw, bytes):
            raise AttachmentError("malformed")
        # Count first with bounded transient chunks. This preflight cannot retain
        # attacker-sized plaintext. Reserve the exact final size before the
        # second decode creates the output, preserving root high-water accounting.
        size = sum(len(chunk) for chunk in _decoded_chunks(raw, codec, self.maximum_bytes))
        origin = str(entry["source"])
        self.reserve(origin, 1, size)
        path = self.output_dir / f"{origin.rsplit('/', 1)[-1]}-{entry['name']}"
        digest = hashlib.sha256()
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                for chunk in _decoded_chunks(raw, codec, self.maximum_bytes):
                    target.write(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        entry.update({"extraction_status": "extracted", "size": size, "sha256": digest.hexdigest()})
        self.result.artifacts.append(
            {
                "filename": str(entry["name"]),
                "source": origin,
                "path": str(path),
                "size": size,
                "sha256": digest.hexdigest(),
                "budget_key": reservation_key(self.job_id, "format-analysis", origin),
            }
        )

    def associated(self, container: dict[str, Any], reference: str) -> None:
        if "/AF" not in container:
            return
        values = _resolve(container.get("/AF"))
        if not isinstance(values, list):
            self.error("malformed_associated_files")
            return
        self.visit(len(values))
        for index, value in enumerate(values):
            self.spec(value, f"{reference}/AF/{index:04d}")

    def tree(self, value: Any, reference: str, ancestors: set[tuple[object, ...]]) -> None:
        self.visit()
        if len(ancestors) >= _MAX_TREE_DEPTH:
            raise BudgetExceeded("pdf_attachment_name_tree_depth_limit")
        identity = _identity(value)
        if identity in ancestors:
            self.error("cyclic_name_tree")
            return
        node = _resolve(value)
        if not isinstance(node, dict):
            self.error("malformed_name_tree")
            return
        if "/Names" in node:
            values = _resolve(node.get("/Names"))
            if not isinstance(values, list):
                self.error("malformed_name_tree")
            else:
                self.visit(len(values))
                if len(values) % 2:
                    self.error("malformed_name_tree")
                for index in range(0, len(values) - 1, 2):
                    self.spec(
                        values[index + 1],
                        f"{reference}/Names/{index // 2:04d}",
                        _name(values[index], ""),
                    )
        if "/Kids" in node:
            kids = _resolve(node.get("/Kids"))
            if not isinstance(kids, list):
                self.error("malformed_name_tree")
            else:
                self.visit(len(kids))
                for index, child in enumerate(kids):
                    self.tree(child, f"{reference}/Kids/{index:04d}", ancestors | {identity})


def extract_pdf_attachments(
    reader: Any,
    *,
    output_dir: Path,
    reserve: Callable[[str, int, int], None],
    maximum_bytes: int,
    maximum_files: int,
    job_id: str,
    depth_limited: bool,
) -> AttachmentExtraction:
    """Extract declared attachment occurrences and retain successful partial work."""
    extractor = _Extractor(output_dir, reserve, maximum_bytes, maximum_files, job_id, depth_limited)
    try:
        root = _resolve(getattr(reader, "trailer", {}).get("/Root"))
        if not isinstance(root, dict):
            extractor.error("malformed_catalog")
            return extractor.result
        names = _resolve(root.get("/Names"))
        if "/Names" in root and not isinstance(names, dict):
            extractor.error("malformed_name_dictionary")
        if isinstance(names, dict) and "/EmbeddedFiles" in names:
            extractor.tree(names.get("/EmbeddedFiles"), "catalog/Names/EmbeddedFiles", set())
        extractor.associated(root, "catalog")
        for page_index, page in enumerate(getattr(reader, "pages", [])):
            extractor.visit()
            page_obj = _resolve(page)
            if not isinstance(page_obj, dict):
                extractor.error("malformed_page")
                continue
            page_path = f"page/{page_index:04d}"
            extractor.associated(page_obj, page_path)
            annots = _resolve(page_obj.get("/Annots"))
            if not isinstance(annots, list):
                if "/Annots" in page_obj:
                    extractor.error("malformed_annotations")
                continue
            extractor.visit(len(annots))
            for index, annotation in enumerate(annots):
                annotation = _resolve(annotation)
                if not isinstance(annotation, dict):
                    extractor.error("malformed_annotation")
                if isinstance(annotation, dict) and annotation.get("/Subtype") == "/FileAttachment":
                    extractor.spec(annotation.get("/FS"), f"{page_path}/Annots/{index:04d}/FS")
    except BudgetExceeded as exc:
        extractor.error(exc.reason, limited=True)
    except AttachmentError:
        extractor.error("malformed")
    except Exception:
        extractor.error("malformed")
    return extractor.result
