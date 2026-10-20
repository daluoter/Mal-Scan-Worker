"""Bounded restoration of supported Office embedded payloads.

This module never opens a referenced path or URL. CFB native Package metadata is
an untrusted label; only the bytes inside the current compound file are emitted.
Recognized opaque CONTENTS streams remain unavailable; other application-specific
OLE layouts are outside the declared restoration scope.
"""
from __future__ import annotations

import hashlib
import io
import re
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

import olefile

from malscan_worker.analyzers.office_decryption import _validate_cfb_header
from malscan_worker.budget import BudgetExceeded

MAX_CFB_BYTES = 50 * 1024 * 1024
MAX_STREAMS = 4096
MAX_NATIVE_METADATA = 16 * 1024
MAX_NAME_BYTES = 4096
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
EmitPayload = Callable[[bytes, str, str, dict[str, Any]], None]


def embedded_filename(name: str, data: bytes, index: int) -> str:
    """Keep a harmless basename and recover common content suffixes from bytes."""
    name = re.split(r"[/\\]", name)[-1]
    name = re.sub(r"[\x00-\x1f\x7f:<>|?*]", "_", name).strip(". ")
    name = name.encode("utf-8")[:160].decode("utf-8", errors="ignore") or f"embedded-{index}"
    suffix = ""
    if data.startswith(b"%PDF-"):
        suffix = ".pdf"
    elif data.startswith(OLE_MAGIC):
        suffix = ".bin"
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        # A supplied Office suffix still routes through ZIP/package detection.
        suffix = (
            Path(name).suffix
            if Path(name).suffix.lower() in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
            else ".zip"
        )
    elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
        suffix = ".7z"
    elif data.startswith(b"MZ") and len(data) > 64:
        suffix = ".exe"
    if suffix:
        if not name.lower().endswith(suffix.lower()):
            name = str(Path(name).with_suffix(suffix))
    elif not Path(name).suffix:
        name += ".bin"
    return name


def _native_payload(data: bytes, maximum_bytes: int) -> tuple[bytes, str]:
    """Parse the bounded embedded (not linked) Ole10Native layout strictly."""
    if len(data) < 6:
        raise ValueError("ole_native_truncated")
    declared, flags = struct.unpack_from("<IH", data)
    if declared != len(data) - 4:
        raise ValueError("ole_native_size_mismatch")
    if flags != 2:
        raise ValueError("ole_native_variant_unsupported")
    cursor = 6

    def terminated() -> bytes:
        nonlocal cursor
        end = data.find(b"\0", cursor, min(len(data), cursor + MAX_NAME_BYTES + 1))
        if end < 0:
            raise ValueError("ole_native_metadata_invalid")
        value = data[cursor:end]
        cursor = end + 1
        if cursor > MAX_NATIVE_METADATA:
            raise ValueError("ole_native_metadata_invalid")
        return value

    filename = terminated().decode("cp1252", errors="replace")
    terminated()  # original source path is not accessed or returned
    if cursor + 8 > len(data):
        raise ValueError("ole_native_truncated")
    cursor += 8
    terminated()  # temporary source path is not accessed or returned
    if cursor == len(data):
        raise ValueError("ole_native_linked_not_embedded")
    if cursor + 4 > len(data):
        raise ValueError("ole_native_truncated")
    size = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    if size > maximum_bytes:
        raise BudgetExceeded("document_embedded_bytes_limit")
    if len(data) - cursor != size:
        raise ValueError("ole_native_payload_size_mismatch")
    return data[cursor:], filename


def extract_ole_payloads(
    file_path: Path,
    *,
    maximum_bytes: int,
    maximum_objects: int,
    reserve: Callable[[str, int, int], None] | None,
    emit: EmitPayload,
) -> dict[str, Any]:
    """Restore Ole10Native and raw Package streams, retaining per-stream outcomes."""
    coverage: dict[str, Any] = {
        "scope": "cfb_ole10native_and_package_streams_v1",
        "status": "complete",
        "candidates": 0,
        "extracted": 0,
        "unavailable": 0,
        "items": [],
    }

    def unavailable(item: dict[str, Any], reason: str) -> None:
        item.update(status="unavailable", reason=reason)
        coverage["status"] = "partial"
        coverage["unavailable"] += 1

    try:
        with file_path.open("rb") as input_stream:
            raw = input_stream.read(MAX_CFB_BYTES + 1)
        if len(raw) > MAX_CFB_BYTES:
            raise BudgetExceeded("document_input_bytes_limit")
        _validate_cfb_header(raw)
        with olefile.OleFileIO(io.BytesIO(raw)) as ole:
            paths = ole.listdir(streams=True, storages=False)
            if len(paths) > MAX_STREAMS or any(len(path) > 32 for path in paths):
                raise BudgetExceeded("document_ole_stream_count_limit")
            normalized = [tuple(component.casefold() for component in path) for path in paths]
            if len(normalized) != len(set(normalized)):
                raise ValueError("ole_stream_names_ambiguous")
            candidates = [
                path
                for path in paths
                if path and path[-1].casefold() in {"\x01ole10native", "package", "contents"}
            ]
            coverage["candidates"] = len(candidates)
            legacy_main_streams = {"worddocument", "workbook", "book", "powerpoint document"}
            if not candidates and not any(
                len(path) == 1 and path[0].casefold() in legacy_main_streams for path in paths
            ):
                coverage.update(status="partial", reason="ole_payload_layout_unsupported")
            for index, path in enumerate(candidates):
                native = path[-1].casefold() == "\x01ole10native"
                supported = native or path[-1].casefold() == "package"
                kind = "native" if native else "package" if supported else "unsupported"
                source = f"ole-{kind}/{index}"
                item: dict[str, Any] = {
                    "source": source,
                    "stream_path": [component.replace("\x01", "\\u0001") for component in path],
                    "kind": "Ole10Native" if native else "Package" if supported else "CONTENTS",
                }
                coverage["items"].append(item)
                if not supported:
                    unavailable(item, "ole_application_payload_unsupported")
                    continue
                if index >= maximum_objects:
                    unavailable(item, "document_embedded_object_count_limit")
                    continue
                try:
                    size = ole.get_size(path)
                    if size < 0 or size > len(raw):
                        raise ValueError("ole_stream_size_invalid")
                    if size > maximum_bytes + (MAX_NATIVE_METADATA if native else 0):
                        raise BudgetExceeded("document_embedded_bytes_limit")
                    # OleFileIO eagerly materializes an uncompressed CFB stream;
                    # physical input and the declared stream size are bounded first.
                    if not native and reserve:
                        reserve(source, 1, size)
                    with ole.openstream(path) as stream:
                        data = stream.read(size + 1)
                    if len(data) != size:
                        raise ValueError("ole_stream_truncated")
                    if native:
                        data, name = _native_payload(data, maximum_bytes)
                    else:
                        name = f"embedded-package-{index}"
                    if reserve:
                        reserve(source, 1, len(data))
                    item["original_filename"] = name
                    name = embedded_filename(name, data, index)
                    digest = hashlib.sha256(data).hexdigest()
                    emit(data, name, source, dict(item))
                    item.update(status="extracted", filename=name, size=len(data), sha256=digest)
                    coverage["extracted"] += 1
                except BudgetExceeded as exc:
                    unavailable(item, exc.reason)
                    # An exhausted shared budget cannot recover by changing stream.
                    if exc.reason.startswith(("root_", "analysis_")):
                        break
                except ValueError as exc:
                    reason = str(exc)
                    unavailable(item, reason if reason.startswith("ole_") else "ole_stream_invalid")
                except Exception:
                    unavailable(item, "ole_stream_unavailable")
    except BudgetExceeded as exc:
        coverage.update(status="partial", reason=exc.reason)
    except Exception:
        coverage.update(status="partial", reason="ole_container_unavailable")
    return coverage


def ooxml_embedding_candidates(
    archive: Any,
) -> tuple[list[tuple[Any, list[str]]], dict[str, Any]]:
    """Find embedding-directory members and internal package/oleObject targets.

    Only normalized, unambiguous ZIP members are used. Relationship references
    to one member are aliases, not additional recovered files.
    """
    import posixpath
    from urllib.parse import unquote, urlsplit
    from xml.etree import ElementTree

    coverage: dict[str, Any] = {
        "scope": "ooxml_embedding_members_and_relationship_targets_v1",
        "status": "complete",
        "candidates": 0,
        "extracted": 0,
        "unavailable": 0,
        "items": [],
    }

    def problem(reason: str) -> None:
        coverage["status"] = "partial"
        coverage.setdefault("errors", []).append(reason)

    members = archive.infolist()
    if len(members) > MAX_STREAMS:
        problem("document_zip_member_count_limit")
        return [], coverage
    mapping: dict[str, Any] = {}
    folded: set[str] = set()
    for info in members:
        name = info.filename
        if info.is_dir():
            continue
        if (
            not name
            or name.startswith("/")
            or "\\" in name
            or any(ord(char) < 32 for char in name)
            or ":" in name
            or len(name) > 1024
            or len(name.split("/")) > 32
            or posixpath.normpath(name) != name
            or name.startswith("../")
        ):
            problem("document_zip_member_path_invalid")
            continue
        folded_name = name.casefold()
        if folded_name in folded:
            problem("document_zip_member_names_ambiguous")
        folded.add(folded_name)
        mapping[name] = info
    if "document_zip_member_names_ambiguous" in coverage.get("errors", []):
        return [], coverage

    aliases: dict[str, list[str]] = {}
    for name in mapping:
        segments = name.lower().split("/")
        if (
            len(segments) >= 3
            and segments[0] in {"word", "xl", "ppt"}
            and segments[1] == "embeddings"
        ):
            aliases[name] = []
        # Preserve the previously supported unconventional oleObject*.bin form.
        elif name.lower().endswith(".bin") and "oleobject" in name.lower():
            aliases[name] = []

    metadata_total = 0
    for name, info in mapping.items():
        if not name.endswith(".rels"):
            continue
        try:
            if info.file_size > 1_000_000 or metadata_total + info.file_size > 8_000_000:
                raise BudgetExceeded("document_metadata_bytes_limit")
            metadata_total += info.file_size
            with archive.open(info) as stream:
                raw = stream.read(1_000_001)
            if len(raw) != info.file_size or len(raw) > 1_000_000:
                raise ValueError("document_relationships_invalid")
            normalized = raw.replace(b"\0", b"").upper()
            if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
                raise ValueError("document_relationships_unsupported_xml")
            root = ElementTree.fromstring(raw)
            namespace = "{http://schemas.openxmlformats.org/package/2006/relationships}"
            if root.tag != namespace + "Relationships":
                raise ValueError("document_relationships_namespace_invalid")
            stack = [(root, 0)]
            nodes = 0
            while stack:
                element, depth = stack.pop()
                nodes += 1
                if nodes > MAX_STREAMS or depth > 32:
                    raise BudgetExceeded("document_relationship_count_limit")
                stack.extend((child, depth + 1) for child in element)
            if any(child.tag != namespace + "Relationship" or len(child) for child in root):
                raise ValueError("document_relationships_structure_invalid")
            if name == "_rels/.rels":
                directory = ""
            elif "/_rels/" in name:
                directory, rest = name.rsplit("/_rels/", 1)
                if "/" in rest:
                    raise ValueError("document_relationships_path_invalid")
            else:
                # Not an OPC relationship part. It remains a package member.
                continue
            for index, relationship in enumerate(root):
                kind = relationship.attrib.get("Type", "").rsplit("/", 1)[-1]
                if kind not in {"package", "oleObject"}:
                    continue
                reference = f"{name}#{index}"
                target = relationship.attrib.get("Target", "")
                mode = relationship.attrib.get("TargetMode", "Internal")
                if mode == "External":
                    coverage["items"].append(
                        {
                            "relationship": reference,
                            "status": "unavailable",
                            "reason": "office_embedded_external_not_fetched",
                        }
                    )
                    coverage["unavailable"] += 1
                    problem("office_embedded_external_not_fetched")
                    continue
                uri = urlsplit(target)
                decoded = unquote(uri.path)
                if (
                    mode != "Internal"
                    or not target
                    or uri.scheme
                    or uri.netloc
                    or uri.query
                    or uri.fragment
                    or "\\" in decoded
                    or ":" in decoded
                    or any(ord(char) < 32 for char in decoded)
                    or re.search(r"%(?:2f|5c)", target, re.IGNORECASE)
                ):
                    problem("document_embedded_relationship_invalid")
                    continue
                resolved = posixpath.normpath(
                    decoded.lstrip("/")
                    if decoded.startswith("/")
                    else posixpath.join(directory, decoded)
                )
                if resolved.startswith("../") or resolved in {".", ".."}:
                    problem("document_embedded_relationship_invalid")
                    continue
                if resolved not in mapping:
                    coverage["items"].append(
                        {
                            "relationship": reference,
                            "status": "unavailable",
                            "reason": "office_embedded_target_missing",
                        }
                    )
                    coverage["unavailable"] += 1
                    problem("office_embedded_target_missing")
                    continue
                aliases.setdefault(resolved, []).append(reference)
        except BudgetExceeded as exc:
            problem(exc.reason)
        except Exception:
            problem("document_relationships_invalid")
    coverage["candidates"] = len(aliases)
    return [(mapping[name], references) for name, references in aliases.items()], coverage
