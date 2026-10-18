"""Bounded PDF plaintext serialization, called only in the parser child process."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, cast

from pypdf import PdfReader, PdfWriter
from pypdf.generic import IndirectObject, StreamObject

from malscan_worker.analyzers.base import AnalyzerArtifact, JsonValue
from malscan_worker.budget import BudgetExceeded, reservation_key

_ORIGIN = "pdf-decrypted"
_MAX_OBJECTS = 100_000
_CRYPT_METHODS = frozenset({"/Identity", "/V2", "/AESV2", "/AESV3"})


@dataclass
class DecryptedPDF:
    access: str
    encryption: dict[str, JsonValue]
    artifact: AnalyzerArtifact | None = None
    object_coverage: dict[str, JsonValue] = field(default_factory=dict)


def _require_supported_crypt_filters(reader: PdfReader) -> None:
    """Reject a filter combination the pinned parser does not decrypt faithfully.

    pypdf 4.x resolves and validates filter names when constructing its encryption
    handler, but decrypts every stream using StmF, including EmbeddedFile streams.
    A distinct EFF method can therefore leave ciphertext or corrupt clear content
    without raising an error. Check resolved methods, allowing aliases of the same
    supported filter, before prompting for a password or serializing any child.
    """
    encryption = getattr(reader, "_encryption", None)
    methods = [getattr(encryption, field, None) for field in ("StmF", "StrF", "EFF")]
    if any(not isinstance(method, str) or method not in _CRYPT_METHODS for method in methods):
        raise NotImplementedError("Unsupported PDF crypt filters")
    if methods[0] != methods[2]:
        raise NotImplementedError("Unsupported PDF embedded-file crypt filter")
    # The same pinned decryptor also applies StmF to metadata streams even when
    # the handler explicitly leaves them clear, corrupting their serialized data.
    if getattr(encryption, "EncryptMetadata", None) is not True:
        raise NotImplementedError("Unsupported PDF metadata crypt settings")


def _active_xref_entries(reader: PdfReader) -> set[tuple[int, int]]:
    entries: set[tuple[int, int]] = set()
    for generation, offsets in reader.xref.items():
        for number in offsets:
            if number:
                entries.add((number, generation))
            if len(entries) > _MAX_OBJECTS:
                raise BudgetExceeded("pdf_object_count_limit")
    for number in reader.xref_objStm:
        entries.add((number, 0))
        if len(entries) > _MAX_OBJECTS:
            raise BudgetExceeded("pdf_object_count_limit")
    return entries


def _require_supported_stream_crypt_filters(reader: PdfReader) -> None:
    """Explicit Crypt overrides are also ignored by the pinned stream decryptor.

    Inspect active objects before cloning. Unreadable objects remain accounted as
    partial by preservation; a readable explicit Crypt stream must never become
    a supposedly complete but incorrectly decrypted plaintext child.
    """
    for number, generation in sorted(_active_xref_entries(reader)):
        try:
            obj = reader.get_object(IndirectObject(number, generation, reader))
        except Exception:
            continue
        if not isinstance(obj, StreamObject):
            continue
        filters = obj.get("/Filter")
        if isinstance(filters, IndirectObject):
            filters = filters.get_object()
        if filters is None:
            continue
        items = filters if isinstance(filters, list) else [filters]
        for item in items:
            if isinstance(item, IndirectObject):
                item = item.get_object()
            if not isinstance(item, str):
                raise NotImplementedError("Unsupported PDF stream filter data")
            if item == "/Crypt":
                raise NotImplementedError("Unsupported explicit PDF stream crypt filter")


def _preserve_xref_objects(reader: PdfReader, writer: PdfWriter) -> dict[str, JsonValue]:
    """Retain active xref objects outside the catalog graph for static scanners.

    A catalog clone alone silently discards unreferenced streams. Include objects
    in compressed-object indexes as well. An unreadable or ambiguous generation
    remains an explicit coverage limitation rather than a complete-content claim.
    """
    entries = _active_xref_entries(reader)
    encryption_reference = (
        reader.trailer.raw_get("/Encrypt") if "/Encrypt" in reader.trailer else None
    )
    generations: dict[int, int] = {}
    unreadable = 0
    preserved = 0
    structural = 0
    for number, generation in sorted(entries):
        # pypdf 4.x clone translation indexes by object number. Conflicting
        # generations cannot be represented faithfully through that mapping.
        if number in generations and generations[number] != generation:
            unreadable += 1
            continue
        generations[number] = generation
        # Encryption dictionaries and xref streams are unencrypted structural
        # metadata already scanned in the original. Do not inject stale crypto
        # parameters into the rewritten child; retain all content stream objects.
        if (
            isinstance(encryption_reference, IndirectObject)
            and number == encryption_reference.idnum
            and generation == encryption_reference.generation
        ):
            structural += 1
            continue
        try:
            reference = IndirectObject(number, generation, reader)
            obj = reader.get_object(reference)
            if obj is None:
                unreadable += 1
                continue
            if isinstance(obj, dict) and obj.get("/Type") == "/XRef":
                structural += 1
                continue
            reference.clone(writer)
            preserved += 1
        except Exception:
            unreadable += 1
    return {
        "scope": "active_xref_objects",
        "status": "partial" if unreadable else "complete",
        "indexed_objects": len(entries),
        "preserved_objects": preserved,
        "structural_objects_omitted": structural,
        "unreadable_or_ambiguous_objects": unreadable,
    }


class _ReservedOutput:
    """Charge a single output's high-water size before every writer operation."""

    def __init__(
        self,
        stream: BinaryIO,
        reserve: Callable[[str, int, int], None],
        maximum_bytes: int,
    ):
        self.stream = stream
        self.reserve = reserve
        self.maximum_bytes = maximum_bytes
        self.high_water = 0

    def write(self, data: bytes) -> int:
        proposed = max(self.high_water, self.stream.tell() + len(data))
        if proposed > self.maximum_bytes:
            raise BudgetExceeded("document_output_bytes_limit")
        self.reserve(_ORIGIN, 1, proposed)
        written = self.stream.write(data)
        self.high_water = max(self.high_water, self.stream.tell())
        return written

    def tell(self) -> int:
        return self.stream.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.stream.seek(offset, whence)

    def flush(self) -> None:
        self.stream.flush()


def encryption_metadata(reader: PdfReader) -> dict[str, JsonValue]:
    """Keep algorithm descriptors, never encryption keys or password-derived data."""
    encryption = reader.trailer.get("/Encrypt")
    resolve = getattr(encryption, "get_object", None)
    if callable(resolve):
        encryption = resolve()
    if not isinstance(encryption, dict):
        return {}
    result: dict[str, JsonValue] = {
        "filter": "Standard" if encryption.get("/Filter") == "/Standard" else "unsupported"
    }
    for source, destination in (("/V", "version"), ("/R", "revision"), ("/Length", "key_bits")):
        value = encryption.get(source)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4096:
            result[destination] = value
    return result


def decrypt_to_child(
    reader: PdfReader,
    *,
    password: str | None,
    output_path: Path,
    reserve: Callable[[str, int, int], None],
    maximum_bytes: int,
    job_id: str,
    depth_limited: bool,
) -> DecryptedPDF:
    """Unlock a supported PDF and emit one catalog-preserving plaintext child.

    The caller owns the process deadline and removes the private working directory
    after every unsuccessful, interrupted, or canceled operation.
    """
    metadata = encryption_metadata(reader)
    _require_supported_crypt_filters(reader)
    if depth_limited:
        raise BudgetExceeded("max_depth")
    if not reader.decrypt(""):
        if password is None:
            return DecryptedPDF("password_required", metadata)
        if not reader.decrypt(password):
            return DecryptedPDF("wrong_password", metadata)
    _require_supported_stream_crypt_filters(reader)
    writer = PdfWriter()
    # append_pages_from_reader loses catalog actions, attachment name trees and
    # additional document structures. Clone the complete document graph instead.
    writer.clone_document_from_reader(reader)
    coverage = _preserve_xref_objects(reader, writer)
    reserve(_ORIGIN, 1, 0)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        target = _ReservedOutput(stream, reserve, maximum_bytes)
        writer.write(cast(Any, target))
        target.flush()
        os.fsync(stream.fileno())
    digest = hashlib.sha256()
    size = 0
    with output_path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            size += len(chunk)
            digest.update(chunk)
    artifact: AnalyzerArtifact = {
        "filename": "decrypted.pdf",
        "source": _ORIGIN,
        "path": str(output_path),
        "sha256": digest.hexdigest(),
        "size": size,
    }
    # AnalyzerArtifact's runtime contract already supports this shared budget
    # identity for embedded-document extraction and downstream submission.
    cast(dict[str, Any], artifact)["budget_key"] = reservation_key(
        job_id, "format-analysis", _ORIGIN
    )
    return DecryptedPDF("decrypted_child", metadata, artifact, coverage)
