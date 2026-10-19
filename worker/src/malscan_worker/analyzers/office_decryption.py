"""Bounded, password-only Office package decryption without document conversion.

Only an authenticated Agile package or a CRC-checked Standard package becomes a
child. All OLE, crypto and ZIP parsing runs in the killable parser process.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import logging
import os
import re
import shutil
import stat
import struct
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast
from xml.etree import ElementTree

from malscan_worker.analyzers.base import AnalyzerArtifact, AnalyzerResult, JsonValue
from malscan_worker.budget import BudgetExceeded, reservation_key
from malscan_worker.config import get_settings
from malscan_worker.exceptions import DocumentPasswordRequiredError, DocumentWrongPasswordError
from malscan_worker.extractors.process import run_parser_bounded

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageContext

_ORIGIN = "office-decrypted"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MAX_INPUT_BYTES = 50 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_MAX_XML_BYTES = 1024 * 1024
_MAX_MAIN_XML_BYTES = 20 * 1024 * 1024
_MAX_ZIP_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_MEMBERS = 4096
_MAX_SPIN_COUNT = 1_000_000
_ENCRYPTION_NS = "http://schemas.microsoft.com/office/2006/encryption"
_PASSWORD_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
_CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_RELATIONSHIP_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_HASH_SIZES = {"SHA256": 32, "SHA384": 48, "SHA512": 64}
_MAIN_CONTENT_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": "docx",
    "application/vnd.ms-word.document.macroEnabled.main+xml": "docm",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": "dotx",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml": "dotm",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": "xlsx",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml": "xlsm",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": "xltx",
    "application/vnd.ms-excel.template.macroEnabled.main+xml": "xltm",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": "pptx",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml": "pptm",
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": "potx",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml": "potm",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": "ppsx",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml": "ppsm",
}


class _UnsupportedOfficeEncryptionError(Exception):
    pass


def is_office_encrypted_candidate(file_path: Path) -> bool:
    """Cheap routing only; inspect encryption streams inside the bounded child."""
    try:
        with file_path.open("rb") as source:
            return source.read(8) == _OLE_MAGIC
    except OSError:
        return False


def _validate_cfb_header(raw: bytes) -> None:
    """Bound header-driven FAT allocation before handing bytes to olefile."""
    if len(raw) < 512 or raw[:8] != _OLE_MAGIC:
        raise ValueError("Invalid compound file header")
    major, byte_order, shift, mini_shift = struct.unpack_from("<4H", raw, 26)
    if byte_order != 0xFFFE or (major, shift) not in {(3, 9), (4, 12)} or mini_shift != 6:
        raise ValueError("Unsupported compound file geometry")
    sector_size = 1 << shift
    if len(raw) < sector_size or len(raw) % sector_size:
        raise ValueError("Truncated compound file")
    sectors = len(raw) // sector_size - 1
    directory_count, fat_count = struct.unpack_from("<2I", raw, 40)
    mini_fat_count = struct.unpack_from("<I", raw, 64)[0]
    difat_count = struct.unpack_from("<I", raw, 72)[0]
    entries = sector_size // 4
    maximum_fat = (sectors + entries - 1) // entries
    maximum_difat = (max(0, fat_count - 109) + entries - 2) // (entries - 1)
    if (
        not 1 <= fat_count <= maximum_fat
        or mini_fat_count > sectors
        or directory_count > sectors
        or (major == 3 and directory_count != 0)
        or difat_count > maximum_difat
    ):
        raise ValueError("Invalid compound file allocation counts")


def _parse_xml(data: bytes, maximum: int) -> ElementTree.Element:
    if len(data) > maximum:
        raise BudgetExceeded("office_xml_bytes_limit")
    # ElementTree does not fetch external entities. Also reject DTDs before
    # parsing to prevent internal entity expansion, including UTF-16/32 XML.
    normalized = data.replace(b"\0", b"").upper()
    if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
        raise ValueError("XML declarations unsupported")
    root = ElementTree.fromstring(data)
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_MEMBERS or depth > 32:
            raise BudgetExceeded("office_xml_structure_limit")
        pending.extend((child, depth + 1) for child in node)
    return root


def _integer(node: ElementTree.Element, name: str, allowed: set[int]) -> int:
    text = node.get(name, "")
    if re.fullmatch(r"[0-9]{1,10}", text) is None:
        raise ValueError("Invalid crypto size")
    value = int(text)
    if value not in allowed:
        raise _UnsupportedOfficeEncryptionError
    return value


def _binary(node: ElementTree.Element, name: str, size: int) -> bytes:
    value = node.get(name, "")
    if len(value) > 512:
        raise ValueError("Invalid crypto data")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid crypto encoding") from None
    if len(decoded) != size:
        raise ValueError("Invalid crypto size")
    return decoded


def _agile_parameters(node: ElementTree.Element, *, password: bool) -> tuple[str, int]:
    if node.get("cipherAlgorithm") != "AES" or node.get("cipherChaining") != "ChainingModeCBC":
        raise _UnsupportedOfficeEncryptionError
    _integer(node, "saltSize", {16})
    _integer(node, "blockSize", {16})
    bits = _integer(node, "keyBits", {128, 192, 256} if password else {128, 256})
    algorithm = node.get("hashAlgorithm", "")
    if algorithm not in _HASH_SIZES:
        # The pinned parser silently falls back to SHA1 for unknown names and
        # cannot verify SHA1's padded verifier hash. Neither is safe to accept.
        raise _UnsupportedOfficeEncryptionError
    _integer(node, "hashSize", {_HASH_SIZES[algorithm]})
    _binary(node, "saltValue", 16)
    return algorithm, bits


def _validate_encryption_info(data: bytes) -> dict[str, JsonValue]:
    if len(data) < 8 or len(data) > _MAX_METADATA_BYTES:
        raise ValueError("Invalid EncryptionInfo size")
    major, minor, flags = struct.unpack_from("<HHI", data)
    if (major, minor) == (4, 4):
        if flags != 0x40:
            raise _UnsupportedOfficeEncryptionError
        root = _parse_xml(data[8:], _MAX_METADATA_BYTES)
        if root.tag != f"{{{_ENCRYPTION_NS}}}encryption":
            raise _UnsupportedOfficeEncryptionError
        # msoffcrypto resolves several nodes by unqualified tag name. Require
        # exactly the normal namespace layout so it cannot choose another node.
        key_data = root.findall(f"{{{_ENCRYPTION_NS}}}keyData")
        integrity = root.findall(f"{{{_ENCRYPTION_NS}}}dataIntegrity")
        encryptors = root.findall(f"{{{_ENCRYPTION_NS}}}keyEncryptors")
        if len(key_data) != 1 or len(integrity) != 1 or len(encryptors) != 1:
            raise ValueError("Invalid encryption descriptor")
        if len(root) != 3 or len(encryptors[0]) != 1:
            raise _UnsupportedOfficeEncryptionError
        encryptor = encryptors[0][0]
        if (
            encryptor.tag != f"{{{_ENCRYPTION_NS}}}keyEncryptor"
            or encryptor.get("uri") != _PASSWORD_NS
            or len(encryptor) != 1
            or encryptor[0].tag != f"{{{_PASSWORD_NS}}}encryptedKey"
        ):
            raise _UnsupportedOfficeEncryptionError
        password_node = encryptor[0]
        # The library uses minidom's unprefixed tag lookup for these nodes.
        # Reject alternate prefixes rather than allowing validation/parser drift.
        if any(b"<" + name not in data for name in (b"keyData", b"dataIntegrity")):
            raise _UnsupportedOfficeEncryptionError
        if any(len(node) for node in (key_data[0], integrity[0], password_node)):
            raise ValueError("Invalid encryption descriptor")
        algorithm, bits = _agile_parameters(key_data[0], password=False)
        password_algorithm, password_bits = _agile_parameters(password_node, password=True)
        spin_text = password_node.get("spinCount", "")
        if re.fullmatch(r"[0-9]{1,10}", spin_text) is None:
            raise ValueError("Invalid spin count")
        spins = int(spin_text)
        if spins > _MAX_SPIN_COUNT:
            raise BudgetExceeded("office_spin_count_limit")
        if spins < 1:
            raise ValueError("Invalid spin count")
        digest_size = _HASH_SIZES[algorithm]
        verifier_size = _HASH_SIZES[password_algorithm]
        _binary(integrity[0], "encryptedHmacKey", digest_size)
        _binary(integrity[0], "encryptedHmacValue", digest_size)
        _binary(password_node, "encryptedVerifierHashInput", 16)
        _binary(password_node, "encryptedVerifierHashValue", verifier_size)
        _binary(password_node, "encryptedKeyValue", bits // 8)
        return {
            "scheme": "agile",
            "cipher": "AES-CBC",
            "key_bits": bits,
            "hash": algorithm,
            "password_key_bits": password_bits,
            "password_hash": password_algorithm,
            "spin_count": spins,
            "integrity": "hmac_required",
        }
    if minor != 2 or major not in {2, 3, 4}:
        raise _UnsupportedOfficeEncryptionError
    if len(data) < 12:
        raise ValueError("Invalid standard header")
    header_size = struct.unpack_from("<I", data, 8)[0]
    if header_size < 32 or header_size > 4096 or header_size % 2:
        raise ValueError("Invalid standard header size")
    if len(data) != 12 + header_size + 72:
        raise ValueError("Invalid standard verifier size")
    (
        header_flags,
        extra,
        algorithm,
        hash_algorithm,
        bits,
        provider,
        reserved1,
        reserved2,
    ) = struct.unpack_from("<8I", data, 12)
    if (
        flags != 0x24
        or header_flags != flags
        or extra
        or reserved1
        or reserved2
        or hash_algorithm != 0x8004
        or provider != 24
        or {0x660E: 128, 0x660F: 192, 0x6610: 256}.get(algorithm) != bits
    ):
        raise _UnsupportedOfficeEncryptionError
    data[44 : 12 + header_size].decode("utf-16le")
    verifier = 12 + header_size
    if struct.unpack_from("<I", data, verifier)[0] != 16:
        raise ValueError("Invalid standard salt")
    if struct.unpack_from("<I", data, verifier + 36)[0] != 20:
        raise ValueError("Invalid standard verifier")
    return {
        "scheme": "standard",
        "cipher": "AES-ECB",
        "key_bits": bits,
        "hash": "SHA1",
        "spin_count": 50_000,
        "integrity": "zip_crc_only_no_authenticated_integrity",
    }


class _ReservedOutput:
    """Reserve the output high-water mark before writing plaintext to disk."""

    def __init__(self, stream: BinaryIO, reserve: Callable[[str, int, int], None], maximum: int):
        self.stream, self.reserve, self.maximum = stream, reserve, maximum
        self.high_water = 0

    def write(self, data: bytes) -> int:
        proposed = max(self.high_water, self.stream.tell() + len(data))
        if proposed > self.maximum:
            raise BudgetExceeded("document_output_bytes_limit")
        self.reserve(_ORIGIN, 1, proposed)
        written = self.stream.write(data)
        self.high_water = max(self.high_water, self.stream.tell())
        return written


def _part_name(name: str) -> str:
    if (
        not name
        or len(name) > 1024
        or "\\" in name
        or "\0" in name
        or name.startswith("/")
        or len(name.split("/")) > 32
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("Invalid package part name")
    return name


def _validate_main_xml(archive: zipfile.ZipFile, name: str, extension: str) -> None:
    """Validate the actual Office XML root with bounded streaming parsing."""
    if extension in {"docx", "docm", "dotx", "dotm"}:
        family, local_name = "wordprocessingml", "document"
    elif extension in {"xlsx", "xlsm", "xltx", "xltm"}:
        family, local_name = "spreadsheetml", "workbook"
    else:
        family, local_name = "presentationml", "presentation"
    allowed_roots = {
        f"{{http://schemas.openxmlformats.org/{family}/2006/main}}{local_name}",
        f"{{http://purl.oclc.org/ooxml/{family}/main}}{local_name}",
    }
    if archive.getinfo(name).file_size > _MAX_MAIN_XML_BYTES:
        raise BudgetExceeded("office_main_xml_bytes_limit")
    parser = ElementTree.XMLPullParser(events=("start", "end"))
    tail = b""
    count = depth = total = 0
    with archive.open(name) as source:
        while chunk := source.read(65536):
            total += len(chunk)
            if total > _MAX_MAIN_XML_BYTES:
                raise BudgetExceeded("office_main_xml_bytes_limit")
            normalized = tail + chunk.replace(b"\0", b"").upper()
            if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
                raise ValueError("Office XML declarations unsupported")
            tail = normalized[-32:]
            parser.feed(chunk)
            for item in parser.read_events():
                event, node = cast(tuple[str, ElementTree.Element], item)
                if event == "start":
                    if count == 0 and node.tag not in allowed_roots:
                        raise ValueError("Invalid Office main XML root")
                    count += 1
                    depth += 1
                    if count > 250_000 or depth > 256:
                        raise BudgetExceeded("office_main_xml_structure_limit")
                else:
                    depth -= 1
                    node.clear()
    parser.close()
    if count == 0 or depth:
        raise ValueError("Invalid Office main XML")


def _validate_package(path: Path, maximum_expanded: int) -> str:
    """Read every member through its CRC, then derive type from OPC metadata."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > _MAX_MEMBERS:
            raise BudgetExceeded("office_zip_member_limit")
        names: set[str] = set()
        file_names: set[str] = set()
        expanded = 0
        metadata: dict[str, bytes] = {}
        for member in members:
            name = _part_name(member.filename.rstrip("/") if member.is_dir() else member.filename)
            folded = name.casefold()
            if folded in names or member.flag_bits & 1 or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError("Ambiguous package member")
            names.add(folded)
            if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise _UnsupportedOfficeEncryptionError
            if member.is_dir():
                continue
            file_names.add(folded)
            expanded += member.file_size
            if expanded > maximum_expanded:
                raise BudgetExceeded("office_zip_expanded_bytes_limit")
            capture = name in {"[Content_Types].xml", "_rels/.rels"}
            if capture and member.file_size > _MAX_XML_BYTES:
                raise BudgetExceeded("office_xml_bytes_limit")
            content = bytearray()
            actual = 0
            with archive.open(member) as source:
                while chunk := source.read(65536):
                    actual += len(chunk)
                    if actual > member.file_size or actual > maximum_expanded:
                        raise BudgetExceeded("office_zip_expanded_bytes_limit")
                    if capture:
                        content.extend(chunk)
            if actual != member.file_size:
                raise ValueError("Truncated package member")
            if capture:
                metadata[name] = bytes(content)
        if len(metadata) != 2:
            raise ValueError("Missing package metadata")
        types = _parse_xml(metadata["[Content_Types].xml"], _MAX_XML_BYTES)
        if types.tag != f"{{{_CONTENT_NS}}}Types":
            raise ValueError("Invalid package content types")
        main_parts: list[tuple[str, str]] = []
        overrides: set[str] = set()
        for node in types:
            if node.tag == f"{{{_CONTENT_NS}}}Override":
                part = node.get("PartName", "")
                if not part.startswith("/"):
                    raise ValueError("Invalid content-type part")
                part = _part_name(part[1:])
                if part.casefold() in overrides or part.casefold() not in file_names:
                    raise ValueError("Missing or duplicate content-type part")
                overrides.add(part.casefold())
                extension = _MAIN_CONTENT_TYPES.get(node.get("ContentType", ""))
                if extension:
                    main_parts.append((part, extension))
            elif node.tag != f"{{{_CONTENT_NS}}}Default":
                raise ValueError("Invalid content-type entry")
        if len(main_parts) != 1:
            raise _UnsupportedOfficeEncryptionError
        if archive.getinfo(main_parts[0][0]).file_size == 0:
            raise ValueError("Empty Office main part")
        relationships = _parse_xml(metadata["_rels/.rels"], _MAX_XML_BYTES)
        if relationships.tag != f"{{{_RELATIONSHIP_NS}}}Relationships":
            raise ValueError("Invalid package relationships")
        if any(node.tag != f"{{{_RELATIONSHIP_NS}}}Relationship" for node in relationships):
            raise ValueError("Invalid package relationship")
        office_relationships = [
            node
            for node in relationships
            if node.get("Type")
            in {
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
                "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument",
            }
        ]
        if len(office_relationships) != 1:
            raise ValueError("Missing Office relationship")
        relation = office_relationships[0]
        if relation.get("TargetMode", "Internal") != "Internal":
            raise ValueError("Invalid Office relationship")
        target = relation.get("Target", "").removeprefix("/")
        if _part_name(target) != main_parts[0][0]:
            raise ValueError("Inconsistent Office content type")
        _validate_main_xml(archive, main_parts[0][0], main_parts[0][1])
        return main_parts[0][1]


def _legacy_encrypted(ole: Any, streams: set[tuple[str, ...]]) -> bool:
    if ("worddocument",) in streams:
        with ole.openstream("WordDocument") as stream:
            header = stream.read(12)
        if len(header) >= 12 and struct.unpack_from("<H", header, 10)[0] & 0x8100:
            return True
    for name in ("Workbook", "Book"):
        if (name.casefold(),) not in streams:
            continue
        with ole.openstream(name) as stream:
            for _ in range(100_000):
                header = stream.read(4)
                if len(header) != 4:
                    break
                record, size = struct.unpack("<HH", header)
                if record == 0x002F:  # BIFF FILEPASS
                    return True
                if len(stream.read(size)) != size:
                    break
            else:
                raise BudgetExceeded("office_record_count_limit")
    if ("current user",) in streams:
        with ole.openstream("Current User") as stream:
            header = stream.read(16)
        if len(header) == 16 and struct.unpack_from("<I", header, 12)[0] == 0xF3D1C4DF:
            return True
    return any("drm" in component.casefold() for path in streams for component in path)


def _load_password_key(document: Any, password: str) -> bool:
    from msoffcrypto.exceptions import InvalidKeyError

    if password:
        try:
            document.load_key(password=password, verify_password=True)
            return True
        except InvalidKeyError:
            return False
    # OOXMLFile.load_key treats an empty string as no key. The crypto methods
    # themselves support it and let empty-password documents open without a wait.
    from msoffcrypto.method.ecma376_agile import ECMA376Agile
    from msoffcrypto.method.ecma376_standard import ECMA376Standard

    info = document.info
    if document.type == "agile":
        valid = ECMA376Agile.verify_password(
            password,
            info["passwordSalt"],
            info["passwordHashAlgorithm"],
            info["encryptedVerifierHashInput"],
            info["encryptedVerifierHashValue"],
            info["spinValue"],
            info["passwordKeyBits"],
        )
        if valid:
            document.secret_key = ECMA376Agile.makekey_from_password(
                password,
                info["passwordSalt"],
                info["passwordHashAlgorithm"],
                info["encryptedKeyValue"],
                info["spinValue"],
                info["passwordKeyBits"],
            )
        return bool(valid)
    header, verifier = info["header"], info["verifier"]
    key = ECMA376Standard.makekey_from_password(
        password,
        header["algId"],
        header["algIdHash"],
        header["providerType"],
        header["keySize"],
        verifier["saltSize"],
        verifier["salt"],
    )
    valid = ECMA376Standard.verifykey(
        key, verifier["encryptedVerifier"], verifier["encryptedVerifierHash"]
    )
    if valid:
        document.secret_key = key
    return bool(valid)


def _analyze_sync(
    file_path: Path,
    *,
    password: str | None,
    output_path: Path,
    reserve: Callable[[str, int, int], None],
    maximum_bytes: int,
    maximum_expanded: int,
    job_id: str,
    depth_limited: bool,
) -> AnalyzerResult | None:
    result = AnalyzerResult(analyzer_name="office", format_type="OFFICE")
    result.features = {"encrypted": None, "content_access": "unavailable"}
    # The library's DEBUG logs include password-derived material. Disable all
    # child logging, including existing handlers, before importing crypto code.
    logging.disable(logging.CRITICAL)
    try:
        import olefile

        with file_path.open("rb") as source:
            raw = source.read(_MAX_INPUT_BYTES + 1)
        if len(raw) > _MAX_INPUT_BYTES:
            raise BudgetExceeded("document_input_bytes_limit")
        _validate_cfb_header(raw)
        # OleStream eagerly buffers a declared stream. Strict FAT/sector checks
        # prevent cyclic chains and bogus lengths from amplifying bounded input.
        with olefile.OleFileIO(io.BytesIO(raw), raise_defects=olefile.DEFECT_INCORRECT) as ole:
            paths = ole.listdir(streams=True, storages=False)
            if len(paths) > _MAX_MEMBERS:
                raise BudgetExceeded("office_ole_stream_limit")
            streams = {tuple(component.casefold() for component in path) for path in paths}
            if len(streams) != len(paths):
                raise ValueError("Ambiguous OLE streams")
            has_info, has_package = ("encryptioninfo",) in streams, ("encryptedpackage",) in streams
            if not has_info and not has_package:
                if not _legacy_encrypted(ole, streams):
                    return None
                result.features["encrypted"] = True
                raise _UnsupportedOfficeEncryptionError
            result.features["encrypted"] = True
            if not has_info or not has_package:
                raise _UnsupportedOfficeEncryptionError
            if ole.get_size("EncryptionInfo") > _MAX_METADATA_BYTES:
                raise BudgetExceeded("office_encryption_metadata_limit")
            with ole.openstream("EncryptionInfo") as stream:
                metadata = _validate_encryption_info(stream.read(_MAX_METADATA_BYTES + 1))
            result.features["encryption"] = metadata
            package_size = ole.get_size("EncryptedPackage")
            if package_size > 8 + (maximum_bytes + 15) // 16 * 16:
                raise BudgetExceeded("document_output_bytes_limit")
            with ole.openstream("EncryptedPackage") as stream:
                header = stream.read(8)
            if len(header) != 8:
                raise ValueError("Missing package header")
            declared_size = struct.unpack("<Q", header)[0]
            if declared_size > maximum_bytes:
                raise BudgetExceeded("document_output_bytes_limit")
            if declared_size < 22 or package_size != 8 + (declared_size + 15) // 16 * 16:
                raise ValueError("Invalid package size")
        if depth_limited:
            raise BudgetExceeded("max_depth")
        if password is not None and len(password) > 1024:
            raise BudgetExceeded("document_password_bytes_limit")
        from msoffcrypto.format.ooxml import OOXMLFile

        document = OOXMLFile(io.BytesIO(raw))
        try:
            if not _load_password_key(document, ""):
                if password is None:
                    result.features["content_access"] = "password_required"
                    return result
                if not _load_password_key(document, password):
                    result.features["content_access"] = "wrong_password"
                    return result
            reserve(_ORIGIN, 1, 0)
            descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                document.decrypt(
                    _ReservedOutput(stream, reserve, maximum_bytes),
                    verify_integrity=metadata["scheme"] == "agile",
                )
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            document.file.close()
        if output_path.stat().st_size != declared_size:
            raise ValueError("Truncated plaintext package")
        extension = _validate_package(output_path, maximum_expanded)
        if metadata["scheme"] == "agile":
            metadata["integrity"] = "hmac_verified"
        child_path = output_path.with_name("decrypted." + extension)
        output_path.rename(child_path)
        digest = hashlib.sha256()
        with child_path.open("rb") as source:
            for chunk in iter(lambda: source.read(65536), b""):
                digest.update(chunk)
        artifact: AnalyzerArtifact = {
            "filename": child_path.name,
            "source": _ORIGIN,
            "path": str(child_path),
            "sha256": digest.hexdigest(),
            "size": declared_size,
            "budget_key": reservation_key(job_id, "format-analysis", _ORIGIN),
        }
        result.extracted_artifacts = [artifact]
        result.features["content_access"] = "decrypted_child"
        result.features["decrypted_child"] = {"sha256": artifact["sha256"], "size": declared_size}
        return result
    except BudgetExceeded as exc:
        result.features.update(
            resource_limited=True, limit_reason=exc.reason, content_access="unavailable"
        )
        result.errors = [exc.reason]
    except _UnsupportedOfficeEncryptionError:
        result.features["content_access"] = "unsupported"
        result.errors = ["Office encryption or package type unsupported"]
    except ImportError:
        result.errors = ["Office decryption dependency unavailable"]
    except Exception:
        # Password verification is the only operation allowed to return wrong
        # password. HMAC/CRC failures and hostile parser messages stay private.
        result.errors = ["Office encrypted package corrupt or unavailable"]
    return result


async def analyze_encrypted_office(file_path: Path, ctx: StageContext) -> AnalyzerResult | None:
    """Return None for ordinary OLE; otherwise report/decrypt its encryption."""
    if not is_office_encrypted_candidate(file_path):
        return None
    result = AnalyzerResult(analyzer_name="office", format_type="OFFICE")
    result.features = {"encrypted": None, "content_access": "unavailable"}
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ctx.job_id) is None:
        result.errors = ["Office working directory unavailable"]
        return result
    settings = getattr(ctx, "analysis_settings", None) or get_settings()
    maximum_bytes = min(
        _MAX_INPUT_BYTES, settings.extraction_max_single_bytes, settings.extraction_max_bytes
    )
    maximum_expanded = min(_MAX_ZIP_EXPANDED_BYTES, settings.extraction_max_bytes)
    max_depth = getattr(ctx.analysis_services, "max_depth", settings.max_job_depth)
    depth = ctx.job.depth if ctx.job else ctx.depth
    parent = Path("/tmp") / ctx.job_id / "office_artifacts"
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="decrypt-", dir=parent))
    except OSError:
        result.errors = ["Office working directory unavailable"]
        return result
    retain = False
    try:

        def parse(reserve: Callable[[str, int, int], None]) -> AnalyzerResult | None:
            with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
                return _analyze_sync(
                    file_path,
                    password=ctx.archive_password,
                    output_path=work / "decrypted.package",
                    reserve=reserve,
                    maximum_bytes=maximum_bytes,
                    maximum_expanded=maximum_expanded,
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
            result = AnalyzerResult(analyzer_name="office", format_type="OFFICE")
            result.features = {
                "encrypted": None,
                "content_access": "unavailable",
                "resource_limited": True,
                "limit_reason": exc.reason,
            }
            result.errors = [exc.reason]
        except Exception:
            result = AnalyzerResult(analyzer_name="office", format_type="OFFICE")
            result.features = {"encrypted": None, "content_access": "unavailable"}
            result.errors = ["Office parser unavailable or failed"]
        if result is not None:
            access = result.features.get("content_access")
            if access == "password_required":
                raise DocumentPasswordRequiredError("office")
            if access == "wrong_password":
                raise DocumentWrongPasswordError("office")
            retain = bool(result.extracted_artifacts)
        return result
    finally:
        if not retain:
            shutil.rmtree(work, ignore_errors=True)
