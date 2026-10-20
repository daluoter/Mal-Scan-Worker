"""Small, deterministic document containers for real embedded-file acceptance.

All contents are inert. EICAR is the standard antivirus test signature, not a
malware payload. The nested encrypted PDF and its public fixture password reuse
the separately frozen PDF-password controls. No fixture opens a real URL or
executes an embedded object. Recipe v1 uses only stable binary/container layouts.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib

from malscan_worker.quality.document_fixtures import build_document_fixture
from malscan_worker.quality.pdf_password_fixtures import build_pdf_password_fixture

DOCUMENT_EMBEDDED_PROFILES = (
    "pdf-name-tree-text",
    "pdf-flate-eicar",
    "pdf-alias-and-duplicate-names",
    "pdf-associated-and-annotation",
    "pdf-password-child",
    "pdf-unsupported-filter",
    "pdf-missing-stream",
    "office-embedded-pdf",
    "office-relationship-package",
    "ole-native-text",
    "ole-package-pdf",
    "ole-native-truncated",
)

_TEXT = b"Inert embedded document quality control.\n"
_SECOND_TEXT = b"A different inert attachment with the same display filename.\n"
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _pdf_string(value: str) -> bytes:
    return (
        b"("
        + value.encode("ascii").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        + b")"
    )


def _pdf(objects: list[bytes]) -> bytes:
    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, payload in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + payload + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output)


def _pdf_attachment_fixture(profile: str) -> bytes:
    catalog = b"<< /Type /Catalog /Pages 2 0 R"
    page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >>"
    # Append-only object numbers keep filespec/stream references deterministic.
    objects = [b"", b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>", b""]

    def add(payload: bytes, name: str, filter_name: bytes = b"") -> int:
        spec_ref = len(objects) + 1
        stream_ref = spec_ref + 1
        objects.append(
            b"<< /Type /Filespec /F "
            + _pdf_string(name)
            + b" /EF << /F "
            + str(stream_ref).encode()
            + b" 0 R >> >>"
        )
        encoded = zlib.compress(payload, 9) if filter_name == b"/FlateDecode" else payload
        dictionary = (
            b"<< /Type /EmbeddedFile /Length "
            + str(len(encoded)).encode()
            + b" /Params << /Size "
            + str(len(payload)).encode()
            + b" >>"
        )
        if filter_name:
            dictionary += b" /Filter " + filter_name
        objects.append(dictionary + b" >>\nstream\n" + encoded + b"\nendstream")
        return spec_ref

    if profile == "pdf-associated-and-annotation":
        first = add(_TEXT, "associated.txt")
        second = add(_SECOND_TEXT, "annotated.txt")
        catalog += f" /AF [{first} 0 R]".encode()
        annotation = len(objects) + 1
        objects.append(
            (
                "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] " f"/FS {second} 0 R >>"
            ).encode()
        )
        page += f" /Annots [{annotation} 0 R]".encode()
    elif profile == "pdf-alias-and-duplicate-names":
        first = add(_TEXT, "same-name.txt")
        second = add(_SECOND_TEXT, "same-name.txt")
        third = add(_TEXT, "same-name.txt")
        leaf = len(objects) + 1
        objects.append(
            f"<< /Names [(first) {first} 0 R (second) {second} 0 R (third) {third} 0 R] >>".encode()
        )
        catalog += (
            f" /Names << /EmbeddedFiles << /Kids [{leaf} 0 R] >> >> /AF [{first} 0 R]".encode()
        )
        annotation = len(objects) + 1
        objects.append(
            (
                "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] " f"/FS {first} 0 R >>"
            ).encode()
        )
        page += f" /Annots [{annotation} 0 R] /AF [{first} 0 R]".encode()
    elif profile == "pdf-missing-stream":
        objects.append(b"<< /Type /Filespec /F (missing.txt) >>")
        catalog += b" /Names << /EmbeddedFiles << /Names [(missing) 4 0 R] >> >>"
    else:
        payload = (
            _EICAR
            if profile == "pdf-flate-eicar"
            else build_pdf_password_fixture("aes-128-normal")
            if profile == "pdf-password-child"
            else _TEXT
        )
        name = "locked.pdf" if profile == "pdf-password-child" else "attachment.txt"
        filter_name = (
            b"/FlateDecode"
            if profile == "pdf-flate-eicar"
            else b"/ASCIIHexDecode"
            if profile == "pdf-unsupported-filter"
            else b""
        )
        first = add(payload, name, filter_name)
        catalog += f" /Names << /EmbeddedFiles << /Names [(attachment) {first} 0 R] >> >>".encode()
    objects[0] = catalog + b" >>"
    objects[2] = page + b" >>"
    return _pdf(objects)


def _zip(parts: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in parts.items():
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    return output.getvalue()


def _office_fixture(profile: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(build_document_fixture("office-normal"))) as archive:
        parts = {name: archive.read(name) for name in archive.namelist()}
    target = (
        "embeddings/attachment.pdf" if profile == "office-embedded-pdf" else "../custom/payload.pdf"
    )
    member = (
        "word/embeddings/attachment.pdf"
        if profile == "office-embedded-pdf"
        else "custom/payload.pdf"
    )
    relation = "oleObject" if profile == "office-embedded-pdf" else "package"
    parts["word/_rels/document.xml.rels"] = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rIdEmbedded" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        + relation
        + '" Target="'
        + target
        + '"/></Relationships>'
    ).encode()
    parts[member] = build_document_fixture("pdf-normal")
    return _zip(parts)


def _cfb_stream(name: str, payload: bytes) -> bytes:
    """Write one exact-size mini stream, with a proper FAT/MiniFAT directory."""
    if not 0 < len(payload) < 4096:
        raise ValueError("Embedded quality stream must fit a CFB mini stream")
    end, free, fat = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    mini_count = (len(payload) + 63) // 64
    root_size = mini_count * 64
    root_sectors = (root_size + 511) // 512
    mini_fat_sector, directory_sector, fat_sector = root_sectors, root_sectors + 1, root_sectors + 2
    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 24, 0x003E, 3, 0xFFFE, 9, 6)
    struct.pack_into(
        "<IIIIIIIII", header, 40, 0, 1, directory_sector, 0, 4096, mini_fat_sector, 1, end, 0
    )
    struct.pack_into("<109I", header, 76, fat_sector, *([free] * 108))

    def directory_entry(
        entry_name: str, kind: int, start: int, size: int, child: int = free
    ) -> bytes:
        value = bytearray(128)
        encoded = entry_name.encode("utf-16-le") + b"\0\0"
        value[: len(encoded)] = encoded
        struct.pack_into("<HBBIII", value, 64, len(encoded), kind, 1, free, free, child)
        struct.pack_into("<IQ", value, 116, start, size)
        return bytes(value)

    mini_fat = [index + 1 for index in range(mini_count)]
    mini_fat[-1] = end
    mini_fat.extend([free] * (128 - len(mini_fat)))
    directory = (
        directory_entry("Root Entry", 5, 0, root_size, 1)
        + directory_entry(name, 2, 0, len(payload))
        + b"\0" * 256
    )
    allocation = [index + 1 for index in range(root_sectors)]
    allocation[-1] = end
    allocation.extend([end, end, fat])
    allocation.extend([free] * (128 - len(allocation)))
    return (
        bytes(header)
        + payload.ljust(root_sectors * 512, b"\0")
        + struct.pack("<128I", *mini_fat)
        + directory
        + struct.pack("<128I", *allocation)
    )


def _native_stream(payload: bytes, *, truncated: bool = False) -> bytes:
    body = (
        struct.pack("<H", 2)
        + b"attachment.txt\0C:\\quality\\attachment.txt\0"
        + struct.pack("<II", 0, 0)
        + b"C:\\quality\\temporary\0"
        + struct.pack("<I", len(payload))
        + payload
    )
    return struct.pack("<I", len(body)) + (body[:-5] if truncated else body)


def build_document_embedded_fixture(profile: str, recipe_version: int = 1) -> bytes:
    """Return a stable original document; manifest validation pins its identity."""
    if (
        not isinstance(recipe_version, int)
        or isinstance(recipe_version, bool)
        or recipe_version != 1
    ):
        raise ValueError("Unsupported embedded document fixture recipe version")
    if profile not in DOCUMENT_EMBEDDED_PROFILES:
        raise ValueError("Unknown embedded document fixture profile")
    if profile.startswith("pdf-"):
        return _pdf_attachment_fixture(profile)
    if profile.startswith("office-"):
        return _office_fixture(profile)
    if profile == "ole-package-pdf":
        return _cfb_stream("Package", build_document_fixture("pdf-normal"))
    return _cfb_stream(
        "\x01Ole10Native", _native_stream(_TEXT, truncated=profile == "ole-native-truncated")
    )


def embedded_fixture_payloads(profile: str) -> tuple[bytes, ...]:
    """Expected recovered payloads, excluding container parts and aliases."""
    if profile not in DOCUMENT_EMBEDDED_PROFILES:
        raise ValueError("Unknown embedded document fixture profile")
    if profile in {"pdf-unsupported-filter", "pdf-missing-stream", "ole-native-truncated"}:
        return ()
    if profile == "pdf-alias-and-duplicate-names":
        return (_TEXT, _SECOND_TEXT, _TEXT)
    if profile == "pdf-associated-and-annotation":
        return (_TEXT, _SECOND_TEXT)
    if profile == "pdf-flate-eicar":
        return (_EICAR,)
    if profile == "pdf-password-child":
        return (build_pdf_password_fixture("aes-128-normal"),)
    if profile.startswith("office-") or profile == "ole-package-pdf":
        return (build_document_fixture("pdf-normal"),)
    return (_TEXT,)


def fixture_identity(profile: str) -> tuple[str, int]:
    payload = build_document_embedded_fixture(profile)
    return hashlib.sha256(payload).hexdigest(), len(payload)
