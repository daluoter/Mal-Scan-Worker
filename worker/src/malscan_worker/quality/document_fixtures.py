"""Deterministic, inert document structures for parser-quality regression cases.

These inputs exercise structural signals, never exploit code. Reserved ``.invalid``
targets cannot identify a real service. The encrypted PDF password is public test
data, and its obsolete RC4 encryption exists solely to exercise locked-file coverage.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

PDF_TEST_PASSWORD = "quality-fixture-only"

DOCUMENT_PROFILES = (
    "office-normal",
    "office-external-references",
    "office-macro-flag",
    "office-malformed",
    "office-metadata-limit",
    "pdf-normal",
    "pdf-active-actions",
    "pdf-malformed",
    "pdf-encrypted",
)

_RELS_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships"
_OFFICE_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"


def build_document_fixture(profile: str, recipe_version: int = 1) -> bytes:
    """Build a stable versioned input without clocks, randomness, or native tools."""
    if recipe_version != 1:
        raise ValueError("Unsupported document fixture recipe version")
    if profile not in DOCUMENT_PROFILES:
        raise ValueError("Unknown document fixture profile")
    if profile.startswith("office-"):
        if profile == "office-malformed":
            return b"PK\x03\x04\x14\x00truncated Office quality fixture\n"
        return _office_fixture(profile)
    if profile == "pdf-malformed":
        return b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    return _pdf_fixture(profile)


def _office_fixture(profile: str) -> bytes:
    macro_flag = profile == "office-macro-flag"
    document_type = (
        "application/vnd.ms-word.document.macroEnabled.main+xml"
        if macro_flag
        else "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="' + document_type + '"/>'
    )
    if macro_flag:
        content_types += (
            '<Override PartName="/word/vbaProject.bin" '
            'ContentType="application/vnd.ms-office.vbaProject"/>'
        )
    content_types += "</Types>"
    parts: dict[str, bytes] = {
        "[Content_Types].xml": content_types.encode(),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="' + _RELS_NAMESPACE + '">'
            '<Relationship Id="rId1" Type="' + _OFFICE_RELS + 'officeDocument" '
            'Target="word/document.xml"/></Relationships>'
        ).encode(),
        "word/document.xml": (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b"<w:body><w:p><w:r><w:t>Inert quality fixture document.</w:t></w:r></w:p>"
            b"<w:sectPr/></w:body></w:document>"
        ),
    }
    relationships = '<Relationships xmlns="' + _RELS_NAMESPACE + '">'
    if profile == "office-external-references":
        relationships += (
            '<Relationship Id="rIdTemplate" Type="' + _OFFICE_RELS + 'attachedTemplate" '
            'Target="https://quality.invalid/inert-template.dotx" TargetMode="External"/>'
            '<Relationship Id="rIdOle" Type="' + _OFFICE_RELS + 'oleObject" '
            'Target="https://quality.invalid/inert-reference.txt" TargetMode="External"/>'
        )
    if macro_flag:
        relationships += (
            '<Relationship Id="rIdVba" '
            'Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
            'Target="vbaProject.bin"/>'
        )
        # A package flag, deliberately not an executable VBA project. A parser may
        # report macro presence, but this input cannot establish successful VBA parsing.
        parts["word/vbaProject.bin"] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    if profile == "office-metadata-limit":
        relationships += "<!--" + (" " * 1_000_001) + "-->"
    relationships += "</Relationships>"
    parts["word/_rels/document.xml.rels"] = relationships.encode()

    output = io.BytesIO()
    compression = zipfile.ZIP_DEFLATED if profile == "office-metadata-limit" else zipfile.ZIP_STORED
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in parts.items():
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = compression
            archive.writestr(info, payload)
    return output.getvalue()


def _pdf_fixture(profile: str) -> bytes:
    catalog = b"<< /Type /Catalog /Pages 2 0 R"
    if profile == "pdf-active-actions":
        catalog += b" /OpenAction 4 0 R /AA << /O 5 0 R >>"
    objects = [
        catalog + b" >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> >>",
    ]
    if profile == "pdf-active-actions":
        objects.extend(
            [
                b"<< /Type /Action /S /JavaScript /JS (void 0;) >>",
                b"<< /Type /Action /S /Launch /F (quality-fixture-never-execute.txt) >>",
            ]
        )
    trailer = b""
    if profile == "pdf-encrypted":
        identifier = bytes.fromhex("00112233445566778899aabbccddeeff")
        owner, user = _pdf_test_encryption(identifier)
        objects.append(
            b"<< /Filter /Standard /V 1 /R 2 /Length 40 /P -4 /O <"
            + owner.hex().encode()
            + b"> /U <"
            + user.hex().encode()
            + b"> >>"
        )
        trailer += b" /Encrypt 4 0 R /ID [<" + identifier.hex().encode() + b"><"
        trailer += identifier.hex().encode() + b">]"
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, payload in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(str(number).encode() + b" 0 obj\n" + payload + b"\nendobj\n")
    xref = len(output)
    output.extend(b"xref\n0 " + str(len(objects) + 1).encode() + b"\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(b"trailer\n<< /Size " + str(len(objects) + 1).encode())
    output.extend(b" /Root 1 0 R" + trailer + b" >>\nstartxref\n" + str(xref).encode())
    output.extend(b"\n%%EOF\n")
    return bytes(output)


def _pdf_test_encryption(identifier: bytes) -> tuple[bytes, bytes]:
    """PDF Standard revision 2 keys for a public test password, never real data."""
    padding = bytes.fromhex("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")
    password = (PDF_TEST_PASSWORD.encode("ascii") + padding)[:32]
    owner_key = hashlib.md5(password, usedforsecurity=False).digest()[:5]
    owner = _test_rc4(owner_key, password)
    material = password + owner + struct.pack("<i", -4) + identifier
    file_key = hashlib.md5(material, usedforsecurity=False).digest()[:5]
    return owner, _test_rc4(file_key, padding)


def _test_rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) % 256])
    return bytes(output)
