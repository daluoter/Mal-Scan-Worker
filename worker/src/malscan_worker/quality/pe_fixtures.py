"""Versioned PE layouts for parser and evidence checks; never executable samples.

The fixtures contain only headers, import metadata and inert padding. Every section
is read-only, has no executable flag, and the entry point is zero. They deliberately
exercise static parsing rather than act as runnable Windows programs.
"""

from __future__ import annotations

import struct

PE_RECIPE_VERSION = 1
PE_PROFILES = frozenset({"benign", "suspicious", "truncated"})


def build_pe_fixture(profile: str, *, recipe_version: int = PE_RECIPE_VERSION) -> bytes:
    """Build one small, byte-for-byte reproducible synthetic PE32 fixture."""
    if recipe_version != PE_RECIPE_VERSION or profile not in PE_PROFILES:
        raise ValueError("Unknown PE fixture recipe")

    suspicious = profile == "suspicious"
    functions = (
        ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        if suspicious
        else ("GetCurrentProcessId",)
    )
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER: i386, one section, a fixed 2020 UTC timestamp, PE32.
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 1577836800, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<HBBIIIIII", data, optional, 0x10B, 14, 0, 0, 0x200, 0, 0, 0, 0x1000)
    struct.pack_into("<III", data, optional + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<HHHHHHI", data, optional + 40, 6, 0, 0, 0, 6, 0, 0)
    struct.pack_into("<IIIHH", data, optional + 56, 0x2000, 0x200, 0, 3, 0x0140)
    struct.pack_into("<IIIIII", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    # Import directory, followed by its null descriptor; other directories are empty.
    struct.pack_into("<II", data, optional + 96 + 8, 0x1000, 40)
    section = 0x178
    data[section : section + 8] = b"UPX1\x00\x00\x00\x00" if suspicious else b".rdata\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI", data, section + 8, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040
    )
    # IMAGE_IMPORT_DESCRIPTOR, DLL name, lookup thunks and address thunks.
    raw = 0x200
    struct.pack_into("<IIIII", data, raw, 0x1060, 0, 0, 0x1040, 0x1080)
    data[raw + 0x40 : raw + 0x40 + 13] = b"KERNEL32.dll\x00"
    name_offset = 0xA0
    for index, function in enumerate(functions):
        entry = b"\x00\x00" + function.encode("ascii") + b"\x00"
        struct.pack_into("<I", data, raw + 0x60 + index * 4, 0x1000 + name_offset)
        struct.pack_into("<I", data, raw + 0x80 + index * 4, 0x1000 + name_offset)
        data[raw + name_offset : raw + name_offset + len(entry)] = entry
        name_offset += (len(entry) + 1) & ~1

    if profile == "truncated":
        # Keep MZ and the PE signature so registry selection remains meaningful,
        # but omit the entire optional header rather than merely pad a bad image.
        return bytes(data[:optional])
    if suspicious:
        data.extend(b"SYNTHETIC STATIC ANALYSIS OVERLAY\n" * 40)
    return bytes(data)
