"""Unsupported embedded-file crypto must not become complete plaintext coverage."""

from __future__ import annotations

import hashlib
import io
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
from malscan_worker.analyzers.pdf_decryption import (
    _require_supported_crypt_filters,
    _require_supported_stream_crypt_filters,
)
from malscan_worker.stages.base import StageContext
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    StreamObject,
)

_PASSWORD = "crypt-filter-test-credential"
_MARKER = b"xmrig synthetic differentiated-EFF control"
_METADATA_MARKER = (
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><label>synthetic metadata control</label></x:xmpmeta>'
)


def _encrypted_embedded_stream(
    *,
    stream_identity=False,
    embedded_identity=False,
    alias=False,
    explicit=None,
    array=False,
    clear_metadata=False,
):
    """Create a real AES document, correctly applying EFF to its embedded stream.

    The pinned pypdf writer shares its reader's EFF limitation, so override only
    encryption of this stream while producing the fixture. All keys, permission
    records, string encryption and document serialization remain real pypdf.
    """
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    stream = DecodedStreamObject()
    stream.set_data(_METADATA_MARKER if clear_metadata else _MARKER)
    stream[NameObject("/Type")] = NameObject("/Metadata" if clear_metadata else "/EmbeddedFile")
    if clear_metadata:
        stream[NameObject("/Subtype")] = NameObject("/XML")
    if explicit:
        stream[NameObject("/Filter")] = (
            ArrayObject([NameObject("/Crypt")]) if array else NameObject("/Crypt")
        )
        parameters = DictionaryObject({NameObject("/Name"): NameObject(explicit)})
        stream[NameObject("/DecodeParms")] = ArrayObject([parameters]) if array else parameters
    reference = writer._add_object(stream)
    if clear_metadata:
        writer._root_object[NameObject("/Metadata")] = reference
    writer.encrypt(_PASSWORD, algorithm="AES-128")
    encryption = writer._encryption
    assert encryption is not None
    entry = writer._encrypt_entry
    assert entry is not None
    if clear_metadata:
        encryption.EncryptMetadata = False
        entry.update(encryption.write_entry(_PASSWORD, None))
        entry[NameObject("/EncryptMetadata")] = BooleanObject(False)
    encryption.StmF = "/Identity" if stream_identity else "/AESV2"
    encryption.EFF = "/Identity" if embedded_identity else "/AESV2"
    entry[NameObject("/StmF")] = NameObject("/Identity" if stream_identity else "/StdCF")
    entry[NameObject("/EFF")] = NameObject("/Identity" if embedded_identity else "/StdCF")
    if alias:
        entry["/CF"][NameObject("/EmbeddedAlias")] = entry["/CF"]["/StdCF"]
        entry[NameObject("/EFF")] = NameObject("/EmbeddedAlias")

    original_encrypt = type(encryption).encrypt_object

    def encrypt_object(handler, obj, idnum, generation):
        if isinstance(obj, StreamObject) and obj.get("/Type") == "/Metadata":
            return obj
        if isinstance(obj, StreamObject) and obj.get("/Type") == "/EmbeddedFile":
            encrypted = DecodedStreamObject()
            encrypted.update(obj)
            filters = handler._make_crypt_filter(idnum, generation)
            if explicit == "/Identity":
                encrypted.set_data(obj.get_data())
            elif explicit == "/StdCF":
                # StrF remains AESV2 even when the document's default stream
                # filter is Identity; StdCF uses this same per-object AES key.
                encrypted.set_data(filters.str_crypt.encrypt(obj.get_data()))
            else:
                encrypted.set_data(filters.ef_crypt.encrypt(obj.get_data()))
            return encrypted
        return original_encrypt(handler, obj, idnum, generation)

    buffer = io.BytesIO()
    with patch.object(type(encryption), "encrypt_object", encrypt_object):
        writer.write(buffer)
    return buffer.getvalue(), reference.idnum


def test_real_differentiated_eff_reproduces_pinned_parser_content_loss():
    data, number = _encrypted_embedded_stream(stream_identity=True)
    assert _MARKER not in data
    reader = PdfReader(io.BytesIO(data))
    assert reader.decrypt(_PASSWORD)
    assert reader._encryption.StmF == "/Identity"
    assert reader._encryption.EFF == "/AESV2"
    # The PDF's encrypted bytes decrypt correctly using its EFF cipher; pypdf's
    # default object decryption instead leaves them encrypted without an error.
    ciphertext = reader.get_object(number).get_data()
    assert ciphertext != _MARKER
    assert reader._encryption._make_crypt_filter(number, 0).ef_crypt.decrypt(ciphertext) == _MARKER
    with pytest.raises(NotImplementedError, match="embedded-file crypt filter"):
        _require_supported_crypt_filters(reader)


@pytest.mark.asyncio
@pytest.mark.parametrize("password", [None, "wrong-filter-test-credential", _PASSWORD])
@pytest.mark.parametrize("stream_identity,embedded_identity", [(True, False), (False, True)])
async def test_differentiated_eff_is_partial_without_password_retry_or_plaintext(
    tmp_path, password, stream_identity, embedded_identity
):
    data, _ = _encrypted_embedded_stream(
        stream_identity=stream_identity, embedded_identity=embedded_identity
    )
    source = tmp_path / "encrypted.pdf"
    source.write_bytes(data)
    identifier = str(uuid4())
    context = StageContext(
        identifier,
        identifier,
        "source",
        hashlib.sha256(data).hexdigest(),
        source.name,
        source,
        archive_password=password,
    )
    try:
        result = await PDFAnalyzer().analyze(source, context)
        assert result.errors == ["failed to parse PDF file: corrupt or unsupported PDF data"]
        assert result.features["encrypted"] is True
        assert result.features["content_access"] == "unavailable"
        assert not result.extracted_artifacts
        assert not list((Path("/tmp") / identifier).rglob("decrypted.pdf"))
        assert source.read_bytes() == data
        assert _PASSWORD not in repr(result)
        if password:
            assert password not in repr(result)
    finally:
        shutil.rmtree(Path("/tmp") / identifier, ignore_errors=True)


def test_alias_names_for_the_same_crypt_method_remain_supported():
    data, number = _encrypted_embedded_stream(alias=True)
    reader = PdfReader(io.BytesIO(data))
    _require_supported_crypt_filters(reader)
    assert reader.decrypt(_PASSWORD)
    assert reader.get_object(number).get_data() == _MARKER


def test_clear_metadata_mode_reproduces_pinned_parser_data_corruption_and_is_rejected():
    data, number = _encrypted_embedded_stream(clear_metadata=True)
    assert _METADATA_MARKER in data
    reader = PdfReader(io.BytesIO(data))
    assert reader.decrypt(_PASSWORD)
    assert reader._encryption.EncryptMetadata is False
    assert reader.get_object(number)._data != _METADATA_MARKER
    with pytest.raises(NotImplementedError, match="metadata crypt settings"):
        _require_supported_crypt_filters(reader)


@pytest.mark.asyncio
@pytest.mark.parametrize("password", [None, "wrong-metadata-test-credential", _PASSWORD])
async def test_clear_metadata_mode_is_partial_without_password_retry_or_plaintext(
    tmp_path, password
):
    data, _ = _encrypted_embedded_stream(clear_metadata=True)
    source = tmp_path / "clear-metadata.pdf"
    source.write_bytes(data)
    identifier = str(uuid4())
    context = StageContext(
        identifier,
        identifier,
        "source",
        hashlib.sha256(data).hexdigest(),
        source.name,
        source,
        archive_password=password,
    )
    try:
        result = await PDFAnalyzer().analyze(source, context)
        assert result.errors == ["failed to parse PDF file: corrupt or unsupported PDF data"]
        assert result.features["encrypted"] is True
        assert result.features["content_access"] == "unavailable"
        assert not result.extracted_artifacts
        assert not list((Path("/tmp") / identifier).rglob("decrypted.pdf"))
        assert source.read_bytes() == data
        assert _PASSWORD not in repr(result)
        if password:
            assert password not in repr(result)
    finally:
        shutil.rmtree(Path("/tmp") / identifier, ignore_errors=True)


@pytest.mark.parametrize("array", [False, True])
@pytest.mark.parametrize("identity", [False, True])
def test_real_explicit_crypt_override_reproduces_content_loss_and_is_rejected(array, identity):
    data, number = _encrypted_embedded_stream(
        stream_identity=not identity,
        embedded_identity=not identity,
        explicit="/Identity" if identity else "/StdCF",
        array=array,
    )
    reader = PdfReader(io.BytesIO(data))
    _require_supported_crypt_filters(reader)
    assert reader.decrypt(_PASSWORD)
    stream = reader.get_object(number)
    assert stream._data != _MARKER
    if not identity:
        assert (
            reader._encryption._make_crypt_filter(number, 0).str_crypt.decrypt(stream._data)
            == _MARKER
        )
    with pytest.raises(NotImplementedError, match="explicit PDF stream crypt filter"):
        _require_supported_stream_crypt_filters(reader)


@pytest.mark.asyncio
@pytest.mark.parametrize("array", [False, True])
@pytest.mark.parametrize("identity", [False, True])
async def test_explicit_crypt_override_produces_no_misleading_plaintext_child(
    tmp_path, array, identity
):
    data, _ = _encrypted_embedded_stream(
        stream_identity=not identity,
        embedded_identity=not identity,
        explicit="/Identity" if identity else "/StdCF",
        array=array,
    )
    source = tmp_path / "explicit-crypt.pdf"
    source.write_bytes(data)
    identifier = str(uuid4())
    context = StageContext(
        identifier,
        identifier,
        "source",
        hashlib.sha256(data).hexdigest(),
        source.name,
        source,
        archive_password=_PASSWORD,
    )
    try:
        result = await PDFAnalyzer().analyze(source, context)
        assert result.errors == ["failed to parse PDF file: corrupt or unsupported PDF data"]
        assert result.features["encrypted"] is True
        assert result.features["content_access"] == "unavailable"
        assert not result.extracted_artifacts
        assert not list((Path("/tmp") / identifier).rglob("decrypted.pdf"))
        assert _PASSWORD not in repr(result)
        assert source.read_bytes() == data
    finally:
        shutil.rmtree(Path("/tmp") / identifier, ignore_errors=True)


@pytest.mark.parametrize("value", [None, {}, [], 1, "/Unknown", "/StdCF"])
@pytest.mark.parametrize("field", ["StmF", "StrF", "EFF"])
def test_unknown_or_malformed_resolved_filter_methods_fail_closed(value, field):
    methods = {"StmF": "/AESV2", "StrF": "/AESV2", "EFF": "/AESV2"}
    methods[field] = value
    reader = SimpleNamespace(_encryption=SimpleNamespace(**methods, EncryptMetadata=True))
    with pytest.raises(NotImplementedError, match="Unsupported PDF crypt filters"):
        _require_supported_crypt_filters(reader)
