"""Real synthetic crypto validates every advertised Office algorithm combination.

Passwords and derived deterministic material are public test data only. These
inputs contain the frozen inert DOCX package and never run document content.
The small spin count keeps this parameter matrix fast; frozen acceptance inputs
independently exercise the ordinary Agile 100,000-spin password recipe.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import logging
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from malscan_worker.analyzers.office_decryption import _analyze_sync
from malscan_worker.quality.office_password_fixtures import (
    OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_plaintext_fixture,
)
from msoffcrypto import exceptions
from msoffcrypto.format.ooxml import OOXMLFile
from msoffcrypto.method import ecma376_agile as agile
from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted
from msoffcrypto.method.ecma376_standard import ECMA376Standard

_HASH_NAMES = ("SHA256", "SHA384", "SHA512")
_AGILE_PARAMETERS = tuple(itertools.product((128, 256), _HASH_NAMES, (128, 192, 256), _HASH_NAMES))


def _fixed_bytes(label: str, length: int) -> bytes:
    return hashlib.sha512(label.encode()).digest()[:length]


def _container(encrypted_package: bytes, encryption_info: bytes) -> bytes:
    output = io.BytesIO()
    ECMA376Encrypted(encrypted_package, encryption_info).write_to(output)
    return output.getvalue()


def _agile_encryption(
    plain: bytes, data_bits: int, data_hash: str, password_bits: int, password_hash: str
) -> bytes:
    """Use the pinned library's real ECMA-376 crypto with explicit parameter sets."""
    info = agile.ECMA376AgileEncryptionInfo()
    info.spinCount = 1_000
    for params, bits, algorithm, label in (
        (info.keyData, data_bits, data_hash, "payload"),
        (info.encryptedKey, password_bits, password_hash, "password"),
    ):
        params.keyBits = bits
        params.hashName = algorithm
        params.hashSize = hashlib.new(algorithm.lower()).digest_size
        params.saltValue = _fixed_bytes(f"public-test-only-{label}-salt", 16)
    password_salt = info.encryptedKey.saltValue
    password_digest = agile.ECMA376Agile._derive_iterated_hash_from_password(
        OFFICE_PASSWORD, password_salt, password_hash, info.spinCount
    ).digest()

    def wrap(plain_value: bytes, block_key: bytes) -> bytes:
        key = agile.ECMA376Agile._derive_encryption_key(
            password_digest, block_key, password_hash, password_bits
        )
        return agile._encrypt_aes_cbc(plain_value, key, password_salt)

    verifier = _fixed_bytes("public-test-only-verifier", 16)
    secret_key = _fixed_bytes("public-test-only-payload-key", data_bits // 8)
    info.encryptedVerifierHashInput = wrap(verifier, agile.blkKey_VerifierHashInput)
    info.encryptedVerifierHashValue = wrap(
        hashlib.new(password_hash.lower(), verifier).digest(),
        agile.blkKey_encryptedVerifierHashValue,
    )
    info.encryptedKeyValue = wrap(secret_key, agile.blkKey_encryptedKeyValue)
    encrypted = agile.ECMA376Agile.encrypt_payload(
        io.BytesIO(plain), info.keyData, secret_key, info.keyData.saltValue
    )
    descriptor = agile.ECMA376Agile.get_encryption_information(info, encrypted, secret_key)
    return _container(encrypted, descriptor)


def _standard_encryption(plain: bytes, bits: int) -> bytes:
    """Build a valid Standard AES container, independently verified by msoffcrypto."""
    algorithm = {128: 0x660E, 192: 0x660F, 256: 0x6610}[bits]
    salt = _fixed_bytes("public-test-only-standard-salt", 16)
    verifier = _fixed_bytes("public-test-only-standard-verifier", 16)
    key = ECMA376Standard.makekey_from_password(
        OFFICE_PASSWORD, algorithm, 0x8004, 0x18, bits, 16, salt
    )

    def encrypt(value: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return cipher.update(value + bytes(-len(value) % 16)) + cipher.finalize()

    header = struct.pack("<8I", 0x24, 0, algorithm, 0x8004, bits, 0x18, 0, 0)
    header += "Microsoft Enhanced RSA and AES Cryptographic Provider\x00".encode("utf-16le")
    descriptor = struct.pack("<HHII", 4, 2, 0x24, len(header)) + header
    descriptor += struct.pack("<I", 16) + salt + encrypt(verifier)
    descriptor += struct.pack("<I", 20) + encrypt(hashlib.sha1(verifier).digest())
    return _container(struct.pack("<Q", len(plain)) + encrypt(plain), descriptor)


def _assert_reference_and_worker_decrypt(raw: bytes, expected: bytes, tmp_path: Path):
    reference = OOXMLFile(io.BytesIO(raw))
    with pytest.raises(exceptions.InvalidKeyError):
        reference.load_key(password=WRONG_PASSWORD, verify_password=True)
    reference.load_key(password=OFFICE_PASSWORD, verify_password=True)
    clear = io.BytesIO()
    reference.decrypt(clear, verify_integrity=True)
    assert clear.getvalue() == expected
    reference.file.close()
    source = tmp_path / "encrypted.bin"
    source.write_bytes(raw)
    previous_logging_disable = logging.root.manager.disable
    try:
        result = _analyze_sync(
            source,
            password=OFFICE_PASSWORD,
            output_path=tmp_path / "decrypted.package",
            reserve=lambda *args: None,
            maximum_bytes=50_000_000,
            maximum_expanded=100_000_000,
            job_id="office-algorithm-matrix",
            depth_limited=False,
        )
    finally:
        # _analyze_sync normally runs in a disposable child process.
        logging.disable(previous_logging_disable)
    assert result is not None
    assert result.errors == []
    assert result.features["content_access"] == "decrypted_child"
    assert len(result.extracted_artifacts) == 1
    artifact = result.extracted_artifacts[0]
    assert artifact["filename"] == "decrypted.docx"
    assert Path(artifact["path"]).read_bytes() == expected
    assert artifact["sha256"] == hashlib.sha256(expected).hexdigest()
    assert artifact["size"] == len(expected)
    return result.features["encryption"]


@pytest.mark.parametrize("data_bits,data_hash,password_bits,password_hash", _AGILE_PARAMETERS)
def test_all_supported_agile_parameter_combinations_decrypt_real_packages(
    data_bits: int, data_hash: str, password_bits: int, password_hash: str, tmp_path: Path
) -> None:
    plain = build_office_plaintext_fixture(profile="docx")
    raw = _agile_encryption(plain, data_bits, data_hash, password_bits, password_hash)
    metadata = _assert_reference_and_worker_decrypt(raw, plain, tmp_path)
    assert metadata == {
        "scheme": "agile",
        "cipher": "AES-CBC",
        "key_bits": data_bits,
        "hash": data_hash,
        "password_key_bits": password_bits,
        "password_hash": password_hash,
        "spin_count": 1_000,
        "integrity": "hmac_verified",
    }


@pytest.mark.parametrize("bits", (128, 192, 256))
def test_all_supported_standard_aes_key_sizes_decrypt_real_packages(
    bits: int, tmp_path: Path
) -> None:
    plain = build_office_plaintext_fixture(profile="docx")
    raw = _standard_encryption(plain, bits)
    metadata = _assert_reference_and_worker_decrypt(raw, plain, tmp_path)
    assert metadata == {
        "scheme": "standard",
        "cipher": "AES-ECB",
        "key_bits": bits,
        "hash": "SHA1",
        "spin_count": 50_000,
        "integrity": "zip_crc_only_no_authenticated_integrity",
    }
