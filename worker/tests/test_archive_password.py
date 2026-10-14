"""Tests for archive password behavior in extraction handlers and stage.

Tests cover:
- ZipHandler password detection and errors
- Stage-level password exception propagation
- Stage-level generic error handling
- Stage passing archive_password through to handlers
- 7z/rar password handling via CLI (tested at handler level)
"""

import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors.base import ExtractionLimits, ExtractionResult
from malscan_worker.extractors.zip_handler import ZipHandler
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext

# ---------------------------------------------------------------
# Stage-level: password exceptions propagate out of execute()
# ---------------------------------------------------------------


@pytest.mark.asyncio
@patch("malscan_worker.stages.archive_extract.create_artifact")
async def test_archive_extract_stage_reraises_password_domain_errors(
    mock_create_artifact, tmp_path
):
    """ArchivePasswordRequiredError raised during extraction propagates."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()

    # Replace the handler's extract to raise password error
    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, *a, **k):
            raise ArchivePasswordRequiredError("zip")

    stage._registry._handlers = [_FakeHandler()]

    with pytest.raises(ArchivePasswordRequiredError):
        await stage.execute(ctx)


@pytest.mark.asyncio
async def test_archive_extract_stage_handles_other_exceptions_as_error_result(tmp_path):
    """Non-password exceptions produce an error StageResult."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    ctx = StageContext(
        job_id="job-2",
        file_id="file-2",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()

    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, *a, **k):
            raise RuntimeError("boom")

    stage._registry._handlers = [_FakeHandler()]
    result = await stage.execute(ctx)

    assert result.status == "error"
    assert "RuntimeError" in result.findings["reason"]
    assert "boom" not in result.findings["reason"]


@pytest.mark.asyncio
@patch("malscan_worker.stages.archive_extract.create_artifact")
async def test_archive_extract_stage_passes_archive_password_to_extract(
    mock_create_artifact, tmp_path
):
    """The archive_password from StageContext is forwarded to the handler."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, file_path, extract_dir, limits, password=None):
            assert password == "secret"
            return ExtractionResult(files=[], archive_type="zip", password_protected=True)

    ctx = StageContext(
        job_id="job-3",
        file_id="file-3",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
        archive_password="secret",
    )

    stage = ArchiveExtractStage()
    stage._registry._handlers = [_FakeHandler()]

    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert result.findings["archive_type"] == "zip"
    assert result.findings["archive_summary"]["password_protected"] is True
    assert [heuristic["key"] for heuristic in result.findings["heuristics"]] == [
        "archive.password_protected"
    ]


@pytest.mark.asyncio
async def test_archive_extract_stage_uses_streaming_sha256_helper(tmp_path):
    """ArchiveExtractStage hashes extracted files through the helper."""
    extracted = tmp_path / "child.bin"
    extracted.write_bytes(b"abc")
    archive_path = tmp_path / "test.zip"
    archive_path.write_bytes(b"PK\x03\x04")

    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, *a, **k):
            from malscan_worker.extractors.base import ExtractedFile, ExtractionResult

            return ExtractionResult(
                files=[
                    ExtractedFile(
                        path=str(extracted),
                        original_name="child.bin",
                        size=3,
                        origin_path="child.bin",
                    )
                ],
                archive_type="zip",
            )

    ctx = StageContext(
        job_id="streaming-sha-job",
        file_id="file-id",
        storage_key="key",
        sha256="root-sha",
        original_filename="test.zip",
        file_path=archive_path,
    )

    stage = ArchiveExtractStage()
    stage._registry._handlers = [_FakeHandler()]

    with patch(
        "malscan_worker.stages.archive_extract._file_sha256",
        return_value="f" * 64,
    ) as mock_hash:
        result = await stage.execute(ctx)

    assert result.status == "ok"
    mock_hash.assert_called_once_with(str(extracted))


# ---------------------------------------------------------------
# ZipHandler password tests (direct handler tests)
# ---------------------------------------------------------------


def test_extract_zip_encrypted_without_password_raises_required(tmp_path):
    """Encrypted zip without password raises ArchivePasswordRequiredError."""
    handler = ZipHandler()

    zip_path = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(zip_path, "w"):
        # Standard zipfile can't create encrypted zips, so we use a mock approach
        pass

    # Create a zip that reports encryption via flag_bits
    # We monkeypatch the zipfile.ZipFile at the module scope for zip_handler
    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1  # encrypted

        def is_dir(self):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with pytest.raises(ArchivePasswordRequiredError) as exc:
            handler.extract(zip_path, tmp_path / "out", ExtractionLimits())
        assert exc.value.args[0] == "zip"


def test_extract_zip_bad_password_raises_wrong_password(tmp_path):
    """Bad password zip raises ArchiveWrongPasswordError."""
    handler = ZipHandler()
    zip_path = tmp_path / "encrypted.zip"
    zip_path.write_bytes(b"PK\x03\x04")  # stub

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1  # encrypted

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("Bad password for file")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def open(self, info, pwd=None):
            return _FakeSrc()

    (tmp_path / "out").mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
            with patch(
                "malscan_worker.extractors.zip_handler.check_expansion_ratio", return_value=None
            ):
                with pytest.raises(ArchiveWrongPasswordError) as exc:
                    handler.extract(
                        zip_path, tmp_path / "out", ExtractionLimits(), password="wrong"
                    )
                assert exc.value.args[0] == "zip"


def test_extract_zip_password_required_runtime_error_with_password_raises_wrong(tmp_path):
    """Runtime error about password encryption with a password supplied maps to wrong password."""
    handler = ZipHandler()
    zip_path = tmp_path / "encrypted.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("File is encrypted, password required for extraction")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def open(self, info, pwd=None):
            return _FakeSrc()

    (tmp_path / "out").mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
            with patch(
                "malscan_worker.extractors.zip_handler.check_expansion_ratio", return_value=None
            ):
                with pytest.raises(ArchiveWrongPasswordError) as exc:
                    handler.extract(
                        zip_path, tmp_path / "out", ExtractionLimits(), password="secret"
                    )
                assert exc.value.args[0] == "zip"


def test_extract_zip_aes_wrong_password_raises_wrong_password(tmp_path):
    """AES-encrypted zip with wrong password raises ArchiveWrongPasswordError."""
    try:
        import pyzipper
    except ImportError:
        pytest.skip("pyzipper not installed")

    handler = ZipHandler()
    zip_path = tmp_path / "aes-wrong.zip"

    with pyzipper.AESZipFile(
        zip_path,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"correct-password")
        zf.writestr("a.txt", "secret content")

    (tmp_path / "out").mkdir(exist_ok=True)

    with pytest.raises(ArchiveWrongPasswordError):
        handler.extract(zip_path, tmp_path / "out", ExtractionLimits(), password="wrong-password")


def test_extract_zip_pyzipper_corrupt_input_runtime_error_is_not_mapped_to_password(tmp_path):
    """Generic corruption runtime errors stay as RuntimeError."""
    handler = ZipHandler()
    zip_path = tmp_path / "aes-wrong.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("Corrupt input data")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeAESZipFile:
        def __init__(self, *a, **k):
            self.password = None

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def setpassword(self, pwd):
            self.password = pwd

        def open(self, info, pwd=None):
            return _FakeSrc()

    extract_dir = tmp_path / "out-runtime"
    extract_dir.mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler._HAS_PYZIPPER", True):
        with patch(
            "malscan_worker.extractors.zip_handler.pyzipper",
            SimpleNamespace(AESZipFile=_FakeAESZipFile),
        ):
            with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
                with patch(
                    "malscan_worker.extractors.zip_handler.check_expansion_ratio",
                    return_value=None,
                ):
                    with pytest.raises(RuntimeError, match="Corrupt input data"):
                        handler._extract_pyzipper(
                            zip_path,
                            extract_dir,
                            ExtractionLimits(),
                            password="wrong-password",
                        )


def test_extract_zip_pyzipper_bad_decrypt_runtime_error_is_not_mapped_to_password(tmp_path):
    """Generic bad decrypt runtime errors stay as RuntimeError."""
    handler = ZipHandler()
    zip_path = tmp_path / "aes-bad-decrypt.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("bad decrypt")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeAESZipFile:
        def __init__(self, *a, **k):
            self.password = None

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def setpassword(self, pwd):
            self.password = pwd

        def open(self, info, pwd=None):
            return _FakeSrc()

    extract_dir = tmp_path / "out-bad-decrypt"
    extract_dir.mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler._HAS_PYZIPPER", True):
        with patch(
            "malscan_worker.extractors.zip_handler.pyzipper",
            SimpleNamespace(AESZipFile=_FakeAESZipFile),
        ):
            with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
                with patch(
                    "malscan_worker.extractors.zip_handler.check_expansion_ratio",
                    return_value=None,
                ):
                    with pytest.raises(RuntimeError, match="bad decrypt"):
                        handler._extract_pyzipper(
                            zip_path,
                            extract_dir,
                            ExtractionLimits(),
                            password="wrong-password",
                        )


def test_extract_zip_aes_correct_password_extracts(tmp_path):
    """AES-encrypted zip with correct password extracts successfully."""
    try:
        import pyzipper
    except ImportError:
        pytest.skip("pyzipper not installed")

    handler = ZipHandler()
    zip_path = tmp_path / "aes-correct.zip"

    with pyzipper.AESZipFile(
        zip_path,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"correct-password")
        zf.writestr("a.txt", "secret content")

    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    result = handler.extract(zip_path, extract_dir, ExtractionLimits(), password="correct-password")
    assert len(result.files) == 1
    assert result.files[0].original_name == "a.txt"
    assert result.password_protected is True


def test_extract_zip_standard_streaming_enforces_total_bytes_limit(tmp_path):
    """Standard ZIP extraction stops when streamed bytes exceed total limit."""
    handler = ZipHandler()
    zip_path = tmp_path / "streaming-standard.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        flag_bits = 0

        def __init__(self, filename):
            self.filename = filename
            self.file_size = 1

        def is_dir(self):
            return False

    class _FakeSrc:
        def __init__(self, payload):
            self._payload = payload
            self._sent = False

        def read(self, size=-1):
            if self._sent:
                return b""
            self._sent = True
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            self._infos = [_FakeInfo("a.txt"), _FakeInfo("b.txt")]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return self._infos

        def open(self, info, pwd=None):
            return _FakeSrc(b"x" * 60)

    extract_dir = tmp_path / "out-standard"
    extract_dir.mkdir()

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=10):
            with patch(
                "malscan_worker.extractors.zip_handler.check_expansion_ratio",
                return_value=None,
            ):
                result = handler.extract(
                    zip_path,
                    extract_dir,
                    ExtractionLimits(max_extracted_bytes=100, max_expansion_ratio=1000.0),
                )

    assert result.malicious is True
    assert result.reason == "Zip bomb: total extracted bytes exceeded during extraction"
    assert len(result.files) == 1
    assert not (extract_dir / "b.txt").exists()


def test_extract_zip_pyzipper_streaming_enforces_cumulative_expansion_ratio(tmp_path):
    """AES fallback extraction enforces cumulative expansion ratio while streaming."""
    handler = ZipHandler()
    zip_path = tmp_path / "streaming-aes.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        flag_bits = 0x1

        def __init__(self, filename):
            self.filename = filename
            self.file_size = 1

        def is_dir(self):
            return False

    class _FakeSrc:
        def __init__(self, payload):
            self._payload = payload
            self._sent = False

        def read(self, size=-1):
            if self._sent:
                return b""
            self._sent = True
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFileFallback:
        def __init__(self, *a, **k):
            raise NotImplementedError

    class _FakeAESZipFile:
        def __init__(self, *a, **k):
            self._infos = [_FakeInfo("a.txt"), _FakeInfo("b.txt")]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return self._infos

        def setpassword(self, pwd):
            self.password = pwd

        def open(self, info, pwd=None):
            return _FakeSrc(b"x" * 60)

    extract_dir = tmp_path / "out-pyzipper"
    extract_dir.mkdir()

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFileFallback):
        with patch("malscan_worker.extractors.zip_handler._HAS_PYZIPPER", True):
            with patch(
                "malscan_worker.extractors.zip_handler.pyzipper",
                SimpleNamespace(AESZipFile=_FakeAESZipFile),
            ):
                with patch(
                    "malscan_worker.extractors.zip_handler.os.path.getsize", return_value=10
                ):
                    with patch(
                        "malscan_worker.extractors.zip_handler.check_expansion_ratio",
                        return_value=None,
                    ):
                        result = handler.extract(
                            zip_path,
                            extract_dir,
                            ExtractionLimits(max_extracted_bytes=1000, max_expansion_ratio=10.0),
                            password="secret",
                        )

    assert result.malicious is True
    assert result.reason == "Zip bomb: expansion ratio exceeded during extraction"
    assert len(result.files) == 1
    assert not (extract_dir / "b.txt").exists()


# ---------------------------------------------------------------
# 7z handler password tests (subprocess-based)
# ---------------------------------------------------------------


def test_extract_7z_encrypted_without_password_raises_required(tmp_path):
    """7z handler raises ArchivePasswordRequiredError when password needed."""

    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")  # magic only, will fail

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.txt", 10)],
                True,
                password_error="required",
            )
        ),
        create=True,
    ):
        with pytest.raises(ArchivePasswordRequiredError):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits())


def test_extract_7z_wrong_password_raises_wrong_password(tmp_path):
    """7z handler raises ArchiveWrongPasswordError with wrong password."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.txt", 10)],
                True,
                password_error="wrong",
            )
        ),
        create=True,
    ):
        with pytest.raises(ArchiveWrongPasswordError):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits(), password="bad-pass")


def test_extract_7z_success_with_password_does_not_mark_password_protected(tmp_path):
    """7z success with a supplied password does not imply encryption was detected."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")
    extract_dir = tmp_path / "out-7z-success"
    extract_dir.mkdir()
    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                False,
                file_payloads={"a.txt": b"hello"},
            )
        ),
        create=True,
    ):
        result = handler.extract(fake_7z, extract_dir, ExtractionLimits(), password="secret")

    assert result.password_protected is False
    assert len(result.files) == 1


def test_extract_7z_success_with_detected_encryption_sets_password_protected(tmp_path):
    """7z preflight needs_password() marks encrypted archives on successful extraction."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted-detected.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")
    extract_dir = tmp_path / "out-7z-detected"
    extract_dir.mkdir()
    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                True,
                file_payloads={"a.txt": b"hello"},
            )
        ),
        create=True,
    ):
        result = handler.extract(fake_7z, extract_dir, ExtractionLimits(), password="secret")

    assert result.password_protected is True
    assert len(result.files) == 1


def test_extract_7z_preflight_max_files_blocks_cli_extraction(tmp_path):
    """7z metadata preflight enforces max_files before any writes."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "too-many.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")
    extract_dir = tmp_path / "out-7z-preflight"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.bin", 1), _FakeArchiveInfo("b.bin", 1)],
                False,
            )
        ),
        create=True,
    ):
        result = handler.extract(fake_7z, extract_dir, ExtractionLimits(max_files=1))

    assert result.malicious is False
    assert result.resource_limited is True
    assert result.reason == "Max files limit exceeded before extraction"
    assert list(extract_dir.iterdir()) == []


def test_extract_7z_preflight_expansion_ratio_blocks_cli_extraction(tmp_path):
    """7z metadata preflight enforces expansion-ratio limits before any writes."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "ratio.7z"
    fake_7z.write_bytes(b"1234567890")
    extract_dir = tmp_path / "out-7z-ratio"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("big.bin", 2000)],
                False,
            )
        ),
        create=True,
    ):
        result = handler.extract(
            fake_7z,
            extract_dir,
            ExtractionLimits(max_expansion_ratio=50.0),
        )

    assert result.malicious is True
    assert result.reason == "Expansion ratio exceeded before extraction"
    assert list(extract_dir.iterdir()) == []


def test_extract_7z_corrupt_input_is_not_mapped_to_wrong_password(tmp_path):
    """7z corruption errors stay as runtime failures."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "corrupt.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                False,
                read_error=RuntimeError("Corrupt input data"),
            )
        ),
        create=True,
    ):
        with pytest.raises(RuntimeError, match="Corrupt input data"):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits(), password="secret")


def test_extract_7z_payload_over_declared_size_is_marked_malicious_without_read_buffering(tmp_path):
    """7z extraction re-checks actual payload bytes without using read()-based buffering."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "oversized.7z"
    fake_7z.write_bytes(b"1234567890")
    extract_dir = tmp_path / "out-7z-oversized"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("tiny.bin", 1)],
                False,
                file_payloads={"tiny.bin": b"x" * 200},
                read_error=AssertionError("read() should not be used for 7z extraction"),
            )
        ),
        create=True,
    ):
        result = handler.extract(
            fake_7z,
            extract_dir,
            ExtractionLimits(
                max_single_file_bytes=100, max_extracted_bytes=150, max_expansion_ratio=100.0
            ),
        )

    assert result.malicious is True
    assert result.reason == "Zip bomb: single file bytes exceeded during extraction"
    assert list(extract_dir.iterdir()) == []


def test_extract_7z_marks_cumulative_actual_output_over_limit_malicious(tmp_path):
    """7z extraction re-checks cumulative extracted bytes from actual output on disk."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "oversized-total.7z"
    fake_7z.write_bytes(b"1234567890")
    extract_dir = tmp_path / "out-7z-oversized-total"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.sevenz_handler.py7zr",
        SimpleNamespace(
            SevenZipFile=lambda *a, **k: _FakeSevenZipArchive(
                [_FakeArchiveInfo("a.bin", 1), _FakeArchiveInfo("b.bin", 1)],
                False,
                file_payloads={"a.bin": b"x" * 90, "b.bin": b"y" * 90},
                read_error=AssertionError("read() should not be used for 7z extraction"),
            )
        ),
        create=True,
    ):
        result = handler.extract(
            fake_7z,
            extract_dir,
            ExtractionLimits(
                max_single_file_bytes=100, max_extracted_bytes=150, max_expansion_ratio=100.0
            ),
        )

    assert result.malicious is True
    assert result.reason == "Zip bomb: total extracted bytes exceeded during extraction"
    assert [file.original_name for file in result.files] == ["a.bin"]
    assert (extract_dir / "a.bin").exists()
    assert not (extract_dir / "b.bin").exists()


# ---------------------------------------------------------------
# RAR handler password tests (subprocess-based)
# ---------------------------------------------------------------


def test_extract_rar_encrypted_without_password_raises_required(tmp_path):
    """RAR handler raises ArchivePasswordRequiredError when password needed."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("a.txt", 10)],
                True,
                password_error="required",
            )
        ),
        create=True,
    ):
        with pytest.raises(ArchivePasswordRequiredError):
            handler.extract(fake_rar, tmp_path / "out", ExtractionLimits())


def test_extract_rar_wrong_password_raises_wrong_password(tmp_path):
    """RAR handler raises ArchiveWrongPasswordError with wrong password."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("a.txt", 10)],
                True,
                password_error="wrong",
            )
        ),
        create=True,
    ):
        with pytest.raises(ArchiveWrongPasswordError):
            handler.extract(fake_rar, tmp_path / "out", ExtractionLimits(), password="bad-pass")


def test_extract_rar_success_with_password_does_not_mark_password_protected(tmp_path):
    """RAR success with a supplied password does not imply encryption was detected."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-success"
    extract_dir.mkdir()
    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                False,
                file_payloads={"a.txt": b"hello"},
            )
        ),
        create=True,
    ):
        result = handler.extract(fake_rar, extract_dir, ExtractionLimits(), password="secret")

    assert result.password_protected is False
    assert len(result.files) == 1


def test_extract_rar_success_with_detected_encryption_sets_password_protected(tmp_path):
    """RAR preflight needs_password() marks encrypted archives on successful extraction."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted-detected.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-detected"
    extract_dir.mkdir()
    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                True,
                file_payloads={"a.txt": b"hello"},
            )
        ),
        create=True,
    ):
        result = handler.extract(fake_rar, extract_dir, ExtractionLimits(), password="secret")

    assert result.password_protected is True
    assert len(result.files) == 1


def test_extract_rar_preflight_total_bytes_blocks_cli_extraction(tmp_path):
    """RAR metadata preflight enforces total extracted bytes before any writes."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "total-bytes.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-preflight"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive([_FakeArchiveInfo("big.bin", 500)], False)
        ),
        create=True,
    ):
        result = handler.extract(
            fake_rar,
            extract_dir,
            ExtractionLimits(max_extracted_bytes=100),
        )

    assert result.malicious is False
    assert result.resource_limited is True
    assert result.reason == "Max total extracted bytes exceeded before extraction"
    assert list(extract_dir.iterdir()) == []


def test_extract_rar_preflight_single_file_blocks_cli_extraction(tmp_path):
    """RAR metadata preflight enforces max_single_file_bytes before any writes."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "single-file.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-single"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive([_FakeArchiveInfo("huge.bin", 500)], False)
        ),
        create=True,
    ):
        result = handler.extract(
            fake_rar,
            extract_dir,
            ExtractionLimits(max_single_file_bytes=100),
        )

    assert result.malicious is False
    assert result.resource_limited is True
    assert result.reason == "Single file size limit exceeded before extraction"
    assert list(extract_dir.iterdir()) == []


def test_extract_rar_corrupt_input_is_not_mapped_to_wrong_password(tmp_path):
    """RAR corruption errors stay as runtime failures."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "corrupt.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("a.txt", 5)],
                False,
                read_error=RuntimeError("Corrupt RAR data"),
            )
        ),
        create=True,
    ):
        with pytest.raises(RuntimeError, match="Corrupt RAR data"):
            handler.extract(fake_rar, tmp_path / "out", ExtractionLimits(), password="secret")


def test_extract_rar_streaming_single_file_limit_is_marked_malicious(tmp_path):
    """RAR extraction rejects files whose streamed bytes exceed the single-file limit."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "oversized-single.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-oversized-single"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("tiny.bin", 1)],
                False,
                file_payloads={"tiny.bin": b"x" * 200},
            )
        ),
        create=True,
    ):
        result = handler.extract(
            fake_rar,
            extract_dir,
            ExtractionLimits(
                max_single_file_bytes=100, max_extracted_bytes=500, max_expansion_ratio=100.0
            ),
        )

    assert result.malicious is True
    assert result.reason == "Zip bomb: single file bytes exceeded during extraction"
    assert not any(path.is_file() for path in extract_dir.rglob("*"))


def test_extract_rar_streaming_total_limit_is_marked_malicious(tmp_path):
    """RAR extraction treats streamed total-byte overruns as malicious, not partial success."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "oversized-total.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")
    extract_dir = tmp_path / "out-rar-oversized-total"
    extract_dir.mkdir()

    with patch(
        "malscan_worker.extractors.rar_handler.rarfile",
        SimpleNamespace(
            RarFile=lambda *a, **k: _FakeRarArchive(
                [_FakeArchiveInfo("tiny.bin", 1)],
                False,
                file_payloads={"tiny.bin": b"x" * 200},
            )
        ),
        create=True,
    ):
        result = handler.extract(
            fake_rar,
            extract_dir,
            ExtractionLimits(
                max_single_file_bytes=500, max_extracted_bytes=100, max_expansion_ratio=100.0
            ),
        )

    assert result.malicious is True
    assert result.reason == "Zip bomb: total extracted bytes exceeded during extraction"
    assert not any(path.is_file() for path in extract_dir.rglob("*"))


class _FakeNeedsPasswordArchive:
    def __init__(self, needs_password, password_error=None):
        self._needs_password = needs_password
        self._password_error = password_error

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def needs_password(self):
        return self._needs_password


class _FakeArchiveInfo:
    def __init__(self, filename, uncompressed):
        self.filename = filename
        self.uncompressed = uncompressed
        self.file_size = uncompressed


class _FakeSevenZipArchive(_FakeNeedsPasswordArchive):
    def __init__(
        self, members, needs_password, file_payloads=None, password_error=None, read_error=None
    ):
        super().__init__(needs_password, password_error=password_error)
        self._members = members
        self._file_payloads = file_payloads or {}
        self._read_error = read_error

    def list(self):
        return self._members

    def read(self, targets=None):
        if self._password_error == "required":
            raise _FakePasswordRequiredError("password required")
        if self._password_error == "wrong":
            raise RuntimeError("Corrupt input data")
        if self._read_error is not None:
            raise self._read_error
        target = targets[0]
        return {target: self._file_payloads[target]}

    def extract(self, path=None, targets=None):
        if self._password_error == "required":
            raise _FakePasswordRequiredError("password required")
        if self._password_error == "wrong":
            raise RuntimeError("Corrupt input data")
        for target in targets or []:
            if self._read_error is not None and target not in self._file_payloads:
                raise self._read_error
            dest = path / target
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self._file_payloads[target])

    def reset(self):
        return None


class _FakeRarArchive(_FakeNeedsPasswordArchive):
    def __init__(
        self, members, needs_password, file_payloads=None, password_error=None, read_error=None
    ):
        super().__init__(needs_password, password_error=password_error)
        self._members = members
        self._file_payloads = file_payloads or {}
        self._read_error = read_error

    def infolist(self):
        return self._members

    def open(self, member, pwd=None):
        if self._password_error == "required":
            raise _FakePasswordRequiredError("password required")
        if self._password_error == "wrong":
            raise _FakeRarWrongPasswordError("wrong password")
        if self._read_error is not None:
            raise self._read_error
        return _FakeBinaryStream(self._file_payloads[member.filename])


class _FakeBinaryStream:
    def __init__(self, payload):
        self._payload = payload
        self._offset = 0

    def read(self, size=-1):
        if size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakePasswordRequiredError(Exception):
    pass


class _FakeRarWrongPasswordError(Exception):
    pass
