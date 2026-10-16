"""Tests for deobfuscation stage wrapper behavior."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from malscan_worker.deobfuscation.models import (
    CandidateProvenance,
    DeobfuscationCandidate,
    DeobfuscationResult,
    DeobfuscationRunStats,
)
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.deobfuscation import DeobfuscationStage


def _context_for_file(file_path: Path) -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key-1",
        sha256="a" * 64,
        original_filename=file_path.name,
        file_path=file_path,
    )


@pytest.mark.asyncio
async def test_deobfuscation_stage_skips_when_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"hello")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(deobfuscation_enabled=False),
    )

    result = await DeobfuscationStage().execute(ctx)

    assert result.stage_name == "deobfuscation"
    assert result.status == "skipped"
    assert result.findings["reason"] == "Deobfuscation disabled"


@pytest.mark.asyncio
async def test_deobfuscation_stage_skips_when_file_too_large(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"abcd")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=3,
        ),
    )

    result = await DeobfuscationStage().execute(ctx)

    assert result.stage_name == "deobfuscation"
    assert result.status == "skipped"
    assert "File too large" in result.findings["reason"]


@pytest.mark.asyncio
async def test_deobfuscation_stage_success_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"payload")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=1024,
            deobfuscation_max_candidates=32,
            deobfuscation_per_decoder_limit=16,
            deobfuscation_confidence_threshold=0.25,
            deobfuscation_max_wall_time_seconds=1.5,
            deobfuscation_min_base64_length=8,
            deobfuscation_xor_min_decoded_length=8,
        ),
    )

    captured_kwargs: dict[str, object] = {}

    class _FakeEngine:
        def __init__(self, **kwargs) -> None:
            captured_kwargs.update(kwargs)

        def run(self, content: bytes) -> DeobfuscationResult:
            assert content == b"payload"
            candidate = DeobfuscationCandidate(
                content=b"http://evil.test",
                confidence=0.92,
                technique="base64",
                provenance=CandidateProvenance(
                    decoder="base64",
                    offset=5,
                    length=20,
                ),
            )
            return DeobfuscationResult(
                candidates=[candidate],
                iocs={
                    "urls": ["http://evil.test"],
                    "domains": ["evil.test"],
                    "ips": [],
                    "commands": [],
                },
                stats=DeobfuscationRunStats(input_bytes=len(content), final_candidate_count=1),
            )

    monkeypatch.setattr("malscan_worker.stages.deobfuscation.DeobfuscationEngine", _FakeEngine)

    result = await DeobfuscationStage().execute(ctx)

    assert result.status == "ok"
    assert "candidates" in result.findings
    assert "extracted_iocs" in result.findings
    assert result.findings["extracted_iocs"] == {
        "urls": ["http://evil.test"],
        "domains": ["evil.test"],
        "ips": [],
        "commands": [],
    }
    assert result.findings["candidates"] == [
        {
            "content": "http://evil.test",
            "decoded_id": "decoded::job-1::1",
            "source_stage": "deobfuscation",
            "content_encoding": "utf-8",
            "content_byte_length": 16,
            "serialized_content_byte_length": 16,
            "content_truncated": False,
            "confidence": 0.92,
            "technique": "base64",
            "truncated": False,
            "tags": [],
            "provenance": {
                "decoder": "base64",
                "offset": 5,
                "length": 20,
                "key": None,
                "meta": {},
            },
        }
    ]
    assert captured_kwargs["max_candidates"] == 32
    assert captured_kwargs["per_decoder_limit"] == 16
    assert captured_kwargs["confidence_threshold"] == 0.25
    assert captured_kwargs["max_wall_time_seconds"] == 1.5
    decoders = captured_kwargs["decoders"]
    assert isinstance(decoders, list)
    assert len(decoders) == 6
    assert decoders[0]._min_decoded_length == 8
    assert decoders[-1]._min_decoded_length == 8


@pytest.mark.asyncio
async def test_deobfuscation_stage_serializes_non_utf8_candidate_without_data_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=1024,
        ),
    )

    class _FakeEngine:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run(self, content: bytes) -> DeobfuscationResult:
            assert content == b"payload"
            candidate = DeobfuscationCandidate(
                content=b"\xff\xfe\x80\x00A",
                confidence=0.61,
                technique="xor",
                provenance=CandidateProvenance(
                    decoder="xor",
                    offset=0,
                    length=5,
                ),
            )
            return DeobfuscationResult(
                candidates=[candidate],
                iocs={
                    "urls": [],
                    "domains": [],
                    "ips": [],
                    "commands": [],
                },
                stats=DeobfuscationRunStats(input_bytes=len(content), final_candidate_count=1),
            )

    monkeypatch.setattr("malscan_worker.stages.deobfuscation.DeobfuscationEngine", _FakeEngine)

    result = await DeobfuscationStage().execute(ctx)

    assert result.status == "ok"
    candidate = result.findings["candidates"][0]
    assert candidate["content_encoding"] == "base64"
    assert candidate["content_byte_length"] == 5
    assert candidate["serialized_content_byte_length"] == 5
    assert candidate["content_truncated"] is False
    assert candidate["content"] == base64.b64encode(b"\xff\xfe\x80\x00A").decode("ascii")


@pytest.mark.asyncio
async def test_deobfuscation_stage_default_threshold_emits_base64_candidate_and_ioc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"prefix aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo suffix")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=1024,
            deobfuscation_min_base64_length=8,
            deobfuscation_xor_min_decoded_length=8,
            deobfuscation_max_candidates=32,
            deobfuscation_per_decoder_limit=16,
            deobfuscation_max_wall_time_seconds=1.5,
        ),
    )

    result = await DeobfuscationStage().execute(ctx)

    assert result.status == "ok"
    assert len(result.findings["candidates"]) >= 1
    assert len(result.findings["extracted_iocs"]["urls"]) >= 1
    assert "https://example.com/path" in result.findings["extracted_iocs"]["urls"]


@pytest.mark.asyncio
async def test_real_candidate_cap_keeps_decoded_evidence_and_marks_report_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from malscan_worker.pipeline import build_analysis_result

    first_url = b"https://first.example/path"
    second_url = b"https://second.example/path"
    sample = tmp_path / "two-encoded-urls.txt"
    sample.write_bytes(base64.b64encode(first_url) + b"\n" + base64.b64encode(second_url))
    ctx = _context_for_file(sample)
    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_candidates=1,
            deobfuscation_per_decoder_limit=16,
            deobfuscation_max_wall_time_seconds=10,
        ),
    )

    result = await DeobfuscationStage().execute(ctx)
    report = build_analysis_result(ctx.job_id, ctx.file_id, ctx, [result], result.duration_ms)

    assert result.status == "partial"
    assert result.error is None
    assert result.findings["stats"]["truncated"] is True
    assert result.findings["stats"]["stop_reason"] == "candidate_cap"
    assert "candidate_cap" in result.findings["reason"]
    candidates = result.findings["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["content"] == first_url.decode()
    assert first_url.decode() in result.findings["extracted_iocs"]["urls"]
    assert second_url.decode() not in result.findings["extracted_iocs"]["urls"]
    assert report["analysis"]["static"]["status"] == "partial"
    coverage = report["analysis"]["static"]["stage_coverage"]
    assert coverage[0]["stage"] == "deobfuscation"
    assert coverage[0]["status"] == "partial"
    assert "candidate_cap" in coverage[0]["reason"]
    assert report["results"]["deobfuscation"]["candidates"] == candidates


@pytest.mark.asyncio
async def test_deobfuscation_stage_truncates_serialized_candidate_content_by_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"payload")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=1024,
            deobfuscation_max_candidate_bytes=8,
        ),
    )

    class _FakeEngine:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run(self, content: bytes) -> DeobfuscationResult:
            assert content == b"payload"
            candidate = DeobfuscationCandidate(
                content=b"http://evil.test",
                confidence=0.61,
                technique="base64",
                provenance=CandidateProvenance(
                    decoder="base64",
                    offset=0,
                    length=20,
                ),
            )
            return DeobfuscationResult(
                candidates=[candidate],
                iocs={
                    "urls": ["http://evil.test"],
                    "domains": ["evil.test"],
                    "ips": [],
                    "commands": [],
                },
                stats=DeobfuscationRunStats(input_bytes=len(content), final_candidate_count=1),
            )

    monkeypatch.setattr("malscan_worker.stages.deobfuscation.DeobfuscationEngine", _FakeEngine)

    result = await DeobfuscationStage().execute(ctx)

    assert result.status == "ok"
    candidate = result.findings["candidates"][0]
    assert candidate["content"] == "http://e"
    assert candidate["content_encoding"] == "utf-8"
    assert candidate["content_byte_length"] == 16
    assert candidate["serialized_content_byte_length"] == 8
    assert candidate["content_truncated"] is True


@pytest.mark.asyncio
async def test_deobfuscation_stage_engine_exception_returns_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"payload")
    ctx = _context_for_file(sample)

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(
            deobfuscation_enabled=True,
            deobfuscation_max_file_size=1024,
        ),
    )

    class _ExplodingEngine:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run(self, content: bytes) -> DeobfuscationResult:
            del content
            raise RuntimeError("engine boom")

    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.DeobfuscationEngine",
        _ExplodingEngine,
    )

    result = await DeobfuscationStage().execute(ctx)

    assert result.stage_name == "deobfuscation"
    assert result.status == "failed"
    assert result.error is not None
    assert "engine boom" in result.error
