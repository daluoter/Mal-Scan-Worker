"""Base64 observations, useful payload retention and bounded discovery controls."""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path

import pytest
from malscan_worker.deobfuscation.decoders.base import DecoderExtraction
from malscan_worker.deobfuscation.decoders.base64_decoder import Base64Decoder
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.deobfuscation import DeobfuscationStage


def _engine(decoder: Base64Decoder, *, limit: int = 25) -> DeobfuscationEngine:
    return DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=100,
        per_decoder_limit=limit,
        confidence_threshold=0.5,
        max_wall_time_seconds=2,
    )


@pytest.mark.parametrize("token", [b"/OpenAction", b"/JavaScript", b"/NormalName"])
def test_pdf_names_are_traceable_observations_even_when_decodable(token: bytes) -> None:
    source = b"<< " + token + b" null >>"
    candidate = Base64Decoder().extract_candidates(source, 25)[0]
    meta = candidate.provenance.meta
    assert meta["score_eligible"] is False
    assert meta["evidence_class"] == "ambiguous_encoding"
    assert meta["assessment_version"] == "base64-evidence-v1"
    assert candidate.provenance.offset == 3
    assert candidate.provenance.length == len(token)
    assert candidate.content == base64.b64decode(token + b"=" * (-len(token) % 4))
    assert "ambiguous_base64" in candidate.tags


@pytest.mark.parametrize("padded", [True, False])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_meaningful_text_survives_with_or_without_padding(padded: bool, encoding: str) -> None:
    payload = "https://quality.invalid/inert".encode(encoding)
    token = base64.b64encode(payload)
    if not padded:
        token = token.rstrip(b"=")
    candidate = Base64Decoder().extract_candidates(token, 25)[0]
    assert candidate.content == payload
    assert candidate.provenance.meta["score_eligible"] is True
    assert candidate.provenance.meta["canonical_encoding"] is True


def test_noncanonical_padding_does_not_suppress_actual_url() -> None:
    payload = b"https://quality.invalid/inert"
    canonical = base64.b64encode(payload)
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    position = len(canonical.rstrip(b"=")) - 1
    changed = bytearray(canonical)
    changed[position] = alphabet[alphabet.index(changed[position]) + 1]
    assert bytes(changed) != canonical
    assert base64.b64decode(changed, validate=True) == payload
    candidate = Base64Decoder().extract_candidates(bytes(changed), 25)[0]
    assert candidate.content == payload
    assert candidate.provenance.meta["canonical_encoding"] is False
    assert candidate.provenance.meta["score_eligible"] is True


@pytest.mark.parametrize("payload", [b"alert('inert');", b"MZ\x00\x01\x02\x03\x04\x05\x06"])
def test_script_and_known_binary_are_preserved_without_url(payload: bytes) -> None:
    candidate = Base64Decoder().extract_candidates(base64.b64encode(payload).rstrip(b"="), 25)[0]
    assert candidate.content == payload
    assert candidate.provenance.meta["score_eligible"] is True


@pytest.mark.parametrize("call", [b"atob", b"base64_decode", b"b64decode", b"FromBase64String"])
def test_explicit_decoder_context_can_upgrade_opaque_binary(call: bytes) -> None:
    payload = bytes(range(16)) + b"\xff"
    token = base64.b64encode(payload)
    source = token + b"; " + call + b"('" + token + b"')"
    result = _engine(Base64Decoder()).run(source)
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.content == payload
    assert candidate.provenance.meta["evidence_class"] == "decoder_call_hint"
    assert candidate.provenance.meta["score_eligible"] is True
    assert candidate.provenance.offset == source.rindex(token)


def test_canonical_unknown_binary_is_retained_without_score() -> None:
    payload = bytes(range(16)) + b"\xff"
    candidate = Base64Decoder().extract_candidates(base64.b64encode(payload), 25)[0]
    assert candidate.content == payload
    assert candidate.provenance.meta["canonical_encoding"] is True
    assert candidate.provenance.meta["score_eligible"] is False


def test_repeated_weak_and_strong_payloads_do_not_starve_later_url() -> None:
    first = b"https://quality.invalid/first"
    second = b"https://quality.invalid/second"
    source = (
        b"/OpenAction /JavaScript " * 30
        + (base64.b64encode(first) + b" ") * 30
        + base64.b64encode(second)
    )
    result = _engine(Base64Decoder(), limit=2).run(source)
    assert result.iocs["urls"] == [first.decode(), second.decode()]
    assert len(result.candidates) == 2
    # Omitted observations are disclosed as incomplete output.
    assert result.stats.candidate_cap_reached is True


def test_cooperative_deadline_preserves_completed_candidates() -> None:
    class InterruptedDecoder(Base64Decoder):
        def extract_candidates_guarded(
            self, content: bytes, limit: int, should_stop: Callable[[], bool]
        ) -> DecoderExtraction:
            checks = iter([False, True])
            return super().extract_candidates_guarded(content, limit, lambda: next(checks))

    first = b"https://quality.invalid/first"
    second = b"https://quality.invalid/second"
    source = base64.b64encode(first) + b" " + base64.b64encode(second)
    result = _engine(InterruptedDecoder()).run(source)
    assert result.iocs["urls"] == [first.decode()]
    assert len(result.candidates) == 1
    assert result.stats.stop_reason == "wall_time"
    assert result.stats.truncated is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "score"),
    [
        (b"<< /OpenAction null /JavaScript null >>", 0),
        (base64.b64encode(b"https://quality.invalid/inert"), 4),
    ],
)
async def test_real_stage_and_shared_scorer_distinguish_observation_from_evidence(
    tmp_path: Path, source: bytes, score: int
) -> None:
    path = tmp_path / "fixture.pdf"
    path.write_bytes(source)
    ctx = StageContext(
        job_id="job",
        file_id="file",
        storage_key="fixture",
        sha256="a" * 64,
        original_filename=path.name,
        file_path=path,
    )
    stage = await DeobfuscationStage().execute(ctx)
    assert stage.status == "ok"
    report = _build_analysis_result("job", "file", ctx, [stage], total_ms=1)
    assert report["score"] == score
    assert report["results"]["deobfuscation"]["candidates"]
    if score == 0:
        assert not any(item["points"] for item in report["risk"]["evidence"])
    else:
        assert report["results"]["iocs"]["urls"] == ["https://quality.invalid/inert"]
