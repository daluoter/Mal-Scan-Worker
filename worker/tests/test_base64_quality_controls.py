"""Frozen Q-06 controls exercise genuine PDF syntax and decoded payload retention."""

from __future__ import annotations

import base64
import hashlib
import io
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from malscan_worker.quality.corpus import fixture_bytes, load_corpus
from malscan_worker.rule_provenance import load_rule_bundle
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.deobfuscation import DeobfuscationStage
from pypdf import PdfReader

_MANIFEST = Path(__file__).parents[1] / "quality" / "corpus-v5.json"
_RULES = Path(__file__).parents[1] / "rules"
_CORPUS = load_corpus(_MANIFEST)
_NEW_SHA256 = {
    "pdf-name-dictionary": "530808fae789a8e9206614a4331f6a8e4f55bd11971840e234731fd7b8cfe4f9",
    "pdf-encoded-url-string": "c7ec83deadcd03974e7e3f90405638ac80456ae3be346d713d75e2118bf14a9b",
    "pdf-name-text": "a830d813e9534d958f877899934281fcfa5f1d038cf36e634eb5bd7ace1380eb",
    "base64-binary": "9e0a5a1f18107e8fe389edbdbd90292fb55f795894bc96efd45599be66ce549a",
    "base64-malformed": "ecb441d2562227a36ebf6dea63724c20c155b7e6599337c7d5dfb7de5e2732b6",
    "base64-inert-text": "e19d9a8ed3af4152148c0ce8188816f4889c27b028ff371aac4f6a3e89472923",
    "base64-noncanonical-url": "716d43602c1508f9de704649cc972851ddc93aba6fda164a5b8a801aad44e3cd",
    "opaque-prefix-then-url": "01178467d5b46bc7940bfd81f7cf12ce192a3c4e7a31e342455b9a3b980e742d",
}


def _bytes(name: str) -> bytes:
    return fixture_bytes(_CORPUS["fixtures"], name)


def _context(tmp_path: Path, name: str) -> StageContext:
    payload = _bytes(name)
    path = tmp_path / (name + ".pdf" if name.startswith("pdf-") else name + ".txt")
    path.write_bytes(payload)
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id="quality-fixture",
        storage_key="quality-fixture",
        sha256=hashlib.sha256(payload).hexdigest(),
        original_filename=path.name,
        file_path=path,
        skip_artifact_submission=True,
    )


@pytest.mark.parametrize("name", sorted(_CORPUS["fixtures"]))
def test_v5_fixture_inputs_remain_reproducible_and_checksum_pinned(name: str) -> None:
    payload = _bytes(name)
    assert payload == _bytes(name)
    assert len(payload) < 1_000_000
    assert hashlib.sha256(payload).hexdigest() == _CORPUS["fixtures"][name]["sha256"]
    if name in _NEW_SHA256:
        assert hashlib.sha256(payload).hexdigest() == _NEW_SHA256[name]


def test_q06_dataset_extends_v4_without_replacing_historical_inputs_or_policy() -> None:
    historical = load_corpus(_MANIFEST.with_name("corpus-v4.json"))
    assert _CORPUS["corpus_version"] == "static-quality-v5.0.0"
    assert _CORPUS["baseline_corpus_version"] == historical["corpus_version"]
    assert _CORPUS["policy_version"] == historical["policy_version"] == "msrs-v1.2"
    assert _CORPUS["rules_sha256"] == historical["rules_sha256"]
    assert len(_CORPUS["cases"]) == len(historical["cases"]) + 8 == 40
    for name, definition in historical["fixtures"].items():
        assert _CORPUS["fixtures"][name] == definition
    assert {case["id"] for case in historical["cases"]} < {case["id"] for case in _CORPUS["cases"]}


@pytest.mark.parametrize("name", sorted(_NEW_SHA256))
def test_new_controls_have_reviewed_native_yara_expectations(name: str) -> None:
    case = next(case for case in _CORPUS["cases"] if case["id"] == name)
    actual = load_rule_bundle(_RULES).rules.match(data=_bytes(name))
    assert sorted(match.rule for match in actual) == case["expect"]["yara_rules"]


def test_pdf_name_dictionary_is_valid_but_contains_no_active_action() -> None:
    reader = PdfReader(io.BytesIO(_bytes("pdf-name-dictionary")))
    assert len(reader.pages) == 1
    catalog = reader.trailer["/Root"]
    names = catalog["/QualityDictionary"]
    assert set(names) == {"/OpenAction", "/JavaScript", "/NormalName"}
    assert "/OpenAction" not in catalog
    assert "/AA" not in catalog
    assert "/Names" not in catalog


def test_encoded_url_is_a_real_pdf_string_not_an_action_or_dictionary_name() -> None:
    reader = PdfReader(io.BytesIO(_bytes("pdf-encoded-url-string")))
    catalog = reader.trailer["/Root"]
    encoded = str(catalog["/QualityEncoded"]).encode("ascii")
    assert base64.b64decode(encoded, validate=True) == b"https://quality.invalid/inert"
    assert "/OpenAction" not in catalog
    assert "/AA" not in catalog


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", ["pdf-name-dictionary", "pdf-name-text", "base64-malformed", "pdf-active-actions"]
)
async def test_native_deobfuscation_retains_opaque_observations_without_inventing_risk(
    tmp_path: Path, name: str
) -> None:
    result = await DeobfuscationStage().execute(_context(tmp_path, name))
    assert result.status == "ok"
    assert result.findings["candidates"]
    assert all(candidate["score_eligible"] is False for candidate in result.findings["candidates"])
    assert result.findings["techniques_found"] == []
    assert result.findings["observed_techniques"] == ["base64"]
    assert result.findings["total_decoded_bytes"] > 0
    assert result.findings["extracted_iocs"] == {
        "urls": [],
        "domains": [],
        "ips": [],
        "commands": [],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "decoded"),
    [
        ("pdf-encoded-url-string", b"https://quality.invalid/inert"),
        ("encoded-url", b"https://example.com/quality"),
        ("base64-binary", bytes(range(16)) + b"\xff"),
        ("base64-inert-text", b"Inert quality control text."),
    ],
)
async def test_native_deobfuscation_keeps_actual_text_binary_and_url_candidates(
    tmp_path: Path, name: str, decoded: bytes
) -> None:
    source = _bytes(name)
    result = await DeobfuscationStage().execute(_context(tmp_path, name))
    assert result.status == "ok"
    eligible = name != "base64-binary"
    assert result.findings["techniques_found"] == (["base64"] if eligible else [])
    assert result.findings["observed_techniques"] == ["base64"]
    candidates = result.findings["candidates"]
    matching = [item for item in candidates if item["score_eligible"] is eligible]
    assert len(matching) == 1
    candidate = matching[0]
    if name == "pdf-encoded-url-string":
        # The real PDF dictionary name is separately retained as an observation.
        assert any(not item["score_eligible"] for item in candidates)
    else:
        assert len(candidates) == 1
    assert candidate["score_eligible"] is eligible
    actual = (
        base64.b64decode(candidate["content"], validate=True)
        if candidate["content_encoding"] == "base64"
        else candidate["content"].encode()
    )
    assert actual == decoded
    assert candidate["content_byte_length"] == len(decoded)
    assert candidate["content_truncated"] is False
    provenance = candidate["provenance"]
    token = source[provenance["offset"] : provenance["offset"] + provenance["length"]]
    assert base64.b64decode(token, validate=True) == decoded
    if decoded.startswith(b"https://"):
        assert result.findings["extracted_iocs"]["urls"] == [decoded.decode()]
    else:
        assert result.findings["extracted_iocs"]["urls"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["base64-noncanonical-url", "opaque-prefix-then-url"])
async def test_meaningful_url_survives_noncanonical_padding_and_opaque_token_prefix(
    tmp_path: Path, name: str
) -> None:
    result = await DeobfuscationStage().execute(_context(tmp_path, name))
    assert result.status == "ok"
    assert result.findings["techniques_found"] == ["base64"]
    assert result.findings["observed_techniques"] == ["base64"]
    assert result.findings["extracted_iocs"]["urls"] == ["https://quality.invalid/inert"]
    eligible = [item for item in result.findings["candidates"] if item["score_eligible"]]
    assert len(eligible) == 1
    assert eligible[0]["content"] == "https://quality.invalid/inert"


@pytest.mark.asyncio
async def test_candidate_limit_remains_explicitly_incomplete_after_noise_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(deobfuscation_max_candidates=1),
    )
    result = await DeobfuscationStage().execute(_context(tmp_path, "two-encoded-urls"))
    assert result.status == "partial"
    assert result.findings["stats"]["candidate_cap_reached"] is True
    assert result.findings["stats"]["truncated"] is True
    assert result.findings["reason"] == "Deobfuscation incomplete: candidate_cap"
    assert len(result.findings["candidates"]) == 1


@pytest.mark.asyncio
async def test_input_size_limit_is_not_relabelled_as_successful_empty_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.deobfuscation.get_settings",
        lambda: SimpleNamespace(deobfuscation_max_file_size=1),
    )
    result = await DeobfuscationStage().execute(_context(tmp_path, "clean"))
    assert result.status == "skipped"
    assert "File too large" in result.findings["reason"]
    assert "candidates" not in result.findings


def test_manifest_preserves_active_pdf_evidence_and_failure_contracts() -> None:
    cases: dict[str, Any] = {case["id"]: case for case in _CORPUS["cases"]}
    active = cases["pdf-active-actions"]["expect"]
    assert (active["risk_score_min"], active["risk_score_max"]) == (84, 84)
    assert {check.get("includes") for check in active["checks"] if "includes" in check} >= {
        "embedded_javascript",
        "launch_action",
    }
    for identifier, stage_status in (
        ("deobfuscation-candidate-limit", "partial"),
        ("deobfuscation-size-limit", "skipped"),
    ):
        expected = cases[identifier]["expect"]
        assert expected["static_status"] == "partial"
        assert expected["root_stages"]["deobfuscation"] == stage_status
