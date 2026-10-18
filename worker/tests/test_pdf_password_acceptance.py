"""Acceptance guards reject stale fixture pins and misleading password reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from malscan_worker.quality.pdf_password_acceptance import (
    _check_secrets,
    _completed_stages,
    _waiting,
    load_manifest,
)
from malscan_worker.quality.pdf_password_fixtures import PDF_PASSWORD

_MANIFEST = Path(__file__).parents[1] / "quality" / "pdf-password-v1.json"


def test_pdf_password_suite_pins_every_crypto_profile() -> None:
    suite = load_manifest(_MANIFEST)
    assert len(suite["cases"]) == 12
    assert {case["scenario"] for case in suite["cases"]} == {"prompt", "empty", "nested"}
    assert sum(case["active_actions"] for case in suite["cases"]) == 5


@pytest.mark.parametrize("mutation", ["hash", "size", "duplicate", "scenario", "rules"])
def test_suite_rejects_corrupted_or_ambiguous_controls(tmp_path: Path, mutation: str) -> None:
    suite = json.loads(_MANIFEST.read_text())
    if mutation == "hash":
        suite["cases"][0]["sha256"] = "0" * 64
    elif mutation == "size":
        suite["cases"][0]["bytes"] += 1
    elif mutation == "duplicate":
        suite["cases"].append(suite["cases"][0])
    elif mutation == "scenario":
        suite["cases"][0]["scenario"] = "pretend-success"
    else:
        suite["rules_sha256"] = "unpinned"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(suite))
    with pytest.raises(ValueError):
        load_manifest(path)


def test_wait_guard_binds_incomplete_challenge_to_occurrence() -> None:
    report = {
        "job_status": "password_required",
        "report_complete": False,
        "password_required_artifacts": ["pdf-child"],
        "artifacts": [
            {
                "artifact_id": "pdf-child",
                "sha256": "abc",
                "status": "password_required",
                "reason": "wrong_password",
            }
        ],
    }
    assert _waiting(report, "abc", wrong=True) == "pdf-child"
    with pytest.raises(ValueError, match="expected occurrence"):
        _waiting(report, "different-hash")
    report["report_complete"] = True
    with pytest.raises(ValueError, match="completed execution"):
        _waiting(report, "abc")


def test_secret_guard_checks_checkpoint_and_public_reports(tmp_path: Path) -> None:
    nested = tmp_path / "state"
    nested.mkdir()
    (tmp_path / "source.pdf").write_bytes(b"binary fixture: " + PDF_PASSWORD.encode())
    _check_secrets(tmp_path)
    (nested / "checkpoint.json").write_text(json.dumps({"accidental_password": PDF_PASSWORD}))
    with pytest.raises(ValueError, match="leaked"):
        _check_secrets(tmp_path)


def test_only_successful_stage_documents_are_eligible_for_reuse() -> None:
    state = {
        "artifacts": {
            "parent": {
                "stage_results": [
                    {"stage_name": "yara", "status": "ok", "findings": []},
                    {"stage_name": "format-analysis", "status": "password_required"},
                    {"stage_name": "archive-extract", "status": "skipped"},
                ]
            }
        }
    }
    assert set(_completed_stages(state)) == {("parent", "yara"), ("parent", "archive-extract")}


def test_private_case_entrypoint_preserves_existing_evidence(tmp_path: Path, monkeypatch) -> None:
    from malscan_worker.quality.pdf_password_acceptance import main

    output = tmp_path / "existing-case"
    output.mkdir()
    retained = output / "case-result.json"
    original = '{"retained_evidence":true}\n'
    retained.write_text(original)
    monkeypatch.setattr(
        "sys.argv",
        [
            "pdf-password-acceptance",
            "--manifest",
            str(_MANIFEST),
            "--output-dir",
            str(output),
            "--execute-case",
            "rc4-40-normal",
        ],
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert retained.read_text() == original
