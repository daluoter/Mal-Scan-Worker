"""Reject stale Office inputs and misleading plaintext, password or resume evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from malscan_worker.quality import office_password_acceptance as acceptance
from malscan_worker.quality.office_password_fixtures import (
    ARCHIVE_PASSWORD,
    NESTED_OFFICE_PROFILES,
    OFFICE_PASSWORD,
    OFFICE_PASSWORD_PROFILES,
    SECOND_OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_plaintext_fixture,
)

_MANIFEST = Path(__file__).parents[1] / "quality" / "office-password-v1.json"


def test_suite_pins_all_office_families_and_independent_nested_occurrences() -> None:
    suite = acceptance.load_manifest(_MANIFEST)
    assert len(suite["cases"]) == 14
    assert {case["profile"] for case in suite["cases"]} == set(OFFICE_PASSWORD_PROFILES)
    assert {case["scenario"] for case in suite["cases"]} == {
        "prompt",
        "nested",
        "unsupported",
        "corrupt",
    }
    prompt = [case for case in suite["cases"] if case["scenario"] == "prompt"]
    assert {case["document_type"] for case in prompt} == {
        "docx",
        "xlsx",
        "pptx",
        "docm",
        "xlsm",
        "pptm",
    }
    assert {case["encryption"] for case in prompt} == {"agile-aes256", "standard-aes128"}
    siblings = next(case for case in suite["cases"] if case["id"] == "zip-aes-office-two-siblings")
    assert tuple(child["profile"] for child in siblings["nested_children"]) == (
        NESTED_OFFICE_PROFILES[siblings["profile"]]
    )
    assert len({child["plaintext_sha256"] for child in siblings["nested_children"]}) == 2
    assert any(case.get("external_template") is True for case in prompt)


@pytest.mark.parametrize(
    "mutation",
    [
        "hash",
        "size",
        "bool_size",
        "bool_version",
        "too_many",
        "duplicate",
        "profile",
        "scenario",
        "rules",
        "policy",
        "plaintext_hash",
        "plaintext_size",
        "plaintext_type",
        "macro_flag",
        "external_template",
        "encryption",
        "password_label",
        "wrong_expectation",
        "nested_inventory",
        "nested_filename",
        "negative_plaintext",
        "non_mapping_case",
    ],
)
def test_suite_rejects_corrupted_or_ambiguous_controls(tmp_path: Path, mutation: str) -> None:
    suite = json.loads(_MANIFEST.read_text())
    case = suite["cases"][0]
    nested = next(case for case in suite["cases"] if case["id"] == "zip-aes-office-two-siblings")
    negative = next(case for case in suite["cases"] if case["id"] == "unsupported-encryption")
    if mutation == "hash":
        case["sha256"] = "0" * 64
    elif mutation == "size":
        case["bytes"] += 1
    elif mutation == "bool_size":
        case["bytes"] = True
    elif mutation == "bool_version":
        suite["schema_version"] = True
    elif mutation == "too_many":
        suite["cases"] *= 2
    elif mutation == "duplicate":
        suite["cases"].append(copy.deepcopy(case))
    elif mutation == "profile":
        case["profile"] = "unknown"
    elif mutation == "scenario":
        case["scenario"] = "unsupported"
    elif mutation == "rules":
        suite["rules_sha256"] = "not-pinned"
    elif mutation == "policy":
        suite["policy_version"] = None
    elif mutation == "plaintext_hash":
        case["plaintext_sha256"] = "0" * 64
    elif mutation == "plaintext_size":
        case["plaintext_bytes"] += 1
    elif mutation == "plaintext_type":
        case["document_type"] = "xlsx"
    elif mutation == "macro_flag":
        case["macro_flag"] = "false"
    elif mutation == "external_template":
        case["external_template"] = True
    elif mutation == "encryption":
        case["encryption"] = "standard-aes128"
    elif mutation == "password_label":
        case["office_password_label"] = "SECOND_OFFICE_PASSWORD"
    elif mutation == "wrong_expectation":
        case["expect_wrong_password"] = "success"
    elif mutation == "nested_inventory":
        nested["nested_children"] = nested["nested_children"][:1]
    elif mutation == "nested_filename":
        nested["nested_children"][0]["filename"] = "../../locked.docx"
    elif mutation == "negative_plaintext":
        negative["plaintext_sha256"] = "0" * 64
    else:
        suite["cases"][0] = None
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(suite))
    with pytest.raises(ValueError):
        acceptance.load_manifest(path)


@pytest.mark.parametrize(
    "password", [OFFICE_PASSWORD, SECOND_OFFICE_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD]
)
@pytest.mark.parametrize("filename", ["report.json", "checkpoint.json", "case.log"])
def test_secret_guard_checks_public_reports_durable_state_and_logs(
    tmp_path: Path, password: str, filename: str
) -> None:
    (tmp_path / "source.bin").write_bytes(password.encode())
    acceptance._check_secrets(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    (state / filename).write_text(json.dumps({"accidental_password": password}))
    with pytest.raises(ValueError, match="leaked"):
        acceptance._check_secrets(tmp_path)


def _waiting_report() -> dict[str, Any]:
    return {
        "job_status": "password_required",
        "report_complete": False,
        "password_required_artifacts": ["word", "sheet"],
        "artifacts": [
            {
                "artifact_id": "word",
                "sha256": "aaa",
                "status": "password_required",
                "reason": "wrong_password",
            },
            {
                "artifact_id": "sheet",
                "sha256": "bbb",
                "status": "password_required",
                "reason": "password_required",
            },
        ],
    }


def test_multiple_password_challenges_bind_to_their_independent_occurrences() -> None:
    report = _waiting_report()
    assert acceptance._waiting_artifacts(report, {"aaa", "bbb"}, wrong_ids={"word"}) == {
        "aaa": "word",
        "bbb": "sheet",
    }
    with pytest.raises(ValueError, match="wrong-password"):
        acceptance._waiting_artifacts(report, {"aaa", "bbb"}, wrong_ids={"sheet"})
    report["artifacts"][1]["sha256"] = "aaa"
    with pytest.raises(ValueError, match="expected occurrences"):
        acceptance._waiting_artifacts(report, {"aaa", "bbb"})


@pytest.mark.parametrize("mutation", ["complete", "missing_reference", "missing_occurrence"])
def test_wait_guard_rejects_ambiguous_or_completed_challenges(mutation: str) -> None:
    report = _waiting_report()
    if mutation == "complete":
        report["report_complete"] = True
    elif mutation == "missing_reference":
        report["password_required_artifacts"] = ["word"]
    else:
        report["artifacts"].pop()
    with pytest.raises(ValueError):
        acceptance._waiting_artifacts(report, {"aaa", "bbb"})


def _plaintext_contract(
    tmp_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    spec = acceptance.load_manifest(_MANIFEST)["cases"][0]
    payload = build_office_plaintext_fixture(spec["plaintext_profile"])
    (tmp_path / "clear-package").write_bytes(payload)
    child = {
        "artifact_id": "clear",
        "parent_id": "encrypted",
        "depth": 1,
        "storage_key": "clear-package",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "original_filename": "decrypted.docx",
        "report": {
            "results": {
                "format_analysis": {
                    "analyzer": "office",
                    "features": {"macros": {"found": False}},
                }
            }
        },
    }
    parent = {
        "artifact_id": "encrypted",
        "depth": 0,
        "report": {
            "results": {
                "format_analysis": {
                    "analyzer": "office",
                    "features": {
                        "encrypted": True,
                        "content_access": "decrypted_child",
                        "encryption": {
                            "scheme": "agile",
                            "cipher": "AES-CBC",
                            "key_bits": 256,
                            "hash": "SHA512",
                            "spin_count": 100_000,
                            "integrity": "hmac_verified",
                        },
                        "decrypted_child": {
                            "sha256": child["sha256"],
                            "size": child["size"],
                            "artifact_ids": ["clear"],
                            "analysis_state": "submitted",
                        },
                    },
                }
            }
        },
    }
    content_types = {"clear-package": acceptance._CONTENT_TYPES["docx"]}
    return child, parent, spec, content_types


def test_plaintext_guard_requires_exact_bytes_members_and_real_submission(tmp_path: Path) -> None:
    child, parent, spec, types = _plaintext_contract(tmp_path)
    result = acceptance._verify_plaintext_child(child, parent, spec, tmp_path, types)
    assert result["exact_plaintext_preserved"] is True
    assert "customXml/opaque.bin" in result["package_members"]
    assert "word/_rels/document.xml.rels" in result["package_members"]


@pytest.mark.parametrize(
    "mutation", ["bytes", "mime", "extension", "identity", "not_submitted", "integrity", "parent"]
)
def test_plaintext_guard_rejects_conversion_or_unverified_child_evidence(
    tmp_path: Path, mutation: str
) -> None:
    child, parent, spec, types = _plaintext_contract(tmp_path)
    features = parent["report"]["results"]["format_analysis"]["features"]
    if mutation == "bytes":
        (tmp_path / "clear-package").write_bytes(b"converted package")
    elif mutation == "mime":
        types["clear-package"] = "application/octet-stream"
    elif mutation == "extension":
        child["original_filename"] = "decrypted.bin"
    elif mutation == "identity":
        features["decrypted_child"]["sha256"] = "0" * 64
    elif mutation == "not_submitted":
        features["decrypted_child"]["analysis_state"] = "not_submitted"
    elif mutation == "integrity":
        features["encryption"]["integrity"] = "hmac_required"
    else:
        features["encrypted"] = False
    with pytest.raises(ValueError):
        acceptance._verify_plaintext_child(child, parent, spec, tmp_path, types)


def _negative_report() -> dict[str, Any]:
    return {
        "job_status": "done",
        "report_complete": True,
        "password_required_artifacts": [],
        "artifacts": [
            {
                "report": {
                    "analysis": {"static": {"status": "partial"}},
                    "results": {
                        "format_analysis": {
                            "features": {
                                "encrypted": True,
                                "content_access": "unavailable",
                            }
                        }
                    },
                }
            }
        ],
    }


def test_negative_guard_requires_partial_without_a_bogus_password_loop_or_child() -> None:
    report = _negative_report()
    acceptance._verify_negative(report)
    report["artifacts"][0]["report"]["results"]["format_analysis"]["features"][
        "content_access"
    ] = "unsupported"
    acceptance._verify_negative(report)


@pytest.mark.parametrize("mutation", ["wait", "child", "complete", "access"])
def test_negative_guard_rejects_misleading_failure_outcomes(mutation: str) -> None:
    report = _negative_report()
    node = report["artifacts"][0]
    if mutation == "wait":
        report["job_status"] = "password_required"
    elif mutation == "child":
        report["artifacts"].append({"origin_path": "office-decrypted"})
    elif mutation == "complete":
        node["report"]["analysis"]["static"]["status"] = "complete"
    else:
        node["report"]["results"]["format_analysis"]["features"][
            "content_access"
        ] = "wrong_password"
    with pytest.raises(ValueError):
        acceptance._verify_negative(report)


def test_private_case_entrypoint_preserves_existing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "existing-case"
    directory.mkdir()
    retained = directory / "case-result.json"
    original = '{"retained_evidence":true}\n'
    retained.write_text(original)
    monkeypatch.setattr(
        "sys.argv",
        [
            "office-password-acceptance",
            "--manifest",
            str(_MANIFEST),
            "--output-dir",
            str(directory),
            "--execute-case",
            "agile-aes256-docx",
        ],
    )
    with pytest.raises(SystemExit) as caught:
        acceptance.main()
    assert caught.value.code == 2
    assert retained.read_text() == original


def test_case_timeout_disables_dynamic_submission_and_kills_parser_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, Any] = {"waits": []}

    class Process:
        pid = 12345

        def __init__(self, command: list[str], **kwargs: Any):
            calls.update(
                command=command, environment=kwargs["env"], session=kwargs["start_new_session"]
            )

        def wait(self, timeout: int | None = None) -> int:
            calls["waits"].append(timeout)
            if timeout is not None:
                raise subprocess.TimeoutExpired("office-case", timeout)
            return -9

    monkeypatch.setattr(acceptance.subprocess, "Popen", Process)
    monkeypatch.setattr(acceptance.os, "killpg", lambda pid, signal: calls.update(killed_pid=pid))
    result = acceptance.run_subprocess({"id": "bounded-case"}, _MANIFEST, tmp_path / "bounded-case")
    assert result["passed"] is False
    assert result["process_exit_code"] is None
    assert calls["environment"]["SANDBOX_ENABLED"] == "false"
    assert calls["environment"]["SANDBOX_ENABLE_URL_SUBMISSION"] == "false"
    assert calls["session"] is True
    assert calls["killed_pid"] == 12345
    assert calls["waits"] == [600, None]


@pytest.mark.parametrize(
    "profile,occurrences,unique_contents",
    [
        ("agile-aes256-docx", 8, 8),
        ("agile-aes256-xlsx", 9, 9),
        ("agile-aes256-pptx", 9, 9),
        ("agile-aes256-docm", 12, 10),
        ("agile-aes256-xlsm", 13, 11),
        ("agile-aes256-pptm", 13, 11),
        ("agile-aes256-external-template-docx", 10, 10),
        ("standard-aes128-docx", 8, 8),
        ("agile-aes256-docx-second-password", 8, 8),
        ("zip-aes-office-agile-aes256-docx", 9, 9),
        ("zip-aes-office-two-siblings", 18, 16),
        ("unsupported-encryption", 1, 1),
        ("corrupt-encrypted-package", 1, 1),
        ("malformed-agile-xml", 1, 1),
    ],
)
def test_recursive_inventory_derives_every_frozen_member_and_extraction_occurrence(
    profile: str, occurrences: int, unique_contents: int
) -> None:
    suite = acceptance.load_manifest(_MANIFEST)
    case = next(case for case in suite["cases"] if case["profile"] == profile)
    inventory = acceptance._expected_artifact_inventory(case)
    assert len(inventory) == occurrences
    assert len({node["sha256"] for node in inventory}) == unique_contents
    for node in inventory:
        assert node["sha256"] == hashlib.sha256(node["payload"]).hexdigest()
        assert node["size"] == len(node["payload"])
    hits = {rule for node in inventory for rule in node["yara_rules"]}
    assert hits == (
        set() if profile in {"unsupported-encryption", "malformed-agile-xml"} else {"network_iocs"}
    )
    if case.get("macro_flag"):
        embeddings = [node for node in inventory if node["filename"] == "oleObject1.bin"]
        assert {node["source"] for node in embeddings} == {
            "archive-extract",
            "format-analysis",
            "document-analysis",
        }
        assert len({node["sha256"] for node in embeddings}) == 1
        for node in inventory:
            partial = node["key"].startswith("plaintext-") and (
                node["origin"] == "office-decrypted" or node["filename"] == "vbaProject.bin"
            )
            assert (node["stages"]["format-analysis"] == "partial") is partial
            assert (node["stages"]["document-analysis"] == "partial") is partial


def _inventory_contract(tmp_path: Path):
    case = next(
        case
        for case in acceptance.load_manifest(_MANIFEST)["cases"]
        if case["profile"] == "agile-aes256-docm"
    )
    inventory = acceptance._expected_artifact_inventory(case)
    report = {"root_artifact_id": "root", "artifacts": []}
    ids = {spec["key"]: f"artifact-{index}" for index, spec in enumerate(inventory)}
    ids["root"] = "root"
    depths: dict[str, int] = {}
    for spec in inventory:
        identifier = ids[spec["key"]]
        depths[spec["key"]] = depths[spec["parent"]] + 1 if spec["parent"] is not None else 0
        storage_key = f"artifacts/root/sha256/{spec['sha256']}"
        path = tmp_path / storage_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(spec["payload"])
        report["artifacts"].append(
            {
                "artifact_id": identifier,
                "parent_id": ids.get(spec["parent"]),
                "root_id": "root",
                "depth": depths[spec["key"]],
                "occurrence_index": spec["occurrence_index"],
                "extraction_source": spec["source"],
                "origin_path": spec["origin"],
                "archive_type": spec["archive_type"],
                "sha256": spec["sha256"],
                "size": spec["size"],
                "status": "done",
                "original_filename": spec["filename"],
                "storage_key": storage_key,
                "report": {
                    "job_id": identifier,
                    "file": {
                        "sha256": spec["sha256"],
                        "size": spec["size"],
                        "original_filename": spec["filename"],
                    },
                    "analysis": {
                        "static": {
                            "stage_coverage": [
                                {"stage": stage, "status": status}
                                for stage, status in spec["stages"].items()
                            ]
                        }
                    },
                    "results": {"yara_hits": [{"rule": rule} for rule in spec["yara_rules"]]},
                    "risk": {
                        "evidence": [
                            {
                                "source": "yara",
                                "raw": {"rule": rule},
                                "tier": "benign_context",
                                "points": 0,
                            }
                            for rule in spec["yara_rules"]
                        ]
                    },
                },
            }
        )
    return report, inventory


def test_recursive_guard_requires_distinct_scans_and_shared_content_objects(tmp_path: Path) -> None:
    report, inventory = _inventory_contract(tmp_path)
    assert acceptance._verify_artifact_inventory(report, inventory, tmp_path) == {
        "artifact_occurrences": 12,
        "unique_content_objects": 10,
        "repeated_content_occurrences": 2,
        "all_occurrences_scanned": True,
        "all_bytes_verified": True,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "bytes",
        "identity",
        "role",
        "unscanned",
        "context",
        "hits",
        "coverage",
        "dedupe",
        "depth",
        "occurrence_index",
    ],
)
def test_recursive_guard_rejects_lost_bytes_scans_occurrences_or_context_meaning(
    tmp_path: Path, mutation: str
) -> None:
    report, inventory = _inventory_contract(tmp_path)
    node = report["artifacts"][2]
    if mutation == "missing":
        report["artifacts"].pop()
    elif mutation == "extra":
        report["artifacts"].append(copy.deepcopy(node))
    elif mutation == "bytes":
        (tmp_path / node["storage_key"]).write_bytes(b"different bytes")
    elif mutation == "identity":
        node["report"]["job_id"] = "another-occurrence"
    elif mutation == "role":
        node["extraction_source"] = "format-analysis"
    elif mutation == "unscanned":
        node["status"] = "limited"
        node["report"] = None
    elif mutation == "context":
        node["report"]["risk"]["evidence"][0]["points"] = 4
    elif mutation == "hits":
        node["report"]["results"]["yara_hits"] = []
    elif mutation == "coverage":
        node["report"]["analysis"]["static"]["stage_coverage"][0]["status"] = "partial"
    elif mutation == "depth":
        node["depth"] += 1
    elif mutation == "occurrence_index":
        node["occurrence_index"] += 1
    else:
        node["storage_key"] = "duplicated-content-object"
    with pytest.raises(ValueError):
        acceptance._verify_artifact_inventory(report, inventory, tmp_path)


def test_office_password_selection_uses_each_occurrence_profile_and_label() -> None:
    assert acceptance._office_password({"profile": "agile-aes256-docx"}) == OFFICE_PASSWORD
    assert (
        acceptance._office_password({"profile": "agile-aes256-docx-second-password"})
        == SECOND_OFFICE_PASSWORD
    )
    assert (
        acceptance._office_password(
            {"profile": "agile-aes256-docx", "office_password_label": "SECOND_OFFICE_PASSWORD"}
        )
        == SECOND_OFFICE_PASSWORD
    )


def _external_template_contract():
    child = {
        "report": {
            "score": 53,
            "risk_level": "medium",
            "risk": {"local_risk": {"score": 53}},
            "results": {"format_analysis": {"risk_factors": ["external_relationship"]}},
        }
    }
    parent = {
        "artifact_id": "encrypted",
        "parent_id": None,
        "report": {
            "score": 15,
            "risk_level": "low",
            "risk": {
                "local_risk": {"score": 0, "risk_level": "clean"},
                "breakdown": {"inherited_score": 15, "descendant_floor": 0},
            },
        },
    }
    return child, parent


def test_external_template_guard_pins_medium_policy_and_visible_inherited_risk() -> None:
    child, parent = _external_template_contract()
    acceptance._verify_external_template_propagation(child, parent, {"encrypted": parent})


@pytest.mark.parametrize(
    "mutation", ["child_score", "child_level", "structure", "local", "ancestor"]
)
def test_external_template_guard_rejects_hidden_or_overstated_structural_risk(
    mutation: str,
) -> None:
    child, parent = _external_template_contract()
    if mutation == "child_score":
        child["report"]["score"] = 15
    elif mutation == "child_level":
        child["report"]["risk_level"] = "high"
    elif mutation == "structure":
        child["report"]["results"]["format_analysis"]["risk_factors"] = []
    elif mutation == "local":
        parent["report"]["risk"] = {}
    else:
        parent["report"].update(score=53, risk_level="medium")
    with pytest.raises(ValueError):
        acceptance._verify_external_template_propagation(child, parent, {"encrypted": parent})


def test_failure_details_redact_every_public_fixture_password() -> None:
    detail = " ".join([OFFICE_PASSWORD, SECOND_OFFICE_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD])
    assert acceptance._redact(detail) == " ".join(["[fixture-password-redacted]"] * 4)
