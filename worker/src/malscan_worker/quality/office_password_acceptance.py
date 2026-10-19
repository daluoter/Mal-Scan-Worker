"""Exercise frozen Office passwords and durable resumes with native static engines.

Cases use isolated processes, local object stores and inert public fixtures. No
cloud job is submitted and dynamic analysis and URL submission stay disabled.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from malscan_worker.budget import BudgetLimits
from malscan_worker.quality.corpus import REQUIRED_STAGES, evaluate_report
from malscan_worker.quality.office_password_fixtures import (
    ARCHIVE_PASSWORD,
    NESTED_OFFICE_PROFILES,
    OFFICE_PASSWORD,
    OFFICE_PASSWORD_PROFILES,
    SECOND_OFFICE_PASSWORD,
    WRONG_PASSWORD,
    build_office_password_fixture,
    build_office_plaintext_fixture,
)
from malscan_worker.quality.pdf_password_acceptance import _completed_stages
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.runtime.manifest import file_identity

_PASSWORDS = (OFFICE_PASSWORD, SECOND_OFFICE_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD)
_NEGATIVE_SCENARIOS = {
    "unsupported-encryption": "unsupported",
    "corrupt-encrypted-package": "corrupt",
    "malformed-agile-xml": "corrupt",
}
_CONTENT_TYPES = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "docm": "application/vnd.ms-word.document.macroEnabled.12",
    "xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    "pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
}
_CASE_TIMEOUT_SECONDS = 600
_ATTEMPT_BUDGET_SECONDS = 300


def _identity_matches(payload: bytes, sha256: object, size: object) -> bool:
    return (
        isinstance(size, int)
        and not isinstance(size, bool)
        and 0 < size <= 1_000_000
        and len(payload) == size
        and hashlib.sha256(payload).hexdigest() == sha256
    )


def _plaintext_specs(case: dict[str, Any]) -> list[dict[str, Any]]:
    if case["scenario"] == "nested":
        return cast(list[dict[str, Any]], case["nested_children"])
    return [case] if case["scenario"] == "prompt" else []


def _validate_plaintext_spec(spec: dict[str, Any], recipe: int) -> None:
    profile = spec.get("profile")
    if not isinstance(profile, str) or not profile.startswith(
        ("agile-aes256-", "standard-aes128-")
    ):
        raise ValueError("Invalid Office plaintext profile")
    plain_profile = (
        profile.removeprefix("agile-aes256-")
        .removeprefix("standard-aes128-")
        .removesuffix("-second-password")
    )
    document_type = plain_profile.removeprefix("external-template-")
    if (
        document_type not in _CONTENT_TYPES
        or spec.get("document_type") != document_type
        or spec.get("plaintext_profile") != plain_profile
    ):
        raise ValueError("Office plaintext package type differs")
    payload = build_office_plaintext_fixture(plain_profile, recipe)
    if not _identity_matches(payload, spec.get("plaintext_sha256"), spec.get("plaintext_bytes")):
        raise ValueError("Office plaintext fixture identity differs")


def load_manifest(path: Path) -> dict[str, Any]:
    """Reject stale fixture pins, ambiguous controls and unbounded case inputs."""
    if path.stat().st_size > 128_000:
        raise ValueError("Office password acceptance manifest is too large")
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("schema_version"), int)
        or isinstance(data.get("schema_version"), bool)
        or data["schema_version"] != 1
        or data.get("scope") != "local_real_office_password_acceptance"
        or not isinstance(data.get("suite_version"), str)
        or not re.fullmatch(r"office-password-v[0-9]+\.[0-9]+\.[0-9]+", data["suite_version"])
        or not isinstance(data.get("recipe_version"), int)
        or isinstance(data.get("recipe_version"), bool)
        or data["recipe_version"] != 1
        or not re.fullmatch(r"[a-f0-9]{64}", str(data.get("rules_sha256", "")))
        or not isinstance(data.get("policy_version"), str)
        or not re.fullmatch(r"msrs-v[0-9]+\.[0-9]+", data["policy_version"])
        or not isinstance(data.get("accuracy_claim"), str)
        or not 1 <= len(data["accuracy_claim"]) <= 512
        or not isinstance(data.get("cases"), list)
        or not 1 <= len(data["cases"]) <= 20
    ):
        raise ValueError("Invalid Office password acceptance manifest")
    identifiers: set[str] = set()
    profiles: set[str] = set()
    for case in data["cases"]:
        if not isinstance(case, dict):
            raise ValueError("Invalid Office password acceptance case")
        identifier, profile = case.get("id"), case.get("profile")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", identifier)
            or identifier in identifiers
            or not isinstance(profile, str)
            or profile not in OFFICE_PASSWORD_PROFILES
            or profile in profiles
        ):
            raise ValueError("Invalid or duplicate Office password acceptance case")
        identifiers.add(identifier)
        profiles.add(profile)
        scenario = (
            "nested"
            if profile in NESTED_OFFICE_PROFILES
            else _NEGATIVE_SCENARIOS.get(profile, "prompt")
        )
        if case.get("scenario") != scenario:
            raise ValueError("Office password acceptance scenario differs")
        payload = build_office_password_fixture(profile, data["recipe_version"])
        if not _identity_matches(payload, case.get("sha256"), case.get("bytes")):
            raise ValueError("Office password acceptance fixture identity differs")
        if scenario in {"unsupported", "corrupt"}:
            if case.get("expect_correct_password") != "static_partial_no_child":
                raise ValueError("Invalid negative Office expectation")
            if any(key in case for key in ("plaintext_sha256", "nested_children")):
                raise ValueError("Negative Office fixture cannot promise plaintext")
            continue
        if case.get("expect_wrong_password") != "needs_password":
            raise ValueError("Invalid Office wrong-password expectation")
        expected_correct = (
            "two_independent_children_emitted_exact_bytes"
            if scenario == "nested" and len(NESTED_OFFICE_PROFILES[profile]) == 2
            else "child_emitted_exact_bytes"
        )
        if case.get("expect_correct_password") != expected_correct:
            raise ValueError("Invalid Office successful-unlock expectation")
        if scenario == "nested":
            children = case.get("nested_children")
            if (
                not isinstance(children, list)
                or not all(isinstance(child, dict) for child in children)
                or tuple(child.get("profile") for child in children)
                != NESTED_OFFICE_PROFILES[profile]
                or case.get("archive_password_label") != "ARCHIVE_PASSWORD"
                or case.get("office_password_label") != "OFFICE_PASSWORD"
            ):
                raise ValueError("Invalid nested Office fixture inventory")
            filenames: set[str] = set()
            for child in children:
                filename = child.get("filename")
                if (
                    not isinstance(filename, str)
                    or not re.fullmatch(r"nested/locked\.(docx|xlsx)", filename)
                    or filename in filenames
                    or not filename.endswith("." + str(child.get("document_type")))
                ):
                    raise ValueError("Invalid nested Office filename")
                filenames.add(filename)
                _validate_plaintext_spec(child, data["recipe_version"])
        else:
            _validate_plaintext_spec(case, data["recipe_version"])
            expected_label = (
                "SECOND_OFFICE_PASSWORD"
                if profile.endswith("-second-password")
                else "OFFICE_PASSWORD"
            )
            if (
                case.get("encryption") != profile.split("-", 2)[0] + "-" + profile.split("-", 2)[1]
                or case.get("macro_flag") is not (case["document_type"] in {"docm", "xlsm", "pptm"})
                or case.get("external_template") is not ("external-template" in profile)
                or case.get("office_password_label", "OFFICE_PASSWORD") != expected_label
            ):
                raise ValueError("Office encryption or structural controls differ")
    return cast(dict[str, Any], data)


def _check_secrets(directory: Path) -> None:
    # Only binary fixtures and verified artifacts may contain arbitrary bytes.
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".log"}:
            if any(password in path.read_text(errors="replace") for password in _PASSWORDS):
                raise ValueError("Fixture password leaked into reports, logs or checkpoints")


def _waiting_artifacts(
    report: dict[str, Any], expected_sha256: set[str], *, wrong_ids: set[str] | None = None
) -> dict[str, str]:
    if (
        report.get("job_status") != "password_required"
        or report.get("report_complete") is not False
    ):
        raise ValueError("Locked Office content was reported as a completed execution")
    waiting = [node for node in report["artifacts"] if node["status"] == "password_required"]
    observed = {node["sha256"]: node["artifact_id"] for node in waiting}
    if len(waiting) != len(expected_sha256) or set(observed) != expected_sha256:
        raise ValueError("Password challenges do not bind to the expected occurrences")
    if set(observed.values()) != set(report.get("password_required_artifacts", [])):
        raise ValueError("Password challenges are missing from the public report")
    if any(
        node.get("reason") != "wrong_password"
        for node in waiting
        if node["artifact_id"] in (wrong_ids or set())
    ):
        raise ValueError("Incorrect Office password lost its explicit wrong-password state")
    return observed


class _RecordingLocalStore(LocalObjectStore):
    """Retain the MIME actually passed through the native child-submission port."""

    def __init__(self, root: Path):
        super().__init__(root)
        self.content_types: dict[str, str] = {}

    async def put_file(
        self,
        key: str,
        source: Path,
        *,
        sha256: str,
        size: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        result = await super().put_file(
            key, source, sha256=sha256, size=size, content_type=content_type
        )
        self.content_types[key] = content_type
        return result


def _decrypted_nodes(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        node
        for node in report["artifacts"]
        if node.get("origin_path") == "office-decrypted"
        and node.get("extraction_source") == "format-analysis"
        and node.get("archive_type") == "office"
    ]


def _office_password(spec: dict[str, Any]) -> str:
    return (
        SECOND_OFFICE_PASSWORD
        if spec.get("office_password_label") == "SECOND_OFFICE_PASSWORD"
        or spec["profile"].endswith("-second-password")
        else OFFICE_PASSWORD
    )


def _expected_artifact_inventory(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive every occurrence from frozen input bytes, independently of reports.

    A macro embedding occurs in three extraction channels. Its bytes share one
    content-addressed object while each occurrence requires its own native scan.
    The pinned network rule matches literal HTTP(S), including OOXML namespaces
    and the clear Agile EncryptionInfo descriptor; these are benign context.
    """
    inventory: list[dict[str, Any]] = []

    def add(
        key: str,
        parent: str | None,
        payload: bytes,
        filename: str,
        source: str,
        origin: str | None,
        archive_type: str | None,
        format_status: str = "skipped",
        archive_status: str = "skipped",
        document_status: str = "skipped",
        occurrence_index: int | None = 0,
    ) -> None:
        inventory.append(
            {
                "key": key,
                "parent": parent,
                "payload": payload,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "filename": filename,
                "source": source,
                "origin": origin,
                "archive_type": archive_type,
                "occurrence_index": None if parent is None else occurrence_index,
                "stages": {
                    **dict.fromkeys(
                        ("file-type", "clamav", "yara", "ioc-extract", "deobfuscation"), "ok"
                    ),
                    "format-analysis": format_status,
                    "archive-extract": archive_status,
                    "document-analysis": document_status,
                },
                "yara_rules": ["network_iocs"]
                if b"http://" in payload or b"https://" in payload
                else [],
            }
        )

    nested = case["scenario"] == "nested"
    add(
        "root",
        None,
        build_office_password_fixture(case["profile"]),
        "source.zip" if nested else "source.bin",
        "upload",
        None,
        None,
        "skipped"
        if nested
        else "partial"
        if case["scenario"] in {"unsupported", "corrupt"}
        else "ok",
        "ok" if nested else "skipped",
    )
    if nested:
        import pyzipper

        with pyzipper.AESZipFile(io.BytesIO(inventory[0]["payload"])) as archive:
            if archive.namelist() != [spec["filename"] for spec in _plaintext_specs(case)]:
                raise ValueError("Frozen outer ZIP membership differs from its pinned inventory")
            for spec in _plaintext_specs(case):
                if archive.read(spec["filename"], pwd=ARCHIVE_PASSWORD.encode()) != (
                    build_office_password_fixture(spec["profile"])
                ):
                    raise ValueError("Frozen outer ZIP member differs from its pinned Office bytes")
    for index, spec in enumerate(_plaintext_specs(case)):
        parent = "root"
        if nested:
            parent = f"encrypted-{index}"
            add(
                parent,
                "root",
                build_office_password_fixture(spec["profile"]),
                Path(spec["filename"]).name,
                "archive-extract",
                spec["filename"],
                "zip",
                "ok",
                occurrence_index=index,
            )
        clear_key = f"plaintext-{index}"
        plain = build_office_plaintext_fixture(spec["plaintext_profile"])
        add(
            clear_key,
            parent,
            plain,
            "decrypted." + spec["document_type"],
            "format-analysis",
            "office-decrypted",
            "office",
            "partial" if spec["document_type"] in {"docm", "xlsm", "pptm"} else "ok",
            "ok",
            "partial" if spec["document_type"] in {"docm", "xlsm", "pptm"} else "ok",
        )
        with zipfile.ZipFile(io.BytesIO(plain)) as archive:
            for member_index, member in enumerate(archive.infolist()):
                if member.is_dir():
                    continue
                payload = archive.read(member)
                add(
                    f"{clear_key}:archive:{member.filename}",
                    clear_key,
                    payload,
                    Path(member.filename).name,
                    "archive-extract",
                    member.filename,
                    "zip",
                    "partial" if member.filename.endswith("/vbaProject.bin") else "skipped",
                    "skipped",
                    "partial" if member.filename.endswith("/vbaProject.bin") else "skipped",
                    occurrence_index=member_index,
                )
                if "/embeddings/" in member.filename and member.filename.endswith(".bin"):
                    for source in ("format-analysis", "document-analysis"):
                        add(
                            f"{clear_key}:{source}:{member.filename}",
                            clear_key,
                            payload,
                            Path(member.filename).name,
                            source,
                            "ooxml_embed_" + member.filename,
                            "office" if source == "format-analysis" else None,
                        )
    return inventory


def _verify_artifact_inventory(
    report: dict[str, Any], expected: list[dict[str, Any]], result_dir: Path
) -> dict[str, Any]:
    """Require all pinned occurrences, native scans and deduplicated stored bytes."""
    nodes = report["artifacts"]
    if len(nodes) != len(expected):
        raise ValueError("Recursive Office artifact occurrence count differs")
    mapped: dict[str, dict[str, Any]] = {}
    storage_by_hash: dict[str, str] = {}
    for spec in expected:
        parent = mapped[spec["parent"]]["artifact_id"] if spec["parent"] is not None else None
        matches = [
            node
            for node in nodes
            if node.get("parent_id") == parent
            and node.get("extraction_source") == spec["source"]
            and node.get("origin_path") == spec["origin"]
            and node.get("archive_type") == spec["archive_type"]
        ]
        if len(matches) != 1:
            raise ValueError("Recursive Office extraction occurrence or provenance differs")
        node = matches[0]
        mapped[spec["key"]] = node
        expected_depth = mapped[spec["parent"]]["depth"] + 1 if parent is not None else 0
        expected_storage = f"artifacts/{report['root_artifact_id']}/sha256/{spec['sha256']}"
        path = result_dir / node["storage_key"]
        child_report = node.get("report") or {}
        if (
            node.get("status") != "done"
            or node.get("root_id") != report["root_artifact_id"]
            or node.get("depth") != expected_depth
            or node.get("occurrence_index") != spec["occurrence_index"]
            or node.get("sha256") != spec["sha256"]
            or node.get("size") != spec["size"]
            or node.get("original_filename") != spec["filename"]
            or node.get("storage_key") != expected_storage
            or path.read_bytes() != spec["payload"]
            or child_report.get("job_id") != node["artifact_id"]
            or child_report.get("file", {}).get("sha256") != spec["sha256"]
            or child_report.get("file", {}).get("size") != spec["size"]
            or child_report.get("file", {}).get("original_filename") != spec["filename"]
        ):
            raise ValueError("An Office artifact lacks its pinned bytes or native scan identity")
        prior_storage = storage_by_hash.setdefault(spec["sha256"], node["storage_key"])
        if prior_storage != node["storage_key"]:
            raise ValueError("Repeated Office bytes did not reuse their content-addressed object")
        coverage = child_report.get("analysis", {}).get("static", {}).get("stage_coverage", [])
        if (
            len(coverage) != len(REQUIRED_STAGES)
            or {stage["stage"]: stage["status"] for stage in coverage} != spec["stages"]
        ):
            raise ValueError("An Office artifact's native stage coverage differs from its role")
        hits = child_report.get("results", {}).get("yara_hits", [])
        if sorted(hit.get("rule") for hit in hits) != spec["yara_rules"]:
            raise ValueError("An Office artifact's pinned native YARA inventory differs")
        yara_evidence = [
            evidence
            for evidence in child_report.get("risk", {}).get("evidence", [])
            if evidence.get("source") == "yara"
        ]
        if sorted(evidence.get("raw", {}).get("rule") for evidence in yara_evidence) != spec[
            "yara_rules"
        ] or any(
            evidence.get("tier") != "benign_context" or evidence.get("points") != 0
            for evidence in yara_evidence
        ):
            raise ValueError("OOXML namespace YARA matches lost their pinned context-only meaning")
    identifiers = [node["artifact_id"] for node in mapped.values()]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Distinct Office extraction occurrences reused an artifact identity")
    return {
        "artifact_occurrences": len(expected),
        "unique_content_objects": len(storage_by_hash),
        "repeated_content_occurrences": len(expected) - len(storage_by_hash),
        "all_occurrences_scanned": True,
        "all_bytes_verified": True,
    }


def _verify_plaintext_child(
    child: dict[str, Any],
    parent: dict[str, Any],
    spec: dict[str, Any],
    result_dir: Path,
    content_types: dict[str, str],
) -> dict[str, Any]:
    payload = build_office_plaintext_fixture(spec["plaintext_profile"])
    child_path = result_dir / child["storage_key"]
    if (
        child_path.read_bytes() != payload
        or file_identity(child_path) != (spec["plaintext_sha256"], spec["plaintext_bytes"])
        or (child["sha256"], child["size"]) != (spec["plaintext_sha256"], spec["plaintext_bytes"])
    ):
        raise ValueError("Decrypted Office package did not preserve its exact plaintext bytes")
    document_type = spec["document_type"]
    if (
        Path(child["original_filename"]).suffix.lower() != "." + document_type
        or content_types.get(child["storage_key"]) != _CONTENT_TYPES[document_type]
    ):
        raise ValueError(
            "Actual Office child submission lost its package extension or content type"
        )
    parent_format = parent["report"]["results"]["format_analysis"]
    features = parent_format["features"]
    provenance = features.get("decrypted_child", {})
    if (
        parent_format.get("analyzer") != "office"
        or features.get("encrypted") is not True
        or features.get("content_access") != "decrypted_child"
        or provenance.get("sha256") != child["sha256"]
        or provenance.get("size") != child["size"]
        or provenance.get("analysis_state") != "submitted"
        or provenance.get("artifact_ids") != [child["artifact_id"]]
        or child["depth"] != parent["depth"] + 1
    ):
        raise ValueError("Decrypted Office child lost encrypted-parent provenance")
    standard = spec["profile"].startswith("standard-")
    encryption = features.get("encryption", {})
    expected_encryption = {
        "scheme": "standard" if standard else "agile",
        "cipher": "AES-ECB" if standard else "AES-CBC",
        "key_bits": 128 if standard else 256,
        "hash": "SHA1" if standard else "SHA512",
        "spin_count": 50_000 if standard else 100_000,
        "integrity": "zip_crc_only_no_authenticated_integrity" if standard else "hmac_verified",
    }
    if any(encryption.get(key) != value for key, value in expected_encryption.items()):
        raise ValueError("Office encryption and integrity provenance differs")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.namelist()
        if archive.testzip() is not None:
            raise ValueError("Canonical plaintext member CRC differs")
    child_format = child["report"]["results"]["format_analysis"]
    if child_format.get("analyzer") != "office":
        raise ValueError("Decrypted Office package was not structurally rescanned")
    macros = child_format["features"].get("macros", {})
    macro_flag = document_type in {"docm", "xlsm", "pptm"}
    if macro_flag and (
        macros.get("found") is not True
        or macros.get("project_present") is not True
        or macros.get("source_status") != "unavailable"
        or macros.get("sources") != []
    ):
        raise ValueError("Inert macro package flag was lost or overstated as parsed VBA")
    return {
        "artifact_id": child["artifact_id"],
        "sha256": child["sha256"],
        "size": child["size"],
        "document_type": document_type,
        "package_members": members,
        "exact_plaintext_preserved": True,
    }


def _verify_negative(report: dict[str, Any]) -> None:
    nodes = report["artifacts"]
    if (
        report.get("job_status") != "done"
        or report.get("report_complete") is not True
        or report.get("password_required_artifacts")
        or len(nodes) != 1
        or _decrypted_nodes(report)
    ):
        raise ValueError("Unsupported or corrupt Office content caused a password loop or child")
    features = nodes[0]["report"]["results"]["format_analysis"]["features"]
    if (
        features.get("encrypted") is not True
        or features.get("content_access") not in {"unavailable", "unsupported"}
        or features.get("decrypted_child")
        or nodes[0]["report"]["analysis"]["static"]["status"] != "partial"
    ):
        raise ValueError("Unreadable Office content was presented as fully scanned plaintext")


def _verify_external_template_propagation(
    child: dict[str, Any], parent: dict[str, Any], nodes: dict[str, dict[str, Any]]
) -> None:
    """Pin the synthetic relationship's policy result and preserve ancestor risk.

    The current policy assigns this isolated structural control 53/medium and
    inherits 15 points into its otherwise clean encrypted parent. This fixture
    tests that policy result and preserves the parent's separate local decision.
    """
    child_report = child["report"]
    if (
        child_report.get("score") != 53
        or child_report.get("risk_level") != "medium"
        or child_report.get("risk", {}).get("local_risk", {}).get("score") != 53
        or "external_relationship" not in child_report["results"]["format_analysis"]["risk_factors"]
    ):
        raise ValueError("Decrypted external-template structure differs from its policy baseline")
    effective = parent["report"]
    risk = effective.get("risk", {})
    local = risk.get("local_risk", {})
    breakdown = risk.get("breakdown", {})
    if (
        parent.get("parent_id") is not None
        or nodes.get(parent["artifact_id"]) != parent
        or effective.get("score") != 15
        or effective.get("risk_level") != "low"
        or local.get("score") != 0
        or local.get("risk_level") != "clean"
        or breakdown.get("inherited_score") != 15
        or breakdown.get("descendant_floor") != 0
    ):
        raise ValueError(
            "Encrypted Office relationship inheritance differs from its policy baseline"
        )


async def execute_case(
    case: dict[str, Any], suite: dict[str, Any], directory: Path
) -> dict[str, Any]:
    """Run actual detectors, password transitions, persistent recovery and reuse."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    # A .bin input forces package metadata to determine each decrypted extension.
    source = directory / ("source.zip" if case["scenario"] == "nested" else "source.bin")
    payload = build_office_password_fixture(case["profile"], suite["recipe_version"])
    source.write_bytes(payload)
    source.chmod(0o400)
    manifest = AnalysisManifest.for_local_file(source)
    state_dir, result_dir = directory / "state", directory / "analysis"
    store = _RecordingLocalStore(result_dir)
    completed: dict[tuple[str, str], dict[str, Any]] = {}
    password_attempts: dict[str, int] = {}
    observations: list[dict[str, Any]] = []
    persistent_recovery = False

    async def attempt(
        label: str, passwords: dict[str, str] | None = None, *, resume: bool = False
    ) -> dict[str, Any]:
        for artifact_id in passwords or {}:
            password_attempts[artifact_id] = password_attempts.get(artifact_id, 0) + 1
        runner = RootBatchRunner(
            manifest=manifest,
            source_store=LocalObjectStore(directory, read_only=True),
            result_store=store,
            state_dir=state_dir,
            limits=BudgetLimits(30, 5_000_000, _ATTEMPT_BUDGET_SECONDS),
            max_depth=4,
            passwords=passwords,
            password_attempts_by_artifact=password_attempts,
            password_attempt_limit=3,
        )
        report = await runner.run(resume=resume)
        state = json.loads((state_dir / "checkpoint.json").read_text())
        current = _completed_stages(state)
        if any(current.get(key) != value for key, value in completed.items()):
            raise ValueError("A completed native stage was rescanned or changed during resume")
        completed.update(current)
        report_path = directory / f"report-{label}.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        if source.read_bytes() != payload or file_identity(source) != (
            case["sha256"],
            case["bytes"],
        ):
            raise ValueError("Original encrypted Office fixture changed")
        _check_secrets(directory)
        observations.append(
            {
                "attempt": label,
                "job_status": report["job_status"],
                "report_complete": report["report_complete"],
                "artifact_count": len(report["artifacts"]),
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            }
        )
        return report

    async def recover(label: str, passwords: dict[str, str]) -> dict[str, Any]:
        nonlocal persistent_recovery
        (state_dir / "checkpoint.json").unlink()
        persistent_recovery = True
        return await attempt(label, passwords, resume=True)

    first = await attempt("initial")
    specs = _plaintext_specs(case)
    negative = case["scenario"] in {"unsupported", "corrupt"}
    if negative and case["profile"] != "corrupt-encrypted-package":
        final = first
        _verify_negative(final)
    elif case["scenario"] == "nested":
        root = _waiting_artifacts(first, {case["sha256"]})[case["sha256"]]
        report = await attempt("archive-unlocked", {root: ARCHIVE_PASSWORD}, resume=True)
        hashes = {
            hashlib.sha256(build_office_password_fixture(spec["profile"])).hexdigest()
            for spec in specs
        }
        inner = _waiting_artifacts(report, hashes)
        if root in inner.values():
            raise ValueError("Office challenge reused the outer ZIP occurrence")
        # Wrong passwords touch each Office occurrence independently.
        wrong_ids: set[str] = set()
        for index, identifier in enumerate(inner.values()):
            wrong_ids.add(identifier)
            report = await attempt(
                f"wrong-office-{index}", {identifier: WRONG_PASSWORD}, resume=True
            )
            if _waiting_artifacts(report, hashes, wrong_ids=wrong_ids) != inner:
                raise ValueError("Wrong Office password changed sibling occurrence identities")
            if _decrypted_nodes(report):
                raise ValueError("A wrong Office password emitted plaintext")
        for index, (digest, identifier) in enumerate(inner.items()):
            spec = next(
                spec
                for spec in specs
                if hashlib.sha256(build_office_password_fixture(spec["profile"])).hexdigest()
                == digest
            )
            report = await recover(f"office-unlocked-{index}", {identifier: _office_password(spec)})
            hashes.remove(digest)
            if hashes:
                remaining = _waiting_artifacts(report, hashes, wrong_ids=wrong_ids)
                if remaining != {key: value for key, value in inner.items() if key in hashes}:
                    raise ValueError("Unlocking an Office sibling changed another challenge")
        final = report
        expected_counts = {root: 1, **dict.fromkeys(inner.values(), 2)}
        if password_attempts != expected_counts:
            raise ValueError("ZIP and Office password attempt counts are not independent")
    else:
        root = _waiting_artifacts(first, {case["sha256"]})[case["sha256"]]
        wrong = await attempt("wrong-password", {root: WRONG_PASSWORD}, resume=True)
        if _waiting_artifacts(wrong, {case["sha256"]}, wrong_ids={root}) != {case["sha256"]: root}:
            raise ValueError("Wrong Office password changed its occurrence identity")
        if _decrypted_nodes(wrong):
            raise ValueError("A wrong Office password emitted plaintext")
        final = await recover("unlocked", {root: _office_password(case)})
        if password_attempts != {root: 2}:
            raise ValueError("Office password attempts were not scoped to their occurrence")
        if negative:
            _verify_negative(final)

    # Macro fixture projects deliberately have no parseable VBA source. Their
    # partial coverage is required; intact OOXML bytes do not prove VBA parsing.
    macro_specs = [spec for spec in specs if spec["document_type"] in {"docm", "xlsm", "pptm"}]
    inventory = _expected_artifact_inventory(case)
    expected_yara_rules = sorted({rule for node in inventory for rule in node["yara_rules"]})
    expected: dict[str, Any] = {
        "static_status": "partial" if negative or macro_specs else "complete",
        "artifact_count": len(inventory),
        "yara_rules": expected_yara_rules,
        "yara_context_rules": expected_yara_rules,
        "yara_risk_rules": [],
        "infected_artifacts": 0,
        "partial_stages": ["format-analysis", "document-analysis"] if macro_specs else [],
    }
    if negative:
        expected["root_stages"] = {"format-analysis": "partial"}
    evaluation = evaluate_report(
        {"expect": expected},
        final,
        source_sha256=case["sha256"],
        source_size=case["bytes"],
        rules_sha256=suite["rules_sha256"],
    )
    if not evaluation["passed"]:
        raise ValueError("Native Office coverage differs: " + "; ".join(evaluation["errors"]))
    inventory_result = _verify_artifact_inventory(final, inventory, result_dir)
    nodes = {node["artifact_id"]: node for node in final["artifacts"]}
    decrypted = _decrypted_nodes(final)
    if len(decrypted) != len(specs):
        raise ValueError("Successful unlock did not emit exactly one child per Office occurrence")
    plaintext_results: list[dict[str, Any]] = []
    for spec in specs:
        children = [node for node in decrypted if node["sha256"] == spec["plaintext_sha256"]]
        if len(children) != 1:
            raise ValueError("Decrypted Office occurrence does not match its pinned plaintext")
        child = children[0]
        parent = nodes[child["parent_id"]]
        if (
            parent["sha256"]
            != hashlib.sha256(build_office_password_fixture(spec["profile"])).hexdigest()
        ):
            raise ValueError("Office plaintext was attached to the wrong encrypted occurrence")
        plaintext_results.append(
            _verify_plaintext_child(child, parent, spec, result_dir, store.content_types)
        )
        if "external-template" in spec["plaintext_profile"]:
            _verify_external_template_propagation(child, parent, nodes)
    for node in nodes.values():
        if node["report"].get("risk", {}).get("policy_version") != suite["policy_version"]:
            raise ValueError("Scoring policy differs from the Office acceptance manifest")
        stages = node["report"]["analysis"]["static"]["stage_coverage"]
        if (
            len(stages) != len(REQUIRED_STAGES)
            or {stage["stage"] for stage in stages} != REQUIRED_STAGES
        ):
            raise ValueError("An Office artifact lacks all eight native stage results")
    final_ids = set(nodes)
    final_stages = json.loads((state_dir / "checkpoint.json").read_text())["artifacts"]
    repeated = await attempt("completed-resume", resume=True)
    repeated_state = json.loads((state_dir / "checkpoint.json").read_text())["artifacts"]
    if (
        {node["artifact_id"] for node in repeated["artifacts"]} != final_ids
        or {node["artifact_id"] for node in _decrypted_nodes(repeated)}
        != {node["artifact_id"] for node in decrypted}
        or any(
            repeated_state[key]["stage_results"] != value["stage_results"]
            for key, value in final_stages.items()
        )
    ):
        raise ValueError(
            "A completed resume duplicated children or changed completed stage evidence"
        )
    return {
        **evaluation,
        "id": case["id"],
        "fixture_sha256": case["sha256"],
        "scenario": case["scenario"],
        "persistent_checkpoint_recovery": persistent_recovery,
        "password_attempts_by_artifact": password_attempts,
        "attempts": observations,
        "decrypted_children": plaintext_results,
        "recursive_inventory": inventory_result,
        "input_immutable": True,
    }


def _redact(detail: str) -> str:
    for password in _PASSWORDS:
        detail = detail.replace(password, "[fixture-password-redacted]")
    return detail


def run_subprocess(case: dict[str, Any], manifest: Path, directory: Path) -> dict[str, Any]:
    """Bound a case process and kill its entire parser-process group on exit."""
    print(f"Office password case: {case['id']}", flush=True)
    started = time.monotonic()
    directory.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "malscan_worker.quality.office_password_acceptance",
        "--manifest",
        str(manifest),
        "--output-dir",
        str(directory),
        "--execute-case",
        case["id"],
    ]
    environment = dict(os.environ)
    environment.update(SANDBOX_ENABLED="false", SANDBOX_ENABLE_URL_SUBMISSION="false")
    log_path = directory.parent / f"{case['id']}.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, env=environment, start_new_session=True
        )
        try:
            code: int | None = process.wait(timeout=_CASE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            code = None
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    result_path = directory / "case-result.json"
    if result_path.is_file():
        result = cast(dict[str, Any], json.loads(result_path.read_text()))
        if code != 0:
            result.update(passed=False, process_exit_code=code)
    else:
        result = {
            "id": case["id"],
            "passed": False,
            "error": "case process failed or timed out",
            "process_exit_code": code,
        }
    try:
        _check_secrets(directory)
        if any(password in log_path.read_text(errors="replace") for password in _PASSWORDS):
            raise ValueError("Fixture password leaked into process log")
    except ValueError as exc:
        result.update(passed=False, error=str(exc))
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--execute-case", help=argparse.SUPPRESS)
    args = parser.parse_args()
    fingerprint = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    suite = load_manifest(args.manifest)
    if args.execute_case:
        selected = [case for case in suite["cases"] if case["id"] == args.execute_case]
        if not selected:
            parser.error("Unknown selected case")
        try:
            result = asyncio.run(execute_case(selected[0], suite, args.output_dir))
        except FileExistsError:
            parser.error("Case output directory already exists")
        except Exception as exc:
            result = {"id": args.execute_case, "passed": False, "error": _redact(str(exc))}
        if args.output_dir.is_dir():
            (args.output_dir / "case-result.json").write_text(json.dumps(result, indent=2) + "\n")
        return 0 if result["passed"] else 1
    cases = suite["cases"]
    if args.case_ids:
        selected_ids = set(args.case_ids)
        if selected_ids - {case["id"] for case in cases}:
            parser.error("Unknown selected case")
        cases = [case for case in cases if case["id"] in selected_ids]
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        results = list(
            executor.map(
                lambda case: run_subprocess(
                    case, args.manifest.resolve(), args.output_dir / case["id"]
                ),
                cases,
            )
        )
    result = {
        "schema_version": 1,
        "suite_version": suite["suite_version"],
        "scope": suite["scope"],
        "manifest_sha256": fingerprint,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "cloud_run_executed": False,
        "passed": all(case["passed"] for case in results),
        "case_count": len(results),
        "passed_count": sum(case["passed"] for case in results),
        "accuracy_claim": suite["accuracy_claim"],
        "cases": results,
    }
    if hashlib.sha256(args.manifest.read_bytes()).hexdigest() != fingerprint:
        result.update(passed=False, error="Office acceptance manifest changed during the run")
    (args.output_dir / "quality-report.json").write_text(json.dumps(result, indent=2) + "\n")
    _check_secrets(args.output_dir)
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
