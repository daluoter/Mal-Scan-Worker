"""Run checksum-pinned PDF/Office embeddings through the real static pipeline.

Every case has isolated persisted state and native scanners. This local-only
suite never fetches referenced resources, calls cloud APIs, or runs attachments.
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from pypdf import PdfReader

from malscan_worker.budget import BudgetLimits
from malscan_worker.quality.corpus import evaluate_report
from malscan_worker.quality.document_embedded_fixtures import (
    DOCUMENT_EMBEDDED_PROFILES,
    build_document_embedded_fixture,
    embedded_fixture_payloads,
)
from malscan_worker.quality.pdf_password_acceptance import _completed_stages, _waiting
from malscan_worker.quality.pdf_password_fixtures import PDF_PASSWORD, WRONG_PASSWORD
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.runtime.manifest import file_identity, validate_key


def _identity(payload: bytes) -> tuple[str, int]:
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _expected_expectation(profile: str) -> dict[str, Any]:
    partial = profile in {"pdf-unsupported-filter", "pdf-missing-stream", "ole-native-truncated"}
    expected: dict[str, Any] = {
        "static_status": "partial" if partial else "complete",
        "artifact_count": 1 + len(expected_inventory(profile)) + (profile == "pdf-password-child"),
        "yara_rules": ["eicar"]
        if profile == "pdf-flate-eicar"
        else ["network_iocs"]
        if profile.startswith("office-")
        else [],
    }
    if profile != "pdf-flate-eicar":
        expected["infected_artifacts"] = 0
    if partial:
        expected["root_stages"] = {"format-analysis": "partial"}
        if profile.startswith("ole-"):
            expected["root_stages"]["document-analysis"] = "partial"
        expected["partial_stages"] = ["format-analysis", "document-analysis"]
    return expected


def expected_inventory(profile: str) -> list[dict[str, Any]]:
    """Derive exact root-child occurrences from fixture bytes, never the report."""
    payload = build_document_embedded_fixture(profile)
    entries: list[dict[str, Any]] = []

    def add(data: bytes, source: str, origin: str, archive_type: str | None) -> None:
        sha256, size = _identity(data)
        entries.append(
            {
                "sha256": sha256,
                "size": size,
                "extraction_source": source,
                "origin_path": origin,
                "archive_type": archive_type,
            }
        )

    if profile.startswith("pdf-"):
        for index, child in enumerate(embedded_fixture_payloads(profile)):
            add(child, "format-analysis", f"pdf-attachment/{index:04d}", "pdf")
    elif profile.startswith("office-"):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.namelist():
                add(archive.read(member), "archive-extract", member, "zip")
            member = (
                "word/embeddings/attachment.pdf"
                if profile == "office-embedded-pdf"
                else "custom/payload.pdf"
            )
            for source in ("format-analysis", "document-analysis"):
                add(
                    archive.read(member),
                    source,
                    "ooxml_embed_" + member,
                    "office" if source == "format-analysis" else None,
                )
    else:
        prefix = "ole-package" if profile == "ole-package-pdf" else "ole-native"
        for child in embedded_fixture_payloads(profile):
            for source in ("format-analysis", "document-analysis"):
                add(child, source, prefix + "/0", "office" if source == "format-analysis" else None)
    return entries


def load_manifest(path: Path) -> dict[str, Any]:
    """Reject changed input bytes, invented cases and ambiguous expectations."""
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or not _is_int(data.get("schema_version"))
        or data.get("schema_version") != 1
        or data.get("recipe_version") != 1
        or not _is_int(data.get("recipe_version"))
        or data.get("scope") != "local_real_document_embedded_acceptance"
        or data.get("suite_version") != "document-embedded-v1.0.0"
        or data.get("policy_version") != "msrs-v1.2"
        or not re.fullmatch(r"[a-f0-9]{64}", str(data.get("rules_sha256", "")))
        or not isinstance(data.get("cases"), list)
        or not 1 <= len(data["cases"]) <= 20
    ):
        raise ValueError("Invalid embedded document acceptance manifest")
    seen: set[str] = set()
    for case in data["cases"]:
        if not isinstance(case, dict):
            raise ValueError("Invalid embedded document case")
        profile = case.get("profile")
        if (
            profile not in DOCUMENT_EMBEDDED_PROFILES
            or case.get("id") != profile
            or profile in seen
        ):
            raise ValueError("Invalid or duplicate embedded document profile")
        seen.add(profile)
        payload = build_document_embedded_fixture(profile)
        if (
            not _is_int(case.get("bytes"))
            or (case.get("sha256"), case["bytes"]) != _identity(payload)
            or case.get("direct_inventory") != expected_inventory(profile)
        ):
            raise ValueError("Embedded document fixture or expected inventory differs")
        partial = profile in {
            "pdf-unsupported-filter",
            "pdf-missing-stream",
            "ole-native-truncated",
        }
        expected_scenario = (
            "password" if profile == "pdf-password-child" else "partial" if partial else "normal"
        )
        if case.get("scenario") != expected_scenario or case.get("expect") != _expected_expectation(
            profile
        ):
            raise ValueError("Embedded document case expectation differs")
    return cast(dict[str, Any], data)


def verify_inventory(
    case: dict[str, Any], report: dict[str, Any], result_directory: Path
) -> dict[str, Any]:
    """Check exact occurrence sources and independently read every stored child."""
    root_id = report["root_artifact_id"]
    nodes = report["artifacts"]
    roots = [node for node in nodes if node.get("parent_id") is None]
    if len(roots) != 1 or roots[0]["artifact_id"] != root_id:
        raise ValueError("Missing unique root occurrence")
    direct = [node for node in nodes if node.get("parent_id") == root_id]
    keys = ("sha256", "size", "extraction_source", "origin_path", "archive_type")
    observed = Counter(tuple(node.get(key) for key in keys) for node in direct)
    expected = Counter(tuple(node.get(key) for key in keys) for node in case["direct_inventory"])
    if observed != expected:
        raise ValueError("Recovered direct attachment inventory or provenance differs")
    inventory: list[dict[str, Any]] = []
    for node in nodes:
        if node["artifact_id"] == root_id:
            continue
        key = validate_key(node["storage_key"])
        path = result_directory.joinpath(*key.split("/"))
        if path.is_symlink() or not path.resolve().is_relative_to(result_directory.resolve()):
            raise ValueError("Stored child path escapes the result directory")
        if file_identity(path) != (node["sha256"], node["size"]):
            raise ValueError("Actual stored child bytes differ from the report")
        inventory.append(
            {key: node.get(key) for key in (*keys, "artifact_id", "parent_id", "depth")}
        )
    if case["profile"] == "pdf-password-child":
        locked = direct[0]
        plaintext = [node for node in nodes if node.get("parent_id") == locked["artifact_id"]]
        if len(plaintext) != 1 or plaintext[0].get("origin_path") != "pdf-decrypted":
            raise ValueError("Password-protected attachment did not produce one plaintext child")
        child = plaintext[0]
        if child["depth"] != 2 or child.get("archive_type") != "pdf":
            raise ValueError("Decrypted attachment lineage differs")
        reader = PdfReader(result_directory / child["storage_key"])
        if reader.is_encrypted or len(reader.pages) != 1:
            raise ValueError("Decrypted attachment is not a readable plain PDF")
    elif len(direct) != len(nodes) - 1:
        raise ValueError("Unexpected nested attachment occurrence")
    if case["profile"] == "pdf-flate-eicar":
        child = direct[0]
        child_report = child["report"]
        if child_report["results"]["av_result"].get("infected") is not True:
            raise ValueError("Native antivirus did not detect the recovered EICAR payload")
        if "eicar" not in {hit["rule"] for hit in child_report["results"]["yara_hits"]}:
            raise ValueError("Native YARA did not scan the recovered EICAR payload")
        if report.get("risk_level") not in {"high", "malicious"}:
            raise ValueError("Detected attachment risk did not reach the parent report")
    if case["profile"].startswith("pdf-"):
        features = roots[0]["report"]["results"]["format_analysis"]["features"]
        summary = features.get("attachment_extraction", {})
        expected_status = "partial" if case["scenario"] == "partial" else "complete"
        if summary.get("status") != expected_status or summary.get("extracted_files") != len(
            direct
        ):
            raise ValueError("PDF attachment extraction summary contradicts the child graph")
        metadata = [
            item
            for item in features.get("embedded_files", [])
            if item.get("extraction_status") == "extracted"
        ]
        if Counter(
            (item.get("source"), item.get("sha256"), item.get("size")) for item in metadata
        ) != Counter((node["origin_path"], node["sha256"], node["size"]) for node in direct):
            raise ValueError("PDF attachment metadata lacks actual child identities")
        if case["profile"] == "pdf-alias-and-duplicate-names":
            if len(metadata) != 3 or max(len(item.get("references", [])) for item in metadata) < 4:
                raise ValueError(
                    "PDF aliases or distinct same-name streams were merged or duplicated"
                )
            if len({node["artifact_id"] for node in direct}) != 3:
                raise ValueError("Distinct same-hash attachment occurrences lost their identity")
    return {"stored_children_verified": len(inventory), "inventory": inventory}


def _check_secrets(directory: Path) -> None:
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".log"}:
            text = path.read_text(errors="replace")
            if PDF_PASSWORD in text or WRONG_PASSWORD in text:
                raise ValueError("Public fixture password leaked into durable JSON or process log")


async def execute_case(
    case: dict[str, Any], suite: dict[str, Any], directory: Path
) -> dict[str, Any]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    suffix = (
        ".pdf"
        if case["profile"].startswith("pdf-")
        else ".docx"
        if case["profile"].startswith("office-")
        else ".bin"
    )
    source = directory / ("source" + suffix)
    payload = build_document_embedded_fixture(case["profile"])
    source.write_bytes(payload)
    manifest = AnalysisManifest.for_local_file(source)
    state_dir, result_dir = directory / "state", directory / "analysis"
    completed: dict[tuple[str, str], dict[str, Any]] = {}
    password_attempts: dict[str, int] = {}
    observations: list[dict[str, Any]] = []

    async def attempt(
        label: str, passwords: dict[str, str] | None = None, *, resume: bool = False
    ) -> dict[str, Any]:
        for artifact_id in passwords or {}:
            password_attempts[artifact_id] = password_attempts.get(artifact_id, 0) + 1
        runner = RootBatchRunner(
            manifest=manifest,
            source_store=LocalObjectStore(directory, read_only=True),
            result_store=LocalObjectStore(result_dir),
            state_dir=state_dir,
            limits=BudgetLimits(30, 5_000_000, 300),
            max_depth=4,
            passwords=passwords,
            password_attempts_by_artifact=password_attempts,
            password_attempt_limit=3,
        )
        report = await runner.run(resume=resume)
        state = json.loads((state_dir / "checkpoint.json").read_text())
        current = _completed_stages(state)
        if any(current.get(key) != value for key, value in completed.items()):
            raise ValueError("A completed stage changed during password/checkpoint resume")
        completed.update(current)
        path = directory / f"report-{label}.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        if source.read_bytes() != payload:
            raise ValueError("The original document bytes changed")
        _check_secrets(directory)
        observations.append(
            {
                "attempt": label,
                "job_status": report["job_status"],
                "artifact_count": len(report["artifacts"]),
                "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        return report

    final = await attempt("initial")
    if case["scenario"] == "password":
        locked_hash = _identity(embedded_fixture_payloads(case["profile"])[0])[0]
        locked_id = _waiting(final, locked_hash)
        wrong = await attempt("wrong-password", {locked_id: WRONG_PASSWORD}, resume=True)
        if _waiting(wrong, locked_hash, wrong=True) != locked_id:
            raise ValueError("Wrong password changed the attachment occurrence")
        (state_dir / "checkpoint.json").unlink()
        final = await attempt("unlocked", {locked_id: PDF_PASSWORD}, resume=True)
        if password_attempts != {locked_id: 2}:
            raise ValueError("Attachment password attempts did not remain artifact-scoped")
    evaluation = evaluate_report(
        case,
        final,
        source_sha256=case["sha256"],
        source_size=case["bytes"],
        rules_sha256=suite["rules_sha256"],
    )
    if not evaluation["passed"]:
        raise ValueError("Final native static coverage differs: " + "; ".join(evaluation["errors"]))
    if final["risk"].get("policy_version") != suite["policy_version"]:
        raise ValueError("Risk policy differs from the declared suite")
    checked = verify_inventory(case, final, result_dir)
    budget = json.loads((state_dir / "checkpoint.json").read_text())["budget"]
    children = [node for node in final["artifacts"] if node.get("parent_id") is not None]
    if budget["used_files"] != len(children) or budget["used_bytes"] != sum(
        node["size"] for node in children
    ):
        raise ValueError("Root budget does not account for every extracted occurrence")
    checked["root_budget"] = {key: budget[key] for key in ("used_files", "used_bytes")}
    original_ids = {node["artifact_id"] for node in final["artifacts"]}
    repeated = await attempt("completed-resume", resume=True)
    if {node["artifact_id"] for node in repeated["artifacts"]} != original_ids:
        raise ValueError("Completed resume duplicated embedded occurrences")
    resumed_budget = json.loads((state_dir / "checkpoint.json").read_text())["budget"]
    if any(
        resumed_budget[key] != budget[key] for key in ("used_files", "used_bytes", "reservations")
    ):
        raise ValueError("Completed resume changed extracted occurrence accounting")
    return {
        "id": case["id"],
        "passed": True,
        "fixture_sha256": case["sha256"],
        "scenario": case["scenario"],
        "attempts": observations,
        "password_attempts_by_artifact": password_attempts,
        **checked,
        **evaluation,
    }


def run_subprocess(case: dict[str, Any], manifest: Path, directory: Path) -> dict[str, Any]:
    print(f"Embedded document case: {case['id']}", flush=True)
    started = time.monotonic()
    directory.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "malscan_worker.quality.document_embedded_acceptance",
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
    with log_path.open("wb") as output:
        process = subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        try:
            code: int | None = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            code = None
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    result_path = directory / "case-result.json"
    result = (
        cast(dict[str, Any], json.loads(result_path.read_text()))
        if result_path.is_file()
        else {"id": case["id"], "passed": False, "error": "Case process failed or timed out"}
    )
    if code != 0:
        result.update(passed=False, process_exit_code=code)
    try:
        _check_secrets(directory.parent)
    except ValueError:
        result.update(passed=False, error="Public fixture password leaked into process output")
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
        case = next(item for item in suite["cases"] if item["id"] == args.execute_case)
        try:
            result = asyncio.run(execute_case(case, suite, args.output_dir))
        except FileExistsError:
            parser.error("Case output directory already exists")
        except Exception as exc:
            detail = (
                str(exc)
                .replace(PDF_PASSWORD, "[public-fixture-password]")
                .replace(WRONG_PASSWORD, "[public-fixture-password]")
            )
            result = {"id": case["id"], "passed": False, "error": detail}
        if args.output_dir.is_dir():
            (args.output_dir / "case-result.json").write_text(json.dumps(result, indent=2) + "\n")
        return 0 if result["passed"] else 1
    cases = suite["cases"]
    if args.case_ids:
        selected = set(args.case_ids)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown selected case")
        cases = [case for case in cases if case["id"] in selected]
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
        result.update(passed=False, error="Acceptance manifest changed during the run")
    (args.output_dir / "quality-report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
