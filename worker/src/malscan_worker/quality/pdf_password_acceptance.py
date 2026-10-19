"""Run real PDF password waits and checkpoint resumes with native static engines.

Every case runs in an isolated process and a new output directory. Only public
fixture passwords are used; this suite never calls a cloud API or changes a live
job. Retain the generated reports for coverage and provenance review.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from pypdf import PdfReader

from malscan_worker.budget import BudgetLimits
from malscan_worker.quality.corpus import REQUIRED_STAGES, evaluate_report
from malscan_worker.quality.pdf_password_fixtures import (
    ARCHIVE_PASSWORD,
    PDF_OWNER_PASSWORD,
    PDF_PASSWORD,
    WRONG_PASSWORD,
    build_pdf_password_fixture,
)
from malscan_worker.runtime import AnalysisManifest, LocalObjectStore, RootBatchRunner
from malscan_worker.runtime.manifest import file_identity


def load_manifest(path: Path) -> dict[str, Any]:
    """Validate checksum-pinned, bounded fixture cases before any analysis."""
    data = json.loads(path.read_text())
    if (
        data.get("schema_version") != 1
        or data.get("scope") != "local_real_pdf_password_acceptance"
        or not isinstance(data.get("suite_version"), str)
        or data.get("recipe_version") != 1
        or not re.fullmatch(r"[a-f0-9]{64}", str(data.get("rules_sha256", "")))
        or not isinstance(data.get("policy_version"), str)
        or not isinstance(data.get("cases"), list)
        or not 1 <= len(data["cases"]) <= 20
    ):
        raise ValueError("Invalid PDF password acceptance manifest")
    seen: set[str] = set()
    for case in data["cases"]:
        identifier = case.get("id", "")
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", identifier)
            or identifier in seen
            or case.get("scenario") not in {"prompt", "empty", "nested"}
            or not isinstance(case.get("active_actions"), bool)
        ):
            raise ValueError("Invalid PDF password acceptance case")
        seen.add(identifier)
        child_rules = case.get("child_yara_rules", [])
        if (
            not isinstance(child_rules, list)
            or any(not isinstance(rule, str) for rule in child_rules)
            or len(set(child_rules)) != len(child_rules)
        ):
            raise ValueError("Invalid plaintext child rule expectation")
        payload = build_pdf_password_fixture(case["profile"], data["recipe_version"])
        if hashlib.sha256(payload).hexdigest() != case.get("sha256") or len(payload) != case.get(
            "bytes"
        ):
            raise ValueError("PDF password acceptance fixture identity differs")
    return cast(dict[str, Any], data)


def _check_secrets(directory: Path) -> None:
    # Source/child PDFs are excluded: their encrypted payload is deliberately
    # arbitrary binary. Public reports and durable checkpoint JSON must be clean.
    for path in directory.rglob("*.json"):
        text = path.read_text()
        if any(
            password in text
            for password in (PDF_PASSWORD, PDF_OWNER_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD)
        ):
            raise ValueError("Fixture password leaked into durable JSON")


def _waiting(report: dict[str, Any], expected_sha256: str, *, wrong: bool = False) -> str:
    if (
        report.get("job_status") != "password_required"
        or report.get("report_complete") is not False
    ):
        raise ValueError("Locked content was reported as a completed execution")
    waiting = [node for node in report["artifacts"] if node["status"] == "password_required"]
    if len(waiting) != 1 or waiting[0]["sha256"] != expected_sha256:
        raise ValueError("Password challenge did not bind to the expected occurrence")
    if wrong and waiting[0].get("reason") != "wrong_password":
        raise ValueError("Incorrect password did not retain an explicit wrong-password state")
    if waiting[0]["artifact_id"] not in report.get("password_required_artifacts", []):
        raise ValueError("Password challenge is missing from the public report")
    return str(waiting[0]["artifact_id"])


def _completed_stages(state: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (identifier, stage["stage_name"]): stage
        for identifier, artifact in state["artifacts"].items()
        for stage in artifact["stage_results"]
        if stage["status"] in {"ok", "skipped"}
    }


async def execute_case(
    case: dict[str, Any], suite: dict[str, Any], directory: Path
) -> dict[str, Any]:
    """Exercise real encryption, stage checkpoints and child evidence end to end."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = directory / ("source.zip" if case["scenario"] == "nested" else "source.pdf")
    payload = build_pdf_password_fixture(case["profile"], suite["recipe_version"])
    source.write_bytes(payload)
    manifest = AnalysisManifest.for_local_file(source)
    state_dir = directory / "state"
    result_dir = directory / "analysis"
    observations: list[dict[str, Any]] = []
    completed: dict[tuple[str, str], dict[str, Any]] = {}
    password_attempts: dict[str, int] = {}

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
            limits=BudgetLimits(30, 5_000_000, 120),
            max_depth=3,
            passwords=passwords,
            password_attempts_by_artifact=password_attempts,
            password_attempt_limit=3,
        )
        report = await runner.run(resume=resume)
        state = json.loads((state_dir / "checkpoint.json").read_text())
        current = _completed_stages(state)
        if any(current.get(key) != value for key, value in completed.items()):
            raise ValueError("A completed stage was rescanned or changed during resume")
        completed.update(current)
        (directory / f"report-{label}.json").write_text(json.dumps(report, indent=2) + "\n")
        if source.read_bytes() != payload:
            raise ValueError("Original encrypted fixture changed")
        _check_secrets(directory)
        observations.append(
            {
                "attempt": label,
                "job_status": report["job_status"],
                "report_complete": report["report_complete"],
                "artifact_count": len(report["artifacts"]),
                "report_sha256": hashlib.sha256(
                    (directory / f"report-{label}.json").read_bytes()
                ).hexdigest(),
            }
        )
        return report

    first = await attempt("initial")
    if case["scenario"] == "empty":
        final = first
    elif case["scenario"] == "nested":
        root = _waiting(first, case["sha256"])
        pdf_wait = await attempt("archive-unlocked", {root: ARCHIVE_PASSWORD}, resume=True)
        inner_payload = build_pdf_password_fixture("aes-128-active-actions")
        inner_sha256 = hashlib.sha256(inner_payload).hexdigest()
        inner = _waiting(pdf_wait, inner_sha256)
        if inner == root:
            raise ValueError("Nested PDF challenge reused the archive occurrence")
        wrong = await attempt("wrong-pdf-password", {inner: ARCHIVE_PASSWORD}, resume=True)
        if _waiting(wrong, inner_sha256, wrong=True) != inner:
            raise ValueError("Wrong password changed the PDF occurrence identity")
        # Drop only the disposable local checkpoint cache. The authenticated
        # persistent checkpoint must restore the same artifact/stage graph.
        (state_dir / "checkpoint.json").unlink()
        final = await attempt("pdf-unlocked", {inner: PDF_PASSWORD}, resume=True)
    else:
        root = _waiting(first, case["sha256"])
        wrong = await attempt("wrong-password", {root: WRONG_PASSWORD}, resume=True)
        if _waiting(wrong, case["sha256"], wrong=True) != root:
            raise ValueError("Wrong password changed the root occurrence identity")
        (state_dir / "checkpoint.json").unlink()
        final = await attempt("unlocked", {root: PDF_PASSWORD}, resume=True)

    expected: dict[str, Any] = {
        "static_status": "complete",
        "artifact_count": 3 if case["scenario"] == "nested" else 2,
        "yara_rules": case.get("child_yara_rules", []),
        "yara_risk_rules": case.get("child_yara_rules", []),
        "infected_artifacts": 0,
    }
    evaluation = evaluate_report(
        {"expect": expected},
        final,
        source_sha256=case["sha256"],
        source_size=case["bytes"],
        rules_sha256=suite["rules_sha256"],
    )
    if not evaluation["passed"]:
        raise ValueError(
            "Final coverage or native detector contract differs: " + "; ".join(evaluation["errors"])
        )
    decrypted = [
        node
        for node in final["artifacts"]
        if node.get("extraction_source") == "format-analysis"
        and node.get("origin_path") == "pdf-decrypted"
        and node.get("archive_type") == "pdf"
    ]
    if len(decrypted) != 1:
        raise ValueError("Successful unlock must produce exactly one decrypted child")
    child = decrypted[0]
    child_report = child["report"]
    child_path = result_dir / child["storage_key"]
    if file_identity(child_path) != (child["sha256"], child["size"]):
        raise ValueError("Stored decrypted content differs from its report identity")
    reader = PdfReader(child_path)
    if reader.is_encrypted or len(reader.pages) != 1:
        raise ValueError("Decrypted child bytes are not a readable unencrypted PDF")
    parent = next(node for node in final["artifacts"] if node["artifact_id"] == child["parent_id"])
    parent_features = parent["report"]["results"]["format_analysis"]["features"]
    features = child_report["results"]["format_analysis"]["features"]
    if parent_features.get("decryption_object_coverage", {}).get("status") != "complete":
        raise ValueError("Encrypted object preservation coverage is incomplete")
    child_rules = sorted(hit["rule"] for hit in child_report["results"]["yara_hits"])
    if child_rules != sorted(case.get("child_yara_rules", [])):
        raise ValueError("Plaintext child did not retain the expected native YARA markers")
    if (
        parent_features.get("encrypted") is not True
        or parent_features.get("content_access") != "decrypted_child"
        or parent_features.get("decrypted_child", {}).get("sha256") != child["sha256"]
        or parent_features.get("decrypted_child", {}).get("size") != child["size"]
        or features.get("encrypted") is not False
        or child["depth"] != parent["depth"] + 1
    ):
        raise ValueError("Decrypted child lost encrypted-parent content provenance")
    encryption = parent_features.get("encryption", {})
    profile = case["profile"]
    revision = (
        2
        if profile.startswith("rc4")
        else 4
        if "aes-128" in profile
        else 5
        if "aes-256-r5" in profile
        else 6
    )
    key_bits = 40 if revision == 2 else 128 if revision == 4 else 256
    if encryption.get("revision") != revision or encryption.get("key_bits") != key_bits:
        raise ValueError("Original encrypted-PDF algorithm provenance differs")
    for node in final["artifacts"]:
        if node["report"].get("risk", {}).get("policy_version") != suite["policy_version"]:
            raise ValueError("Scoring policy differs from the acceptance manifest")
        stages = node["report"]["analysis"]["static"]["stage_coverage"]
        if {stage["stage"] for stage in stages} != REQUIRED_STAGES:
            raise ValueError("A decrypted occurrence lacks required native stage coverage")
    if case["active_actions"]:
        indexed = {node["artifact_id"]: node for node in final["artifacts"]}
        ancestor = parent
        while True:
            effective = ancestor["report"]
            if (
                effective.get("score", 0) < child_report["score"]
                or effective.get("risk_level") not in {"high", "malicious"}
                or not isinstance(effective.get("risk", {}).get("local_risk"), dict)
            ):
                raise ValueError("An encrypted ancestor hides its verified high-risk plaintext")
            parent_id = ancestor.get("parent_id")
            if parent_id is None:
                break
            ancestor = indexed[parent_id]
        if case["scenario"] == "nested" and sorted(password_attempts.values()) != [1, 2]:
            raise ValueError("Outer ZIP and inner PDF password attempts were not independent")
        if features.get("js_code") != ["void 0;"] or features.get("launch_actions") != [
            "quality-fixture-never-execute.txt"
        ]:
            raise ValueError("Unlock lost inert JavaScript or Launch action content")
        factors = child_report["results"]["format_analysis"]["risk_factors"]
        if not {"embedded_javascript", "auto_open_action", "launch_action"} <= {
            str(item) for item in factors
        }:
            raise ValueError("Decrypted PDF structural signals were not rescanned")
        findings = final["explainability"]["findings"]
        evidence = final["explainability"]["evidence"]
        evidence_ids = {
            entry["id"] for entry in evidence if entry.get("artifact_id") == child["artifact_id"]
        }
        if not any(
            entry.get("artifact_id") == child["artifact_id"]
            and set(entry.get("evidence_ids", [])) & evidence_ids
            for entry in findings
        ):
            raise ValueError("Decrypted PDF finding lacks artifact-scoped evidence provenance")
    elif child_report["results"]["format_analysis"]["risk_factors"]:
        raise ValueError("Normal decrypted PDF acquired structural risk factors")
    final_ids = {node["artifact_id"] for node in final["artifacts"]}
    repeated = await attempt("completed-resume", resume=True)
    if {node["artifact_id"] for node in repeated["artifacts"]} != final_ids:
        raise ValueError("A completed resume duplicated decrypted child occurrences")
    return {
        "passed": True,
        "id": case["id"],
        "fixture_sha256": case["sha256"],
        "scenario": case["scenario"],
        "persistent_checkpoint_recovery": case["scenario"] != "empty",
        "password_attempts_by_artifact": dict(password_attempts),
        "attempts": observations,
        "decrypted_child_sha256": child["sha256"],
        **evaluation,
    }


def run_subprocess(case: dict[str, Any], manifest: Path, directory: Path) -> dict[str, Any]:
    print(f"PDF password case: {case['id']}", flush=True)
    started = time.monotonic()
    directory.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "malscan_worker.quality.pdf_password_acceptance",
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
            code: int | None = process.wait(timeout=300)
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
            result["passed"] = False
            result["process_exit_code"] = code
    else:
        result = {
            "id": case["id"],
            "passed": False,
            "error": "case process failed or timed out",
            "process_exit_code": code,
        }
    log_text = log_path.read_text(errors="replace")
    if any(
        password in log_text
        for password in (PDF_PASSWORD, PDF_OWNER_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD)
    ):
        result.update(passed=False, error="Fixture password leaked into process log")
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
            # Preserve the prior case evidence even when this private subprocess
            # interface is called directly or two invocations race.
            parser.error("Case output directory already exists")
        except Exception as exc:
            detail = str(exc)
            for password in (PDF_PASSWORD, PDF_OWNER_PASSWORD, ARCHIVE_PASSWORD, WRONG_PASSWORD):
                detail = detail.replace(password, "[fixture-password-redacted]")
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
