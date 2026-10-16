"""Run the local synthetic quality corpus against the real shared static pipeline.

Each case uses a fresh Python process and checkpoint. This isolates deliberate
missing-tool/invalid-rule controls from normal cases and never mocks detectors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malscan_worker.quality.corpus import evaluate_report, fixture_bytes, load_corpus


def run_case(case: dict[str, Any], definitions: dict[str, Any], directory: Path) -> dict[str, Any]:
    directory.mkdir(mode=0o700)
    source = directory / case["filename"]
    source.write_bytes(fixture_bytes(definitions, case["fixture"]))
    environment = dict(os.environ)
    environment.update(SANDBOX_ENABLED="false", SANDBOX_ENABLE_URL_SUBMISSION="false")
    scenario = case.get("scenario", "normal")
    if scenario == "missing_av":
        environment.update(CLAMAV_MODE="cli", CLAMAV_CLI_PATH=str(directory / "missing-clamscan"))
    elif scenario in {"missing_rules", "invalid_rules"}:
        rules = directory / "control-rules"
        rules.mkdir()
        if scenario == "invalid_rules":
            (rules / "invalid.yar").write_text("rule invalid { condition: }\n")
        environment["YARA_RULES_PATH"] = str(rules)
    elif scenario == "candidate_cap":
        environment["DEOBFUSCATION_MAX_CANDIDATES"] = "1"
    elif scenario == "deob_size_limit":
        environment["DEOBFUSCATION_MAX_FILE_SIZE"] = "1"
    command = [
        sys.executable,
        "-m",
        "malscan_worker.runtime",
        "--file",
        str(source),
        "--output-dir",
        str(directory / "analysis"),
        "--attempt-timeout",
        "120",
    ]
    if scenario == "depth_limit":
        command.extend(["--max-depth", "1"])
    started = time.monotonic()
    with (directory / "runner.log").open("wb") as output:
        process = subprocess.Popen(
            command,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code: int | None = process.wait(timeout=150)
        except subprocess.TimeoutExpired:
            code = None
        finally:
            # Stop the runner's process group, including any children sharing it.
            # Scanner/extractor ports also enforce their own deadline cleanup.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    report_path = directory / "analysis" / "report.json"
    observed: dict[str, Any]
    if code != 0 or not report_path.is_file():
        observed = {
            "passed": False,
            "errors": ["pipeline process failed or timed out"],
            "process_exit_code": code,
        }
    else:
        try:
            observed = evaluate_report(
                case,
                json.loads(report_path.read_text()),
                source_sha256=definitions[case["fixture"]]["sha256"],
                source_size=source.stat().st_size,
            )
        except (KeyError, TypeError, ValueError):
            observed = {"passed": False, "errors": ["invalid pipeline report structure"]}
        if (
            hashlib.sha256(source.read_bytes()).hexdigest()
            != definitions[case["fixture"]]["sha256"]
        ):
            observed["passed"] = False
            observed["errors"].append("source fixture changed during analysis")
        observed["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    return {
        "id": case["id"],
        "label": case["label"],
        "scenario": scenario,
        "fixture_sha256": definitions[case["fixture"]]["sha256"],
        "known_limitations": case.get("known_limitations", []),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        **observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="New local directory")
    parser.add_argument(
        "--case", action="append", dest="case_ids", help="Select a case; repeatable"
    )
    args = parser.parse_args()
    manifest_sha256 = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    corpus = load_corpus(args.manifest)
    if hashlib.sha256(args.manifest.read_bytes()).hexdigest() != manifest_sha256:
        parser.error("Corpus changed during loading")
    cases = corpus["cases"]
    if args.case_ids:
        selected = set(args.case_ids)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown selected case")
        cases = [case for case in cases if case["id"] in selected]
    # Fresh output is mandatory: retained evidence is never silently overwritten.
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    started_at = datetime.now(timezone.utc).isoformat()
    results = []
    for case in cases:
        print(f"Quality case: {case['id']}", flush=True)
        results.append(run_case(case, corpus["fixtures"], args.output_dir / case["id"]))
    result = {
        "schema_version": 1,
        "corpus_version": corpus["corpus_version"],
        "manifest_sha256": manifest_sha256,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "scope": "local_synthetic_static_quality",
        "cloud_run_executed": False,
        "passed": all(item["passed"] for item in results),
        "case_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "benign_cases_with_rule_hits": [
            item["id"] for item in results if item["label"] == "benign" and item.get("yara_rules")
        ],
        "accuracy_claim": "Synthetic contract baseline; no real-world detection-rate claim",
        "cases": results,
    }
    if hashlib.sha256(args.manifest.read_bytes()).hexdigest() != manifest_sha256:
        result["passed"] = False
        result["error"] = "Corpus changed during the run"
    (args.output_dir / "quality-report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
