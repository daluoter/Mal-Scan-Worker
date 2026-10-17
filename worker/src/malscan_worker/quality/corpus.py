"""Build checksum-pinned, deterministic inputs and validate actual engine reports."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any, cast

from malscan.analysis_contract import build_analysis, summarize_static_artifacts

from malscan_worker.runtime.engine_controls import EICAR

SCENARIOS = {
    "normal",
    "missing_av",
    "missing_rules",
    "invalid_rules",
    "candidate_cap",
    "deob_size_limit",
    "depth_limit",
}
REQUIRED_STAGES = {
    "file-type",
    "clamav",
    "yara",
    "ioc-extract",
    "deobfuscation",
    "format-analysis",
    "archive-extract",
    "document-analysis",
}


def fixture_bytes(definitions: dict[str, Any], name: str, stack: tuple[str, ...] = ()) -> bytes:
    """Generate a small fixed fixture, rejecting cycles and unpinned content."""
    if name in stack or len(stack) > 8 or name not in definitions:
        raise ValueError("Invalid fixture dependency")
    spec = definitions[name]
    kind = spec.get("kind")
    if kind == "text":
        payload = spec["text"].encode("utf-8")
    elif kind == "eicar":
        payload = EICAR
    elif kind == "pe":
        from malscan_worker.quality.pe_fixtures import build_pe_fixture

        payload = build_pe_fixture(spec["profile"], recipe_version=spec["recipe_version"])
    elif kind == "document":
        from malscan_worker.quality.document_fixtures import build_document_fixture

        payload = build_document_fixture(spec["profile"], recipe_version=spec["recipe_version"])
    elif kind == "zip":
        output = io.BytesIO()
        compression = zipfile.ZIP_DEFLATED if spec.get("deflated") else zipfile.ZIP_STORED
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            for entry in spec["entries"]:
                info = zipfile.ZipInfo(entry["name"], (2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = compression
                archive.writestr(info, fixture_bytes(definitions, entry["fixture"], (*stack, name)))
        payload = output.getvalue()
    elif kind == "gzip":
        output = io.BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as archive:
            archive.write(fixture_bytes(definitions, spec["fixture"], (*stack, name)))
        payload = output.getvalue()
    else:
        raise ValueError("Unknown fixture recipe")
    if len(payload) > 1_000_000:
        raise ValueError("Quality fixtures must remain small")
    if hashlib.sha256(payload).hexdigest() != spec["sha256"]:
        raise ValueError(f"Fixture checksum differs: {name}")
    return cast(bytes, payload)


def load_corpus(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("corpus_version"), str):
        raise ValueError("Unsupported quality corpus")
    if not isinstance(data.get("fixtures"), dict) or not isinstance(data.get("cases"), list):
        raise ValueError("Invalid corpus definitions")
    if not 1 <= len(data["cases"]) <= 100:
        raise ValueError("Invalid corpus case count")
    rules_hash = data.get("rules_sha256")
    if rules_hash is not None and (
        not isinstance(rules_hash, str) or re.fullmatch(r"[a-f0-9]{64}", rules_hash) is None
    ):
        raise ValueError("Invalid corpus rules fingerprint")
    for name in data["fixtures"]:
        fixture_bytes(data["fixtures"], name)
    identifiers: set[str] = set()
    for case in data["cases"]:
        identifier = case.get("id", "")
        filename = case.get("filename", "")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", identifier) or identifier in identifiers:
            raise ValueError("Invalid or duplicate case identifier")
        identifiers.add(identifier)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", filename) or filename in {".", ".."}:
            raise ValueError("Invalid fixture filename")
        if case.get("scenario", "normal") not in SCENARIOS:
            raise ValueError("Unknown quality scenario")
        if case.get("label") not in {"benign", "synthetic_indicator", "test_signature", "failure"}:
            raise ValueError("Unknown sample label")
        if case.get("fixture") not in data["fixtures"] or not isinstance(case.get("expect"), dict):
            raise ValueError("Missing quality expectation")
        checks = case["expect"].get("checks", [])
        if not isinstance(checks, list) or len(checks) > 100:
            raise ValueError("Invalid format evidence checks")
        for check in checks:
            if not isinstance(check, dict):
                raise ValueError("Invalid format evidence check")
            operators = set(check) - {"path"}
            if len(operators) != 1 or not operators <= {
                "equals",
                "includes",
                "text_contains",
                "min_length",
            }:
                raise ValueError("Unknown format evidence check")
            path_components = check.get("path")
            if not isinstance(path_components, list) or not 1 <= len(path_components) <= 20:
                raise ValueError("Invalid format evidence path")
            if any(
                not isinstance(part, (str, int)) or isinstance(part, bool)
                for part in path_components
            ):
                raise ValueError("Invalid format evidence path")
            if "text_contains" in check and not isinstance(check["text_contains"], str):
                raise ValueError("Invalid evidence text check")
            if "min_length" in check and (
                not isinstance(check["min_length"], int)
                or isinstance(check["min_length"], bool)
                or check["min_length"] < 0
            ):
                raise ValueError("Invalid evidence length check")
    return cast(dict[str, Any], data)


def evaluate_report(
    case: dict[str, Any],
    report: dict[str, Any],
    *,
    source_sha256: str,
    source_size: int,
    rules_sha256: str | None = None,
) -> dict[str, Any]:
    """Check coverage and evidence independently from clean/empty legacy fields."""
    errors: list[str] = []
    expected = case["expect"]

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(report.get("report_complete") is True, "execution did not finish")
    require(report.get("job_status") == "done", "unexpected execution state")
    static = report.get("analysis", {}).get("static", {})
    require(static.get("status") == expected["static_status"], "static coverage differs")
    require(
        report.get("analysis", {}).get("dynamic", {}).get("status") == "disabled",
        "dynamic analysis must remain disabled",
    )
    nodes = report.get("artifacts", [])
    require(len(nodes) == expected["artifact_count"], "artifact occurrence count differs")
    identifiers = [node["artifact_id"] for node in nodes]
    require(len(set(identifiers)) == len(identifiers), "artifact IDs are not unique")
    root_id = str(report.get("root_artifact_id") or "")
    root_nodes = [node for node in nodes if node.get("parent_id") is None]
    require(len(root_nodes) == 1, "there must be exactly one root occurrence")
    require(
        bool(root_nodes) and root_nodes[0]["artifact_id"] == root_id,
        "root identity is not a root occurrence",
    )
    require(report.get("job_id") == root_id, "report job and root identity differ")
    parents = {node["artifact_id"]: node.get("parent_id") for node in nodes}
    for identifier in identifiers:
        visited: set[str] = set()
        current = identifier
        while current != root_id:
            if current in visited:
                require(False, "artifact parent graph contains a cycle")
                break
            visited.add(current)
            parent = parents.get(current)
            if parent is None or parent not in parents:
                require(False, "artifact occurrence cannot reach the root")
                break
            current = parent
    require(
        report.get("file", {}).get("sha256") == source_sha256
        and report.get("file", {}).get("size") == source_size,
        "root report is not bound to the pinned fixture",
    )
    all_hits: set[str] = set()
    risk_rule_hits: set[str] = set()
    context_rule_hits: set[str] = set()
    infected = 0
    detector_failures: list[dict[str, Any]] = []
    observed_coverage: dict[str, str] = {}
    for node in nodes:
        identifier = node["artifact_id"]
        require(node.get("root_id") == root_id, "artifact root identity differs")
        require(
            node.get("parent_id") is None or node["parent_id"] in identifiers,
            "artifact parent is missing",
        )
        child = node.get("report") or {}
        if node.get("parent_id") is None:
            require(
                node.get("sha256") == source_sha256 and node.get("size") == source_size,
                "root occurrence is not bound to the pinned fixture",
            )
        require(
            child.get("file", {}).get("sha256") == node["sha256"]
            and child.get("file", {}).get("size") == node.get("size"),
            "artifact report content identity differs",
        )
        coverage = child.get("analysis", {}).get("static", {}).get("stage_coverage", [])
        stages = {item["stage"]: item for item in coverage}
        require(
            set(stages) == REQUIRED_STAGES and len(coverage) == len(REQUIRED_STAGES),
            "required stage coverage is missing or duplicated",
        )
        calculated = build_analysis(stages=coverage)["static"]["status"]
        observed_coverage[identifier] = calculated
        require(
            child.get("analysis", {}).get("static", {}).get("status") == calculated,
            "artifact stage coverage contradicts its declared status",
        )
        overrides = expected.get("root_stages", {}) if node["parent_id"] is None else {}
        for name in ("clamav", "yara", "file-type", "ioc-extract", "deobfuscation"):
            status = stages.get(name, {}).get("status")
            require(status == overrides.get(name, "ok"), f"{identifier}: {name} status differs")
            if name in {"clamav", "yara"} and status != "ok":
                detector_failures.append(
                    {"artifact_id": identifier, "stage": name, "status": status}
                )
        for name, status in overrides.items():
            require(stages.get(name, {}).get("status") == status, f"root {name} status differs")
        for name in ("format-analysis", "archive-extract", "document-analysis"):
            status = stages.get(name, {}).get("status")
            if name not in overrides and name not in expected.get("partial_stages", []):
                require(
                    status in {"ok", "skipped"}, f"{identifier}: {name} unexpectedly incomplete"
                )
        for item in coverage:
            if item["status"] not in {"ok", "skipped"}:
                require(bool(item.get("reason")), "incomplete stage lacks a reason")
        results = child.get("results", {})
        av = results.get("av_result", {})
        if stages.get("clamav", {}).get("status") == "ok":
            require(isinstance(av.get("infected"), bool), "successful AV lacks detection state")
            infected += av.get("infected") is True
        hits = results.get("yara_hits", [])
        all_hits.update(hit["rule"] for hit in hits)
        for evidence in child.get("risk", {}).get("evidence", []):
            if evidence.get("source") != "yara":
                continue
            rule_name = evidence.get("raw", {}).get("rule")
            if not isinstance(rule_name, str):
                continue
            if evidence.get("tier") == "benign_context" and evidence.get("points") == 0:
                context_rule_hits.add(rule_name)
            else:
                risk_rule_hits.add(rule_name)
        if stages.get("yara", {}).get("status") == "ok":
            require(bool(stages["yara"].get("rules_version")), "YARA lacks a rule fingerprint")
            require(bool(stages["yara"].get("tool_version")), "YARA lacks an engine version")
            if rules_sha256:
                require(
                    stages["yara"].get("rules_version") == rules_sha256,
                    "YARA rules differ from the versioned corpus",
                )
        if node["parent_id"] is not None and (av.get("infected") is True or hits):
            explain = report.get("explainability", {})
            evidence = explain.get("evidence", [])
            findings = [
                f for f in explain.get("findings", []) if f.get("artifact_id") == identifier
            ]
            require(bool(findings), "child detection has no explainable finding")
            evidence_ids = {e["id"] for e in evidence if e.get("artifact_id") == identifier}
            require(
                any(set(f.get("evidence_ids", [])) & evidence_ids for f in findings),
                "child finding lacks a resolvable artifact-scoped evidence reference",
            )
    require(sorted(all_hits) == sorted(expected["yara_rules"]), "YARA match inventory differs")
    for key, observed in (
        ("yara_risk_rules", risk_rule_hits),
        ("yara_context_rules", context_rule_hits),
    ):
        if key in expected:
            require(sorted(observed) == sorted(expected[key]), f"{key} differs")
    if "infected_artifacts" in expected:
        require(infected == expected["infected_artifacts"], "AV detection count differs")
    risk = report.get("risk", {})
    if "risk_score_min" in expected:
        require(
            expected["risk_score_min"] <= report.get("score", -1) <= expected["risk_score_max"],
            "risk score is outside the fixture baseline",
        )
        require(
            report.get("verdict") in expected["verdicts"], "verdict differs from fixture baseline"
        )
    for key, top_key in (
        ("risk_score", "score"),
        ("risk_level", "risk_level"),
        ("legacy_verdict", "verdict"),
    ):
        require(risk.get(key) == report.get(top_key), f"merged risk {key} is inconsistent")
    for key in ("high_gate_open", "malicious_gate_open", "independent_source_count"):
        require(risk.get(key) == risk.get("breakdown", {}).get(key), f"merged risk {key} differs")
    explain_evidence = report.get("explainability", {}).get("evidence", [])
    global_evidence_ids = [entry["id"] for entry in explain_evidence]
    require(
        len(global_evidence_ids) == len(set(global_evidence_ids)),
        "explainability evidence IDs collide",
    )
    if expected.get("inherited_risk"):
        require(
            risk.get("breakdown", {}).get("inherited_score", 0) > 0,
            "child detection did not contribute inherited risk",
        )
    require(
        report.get("artifact_tree", {}).get("analysis_status") == static.get("status"),
        "artifact tree and root coverage differ",
    )
    require(
        summarize_static_artifacts(
            observed_coverage.get(root_id, "unknown"),
            [value for key, value in observed_coverage.items() if key != root_id],
        )
        == static.get("status"),
        "root coverage contradicts artifact stage results",
    )
    for check in expected.get("checks", []):
        value: Any = report
        path = check["path"]
        try:
            for component in path:
                value = value[component]
        except (IndexError, KeyError, TypeError):
            require(False, f"required format evidence is missing: {path}")
            continue
        if "equals" in check:
            valid = value == check["equals"]
        elif "includes" in check:
            valid = isinstance(value, list) and check["includes"] in value
        elif "text_contains" in check:
            text = check["text_contains"]
            valid = (isinstance(value, str) and text in value) or (
                isinstance(value, list)
                and any(isinstance(item, str) and text in item for item in value)
            )
        else:
            valid = isinstance(value, (list, dict, str)) and len(value) >= check["min_length"]
        require(valid, f"format evidence differs: {path}")
    return {
        "passed": not errors,
        "errors": errors,
        "static_status": static.get("status"),
        "artifact_count": len(nodes),
        "yara_rules": sorted(all_hits),
        "yara_risk_rules": sorted(risk_rule_hits),
        "yara_context_rules": sorted(context_rule_hits),
        "infected_artifacts": infected,
        "detector_failures": detector_failures,
        "verdict": report.get("verdict"),
        "score": report.get("score"),
    }
