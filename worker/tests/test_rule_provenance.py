"""Real native YARA controls and truthful provenance for bundled/custom rules."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yara
from malscan_worker.rule_provenance import RuleBundleError, load_rule_bundle
from malscan_worker.runtime.engine_controls import EICAR
from malscan_worker.stages import yara_scan
from malscan_worker.stages.base import StageContext

BUNDLED_RULES = Path(__file__).parents[1] / "rules"


@pytest.fixture
def rules_copy(tmp_path):
    directory = tmp_path / "rules"
    shutil.copytree(BUNDLED_RULES, directory)
    return directory


@pytest.fixture
def stage(monkeypatch):
    """Reset the startup cache so every test uses its own real native compiler."""
    for name, value in (
        ("_rules_loaded", False),
        ("_compiled_rules", None),
        ("_rules_load_error", None),
        ("_rules_version", None),
        ("_rule_bundle", None),
    ):
        monkeypatch.setattr(yara_scan, name, value)

    def create(directory):
        monkeypatch.setattr(yara_scan.settings, "yara_rules_path", str(directory))
        return yara_scan.YaraStage()

    return create


def context(path):
    return StageContext(
        job_id="rule-quality",
        file_id="rule-quality",
        storage_key="local",
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        original_filename=path.name,
        file_path=path,
    )


def test_bundled_manifest_native_rule_inventory_and_legacy_digest():
    bundle = load_rule_bundle(BUNDLED_RULES)
    assert bundle.provenance["status"] == "verified"
    assert bundle.provenance["file_count"] == 5
    assert bundle.provenance["rule_count"] == 15
    assert len(bundle.rule_metadata) == 15
    assert bundle.rules_sha256 == (
        "52cc7df2f9732941bce0f079bb70b36f01f04008b0a458398ef3ee58679a7dcc"
    )
    assert bundle.provenance["license"]["spdx_expression"] == "NOASSERTION"
    assert bundle.provenance["license"]["permission_verified"] is False
    assert bundle.provenance["source"]["authorship_status"] == (
        "self_declared_not_independently_verified"
    )
    assert bundle.rules.match(data=b"A short ordinary sentence without indicators.\n") == []
    hits = bundle.rules.match(data=EICAR)
    assert [(hit.namespace, hit.rule) for hit in hits] == [("eicar", "eicar")]
    assert bundle.match_provenance("eicar", "eicar")["category"] == "test"


def test_network_url_remains_observed_but_is_explicit_context():
    bundle = load_rule_bundle(BUNDLED_RULES)
    matches = bundle.rules.match(data=b'<a href="https://example.org/">Documentation</a>')
    assert [match.rule for match in matches] == ["network_iocs"]
    match = matches[0]
    assert match.meta["classification"] == "informational"
    assert match.meta["severity"] == "info"
    provenance = bundle.match_provenance(match.namespace, match.rule)
    assert provenance["status"] == "verified"
    assert provenance["category"] == "context"
    assert provenance["limitations"]
    assert bundle.provenance["ruleset_version"] == "1.1.0"
    assert bundle.provenance["source"]["introduced_commit"] == (
        "874bd482afe1cc779afe63f00a1005e6eb19ac23"
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"// Java documentation: getInputStream()",
        b'new ProcessBuilder("echo", "hello").start();',
        b'Runtime.getRuntime().exec("echo hello");',
        b'String value = request.getParameter("cmd");',
        b'new ProcessBuilder(request.getParameter("cmd")); // never started',
        # A request reference in another large region is not nearby process context.
        b'request.getParameter("cmd")' + b" " * 4097 + b"getRuntime().exec(value)",
        b"getRuntime().exec(value)" + b" " * 4097 + b'request.getParameter("cmd")',
    ],
)
def test_benign_java_api_or_unrelated_strings_do_not_match_jsp(payload):
    bundle = load_rule_bundle(BUNDLED_RULES)
    assert "jsp_webshell" not in [match.rule for match in bundle.rules.match(data=payload)]


@pytest.mark.parametrize(
    "payload",
    [
        b'Runtime.getRuntime().exec(request.getParameter("cmd"));',
        b'String cmd = request.getParameter("command"); Runtime.getRuntime().exec(cmd);',
        b'new ProcessBuilder(request.getParameter("cmd")).start();',
        b"ProcessBuilder pb = new ProcessBuilder(command); pb.start();"
        b' String command = request.getParameter("cmd");',
    ],
)
def test_jsp_request_and_process_context_controls_still_match(payload):
    bundle = load_rule_bundle(BUNDLED_RULES)
    assert [match.rule for match in bundle.rules.match(data=payload)] == ["jsp_webshell"]
    provenance = bundle.match_provenance("webshells", "jsp_webshell")
    assert provenance["category"] == "heuristic"
    assert "taint flow" in provenance["limitations"]


def test_php_and_eicar_native_controls_unchanged():
    bundle = load_rule_bundle(BUNDLED_RULES)
    assert [match.rule for match in bundle.rules.match(data=b"// PHP passthru() reference")] == [
        "php_webshell"
    ]
    assert [match.rule for match in bundle.rules.match(data=EICAR)] == ["eicar"]


def test_custom_unmanifested_rules_scan_without_claiming_provenance(tmp_path):
    (tmp_path / "custom.yara").write_text(
        'rule custom_indicator { strings: $a = "custom-fixture" condition: $a }'
    )
    bundle = load_rule_bundle(tmp_path)
    assert [match.rule for match in bundle.rules.match(data=b"custom-fixture")] == [
        "custom_indicator"
    ]
    assert bundle.provenance == {"status": "unverified", "reason": "manifest_missing"}
    assert bundle.match_provenance("custom", "custom_indicator")["status"] == "unverified"


@pytest.mark.parametrize("mutation", ["file_hash", "rule_name", "namespace", "extra_file"])
def test_manifest_mismatches_leave_scan_usable_but_unverified(rules_copy, mutation):
    manifest_path = rules_copy / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    first = manifest["files"][0]
    if mutation == "file_hash":
        (rules_copy / first["path"]).write_text(
            (rules_copy / first["path"]).read_text() + "\n// changed after manifest\n"
        )
    elif mutation == "rule_name":
        first["rules"][0]["name"] = "invented_rule_in_metadata"
    elif mutation == "namespace":
        first["namespace"] = "other_namespace"
    else:
        (rules_copy / "extra.yar").write_text("rule extra { condition: false }")
    manifest_path.write_text(json.dumps(manifest))
    bundle = load_rule_bundle(rules_copy)
    assert bundle.provenance["status"] == "unverified"
    assert bundle.rule_metadata == {}
    assert bundle.match_provenance("eicar", "eicar")["status"] == "unverified"
    assert "source" not in bundle.match_provenance("eicar", "eicar")
    assert [match.rule for match in bundle.rules.match(data=EICAR)] == ["eicar"]


@pytest.mark.parametrize("mutation", ["json", "duplicate_file", "duplicate_rule", "path"])
def test_invalid_manifest_never_silently_verifies(rules_copy, mutation):
    manifest_path = rules_copy / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "duplicate_file":
        manifest["files"].append(manifest["files"][0])
    elif mutation == "duplicate_rule":
        manifest["files"][0]["rules"].append(manifest["files"][0]["rules"][0])
    elif mutation == "path":
        manifest["files"][0]["path"] = "../outside.yar"
    manifest_path.write_text("not JSON" if mutation == "json" else json.dumps(manifest))
    bundle = load_rule_bundle(rules_copy)
    assert bundle.provenance == {"status": "unverified", "reason": "manifest_invalid"}
    assert [match.rule for match in bundle.rules.match(data=EICAR)] == ["eicar"]


def test_namespace_collision_fails_instead_of_dropping_a_rule(tmp_path):
    (tmp_path / "same.yar").write_text("rule first { condition: true }")
    (tmp_path / "same.yara").write_text("rule second { condition: true }")
    with pytest.raises(RuleBundleError, match="namespace collision"):
        load_rule_bundle(tmp_path)


def test_invalid_native_rule_fails_entire_bundle(tmp_path):
    (tmp_path / "valid.yar").write_text("rule valid { condition: true }")
    (tmp_path / "invalid.yar").write_text("this is not YARA syntax")
    with pytest.raises(yara.SyntaxError):
        load_rule_bundle(tmp_path)


@pytest.mark.parametrize("directory_exists", [False, True])
def test_missing_or_empty_rules_report_unavailable_not_clean(tmp_path, directory_exists):
    directory = tmp_path if directory_exists else tmp_path / "absent"
    bundle = load_rule_bundle(directory)
    assert bundle.rules is None
    assert bundle.rules_sha256 is None
    assert bundle.provenance["status"] == "unverified"


@pytest.mark.asyncio
async def test_stage_has_provenance_for_clean_scan_and_eicar_hit(tmp_path, stage):
    scanner = stage(BUNDLED_RULES)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"Ordinary sentence without indicators.")
    clean = await scanner.execute(context(sample))
    assert clean.status == "ok"
    assert clean.findings["matches"] == []
    assert clean.findings["rule_provenance"]["status"] == "verified"
    sample.write_bytes(EICAR)
    hit = await scanner.execute(context(sample))
    assert hit.status == "ok"
    assert hit.findings["matches"][0]["provenance"]["category"] == "test"
    assert hit.rules_version == clean.rules_version
    assert hit.tool_version == yara.__version__


@pytest.mark.asyncio
async def test_stage_compile_error_is_failed_not_skipped_or_clean(tmp_path, stage):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "invalid.yar").write_text("invalid syntax")
    sample = tmp_path / "sample"
    sample.write_bytes(b"benign")
    result = await stage(rules).execute(context(sample))
    assert result.status == "failed"
    assert result.error == "YARA rule compilation failed"
    assert result.findings["matches"] == []
    assert result.findings["rule_provenance"]["status"] == "unverified"


@pytest.mark.asyncio
async def test_stage_missing_rules_is_explicit_skip_not_clean(tmp_path, stage):
    sample = tmp_path / "sample"
    sample.write_bytes(b"benign")
    result = await stage(tmp_path / "absent").execute(context(sample))
    assert result.status == "skipped"
    assert result.findings["reason"] == "No YARA rules configured"
    assert result.findings["rule_provenance"]["reason"] == "rules_directory_missing"


def test_unhashed_include_dependency_cannot_gain_verified_provenance(tmp_path):
    included = tmp_path / "helper.inc"
    included.write_text('rule dependency { strings: $a = "included-fixture" condition: $a }')
    source = tmp_path / "custom.yar"
    source.write_text('include "helper.inc"\n')
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "ruleset_id": "custom",
                "ruleset_version": "1",
                "source": {"type": "operator-declared"},
                "license": {"spdx_expression": "NOASSERTION"},
                "files": [
                    {
                        "path": source.name,
                        "namespace": source.stem,
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "rules": [
                            {
                                "name": "dependency",
                                "category": "heuristic",
                                "limitations": "Synthetic test indicator only.",
                            }
                        ],
                    }
                ],
            }
        )
    )
    bundle = load_rule_bundle(tmp_path)
    # Preserve native custom include behavior, but never verify a dependency
    # whose bytes are absent from the manifest's top-level rule inventory.
    assert [match.rule for match in bundle.rules.match(data=b"included-fixture")] == ["dependency"]
    assert bundle.provenance == {"status": "unverified", "reason": "manifest_invalid"}


@pytest.mark.asyncio
async def test_stage_namespace_collision_is_failed(tmp_path, stage):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "same.yar").write_text("rule first { condition: true }")
    (rules / "same.yara").write_text("rule second { condition: true }")
    sample = tmp_path / "sample"
    sample.write_bytes(b"benign")
    result = await stage(rules).execute(context(sample))
    assert result.status == "failed"
    assert result.error == "YARA rule compilation failed"


@pytest.mark.parametrize("source", ["// no detector rules configured\n", 'import "pe"\n'])
def test_comment_or_import_only_native_sources_are_unavailable(tmp_path, source):
    (tmp_path / "empty.yar").write_text(source)
    bundle = load_rule_bundle(tmp_path)
    assert bundle.rules is None
    assert bundle.rules_sha256 is None
    assert bundle.provenance == {"status": "unverified", "reason": "rules_missing"}


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["// no detector rules configured\n", 'import "pe"\n'])
async def test_stage_without_actual_native_rules_has_partial_coverage(tmp_path, stage, source):
    from malscan.analysis_contract import build_analysis

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "empty.yar").write_text(source)
    sample = tmp_path / "sample"
    sample.write_bytes(b"benign")
    result = await stage(rules).execute(context(sample))
    assert result.status == "skipped"
    assert result.findings["reason"] == "No YARA rules configured"
    assert result.findings["rule_provenance"]["reason"] == "rules_missing"
    coverage = build_analysis(
        stages=[
            {
                "stage": result.stage_name,
                "status": result.status,
                "reason": result.findings["reason"],
            }
        ],
        job_status="done",
    )
    assert coverage["static"]["status"] == "partial"


@pytest.mark.asyncio
async def test_real_url_match_stage_and_scoring_are_context_only(tmp_path, stage):
    from malscan.scoring.adapters import build_direct_evidence
    from malscan.scoring.engine import score_direct_evidence

    sample = tmp_path / "documentation.html"
    sample.write_bytes(b'<a href="https://example.org/">Documentation</a>')
    result = await stage(BUNDLED_RULES).execute(context(sample))
    assert result.status == "ok"
    assert [match["rule"] for match in result.findings["matches"]] == ["network_iocs"]
    match = result.findings["matches"][0]
    assert match["classification"] == "informational"
    assert match["severity"] == "info"
    assert match["provenance"]["category"] == "context"
    evidence = build_direct_evidence(artifact_id="root", stage_findings={"yara": result.findings})
    decision = score_direct_evidence(direct_evidence=evidence)
    assert len(decision.evidence) == 1
    assert decision.evidence[0].kind == "yara_context_observation"
    assert decision.risk_score == 0
    assert decision.breakdown.independent_source_count == 0


@pytest.mark.parametrize("category", ["confirmed", "malicious_family", "invented_category"])
def test_manifest_category_cannot_claim_detection_strength(rules_copy, category):
    manifest_path = rules_copy / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][0]["rules"][0]["category"] = category
    manifest_path.write_text(json.dumps(manifest))
    bundle = load_rule_bundle(rules_copy)
    assert bundle.provenance == {"status": "unverified", "reason": "manifest_invalid"}
    assert [match.rule for match in bundle.rules.match(data=EICAR)] == ["eicar"]


@pytest.mark.parametrize("distance, expected", [(4096, True), (4097, False)])
@pytest.mark.parametrize("request_first", [False, True])
def test_jsp_context_window_boundary_is_measured_from_string_offsets(
    distance, expected, request_first
):
    request = b'request.getParameter("cmd")'
    process = b"getRuntime().exec(command)"
    first, last = (request, process) if request_first else (process, request)
    payload = first + b" " * (distance - len(first)) + last
    bundle = load_rule_bundle(BUNDLED_RULES)
    matches = [match.rule for match in bundle.rules.match(data=payload)]
    assert ("jsp_webshell" in matches) is expected
