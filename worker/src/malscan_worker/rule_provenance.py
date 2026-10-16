"""Load native YARA rules and check a local manifest without asserting authorship.

``verified`` means the local file hashes and native rule inventory agree with the
manifest. It does not authenticate an author, grant a license or measure accuracy.
Custom rule directories remain usable without a manifest and are marked unverified.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

MANIFEST_NAME = "manifest.json"
VERIFICATION_SCOPE = "local_file_hashes_and_native_rule_inventory"


class RuleBundleError(ValueError):
    """A bundle cannot be loaded without dropping or ambiguously naming rules."""


@dataclass(frozen=True)
class RuleBundle:
    """Native compiled rules, compatible content digest and checked metadata."""

    rules: Any
    rules_sha256: str | None
    provenance: dict[str, Any]
    rule_metadata: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def match_provenance(self, namespace: str, rule: str) -> dict[str, Any]:
        """Return only checked rule metadata, or an explicit unverified marker."""
        metadata = self.rule_metadata.get((namespace, rule))
        if self.provenance["status"] != "verified" or metadata is None:
            return {
                "status": "unverified",
                "reason": self.provenance.get("reason", "rule_not_in_verified_inventory"),
                "ruleset_sha256": self.rules_sha256,
            }
        return {
            "status": "verified",
            "verification_scope": VERIFICATION_SCOPE,
            "ruleset_id": self.provenance["ruleset_id"],
            "ruleset_version": self.provenance["ruleset_version"],
            "ruleset_sha256": self.rules_sha256,
            "manifest_sha256": self.provenance["manifest_sha256"],
            "source": self.provenance["source"],
            "license": self.provenance["license"],
            **metadata,
        }


def _unverified(reason: str, **details: Any) -> dict[str, Any]:
    return {"status": "unverified", "reason": reason, **details}


def _verify_manifest(
    directory: Path, files: list[Path], contents: dict[str, bytes]
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    """Verify metadata against the same file inventory used for compilation."""
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.exists():
        return _unverified("manifest_missing"), {}
    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise ValueError("manifest schema")
        for key in ("ruleset_id", "ruleset_version"):
            if not isinstance(manifest.get(key), str) or not manifest[key]:
                raise ValueError("manifest identity")
        for key in ("source", "license"):
            if not isinstance(manifest.get(key), dict) or not manifest[key]:
                raise ValueError("manifest attribution")
        records = manifest.get("files")
        if not isinstance(records, list) or not records:
            raise ValueError("manifest inventory")
        indexed: dict[str, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("manifest file")
            name = record.get("path")
            if not isinstance(name, str) or Path(name).name != name or name in indexed:
                raise ValueError("manifest path")
            indexed[name] = record
        if set(indexed) != set(contents):
            return _unverified("file_inventory_mismatch"), {}
        metadata: dict[tuple[str, str], dict[str, Any]] = {}
        for rule_file in files:
            record = indexed[rule_file.name]
            actual_hash = hashlib.sha256(contents[rule_file.name]).hexdigest()
            if record.get("sha256") != actual_hash:
                return _unverified("file_hash_mismatch"), {}
            if record.get("namespace") != rule_file.stem:
                return _unverified("namespace_mismatch"), {}
            rule_records = record.get("rules")
            if not isinstance(rule_records, list) or not rule_records:
                raise ValueError("manifest rules")
            names: set[str] = set()
            for entry in rule_records:
                if not isinstance(entry, dict):
                    raise ValueError("manifest rule")
                name = entry.get("name")
                if not isinstance(name, str) or not name or name in names:
                    raise ValueError("manifest rule name")
                if entry.get("category") not in {"test", "heuristic"}:
                    raise ValueError("manifest rule category")
                limitations = entry.get("limitations")
                if not isinstance(limitations, str) or not limitations:
                    raise ValueError("manifest rule limitations")
                names.add(name)
                metadata[(rule_file.stem, name)] = {
                    "file": rule_file.name,
                    "file_sha256": actual_hash,
                    "category": entry["category"],
                    "limitations": limitations,
                }
            # Use the native parser rather than extracting rule names with a regex
            # that could mistake a comment/string for a rule declaration.
            parsed = yara.compile(filepaths={rule_file.stem: str(rule_file)}, includes=False)
            if {rule.identifier for rule in parsed} != names:
                return _unverified("rule_inventory_mismatch"), {}
        return (
            {
                "status": "verified",
                "verification_scope": VERIFICATION_SCOPE,
                "ruleset_id": manifest["ruleset_id"],
                "ruleset_version": manifest["ruleset_version"],
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "source": manifest["source"],
                "license": manifest["license"],
                "file_count": len(files),
                "rule_count": len(metadata),
            },
            metadata,
        )
    except (OSError, ValueError, TypeError, yara.Error):
        # Broken attribution must never prevent custom native rules from scanning
        # or silently turn into a verified attribution claim.
        return _unverified("manifest_invalid"), {}


def load_rule_bundle(directory: Path) -> RuleBundle:
    """Compile every top-level .yar/.yara file and expose checked local provenance.

    Missing/empty directories or zero native rules return ``rules=None``. Syntax errors and
    namespace collisions raise; callers must report these as failed analysis.
    The rules digest deliberately preserves the existing filename/NUL/bytes format.
    No network, subprocess, configuration singleton or global cache is used.
    """
    if not directory.is_dir():
        return RuleBundle(None, None, _unverified("rules_directory_missing"))
    files = sorted([*directory.glob("*.yar"), *directory.glob("*.yara")])
    if not files:
        return RuleBundle(None, None, _unverified("rules_missing"))
    namespaces = [rule_file.stem for rule_file in files]
    if len(namespaces) != len(set(namespaces)):
        raise RuleBundleError("YARA rule namespace collision between .yar/.yara files")
    contents = {rule_file.name: rule_file.read_bytes() for rule_file in files}
    digest = hashlib.sha256()
    for rule_file in files:
        digest.update(rule_file.name.encode())
        digest.update(b"\0")
        digest.update(contents[rule_file.name])
    rules = yara.compile(filepaths={rule_file.stem: str(rule_file) for rule_file in files})
    # Native YARA accepts comment-only and import-only sources. Successful
    # compilation without an actual rule is unavailable coverage, not a clean scan.
    if not list(rules):
        return RuleBundle(None, None, _unverified("rules_missing"))
    provenance, metadata = _verify_manifest(directory, files, contents)
    # Files are normally immutable image/configuration input. If an operator
    # changes them during loading, fail rather than attaching a stale digest.
    if any(rule_file.read_bytes() != contents[rule_file.name] for rule_file in files):
        raise RuleBundleError("YARA rule files changed during loading")
    return RuleBundle(rules, digest.hexdigest(), provenance, metadata)
