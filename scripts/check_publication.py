#!/usr/bin/env python3
"""Reject private operator artifacts in Git's index without reading their contents.

This is a filename/mode guard, complementary to a secret-content scanner. It
never follows a worktree symlink, prints a filename, or displays Git stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter
from typing import Sequence


class GuardError(RuntimeError):
    """A fixed, non-sensitive failure code."""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GuardError("usage_invalid")


PRIVATE_DIRECTORIES = frozenset(
    {
        ".wrangler",
        ".malscan-maintenance",
        ".malscan-v2-operations",
        ".malscan-v2-acceptance",
        ".malscan-v2-deploy",
        ".cloud-acceptance",
        ".local-cloud-smoke",
        "billing-exports",
    }
)
PRIVATE_FILES = frozenset(
    {
        "plan.json",
        "apply-state.json",
        "build-source-retention-baseline.json",
        "recovery-rehearsal.json",
        "notification-test.json",
        "guarded-registry-operation.json",
        ".checkpoint-auth.key",
        "deployments-before.txt",
        "deployments-after.txt",
    }
)
CREDENTIAL_FILES = frozenset(
    {
        "credentials.json",
        "application_default_credentials.json",
        "service-account.json",
        "service_account.json",
        "service-account-key.json",
        "service_account_key.json",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)


def private_rule(path: str, mode: str) -> str | None:
    """Classify an index entry; paths remain private to this process."""
    if mode not in {"100644", "100755"}:
        return "indirect_index_entry"
    parts = path.casefold().split("/")
    name = parts[-1]
    if any(
        part in PRIVATE_DIRECTORIES
        or part.startswith(("malscan-v2-auto-plan.", "malscan-v2-legacy-cleanup."))
        for part in parts[:-1]
    ):
        return "private_operator_directory"
    # Example files still undergo content scanning; an example inside a private
    # operator directory is not exempt from the directory rule above.
    if name.endswith(".example"):
        return None
    if name == ".env" or name.startswith(".env."):
        return "private_environment_file"
    if name == ".dev.vars" or name.startswith(".dev.vars."):
        return "private_environment_file"
    if name in PRIVATE_FILES or re.fullmatch(r"malscan-v2-.+-path\.txt", name):
        return "private_operator_state"
    if name in CREDENTIAL_FILES or name.endswith((".pem", ".key", ".p12", ".pfx", ".jks")):
        return "credential_file"
    if re.fullmatch(r".*firebase-adminsdk.*\.json", name):
        return "credential_file"
    if (
        re.fullmatch(r"cloud-static-job.*\.flags\.json", name)
        or name == "keyless-dispatcher-service.flags.json"
        or re.fullmatch(r"wrangler-feedback.*\.jsonc?", name)
        or re.fullmatch(r"wrangler[.-](?:downloaded|backup).*\.jsonc?", name)
        or name in {"wrangler.json", "wrangler.jsonc"}
        and "/".join(parts) != "deployment/cloudflare/wrangler.jsonc"
    ):
        return "private_deployment_configuration"
    if re.fullmatch(
        r"(?:demo-cloud-evidence.*|registry-inventory.*|registry-prune.*|"
        r"malscan-report-.+|retention-.+)\.json",
        name,
    ):
        return "private_raw_evidence"
    if parts[-2:] == ["k8s", "secrets.yaml"]:
        return "credential_file"
    return None


def git_bytes(arguments: Sequence[str]) -> bytes:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *arguments],
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GuardError("git_index_read_failed") from None
    if result.returncode or len(result.stdout) > 32 * 1024 * 1024:
        raise GuardError("git_index_read_failed")
    return result.stdout


def index_entries(snapshot: bytes) -> dict[bytes, str]:
    result: dict[bytes, str] = {}
    for record in snapshot.split(b"\0"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, object_id, stage = header.split(b" ")
            if not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
                raise ValueError
            if stage not in {b"0", b"1", b"2", b"3"}:
                raise ValueError
            if stage != b"0":
                raise GuardError("unmerged_index")
            if (
                not path
                or path.startswith(b"/")
                or any(part in {b"", b".", b".."} for part in path.split(b"/"))
                or path in result
                or mode not in {b"100644", b"100755", b"120000", b"160000"}
            ):
                raise ValueError
            result[path] = mode.decode("ascii")
        except (ValueError, UnicodeError):
            raise GuardError("git_index_response_invalid") from None
    return result


def check(mode: str) -> dict:
    query = ["ls-files", "--stage", "--full-name", "-z"]
    snapshot = git_bytes(query)
    entries = index_entries(snapshot)
    if mode == "staged":
        changed = {
            path
            for path in git_bytes(
                [
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-relative",
                    "--no-renames",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--diff-filter=ACMTUXB",
                    "-z",
                ]
            ).split(b"\0")
            if path
        }
        if not changed <= entries.keys():
            raise GuardError("git_index_changed_during_read")
        entries = {path: value for path, value in entries.items() if path in changed}
    rules: Counter[str] = Counter()
    for path, entry_mode in entries.items():
        rule = private_rule(path.decode("utf-8", "surrogateescape"), entry_mode)
        if rule:
            rules[rule] += 1
    if git_bytes(query) != snapshot:
        raise GuardError("git_index_changed_during_read")
    return {
        "scope": "publication_private_artifact_guard",
        "mode": mode,
        "success": not rules,
        "checked_files": len(entries),
        "blocked_files": sum(rules.values()),
        "rules": [{"rule": key, "count": rules[key]} for key in sorted(rules)],
    }


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        parser = Parser(prog="check_publication.py", description=__doc__)
        modes = parser.add_mutually_exclusive_group(required=True)
        modes.add_argument("--staged", action="store_true")
        modes.add_argument("--tracked", action="store_true")
        args = parser.parse_args(arguments)
        report = check("staged" if args.staged else "tracked")
        print(json.dumps(report, sort_keys=True))
        return 0 if report["success"] else 1
    except GuardError as error:
        print(
            json.dumps(
                {
                    "scope": "publication_private_artifact_guard",
                    "success": False,
                    "error": str(error),
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
