"""Real-index tests for accidental publication guards; no network or credentials."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check_publication.py").resolve()
PRIVATE = "PRIVATE_FILENAME_OR_VALUE_DO_NOT_EMIT"
SPEC = importlib.util.spec_from_file_location("publication_guard", SCRIPT)
guard_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard_module)


class PublicationGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="publication-guard-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Guard fixture")
        self.git("config", "user.email", "guard@example.invalid")
        self.git("config", "core.autocrlf", "false")

    def git(self, *arguments, input=None):
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            input=input,
            capture_output=True,
            check=True,
        ).stdout

    def write(self, name, value="public fixture\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def stage(self, name, value="public fixture\n"):
        path = self.write(name, value)
        self.git("add", "--force", "--", name)
        return path

    def commit(self):
        self.git("commit", "--quiet", "-m", "public fixture")

    def guard(self, mode="--staged", *, cwd=None, env=None, expect=0):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), mode],
            cwd=cwd or self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, expect, result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertNotIn(PRIVATE, result.stdout)
        self.assertNotIn(str(self.root), result.stdout)
        return json.loads(result.stdout)

    def test_unborn_repository_accepts_public_examples_and_milestones(self):
        names = [
            ".env.example",
            ".env.production.example",
            "deployment/.dev.vars.example",
            "k8s/secrets.yaml.example",
            "docs/milestones/2026-11-12-build-source-retention-baseline.json",
            "docs/milestones/2026-11-12-automatic-image-cleanup-acceptance.json",
            "docs/superpowers/plans/proposed-design.md",
            "deployment/cloudflare/wrangler.jsonc",
            "public/certificate.crt",
            "public/id_ed25519.pub",
            "fixtures/benign.csv",
            "fixtures/response.expected.json",
        ]
        for name in names:
            self.stage(name)
        report = self.guard()
        self.assertEqual(report["checked_files"], len(names))
        self.assertTrue(report["success"])

    def test_forced_ignored_private_sidecar_is_blocked(self):
        self.stage(".gitignore", "build-source-retention-baseline.json\n")
        self.stage("private/build-source-retention-baseline.json", PRIVATE)
        report = self.guard(expect=1)
        self.assertEqual(report["blocked_files"], 1)
        self.assertEqual(report["rules"], [{"rule": "private_operator_state", "count": 1}])

    def test_private_rules_cover_operator_environment_and_credentials(self):
        names = [
            "backup/.malscan-v2-operations/state.json",
            "backup/malscan-v2-auto-plan.private/plan.json",
            "backup/billing-exports/month.csv",
            "backup/.wrangler/config.json",
            ".env.production",
            "worker/.dev.vars.private",
            "recovery-rehearsal.json",
            "notification-test.json",
            "apply-state.json",
            "malscan-v2-auto-update-plan-path.txt",
            "root/credentials.json",
            "root/id_ed25519",
            "root/key.pem",
            "root/credential.p12",
            "cloud-static-job-current.flags.json",
            "keyless-dispatcher-service.flags.json",
            "wrangler-feedback.json",
            "wrangler.downloaded.jsonc",
            "wrangler-backup.json",
            "copied/malscan-v2-demo-control/wrangler.jsonc",
            "demo-cloud-evidence-private.json",
            "registry-inventory-private.json",
            "registry-prune-result.json",
            "malscan-report-private.json",
            "retention-smoke-private.json",
            "k8s/secrets.yaml",
        ]
        for name in names:
            self.stage(name, PRIVATE)
        report = self.guard(expect=1)
        self.assertEqual(report["blocked_files"], len(names))

    def test_private_directory_is_not_bypassed_by_example_suffix(self):
        self.stage(".malscan-v2-operations/secret.example", PRIVATE)
        self.assertEqual(self.guard(expect=1)["blocked_files"], 1)

    def test_unicode_newline_and_tab_paths_never_reach_output(self):
        self.stage("中文\n目錄\t/malscan-report-" + PRIVATE + ".json", PRIVATE)
        report = self.guard(expect=1)
        self.assertEqual(report["checked_files"], 1)
        self.assertNotIn("中文", json.dumps(report, ensure_ascii=False))

    def test_staged_file_is_checked_after_worktree_file_is_removed(self):
        path = self.stage(".env", PRIVATE)
        path.unlink()
        self.assertEqual(self.guard(expect=1)["blocked_files"], 1)

    def test_untracked_private_file_is_not_read_or_reported(self):
        self.stage("README.md")
        self.write(".env", PRIVATE)
        report = self.guard()
        self.assertEqual(report["checked_files"], 1)
        self.assertTrue(report["success"])

    def test_tracked_mode_catches_private_file_without_staged_changes(self):
        self.stage("plan.json", PRIVATE)
        self.commit()
        self.assertEqual(self.guard()["checked_files"], 0)
        self.assertEqual(self.guard("--tracked", expect=1)["blocked_files"], 1)

    def test_staged_deletion_of_private_file_is_allowed(self):
        self.stage(".env", PRIVATE)
        self.commit()
        self.git("rm", "--quiet", "--", ".env")
        self.assertEqual(self.guard()["checked_files"], 0)
        self.assertEqual(self.guard("--tracked")["checked_files"], 0)

    def test_rename_to_private_name_is_blocked(self):
        self.stage("safe.txt")
        self.commit()
        self.git("mv", "safe.txt", ".env.staging")
        self.assertEqual(self.guard(expect=1)["blocked_files"], 1)

    def test_symlink_is_blocked_without_following_its_nonexistent_target(self):
        path = self.root / "visible.txt"
        path.symlink_to(self.root / PRIVATE)
        self.git("add", "--", path.name)
        report = self.guard(expect=1)
        self.assertEqual(report["rules"], [{"rule": "indirect_index_entry", "count": 1}])
        self.assertFalse((self.root / PRIVATE).exists())

    def test_submodule_index_entry_is_blocked(self):
        self.stage("README.md")
        self.commit()
        oid = self.git("rev-parse", "HEAD").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "160000," + oid + ",vendor/module")
        report = self.guard(expect=1)
        self.assertEqual(report["rules"], [{"rule": "indirect_index_entry", "count": 1}])

    def test_unmerged_index_fails_without_printing_conflict_path(self):
        self.stage("README.md")
        oid = self.git("hash-object", "README.md").strip()
        entries = b"".join(
            b"100644 " + oid + b" " + str(stage).encode() + b"\t" + PRIVATE.encode() + b"\n"
            for stage in (1, 2)
        )
        self.git("update-index", "--index-info", input=entries)
        self.assertEqual(self.guard(expect=2)["error"], "unmerged_index")

    def test_nested_working_directory_uses_root_relative_index_paths(self):
        self.stage("nested/.env", PRIVATE)
        self.assertEqual(self.guard(cwd=self.root / "nested", expect=1)["blocked_files"], 1)

    def test_missing_git_fails_closed_without_raw_process_error(self):
        env = dict(os.environ, PATH=str(self.root / "missing-command-directory"))
        self.assertEqual(self.guard(env=env, expect=2)["error"], "git_index_read_failed")

    def test_non_repository_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="publication-not-a-repository-") as other:
            report = self.guard(cwd=other, expect=2)
        self.assertEqual(report["error"], "git_index_read_failed")

    def test_invalid_cli_argument_is_not_echoed(self):
        self.assertEqual(self.guard("--" + PRIVATE, expect=2)["error"], "usage_invalid")

    def test_index_changes_during_read_fail_closed_even_for_same_filename(self):
        first = b"100644 " + b"a" * 40 + b" 0\t" + PRIVATE.encode() + b".txt\0"
        later = first.replace(b"a" * 40, b"b" * 40)
        output = io.StringIO()
        with patch.object(
            guard_module, "git_bytes", side_effect=[first, PRIVATE.encode() + b".txt\0", later]
        ):
            with redirect_stdout(output):
                status = guard_module.main(["--staged"])
        self.assertEqual(status, 2)
        self.assertNotIn(PRIVATE, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["error"], "git_index_changed_during_read")


if __name__ == "__main__":
    unittest.main()
