"""Local tests for preserving downloaded production settings without credentials."""

import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("prepare-feedback-config.py")
SPEC = importlib.util.spec_from_file_location("prepare_feedback_config", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PrepareFeedbackConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir(mode=0o700)
        (self.checkout / ".git").mkdir()
        self.source = self.checkout / "reviewed-worker.mjs"
        self.source.write_text("export class DemoControl {}\nexport default {};\n")
        self.original = self.root / "downloaded.json"
        self.output = self.root / "feedback.json"
        self.config = {
            "name": "test-control",
            "main": "src/old.mjs",
            "workers_dev": True,
            "compatibility_date": "2026-07-30",
            "compatibility_flags": ["nodejs_compat"],
            "preview_urls": False,
            "observability": {"enabled": True, "head_sampling_rate": 0.1},
            "routes": [{"pattern": "api.test.invalid/*", "zone_name": "test.invalid"}],
            "durable_objects": {"bindings": [{"name": "CONTROL", "class_name": "DemoControl"}]},
            "r2_buckets": [
                {"binding": "UPLOADS", "bucket_name": "test-uploads"},
                {"binding": "RESULTS", "bucket_name": "test-results", "jurisdiction": "eu"},
            ],
            "vars": {
                "ALLOWED_ORIGIN": "https://test-ui.pages.dev",
                "PUBLIC_UPLOADS": "true",
                "DAILY_JOB_LIMIT": "10",
                "DAILY_EXECUTION_LIMIT": "20",
                "MONTHLY_EXECUTION_LIMIT": "40",
                "RETENTION_SECONDS": "86400",
                "GCP_PROJECT": "test-cloud-123",
                "GCP_REGION": "us-central1",
                "GCP_JOB": "test-scan",
                "GCP_DISPATCH_URL": "https://test-dispatcher-xyz.a.run.app",
            },
        }

    def run_prepare(self, config=None, output=None):
        self.original.write_text(json.dumps(self.config if config is None else config))
        return MODULE.prepare(self.source, self.original, output or self.output, "test-control")

    def test_preserves_every_setting_except_main_and_is_private(self):
        before = copy.deepcopy(self.config)
        result = self.run_prepare()
        expected = copy.deepcopy(before)
        expected["main"] = str(self.source.resolve())
        self.assertEqual(json.loads(self.output.read_text()), expected)
        self.assertEqual(json.loads(self.original.read_text()), before)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(result["changed_fields"], ["main"])
        self.assertNotIn("test-cloud", json.dumps(result))
        self.assertNotIn("test-uploads", json.dumps(result))

    def test_preserves_absent_empty_and_reconstructed_lifecycle_exactly(self):
        for index, lifecycle in enumerate((
            {},
            {"migrations": []},
            {"exports": {}},
            {"migrations": [], "exports": {}},
            {"migrations": [{"tag": "v1", "new_classes": ["DemoControl"]}]},
            {"migrations": [{"tag": "v1", "new_sqlite_classes": ["DemoControl"]}]},
            {"exports": {"DemoControl": {"type": "durable-object", "storage": "sqlite"}}},
        )):
            with self.subTest(lifecycle=lifecycle):
                current = copy.deepcopy(self.config)
                current.update(lifecycle)
                output = self.root / f"feedback-{index}.json"
                self.run_prepare(current, output)
                actual = json.loads(output.read_text())
                for key in ("migrations", "exports"):
                    self.assertEqual(key in actual, key in current)
                    self.assertEqual(actual.get(key), current.get(key))

    def test_identical_resume_is_idempotent_and_restricts_file_mode(self):
        self.run_prepare()
        self.output.chmod(0o644)
        second = self.run_prepare()
        self.assertFalse(second["output_created"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_reported_download_shape_preserves_omitted_local_script(self):
        self.config["migrations"] = []
        self.config["exports"] = {}
        # The user's diagnostic used binding.get(), displaying null for this omission.
        self.assertIsNone(self.config["durable_objects"]["bindings"][0].get("script_name"))
        self.run_prepare()
        updated = json.loads(self.output.read_text())
        self.assertEqual(updated["migrations"], [])
        self.assertEqual(updated["exports"], {})
        self.assertNotIn("script_name", updated["durable_objects"]["bindings"][0])

    def test_explicit_same_worker_script_name_is_preserved(self):
        self.config["durable_objects"]["bindings"][0]["script_name"] = "test-control"
        self.run_prepare()
        updated = json.loads(self.output.read_text())
        self.assertEqual(updated["durable_objects"]["bindings"][0]["script_name"], "test-control")

    def test_explicit_null_and_nonstring_optional_binding_fields_are_rejected(self):
        for key in ("script_name", "environment"):
            for value in (None, 12, {}, []):
                with self.subTest(key=key, value=value):
                    current = copy.deepcopy(self.config)
                    current["durable_objects"]["bindings"][0][key] = value
                    with self.assertRaisesRegex(MODULE.ConfigurationError, "must be a string"):
                        self.run_prepare(current)
                    self.assertFalse(self.output.exists())

    def test_cli_success_outputs_only_checks_and_delta(self):
        self.original.write_text(json.dumps(self.config))
        result = subprocess.run([
            sys.executable, str(SCRIPT), "--worker-name", "test-control",
            "--source", str(self.source), "--downloaded-config", str(self.original),
            "--output", str(self.output),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["changed_fields"], ["main"])
        for private_detail in ("test-control", "test-cloud-123", "test-uploads", str(self.root)):
            self.assertNotIn(private_detail, result.stdout + result.stderr)

    def test_different_existing_output_is_not_overwritten(self):
        self.output.write_text("keep previous attempt")
        with self.assertRaisesRegex(MODULE.ConfigurationError, "Existing output differs"):
            self.run_prepare()
        self.assertEqual(self.output.read_text(), "keep previous attempt")

    def test_quota_or_retention_drift_stops_without_output(self):
        for name in ("DAILY_JOB_LIMIT", "DAILY_EXECUTION_LIMIT", "MONTHLY_EXECUTION_LIMIT", "RETENTION_SECONDS"):
            with self.subTest(name=name):
                current = copy.deepcopy(self.config)
                current["vars"][name] = "9999"
                with self.assertRaisesRegex(MODULE.ConfigurationError, "quotas or retention"):
                    self.run_prepare(current)
                self.assertFalse(self.output.exists())

    def test_foreign_or_changed_durable_object_is_rejected(self):
        for change in ({"script_name": "other-worker"}, {"class_name": "OtherControl"}, {"name": "OTHER"}, {"environment": "staging"}):
            with self.subTest(change=change):
                current = copy.deepcopy(self.config)
                current["durable_objects"]["bindings"][0].update(change)
                with self.assertRaises(MODULE.ConfigurationError):
                    self.run_prepare(current)
                self.assertFalse(self.output.exists())

    def test_plaintext_credentials_are_rejected_without_value_in_errors(self):
        for key in ("CONTROL_HMAC_KEY", "POC_ADMIN_TOKEN", "R2_SECRET_ACCESS_KEY", "API_KEY", "PRIVATE_KEY", "PASSWORD"):
            with self.subTest(key=key):
                current = copy.deepcopy(self.config)
                current["vars"][key] = "sentinel-do-not-print"
                with self.assertRaises(MODULE.ConfigurationError) as caught:
                    self.run_prepare(current)
                self.assertNotIn("sentinel", str(caught.exception))
                self.assertFalse(self.output.exists())

    def test_url_placeholders_credentials_and_nonorigins_are_rejected(self):
        for value in ("https://REPLACE-ui.example", "http://test-ui.pages.dev", "https://user:pass@test-ui.pages.dev", "https://test-ui.pages.dev/path", "https://test-ui.pages.dev?token=sentinel"):
            with self.subTest(value=value):
                current = copy.deepcopy(self.config)
                current["vars"]["ALLOWED_ORIGIN"] = value
                with self.assertRaises(MODULE.ConfigurationError):
                    self.run_prepare(current)
                self.assertFalse(self.output.exists())

    def test_dispatcher_target_and_public_uploads_require_review(self):
        for key, value in (("GCP_DISPATCH_URL", "https://dispatcher.test.invalid"), ("GCP_PROJECT", "REPLACE-project"), ("PUBLIC_UPLOADS", "false")):
            with self.subTest(key=key):
                current = copy.deepcopy(self.config)
                current["vars"][key] = value
                with self.assertRaises(MODULE.ConfigurationError):
                    self.run_prepare(current)

    def test_wrong_identity_or_buckets_stop(self):
        for change in ("worker", "bucket_binding", "same_bucket"):
            with self.subTest(change=change):
                current = copy.deepcopy(self.config)
                if change == "worker":
                    current["name"] = "foreign-worker"
                elif change == "bucket_binding":
                    current["r2_buckets"][0]["binding"] = "OTHER"
                else:
                    current["r2_buckets"][1]["bucket_name"] = "test-uploads"
                with self.assertRaises(MODULE.ConfigurationError):
                    self.run_prepare(current)

    def test_missing_source_or_directory_is_rejected(self):
        self.original.write_text(json.dumps(self.config))
        with self.assertRaises(OSError):
            MODULE.prepare(self.root / "missing.mjs", self.original, self.output, "test-control")
        with self.assertRaises(MODULE.ConfigurationError):
            MODULE.prepare(self.root, self.original, self.output, "test-control")

    def test_symlink_sources_and_outputs_or_input_overwrite_are_rejected(self):
        self.run_prepare()
        for target in (self.original, self.source):
            with self.subTest(target=target.name):
                with self.assertRaises(MODULE.ConfigurationError):
                    self.run_prepare(output=target)
        linked = self.root / "linked.json"
        linked.symlink_to(self.output)
        with self.assertRaises(MODULE.ConfigurationError):
            self.run_prepare(output=linked)
        source_link = self.root / "linked.mjs"
        source_link.symlink_to(self.source)
        with self.assertRaises(MODULE.ConfigurationError):
            MODULE.prepare(source_link, self.original, self.root / "unused.json", "test-control")

    def test_hardlinked_output_and_public_directory_are_rejected(self):
        self.run_prepare()
        linked = self.root / "hardlinked.json"
        os.link(self.output, linked)
        with self.assertRaises(MODULE.ConfigurationError):
            self.run_prepare(output=linked)
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        with self.assertRaisesRegex(MODULE.ConfigurationError, "directory must be private"):
            self.run_prepare(output=public / "feedback.json")

    def test_generated_production_config_stays_outside_source_git_checkout(self):
        checkout = self.root / "source-checkout"
        checkout.mkdir(mode=0o700)
        (checkout / ".git").mkdir()
        source = checkout / "worker.mjs"
        source.write_text(self.source.read_text())
        self.original.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(MODULE.ConfigurationError, "outside the source Git checkout"):
            MODULE.prepare(source, self.original, checkout / "feedback.json", "test-control")
        result = MODULE.prepare(source, self.original, self.output, "test-control")
        self.assertTrue(result["success"])

    def test_malformed_json_does_not_print_content_or_create_output(self):
        self.original.write_text('{"name":"sentinel-private",broken}')
        result = subprocess.run([
            sys.executable, str(SCRIPT), "--worker-name", "test-control",
            "--source", str(self.source), "--downloaded-config", str(self.original),
            "--output", str(self.output),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("sentinel", result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_duplicate_json_keys_are_rejected(self):
        self.original.write_text('{"name":"test-control","name":"other"}')
        with self.assertRaisesRegex(MODULE.ConfigurationError, "duplicate keys"):
            MODULE.prepare(self.source, self.original, self.output, "test-control")


if __name__ == "__main__":
    unittest.main()
