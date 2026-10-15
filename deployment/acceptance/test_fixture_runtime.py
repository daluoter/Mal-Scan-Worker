"""Opt-in offline fixtures through the real recursive archive/checkpoint core.

Run with worker/.venv/bin/python -m unittest discover -s deployment/acceptance
-p test_fixture_runtime.py. Native ClamAV/YARA quality is covered elsewhere;
this test substitutes only the expensive AV stage with a counting stage.
"""

import copy
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "cloud_acceptance", Path(__file__).with_name("cloud_acceptance.py")
)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)
AVAILABLE = all(
    importlib.util.find_spec(name) is not None
    for name in ("py7zr", "pyzipper", "malscan_worker")
)


@unittest.skipUnless(
    AVAILABLE, "Use the existing worker virtualenv for real archive fixtures."
)
class RealFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_fixture_counts_hashes_nested_sevenzip_passwords_and_preserved_stages(
        self,
    ):
        from malscan_worker.runtime import (
            AnalysisManifest,
            LocalObjectStore,
            RootBatchRunner,
        )
        from malscan_worker.stages.archive_extract import ArchiveExtractStage
        from malscan_worker.stages.base import StageResult
        from malscan_worker.stages.document_analysis import DocumentAnalysisStage
        from malscan_worker.stages.filetype import FileTypeStage
        from malscan_worker.stages.format_analysis import FormatAnalysisStage

        calls = []

        class CountingAntivirus:
            name = "clamav"

            async def execute(self, context):
                calls.append(context.artifact_id)
                instant = datetime.now(timezone.utc)
                return StageResult(
                    self.name, "ok", instant, instant, 0, {"infected": False}, []
                )

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "campaign"
            with client.Campaign(directory).locked() as campaign:
                campaign.prepare()
                self.assertEqual(
                    campaign.state["cases"]["20mb"]["fixture"]["bytes"], 20_000_000
                )
                for case in ("nested", "passwords"):
                    item, source = campaign.fixture(case)
                    manifest = AnalysisManifest.for_local_file(source)
                    item["ticket"] = {"job_id": manifest.root_job_id}

                    def runner(
                        passwords=None, manifest=manifest, source=source, case=case
                    ):
                        return RootBatchRunner(
                            manifest=manifest,
                            source_store=LocalObjectStore(
                                source.parent, read_only=True
                            ),
                            result_store=LocalObjectStore(directory / case / "results"),
                            state_dir=directory / case / "state",
                            passwords=passwords,
                            parallel_stages=[FileTypeStage(), CountingAntivirus()],
                            format_stage=FormatAnalysisStage(),
                            sequential_stages=[
                                ArchiveExtractStage(),
                                DocumentAnalysisStage(),
                            ],
                        )

                    report = await runner().run()
                    reports = [copy.deepcopy(report)]
                    if case == "passwords":
                        self.assertEqual(report["job_status"], "password_required")
                        self.assertEqual(
                            report["password_required_artifacts"],
                            [manifest.root_job_id],
                        )
                        before_calls = len(calls)
                        report = await runner(
                            {manifest.root_job_id: client.PASSWORDS["wrong"]}
                        ).run(resume=True)
                        self.assertEqual(
                            report["artifacts"][0]["reason"], "wrong_password"
                        )
                        self.assertEqual(len(calls), before_calls)
                        reports.append(copy.deepcopy(report))
                        report = await runner(
                            {manifest.root_job_id: client.PASSWORDS["outer"]}
                        ).run(resume=True)
                        reports.append(copy.deepcopy(report))
                        pending = report["password_required_artifacts"]
                        self.assertEqual(len(pending), 1)
                        self.assertNotEqual(pending[0], manifest.root_job_id)
                        report = await runner(
                            {pending[0]: client.PASSWORDS["inner"]}
                        ).run(resume=True)
                        reports.append(copy.deepcopy(report))
                    self.assertEqual(
                        client.verify_report(report, item, require_full_pipeline=False),
                        [],
                    )
                    if case == "passwords":
                        for phase, snapshot_report in zip(
                            ("initial", "wrong", "outer", "inner"), reports
                        ):
                            content = client.encode(snapshot_report)
                            filename = phase + ".json"
                            client.write_private(
                                directory / "reports" / filename, content
                            )
                            item["snapshots"].append(
                                {
                                    "file": filename,
                                    "sha256": client.digest(content),
                                    "round": phase,
                                    "status": snapshot_report["job_status"],
                                }
                            )
                        item["last_status"] = {"password_attempts": 3}
                        result = campaign.verify(case, require_full_pipeline=False)
                        self.assertTrue(result["success"])
                        self.assertFalse(result["full_static_analysis_verified"])


if __name__ == "__main__":
    unittest.main()
