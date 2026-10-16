"""Exercise the collector's formats with the real SDK, without cloud access.

Use an installed gcloud SDK or set MALSCAN_GCLOUD_SDK_LIB to its lib directory.
These optional checks never install the SDK or execute a gcloud command.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "projection_collector", Path(__file__).with_name("collect-demo-evidence.py")
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

SENTINEL = "PRIVATE_FIXTURE_MUST_NOT_BE_EXPORTED"
FORMATTER = """
import io
import json
import sys
from googlecloudsdk.core.resource import resource_printer
request = json.load(sys.stdin)
output = io.StringIO()
resource_printer.Print(
    request['resource'], request['format'], out=output,
    single=not isinstance(request['resource'], list),
)
sys.stdout.write(output.getvalue())
"""


def sdk_library() -> Path | None:
    configured = os.environ.get("MALSCAN_GCLOUD_SDK_LIB")
    executable = shutil.which("gcloud")
    candidate = (
        Path(configured)
        if configured
        else Path(executable).resolve().parent.parent / "lib"
        if executable
        else None
    )
    if (
        candidate
        and (candidate / "googlecloudsdk/core/resource/resource_printer.py").is_file()
    ):
        return candidate.resolve()
    return None


def fixtures():
    containers = [
        {
            "image": "worker@sha256:" + "1" * 64,
            "resources": {"limits": {"cpu": "2", "memory": "4Gi"}},
            "env": [{"name": "PRIVATE", "value": SENTINEL}],
        },
        {
            "image": "sidecar@sha256:" + "2" * 64,
            "resources": {"limits": {"cpu": "1", "memory": "128Mi"}},
            "env": [{"name": "PRIVATE", "value": SENTINEL}],
        },
    ]
    task = {"containers": containers, "volumes": [{"secret": SENTINEL}]}
    return {
        "runner_job": {
            "metadata": {"name": collector.JOB},
            "spec": {
                "template": {
                    "spec": {
                        "taskCount": 1,
                        "parallelism": 1,
                        "template": {"spec": task},
                    }
                }
            },
        },
        "dispatcher_service": {
            "metadata": {"name": collector.DISPATCHER},
            "spec": {"template": {"spec": task}},
        },
        "runner_executions": [
            {
                "metadata": {"name": "execution-one"},
                "spec": {"taskCount": 1, "template": {"spec": task}},
                "status": {
                    "startTime": "2026-10-15T01:00:00Z",
                    "completionTime": "2026-10-15T01:00:10Z",
                },
            }
        ],
        "recent_builds": [
            {
                "id": "build-one",
                "status": "SUCCESS",
                "results": {
                    "images": [
                        {
                            "name": "worker:first",
                            "digest": "sha256:" + "3" * 64,
                            "pushTiming": {"private": SENTINEL},
                        },
                        {
                            "name": "worker:second",
                            "digest": "sha256:" + "4" * 64,
                            "pushTiming": {"private": SENTINEL},
                        },
                    ],
                    "private": SENTINEL,
                },
                "secrets": [SENTINEL],
            }
        ],
    }


class RealGcloudProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = sdk_library()
        if library is None:
            raise unittest.SkipTest(
                "No SDK library; install gcloud or set MALSCAN_GCLOUD_SDK_LIB"
            )
        cls.projected = {}
        raw = fixtures()
        commands = {
            ("run", "jobs", "describe"): "runner_job",
            ("run", "services", "describe"): "dispatcher_service",
            ("run", "jobs", "executions"): "runner_executions",
            ("builds", "list"): "recent_builds",
        }
        with tempfile.TemporaryDirectory(prefix="malscan-sdk-format-") as config:
            env = dict(os.environ)
            env.update(
                PYTHONPATH=os.pathsep.join(
                    (str(library), str(library / "third_party"))
                ),
                PYTHONDONTWRITEBYTECODE="1",
                CLOUDSDK_CONFIG=config,
                CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
                CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true",
            )

            def runner(args):
                key = commands.get(tuple(args[:3])) or commands.get(tuple(args[:2]))
                if key is None:
                    return {"observed": True, "data": [] if "list" in args else {}}
                format_arg = next(arg for arg in args if arg.startswith("--format="))
                result = subprocess.run(
                    [sys.executable, "-c", FORMATTER],
                    input=json.dumps(
                        {"resource": raw[key], "format": format_arg.split("=", 1)[1]}
                    ),
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=30,
                    env=env,
                )
                if SENTINEL in result.stdout or SENTINEL in result.stderr:
                    raise AssertionError("SDK projection exported a private fixture")
                cls.projected[key] = json.loads(result.stdout)
                return {"observed": True, "data": cls.projected[key]}

            cls.report = collector.collect(
                days=30,
                limit=200,
                now=dt.datetime(2026, 10, 16, tzinfo=dt.timezone.utc),
                runner=runner,
            )

    def data(self, key):
        observation = self.report["observations"][key]
        self.assertTrue(observation["observed"])
        self.assertNotIn(SENTINEL, json.dumps(observation))
        return observation["data"]

    def check_containers(self, actual):
        self.assertEqual(len(actual), 2)
        self.assertEqual(actual[0]["image"], "worker@sha256:" + "1" * 64)
        self.assertEqual(actual[0]["limits"], {"cpu": "2", "memory": "4Gi"})
        self.assertEqual(actual[1]["image"], "sidecar@sha256:" + "2" * 64)
        self.assertEqual(actual[1]["limits"], {"cpu": "1", "memory": "128Mi"})

    def test_runner_job_container_array_survives_actual_projection(self):
        task = self.projected["runner_job"]["spec"]["template"]["spec"]["template"][
            "spec"
        ]
        self.assertEqual(len(task["containers"]), 2)
        self.assertNotIn("env", task["containers"][0])
        self.assertNotIn("volumes", task)
        self.check_containers(self.data("runner_job")["containers"])

    def test_dispatcher_container_array_survives_actual_projection(self):
        task = self.projected["dispatcher_service"]["spec"]["template"]["spec"]
        self.assertEqual(len(task["containers"]), 2)
        self.assertNotIn("env", task["containers"][1])
        self.check_containers(self.data("dispatcher_service")["containers"])

    def test_execution_resources_survive_and_produce_nonzero_envelope(self):
        data = self.data("runner_executions")
        self.check_containers(data["executions"][0]["containers"])
        envelope = data["resource_time_envelope"]
        self.assertEqual(envelope["included_completed_executions"], 1)
        self.assertEqual(envelope["vcpu_seconds"], 30)
        self.assertEqual(envelope["gib_seconds"], 41.25)
        self.assertFalse(envelope["is_billable_usage"])

    def test_build_image_name_digest_pairs_survive_without_other_results(self):
        projected = self.projected["recent_builds"][0]
        self.assertNotIn("secrets", projected)
        self.assertEqual(set(projected["results"]), {"images"})
        images = self.data("recent_builds")["builds"][0]["images"]
        self.assertEqual(
            images,
            [
                {"name": "worker:first", "digest": "sha256:" + "3" * 64},
                {"name": "worker:second", "digest": "sha256:" + "4" * 64},
            ],
        )


if __name__ == "__main__":
    unittest.main()
