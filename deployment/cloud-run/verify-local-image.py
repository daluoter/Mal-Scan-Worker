"""Exercise the real full-worker image through signed controls and local S3."""
import argparse
import hashlib
import io
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pyzipper
from minio import Minio
from malscan_worker.config import get_settings
from malscan_worker.runtime.cloud_entrypoint import canonical, open_envelope, seal
from malscan_worker.runtime.manifest import AnalysisManifest, SourceReference

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", default="malscan-v2-full-cloud:verified")
parser.add_argument("--output-dir", type=Path, default=Path(".local-cloud-smoke"))
parser.add_argument(
    "--diagnose", action="store_true", help="Print only sanitized local S3 error codes"
)
args = parser.parse_args()
settings = get_settings()
if not settings.minio_endpoint or not settings.minio_endpoint.startswith(
    ("127.0.0.1:", "localhost:")
):
    parser.error("Use a local MinIO endpoint for this fixture-only test")
client = Minio(
    settings.minio_endpoint,
    access_key=settings.minio_access_key,
    secret_key=settings.minio_secret_key,
    secure=settings.minio_secure,
)
run_id = uuid.uuid4().hex
source_bucket, result_bucket = "v2-source-" + run_id, "v2-results-" + run_id
root, attempt = str(uuid.uuid4()), str(uuid.uuid4())
# Public fixture key, solely for this local integration (never a deployment key).
signing_key = bytes(range(32))
output = args.output_dir.resolve() / run_id
output.mkdir(parents=True, mode=0o700)


def put(bucket, key, value):
    data = canonical(value)
    client.put_object(
        bucket, key, io.BytesIO(data), len(data), content_type="application/json"
    )


def read(bucket, key):
    response = client.get_object(bucket, key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def archive(name, content, password):
    stream = io.BytesIO()
    with pyzipper.AESZipFile(stream, "w", encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode())
        z.writestr(name, content)
    return stream.getvalue()


outer_pw, inner_pw = secrets.token_hex(12), secrets.token_hex(12)
payload = archive(
    "inner.zip",
    archive(
        "harmless.txt", b"Harmless full image integration " + run_id.encode(), inner_pw
    ),
    outer_pw,
)
manifest = AnalysisManifest(
    root,
    attempt,
    SourceReference(
        f"uploads/{root}/source",
        hashlib.sha256(payload).hexdigest(),
        len(payload),
        "nested-cloud.zip",
    ),
    f"reports/{root}/{attempt}.json",
)
manifest_key = f"manifests/{root}/{attempt}.json"
evidence = []
docker_env = {
    k: v
    for k, v in os.environ.items()
    if k
    not in (
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_HOST",
    )
}
try:
    client.make_bucket(source_bucket)
    client.make_bucket(result_bucket)
    client.put_object(
        source_bucket, manifest.source.key, io.BytesIO(payload), len(payload)
    )
    put(source_bucket, manifest_key, manifest.to_dict())
    with tempfile.TemporaryDirectory(prefix="v2-private-", dir=output) as private:
        private = Path(private)
        credential = private / "credentials.json"
        credential.write_text(
            json.dumps(
                {
                    "access_key_id": settings.minio_access_key,
                    "secret_access_key": settings.minio_secret_key,
                }
            )
        )
        hmac_file = private / "control-hmac"
        hmac_file.write_text(signing_key.hex())
        credential.chmod(0o444)
        hmac_file.chmod(0o444)
        passwords = {}
        previous_budget = None
        for sequence in range(1, 4):
            dispatch = str(uuid.uuid4())
            control_key, status_key = (
                f"controls/{root}/{dispatch}.json",
                f"statuses/{root}/{dispatch}.json",
            )
            control = {
                "control_version": 1,
                "manifest_sha256": manifest.fingerprint,
                "checkpoint_key": f"checkpoints/{root}/{attempt}.json",
                "resume": sequence > 1,
                "passwords": passwords,
                "status_key": status_key,
                "dispatch_id": dispatch,
                "sequence": sequence,
                "expires_at": int(time.time() * 1000) + 3600000,
            }
            put(result_bucket, control_key, seal(control, signing_key))
            values = {
                "MALSCAN_ROOT_JOB_ID": root,
                "MALSCAN_ATTEMPT_ID": attempt,
                "MALSCAN_DISPATCH_ID": dispatch,
                "MALSCAN_SEQUENCE": str(sequence),
                "MALSCAN_MANIFEST_KEY": manifest_key,
                "MALSCAN_CONTROL_KEY": control_key,
                "MALSCAN_STATUS_KEY": status_key,
                "MALSCAN_REPORT_KEY": manifest.report_key,
                "MALSCAN_R2_ENDPOINT": "http://" + settings.minio_endpoint,
                "MALSCAN_UPLOAD_BUCKET": source_bucket,
                "MALSCAN_RESULT_BUCKET": result_bucket,
            }
            command = [
                "docker",
                "--host=unix:///var/run/docker.sock",
                "run",
                "--rm",
                "--network=host",
                "--cpus=2",
                "--memory=4g",
                "--mount",
                f"type=bind,src={credential},dst=/secrets/r2-read.json,readonly",
                "--mount",
                f"type=bind,src={credential},dst=/secrets/r2-result.json,readonly",
                "--mount",
                f"type=bind,src={hmac_file},dst=/secrets/control-hmac,readonly",
            ]
            for name, value in values.items():
                command += ["--env", name + "=" + value]
            if args.diagnose:
                command += [
                    "--entrypoint=python",
                    args.image,
                    "-c",
                    (
                        "import asyncio,json\n"
                        "from malscan_worker.runtime.cloud_entrypoint import _run_with_signals\n"
                        "from minio.error import S3Error\n"
                        "try: print(json.dumps(asyncio.run(_run_with_signals())))\n"
                        "except S3Error as error:\n"
                        " print(json.dumps({'error_type':'S3Error','s3_code':error.code})); raise SystemExit(1)\n"
                    ),
                ]
            else:
                command += [args.image]
            with (output / f"execution-{sequence}.log").open("w") as log:
                completed = subprocess.run(
                    command,
                    env=docker_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                )
            assert completed.returncode == 0, (sequence, completed.returncode)
            status_raw = read(result_bucket, status_key)
            status = open_envelope(json.loads(status_raw), signing_key)
            (output / f"status-envelope-{sequence}.json").write_bytes(status_raw)
            raw_report = read(result_bucket, status["report_key"])
            assert hashlib.sha256(raw_report).hexdigest() == status["report_sha256"]
            report = json.loads(raw_report)
            assert report["report_schema_version"] == "mswr-report-v3"
            assert report["analysis_attempt_id"] == attempt
            assert report["analysis"]["dynamic"]["status"] == "disabled"
            assert (
                outer_pw not in raw_report.decode()
                and inner_pw not in raw_report.decode()
            )
            checkpoint_raw = read(
                result_bucket, f"checkpoints/{root}/{attempt}.json"
            ).decode()
            assert outer_pw not in checkpoint_raw and inner_pw not in checkpoint_raw
            try:
                client.stat_object(result_bucket, control_key)
                raise AssertionError("Private control was not deleted")
            except Exception as exc:
                assert getattr(exc, "code", None) == "NoSuchKey", type(exc).__name__
            (output / f"report-{sequence}.json").write_bytes(raw_report)
            (output / f"status-{sequence}.json").write_text(
                json.dumps(status, indent=2)
            )
            budget = report["execution_budget"]
            if previous_budget:
                assert budget["used_files"] >= previous_budget["used_files"]
                assert budget["used_bytes"] >= previous_budget["used_bytes"]
            previous_budget = budget
            evidence.append(
                {
                    "sequence": sequence,
                    "status": status["status"],
                    "root": root,
                    "static": report["analysis"]["static"]["status"],
                    "budget": budget,
                }
            )
            waiting = status["password_required_artifacts"]
            if sequence < 3:
                assert status["status"] == "password_required" and len(waiting) == 1
                assert (waiting[0] == root) is (sequence == 1)
                passwords = {waiting[0]: outer_pw if sequence == 1 else inner_pw}
            else:
                assert status["status"] == "done" and not waiting
                assert report["analysis"]["static"]["status"] == "complete"
                assert budget["used_files"] == 2
                for artifact in report["artifacts"]:
                    result = artifact["report"]["results"]
                    assert result["av_result"]["infected"] is False
                    assert result["yara_hits"] is not None
    (output / "acceptance.json").write_text(
        json.dumps(
            {
                "success": True,
                "scope": "local_full_cloud_image_real_s3",
                "evidence": evidence,
            },
            indent=2,
        )
    )
    print(
        json.dumps(
            {
                "success": True,
                "scope": "local_full_cloud_image_real_s3",
                "output": str(output),
                "executions": len(evidence),
            }
        )
    )
finally:
    for bucket in (source_bucket, result_bucket):
        if client.bucket_exists(bucket):
            for item in client.list_objects(bucket, recursive=True):
                client.remove_object(bucket, item.object_name)
            client.remove_bucket(bucket)
