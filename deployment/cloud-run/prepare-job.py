#!/usr/bin/env python3
"""Prepare reviewable Cloud Run flags without credentials or remote mutations."""

import argparse
import json
import os
import re
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--project", default="malscan-v2-poc")
    parser.add_argument("--region", default="us-central1")
    parser.add_argument("--account-id", default="4caa88de736dafcb865ded345a359776")
    parser.add_argument("--source-bucket", default="malscan-v2-upload-poc")
    parser.add_argument("--result-bucket", default="malscan-v2-analysis-results")
    parser.add_argument("--read-secret-version", type=int, default=1)
    parser.add_argument("--result-secret-version", type=int, default=1)
    parser.add_argument("--hmac-secret-version", type=int, default=1)
    parser.add_argument(
        "--output", type=Path, default=Path("cloud-static-job.flags.json")
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", args.project):
        parser.error("Invalid project ID")
    if not re.fullmatch(r"[a-f0-9]{32}", args.account_id):
        parser.error("Invalid Cloudflare Account ID")
    if not re.fullmatch(r"[a-z]+-[a-z]+[0-9]", args.region):
        parser.error("Invalid region")
    for bucket in (args.source_bucket, args.result_bucket):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
            parser.error("Invalid private bucket name")
    if args.source_bucket == args.result_bucket:
        parser.error("Use separate source and result buckets")
    prefix = f"{args.region}-docker.pkg.dev/{args.project}/malscan-v2-poc/full-worker@sha256:"
    if not args.image_digest.startswith(prefix) or not re.fullmatch(
        r"[a-f0-9]{64}", args.image_digest[len(prefix) :]
    ):
        parser.error(
            "Use the published full-worker immutable digest, not the old PoC image"
        )
    versions = (
        args.read_secret_version,
        args.result_secret_version,
        args.hmac_secret_version,
    )
    if any(version < 1 for version in versions):
        parser.error("Secret versions must be positive immutable version numbers")
    flags = {
        "--project": args.project,
        "--region": args.region,
        "--image": args.image_digest,
        "--service-account": f"malscan-v2-static-demo@{args.project}.iam.gserviceaccount.com",
        "--tasks": "1",
        "--parallelism": "1",
        "--cpu": "2",
        "--memory": "4Gi",
        "--task-timeout": "900s",
        "--max-retries": "0",
        "--command": "python",
        "--args": ["-m", "malscan_worker.runtime.cloud_entrypoint"],
        "--set-env-vars": {
            "MALSCAN_R2_ENDPOINT": f"https://{args.account_id}.r2.cloudflarestorage.com",
            "MALSCAN_UPLOAD_BUCKET": args.source_bucket,
            "MALSCAN_RESULT_BUCKET": args.result_bucket,
            "MALSCAN_R2_READ_SECRET_FILE": "/secrets/source/credentials.json",
            "MALSCAN_R2_RESULT_SECRET_FILE": "/secrets/results/credentials.json",
            "MALSCAN_HMAC_SECRET_FILE": "/secrets/control/key",
            "MALSCAN_MAX_FILES": "20",
            "MALSCAN_MAX_EXPANDED_BYTES": "100000000",
            "MALSCAN_ATTEMPT_TIMEOUT": "840",
            "MALSCAN_MAX_DEPTH": "3",
            "SANDBOX_ENABLED": "false",
        },
        "--set-secrets": {
            "/secrets/source/credentials.json": f"malscan-v2-r2-read:{args.read_secret_version}",
            "/secrets/results/credentials.json": f"malscan-v2-r2-results:{args.result_secret_version}",
            "/secrets/control/key": f"malscan-v2-control-hmac:{args.hmac_secret_version}",
        },
    }
    with args.output.open("x", encoding="utf-8") as stream:
        os.chmod(args.output, 0o600)
        json.dump(flags, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "success": True,
                "scope": "configuration_only",
                "flags_file": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()
