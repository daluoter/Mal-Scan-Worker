#!/usr/bin/env python3
"""Store demo R2/HMAC values using hidden input and private temporary files."""

import argparse
import getpass
import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="malscan-v2-poc")
    parser.add_argument(
        "--worker-directory", type=Path, default=Path("deployment/cloudflare")
    )
    parser.add_argument(
        "--resume", action="store_true", help="Reuse existing immutable v1 values"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", args.project):
        parser.error("Invalid project ID")
    # Commands receive file paths or stdin, never credential command arguments.
    env = dict(
        os.environ,
        CLOUDSDK_CORE_LOG_HTTP="false",
        CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
    )
    if args.resume:
        # Recover the same key after Cloud Shell disconnected between platforms.
        # Access output is captured in memory and never written to the terminal.
        recovered = subprocess.run(
            [
                "gcloud",
                "secrets",
                "versions",
                "access",
                "1",
                "--secret=malscan-v2-control-hmac",
                "--project=" + args.project,
                "--quiet",
            ],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        signing_key = recovered.stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{64}", signing_key):
            parser.error("Existing signing key has an invalid format")
        contents_to_create = ()
        writer = subprocess.run(
            [
                "gcloud",
                "secrets",
                "describe",
                "malscan-v2-r2-results",
                "--project=" + args.project,
                "--format=value(name)",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        if writer.returncode:
            if not any(
                marker in writer.stderr.lower() for marker in ("not_found", "not found")
            ):
                parser.error(
                    "Unable to check the existing result secret; check GCP access"
                )
            access = getpass.getpass("Missing result secret: Access Key ID (hidden): ")
            secret = getpass.getpass(
                "Missing result secret: Secret Access Key (hidden): "
            )
            if not access or not secret:
                parser.error("Both result-bucket credentials are required")
            contents_to_create = (
                (
                    "malscan-v2-r2-results",
                    json.dumps({"access_key_id": access, "secret_access_key": secret}),
                ),
            )
    else:
        access = getpass.getpass(
            "Result bucket Object Read & Write Access Key ID (hidden): "
        )
        secret = getpass.getpass("Result bucket Secret Access Key (hidden): ")
        if not access or not secret:
            parser.error("Both result-bucket credentials are required")
        signing_key = secrets.token_hex(32)
        contents_to_create = (
            ("malscan-v2-control-hmac", signing_key),
            (
                "malscan-v2-r2-results",
                json.dumps({"access_key_id": access, "secret_access_key": secret}),
            ),
        )
    with tempfile.TemporaryDirectory(prefix="malscan-secrets-") as directory:
        os.chmod(directory, 0o700)
        for name, contents in contents_to_create:
            path = Path(directory) / name
            path.write_text(contents)
            path.chmod(0o600)
            # Create only new secrets. A rerun must not silently rotate the key
            # in one platform while another platform retains its previous value.
            subprocess.run(
                [
                    "gcloud",
                    "secrets",
                    "create",
                    name,
                    "--project=" + args.project,
                    "--replication-policy=automatic",
                    "--data-file=" + str(path),
                    "--quiet",
                ],
                check=True,
                env=env,
            )
        subprocess.run(
            ["npx", "--no-install", "wrangler", "secret", "put", "CONTROL_HMAC_KEY"],
            input=signing_key + "\n",
            text=True,
            check=True,
            cwd=args.worker_directory,
        )
    print(
        json.dumps(
            {
                "success": True,
                "scope": "new_secret_setup_only",
                "cloud_run_executed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
