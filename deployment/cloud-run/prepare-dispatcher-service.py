#!/usr/bin/env python3
"""Write bounded keyless dispatcher service flags; no cloud API calls."""

import argparse
import json
import os
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument(
        "--output", type=Path, default=Path("keyless-dispatcher-service.flags.json")
    )
    args = parser.parse_args()
    prefix = "us-central1-docker.pkg.dev/malscan-v2-poc/malscan-v2-poc/demo-dispatcher@sha256:"
    if not args.image_digest.startswith(prefix) or not re.fullmatch(
        r"[a-f0-9]{64}", args.image_digest[len(prefix) :]
    ):
        parser.error("Use the published demo-dispatcher immutable image digest")
    flags = {
        "--project": "malscan-v2-poc",
        "--region": "us-central1",
        "--image": args.image_digest,
        "--service-account": "malscan-v2-demo-invoker@malscan-v2-poc.iam.gserviceaccount.com",
        "--cpu": "1",
        "--memory": "256Mi",
        "--min-instances": "0",
        "--max-instances": "1",
        "--concurrency": "1",
        "--timeout": "60s",
        "--port": "8080",
        "--cpu-throttling": True,
        "--allow-unauthenticated": True,
        "--ingress": "all",
        "--set-env-vars": {
            "GCP_PROJECT": "malscan-v2-poc",
            "GCP_REGION": "us-central1",
            "GCP_JOB": "malscan-v2-static-demo",
            "CONTROL_ORIGIN": "https://malscan-v2-demo-control.daluoter.workers.dev",
            "CONTROL_HMAC_SECRET_FILE": "/secrets/control/key",
        },
        "--set-secrets": {"/secrets/control/key": "malscan-v2-control-hmac:1"},
    }
    with args.output.open("x") as output:
        os.chmod(args.output, 0o600)
        json.dump(flags, output, indent=2)
        output.write("\n")
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
