#!/usr/bin/env python3
"""Set the closed control Worker's trusted dispatcher origin without API calls."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatcher-url", required=True)
    args = parser.parse_args()
    url = urlsplit(args.dispatcher_url)
    if (
        url.scheme != "https"
        or not url.hostname
        or not url.hostname.endswith(".run.app")
        or url.username
        or url.password
        or url.port
        or url.path not in ("", "/")
        or url.query
        or url.fragment
    ):
        parser.error(
            "Use the Cloud Run service's HTTPS status.url origin without a path"
        )
    path = Path("deployment/cloudflare/wrangler.jsonc")
    config = json.loads(path.read_text())
    if config.get("name") != "malscan-v2-demo-control":
        parser.error("Unexpected Worker configuration")
    values = config["vars"]
    if (values.get("GCP_PROJECT"), values.get("GCP_REGION"), values.get("GCP_JOB")) != (
        "malscan-v2-poc",
        "us-central1",
        "malscan-v2-static-demo",
    ):
        parser.error("Unexpected Job configuration")
    values["GCP_DISPATCH_URL"] = "https://" + url.hostname
    values["PUBLIC_UPLOADS"] = "false"
    pending = path.with_name("wrangler.keyless.tmp")
    pending.write_text(json.dumps(config, indent=2) + "\n")
    pending.replace(path)
    print(
        json.dumps(
            {
                "success": True,
                "scope": "configuration_only",
                "public_uploads": False,
                "dispatcher_origin": values["GCP_DISPATCH_URL"],
            }
        )
    )


if __name__ == "__main__":
    main()
