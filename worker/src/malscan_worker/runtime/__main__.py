"""Run the shared static engine locally or as a Cloud Run one-shot container.

Examples:
  python -m malscan_worker.runtime --file sample.zip --output-dir ./analysis
  python -m malscan_worker.runtime --file sample.zip --output-dir ./analysis --resume

Remote stores are selected explicitly. Credentials are read from a mounted JSON
secret file, never from command-line values, the source manifest, or the report.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from malscan_worker.budget import BudgetLimits
from malscan_worker.runtime.batch import RootBatchRunner
from malscan_worker.runtime.checkpoint import load_secret
from malscan_worker.runtime.manifest import AnalysisManifest, file_identity
from malscan_worker.runtime.store import LocalObjectStore, S3ObjectStore, atomic_json


def _store_arguments(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(f"--{name}-store", choices=("local", "s3"), default="local")
    parser.add_argument(f"--{name}-root", type=Path)
    parser.add_argument(f"--{name}-endpoint")
    parser.add_argument(f"--{name}-bucket")
    parser.add_argument(f"--{name}-region")
    parser.add_argument(f"--{name}-credentials-file", type=Path)


def _store(args: argparse.Namespace, name: str, default_root: Path, *, read_only: bool) -> Any:
    if getattr(args, f"{name}_store") == "local":
        return LocalObjectStore(getattr(args, f"{name}_root") or default_root, read_only=read_only)
    endpoint = getattr(args, f"{name}_endpoint")
    bucket = getattr(args, f"{name}_bucket")
    credentials_file = getattr(args, f"{name}_credentials_file")
    if not endpoint or not bucket or not credentials_file:
        raise ValueError(f"S3 {name} storage requires endpoint, bucket and credentials file")
    if credentials_file.stat().st_size > 16384:
        raise ValueError("Invalid credential file")
    credentials = json.loads(credentials_file.read_text())
    if not isinstance(credentials, dict):
        raise ValueError("Invalid credential file")
    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    if (
        not isinstance(access_key, str)
        or not access_key
        or not isinstance(secret_key, str)
        or not secret_key
    ):
        raise ValueError("Invalid credential file")
    return S3ObjectStore(
        endpoint=endpoint,
        bucket=bucket,
        access_key=access_key,
        secret_key=secret_key,
        region=getattr(args, f"{name}_region"),
        read_only=read_only,
    )


async def _execute(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = args.output_dir.resolve()
    state_dir = (args.state_dir or output_dir / ".state").resolve()
    if args.manifest:
        manifest = AnalysisManifest.from_dict(json.loads(args.manifest.read_text()))
        source_root = args.manifest.resolve().parent
    else:
        source = args.file.resolve()
        source_root = source.parent
        manifest_file = output_dir / "source-manifest.json"
        if args.resume and manifest_file.exists():
            manifest = AnalysisManifest.from_dict(json.loads(manifest_file.read_text()))
            if file_identity(source) != (manifest.source.sha256, manifest.source.size):
                raise ValueError("Resume input does not match the retained source")
        else:
            manifest = AnalysisManifest.for_local_file(source)
            await asyncio.to_thread(atomic_json, manifest_file, manifest.to_dict())
    source_store = _store(args, "source", source_root, read_only=True)
    result_store = _store(args, "result", output_dir, read_only=False)
    passwords = {}
    if args.password_artifact:
        passwords[args.password_artifact] = getpass.getpass("Archive password (hidden input): ")
    elif args.ask_password:
        passwords[manifest.root_job_id] = getpass.getpass("Archive password (hidden input): ")
    runner = RootBatchRunner(
        manifest=manifest,
        source_store=source_store,
        result_store=result_store,
        state_dir=state_dir,
        limits=BudgetLimits(args.max_files, args.max_expanded_bytes, args.attempt_timeout),
        max_depth=args.max_depth,
        passwords=passwords,
        checkpoint_key=args.checkpoint_key,
        checkpoint_secret=load_secret(args.checkpoint_auth_file, hexadecimal=True)
        if args.checkpoint_auth_file
        else None,
    )
    return await runner.run(resume=args.resume)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="Local source file (original is never modified)")
    source.add_argument("--manifest", type=Path, help="Validated source/reference manifest JSON")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--state-dir", type=Path, help="Local checkpoint cache; defaults under output-dir"
    )
    parser.add_argument(
        "--checkpoint-key", help="Persistent result-store checkpoint key for remote resume"
    )
    parser.add_argument(
        "--checkpoint-auth-file",
        type=Path,
        help="Mounted 64-lowercase-hex executor key, required for S3 checkpoints",
    )
    parser.add_argument("--resume", action="store_true")
    passwords = parser.add_mutually_exclusive_group()
    passwords.add_argument(
        "--ask-password", action="store_true", help="Prompt for the root archive password"
    )
    passwords.add_argument(
        "--password-artifact", help="Prompt for this waiting artifact's password"
    )
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-files", type=int, default=100)
    parser.add_argument("--max-expanded-bytes", type=int, default=500_000_000)
    parser.add_argument("--attempt-timeout", type=float, default=3600)
    _store_arguments(parser, "source")
    _store_arguments(parser, "result")
    args = parser.parse_args()
    try:
        report = asyncio.run(_execute(args))
    except Exception as exc:
        # SDK exception messages can contain URLs or credentials. Keep stdout
        # predictable and leave provider detail to explicit owner diagnostics.
        print(
            json.dumps(
                {"success": False, "error": type(exc).__name__, "scope": "shared_static_root_batch"}
            )
        )
        return 1
    print(
        json.dumps(
            {
                "success": True,
                "scope": "shared_static_root_batch",
                "root_artifact_id": report["root_artifact_id"],
                "attempt_id": report["attempt_id"],
                "report_revision": report["report_revision"],
                "batch_analysis": report["batch_analysis"],
                "report_key": (report.get("report_key") or "report.json"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
