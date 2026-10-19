#!/usr/bin/env python3
"""Prepare a private, source-only Worker update from a downloaded JSON config."""

import argparse
import copy
import datetime
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """A local configuration cannot safely be used for this update."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigurationError(message)


def _placeholder(value: str) -> bool:
    return any(word in value.lower() for word in ("replace", "placeholder", "example"))


def _url(value: object, *, dispatcher: bool = False) -> None:
    _require(isinstance(value, str), "An HTTPS production URL is required")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and parsed.path in ("", "/")
            and parsed.port in (None, 443)
            and not _placeholder(value)
        )
    except ValueError:
        valid = False
    _require(bool(valid), "An HTTPS production URL without credentials is required")
    if dispatcher:
        _require(parsed.hostname.endswith(".run.app"), "Review the dispatcher URL")


def _private_write(path: Path, content: bytes, original: Path, source: Path) -> bool:
    """Create once, or retain identical private output; never replace another file."""
    _require(not path.is_symlink(), "Output must not be a symbolic link")
    parent = path.parent.resolve(strict=True)
    parent_info = parent.stat()
    _require(
        parent_info.st_uid == os.getuid() and not parent_info.st_mode & 0o077,
        "Output directory must be private to the current user",
    )
    target = parent / path.name
    _require(target not in (original, source), "Output must differ from both input files")
    for ancestor in source.parents:
        if (ancestor / ".git").exists():
            _require(
                not target.is_relative_to(ancestor),
                "Generated production config must stay outside the source Git checkout",
            )
            break
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(target, read_flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid == os.getuid(),
                "Existing output must be a private regular file",
            )
            _require(
                (info.st_dev, info.st_ino)
                not in {
                    (original.stat().st_dev, original.stat().st_ino),
                    (source.stat().st_dev, source.stat().st_ino),
                },
                "Output must differ from both input files",
            )
            _require(
                stream.read(len(content) + 1) == content,
                "Existing output differs; preserve it and use a new output filename",
            )
            os.fchmod(stream.fileno(), 0o600)
        return False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return True


def prepare(source: Path, downloaded_config: Path, output: Path, worker_name: str) -> dict:
    _require(
        bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", worker_name)),
        "Invalid expected Worker name",
    )
    _require(not source.is_symlink(), "Source must not be a symbolic link")
    source = source.resolve(strict=True)
    downloaded_config = downloaded_config.resolve(strict=True)
    _require(source.is_file(), "Source must be an existing regular file")
    _require(downloaded_config.is_file(), "Downloaded config must be a regular JSON file")

    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "Downloaded JSON contains duplicate keys")
            result[key] = value
        return result

    try:
        config = json.loads(downloaded_config.read_text(), object_pairs_hook=unique_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("Downloaded config is not valid JSON") from error
    _require(isinstance(config, dict), "Downloaded config must be a JSON object")
    _require(config.get("name") == worker_name, "Downloaded Worker identity differs")
    values = config.get("vars")
    _require(isinstance(values, dict), "Downloaded production variables are missing")
    secret_name = re.compile(
        r"token|secret|password|hmac|private.?key|access.?key|api.?key|capability|authorization|cookie|credential",
        re.I,
    )
    _require(
        not any(secret_name.search(key) for key in values),
        "Credential-like plain variables found; keep credentials in Worker secrets",
    )
    _url(values.get("ALLOWED_ORIGIN"))
    _require(
        values.get("PUBLIC_UPLOADS") is True or values.get("PUBLIC_UPLOADS") == "true",
        "Public uploads are not enabled",
    )
    expected_limits = {
        "DAILY_JOB_LIMIT": "10",
        "DAILY_EXECUTION_LIMIT": "20",
        "MONTHLY_EXECUTION_LIMIT": "40",
        "RETENTION_SECONDS": "86400",
    }
    _require(
        all(str(values.get(key)) == value for key, value in expected_limits.items()),
        "Review the current production quotas or retention; no limits were changed",
    )
    for key, pattern in (
        ("GCP_PROJECT", r"[a-z][a-z0-9-]{4,28}[a-z0-9]"),
        ("GCP_REGION", r"[a-z]+-[a-z]+[0-9]"),
        ("GCP_JOB", r"[a-z][a-z0-9-]{0,61}[a-z0-9]"),
    ):
        value = values.get(key)
        _require(
            isinstance(value, str) and bool(re.fullmatch(pattern, value)) and not _placeholder(value),
            "Review the production Cloud Run target",
        )
    _url(values.get("GCP_DISPATCH_URL"), dispatcher=True)
    objects = config.get("durable_objects", {})
    _require(isinstance(objects, dict), "Invalid Durable Object configuration")
    bindings = objects.get("bindings")
    _require(
        isinstance(bindings, list) and len(bindings) == 1 and isinstance(bindings[0], dict),
        "Expected exactly one CONTROL Durable Object binding",
    )
    binding = bindings[0]
    if "script_name" in binding:
        _require(
            isinstance(binding["script_name"], str),
            "A present CONTROL script_name must be a string; preserve the downloaded binding",
        )
    if "environment" in binding:
        _require(
            isinstance(binding["environment"], str),
            "A present CONTROL environment must be a string; preserve the downloaded binding",
        )
    _require(
        binding.get("name") == "CONTROL"
        and binding.get("class_name") == "DemoControl"
        and ("script_name" not in binding or binding["script_name"] == worker_name)
        and ("environment" not in binding or binding["environment"] == "production"),
        "CONTROL must refer to this Worker's existing DemoControl class",
    )
    buckets = config.get("r2_buckets")
    _require(isinstance(buckets, list) and len(buckets) == 2, "Expected two existing R2 bindings")
    _require(all(isinstance(item, dict) for item in buckets), "Invalid R2 bindings")
    _require(
        all(isinstance(item.get("binding"), str) for item in buckets),
        "Invalid R2 binding names",
    )
    _require(
        {item.get("binding") for item in buckets} == {"UPLOADS", "RESULTS"},
        "Expected UPLOADS and RESULTS R2 bindings",
    )
    bucket_names = [item.get("bucket_name") for item in buckets]
    _require(
        all(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", name)
            and not _placeholder(name)
            for name in bucket_names
        ) and bucket_names[0] != bucket_names[1],
        "Expected two distinct existing production buckets",
    )
    _require(config.get("workers_dev") is True, "The production workers.dev endpoint is disabled")
    try:
        datetime.date.fromisoformat(config.get("compatibility_date", ""))
    except (TypeError, ValueError) as error:
        raise ConfigurationError("Invalid production compatibility date") from error
    if "migrations" in config:
        _require(isinstance(config["migrations"], list), "Invalid downloaded lifecycle configuration")
    if "exports" in config:
        _require(isinstance(config["exports"], dict), "Invalid downloaded lifecycle configuration")

    updated = copy.deepcopy(config)
    updated["main"] = str(source)
    changed = sorted(key for key in updated if updated[key] != config.get(key))
    _require(changed == ["main"], "Expected only the source entry point to change")
    encoded = (json.dumps(updated, indent=2, ensure_ascii=False) + "\n").encode()
    created = _private_write(output, encoded, downloaded_config, source)
    return {
        "success": True,
        "scope": "local_configuration_only",
        "changed_fields": changed,
        "production_settings_preserved": True,
        "lifecycle_configuration_preserved": True,
        "credential_files_read": False,
        "remote_mutations": False,
        "output_mode": "0600",
        "output_created": created,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-name", required=True)
    parser.add_argument("--source", required=True, type=Path, help="Reviewed worker.mjs source file")
    parser.add_argument("--downloaded-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.source, args.downloaded_config, args.output, args.worker_name)
    except (ConfigurationError, OSError) as error:
        message = str(error) if isinstance(error, ConfigurationError) else "Local file access failed; review paths and permissions"
        parser.exit(1, json.dumps({"success": False, "error": message, "remote_mutations": False}) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
