#!/usr/bin/env python3
"""Observe physical R2 prefix absence after demo retention, without modifying data.

Run in the authenticated operator's Cloud Shell. Only the two existing R2
credential Secret versions and seven metadata-only ListObjectsV2 requests are
read. Before expiry plus the cleanup grace period, the default performs no cloud
requests. --observe permits an early observation, but never a passing result.

Exit codes: 0 verified absent; 1 present or unknown; 2 invalid input/output;
3 not yet due. An absent R2 prefix proves neither Durable Object row deletion,
bucket lifecycle configuration, nor billed usage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

PROJECT = "malscan-v2-poc"
HOST = "4caa88de736dafcb865ded345a359776.r2.cloudflarestorage.com"
SOURCE_BUCKET = "malscan-v2-upload-poc"
RESULT_BUCKET = "malscan-v2-analysis-results"
BUCKETS = {
    SOURCE_BUCKET: ("malscan-v2-r2-read", ("uploads", "manifests")),
    RESULT_BUCKET: (
        "malscan-v2-r2-results",
        ("controls", "statuses", "reports", "checkpoints", "artifacts"),
    ),
}
GRACE = dt.timedelta(minutes=20)
MAX_RESPONSE_BYTES = 65536
USER_AGENT = "MalScanWorker-retention-check/1.0"
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


class ObservationError(Exception):
    """A bounded, non-secret failure category safe to include in the report."""

    def __init__(self, reason: str, http_status: int | None = None):
        self.reason = reason
        self.http_status = http_status
        super().__init__(reason)


@dataclass(frozen=True, repr=False)
class Credentials:
    access_key_id: str
    secret_access_key: str


def stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_expiry(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        parsed = parsed.astimezone(dt.timezone.utc)
        # Also reject timestamps whose grace period cannot be represented.
        parsed + GRACE
        return parsed
    except (ValueError, OverflowError):
        raise ValueError("Expiry must be an ISO timestamp with a timezone") from None


def validate_job_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("Job ID must be a canonical UUIDv4") from None
    if str(parsed) != value or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        raise ValueError("Job ID must be a canonical UUIDv4")
    return value


def read_credentials(secret: str) -> Credentials:
    if secret not in {value[0] for value in BUCKETS.values()}:
        raise ObservationError("credential_source_not_allowed")
    env = dict(os.environ)
    env.update(
        CLOUDSDK_CORE_LOG_HTTP="false",
        CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
        CLOUDSDK_CORE_DISABLE_PROMPTS="true",
    )
    try:
        result = subprocess.run(
            [
                "gcloud",
                "secrets",
                "versions",
                "access",
                "1",
                "--secret=" + secret,
                "--project=" + PROJECT,
                "--quiet",
                "--verbosity=error",
            ],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        raise ObservationError("gcloud_not_installed") from None
    except subprocess.TimeoutExpired:
        raise ObservationError("credential_read_timed_out") from None
    except OSError:
        raise ObservationError("credential_read_failed") from None
    if result.returncode:
        # Do not copy subprocess output, error messages, or credential values.
        raise ObservationError("credential_read_failed")
    try:
        if len(result.stdout) > MAX_RESPONSE_BYTES:
            raise ValueError
        data = json.loads(result.stdout)
        access, secret_value = data["access_key_id"], data["secret_access_key"]
        if not isinstance(access, str) or not re.fullmatch(
            r"[A-Za-z0-9]{16,128}", access
        ):
            raise ValueError
        if not isinstance(secret_value, str) or not re.fullmatch(
            r"[\x21-\x7e]{16,256}", secret_value
        ):
            raise ValueError
        return Credentials(access, secret_value)
    except (ValueError, TypeError, KeyError):
        raise ObservationError("credential_format_invalid") from None


def signed_listing_request(
    bucket: str, prefix: str, credentials: Credentials, now: dt.datetime
) -> urllib.request.Request:
    # Defense in depth: callers cannot redirect signed credentials to a different
    # host, bucket, object, or arbitrary prefix, even through this Python API.
    if bucket not in BUCKETS:
        raise ValueError("Bucket not allowed")
    parts = prefix.split("/")
    if len(parts) != 3 or parts[0] not in BUCKETS[bucket][1] or parts[2] != "":
        raise ValueError("Prefix not allowed")
    validate_job_id(parts[1])
    now = now.astimezone(dt.timezone.utc)
    date = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    scope = f"{date}/auto/s3/aws4_request"
    query = urllib.parse.urlencode(
        sorted({"list-type": "2", "max-keys": "1", "prefix": prefix}.items()),
        quote_via=urllib.parse.quote,
        safe="",
    )
    path = "/" + bucket
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_headers = (
        f"host:{HOST}\nx-amz-content-sha256:{EMPTY_HASH}\nx-amz-date:{amz_date}\n"
    )
    canonical = "\n".join(
        ("GET", path, query, canonical_headers, signed_headers, EMPTY_HASH)
    )
    to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        )
    )
    key = ("AWS4" + credentials.secret_access_key).encode()
    for component in (date, "auto", "s3", "aws4_request"):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return urllib.request.Request(
        f"https://{HOST}{path}?{query}",
        method="GET",
        headers={
            "Host": HOST,
            "User-Agent": USER_AGENT,
            "X-Amz-Date": amz_date,
            "X-Amz-Content-Sha256": EMPTY_HASH,
            "Authorization": authorization,
        },
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_remote(request: urllib.request.Request) -> bytes:
    # Retain inherited proxy and CA configuration. The default HTTPS handler
    # performs certificate/hostname validation; redirects are never followed.
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise ObservationError("listing_http_error", response.status)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ObservationError("listing_response_too_large", 200)
            return body
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        reason = (
            "listing_permission_denied"
            if status in (401, 403)
            else "listing_http_error"
        )
        raise ObservationError(reason, status) from None
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException):
        raise ObservationError("listing_network_error") from None


def listing_presence(body: bytes, bucket: str, prefix: str) -> bool:
    try:
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError
        text = body.decode("utf-8")
        if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
            raise ValueError
        root = ET.fromstring(text)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        if root.tag == "ListBucketResult":
            ns = ""
        elif root.tag != ns + "ListBucketResult":
            raise ValueError

        def field(name: str) -> str:
            elements = root.findall(ns + name)
            if len(elements) != 1 or elements[0].text is None:
                raise ValueError
            return elements[0].text

        if (
            field("Name") != bucket
            or field("Prefix") != prefix
            or field("MaxKeys") != "1"
        ):
            raise ValueError
        count, truncated = field("KeyCount"), field("IsTruncated")
        contents = root.findall(ns + "Contents")
        if root.findall(ns + "CommonPrefixes") or count not in ("0", "1"):
            raise ValueError
        if truncated not in ("true", "false") or len(contents) != int(count):
            raise ValueError
        if count == "0":
            if truncated != "false":
                raise ValueError
            return False
        keys = contents[0].findall(ns + "Key")
        if len(keys) != 1 or not (keys[0].text or "").startswith(prefix):
            raise ValueError
        # Only presence is retained. Names, object bodies and user filenames are
        # never copied into the evidence report.
        return True
    except (ET.ParseError, ValueError, TypeError, UnicodeError):
        raise ObservationError("listing_response_invalid", 200) from None


def verify(
    job_id: str,
    expires_at: dt.datetime,
    *,
    observe: bool = False,
    now: dt.datetime | None = None,
    credential_reader: Callable[[str], Credentials] = read_credentials,
    transport: Callable[[urllib.request.Request], bytes] = request_remote,
) -> dict:
    job_id = validate_job_id(job_id)
    now = now or dt.datetime.now(dt.timezone.utc)
    if expires_at.tzinfo is None or now.tzinfo is None:
        raise ValueError("Timezone required")
    due_at = expires_at + GRACE
    due = now >= due_at
    report = {
        "schema_version": 1,
        "scope": "r2_prefix_retention_verification",
        "read_only": True,
        "metadata_only": True,
        "job_id": job_id,
        "observed_at": stamp(now),
        "retention_expires_at": stamp(expires_at),
        "verification_due_at": stamp(due_at),
        "grace_seconds": int(GRACE.total_seconds()),
        "verification_due": due,
        "status": "not_due",
        "r2_absence_confirmed": False,
        "prefixes": [],
        "durable_object_row_deletion": "not_observed",
        "bucket_lifecycle_configuration": "not_observed",
        "billed_usage": "not_observed",
        "public_api_withdrawal_is_physical_deletion_proof": False,
    }
    for bucket, (secret, roots) in BUCKETS.items():
        credentials = None
        credential_error = None
        if due or observe:
            try:
                credentials = credential_reader(secret)
            except ObservationError as error:
                credential_error = error
        for root in roots:
            prefix = f"{root}/{job_id}/"
            result = {
                "bucket": bucket,
                "prefix": prefix,
                "observed": False,
                "http_status": None,
                "objects_present": None,
            }
            report["prefixes"].append(result)
            if not due and not observe:
                result["reason"] = "verification_not_due"
                continue
            try:
                if credential_error:
                    raise credential_error
                request = signed_listing_request(bucket, prefix, credentials, now)
                body = transport(request)
                result.update(
                    observed=True,
                    http_status=200,
                    objects_present=listing_presence(body, bucket, prefix),
                )
            except ObservationError as error:
                result.update(reason=error.reason, http_status=error.http_status)
    if due:
        if any(row["objects_present"] is True for row in report["prefixes"]):
            report["status"] = "objects_present"
        elif all(row["objects_present"] is False for row in report["prefixes"]):
            report["status"] = "verified_absent"
            report["r2_absence_confirmed"] = True
        else:
            report["status"] = "unknown"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--retention-expires-at", required=True)
    parser.add_argument("--observe", action="store_true")
    parser.add_argument(
        "--output", type=Path, help="Create a new private JSON evidence file"
    )
    args = parser.parse_args(argv)
    try:
        job_id = validate_job_id(args.job_id)
        expires_at = parse_expiry(args.retention_expires_at)
    except ValueError as error:
        parser.error(str(error))
    report = verify(job_id, expires_at, observe=args.observe)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        try:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(encoded)
        except OSError:
            print(json.dumps({"status": "report_write_failed", "read_only": True}))
            return 2
    print(encoded, end="")
    return {"verified_absent": 0, "not_due": 3}.get(report["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
