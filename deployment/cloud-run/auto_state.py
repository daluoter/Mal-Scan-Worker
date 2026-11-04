"""Private GCS compare-and-swap state and terminal-owner maintenance locking.

Only the GCS JSON API is used. A lost write response never becomes a blind retry,
and a marker has no time-based expiry. Callers must persist every remote mutation
intent before issuing that mutation and verify ownership immediately beforehand.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import uuid
from typing import Any, Callable, Protocol
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROJECT = "malscan-v2-poc"
MAX_GENERATION = 2**63 - 1
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_JSON_DEPTH = 100
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class StateError(RuntimeError):
    """A fixed, non-sensitive error code; provider response bodies are excluded."""


class ConflictError(StateError):
    """The expected object generation no longer matches."""


class UncertainWriteError(StateError):
    """A write may have reached storage; reconcile instead of repeating it."""


class Transport(Protocol):
    def request(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HTTPTransport:
    def __init__(self):
        # Preserve the process proxy/CA configuration and normal TLS validation.
        self.opener = build_opener(ProxyHandler(), _NoRedirect())

    def request(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "storage.googleapis.com"
            or parsed.fragment
            or method not in {"GET", "POST", "DELETE"}
        ):
            raise StateError("storage_endpoint_invalid")
        env = dict(os.environ)
        env.update(
            CLOUDSDK_CORE_LOG_HTTP="false",
            CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
            CLOUDSDK_CORE_DISABLE_PROMPTS="true",
        )
        try:
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token", f"--project={PROJECT}", "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise StateError("storage_auth_unavailable") from None
        token = result.stdout.strip()
        if (
            result.returncode
            or not 1 <= len(token) <= 8192
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token)
        ):
            raise StateError("storage_auth_unavailable")
        authenticated = {**headers, "Authorization": "Bearer " + token}
        request = Request(url, method=method, headers=authenticated, data=body)
        try:
            with self.opener.open(request, timeout=45) as response:
                payload = response.read(MAX_JSON_BYTES + 1)
                return response.status, payload
        except HTTPError as error:
            # The code is sufficient; never read, print or attach an arbitrary
            # Google error body or a redirect URL to a public error message.
            return error.code, b""


def _generation(value: Any, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, str):
        if not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
            raise StateError("storage_generation_invalid")
        value = int(value)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_GENERATION
    ):
        raise StateError("storage_generation_invalid")
    return value


def _object_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not all(_SEGMENT.fullmatch(part) for part in value.split("/"))
    ):
        raise StateError("storage_object_name_invalid")
    return value


def _validate_json(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StateError("storage_json_invalid")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise StateError("storage_json_invalid")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise StateError("storage_json_invalid")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None:
            if not isinstance(item, (str, bool, int, float)):
                raise StateError("storage_json_invalid")
            if isinstance(item, float) and not math.isfinite(item):
                raise StateError("storage_json_invalid")
    return value


def _decode_json(body: bytes, maximum: int) -> dict[str, Any]:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError

    try:
        if not isinstance(body, bytes) or len(body) > maximum:
            raise ValueError
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
        return _validate_json(value)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise StateError("storage_json_invalid") from None


class Store:
    """Read exact generations and perform explicit generation-conditional writes.

    The deployment layer must verify that bucket is the intended private,
    regional operations bucket. This class neither changes bucket settings nor
    reads bucket credentials or other services.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "database-updates",
        *,
        transport: Transport | None = None,
    ):
        if not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket):
            raise StateError("storage_bucket_invalid")
        self.bucket = bucket
        self.prefix = _object_name(prefix)
        self.transport = transport if transport is not None else _HTTPTransport()

    def _name(self, name: str) -> str:
        return _object_name(self.prefix + "/" + _object_name(name))

    def _call(self, method: str, url: str, *, body: bytes | None = None) -> tuple[int, bytes]:
        try:
            status, payload = self.transport.request(
                method, url, {"Content-Type": "application/json"}, body
            )
            if (
                not isinstance(status, int)
                or isinstance(status, bool)
                or not isinstance(payload, bytes)
            ):
                raise ValueError
            return status, payload
        except StateError as error:
            if str(error) == "storage_auth_unavailable":
                raise StateError("storage_auth_unavailable") from None
        except Exception:
            pass
        if method == "GET":
            raise StateError("storage_read_failed") from None
        raise UncertainWriteError("storage_write_response_unknown") from None

    def load_json(self, name: str) -> tuple[dict[str, Any] | None, int]:
        encoded = quote(self._name(name), safe="")
        base = f"https://storage.googleapis.com/storage/v1/b/{self.bucket}/o/{encoded}"
        status, body = self._call("GET", base + "?fields=generation,size")
        if status == 404:
            return None, 0
        if status != 200:
            raise StateError("storage_read_failed")
        metadata = _decode_json(body, MAX_METADATA_BYTES)
        generation = _generation(metadata.get("generation"))
        size = metadata.get("size")
        if (
            not isinstance(size, str)
            or not re.fullmatch(r"0|[1-9][0-9]{0,18}", size)
            or int(size) > MAX_JSON_BYTES
        ):
            raise StateError("storage_object_size_invalid")
        status, body = self._call("GET", base + f"?alt=media&generation={generation}")
        if status != 200 or len(body) != int(size):
            raise StateError("storage_exact_generation_unavailable")
        return _decode_json(body, MAX_JSON_BYTES), generation

    def put_json(self, name: str, value: dict[str, Any], expected_generation: int) -> int:
        # A string is accepted for API response generations, not caller CAS
        # preconditions: reject accidental booleans/coercions before any I/O.
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
            raise StateError("storage_generation_invalid")
        expected = _generation(expected_generation, allow_zero=True)
        try:
            body = json.dumps(
                _validate_json(value), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (ValueError, TypeError, RecursionError):
            raise StateError("storage_json_invalid") from None
        if len(body) > MAX_JSON_BYTES:
            raise StateError("storage_object_size_invalid")
        query = urlencode(
            {
                "uploadType": "media",
                "name": self._name(name),
                "ifGenerationMatch": expected,
                "fields": "generation",
            }
        )
        status, response = self._call(
            "POST",
            f"https://storage.googleapis.com/upload/storage/v1/b/{self.bucket}/o?{query}",
            body=body,
        )
        if status == 412:
            raise ConflictError("storage_generation_conflict")
        if status >= 500:
            raise UncertainWriteError("storage_write_response_unknown")
        if status not in {200, 201}:
            raise StateError("storage_write_failed")
        try:
            generation = _generation(_decode_json(response, MAX_METADATA_BYTES).get("generation"))
            if generation == expected:
                raise StateError("storage_generation_invalid")
            return generation
        except StateError:
            raise UncertainWriteError("storage_write_response_unknown") from None

    def delete(self, name: str, expected_generation: int) -> None:
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
            raise StateError("storage_generation_invalid")
        expected = _generation(expected_generation)
        encoded = quote(self._name(name), safe="")
        status, _ = self._call(
            "DELETE",
            f"https://storage.googleapis.com/storage/v1/b/{self.bucket}/o/{encoded}"
            f"?ifGenerationMatch={expected}",
        )
        if status in {404, 412}:
            raise ConflictError("storage_generation_conflict")
        if status >= 500:
            raise UncertainWriteError("storage_delete_response_unknown")
        if status != 204:
            raise StateError("storage_delete_failed")


def _owner(value: Any) -> str:
    try:
        if (
            not isinstance(value, str)
            or str(uuid.UUID(value)) != value
            or uuid.UUID(value).int == 0
        ):
            raise ValueError
    except (ValueError, AttributeError):
        raise StateError("lease_owner_invalid") from None
    return value


def _marker(value: Any) -> str:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "owner_build_id"}
        or not isinstance(value.get("schema_version"), int)
        or isinstance(value.get("schema_version"), bool)
        or value["schema_version"] != 1
    ):
        raise StateError("lease_marker_invalid")
    return _owner(value.get("owner_build_id"))


class Lease:
    """A persistent owner marker; only a proven terminal owner may be replaced."""

    def __init__(self, store: Store, owner_build_id: str, name: str = "lease.json"):
        self.store = store
        self.owner_build_id = _owner(owner_build_id)
        self.name = _object_name(name)
        self._generation: int | None = None
        self._released = False

    def acquire(self, owner_terminal: Callable[[str], bool | None]) -> bool:
        value, generation = self.store.load_json(self.name)
        generation = _generation(generation, allow_zero=True)
        if self._generation is not None:
            if (
                value is None
                or _marker(value) != self.owner_build_id
                or generation != self._generation
            ):
                raise StateError("lease_ownership_changed")
            return True
        if value is None:
            if generation != 0:
                raise StateError("lease_marker_invalid")
        else:
            if generation == 0:
                raise StateError("lease_marker_invalid")
            previous = _marker(value)
            if previous == self.owner_build_id:
                self._generation, self._released = generation, False
                return True
            try:
                terminal = owner_terminal(previous)
            except Exception:
                raise StateError("lease_owner_state_unknown") from None
            if terminal is False:
                return False
            if terminal is not True:
                raise StateError("lease_owner_state_unknown")
        try:
            generation = self.store.put_json(
                self.name,
                {"schema_version": 1, "owner_build_id": self.owner_build_id},
                generation,
            )
        except ConflictError:
            return False
        self._generation, self._released = _generation(generation), False
        return True

    def assert_owned(self) -> None:
        if self._generation is None:
            raise StateError("lease_not_owned")
        value, generation = self.store.load_json(self.name)
        if (
            value is None
            or _marker(value) != self.owner_build_id
            or _generation(generation) != self._generation
        ):
            raise StateError("lease_not_owned")

    def release(self) -> None:
        if self._released:
            return
        self.assert_owned()
        generation = self._generation
        if generation is None:
            raise StateError("lease_not_owned")
        self.store.delete(self.name, generation)
        self._generation, self._released = None, True
