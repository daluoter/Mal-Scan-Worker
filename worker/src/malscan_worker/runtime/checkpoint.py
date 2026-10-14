"""Authenticated checkpoints issued only by trusted analysis executors.

Source manifests may come from upload clients; completed stage state must not.
The signing key is a private executor secret, never an artifact or report field.
Local runs keep it separately from the disposable state cache. Remote runners
must mount the same secret on every execution; granting clients write access to
result storage does not grant permission to manufacture a completed stage.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any


def canonical_state(state: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in state.items() if key != "checkpoint_hmac"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_state(state: dict[str, Any], secret: bytes) -> dict[str, Any]:
    signed = dict(state)
    signed["checkpoint_hmac"] = hmac.new(secret, canonical_state(state), hashlib.sha256).hexdigest()
    return signed


def verify_state(state: dict[str, Any], secret: bytes) -> None:
    supplied = state.get("checkpoint_hmac")
    expected = hmac.new(secret, canonical_state(state), hashlib.sha256).hexdigest()
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise ValueError("Checkpoint authentication failed; trusted executor state is required")


def load_secret(path: Path, *, create: bool = False, hexadecimal: bool = False) -> bytes:
    """Read a private, owner-controlled raw key or a mounted 64-hex cloud key."""
    if create:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise ValueError("Invalid checkpoint authentication file")
        if create and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
            raise ValueError("Local checkpoint key must be private and owned by this executor")
        secret = stream.read()
    if hexadecimal:
        text = secret.decode("ascii").strip()
        if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
            raise ValueError("Mounted checkpoint key must be 64 lowercase hexadecimal characters")
        secret = bytes.fromhex(text)
    if len(secret) < 32:
        raise ValueError("Checkpoint authentication requires at least 256 bits")
    return secret
