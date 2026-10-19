"""Decode Base64 while distinguishing useful evidence from ambiguous observations."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from typing import Any, Literal

from malscan_worker.deobfuscation.decoders.base import DecoderBase, DecoderExtraction
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_BASE64_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{4,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_DECODER_CALL_RE = re.compile(
    rb"\b(?:atob|b64decode|base64_decode|decodebytes|frombase64string|decode64)\s*\(\s*(?:[br]{0,2})?['\"]?\s*$",
    re.IGNORECASE,
)
_BINARY_PREFIXES = (
    b"MZ",
    b"\x7fELF",
    b"PK\x03\x04",
    b"%PDF-",
    b"\x1f\x8b",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
)
ASSESSMENT_VERSION = "base64-evidence-v1"


class Base64Decoder(DecoderBase):
    """Keep opaque decodes as observations, with stronger candidates first."""

    @property
    def name(self) -> str:
        return "base64"

    def __init__(self, min_decoded_length: int = 8) -> None:
        self._min_decoded_length = min_decoded_length

    def extract_candidates(self, content: bytes, limit: int) -> list[DeobfuscationCandidate]:
        return self.extract_candidates_guarded(content, limit, lambda: False).candidates

    def extract_candidates_guarded(
        self, content: bytes, limit: int, should_stop: Callable[[], bool]
    ) -> DecoderExtraction:
        if limit <= 0:
            return DecoderExtraction([])
        evidence: dict[bytes, DeobfuscationCandidate] = {}
        observations: dict[bytes, DeobfuscationCandidate] = {}
        omitted = False
        stopped = False
        for match in _BASE64_TOKEN_RE.finditer(content):
            if should_stop():
                stopped = True
                break
            token = match.group(0)
            decoded = self._decode_token(token)
            if decoded is None or len(decoded) < self._min_decoded_length:
                continue
            assessment = self._assess(
                token, decoded, content[max(0, match.start() - 128) : match.start()]
            )
            eligible = assessment["score_eligible"] is True
            if not eligible and not any(char in token for char in (b"+", b"/", b"=", b"-", b"_")):
                # Ordinary words also fit the alphabet. Decoder context and
                # recognizable content can still justify an unpadded token.
                continue
            # Unique payloads share the allowance. Repeated names cannot crowd
            # out useful evidence; explicit decoder context upgrades an observation.
            if decoded in evidence or (not eligible and decoded in observations):
                continue
            target = evidence if eligible else observations
            if len(target) >= limit:
                omitted = True
                if eligible:
                    break
                continue
            if eligible:
                observations.pop(decoded, None)
            confidence = self._estimate_confidence(decoded)
            if eligible:
                confidence = max(confidence, 0.8)
            target[decoded] = DeobfuscationCandidate(
                content=decoded,
                confidence=confidence,
                tags=[] if eligible else ["context_only", "ambiguous_base64"],
                provenance=CandidateProvenance(
                    decoder=self.name,
                    offset=match.start(),
                    length=len(token),
                    meta=assessment,
                ),
            )
        candidates = list(evidence.values()) + list(observations.values())
        omitted = omitted or len(candidates) > limit
        reason: Literal["candidate_cap", "wall_time"] | None = (
            "wall_time" if stopped else "candidate_cap" if omitted else None
        )
        return DecoderExtraction(candidates[:limit], reason)

    @staticmethod
    def _decode_token(token: bytes) -> bytes | None:
        normalized = token.replace(b"-", b"+").replace(b"_", b"/")
        remainder = len(normalized) % 4
        if remainder == 1:
            return None
        if remainder:
            normalized += b"=" * (4 - remainder)
        try:
            decoded = base64.b64decode(normalized, validate=True)
        except (ValueError, binascii.Error):
            return None
        return decoded

    @staticmethod
    def _looks_textual_candidate(decoded: bytes) -> bool:
        if not decoded:
            return False
        encodings = ["utf-8"]
        if len(decoded) % 2 == 0 and (
            decoded.startswith((b"\xff\xfe", b"\xfe\xff"))
            or decoded.count(b"\0") >= len(decoded) // 4
        ):
            encodings.extend(["utf-16", "utf-16-le", "utf-16-be"])
        for encoding in encodings:
            try:
                text = decoded.decode(encoding, errors="strict")
            except UnicodeError:
                continue
            printable = sum(char.isprintable() or char in "\t\r\n" for char in text)
            if (
                text
                and printable / len(text) >= 0.85
                and any(
                    char in text
                    for char in (":", "/", ".", "@", " ", "(", ")", ";", "{", "}", "=", "\n")
                )
            ):
                return True
        return False

    @staticmethod
    def _assess(token: bytes, decoded: bytes, prefix: bytes) -> dict[str, Any]:
        normalized = token.replace(b"-", b"+").replace(b"_", b"/")
        canonical = base64.b64encode(decoded).rstrip(b"=") == normalized.rstrip(b"=")
        if _DECODER_CALL_RE.search(prefix):
            evidence_class = "decoder_call_hint"
            reason = (
                "Encoded bytes occur in a recognizable decoder-call context; "
                "this is not execution proof."
            )
        elif Base64Decoder._looks_textual_candidate(decoded):
            evidence_class = "decoded_text"
            reason = (
                "Decoded content has readable text structure. "
                "Encoding alone does not imply malware."
            )
        elif decoded.startswith(_BINARY_PREFIXES):
            evidence_class = "binary_signature"
            reason = (
                "Decoded bytes start with a recognized file signature; "
                "this is not a malware detection."
            )
        else:
            evidence_class = "ambiguous_encoding"
            reason = (
                "Decodable bytes without text, file signature or decoder context "
                "are retained as an unscored observation."
            )
        return {
            "assessment_version": ASSESSMENT_VERSION,
            "canonical_encoding": canonical,
            "padding_added": (4 - len(normalized) % 4) % 4,
            "evidence_class": evidence_class,
            "score_eligible": evidence_class != "ambiguous_encoding",
            "assessment_reason": reason,
        }

    @staticmethod
    def _estimate_confidence(decoded: bytes) -> float:
        lowered = decoded.lower()
        if any(token in lowered for token in (b"http://", b"https://", b"://", b"www.")):
            return 0.9
        return 0.75 if Base64Decoder._looks_textual_candidate(decoded) else 0.6
