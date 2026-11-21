"""Single-byte XOR decoder for extracting deobfuscation candidates."""

from __future__ import annotations

from collections import Counter
from math import isfinite, log2

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate


class XorDecoder(DecoderBase):
    """Extract plaintext candidates from single-byte XOR obfuscated blobs."""

    def __init__(
        self,
        *,
        min_decoded_length: int = 8,
        min_printable_ratio: float = 0.85,
        min_blob_entropy: float = 3.0,
        max_blob_entropy: float = 7.95,
    ) -> None:
        if min_decoded_length < 0:
            raise ValueError("min_decoded_length must be >= 0")

        if not (0.0 <= min_printable_ratio <= 1.0):
            raise ValueError("min_printable_ratio must be between 0 and 1")

        entropy_values = (min_blob_entropy, max_blob_entropy)
        if not all(isfinite(value) for value in entropy_values):
            raise ValueError("entropy thresholds must be finite")
        if not (0.0 <= min_blob_entropy <= max_blob_entropy <= 8.0):
            raise ValueError("entropy thresholds must satisfy 0 <= min <= max <= 8")

        self._min_decoded_length = min_decoded_length
        self._min_printable_ratio = min_printable_ratio
        self._min_blob_entropy = min_blob_entropy
        self._max_blob_entropy = max_blob_entropy

    @property
    def name(self) -> str:
        return "xor"

    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        if limit <= 0 or not content or len(content) < self._min_decoded_length:
            return []

        blob_entropy = self._shannon_entropy(content)
        if not (self._min_blob_entropy <= blob_entropy <= self._max_blob_entropy):
            return []

        candidates: list[DeobfuscationCandidate] = []
        seen_plaintexts: set[bytes] = set()

        for key in self._candidate_keys(content):
            decoded = bytes(byte ^ key for byte in content)
            if decoded in seen_plaintexts:
                continue
            if not self._passes_printable_filter(decoded):
                continue
            if not self._looks_meaningful(decoded):
                continue

            seen_plaintexts.add(decoded)
            candidates.append(
                DeobfuscationCandidate(
                    content=decoded,
                    confidence=self._estimate_confidence(decoded),
                    provenance=CandidateProvenance(
                        decoder=self.name,
                        offset=0,
                        length=len(content),
                        key=f"0x{key:02x}",
                        meta={"blob_entropy": round(blob_entropy, 3)},
                    ),
                )
            )
            if len(candidates) >= limit:
                break

        return candidates

    def _candidate_keys(self, content: bytes) -> list[int]:
        common_keys = [
            0x01,
            0x0F,
            0x10,
            0x13,
            0x20,
            0x23,
            0x2A,
            0x3A,
            0x55,
            0x5A,
            0x69,
            0x7F,
            0x80,
            0x90,
            0xAA,
            0xC3,
            0xFF,
        ]

        most_frequent_byte, _ = Counter(content).most_common(1)[0]
        heuristic_keys = {
            most_frequent_byte ^ ord(" "),
            most_frequent_byte ^ ord("e"),
            most_frequent_byte ^ ord("t"),
            most_frequent_byte ^ ord("a"),
            most_frequent_byte ^ ord("/"),
            most_frequent_byte ^ ord(":"),
        }

        ordered: list[int] = []
        seen: set[int] = set()
        for key in [*common_keys, *sorted(heuristic_keys)]:
            key &= 0xFF
            # A zero key returns the input unchanged. Plaintext URLs and
            # keywords would otherwise count as decoded XOR evidence.
            if key == 0 or key in seen:
                continue
            ordered.append(key)
            seen.add(key)
        return ordered

    def _passes_printable_filter(self, data: bytes) -> bool:
        if not data:
            return False
        printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
        return (printable / len(data)) >= self._min_printable_ratio

    @staticmethod
    def _looks_meaningful(data: bytes) -> bool:
        lowered = data.lower()
        strong_signals = (
            b"http",
            b"://",
            b"www.",
        )
        if any(token in lowered for token in strong_signals):
            return True

        weak_signals = (
            b"powershell",
            b"cmd",
            b"invoke",
            b"download",
        )
        if not any(token in lowered for token in weak_signals):
            return False

        letters = sum(1 for byte in data if 65 <= byte <= 90 or 97 <= byte <= 122)
        return (letters / len(data)) >= 0.5

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * log2(count / total) for count in counts.values())

    @staticmethod
    def _estimate_confidence(decoded: bytes) -> float:
        lowered = decoded.lower()
        if any(token in lowered for token in (b"http://", b"https://", b"://", b"www.")):
            return 0.9

        strong_keywords = (
            b"powershell",
            b"cmd",
            b"invoke",
            b"download",
        )
        if any(token in lowered for token in strong_keywords):
            return 0.75
        return 0.6
