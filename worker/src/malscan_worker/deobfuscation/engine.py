"""Deobfuscation orchestration engine and IOC extraction."""

from __future__ import annotations

import math
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import (
    DeobfuscationCandidate,
    DeobfuscationResult,
    DeobfuscationRunStats,
)
from malscan_worker.deobfuscation.safety import DeobfuscationSafetyGuard

_URL_RE = re.compile(r"https?://[A-Za-z0-9][A-Za-z0-9.-]*(?:/[^\s\"'<>]*)?", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b(?:(?:\d{1,3})\.){3}(?:\d{1,3})\b")
_COMMAND_RE = re.compile(
    r"(?im)\b(?:cmd(?:\.exe)?\s*/c\s+[^\r\n]+|powershell(?:\.exe)?\s+[^\r\n]+|bash\s+-c\s+[^\r\n]+|sh\s+-c\s+[^\r\n]+)",
)


class DeobfuscationEngine:
    """Run decoders in order and aggregate deobfuscation output."""

    def __init__(
        self,
        *,
        decoders: list[DecoderBase],
        max_candidates: int,
        per_decoder_limit: int,
        confidence_threshold: float,
        max_wall_time_seconds: float,
    ) -> None:
        if max_candidates < 0:
            raise ValueError("max_candidates must be >= 0")
        if per_decoder_limit < 0:
            raise ValueError("per_decoder_limit must be >= 0")
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if max_wall_time_seconds < 0 or not math.isfinite(max_wall_time_seconds):
            raise ValueError("max_wall_time_seconds must be finite and >= 0")

        self._decoders = decoders
        self._max_candidates = max_candidates
        self._per_decoder_limit = per_decoder_limit
        self._confidence_threshold = confidence_threshold
        self._max_wall_time_seconds = max_wall_time_seconds

    def run(self, content: bytes) -> DeobfuscationResult:
        guard = DeobfuscationSafetyGuard(
            max_candidates=self._max_candidates,
            max_wall_time_seconds=self._max_wall_time_seconds,
        )
        stats = DeobfuscationRunStats(input_bytes=len(content))

        raw_candidates: list[DeobfuscationCandidate] = []
        per_decoder_counts: dict[str, int] = {}
        decoder_cap_reached = False

        for decoder in self._decoders:
            if guard.should_stop():
                break

            decoder_name = decoder.name
            stats.applied_decoders.append(decoder_name)
            if self._per_decoder_limit <= 0:
                per_decoder_counts[decoder_name] = 0
                continue

            extraction = decoder.extract_candidates_guarded(
                content, self._per_decoder_limit, guard.should_stop
            )
            decoder_cap_reached |= extraction.stop_reason == "candidate_cap"
            accepted = 0
            if extraction.stop_reason == "wall_time":
                # These candidates completed before the cooperative deadline.
                # Preserve them within the global cap and report incomplete work.
                remaining = max(0, self._max_candidates - len(raw_candidates))
                completed = extraction.candidates[:remaining]
                raw_candidates.extend(completed)
                per_decoder_counts[decoder_name] = len(completed)
                guard.stop_reason = "wall_time"
                break
            for candidate in extraction.candidates:
                if not guard.try_register_candidate():
                    break
                raw_candidates.append(candidate)
                accepted += 1

            per_decoder_counts[decoder_name] = accepted

        stats.raw_candidate_count = len(raw_candidates)
        deduped_candidates = self._dedupe_candidates(raw_candidates)
        stats.deduplicated_candidate_count = len(deduped_candidates)

        filtered_candidates = [
            candidate
            for candidate in deduped_candidates
            if candidate.confidence >= self._confidence_threshold
        ]
        stats.filtered_low_confidence_count = len(deduped_candidates) - len(filtered_candidates)
        stats.final_candidate_count = len(filtered_candidates)
        stats.per_decoder_candidate_counts = per_decoder_counts
        stats.stop_reason = guard.stop_reason or ("candidate_cap" if decoder_cap_reached else None)
        stats.candidate_cap_reached = stats.stop_reason == "candidate_cap"
        stats.wall_time_reached = stats.stop_reason == "wall_time"
        stats.truncated = stats.candidate_cap_reached or stats.wall_time_reached

        if stats.candidate_cap_reached and filtered_candidates:
            filtered_candidates[-1].truncated = True

        iocs = self.extract_iocs(filtered_candidates)
        return DeobfuscationResult(candidates=filtered_candidates, iocs=iocs, stats=stats)

    def extract_iocs(self, candidates: list[DeobfuscationCandidate]) -> dict[str, list[str]]:
        urls: list[str] = []
        domains: list[str] = []
        ips: list[str] = []
        commands: list[str] = []

        for candidate in candidates:
            text = candidate.content.decode("utf-8", errors="ignore")

            for match in _URL_RE.findall(text):
                self._append_unique(urls, match)

            for match in _DOMAIN_RE.findall(text):
                lowered = match.lower()
                if lowered.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1")):
                    continue
                self._append_unique(domains, lowered)

            for match in _IP_RE.findall(text):
                if self._is_valid_ipv4(match):
                    self._append_unique(ips, match)

            for match in _COMMAND_RE.findall(text):
                self._append_unique(commands, match.strip())

        return {
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "commands": commands,
        }

    @staticmethod
    def _dedupe_candidates(
        candidates: list[DeobfuscationCandidate],
    ) -> list[DeobfuscationCandidate]:
        deduped_by_content: dict[bytes, DeobfuscationCandidate] = {}
        order: list[bytes] = []

        for candidate in candidates:
            existing = deduped_by_content.get(candidate.content)
            if existing is None:
                deduped_by_content[candidate.content] = candidate
                order.append(candidate.content)
                continue

            if candidate.confidence > existing.confidence:
                deduped_by_content[candidate.content] = candidate

        return [deduped_by_content[key] for key in order]

    @staticmethod
    def _append_unique(target: list[str], value: str) -> None:
        if value and value not in target:
            target.append(value)

    @staticmethod
    def _is_valid_ipv4(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
