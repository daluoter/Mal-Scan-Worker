"""Base contract for deobfuscation decoders."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from malscan_worker.deobfuscation.models import DeobfuscationCandidate


@dataclass
class DecoderExtraction:
    """Candidates completed before a decoder exhausted its scan allowance."""

    candidates: list[DeobfuscationCandidate]
    stop_reason: Literal["candidate_cap", "wall_time"] | None = None


class DecoderBase(ABC):
    """Abstract decoder that extracts candidates from raw bytes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable decoder name used in provenance."""

    @abstractmethod
    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        """Return candidates discovered in input bytes."""

    def extract_candidates_guarded(
        self, content: bytes, limit: int, should_stop: Callable[[], bool]
    ) -> DecoderExtraction:
        """Allow cooperative scanning without changing existing decoder contracts."""
        return DecoderExtraction(self.extract_candidates(content, limit))
