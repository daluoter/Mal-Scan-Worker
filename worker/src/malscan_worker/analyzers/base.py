"""Base classes for format-specific analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias, TypedDict

if TYPE_CHECKING:
    from malscan_worker.heuristics.models import HeuristicHit
    from malscan_worker.stages.base import StageContext

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class AnalyzerIndicator(TypedDict, total=False):
    """Structured indicator emitted by analyzers."""

    type: str
    severity: str
    detail: str
    evidence: JsonValue


class AnalyzerArtifact(TypedDict, total=False):
    """Structured extracted artifact metadata for downstream submission."""

    filename: str
    sha256: str
    size: int
    path: str
    source: str
    budget_key: str
    artifact_id: str
    analysis_state: str


@dataclass
class AnalyzerResult:
    """Standardized result from a format-specific analyzer."""

    analyzer_name: str
    format_type: str
    indicators: list[AnalyzerIndicator] = field(default_factory=list)
    features: dict[str, JsonValue] = field(default_factory=dict)
    extracted_strings: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)
    heuristics: list[HeuristicHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    extracted_artifacts: list[AnalyzerArtifact] = field(default_factory=list)


class FormatAnalyzer(ABC):
    """Base class for format-specific analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this analyzer."""
        ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this analyzer should process the file."""
        ...

    @abstractmethod
    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        """Run format-specific analysis and return standardized findings."""
        ...
