"""Shared scoring dataclasses."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from malscan.scoring.policy import POLICY_VERSION


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    kind: str
    tier: str
    severity: str
    confidence: float
    points: int
    cap_group: str
    scope: str
    artifact_id: str | None
    related_artifact_id: str | None
    depth: int
    reason: str
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)
    stage: str | None = None
    analyzer: str | None = None
    score_contribution: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", MappingProxyType(dict(self.raw)))
        object.__setattr__(
            self, "score_contribution", MappingProxyType(dict(self.score_contribution))
        )


@dataclass
class ScoreBreakdown:
    local_score: int = 0
    inherited_score: int = 0
    descendant_floor: int = 0
    synergy_bonus: int = 0
    dampener: int = 0
    final_score: int = 0
    malicious_gate_open: bool = False
    high_gate_open: bool = False
    independent_source_count: int = 0


@dataclass
class RiskDecision:
    risk_score: int
    risk_level: str
    legacy_verdict: str
    evidence: list[EvidenceRecord]
    top_evidence: list[EvidenceRecord]
    breakdown: ScoreBreakdown
    descendant_summary: dict[str, Any] = field(default_factory=dict)
    policy_version: str = POLICY_VERSION
    score_trace: dict[str, Any] = field(default_factory=dict)
