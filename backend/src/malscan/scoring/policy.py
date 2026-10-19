"""Shared scoring policy constants."""

from types import MappingProxyType

LEVEL_THRESHOLDS = MappingProxyType(
    {
        "clean": (0, 9),
        "low": (10, 29),
        "medium": (30, 59),
        "high": (60, 84),
        "malicious": (85, 100),
    }
)

LEGACY_VERDICT_MAP = MappingProxyType(
    {
        "clean": "clean",
        "low": "suspicious",
        "medium": "suspicious",
        "high": "suspicious",
        "malicious": "malicious",
    }
)

INHERITANCE_BASE = MappingProxyType(
    {
        "malicious": 35,
        "high": 25,
        "medium": 15,
        "low": 6,
        "clean": 0,
    }
)

DEPTH_DECAY = MappingProxyType(
    {
        1: 1.00,
        2: 0.70,
        3: 0.50,
    }
)

WEAK_ONLY_CAP = 29
NO_HIGH_GATE_CAP = 59
NO_MALICIOUS_GATE_CAP = 84
CAP_GROUP_LIMITS = MappingProxyType(
    {
        "ioc_raw": 15,
        "deob": 20,
        "heuristic_entropy": 12,
        "heuristic_packer": 18,
        "heuristic_api": 35,
        "heuristic_structure": 20,
        "heuristic_resource": 30,
        "heuristic_script": 30,
        "heuristic_lolbin": 25,
        "heuristic_archive": 25,
    }
)
PURE_DEOB_CAP = 20
INHERITED_SCORE_CAP = 40
SYNERGY_CAP = 15
POLICY_VERSION = "msrs-v1.2"
