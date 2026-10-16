"""YARA scanning stage using memory-resident yara-python."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yara

from malscan_worker.config import get_settings
from malscan_worker.rule_provenance import RuleBundle, load_rule_bundle
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()
log = structlog.get_logger()

# Global variable to hold compiled YARA rules
_compiled_rules = None
_rules_loaded = False
_rules_load_error: str | None = None
_rules_version: str | None = None
_rule_bundle: RuleBundle | None = None


def _load_yara_rules() -> yara.Rules | None:
    """Load and compile all YARA rules from the configured directory.

    This runs synchronously and should be called once during startup.
    """
    global _compiled_rules, _rules_loaded, _rules_load_error, _rules_version, _rule_bundle

    if _rules_loaded:
        return _compiled_rules

    _rule_bundle = None
    _rules_load_error = None
    _rules_version = None
    try:
        _rule_bundle = load_rule_bundle(Path(settings.yara_rules_path))
        _compiled_rules = _rule_bundle.rules
        _rules_version = _rule_bundle.rules_sha256
        if _compiled_rules is None:
            log.warning("no_yara_rules_found", path=settings.yara_rules_path)
        else:
            log.info(
                "yara_rules_compiled_successfully",
                provenance_status=_rule_bundle.provenance["status"],
            )
    except Exception as e:
        log.error("yara_rules_compile_failed", error=str(e))
        _compiled_rules = None
        _rules_load_error = "YARA rule compilation failed"

    _rules_loaded = True
    return _compiled_rules


def _provenance() -> dict[str, Any]:
    if _rule_bundle is None:
        return {"status": "unverified", "reason": "rules_not_loaded"}
    return _rule_bundle.provenance


class YaraStage(Stage):
    """Scan file with memory-resident YARA rules."""

    @property
    def name(self) -> str:
        return "yara"

    def __init__(self) -> None:
        # Trigger compilation on instantiation (which happens once at worker start)
        _load_yara_rules()

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            rules = _load_yara_rules()

            if rules is None:
                # No rules available - skip
                ended_at = datetime.now(timezone.utc)
                duration_ms = int((ended_at - started_at).total_seconds() * 1000)
                return StageResult(
                    stage_name=self.name,
                    status="failed" if _rules_load_error else "skipped",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    findings={
                        "matches": [],
                        "reason": _rules_load_error or "No YARA rules configured",
                        "rule_provenance": _provenance(),
                    },
                    artifacts=[],
                    error=_rules_load_error,
                    tool_version=getattr(yara, "__version__", None),
                    rules_version=_rules_version,
                )

            # Run yara scan (offload to thread pool to avoid blocking async loop)
            loop = asyncio.get_event_loop()
            # Cancelling an asyncio executor future cannot stop native YARA.
            # Bound the native operation as well as the outer stage coroutine.
            timeout_seconds = max(1, int(settings.stage_timeout_seconds))
            yara_matches = await loop.run_in_executor(
                None, lambda: rules.match(str(ctx.file_path), timeout=timeout_seconds)
            )

            matches: list[dict[str, Any]] = []

            for match in yara_matches:
                # Extract meta
                meta_dict = match.meta

                # Extract matching strings
                strings_list = []
                for s in match.strings:
                    # s is a yara.StringMatch object
                    string_id = getattr(s, "identifier", "")
                    # decode to string or keep as repr if it's binary
                    if string_id not in strings_list:
                        strings_list.append(string_id)

                matches.append(
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "description": meta_dict.get("description", ""),
                        "classification": meta_dict.get("classification", "generic"),
                        "confidence": meta_dict.get("confidence", "medium"),
                        "family": meta_dict.get("family", ""),
                        "severity": meta_dict.get("severity", "medium"),
                        "author": meta_dict.get("author", ""),
                        "tags": match.tags,
                        "strings": strings_list,
                        "provenance": (
                            _rule_bundle.match_provenance(match.namespace, match.rule)
                            if _rule_bundle is not None
                            else {"status": "unverified", "reason": "rules_not_loaded"}
                        ),
                    }
                )

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={"matches": matches, "rule_provenance": _provenance()},
                artifacts=[],
                error=None,
                tool_version=getattr(yara, "__version__", None),
                rules_version=_rules_version,
            )

        except Exception as e:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={"rule_provenance": _provenance()},
                artifacts=[],
                error=str(e),
                tool_version=getattr(yara, "__version__", None),
                rules_version=_rules_version,
            )
