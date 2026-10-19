"""Persistent, resumable root-batch adapter for the existing static engine."""

from __future__ import annotations

import asyncio
import fcntl
import json
import re
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid5

from malscan.analysis_contract import (
    REPORT_SCHEMA_VERSION,
    analysis_from_report,
    summarize_static_artifacts,
)
from malscan.report_explainability import build_explainability
from malscan.scoring.adapters import build_direct_evidence
from malscan.scoring.engine import score_direct_evidence
from malscan.scoring.tree import apply_descendant_risk

from malscan_worker.budget import BudgetExceeded, BudgetLimits, InMemoryRootBudget
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.reporting import build_password_attempts_exhausted_report
from malscan_worker.runtime.checkpoint import load_secret, sign_state, verify_state
from malscan_worker.runtime.dispatch import BatchDispatcher
from malscan_worker.runtime.manifest import AnalysisManifest, file_identity
from malscan_worker.runtime.ports import ObjectStore
from malscan_worker.runtime.store import LocalObjectStore, atomic_json
from malscan_worker.stages.base import StageContext, StageResult


def _stage_document(result: StageResult) -> dict[str, Any]:
    document = asdict(result)
    document["started_at"] = result.started_at.isoformat()
    document["ended_at"] = result.ended_at.isoformat()
    return document


def _stage_result(document: dict[str, Any]) -> StageResult:
    data = dict(document)
    data["started_at"] = datetime.fromisoformat(data["started_at"])
    data["ended_at"] = datetime.fromisoformat(data["ended_at"])
    return StageResult(**data)


class RootBatchRunner:
    """Run a root and all derived artifacts through the shared stage executor.

    Passwords only live in memory. Checkpoints contain verified artifact object
    references and completed stage results, so reconnecting never needs a Docker
    daemon cache and does not rerun finished stages after a password wait.
    """

    def __init__(
        self,
        *,
        manifest: AnalysisManifest,
        source_store: ObjectStore,
        result_store: ObjectStore,
        state_dir: Path,
        limits: BudgetLimits | None = None,
        max_depth: int = 3,
        passwords: dict[str, str] | None = None,
        password_attempts_by_artifact: dict[str, int] | None = None,
        password_attempt_limit: int | None = None,
        checkpoint_key: str | None = None,
        parallel_stages: list[Any] | None = None,
        format_stage: Any = None,
        sequential_stages: list[Any] | None = None,
        checkpoint_secret: bytes | None = None,
        on_report: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ):
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
            raise ValueError("Max depth must be non-negative")
        self.manifest = manifest
        self.source_store = source_store
        self.result_store = result_store
        self.state_dir = state_dir.resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if checkpoint_secret is None:
            if not isinstance(result_store, LocalObjectStore):
                raise ValueError("Remote checkpoints require a mounted executor authentication key")
            checkpoint_secret = load_secret(result_store.root / ".checkpoint-auth.key", create=True)
        if not isinstance(checkpoint_secret, bytes) or len(checkpoint_secret) < 32:
            raise ValueError("Checkpoint authentication requires at least 256 bits")
        self.checkpoint_secret = checkpoint_secret
        self.on_report = on_report
        self.checkpoint_path = self.state_dir / "checkpoint.json"
        self.checkpoint_key = checkpoint_key or (
            f"checkpoints/{manifest.root_job_id}/{manifest.attempt_id}.json"
        )
        self.budget = InMemoryRootBudget(limits or BudgetLimits())
        self.max_depth = max_depth
        self.passwords = passwords or {}
        if password_attempts_by_artifact is not None:
            if (
                not isinstance(password_attempt_limit, int)
                or password_attempt_limit != 3
                or any(
                    not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 3
                    for count in password_attempts_by_artifact.values()
                )
            ):
                raise ValueError("Invalid per-file password attempt policy")
        elif password_attempt_limit is not None:
            raise ValueError("Password attempt counts are required")
        self.password_attempts_by_artifact = dict(password_attempts_by_artifact or {})
        self.password_attempt_limit = password_attempt_limit
        self.dispatcher = BatchDispatcher()
        self.parallel_stages = parallel_stages
        self.format_stage = format_stage
        self.sequential_stages = sequential_stages
        self.state: dict[str, Any] = {}
        self._state_lock = asyncio.Lock()

    @property
    def artifacts(self) -> dict[str, dict[str, Any]]:
        return cast(dict[str, dict[str, Any]], self.state["artifacts"])

    async def _save(self) -> None:
        self.state["budget"] = (await self.budget.snapshot()).to_dict()
        self.state["updated_at"] = datetime.now(timezone.utc).isoformat()
        signed = sign_state(self.state, self.checkpoint_secret)
        await asyncio.to_thread(atomic_json, self.checkpoint_path, signed)
        # A published checkpoint is independent of the execution container's disk.
        await self.result_store.put_json(self.checkpoint_key, signed)

    async def _load(self, resume: bool) -> None:
        if self.checkpoint_path.exists():
            if not resume:
                raise ValueError("Existing checkpoint requires --resume")
            self.state = json.loads(self.checkpoint_path.read_text())
        elif resume:
            self.state = await self.result_store.read_json(self.checkpoint_key)
        else:
            self.state = {
                "checkpoint_version": 2,
                "manifest": self.manifest.to_dict(),
                "manifest_sha256": self.manifest.fingerprint,
                "report_revision": 0,
                "artifacts": {},
                "max_depth": self.max_depth,
                "stage_names": self._stage_names(),
            }
            source = self.manifest.source
            with tempfile.TemporaryDirectory(prefix="malscan-source-", dir=self.state_dir) as tmp:
                path = await self.source_store.fetch(
                    source.key,
                    Path(tmp) / "input.bin",
                    sha256=source.sha256,
                    size=source.size,
                )
                key = f"artifacts/{self.manifest.root_job_id}/sha256/{source.sha256}"
                await self.result_store.put_file(key, path, sha256=source.sha256, size=source.size)
            self.artifacts[self.manifest.root_job_id] = {
                "artifact_id": self.manifest.root_job_id,
                "parent_id": None,
                "root_id": self.manifest.root_job_id,
                "depth": 0,
                "sha256": source.sha256,
                "size": source.size,
                "storage_key": key,
                "original_filename": source.filename,
                "origin_path": None,
                "extraction_source": "upload",
                "archive_type": None,
                "ancestor_hashes": [],
                "status": "queued",
                "stage_results": [],
                "report": None,
            }
        if resume:
            verify_state(self.state, self.checkpoint_secret)
            self.state.pop("checkpoint_hmac", None)
        if self.state.get("checkpoint_version") != 2:
            raise ValueError("Unsupported checkpoint")
        if self.state.get("manifest_sha256") != self.manifest.fingerprint:
            raise ValueError("Checkpoint belongs to a different source or attempt")
        if self.state.get("manifest") != self.manifest.to_dict():
            raise ValueError("Checkpoint manifest mismatch")
        if resume:
            stored = self.state["budget"]
            current = self.budget.limits
            incoming_deadline = self.budget.deadline_at
            stored_limits = BudgetLimits(**stored["limits"])
            stored["limits"] = asdict(
                BudgetLimits(
                    min(current.max_files, stored_limits.max_files),
                    min(current.max_bytes, stored_limits.max_bytes),
                    min(current.timeout_seconds, stored_limits.timeout_seconds),
                )
            )
            self.budget = InMemoryRootBudget.from_snapshot(stored, new_attempt=True)
            # Fetching and authenticating the checkpoint spend the incoming
            # attempt's time window. Retention may set a tighter deadline than
            # the persisted timeout, so restore must never extend that window.
            self.budget.deadline_at = min(self.budget.deadline_at, incoming_deadline)
            self.max_depth = min(self.max_depth, int(self.state["max_depth"]))
            self.state["max_depth"] = self.max_depth
        if self.manifest.root_job_id not in self.artifacts:
            raise ValueError("Checkpoint root is missing")
        if self.state.get("stage_names") != self._stage_names():
            raise ValueError("Checkpoint stage identity differs from this executor")
        root = self.artifacts[self.manifest.root_job_id]
        if (root["sha256"], root["size"], root["parent_id"], root["depth"]) != (
            self.manifest.source.sha256,
            self.manifest.source.size,
            None,
            0,
        ):
            raise ValueError("Checkpoint source identity mismatch")
        for artifact in sorted(
            self.artifacts.values(),
            key=lambda item: (
                item["depth"],
                item.get("origin_path") or "",
                item["artifact_id"],
            ),
        ):
            artifact_id = artifact["artifact_id"]
            if str(UUID(artifact_id)) != artifact_id or artifact.get("artifact_id") != artifact_id:
                raise ValueError("Invalid checkpoint artifact identity")
            if (
                artifact["storage_key"]
                != (f"artifacts/{self.manifest.root_job_id}/sha256/{artifact['sha256']}")
                or artifact["root_id"] != self.manifest.root_job_id
            ):
                raise ValueError("Checkpoint artifact storage is outside this root")
            names = [item["stage_name"] for item in artifact["stage_results"]]
            if len(set(names)) != len(names) or any(
                name not in self._stage_names() for name in names
            ):
                raise ValueError("Invalid checkpoint stage identity")
            if artifact["status"] == "done" and set(names) != set(self._stage_names()):
                raise ValueError("Checkpoint completion lacks required stages")
            if artifact["parent_id"] is not None:
                parent = self.artifacts.get(artifact["parent_id"])
                if parent is None or artifact["depth"] != parent["depth"] + 1:
                    raise ValueError("Invalid checkpoint lineage")
            if artifact["status"] in {"queued", "running"}:
                if artifact["depth"] > self.max_depth:
                    artifact["status"], artifact["reason"] = "limited", "max_depth"
                else:
                    self.dispatcher.dispatch(artifact_id)
            elif artifact["status"] == "password_required" and artifact_id in self.passwords:
                if artifact["depth"] > self.max_depth:
                    artifact["status"], artifact["reason"] = "limited", "max_depth"
                else:
                    artifact["status"] = "queued"
                    self.dispatcher.dispatch(artifact_id)
        await self._save()

    def _stage_names(self) -> list[str]:
        from malscan_worker.pipeline import (
            FORMAT_ANALYSIS_STAGE,
            PARALLEL_STAGES,
            SEQUENTIAL_STAGES,
        )

        parallel = PARALLEL_STAGES if self.parallel_stages is None else self.parallel_stages
        sequential = SEQUENTIAL_STAGES if self.sequential_stages is None else self.sequential_stages
        formatter = self.format_stage or FORMAT_ANALYSIS_STAGE
        return [stage.name for stage in [*parallel, formatter, *sequential]]

    async def submit_child(
        self,
        *,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job_id: str,
        parent_job_depth: int,
        artifact_id: str | None = None,
        root_artifact_id: str | None = None,
        root_job_id: str | None = None,
        ancestor_hashes: set[str] | None = None,
        origin_path: str | None = None,
        extraction_source: str | None = None,
        archive_type: str | None = None,
        occurrence_index: int | None = None,
    ) -> str | None:
        if occurrence_index is None:
            occurrence_index = 0
        if (
            isinstance(occurrence_index, bool)
            or not isinstance(occurrence_index, int)
            or occurrence_index < 0
        ):
            raise ValueError("Child occurrence index must be a non-negative integer")
        parent = self.artifacts[parent_job_id]
        if parent_job_depth != parent["depth"]:
            raise ValueError("Child parent depth mismatch")
        source_path = Path(file_path)
        if await asyncio.to_thread(file_identity, source_path) != (sha256_hash, file_size):
            raise ValueError("Derived artifact identity mismatch")
        identity = json.dumps(
            [
                parent_job_id,
                extraction_source,
                origin_path or filename,
                sha256_hash,
                occurrence_index,
            ],
            separators=(",", ":"),
        )
        child_id = str(uuid5(UUID(self.manifest.root_job_id), identity))
        async with self._state_lock:
            if child_id in self.artifacts:
                return child_id
            key = f"artifacts/{self.manifest.root_job_id}/sha256/{sha256_hash}"
            await self.result_store.put_file(
                key,
                source_path,
                sha256=sha256_hash,
                size=file_size,
                content_type=content_type,
            )
            ancestors = set(parent["ancestor_hashes"]) | {parent["sha256"]}
            depth = parent["depth"] + 1
            status = "queued"
            reason = None
            if sha256_hash in ancestors:
                status, reason = "limited", "recursive_content_cycle"
            elif depth > self.max_depth:
                status, reason = "limited", "max_depth"
            self.artifacts[child_id] = {
                "artifact_id": child_id,
                "parent_id": parent_job_id,
                "root_id": self.manifest.root_job_id,
                "depth": depth,
                "sha256": sha256_hash,
                "size": file_size,
                "storage_key": key,
                "original_filename": filename,
                "origin_path": origin_path or filename,
                "extraction_source": extraction_source,
                "archive_type": archive_type,
                "occurrence_index": occurrence_index,
                "ancestor_hashes": sorted(ancestors),
                "status": status,
                "reason": reason,
                "stage_results": [],
                "report": None,
            }
            if status == "queued":
                self.dispatcher.dispatch(child_id)
            await self._save()
            return child_id

    async def _analyze(self, artifact: dict[str, Any]) -> None:
        work = self.state_dir / "work" / artifact["artifact_id"]
        try:
            remaining = (self.budget.deadline_at - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                raise TimeoutError
            await asyncio.wait_for(self._analyze_work(artifact), timeout=remaining)
        except TimeoutError:
            artifact["status"] = "limited"
            artifact["reason"] = "analysis_attempt_deadline"
        finally:
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(Path("/tmp") / artifact["artifact_id"], ignore_errors=True)
            await self._save()

    async def _analyze_work(self, artifact: dict[str, Any]) -> None:
        # Import lazily: CLI help and object-store use require no service settings.
        from malscan_worker.pipeline import build_analysis_result, execute_analysis_stages

        artifact_id = artifact["artifact_id"]
        work = self.state_dir / "work" / artifact_id
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Analyzer detection may use the original extension (not only magic).
        suffix = Path(artifact["original_filename"]).suffix
        if not re.fullmatch(r"\.[a-zA-Z0-9]{1,16}", suffix):
            suffix = ".bin"
        path = await self.result_store.fetch(
            artifact["storage_key"],
            work / f"input{suffix}",
            sha256=artifact["sha256"],
            size=artifact["size"],
        )
        ctx = StageContext(
            job_id=artifact_id,
            file_id=artifact_id,
            storage_key=artifact["storage_key"],
            sha256=artifact["sha256"],
            original_filename=artifact["original_filename"],
            file_path=path,
            archive_password=self.passwords.get(artifact_id),
            artifact_id=artifact_id,
            root_artifact_id=self.manifest.root_job_id,
            root_job_id=self.manifest.root_job_id,
            ancestor_hashes=set(artifact["ancestor_hashes"]),
            analysis_services=self,
            root_budget=self.budget,
            depth=artifact["depth"],
        )
        initial = [
            _stage_result(document)
            for document in artifact["stage_results"]
            if document["status"] != "password_required"
        ]
        started_at = datetime.now(timezone.utc)
        artifact["status"] = "running"
        artifact.pop("reason", None)

        async def checkpoint(results: list[StageResult]) -> None:
            artifact["stage_results"] = [_stage_document(result) for result in results]
            artifact["report"] = build_analysis_result(
                artifact_id,
                artifact_id,
                ctx,
                results,
                int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000),
            )
            await self._save()
            await self._publish_report()

        try:
            results = await execute_analysis_stages(
                ctx,
                initial_results=initial,
                on_checkpoint=checkpoint,
                parallel_stages=self.parallel_stages,
                format_stage=self.format_stage,
                sequential_stages=self.sequential_stages,
            )
            await checkpoint(results)
            artifact["status"] = "done"
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError) as exc:
            artifact["status"] = "password_required"
            artifact["reason"] = (
                "wrong_password"
                if isinstance(exc, ArchiveWrongPasswordError)
                else "password_required"
            )
            if (
                self.password_attempt_limit is not None
                and artifact_id in self.passwords
                and self.password_attempts_by_artifact.get(artifact_id, 0)
                >= self.password_attempt_limit
            ):
                artifact["status"] = "failed"
                artifact["reason"] = "password_attempts_exhausted"
                artifact["report"] = build_password_attempts_exhausted_report(
                    {
                        "job_id": artifact_id,
                        "file_id": artifact_id,
                        "sha256": artifact["sha256"],
                        "original_filename": artifact["original_filename"],
                    },
                    existing_report=artifact.get("report"),
                )
                artifact["stage_results"] = artifact["report"]["stages"]
        except BudgetExceeded as exc:
            artifact["status"] = "limited"
            artifact["reason"] = exc.reason
        finally:
            # Child bytes and every completed stage were persisted before cleanup.
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(Path("/tmp") / artifact_id, ignore_errors=True)
            await self._save()

    def _report(self) -> dict[str, Any]:
        root = self.artifacts[self.manifest.root_job_id]
        effective_reports: dict[str, dict[str, Any]] = {}

        def display_path(item: dict[str, Any]) -> str:
            parts = []
            current = item
            while current["parent_id"] is not None:
                parts.append(current.get("origin_path") or current["original_filename"])
                current = self.artifacts[current["parent_id"]]
            parts.append(current["original_filename"])
            return "!/".join(reversed(parts))

        # Every parent gets a subtree decision, including encrypted documents
        # nested in archives. Always aggregate original direct stage reports:
        # reusing an already aggregated parent would count its children twice.
        for artifact in self.artifacts.values():
            direct_report = artifact.get("report")
            if not isinstance(direct_report, dict):
                continue
            descendants = []
            for item in self.artifacts.values():
                parent_id = item["parent_id"]
                while parent_id is not None and parent_id != artifact["artifact_id"]:
                    parent_id = self.artifacts[parent_id]["parent_id"]
                if parent_id is None:
                    continue
                child_report = item.get("report") or {}
                file_info = child_report.get("file") or {}
                descendants.append(
                    {
                        "artifact_id": item["artifact_id"],
                        "sha256": item["sha256"],
                        "size": item["size"],
                        "relative_depth": item["depth"] - artifact["depth"],
                        "risk_score": child_report.get("score", 0),
                        "risk_level": child_report.get("risk_level", "unknown"),
                        "verdict": child_report.get("verdict", "unknown"),
                        "origin_path": item.get("origin_path"),
                        "display_path": display_path(item),
                        "risk_verified": (
                            child_report.get("job_id") == item["artifact_id"]
                            and isinstance(file_info.get("size"), int)
                            and not isinstance(file_info.get("size"), bool)
                            and file_info.get("sha256") == item["sha256"]
                            and file_info.get("size") == item["size"]
                            and file_info.get("original_filename") == item["original_filename"]
                        ),
                    }
                )
            local = score_direct_evidence(
                direct_evidence=build_direct_evidence(
                    artifact_id=artifact["artifact_id"],
                    stage_findings={
                        item["stage_name"]: item["findings"] for item in artifact["stage_results"]
                    },
                )
            )
            effective_reports[artifact["artifact_id"]] = apply_descendant_risk(
                deepcopy(direct_report), local=local, descendants=descendants
            )
        report = deepcopy(
            effective_reports.get(root["artifact_id"])
            or root.get("report")
            or {
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "job_id": self.manifest.root_job_id,
                "file": {
                    "sha256": root["sha256"],
                    "size": root["size"],
                    "original_filename": root["original_filename"],
                },
                "verdict": "unknown",
                "score": 0,
                "risk_level": "unknown",
                "results": {},
            }
        )
        nodes = []
        incomplete = []
        for artifact in sorted(
            self.artifacts.values(),
            key=lambda item: (
                item["depth"],
                item.get("origin_path") or "",
                item["artifact_id"],
            ),
        ):
            node = {
                key: value
                for key, value in artifact.items()
                if key not in {"ancestor_hashes", "stage_results", "report"}
            }
            node["report"] = effective_reports.get(artifact["artifact_id"])
            nodes.append(node)
            if artifact["status"] != "done":
                incomplete.append(
                    {
                        "artifact_id": artifact["artifact_id"],
                        "status": artifact["status"],
                        "reason": artifact.get("reason"),
                    }
                )
            elif (artifact.get("report") or {}).get("analysis", {}).get("static", {}).get(
                "status"
            ) in {"partial", "failed", "unknown", "password_required"} or any(
                result["status"]
                in {
                    "error",
                    "failed",
                    "unavailable",
                    "limited",
                    "partial",
                    "timeout",
                    "password_required",
                }
                for result in artifact["stage_results"]
            ):
                incomplete.append(
                    {
                        "artifact_id": artifact["artifact_id"],
                        "status": "partial",
                        "reason": "stage_incomplete",
                    }
                )
        report.update(
            root_artifact_id=self.manifest.root_job_id,
            attempt_id=self.manifest.attempt_id,
            analysis_attempt_id=self.manifest.attempt_id,
            report_revision=self.state["report_revision"],
            artifacts=nodes,
            report_key=self.manifest.report_key,
            execution_budget={
                key: value
                for key, value in self.state.get("budget", {}).items()
                if key
                in {
                    "limits",
                    "used_files",
                    "used_bytes",
                    "deadline_at",
                    "time_scope",
                    "accounting_scope",
                }
            },
            batch_analysis={
                "status": "complete" if not incomplete else "partial",
                "artifact_count": len(nodes),
                "incomplete_artifacts": incomplete,
            },
        )
        pending = [
            item
            for item in self.artifacts.values()
            if item["status"] in {"queued", "running", "password_required"}
        ]
        waiting = [item for item in pending if item["status"] == "password_required"]
        status = "password_required" if waiting else "scanning" if pending else "done"
        report.update(
            report_schema_version=REPORT_SCHEMA_VERSION,
            job_status=status,
            report_complete=not pending,
            pending_descendants=sum(
                item["artifact_id"] != self.manifest.root_job_id for item in pending
            ),
            password_required_artifacts=[item["artifact_id"] for item in waiting],
            child_jobs=[
                {
                    "job_id": item["artifact_id"],
                    "filename": item["original_filename"],
                    "sha256": item["sha256"],
                    "status": item["status"],
                    "verdict": effective_reports.get(item["artifact_id"], {}).get("verdict"),
                }
                for item in self.artifacts.values()
                if item["parent_id"] is not None
            ],
        )
        report["analysis"] = analysis_from_report(report, status)
        tree_nodes: dict[str, dict[str, Any]] = {}
        for artifact in self.artifacts.values():
            child_report = effective_reports.get(artifact["artifact_id"], {})
            local_risk = child_report.get("risk", {}).get("local_risk", {})
            child_analysis = analysis_from_report(child_report, artifact["status"])
            if artifact["status"] == "limited":
                child_analysis["static"]["status"] = "partial"
            tree_nodes[artifact["artifact_id"]] = {
                "id": artifact["artifact_id"],
                "job_id": artifact["artifact_id"],
                "filename": artifact["original_filename"],
                "sha256": artifact["sha256"],
                "mime": child_report.get("file", {}).get("mime"),
                "size": artifact["size"],
                "depth": artifact["depth"],
                "origin_path": artifact.get("origin_path"),
                "extraction_source": artifact.get("extraction_source"),
                "archive_type": artifact.get("archive_type"),
                "extraction_note": artifact.get("reason"),
                "job_status": artifact["status"],
                "analysis_status": child_analysis["static"]["status"],
                "analysis": child_analysis,
                "score": child_report.get("score"),
                "verdict": child_report.get("verdict"),
                "risk_level": child_report.get("risk_level"),
                "local_score": local_risk.get("score"),
                "local_verdict": local_risk.get("verdict"),
                "local_risk_level": local_risk.get("risk_level"),
                "children": [],
                "finding_ids": [],
                "uncertainty_ids": [],
                "diagnostic_ids": [],
                "top_finding_titles": [],
            }
        report["analysis"]["static"]["status"] = summarize_static_artifacts(
            report["analysis"]["static"]["status"],
            [
                node["analysis_status"]
                for artifact_id, node in tree_nodes.items()
                if artifact_id != self.manifest.root_job_id
            ],
        )
        for artifact in self.artifacts.values():
            if artifact["parent_id"]:
                tree_nodes[artifact["parent_id"]]["children"].append(
                    tree_nodes[artifact["artifact_id"]]
                )
        tree = tree_nodes[self.manifest.root_job_id]
        tree.update(
            score=report["score"],
            verdict=report["verdict"],
            risk_level=report["risk_level"],
            analysis=report["analysis"],
            analysis_status=report["analysis"]["static"]["status"],
        )
        report["artifact_tree"] = tree
        report["explainability"] = build_explainability(report=report, artifact_tree=tree)
        return report

    async def _publish_report(self) -> dict[str, Any]:
        self.state["report_revision"] += 1
        report = self._report()
        await self.result_store.put_json(self.manifest.report_key, report)
        if self.on_report:
            await self.on_report(report)
        return report

    async def run(self, *, resume: bool = False) -> dict[str, Any]:
        lock = (self.state_dir / ".run.lock").open("a")
        try:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("This root batch already has an active local execution") from exc
            await self._load(resume)
            while (artifact_id := self.dispatcher.next_artifact()) is not None:
                await self._analyze(self.artifacts[artifact_id])
            report = await self._publish_report()
            await self._save()
            return report
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
