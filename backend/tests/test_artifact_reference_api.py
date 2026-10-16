"""The self-hosted DB report builder resolves duplicate occurrences."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from malscan.api.routes import _build_artifact_tree
from malscan.report_explainability import build_explainability
from malscan.schemas.requests import ArtifactTreeNode


@pytest.mark.asyncio
async def test_db_occurrences_keep_jobs_separate_and_publish_scoped_reference() -> None:
    root_job_id, source_job_id, root_id, source_id, duplicate_id = (uuid4() for _ in range(5))

    def make_artifact(artifact_id, *, parent_id, sha256, job_id, duplicate=False):
        report = {
            "job_id": str(job_id),
            "file": {"sha256": sha256, "size": 68, "original_filename": "eicar.txt"},
            "score": 95,
            "risk_level": "malicious",
            "verdict": "malicious",
            "risk": {"evidence": [{"evidence_id": "ev-1", "points": 95}]},
            "timings": {
                "stages": [
                    {"name": name, "status": "ok"}
                    for name in (
                        "file-type",
                        "clamav",
                        "yara",
                        "ioc-extract",
                        "deobfuscation",
                        "format-analysis",
                        "archive-extract",
                        "document-analysis",
                    )
                ]
            },
            "results": {},
        }
        return SimpleNamespace(
            id=artifact_id,
            parent_id=parent_id,
            root_id=root_id if parent_id else None,
            root_job_id=root_job_id,
            depth=int(parent_id is not None),
            original_filename="eicar.txt",
            sha256=sha256,
            mime="text/plain",
            size=68,
            origin_path=f"{artifact_id}/eicar.txt" if parent_id else None,
            extraction_source="archive-extract",
            archive_type=None,
            extraction_note="duplicate_within_extraction" if duplicate else None,
            verdict="skipped" if duplicate else "malicious",
            score=None if duplicate else 95,
            risk_level=None if duplicate else "malicious",
            policy_version="msrs-v1",
            job_id=job_id,
            job=SimpleNamespace(status="done", result=report) if job_id else None,
        )

    root = make_artifact(root_id, parent_id=None, sha256="b" * 64, job_id=root_job_id)
    source = make_artifact(source_id, parent_id=root_id, sha256="a" * 64, job_id=source_job_id)
    duplicate = make_artifact(
        duplicate_id, parent_id=root_id, sha256="a" * 64, job_id=None, duplicate=True
    )
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = [root, source, duplicate]
    db.execute.return_value = result
    reports = {}
    tree = await _build_artifact_tree(str(root_job_id), db, reports)
    assert tree is not None
    explanation = build_explainability(
        report=root.job.result,
        artifact_tree=tree,
        artifact_reports=reports,
    )
    published = ArtifactTreeNode.model_validate(tree).model_dump()
    inherited = published["children"][1]
    assert inherited["job_id"] is None
    assert inherited["analysis_status"] == "complete"
    assert inherited["analysis"]["static"]["stage_coverage"] == []
    assert inherited["analysis_reference"]["source_job_id"] == str(source_job_id)
    assert inherited["analysis_reference"]["source_artifact_id"] == str(source_id)
    assert inherited["inherited_evidence_ids"] == [f"evidence::{source_id}::ev-1"]
    assert "report" not in inherited
    assert len(explanation["findings"]) == 2
