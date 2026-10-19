"""Nested report pages keep their subtree and original enclosing-root identity."""

import uuid
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from malscan.api.routes import _apply_tree_risk_rollup, _build_artifact_tree
from malscan.models import Job
from malscan.models.artifact import Artifact
from malscan.report_explainability import build_explainability
from malscan.schemas.requests import ArtifactTreeNode


def _records():
    root_artifact, parent_artifact, child_artifact, sibling_artifact = (
        uuid.uuid4() for _ in range(4)
    )
    root_job, parent_job, child_job, sibling_job = (uuid.uuid4() for _ in range(4))
    records = []
    for index, (identifier, job_id, parent_id, depth, name, score) in enumerate(
        [
            (root_artifact, root_job, None, 0, "outer.zip", 0),
            (parent_artifact, parent_job, root_artifact, 1, "locked.pdf", 4),
            (sibling_artifact, sibling_job, root_artifact, 1, "sibling.txt", 0),
            (child_artifact, child_job, parent_artifact, 2, "decrypted.pdf", 84),
        ]
    ):
        level = "high" if score == 84 else "clean"
        verdict = "suspicious" if score == 84 else "clean"
        sha256 = str(index + 1) * 64
        report = {
            "job_id": str(job_id),
            "file": {"sha256": sha256, "size": 1024, "original_filename": name},
            "score": score,
            "risk_level": level,
            "verdict": verdict,
            "timings": {"stages": [{"name": "format-analysis", "status": "ok"}]},
            "results": {},
            "risk": {
                "risk_score": score,
                "risk_level": level,
                "legacy_verdict": verdict,
                "high_gate_open": level == "high",
                "malicious_gate_open": False,
                "breakdown": {"local_score": score, "final_score": score},
            },
        }
        artifact = Artifact(
            id=identifier,
            job_id=job_id,
            parent_id=parent_id,
            root_id=root_artifact,
            root_job_id=root_job,
            depth=depth,
            original_filename=name,
            sha256=sha256,
            size=1024,
            score=score,
            risk_level=level,
            verdict=verdict,
            origin_path="pdf-decrypted" if depth == 2 else name,
            extraction_source="format-analysis" if depth == 2 else "archive-extract",
        )
        artifact.job = Job(id=job_id, status="done", result=report)
        records.append(artifact)
    return records


def _db(records):
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = records
    db.execute.return_value = result
    return db


@pytest.mark.asyncio
async def test_nested_pdf_report_contains_only_requested_subtree_and_preserves_risk_binding():
    records = _records()
    root, parent, sibling, child = records
    reports = {}
    db = _db(records)
    tree = await _build_artifact_tree(str(parent.job_id), db, reports)
    assert tree is not None
    assert tree["id"] == str(parent.id)
    assert tree["job_id"] == str(parent.job_id)
    assert tree["root_artifact_id"] == str(root.id)
    assert tree["root_job_id"] == str(root.job_id)
    assert [node["id"] for node in tree["children"]] == [str(child.id)]
    assert str(sibling.id) not in {tree["id"], *(node["id"] for node in tree["children"])}
    # Both the initial and later explainability resolution must retain the real
    # enclosing root, rather than treating the nested page as a new upload.
    report = _apply_tree_risk_rollup(deepcopy(parent.job.result), tree, reports)
    assert report["score"] == tree["score"] == 84
    assert tree["local_score"] == 4
    assert report["risk"]["local_risk"]["score"] == 4
    published = ArtifactTreeNode.model_validate(tree).model_dump()
    assert published["score"] == 84
    assert published["local_score"] == 4
    assert published["local_risk_level"] == "clean"
    assert published["local_verdict"] == "clean"
    report["artifact_tree"] = tree
    explanation = build_explainability(report=report, artifact_tree=tree, artifact_reports=reports)
    for node in explanation["artifacts"]:
        assert node["root_artifact_id"] == str(root.id)
        assert node["analysis_reference"]["status"] == "verified"
        assert node["analysis_reference"]["source_root_artifact_id"] == str(root.id)
        assert node["analysis_reference"]["source_root_job_id"] == str(root.job_id)
    assert len(explanation["artifacts"]) == 2
    # The lookup uses the requested job's authoritative Artifact.root_job_id in
    # the same database read; it does not depend on a client-supplied root id.
    stmt = db.execute.call_args.args[0]
    sql = str(stmt)
    assert "artifacts.job_id" in sql
    assert "SELECT artifacts.root_job_id" in sql
    assert str(parent.job_id) in {str(value) for value in stmt.compile().params.values()}


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["root_id", "root_job_id"])
async def test_child_subtree_rejects_foreign_enclosing_root_metadata(field):
    records = _records()
    parent = records[1]
    child = records[-1]
    setattr(child, field, uuid.uuid4())
    assert await _build_artifact_tree(str(parent.job_id), _db(records), {}) is None
