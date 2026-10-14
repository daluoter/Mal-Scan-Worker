"""Coverage must distinguish unsuccessful analysis from a clean verdict."""

import pytest
from malscan.analysis_contract import (
    analysis_from_report,
    build_analysis,
    summarize_static_artifacts,
)


def test_missing_execution_evidence_remains_unknown():
    report = {"verdict": "clean", "score": 0, "timings": {"stages": []}}
    analysis = analysis_from_report(report, "done")
    assert analysis["static"]["status"] == "unknown"
    assert analysis["dynamic"]["status"] == "unknown"
    assert report == {"verdict": "clean", "score": 0, "timings": {"stages": []}}


@pytest.mark.parametrize(
    "reason", ["No YARA rules configured", "Depth limit reached", "budget exhausted"]
)
def test_limit_or_missing_rules_cannot_claim_complete(reason):
    analysis = build_analysis(stages=[{"name": "yara", "status": "skipped", "reason": reason}])
    assert analysis["static"]["status"] == "partial"
    assert analysis["static"]["stage_coverage"][0]["status"] == "skipped"


def test_not_applicable_stage_does_not_block_successful_static_analysis():
    analysis = build_analysis(
        stages=[
            {"name": "clamav", "status": "ok", "tool_version": "test-engine"},
            {"name": "archive-extract", "status": "skipped", "reason": "Not an archive"},
            {"name": "sandbox", "status": "deferred"},
        ],
        sandbox={"status": "deferred", "provider": "capev2"},
        job_status="scanning",
    )
    assert analysis["static"]["status"] == "complete"
    assert len(analysis["static"]["stage_coverage"]) == 2
    assert analysis["dynamic"] == {"status": "queued", "provider": "capev2"}


def test_mock_or_failed_sandbox_never_claims_real_completion():
    for sandbox, expected in [
        ({"executed": True, "is_mock": True}, "mock"),
        ({"executed": True, "synthetic": True, "status": "complete"}, "mock"),
        ({"executed": True, "provider": "mock", "status": "complete"}, "mock"),
        ({"executed": False, "status": "completed"}, "unavailable"),
        (
            {"executed": False, "status": "unavailable", "errors": ["provider_unavailable"]},
            "unavailable",
        ),
        ({"executed": True, "errors": ["execution_failed"]}, "failed"),
    ]:
        analysis = build_analysis(stages=[{"name": "clamav", "status": "ok"}], sandbox=sandbox)
        assert analysis["static"]["status"] == "complete"
        assert analysis["dynamic"]["status"] == expected


def test_live_password_and_queue_status_override_stale_complete_report():
    existing = {
        "static": {"status": "complete", "stage_coverage": [{"stage": "clamav", "status": "ok"}]}
    }
    for status in ("password_required", "queued"):
        assert (
            build_analysis(stages=[], existing=existing, job_status=status)["static"]["status"]
            == status
        )


def test_sandbox_submission_and_uncertain_provider_state_remain_distinct():
    assert (
        build_analysis(stages=[], sandbox={"status": "submitting"})["dynamic"]["status"]
        == "running"
    )
    assert (
        build_analysis(stages=[], sandbox={"status": "running"})["dynamic"]["status"] == "running"
    )
    analysis = build_analysis(
        stages=[],
        sandbox={
            "status": "unavailable",
            "executed": False,
            "error_code": "submission_outcome_unknown",
            "recovery_required": True,
        },
    )
    assert analysis["dynamic"]["status"] == "unavailable"


def test_coverage_does_not_copy_passwords_findings_or_raw_exception():
    coverage = build_analysis(
        stages=[
            {
                "name": "archive-extract",
                "status": "failed",
                "reason": "extractor_failed",
                "findings": {"password": "private-password"},
                "error": "private-password",
                "password": "private-password",
                "duration_ms": 3,
            }
        ]
    )["static"]["stage_coverage"]
    assert coverage == [
        {
            "stage": "archive-extract",
            "status": "failed",
            "reason": "extractor_failed",
            "duration_ms": 3,
        }
    ]


@pytest.mark.parametrize(
    "descendants,expected",
    [
        (["complete"], "complete"),
        (["unknown"], "partial"),
        (["partial"], "partial"),
        (["password_required"], "password_required"),
        (["running"], "running"),
    ],
)
def test_descendant_coverage_affects_tree_summary(descendants, expected):
    assert summarize_static_artifacts("complete", descendants) == expected
