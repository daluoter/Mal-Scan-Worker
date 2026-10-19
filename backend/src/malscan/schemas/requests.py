"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

JobStatusLiteral = Literal["queued", "scanning", "password_required", "done", "failed"]


class UploadResponse(BaseModel):
    """Response for POST /files."""

    job_id: str
    file_id: str
    sha256: str
    status: Literal["queued"]
    created_at: datetime


class JobProgress(BaseModel):
    """Job progress information."""

    current_stage: str | None
    stages_done: int
    stages_total: int
    percent: int


class JobStatusResponse(BaseModel):
    """Response for GET /jobs/{job_id}."""

    job_id: str
    parent_job_id: str | None = None
    depth: int = 0
    status: JobStatusLiteral
    password_attempts: int
    password_attempts_remaining: int
    progress: JobProgress
    updated_at: datetime
    error_message: str | None

    # Sub-job statistics overview
    total_sub: int = 0
    completed_sub: int = 0
    malicious_sub: int = 0
    report_available: bool = False


class FileMetadata(BaseModel):
    """File metadata in report."""

    file_id: str
    sha256: str
    mime: str
    size: int
    original_filename: str


class AvResult(BaseModel):
    """Antivirus scan result."""

    engine: str
    infected: bool
    threat_name: str | None


class YaraHit(BaseModel):
    """YARA rule match."""

    rule: str
    namespace: str
    description: str = ""
    classification: str = "generic"
    confidence: str = "medium"
    family: str = ""
    severity: str = "medium"
    author: str = ""
    tags: list[str]
    strings: list[str]


class Hashes(BaseModel):
    """File hashes."""

    md5: str
    sha1: str
    sha256: str


class Iocs(BaseModel):
    """Indicators of Compromise."""

    urls: list[str]
    domains: list[str]
    ips: list[str]
    hashes: Hashes


class ArchiveExtractResult(BaseModel):
    """Archive extraction result."""

    archive_type: str | None = None
    extracted_count: int = 0
    sub_jobs_created: int = 0
    total_extracted_bytes: int = 0
    malicious: bool = False
    reason: str | None = None
    extraction_failed: bool | None = None


class SandboxBehavior(BaseModel):
    """Sandbox behavior entry."""

    type: str
    path: str | None = None
    key: str | None = None
    detail: str | None = None


class SandboxConnection(BaseModel):
    """Sandbox network connection."""

    dst_ip: str
    dst_port: int
    protocol: str


class SandboxResult(BaseModel):
    """Sandbox analysis result."""

    executed: bool
    behaviors: list[SandboxBehavior] = Field(default_factory=list)
    network_connections: list[SandboxConnection] = Field(default_factory=list)
    provider: str | None = None
    task_id: str | None = None
    is_mock: bool
    verdict_hint: str | None = None
    processes: list[dict[str, Any]] = Field(default_factory=list)
    files: list[dict[str, Any]] = Field(default_factory=list)
    registry: list[dict[str, Any]] = Field(default_factory=list)
    mutexes: list[dict[str, Any]] = Field(default_factory=list)
    dns: list[dict[str, Any]] = Field(default_factory=list)
    http: list[dict[str, Any]] = Field(default_factory=list)
    tcp_udp: list[SandboxConnection] = Field(default_factory=list)
    dropped_files: list[dict[str, Any]] = Field(default_factory=list)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    pcap: dict[str, Any] = Field(default_factory=dict)
    memory_dump: dict[str, Any] = Field(default_factory=dict)
    iocs: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    raw_report_ref: str | None = None
    status: str | None = None
    reason: str | None = None
    synthetic: bool = False
    error_code: str | None = None
    recovery_required: bool = False
    reconcile_required: bool = False
    task_ids: list[str] = Field(default_factory=list)


class RiskEvidence(BaseModel):
    """Single normalized risk evidence entry."""

    id: str | None = None
    source: str
    kind: str
    tier: str
    severity: str
    confidence: float | None = None
    points: int
    scope: str
    depth: int
    artifact_id: str | None = None
    related_artifact_id: str | None = None
    stage: str | None = None
    analyzer: str | None = None
    reason: str
    raw: dict[str, Any] = Field(default_factory=dict)
    finding_ids: list[str] = Field(default_factory=list)
    ioc_ids: list[str] = Field(default_factory=list)
    decoded_ids: list[str] = Field(default_factory=list)
    score_contribution: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdown(BaseModel):
    """Risk score component breakdown."""

    local_score: int
    inherited_score: int
    descendant_floor: int = 0
    synergy_bonus: int
    dampener: int
    final_score: int


class RiskSummary(BaseModel):
    """Top-level risk summary block."""

    policy_version: str
    risk_score: int
    risk_level: str
    legacy_verdict: str
    malicious_gate_open: bool
    high_gate_open: bool
    independent_source_count: int
    breakdown: RiskBreakdown
    evidence: list[RiskEvidence] = Field(default_factory=list)
    top_evidence: list[RiskEvidence] = Field(default_factory=list)
    descendant_summary: dict[str, Any] = Field(default_factory=dict)
    score_trace: dict[str, Any] = Field(default_factory=dict)
    local_risk: dict[str, Any] = Field(default_factory=dict)


class ExplainabilitySummary(BaseModel):
    headline: str = ""
    primary_artifact_id: str | None = None
    primary_artifact_path: str | None = None
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    final_verdict_explainer: str = ""


class ExplainabilityBlock(BaseModel):
    summary: ExplainabilitySummary = Field(default_factory=ExplainabilitySummary)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    decoded_strings: list[dict[str, Any]] = Field(default_factory=list)
    uncertainties: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    failure_diagnostics: dict[str, Any] = Field(default_factory=dict)
    artifact_coverage: dict[str, int] = Field(default_factory=dict)


class AnalysisResults(BaseModel):
    """All analysis results."""

    av_result: AvResult
    yara_hits: list[YaraHit]
    iocs: Iocs
    sandbox: SandboxResult
    format_analysis: dict[str, Any] | None = None
    deobfuscation: dict[str, Any] | None = None
    document_analysis: dict[str, Any] | None = None
    archive_extract: ArchiveExtractResult | None = None


class StageTiming(BaseModel):
    """Stage timing information."""

    name: str
    status: str
    duration_ms: int
    started_at: str | None = None
    ended_at: str | None = None


class Timings(BaseModel):
    """Analysis timings."""

    total_ms: int
    stages: list[StageTiming]


class ChildJobSummary(BaseModel):
    """Summary of a child job."""

    job_id: str
    filename: str
    sha256: str
    status: str
    verdict: str | None = None
    password_attempts: int = 0
    password_attempts_remaining: int = 3


class StageCoverage(BaseModel):
    """Recorded execution coverage, independent from detection verdict."""

    stage: str
    status: str
    reason: str | None = None
    duration_ms: int | None = None
    tool_version: str | None = None
    rules_version: str | None = None


class StaticAnalysisState(BaseModel):
    status: str = "unknown"
    stage_coverage: list[StageCoverage] = Field(default_factory=list)


class DynamicAnalysisState(BaseModel):
    status: str = "unknown"
    provider: str | None = None
    reason: str | None = None


class AnalysisState(BaseModel):
    schema_version: str = "mswr-analysis-v1"
    static: StaticAnalysisState = Field(default_factory=StaticAnalysisState)
    dynamic: DynamicAnalysisState = Field(default_factory=DynamicAnalysisState)


class ExecutionBudgetLimits(BaseModel):
    max_files: int = Field(ge=1)
    max_bytes: int = Field(ge=1)
    timeout_seconds: float = Field(gt=0)


class ExecutionBudget(BaseModel):
    """Expansion accounting and attempt deadline, not billing or resource peaks."""

    limits: ExecutionBudgetLimits
    used_files: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    deadline_at: datetime
    time_scope: Literal["analysis_attempt"]
    accounting_scope: Literal["root_artifact_tree"]
    accounting_source: Literal["durable_root_budget"] | None = None
    deadline_active: bool = False


class ArtifactTreeNode(BaseModel):
    """A node in the artifact extraction tree."""

    id: str
    filename: str
    sha256: str
    mime: str | None = None
    size: int
    depth: int
    origin_path: str | None = None
    extraction_source: str | None = None
    archive_type: str | None = None
    extraction_note: str | None = None
    verdict: str | None = None
    score: int | None = None
    risk_level: str | None = None
    local_score: int | None = None
    local_risk_level: str | None = None
    local_verdict: str | None = None
    policy_version: str | None = None
    job_id: str | None = None
    root_artifact_id: str | None = None
    root_job_id: str | None = None
    display_path: str | None = None
    archive_layer: int | None = None
    analysis_status: str | None = None
    job_status: str | None = None
    analysis: AnalysisState = Field(default_factory=AnalysisState)
    analysis_reference: dict[str, Any] | None = None
    direct_finding_ids: list[str] = Field(default_factory=list)
    inherited_finding_ids: list[str] = Field(default_factory=list)
    direct_evidence_ids: list[str] = Field(default_factory=list)
    inherited_evidence_ids: list[str] = Field(default_factory=list)
    primary_analyzer: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    uncertainty_ids: list[str] = Field(default_factory=list)
    diagnostic_ids: list[str] = Field(default_factory=list)
    top_finding_titles: list[str] = Field(default_factory=list)
    children: list["ArtifactTreeNode"] = Field(default_factory=list)


class ReportResponse(BaseModel):
    """Response for GET /reports/{job_id}."""

    job_id: str
    parent_job_id: str | None = None
    file: FileMetadata
    verdict: str
    score: int
    risk_level: str
    risk: RiskSummary
    results: AnalysisResults
    timings: Timings
    created_at: datetime
    child_jobs: list[ChildJobSummary] = Field(default_factory=list)
    artifact_tree: ArtifactTreeNode | None = None
    report_schema_version: str = "mswr-report-v3"
    job_status: str | None = None
    report_complete: bool = False
    pending_descendants: int = 0
    analysis: AnalysisState = Field(default_factory=AnalysisState)
    analysis_attempt_id: str | None = None
    execution_budget: ExecutionBudget | None = None
    explainability: ExplainabilityBlock = Field(default_factory=ExplainabilityBlock)


class ApiError(BaseModel):
    """API error response."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class ApiErrorResponse(BaseModel):
    """Wrapper for API errors."""

    error: ApiError


class PasswordSubmitRequest(BaseModel):
    """Request for POST /jobs/{job_id}/password."""

    password: str = Field(min_length=1, max_length=256)


class PasswordSubmitResponse(BaseModel):
    """Response for POST /jobs/{job_id}/password."""

    job_id: str
    status: Literal["queued", "password_required"]
    message: str
    attempts_used: int
    attempts_remaining: int
