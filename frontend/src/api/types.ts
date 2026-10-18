export interface UploadResponse {
    job_id: string
    file_id: string
    sha256: string
    status: string
    created_at: string
    dispatch_uncertain?: boolean
}

export interface JobProgress {
    current_stage: string
    stages_done: number
    stages_total: number
    percent: number
}

export interface JobStatus {
    job_id: string
    parent_job_id?: string | null
    status: 'queued' | 'scanning' | 'password_required' | 'done' | 'failed'
    progress: JobProgress
    updated_at: string
    error_message: string | null
    password_attempts: number
    password_attempts_remaining: number
    report_available?: boolean
    password_required_artifacts?: string[]
    dispatch_uncertain?: boolean
    retention_expires_at?: string
}

export interface FileMetadata {
    file_id: string
    sha256: string
    mime: string
    size: number
    original_filename: string
}

export interface AvResult {
    engine: string
    engine_version?: string | null
    database_version?: string | null
    database_timestamp?: string | null
    infected: boolean
    threat_name: string | null
}

export interface YaraHit {
    rule: string
    namespace: string
    description: string
    classification?: string
    confidence?: string
    family?: string
    severity: string
    author: string
    tags: string[]
    strings: string[]
    provenance?: YaraRuleProvenance
}

export interface YaraRuleProvenance {
    status: string
    reason?: string
    verification_scope?: string
    ruleset_id?: string
    ruleset_version?: string
    ruleset_sha256?: string | null
    manifest_sha256?: string
    file_count?: number
    rule_count?: number
    source?: {
        type?: string
        repository?: string
        introduced_commit?: string
        declared_author?: string
        authorship_status?: string
        external_upstream_status?: string
    }
    license?: {
        spdx_expression?: string
        status?: string
        permission_verified?: boolean
        note?: string
    }
    file?: string
    file_sha256?: string
    category?: string
    limitations?: string
}

export interface Iocs {
    urls: string[]
    domains: string[]
    ips: string[]
    hashes: {
        md5: string
        sha1: string
        sha256: string
    }
}

export interface StageTiming {
    name: string
    status: string
    duration_ms: number
    started_at?: string | null
    ended_at?: string | null
}

export interface RiskBreakdown {
    local_score: number
    inherited_score: number
    synergy_bonus: number
    dampener: number
    final_score: number
}

export interface RiskEvidence {
    id?: string | null
    source: string
    kind: string
    tier: string
    severity: string
    confidence?: number | null
    points: number
    scope: string
    depth: number
    artifact_id?: string | null
    related_artifact_id?: string | null
    stage?: string | null
    analyzer?: string | null
    reason: string
    raw: Record<string, unknown>
    finding_ids: string[]
    ioc_ids: string[]
    decoded_ids: string[]
    score_contribution: Record<string, unknown>
}

export interface ScoreTraceComponent {
    type: string
    artifact_id?: string | null
    related_artifact_id?: string | null
    evidence_id?: string | null
    label?: string | null
    base_points?: number | null
    applied_points?: number | null
    relative_depth?: number | null
    source_score?: number | null
    reason: string
}

export interface ScoreTrace {
    formula: string
    components: ScoreTraceComponent[]
    gates: Record<string, unknown>
    breakdown: Record<string, unknown>
}

export interface RiskSummary {
    policy_version: string
    risk_score: number
    risk_level: string
    legacy_verdict: string
    malicious_gate_open: boolean
    high_gate_open: boolean
    independent_source_count: number
    breakdown: RiskBreakdown
    evidence: RiskEvidence[]
    top_evidence: RiskEvidence[]
    descendant_summary: Record<string, unknown>
    score_trace?: ScoreTrace
}

export interface ArtifactTreeNode {
    id: string
    filename: string
    sha256: string
    mime?: string | null
    size: number
    depth: number
    origin_path?: string | null
    extraction_source?: string | null
    archive_type?: string | null
    extraction_note?: string | null
    verdict?: string | null
    score?: number | null
    risk_level?: string | null
    policy_version?: string | null
    job_id?: string | null
    display_path?: string | null
    archive_layer?: number | null
    analysis_status?: string | null
    job_status?: JobStatus['status'] | null
    analysis?: AnalysisState
    primary_analyzer?: string | null
    finding_ids: string[]
    direct_finding_ids?: string[]
    inherited_finding_ids?: string[]
    direct_evidence_ids?: string[]
    inherited_evidence_ids?: string[]
    analysis_reference?: ArtifactAnalysisReference
    uncertainty_ids: string[]
    diagnostic_ids: string[]
    top_finding_titles: string[]
    children: ArtifactTreeNode[]
}

export interface ArtifactAnalysisReference {
    schema_version: string
    mode: string
    status: string
    source_artifact_id?: string | null
    source_job_id?: string | null
    source_root_artifact_id?: string | null
    source_sha256?: string | null
    source_size?: number | null
    source_analysis_status?: string | null
    source_stage_coverage?: StageCoverage[]
    source_evidence_ids?: string[]
    source_finding_ids?: string[]
    risk?: {
        score?: number | null
        risk_level?: string | null
        verdict?: string | null
    }
    reason?: string | null
}

export interface ExplainabilitySummaryFinding {
    finding_id: string
    artifact_id: string
    artifact_path: string
    archive_layer: number
    title: string
    score_impact: number
    why_flagged: string
}

export interface ExplainabilitySummary {
    headline: string
    primary_artifact_id?: string | null
    primary_artifact_path?: string | null
    top_findings: ExplainabilitySummaryFinding[]
    final_verdict_explainer: string
}

export interface ExplainabilityFinding {
    finding_id: string
    artifact_id: string
    title: string
    summary: string
    severity: string
    confidence: string
    kind: string
    primary: boolean
    score_impact: number
    found_by: Array<{ stage?: string | null; analyzer?: string | null }>
    evidence_ids: string[]
    ioc_ids: string[]
    decoded_ids: string[]
    uncertainty_ids: string[]
    timeline_event_ids: string[]
    artifact_path?: string
    archive_layer?: number
}

export interface ExplainabilityIoc {
    ioc_id: string
    artifact_id: string
    type: string
    value: string
    source_stage: string
    source_kind: string
    decoder?: string | null
    decoded_id?: string | null
    first_seen_in?: string | null
    finding_ids: string[]
}

export interface ExplainabilityDecodedString {
    decoded_id: string
    artifact_id: string
    source_stage: string
    decoder?: string | null
    technique?: string | null
    confidence?: number | null
    content_preview: string
    content_encoding?: string | null
    content_truncated: boolean
    provenance: Record<string, unknown>
    ioc_ids: string[]
    finding_ids: string[]
}

export interface ExplainabilityUncertainty {
    uncertainty_id: string
    artifact_id: string
    kind: string
    severity: string
    direction: string
    message: string
    finding_ids: string[]
}

export interface ExplainabilityTimelineEvent {
    timeline_event_id: string
    seq: number
    artifact_id: string
    kind: string
    stage?: string | null
    analyzer?: string | null
    status: string
    summary: string
    refs: {
        finding_ids: string[]
        evidence_ids: string[]
        ioc_ids: string[]
        decoded_ids: string[]
    }
}

export interface FailureDiagnostic {
    diagnostic_id?: string
    artifact_id?: string
    stage: string
    code: string
    category: string
    severity: string
    likely_effect: string
    confidence: string
    message: string
    recommended_action?: string
}

export interface SuspectedMissStage {
    artifact_id?: string
    stage: string
    reason: string
    confidence: string
}

export interface FailureDiagnostics {
    status: string
    headline: string
    diagnostics: FailureDiagnostic[]
    suspected_miss_stages: SuspectedMissStage[]
}

export interface ExplainabilityBlock {
    summary: ExplainabilitySummary
    artifacts: Array<Record<string, unknown>>
    findings: ExplainabilityFinding[]
    evidence: Array<Record<string, unknown>>
    iocs: ExplainabilityIoc[]
    decoded_strings: ExplainabilityDecodedString[]
    uncertainties: ExplainabilityUncertainty[]
    timeline: ExplainabilityTimelineEvent[]
    failure_diagnostics: FailureDiagnostics
    artifact_coverage?: {
        occurrences: number
        direct: number
        inherited: number
        unresolved: number
    }
}

export interface Report {
    job_id: string
    parent_job_id?: string | null
    file: FileMetadata
    verdict: string
    score: number
    risk_level: string
    report_schema_version?: string
    analysis?: AnalysisState
    job_status?: JobStatus['status']
    report_complete?: boolean
    pending_descendants?: number
    password_required_artifacts?: string[]
    execution_active?: boolean | null
    requires_reconciliation?: boolean
    error_message?: string | null
    artifacts?: Array<{ artifact_id: string; status: string; reason?: string | null; report: Report | null }>
    risk?: RiskSummary
    results: {
        av_result: AvResult
        yara_hits: YaraHit[]
        yara_rule_provenance?: YaraRuleProvenance
        iocs: Iocs
        sandbox: {
            executed: boolean
            status?: string
            reason?: string | null
            synthetic?: boolean
            provider?: string | null
            task_id?: string | null
            behaviors: Array<{ type: string; path?: string | null; key?: string | null; detail?: string | null }>
            network_connections: Array<{ dst_ip: string; dst_port: number; protocol: string }>
            is_mock: boolean
            verdict_hint?: string | null
            processes?: Array<Record<string, unknown>>
            files?: Array<Record<string, unknown>>
            registry?: Array<Record<string, unknown>>
            mutexes?: Array<Record<string, unknown>>
            dns?: Array<Record<string, unknown>>
            http?: Array<Record<string, unknown>>
            tcp_udp?: Array<{ dst_ip: string; dst_port: number; protocol: string }>
            dropped_files?: Array<Record<string, unknown>>
            screenshots?: Array<Record<string, unknown>>
            pcap?: Record<string, unknown>
            memory_dump?: Record<string, unknown>
            iocs?: Record<string, unknown>
            errors?: string[]
            raw_report_ref?: string | null
        }
        archive_extract?: {
            archive_type: string | null
            extracted_count: number
            sub_jobs_created: number
            total_extracted_bytes: number
            malicious: boolean
            reason: string | null
            extraction_failed?: boolean
        }
        format_analysis?: Record<string, unknown>
        deobfuscation?: Record<string, unknown>
        document_analysis?: Record<string, unknown>
    }
    timings: {
        total_ms: number
        stages: StageTiming[]
    }
    child_jobs: Array<{
        job_id: string
        filename: string
        sha256: string
        status: string
        verdict: string | null
        password_attempts?: number
        password_attempts_remaining?: number
    }>
    created_at: string
    artifact_tree?: ArtifactTreeNode | null
    explainability?: ExplainabilityBlock
}

export interface StageCoverage {
    stage: string
    status: string
    reason?: string | null
    duration_ms?: number | null
    tool_version?: string | null
    rules_version?: string | null
}

export interface AnalysisState {
    schema_version: string
    static: { status: string; stage_coverage: StageCoverage[] }
    dynamic: { status: string; provider?: string | null; reason?: string | null }
}

export interface ApiError {
    error: {
        code: string
        message: string
        details?: Record<string, unknown>
    }
}

export interface HealthResponse {
    status: string
}

export interface PasswordSubmitRequest {
    /** Password for this supported encrypted archive or PDF; never persisted in a report. */
    password: string
}

export interface PasswordSubmitResponse {
    job_id: string
    status: string
    message: string
    attempts_used: number
    attempts_remaining: number
}
