import type { ArtifactTreeNode, JobStatus, Report, StageCoverage } from '../../api/types'
import { artifactReferenceIsVerified } from './reportRisk'

const waitingStates = new Set(['queued', 'pending', 'running', 'scanning', 'deferred', 'password_required'])

export function jobNeedsPassword(job: Pick<JobStatus, 'job_id' | 'status' | 'password_required_artifacts'>): boolean {
    return job.status === 'password_required' && (!job.password_required_artifacts || job.password_required_artifacts.includes(job.job_id))
}

export function dynamicStatus(report: Pick<Report, 'analysis' | 'results'>): string {
    const sandbox = report.results.sandbox
    if (sandbox.is_mock || sandbox.synthetic) return 'synthetic'
    const supplied = report.analysis?.dynamic.status || sandbox.status
    const status = supplied === 'complete' ? 'completed' : supplied === 'mock' ? 'synthetic' : supplied
    if (status === 'completed' && !sandbox.executed) return 'unknown'
    if (status) return status
    return sandbox.executed ? 'completed' : 'unknown'
}

export function shouldRefreshReport(report: Report): boolean {
    if (report.report_complete === true) return false
    if (report.requires_reconciliation || report.execution_active === true) return true
    if (report.job_status === 'done' && report.report_complete === false) return true
    if ((report.pending_descendants ?? 0) > 0) return true
    return waitingStates.has(report.job_status ?? '') || waitingStates.has(dynamicStatus(report))
}

export function stageCoverage(report: Pick<Report, 'analysis' | 'timings'>, stage: string): StageCoverage | undefined {
    return report.analysis?.static?.stage_coverage?.find((entry) => entry.stage === stage)
}

export function stageCompleted(report: Pick<Report, 'analysis' | 'timings'>, stage: string): boolean {
    const coverage = stageCoverage(report, stage)
    if (coverage) return ['completed', 'complete', 'ok'].includes(coverage.status)
    // Older reports do not carry coverage. Only an actual successful timing is proof.
    return report.timings.stages.some((entry) => entry.name === stage && entry.status === 'ok')
}

// A terminal job is not proof that every analyzer succeeded. In particular,
// stale antivirus databases leave both the root and extracted files partial.
export function reportCoverageSummary(report: Report): { complete: boolean; antivirusStatus: 'complete' | 'incomplete' | 'unknown' } {
    const successful = new Set(['ok', 'complete', 'completed'])
    const antivirusStates: Array<'complete' | 'incomplete' | 'unknown'> = []
    const scanState = (coverage?: StageCoverage[], timingStatus?: string) => {
        const status = coverage?.find((stage) => stage.stage === 'clamav')?.status || timingStatus
        const state = !status ? 'unknown' : successful.has(status) ? 'complete' : 'incomplete'
        antivirusStates.push(state)
        return state
    }
    const staticStateComplete = (status?: string, coverage?: StageCoverage[]) =>
        Boolean(status && successful.has(status) && coverage?.length
            && coverage.every((stage) => successful.has(stage.status) || stage.status === 'skipped'))

    const rootCoverage = report.analysis?.static?.stage_coverage
    let complete = report.report_complete === true
        && staticStateComplete(report.analysis?.static?.status, rootCoverage)
    scanState(rootCoverage, report.timings?.stages?.find((stage) => stage.name === 'clamav')?.status)

    const coveredArtifacts = new Set([report.job_id])
    const visit = (node: ArtifactTreeNode) => {
        coveredArtifacts.add(node.job_id || node.id)
        const reference = node.analysis_reference
        const verified = artifactReferenceIsVerified(node)
        const inherited = verified && reference?.mode === 'inherited'
        const coverage = inherited ? reference.source_stage_coverage : node.analysis?.static?.stage_coverage
        const status = inherited ? reference.source_analysis_status : node.analysis?.static?.status || node.analysis_status
        if (!verified || !staticStateComplete(status ?? undefined, coverage)) complete = false
        scanState(verified ? coverage : undefined)
        for (const child of node.children ?? []) visit(child)
    }
    const children = report.artifact_tree?.children
    children?.forEach(visit)
    // A projected/legacy tree can omit artifacts that still have raw reports.
    // Read those too, and retain any disagreement as incomplete coverage.
    for (const artifact of report.artifacts ?? []) {
        if (artifact.artifact_id === report.job_id) continue
        if (artifact.report || !coveredArtifacts.has(artifact.artifact_id)) {
            const coverage = artifact.report?.analysis?.static?.stage_coverage
            if (!staticStateComplete(artifact.report?.analysis?.static?.status, coverage)) complete = false
            scanState(coverage)
        }
        coveredArtifacts.add(artifact.artifact_id)
    }
    if ((report.child_jobs ?? []).some((child) => !coveredArtifacts.has(child.job_id))
        || (report.batch_analysis?.artifact_count ?? 0) > coveredArtifacts.size) {
        complete = false
        antivirusStates.push('unknown')
    }
    if (report.batch_analysis && (!successful.has(report.batch_analysis.status)
        || (report.batch_analysis.incomplete_artifacts?.length ?? 0) > 0)) complete = false
    const antivirusStatus = antivirusStates.includes('incomplete') ? 'incomplete'
        : antivirusStates.includes('unknown') ? 'unknown' : 'complete'
    return { complete: complete && antivirusStatus === 'complete', antivirusStatus }
}

export function hasAvailableReference(reference: Record<string, unknown> | undefined): boolean {
    return Boolean(reference && reference.available === true)
}

export function passwordTargets(report: Report): Array<{ jobId: string; filename: string; path?: string | null }> {
    const targets = new Map<string, { jobId: string; filename: string; path?: string | null }>()
    const declared = report.password_required_artifacts
    const allowed = (id: string) => !declared || declared.includes(id)
    if (report.job_status === 'password_required' && allowed(report.job_id) &&
        (!report.artifact_tree || report.artifact_tree.job_status === 'password_required' || declared?.includes(report.job_id))) {
        targets.set(report.job_id, { jobId: report.job_id, filename: report.file.original_filename })
    }
    for (const child of report.child_jobs) {
        if (child.status === 'password_required' && allowed(child.job_id)) targets.set(child.job_id, { jobId: child.job_id, filename: child.filename })
    }
    const visit = (node: ArtifactTreeNode) => {
        if (node.job_id && node.job_status === 'password_required' && allowed(node.job_id)) {
            targets.set(node.job_id, { jobId: node.job_id, filename: node.filename, path: node.display_path || node.origin_path })
        }
        node.children.forEach(visit)
    }
    if (report.artifact_tree) visit(report.artifact_tree)
    return [...targets.values()]
}

export function passwordTargetError(report: Report, jobId: string): string | undefined {
    // Encryption metadata alone does not authorize a retry. Only expose a
    // wrong-password hint for a target the current waiting state identifies.
    if (!passwordTargets(report).some((target) => target.jobId === jobId)) return undefined
    const artifact = report.artifacts?.find((item) => item.artifact_id === jobId)
    if (artifact?.reason === 'wrong_password') return 'wrong_password'
    const local = jobId === report.job_id ? report : artifact?.report
    const format = local?.results?.format_analysis
    const features = format?.features
    if (features && typeof features === 'object' && !Array.isArray(features)
        && (features as Record<string, unknown>).content_access === 'wrong_password') return 'wrong_password'
    return undefined
}
