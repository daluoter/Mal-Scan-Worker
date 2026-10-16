import type { ArtifactTreeNode, JobStatus, Report, StageCoverage } from '../../api/types'

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
