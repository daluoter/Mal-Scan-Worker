import type { ArtifactTreeNode, JobStatus, Report, UploadResponse } from './types'
import { passwordTargetError, passwordTargets } from '../components/report/reportState'

interface Ownership { rootId: string; capability: string }
interface Ticket { token: string; capability_token: string; job_id: string; max_bytes: number; expires_at: number }
type OwnershipStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/
const TOKEN = /^[a-f0-9]{64}$/

export class CloudTransport {
    private reports = new Map<string, Report>()
    private passwordSnapshots = new Map<string, string>()
    constructor(private baseUrl: string, private storage: OwnershipStorage) {}

    private key(jobId: string): string { return `malscan:cloud:${this.baseUrl}:${jobId}` }

    private ownership(jobId: string): Ownership {
        if (!UUID.test(jobId)) throw new Error('Demo 工作 ID 無效。')
        let text: string | null
        try { text = this.storage.getItem(this.key(jobId)) } catch { throw new Error('無法讀取此分頁保存的 demo 存取憑證。') }
        if (!text) throw new Error('此分頁沒有這份 demo 報告的存取憑證。請回到原上傳分頁。')
        const value = JSON.parse(text) as Ownership
        if (!UUID.test(value.rootId) || !TOKEN.test(value.capability)) throw new Error('Demo 存取憑證無效。')
        return value
    }

    private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
        const response = await fetch(`${this.baseUrl}${path}`, { cache: 'no-store', credentials: 'omit', redirect: 'error', ...options })
        if (!response.ok) {
            let message = '雲端 demo 請求失敗'
            try {
                const body = await response.json()
                message = String(body.error?.message || body.error?.code || body.error || message)
            } catch { /* Keep the predictable fallback. */ }
            const error = new Error(message) as Error & { status?: number }
            error.status = response.status
            throw error
        }
        return response.json() as Promise<T>
    }

    async upload(file: File): Promise<UploadResponse> {
        if (file.size < 1 || file.size > 20_000_000) throw new Error('雲端 demo 支援 1 至 20,000,000 bytes 的檔案。')
        const probe = this.key('storage-check')
        try { this.storage.setItem(probe, 'ok'); this.storage.removeItem(probe) } catch { throw new Error('請允許此分頁使用 sessionStorage，才能保留 demo 報告的存取憑證。') }
        const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
        const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
        const ticket = await this.request<Ticket>('/api/v1/upload-tickets', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: file.name, bytes: file.size, sha256 }),
        })
        if (!UUID.test(ticket.job_id) || !TOKEN.test(ticket.token) || !TOKEN.test(ticket.capability_token)
            || ticket.max_bytes !== file.size || !Number.isSafeInteger(ticket.expires_at) || ticket.expires_at <= Date.now()) throw new Error('Demo 上傳票證格式無效。')
        this.storage.setItem(this.key(ticket.job_id), JSON.stringify({ rootId: ticket.job_id, capability: ticket.capability_token }))
        // The browser supplies Content-Length; forbidden request headers are not set manually.
        try {
            const uploaded = await this.request<UploadResponse>('/api/v1/files', {
                method: 'POST', headers: { Authorization: `Bearer ${ticket.token}`, 'Content-Type': 'application/octet-stream' }, body: file,
            })
            if (uploaded.job_id !== ticket.job_id) throw new Error('Demo 上傳工作 ID 不符。')
            return uploaded
        } catch (error) {
            // Keep the original job reachable even when the upload response is lost.
            if (error instanceof Error) Object.assign(error, { jobId: ticket.job_id })
            throw error
        }
    }

    private headers(ownership: Ownership): Record<string, string> { return { Authorization: `Bearer ${ownership.capability}` } }

    private register(ownership: Ownership, ids: string[]) {
        for (const id of ids) {
            if (UUID.test(id)) this.storage.setItem(this.key(id), JSON.stringify(ownership))
        }
    }

    private childStatus(root: JobStatus, report: Report | undefined, jobId: string): JobStatus['status'] {
        if (root.status === 'failed') return 'failed'
        if (root.status === 'queued' || root.status === 'scanning') return root.status
        if (root.status === 'password_required' && root.password_required_artifacts?.includes(jobId)) return 'password_required'
        const artifact = report?.artifacts?.find((item) => item.artifact_id === jobId)
        if (artifact?.status === 'limited' || artifact?.status === 'failed') return 'failed'
        if (artifact?.status === 'done') return 'done'
        // Root password_required can refer to a different artifact. Never guess this child's password state.
        return 'scanning'
    }

    private passwordSnapshotKey(root: JobStatus): string {
        return JSON.stringify([root.password_attempts, root.total_password_submissions,
            [...(root.password_required_artifacts ?? [])].sort()])
    }

    private async rootStatus(ownership: Ownership): Promise<JobStatus> {
        const root = await this.request<JobStatus>(`/api/v1/jobs/${ownership.rootId}`, { headers: this.headers(ownership) })
        this.register(ownership, root.password_required_artifacts ?? [])
        return root
    }

    private async readReport(ownership: Ownership, root: JobStatus): Promise<Report> {
        const report = await this.request<Report>(`/api/v1/reports/${ownership.rootId}`, { headers: this.headers(ownership) })
        if (report.job_id !== ownership.rootId) throw new Error('Demo 報告工作 ID 不符。')
        this.reports.set(ownership.rootId, report)
        if (root.status === 'password_required') this.passwordSnapshots.set(ownership.rootId, this.passwordSnapshotKey(root))
        this.register(ownership, report.child_jobs.map((child) => child.job_id))
        const visit = (node: ArtifactTreeNode) => { if (node.job_id) this.register(ownership, [node.job_id]); node.children.forEach(visit) }
        if (report.artifact_tree) visit(report.artifact_tree)
        return report
    }

    async getReport(jobId: string): Promise<Report> {
        const ownership = this.ownership(jobId)
        const root = await this.rootStatus(ownership)
        const report = await this.readReport(ownership, root)
        report.password_required_artifacts = root.status === 'password_required' ? root.password_required_artifacts ?? [] : []
        report.job_status = root.status
        report.execution_active = root.dispatch_uncertain ? null : root.status === 'queued' || root.status === 'scanning'
        report.requires_reconciliation = Boolean(root.dispatch_uncertain)
        report.error_message = root.error_message
        report.password_attempts_by_artifact = root.password_attempts_by_artifact
        report.password_attempts_scope = root.password_attempts_scope
        report.total_password_submissions = root.total_password_submissions
        report.legacy_password_submissions = root.legacy_password_submissions
        report.report_complete = root.status === 'done' && report.report_complete === true
        if (jobId === ownership.rootId) return report
        const artifact = report.artifacts?.find((item) => item.artifact_id === jobId)
        if (!artifact?.report) {
            const error = new Error('此子檔尚未建立可閱讀的報告；已保留根工作報告。') as Error & { status?: number }
            error.status = 409
            throw error
        }
        let subtree: ArtifactTreeNode | null = null
        const ids = new Set<string>()
        const find = (node: ArtifactTreeNode) => {
            if (node.job_id === jobId) subtree = node
            node.children.forEach(find)
        }
        if (report.artifact_tree) find(report.artifact_tree)
        const collect = (node: ArtifactTreeNode) => { if (node.job_id) ids.add(node.job_id); node.children.forEach(collect) }
        if (subtree) collect(subtree)
        const pending = report.child_jobs.filter((child) => child.job_id !== jobId && ids.has(child.job_id) && ['queued', 'running', 'password_required'].includes(child.status)).length
        const status = this.childStatus(root, report, jobId)
        return { ...artifact.report, job_id: jobId, parent_job_id: ownership.rootId,
            report_schema_version: report.report_schema_version,
            job_status: status, report_complete: status === 'done' && pending === 0,
            pending_descendants: pending,
            execution_active: report.execution_active, requires_reconciliation: report.requires_reconciliation,
            error_message: report.error_message,
            password_attempts_scope: root.password_attempts_scope,
            password_attempts_by_artifact: root.password_attempts_by_artifact ? Object.fromEntries(
                Object.entries(root.password_attempts_by_artifact).filter(([id]) => id === jobId || ids.has(id))) : undefined,
            child_jobs: report.child_jobs.filter((child) => child.job_id !== jobId && ids.has(child.job_id)),
            artifact_tree: subtree, password_required_artifacts: report.password_required_artifacts }
    }

    async getJobStatus(jobId: string): Promise<JobStatus> {
        const ownership = this.ownership(jobId)
        const root = await this.rootStatus(ownership)
        let previous = this.reports.get(ownership.rootId)
        let unavailable = false
        if (root.report_available && (
            (root.status === 'password_required' && this.passwordSnapshots.get(ownership.rootId) !== this.passwordSnapshotKey(root))
            || (jobId !== ownership.rootId && this.childStatus(root, previous, jobId) === 'scanning' && root.status !== 'queued' && root.status !== 'scanning')
        )) {
            try { previous = await this.readReport(ownership, root) } catch (error) {
                if (root.status !== 'password_required') throw error
                // The signed status remains useful, but an old snapshot cannot
                // tell whether the most recent credential was rejected.
                unavailable = true
                previous = undefined
            }
        }
        const status = jobId === ownership.rootId ? root.status : this.childStatus(root, previous, jobId)
        const counts = root.password_attempts_by_artifact?.[jobId]
        const authorized = previous ? { ...previous, job_status: root.status,
            password_required_artifacts: root.status === 'password_required' ? root.password_required_artifacts ?? [] : [] } : undefined
        const target = authorized ? passwordTargets(authorized).find((item) => item.jobId === jobId) : undefined
        return { ...root, job_id: jobId, parent_job_id: jobId === ownership.rootId ? null : ownership.rootId, status,
            ...(counts ? { password_attempts: counts.attempts_used, password_attempts_remaining: counts.attempts_remaining } : {}),
            password_target: target ? { filename: target.filename, path: target.path } : undefined,
            error_message: unavailable ? '無法取得最新密碼驗證結果，正在重新查詢。'
                : status === 'password_required' && authorized ? passwordTargetError(authorized, jobId) ?? root.error_message
                    : previous?.artifacts?.find((item) => item.artifact_id === jobId)?.reason === 'password_attempts_exhausted'
                        ? '此檔案的三次密碼提交已用完，加密內容未能分析。' : root.error_message }
    }

    async submitPassword(jobId: string, password: string) {
        if (!password || password.length > 256 || password.includes('\0')) throw new Error('密碼必須為 1 至 256 個字元，且不能包含空字元。')
        const ownership = this.ownership(jobId)
        return this.request<{ job_id: string; status: string; password_attempts: number; password_attempts_remaining: number }>(`/api/v1/jobs/${jobId}/password`, {
            method: 'POST', headers: { ...this.headers(ownership), 'Content-Type': 'application/json' }, body: JSON.stringify({ password }),
        })
    }
}
