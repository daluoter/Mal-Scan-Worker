import type {
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    Report,
    UploadResponse,
} from './types'
import { CloudTransport } from './cloudTransport'

export type {
    ApiError,
    AvResult,
    FileMetadata,
    HealthResponse,
    Iocs,
    JobProgress,
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    Report,
    StageTiming,
    UploadResponse,
    YaraHit,
} from './types'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '')

class ApiClient {
    public baseUrl: string
    private cloud?: CloudTransport

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl
        if (import.meta.env.VITE_DEPLOYMENT_MODE === 'cloud-demo' || import.meta.env.VITE_API_DEPLOYMENT === 'cloud-demo') {
            // Access storage lazily: browsers may deny it until an upload is attempted.
            this.cloud = new CloudTransport(baseUrl, {
                getItem: (key) => window.sessionStorage.getItem(key),
                setItem: (key, value) => window.sessionStorage.setItem(key, value),
                removeItem: (key) => window.sessionStorage.removeItem(key),
            })
        }
    }

    supportsJobStream(): boolean { return !this.cloud }
    isCloudDemo(): boolean { return Boolean(this.cloud) }

    getJobStreamUrl(jobId: string): string {
        return `${this.baseUrl}/api/v1/jobs/${jobId}/stream`
    }

    async checkHealth(): Promise<boolean> {
        try {
            const response = await fetch(`${this.baseUrl}${this.cloud ? '/api/v1/capabilities' : '/health'}`)
            return response.ok
        } catch {
            return false
        }
    }

    async uploadFile(file: File): Promise<UploadResponse> {
        if (this.cloud) return this.cloud.upload(file)
        const formData = new FormData()
        formData.append('file', file)

        const response = await fetch(`${this.baseUrl}/api/v1/files`, {
            method: 'POST',
            body: formData,
        })

        if (!response.ok) {
            const errorData = await response.json()
            // FastAPI wraps HTTPException detail in {"detail": ...}
            // Handle both {"detail": {"error": {"message": "..."}}} and {"error": {"message": "..."}}
            const errorMessage =
                errorData?.detail?.error?.message ||
                errorData?.detail?.message ||
                errorData?.error?.message ||
                errorData?.detail ||
                '上傳失敗'
            throw new Error(String(errorMessage))
        }

        return response.json()
    }

    async getJobStatus(jobId: string): Promise<JobStatus> {
        if (this.cloud) return this.cloud.getJobStatus(jobId)
        const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}`)

        if (!response.ok) {
            let errorMessage = '取得工作狀態失敗'
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                               errorData?.detail?.message ||
                               errorData?.error?.message ||
                               errorData?.detail ||
                               errorMessage
            } catch {
                errorMessage = response.statusText
            }
            const error = new Error(String(errorMessage)) as Error & { status?: number }
            error.status = response.status
            throw error
        }

        return response.json()
    }

    async getReport(jobId: string): Promise<Report> {
        if (this.cloud) return this.cloud.getReport(jobId)
        const response = await fetch(`${this.baseUrl}/api/v1/reports/${jobId}`)

        if (!response.ok) {
            let errorMessage = '取得報告失敗'
            const error = new Error(errorMessage) as Error & { status?: number }
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                                errorData?.error?.message ||
                                errorData?.detail ||
                                errorMessage
            } catch {
                errorMessage = response.statusText
            }
            error.message = errorMessage
            error.status = response.status
            throw error
        }

        return response.json()
    }

    /** Submit a file password for a supported archive or PDF; retain the legacy method name. */
    async submitArchivePassword(jobId: string, payload: PasswordSubmitRequest): Promise<PasswordSubmitResponse> {
        if (this.cloud) {
            const response = await this.cloud.submitPassword(jobId, payload.password)
            return { job_id: response.job_id, status: response.status, message: '已提交指定檔案密碼',
                attempts_used: response.password_attempts, attempts_remaining: response.password_attempts_remaining }
        }
        const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}/password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        })

        if (!response.ok) {
            let errorMessage = '提交檔案密碼失敗'
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                               errorData?.detail?.message ||
                               errorData?.error?.message ||
                               errorData?.detail ||
                               errorMessage
            } catch {
                errorMessage = response.statusText || errorMessage
            }
            throw new Error(String(errorMessage))
        }

        return response.json()
    }
}

export const apiClient = new ApiClient()
