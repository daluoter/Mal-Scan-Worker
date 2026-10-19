import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate, Link, useLocation } from 'react-router-dom'
import { apiClient, JobStatus } from '../api/client'
import PasswordForm from '../components/PasswordForm'
import { jobNeedsPassword } from '../components/report/reportState'
import { STATUS_COLORS, STATUS_LABELS } from '../constants/status'

interface LocationState {
    fileName?: string
    fileSize?: number
}

export default function JobStatusPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const navigate = useNavigate()
    const location = useLocation()
    const fileInfo = (location.state as LocationState) || {}
    const [job, setJob] = useState<JobStatus | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [passwordSubmitError, setPasswordSubmitError] = useState<string | null>(null)
    const [refreshKey, setRefreshKey] = useState(0)
    const previousStatusRef = useRef<JobStatus['status'] | null>(null)

    useEffect(() => {
        if (!jobId) return

        setPasswordSubmitError(null)
        setJob(null)
        setError(null)
        previousStatusRef.current = null

        const es = apiClient.supportsJobStream() && typeof EventSource !== 'undefined' ? new EventSource(apiClient.getJobStreamUrl(jobId)) : null
        let cancelled = false
        let fallbackTimer: ReturnType<typeof setTimeout> | null = null
        const applyStatus = (data: JobStatus) => {
            if (cancelled) return
            setJob(data)
            setError(null)
            if (data.status === 'done') {
                es?.close()
                navigate(`/reports/${jobId}`)
            } else if (data.status === 'failed') {
                es?.close()
            }
        }
        const fetchStatus = async () => {
            if (cancelled) return
            try {
                const data = await apiClient.getJobStatus(jobId)
                applyStatus(data)
                if (!cancelled && data.status !== 'done' && (data.status !== 'failed' || data.dispatch_uncertain) && (!es || es.readyState !== EventSource.OPEN)) {
                    fallbackTimer = setTimeout(fetchStatus, 3000)
                }
            } catch (err) {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : '無法取得狀態')
                    fallbackTimer = setTimeout(fetchStatus, 5000)
                }
            }
        }
        fetchStatus()

        if (es) es.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data) as JobStatus
                if (fallbackTimer) clearTimeout(fallbackTimer)
                applyStatus(data)
            } catch {
                // ignore malformed messages
            }
        }

        if (es) es.onerror = () => {
            // REST keeps password/partial-report state readable while SSE reconnects.
            if (fallbackTimer) clearTimeout(fallbackTimer)
            fallbackTimer = setTimeout(fetchStatus, 1000)
        }

        return () => {
            cancelled = true
            if (fallbackTimer) clearTimeout(fallbackTimer)
            es?.close()
        }
    }, [jobId, navigate, refreshKey])

    useEffect(() => {
        if (!job) return

        if (previousStatusRef.current !== job.status) {
            setPasswordSubmitError(null)
            previousStatusRef.current = job.status
        }
    }, [job])

    const stageLabels: Record<string, string> = {
        'file-type': '檔案類型偵測',
        clamav: 'ClamAV 掃描',
        yara: 'YARA 規則比對',
        'ioc-extract': 'IOC 擷取',
        sandbox: '沙箱分析',
        sandbox_pending: '等待沙箱結果',
        'format-analysis': '格式分析',
        'archive-extract': '封存解壓',
        deobfuscation: '去混淆分析',
    }

    if (error && !job) {
        return (
            <div className="container">
                <h1 className="text-3xl font-bold mb-6 text-alert-red">
                    ❌ 錯誤
                </h1>
                <div className="error-message">
                    <span className="font-mono">{error}</span>
                </div>
                <Link to="/" className="inline-block mt-6 text-neon-cyan hover:text-neon-purple">
                    ← 返回上傳
                </Link>
            </div>
        )
    }

    if (!job) {
        return (
            <div className="container">
                <div className="glass-card p-8 text-center">
                    <div className="text-4xl mb-4 animate-pulse">⏳</div>
                    <p className="text-xl font-mono text-neon-cyan terminal-cursor">
                        載入中
                    </p>
                </div>
            </div>
        )
    }

    const handlePasswordSubmit = async (password: string) => {
        if (!jobId) return

        setPasswordSubmitError(null)
        try {
            await apiClient.submitArchivePassword(jobId, { password })
            setRefreshKey((previous) => previous + 1)
        } catch (submitError) {
            const message = submitError instanceof Error ? submitError.message : '提交密碼失敗，請再試一次'
            setPasswordSubmitError(message)
            throw submitError
        }
    }

    return (
        <div className="container">
            {/* Header */}
            <h1 className="text-3xl font-bold mb-6 bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                🔄 分析進度
            </h1>

            <div className="glass-card p-6">
                {error && <p className="mb-4 text-sm text-caution-yellow">狀態更新暫時失敗：{error}。稍後自動重試。</p>}
                {job.dispatch_uncertain && <p className="mb-4 text-sm text-caution-yellow">雲端執行狀態尚未確認，系統會繼續查詢。請保留此工作頁，避免重新上傳建立重複工作；管理者可能需要核對 Cloud Run 執行紀錄。</p>}
                {/* Terminal Header */}
                <div className="flex items-center gap-2 mb-4 pb-4 border-b border-white/10">
                    <div className="w-3 h-3 rounded-full bg-alert-red" />
                    <div className="w-3 h-3 rounded-full bg-caution-yellow" />
                    <div className="w-3 h-3 rounded-full bg-matrix-green" />
                    <span className="ml-2 text-slate-500 text-sm font-mono">malscan-terminal</span>
                </div>

                {job.report_available && (
                    <Link to={`/reports/${jobId}`} className="mt-4 inline-block text-sm text-neon-cyan hover:text-neon-purple">
                        閱讀目前分析報告（後續成果會持續更新） →
                    </Link>
                )}

                {/* Job Info - Terminal Style */}
                <div className="space-y-2 font-mono text-sm">
                    {fileInfo.fileName && (
                        <div className="flex items-start gap-2">
                            <span className="text-neon-purple">$</span>
                            <span className="text-slate-400">檔案：</span>
                            <span className="text-white">{fileInfo.fileName}</span>
                            {fileInfo.fileSize && (
                                <span className="text-slate-500">
                                    ({(fileInfo.fileSize / 1024 / 1024).toFixed(2)} MB)
                                </span>
                            )}
                        </div>
                    )}
                    <div className="flex items-start gap-2">
                        <span className="text-neon-purple">$</span>
                        <span className="text-slate-400">工作 ID：</span>
                        <span className="text-neon-cyan break-all">{job.job_id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-neon-purple">$</span>
                        <span className="text-slate-400">狀態：</span>
                        <span className={`font-bold ${STATUS_COLORS[job.status]}`}>
                            {STATUS_LABELS[job.status] || job.status}
                        </span>
                    </div>
                </div>

                {jobNeedsPassword(job) && (
                    <div className="mt-6">
                        <PasswordForm
                            filename={job.password_target?.filename ?? fileInfo.fileName}
                            artifactPath={job.password_target?.path}
                            attemptsUsed={job.password_attempts}
                            attemptsRemaining={job.password_attempts_remaining}
                            attemptsScope={job.password_attempts_scope === 'artifact' || !apiClient.isCloudDemo()
                                ? '這個檔案最多可提交三次密碼；其他檔案各自計算。成功或錯誤的提交都會計入本檔次數。'
                                : '目前服務仍使用整個上傳工作共用的密碼次數；更新控制層後才會改成逐檔計算。'}
                            onSubmit={handlePasswordSubmit}
                            error={passwordSubmitError ?? job.error_message ?? null}
                        />
                    </div>
                )}
                {apiClient.isCloudDemo() && job.status === 'password_required' && job.password_required_artifacts?.some((id) => id !== job.job_id) && (
                    <div className="mt-6 rounded-lg border border-caution-yellow/40 p-4">
                        <p className="mb-3 text-sm text-caution-yellow">子檔需要密碼，請開啟指定檔案提交；次數與剩餘額度以該檔案的密碼表單為準。</p>
                        <div className="flex flex-col gap-2">{job.password_required_artifacts.filter((id) => id !== job.job_id).map((id) => <Link key={id} className="break-all text-sm text-neon-cyan hover:text-neon-purple" to={`/jobs/${id}`}>等待密碼的子檔：{id}</Link>)}</div>
                    </div>
                )}

                {/* HUD Progress Bar */}
                <div className="mt-6">
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-sm text-slate-400 font-mono">進度</span>
                        <span className="text-sm font-mono text-neon-cyan">
                            {job.progress.percent}%
                        </span>
                    </div>
                    <div className="hud-progress">
                        <div
                            className="hud-progress-fill"
                            style={{ width: `${job.progress.percent}%` }}
                        />
                        <div className="hud-progress-scan" />
                    </div>
                </div>

                {/* Current Stage */}
                {job.progress.current_stage && (
                    <div className="mt-6 p-4 bg-deep-space rounded-lg border border-neon-cyan/20">
                        <div className="flex items-center gap-2 font-mono text-sm">
                            <span className="text-neon-cyan animate-pulse">▶</span>
                            <span className="text-matrix-green">執行中：</span>
                            <span className="text-white">
                                {stageLabels[job.progress.current_stage] || job.progress.current_stage}
                            </span>
                            <span className="text-slate-500 animate-pulse">...</span>
                        </div>
                    </div>
                )}

                {/* Stage Progress */}
                <div className="mt-4 text-sm text-slate-400 font-mono">
                    <span className="text-neon-purple">[</span>
                    <span className="text-matrix-green">{job.progress.stages_done}</span>
                    <span className="text-slate-500">/</span>
                    <span className="text-white">{job.progress.stages_total}</span>
                    <span className="text-neon-purple">]</span>
                    <span className="ml-2">已完成階段</span>
                </div>

                {/* Error Display */}
                {job.status === 'failed' && job.error_message && (
                    <div className="mt-6 p-4 rounded-lg bg-alert-red/10 border border-alert-red">
                        <div className="font-mono text-sm">
                            <span className="text-alert-red">錯誤：</span>
                            <span className="text-white ml-2">{job.error_message}</span>
                        </div>
                    </div>
                )}
            </div>

            {/* Back Link */}
            <div className="mt-6 flex flex-col gap-2">
                {job.parent_job_id && (
                    <Link
                        to={`/jobs/${job.parent_job_id}`}
                        className="inline-flex items-center gap-2 text-sm font-mono text-neon-cyan hover:text-neon-purple transition-colors"
                    >
                        <span>←</span>
                        <span>返回上一層分析</span>
                    </Link>
                )}

                <Link
                    to="/"
                    className="inline-flex items-center gap-2 text-sm font-mono text-slate-400 hover:text-neon-cyan transition-colors"
                >
                    <span>←</span>
                    <span>返回上傳</span>
                </Link>
            </div>
        </div>
    )
}
