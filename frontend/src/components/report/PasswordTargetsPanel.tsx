import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiClient } from '../../api/client'
import type { JobStatus, Report } from '../../api/types'
import PasswordForm from '../PasswordForm'
import { passwordTargetError, passwordTargets } from './reportState'

export default function PasswordTargetsPanel({ report, onSubmitted }: { report: Report; onSubmitted: () => void }) {
    const [jobs, setJobs] = useState<Record<string, JobStatus>>({})
    const [errors, setErrors] = useState<Record<string, string>>({})
    const targets = passwordTargets(report)
    const targetIds = targets.map((target) => target.jobId).join(',')
    const updatedAt = report.created_at

    useEffect(() => {
        let cancelled = false
        setErrors({})
        setJobs({})
        let timer: ReturnType<typeof setTimeout> | null = null
        const fetchJobs = async () => {
            await Promise.all(targetIds.split(',').filter(Boolean).map(async (id) => {
                try {
                    const job = await apiClient.getJobStatus(id)
                    if (!cancelled) setJobs((previous) => ({ ...previous, [id]: job }))
                } catch (error) {
                    if (!cancelled) setErrors((previous) => ({ ...previous, [id]: error instanceof Error ? error.message : '無法取得密碼工作狀態' }))
                }
            }))
            if (!cancelled && targetIds) timer = setTimeout(fetchJobs, 3000)
        }
        if (targetIds) fetchJobs()
        return () => {
            cancelled = true
            if (timer) clearTimeout(timer)
        }
    }, [targetIds, updatedAt])

    const submit = async (jobId: string, password: string) => {
        setErrors((previous) => ({ ...previous, [jobId]: '' }))
        try {
            await apiClient.submitArchivePassword(jobId, { password })
            setJobs((previous) => {
                const next = { ...previous }
                delete next[jobId]
                return next
            })
            onSubmitted()
        } catch (error) {
            setErrors((previous) => ({ ...previous, [jobId]: error instanceof Error ? error.message : '提交密碼失敗' }))
            throw error
        }
    }

    if (!targets.length) return null
    return (
        <section className="glass-card p-6 mb-4">
            <h2 className="mb-3 text-lg font-bold text-caution-yellow">等待密碼的檔案（{targets.length}）</h2>
            <p className="mb-4 text-sm text-slate-300">每次提交只用於指定檔案；其他已完成的分析成果會保留。</p>
            <div className="space-y-4">
                {targets.map((target) => (
                    <div key={target.jobId}>
                        <Link className="mb-2 inline-block break-all text-sm text-neon-cyan hover:text-neon-purple" to={`/jobs/${target.jobId}`}>檔案工作：{target.path || target.filename}</Link>
                        {jobs[target.jobId]?.status === 'password_required' ? <PasswordForm
                            filename={target.filename}
                            artifactPath={target.path}
                            attemptsScope={jobs[target.jobId].password_attempts_scope === 'artifact' || !apiClient.isCloudDemo()
                                ? '每個檔案各自最多提交三次密碼；解開 ZIP 不會扣掉內層 PDF 的次數。'
                                : '目前服務仍使用整個上傳工作共用的密碼次數；更新控制層後才會改成逐檔計算。'}
                            attemptsUsed={jobs[target.jobId].password_attempts}
                            attemptsRemaining={jobs[target.jobId].password_attempts_remaining}
                            onSubmit={(password) => submit(target.jobId, password)}
                            error={errors[target.jobId] || passwordTargetError(report, target.jobId) || jobs[target.jobId].error_message}
                        /> : <p className="text-sm text-slate-400">{errors[target.jobId] || (jobs[target.jobId] ? '此檔案的工作狀態已更新。' : '取得密碼工作狀態中…')}</p>}
                    </div>
                ))}
            </div>
        </section>
    )
}
