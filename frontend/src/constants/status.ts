import type { JobStatus } from '../api/client'

type JobState = JobStatus['status']

export const STATUS_LABELS: Record<JobState, string> = {
    queued: '排隊中',
    scanning: '分析中',
    password_required: '需要檔案密碼',
    done: '完成',
    failed: '失敗',
}

export const STATUS_COLORS: Record<JobState, string> = {
    queued: 'text-slate-400',
    scanning: 'text-neon-cyan',
    password_required: 'text-caution-yellow',
    done: 'text-matrix-green',
    failed: 'text-alert-red',
}
