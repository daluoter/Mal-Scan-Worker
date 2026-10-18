import { FormEvent, useState } from 'react'
import { localizeReportText } from './report/reportText'

interface PasswordFormProps {
    attemptsUsed: number
    attemptsRemaining: number
    onSubmit: (password: string) => Promise<void>
    error?: string | null
    filename?: string
    artifactPath?: string | null
    attemptsScope?: string
}

export default function PasswordForm({
    attemptsUsed,
    attemptsRemaining,
    onSubmit,
    error,
    filename,
    artifactPath,
    attemptsScope,
}: PasswordFormProps) {
    const [password, setPassword] = useState('')
    const [isSubmitting, setIsSubmitting] = useState(false)
    const isAttemptsExhausted = attemptsRemaining <= 0

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()
        if (password.length === 0 || isSubmitting || isAttemptsExhausted) return

        setIsSubmitting(true)
        try {
            await onSubmit(password)
            setPassword('')
        } catch {
            // Error UI is controlled by parent via `error` prop.
        } finally {
            setIsSubmitting(false)
        }
    }

    return (
        <div className="p-4 rounded-lg bg-caution-yellow/10 border border-caution-yellow/40">
            <h2 className="text-lg font-semibold text-caution-yellow">需要檔案密碼</h2>
            {filename && <p className="mt-2 break-all font-mono text-sm text-white">{artifactPath || filename}</p>}
            <p className="mt-2 text-sm text-slate-300">
                這個檔案需要密碼才能繼續分析。請輸入加密壓縮檔或 PDF 的密碼；已完成的分析成果會保留。
            </p>

            <div className="mt-3 font-mono text-sm text-slate-300">
                {attemptsScope && <p className="mb-2 text-xs text-slate-400">{attemptsScope}</p>}
                <span>已嘗試: {attemptsUsed}</span>
                <span className="mx-2 text-slate-500">|</span>
                <span>剩餘次數: {attemptsRemaining}</span>
            </div>

            {isAttemptsExhausted && (
                <div className="mt-3 rounded-md border border-alert-red bg-alert-red/10 px-3 py-2 text-sm text-alert-red">
                    已達密碼嘗試上限，無法再次提交密碼。
                </div>
            )}

            <form className="mt-4 flex flex-col gap-3" onSubmit={handleSubmit}>
                <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    aria-label="檔案密碼"
                    placeholder="輸入檔案密碼"
                    className="w-full rounded-lg border border-slate-700 bg-deep-space px-3 py-2 text-white placeholder:text-slate-500 focus:border-caution-yellow focus:outline-none"
                    autoComplete="off"
                    maxLength={256}
                    disabled={isSubmitting || isAttemptsExhausted}
                />

                <button
                    type="submit"
                    className="self-start rounded-lg bg-caution-yellow px-4 py-2 font-semibold text-black transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={isSubmitting || isAttemptsExhausted || password.length === 0}
                >
                    {isSubmitting ? '提交中...' : '提交密碼'}
                </button>
            </form>

            {error && (
                <div className="mt-3 rounded-md border border-alert-red bg-alert-red/10 px-3 py-2 text-sm text-alert-red">
                    {localizeReportText(error)}
                </div>
            )}
        </div>
    )
}
