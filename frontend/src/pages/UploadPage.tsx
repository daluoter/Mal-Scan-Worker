import { useState, useCallback, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'

const CLOUD_DEMO = apiClient.isCloudDemo()
const MAX_SIZE = CLOUD_DEMO ? 20_000_000 : 100 * 1024 * 1024
const SIZE_LABEL = CLOUD_DEMO ? '20 MB（20,000,000 bytes）' : '100 MB'

export default function UploadPage() {
    const navigate = useNavigate()
    const [file, setFile] = useState<File | null>(null)
    const [isDragging, setIsDragging] = useState(false)
    const [isUploading, setIsUploading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [recoveryJobId, setRecoveryJobId] = useState<string | null>(null)
    const [isBackendOnline, setIsBackendOnline] = useState<boolean | null>(null)

    // Health check polling
    useEffect(() => {
        const checkBackend = async () => {
            const online = await apiClient.checkHealth()
            setIsBackendOnline(online)
        }
        checkBackend()
        const interval = setInterval(checkBackend, 10000)
        return () => clearInterval(interval)
    }, [])

    const handleFile = useCallback((selectedFile: File) => {
        if (selectedFile.size < 1 || selectedFile.size > MAX_SIZE) {
            setError(`請選擇非空白且不超過 ${SIZE_LABEL} 的檔案（實際：${selectedFile.size.toLocaleString()} bytes）`)
            return
        }
        setError(null)
        setFile(selectedFile)
    }, [])

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(false)
        const droppedFile = e.dataTransfer.files[0]
        if (droppedFile) {
            handleFile(droppedFile)
        }
    }, [handleFile])

    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(true)
    }, [])

    const handleDragLeave = useCallback(() => {
        setIsDragging(false)
    }, [])

    const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0]
        if (selectedFile) {
            handleFile(selectedFile)
        }
    }, [handleFile])

    const handleUpload = async () => {
        if (!file) return

        setIsUploading(true)
        setError(null)
        setRecoveryJobId(null)

        try {
            const result = await apiClient.uploadFile(file)
            navigate(`/jobs/${result.job_id}`, {
                state: {
                    fileName: file.name,
                    fileSize: file.size
                }
            })
        } catch (err) {
            setError(err instanceof Error ? err.message : '上傳失敗')
            setRecoveryJobId((err as Error & { jobId?: string }).jobId ?? null)
        } finally {
            setIsUploading(false)
        }
    }

    return (
        <div className="container">
            {/* Header */}
            <div className="mb-8">
                <h1 className="text-4xl font-bold mb-2 bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                    🔍 MalScan
                </h1>
                <p className="text-slate-400">
                    上傳檔案進行惡意軟體分析
                </p>
                {CLOUD_DEMO && <p className="mt-3 text-sm text-caution-yellow">雲端 demo 提供靜態分析，使用量與保存時間有限。報告權限保存在此分頁；重新整理後可繼續查看，請保留此分頁。</p>}
            </div>

            {/* Main Card */}
            <div className="glass-card p-6">
                {/* Backend Status Indicator */}
                <div className="flex items-center justify-center gap-3 mb-6 p-3 rounded-lg bg-void/50">
                    <div className={`status-dot ${isBackendOnline === null
                        ? 'status-dot-checking animate-pulse'
                        : isBackendOnline
                            ? 'status-dot-online'
                            : 'status-dot-offline'
                        }`} />
                    <span className={`text-sm font-medium ${isBackendOnline === null
                        ? 'text-slate-400'
                        : isBackendOnline
                            ? 'text-matrix-green'
                            : 'text-alert-red'
                        }`}>
                        {isBackendOnline === null
                            ? '檢查連線中...'
                            : isBackendOnline
                                ? '後端已連線'
                                : '後端離線 - 無法上傳'}
                    </span>
                </div>

                {/* Holographic Drop Zone */}
                <div
                    className={`drop-zone holographic ${isDragging ? 'dragging' : ''}`}
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onClick={() => document.getElementById('file-input')?.click()}
                >
                    <input
                        id="file-input"
                        type="file"
                        onChange={handleFileSelect}
                        className="hidden"
                    />

                    {file ? (
                        <div className="text-center">
                            <div className="text-5xl mb-4">📄</div>
                            <p className="text-xl font-semibold text-neon-cyan mb-2">
                                {file.name}
                            </p>
                            <p className="text-slate-400 font-mono text-sm">
                                {(file.size / 1024 / 1024).toFixed(2)} MB
                            </p>
                        </div>
                    ) : (
                        <div className="text-center">
                            <div className="text-5xl mb-4 opacity-50">
                                ⬆️
                            </div>
                            <p className="text-xl font-medium mb-2">
                                拖放檔案到此處
                            </p>
                            <p className="text-slate-400 text-sm">
                                或點擊選擇檔案 • 最大 {SIZE_LABEL}
                            </p>
                        </div>
                    )}
                </div>

                {/* Error Message */}
                {error && (
                    <div className="error-message mt-4">
                        <span className="font-mono text-sm">⚠ {error}</span>
                    </div>
                )}
                {recoveryJobId && <p className="mt-4 text-sm text-caution-yellow">上傳回應未成功，已保留既有工作。<Link className="ml-2 text-neon-cyan underline" to={`/jobs/${recoveryJobId}`}>先查看此工作狀態</Link>，避免重複上傳。</p>}

                {/* Upload Button */}
                <button
                    className={`btn-neon w-full mt-6 glitch-hover ${isUploading ? 'animate-pulse' : ''}`}
                    onClick={handleUpload}
                    disabled={!file || isUploading || isBackendOnline === false}
                >
                    {isUploading ? (
                        <span className="flex items-center justify-center gap-2">
                            <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            分析中...
                        </span>
                    ) : (
                        '🚀 開始分析'
                    )}
                </button>
            </div>

            {/* Footer */}
            <div className="mt-8 text-center">
                <p className="text-slate-500 text-xs font-mono">
                    MALSCAN v0.1.0 • 惡意附件分析平台
                </p>
            </div>
        </div>
    )
}
