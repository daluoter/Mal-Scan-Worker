import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiClient, Report } from '../api/client'
import ArtifactTreePanel from '../components/report/ArtifactTreePanel'
import EvidenceTimelinePanel from '../components/report/EvidenceTimelinePanel'
import FailureDiagnosticsPanel from '../components/report/FailureDiagnosticsPanel'
import ScoreTracePanel from '../components/report/ScoreTracePanel'
import TopFindingsSummary from '../components/report/TopFindingsSummary'
import AnalysisCoveragePanel from '../components/report/AnalysisCoveragePanel'
import DynamicAnalysisPanel from '../components/report/DynamicAnalysisPanel'
import PasswordTargetsPanel from '../components/report/PasswordTargetsPanel'
import { shouldRefreshReport, stageCompleted, stageCoverage } from '../components/report/reportState'
import { localizeReportText, localizeStage, localizeVerdict } from '../components/report/reportText'

export default function ReportPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const [report, setReport] = useState<Report | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [isWaitingDescendants, setIsWaitingDescendants] = useState(false)
    const [copiedHash, setCopiedHash] = useState(false)
    const [refreshKey, setRefreshKey] = useState(0)

    useEffect(() => { setReport(null) }, [jobId])

    useEffect(() => {
        if (!jobId) return

        let cancelled = false
        let retryTimer: ReturnType<typeof setTimeout> | null = null

        const fetchReport = async () => {
            if (cancelled) return

            try {
                const data = await apiClient.getReport(jobId)
                if (cancelled) return
                setReport(data)
                setError(null)
                setIsWaitingDescendants(false)
                if (shouldRefreshReport(data)) retryTimer = setTimeout(fetchReport, 3000)
            } catch (err) {
                if (cancelled) return

                const maybeStatus = (err as Error & { status?: number }).status
                if (maybeStatus === 404 || maybeStatus === 409) {
                    try {
                        const status = await apiClient.getJobStatus(jobId)
                        if (cancelled) return
                        if (status.status === 'failed' && !status.dispatch_uncertain) {
                            setError(status.error_message || '工作失敗，尚未建立可閱讀的報告。')
                            return
                        }
                    } catch (statusError) {
                        if (!cancelled) setError(statusError instanceof Error ? statusError.message : '無法取得工作狀態')
                        if ((statusError as Error & { status?: number }).status !== 404) retryTimer = setTimeout(fetchReport, 5000)
                        return
                    }
                }
                if (maybeStatus === 409 || maybeStatus === 404) {
                    setIsWaitingDescendants(true)
                    setError(null)
                    retryTimer = setTimeout(fetchReport, 3000)
                    return
                }

                setIsWaitingDescendants(false)
                setError(err instanceof Error ? err.message : '無法取得報告')
                retryTimer = setTimeout(fetchReport, 5000)
            }
        }

        setError(null)
        setIsWaitingDescendants(false)
        fetchReport()

        return () => {
            cancelled = true
            if (retryTimer) {
                clearTimeout(retryTimer)
            }
        }
    }, [jobId, refreshKey])

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text)
            setCopiedHash(true)
            setTimeout(() => setCopiedHash(false), 2000)
        } catch {
            // Fallback for older browsers
            console.error('Failed to copy')
        }
    }

    if (error && !report) {
        return (
            <div className="container">
                <h1 className="text-3xl font-bold mb-6 text-alert-red">❌ 錯誤</h1>
                <div className="error-message">
                    <span className="font-mono">{error}</span>
                </div>
                <Link to="/" className="inline-block mt-6 text-neon-cyan hover:text-neon-purple">
                    ← 返回上傳
                </Link>
            </div>
        )
    }

    if (!report) {
        return (
            <div className="container">
                <div className="glass-card p-8 text-center">
                    <div className="text-4xl mb-4 animate-pulse">📋</div>
                    <p className="text-xl font-mono text-neon-cyan terminal-cursor">
                        {isWaitingDescendants ? '等待第一份分析成果' : '載入分析報告中'}
                    </p>
                    {isWaitingDescendants && (
                        <p className="mt-3 text-sm text-slate-400 font-mono">
                            成果建立後即可閱讀，後續子檔與動態結果會自動更新。
                        </p>
                    )}
                </div>
            </div>
        )
    }

    const verdictLabels: Record<string, string> = {
        clean: '未發現威脅',
        suspicious: '可疑',
        malicious: '惡意',
        unknown: '未知',
    }

    const verdictIcons: Record<string, string> = {
        clean: '✅',
        suspicious: '⚠️',
        malicious: '☠️',
        unknown: '❓',
    }

    const verdictClasses: Record<string, string> = {
        clean: 'verdict-clean',
        suspicious: 'verdict-suspicious',
        malicious: 'verdict-malicious',
        unknown: 'glass-card',
    }

    const stageLabels: Record<string, string> = {
        'file-type': '檔案類型判定',
        clamav: '防毒掃描',
        yara: 'YARA 規則比對',
        'ioc-extract': 'IOC 擷取',
        'archive-extract': '封存解壓',
        sandbox: '沙箱分析',
        'format-analysis': '格式分析',
        deobfuscation: '去混淆',
        'document-analysis': '文件分析',
    }

    const avCompleted = stageCompleted(report, 'clamav')
    const iocCompleted = stageCompleted(report, 'ioc-extract')
    const yaraCompleted = stageCompleted(report, 'yara')
    const archiveCompleted = stageCompleted(report, 'archive-extract')
    const downloadReport = () => {
        const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
        const anchor = document.createElement('a')
        anchor.href = url
        anchor.download = `malscan-report-${report.job_id.replace(/[^a-zA-Z0-9-]/g, '_')}.json`
        anchor.click()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
    }

    return (
        <div className="container">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <h1 className="text-3xl font-bold bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                    📋 分析報告
                </h1>
                {report.file.mime.includes('7z') || report.file.mime.includes('zip') || report.file.mime.includes('rar') ? (
                    <span className="px-3 py-1 bg-neon-cyan/20 text-neon-cyan text-xs font-mono rounded-full border border-neon-cyan/30 animate-pulse">
                        📦 ARCHIVE
                    </span>
                ) : null}
            </div>

            {error && <p className="mb-4 rounded-lg border border-caution-yellow/30 p-3 text-sm text-caution-yellow">報告更新暫時失敗：{error}。保留上次取得的成果，稍後自動重試。</p>}
            {report.requires_reconciliation && <p className="mb-4 rounded-lg border border-caution-yellow/30 p-3 text-sm text-caution-yellow">雲端執行狀態尚待核對。以下保留已確認的部分成果，系統會繼續查詢，請避免重新上傳。</p>}
            {report.error_message && <p className="mb-4 text-sm text-caution-yellow">工作狀態說明：{localizeReportText(report.error_message)}</p>}
            <div className="mb-4 flex flex-wrap gap-4 text-sm">
                <button onClick={downloadReport} className="text-neon-cyan hover:text-neon-purple">下載目前完整 JSON 報告</button>
                <Link to={`/jobs/${jobId}`} className="text-slate-300 hover:text-neon-cyan">查看工作狀態</Link>
                {shouldRefreshReport(report) && <span className="text-caution-yellow">成果持續更新中</span>}
            </div>
            <AnalysisCoveragePanel analysis={report.analysis} complete={report.report_complete} pendingDescendants={report.pending_descendants} />
            <PasswordTargetsPanel report={report} onSubmitted={() => setRefreshKey((previous) => previous + 1)} />

            {report.parent_job_id && (
                <Link
                    to={`/jobs/${report.parent_job_id}`}
                    className="inline-flex items-center gap-2 mb-4 text-sm font-mono text-neon-cyan hover:text-neon-purple transition-colors"
                >
                    <span>←</span>
                    <span>返回上一層分析</span>
                </Link>
            )}

            {/* Verdict Card - Prominent Neon Border */}
            <div className={`verdict-card ${report.verdict === 'clean' && report.report_complete !== true ? 'glass-card' : verdictClasses[report.verdict]} mb-6 animate-glow-pulse`}>
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-sm font-mono text-slate-400 mb-1">{report.report_complete === false ? '目前成果判定（分析尚未完成）' : '已取得成果的判定'}</p>
                        <p className="text-3xl font-bold">
                            {verdictIcons[report.verdict]} {verdictLabels[report.verdict] || report.verdict}
                        </p>
                    </div>
                    <div className="text-right">
                        <p className="text-sm font-mono text-slate-400 mb-1">風險分數</p>
                        <p className="text-4xl font-bold font-mono">
                            {report.score}<span className="text-lg text-slate-400">/100</span>
                        </p>
                    </div>
                </div>
            </div>

            <TopFindingsSummary explainability={report.explainability} />
            <ScoreTracePanel risk={report.risk} />
            <ArtifactTreePanel tree={report.artifact_tree} />
            <EvidenceTimelinePanel explainability={report.explainability} />
            <FailureDiagnosticsPanel explainability={report.explainability} />

            {/* Archive Extraction Info (If present) */}
            {report.results.archive_extract && report.results.archive_extract.archive_type && (
                <div className="glass-card p-6 mb-4 border-l-4 border-neon-cyan">
                    <h2 className="text-lg font-bold mb-4 text-neon-cyan flex items-center gap-2">
                        <span>📦 解壓縮資訊</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-neon-cyan/10 border border-neon-cyan/30 uppercase">
                            {report.results.archive_extract.archive_type}
                        </span>
                    </h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-sm">
                        <div>
                            <p className="text-slate-400 mb-1">檔案數量</p>
                            <p className="text-white text-lg font-bold">{report.results.archive_extract.extracted_count}</p>
                        </div>
                        <div>
                            <p className="text-slate-400 mb-1">子工作數</p>
                            <p className="text-neon-cyan text-lg font-bold">{report.results.archive_extract.sub_jobs_created}</p>
                        </div>
                        <div>
                            <p className="text-slate-400 mb-1">解壓後大小</p>
                            <p className="text-white text-lg font-bold">{(report.results.archive_extract.total_extracted_bytes / 1024).toFixed(1)} KB</p>
                        </div>
                        <div>
                            <p className="text-slate-400 mb-1">解壓狀態</p>
                            <p className={report.results.archive_extract.malicious ? 'text-alert-red text-lg font-bold' : archiveCompleted ? 'text-matrix-green text-lg font-bold' : 'text-caution-yellow text-lg font-bold'}>
                                {report.results.archive_extract.malicious ? '⚠️ 警示' : archiveCompleted ? '已完成解壓階段' : '尚未完成'}
                            </p>
                        </div>
                    </div>
                    {report.results.archive_extract.reason && (
                        <p className="mt-4 text-xs text-caution-yellow italic">
                            說明：{localizeReportText(report.results.archive_extract.reason)}
                        </p>
                    )}
                </div>
            )}

            {/* Archive Extraction Failure Banner */}
            {report.results.archive_extract?.extraction_failed && (
                <div className="glass-card p-6 mb-4 border-l-4 border-alert-red bg-alert-red/10">
                    <h2 className="text-lg font-bold mb-2 text-alert-red flex items-center gap-2">
                        <span>❌ 解壓縮失敗</span>
                    </h2>
                    <p className="text-sm text-slate-200 font-mono">
                        封存檔案未能完整解壓，未提取的內層內容尚未分析。請查看階段說明與分析限制。
                    </p>
                </div>
            )}

            {/* Child Jobs / Extracted Files List */}
            {report.child_jobs.length > 0 && (
                <div className="glass-card p-6 mb-4">
                    <h2 className="text-lg font-bold mb-4 text-neon-purple">📂 衍生檔案分析 ({report.child_jobs.length})</h2>
                    <div className="space-y-2">
                        {report.child_jobs.map((child) => (
                            <Link
                                key={child.job_id}
                                to={`/jobs/${child.job_id}`}
                                className="stage-item flex items-center justify-between hover:bg-white/5 transition-all group"
                            >
                                <div className="flex items-center gap-3 overflow-hidden">
                                    <span className="text-xl group-hover:scale-110 transition-transform">📄</span>
                                    <div className="overflow-hidden">
                                        <p className="text-sm font-bold truncate group-hover:text-neon-cyan">{child.filename}</p>
                                        <p className="text-[10px] text-slate-500 font-mono truncate uppercase">{child.sha256}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4 flex-shrink-0">
                                    <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                                        child.verdict === 'malicious' ? 'bg-alert-red/10 text-alert-red border border-alert-red/20' :
                                        child.verdict === 'suspicious' ? 'bg-caution-yellow/10 text-caution-yellow border border-caution-yellow/20' :
                                        child.verdict === 'clean' ? 'bg-matrix-green/10 text-matrix-green border border-matrix-green/20' :
                                        'bg-slate-500/10 text-slate-400'
                                    }`}>
                                        {localizeVerdict(child.verdict || 'pending')}
                                    </span>
                                    <span className="text-slate-600 font-mono text-xs group-hover:translate-x-1 transition-transform">→</span>
                                </div>
                            </Link>
                        ))}
                    </div>
                </div>
            )}

            {/* File Info */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">📄 檔案資訊</h2>
                <div className="space-y-3 font-mono text-sm">
                    <div className="flex justify-between">
                        <span className="text-slate-400">檔案名稱</span>
                        <span className="text-white">{report.file.original_filename}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">MIME 類型</span>
                        <span className="text-neon-purple">{report.file.mime}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">檔案大小</span>
                        <span className="text-white">{(report.file.size / 1024).toFixed(2)} KB</span>
                    </div>
                    <div className="pt-3 border-t border-white/10">
                        <div className="flex justify-between items-start mb-2">
                            <span className="text-slate-400">SHA256</span>
                            <button
                                onClick={() => copyToClipboard(report.file.sha256)}
                                className="text-xs text-neon-cyan hover:text-neon-purple transition-colors"
                            >
                                {copiedHash ? '✓ 已複製' : '📋 複製'}
                            </button>
                        </div>
                        <div className="code-block text-xs break-all text-matrix-green">
                            {report.file.sha256}
                        </div>
                    </div>
                </div>
            </div>

            {/* AV Results */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">🛡️ 防毒掃描</h2>
                    <div className="flex justify-between items-center font-mono text-sm">
                        <span className="text-slate-400">{report.results.av_result.engine}</span>
                        <span className={report.results.av_result.infected ? 'text-alert-red' : avCompleted ? 'text-matrix-green' : 'text-caution-yellow'}>
                            {report.results.av_result.infected
                                ? `☠️ ${report.results.av_result.threat_name}`
                                : avCompleted ? '✓ 已掃描，未發現威脅' : `尚未完成有效掃描：${localizeReportText(stageCoverage(report, 'clamav')?.reason) || '請查看分析範圍與限制'}`}
                        </span>
                    </div>
                </div>

            {/* YARA Hits */}
            {(
                <div className="glass-card p-6 mb-4">
                    <h2 className="text-lg font-bold mb-4 text-neon-cyan">🎯 YARA 規則匹配</h2>
                    {report.results.yara_hits.length === 0 && <p className={`text-sm ${yaraCompleted ? 'text-slate-300' : 'text-caution-yellow'}`}>{yaraCompleted ? '已比對，未命中規則。' : `尚未完成有效規則比對：${localizeReportText(stageCoverage(report, 'yara')?.reason) || '請查看分析範圍與限制'}`}</p>}
                    <div className="space-y-3">
                        {report.results.yara_hits.map((hit, index) => (
                            <div key={index} className="stage-item flex-col items-start">
                                <div className="flex items-center gap-3 w-full">
                                    <span className="font-mono text-alert-red font-bold">{hit.rule}</span>
                                    {hit.severity && (
                                        <span className={`text-xs px-2 py-0.5 rounded font-mono ${hit.severity === 'high' ? 'bg-alert-red/20 text-alert-red' :
                                                hit.severity === 'medium' ? 'bg-caution-yellow/20 text-caution-yellow' :
                                                    'bg-slate-500/20 text-slate-400'
                                            }`}>
                                            {hit.severity.toUpperCase()}
                                        </span>
                                    )}
                                </div>
                                {hit.description && (
                                    <p className="text-sm text-slate-400 mt-1">{hit.description}</p>
                                )}
                                {hit.tags.length > 0 && (
                                    <div className="flex gap-2 mt-2">
                                        {hit.tags.map((tag, i) => (
                                            <span key={i} className="text-xs px-2 py-0.5 rounded bg-neon-purple/20 text-neon-purple">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* IOC - Code Snippet Style */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">🔗 IOC 指標</h2>

                {report.results.iocs.urls.length > 0 && (
                    <div className="mb-4">
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            網址 <span className="text-neon-cyan">({report.results.iocs.urls.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.urls.map((url, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-caution-yellow break-all">{url}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.domains.length > 0 && (
                    <div className="mb-4">
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            網域 <span className="text-neon-cyan">({report.results.iocs.domains.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.domains.map((domain, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-neon-purple break-all">{domain}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.ips.length > 0 && (
                    <div>
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            IP 位址 <span className="text-neon-cyan">({report.results.iocs.ips.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.ips.map((ip, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-alert-red">{ip}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.urls.length === 0 &&
                    report.results.iocs.domains.length === 0 &&
                    report.results.iocs.ips.length === 0 && (
                        <p className="text-slate-500 font-mono text-sm">{iocCompleted ? '已擷取，未發現 IOC 指標' : '尚未確認 IOC 擷取已完成，請查看分析範圍與限制'}</p>
                    )}
            </div>

            {/* Timing */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">⏱️ 分析耗時</h2>
                <div className="space-y-1">
                    {report.timings.stages.map((stage, index) => (
                        <div key={index} className="stage-item font-mono text-sm">
                            <span className="text-slate-400">{stageLabels[stage.name] || localizeStage(stage.name)}</span>
                            <span className="text-matrix-green">{stage.duration_ms} ms</span>
                        </div>
                    ))}
                    <div className="stage-item font-mono text-sm pt-2 border-t border-white/10">
                        <span className="font-bold text-white">總計</span>
                        <span className="font-bold text-neon-cyan">{report.timings.total_ms} ms</span>
                    </div>
                </div>
            </div>

            <DynamicAnalysisPanel report={report} />

            {/* Back Link */}
            <Link
                to="/"
                className="inline-flex items-center gap-2 mt-2 text-sm font-mono text-slate-400 hover:text-neon-cyan transition-colors"
            >
                <span>←</span>
                <span>上傳新檔案</span>
            </Link>
        </div>
    )
}
