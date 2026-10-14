import type { Report } from '../../api/types'
import { dynamicStatus, hasAvailableReference } from './reportState'
import { localizeReportText, localizeStatus } from './reportText'

const MAX_VISIBLE_RECORDS = 100

function Records({ title, items }: { title: string; items: Array<Record<string, unknown>> }) {
    return (
        <details className="mt-3 rounded-lg border border-white/10 bg-deep-space p-3">
            <summary className="cursor-pointer text-sm text-neon-cyan">{title}（{items.length}）</summary>
            {items.length === 0 ? <p className="mt-2 text-sm text-slate-400">Provider 未回傳此類記錄。</p> : (
                <div className="mt-3 space-y-2">
                    {items.slice(0, MAX_VISIBLE_RECORDS).map((item, index) => (
                        <pre key={index} className="overflow-x-auto whitespace-pre-wrap break-all rounded border border-white/10 p-3 font-mono text-xs text-slate-300">
                            {JSON.stringify(item, null, 2)}
                        </pre>
                    ))}
                    {items.length > MAX_VISIBLE_RECORDS && <p className="text-xs text-slate-400">畫面顯示前 {MAX_VISIBLE_RECORDS} 筆；完整資料包含在下載的 JSON 報告中。</p>}
                </div>
            )}
        </details>
    )
}

function ArtifactReference({ title, reference }: { title: string; reference?: Record<string, unknown> }) {
    return (
        <div className="mt-3 rounded-lg border border-white/10 bg-deep-space p-3">
            <p className="text-sm text-neon-cyan">{title}：{hasAvailableReference(reference) ? 'Provider 回報可用' : '未提供'}</p>
            {hasAvailableReference(reference) && <pre className="mt-2 whitespace-pre-wrap break-all text-xs text-slate-300">{JSON.stringify(reference, null, 2)}</pre>}
        </div>
    )
}

export default function DynamicAnalysisPanel({ report }: { report: Report }) {
    const sandbox = report.results.sandbox
    const status = dynamicStatus(report)
    const completed = status === 'completed' && sandbox.executed && !sandbox.is_mock && !sandbox.synthetic
    const reason = report.analysis?.dynamic.reason || sandbox.reason

    return (
        <section className="glass-card p-6 mb-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-lg font-bold text-neon-purple">動態沙箱分析</h2>
                <span className={`rounded-full border px-3 py-1 text-sm ${completed ? 'border-neon-purple/30 text-neon-purple' : 'border-caution-yellow/30 text-caution-yellow'}`}>
                    {localizeStatus(status)}
                </span>
            </div>
            <div className="mt-3 font-mono text-sm text-slate-400">
                <span>Provider：{report.analysis?.dynamic.provider || sandbox.provider || '未提供'}</span>
                {sandbox.task_id && <span className="ml-4">任務：{sandbox.task_id}</span>}
            </div>
            {status === 'synthetic' ? (
                <p className="mt-3 text-sm text-caution-yellow">這是開發測試用的合成資料，沒有執行真實動態分析，也不能作為安全或惡意判定的證據。</p>
            ) : !completed ? (
                <p className="mt-3 text-sm text-slate-300">此部分尚未取得完成的真實動態分析結果。已取得的靜態成果仍可閱讀。</p>
            ) : (
                <p className="mt-3 text-sm text-slate-300">以下為此檔案的 Provider 分析成果；未回傳某類記錄不代表未發生該行為。</p>
            )}
            {reason && <p className="mt-2 break-words text-sm text-caution-yellow">{localizeReportText(reason)}</p>}
            {(sandbox.errors ?? []).length > 0 && <ul className="mt-2 space-y-1 text-sm text-caution-yellow">{sandbox.errors?.map((error, index) => <li key={index}>{localizeReportText(error)}</li>)}</ul>}
            {completed && (
                <div className="mt-4">
                    <Records title="行為證據" items={sandbox.behaviors} />
                    <Records title="程序與父程序關係" items={sandbox.processes ?? []} />
                    <Records title="檔案變動" items={sandbox.files ?? []} />
                    <Records title="Registry 變動" items={sandbox.registry ?? []} />
                    <Records title="Mutex" items={sandbox.mutexes ?? []} />
                    <Records title="TCP／UDP 連線" items={sandbox.tcp_udp ?? sandbox.network_connections} />
                    <Records title="DNS" items={sandbox.dns ?? []} />
                    <Records title="HTTP" items={sandbox.http ?? []} />
                    <Records title="動態 IOC" items={sandbox.iocs ? [sandbox.iocs] : []} />
                    <Records title="掉落檔案" items={sandbox.dropped_files ?? []} />
                    <Records title="截圖參照" items={sandbox.screenshots ?? []} />
                    <ArtifactReference title="PCAP" reference={sandbox.pcap} />
                    <ArtifactReference title="Memory dump" reference={sandbox.memory_dump} />
                    {sandbox.raw_report_ref && <div className="mt-3 rounded-lg border border-white/10 p-3"><p className="text-sm text-neon-cyan">原始 Provider 報告參照</p><p className="mt-2 break-all font-mono text-xs text-slate-300">{sandbox.raw_report_ref}</p></div>}
                    <p className="mt-3 text-xs text-slate-400">成果參照僅顯示 metadata。請透過自架沙箱的授權介面取得檔案。</p>
                </div>
            )}
        </section>
    )
}
