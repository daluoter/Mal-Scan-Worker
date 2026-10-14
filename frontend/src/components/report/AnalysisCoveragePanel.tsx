import type { AnalysisState } from '../../api/types'
import { localizeReportText, localizeStage, localizeStatus } from './reportText'

interface AnalysisCoveragePanelProps {
    analysis?: AnalysisState
    complete?: boolean
    pendingDescendants?: number
}

export default function AnalysisCoveragePanel({ analysis, complete, pendingDescendants = 0 }: AnalysisCoveragePanelProps) {
    return (
        <section className="glass-card p-6 mb-4">
            <h2 className="text-lg font-bold text-neon-cyan">分析範圍與完成狀態</h2>
            <p className="mt-2 text-sm text-slate-300">
                {complete === true ? '本次工作已結束，分析範圍與限制如下。' : '這是目前已取得的分析成果，部分內容可能尚未完成。'}
                {' '}工作結束不代表所有內容都已成功分析。
            </p>
            <div className="mt-3 flex flex-wrap gap-3 font-mono text-sm text-slate-300">
                <span>靜態分析：{localizeStatus(analysis?.static.status || 'unknown')}</span>
                {pendingDescendants > 0 && <span className="text-caution-yellow">等待子檔：{pendingDescendants}</span>}
            </div>
            {!analysis?.static.stage_coverage.length ? (
                <p className="mt-3 text-sm text-caution-yellow">未提供逐階段覆蓋資料，無法確認完整分析範圍。</p>
            ) : (
                <div className="mt-4 overflow-x-auto">
                    <table className="w-full text-left text-sm">
                        <thead className="text-slate-400"><tr><th className="pb-2">分析階段</th><th className="pb-2">狀態</th><th className="pb-2">版本／耗時</th><th className="pb-2">說明</th></tr></thead>
                        <tbody>
                            {analysis.static.stage_coverage.map((entry, index) => (
                                <tr key={`${entry.stage}-${index}`} className="border-t border-white/10">
                                    <td className="py-2 pr-3 text-white">{localizeStage(entry.stage)}</td>
                                    <td className="py-2 pr-3 text-slate-300">{localizeStatus(entry.status)}</td>
                                    <td className="py-2 pr-3 font-mono text-xs text-slate-400">
                                        {entry.tool_version && <div>工具 {entry.tool_version}</div>}
                                        {entry.rules_version && <div>規則 {entry.rules_version}</div>}
                                        {typeof entry.duration_ms === 'number' && <div>{entry.duration_ms} ms</div>}
                                    </td>
                                    <td className="py-2 text-slate-300 break-words">{localizeReportText(entry.reason) || '—'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    )
}
