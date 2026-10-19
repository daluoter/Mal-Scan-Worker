import type { Report } from '../../api/types'
import { reportRiskPresentation, riskIsElevated, riskLabel } from './reportRisk'

export default function VerdictSummaryPanel({ report }: { report: Report }) {
    const risk = reportRiskPresentation(report)
    const elevated = riskIsElevated(risk.effective)
    const malicious = risk.effective.verdict === 'malicious' || risk.effective.level === 'malicious'
    const warning = elevated || risk.effective.level === 'medium'
    const cardClass = elevated ? 'verdict-malicious' : warning ? 'verdict-suspicious'
        : risk.effective.verdict === 'clean' && report.report_complete === true ? 'verdict-clean' : 'glass-card'
    const hasRiskyDescendant = Boolean(risk.descendant && riskIsElevated(risk.descendant))
    return (
        <section className={`verdict-card ${cardClass} mb-6`} aria-label="包含子檔的整體風險">
            <div className="flex items-center justify-between gap-4">
                <div>
                    <p className="text-sm font-mono text-slate-400 mb-1">{report.report_complete === false ? '目前已知風險（分析尚未完成）' : '包含子檔的整體風險'}</p>
                    <p className={`text-3xl font-bold ${elevated ? 'text-alert-red' : ''}`}>
                        {malicious ? '☠️' : warning ? '⚠️' : risk.effective.verdict === 'clean' ? '✅' : '❓'} {riskLabel(risk.effective)}
                    </p>
                </div>
                <div className="text-right">
                    <p className="text-sm font-mono text-slate-400 mb-1">{risk.legacyDescendantFallback ? '已知子檔最高分數' : '整體風險分數'}</p>
                    <p className={`text-4xl font-bold font-mono ${elevated ? 'text-alert-red' : ''}`}>
                        {risk.effective.score ?? '—'}<span className="text-lg text-slate-400">/100</span>
                    </p>
                </div>
            </div>
            {hasRiskyDescendant && <div className="mt-4 rounded-lg border border-alert-red/40 bg-alert-red/10 p-3 text-alert-red">
                <p className="font-bold">⚠️ 內含{riskLabel(risk.descendant!)}檔案：{risk.descendant?.sourceFilename}</p>
                <p className="mt-1 break-all font-mono text-xs">{risk.descendant?.sourcePath}</p>
                <p className="mt-2 text-sm text-slate-200">{risk.localRiskKnown ? '本檔直接分數' : '舊報告記錄分數'} {risk.localRiskKnown ? risk.local.score ?? '—' : risk.recorded.score ?? '—'}/100；內層內容另行分析，請一併查看下方檔案關聯樹。</p>
                {!risk.localRiskKnown && <p className="mt-2 text-xs text-slate-300">此記錄分數可能已含子檔繼承，無法據此確認本檔直接分數。</p>}
            </div>}
            {elevated && !malicious && <p className="mt-3 text-sm text-slate-300">高風險代表已發現需優先檢視的證據，不等同已確認惡意程式。</p>}
            {risk.legacyDescendantFallback && <p className="mt-3 text-xs text-slate-400">舊版主分數可能已含部分子檔繼承；此處另顯示已知子檔最高風險，原始 JSON 分數保留不變。</p>}
        </section>
    )
}
