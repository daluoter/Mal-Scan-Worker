import type { ExplainabilityBlock, ExplainabilitySummaryFinding } from '../../api/types'
import { localizeFindingLabel, localizeReportText, localizeSeverity } from './reportText'

interface TopFindingsSummaryProps {
    explainability?: ExplainabilityBlock
}

const contextKinds = new Set([
    'yara_context_observation',
    'raw_url_ioc',
    'raw_domain_ioc',
    'raw_ip_ioc',
    'ioc_multiple_types_bonus',
    'ioc_multiple_types_observation',
])

export default function TopFindingsSummary({ explainability }: TopFindingsSummaryProps) {
    const summary = explainability?.summary
    const topFindings = summary?.top_findings ?? []
    const findings = new Map((explainability?.findings ?? []).map((item) => [item.finding_id, item]))
    const evidence = new Map((explainability?.evidence ?? []).map((item) => [item.id || item.evidence_id, item]))

    // Use the recorded evidence kind/tier and contribution together. An unknown
    // or legacy finding that merely has zero points must keep its original style.
    const isContextObservation = (finding: ExplainabilitySummaryFinding) => {
        const detail = findings.get(finding.finding_id)
        return finding.score_impact === 0
            && detail !== undefined
            && contextKinds.has(detail.kind)
            && detail.severity === 'info'
            && detail.score_impact === 0
            && (detail.evidence_ids ?? []).length > 0
            && (detail.evidence_ids ?? []).every((id) => {
                const item = evidence.get(id)
                return typeof item?.kind === 'string'
                    && contextKinds.has(item.kind)
                    && item.tier === 'benign_context'
                    && item.points === 0
                    && item.severity === 'info'
            })
    }

    if (!summary) {
        return null
    }

    return (
        <section className="glass-card p-6 mb-4 border border-neon-cyan/30">
            <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                    <p className="text-xs font-mono tracking-[0.3em] text-neon-cyan/70">可解釋性</p>
                    <h2 className="mt-2 text-2xl font-bold text-white">
                        {localizeReportText(summary.headline) || '此報告已產生可解釋性摘要。'}
                    </h2>
                    {summary.primary_artifact_path && (
                        <p className="mt-2 font-mono text-sm text-neon-purple">
                            主要判定檔案：{summary.primary_artifact_path}
                        </p>
                    )}
                    {summary.final_verdict_explainer && (
                        <p className="mt-3 max-w-3xl text-sm text-slate-300">
                            {localizeReportText(summary.final_verdict_explainer)}
                        </p>
                    )}
                </div>
                {summary.primary_artifact_id && (
                    <div className="rounded-lg border border-neon-purple/30 bg-neon-purple/10 px-4 py-3 font-mono text-xs text-neon-purple">
                        <div>主要檔案</div>
                        <div className="mt-1 text-slate-200">{summary.primary_artifact_id}</div>
                    </div>
                )}
            </div>

            <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {topFindings.length > 0 ? (
                    topFindings.map((finding) => {
                        const context = isContextObservation(finding)
                        const detail = findings.get(finding.finding_id)
                        return (
                        <article
                            key={finding.finding_id}
                            className={`rounded-xl border bg-slate-900/70 p-4 ${context ? 'border-neon-cyan/25' : 'border-caution-yellow/25 shadow-[0_0_24px_rgba(234,179,8,0.08)]'}`}
                        >
                            <div className="flex items-center justify-between gap-3">
                                <span className={`text-xs font-mono tracking-wide ${context ? 'text-neon-cyan' : 'text-caution-yellow'}`}>
                                    第 {finding.archive_layer} 層
                                </span>
                                <span className="rounded-full border border-white/10 px-2 py-0.5 font-mono text-xs text-white/80">
                                    {context ? '不計入風險' : `+${finding.score_impact}`}
                                </span>
                            </div>
                            {detail && <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-400">
                                <span>{localizeFindingLabel(detail.kind)}</span>
                                <span>嚴重度 {localizeSeverity(detail.severity)}</span>
                                {context && <span>{localizeFindingLabel('benign_context')}</span>}
                            </div>}
                            <h3 className="mt-3 text-base font-bold text-white">{localizeReportText(finding.title)}</h3>
                            <p className="mt-2 break-all font-mono text-xs text-neon-cyan/80">
                                {finding.artifact_path}
                            </p>
                            <p className="mt-3 text-sm text-slate-300">{localizeReportText(finding.why_flagged)}</p>
                        </article>
                        )
                    })
                ) : (
                    <div className="rounded-xl border border-white/10 bg-slate-900/40 p-4 text-sm text-slate-400">
                        這份報告目前沒有可分組呈現的重要發現。
                    </div>
                )}
            </div>
        </section>
    )
}
