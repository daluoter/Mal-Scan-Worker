import type { RiskSummary } from '../../api/types'
import {
    localizeFindingLabel,
    localizeReportText,
    localizeScoreComponentType,
} from './reportText'

interface ScoreTracePanelProps {
    risk?: RiskSummary
}

export default function ScoreTracePanel({ risk }: ScoreTracePanelProps) {
    const scoreTrace = risk?.score_trace
    const breakdown = risk?.breakdown

    if (!risk || !breakdown) {
        return null
    }

    const components = scoreTrace?.components ?? []

    return (
        <section className="glass-card p-6 mb-4">
            <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <h2 className="text-lg font-bold text-neon-cyan">🧮 分數形成</h2>
                    {scoreTrace?.formula && (
                        <p className="mt-1 text-xs font-mono text-slate-400">分數計算公式已記錄於報告中</p>
                    )}
                </div>
                <div className={`grid grid-cols-2 gap-2 font-mono text-xs ${breakdown.descendant_floor ? 'md:grid-cols-6' : 'md:grid-cols-5'}`}>
                    <div className="rounded-lg border border-white/10 bg-slate-900/50 px-3 py-2">
                        <div className="text-slate-500">本地分數</div>
                        <div className="text-white">{breakdown.local_score}</div>
                    </div>
                    <div className="rounded-lg border border-white/10 bg-slate-900/50 px-3 py-2">
                        <div className="text-slate-500">繼承分數</div>
                        <div className="text-white">{breakdown.inherited_score}</div>
                    </div>
                    <div className="rounded-lg border border-white/10 bg-slate-900/50 px-3 py-2">
                        <div className="text-slate-500">交叉加分</div>
                        <div className="text-white">{breakdown.synergy_bonus}</div>
                    </div>
                    <div className="rounded-lg border border-white/10 bg-slate-900/50 px-3 py-2">
                        <div className="text-slate-500">抑制因子</div>
                        <div className="text-white">{breakdown.dampener}</div>
                    </div>
                    {!!breakdown.descendant_floor && <div className="rounded-lg border border-alert-red/40 bg-alert-red/10 px-3 py-2">
                        <div className="text-slate-300">子檔風險下限補足</div>
                        <div className="text-alert-red">+{breakdown.descendant_floor}</div>
                    </div>}
                    <div className="rounded-lg border border-neon-purple/30 bg-neon-purple/10 px-3 py-2">
                        <div className="text-slate-300">最終分數</div>
                        <div className="text-neon-purple">{breakdown.final_score}</div>
                    </div>
                </div>
            </div>

            {!!breakdown.descendant_floor && <p className="mt-3 text-sm text-slate-300">整體分數至少保留已確認來源的高風險子檔分數。此補足不代表新增偵測，也不會把同一證據重複計算為獨立來源。</p>}

            <div className="mt-4 space-y-3">
                {components.length > 0 ? (
                    components.map((component, index) => (
                        <div key={`${component.type}-${index}`} className="rounded-xl border border-white/10 bg-slate-900/50 p-4">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                    <span className="font-mono text-xs tracking-wide text-neon-cyan">
                                        {localizeScoreComponentType(component.type)}
                                    </span>
                                    {component.label && (
                                        <span className="text-sm font-semibold text-white">{localizeFindingLabel(component.label)}</span>
                                    )}
                                </div>
                                {typeof component.applied_points === 'number' && (
                                    <span className="rounded-full border border-caution-yellow/25 px-2 py-0.5 font-mono text-xs text-caution-yellow">
                                        +{component.applied_points}
                                    </span>
                                )}
                            </div>
                            <p className="mt-2 text-sm text-slate-300">{component.type === 'descendant_risk_floor' ? '已驗證的高風險子檔設定整體內容風險下限。' : localizeReportText(component.reason)}</p>
                            <div className="mt-2 flex flex-wrap gap-3 font-mono text-xs text-slate-500">
                                {component.artifact_id && <span>檔案 {component.artifact_id}</span>}
                                {component.related_artifact_id && <span>相關檔案 {component.related_artifact_id}</span>}
                                {typeof component.base_points === 'number' && <span>原始分數 {component.base_points}</span>}
                                {typeof component.source_score === 'number' && <span>來源分數 {component.source_score}</span>}
                                {component.display_path && <span className="break-all">來源路徑 {component.display_path}</span>}
                            </div>
                        </div>
                    ))
                ) : (
                    <div className="rounded-xl border border-white/10 bg-slate-900/40 p-4 text-sm text-slate-400">
                        這份報告目前沒有更細部的分數構成紀錄。
                    </div>
                )}
            </div>
        </section>
    )
}
