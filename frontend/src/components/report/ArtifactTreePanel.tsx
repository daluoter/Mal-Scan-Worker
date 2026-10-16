import type { ArtifactAnalysisReference, ArtifactTreeNode, ExplainabilityBlock } from '../../api/types'
import { Link } from 'react-router-dom'
import { localizeAnalyzer, localizeReportText, localizeStage, localizeStatus, localizeVerdict } from './reportText'

interface ArtifactTreePanelProps {
    tree?: ArtifactTreeNode | null
    coverage?: ExplainabilityBlock['artifact_coverage']
}

function riskClass(riskLevel?: string | null): string {
    if (riskLevel === 'malicious') return 'border-alert-red/30 text-alert-red'
    if (riskLevel === 'high' || riskLevel === 'suspicious') return 'border-caution-yellow/30 text-caution-yellow'
    if (riskLevel === 'clean') return 'border-matrix-green/30 text-matrix-green'
    return 'border-white/10 text-slate-300'
}

function AnalysisReference({ reference }: { reference?: ArtifactAnalysisReference }) {
    if (!reference) return null
    if (reference.status !== 'verified' || reference.mode === 'unresolved') {
        return <div className="mt-3 rounded-lg border border-caution-yellow/20 p-3 text-xs text-caution-yellow">分析來源尚未確認；此節點的覆蓋範圍仍不完整。{reference.reason && <p className="mt-1 break-words">{localizeReportText(reference.reason)}</p>}</div>
    }
    if (reference.mode !== 'direct' && reference.mode !== 'inherited') return null
    const inherited = reference.mode === 'inherited'

    return (
        <details className="mt-3 rounded-lg border border-neon-cyan/20 p-3 text-xs text-slate-300">
            <summary className="cursor-pointer text-neon-cyan">{inherited ? '沿用相同內容的既有分析；本節點未重跑階段。' : '分析來源：本檔直接分析。查看逐階段覆蓋範圍。'}</summary>
            <dl className="mt-3 space-y-2">
                <div><dt className="text-slate-400">分析來源檔案</dt><dd className="font-mono break-all">{reference.source_artifact_id || '未提供'}</dd></div>
                {reference.source_job_id && <div><dt className="text-slate-400">來源工作</dt><dd><Link className="font-mono break-all text-neon-cyan hover:underline" to={`/jobs/${encodeURIComponent(reference.source_job_id)}`}>{reference.source_job_id}</Link></dd></div>}
                <div><dt className="text-slate-400">來源分析狀態</dt><dd>{localizeStatus(reference.source_analysis_status || 'unknown')}</dd></div>
                {inherited && reference.risk && <div><dt className="text-slate-400">沿用來源風險</dt><dd className={riskClass(reference.risk.risk_level)}>風險 {localizeVerdict(reference.risk.risk_level || 'unknown')} / 分數 {reference.risk.score ?? '—'} / 判定 {localizeVerdict(reference.risk.verdict || 'unknown')}</dd></div>}
                {reference.source_sha256 && <div><dt className="text-slate-400">來源 SHA-256</dt><dd className="font-mono break-all">{reference.source_sha256}</dd></div>}
                <div><dt className="text-slate-400">{inherited ? '沿用來源證據' : '本檔分析證據'}</dt><dd>{reference.source_evidence_ids?.length ?? 0} 筆證據 / {reference.source_finding_ids?.length ?? 0} 筆發現</dd></div>
            </dl>
            {(reference.source_stage_coverage ?? []).length > 0 ? <ul className="mt-3 space-y-1">{reference.source_stage_coverage?.map((stage, index) => <li key={`${stage.stage}-${index}`}><span>{localizeStage(stage.stage)}：{localizeStatus(stage.status)}</span>{stage.reason && <span className="ml-2 text-slate-400">{localizeReportText(stage.reason)}</span>}</li>)}</ul> : <p className="mt-3 text-caution-yellow">未提供來源的逐階段覆蓋資料。</p>}
        </details>
    )
}

function ArtifactNode({ node }: { node: ArtifactTreeNode }) {
    const inherited = node.analysis_reference?.status === 'verified' && node.analysis_reference.mode === 'inherited'
    return (
        <li className="relative pl-5">
            <div className="absolute left-0 top-3 h-full w-px bg-white/10" />
            <div className="absolute left-0 top-3 h-px w-3 bg-white/10" />
            <div className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
                <div className="flex flex-wrap items-center gap-2">
                    {node.job_id ? <Link className="font-bold text-white hover:text-neon-cyan" to={`/jobs/${node.job_id}`}>{node.filename}</Link> : <span className="font-bold text-white">{node.filename}</span>}
                    <span className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${riskClass(node.risk_level)}`}>
                        {inherited && !node.risk_level ? '本節點無直接判定' : localizeVerdict(node.risk_level || 'unknown')}
                    </span>
                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] text-slate-300">
                        靜態：{localizeStatus(node.analysis?.static?.status || node.analysis_status || 'unknown')}
                    </span>
                    {node.job_status === 'password_required' && <span className="text-xs text-caution-yellow">等待解壓密碼</span>}
                    {typeof node.archive_layer === 'number' && (
                        <span className="rounded-full border border-neon-cyan/20 px-2 py-0.5 font-mono text-[11px] text-neon-cyan">
                            第 {node.archive_layer} 層
                        </span>
                    )}
                    {node.primary_analyzer && (
                        <span className="rounded-full border border-neon-purple/20 px-2 py-0.5 font-mono text-[11px] text-neon-purple">
                            {localizeAnalyzer(node.primary_analyzer)}
                        </span>
                    )}
                </div>
                <div className="mt-2 grid gap-2 text-sm text-slate-300 md:grid-cols-[1fr_auto]">
                    <div>
                        <div className="font-mono text-xs text-neon-cyan/80">
                            {node.display_path || node.origin_path || node.filename}
                        </div>
                        <div className="mt-1 font-mono text-[11px] text-slate-500">{node.sha256}</div>
                    </div>
                    <div className="text-right font-mono text-xs text-slate-400">
                        <div>{inherited ? '直接分數' : '分數'} {node.score ?? '—'}</div>
                        <div>深度 {node.depth}</div>
                    </div>
                </div>
                <AnalysisReference reference={node.analysis_reference} />
                {(node.top_finding_titles ?? []).length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-2">
                        {node.top_finding_titles.map((title) => (
                            <span
                                key={title}
                                className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-300"
                            >
                                {title}
                            </span>
                        ))}
                    </div>
                )}
            </div>
            {(node.children ?? []).length > 0 && (
                <ul className="mt-3 space-y-3">
                    {node.children.map((child) => (
                        <ArtifactNode key={child.id} node={child} />
                    ))}
                </ul>
            )}
        </li>
    )
}

export default function ArtifactTreePanel({ tree, coverage }: ArtifactTreePanelProps) {
    if (!tree) {
        return null
    }

    return (
        <section className="glass-card p-6 mb-4">
            <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="text-lg font-bold text-neon-cyan">🌲 檔案關聯樹</h2>
                <span className="font-mono text-xs text-slate-400">
                    {tree.display_path || tree.filename}
                </span>
            </div>
            {coverage && [coverage.occurrences, coverage.direct, coverage.inherited, coverage.unresolved].every(Number.isSafeInteger) && <p className="mb-4 text-sm text-slate-300">檔案節點 {coverage.occurrences} 個：直接分析 {coverage.direct}、沿用分析 {coverage.inherited}、來源未確認 {coverage.unresolved}。節點數包含相同內容在不同路徑的出現位置。</p>}
            <ul className="space-y-3">
                <ArtifactNode node={tree} />
            </ul>
        </section>
    )
}
