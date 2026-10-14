import type { ArtifactTreeNode } from '../../api/types'
import { Link } from 'react-router-dom'
import { localizeAnalyzer, localizeStatus, localizeVerdict } from './reportText'

interface ArtifactTreePanelProps {
    tree?: ArtifactTreeNode | null
}

function riskClass(riskLevel?: string | null): string {
    if (riskLevel === 'malicious') return 'border-alert-red/30 text-alert-red'
    if (riskLevel === 'high' || riskLevel === 'suspicious') return 'border-caution-yellow/30 text-caution-yellow'
    if (riskLevel === 'clean') return 'border-matrix-green/30 text-matrix-green'
    return 'border-white/10 text-slate-300'
}

function ArtifactNode({ node }: { node: ArtifactTreeNode }) {
    return (
        <li className="relative pl-5">
            <div className="absolute left-0 top-3 h-full w-px bg-white/10" />
            <div className="absolute left-0 top-3 h-px w-3 bg-white/10" />
            <div className="rounded-xl border border-white/10 bg-slate-900/60 p-4">
                <div className="flex flex-wrap items-center gap-2">
                    {node.job_id ? <Link className="font-bold text-white hover:text-neon-cyan" to={`/jobs/${node.job_id}`}>{node.filename}</Link> : <span className="font-bold text-white">{node.filename}</span>}
                    <span className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${riskClass(node.risk_level)}`}>
                        {localizeVerdict(node.risk_level || 'unknown')}
                    </span>
                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] text-slate-300">
                        靜態：{localizeStatus(node.analysis?.static.status || node.analysis_status || 'unknown')}
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
                        <div>分數 {node.score ?? 0}</div>
                        <div>深度 {node.depth}</div>
                    </div>
                </div>
                {node.top_finding_titles.length > 0 && (
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
            {node.children.length > 0 && (
                <ul className="mt-3 space-y-3">
                    {node.children.map((child) => (
                        <ArtifactNode key={child.id} node={child} />
                    ))}
                </ul>
            )}
        </li>
    )
}

export default function ArtifactTreePanel({ tree }: ArtifactTreePanelProps) {
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
            <ul className="space-y-3">
                <ArtifactNode node={tree} />
            </ul>
        </section>
    )
}
