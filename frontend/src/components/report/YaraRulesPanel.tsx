import type { StageCoverage, YaraHit, YaraRuleProvenance } from '../../api/types'
import { localizeReportText, localizeSeverity, localizeStatus } from './reportText'

interface YaraRulesPanelProps {
    hits?: YaraHit[]
    coverage?: StageCoverage
    completed?: boolean
    provenance?: YaraRuleProvenance
}

const provenanceReasons: Record<string, string> = {
    manifest_missing: '未提供規則集清單',
    manifest_invalid: '規則集清單無效',
    file_inventory_mismatch: '規則檔案清單不一致',
    file_hash_mismatch: '規則檔案雜湊不一致',
    namespace_mismatch: '規則命名空間不一致',
    rule_inventory_mismatch: '規則名稱清單不一致',
    rules_not_loaded: '尚未載入規則',
    rules_directory_missing: '找不到規則目錄',
    rules_missing: '沒有規則檔案',
}

function ProvenanceDetails({ provenance, rulesHash }: { provenance?: YaraRuleProvenance; rulesHash?: string | null }) {
    const verified = provenance?.status === 'verified'
    const source = verified ? provenance.source : undefined
    const license = verified ? provenance.license : undefined
    const hash = provenance?.ruleset_sha256 || rulesHash

    return (
        <div className="mb-4 rounded-lg border border-white/10 bg-slate-900/50 p-3 text-sm text-slate-300">
            <p className={verified ? 'text-neon-cyan' : 'text-caution-yellow'}>
                規則來源資料：{verified ? '本地檔案雜湊與規則清單校驗完成' : '未驗證'}
                {!verified && provenance?.reason && `（${provenanceReasons[provenance.reason] || provenance.reason}）`}
            </p>
            {!provenance && <p className="mt-1 text-slate-400">此報告未提供規則來源清單；保留原有掃描結果。</p>}
            {verified && <p className="mt-1 text-xs text-slate-400">校驗範圍限本地檔案與清單的一致性；作者身分、授權許可與偵測準確率仍需另行確認。</p>}
            <dl className="mt-2 grid gap-2 md:grid-cols-2">
                {verified && provenance.ruleset_id && <div><dt className="text-slate-400">規則集／版本</dt><dd className="font-mono break-all">{provenance.ruleset_id} / {provenance.ruleset_version || '未提供'}</dd></div>}
                {hash && <div className="md:col-span-2"><dt className="text-slate-400">{/^[a-f0-9]{64}$/i.test(hash) ? '規則內容 SHA-256' : '原報告規則版本'}</dt><dd className="font-mono text-xs break-all">{hash}</dd></div>}
                {verified && typeof provenance.rule_count === 'number' && <div><dt className="text-slate-400">規則數</dt><dd>{provenance.rule_count} 條 / {provenance.file_count ?? '未知'} 個檔案</dd></div>}
                {source?.repository && <div className="md:col-span-2"><dt className="text-slate-400">清單記錄的來源</dt><dd className="font-mono text-xs break-all">{source.repository}</dd>{source.introduced_commit && <dd className="mt-1 font-mono text-xs break-all">引入版本 {source.introduced_commit}</dd>}</div>}
                {source?.declared_author && <div><dt className="text-slate-400">自述作者（未獨立驗證）</dt><dd>{source.declared_author}</dd></div>}
                <div><dt className="text-slate-400">授權聲明</dt><dd>{!license || license.spdx_expression === 'NOASSERTION' || license.status === 'not_declared' ? '未聲明／尚未確認授權許可' : `${license.spdx_expression || '未提供'}（清單記錄）`}</dd></div>
            </dl>
        </div>
    )
}

function hitCategory(hit: YaraHit): string {
    if (hit.provenance?.status !== 'verified') return '規則分類未驗證'
    if (hit.provenance.category === 'test') return '測試標記'
    if (hit.provenance.category === 'heuristic') return '啟發式／脈絡線索'
    if (isContextObservation(hit)) return '資訊觀察／不計入風險'
    return '規則分類未提供'
}

function isContextObservation(hit: YaraHit): boolean {
    return hit.provenance?.status === 'verified'
        && hit.provenance.category === 'context'
        && hit.classification === 'informational'
        && hit.severity === 'info'
}

export default function YaraRulesPanel({ hits = [], coverage, completed = false, provenance }: YaraRulesPanelProps) {
    const contextCount = hits.filter(isContextObservation).length
    const otherCount = hits.length - contextCount

    return (
        <section className="glass-card p-6 mb-4">
            <h2 className="text-lg font-bold mb-3 text-neon-cyan">🎯 YARA 規則比對</h2>
            <p className="mb-3 text-sm text-slate-300">比對引擎：{coverage?.tool_version ? `YARA ${coverage.tool_version}` : '版本未提供'}。引擎版本與規則集版本分別記錄。</p>
            <ProvenanceDetails provenance={provenance} rulesHash={coverage?.rules_version} />
            {hits.length === 0 && <p className={`text-sm ${completed ? 'text-slate-300' : 'text-caution-yellow'}`}>{completed ? '已比對，未命中本次配置的規則。' : `${coverage ? `比對狀態：${localizeStatus(coverage.status)}。` : ''}尚未完成有效規則比對：${localizeReportText(coverage?.reason) || '請查看分析範圍與限制'}`}</p>}
            {contextCount > 0 && <p className="mb-3 text-sm text-slate-300">資訊觀察 {contextCount} 筆：保留內容線索，這些命中不增加 YARA 風險分數，也不代表檔案安全或惡意。</p>}
            {otherCount > 0 && <p className="mb-3 text-sm text-caution-yellow">其他規則命中 {otherCount} 筆：需結合檔案內容與其他證據；測試標記、啟發式規則與嚴重度標示本身皆不代表已確認惡意。</p>}
            <div className="space-y-3">
                {hits.map((hit, index) => (
                    <div key={`${hit.namespace}-${hit.rule}-${index}`} className="stage-item flex-col items-start">
                        <div className="flex flex-wrap items-center gap-3 w-full">
                            <span className={`font-mono ${isContextObservation(hit) ? 'text-neon-cyan' : 'text-caution-yellow'} font-bold break-all`}>{hit.rule}</span>
                            <span className={`text-xs rounded border border-white/10 px-2 py-0.5 ${isContextObservation(hit) ? 'text-neon-cyan' : 'text-slate-300'}`}>{hitCategory(hit)}</span>
                            {hit.severity && <span className="text-xs font-mono text-slate-400">規則嚴重度 {localizeSeverity(hit.severity)}</span>}
                        </div>
                        {hit.description && <p className="text-sm text-slate-400 mt-1">{hit.description}</p>}
                        {hit.provenance?.status === 'verified' && hit.provenance.category === 'test' && <p className="mt-2 text-sm text-slate-300">此命中用於測試偵測流程，不等同真實惡意程式。</p>}
                        {hit.provenance?.status === 'verified' && hit.provenance.limitations && <p className="mt-2 text-sm text-slate-300">規則限制：{hit.provenance.limitations}</p>}
                        {hit.provenance?.status === 'verified' && hit.provenance.file && <p className="mt-2 font-mono text-xs text-slate-400 break-all">規則檔案：{hit.provenance.file}</p>}
                        {(hit.tags ?? []).length > 0 && <div className="flex flex-wrap gap-2 mt-2">{hit.tags.map((tag, i) => <span key={i} className="text-xs px-2 py-0.5 rounded bg-neon-purple/20 text-neon-purple">{tag}</span>)}</div>}
                    </div>
                ))}
            </div>
        </section>
    )
}
