import type { AvResult, StageCoverage } from '../../api/types'
import { localizeReportText, localizeStatus } from './reportText'

interface AntivirusPanelProps {
    result: AvResult
    coverage?: StageCoverage
    completed?: boolean
}

export default function AntivirusPanel({ result, coverage, completed = false }: AntivirusPanelProps) {
    const hasSeparatedVersions = Boolean(result.engine_version || result.database_version || result.database_timestamp)
    return (
        <section className="glass-card p-6 mb-4">
            <h2 className="text-lg font-bold mb-4 text-neon-cyan">🛡️ 防毒掃描</h2>
            <div className="flex flex-wrap justify-between gap-3 font-mono text-sm">
                <span className="text-slate-400">{result.engine}{result.engine_version && ` ${result.engine_version}`}</span>
                <span className={result.infected ? 'text-alert-red' : completed ? 'text-matrix-green' : 'text-caution-yellow'}>
                    {result.infected ? `偵測命中：${result.threat_name || '未提供名稱'}` : completed ? '已掃描，未命中本次使用的病毒特徵' : `${coverage ? `掃描狀態：${localizeStatus(coverage.status)}。` : ''}尚未完成有效掃描：${localizeReportText(coverage?.reason) || '請查看分析範圍與限制'}`}
                </span>
            </div>
            {hasSeparatedVersions ? (
                <dl className="mt-3 grid gap-2 text-sm text-slate-300 md:grid-cols-2">
                    <div><dt className="text-slate-400">病毒資料庫版本</dt><dd className="font-mono">{result.database_version || '未提供'}</dd></div>
                    <div><dt className="text-slate-400">病毒資料庫所載時間</dt><dd className="font-mono break-words">{result.database_timestamp || '未提供'}</dd></div>
                </dl>
            ) : <p className="mt-3 text-xs text-slate-400 break-all">原始工具版本：{coverage?.tool_version || '未提供'}；此報告未分開記錄引擎與病毒資料庫版本。</p>}
            <p className="mt-3 text-xs text-slate-400">資料庫所載時間用來辨識本次掃描使用的版本，不能單獨證明它是官方目前最新版本。測試特徵命中也可能是 EICAR 等驗證樣本。</p>
        </section>
    )
}
