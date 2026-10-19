const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const test = require('node:test')
const ts = require('typescript')
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')
const { StaticRouter } = require('react-router')

// Compile the real dependency-free report helpers and components in this test
// process. This uses existing build dependencies and leaves no generated files.
for (const extension of ['.ts', '.tsx']) {
    require.extensions[extension] = (module, filename) => {
        const { outputText } = ts.transpileModule(readFileSync(filename, 'utf8'), {
            compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2020 },
            fileName: filename,
        })
        module._compile(outputText, filename)
    }
}

const { dynamicStatus, jobNeedsPassword, passwordTargetError, passwordTargets, shouldRefreshReport, stageCompleted } = require('../src/components/report/reportState.ts')
const CoveragePanel = require('../src/components/report/AnalysisCoveragePanel.tsx').default
const DynamicPanel = require('../src/components/report/DynamicAnalysisPanel.tsx').default
const ArtifactTreePanel = require('../src/components/report/ArtifactTreePanel.tsx').default
const YaraRulesPanel = require('../src/components/report/YaraRulesPanel.tsx').default
const TopFindingsSummary = require('../src/components/report/TopFindingsSummary.tsx').default
const AntivirusPanel = require('../src/components/report/AntivirusPanel.tsx').default
const PasswordForm = require('../src/components/PasswordForm.tsx').default

function report(overrides = {}) {
    return {
        job_id: 'root-job', job_status: 'scanning', report_complete: false, pending_descendants: 0,
        file: { original_filename: 'root.zip' },
        analysis: { schema_version: 'mswr-analysis-v1', static: { status: 'complete', stage_coverage: [] }, dynamic: { status: 'queued' } },
        results: { sandbox: { executed: false, is_mock: false, behaviors: [], network_connections: [] } },
        timings: { stages: [] }, child_jobs: [], ...overrides,
    }
}

function render(Component, props) {
    return renderToStaticMarkup(React.createElement(StaticRouter, { location: '/' }, React.createElement(Component, props)))
}

test('partial static reports refresh for child/password/dynamic work and stop once complete', () => {
    assert.equal(shouldRefreshReport(report()), true)
    assert.equal(shouldRefreshReport(report({ job_status: 'password_required' })), true)
    assert.equal(shouldRefreshReport(report({ job_status: 'done', pending_descendants: 2 })), true)
    assert.equal(shouldRefreshReport(report({ report_complete: true })), false)
    const finished = report({ job_status: 'failed', analysis: { dynamic: { status: 'unavailable' } } })
    assert.equal(shouldRefreshReport(finished), false)
})

test('missing rules and failed scans cannot be presented as successful empty scans', () => {
    const partial = report({
        analysis: { static: { stage_coverage: [{ stage: 'yara', status: 'skipped', reason: 'no_rules' }] } },
        timings: { stages: [{ name: 'yara', status: 'ok' }, { name: 'clamav', status: 'error' }] },
    })
    assert.equal(stageCompleted(partial, 'yara'), false)
    assert.equal(stageCompleted(partial, 'clamav'), false)
    assert.equal(stageCompleted(report({ timings: { stages: [{ name: 'clamav', status: 'ok' }] } }), 'clamav'), true)
})

test('coverage shows explicit partial status, rule versions and omitted-stage reason', () => {
    const html = render(CoveragePanel, { complete: false, pendingDescendants: 1, analysis: {
        static: { status: 'partial', stage_coverage: [{ stage: 'yara', status: 'skipped', reason: 'no_rules', tool_version: '4.5.7', rules_version: 'rules-2026' }] },
    } })
    assert.match(html, /部分完成/)
    assert.match(html, /等待子檔：1/)
    assert.match(html, /未配置規則/)
    assert.match(html, /rules-2026/)
    assert.match(render(CoveragePanel, {}), /無法確認完整分析範圍/)
})

test('synthetic results are explicit even when not executed and never show real behavior evidence', () => {
    const synthetic = report({ analysis: { dynamic: { status: 'mock' } }, results: { sandbox: {
        executed: false, is_mock: true, synthetic: true, behaviors: [{ type: 'credential_theft' }], network_connections: [],
    } } })
    assert.equal(dynamicStatus(synthetic), 'synthetic')
    const html = render(DynamicPanel, { report: synthetic })
    assert.match(html, /沒有執行真實動態分析/)
    assert.doesNotMatch(html, /credential_theft/)
    assert.doesNotMatch(html, /無威脅|未發現威脅|text-matrix-green/)
})

test('completed dynamic results preserve process/network details and inert download references', () => {
    const completed = report({ analysis: { dynamic: { status: 'complete', provider: 'capev2' } }, results: { sandbox: {
        executed: true, is_mock: false, behaviors: [{ type: 'process_injection' }],
        processes: [{ pid: 10, parent_pid: 1, name: 'sample.exe' }],
        network_connections: [{ dst_ip: '192.0.2.5', dst_port: 443, protocol: 'tcp' }],
        dns: [{ request: 'example.test' }], http: [{ uri: 'http://example.test/a' }],
        screenshots: [{ url: 'javascript:alert(1)' }],
        pcap: { available: false, url: 'https://example.test/unavailable' },
        memory_dump: { available: true, url: 'https://example.test/memory.bin' },
        raw_report_ref: 'https://example.test/raw',
    } } })
    const html = render(DynamicPanel, { report: completed })
    assert.match(html, /sample.exe/)
    assert.match(html, /parent_pid/)
    assert.match(html, /192.0.2.5/)
    assert.match(html, /example.test/)
    assert.match(html, /memory.bin/)
    assert.doesNotMatch(html, /href=|<img|<iframe|unavailable/)
    assert.match(html, /未回傳某類記錄不代表/)
})

test('disabled, pending, unavailable and failed dynamic states never imply clean analysis', () => {
    for (const status of ['disabled', 'queued', 'deferred', 'unavailable', 'failed']) {
        const html = render(DynamicPanel, { report: report({ analysis: { dynamic: { status } } }) })
        assert.match(html, /尚未取得完成的真實動態分析/)
        assert.doesNotMatch(html, /無威脅|安全|未發現威脅/)
    }
    assert.equal(dynamicStatus(report({ analysis: { dynamic: { status: 'complete' } } })), 'unknown')
})

test('password targets address nested child job identities and preserve artifact path', () => {
    const leaf = { id: 'leaf-artifact', job_id: 'leaf-job', job_status: 'password_required', filename: 'locked.7z', display_path: 'root.zip/inner.zip/locked.7z', children: [] }
    const nested = report({ child_jobs: [{ job_id: 'leaf-job', status: 'password_required', filename: 'locked.7z' }], artifact_tree: { id: 'root', job_id: 'root-job', filename: 'root.zip', children: [leaf] } })
    assert.deepEqual(passwordTargets(nested), [{ jobId: 'leaf-job', filename: 'locked.7z', path: 'root.zip/inner.zip/locked.7z' }])
    assert.deepEqual(passwordTargets(report()), [])
})

test('a supported encrypted PDF waits in the generic file password form', () => {
    const pdf = report({ job_status: 'password_required', password_required_artifacts: ['root-job'],
        file: { original_filename: 'locked.pdf', mime: 'application/pdf' },
        results: { format_analysis: { analyzer: 'pdf', features: { encrypted: true, content_access: 'password_required' } } },
    })
    assert.equal(jobNeedsPassword({ job_id: pdf.job_id, status: pdf.job_status, password_required_artifacts: pdf.password_required_artifacts }), true)
    assert.deepEqual(passwordTargets(pdf), [{ jobId: 'root-job', filename: 'locked.pdf' }])
    const html = render(PasswordForm, { filename: 'locked.pdf', attemptsUsed: 0, attemptsRemaining: 3, onSubmit: async () => {} })
    assert.match(html, /需要檔案密碼/)
    assert.match(html, /加密壓縮檔、PDF 或支援的 Office 文件/)
    assert.match(html, /已完成的分析成果會保留/)
    assert.match(html, /aria-label="檔案密碼"/)
    assert.match(html, /placeholder="輸入檔案密碼"/)
    assert.match(html, /locked.pdf/)
    assert.doesNotMatch(html, /需要解壓密碼|輸入壓縮檔密碼/)
})

test('nested PDF wrong passwords remain attached to the target and per-file retry budget', () => {
    const child = report({ job_id: 'pdf-child', job_status: 'password_required',
        file: { original_filename: 'locked.pdf' },
        results: { format_analysis: { analyzer: 'pdf', features: { encrypted: true, content_access: 'wrong_password' } } },
    })
    const nested = report({ job_status: 'password_required', password_required_artifacts: ['pdf-child'],
        child_jobs: [{ job_id: 'pdf-child', filename: 'locked.pdf', status: 'password_required' }],
        artifacts: [{ artifact_id: 'pdf-child', status: 'password_required', reason: 'wrong_password', report: child }],
        artifact_tree: { id: 'root', job_id: 'root-job', filename: 'outer.zip', children: [
            { id: 'pdf-child', job_id: 'pdf-child', filename: 'locked.pdf', display_path: 'outer.zip/locked.pdf', job_status: 'password_required', children: [] },
        ] },
    })
    assert.deepEqual(passwordTargets(nested), [{ jobId: 'pdf-child', filename: 'locked.pdf', path: 'outer.zip/locked.pdf' }])
    assert.equal(passwordTargetError(nested, 'pdf-child'), 'wrong_password')
    assert.equal(passwordTargetError(nested, 'root-job'), undefined)
    assert.equal(passwordTargetError(child, 'pdf-child'), 'wrong_password')
    const html = render(PasswordForm, { filename: 'locked.pdf', artifactPath: 'outer.zip/locked.pdf',
        attemptsUsed: 1, attemptsRemaining: 2, attemptsScope: '每個檔案各自最多提交三次密碼。',
        error: passwordTargetError(nested, 'pdf-child'), onSubmit: async () => {},
    })
    assert.match(html, /outer.zip\/locked.pdf/)
    assert.match(html, /密碼不正確/)
    assert.match(html, /role="alert"/)
    assert.match(html, /aria-live="assertive"/)
    assert.match(html, /剩餘次數: 2/)
    assert.match(html, /每個檔案各自/)
    const exhausted = render(PasswordForm, { filename: 'locked.pdf', attemptsUsed: 3, attemptsRemaining: 0,
        error: 'password_attempt_limit', onSubmit: async () => {},
    })
    assert.match(exhausted, /剩餘次數: 0/)
    assert.match(exhausted, /已達密碼嘗試上限/)
    assert.match(exhausted, /disabled=""/)
})

test('unsupported encrypted PDFs stay partial without offering an unauthorized password retry', () => {
    const unsupported = report({ job_status: 'done', report_complete: true, password_required_artifacts: [],
        file: { original_filename: 'unsupported.pdf' },
        analysis: { static: { status: 'partial', stage_coverage: [{ stage: 'format-analysis', status: 'unsupported', reason: 'unsupported_encryption' }] }, dynamic: { status: 'disabled' } },
        results: { format_analysis: { analyzer: 'pdf', features: { encrypted: true, content_access: 'password_required' } } },
    })
    assert.deepEqual(passwordTargets(unsupported), [])
    assert.equal(passwordTargetError(unsupported, unsupported.job_id), undefined)
    assert.equal(stageCompleted(unsupported, 'format-analysis'), false)
    assert.match(render(CoveragePanel, { analysis: unsupported.analysis, complete: true }), /部分完成/)
})

test('legacy archive-named password errors remain compatible with the generic file form', () => {
    for (const [error, expected] of [
        ['invalid_archive_password', /檔案密碼格式無效/],
        ['archive_not_waiting', /此檔案目前未等待密碼/],
        ['Archive password was rejected', /密碼不正確/],
        ['Password attempts exhausted', /已達密碼嘗試上限/],
    ]) {
        const html = render(PasswordForm, { attemptsUsed: 1, attemptsRemaining: 2, error, onSubmit: async () => {} })
        assert.match(html, expected)
        assert.doesNotMatch(html, new RegExp(error))
    }
})

test('signed child password requirements never turn the root into a password target', () => {
    const root = report({ job_status: 'password_required', password_required_artifacts: ['child-job'],
        child_jobs: [{ job_id: 'child-job', filename: 'inner.zip', status: 'password_required' }] })
    assert.deepEqual(passwordTargets(root), [{ jobId: 'child-job', filename: 'inner.zip' }])
    assert.equal(jobNeedsPassword({ job_id: 'root-job', status: 'password_required', password_required_artifacts: ['child-job'] }), false)
    assert.equal(jobNeedsPassword({ job_id: 'child-job', status: 'password_required', password_required_artifacts: ['child-job'] }), true)
    assert.equal(jobNeedsPassword({ job_id: 'legacy-job', status: 'password_required' }), true)
    assert.deepEqual(passwordTargets({ ...root, job_status: 'queued', password_required_artifacts: [] }), [])
})

test('uncertain dispatches and a newer completed status keep polling the prior partial snapshot', () => {
    assert.equal(shouldRefreshReport(report({ job_status: 'failed', requires_reconciliation: true })), true)
    assert.equal(shouldRefreshReport(report({ job_status: 'done', report_complete: false, analysis: { dynamic: { status: 'disabled' } } })), true)
})

test('exhausted file password controls explain the per-file limit and disable submission', () => {
    const html = render(PasswordForm, { attemptsUsed: 3, attemptsRemaining: 0, onSubmit: async () => {},
        attemptsScope: '每個檔案各自最多提交三次密碼。', filename: 'inner.zip' })
    assert.match(html, /每個檔案各自/)
    assert.match(html, /已達密碼嘗試上限/)
    assert.match(html, /disabled=""/)
    assert.match(html, /inner.zip/)
})

test('artifact tree shows password state and links to the specific descendant job', () => {
    const html = render(ArtifactTreePanel, { tree: { id: 'leaf', job_id: 'leaf-job', job_status: 'password_required', analysis_status: 'partial', filename: 'locked.7z', sha256: 'abcd', depth: 2, children: [], top_finding_titles: [] } })
    assert.match(html, /href="\/jobs\/leaf-job"/)
    assert.match(html, /等待檔案密碼/)
    assert.match(html, /部分完成/)
})

test('YARA engine, content digest and unverified legacy provenance stay separate', () => {
    const html = render(YaraRulesPanel, { hits: [], completed: true, coverage: {
        stage: 'yara', status: 'ok', tool_version: '4.5.4', rules_version: 'a'.repeat(64),
    } })
    assert.match(html, /比對引擎：YARA 4\.5\.4/)
    assert.match(html, /規則內容 SHA-256/)
    assert.match(html, /未驗證/)
    assert.match(html, /未提供規則來源清單/)
    assert.match(html, /未命中本次配置的規則/)
    assert.doesNotMatch(html, /確認安全|已確認惡意/)
})

test('verified local YARA inventory never becomes an authorship, licensing or malware claim', () => {
    const provenance = { status: 'verified', ruleset_id: 'bundled-basic', ruleset_version: '1.0.0',
        ruleset_sha256: 'b'.repeat(64), file_count: 2, rule_count: 2,
        source: { repository: 'https://example.test/rules', declared_author: 'Self-declared author' },
        license: { spdx_expression: 'NOASSERTION', status: 'not_declared', permission_verified: false },
    }
    const html = render(YaraRulesPanel, { completed: true, provenance, hits: [
        { rule: 'eicar', namespace: 'tests', severity: 'high', provenance: { ...provenance, category: 'test', limitations: 'Test only.' } },
        { rule: 'network_strings', namespace: 'context', provenance: { ...provenance, category: 'heuristic', limitations: 'Benign documentation also matches.' } },
    ] })
    assert.match(html, /bundled-basic/)
    assert.match(html, /1\.0\.0/)
    assert.match(html, /本地檔案雜湊與規則清單校驗完成/)
    assert.match(html, /自述作者（未獨立驗證）/)
    assert.match(html, /未聲明／尚未確認授權許可/)
    assert.match(html, /測試標記/)
    assert.match(html, /啟發式／脈絡線索/)
    assert.match(html, /不等同真實惡意程式/)
    assert.match(html, /Benign documentation also matches/)
    assert.doesNotMatch(html, /text-alert-red|href=/)
})

test('unverified rule metadata is not promoted to checked source or test classification', () => {
    const unknown = { status: 'unverified', reason: 'file_hash_mismatch', category: 'test',
        source: { repository: 'untrusted-source' }, license: { spdx_expression: 'InventedLicense' } }
    const html = render(YaraRulesPanel, { provenance: unknown, hits: [{ rule: 'custom', namespace: 'custom', provenance: unknown }] })
    assert.match(html, /規則檔案雜湊不一致/)
    assert.match(html, /規則分類未驗證/)
    assert.doesNotMatch(html, /untrusted-source|InventedLicense|此命中用於測試偵測流程/)
})

test('verified context-only YARA hits remain visible without a warning color or malware implication', () => {
    const provenance = { status: 'verified', category: 'context', limitations: 'URLs are present in normal documentation.' }
    const html = render(YaraRulesPanel, { completed: true, provenance, hits: [{
        rule: 'network_iocs', namespace: 'network', classification: 'informational', severity: 'info',
        description: 'Observed URL https://example.test/readme', provenance,
    }] })
    assert.match(html, /network_iocs/)
    assert.match(html, /https:\/\/example.test\/readme/)
    assert.match(html, /資訊觀察／不計入風險/)
    assert.match(html, /資訊觀察 1 筆/)
    assert.match(html, /規則嚴重度 資訊/)
    assert.match(html, /不代表檔案安全或惡意/)
    assert.match(html, /作者身分、授權許可與偵測準確率仍需另行確認/)
    assert.doesNotMatch(html, /text-caution-yellow|text-alert-red|其他規則命中|href=/)
})

test('mixed YARA hits distinguish contextual observations from heuristic and test matches', () => {
    const verified = { status: 'verified' }
    const html = render(YaraRulesPanel, { completed: true, provenance: verified, hits: [
        { rule: 'network_iocs', namespace: 'network', classification: 'informational', severity: 'info', provenance: { ...verified, category: 'context' } },
        { rule: 'jsp_execution', namespace: 'webshells', classification: 'suspicious', severity: 'medium', provenance: { ...verified, category: 'heuristic' } },
        { rule: 'eicar', namespace: 'tests', classification: 'test', severity: 'high', provenance: { ...verified, category: 'test' } },
    ] })
    assert.match(html, /資訊觀察 1 筆/)
    assert.match(html, /其他規則命中 2 筆/)
    assert.match(html, /資訊觀察／不計入風險/)
    assert.match(html, /啟發式／脈絡線索/)
    assert.match(html, /測試標記/)
    assert.match(html, /此命中用於測試偵測流程，不等同真實惡意程式/)
    assert.match(html, /text-neon-cyan font-bold break-all">network_iocs/)
    assert.match(html, /text-caution-yellow font-bold break-all">jsp_execution/)
})

test('unverified informational metadata and inconsistent context metadata never imply unscored hits', () => {
    for (const hit of [
        { classification: 'informational', severity: 'info', provenance: { status: 'unverified', category: 'context' } },
        { classification: 'informational', severity: 'info' },
        { classification: 'malicious', severity: 'high', provenance: { status: 'verified', category: 'context' } },
    ]) {
        const html = render(YaraRulesPanel, { completed: true, hits: [{ rule: 'custom', namespace: 'custom', ...hit }] })
        assert.match(html, /其他規則命中 1 筆/)
        assert.match(html, /text-caution-yellow font-bold break-all">custom/)
        assert.doesNotMatch(html, /資訊觀察／不計入風險|這些命中不增加/)
    }
})

function findingsBlock(items) {
    return {
        summary: { headline: 'Analysis observations', top_findings: items.map((item) => ({
            finding_id: item.id, artifact_id: 'root', artifact_path: 'readme.txt', archive_layer: 0,
            title: item.reason || item.kind, why_flagged: item.reason || item.kind, score_impact: item.points,
        })) },
        findings: items.map((item) => ({ finding_id: item.id, kind: item.kind, severity: item.severity,
            score_impact: item.points, evidence_ids: [`evidence-${item.id}`],
        })),
        evidence: items.map((item) => ({ ...item, id: `evidence-${item.id}` })),
    }
}

test('contextual findings preserve linked benign evidence and use neutral zero-contribution presentation', () => {
    const context = { id: 'context', kind: 'yara_context_observation', tier: 'benign_context', points: 0,
        severity: 'info', reason: 'YARA classification informational matched rule network_iocs' }
    const html = render(TopFindingsSummary, { explainability: findingsBlock([context]) })
    assert.match(html, /YARA 資訊觀察/)
    assert.match(html, /資訊觀察／不計入風險/)
    assert.match(html, /嚴重度 資訊/)
    assert.match(html, /YARA 以 資訊性 分類命中規則：network_iocs/)
    assert.doesNotMatch(html, /caution-yellow|text-alert-red|\+0/)

    const mixed = render(TopFindingsSummary, { explainability: findingsBlock([context,
        { id: 'suspicious', kind: 'yara_suspicious', tier: 'medium', severity: 'medium', points: 45 },
    ]) })
    assert.match(mixed, /資訊觀察／不計入風險/)
    assert.match(mixed, /嚴重度 中/)
    assert.match(mixed, /caution-yellow/)
    assert.match(mixed, /\+45/)
})

test('unattributed network indicator observations stay visible without a risk contribution', () => {
    const observations = ['raw_url_ioc', 'raw_domain_ioc', 'raw_ip_ioc', 'ioc_multiple_types_observation']
        .map((kind) => ({ id: kind, kind, tier: 'benign_context', points: 0, severity: 'info' }))
    const html = render(TopFindingsSummary, { explainability: findingsBlock(observations) })
    assert.match(html, /URL IOC/)
    assert.match(html, /網域 IOC/)
    assert.match(html, /IP IOC/)
    assert.match(html, /多類型網路指標觀察/)
    assert.equal((html.match(/資訊觀察／不計入風險/g) ?? []).length, 4)
    assert.doesNotMatch(html, /caution-yellow|text-alert-red|\+0/)
})

test('zero-impact legacy and unknown findings are not silently reclassified as benign context', () => {
    for (const item of [
        { id: 'unknown', kind: 'future_context_kind', tier: 'benign_context', severity: 'info', points: 0 },
        { id: 'inconsistent', kind: 'yara_context_observation', tier: 'weak', severity: 'info', points: 0 },
        { id: 'legacy', kind: 'raw_url_ioc', tier: 'weak', severity: 'low', points: 8 },
    ]) {
        const html = render(TopFindingsSummary, { explainability: findingsBlock([item]) })
        assert.match(html, /caution-yellow/)
        assert.match(html, new RegExp(`\\+${item.points}`))
        assert.doesNotMatch(html, /不計入風險/)
    }
    const legacy = render(TopFindingsSummary, { explainability: { summary: {
        headline: 'Legacy', top_findings: [{ finding_id: 'legacy', title: 'Legacy match', score_impact: 0 }],
    } } })
    assert.match(legacy, /Legacy match/)
    assert.match(legacy, /\+0/)
    assert.doesNotMatch(legacy, /不計入風險/)
})

test('failed and unsupported YARA scans remain distinct from successful empty scans', () => {
    for (const [status, label] of [['failed', '失敗'], ['unsupported', '不支援']]) {
        const html = render(YaraRulesPanel, { coverage: { stage: 'yara', status, reason: 'rules_unavailable' } })
        assert.match(html, new RegExp(`比對狀態：${label}`))
        assert.match(html, /尚未完成有效規則比對/)
        assert.doesNotMatch(html, /已比對，未命中/)
    }
})

test('ClamAV engine and database metadata are separate and do not imply an upstream latest check', () => {
    const html = render(AntivirusPanel, { completed: true, result: { engine: 'ClamAV', engine_version: '1.4.3',
        database_version: '28153', database_timestamp: 'Wed Oct 14 06:24:15 2026', infected: false },
    })
    assert.match(html, /ClamAV 1\.4\.3/)
    assert.match(html, /病毒資料庫版本/)
    assert.match(html, /28153/)
    assert.match(html, /病毒資料庫所載時間/)
    assert.match(html, /不能單獨證明/)
    const legacy = render(AntivirusPanel, { result: { engine: 'ClamAV', infected: false },
        coverage: { stage: 'clamav', status: 'failed', tool_version: 'ClamAV 1.4.3/28153/date' },
    })
    assert.match(legacy, /原始工具版本：ClamAV 1\.4\.3\/28153\/date/)
    assert.match(legacy, /掃描狀態：失敗/)
    assert.doesNotMatch(legacy, /已掃描，未命中/)
})

test('duplicate artifacts expose inherited source coverage without inventing a direct rerun', () => {
    const html = render(ArtifactTreePanel, { coverage: { occurrences: 2, direct: 1, inherited: 1, unresolved: 0 }, tree: {
        id: 'duplicate', filename: 'repeated.txt', sha256: 'c'.repeat(64), analysis_status: 'complete',
        analysis_reference: { mode: 'inherited', status: 'verified', source_artifact_id: 'source-artifact', source_job_id: 'source-job',
            source_sha256: 'c'.repeat(64), source_analysis_status: 'partial', source_evidence_ids: ['e1'], source_finding_ids: ['f1'],
            risk: { score: 95, risk_level: 'malicious', verdict: 'malicious' },
            source_stage_coverage: [{ stage: 'clamav', status: 'ok' }, { stage: 'deobfuscation', status: 'unsupported' }, { stage: 'yara', status: 'failed' }],
        },
    } })
    assert.match(html, /直接分析 1、沿用分析 1、來源未確認 0/)
    assert.match(html, /本節點未重跑階段/)
    assert.match(html, /source-artifact/)
    assert.match(html, /href="\/jobs\/source-job"/)
    assert.match(html, /部分完成/)
    assert.match(html, /去混淆：不支援/)
    assert.match(html, /YARA 規則比對：失敗/)
    assert.match(html, /直接分數 —/)
    assert.match(html, /本節點無直接判定/)
    assert.match(html, /沿用來源風險/)
    assert.match(html, /風險 惡意 \/ 分數 95 \/ 判定 惡意/)
    assert.doesNotMatch(html, /直接分數 0/)
    assert.doesNotMatch(html, /本檔直接分析/)
})

test('unresolved artifact references and incomplete legacy coverage remain readable', () => {
    const html = render(ArtifactTreePanel, { coverage: {}, tree: { id: 'missing', filename: 'unresolved.bin',
        analysis_reference: { mode: 'unresolved', status: 'unresolved', reason: 'source_missing' },
    } })
    assert.match(html, /分析來源尚未確認/)
    assert.match(html, /覆蓋範圍仍不完整/)
    assert.match(html, /分數 —/)
    assert.doesNotMatch(html, /分數 0/)
    assert.doesNotMatch(html, /本檔直接分析|沿用相同內容/)
    assert.doesNotMatch(html, /檔案節點.*個：直接分析/)
    assert.match(render(CoveragePanel, { analysis: { static: {} } }), /無法確認完整分析範圍/)
    assert.equal(stageCompleted(report({ analysis: { static: {} } }), 'yara'), false)
})

test('direct artifact details preserve partial and failed coverage rather than inheriting completion', () => {
    const html = render(ArtifactTreePanel, { tree: { id: 'direct', filename: 'direct.bin',
        analysis_status: 'partial', analysis_reference: { mode: 'direct', status: 'verified',
            source_analysis_status: 'partial', source_stage_coverage: [{ stage: 'yara', status: 'failed' }],
        },
    } })
    assert.match(html, /本檔直接分析/)
    assert.match(html, /部分完成/)
    assert.match(html, /YARA 規則比對：失敗/)
    assert.doesNotMatch(html, /沿用相同內容/)
})

test('nested Office password feedback binds to that file and preserves its retry allowance', () => {
    const office = { artifact_id: 'office-child', reason: 'wrong_password', report: {
        job_id: 'office-child', results: { format_analysis: {
            analyzer: 'office', password_kind: 'office',
            features: { encrypted: true, content_access: 'wrong_password' },
        } },
    } }
    const nested = report({ job_status: 'password_required', password_required_artifacts: ['office-child'],
        artifacts: [office], child_jobs: [{ job_id: 'office-child', filename: 'locked.docx', status: 'password_required' }],
    })
    assert.deepEqual(passwordTargets(nested), [{ jobId: 'office-child', filename: 'locked.docx' }])
    assert.equal(passwordTargetError(nested, 'root-job'), undefined)
    assert.equal(passwordTargetError(nested, 'office-child'), 'wrong_password')
    const html = render(PasswordForm, { filename: 'locked.docx', attemptsUsed: 1, attemptsRemaining: 2,
        error: 'Office password was rejected', onSubmit: async () => {} })
    assert.match(html, /Office 文件/)
    assert.match(html, /密碼不正確/)
    assert.match(html, /locked.docx/)
    assert.match(html, /role="alert"/)
    assert.doesNotMatch(html, /Office password was rejected/)
})

test('unsupported Office encryption remains partial and cannot authorize a password submission', () => {
    const unsupported = report({ job_status: 'done', report_complete: true, password_required_artifacts: [],
        file: { original_filename: 'unsupported.docx' },
        results: { format_analysis: { analyzer: 'office', features: { encrypted: true, content_access: 'unsupported' } } },
        analysis: { static: { status: 'partial', stage_coverage: [{ stage: 'format-analysis', status: 'partial', reason: 'unsupported_office_encryption' }] }, dynamic: { status: 'disabled' } },
    })
    assert.deepEqual(passwordTargets(unsupported), [])
    assert.equal(passwordTargetError(unsupported, unsupported.job_id), undefined)
    assert.equal(stageCompleted(unsupported, 'format-analysis'), false)
    assert.match(render(CoveragePanel, { analysis: unsupported.analysis, complete: true }), /部分完成/)
})
