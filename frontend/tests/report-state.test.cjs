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

const { dynamicStatus, jobNeedsPassword, passwordTargets, shouldRefreshReport, stageCompleted } = require('../src/components/report/reportState.ts')
const CoveragePanel = require('../src/components/report/AnalysisCoveragePanel.tsx').default
const DynamicPanel = require('../src/components/report/DynamicAnalysisPanel.tsx').default
const ArtifactTreePanel = require('../src/components/report/ArtifactTreePanel.tsx').default
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

test('exhausted cloud password controls explain the root-wide limit and disable submission', () => {
    const html = render(PasswordForm, { attemptsUsed: 3, attemptsRemaining: 0, onSubmit: async () => {},
        attemptsScope: '雲端 demo 最多三次密碼重試，由整個上傳工作共用。', filename: 'inner.zip' })
    assert.match(html, /整個上傳工作共用/)
    assert.match(html, /已達密碼嘗試上限/)
    assert.match(html, /disabled=""/)
    assert.match(html, /inner.zip/)
})

test('artifact tree shows password state and links to the specific descendant job', () => {
    const html = render(ArtifactTreePanel, { tree: { id: 'leaf', job_id: 'leaf-job', job_status: 'password_required', analysis_status: 'partial', filename: 'locked.7z', sha256: 'abcd', depth: 2, children: [], top_finding_titles: [] } })
    assert.match(html, /href="\/jobs\/leaf-job"/)
    assert.match(html, /等待解壓密碼/)
    assert.match(html, /部分完成/)
})
