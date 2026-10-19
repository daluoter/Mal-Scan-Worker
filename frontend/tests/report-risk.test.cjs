const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const test = require('node:test')
const ts = require('typescript')
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')
const { StaticRouter } = require('react-router')

for (const extension of ['.ts', '.tsx']) {
    require.extensions[extension] = (module, filename) => {
        const { outputText } = ts.transpileModule(readFileSync(filename, 'utf8'), {
            compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2020 },
            fileName: filename,
        })
        module._compile(outputText, filename)
    }
}

const { artifactRiskPresentations, reportRiskPresentation } = require('../src/components/report/reportRisk.ts')
const VerdictSummaryPanel = require('../src/components/report/VerdictSummaryPanel.tsx').default
const ArtifactTreePanel = require('../src/components/report/ArtifactTreePanel.tsx').default
const ScoreTracePanel = require('../src/components/report/ScoreTracePanel.tsx').default

function node(id, overrides = {}) {
    return { id, filename: `${id}.pdf`, sha256: id.repeat(64), size: 1200, depth: 0,
        score: 0, risk_level: 'clean', verdict: 'clean', children: [], top_finding_titles: [], ...overrides }
}

function report(tree, overrides = {}) {
    return { score: 4, risk_level: 'clean', verdict: 'clean', report_complete: true, artifact_tree: tree, ...overrides }
}

function render(Component, props) {
    return renderToStaticMarkup(React.createElement(StaticRouter, { location: '/' }, React.createElement(Component, props)))
}

test('legacy locked parent surfaces red high-risk decrypted content without rewriting its local score', () => {
    const decrypted = node('d', { filename: 'decrypted.pdf', score: 84, risk_level: 'high', verdict: 'suspicious',
        display_path: 'locked.pdf!/pdf-decrypted' })
    const locked = node('l', { filename: 'locked.pdf', score: 4, children: [decrypted] })
    const data = report(locked)
    const summary = reportRiskPresentation(data)
    assert.equal(summary.effective.score, 84)
    assert.equal(summary.local.score, null)
    assert.equal(summary.localRiskKnown, false)
    assert.equal(summary.recorded.score, 4)
    assert.equal(summary.legacyDescendantFallback, true)
    assert.equal(data.score, 4)
    assert.equal(locked.score, 4)

    const html = render(VerdictSummaryPanel, { report: data })
    assert.match(html, /verdict-malicious/)
    assert.match(html, /text-alert-red/)
    assert.match(html, /⚠️ 高風險/)
    assert.match(html, /內含高風險檔案：decrypted.pdf/)
    assert.match(html, /locked.pdf!\/pdf-decrypted/)
    assert.match(html, /舊報告記錄分數 4\/100/)
    assert.match(html, /已知子檔最高分數/)
    assert.match(html, /不等同已確認惡意程式/)
    assert.doesNotMatch(html, /未發現威脅|☠️|原始分數 84/)
})

test('legacy aggregate 29 remains a recorded score while a high-risk child 84 stays visible', () => {
    const decrypted = node('d', { filename: 'decrypted.pdf', score: 84, risk_level: 'high', verdict: 'suspicious',
        display_path: 'locked.pdf!/pdf-decrypted' })
    const locked = node('l', { filename: 'locked.pdf', score: 29, risk_level: 'low', verdict: 'suspicious', children: [decrypted] })
    const data = report(locked, { score: 29, risk_level: 'low', verdict: 'suspicious', risk: {
        breakdown: { local_score: 4, inherited_score: 25, synergy_bonus: 0, dampener: 0, final_score: 29 },
    } })
    const risk = reportRiskPresentation(data)
    assert.equal(risk.localRiskKnown, false)
    assert.equal(risk.local.score, null)
    assert.equal(risk.recorded.score, 29)
    assert.equal(risk.effective.score, 84)
    assert.equal(data.risk.breakdown.local_score, 4)

    const html = render(VerdictSummaryPanel, { report: data })
    assert.match(html, /⚠️ 高風險/)
    assert.match(html, /84<span/)
    assert.match(html, /舊報告記錄分數 29\/100/)
    assert.match(html, /記錄分數可能已含子檔繼承/)
    assert.doesNotMatch(html, /本檔直接分數 29|主分數未整合子檔/)
    const treeHtml = render(ArtifactTreePanel, { tree: locked })
    assert.match(treeHtml, /包含內容分數 84/)
    assert.match(treeHtml, /舊報告記錄分數 29/)
    assert.match(treeHtml, /舊報告記錄判定：低風險/)
    assert.doesNotMatch(treeHtml, /本檔直接分數 29|本檔直接判定：低風險/)
})

test('legacy reports honor the shared 60-point high-risk boundary without inventing malicious verdicts', () => {
    for (const riskLevel of [undefined, null, 'suspicious']) {
        const child = node('b', { filename: 'decrypted.pdf', score: 60, risk_level: riskLevel, verdict: 'suspicious' })
        const locked = node('l', { filename: 'locked.pdf', score: 4, children: [child] })
        const data = report(locked)
        assert.equal(reportRiskPresentation(data).effective.level, 'high')
        const html = render(VerdictSummaryPanel, { report: data })
        assert.match(html, /verdict-malicious/)
        assert.match(html, /text-alert-red/)
        assert.match(html, /⚠️ 高風險/)
        assert.match(html, /內含高風險檔案：decrypted.pdf/)
        assert.match(html, /60<span/)
        assert.doesNotMatch(html, /☠️ 惡意/)
        assert.match(render(ArtifactTreePanel, { tree: child }), /text-alert-red[^>]*>decrypted.pdf/)
    }

    const direct = report(null, { score: 60, risk_level: undefined, verdict: 'suspicious' })
    assert.match(render(VerdictSummaryPanel, { report: direct }), /⚠️ 高風險/)
    const belowBoundary = report(null, { score: 59, risk_level: undefined, verdict: 'suspicious' })
    const mediumHtml = render(VerdictSummaryPanel, { report: belowBoundary })
    assert.match(mediumHtml, /verdict-suspicious/)
    assert.match(mediumHtml, /⚠️ 中風險/)
    assert.doesNotMatch(mediumHtml, /text-alert-red|verdict-malicious/)
    const malicious = report(null, { score: 85, risk_level: undefined, verdict: 'malicious' })
    assert.match(render(VerdictSummaryPanel, { report: malicious }), /☠️ 惡意/)
})

test('new effective risk preserves the decrypted leaf path across multiple encrypted ancestors', () => {
    const decrypted = node('d', { filename: 'decrypted.pdf', score: 84, risk_level: 'high', verdict: 'suspicious',
        local_score: 84, local_risk_level: 'high', local_verdict: 'suspicious',
        display_path: 'outer.zip!/locked.pdf!/pdf-decrypted' })
    const locked = node('l', { filename: 'locked.pdf', score: 84, risk_level: 'high', verdict: 'suspicious',
        local_score: 4, local_risk_level: 'clean', local_verdict: 'clean', children: [decrypted] })
    const archive = node('a', { filename: 'outer.zip', score: 84, risk_level: 'high', verdict: 'suspicious',
        local_score: 0, local_risk_level: 'clean', local_verdict: 'clean', children: [locked] })
    const risks = artifactRiskPresentations(archive)
    assert.equal(risks.get(archive).descendant.sourceFilename, 'decrypted.pdf')
    assert.equal(risks.get(locked).local.score, 4)
    const data = report(archive, { score: 84, risk_level: 'high', verdict: 'suspicious',
        risk: { local_risk: { score: 0, risk_level: 'clean', verdict: 'clean' } } })
    assert.equal(reportRiskPresentation(data).legacyDescendantFallback, false)
    const html = render(ArtifactTreePanel, { tree: archive })
    assert.match(html, /text-alert-red[^>]*>decrypted.pdf/)
    assert.match(html, /高風險（含內層內容）/)
    assert.match(html, /本檔直接分數 4/)
    assert.match(html, /本檔直接判定：未發現威脅。外層檔案的直接判定不代表內層內容安全/)
    assert.doesNotMatch(html, /舊版報告/)
})

test('a verified same-content reference can elevate visibility without inventing a direct scan', () => {
    const repeated = node('r', { score: null, risk_level: null, verdict: null,
        analysis_reference: { mode: 'inherited', status: 'verified', source_sha256: 'r'.repeat(64), source_size: 1200,
            source_artifact_id: 'original', source_job_id: 'original-job', risk: { score: 95, risk_level: 'malicious', verdict: 'malicious' } } })
    const data = report(node('p', { children: [repeated] }))
    assert.equal(reportRiskPresentation(data).effective.verdict, 'malicious')
    const html = render(ArtifactTreePanel, { tree: repeated })
    assert.match(html, /text-alert-red/)
    assert.match(html, /本節點未重跑階段/)
    assert.match(html, /直接分數 —/)
    assert.match(html, /本節點無直接判定/)
})

test('unresolved or identity-mismatched references never elevate ancestors using unverified risk', () => {
    for (const reference of [
        { mode: 'unresolved', status: 'unresolved' },
        { mode: 'inherited', status: 'verified', source_sha256: 'different' },
        { mode: 'inherited', status: 'verified', source_size: 999 },
        { mode: 'direct', status: 'verified', source_artifact_id: 'different' },
    ]) {
        const child = node('u', { score: 99, risk_level: 'malicious', verdict: 'malicious',
            analysis_reference: { ...reference, risk: { score: 99, risk_level: 'malicious', verdict: 'malicious' } } })
        const data = report(node('p', { score: 4, children: [child] }))
        assert.equal(reportRiskPresentation(data).effective.score, 4)
        const html = render(ArtifactTreePanel, { tree: child })
        assert.match(html, /分析來源尚未確認/)
        assert.doesNotMatch(html, /text-alert-red|沿用來源風險|本檔直接分析/)
    }
})

test('higher confidence malicious root and ordinary completed clean report retain their distinct verdicts', () => {
    const child = node('c', { score: 84, risk_level: 'high', verdict: 'suspicious' })
    const malicious = report(node('m', { score: 95, risk_level: 'malicious', verdict: 'malicious', children: [child] }),
        { score: 95, risk_level: 'malicious', verdict: 'malicious' })
    const maliciousHtml = render(VerdictSummaryPanel, { report: malicious })
    assert.match(maliciousHtml, /☠️ 惡意/)
    assert.match(maliciousHtml, /95<span/)
    const cleanHtml = render(VerdictSummaryPanel, { report: report(node('c'), { score: 0 }) })
    assert.match(cleanHtml, /verdict-clean/)
    assert.match(cleanHtml, /✅ 未發現威脅/)
    assert.doesNotMatch(cleanHtml, /text-alert-red|內含高風險/)
})

test('an incomplete clean snapshot remains neutral while an observed high-risk snapshot stays red', () => {
    const incomplete = report(node('p'), { score: 0, report_complete: false })
    assert.doesNotMatch(render(VerdictSummaryPanel, { report: incomplete }), /verdict-clean/)
    const high = report(node('h', { score: 84, risk_level: 'high', verdict: 'suspicious' }),
        { score: 84, risk_level: 'high', verdict: 'suspicious', report_complete: false })
    const html = render(VerdictSummaryPanel, { report: high })
    assert.match(html, /verdict-malicious/)
    assert.match(html, /目前已知風險（分析尚未完成）/)
})

test('descendant floor remains explicit in score formation and keeps source path visible', () => {
    const html = render(ScoreTracePanel, { risk: {
        breakdown: { local_score: 4, inherited_score: 0, synergy_bonus: 0, dampener: 0, descendant_floor: 80, final_score: 84 },
        score_trace: { components: [{ type: 'descendant_risk_floor', applied_points: 80, source_score: 84,
            related_artifact_id: 'decrypted', display_path: 'locked.pdf!/pdf-decrypted',
            reason: 'verified high-risk descendant sets the minimum effective subtree risk' }] },
    } })
    assert.match(html, /子檔風險下限補足/)
    assert.match(html, /\+80/)
    assert.match(html, /最終分數/)
    assert.match(html, /來源分數 84/)
    assert.match(html, /來源路徑 locked.pdf!\/pdf-decrypted/)
    assert.match(html, /不代表新增偵測/)
})
