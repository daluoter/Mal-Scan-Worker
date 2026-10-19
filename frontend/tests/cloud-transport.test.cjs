const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const test = require('node:test')
const { File } = require('node:buffer')
const { webcrypto } = require('node:crypto')
const ts = require('typescript')

require.extensions['.ts'] = (module, filename) => {
    const { outputText } = ts.transpileModule(readFileSync(filename, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }, fileName: filename,
    })
    module._compile(outputText, filename)
}
const { CloudTransport } = require('../src/api/cloudTransport.ts')
const ROOT = '11111111-1111-4111-8111-111111111111'
const CHILD = '22222222-2222-5222-8222-222222222222'
const OTHER = '33333333-3333-5333-8333-333333333333'
const CAP = 'a'.repeat(64)
const TICKET = 'b'.repeat(64)
const BASE = 'https://demo.invalid'
global.crypto = webcrypto

function storage() {
    const values = new Map()
    return {
        values, getItem: (key) => values.get(key) ?? null,
        setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key),
    }
}
function ownedStorage() {
    const result = storage()
    result.setItem(`malscan:cloud:${BASE}:${ROOT}`, JSON.stringify({ rootId: ROOT, capability: CAP }))
    return result
}
function json(body, status = 200) { return new Response(JSON.stringify(body), { status }) }
function status(overrides = {}) {
    return { job_id: ROOT, status: 'password_required', password_required_artifacts: [CHILD],
        password_attempts: 1, password_attempts_remaining: 2, report_available: true,
        progress: { current_stage: 'password_required', percent: 0, stages_done: 0, stages_total: 1 }, ...overrides }
}
function report(overrides = {}) {
    const tree = { id: ROOT, job_id: ROOT, filename: 'root.zip', children: [
        { id: CHILD, job_id: CHILD, filename: 'inner.zip', children: [], job_status: 'password_required' },
        { id: OTHER, job_id: OTHER, filename: 'done.txt', children: [], job_status: 'done' },
    ] }
    return { job_id: ROOT, report_complete: false, job_status: 'password_required',
        password_required_artifacts: [CHILD], pending_descendants: 1, report_schema_version: 'mswr-report-v3',
        file: { original_filename: 'root.zip' }, child_jobs: [
            { job_id: CHILD, filename: 'inner.zip', status: 'password_required' },
            { job_id: OTHER, filename: 'done.txt', status: 'done' },
        ], artifact_tree: tree, artifacts: [
            { artifact_id: CHILD, status: 'password_required', report: { job_id: CHILD, file: { original_filename: 'inner.zip' } } },
            { artifact_id: OTHER, status: 'done', report: { job_id: OTHER, file: { original_filename: 'done.txt' } } },
        ], ...overrides }
}

test('ticket upload hashes the original bytes and saves ownership before sending the raw file', async (t) => {
    const saved = storage()
    const client = new CloudTransport(BASE, saved)
    const file = new File(['benign sample'], 'sample.txt')
    const calls = []
    t.mock.method(global, 'fetch', async (url, options) => {
        calls.push(url)
        assert.equal(options.redirect, 'error')
        assert.equal(options.credentials, 'omit')
        assert.equal(url.includes(CAP), false)
        if (url.endsWith('/upload-tickets')) {
            const body = JSON.parse(options.body)
            assert.equal(body.bytes, file.size)
            assert.equal(body.filename, file.name)
            assert.equal(body.sha256, Buffer.from(await webcrypto.subtle.digest('SHA-256', await file.arrayBuffer())).toString('hex'))
            assert.equal(options.headers.Authorization, undefined)
            return json({ job_id: ROOT, token: TICKET, capability_token: CAP, max_bytes: file.size, expires_at: Date.now() + 300_000 }, 201)
        }
        assert.equal(saved.values.size, 1)
        assert.equal(options.headers.Authorization, `Bearer ${TICKET}`)
        assert.equal(options.headers['Content-Type'], 'application/octet-stream')
        assert.equal(options.headers['Content-Length'], undefined)
        assert.equal(options.body, file)
        return json({ job_id: ROOT, status: 'queued' }, 201)
    })
    assert.equal((await client.upload(file)).job_id, ROOT)
    assert.deepEqual(calls, [`${BASE}/api/v1/upload-tickets`, `${BASE}/api/v1/files`])
})

test('lost upload responses retain the existing capability and expose only its public job ID for recovery', async (t) => {
    const saved = storage()
    const client = new CloudTransport(BASE, saved)
    const file = new File(['x'], 'x.txt')
    let calls = 0
    t.mock.method(global, 'fetch', async () => {
        if (++calls === 1) return json({ job_id: ROOT, token: TICKET, capability_token: CAP, max_bytes: 1, expires_at: Date.now() + 300_000 }, 201)
        throw new Error('network response lost')
    })
    await assert.rejects(client.upload(file), (error) => error.jobId === ROOT && !error.message.includes(CAP))
    assert.equal(saved.values.size, 1)
    assert.equal(calls, 2)
})

test('blocked browser storage and oversized files are rejected before taking an upload ticket', async (t) => {
    let calls = 0
    t.mock.method(global, 'fetch', async () => { calls++; throw new Error('unexpected request') })
    const client = new CloudTransport(BASE, { setItem: () => { throw new Error('storage denied') } })
    await assert.rejects(client.upload(new File(['x'], 'x.txt')), /sessionStorage/)
    await assert.rejects(client.upload({ size: 20_000_001 }), /20,000,000/)
    assert.equal(calls, 0)
})

test('root signed password IDs authorize child polling and child password POST with the root capability', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    const calls = []
    t.mock.method(global, 'fetch', async (url, options) => {
        calls.push(url)
        assert.equal(options.headers.Authorization, `Bearer ${CAP}`)
        assert.equal(url.includes(CAP), false)
        if (options.method === 'POST') {
            assert.equal(url, `${BASE}/api/v1/jobs/${CHILD}/password`)
            assert.deepEqual(JSON.parse(options.body), { password: 'inner password' })
            return json({ job_id: CHILD, status: 'queued', password_attempts: 2, password_attempts_remaining: 1 })
        }
        if (url.includes('/reports/')) return json(report())
        assert.equal(url, `${BASE}/api/v1/jobs/${ROOT}`)
        return json(status())
    })
    await client.getJobStatus(ROOT)
    const child = await client.getJobStatus(CHILD)
    assert.equal(child.status, 'password_required')
    assert.equal(child.parent_job_id, ROOT)
    assert.equal(child.password_attempts_remaining, 2)
    assert.equal((await client.submitPassword(CHILD, 'inner password')).password_attempts_remaining, 1)
    assert.equal(calls.length, 4)
})

test('encrypted PDF password retries use the existing target route and original root ownership', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    let attempts = 1
    let active = false
    let submitted
    const calls = []
    const encrypted = report({
        child_jobs: [{ job_id: CHILD, filename: 'locked.pdf', status: 'password_required' }],
        artifacts: [{ artifact_id: CHILD, status: 'password_required', reason: 'wrong_password', report: {
            job_id: CHILD, file: { original_filename: 'locked.pdf', mime: 'application/pdf' },
            results: { format_analysis: { analyzer: 'pdf', features: { encrypted: true, content_access: 'wrong_password' } } },
        } }],
    })
    t.mock.method(global, 'fetch', async (url, options) => {
        calls.push(url)
        assert.equal(options.headers.Authorization, `Bearer ${CAP}`)
        assert.equal(options.redirect, 'error')
        assert.equal(url.includes(CAP), false)
        if (options.method === 'POST') {
            assert.equal(url, `${BASE}/api/v1/jobs/${CHILD}/password`)
            assert.equal(options.headers['Content-Type'], 'application/json')
            submitted = JSON.parse(options.body)
            assert.deepEqual(submitted, { password: 'PDF user password' })
            attempts++
            active = true
            return json({ job_id: CHILD, status: 'queued', password_attempts: attempts, password_attempts_remaining: 3 - attempts })
        }
        if (url.includes('/reports/')) {
            assert.equal(url, `${BASE}/api/v1/reports/${ROOT}`)
            return json(encrypted)
        }
        assert.equal(url, `${BASE}/api/v1/jobs/${ROOT}`)
        return json(status({ status: active ? 'queued' : 'password_required', password_attempts: attempts, password_attempts_remaining: 3 - attempts }))
    })
    await client.getReport(ROOT)
    const child = await client.getReport(CHILD)
    assert.equal(child.file.original_filename, 'locked.pdf')
    assert.equal(child.job_status, 'password_required')
    assert.equal(child.parent_job_id, ROOT)
    assert.equal(child.results.format_analysis.features.content_access, 'wrong_password')
    assert.equal((await client.getJobStatus(CHILD)).password_attempts_remaining, 2)
    assert.equal((await client.submitPassword(CHILD, 'PDF user password')).password_attempts_remaining, 1)
    const queued = await client.getReport(CHILD)
    assert.equal(queued.job_status, 'queued')
    assert.deepEqual(queued.password_required_artifacts, [])
    assert.equal(queued.results.format_analysis.features.content_access, 'wrong_password')
    assert.equal(calls.filter((url) => url.endsWith('/password')).length, 1)
})

test('status-page polling exposes wrong PDF password and refreshes only when a new submission completes', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    let submitted = 0
    let active = false
    let reportReads = 0
    t.mock.method(global, 'fetch', async (url, options) => {
        if (options.method === 'POST') {
            submitted++
            active = true
            return json({ job_id: ROOT, status: 'queued', password_attempts: submitted, password_attempts_remaining: 3 - submitted })
        }
        if (url.includes('/reports/')) {
            reportReads++
            return json(report({
                file: { original_filename: 'locked.pdf' }, password_required_artifacts: [ROOT],
                artifact_tree: { id: ROOT, job_id: ROOT, filename: 'locked.pdf', job_status: 'password_required', children: [] },
                artifacts: [{ artifact_id: ROOT, status: 'password_required', reason: submitted ? 'wrong_password' : 'password_required' }],
            }))
        }
        return json(status({ status: active ? 'queued' : 'password_required', error_message: null,
            password_required_artifacts: [ROOT], password_attempts: submitted, password_attempts_remaining: 3 - submitted,
            password_attempts_scope: 'artifact', total_password_submissions: submitted }))
    })
    const initial = await client.getJobStatus(ROOT)
    assert.equal(initial.error_message, null)
    assert.equal(initial.password_target.filename, 'locked.pdf')
    await client.getJobStatus(ROOT)
    assert.equal(reportReads, 1)
    await client.submitPassword(ROOT, 'incorrect-public-fixture-credential')
    assert.equal((await client.getJobStatus(ROOT)).error_message, null)
    active = false
    const rejected = await client.getJobStatus(ROOT)
    assert.equal(rejected.error_message, 'wrong_password')
    assert.equal(rejected.password_attempts_remaining, 2)
    assert.equal(reportReads, 2)
})

test('nested file status uses its own three submissions rather than the already-unlocked ZIP count', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    let count = 0
    t.mock.method(global, 'fetch', async (url) => {
        if (url.includes('/reports/')) return json(report({ artifacts: [{ artifact_id: CHILD, status: 'password_required', reason: count ? 'wrong_password' : 'password_required' }] }))
        return json(status({ password_attempts: 1, password_attempts_remaining: 2, error_message: null,
            password_attempts_scope: 'artifact', total_password_submissions: 1 + count,
            password_attempts_by_artifact: {
                [ROOT]: { attempts_used: 1, attempts_remaining: 2, limit: 3 },
                [CHILD]: { attempts_used: count, attempts_remaining: 3 - count, limit: 3 },
            } }))
    })
    await client.getJobStatus(ROOT)
    const initial = await client.getJobStatus(CHILD)
    assert.equal(initial.password_attempts, 0)
    assert.equal(initial.password_attempts_remaining, 3)
    count = 1
    const rejected = await client.getJobStatus(CHILD)
    assert.equal(rejected.password_attempts, 1)
    assert.equal(rejected.password_attempts_remaining, 2)
    assert.equal(rejected.error_message, 'wrong_password')
    assert.equal(rejected.password_target.path, undefined)
    assert.equal(rejected.password_target.filename, 'inner.zip')
})

test('temporary report failure preserves a password wait without inventing a wrong-password result', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    t.mock.method(global, 'fetch', async (url) => url.includes('/reports/') ? json({ error: 'unavailable' }, 503)
        : json(status({ error_message: null })))
    const job = await client.getJobStatus(ROOT)
    assert.equal(job.status, 'password_required')
    assert.match(job.error_message, /重新查詢/)
    assert.notEqual(job.error_message, 'wrong_password')
})

test('downloadable reports retain per-file audit counts and child projections include only their subtree', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    const counts = {
        [ROOT]: { attempts_used: 1, attempts_remaining: 2, limit: 3 },
        [CHILD]: { attempts_used: 2, attempts_remaining: 1, limit: 3 },
        [OTHER]: { attempts_used: 0, attempts_remaining: 3, limit: 3 },
    }
    t.mock.method(global, 'fetch', async (url) => url.includes('/reports/') ? json(report())
        : json(status({ password_attempts_by_artifact: counts, password_attempts_scope: 'artifact',
            total_password_submissions: 3, legacy_password_submissions: 0 })))
    const root = await client.getReport(ROOT)
    assert.deepEqual(root.password_attempts_by_artifact, counts)
    assert.equal(root.password_attempts_scope, 'artifact')
    assert.equal(root.total_password_submissions, 3)
    const child = await client.getReport(CHILD)
    assert.deepEqual(child.password_attempts_by_artifact, { [CHILD]: counts[CHILD] })
    assert.equal(child.password_attempts_scope, 'artifact')
})

test('a child reload fetches the root snapshot rather than a nonexistent child GET route', async (t) => {
    const saved = ownedStorage()
    saved.setItem(`malscan:cloud:${BASE}:${OTHER}`, saved.getItem(`malscan:cloud:${BASE}:${ROOT}`))
    const client = new CloudTransport(BASE, saved)
    t.mock.method(global, 'fetch', async (url) => {
        if (url === `${BASE}/api/v1/reports/${ROOT}`) return json(report())
        assert.equal(url, `${BASE}/api/v1/jobs/${ROOT}`)
        return json(status())
    })
    assert.equal((await client.getJobStatus(OTHER)).status, 'done')
    const childReport = await client.getReport(OTHER)
    assert.equal(childReport.job_id, OTHER)
    assert.equal(childReport.report_complete, true)
    assert.equal(childReport.parent_job_id, ROOT)
})

test('queued password resumption clears stale snapshot password targets and keeps partial results readable', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    t.mock.method(global, 'fetch', async (url) => url.includes('/reports/')
        ? json(report()) : json(status({ status: 'queued', password_required_artifacts: [CHILD] })))
    const snapshot = await client.getReport(ROOT)
    assert.equal(snapshot.job_status, 'queued')
    assert.equal(snapshot.report_complete, false)
    assert.equal(snapshot.execution_active, true)
    assert.deepEqual(snapshot.password_required_artifacts, [])
    assert.equal(snapshot.artifacts.length, 2)
})

test('child polling refreshes an earlier queued snapshot after the root finishes', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    let completed = false
    t.mock.method(global, 'fetch', async (url) => {
        if (url.includes('/reports/')) return json(report({
            artifacts: [{ artifact_id: CHILD, status: completed ? 'done' : 'queued', report: { job_id: CHILD } }],
            report_complete: completed,
        }))
        return json(status({ status: completed ? 'done' : 'scanning', password_required_artifacts: [] }))
    })
    await client.getReport(ROOT)
    completed = true
    assert.equal((await client.getJobStatus(CHILD)).status, 'done')
})

test('a missing child report is not replaced by the root report', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    t.mock.method(global, 'fetch', async (url) => url.includes('/reports/')
        ? json(report({ artifacts: [] })) : json(status()))
    await client.getReport(ROOT)
    await assert.rejects(client.getReport(CHILD), (error) => error.status === 409)
})

test('unknown ownership never sends a request, and invalid passwords never send their content', async (t) => {
    const client = new CloudTransport(BASE, ownedStorage())
    let calls = 0
    t.mock.method(global, 'fetch', async () => { calls++; throw new Error('unexpected request') })
    await assert.rejects(client.getJobStatus(CHILD), /原上傳分頁/)
    await assert.rejects(client.submitPassword(ROOT, 'x'.repeat(257)), /256/)
    assert.equal(calls, 0)
})
