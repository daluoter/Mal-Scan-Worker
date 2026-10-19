import assert from 'node:assert/strict';
import {createHash, createHmac, randomBytes, randomUUID} from 'node:crypto';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {request as httpRequest} from 'node:http';
import {Miniflare} from 'miniflare';

const hash = data => createHash('sha256').update(data).digest('hex');
const key = randomBytes(32).toString('hex');
const signed = payload => {
  const text = JSON.stringify(payload);
  return {payload: text, hmac_sha256: createHmac('sha256', Buffer.from(key, 'hex')).update(text).digest('hex')};
};
const signedDispatch = (payload, domain = 'malscan:v2:dispatch-claim\n') => ({
  payload: typeof payload === 'string' ? payload : JSON.stringify(payload),
  hmac_sha256: createHmac('sha256', Buffer.from(key, 'hex')).update(domain)
    .update(typeof payload === 'string' ? payload : JSON.stringify(payload)).digest('hex'),
});
async function runtime(extra = {}) {
  const calls = [];
  const dispatches = [];
  let rejectDispatch = false;
  let dispatchGate;
  let claimGate;
  const options = {
    name: 'control-test', modules: true, unsafeInspectDurableObjects: true,
    scriptPath: fileURLToPath(new URL('../src/worker.mjs', import.meta.url)),
    compatibilityDate: '2026-07-30', r2Buckets: ['UPLOADS', 'RESULTS'], r2Persist: false,
    durableObjects: {CONTROL: {className: 'DemoControl', useSQLite: true}}, durableObjectsPersist: false,
    bindings: {PUBLIC_UPLOADS: 'true', ALLOWED_ORIGIN: 'https://demo.test', CONTROL_HMAC_KEY: key,
      GCP_PROJECT: 'local-test', GCP_REGION: 'us-central1', GCP_JOB: 'static-demo', DAILY_JOB_LIMIT: '100', DAILY_EXECUTION_LIMIT: '100',
      GCP_DISPATCH_URL: 'https://dispatcher.test', ...extra},
    // This local stub has no Google credentials and never calls a network API.
    outboundService: async request => {
      const url = new URL(request.url);
      assert.equal(url.href, 'https://dispatcher.test/dispatch');
      assert.equal(request.method, 'POST');
      const envelope = await request.json();
      assert.deepEqual(Object.keys(envelope).sort(), ['hmac_sha256', 'payload']);
      assert.equal(envelope.hmac_sha256, signedDispatch(envelope.payload, 'malscan:v2:dispatch\n').hmac_sha256);
      const body = JSON.parse(envelope.payload);
      assert.deepEqual(Object.keys(body).sort(), ['attempt_id', 'control_key', 'dispatch_id', 'dispatch_version',
        'expires_at', 'issued_at', 'job_id', 'job_name', 'manifest_key', 'report_key', 'sequence', 'status_key']);
      assert.equal(body.dispatch_version, 1);
      assert.equal(body.job_name, 'projects/local-test/locations/us-central1/jobs/static-demo');
      assert.ok(body.issued_at <= Date.now());
      assert.ok(body.expires_at > body.issued_at && body.expires_at - body.issued_at <= 120000);
      assert.match(body.job_id, /^[a-f0-9-]{36}$/);
      assert.match(body.attempt_id, /^[a-f0-9-]{36}$/);
      assert.match(body.dispatch_id, /^[a-f0-9-]{36}$/);
      assert.equal(body.manifest_key, `manifests/${body.job_id}/${body.attempt_id}.json`);
      assert.equal(body.control_key, `controls/${body.job_id}/${body.dispatch_id}.json`);
      assert.equal(body.status_key, `statuses/${body.job_id}/${body.dispatch_id}.json`);
      assert.equal(body.report_key, `reports/${body.job_id}/${body.attempt_id}.json`);
      assert.ok(Number.isSafeInteger(body.sequence) && body.sequence > 0);
      dispatches.push(envelope);
      if (claimGate) {
        const gate = claimGate; gate.markStarted(); await gate.resume; claimGate = null;
        if (gate.skipClaim) return Response.json({error: 'local-test-claim-interrupted'}, {status: 503});
      }
      const claim = await mf.dispatchFetch('https://control.test/internal/dispatch/claim', {method: 'POST',
        headers: {'content-type': 'application/json'}, body: JSON.stringify(signedDispatch(envelope.payload))});
      assert.equal(claim.status, 200, await claim.clone().text());
      const claimed = await claim.json();
      assert.equal(claimed.claimed, true);
      assert.equal(claimed.dispatch_id, body.dispatch_id);
      assert.equal(claimed.request_sha256, hash(envelope.payload));
      const names = {MALSCAN_MANIFEST_KEY: body.manifest_key, MALSCAN_CONTROL_KEY: body.control_key,
        MALSCAN_STATUS_KEY: body.status_key, MALSCAN_REPORT_KEY: body.report_key,
        MALSCAN_ROOT_JOB_ID: body.job_id, MALSCAN_ATTEMPT_ID: body.attempt_id,
        MALSCAN_DISPATCH_ID: body.dispatch_id, MALSCAN_SEQUENCE: String(body.sequence)};
      calls.push({overrides: {taskCount: 1, containerOverrides: [{env: Object.entries(names).map(([name, value]) => ({name, value}))}]}});
      if (dispatchGate) {const gate = dispatchGate; gate.markStarted(); await gate.resume; dispatchGate = null;}
      if (rejectDispatch) return Response.json({error: 'local-test-rejected'}, {status: 503});
      return Response.json({name: `projects/local-test/locations/us-central1/operations/test-${calls.length}`});
    },
  };
  const mf = new Miniflare(options);
  let localUrl;
  try {localUrl = await mf.ready;} catch (exception) {await mf.dispose(); throw exception;}
  let uploadStore = await mf.getR2Bucket('UPLOADS');
  let resultStore = await mf.getR2Bucket('RESULTS');
  let sql;
  try {sql = await mf.unsafeGetDurableObjectStorage('control-test', 'DemoControl', {name: 'demo-control'});}
  catch (exception) {await mf.dispose(); throw exception;}
  const fetch = (path, init = {}) => mf.dispatchFetch('https://control.test' + path, init);
  const ticket = async (body, filename = 'fixture.bin') => {
    const response = await fetch('/api/v1/upload-tickets', {method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({bytes: body.length, filename, sha256: hash(body)})});
    assert.equal(response.status, 201, await response.clone().text());
    return response.json();
  };
  const upload = (ticket, body) => fetch('/api/v1/files', {method: 'POST',
    headers: {'content-type': 'application/octet-stream', 'content-length': String(body.length), authorization: 'Bearer ' + ticket.token}, body});
  // An eager 20 MB Undici replay can race the early rejection and get a
  // connection reset. Header-first replay also proves no body is required.
  const headerOnlyUpload = (ticket, size) => new Promise((resolve, reject) => {
    const request = httpRequest(new URL('/api/v1/files', localUrl), {method: 'POST',
      headers: {'content-type': 'application/octet-stream', 'content-length': String(size), authorization: 'Bearer ' + ticket.token}}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {resolve({status: response.statusCode, body: Buffer.concat(chunks).toString()}); request.destroy();});
      response.on('error', reject);
    });
    request.on('error', reject);
    request.setTimeout(10000, () => request.destroy(new Error('Header-first replay timed out')));
    request.flushHeaders();
  });
  const owned = (ticket, path, init = {}) => fetch(path, {...init, headers: {authorization: 'Bearer ' + ticket.capability_token, ...init.headers}});
  const row = async id => (await sql.exec('SELECT * FROM jobs WHERE id = ?', id))[0];
  const publish = async (ticket, status, artifactIds = [], revision = 1) => {
    const job = await row(ticket.job_id);
    const report = {report_schema_version: 'mswr-report-v3', job_id: job.id, analysis_attempt_id: job.attempt_id,
      job_status: status, analysis: {static: {status: status === 'done' ? 'complete' : 'partial'}, dynamic: {status: 'disabled'}}};
    const body = JSON.stringify(report);
    const reportKey = `reports/${job.id}/${job.attempt_id}/${job.dispatch_id}/${revision}.json`;
    await resultStore.put(reportKey, body);
    const payload = {status_version: 1, job_id: job.id, attempt_id: job.attempt_id, dispatch_id: job.dispatch_id,
      sequence: job.dispatch_sequence, manifest_sha256: job.manifest_sha256, status, report_key: reportKey,
      report_sha256: hash(body), password_required_artifacts: artifactIds, error_code: null};
    await resultStore.put(job.status_key, JSON.stringify(signed(payload)));
    return {job, report, payload, reportKey};
  };
  return {mf, get sql() {return sql;}, fetch, get uploadStore() {return uploadStore;}, get resultStore() {return resultStore;}, calls, dispatches, ticket, upload, headerOnlyUpload, owned, row, publish,
    async restart() {
      await mf.setOptions({...options, bindings: {...options.bindings, TEST_RELOAD_ID: randomUUID()}});
      localUrl = await mf.ready;
      uploadStore = await mf.getR2Bucket('UPLOADS');
      resultStore = await mf.getR2Bucket('RESULTS');
      sql = await mf.unsafeGetDurableObjectStorage('control-test', 'DemoControl', {name: 'demo-control'});
    },
    claim(envelope) {return fetch('/internal/dispatch/claim', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(envelope)});},
    pauseClaim() {
      let markStarted, release;
      const started = new Promise(resolve => {markStarted = resolve;});
      const resume = new Promise(resolve => {release = resolve;});
      const gate = {markStarted, resume, skipClaim: false};
      claimGate = gate;
      return {started, release, cancel() {gate.skipClaim = true; release();}};
    },
    setReject(value) {rejectDispatch = value;},
    pauseDispatch() {
      let markStarted, release;
      const started = new Promise(resolve => {markStarted = resolve;});
      const resume = new Promise(resolve => {release = resolve;});
      dispatchGate = {markStarted, resume};
      return {started, release};
    },
  };
}

test('real workerd, SQLite and R2 demo control contract', {timeout: 180000}, async suite => {
  const r = await runtime();
  try {
    await suite.test('capabilities, strict CORS, invalid metadata', async () => {
      assert.equal((await r.fetch('/health')).status, 200);
      const capabilities = await (await r.fetch('/api/v1/capabilities')).json();
      assert.equal(capabilities.upload_transport, 'raw-ticket'); assert.equal(capabilities.dynamic_analysis.status, 'disabled');
      assert.equal((await r.fetch('/health', {headers: {origin: 'https://evil.test'}})).status, 403);
      const allowed = await r.fetch('/health', {headers: {origin: 'https://demo.test'}});
      assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://demo.test');
      for (const metadata of [{bytes: 20000001, filename: 'x', sha256: hash('x')}, {bytes: 1, filename: '../x', sha256: hash('x')},
        {bytes: 1, filename: 'x', sha256: 'bad'}, {bytes: 1, filename: 'x', sha256: hash('x'), extra: true}]) {
        assert.equal((await r.fetch('/api/v1/upload-tickets', {method: 'POST', body: JSON.stringify(metadata)})).status, 400);
      }
      assert.equal((await r.fetch('/api/v1/upload-tickets', {method: 'POST', body: JSON.stringify({bytes: 1, filename: '\ud800.bin', sha256: hash('x')})})).status, 400);
    });
    await suite.test('20 MB stream uses native R2 SHA256 checksum, dispatches exactly once', async () => {
      const body = Buffer.alloc(20_000_000, 0x41);
      const ticket = await r.ticket(body, '檔案.bin');
      const response = await r.upload(ticket, body);
      assert.equal(response.status, 201, await response.clone().text());
      const uploaded = await response.json(); assert.equal(uploaded.status, 'queued'); assert.equal(uploaded.sha256, hash(body));
      assert.equal(r.calls.length, 1);
      assert.equal((await r.uploadStore.get(`uploads/${ticket.job_id}/source`)).size, body.length);
      const job = await r.row(ticket.job_id);
      const manifest = await (await r.uploadStore.get(job.manifest_key)).json();
      assert.equal(manifest.source.filename, '檔案.bin');
      const canonical = '{"attempt_id":' + JSON.stringify(job.attempt_id) + ',"manifest_version":1,"report_key":' + JSON.stringify(job.report_key)
        + ',"root_job_id":' + JSON.stringify(job.id) + ',"source":{"filename":"\\u6a94\\u6848.bin","key":' + JSON.stringify(`uploads/${job.id}/source`)
        + ',"sha256":' + JSON.stringify(hash(body)) + ',"size":20000000}}';
      assert.equal(job.manifest_sha256, hash(canonical));
      const env = Object.fromEntries(r.calls[0].overrides.containerOverrides[0].env.map(item => [item.name, item.value]));
      assert.equal(env.MALSCAN_SEQUENCE, '1'); assert.equal(env.MALSCAN_ROOT_JOB_ID, ticket.job_id);
      assert.ok(!JSON.stringify(r.calls).includes(key)); assert.ok(!JSON.stringify(r.calls).includes(ticket.capability_token));
      assert.equal((await r.headerOnlyUpload(ticket, body.length)).status, 409); assert.equal(r.calls.length, 1);
      assert.equal((await r.fetch(`/api/v1/jobs/${ticket.job_id}`)).status, 401);
      assert.equal((await r.owned({...ticket, capability_token: randomBytes(32).toString('hex')}, `/api/v1/jobs/${ticket.job_id}`)).status, 404);
      assert.equal((await r.owned(ticket, `/api/v1/reports/${ticket.job_id}`)).status, 409);
      const published = await r.publish(ticket, 'done');
      const report = await r.owned(ticket, `/api/v1/reports/${ticket.job_id}`);
      assert.equal(report.status, 200);
      const received = await report.json();
      assert.deepEqual(received.analysis, published.report.analysis);
      assert.equal(received.job_status, 'done'); assert.equal(received.execution_active, false);
      assert.equal((await r.resultStore.get(`controls/${job.id}/${job.dispatch_id}.json`)), null);
      await r.resultStore.put(published.reportKey, JSON.stringify({...published.report, job_id: randomUUID()}));
      assert.equal((await r.owned(ticket, `/api/v1/reports/${ticket.job_id}`)).status, 502);
    });
    await suite.test('keyless claim authenticates the exact stored request and consumes it only once', async () => {
      const body = Buffer.from('claim-gate'), ticket = await r.ticket(body);
      const gate = r.pauseClaim();
      const uploaded = r.upload(ticket, body);
      try {
        await gate.started;
        const dispatch = r.dispatches.at(-1);
        const payload = JSON.parse(dispatch.payload);
        const before = await r.row(ticket.job_id);
        assert.equal(before.dispatch_request_sha256, hash(dispatch.payload));
        assert.equal(before.dispatch_claimed_at, null);
        const cases = [
          [{payload: dispatch.payload, hmac_sha256: '0'.repeat(64)}, 401],
          // The dispatch proof and runner status proof cannot authenticate a claim.
          [dispatch, 401],
          [signed(payload), 401],
          [signedDispatch('not-json'), 401],
          [signedDispatch({...payload, issued_at: Date.now() - 180000, expires_at: Date.now() - 60000}), 401],
          [signedDispatch({...payload, expires_at: payload.issued_at + 120001}), 401],
          // A valid claim signature cannot authorize a changed execution request.
          [signedDispatch({...payload, expires_at: payload.expires_at - 1}), 409],
          [signedDispatch({...payload, sequence: payload.sequence + 1}), 409],
        ];
        for (const [envelope, expected] of cases) {
          const response = await r.claim(envelope);
          assert.equal(response.status, expected, await response.clone().text());
          assert.equal((await r.row(ticket.job_id)).dispatch_claimed_at, null);
        }
      } finally {gate.release();}
      assert.equal((await uploaded).status, 201);
      const dispatch = r.dispatches.at(-1);
      assert.ok(Number.isSafeInteger((await r.row(ticket.job_id)).dispatch_claimed_at));
      const replay = await r.claim(signedDispatch(dispatch.payload));
      assert.equal(replay.status, 409);
      assert.equal((await replay.json()).error.code, 'dispatch_claim_conflict');
    });
    await suite.test('unclaimed requests cannot dispatch after completion or a newer sequence', async () => {
      const body = Buffer.from('claim-after-terminal'), ticket = await r.ticket(body);
      const gate = r.pauseClaim();
      const uploaded = r.upload(ticket, body);
      let dispatch;
      try {
        await gate.started;
        dispatch = r.dispatches.at(-1);
        await r.publish(ticket, 'password_required', [ticket.job_id]);
        assert.equal((await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json()).status, 'password_required');
        assert.equal((await r.row(ticket.job_id)).dispatch_claimed_at, null);
        assert.equal((await r.claim(signedDispatch(dispatch.payload))).status, 409);
      } finally {gate.cancel();}
      assert.equal((await uploaded).status, 201);
      const response = await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}/password`, {
        method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({password: 'local-only'}),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const next = await r.row(ticket.job_id);
      assert.equal(next.dispatch_sequence, 2);
      assert.notEqual(next.dispatch_request_sha256, hash(dispatch.payload));
      assert.equal((await r.claim(signedDispatch(dispatch.payload))).status, 409);
    });
    await suite.test('uncertain dispatch allows exactly one concurrent late claim without resubmission', async () => {
      const body = Buffer.from('late-claim'), ticket = await r.ticket(body);
      const gate = r.pauseClaim();
      const count = r.calls.length;
      const uploaded = r.upload(ticket, body);
      try {await gate.started;} finally {gate.cancel();}
      assert.equal((await uploaded).status, 201);
      const dispatch = r.dispatches.at(-1);
      const job = await r.row(ticket.job_id);
      assert.equal(job.status, 'dispatch_uncertain');
      assert.equal(job.dispatch_claimed_at, null);
      const claims = await Promise.all([r.claim(signedDispatch(dispatch.payload)), r.claim(signedDispatch(dispatch.payload))]);
      assert.deepEqual(claims.map(response => response.status).sort(), [200, 409]);
      assert.ok(Number.isSafeInteger((await r.row(ticket.job_id)).dispatch_claimed_at));
      assert.equal(r.calls.length, count);
    });
    await suite.test('unclaimed dispatch cannot outlive durable root retention', async () => {
      const body = Buffer.from('claim-root-expired'), ticket = await r.ticket(body);
      const gate = r.pauseClaim();
      const uploaded = r.upload(ticket, body);
      try {
        await gate.started;
        const dispatch = r.dispatches.at(-1);
        await r.sql.exec('UPDATE jobs SET expires_at = 1 WHERE id = ?', ticket.job_id);
        assert.equal((await r.claim(signedDispatch(dispatch.payload))).status, 410);
        assert.equal((await r.row(ticket.job_id)).dispatch_claimed_at, null);
      } finally {gate.cancel();}
      assert.equal((await uploaded).status, 201);
    });
    await suite.test('wrong file content fails platform checksum and consumed ticket cannot replay', async () => {
      const ticket = await r.ticket(Buffer.from('expected'));
      assert.equal((await r.upload(ticket, Buffer.from('wrong___'))).status, 400);
      assert.equal((await r.upload(ticket, Buffer.from('expected'))).status, 409);
      assert.equal(await r.uploadStore.get(`uploads/${ticket.job_id}/source`), null);
      assert.equal((await r.row(ticket.job_id)).status, 'failed');
    });
    await suite.test('expired authorization has no writes', async () => {
      const body = Buffer.from('x'), ticket = await r.ticket(body);
      await r.sql.exec('UPDATE jobs SET ticket_expires = 1 WHERE id = ?', ticket.job_id);
      assert.equal((await r.upload(ticket, body)).status, 403);
      assert.equal(await r.uploadStore.get(`uploads/${ticket.job_id}/source`), null);
      const status = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
      assert.equal(status.status, 'failed'); assert.equal(status.error_message, 'upload_ticket_expired');
    });
    await suite.test('signed password-required child resumes same attempt, consumes one dispatch lease', async () => {
      const body = Buffer.from('encrypted archive placeholder'), ticket = await r.ticket(body);
      assert.equal((await r.upload(ticket, body)).status, 201);
      const child = '00000000-0000-5000-8000-000000000001';
      const before = await r.publish(ticket, 'password_required', [child]);
      const required = await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      assert.equal(required.status, 200);
      assert.deepEqual((await required.json()).password_required_artifacts, [child]);
      const request = {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({password: 'hidden-local-password'})};
      const results = await Promise.all([r.owned(ticket, `/api/v1/jobs/${child}/password`, request), r.owned(ticket, `/api/v1/jobs/${child}/password`, request)]);
      assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
      const next = await r.row(ticket.job_id); assert.equal(next.attempt_id, before.job.attempt_id);
      assert.equal(next.manifest_sha256, before.job.manifest_sha256); assert.notEqual(next.dispatch_id, before.job.dispatch_id);
      assert.equal(next.password_attempts, 1); assert.equal(next.dispatch_sequence, 2);
      const envelope = await (await r.resultStore.get(`controls/${next.id}/${next.dispatch_id}.json`)).json();
      const control = JSON.parse(envelope.payload);
      assert.equal(control.resume, true); assert.equal(control.passwords[child], 'hidden-local-password');
      assert.equal(control.password_attempts_scope, 'artifact');
      assert.equal(control.password_attempt_limit, 3);
      assert.deepEqual(control.password_attempts_by_artifact, {[child]: 1});
      assert.equal(control.checkpoint_key, `checkpoints/${next.id}/${next.attempt_id}.json`);
      assert.equal(control.expires_at, next.expires_at);
      assert.ok(!JSON.stringify(r.calls).includes('hidden-local-password'));
      // An old completion cannot overwrite the latest dispatch state.
      await r.resultStore.put(next.status_key, JSON.stringify(signed(before.payload)));
      assert.equal((await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).status, 503);
      assert.equal((await r.row(ticket.job_id)).status, 'queued');
      for (const expected of [2, 3]) {
        await r.publish(ticket, 'password_required', [child]);
        await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
        const resumed = await r.owned(ticket, `/api/v1/jobs/${child}/password`, request);
        assert.equal(resumed.status, 200);
        assert.equal((await resumed.json()).password_attempts, expected);
      }
      await r.publish(ticket, 'password_required', [child]);
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      const count = r.calls.length;
      const exhausted = await r.owned(ticket, `/api/v1/jobs/${child}/password`, request);
      assert.equal(exhausted.status, 409);
      assert.equal((await exhausted.json()).error.code, 'password_attempt_limit');
      assert.equal(r.calls.length, count);
    });
    await suite.test('untrusted signatures are rejected, ambiguous dispatch does not retry', async () => {
      r.setReject(true);
      const body = Buffer.from('uncertain dispatch'), ticket = await r.ticket(body);
      const response = await r.upload(ticket, body);
      const uploaded = await response.json(); assert.equal(uploaded.dispatch_uncertain, true);
      const count = r.calls.length;
      assert.equal((await r.upload(ticket, body)).status, 409); assert.equal(r.calls.length, count);
      const published = await r.publish(ticket, 'done');
      const bad = signed(published.payload); bad.hmac_sha256 = '0'.repeat(64);
      await r.resultStore.put(published.job.status_key, JSON.stringify(bad));
      assert.equal((await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).status, 503);
      await r.resultStore.put(published.job.status_key, JSON.stringify(signed(published.payload)));
      assert.equal((await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json()).status, 'done');
      assert.equal(r.calls.length, count); r.setReject(false);
    });
    await suite.test('execution without signed status becomes a visible timeout and late completion can resolve it', async () => {
      const body = Buffer.from('never-started'), ticket = await r.ticket(body);
      await r.upload(ticket, body);
      await r.sql.exec('UPDATE jobs SET dispatch_deadline_at = 1 WHERE id = ?', ticket.job_id);
      const status = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
      assert.equal(status.status, 'failed'); assert.equal(status.dispatch_uncertain, true);
      assert.equal(status.error_message, 'analysis_status_timeout');
      const count = r.calls.length;
      await r.publish(ticket, 'done');
      assert.equal((await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json()).status, 'done');
      assert.equal(r.calls.length, count);
    });
    await suite.test('signed completion arriving before Google run response cannot regress to queued or uncertain', async () => {
      for (const reject of [false, true]) {
        r.setReject(reject);
        const body = Buffer.from('completed-before-api-response');
        const ticket = await r.ticket(body);
        const gate = r.pauseDispatch();
        const upload = r.upload(ticket, body);
        try {
          await gate.started;
          await r.publish(ticket, 'done');
          assert.equal((await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json()).status, 'done');
        } finally {gate.release();}
        assert.equal((await upload).status, 201);
        const job = await r.row(ticket.job_id);
        assert.equal(job.status, 'done'); assert.equal(job.error_code, null);
      }
      r.setReject(false);
    });
    await suite.test('older signed report revision cannot overwrite a newer partial or a terminal report', async () => {
      const body = Buffer.from('monotonic snapshots'), ticket = await r.ticket(body);
      await r.upload(ticket, body);
      const current = await r.publish(ticket, 'scanning', [], 2);
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      const old = await r.publish(ticket, 'scanning', [], 1);
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      assert.equal((await r.row(ticket.job_id)).accepted_report_key, current.reportKey);
      await r.publish(ticket, 'done', [], 3);
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      await r.resultStore.put(old.job.status_key, JSON.stringify(signed(old.payload)));
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      const final = await r.row(ticket.job_id);
      assert.equal(final.status, 'done'); assert.equal(final.accepted_revision, 3);
    });
    await suite.test('stale ownership cannot reserve a dispatch after root retention expires', async () => {
      const ticket = await r.ticket(Buffer.from('expire-before-reservation'));
      const stale = await r.row(ticket.job_id);
      await r.sql.exec("UPDATE jobs SET expires_at = 1, status = 'uploading' WHERE id = ?", ticket.job_id);
      const namespace = await r.mf.getDurableObjectNamespace('CONTROL');
      const stub = namespace.get(namespace.idFromName('demo-control'));
      const count = r.calls.length;
      const rejected = await stub.fetch('https://internal.invalid/control', {method: 'POST', body: JSON.stringify({action: 'uploaded', id: ticket.job_id})});
      assert.equal(rejected.status, 410);
      assert.equal((await rejected.json()).error.code, 'job_retention_expired');
      assert.equal(r.calls.length, count);
      assert.equal((await r.resultStore.list({prefix: `controls/${ticket.job_id}/`})).objects.length, 0);
      assert.equal(stale.cleanup_after - stale.expires_at, 1200000);
    });
    await suite.test('failed execution keeps verified partial evidence and overlays only current control metadata', async () => {
      const body = Buffer.from('partial-before-failure'), ticket = await r.ticket(body);
      await r.upload(ticket, body);
      const partial = await r.publish(ticket, 'scanning', [], 2);
      await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
      const failed = {...partial.payload, status: 'failed', report_key: null, report_sha256: null, error_code: 'must-not-expose-details'};
      await r.resultStore.put(partial.job.status_key, JSON.stringify(signed(failed)));
      const response = await r.owned(ticket, `/api/v1/reports/${ticket.job_id}`);
      assert.equal(response.status, 200);
      const report = await response.json();
      assert.equal(report.job_status, 'failed'); assert.equal(report.control_error_code, 'analysis_failed');
      assert.equal(report.execution_active, false); assert.equal(report.pending_descendants, 0);
      assert.equal(report.report_complete, false); assert.deepEqual(report.analysis, partial.report.analysis);
      assert.equal((await r.row(ticket.job_id)).accepted_report_key, partial.reportKey);
    });
    await suite.test('expired ownership is inaccessible, alarm removes only root-owned prefixes', async () => {
      const body = Buffer.from('expires'), ticket = await r.ticket(body);
      await r.upload(ticket, body);
      const job = await r.row(ticket.job_id);
      await r.resultStore.put(`checkpoints/${job.id}/${job.attempt_id}.json`, '{}');
      await r.resultStore.put(`artifacts/${job.id}/child`, 'child');
      await r.resultStore.put('unrelated/keep', 'retained');
      const otherRoot = randomUUID();
      await r.uploadStore.put(`uploads/${otherRoot}/source`, 'other-source');
      await r.resultStore.put(`artifacts/${otherRoot}/sha256/other`, 'other-artifact');
      await r.publish(ticket, 'done');
      await r.sql.exec('UPDATE jobs SET expires_at = 1, cleanup_after = 1 WHERE id = ?', ticket.job_id);
      assert.equal((await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).status, 404);
      const namespace = await r.mf.getDurableObjectNamespace('CONTROL');
      const stub = namespace.get(namespace.idFromName('demo-control'));
      await stub.schedule();
      const deadline = Date.now() + 5000;
      while (await r.row(ticket.job_id)) {
        assert.ok(Date.now() < deadline, 'real workerd alarm should clean the expired root');
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      assert.equal(await r.row(ticket.job_id), undefined);
      assert.equal(await r.uploadStore.get(`uploads/${job.id}/source`), null);
      assert.equal(await r.uploadStore.get(job.manifest_key), null);
      assert.equal((await r.resultStore.list({prefix: `reports/${job.id}/`})).objects.length, 0);
      assert.equal(await r.resultStore.get(`artifacts/${job.id}/child`), null);
      assert.equal((await r.resultStore.get('unrelated/keep')).size, 8);
      assert.equal((await r.uploadStore.get(`uploads/${otherRoot}/source`)).size, 12);
      assert.equal((await r.resultStore.get(`artifacts/${otherRoot}/sha256/other`)).size, 14);
    });
  } finally {await r.mf.dispose();}
});

test('public demo intake must be explicitly enabled; global daily quota is durable', async () => {
  const disabled = await runtime({PUBLIC_UPLOADS: 'false'});
  try {assert.equal((await disabled.fetch('/api/v1/upload-tickets', {method: 'POST', body: '{}'})).status, 503);} finally {await disabled.mf.dispose();}
  const limited = await runtime({DAILY_JOB_LIMIT: '1'});
  try {
    await limited.ticket(Buffer.from('x'));
    const response = await limited.fetch('/api/v1/upload-tickets', {method: 'POST', body: JSON.stringify({bytes: 1, filename: 'x', sha256: hash('x')})});
    assert.equal(response.status, 429);
  } finally {await limited.mf.dispose();}
});

test('password submissions are counted durably for each file while execution admission stays global', {timeout: 120000}, async () => {
  const r = await runtime({MONTHLY_EXECUTION_LIMIT: '100'});
  try {
    const body = Buffer.from('nested ZIP and PDF placeholders');
    const ticket = await r.ticket(body, 'protected.zip');
    await r.upload(ticket, body);
    const pdf = '00000000-0000-5000-8000-000000000011';
    const sibling = '00000000-0000-5000-8000-000000000012';
    const wait = async targets => {
      await r.publish(ticket, 'password_required', targets);
      return (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
    };
    const submit = id => r.owned(ticket, `/api/v1/jobs/${id}/password`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({password: 'test-only'}),
    });

    // A wrong ZIP submission followed by the valid ZIP submission consumes two
    // ZIP attempts. Discovering its encrypted PDF starts that file at zero.
    await wait([ticket.job_id]);
    assert.equal((await (await submit(ticket.job_id)).json()).password_attempts, 1);
    await wait([ticket.job_id]);
    assert.equal((await (await submit(ticket.job_id)).json()).password_attempts, 2);
    const discovered = await wait([pdf, sibling]);
    assert.equal(discovered.password_attempts, 2);
    assert.equal(discovered.password_attempts_scope, 'artifact');
    assert.equal(discovered.password_attempt_limit, 3);
    assert.equal(discovered.total_password_submissions, 2);
    assert.deepEqual(discovered.password_attempts_by_artifact[pdf], {attempts_used: 0, attempts_remaining: 3, limit: 3});
    assert.deepEqual(discovered.password_attempts_by_artifact[sibling], {attempts_used: 0, attempts_remaining: 3, limit: 3});

    const callsBeforeInvalid = r.calls.length;
    const stateBeforeInvalid = await r.row(ticket.job_id);
    // The root is owned, but it is no longer a canonical pending target.
    assert.equal((await submit(ticket.job_id)).status, 409);
    assert.equal((await submit('00000000-0000-5000-8000-000000000099')).status, 404);
    assert.equal(r.calls.length, callsBeforeInvalid);
    assert.equal((await r.row(ticket.job_id)).password_attempts, stateBeforeInvalid.password_attempts);
    assert.deepEqual(await r.sql.exec('SELECT * FROM quota'), [{day: new Date().toISOString().slice(0, 10), jobs: 1, executions: 3}]);

    for (const expected of [1, 2, 3]) {
      const response = await submit(pdf);
      assert.equal(response.status, 200, await response.clone().text());
      const result = await response.json();
      assert.equal(result.password_attempts, expected);
      assert.equal(result.password_attempts_remaining, 3 - expected);
      assert.equal(result.password_attempts_by_artifact[ticket.job_id].attempts_used, 2);
      const job = await r.row(ticket.job_id);
      const envelope = await (await r.resultStore.get(`controls/${job.id}/${job.dispatch_id}.json`)).json();
      const control = JSON.parse(envelope.payload);
      assert.equal(control.password_attempts_by_artifact[pdf], expected);
      assert.equal(control.password_attempts_by_artifact[ticket.job_id], 2);
      await wait([pdf, sibling]);
    }
    const countAtExhaustion = r.calls.length;
    const exhausted = await submit(pdf);
    assert.equal(exhausted.status, 409);
    assert.equal((await exhausted.json()).error.code, 'password_attempt_limit');
    assert.equal(r.calls.length, countAtExhaustion);
    // An exhausted PDF neither consumes its sibling's attempts nor blocks its
    // dispatch. Runtime later decides which failed targets become terminal.
    const other = await submit(sibling);
    assert.equal(other.status, 200);
    assert.equal((await other.json()).password_attempts, 1);
    await wait([pdf]);
    const quotaBeforeRestart = await r.sql.exec('SELECT * FROM quota');
    const monthlyBeforeRestart = await r.sql.exec('SELECT * FROM monthly_quota');
    await r.restart();
    const afterRestart = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
    assert.equal(afterRestart.total_password_submissions, 6);
    assert.equal(afterRestart.legacy_password_submissions, 0);
    assert.deepEqual(afterRestart.password_attempts_by_artifact[pdf], {attempts_used: 3, attempts_remaining: 0, limit: 3});
    assert.equal(afterRestart.password_attempts_by_artifact[sibling].attempts_used, 1);
    assert.deepEqual(await r.sql.exec('SELECT * FROM quota'), quotaBeforeRestart);
    assert.deepEqual(await r.sql.exec('SELECT * FROM monthly_quota'), monthlyBeforeRestart);
    assert.equal((await submit(pdf)).status, 409);
  } finally {await r.mf.dispose();}
});

test('global execution rejection does not consume a fresh nested file password submission', async () => {
  const r = await runtime({DAILY_EXECUTION_LIMIT: '2'});
  try {
    const body = Buffer.from('nested-quota'), ticket = await r.ticket(body);
    await r.upload(ticket, body);
    await r.publish(ticket, 'password_required', [ticket.job_id]);
    await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
    const submit = id => r.owned(ticket, `/api/v1/jobs/${id}/password`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({password: 'test-only'}),
    });
    assert.equal((await submit(ticket.job_id)).status, 200);
    const pdf = '00000000-0000-5000-8000-000000000021';
    await r.publish(ticket, 'password_required', [pdf]);
    await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
    const rejected = await submit(pdf);
    assert.equal(rejected.status, 429);
    assert.equal((await rejected.json()).error.code, 'daily_demo_limit_reached');
    const status = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
    assert.equal(status.status, 'password_required');
    assert.equal(status.total_password_submissions, 1);
    assert.deepEqual(status.password_attempts_by_artifact[pdf], {attempts_used: 0, attempts_remaining: 3, limit: 3});
    assert.equal(r.calls.length, 2);
  } finally {await r.mf.dispose();}
});

test('old root-wide counters migrate once without fabricated per-file history or quota resets', {timeout: 120000}, async () => {
  const r = await runtime();
  try {
    const body = Buffer.from('legacy-counter'), ticket = await r.ticket(body);
    await r.upload(ticket, body);
    const pdf = '00000000-0000-5000-8000-000000000031';
    await r.publish(ticket, 'password_required', [pdf]);
    await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`);
    // Recreate the deployed pre-migration SQLite shape in the real runtime.
    await r.sql.exec('ALTER TABLE jobs DROP COLUMN password_attempts_by_artifact');
    await r.sql.exec('ALTER TABLE jobs DROP COLUMN legacy_password_submissions');
    await r.sql.exec('UPDATE jobs SET password_attempts = 3 WHERE id = ?', ticket.job_id);
    await r.sql.exec('UPDATE quota SET executions = 5');
    await r.sql.exec('UPDATE monthly_quota SET executions = 9');
    await r.restart();
    const status = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
    assert.equal(status.total_password_submissions, 3);
    assert.equal(status.legacy_password_submissions, 3);
    assert.equal(status.password_attempts, 0);
    assert.deepEqual(status.password_attempts_by_artifact[pdf], {attempts_used: 0, attempts_remaining: 3, limit: 3});
    assert.equal((await r.sql.exec('SELECT executions FROM quota'))[0].executions, 5);
    assert.equal((await r.sql.exec('SELECT executions FROM monthly_quota'))[0].executions, 9);
    const resumed = await r.owned(ticket, `/api/v1/jobs/${pdf}/password`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({password: 'test-only'}),
    });
    assert.equal(resumed.status, 200);
    assert.equal((await resumed.json()).password_attempts, 1);
    await r.restart();
    const current = await (await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).json();
    assert.equal(current.total_password_submissions, 4);
    assert.equal(current.legacy_password_submissions, 3);
    assert.equal(current.password_attempts_by_artifact[pdf].attempts_used, 1);
    assert.equal((await r.sql.exec('SELECT executions FROM quota'))[0].executions, 6);
    assert.equal((await r.sql.exec('SELECT executions FROM monthly_quota'))[0].executions, 10);
  } finally {await r.mf.dispose();}
});

test('monthly execution cap blocks dispatch and cannot be bypassed by a second ticket', async () => {
  const r = await runtime({MONTHLY_EXECUTION_LIMIT: '1'});
  try {
    const body = Buffer.from('x');
    const first = await r.ticket(body);
    assert.equal((await r.upload(first, body)).status, 201);
    const second = await r.ticket(body);
    const rejected = await r.upload(second, body);
    assert.equal(rejected.status, 429);
    assert.equal((await rejected.json()).error.code, 'monthly_demo_limit_reached');
    assert.equal(r.calls.length, 1);
    const status = await (await r.owned(second, `/api/v1/jobs/${second.job_id}`)).json();
    assert.equal(status.status, 'failed'); assert.equal(status.error_message, 'execution_admission_limit');
    assert.equal((await r.upload(second, body)).status, 409);
  } finally {await r.mf.dispose();}
});

test('public admission refuses missing or insecure keyless dispatcher configuration', async () => {
  for (const url of ['', 'http://dispatcher.test', 'https://dispatcher.test/dispatch', 'https://user:password@dispatcher.test']) {
    const r = await runtime({GCP_DISPATCH_URL: url});
    try {
      const response = await r.fetch('/api/v1/upload-tickets', {method: 'POST',
        body: JSON.stringify({bytes: 1, filename: 'fixture.bin', sha256: hash('x')})});
      assert.equal(response.status, 503, url);
      assert.equal(r.calls.length, 0);
      assert.equal((await r.sql.exec('SELECT count(*) AS n FROM jobs'))[0].n, 0);
    } finally {await r.mf.dispose();}
  }
});

test('existing durable SQLite jobs and quotas survive the keyless schema migration', async () => {
  const r = await runtime({DAILY_JOB_LIMIT: '1'});
  try {
    const ticket = await r.ticket(Buffer.from('retained-before-keyless'));
    const before = await r.row(ticket.job_id);
    // Model the schema of the already-deployed control Worker, then force a
    // genuine Durable Object restart so its new constructor performs migration.
    await r.sql.exec('ALTER TABLE jobs DROP COLUMN dispatch_request_sha256');
    await r.sql.exec('ALTER TABLE jobs DROP COLUMN dispatch_claimed_at');
    const oldColumns = (await r.sql.exec('PRAGMA table_info(jobs)')).map(column => column.name);
    assert.ok(!oldColumns.includes('dispatch_request_sha256'));
    assert.ok(!oldColumns.includes('dispatch_claimed_at'));
    await r.mf.unsafeEvictDurableObject('control-test', 'DemoControl', {name: 'demo-control'});
    assert.equal((await r.owned(ticket, `/api/v1/jobs/${ticket.job_id}`)).status, 200);
    const after = await r.row(ticket.job_id);
    assert.equal(after.dispatch_request_sha256, null);
    assert.equal(after.dispatch_claimed_at, null);
    const {dispatch_request_sha256, dispatch_claimed_at, ...oldBefore} = before;
    const {dispatch_request_sha256: newHash, dispatch_claimed_at: newClaim, ...oldAfter} = after;
    assert.deepEqual(oldAfter, oldBefore);
    const response = await r.fetch('/api/v1/upload-tickets', {method: 'POST',
      body: JSON.stringify({bytes: 1, filename: 'x', sha256: hash('x')})});
    assert.equal(response.status, 429);
    assert.equal((await response.json()).error.code, 'daily_demo_limit_reached');
  } finally {await r.mf.dispose();}
});
