// Opt-in: consume untouched reports/status from the real full-worker image.
// The fixture key is public test data. No Google/Cloudflare credentials are used.
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {Miniflare} from 'miniflare';

const directory = process.env.MALSCAN_RUNNER_FIXTURE_DIR;
test('real Python container reports and signed status pass the workerd verification gate',
  {skip: !directory, timeout: 60000}, async () => {
    const hash = data => createHash('sha256').update(data).digest('hex');
    const key = Buffer.from(Array.from({length: 32}, (_, i) => i)).toString('hex');
    const mf = new Miniflare({
      name: 'runner-fixture', modules: true, unsafeInspectDurableObjects: true,
      scriptPath: fileURLToPath(new URL('../src/worker.mjs', import.meta.url)),
      compatibilityDate: '2026-07-30', r2Buckets: ['UPLOADS', 'RESULTS'],
      durableObjects: {CONTROL: {className: 'DemoControl', useSQLite: true}},
      bindings: {PUBLIC_UPLOADS: 'true', CONTROL_HMAC_KEY: key,
        GCP_PROJECT: 'local-fixture', GCP_REGION: 'us-central1', GCP_JOB: 'static-demo',
        GCP_DISPATCH_URL: 'https://dispatcher.test', ALLOWED_ORIGIN: 'https://fixture.test'},
      outboundService: () => {throw new Error('Fixture verification must not dispatch');},
    });
    try {
      await mf.ready;
      const ticketResponse = await mf.dispatchFetch('https://fixture.test/api/v1/upload-tickets', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({filename: 'fixture.bin', bytes: 1, sha256: hash('x')}),
      });
      assert.equal(ticketResponse.status, 201);
      const ticket = await ticketResponse.json();
      const sql = await mf.unsafeGetDurableObjectStorage('runner-fixture', 'DemoControl', {name: 'demo-control'});
      const bucket = await mf.getR2Bucket('RESULTS');
      let rowId = ticket.job_id;
      for (const sequence of [1, 2, 3]) {
        const raw = await readFile(join(directory, `report-${sequence}.json`));
        const envelope = await readFile(join(directory, `status-envelope-${sequence}.json`));
        const status = JSON.parse(JSON.parse(envelope).payload);
        const report = JSON.parse(raw);
        assert.equal(hash(raw), status.report_sha256);
        const statusKey = `statuses/${status.job_id}/${status.dispatch_id}.json`;
        await sql.exec(`UPDATE jobs SET id=?, attempt_id=?, dispatch_id=?, dispatch_sequence=?,
          manifest_sha256=?, status_key=?, report_key=?, status='scanning', accepted_revision=0
          WHERE id=?`, status.job_id, status.attempt_id, status.dispatch_id, sequence,
          status.manifest_sha256, statusKey, report.report_key, rowId);
        rowId = status.job_id;
        await bucket.put(status.report_key, raw);
        await bucket.put(statusKey, envelope);
        const headers = {authorization: 'Bearer ' + ticket.capability_token};
        const response = await mf.dispatchFetch(`https://fixture.test/api/v1/reports/${rowId}`, {headers});
        assert.equal(response.status, 200, await response.clone().text());
        const accepted = await response.json();
        assert.equal(accepted.analysis_attempt_id, status.attempt_id);
        assert.equal(accepted.job_status, status.status);
        assert.deepEqual(accepted.results, report.results);
        assert.equal(accepted.analysis.dynamic.status, 'disabled');
        assert.equal(accepted.artifact_tree.id, status.job_id);
        const wrong = await mf.dispatchFetch(`https://fixture.test/api/v1/reports/${rowId}`,
          {headers: {authorization: 'Bearer ' + randomUUID().replaceAll('-', '').repeat(2)}});
        assert.equal(wrong.status, 404);
      }
    } finally {await mf.dispose();}
  });
