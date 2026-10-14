// Exercise the actual JavaScript/Python protocol over local HTTP. Only metadata
// and the Google Jobs API are stubbed; the Python dispatcher and SQLite claim
// handler are production code. All data below is a public, harmless fixture.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {Miniflare} from 'miniflare';

const fixtureKey = '12'.repeat(32);
const hash = data => createHash('sha256').update(data).digest('hex');
const bridgeSource = String.raw`
import json
import sys
from http.server import HTTPServer

sys.path.insert(0, sys.argv[1])
from server import Config, Dispatcher, METADATA_URL, Reply, Transport, encoded, handler_for

local_control = sys.argv[2].rstrip("/")
config = Config("local-test", "us-central1", "static-demo", "https://control.test", bytes.fromhex(sys.argv[3]))

def emit(kind, **values):
    print(json.dumps({"kind": kind, **values}), flush=True)

class LocalTransport(Transport):
    def request(self, method, url, headers, body, timeout):
        if url == METADATA_URL:
            assert method == "GET"
            assert headers == {"Metadata-Flavor": "Google"}
            emit("metadata")
            return Reply(200, encoded({"access_token": "public-local-fixture-token"}))
        if url == config.control_origin + "/internal/dispatch/claim":
            # This mapping exists only in the test bridge; production always
            # sends claims to the fixed HTTPS control origin.
            reply = super().request(method, local_control + "/internal/dispatch/claim", headers, body, timeout)
            emit("claim", status=reply.status, response=json.loads(reply.body))
            return reply
        assert url == "https://run.googleapis.com/v2/" + config.job_name + ":run", url
        assert method == "POST"
        assert headers["Authorization"] == "Bearer public-local-fixture-token"
        emit("google", request=json.loads(body))
        return Reply(200, encoded({"name": "projects/local-test/locations/us-central1/operations/cross-language-fixture"}))

server = HTTPServer(("127.0.0.1", 0), handler_for(Dispatcher(config, LocalTransport())))
emit("ready", port=server.server_address[1])
server.serve_forever()
`;

async function waitFor(predicate, message) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, message);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

async function stopProcess(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  let timer;
  const stopped = new Promise(resolve => child.once('exit', resolve));
  try {
    child.kill('SIGTERM');
    timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    await stopped;
  } finally {clearTimeout(timer);}
}

test('real Worker and Python HTTP dispatcher share one durable claim and cannot replay a Google run',
  {timeout: 60000}, async () => {
    const temporary = await mkdtemp(join(tmpdir(), 'malscan-keyless-protocol-'));
    const events = [];
    const dispatches = [];
    let dispatcherOrigin;
    let child;
    let lines;
    let stderr = '';
    const mf = new Miniflare({
      name: 'cross-language-control', modules: true, unsafeInspectDurableObjects: true,
      scriptPath: fileURLToPath(new URL('../src/worker.mjs', import.meta.url)),
      compatibilityDate: '2026-07-30', r2Buckets: ['UPLOADS', 'RESULTS'], r2Persist: false,
      durableObjects: {CONTROL: {className: 'DemoControl', useSQLite: true}}, durableObjectsPersist: false,
      bindings: {PUBLIC_UPLOADS: 'true', ALLOWED_ORIGIN: 'https://demo.test', CONTROL_HMAC_KEY: fixtureKey,
        GCP_PROJECT: 'local-test', GCP_REGION: 'us-central1', GCP_JOB: 'static-demo',
        GCP_DISPATCH_URL: 'https://dispatcher.test'},
      outboundService: async request => {
        assert.equal(request.url, 'https://dispatcher.test/dispatch');
        assert.equal(request.method, 'POST');
        const raw = await request.text();
        dispatches.push(raw);
        const response = await fetch(dispatcherOrigin + '/dispatch', {
          method: 'POST', headers: {'content-type': 'application/json'}, body: raw,
        });
        return new Response(await response.arrayBuffer(), {status: response.status,
          headers: {'content-type': 'application/json'}});
      },
    });
    try {
      const localControl = await mf.ready;
      const bridgePath = join(temporary, 'bridge.py');
      await writeFile(bridgePath, bridgeSource);
      let resolveReady, rejectReady;
      const ready = new Promise((resolve, reject) => {resolveReady = resolve; rejectReady = reject;});
      child = spawn('python3', [bridgePath, fileURLToPath(new URL('../../dispatcher/', import.meta.url)),
        localControl.toString(), fixtureKey], {
        env: {...process.env, PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1'},
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      child.once('error', rejectReady);
      child.once('exit', code => rejectReady(new Error(`Python bridge exited (${code}): ${stderr}`)));
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', chunk => {stderr = (stderr + chunk).slice(-8192);});
      lines = createInterface({input: child.stdout});
      lines.on('line', line => {
        try {
          const event = JSON.parse(line);
          if (event.kind === 'ready') resolveReady(event.port);
          else events.push(event);
        } catch (error) {rejectReady(error);}
      });
      let startupTimer;
      try {
        const port = await Promise.race([ready, new Promise((_, reject) => {
          startupTimer = setTimeout(() => reject(new Error(`Python bridge startup timed out: ${stderr}`)), 10000);
        })]);
        dispatcherOrigin = `http://127.0.0.1:${port}`;
      } finally {clearTimeout(startupTimer);}

      const body = Buffer.from('Harmless cross-language keyless dispatch fixture.');
      const ticketResponse = await mf.dispatchFetch('https://control.test/api/v1/upload-tickets', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({bytes: body.length, filename: 'fixture.txt', sha256: hash(body)}),
      });
      assert.equal(ticketResponse.status, 201, await ticketResponse.clone().text());
      const ticket = await ticketResponse.json();
      const uploaded = await mf.dispatchFetch('https://control.test/api/v1/files', {
        method: 'POST', headers: {'content-type': 'application/octet-stream', 'content-length': String(body.length),
          authorization: 'Bearer ' + ticket.token}, body,
      });
      assert.equal(uploaded.status, 201, await uploaded.clone().text());
      assert.equal((await uploaded.json()).status, 'queued');
      assert.equal(dispatches.length, 1);
      const original = JSON.parse(dispatches[0]);
      const payload = JSON.parse(original.payload);
      const sql = await mf.unsafeGetDurableObjectStorage('cross-language-control', 'DemoControl', {name: 'demo-control'});
      const row = (await sql.exec('SELECT * FROM jobs WHERE id = ?', ticket.job_id))[0];
      assert.ok(Number.isSafeInteger(row.dispatch_claimed_at));
      assert.equal(row.dispatch_request_sha256, hash(original.payload));
      assert.equal(row.operation_name, 'projects/local-test/locations/us-central1/operations/cross-language-fixture');
      await waitFor(() => events.length === 3, 'metadata, real claim and Google stub should be recorded');
      assert.deepEqual(events.map(event => event.kind), ['metadata', 'claim', 'google']);
      assert.equal(events[1].status, 200);
      assert.deepEqual(events[1].response, {claimed: true, dispatch_id: payload.dispatch_id, request_sha256: hash(original.payload)});
      const overrides = events[2].request.overrides;
      assert.deepEqual(Object.keys(overrides).sort(), ['containerOverrides', 'taskCount']);
      assert.equal(overrides.taskCount, 1);
      assert.equal(overrides.containerOverrides.length, 1);
      const expectedEnv = {MALSCAN_MANIFEST_KEY: payload.manifest_key, MALSCAN_CONTROL_KEY: payload.control_key,
        MALSCAN_STATUS_KEY: payload.status_key, MALSCAN_DISPATCH_ID: payload.dispatch_id,
        MALSCAN_ROOT_JOB_ID: payload.job_id, MALSCAN_ATTEMPT_ID: payload.attempt_id,
        MALSCAN_REPORT_KEY: payload.report_key, MALSCAN_SEQUENCE: String(payload.sequence)};
      assert.deepEqual(Object.fromEntries(overrides.containerOverrides[0].env.map(item => [item.name, item.value])), expectedEnv);

      const replay = await fetch(dispatcherOrigin + '/dispatch', {method: 'POST',
        headers: {'content-type': 'application/json'}, body: dispatches[0]});
      assert.equal(replay.status, 409);
      assert.equal((await replay.json()).error, 'dispatch_claim_unavailable');
      await waitFor(() => events.length === 5, 'replay must reach the real claim gate before being rejected');
      assert.deepEqual(events.map(event => event.kind), ['metadata', 'claim', 'google', 'metadata', 'claim']);
      assert.equal(events[4].status, 409);
      assert.equal(events.filter(event => event.kind === 'google').length, 1);

      const invalid = {...original, hmac_sha256: '0'.repeat(64)};
      const unauthorized = await fetch(dispatcherOrigin + '/dispatch', {method: 'POST',
        headers: {'content-type': 'application/json'}, body: JSON.stringify(invalid)});
      assert.equal(unauthorized.status, 401);
      assert.equal((await unauthorized.json()).error, 'dispatch_authentication_failed');
      assert.equal(events.length, 5, 'invalid HMAC must not request metadata, a claim, or a Google run');
      assert.equal(dispatches.length, 1, 'direct replay cannot cause the Worker to dispatch again');
    } finally {
      await stopProcess(child);
      lines?.close();
      await mf.dispose();
      await rm(temporary, {recursive: true, force: true});
    }
  });
