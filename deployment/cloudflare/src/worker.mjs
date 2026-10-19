// Low-volume demo control plane. Full analysis runs in the shared Python core.
// No file buffering, cloud credentials in responses, automatic uncertain retry,
// or synthetic fallback reports. Deploy this separately from the upload PoC.
import {DurableObject} from 'cloudflare:workers';

const MAX_BYTES = 20_000_000;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const PASSWORD_ATTEMPT_LIMIT = 3;
const encoder = new TextEncoder();
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const ARTIFACT = /^[a-f0-9]{8}-[a-f0-9]{4}-[45][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX = /^[a-f0-9]{64}$/;
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
});
const error = (code, status, message = code) => json({error: {code, message}}, status);
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
const sha = async value => hex(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? encoder.encode(value) : value));
const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const validUnicode = text => {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
};
const bearer = request => {
  const header = request.headers.get('authorization') ?? '';
  return /^Bearer [a-f0-9]{64}$/.test(header) ? header.slice(7) : '';
};
const canonical = object => {
  if (Array.isArray(object)) return '[' + object.map(canonical).join(',') + ']';
  if (object && typeof object === 'object') return '{' + Object.keys(object).sort().map(key => JSON.stringify(key) + ':' + canonical(object[key])).join(',') + '}';
  return JSON.stringify(object).replace(/[\u007f-\uffff]/g, value => '\\u' + value.charCodeAt(0).toString(16).padStart(4, '0'));
};
async function hmacKey(env) {
  if (!HEX.test(env.CONTROL_HMAC_KEY ?? '')) throw new Error('signature_configuration_missing');
  const bytes = Uint8Array.from(env.CONTROL_HMAC_KEY.match(/../g), part => parseInt(part, 16));
  return crypto.subtle.importKey('raw', bytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']);
}
async function signed(env, payload) {
  const text = canonical(payload);
  return {payload: text, hmac_sha256: hex(await crypto.subtle.sign('HMAC', await hmacKey(env), encoder.encode(text)))};
}
async function verified(env, envelope) {
  if (!envelope || typeof envelope.payload !== 'string' || !HEX.test(envelope.hmac_sha256 ?? '')) throw new Error('invalid_signed_status');
  const signature = Uint8Array.from(envelope.hmac_sha256.match(/../g), part => parseInt(part, 16));
  if (!await crypto.subtle.verify('HMAC', await hmacKey(env), signature, encoder.encode(envelope.payload))) throw new Error('invalid_signed_status');
  return JSON.parse(envelope.payload);
}
async function boundedJson(request, max = 4096) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error('invalid_json');
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) throw new Error('request_too_large');
      chunks.push(value);
    }
    const data = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {data.set(chunk, offset); offset += chunk.length;}
    return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(data));
  } finally {await reader.cancel().catch(() => {});}
}
const stub = env => env.CONTROL.get(env.CONTROL.idFromName('demo-control'));
const internal = (env, body) => stub(env).fetch('https://internal.invalid/control', {
  method: 'POST', body: JSON.stringify(body), headers: {'content-type': 'application/json'},
});
const configInt = (env, name, fallback, min, max) => {
  const value = Number(env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error('invalid_demo_configuration');
  return value;
};
const DISPATCH_DOMAIN = 'malscan:v2:dispatch\n';
const CLAIM_DOMAIN = 'malscan:v2:dispatch-claim\n';
async function signedDomain(env, payload, domain) {
  const text = canonical(payload);
  return {payload: text, hmac_sha256: hex(await crypto.subtle.sign('HMAC', await hmacKey(env), encoder.encode(domain + text)))};
}
async function verifiedDomain(env, envelope, domain) {
  if (!envelope || Object.keys(envelope).sort().join(',') !== 'hmac_sha256,payload'
    || typeof envelope.payload !== 'string' || !HEX.test(envelope.hmac_sha256 ?? '')) throw new Error('invalid_dispatch_signature');
  const signature = Uint8Array.from(envelope.hmac_sha256.match(/../g), part => parseInt(part, 16));
  if (!await crypto.subtle.verify('HMAC', await hmacKey(env), signature, encoder.encode(domain + envelope.payload))) throw new Error('invalid_dispatch_signature');
  return JSON.parse(envelope.payload);
}
function dispatchUrl(env) {
  const url = new URL(env.GCP_DISPATCH_URL);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash) throw new Error('dispatch_configuration_missing');
  return url.origin + '/dispatch';
}
function validDispatch(env, value) {
  const fields = ['dispatch_version', 'job_name', 'issued_at', 'expires_at', 'job_id', 'attempt_id', 'dispatch_id', 'sequence', 'manifest_key', 'control_key', 'status_key', 'report_key'];
  if (!value || Object.keys(value).sort().join(',') !== fields.sort().join(',')
    || value.dispatch_version !== 1 || value.job_name !== googleJob(env)
    || ![value.job_id, value.attempt_id, value.dispatch_id].every(id => UUID.test(id ?? ''))
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1 || value.sequence > 999999999
    || !Number.isSafeInteger(value.issued_at) || !Number.isSafeInteger(value.expires_at)
    || value.issued_at > Date.now() + 5000 || value.expires_at <= Date.now()
    || value.expires_at <= value.issued_at || value.expires_at > value.issued_at + 120000
    || value.manifest_key !== `manifests/${value.job_id}/${value.attempt_id}.json`
    || value.control_key !== `controls/${value.job_id}/${value.dispatch_id}.json`
    || value.status_key !== `statuses/${value.job_id}/${value.dispatch_id}.json`
    || value.report_key !== `reports/${value.job_id}/${value.attempt_id}.json`) throw new Error('invalid_dispatch_request');
  return value;
}
function googleJob(env) {
  if (!/^[a-z][a-z0-9-]{4,62}$/.test(env.GCP_PROJECT ?? '') || !/^[a-z]+-[a-z]+\d$/.test(env.GCP_REGION ?? '')
    || !/^[a-z][a-z0-9-]{0,62}$/.test(env.GCP_JOB ?? '')) throw new Error('google_job_configuration_missing');
  return `projects/${env.GCP_PROJECT}/locations/${env.GCP_REGION}/jobs/${env.GCP_JOB}`;
}
async function runJob(env, envelope) {
  const response = await fetch(dispatchUrl(env), {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(45000),
    headers: {'content-type': 'application/json'}, body: JSON.stringify(envelope),
  });
  if (!response.ok) throw new Error('job_dispatch_rejected');
  const result = await boundedJson(response, 32768);
  const prefix = `projects/${env.GCP_PROJECT}/locations/${env.GCP_REGION}/operations/`;
  if (typeof result.name !== 'string' || !result.name.startsWith(prefix) || !/^[a-zA-Z0-9_-]+$/.test(result.name.slice(prefix.length))) throw new Error('job_dispatch_response_invalid');
  return result.name;
}

export class DemoControl extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY, capability_hash TEXT NOT NULL UNIQUE, ticket_hash TEXT NOT NULL UNIQUE,
      ticket_expires INTEGER NOT NULL, ticket_consumed INTEGER NOT NULL DEFAULT 0,
      bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, filename TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL,
      cleanup_after INTEGER NOT NULL,
      attempt_id TEXT NOT NULL, dispatch_id TEXT, dispatch_sequence INTEGER NOT NULL DEFAULT 0,
      dispatch_deadline_at INTEGER, dispatch_request_sha256 TEXT, dispatch_claimed_at INTEGER,
      password_attempts INTEGER NOT NULL DEFAULT 0,
      password_attempts_by_artifact TEXT NOT NULL DEFAULT '{}',
      legacy_password_submissions INTEGER NOT NULL DEFAULT 0, manifest_key TEXT NOT NULL,
      manifest_sha256 TEXT, status_key TEXT, report_key TEXT NOT NULL, report_sha256 TEXT, accepted_report_key TEXT,
      accepted_revision INTEGER NOT NULL DEFAULT 0,
      password_artifacts TEXT NOT NULL DEFAULT '[]', operation_name TEXT, error_code TEXT,
      cleanup_pending INTEGER NOT NULL DEFAULT 0
    )`);
    // Preserve already-deployed SQLite state when adding keyless dispatch.
    const columns = new Set(this.sql.exec('PRAGMA table_info(jobs)').toArray().map(column => column.name));
    if (!columns.has('dispatch_request_sha256')) this.sql.exec('ALTER TABLE jobs ADD COLUMN dispatch_request_sha256 TEXT');
    if (!columns.has('dispatch_claimed_at')) this.sql.exec('ALTER TABLE jobs ADD COLUMN dispatch_claimed_at INTEGER');
    // Older deployments only recorded a root-wide total. Keep that audit total
    // and snapshot its unattributable part once; never invent per-file history
    // or reset the independent daily/monthly execution admission counters.
    this.ctx.storage.transactionSync(() => {
      if (!columns.has('password_attempts_by_artifact')) this.sql.exec("ALTER TABLE jobs ADD COLUMN password_attempts_by_artifact TEXT NOT NULL DEFAULT '{}'");
      if (!columns.has('legacy_password_submissions')) {
        this.sql.exec('ALTER TABLE jobs ADD COLUMN legacy_password_submissions INTEGER NOT NULL DEFAULT 0');
        this.sql.exec('UPDATE jobs SET legacy_password_submissions = password_attempts');
      }
    });
    this.sql.exec('CREATE TABLE IF NOT EXISTS quota (day TEXT PRIMARY KEY, jobs INTEGER NOT NULL DEFAULT 0, executions INTEGER NOT NULL DEFAULT 0)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS monthly_quota (month TEXT PRIMARY KEY, executions INTEGER NOT NULL DEFAULT 0)');
  }
  job(id) {return this.sql.exec('SELECT * FROM jobs WHERE id = ?', id).toArray()[0];}
  passwordCounts(row) {
    const counts = JSON.parse(row.password_attempts_by_artifact);
    if (!counts || typeof counts !== 'object' || Array.isArray(counts)
      || Object.entries(counts).some(([id, count]) => !ARTIFACT.test(id)
        || !Number.isSafeInteger(count) || count < 0 || count > PASSWORD_ATTEMPT_LIMIT)) throw new Error('invalid_password_attempt_state');
    return counts;
  }
  passwordSummary(row, id = row.id) {
    const counts = this.passwordCounts(row);
    const ids = [...new Set([row.id, ...JSON.parse(row.password_artifacts), ...Object.keys(counts)])].sort();
    const attempts = counts[id] ?? 0;
    return {password_attempts: attempts, password_attempts_remaining: Math.max(0, PASSWORD_ATTEMPT_LIMIT - attempts),
      password_attempts_by_artifact: Object.fromEntries(ids.map(artifactId => {
        const used = counts[artifactId] ?? 0;
        return [artifactId, {attempts_used: used, attempts_remaining: Math.max(0, PASSWORD_ATTEMPT_LIMIT - used), limit: PASSWORD_ATTEMPT_LIMIT}];
      })), password_attempt_limit: PASSWORD_ATTEMPT_LIMIT, password_attempts_scope: 'artifact',
      total_password_submissions: row.password_attempts, legacy_password_submissions: row.legacy_password_submissions};
  }
  owned(id, capabilityHash, allowChild = false) {
    const row = this.sql.exec('SELECT * FROM jobs WHERE capability_hash = ?', capabilityHash).toArray()[0];
    if (!row || row.expires_at <= Date.now() || (row.id !== id && (!allowChild || !JSON.parse(row.password_artifacts).includes(id)))) return null;
    return row;
  }
  async schedule() {
    const next = this.sql.exec('SELECT MIN(cleanup_after) AS next FROM jobs').toArray()[0]?.next;
    if (next) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, next));
  }
  reserve(kind) {
    const day = new Date().toISOString().slice(0, 10);
    const field = kind === 'jobs' ? 'jobs' : 'executions';
    const limit = kind === 'jobs' ? configInt(this.env, 'DAILY_JOB_LIMIT', 10, 1, 1000) : configInt(this.env, 'DAILY_EXECUTION_LIMIT', 20, 1, 1000);
    this.sql.exec('INSERT OR IGNORE INTO quota (day) VALUES (?)', day);
    const current = this.sql.exec('SELECT * FROM quota WHERE day = ?', day).toArray()[0];
    if (current[field] >= limit) throw new Error('daily_demo_limit_reached');
    if (kind === 'executions') {
      const month = day.slice(0, 7);
      const monthlyLimit = configInt(this.env, 'MONTHLY_EXECUTION_LIMIT', 40, 1, 1000);
      this.sql.exec('INSERT OR IGNORE INTO monthly_quota (month) VALUES (?)', month);
      const used = this.sql.exec('SELECT executions FROM monthly_quota WHERE month = ?', month).toArray()[0].executions;
      if (used >= monthlyLimit) throw new Error('monthly_demo_limit_reached');
      this.sql.exec('UPDATE monthly_quota SET executions = executions + 1 WHERE month = ?', month);
      this.sql.exec('DELETE FROM monthly_quota WHERE month < ?', month);
    }
    this.sql.exec(`UPDATE quota SET ${field} = ${field} + 1 WHERE day = ?`, day);
    this.sql.exec('DELETE FROM quota WHERE day < ?', day);
  }
  async issue(input) {
    const token = random(), capability = random(), id = crypto.randomUUID(), attempt = crypto.randomUUID();
    const now = Date.now();
    const ttl = configInt(this.env, 'RETENTION_SECONDS', 86400, 1800, 604800);
    const ticketHash = await sha(token), capabilityHash = await sha(capability);
    this.ctx.storage.transactionSync(() => {
      this.reserve('jobs');
      this.sql.exec(`INSERT INTO jobs (id, capability_hash, ticket_hash, ticket_expires,
        bytes, sha256, filename, created_at, expires_at, cleanup_after, status, attempt_id, manifest_key, report_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'awaiting_upload', ?, ?, ?)`,
      id, capabilityHash, ticketHash, now + 300000, input.bytes, input.sha256, input.filename,
      now, now + ttl * 1000, now + ttl * 1000 + 1200000, attempt, `manifests/${id}/${attempt}.json`, `reports/${id}/${attempt}.json`);
    });
    await this.schedule();
    return json({token, capability_token: capability, job_id: id, expires_at: now + 300000, max_bytes: input.bytes}, 201);
  }
  consume(input) {
    return this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec('SELECT * FROM jobs WHERE ticket_hash = ?', input.ticket_hash).toArray()[0];
      if (!row) return error('upload_credential_invalid', 401);
      if (row.ticket_expires <= Date.now() || row.expires_at <= Date.now()) return error('upload_credential_expired', 403);
      if (row.ticket_consumed) return error('upload_credential_used', 409);
      if (input.validation_error) return error(input.validation_error, input.validation_status);
      if (row.bytes !== input.bytes) return error('upload_size_not_authorized', 400);
      this.sql.exec("UPDATE jobs SET ticket_consumed = 1, status = 'uploading' WHERE id = ?", row.id);
      return json({job_id: row.id, source_key: `uploads/${row.id}/source`, bytes: row.bytes, sha256: row.sha256, filename: row.filename, expires_at: row.expires_at});
    });
  }
  async dispatch(row, passwords = null) {
    // Durable reservation precedes every external call. An ambiguous response
    // remains uncertain; a client retry cannot create another execution.
    const dispatch = crypto.randomUUID();
    const sequence = row.dispatch_sequence + 1;
    try {this.ctx.storage.transactionSync(() => {
      const fresh = this.job(row.id);
      if (!fresh || fresh.expires_at <= Date.now()) throw new Error('job_retention_expired');
      const expected = passwords ? 'password_required' : 'uploading';
      if (fresh.status !== expected || fresh.dispatch_sequence !== row.dispatch_sequence) throw new Error('dispatch_already_reserved');
      const counts = this.passwordCounts(fresh);
      if (passwords) {
        const targets = Object.keys(passwords);
        // Revalidate the canonical pending target inside the same durable
        // transaction that reserves its submission and a global execution.
        if (targets.length !== 1 || !ARTIFACT.test(targets[0])
          || !JSON.parse(fresh.password_artifacts).includes(targets[0])) throw new Error('archive_not_waiting');
        const target = targets[0];
        if ((counts[target] ?? 0) >= PASSWORD_ATTEMPT_LIMIT) throw new Error('password_attempt_limit');
        counts[target] = (counts[target] ?? 0) + 1;
      }
      this.reserve('executions');
      this.sql.exec("UPDATE jobs SET status = 'dispatching', dispatch_id = ?, dispatch_sequence = ?, dispatch_deadline_at = ?, dispatch_request_sha256 = NULL, dispatch_claimed_at = NULL, accepted_revision = 0, password_attempts = password_attempts + ?, password_attempts_by_artifact = ? WHERE id = ?",
        dispatch, sequence, Date.now() + 1200000, passwords ? 1 : 0, JSON.stringify(counts), row.id);
    });} catch (exception) {
      if (!passwords && ['daily_demo_limit_reached', 'monthly_demo_limit_reached'].includes(exception.message)) {
        this.sql.exec("UPDATE jobs SET status = 'failed', error_code = 'execution_admission_limit' WHERE id = ? AND status = 'uploading'", row.id);
      }
      throw exception;
    }
    const manifest = {manifest_version: 1, root_job_id: row.id, attempt_id: row.attempt_id,
      source: {key: `uploads/${row.id}/source`, sha256: row.sha256, size: row.bytes, filename: row.filename}, report_key: row.report_key};
    const fingerprint = await sha(canonical(manifest));
    const controlKey = `controls/${row.id}/${dispatch}.json`;
    const statusKey = `statuses/${row.id}/${dispatch}.json`;
    this.sql.exec('UPDATE jobs SET manifest_sha256 = ?, status_key = ? WHERE id = ?', fingerprint, statusKey, row.id);
    let dispatched = false;
    try {
      await this.env.UPLOADS.put(row.manifest_key, JSON.stringify(manifest), {httpMetadata: {contentType: 'application/json'}});
      const control = {control_version: 1, manifest_sha256: fingerprint,
        checkpoint_key: `checkpoints/${row.id}/${row.attempt_id}.json`, resume: !!passwords,
        passwords: passwords ?? {}, password_attempts_by_artifact: this.passwordCounts(this.job(row.id)),
        password_attempt_limit: PASSWORD_ATTEMPT_LIMIT, password_attempts_scope: 'artifact',
        status_key: statusKey, dispatch_id: dispatch, sequence, expires_at: row.expires_at};
      await this.env.RESULTS.put(controlKey, JSON.stringify(await signed(this.env, control)), {httpMetadata: {contentType: 'application/json'}});
      const now = Date.now();
      const payload = {dispatch_version: 1, job_name: googleJob(this.env), issued_at: now,
        expires_at: Math.min(now + 120000, row.expires_at), job_id: row.id, attempt_id: row.attempt_id,
        dispatch_id: dispatch, sequence, manifest_key: row.manifest_key,
        control_key: controlKey, status_key: statusKey, report_key: row.report_key};
      const envelope = await signedDomain(this.env, payload, DISPATCH_DOMAIN);
      this.sql.exec('UPDATE jobs SET dispatch_request_sha256 = ? WHERE id = ? AND dispatch_id = ?', await sha(envelope.payload), row.id, dispatch);
      dispatched = true;
      const operation = await runJob(this.env, envelope);
      this.sql.exec(`UPDATE jobs SET operation_name = ?,
        status = CASE WHEN status = 'dispatching' THEN 'queued' ELSE status END,
        error_code = CASE WHEN status = 'dispatching' THEN NULL ELSE error_code END
        WHERE id = ? AND dispatch_id = ?`, operation, row.id, dispatch);
    } catch {
      this.sql.exec("UPDATE jobs SET status = ?, error_code = ? WHERE id = ? AND dispatch_id = ? AND status = 'dispatching'",
        dispatched ? 'dispatch_uncertain' : 'failed', dispatched ? 'job_dispatch_uncertain' : 'job_preparation_failed', row.id, dispatch);
    }
    return this.job(row.id);
  }
  claimDispatch(input) {
    return this.ctx.storage.transactionSync(() => {
      const payload = input.payload;
      const row = this.job(payload.job_id);
      if (!row || row.expires_at <= Date.now()) return error('job_retention_expired', 410);
      if (!['dispatching', 'dispatch_uncertain'].includes(row.status)
        || row.attempt_id !== payload.attempt_id || row.dispatch_id !== payload.dispatch_id
        || row.dispatch_sequence !== payload.sequence || row.manifest_key !== payload.manifest_key
        || row.status_key !== payload.status_key || row.report_key !== payload.report_key
        || payload.control_key !== `controls/${row.id}/${row.dispatch_id}.json`
        || row.dispatch_claimed_at !== null || row.dispatch_request_sha256 !== input.request_sha256
        || payload.expires_at <= Date.now()) return error('dispatch_claim_conflict', 409);
      this.sql.exec('UPDATE jobs SET dispatch_claimed_at = ? WHERE id = ? AND dispatch_id = ?', Date.now(), row.id, row.dispatch_id);
      return json({claimed: true, dispatch_id: row.dispatch_id, request_sha256: input.request_sha256});
    });
  }
  async refresh(row) {
    if (!row.status_key || ['done', 'failed', 'awaiting_upload', 'uploading'].includes(row.status)) return row;
    const object = await this.env.RESULTS.get(row.status_key);
    if (!object) {
      if (row.dispatch_deadline_at && row.dispatch_deadline_at <= Date.now()) {
        this.sql.exec("UPDATE jobs SET status = 'dispatch_uncertain', error_code = 'analysis_status_timeout' WHERE id = ? AND dispatch_id = ? AND status NOT IN ('done', 'failed', 'password_required')", row.id, row.dispatch_id);
        return this.job(row.id);
      }
      return row;
    }
    if (object.size > 131072) throw new Error('invalid_signed_status');
    const status = await verified(this.env, await object.json());
    if (status.status_version !== 1 || status.job_id !== row.id || status.attempt_id !== row.attempt_id
      || status.dispatch_id !== row.dispatch_id || status.sequence !== row.dispatch_sequence
      || !['scanning', 'password_required', 'done', 'failed'].includes(status.status)
      || status.manifest_sha256 !== row.manifest_sha256
      || (status.report_key !== null && (typeof status.report_key !== 'string'
        || !new RegExp(`^reports/${row.id}/${row.attempt_id}/${row.dispatch_id}/[1-9][0-9]*\\.json$`).test(status.report_key)))
      || (status.report_sha256 !== null && !HEX.test(status.report_sha256 ?? ''))
      || !Array.isArray(status.password_required_artifacts) || status.password_required_artifacts.length > 1000
      || status.password_required_artifacts.some(id => !ARTIFACT.test(id))) throw new Error('invalid_signed_status');
    if (!!status.report_key !== !!status.report_sha256 || (['done', 'password_required'].includes(status.status) && !HEX.test(status.report_sha256 ?? ''))) throw new Error('invalid_signed_status');
    const revision = status.report_key ? Number(status.report_key.split('/').at(-1).slice(0, -5)) : 0;
    if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('invalid_signed_status');
    const timedOut = status.status === 'scanning' && row.dispatch_deadline_at && row.dispatch_deadline_at <= Date.now();
    const code = timedOut ? 'analysis_status_timeout' : status.status === 'failed' ? 'analysis_failed' : null;
    // Awaiting R2 and crypto permits interleaving. Compare the current durable
    // state when committing, rather than assuming the original row is current.
    // Terminal statuses absorb older snapshots within this dispatch; report
    // revisions cannot move backwards. A failure without a new report retains
    // the previous verified partial report for diagnostics.
    this.sql.exec(`UPDATE jobs SET status = ?, report_sha256 = COALESCE(?, report_sha256),
      accepted_report_key = COALESCE(?, accepted_report_key), accepted_revision = MAX(accepted_revision, ?),
      password_artifacts = ?, error_code = ? WHERE id = ? AND dispatch_id = ?
      AND status NOT IN ('done', 'failed', 'password_required')
      AND (accepted_revision <= ? OR ? = 1)`,
      timedOut ? 'dispatch_uncertain' : status.status, status.report_sha256, status.report_key, revision,
      JSON.stringify(status.password_required_artifacts), code, row.id, row.dispatch_id, revision,
      status.status === 'failed' && !status.report_key ? 1 : 0);
    if (['done', 'password_required', 'failed'].includes(status.status)) await this.env.RESULTS.delete(`controls/${row.id}/${row.dispatch_id}.json`);
    return this.job(row.id);
  }
  summary(row, id = row.id) {
    const ticketExpired = row.status === 'awaiting_upload' && row.ticket_expires <= Date.now();
    const status = ticketExpired ? 'failed' : ['awaiting_upload', 'uploading', 'dispatching'].includes(row.status) ? 'queued'
      : row.status === 'dispatch_uncertain' ? 'failed' : row.status;
    return {job_id: id, parent_job_id: id === row.id ? null : row.id, status,
      progress: {current_stage: status, stages_done: status === 'done' ? 1 : 0, stages_total: 1, percent: status === 'done' ? 100 : 0},
      updated_at: new Date().toISOString(), error_message: ticketExpired ? 'upload_ticket_expired' : row.error_code,
      ...this.passwordSummary(row, id),
      password_required_artifacts: JSON.parse(row.password_artifacts),
      report_available: !!row.report_sha256, dispatch_uncertain: row.status === 'dispatch_uncertain',
      retention_expires_at: new Date(row.expires_at).toISOString()};
  }
  async fetch(request) {
    let input;
    try {input = await request.json();} catch {return error('invalid_internal_request', 400);}
    try {
      if (input.action === 'claim_dispatch') return this.claimDispatch(input);
      if (input.action === 'issue') return await this.issue(input);
      if (input.action === 'consume') return this.consume(input);
      if (input.action === 'uploaded') {
        const row = this.job(input.id);
        if (!row || row.expires_at <= Date.now()) return error('job_retention_expired', 410);
        if (row.status !== 'uploading') return error('upload_state_conflict', 409);
        const next = await this.dispatch(row);
        return json({job_id: row.id, file_id: row.id, sha256: row.sha256,
          status: this.summary(next).status, created_at: new Date(row.created_at).toISOString(),
          dispatch_uncertain: next.status === 'dispatch_uncertain'}, 201);
      }
      if (input.action === 'upload_failed') {
        this.sql.exec("UPDATE jobs SET status = 'failed', error_code = 'upload_failed', cleanup_pending = ? WHERE id = ? AND status = 'uploading'", input.cleanup_pending ? 1 : 0, input.id);
        return json({success: true});
      }
      let row = this.owned(input.id, input.capability_hash, input.action === 'password');
      if (!row) return error('job_not_found', 404);
      row = await this.refresh(row);
      if (input.action === 'status') return json(this.summary(row));
      if (input.action === 'report') {
        if (!row.report_sha256) return error('report_not_available', 409);
        const object = await this.env.RESULTS.get(row.accepted_report_key);
        if (!object || object.size > MAX_REPORT_BYTES) return error('report_storage_invalid', 502);
        const body = await object.arrayBuffer();
        if (await sha(body) !== row.report_sha256) return error('report_integrity_invalid', 502);
        const report = JSON.parse(new TextDecoder().decode(body));
        if (report.job_id !== row.id || report.report_schema_version !== 'mswr-report-v3'
          || report.analysis_attempt_id !== row.attempt_id) return error('report_identity_invalid', 502);
        const latest = this.summary(row);
        report.job_status = latest.status;
        if (row.status !== 'done') report.report_complete = false;
        report.control_error_code = latest.error_message;
        report.error_message = latest.error_message;
        report.execution_active = row.status === 'dispatch_uncertain' ? null : ['queued', 'scanning', 'dispatching'].includes(row.status);
        report.requires_reconciliation = row.status === 'dispatch_uncertain';
        if (row.status === 'failed') report.pending_descendants = 0;
        return json(report);
      }
      if (input.action === 'password') {
        if (row.status !== 'password_required' || !JSON.parse(row.password_artifacts).includes(input.id)) return error('archive_not_waiting', 409);
        const next = await this.dispatch(row, {[input.id]: input.password});
        return json({job_id: input.id, status: this.summary(next).status, ...this.passwordSummary(next, input.id)});
      }
      return error('invalid_internal_request', 400);
    } catch (exception) {
      const known = ['daily_demo_limit_reached', 'monthly_demo_limit_reached', 'dispatch_already_reserved', 'password_attempt_limit', 'job_retention_expired', 'archive_not_waiting'];
      const code = known.includes(exception.message) ? exception.message : 'control_operation_failed';
      return error(code, code.endsWith('_demo_limit_reached') ? 429 : code === 'control_operation_failed' ? 503 : code === 'job_retention_expired' ? 410 : 409);
    }
  }
  async alarm() {
    // Deletion is private and idempotent. Never delete a bucket or cloud Job.
    const expired = this.sql.exec('SELECT * FROM jobs WHERE expires_at <= ? AND cleanup_after <= ? LIMIT 3', Date.now(), Date.now()).toArray();
    let retry = false;
    for (const row of expired) {
      try {
        for (const [bucket, prefixes] of [[this.env.UPLOADS, [`uploads/${row.id}/`, `manifests/${row.id}/`]],
          [this.env.RESULTS, ['controls', 'statuses', 'reports', 'checkpoints', 'artifacts'].map(prefix => `${prefix}/${row.id}/`)]]) {
          for (const prefix of prefixes) {
            const objects = await bucket.list({prefix, limit: 1000});
            if (objects.objects.length) await bucket.delete(objects.objects.map(object => object.key));
            if (objects.truncated) {retry = true; throw new Error('cleanup_more_objects');}
          }
        }
        this.sql.exec('DELETE FROM jobs WHERE id = ?', row.id);
      } catch {retry = true;}
    }
    if (retry || expired.length === 3) await this.ctx.storage.setAlarm(Date.now() + 60000);
    else await this.schedule();
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('origin');
    const allowed = env.ALLOWED_ORIGIN;
    if (origin && origin !== allowed) return error('origin_not_allowed', 403);
    const cors = response => {
      const headers = new Headers(response.headers);
      if (origin && origin === allowed) {headers.set('access-control-allow-origin', origin); headers.set('vary', 'Origin');}
      headers.set('x-content-type-options', 'nosniff');
      return new Response(response.body, {status: response.status, headers});
    };
    if (request.method === 'OPTIONS') return cors(new Response(null, {status: 204,
      headers: {'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'Authorization, Content-Type', 'access-control-max-age': '600'}}));
    try {
      const path = new URL(request.url).pathname;
      if (path === '/internal/dispatch/claim' && request.method === 'POST') {
        let envelope, payload;
        try {
          envelope = await boundedJson(request, 16384);
          payload = validDispatch(env, await verifiedDomain(env, envelope, CLAIM_DOMAIN));
        } catch {return cors(error('dispatch_claim_invalid', 401));}
        return cors(await internal(env, {action: 'claim_dispatch', payload, request_sha256: await sha(envelope.payload)}));
      }
      if (path === '/health' && request.method === 'GET') return cors(json({status: 'ok', scope: 'demo_control_only'}));
      if (path === '/api/v1/capabilities' && request.method === 'GET') return cors(json({deployment_mode: 'cloud-demo',
        upload_transport: 'raw-ticket', job_authorization: 'bearer', stream: false, max_upload_bytes: MAX_BYTES,
        dynamic_analysis: {status: 'disabled', reason: 'cloud_demo_static_only'}}));
      if (path === '/api/v1/upload-tickets' && request.method === 'POST') {
        if (env.PUBLIC_UPLOADS !== 'true') return cors(error('public_uploads_disabled', 503));
        const input = await boundedJson(request);
        if (!input || Object.keys(input).sort().join(',') !== 'bytes,filename,sha256'
          || !Number.isSafeInteger(input.bytes) || input.bytes < 1 || input.bytes > MAX_BYTES
          || !HEX.test(input.sha256 ?? '') || typeof input.filename !== 'string' || !input.filename
          || !validUnicode(input.filename) || encoder.encode(input.filename).length > 512 || /[\x00-\x1f\x7f/\\]/.test(input.filename)) return cors(error('invalid_upload_metadata', 400));
        // Cloud identity/signature configuration is checked before taking quota.
        try {googleJob(env); dispatchUrl(env); await hmacKey(env);}
        catch {return cors(error('demo_configuration_missing', 503));}
        return cors(await internal(env, {action: 'issue', ...input}));
      }
      if (path === '/api/v1/files' && request.method === 'POST') {
        const token = bearer(request);
        if (!token) return cors(error('upload_credential_required', 401));
        const length = request.headers.get('content-length');
        let validationError, validationStatus;
        const bytes = length && /^\d+$/.test(length) ? Number(length) : null;
        if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/octet-stream') {validationError = 'raw_octet_stream_required'; validationStatus = 415;}
        else if (bytes === null) {validationError = 'content_length_required'; validationStatus = 411;}
        else if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_BYTES) {validationError = 'file_size_out_of_range'; validationStatus = 413;}
        const consumed = await internal(env, {action: 'consume', ticket_hash: await sha(token), bytes,
          validation_error: validationError, validation_status: validationStatus});
        if (!consumed.ok) return cors(consumed);
        const metadata = await consumed.json();
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), Math.max(1, Math.min(300000, metadata.expires_at - Date.now())));
        try {
          // A fixed-length native stream preserves R2 streaming semantics while
          // bounding a slow uploader. No JavaScript file hashing or buffering.
          const stream = new FixedLengthStream(metadata.bytes);
          const forwarding = request.body.pipeTo(stream.writable, {signal: controller.signal});
          const [, object] = await Promise.all([forwarding, env.UPLOADS.put(metadata.source_key, stream.readable, {
            sha256: metadata.sha256, httpMetadata: {contentType: 'application/octet-stream'},
            customMetadata: {job_id: metadata.job_id},
          })]);
          if (!object || object.size !== metadata.bytes) throw new Error('stored_size_mismatch');
          if (metadata.expires_at <= Date.now()) throw new Error('job_retention_expired');
        } catch {
          controller.abort();
          let pending = false;
          try {await env.UPLOADS.delete(metadata.source_key);} catch {pending = true;}
          await internal(env, {action: 'upload_failed', id: metadata.job_id, cleanup_pending: pending});
          return cors(error(pending ? 'upload_cleanup_required' : 'upload_integrity_failed', pending ? 503 : 400));
        } finally {clearTimeout(timeout);}
        return cors(await internal(env, {action: 'uploaded', id: metadata.job_id}));
      }
      const route = /^\/api\/v1\/(jobs|reports)\/([a-f0-9-]{36})(\/password)?$/.exec(path);
      if (!route || !ARTIFACT.test(route[2])) return cors(error('not_found', 404));
      const capability = bearer(request);
      if (!capability) return cors(error('job_credential_required', 401));
      const input = {id: route[2], capability_hash: await sha(capability)};
      if (route[1] === 'jobs' && route[3] === '/password' && request.method === 'POST') {
        const data = await boundedJson(request, 2048);
        if (!data || Object.keys(data).join(',') !== 'password' || typeof data.password !== 'string'
          || data.password.length < 1 || data.password.length > 256 || data.password.includes('\0')) return cors(error('invalid_archive_password', 400));
        return cors(await internal(env, {...input, action: 'password', password: data.password}));
      }
      if (request.method !== 'GET' || route[3]) return cors(error('not_found', 404));
      return cors(await internal(env, {...input, action: route[1] === 'jobs' ? 'status' : 'report'}));
    } catch {return cors(error('request_or_configuration_invalid', 400));}
  },
};
