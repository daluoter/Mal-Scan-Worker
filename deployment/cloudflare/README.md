# Static demo control plane

This Worker is a separate deployment from the existing upload-only PoC. It
streams sources to R2 and dispatches a **new full-worker Cloud Run Job** through
a small Cloud Run dispatcher whose runtime service identity calls the Jobs API.
The Job command is `python -m malscan_worker.runtime.cloud_entrypoint`. The old PoC
engine image only runs engine controls and cannot serve this API.

The application report contract is `mswr-report-v3`. Analysis, extraction,
password recovery, scoring and report assembly remain in the shared Python
worker. SQLite Durable Objects store admission counters, ticket hashes, job
ownership and dispatch identities, not a second analysis database.

## Deployment milestone

On 2026-10-14 (Asia/Taipei), a benign 13-byte `hello.txt` uploaded through the
production Pages site completed the full v2 application path and produced a
complete static report with dynamic analysis disabled. The production frontend
origin is `https://malscan-v2-demo.pages.dev`; the API is
`https://malscan-v2-demo-control.daluoter.workers.dev`. A Pages deployment preview
has a different origin and is not permitted by the production CORS policy.
See the [milestone record](../../docs/milestones/2026-10-15-cloud-demo.md) for the
execution ID, timing, tool versions, and remaining live acceptance cases.

The checked-in `wrangler.jsonc` intentionally keeps `PUBLIC_UPLOADS=false` and
placeholder origins. Review and fill a deployment configuration before using
`wrangler deploy`; pushing source to GitHub does not update the deployed Worker.
Do not replace an activated deployment with the unmodified template.

## Local verification

Use Node 22 or newer and run `npm ci && npm test` in this directory. The lockfile
also pins Wrangler for deployment. Tests run the real workerd runtime,
SQLite Durable Objects and local R2. External dispatch and Google endpoints use
local test stubs; the tests do not prove live GCP permissions, Cloudflare CPU limits,
Cloud Run scheduling, or zero billing. There is no production test endpoint. The milestone rerun passed 23 cases with
the real Python container fixture supplied; without that opt-in fixture, its
specific test is reported as skipped.

An optional cross-runtime check consumes untouched reports and HMAC envelopes
from `deployment/cloud-run/verify-local-image.py` (three fresh local containers,
real S3-compatible storage, and the shared pipeline):

```bash
MALSCAN_RUNNER_FIXTURE_DIR=/absolute/path/to/smoke/RUN_ID node --test test/runner-fixture.test.mjs
```

This fixture uses the documented public test key only. It verifies real Python
output through workerd's ownership/hash/signature/report gate. It does not call
Google or prove live cloud deployment. The optional test skips when no fixture
directory is supplied.

## Deployment configuration

Review the example project/buckets and fill the origin in `wrangler.jsonc`; use distinct **private** source and
result buckets. Point the frontend at this Worker with
`VITE_API_DEPLOYMENT=cloud-demo` and its API URL. Set `ALLOWED_ORIGIN` to the
frontend's exact HTTPS origin. Keep `PUBLIC_UPLOADS=false` until the image,
secrets, IAM, quotas and lifecycle policy are installed; enabling intake is an
explicit deployment setting. The API has no public list or object-read route.

The Worker requires one server-side secret, `CONTROL_HMAC_KEY`: a random 256-bit
value encoded as exactly 64 lowercase hex characters. Mount the same hex string
at `/secrets/control/key` in the runner and dispatcher; each implementation
decodes hex to the HMAC key. Enter it through the secret setup helper, never the
config, browser, command arguments or chat. Control objects, dispatcher requests
and claim callbacks use distinct signing purposes.

Set `GCP_DISPATCH_URL` to the deployed service's HTTPS origin (`status.url`,
without `/dispatch` or any other path; the Worker adds `/dispatch`) and keep
`GCP_PROJECT`, `GCP_REGION` and `GCP_JOB` fixed. The dispatcher uses
`malscan-v2-demo-invoker@malscan-v2-poc.iam.gserviceaccount.com` as its Cloud Run
service identity. It obtains short-lived OAuth credentials from the Google
metadata server and can run only the configured Job. Grant it access to only
the control HMAC Secret; it does not need either R2 credential.

This deployment uses no Google service-account private key or
`GCP_INVOKER_JSON`. The project's `constraints/iam.disableServiceAccountKeyCreation`
policy remains enabled. Do not run `store-invoker-secret.py` or retry key creation.
Workers does not provide a verified native workload OIDC issuer in this setup;
Wrangler's user login and Worker version metadata are not Google federation
credentials. See [Cloud Run deployment](../cloud-run/README.md) for the keyless
service and IAM commands.

The Cloud Run Job needs a source-bucket read credential and a result-bucket
read/write credential mounted through Secret Manager, using JSON keys
`access_key_id` and `secret_access_key`. Keep both buckets private. The runner
does not need dispatcher credentials. Use an immutable full-worker image
digest, one task, parallelism one, zero automatic task retries, and a bounded
timeout. Cloud Run overrides require the `run.jobs.runWithOverrides` permission
in addition to `run.jobs.run`; ordinary invoker permission alone is insufficient.

The deployed Job supplies:

```
MALSCAN_R2_ENDPOINT=https://ACCOUNT.r2.cloudflarestorage.com
MALSCAN_UPLOAD_BUCKET=SOURCE_BUCKET
MALSCAN_RESULT_BUCKET=RESULT_BUCKET
MALSCAN_R2_READ_SECRET_FILE=/secrets/source/credentials.json
MALSCAN_R2_RESULT_SECRET_FILE=/secrets/results/credentials.json
MALSCAN_HMAC_SECRET_FILE=/secrets/control/key
```

The Worker supplies only non-secret per-execution overrides:
`MALSCAN_MANIFEST_KEY`, `MALSCAN_CONTROL_KEY`, `MALSCAN_STATUS_KEY`,
`MALSCAN_ROOT_JOB_ID`, `MALSCAN_ATTEMPT_ID`, `MALSCAN_REPORT_KEY`,
`MALSCAN_DISPATCH_ID` and `MALSCAN_SEQUENCE`.

## HTTP client identification

A Python client using its default `Python-urllib` User-Agent was rejected by
Cloudflare Browser Integrity with a plain-text HTTP 403 / error 1010 before it
reached this Worker's authentication or CORS checks. Diagnostics should identify
their application, for example `User-Agent: MalScanWorker-control-check/1.0`.
The deployed dispatcher sets `MalScanWorker-dispatcher/1.0` for its authenticated
claim callback. This does not bypass authorization: an invalid callback HMAC
still returns the Worker's JSON 401 response. Keep the exact-origin CORS and
Cloudflare protections enabled.

## Browser API

1. `GET /api/v1/capabilities` advertises `raw-ticket`, bearer job ownership,
   polling rather than SSE, the 20,000,000-byte limit, and disabled dynamics.
2. `POST /api/v1/upload-tickets` with `{filename,bytes,sha256}` admits one job
   and returns `{token,capability_token,job_id,expires_at,max_bytes}`. The SHA256
   covers the original file. Filename is metadata, never an object path.
3. `POST /api/v1/files` with the raw file, `application/octet-stream`, its
   browser-generated `Content-Length`, and `Authorization: Bearer <token>`.
   Tickets expire after five minutes and cannot be reused, including after a
   failed upload. Each upload stream has a five-minute deadline, bounded further
   by root retention. R2 verifies the declared SHA256 natively; the Worker does not
   buffer or hash the file. Save the ownership capability before uploading.
4. Use `Authorization: Bearer <capability_token>` for job polling and report
   retrieval. The capability must not appear in URLs, log output or analytics. The
   frontend retains it in `sessionStorage` before uploading; use the same browser
   tab, including after a refresh. Closing the tab can discard access. Do not
   upload again merely because a request or Cloud Shell connection was lost;
   first follow the existing job and reconcile an uncertain dispatch.
5. A password-required artifact can be resumed through
   `POST /api/v1/jobs/<artifact_uuid>/password` with `{password}` and the same
   root capability. Only currently signed password-required targets are
   accepted. The password is sent in a private signed R2 control object,
   never a job environment value. The runner deletes it after verified read.

Tickets are bound to byte count, hash and filename. Admission is deliberately
limited globally: `DAILY_JOB_LIMIT` counts issued tickets (including abandoned
ones); `DAILY_EXECUTION_LIMIT` counts every reserved execution, including
password submissions. Each file has its own allowance of three accepted
password submissions. A successful ZIP submission consumes one ZIP allowance;
its encrypted PDF child starts with three separate submissions. Reaching one
file's limit does not prevent another waiting file from being resumed. Both
successful and unsuccessful submissions count, because each starts an execution.
Defaults are ten admissions and twenty executions per UTC day. Execution
reservations are also capped at forty per UTC calendar month through
`MONTHLY_EXECUTION_LIMIT`, including ambiguous starts and password resumes.
Keep the deployment's task count, CPU, memory and timeout fixed when estimating
its maximum monthly resource use. Free allowances are shared across the billing
account, and registry, secrets, logs and storage may have their own charges.
These controls limit spend; they do not guarantee availability against public quota exhaustion
or guarantee a free invoice. Intake can be disabled without deleting resources.

Job status includes `password_attempts_scope:"artifact"`,
`password_attempt_limit:3`, and `password_attempts_by_artifact`, whose values are
`{attempts_used,attempts_remaining,limit}`. The scalar `password_attempts` and
`password_attempts_remaining` describe the requested file: root status describes
the original upload, while a password POST response describes its target file.
The browser projects child status from the authorized root snapshot and this
map; child GET routes do not gain access solely from knowing an artifact ID.
`total_password_submissions` retains the root aggregate for auditing.

On the first upgrade from the previous root-wide policy, SQLite preserves that
aggregate and snapshots it as `legacy_password_submissions`. Historical controls
have already been deleted, so those old submissions cannot be assigned truthfully
to specific files. Their per-file ledger starts empty once; later Worker reloads
preserve every new per-file count. Daily and monthly execution counters retain
all previous reservations. Invalid targets, exhausted files and admission-quota
rejections do not consume an additional password submission or execution.

## Runner protocol and recovery

`UPLOADS/manifests/<root>/<attempt>.json` uses `AnalysisManifest` version 1.
Its SHA256 uses Python-compatible sorted compact JSON with ASCII escapes.
The same attempt and manifest survive password recovery. Each execution uses
a new `dispatch_id` and increasing `sequence`.

`RESULTS/controls/<root>/<dispatch>.json` has the envelope
`{payload: <JSON string>, hmac_sha256: <hex>}`. HMAC-SHA256 covers the exact UTF8
payload string. Its payload is:

```json
{
  "control_version": 1,
  "manifest_sha256": "SHA256",
  "checkpoint_key": "checkpoints/ROOT/ATTEMPT.json",
  "resume": false,
  "passwords": {},
  "password_attempts_by_artifact": {},
  "password_attempt_limit": 3,
  "password_attempts_scope": "artifact",
  "status_key": "statuses/ROOT/DISPATCH.json",
  "dispatch_id": "DISPATCH",
  "sequence": 1,
  "expires_at": 1791849600000
}
```

Unlike the browser status map, the private control's
`password_attempts_by_artifact` maps each file ID directly to an integer count.
It includes the currently reserved submission. After a third wrong password the
runner finalizes that file as limited, preserves its partial evidence, and keeps
other waiting or runnable files independent. Older signed controls without the
new optional fields remain readable during an ordered rollout.

The runner writes the same envelope form at `status_key`. Its payload contains
`status_version:1`, `job_id`, `attempt_id`, `dispatch_id`, `sequence`,
`manifest_sha256`, `status`, `report_key`, `report_sha256`,
`password_required_artifacts` and `error_code`. Status is `scanning`,
`password_required`, `done` or `failed`. Before a report exists, both report
fields are null. Published snapshots use immutable
`reports/<root>/<attempt>/<dispatch>/<revision>.json` keys; SHA256 covers exact
stored report bytes. The Worker verifies signature, dispatch identity, manifest
fingerprint, private report prefix, hash and report schema/attempt identity
before returning any report.
After verifying the immutable snapshot, the API overlays only current control
metadata (`job_status`, `report_complete`, `control_error_code`,
`execution_active`, `requires_reconciliation`). A failed attempt can still
return its last verified partial snapshot; analysis coverage, evidence and
tool results are preserved. An uncertain dispatch has unknown execution state
and requires reconciliation, rather than being treated as a clean result.

The Durable Object reserves dispatch **before** making external calls. The
dispatcher verifies a short-lived HMAC request and claims that exact persisted
dispatch through a separate authenticated callback to this Worker. The Durable
Object atomically allows one claim for that dispatch and request identity. A
replayed request cannot cause a second Jobs API call, including after a dispatcher
restart; there is no in-memory-only nonce cache or extra GCS/Firestore ledger.
The callback remains available while public uploads are disabled, but requires
its server-side signature and matching current reservation. It is not a browser API.

Only after a successful claim does the dispatcher issue one Jobs request. It
accepts only the configured project, region, Job and validated per-execution
references, never caller-selected CPU, image or service account. A crash after
the claim and before a known Jobs response is uncertain; claim expiry does not
authorize another launch. If a Jobs response is uncertain, it does not retry: status exposes
`dispatch_uncertain=true` and `job_dispatch_uncertain`. A later valid signed
runner status can resolve that state. An operator must reconcile an execution
that fails before publishing status; browser retries never create a second job.
This is a visible operational error, not a synthetic analysis result.
If no completed signed status arrives within twenty minutes of a reservation,
polling exposes `analysis_status_timeout` without restarting the job. A valid
late completion can still resolve that uncertain state while retention lasts.

Retention defaults to 24 hours, configurable from 30 minutes to seven days.
`expires_at` is the fixed root retention deadline in epoch milliseconds, not a
new deadline per password retry. Expired ownership capabilities stop working
immediately, and a fresh durable expiry check precedes dispatch. The runner
rejects expired controls and guards every result write against the same expiry.
Durable Object alarms retain an inaccessible metadata tombstone for a twenty-
minute grace period, then delete root-specific source, manifest, control, status, checkpoint, artifact and
report prefixes, with bounded batches and retries. Add equivalent bucket
lifecycle rules as a fallback for prolonged control-plane failure. Do not put
unrelated retained data in these prefixes. No cleanup deletes buckets, secrets,
Cloud Run Job definitions or service accounts.

Dynamic analysis remains `disabled` in this cloud profile. Enable it only in
the self-hosted profile with a real, configured sandbox provider.

The dispatch service has public HTTPS reachability and authenticates requests
inside the application with HMAC. If organization policy refuses public service
access, stop rather than changing that policy. Invalid traffic can still start a
Cloud Run instance and incur charges; minimum instances zero, maximum instances
one, request CPU throttling and small request/time limits reduce exposure but do
not guarantee a free invoice. Keep the frontend pointed at this Worker, never
directly at the dispatcher.
