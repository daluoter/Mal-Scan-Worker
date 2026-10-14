# Keyless demo dispatcher

This small Cloud Run HTTP service dispatches Jobs without a Cloudflare-held Google
service-account private key. The project policy disabling key creation remains
enabled; an earlier key-based setup was rejected and no key was created. It uses
the attached `malscan-v2-demo-invoker` service account's metadata access token. It needs only that account's existing single-Job dispatch permission
and read access to the existing `malscan-v2-control-hmac:1` secret.

Build from the repository root using the dispatcher directory as source context
and a unique `_RELEASE`:

```bash
V2_DISPATCHER_RELEASE="dispatch-$(date -u +%Y%m%dT%H%M%SZ)"
gcloud builds submit deployment/dispatcher \
  --project=malscan-v2-poc --region=us-central1 \
  --config=deployment/dispatcher/cloudbuild.yaml \
  --substitutions="_RELEASE=$V2_DISPATCHER_RELEASE" --async
```

The directory context avoids the main application's source-upload exclusions.
It publishes a separate `demo-dispatcher` image. The existing analysis Job image
does not need rebuilding.

Required service environment:

| Variable | Value for this demo |
| --- | --- |
| `GCP_PROJECT` | `malscan-v2-poc` |
| `GCP_REGION` | `us-central1` |
| `GCP_JOB` | `malscan-v2-static-demo` |
| `CONTROL_ORIGIN` | `https://malscan-v2-demo-control.daluoter.workers.dev` |
| `CONTROL_HMAC_SECRET_FILE` | `/secrets/control/key` |

Mount `malscan-v2-control-hmac:1` at `/secrets/control/key`. The file contains the
existing 64-character hexadecimal secret, which is decoded to 32 HMAC key bytes.
Use request-based billing, 1 CPU, 256Mi, minimum instances 0, maximum instances 1,
concurrency 1, request timeout 60 seconds. Expose HTTPS publicly because the
Cloudflare caller has no Google identity; every dispatch is authenticated in the
application. Do not change organization policies if public services are forbidden.
Only `GET /health` is unauthenticated and it exposes no configuration or secrets.

## Verified deployment and updates

The deployed service is `malscan-v2-dispatcher` in `us-central1`. Revision
`malscan-v2-dispatcher-00003-z2d` was Ready and served the first successful v2
browser upload on 2026-10-14 (Asia/Taipei). Its fixed Worker origin is configured
above. Use the service's `status.url` as the Worker's `GCP_DISPATCH_URL`, without
`/dispatch`; neither the frontend nor browsers call this service directly.

Wait for a submitted build to finish `SUCCESS`, then read its published digest.
When updating only dispatcher code, use `gcloud run services update` with that
immutable `demo-dispatcher@sha256:...` image and preserve the existing runtime
identity, HMAC Secret mount and resource settings. Do not rebuild the analyzer,
create another key, or recreate the service. Cloud Build and Cloud Run continue
independently of Cloud Shell; reconnect and query the original build/execution ID.
Detailed deployment and IAM commands are in the [Cloud Run guide](../cloud-run/README.md).

The transport explicitly identifies itself as
`User-Agent: MalScanWorker-dispatcher/1.0`. This is required for the deployed
Cloudflare claim callback: its Browser Integrity protection rejected Python's
default urllib signature with error 1010 before authentication. Keep this header
and the existing HMAC/claim checks; do not disable Cloudflare protection.

## Dispatch protocol

`POST /dispatch` accepts a JSON envelope no larger than 16KiB:

```text
{payload: <exact canonical JSON string>, hmac_sha256: <64 lowercase hex>}
HMAC input = UTF8("malscan:v2:dispatch\n") || UTF8(payload)
```

The payload has exactly these keys: `dispatch_version`, `job_name`, `issued_at`,
`expires_at`, `job_id`, `attempt_id`, `dispatch_id`, `sequence`, `manifest_key`,
`control_key`, `status_key`, and `report_key`. Times are epoch milliseconds; the
validity window is at most 120 seconds. Only version 1, the configured Job, UUID4
identities, integer sequences from 1 through 999999999, and the existing
deterministic R2 paths are accepted. Issue times may be at most five seconds in
the future. Additional overrides, targets, URLs, or environment variables are
rejected before any upstream call. Authentication covers the exact payload
bytes; the service never parses and reserializes them for signature checking.

After obtaining a metadata token, the service sends the same exact payload string
to the fixed `CONTROL_ORIGIN + /internal/dispatch/claim` endpoint, signed with the
separate domain `malscan:v2:dispatch-claim\n`. The Worker/DO must atomically permit
only one claim for that current reserved dispatch and exact request hash. A valid
claim response is exactly:

```text
{claimed: true, dispatch_id: <same UUID>, request_sha256: <SHA256 exact payload>}
```

Only after this response does the service call the configured Google `:run` API
once, with one task and exactly the eight existing `MALSCAN_*` reference/identity
overrides. It returns only the validated Google operation name. Metadata, claim,
and Google timeouts are respectively 5, 10, and 20 seconds. All HTTP calls disable
redirects, inherited proxies, and automatic retries. No request-supplied URL is
ever fetched. The service does not log request paths, bodies, signatures, tokens,
or passwords.

The guarantee is one startup attempt per durable claim, not exactly-once delivery.
If the claim response, Google response, or service process is lost, execution may
remain `dispatch_uncertain`. The control plane must not blindly retry it. Claim
consumption is durable in the existing DO; no local filesystem or process memory
is used for idempotency. Min/max instance settings are cost controls, not the
duplicate-execution protection. Invalid public requests can still consume billed
HTTP resources; this deployment does not guarantee a zero bill.

Run the offline protocol and local HTTP tests:

```bash
cd deployment/dispatcher
python3 -m unittest -v test_dispatcher.py
```

The milestone rerun passed all 17 tests, including an actual local HTTP check of
the explicit User-Agent header. The tests never access Google or Cloudflare. Test
credentials are inert generated values. The one-time-claim simulation validates that a fresh dispatcher process
also refuses a repeated dispatch; real atomic claim behavior is tested separately
in the Worker/DO integration tests.
