# MalScan Frontend

React + TypeScript + Vite frontend for MalScan.

## Development

```bash
npm ci
npm run dev
```

## Pages

- `/` - Upload page
- `/jobs/:jobId` - Job status page
- `/reports/:jobId` - Report page

## Cloud demo build

Build against the separately deployed full-analysis control Worker:

```bash
VITE_API_DEPLOYMENT=cloud-demo \
VITE_API_BASE_URL=https://YOUR-DEMO-WORKER.workers.dev \
npm run build
```

Set the Worker's `ALLOWED_ORIGIN` to this frontend's exact HTTPS origin. The
browser needs HTTPS (or localhost for development) for the file SHA256 operation.
The demo accepts nonempty files up to **20,000,000 bytes**; self-hosted uploads
retain their own size limit. No Google, R2 or administrative secret belongs in
any `VITE_*` value or frontend build.

The cloud client requests a single-use upload ticket, saves the private root
capability in `sessionStorage` **before** sending the raw file, and polls the
root status with a bearer header. Cloud mode does not open an SSE connection.
Keep the upload tab open; refreshing that tab preserves its capability, while
closing it normally clears it. A public job ID alone cannot restore access.
If an upload response is lost, follow the existing-work link before retrying.
Capabilities are never placed in URLs.

Nested artifact links use the same root ownership capability. Signed
password-required artifact IDs determine which file can receive a password;
a root waiting on a child is not itself a password target. Cloud demo password
retries are limited to three **per root upload**, shared across nested files.
Previous results remain readable during recovery or a failed execution. A
dispatch with uncertain state keeps polling and displays its reconciliation
requirement instead of starting another job.

Reports expose static stage coverage, tool and rule versions, partial results,
artifact paths and independent dynamic-analysis state. Cloud dynamics remain
disabled. Self-hosted real sandbox reports show process, network and other
returned evidence; synthetic controls are explicitly marked and excluded from
real behavior presentation. Returned download references are displayed as inert
metadata rather than embedded external content.

## Checks

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

Transport tests exercise browser request shapes, capability preservation,
nested password routing and stale-report recovery with mocked HTTP responses.
They do not prove a live Cloudflare/Google deployment or sandbox execution.
