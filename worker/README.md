# MalScan Worker

The v2 worker uses one static analysis core for self-hosted queue workers,
one-shot local analysis, and Cloud Run Jobs. It records evidence, artifact
ancestry, stage coverage, resource limits and partial results in
`mswr-report-v3`. A completed execution does not imply that every format or stage
was supported. See the [support matrix](../docs/analysis-support.md) and
[architecture](../docs/v2-architecture.md).

## Runtime entry points

| Entry point | Purpose |
| --- | --- |
| `python -m malscan_worker.main` | Self-hosted static worker consuming `malscan.jobs`; uses PostgreSQL, RabbitMQ and MinIO |
| `python -m malscan_worker.sandbox_main` | Separate self-hosted dynamic worker consuming `malscan.jobs.sandbox` |
| `python -m malscan_worker.runtime` | Portable static root batch using explicit local or S3-compatible stores; no broker or database required |
| `python -m malscan_worker.runtime.cloud_entrypoint` | Cloud Job adapter reading a validated manifest and private signed control; used by the full-worker image |

The portable runner recursively analyzes a root and its descendants in the same
bounded batch. It does not create a Cloud Run Job per extracted file. The cloud
demo is static-only; dynamic analysis is explicitly `disabled` in its report.
Do not execute the cloud entry point without the control plane's per-execution
references. Deployment instructions are in the [Cloud Run guide](../deployment/cloud-run/README.md).

## Static pipeline

1. Parallel `file-type`, `clamav`, `yara`, `ioc-extract` and `deobfuscation` stages.
2. `format-analysis` selects a format analyzer through `AnalyzerRegistry`.
3. `archive-extract` and `document-analysis` extract descendants and retain their
   source relationships. Self-hosted analysis may then defer to `sandbox`.

`file-type` uses python-magic/libmagic. ClamAV invokes `clamscan`; YARA uses the
memory-resident **yara-python library**, not a YARA CLI subprocess. A stage records
its tool and rules version when available and reports skipped, failed or partial
coverage with a reason. Missing rules or parser dependencies are not recorded as
successful scans. `analysis.static` and `analysis.dynamic` have independent states.

Root budgets accumulate extracted file count and bytes across the whole tree and
across password recovery. Depth and execution deadlines are bounded separately.
Extraction runs inside a killable process group; attempt fencing prevents stale
results from overwriting a newer execution. Same-name archive entries retain
ordinal identities instead of overwriting one another. See the architecture for
the PostgreSQL and portable accounting adapters.

A password-required artifact can be resumed while already completed stages remain
in its checkpoint. The report remains readable while waiting. Passwords are not
included in reports or checkpoints. Cloud controls carry them in private signed
R2 objects that the runner deletes after verified read, not environment overrides.

## Tool and detection content versions

The initial live cloud report used ClamAV engine `1.4.3`, database `28153` with a
2026-10-14 database timestamp, and yara-python `4.5.4`. These are recorded versions
from that image, not a promise of the latest upstream release.

The bundled YARA baseline contains five files and fifteen rules. Its reported
SHA256 fingerprints the rule filenames and bytes; it is separate from the YARA
library version. This is a small project rule set, not a comprehensive community
feed. A versioned manifest now records file/rule inventory, hashes, repository
origin, test/heuristic categories and limitations. Local verification checks
consistency, not author identity or accuracy. No rule license is currently
declared (`NOASSERTION`); external-feed acquisition and licensing remain open.
The [static quality baseline](../docs/static-quality.md) records 18 synthetic
cases, including two known benign-rule hits, and runs the real shared pipeline.

The `cloud-job` Docker target updates and verifies signed ClamAV databases during
build. Build/runtime checks reject a daily CVD older than seven days. There is no
automatic daily refresh schedule yet: deploy a newly built immutable image before
the retained database expires. A stale database produces failed AV coverage.

## Format analyzers

`AnalyzerRegistry` selects the first analyzer whose `can_handle(...)` accepts the
file MIME/magic. The current priority order is PE, Office adapter, PDF, LNK and
script. Office reuses document parsing through `OfficeAnalyzerAdapter`; results
appear under `results.format_analysis`, with legacy `results.document_analysis`
retained where applicable. Extracted artifacts enter the same recursive pipeline.

Supported depth varies by format. The matrix covers ZIP/7z/RAR/TAR/gzip/bzip2,
Office, PDF, PE, LNK and scripts together with their tool requirements and limits.
Encrypted Office/PDF decryption, ISO extraction, ELF/Mach-O/email/APK dedicated
deep analysis, PDF JavaScript emulation, full LNK extra-data semantics and
cross-format attack-chain correlation are not complete.

## Optional dynamic analysis

The default is `SANDBOX_ENABLED=false` and `SANDBOX_PROVIDER=capev2`. Static
analysis can publish a partial report before a dynamic task completes. A separate
sandbox worker retrieves provider results, stores normalized process, file,
registry, network and available artifact references, and updates the same report.

Configure a real CAPE host, analysis guest/snapshot and isolated network, then use
[`scripts/enable-sandbox.sh`](../scripts/enable-sandbox.sh). Its read-only preflight
checks CAPE API access and an available registered guest before enabling workers;
it does not provision CAPE, boot the guest or prove a real detonation. Live CAPE
end-to-end acceptance remains outstanding.

Important settings include:

- `SANDBOX_ENABLED`, `SANDBOX_PROVIDER`
- `SANDBOX_BASE_URL`, `SANDBOX_API_TOKEN`
- `SANDBOX_TIMEOUT_SECONDS`, `SANDBOX_POLL_INTERVAL_SECONDS`
- `SANDBOX_ENABLE_URL_SUBMISSION` (explicit self-hosted opt-in)
- `RABBITMQ_SANDBOX_QUEUE`

Unavailable providers, timeouts, circuit failures and report errors remain
`failed` or `unavailable`. **There is no automatic fallback to mock.** The `mock`
provider is an explicit development choice: its results are synthetic,
`executed=false`, and do not contribute real dynamic risk evidence.

Submission state and known CAPE task IDs are persisted. Redelivery polls a known
task instead of resubmitting. An unknown submission result without a task ID, or
a response containing multiple task IDs, requires reconciliation rather than an
automatic new detonation. Multi-task aggregation and dropped-file static
reanalysis remain future work.

## Development and verification

Install the OS tools and services documented in the repository setup before
running a queue worker. From this directory:

```bash
poetry install
poetry run pytest --asyncio-mode=auto
poetry run ruff check src tests
poetry run mypy src
```

A standalone local analysis uses the same stages:

```bash
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/sample.zip --output-dir ./analysis
# Resume a waiting root archive; the password is prompted with hidden input.
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/sample.zip --output-dir ./analysis --resume --ask-password
```

S3 checkpoints require an executor HMAC key supplied through a file; keep the
store, manifest and identity unchanged when resuming. Read `--help` for explicit
source/result store configuration and artifact-specific password prompts.

Use PostgreSQL opt-in tests only with their documented disposable fixtures;
`MALSCAN_TEST_POSTGRES_URL` must never point to retained application data. Native
7z/ClamAV and full-container checks exercise external tools beyond unit tests.
The [validation record](../docs/v2-validation.md) distinguishes the latest local
rerun, earlier PostgreSQL/container evidence and first live cloud report. A
single benign cloud report does not replace large-file, password recovery,
retention, cost or live sandbox acceptance.
