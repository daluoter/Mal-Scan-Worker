# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS worker-base

WORKDIR /app

# Install system dependencies.
# company_ca is optional and is only used during this build step.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt update; \
        apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt install -y --no-install-recommends \
            libmagic1 \
            unar; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            libmagic1 \
            unar; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Install Poetry.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        PIP_CERT=/tmp/build-ca.crt \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            pip install poetry; \
    else \
        pip install poetry; \
    fi

# Copy backend package first (worker has a path dependency on malscan-api)
COPY backend/ /backend

# Copy worker dependency files
COPY worker/pyproject.toml worker/poetry.lock* ./

# Install dependencies.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            poetry config virtualenvs.create false; \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            poetry install --only main --no-root --no-interaction --no-ansi; \
    else \
        poetry config virtualenvs.create false; \
        poetry install --only main --no-root --no-interaction --no-ansi; \
    fi

# Copy worker source code
COPY worker/src/ ./src/

# Copy YARA rules
COPY worker/rules/ /etc/yara/rules/

ENV PYTHONPATH=/app/src

EXPOSE 9090

CMD ["python", "-m", "malscan_worker.main"]

# Build signed databases separately; no updater runs during analysis jobs.
# This immutable official manifest is the same verified source used by the PoC.
FROM clamav/clamav@sha256:ebec5bc138401b36ae987caa1a3fa3c3b2a21ed3d51f0bfa5852825e663e67b0 AS signatures
USER root
ARG SIGNATURE_REFRESH=initial
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    printf 'Signed database refresh: %s\n' "$SIGNATURE_REFRESH"; \
    trap 'rm -f /tmp/build-ca.pem /tmp/build-freshclam.conf' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/company_ca > /tmp/build-ca.pem; \
      chmod 0644 /tmp/build-ca.pem; \
      export CURL_CA_BUNDLE=/tmp/build-ca.pem; \
    fi; \
    printf '%s\n' \
      'DatabaseDirectory /var/lib/clamav' \
      'DatabaseOwner clamav' \
      'DatabaseMirror database.clamav.net' \
      'ScriptedUpdates no' \
      'MaxAttempts 1' \
      'ConnectTimeout 15' \
      'ReceiveTimeout 60' \
      'TestDatabases yes' \
      'Bytecode yes' > /tmp/build-freshclam.conf; \
    timeout 300 freshclam --no-dns --config-file=/tmp/build-freshclam.conf; \
    for database in main daily bytecode; do \
      test -s "/var/lib/clamav/$database.cvd"; \
      sigtool --info "/var/lib/clamav/$database.cvd"; \
    done

# Opt-in one-shot target: the full shared pipeline, not the control-only PoC.
FROM worker-base AS cloud-job
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/company_ca > /tmp/build-ca.crt; \
      apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt update; \
      apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt install -y --no-install-recommends clamav; \
    else \
      apt-get update; \
      apt-get install -y --no-install-recommends clamav; \
    fi; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --uid 10001 --user-group --create-home malscan
COPY --from=signatures /var/lib/clamav/*.cvd /var/lib/clamav/*.cvd.sign /var/lib/clamav/
RUN set -eu; \
    chmod -R a+rX /app/src /backend /etc/yara/rules; \
    for database in main daily bytecode; do sigtool --info "/var/lib/clamav/$database.cvd"; done; \
    python -c 'import pathlib,time; fields=pathlib.Path("/var/lib/clamav/daily.cvd").open("rb").read(512).decode("ascii").strip().split(":"); assert fields[0]=="ClamAV-VDB" and 0<=time.time()-int(fields[8])<=604800, "daily database is stale"'; \
    chmod a+r /var/lib/clamav/*.cvd /var/lib/clamav/*.cvd.sign
ENV CLAMAV_MODE=cli CLAMAV_DATABASE_PATH=/var/lib/clamav CLAMAV_MAX_DATABASE_AGE_SECONDS=604800 SANDBOX_ENABLED=false
USER malscan
RUN python -c 'from malscan_worker.runtime.cloud_entrypoint import execute_cloud; from malscan_worker.pipeline import execute_analysis_stages'
CMD ["python", "-m", "malscan_worker.runtime.cloud_entrypoint"]

# Preserve the existing queue-worker build as the default target.
FROM worker-base AS worker
