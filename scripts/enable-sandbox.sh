#!/usr/bin/env bash
# Enable the existing CAPE integration after a read-only check. No VMs are built.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/enable-sandbox.sh [--allow-mock]

Configure SANDBOX_BASE_URL and SANDBOX_API_TOKEN in .env or the environment first.
The default provider is capev2. A configured CAPE host with an unlocked guest is
required; this command checks access but does not boot or provision a VM.

Development only: SANDBOX_PROVIDER=mock scripts/enable-sandbox.sh --allow-mock
USAGE
}

allow_mock=false
if (( $# > 1 )); then
  usage >&2
  exit 2
fi
if (( $# == 1 )); then
  case "$1" in
    --allow-mock) allow_mock=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
fi

provider="${SANDBOX_PROVIDER:-capev2}"
case "$provider" in
  capev2) ;;
  mock)
    if [[ "$allow_mock" != true ]]; then
      printf '%s\n' 'Mock requires --allow-mock and produces synthetic data only.' >&2
      exit 2
    fi
    ;;
  *) printf '%s\n' 'Unsupported sandbox provider.' >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Docker Compose v2 is required.' >&2
  exit 1
fi

script_directory="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$script_directory/.."
export SANDBOX_ENABLED=true
# Override legacy .env mock defaults; mock requires an explicit shell selection.
export SANDBOX_PROVIDER="$provider"

if [[ "$provider" == mock ]]; then
  printf '%s\n' 'Development mock selected: no real dynamic analysis will run.' >&2
else
  docker compose run --build --rm --no-deps sandbox-preflight
fi

docker compose --profile sandbox up --build -d worker sandbox-worker
