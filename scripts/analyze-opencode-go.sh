#!/usr/bin/env bash
set -Eeuo pipefail

input=${1:?usage: analyze-opencode-go.sh EVIDENCE_JSON}
root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

# config/rescue.env is optional; the environment may already provide the settings.
rescue_load_env "$root/config/rescue.env" || exit 1

[[ -s "$input" ]] || { printf 'evidence file is missing or empty\n' >&2; exit 2; }
[[ -n "${OPENCODE_ADAPTER_COMMAND:-}" ]] || { printf 'OPENCODE_ADAPTER_COMMAND is not configured\n' >&2; exit 2; }

timeout_seconds=${OPENCODE_TIMEOUT_SECONDS:-120}
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || {
  printf 'OPENCODE_TIMEOUT_SECONDS must be a positive integer, got: %s\n' "$timeout_seconds" >&2
  exit 2
}

# Never send unvalidated evidence to the cloud adapter.
python3 "$root/scripts/validate-evidence.py" "$input" >&2 || {
  printf 'evidence failed schema validation; nothing was sent to the adapter\n' >&2
  exit 2
}

# Restricted evidence never leaves this machine.
if ! python3 -c 'import json,sys; sys.exit(json.load(open(sys.argv[1])).get("classification") == "restricted")' "$input"; then
  printf 'evidence is classified restricted; nothing was sent to the adapter\n' >&2
  exit 2
fi

# OPENCODE_ADAPTER_COMMAND is an explicit operator setting and is executed as-is
# by bash -c. It is never derived from model output, logs, filenames or web
# content. It receives the validated, sanitized JSON on stdin only.
timeout "$timeout_seconds" bash -c "$OPENCODE_ADAPTER_COMMAND" < "$input"
