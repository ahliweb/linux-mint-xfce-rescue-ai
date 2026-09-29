#!/usr/bin/env bash
set -Eeuo pipefail

input=${1:?usage: analyze-opencode-go.sh EVIDENCE_JSON}
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$root/config/rescue.env"

[[ -s "$input" ]] || { printf 'evidence file is missing or empty\n' >&2; exit 2; }
[[ -n "${OPENCODE_ADAPTER_COMMAND:-}" ]] || { printf 'OPENCODE_ADAPTER_COMMAND is not configured\n' >&2; exit 2; }

# The command is intentionally operator-configured. It receives sanitized JSON only.
timeout "${OPENCODE_TIMEOUT_SECONDS:-120}" bash -c "$OPENCODE_ADAPTER_COMMAND" < "$input"
