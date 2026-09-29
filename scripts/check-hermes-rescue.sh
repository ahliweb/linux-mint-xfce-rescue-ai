#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
state_dir=${RESCUE_STATE_DIR:-"$HOME/.local/share/rescue-omes"}
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
    *) printf 'usage: %s [--state-dir DIR]\n' "$0" >&2; exit 2 ;;
  esac
done

if [[ -f "$root/config/rescue.env" ]]; then
  # shellcheck disable=SC1091
  source "$root/config/rescue.env"
fi
if [[ -f "$state_dir/hermes/env" ]]; then
  # shellcheck disable=SC1091
  source "$state_dir/hermes/env"
fi
export HERMES_HOME="$state_dir/hermes"

fail=0
command -v hermes >/dev/null 2>&1 || { printf 'FAIL: Hermes executable not found\n'; fail=1; }
[[ -f "$HERMES_HOME/config.yaml" ]] || { printf 'FAIL: Hermes config missing: %s\n' "$HERMES_HOME/config.yaml"; fail=1; }
[[ -f "$HERMES_HOME/SOUL.md" ]] || { printf 'FAIL: Rescue SOUL.md missing\n'; fail=1; }
[[ -n "${OPENCODE_GO_API_KEY:-}" ]] || { printf 'WARN: OPENCODE_GO_API_KEY is not set\n'; fail=1; }

if [[ -f "$HERMES_HOME/config.yaml" ]]; then
  grep -Fq 'provider: custom' "$HERMES_HOME/config.yaml" || { printf 'FAIL: provider is not custom\n'; fail=1; }
  grep -Fq 'default: mimo-v2.6-flash' "$HERMES_HOME/config.yaml" || { printf 'FAIL: default model is not mimo-v2.6-flash\n'; fail=1; }
  grep -Fq 'https://opencode.ai/zen/go/v1' "$HERMES_HOME/config.yaml" || { printf 'FAIL: OpenCode Go base URL missing\n'; fail=1; }
fi

if command -v curl >/dev/null 2>&1 && [[ -n "${OPENCODE_GO_API_KEY:-}" ]]; then
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --max-time 15 -H "Authorization: Bearer ${OPENCODE_GO_API_KEY}" \
    https://opencode.ai/zen/go/v1/models || true)
  [[ "$status" =~ ^2|^3 ]] || { printf 'FAIL: provider endpoint returned HTTP %s\n' "$status"; fail=1; }
  printf 'OpenCode Go endpoint check: HTTP %s\n' "$status"
else
  printf 'Provider network check skipped because curl/key is unavailable.\n'
fi

if ((fail)); then
  printf 'Rescue Hermes check: NOT READY\n'
  exit 1
fi
printf 'Rescue Hermes check: READY (custom / mimo-v2.6-flash / OpenCode Go)\n'
