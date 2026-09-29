#!/usr/bin/env bash
set -Eeuo pipefail

state_dir=${RESCUE_STATE_DIR:-"$HOME/.local/share/rescue-omes"}
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
    --live) live=1; shift ;;
    *) printf 'usage: %s [--state-dir DIR] [--live]\n' "$0" >&2; exit 2 ;;
  esac
done

[[ -f "$state_dir/hermes/env" ]] || { printf 'Hermes state not found: %s\n' "$state_dir/hermes" >&2; exit 1; }
# shellcheck disable=SC1091
source "$state_dir/hermes/env"
export HERMES_HOME="$state_dir/hermes"

if [[ "${live:-0}" -ne 1 ]]; then
  printf 'DRY RUN: would send one bounded conversation to OpenCode Go MiMo-V2.6-Flash.\n'
  printf 'Use --live only when OPENCODE_GO_API_KEY is configured and cloud cost is approved.\n'
  exit 0
fi
[[ -n "${OPENCODE_GO_API_KEY:-}" ]] || { printf 'OPENCODE_GO_API_KEY is not set.\n' >&2; exit 1; }
command -v hermes >/dev/null || { printf 'Hermes is not installed.\n' >&2; exit 1; }

exec hermes chat --query 'Rescue smoke test. Reply exactly with: RESCUE_HERMES_READY, then one sentence confirming that you will only propose read-only diagnostics until an operator approves a mutation.' \
  --oneshot --quiet --provider custom --model mimo-v2.6-flash \
  --skills rescue-boot-diagnosis --max-turns 1 --run-budget 90
