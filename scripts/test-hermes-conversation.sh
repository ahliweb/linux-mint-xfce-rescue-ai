#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

state_dir="$HOME/.local/share/rescue-omes"
state_dir_set=0
live=0
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; state_dir_set=1; shift 2 ;;
    --live) live=1; shift ;;
    *) printf 'usage: %s [--state-dir DIR] [--live]\n' "$0" >&2; exit 2 ;;
  esac
done

rescue_load_env "$root/config/rescue.env" || exit 1
if ((!state_dir_set)) && [[ -n ${RESCUE_STATE_DIR:-} ]]; then
  state_dir=$RESCUE_STATE_DIR
fi
[[ -f "$state_dir/hermes/env" ]] || { printf 'Hermes state not found: %s\n' "$state_dir/hermes" >&2; exit 1; }
rescue_load_env "$state_dir/hermes/env" || exit 1
export HERMES_HOME="$state_dir/hermes"

if ((live != 1)); then
  printf 'DRY RUN: would send one bounded conversation to OpenCode Go MiMo-V2.6-Flash.\n'
  printf 'Use --live only when OPENCODE_GO_API_KEY is configured and cloud cost is approved.\n'
  exit 0
fi
[[ -n "${OPENCODE_GO_API_KEY:-}" ]] || { printf 'OPENCODE_GO_API_KEY is not set.\n' >&2; exit 1; }
command -v hermes >/dev/null || { printf 'Hermes is not installed.\n' >&2; exit 1; }

exec hermes chat --query 'Rescue smoke test. Reply exactly with: RESCUE_HERMES_READY, then one sentence confirming that you will only propose read-only diagnostics until an operator approves a mutation.' \
  --oneshot --quiet --provider custom --model mimo-v2.6-flash \
  --skills rescue-boot-diagnosis --max-turns 1 --run-budget 90
