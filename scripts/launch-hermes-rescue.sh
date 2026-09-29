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
export OPENCODE_GO_API_KEY="${OPENCODE_GO_API_KEY:-}"

[[ -d "$HERMES_HOME" ]] || { printf 'Hermes state not installed: %s\n' "$HERMES_HOME" >&2; exit 1; }
command -v hermes >/dev/null 2>&1 || { printf 'Hermes is not installed. Run install-hermes-rescue.sh first.\n' >&2; exit 1; }

exec hermes --tui --provider custom --model mimo-v2.6-flash
