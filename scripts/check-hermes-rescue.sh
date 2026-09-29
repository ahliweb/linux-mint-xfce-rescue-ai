#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

state_dir="$HOME/.local/share/rescue-omes"
state_dir_set=0
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; state_dir_set=1; shift 2 ;;
    *) printf 'usage: %s [--state-dir DIR]\n' "$0" >&2; exit 2 ;;
  esac
done

rescue_load_env "$root/config/rescue.env" || exit 1
if ((!state_dir_set)) && [[ -n ${RESCUE_STATE_DIR:-} ]]; then
  state_dir=$RESCUE_STATE_DIR
fi
rescue_load_env "$state_dir/hermes/env" || exit 1
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
  key=${OPENCODE_GO_API_KEY}
  if [[ $key == *[[:cntrl:]]* ]]; then
    printf 'FAIL: OPENCODE_GO_API_KEY contains control characters\n'
    fail=1
    status=''
  else
    # The key is sent to curl as a config file on stdin so it never appears in
    # the process argument list (visible via ps). printf is a shell builtin.
    key=${key//\\/\\\\}
    key=${key//\"/\\\"}
    status=$(printf 'header = "Authorization: Bearer %s"\n' "$key" | curl --config - \
      --silent --show-error --output /dev/null --write-out '%{http_code}' \
      --max-time 15 https://opencode.ai/zen/go/v1/models || true)
    unset key
    [[ "$status" =~ ^[23] ]] || { printf 'FAIL: provider endpoint returned HTTP %s\n' "${status:-000}"; fail=1; }
    printf 'OpenCode Go endpoint check: HTTP %s\n' "${status:-000}"
  fi
else
  printf 'Provider network check skipped because curl/key is unavailable.\n'
fi

if ((fail)); then
  printf 'Rescue Hermes check: NOT READY\n'
  exit 1
fi
printf 'Rescue Hermes check: READY (custom / mimo-v2.6-flash / OpenCode Go)\n'
