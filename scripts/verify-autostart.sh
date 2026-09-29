#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

state_dir="$HOME/.local/share/rescue-omes"
state_dir_set=0
bin_dir=''
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; state_dir_set=1; shift 2 ;;
    --bin-dir) bin_dir=${2:?missing launcher directory}; shift 2 ;;
    *) printf 'usage: %s [--state-dir DIR] [--bin-dir DIR]\n' "$0" >&2; exit 2 ;;
  esac
done

rescue_load_env "$root/config/rescue.env" || exit 1
if ((!state_dir_set)) && [[ -n ${RESCUE_STATE_DIR:-} ]]; then
  state_dir=$RESCUE_STATE_DIR
fi

autostart="$HOME/.config/autostart/hermes-rescue.desktop"
[[ -f "$autostart" ]] || { printf 'FAIL: autostart file missing: %s\n' "$autostart"; exit 1; }

exec_line=''
while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line == Exec=* ]]; then exec_line=${line#Exec=}; break; fi
done < "$autostart"
[[ -n $exec_line ]] || { printf 'FAIL: autostart Exec line missing\n'; exit 1; }

launcher_part=${exec_line%%" --state-dir "*}
if [[ -n $bin_dir ]]; then
  expected_launcher=$(rescue_desktop_quote "${bin_dir%/}/launch-hermes-rescue.sh") || { printf 'FAIL: unsupported launcher path\n'; exit 1; }
  [[ $launcher_part == "$expected_launcher" ]] || { printf 'FAIL: autostart launcher mismatch\n'; exit 1; }
else
  [[ $launcher_part == *launch-hermes-rescue.sh || $launcher_part == *launch-hermes-rescue.sh\" ]] || { printf 'FAIL: autostart launcher missing\n'; exit 1; }
fi

expected_state=$(rescue_desktop_quote "$state_dir") || { printf 'FAIL: state path contains an unsupported character (newline or %%)\n'; exit 1; }
fragment=" --state-dir $expected_state"
if [[ $exec_line != *"$fragment" && $exec_line != *"$fragment "* ]]; then
  printf 'FAIL: autostart state path mismatch\n'
  exit 1
fi
printf 'Autostart configuration: PASS\n'
printf 'A reboot test must be performed on the live PC; after login run: command -v hermes; pgrep -af "hermes.*mimo-v2.6-flash"\n'
