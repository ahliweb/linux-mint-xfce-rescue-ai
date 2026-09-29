#!/usr/bin/env bash
set -Eeuo pipefail

state_dir=${RESCUE_STATE_DIR:-"$HOME/.local/share/rescue-omes"}
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
    *) printf 'usage: %s [--state-dir DIR]\n' "$0" >&2; exit 2 ;;
  esac
done

autostart="$HOME/.config/autostart/hermes-rescue.desktop"
[[ -f "$autostart" ]] || { printf 'FAIL: autostart file missing: %s\n' "$autostart"; exit 1; }
grep -Fq '/usr/local/bin/launch-hermes-rescue.sh' "$autostart" || { printf 'FAIL: autostart launcher missing\n'; exit 1; }
grep -Fq -- "--state-dir $state_dir" "$autostart" || { printf 'FAIL: autostart state path mismatch\n'; exit 1; }
printf 'Autostart configuration: PASS\n'
printf 'A reboot test must be performed on the live PC; after login run: command -v hermes; pgrep -af "hermes.*mimo-v2.6-flash"\n'
