#!/usr/bin/env bash
# Helpers for scripts/launch-hermes-rescue.sh (source, do not execute). Read-only: they only look at the
# default route and talk to the operator. See docs/hardware.md (network is advisory) and docs/persistence.md.
#
#   rescue_default_route             true when the kernel has a default route (ip, else /proc/net/route)
#   rescue_wait_for_route SECONDS    poll for a default route for at most SECONDS (0 = check once)
#   rescue_offline_prompt            bilingual prompt loop; returns 0 once a route exists, 1 to continue offline
#                                    (type L, EOF, or no answer within RESCUE_NET_PROMPT_TIMEOUT seconds)
#   rescue_pause_for_enter           wait for Enter; never hangs on EOF
#   rescue_journal_executed_ok J RID true when journal J has an execute/ok entry of run RID (python JSON parse)

rescue_default_route() {
  local found dest rest
  if command -v ip >/dev/null 2>&1; then
    found=$(ip route show default 2>/dev/null || true)
    [[ -n $found ]]
    return
  fi
  [[ -r /proc/net/route ]] || return 1
  while read -r _ dest rest; do
    [[ $dest == 00000000 && -n $rest ]] && return 0
  done < /proc/net/route
  return 1
}

rescue_wait_for_route() {
  local max=${1:-60} waited=0
  [[ $max =~ ^[0-9]+$ ]] || max=60
  while ! rescue_default_route; do
    ((waited >= max)) && return 1
    sleep 1
    waited=$((waited + 1))
  done
  return 0
}

rescue_offline_prompt() {
  local answer timeout=${RESCUE_NET_PROMPT_TIMEOUT:-180}
  [[ $timeout =~ ^[0-9]+$ ]] || timeout=180
  while ! rescue_default_route; do
    {
      printf '\n'
      printf 'Belum ada koneksi internet. Sambungkan Wi-Fi lewat ikon jaringan di panel, lalu tekan Enter untuk memeriksa ulang,\n'
      printf 'atau ketik L lalu Enter untuk lanjut tanpa internet (pemindaian lokal tetap berjalan; analisis OpenCode Go dilewati).\n'
      printf 'No internet connection yet. Connect Wi-Fi with the network icon in the panel, then press Enter to re-check,\n'
      printf 'or type L then Enter to continue offline (the local scan still runs; the OpenCode Go analysis is skipped).\n'
      printf '(otomatis lanjut offline dalam %s detik / continuing offline automatically in %s s) > ' "$timeout" "$timeout"
    } >&2
    if ! read -r -t "$timeout" answer; then
      printf '\n' >&2
      return 1
    fi
    case $answer in l | L) return 1 ;; esac
    rescue_wait_for_route 3 || true
  done
  return 0
}

rescue_pause_for_enter() {
  local ignored
  printf 'Tekan Enter untuk menutup jendela ini. / Press Enter to close this window.\n' >&2
  # shellcheck disable=SC2034
  read -r ignored || true
}

# rescue_journal_executed_ok JOURNAL RUN_ID: true when the repair journal (JSON lines) holds at least one entry of
# THIS run with stage "execute" and outcome "ok". Parsed with python, never grep on key order; a missing or
# unreadable journal, or a malformed line, simply does not count.
rescue_journal_executed_ok() {
  [[ -s ${1:-} && -n ${2:-} ]] || return 1
  python3 -c '
import json, sys
try:
    handle = open(sys.argv[1], encoding="utf-8", errors="replace")
except OSError:
    sys.exit(1)
with handle:
    for line in handle:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("run_id") == sys.argv[2] and row.get("stage") == "execute" and row.get("outcome") == "ok":
            sys.exit(0)
sys.exit(1)
' "$1" "$2" 2>/dev/null
}
