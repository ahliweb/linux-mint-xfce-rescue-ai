# shellcheck shell=bash
# Terminal progress helpers for bash launchers (source this file; do not execute it).
#
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Owned by ahliweb/linux-mint-xfce-rescue-ai#67. Behavior: docs/target-os-scan.md.
#
# Progress is drawn only on /dev/tty, never on stdout/stderr (launchers tee those into a log). Disabled when
# RESCUE_PROGRESS=0, when TERM=dumb or when the terminal cannot be written.
# Test hook (tests only): RESCUE_PROGRESS_TTY=/path/to/file replaces /dev/tty.
#
#   rescue_progress_step N TOTAL LABEL
#   rescue_progress_run LABEL BUDGET_SECONDS -- CMD...   (returns CMD's exit code)

_rescue_progress_tty() {
  [ "${RESCUE_PROGRESS:-1}" = "0" ] && return 1
  [ "${TERM:-}" = "dumb" ] && return 1
  _RESCUE_PROGRESS_TTY_PATH="${RESCUE_PROGRESS_TTY:-/dev/tty}"
  { : >>"$_RESCUE_PROGRESS_TTY_PATH"; } 2>/dev/null || return 1
  return 0
}

rescue_progress_step() {
  local n="${1:-}" total="${2:-}" label="${3:-}"
  # The plain line always goes to stdout so the launcher log keeps a record of the phase.
  printf '[%s/%s] %s\n' "$n" "$total" "$label"
  # On an interactive stdout the plain line is already visible; do not print the header twice.
  if [ ! -t 1 ] && _rescue_progress_tty; then
    { printf '[%s/%s] %s\n' "$n" "$total" "$label" >>"$_RESCUE_PROGRESS_TTY_PATH"; } 2>/dev/null || true
  fi
  return 0
}

# Drawer: runs in a background subshell, writes only to the terminal path, stops when the parent shell is gone.
_rescue_progress_draw() {
  local label="$1" budget="$2" parent="$3" tty="$4"
  local start=$SECONDS elapsed pct filled bar text
  while kill -0 "$parent" 2>/dev/null; do
    elapsed=$((SECONDS - start))
    pct=$((elapsed * 100 / budget))
    [ "$pct" -gt 99 ] && pct=99
    filled=$((pct * 20 / 100))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((20 - filled))" '' | tr ' ' '-')"
    text="$(printf '[%s] %3d%%  %s  %02d:%02d/%02d:%02d' "$bar" "$pct" "$label" \
      $((elapsed / 60)) $((elapsed % 60)) $((budget / 60)) $((budget % 60)))"
    { printf '\r%.*s' "$((${COLUMNS:-80} - 1))" "$text   " >>"$tty"; } 2>/dev/null || exit 0
    sleep 1
  done
}

rescue_progress_run() {
  local label="${1:-}" budget="${2:-1}"
  shift 2 || true
  [ "${1:-}" = "--" ] && shift
  [ "$#" -gt 0 ] || return 2
  case "$budget" in '' | *[!0-9]*) budget=1 ;; esac
  [ "$budget" -ge 1 ] || budget=1

  if ! _rescue_progress_tty; then
    "$@"
    return $?
  fi
  local tty="$_RESCUE_PROGRESS_TTY_PATH" drawer rc=0
  (
    exec >/dev/null 2>&1 </dev/null
    _rescue_progress_draw "$label" "$budget" "$$" "$tty"
  ) &
  drawer=$!
  "$@" || rc=$?
  kill "$drawer" 2>/dev/null || true
  { printf '\r[####################] 100%%  %s  %s\n' "$label" "                    " >>"$tty"; } 2>/dev/null || true
  return "$rc"
}
