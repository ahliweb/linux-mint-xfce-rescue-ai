#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

state_dir="$HOME/.local/share/rescue-omes"
state_dir_set=0
hardware_mode=${RESCUE_HARDWARE_MODE:-auto}
min_cpu=${RESCUE_MIN_CPU:-2}
min_ram_gib=${RESCUE_MIN_RAM_GIB:-4}
min_usb_gib=${RESCUE_MIN_USB_GIB:-8}
scan_targets=1
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; state_dir_set=1; shift 2 ;;
    --hardware-mode) hardware_mode=${2:?missing hardware mode (auto|wizard)}; shift 2 ;;
    --min-cpu) min_cpu=${2:?missing CPU threshold}; shift 2 ;;
    --min-ram-gib) min_ram_gib=${2:?missing RAM threshold}; shift 2 ;;
    --min-usb-gib) min_usb_gib=${2:?missing USB threshold}; shift 2 ;;
    --no-target-scan) scan_targets=0; shift ;;
    *) printf 'usage: %s [--state-dir DIR] [--hardware-mode auto|wizard] [--min-cpu N] [--min-ram-gib N] [--min-usb-gib N] [--no-target-scan]\n' "$0" >&2; exit 2 ;;
  esac
done
[[ "$hardware_mode" == auto || "$hardware_mode" == wizard ]] || { printf 'Invalid hardware mode: %s\n' "$hardware_mode" >&2; exit 2; }
[[ $min_cpu =~ ^[1-9][0-9]*$ ]] || { printf 'Invalid --min-cpu (positive integer required): %s\n' "$min_cpu" >&2; exit 2; }
for pair in "min-ram-gib:$min_ram_gib" "min-usb-gib:$min_usb_gib"; do
  value=${pair#*:}
  [[ $value =~ ^([0-9]+\.?[0-9]*|\.[0-9]+)$ && $value =~ [1-9] ]] || {
    printf 'Invalid --%s (positive number required): %s\n' "${pair%%:*}" "$value" >&2
    exit 2
  }
done

rescue_load_env "$root/config/rescue.env" || exit 1
if ((!state_dir_set)) && [[ -n ${RESCUE_STATE_DIR:-} ]]; then
  state_dir=$RESCUE_STATE_DIR
fi
rescue_load_env "$state_dir/hermes/env" || exit 1
export HERMES_HOME="$state_dir/hermes"
export OPENCODE_GO_API_KEY="${OPENCODE_GO_API_KEY:-}"

[[ -d "$HERMES_HOME" ]] || { printf 'Hermes state not installed: %s\n' "$HERMES_HOME" >&2; exit 1; }
command -v hermes >/dev/null 2>&1 || { printf 'Hermes is not installed. Run install-hermes-rescue.sh first.\n' >&2; exit 1; }

report_dir="$state_dir/reports"
report_file="$report_dir/hardware-readiness-$(date -u +%Y%m%d-%H%M%S).json"
install -d -m 0700 -- "$report_dir"
printf 'Running hardware readiness preflight (mode: %s) ...\n' "$hardware_mode"
if ! python3 "$root/scripts/check-hardware-readiness.py" \
  --mode "$hardware_mode" \
  --output "$report_file" \
  --min-cpu "$min_cpu" \
  --min-ram-gib "$min_ram_gib" \
  --min-usb-gib "$min_usb_gib"; then
  printf 'Preflight perangkat keras GAGAL; Hermes tidak dijalankan. Periksa laporan: %s\n' "$report_file" >&2
  printf 'Hardware readiness preflight FAILED; Hermes was not started. See report: %s\n' "$report_file" >&2
  exit 1
fi

# Automatic read-only scan of the operating systems on the internal disks, then
# cloud analysis of the resulting evidence. Neither step may block Hermes: on any
# failure print a bilingual warning and continue. Everything is written to the
# state directory on the USB, never to the internal disks.
if ((scan_targets)); then
  ts=$(date -u +%Y%m%d-%H%M%S)
  evidence_file="$report_dir/target-evidence-$ts.json"
  analysis_file="$report_dir/analysis-$ts.md"
  printf 'Memindai sistem operasi di disk internal (read-only) ...\n'
  printf 'Scanning installed operating systems on internal disks (read-only) ...\n'
  if timeout 900 sudo -n python3 "$root/scripts/scan-target-os.py" --output "$evidence_file" && [[ -s $evidence_file ]]; then
    # The scan runs as root; hand the evidence back to the desktop user (best effort: FAT/exFAT ignores it).
    [[ -O $evidence_file ]] || sudo -n chown "$(id -u):$(id -g)" -- "$evidence_file" 2>/dev/null || true
    cp -f -- "$evidence_file" "$report_dir/latest-evidence.json" 2>/dev/null || true
    chmod 0600 -- "$evidence_file" "$report_dir/latest-evidence.json" 2>/dev/null || true
    printf 'Bukti tersimpan: %s\n' "$evidence_file"
    printf 'Menganalisis dengan OpenCode Go (%s) ...\n' 'mimo-v2.6-flash'
    if python3 "$root/scripts/opencode-go-analyze.py" \
      --evidence "$evidence_file" \
      --output "$analysis_file" \
      --env-file "$root/config/rescue.env" \
      --env-file "$state_dir/hermes/env"; then
      printf 'Analisis tersimpan: %s\nAnalysis saved: %s\n' "$analysis_file" "$analysis_file"
    else
      printf 'PERINGATAN: analisis OpenCode Go gagal; Hermes tetap dijalankan. Bukti: %s\n' "$evidence_file" >&2
      printf 'WARNING: OpenCode Go analysis failed; starting Hermes anyway. Evidence: %s\n' "$evidence_file" >&2
    fi
  else
    rm -f -- "$evidence_file" 2>/dev/null || true
    printf 'PERINGATAN: pemindaian sistem operasi gagal atau tidak diizinkan (sudo -n); Hermes tetap dijalankan.\n' >&2
    printf 'WARNING: target OS scan failed or was not permitted (sudo -n); starting Hermes anyway.\n' >&2
  fi
fi

exec hermes --tui --provider custom --model mimo-v2.6-flash
