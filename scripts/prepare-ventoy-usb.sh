#!/usr/bin/env bash
set -Eeuo pipefail

mountpoint=''
iso=''
sums=''
sig=''
auto_boot=1
menu_timeout=5
while (($#)); do
  case "$1" in
    --ventoy-mount) mountpoint=${2:?missing Ventoy mount}; shift 2 ;;
    --mint-iso) iso=${2:?missing Linux Mint ISO}; shift 2 ;;
    --sha256sums) sums=${2:?missing sha256sum.txt}; shift 2 ;;
    --signature) sig=${2:?missing sha256sum.txt.gpg}; shift 2 ;;
    --no-auto-boot|--manual-menu) auto_boot=0; shift ;;
    --menu-timeout) menu_timeout=${2:?missing timeout seconds}; shift 2 ;;
    *) printf 'usage: %s --ventoy-mount DIR --mint-iso FILE --sha256sums FILE --signature FILE [--no-auto-boot] [--menu-timeout SECONDS]\n' "$0" >&2; exit 2 ;;
  esac
done
[[ "$menu_timeout" =~ ^[0-9]+$ ]] || { printf 'Menu timeout must be a non-negative integer.\n' >&2; exit 2; }
[[ -n "$mountpoint" && -n "$iso" && -n "$sums" && -n "$sig" ]] || {
  printf 'Ventoy mount, ISO, checksum file, and GPG signature are required.\n' >&2; exit 2;
}
[[ -d "$mountpoint" ]] || { printf 'Not a directory: %s\n' "$mountpoint" >&2; exit 1; }
[[ -f "$iso" ]] || { printf 'ISO not found: %s\n' "$iso" >&2; exit 1; }
mountpoint -q "$mountpoint" || { printf 'Refusing: mount path is not a mounted filesystem: %s\n' "$mountpoint" >&2; exit 1; }
[[ -d "$mountpoint/ventoy" || -f "$mountpoint/ventoy.json" || -d "$mountpoint/EFI" ]] || {
  printf 'Refusing: mount does not look like a Ventoy data partition.\n' >&2; exit 1;
}

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
"$root/scripts/verify-mint-iso.sh" --iso "$iso" --sha256sums "$sums" --signature "$sig"
mkdir -p "$mountpoint/ISO/LinuxMintXFCE" "$mountpoint/rescue-omes"
cp --preserve=mode,timestamps "$iso" "$mountpoint/ISO/LinuxMintXFCE/"
cp -a "$root/." "$mountpoint/rescue-omes/"
# Never copy a local API key or secret environment file onto the USB bundle.
rm -f "$mountpoint/rescue-omes/config/rescue.env" "$mountpoint/rescue-omes/.env"

if ((auto_boot)); then
  # Preserve unrelated Ventoy settings while making the verified Mint ISO the
  # default image. A timeout of zero means immediate selection by Ventoy.
  iso_name=$(basename -- "$iso")
  python3 - "$mountpoint/ventoy.json" "/ISO/LinuxMintXFCE/$iso_name" "$menu_timeout" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
image = sys.argv[2]
timeout = sys.argv[3]
config = {}
if path.exists():
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Refusing to overwrite invalid Ventoy config: {exc}")
if not isinstance(config, dict):
    raise SystemExit("Refusing to overwrite non-object Ventoy config")
control = config.get("control", [])
if not isinstance(control, list):
    raise SystemExit("Refusing to overwrite invalid Ventoy control array")
new_control = []
for item in control:
    if not isinstance(item, dict):
        new_control.append(item)
    elif not ("VTOY_MENU_TIMEOUT" in item or "VTOY_DEFAULT_IMAGE" in item):
        new_control.append(item)
new_control.extend([
    {"VTOY_MENU_TIMEOUT": timeout},
    {"VTOY_DEFAULT_IMAGE": image},
])
config["control"] = new_control
path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY
  printf 'Ventoy auto-boot configured: %s (timeout %ss)\n' "$iso_name" "$menu_timeout"
else
  printf 'Ventoy auto-boot not changed; existing menu configuration is preserved.\n'
fi
printf 'Copied verified Linux Mint ISO and rescue bundle to %s\n' "$mountpoint"
printf 'Boot instruction: select the USB in firmware. Ventoy will auto-select Linux Mint when auto-boot is enabled; firmware boot selection still cannot be forced by a file.\n'
