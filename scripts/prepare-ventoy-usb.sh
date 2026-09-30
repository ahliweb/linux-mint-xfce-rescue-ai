#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
mountpoint=''
iso=''
sums=''
sig=''
auto_boot=1
menu_timeout=5
provision_secrets=1
env_file="$root/.env"
env_file_explicit=0
signer_fpr=''
gpg_homedir=''
bundle_only=''
persistence=''
replace_persistence=0
persistence_rel=persistence/rescue-omes-casper-rw.dat
usage() {
  printf 'usage: %s --ventoy-mount DIR --mint-iso FILE --sha256sums FILE --signature FILE [--no-auto-boot] [--menu-timeout SECONDS] [--env-file FILE] [--no-provision-secrets] [--signer-fingerprint FPR] [--gpg-homedir DIR] [--persistence FILE.dat [--replace-persistence]]\n' "$0" >&2
  printf '       %s --bundle-only DEST   (testing/inspection: copy only the allowlisted rescue bundle into new/empty DEST and exit)\n' "$0" >&2
}

# Copy only allowlisted repository paths into $2 (never .git, dotenv files,
# ISOs, images, archives, caches, downloads, or evidence), so excluded files
# are never written to the target media in the first place.
copy_bundle() {
  python3 - "$1" "$2" <<'PY'
import os
import shutil
import sys

root, dest = sys.argv[1:]
ALLOW = [
    "AGENTS.md", "LICENSE", "Makefile", "README.md", "CHANGELOG.md", "VERSION",
    "config/hermes-rescue.config.yaml", "config/rescue.env.example",
    "docs", "host", "profiles", "rescue-ai", "scripts", "tests",
]
SKIP_DIRS = {"__pycache__", ".git"}
SKIP_SUFFIXES = (".pyc", ".iso", ".img", ".tar.gz")


def excluded(name):
    if name in SKIP_DIRS:
        return True
    if name.endswith(SKIP_SUFFIXES):
        return True
    if name.endswith(".example"):
        return False
    return name == ".env" or name.endswith(".env") or name.startswith(".env.")


def copy_file(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    try:
        shutil.copystat(src, dst)
    except OSError:
        pass  # FAT/exFAT targets may reject mode/time changes


count = 0
for rel in ALLOW:
    src = os.path.join(root, rel)
    if os.path.islink(src) or not os.path.exists(src):
        continue
    if os.path.isfile(src):
        if not excluded(os.path.basename(rel)):
            copy_file(src, os.path.join(dest, rel))
            count += 1
        continue
    for cur, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not excluded(d) and not os.path.islink(os.path.join(cur, d)))
        for name in sorted(files):
            path = os.path.join(cur, name)
            if excluded(name) or os.path.islink(path):
                continue
            copy_file(path, os.path.join(dest, os.path.relpath(path, root)))
            count += 1
os.makedirs(dest, exist_ok=True)
print(f"Copied {count} allowlisted files into {dest}")
PY
}

# Defensive check: the only dotenv-style file allowed in the bundle is the
# private config/rescue.env written by the allowlisted provisioning step.
assert_bundle_clean() {
  local bundle=$1 leaked
  leaked=$(find "$bundle" \( -name '.env' -o -name '.env.*' -o -name '*.env' \) ! -name '*.example' ! -path "$bundle/config/rescue.env" -print)
  [[ -z "$leaked" ]] || { printf 'Refusing: unexpected dotenv file(s) in USB bundle:\n%s\n' "$leaked" >&2; exit 1; }
  if [[ -e "$bundle/.git" ]]; then printf 'Refusing: .git found in USB bundle.\n' >&2; exit 1; fi
}

while (($#)); do
  case "$1" in
    --ventoy-mount) mountpoint=${2:?missing Ventoy mount}; shift 2 ;;
    --mint-iso) iso=${2:?missing Linux Mint ISO}; shift 2 ;;
    --sha256sums) sums=${2:?missing sha256sum.txt}; shift 2 ;;
    --signature) sig=${2:?missing sha256sum.txt.gpg}; shift 2 ;;
    --no-auto-boot|--manual-menu) auto_boot=0; shift ;;
    --menu-timeout) menu_timeout=${2:?missing timeout seconds}; shift 2 ;;
    --env-file) env_file=${2:?missing dotenv file}; env_file_explicit=1; shift 2 ;;
    --no-provision-secrets) provision_secrets=0; shift ;;
    --signer-fingerprint) signer_fpr=${2:?missing fingerprint}; shift 2 ;;
    --gpg-homedir) gpg_homedir=${2:?missing GPG homedir}; shift 2 ;;
    --bundle-only) bundle_only=${2:?missing destination}; shift 2 ;;
    --persistence) persistence=${2:?missing persistence image}; shift 2 ;;
    --replace-persistence) replace_persistence=1; shift ;;
    *) usage; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { printf 'python3 is required.\n' >&2; exit 1; }
if [[ -n "$bundle_only" ]]; then
  if [[ -e "$bundle_only" ]] && { [[ ! -d "$bundle_only" ]] || [[ -n "$(ls -A -- "$bundle_only")" ]]; }; then
    printf 'Refusing: --bundle-only destination must not exist or must be an empty directory: %s\n' "$bundle_only" >&2
    exit 1
  fi
  copy_bundle "$root" "$bundle_only"
  assert_bundle_clean "$bundle_only"
  exit 0
fi
[[ "$menu_timeout" =~ ^[0-9]+$ ]] || { printf 'Menu timeout must be a non-negative integer.\n' >&2; exit 2; }
[[ -n "$mountpoint" && -n "$iso" && -n "$sums" && -n "$sig" ]] || {
  printf 'Ventoy mount, ISO, checksum file, and GPG signature are required.\n' >&2; exit 2;
}
[[ -d "$mountpoint" ]] || { printf 'Not a directory: %s\n' "$mountpoint" >&2; exit 1; }
[[ -f "$iso" ]] || { printf 'ISO not found: %s\n' "$iso" >&2; exit 1; }
if [[ -n "$persistence" ]]; then
  [[ -f "$persistence" ]] || { printf 'Persistence image not found: %s\n' "$persistence" >&2; exit 1; }
  # Ventoy/casper only use an ext filesystem labelled casper-rw.
  python3 - "$persistence" <<'PY' || exit 1
import struct
import sys

with open(sys.argv[1], "rb") as fh:
    head = fh.read(2048)
if len(head) < 2048 or struct.unpack_from("<H", head, 1024 + 56)[0] != 0xEF53:
    raise SystemExit("Refusing: persistence image is not an ext2/3/4 filesystem (build it with scripts/build-persistence.sh).")
label = head[1024 + 120:1024 + 136].split(b"\0", 1)[0]
if label != b"casper-rw":
    raise SystemExit(f"Refusing: persistence image label is {label!r}, casper needs 'casper-rw'.")
PY
fi
mountpoint -q "$mountpoint" || { printf 'Refusing: mount path is not a mounted filesystem: %s\n' "$mountpoint" >&2; exit 1; }
# A freshly installed Ventoy data partition is empty (EFI lives on the separate
# VTOYEFI partition), so also accept a partition labelled "Ventoy" whose disk
# has a sibling partition labelled "VTOYEFI".
is_ventoy_layout() {
  local src disk
  src=$(findmnt -no SOURCE -- "$mountpoint" 2>/dev/null) || return 1
  [[ -b "$src" && "$(lsblk -dno LABEL -- "$src" 2>/dev/null)" == Ventoy ]] || return 1
  disk=$(lsblk -dno PKNAME -- "$src" 2>/dev/null) || return 1
  [[ -n "$disk" ]] || return 1
  lsblk -nr -o LABEL -- "/dev/$disk" 2>/dev/null | grep -qx VTOYEFI
}
[[ -d "$mountpoint/ventoy" || -d "$mountpoint/EFI" ]] || is_ventoy_layout || {
  printf 'Refusing: mount does not look like a Ventoy data partition.\n' >&2; exit 1;
}

if [[ -n "$persistence" && -e "$mountpoint/$persistence_rel" ]] && ((!replace_persistence)); then
  printf 'Refusing: %s already exists on the USB and may hold Hermes memory/sessions. Use --replace-persistence to overwrite it (this DESTROYS that state).\n' "$mountpoint/$persistence_rel" >&2
  exit 1
fi

verify_args=(--iso "$iso" --sha256sums "$sums" --signature "$sig")
[[ -z "$signer_fpr" ]] || verify_args+=(--signer-fingerprint "$signer_fpr")
[[ -z "$gpg_homedir" ]] || verify_args+=(--gpg-homedir "$gpg_homedir")
"$root/scripts/verify-mint-iso.sh" "${verify_args[@]}"

iso_name=$(basename -- "$iso")
bundle="$mountpoint/rescue-omes"
mkdir -p "$mountpoint/ISO/LinuxMintXFCE"
cp --preserve=mode,timestamps "$iso" "$mountpoint/ISO/LinuxMintXFCE/"
sync
# Read-back verification of the copied ISO against the verified source.
src_sum=$(sha256sum -- "$iso"); src_sum=${src_sum%% *}
dst_sum=$(sha256sum -- "$mountpoint/ISO/LinuxMintXFCE/$iso_name"); dst_sum=${dst_sum%% *}
[[ "$src_sum" == "$dst_sum" ]] || {
  printf 'Copied ISO checksum mismatch: source=%s copy=%s\n' "$src_sum" "$dst_sum" >&2
  exit 1
}
printf 'Copied ISO read-back: PASS (%s)\n' "$dst_sum"

# The bundle directory is our own; recreate it cleanly, then copy only the
# allowlisted paths so secrets and large artifacts are never written to USB.
rm -rf -- "$bundle"
copy_bundle "$root" "$bundle"

if ((provision_secrets)); then
  if [[ -f "$env_file" ]]; then
    python3 - "$env_file" "$mountpoint/rescue-omes/config/rescue.env" <<'PY'
import pathlib
import shlex
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
values = {}
for raw in source.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit(f"Invalid dotenv line (expected KEY=VALUE): {raw!r}")
    key, value = line.split("=", 1)
    key = key.strip()
    if key != "OPENCODE_GO_API_KEY":
        continue
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    values[key] = value
api_key = values.get("OPENCODE_GO_API_KEY", "")
if not api_key:
    raise SystemExit("dotenv does not contain a non-empty OPENCODE_GO_API_KEY")
# Do not copy arbitrary dotenv settings or execute the file as shell code.
lines = [f"OPENCODE_GO_API_KEY={shlex.quote(api_key)}"]
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
destination.chmod(0o600)
PY
    printf 'Provider secret provisioned from %s into the private USB rescue config.\n' "$env_file"
  elif ((env_file_explicit)); then
    printf 'Explicit dotenv file not found: %s\n' "$env_file" >&2
    exit 1
  else
    printf 'Default dotenv file not found: %s; use --no-provision-secrets to build without an API key.\n' "$env_file" >&2
    exit 1
  fi
else
  printf 'Secret provisioning disabled; USB bundle contains no API key.\n'
fi

if ((auto_boot)); then
  # Preserve unrelated Ventoy settings while making the verified Mint ISO the
  # default image. A timeout of zero means immediate selection by Ventoy.
  # Ventoy reads plugin configuration only from /ventoy/ventoy.json.
  mkdir -p -- "$mountpoint/ventoy"
  python3 - "$mountpoint/ventoy/ventoy.json" "/ISO/LinuxMintXFCE/$iso_name" "$menu_timeout" <<'PY'
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
if [[ -n "$persistence" ]]; then
  # Persistence image: Hermes memory, sessions and reports live on the USB.
  # The backend must be on the Ventoy data partition; copy, then read back.
  mkdir -p -- "$mountpoint/persistence"
  cp --sparse=never -- "$persistence" "$mountpoint/$persistence_rel"
  sync
  src_sum=$(sha256sum -- "$persistence"); src_sum=${src_sum%% *}
  dst_sum=$(sha256sum -- "$mountpoint/$persistence_rel"); dst_sum=${dst_sum%% *}
  [[ "$src_sum" == "$dst_sum" ]] || {
    printf 'Copied persistence image checksum mismatch: source=%s copy=%s\n' "$src_sum" "$dst_sum" >&2
    exit 1
  }
  printf 'Copied persistence image read-back: PASS (%s)\n' "$dst_sum"
  # Merge (not replace) a persistence entry; other keys and entries survive.
  # autosel 1 + timeout 0 select the image without any prompt.
  mkdir -p -- "$mountpoint/ventoy"
  python3 - "$mountpoint/ventoy/ventoy.json" "/ISO/LinuxMintXFCE/$iso_name" "/$persistence_rel" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
image, backend = sys.argv[2], sys.argv[3]
config = {}
if path.exists():
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Refusing to overwrite invalid Ventoy config: {exc}")
if not isinstance(config, dict):
    raise SystemExit("Refusing to overwrite non-object Ventoy config")
entries = config.get("persistence", [])
if not isinstance(entries, list):
    raise SystemExit("Refusing to overwrite invalid Ventoy persistence array")
kept = [e for e in entries if not (isinstance(e, dict) and e.get("image") == image)]
kept.append({"image": image, "backend": backend, "autosel": 1, "timeout": 0})
config["persistence"] = kept
path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY
  printf 'Ventoy persistence configured: %s -> %s (autosel 1, timeout 0)\n' "$iso_name" "/$persistence_rel"
fi

# Host launchers for Windows/macOS/Linux operators live at the USB root; they
# locate the bundle at <usb root>/rescue-omes. Only these known files are copied.
if [[ -d "$root/host" ]]; then
  for launcher in RESCUE-WINDOWS.cmd RESCUE-MACOS.command rescue-linux.sh; do
    if [[ -f "$root/host/$launcher" && ! -L "$root/host/$launcher" ]]; then
      cp -- "$root/host/$launcher" "$mountpoint/$launcher"
      cmp -s -- "$root/host/$launcher" "$mountpoint/$launcher" || { printf 'Host launcher read-back mismatch: %s\n' "$launcher" >&2; exit 1; }
      printf 'Copied host launcher to USB root: %s\n' "$launcher"
    fi
  done
fi
assert_bundle_clean "$bundle"
sync
printf 'Copied verified Linux Mint ISO and rescue bundle to %s\n' "$mountpoint"
printf 'Boot instruction: select the USB in firmware. Ventoy will auto-select Linux Mint when auto-boot is enabled; firmware boot selection still cannot be forced by a file.\n'
