#!/usr/bin/env bash
set -Eeuo pipefail

device=''
ventoy_dir=''
yes=0
reinstall=0
while (($#)); do
  case "$1" in
    --device) device=${2:?missing device}; shift 2 ;;
    --ventoy-dir) ventoy_dir=${2:?missing extracted Ventoy directory}; shift 2 ;;
    --yes) yes=1; shift ;;
    --reinstall) reinstall=1; shift ;;
    *) printf 'usage: %s --device /dev/sdX --ventoy-dir DIR [--reinstall] --yes\n' "$0" >&2; exit 2 ;;
  esac
done
[[ -n "$device" && -n "$ventoy_dir" ]] || { printf 'Device and extracted Ventoy directory are required.\n' >&2; exit 2; }
[[ $yes -eq 1 ]] || { printf 'Refusing: add --yes only after reviewing the target device.\n' >&2; exit 1; }
[[ "$device" == /dev/* && -b "$device" ]] || { printf 'Not a block device: %s\n' "$device" >&2; exit 1; }
command -v lsblk >/dev/null || { printf 'lsblk is required.\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'python3 is required.\n' >&2; exit 1; }

# Parse lsblk JSON in python so MODEL values containing spaces are safe.
# Output is NUL-separated: type, removable, transport, model, size(bytes),
# human size, whole-disk/child mounts (one per line, may be empty).
disk_json=$(lsblk -J -d -b -o PATH,TYPE,RM,TRAN,MODEL,SIZE,MOUNTPOINT -- "$device")
tree_json=$(lsblk -J -o PATH,MOUNTPOINT -- "$device")
fields=()
while IFS= read -r -d '' item; do fields+=("$item"); done < <(python3 - "$disk_json" "$tree_json" <<'PY'
import json, sys

disk = json.loads(sys.argv[1])["blockdevices"]
tree = json.loads(sys.argv[2])["blockdevices"]
if len(disk) != 1:
    raise SystemExit("expected exactly one block device from lsblk")
d = disk[0]
def s(v):
    return "" if v is None else str(v).replace("\0", "").strip()
rm = d.get("rm")
rm = "1" if rm in (True, 1, "1", "true") else "0"
size = int(d.get("size") or 0)
value = float(size)
for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
    if value < 1024 or unit == "PiB":
        human = f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        break
    value /= 1024
mounted = []
def walk(node):
    mp = node.get("mountpoint")
    if mp is None and node.get("mountpoints"):
        mp = next((m for m in node["mountpoints"] if m), None)
    if mp:
        path = s(node.get("path"))
        mounted.append(f"{path} -> {s(mp)}")
    for child in node.get("children") or []:
        walk(child)
for n in tree:
    walk(n)
for v in (s(d.get("type")), rm, s(d.get("tran")), s(d.get("model")), str(size), human, "\n".join(mounted)):
    sys.stdout.write(v + "\0")
PY
)
((${#fields[@]} == 7)) || { printf 'Could not parse lsblk output for %s.\n' "$device" >&2; exit 1; }
type=${fields[0]} rm=${fields[1]} tran=${fields[2]} model=${fields[3]} size_human=${fields[5]} mounted=${fields[6]}

[[ "$type" == disk ]] || { printf 'Refusing: target is not a whole disk (%s).\n' "$type" >&2; exit 1; }
[[ "$rm" == 1 || "$tran" == usb ]] || { printf 'Refusing: %s is not marked removable/USB.\n' "$device" >&2; exit 1; }
[[ -z "$mounted" ]] || { printf 'Refusing: target or its partitions are mounted:\n%s\n' "$mounted" >&2; exit 1; }

# Refuse the disk that backs the running root filesystem (including LVM/crypt
# stacks on top of it: lsblk -s lists every ancestor of the root source).
root_src=$(findmnt -no SOURCE / 2>/dev/null || true)
if [[ -n "$root_src" && -b "$root_src" ]]; then
  real_device=$(readlink -f -- "$device")
  while read -r anc_path anc_type; do
    [[ "$anc_type" == disk ]] || continue
    if [[ "$(readlink -f -- "$anc_path")" == "$real_device" ]]; then
      printf 'Refusing: %s backs the running root filesystem (%s).\n' "$device" "$root_src" >&2
      exit 1
    fi
  done < <(lsblk -s -n -r -o PATH,TYPE -- "$root_src" 2>/dev/null || true)
fi
[[ -x "$ventoy_dir/Ventoy2Disk.sh" ]] || { printf 'Ventoy2Disk.sh not found in %s\n' "$ventoy_dir" >&2; exit 1; }

printf 'TARGET: %s | model=%s | size=%s | transport=%s\n' "$device" "$model" "$size_human" "$tran"
printf 'This operation formats the target USB and destroys all data.\n'
if [[ $reinstall -eq 1 ]]; then
  printf 'PERINGATAN: --reinstall memaksa instal ulang Ventoy; SELURUH isi %s akan dihapus. / WARNING: --reinstall forces a Ventoy reinstall; ALL data on %s will be erased.\n' "$device" "$device"
fi
ventoy_flag='-i'
[[ $reinstall -eq 1 ]] && ventoy_flag='-I'
sudo bash "$ventoy_dir/Ventoy2Disk.sh" "$ventoy_flag" -s "$device"
udevadm settle 2>/dev/null || true
lsblk -o NAME,PATH,TYPE,RM,SIZE,MODEL,TRAN,MOUNTPOINT "$device"
printf 'Ventoy installation completed. Mount the first partition before copying the ISO.\n'
