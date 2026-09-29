#!/usr/bin/env bash
set -Eeuo pipefail

device=''
ventoy_dir=''
yes=0
while (($#)); do
  case "$1" in
    --device) device=${2:?missing device}; shift 2 ;;
    --ventoy-dir) ventoy_dir=${2:?missing extracted Ventoy directory}; shift 2 ;;
    --yes) yes=1; shift ;;
    *) printf 'usage: %s --device /dev/sdX --ventoy-dir DIR --yes\n' "$0" >&2; exit 2 ;;
  esac
done
[[ -n "$device" && -n "$ventoy_dir" ]] || { printf 'Device and extracted Ventoy directory are required.\n' >&2; exit 2; }
[[ "$device" == /dev/* && -b "$device" ]] || { printf 'Not a block device: %s\n' "$device" >&2; exit 1; }
[[ $yes -eq 1 ]] || { printf 'Refusing: add --yes only after reviewing the target device.\n' >&2; exit 1; }
command -v lsblk >/dev/null || exit 1

read -r type rm tran model size mountpoints < <(lsblk -dn -o TYPE,RM,TRAN,MODEL,SIZE,MOUNTPOINTS "$device")
[[ "$type" == disk ]] || { printf 'Refusing: target is not a whole disk (%s).\n' "$type" >&2; exit 1; }
[[ "$rm" == 1 || "$tran" == usb ]] || { printf 'Refusing: %s is not marked removable/USB.\n' "$device" >&2; exit 1; }
children=$(lsblk -ln -o PATH,MOUNTPOINTS "$device" | tail -n +2 | awk 'NF>1 {print}')
[[ -z "$children" ]] || { printf 'Refusing: target has mounted children:\n%s\n' "$children" >&2; exit 1; }
[[ -x "$ventoy_dir/Ventoy2Disk.sh" ]] || { printf 'Ventoy2Disk.sh not found in %s\n' "$ventoy_dir" >&2; exit 1; }

printf 'TARGET: %s | model=%s | size=%s | transport=%s\n' "$device" "$model" "$size" "$tran"
printf 'This operation formats the target USB and destroys all data.\n'
sudo bash "$ventoy_dir/Ventoy2Disk.sh" -i -s "$device"
udevadm settle 2>/dev/null || true
lsblk -o NAME,PATH,TYPE,RM,SIZE,MODEL,TRAN,MOUNTPOINTS "$device"
printf 'Ventoy installation completed. Mount the first partition before copying the ISO.\n'
