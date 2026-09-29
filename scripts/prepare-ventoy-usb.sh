#!/usr/bin/env bash
set -Eeuo pipefail

mountpoint=''
iso=''
sums=''
sig=''
while (($#)); do
  case "$1" in
    --ventoy-mount) mountpoint=${2:?missing Ventoy mount}; shift 2 ;;
    --mint-iso) iso=${2:?missing Linux Mint ISO}; shift 2 ;;
    --sha256sums) sums=${2:?missing sha256sum.txt}; shift 2 ;;
    --signature) sig=${2:?missing sha256sum.txt.gpg}; shift 2 ;;
    *) printf 'usage: %s --ventoy-mount DIR --mint-iso FILE --sha256sums FILE --signature FILE\n' "$0" >&2; exit 2 ;;
  esac
done
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
printf 'Copied verified Linux Mint ISO and rescue bundle to %s\n' "$mountpoint"
printf 'Boot instruction: select the ISO from the Ventoy menu; USB auto-boot still depends on firmware boot order.\n'
