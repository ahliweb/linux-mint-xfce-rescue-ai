#!/usr/bin/env bash
set -Eeuo pipefail

iso=''
sums=''
sig=''
while (($#)); do
  case "$1" in
    --iso) iso=${2:?missing ISO}; shift 2 ;;
    --sha256sums) sums=${2:?missing sha256sum.txt}; shift 2 ;;
    --signature) sig=${2:?missing sha256sum.txt.gpg}; shift 2 ;;
    *) printf 'usage: %s --iso FILE --sha256sums FILE --signature FILE\n' "$0" >&2; exit 2 ;;
  esac
done
[[ -f "$iso" && -f "$sums" && -f "$sig" ]] || { printf 'ISO, checksum file, and GPG signature are all required.\n' >&2; exit 1; }
command -v sha256sum >/dev/null || { printf 'sha256sum is required.\n' >&2; exit 1; }
command -v gpg >/dev/null || { printf 'gpg is required.\n' >&2; exit 1; }

printf 'Checking Linux Mint checksum signature...\n'
gpg --verify "$sig" "$sums"
printf 'Checking ISO checksum...\n'
name=$(basename -- "$iso")
grep -E "[[:space:]]${name//./\\.}$" "$sums" | sha256sum --check --status --ignore-missing
printf 'Linux Mint ISO verification: PASS (%s)\n' "$name"
