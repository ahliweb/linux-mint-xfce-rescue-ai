#!/usr/bin/env bash
set -Eeuo pipefail

# Linux Mint signing key (primary key fingerprint). Override only with
# --signer-fingerprint after verifying the key out of band.
mint_signer_fpr='27DEB15644C6B3CF3BD7D291300F846BA25BAE09'

iso=''
sums=''
sig=''
signer_fpr=$mint_signer_fpr
gpg_homedir=''
usage() {
  printf 'usage: %s --iso FILE --sha256sums FILE --signature FILE [--signer-fingerprint FPR] [--gpg-homedir DIR]\n' "$0" >&2
}
while (($#)); do
  case "$1" in
    --iso) iso=${2:?missing ISO}; shift 2 ;;
    --sha256sums) sums=${2:?missing sha256sum.txt}; shift 2 ;;
    --signature) sig=${2:?missing sha256sum.txt.gpg}; shift 2 ;;
    --signer-fingerprint) signer_fpr=${2:?missing fingerprint}; shift 2 ;;
    --gpg-homedir) gpg_homedir=${2:?missing GPG homedir}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -f "$iso" && -f "$sums" && -f "$sig" ]] || { printf 'ISO, checksum file, and GPG signature are all required.\n' >&2; exit 1; }
command -v sha256sum >/dev/null || { printf 'sha256sum is required.\n' >&2; exit 1; }
command -v gpg >/dev/null || { printf 'gpg is required.\n' >&2; exit 1; }

# Normalize the expected signer fingerprint: strip whitespace, uppercase.
signer_fpr=${signer_fpr//[[:space:]]/}
signer_fpr=${signer_fpr^^}
[[ "$signer_fpr" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]] || {
  printf 'Invalid signer fingerprint (expected 40 or 64 hex characters): %s\n' "$signer_fpr" >&2
  exit 2
}

gpg_args=()
[[ -z "$gpg_homedir" ]] || gpg_args+=(--homedir "$gpg_homedir")

printf 'Checking Linux Mint checksum signature...\n'
status=''
if ! status=$(gpg "${gpg_args[@]}" --status-fd 1 --verify "$sig" "$sums"); then
  printf 'GPG signature verification FAILED for %s\n' "$sums" >&2
  exit 1
fi
# VALIDSIG <fpr> <date> <ts> <expire> <ver> <rsvd> <pk-algo> <hash-algo> <class> <primary-fpr>
primary=$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print toupper($NF); exit}' <<<"$status")
[[ -n "$primary" ]] || { printf 'No VALIDSIG line from gpg; signature is not valid.\n' >&2; exit 1; }
[[ "$primary" == "$signer_fpr" ]] || {
  printf 'Signature is valid but made by an unexpected key.\n  expected primary fingerprint: %s\n  actual primary fingerprint:   %s\n' "$signer_fpr" "$primary" >&2
  exit 1
}
printf 'GPG signature: PASS (signer %s)\n' "$primary"

printf 'Checking ISO checksum...\n'
name=$(basename -- "$iso")
matches=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  if [[ "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]][[:space:]*](.+)$ ]]; then
    if [[ "${BASH_REMATCH[2]}" == "$name" ]]; then
      matches+=("${BASH_REMATCH[1],,}")
    fi
  fi
done <"$sums"
((${#matches[@]} == 1)) || {
  printf 'Expected exactly one checksum entry for %s in %s, found %d.\n' "$name" "$sums" "${#matches[@]}" >&2
  exit 1
}
expected=${matches[0]}
actual=$(sha256sum -- "$iso")
actual=${actual%% *}
[[ "$actual" == "$expected" ]] || {
  printf 'ISO checksum MISMATCH for %s\n  expected: %s\n  actual:   %s\n' "$iso" "$expected" "$actual" >&2
  exit 1
}
printf 'Linux Mint ISO verification: PASS (%s)\n' "$name"
