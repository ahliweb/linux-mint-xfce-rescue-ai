#!/usr/bin/env bash
# Sign a skills bundle manifest with the OWNER's SSH key, on the owner's own machine.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# usage: sign-skills-bundle.sh --key PATH --manifest dist/rescue-skills-<V>.manifest.json [--allowed-signers FILE]
#
#   --key PATH   private key file (its PATH.pub must exist next to it) or a PUBLIC key file ending in .pub
#                (then ssh-agent holds the private half). The key is only passed to ssh-keygen by path:
#                it is never read, copied, or printed by this script.
#
# Refuses to run when CI or GITHUB_ACTIONS is set. Never signs a bundle that fails the format check.
# Writes <manifest>.sig next to the manifest and prints the `gh release upload` command; it uploads nothing.
set -Eeuo pipefail

namespace='rescue-skills'
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(dirname -- "$here")

fail() { printf 'sign-skills-bundle: %s\n' "$*" >&2; exit 1; }
usage() { printf 'usage: %s --key PATH --manifest FILE [--allowed-signers FILE]\n' "$0" >&2; exit 2; }

if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
  fail 'refusing to sign in CI: signing is done only by the owner, manually, on the owner machine.'
fi

key='' manifest='' signers="$root/config/skills-allowed-signers"
while (($#)); do
  case "$1" in
    --key) key=${2:?missing key path}; shift 2 ;;
    --manifest) manifest=${2:?missing manifest path}; shift 2 ;;
    --allowed-signers) signers=${2:?missing file}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$key" && -n "$manifest" ]] || usage
command -v ssh-keygen >/dev/null || fail 'ssh-keygen is required.'
command -v python3 >/dev/null || fail 'python3 is required.'
[[ -f "$key" && ! -L "$key" ]] || fail 'the key path must be an existing regular file (not a symlink).'
[[ -f "$manifest" && ! -L "$manifest" ]] || fail 'the manifest must be an existing regular file.'
[[ ! -e "$manifest.sig" ]] || fail "$manifest.sig already exists; remove it deliberately to sign again."

if [[ "$key" == *.pub ]]; then pub=$key; else pub="$key.pub"; fi
[[ -f "$pub" ]] || fail 'the matching public key file was not found next to the key.'

# 1. The bundle must be well formed before anything is signed (format, hashes, only SKILL.md files).
python3 "$here/build-skills-bundle.py" check --manifest "$manifest" || fail 'bundle check failed; nothing was signed.'

version=$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8'))['bundle_version'])
PY
)

tmp=$(mktemp -d)
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

# 2. Sign. ssh-keygen asks for the key passphrase itself; this script never sees it.
ssh-keygen -Y sign -f "$key" -n "$namespace" "$manifest" || fail 'ssh-keygen -Y sign failed.'
[[ -f "$manifest.sig" ]] || fail 'no signature file was produced.'

# 3. Read back: verify with the pinned allowed_signers when it is real, else with the public key only
#    (placeholder state) and say so, so a wrong key is caught before upload.
state=$(python3 "$here/build-skills-bundle.py" signers-status --file "$signers" 2>/dev/null || true)
principals=()
if [[ "$state" == pinned:* ]]; then
  verify_file=$signers
  while read -r p; do principals+=("$p"); done < <(awk '!/^[[:space:]]*#/ && NF {print $1}' "$signers" | sort -u)
  note='verified against the pinned config/skills-allowed-signers'
else
  verify_file="$tmp/allowed_signers"
  principals=('rescue-owner')
  printf '%s namespaces="%s" %s\n' 'rescue-owner' "$namespace" "$(awk '{print $1, $2}' "$pub")" >"$verify_file"
  note='WARNING: config/skills-allowed-signers is not pinned yet; verified only against your public key. Open the PR that pins it BEFORE releasing: a USB will refuse this bundle until then.'
fi
ok=0
for principal in "${principals[@]}"; do
  if ssh-keygen -Y verify -f "$verify_file" -I "$principal" -n "$namespace" -s "$manifest.sig" <"$manifest" >/dev/null 2>&1; then
    ok=1
    break
  fi
done
((ok)) || { rm -f -- "$manifest.sig"; fail 'read-back verification failed (is this the pinned key?); signature removed.'; }
printf 'Signed and read back: %s.sig\n%s\n' "$manifest" "$note"

dir=$(dirname -- "$manifest")
tarball="$dir/rescue-skills-$version.tar.gz"
printf '\nUpload (run it yourself after the release authorization; nothing was uploaded):\n'
printf '  gh release upload v%s -R ahliweb/linux-mint-xfce-rescue-ai %q %q %q\n' \
  "$version" "$tarball" "$manifest" "$manifest.sig"
