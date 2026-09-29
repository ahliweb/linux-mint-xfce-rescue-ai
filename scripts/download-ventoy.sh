#!/usr/bin/env bash
set -Eeuo pipefail

out_dir="$PWD/ventoy-download"
version=''
while (($#)); do
  case "$1" in
    --output-dir) out_dir=${2:?missing output directory}; shift 2 ;;
    --version) version=${2:?missing version}; shift 2 ;;
    *) printf 'usage: %s [--output-dir DIR] [--version TAG]\n' "$0" >&2; exit 2 ;;
  esac
done
# Validate input before any network access.
if [[ -n "$version" ]] && ! [[ "$version" =~ ^v?[0-9]+(\.[0-9]+)*$ ]]; then
  printf 'Invalid --version (expected e.g. 1.0.99 or v1.0.99): %s\n' "$version" >&2
  exit 2
fi
command -v curl >/dev/null || { printf 'curl is required.\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'python3 is required.\n' >&2; exit 1; }
command -v sha256sum >/dev/null || { printf 'sha256sum is required.\n' >&2; exit 1; }
mkdir -p "$out_dir"

# Exactly one GitHub API call: the same release JSON provides the asset name,
# URL and digest, so "latest" cannot change between lookups.
url=$(python3 - "$version" "$out_dir" <<'PY'
import json, pathlib, sys, urllib.request
version, out = sys.argv[1:]
if version:
    tag = version if version.startswith('v') else f'v{version}'
    url = f'https://api.github.com/repos/ventoy/Ventoy/releases/tags/{tag}'
else:
    url = 'https://api.github.com/repos/ventoy/Ventoy/releases/latest'
req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'linux-mint-xfce-rescue-ai'})
with urllib.request.urlopen(req, timeout=30) as r:
    release = json.load(r)
assets = [a for a in release.get('assets', []) if a['name'].endswith('-linux.tar.gz')]
if len(assets) != 1:
    raise SystemExit(f'expected one Ventoy Linux asset, found {len(assets)}')
a = assets[0]
prefix = 'https://github.com/ventoy/Ventoy/releases/download/'
if not a['browser_download_url'].startswith(prefix):
    raise SystemExit(f"unexpected download URL: {a['browser_download_url']}")
if '/' in a['name'] or a['name'].startswith('.'):
    raise SystemExit(f"unsafe asset name: {a['name']}")
(pathlib.Path(out) / 'ventoy-release.json').write_text(json.dumps({
    'tag_name': release['tag_name'],
    'asset': a['name'],
    'browser_download_url': a['browser_download_url'],
    'digest': a.get('digest'),
}, indent=2) + '\n')
print(a['browser_download_url'])
PY
)
[[ "$url" == https://github.com/ventoy/Ventoy/releases/download/* ]] || {
  printf 'Refusing unexpected Ventoy download URL: %s\n' "$url" >&2
  exit 1
}
file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["asset"])' "$out_dir/ventoy-release.json")
expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("digest") or "")' "$out_dir/ventoy-release.json")
if [[ "$expected" != sha256:* ]]; then
  printf 'Ventoy release metadata did not expose a sha256 digest; refusing automatic installation.\n' >&2
  exit 1
fi
curl --fail --location --show-error --output "$out_dir/$file" "$url"
actual=$(sha256sum "$out_dir/$file")
actual=${actual%% *}
if [[ "${expected#sha256:}" != "$actual" ]]; then
  rm -f -- "$out_dir/$file"
  printf 'Ventoy digest mismatch: expected=%s actual=%s (downloaded file removed)\n' "$expected" "$actual" >&2
  exit 1
fi
printf 'Ventoy release digest: PASS (%s)\n' "$actual"
