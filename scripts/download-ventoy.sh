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
command -v curl >/dev/null || { printf 'curl is required.\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'python3 is required.\n' >&2; exit 1; }
mkdir -p "$out_dir"

python3 - "$version" "$out_dir" <<'PY'
import json, pathlib, sys, urllib.request
version, out = sys.argv[1:]
if version:
    url = f'https://api.github.com/repos/ventoy/Ventoy/releases/tags/{version}'
else:
    url = 'https://api.github.com/repos/ventoy/Ventoy/releases/latest'
req = urllib.request.Request(url, headers={'Accept':'application/vnd.github+json','User-Agent':'linux-mint-xfce-rescue-ai'})
with urllib.request.urlopen(req, timeout=30) as r:
    release = json.load(r)
assets = [a for a in release.get('assets', []) if a['name'].endswith('-linux.tar.gz')]
if len(assets) != 1:
    raise SystemExit(f'expected one Ventoy Linux asset, found {len(assets)}')
a = assets[0]
path = pathlib.Path(out) / a['name']
(path.parent / 'ventoy-release.json').write_text(json.dumps({'tag_name':release['tag_name'],'asset':a['name'],'browser_download_url':a['browser_download_url'],'digest':a.get('digest')}, indent=2)+'\n')
print(a['browser_download_url'])
print(a.get('digest') or '')
print(path)
PY
url=$(sed -n '1p' <(python3 - "$version" "$out_dir" <<'PY'
import json,sys,urllib.request
v,o=sys.argv[1:]; u=f'https://api.github.com/repos/ventoy/Ventoy/releases/tags/{v}' if v else 'https://api.github.com/repos/ventoy/Ventoy/releases/latest'
r=urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'rescue-ai'}),timeout=30); d=json.load(r)
print([a['browser_download_url'] for a in d['assets'] if a['name'].endswith('-linux.tar.gz')][0])
PY
))
file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["asset"])' "$out_dir/ventoy-release.json")
curl --fail --location --show-error --output "$out_dir/$file" "$url"
expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("digest") or "")' "$out_dir/ventoy-release.json")
actual=$(sha256sum "$out_dir/$file" | awk '{print $1}')
if [[ "$expected" == sha256:* ]]; then
  [[ "${expected#sha256:}" == "$actual" ]] || {
    printf 'Ventoy digest mismatch: expected=%s actual=%s\n' "$expected" "$actual" >&2
    exit 1
  }
  printf 'Ventoy release digest: PASS (%s)\n' "$actual"
else
  printf 'Ventoy release metadata did not expose a digest; refusing automatic installation.\n' >&2
  exit 1
fi
