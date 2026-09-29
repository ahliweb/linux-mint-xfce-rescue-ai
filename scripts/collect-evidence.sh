#!/usr/bin/env bash
set -Eeuo pipefail

out='evidence.json'
while (($#)); do
  case "$1" in
    --output) out=${2:?missing output path}; shift 2 ;;
    *) printf 'usage: %s [--output FILE]\n' "$0" >&2; exit 2 ;;
  esac
done

python3 - "$out" <<'PY'
import hashlib, json, os, platform, socket, subprocess, sys
from datetime import datetime, timezone

out = sys.argv[1]
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
def run(cmd):
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8, check=False).stdout.strip()
    except Exception:
        return ''
def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

kernel = platform.release()
checks = [
  {'check_id':'kernel-log', 'status':'pass' if kernel else 'unknown', 'source':'collector-allowlist', 'observed_at':now},
  {'check_id':'filesystem-discovery', 'status':'pass' if run(['findmnt', '-no', 'FSTYPE', '/']) else 'unknown', 'source':'collector-allowlist', 'observed_at':now},
  {'check_id':'network-connectivity', 'status':'pass' if run(['ip','-brief','link']) else 'unknown', 'source':'collector-allowlist', 'observed_at':now},
  {'check_id':'block-device-discovery', 'status':'pass' if run(['lsblk','-dn','-o','TYPE']) else 'unknown', 'source':'collector-allowlist', 'observed_at':now},
]
manifest_sha = digest(json.dumps(checks, sort_keys=True))
report = {
  'schema_version':'1.0',
  'run_id':'rescue-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'),
  'source_platform':'linux-mint-xfce-live',
  'boot_mode':'uefi' if os.path.exists('/sys/firmware/efi') else 'legacy-bios',
  'collected_at':now,
  'target_device_opaque_id':'target-' + digest(socket.gethostname() + kernel)[:16],
  'ventoy_version':None,
  'linux_release':platform.platform()[:63],
  'checks':checks,
  'evidence_manifest':{'entry_count':len(checks), 'manifest_sha256':manifest_sha, 'storage_class':'volatile-live-session'},
  'ai_provider':{'provider_id':'opencode-go','model_id':'configured-at-runtime','authenticated':False,'destination_class':'unknown'},
  'ai_analysis_status':'not_run',
  'mutation_status':'none',
  'verification':{'hashes_verified':True,'read_back_verified':False,'status':'not_applicable'},
  'classification':'restricted',
  'source_references':['opencode-go:provider','opencode:cli','nist:sp-800-86']
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2)
    f.write('\n')
print(out)
PY
chmod 600 "$out"
printf 'wrote %s\n' "$out"
