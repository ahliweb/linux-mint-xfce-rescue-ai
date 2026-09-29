#!/usr/bin/env bash
set -Eeuo pipefail
# Read-only evidence collector. Output is created with a restrictive umask.
umask 077

usage() {
  printf 'usage: %s [--output FILE]\n' "$0" >&2
  exit 2
}

out='evidence.json'
while (($#)); do
  case "$1" in
    --output)
      if (($# < 2)) || [[ -z "${2:-}" ]]; then
        printf 'error: --output requires a non-empty FILE argument\n' >&2
        usage
      fi
      out=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

python3 - "$out" <<'PY'
import hashlib, json, os, platform, shutil, socket, subprocess, sys, tempfile
from datetime import datetime, timezone

out = sys.argv[1]
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def run(cmd):
    """Return stdout (stripped) of an allowlisted read-only command, or None if it cannot run or fails."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=8, check=False)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def check(check_id, status):
    return {'check_id': check_id, 'status': status, 'source': 'collector-allowlist', 'observed_at': now}

def kernel_log_status():
    for cmd in (['journalctl', '-k', '-b', '--no-pager', '-n', '1'], ['dmesg']):
        text = run(cmd)
        if text:
            lines = [l for l in text.splitlines()
                     if l.strip() and not l.startswith('-- ') and not l.startswith('No journal files')]
            if lines:
                return 'pass'
    return 'unknown'

def filesystem_status():
    return 'pass' if run(['findmnt', '-no', 'FSTYPE', '/']) else 'unknown'

def network_status():
    if shutil.which('ip') is None:
        return 'unknown'
    route = run(['ip', 'route', 'show', 'default'])
    if route is None:
        return 'unknown'
    if route:
        return 'pass'
    links = run(['ip', '-brief', 'link']) or ''
    non_loopback = [l for l in links.splitlines() if l.split() and l.split()[0] != 'lo']
    return 'warn' if non_loopback else 'unknown'

def block_status():
    return 'pass' if run(['lsblk', '-dn', '-o', 'TYPE']) else 'unknown'

def opaque_seed():
    # Prefer /etc/machine-id (hashed and truncated below; never emitted raw).
    try:
        with open('/etc/machine-id', encoding='ascii') as f:
            mid = f.read().strip()
        if mid:
            return 'machine-id:' + mid
    except (OSError, UnicodeDecodeError):
        pass
    return 'hostname:' + socket.gethostname() + '|' + platform.release()

checks = [
    check('kernel-log', kernel_log_status()),
    check('filesystem-discovery', filesystem_status()),
    check('network-connectivity', network_status()),
    check('block-device-discovery', block_status()),
]
manifest_sha = digest(json.dumps(checks, sort_keys=True))
report = {
    'schema_version': '1.0',
    'run_id': 'rescue-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'),
    'source_platform': 'linux-mint-xfce-live',
    'boot_mode': 'uefi' if os.path.exists('/sys/firmware/efi') else 'legacy-bios',
    'collected_at': now,
    'target_device_opaque_id': 'target-' + digest(opaque_seed())[:16],
    'ventoy_version': None,
    'linux_release': platform.platform()[:63],
    'checks': checks,
    'evidence_manifest': {'entry_count': len(checks), 'manifest_sha256': manifest_sha, 'storage_class': 'volatile-live-session'},
    'ai_provider': {'provider_id': 'opencode-go', 'model_id': 'configured-at-runtime', 'authenticated': False, 'destination_class': 'unknown'},
    'ai_analysis_status': 'not_run',
    'mutation_status': 'none',
    # Nothing is hashed against a trusted reference or read back by this collector.
    'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
    'classification': 'restricted',
    'source_references': ['opencode-go:provider', 'opencode:cli', 'nist:sp-800-86'],
}

# Atomic, private creation: temp file is 0600 from birth (mkstemp + umask 077), then renamed into place.
directory = os.path.dirname(os.path.abspath(out))
os.makedirs(directory, mode=0o700, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=directory)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print(out)
PY
printf 'wrote %s\n' "$out"
