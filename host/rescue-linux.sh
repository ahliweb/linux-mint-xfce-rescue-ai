#!/usr/bin/env bash
# Host launcher for a RUNNING Linux / Linux Mint (not the live USB session).
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# Read-only checks (OS + rescue_modules) -> schema 1.2 evidence -> direct OpenCode Go analysis
# -> catalog repairs under the operator's policy (scripts/rescue-repair.py).
# Everything is read from and written to the rescue USB (<bundle>/reports/).
# Nothing is installed and nothing is written to the host disk.
#
# Every exit after the reports folder is known also writes the comprehensive run report
# (reports/run-<utc>/report.md + report.json, reports/index.md; docs/run-report.md) to the USB.
#
# Exit codes: 0 ok | 1 a repair action failed or was rolled back | 2 invalid evidence, catalog or
#             selection | 3 no API key | 4 network/HTTP error (run outcome network-error, or
#             provider-rejected when the provider answered with an HTTP 4xx other than
#             401/403/408/429) | 5 bundle/reports dir or repair journal unusable | 6 analyzer script
#             missing or python3-jsonschema missing on this host (outcome dependency-missing; the
#             evidence is still collected, nothing is installed, no analysis and no repairs) |
#             64 usage   (3 and 4 take precedence over 1 and 2, as in the Windows and macOS launchers)
# Outcome precedence: the run outcome is the FIRST failure (scan, evidence, key, network, provider,
#             analyzer); a repair-engine failure never replaces it. It is added to the report as the
#             open item repair-engine-failed (exit-2 or exit-3) and the exit code stays the first
#             failure's. A repair journal that cannot be used (engine exit 3) outranks everything,
#             as in the macOS launcher: outcome journal-unusable and exit 5.
# Launcher log: everything this launcher and its child tools print (none of them prints the API key)
#             is also appended to reports/launcher-linux-<utc>.log on the USB (0600 where the
#             filesystem has modes; never on the host disk).
set -Eeuo pipefail
umask 077

usage() {
  cat >&2 <<'EOF'
usage: rescue-linux.sh [--evidence-only] [--dry-run] [--bundle DIR] [--pause]
                       [--scope LIST] [--packages LIST] [--repair-policy POLICY] [--malware-full-disk]
  --evidence-only  collect + validate + save evidence; no network, no AI call; repairs listed only
  --dry-run        like --evidence-only, and ask the analyzer to show what it would send
  --scope LIST     all (default) | hardware | hardware.cpu,... | os | software | software.selected | malware
  --malware-full-disk  scan the whole system for malware (slow; default: user-writable and autostart areas)
  --packages LIST  comma list of packages for --scope software.selected
  --repair-policy  detect-only | approve-each (default) | auto-safe
  --bundle DIR     rescue-omes bundle directory (default: auto-detect next to this script)
  --pause          wait for Enter before exiting (for double-click terminals)
EOF
  exit 64
}

evidence_only=0
dry_run=0
pause=0
bundle=''
scope=all
packages=''
repair_policy=approve-each
malware_full=0
while (($#)); do
  case "$1" in
    --evidence-only) evidence_only=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --pause) pause=1; shift ;;
    --bundle) bundle=${2:?--bundle needs a directory}; shift 2 ;;
    --scope) scope=${2:?--scope needs a list}; shift 2 ;;
    --packages) packages=${2:?--packages needs a list}; shift 2 ;;
    --repair-policy) repair_policy=${2:?--repair-policy needs a policy}; shift 2 ;;
    --malware-full-disk) malware_full=1; shift ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done

case $repair_policy in detect-only | approve-each | auto-safe) ;; *) usage ;; esac
[[ $scope =~ ^[a-z.,]+$ ]] || usage
[[ -z $packages || $packages =~ ^[A-Za-z0-9][A-Za-z0-9+._:@,-]*$ ]] || usage

run_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id="rescue-$(date -u +%Y%m%d-%H%M%S)-lh"   # the one run id: report and evidence share it (the re-scan adds -after)
run_outcome=scan-failed
report_ready=0 report_done=0
run_evidence='' run_evidence_after='' run_analysis='' repair_rc=0

# Write the run report to the USB (never blocks or changes the exit code). Idempotent.
emit_report() {
  ((report_ready && !report_done)) || return 0
  report_done=1
  local -a rargs=(python3 "$bundle/scripts/rescue-report.py" --reports-dir "$reports" --run-id "$run_id" --mode linux-host
    --outcome "$run_outcome" --scope "$scope" --repair-policy "$repair_policy" --started-at "$run_started"
    --ended-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --env-file "$bundle/config/rescue.env")
  ((repair_rc == 0)) || rargs+=(--repair-exit "$repair_rc")
  [[ -f $bundle/scripts/rescue-report.py ]] || return 0
  [[ -z $run_evidence || ! -s $run_evidence ]] || rargs+=(--evidence "$run_evidence")
  [[ -z $run_evidence_after || ! -s $run_evidence_after ]] || rargs+=(--evidence-after "$run_evidence_after")
  [[ -z $run_analysis || ! -s $run_analysis ]] || rargs+=(--analysis "$run_analysis")
  [[ ! -e $reports/repairs/journal.jsonl ]] || rargs+=(--journal "$reports/repairs/journal.jsonl")
  "${rargs[@]}" ||
    printf 'PERINGATAN: laporan proses tidak dapat ditulis penuh.\nWARNING: the run report could not be fully written.\n' >&2
}
trap 'emit_report' EXIT
trap 'run_outcome=interrupted; pause=0; finish 130' INT TERM HUP

finish() {
  local rc=$1
  emit_report
  if ((pause)) && [[ -t 0 ]]; then
    printf '\nTekan Enter untuk menutup / Press Enter to close... '
    read -r _ || true
  fi
  exit "$rc"
}

script_dir=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
marker='profiles/rescue-hermes/analysis-prompt.md'
if [[ -z $bundle ]]; then
  for cand in "$script_dir/rescue-omes" "$script_dir/.."; do
    if [[ -f $cand/$marker ]]; then
      bundle=$(cd -- "$cand" && pwd)
      break
    fi
  done
fi
if [[ -z $bundle || ! -f $bundle/$marker ]]; then
  printf 'ERROR: bundle rescue-omes tidak ditemukan / rescue-omes bundle not found next to %s\n' "$script_dir" >&2
  finish 5
fi

reports="$bundle/reports"
if ! mkdir -p -- "$reports" 2>/dev/null || [[ ! -w $reports ]]; then
  printf 'ERROR: folder reports di USB tidak bisa ditulis (USB write-protect?) / reports directory on the USB is not writable.\n' >&2
  finish 5
fi

report_ready=1
export TMPDIR="$reports"          # any tool that wants a temp file uses the USB, not this host
((malware_full)) && export RESCUE_MALWARE_FULL_DISK=1
export PYTHONDONTWRITEBYTECODE=1  # no __pycache__ clutter on the USB bundle

stamp=$(date -u +%Y%m%dT%H%M%SZ)
evidence="$reports/linux-$stamp-evidence.json"
analysis="$reports/linux-$stamp-analysis.md"

# Launcher log on the USB (never the host): everything printed from here on is also appended to it.
# The tools never print the key. fd 3 keeps the real terminal for the interactive repair step.
launcher_log="$reports/launcher-linux-$stamp.log"
interactive_tty=0
if [[ -t 0 && -t 1 ]]; then interactive_tty=1; fi
if : >>"$launcher_log" 2>/dev/null; then
  chmod 600 -- "$launcher_log" 2>/dev/null || true   # exFAT has no modes
  exec 3>&1
  exec > >(tee -a -- "$launcher_log") 2> >(tee -a -- "$launcher_log" >&2)
else
  printf 'PERINGATAN / WARNING: the launcher log could not be created on the USB; continuing without it.\n' >&2
fi
export PYTHONUNBUFFERED=1

# python3-jsonschema is checked once. Without it schema validation, the AI analysis and the catalog
# repairs cannot run; this launcher never installs anything on the host, so it says so and stops there.
have_jsonschema=1
python3 -c 'import jsonschema' 2>/dev/null || have_jsonschema=0

skip_network=0
if ((evidence_only || dry_run || !have_jsonschema)); then skip_network=1; fi   # nothing will be sent
# The analyzer's loopback test hook means no real network is wanted: skip the internet probe too.
if [[ ${RESCUE_TEST_BASE_URL:-} == http://127.0.0.1:* ]]; then skip_network=1; fi

printf 'Rescue host launcher (Linux) - read-only checks; output goes to the USB only.\n'

# Collector: allowlisted read-only commands; only closed-set statuses, bounded numbers.
# collect_evidence OUTPUT_FILE RUN_ID (also used for the post-repair re-scan, with RUN_ID-after).
collect_evidence() {
python3 - "$1" "$skip_network" "$reports" "$bundle" "$scope" "$packages" "$repair_policy" "$2" <<'PY'
import hashlib, json, os, platform, re, shutil, socket, subprocess, sys, tempfile
from datetime import datetime, timezone

out, skip_network, reports = sys.argv[1], sys.argv[2] == '1', sys.argv[3]
bundle, scope_arg, packages_arg, policy, run_id = sys.argv[4:9]
if not re.match(r'^rescue-[0-9]{8}-[0-9]{6}-lh(-after)?$', run_id):  # only the launcher's own run id
    print('invalid run id', file=sys.stderr)
    raise SystemExit(2)
sys.path[:0] = [os.path.join(bundle, 'scripts'), os.path.join(bundle, 'scripts', 'lib')]
try:
    import repair_catalog
    import rescue_modules
except Exception as exc:  # older bundle or missing python3-jsonschema: OS checks only
    repair_catalog = rescue_modules = None
    print('note: detection modules/repair catalog unavailable (%s)' % exc.__class__.__name__, file=sys.stderr)
try:
    scope = repair_catalog.normalize_scope(scope_arg) if repair_catalog else ('all',)
except ValueError as exc:
    print('invalid --scope: %s' % exc, file=sys.stderr)
    raise SystemExit(64)
packages = tuple(x for x in packages_arg.split(',') if x)


def provider_ready():
    """A usable key exists (environment or rescue.env, parsed as data) and the network will be used."""
    if skip_network:
        return False
    if os.environ.get('OPENCODE_GO_API_KEY'):
        return True
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('rescue_analyzer', os.path.join(bundle, 'scripts', 'opencode-go-analyze.py'))
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)
        return bool(analyzer.find_api_key([os.path.join(bundle, 'config', 'rescue.env')]))
    except (Exception, SystemExit):  # the analyzer exits 2 when python3-jsonschema is missing
        return False


ready = provider_ready()
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
REF = 'os-0'


def run(cmd, timeout=20):
    """(rc, stdout, stderr) of an allowlisted read-only command, or None if it cannot run."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
    except Exception:
        return None
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def rec(check_id, status, kind=None, number=None, ref=REF):
    item = {'check_id': check_id, 'status': status, 'source': 'host-allowlist', 'observed_at': now}
    if ref:
        item['target_ref'] = ref
    if kind is not None:
        item['value'] = {'kind': kind, 'number': number}
    return item


def sanitize_release(text):
    text = re.sub(r'[^A-Za-z0-9 ._+()/-]', ' ', text or '')
    text = re.sub(r' +', ' ', text).strip()
    text = re.sub(r'^[^A-Za-z0-9]+', '', text)[:64].strip()
    return text or None


def os_release():
    data = {}
    for path in ('/etc/os-release', '/usr/lib/os-release'):
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
                    if m:
                        data[m.group(1)] = m.group(2).strip('"\'')
            break
        except OSError:
            continue
    return data


osr = os_release()
ids = ((osr.get('ID') or '') + ' ' + (osr.get('ID_LIKE') or '')).lower().split()
family = 'linuxmint' if 'linuxmint' in ids else ('linux-other' if osr else 'unknown')
release = sanitize_release(osr.get('PRETTY_NAME') or osr.get('NAME'))
machine = platform.machine().lower()
arch = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, 'unknown')


def count_status(n, fail_at=None):
    if fail_at is not None and n >= fail_at:
        return 'fail'
    return 'warn' if n > 0 else 'pass'


def check_disk_free():
    try:
        u = shutil.disk_usage('/')
    except OSError:
        return rec('disk-free-space', 'unknown')
    pct = round(u.free * 100.0 / u.total, 1) if u.total else 0
    status = 'fail' if pct < 5 else ('warn' if pct < 10 else 'pass')
    return rec('disk-free-space', status, 'percent', pct)


def check_failed_units():
    r = run(['systemctl', '--failed', '--no-legend', '--plain'])
    if r is None or r[0] != 0:
        return rec('linux-failed-units', 'unknown')
    n = len([l for l in r[1].splitlines() if l.strip()])
    return rec('linux-failed-units', count_status(n), 'count', n)


def check_journal_errors():
    r = run(['journalctl', '-p', '3', '-b', '--no-pager'], timeout=30)
    if r is None or r[0] != 0:
        return rec('linux-journal-errors', 'unknown')
    text = r[1] + '\n' + r[2]
    low = text.lower()
    if 'insufficient permissions' in low or 'not seeing messages from other users' in low or 'no journal files' in low:
        return rec('linux-journal-errors', 'unknown')
    n = len([l for l in r[1].splitlines() if l.strip() and not l.startswith('-- ')])
    return rec('linux-journal-errors', count_status(n, fail_at=50), 'count', n)


def check_kernel_initrd():
    ver = platform.release()
    try:
        names = set(os.listdir('/boot'))
    except OSError:
        return rec('linux-kernel-initrd', 'unknown')
    kernels = {'vmlinuz-' + ver, 'vmlinux-' + ver, 'kernel-' + ver}
    initrds = {'initrd.img-' + ver, 'initramfs-' + ver + '.img', 'initrd-' + ver, 'initrd-' + ver + '.img', 'initramfs-linux.img'}
    if not (names & kernels) and not (names & initrds):
        return rec('linux-kernel-initrd', 'unknown')
    return rec('linux-kernel-initrd', 'pass' if names & initrds else 'fail')


def check_package_state():
    if shutil.which('dpkg') is None:
        return rec('linux-package-state', 'not_applicable')
    r = run(['dpkg', '--audit'])
    if r is None or r[0] != 0:
        return rec('linux-package-state', 'unknown')
    return rec('linux-package-state', 'warn' if r[1].strip() else 'pass')


def detect_encryption():
    r = run(['lsblk', '-rno', 'TYPE,FSTYPE'])
    if r is None or r[0] != 0:
        return 'unknown'
    for line in r[1].splitlines():
        parts = line.split()
        if (parts and parts[0] == 'crypt') or 'crypto_LUKS' in parts:
            return 'luks'
    return 'none'


def check_smart():
    if shutil.which('smartctl') is None:
        return rec('smart-health', 'unknown')
    scan = run(['smartctl', '--scan'])
    if scan is None or scan[0] != 0:
        return rec('smart-health', 'unknown')
    results = []
    for line in scan[1].splitlines()[:4]:
        dev = line.split()[0] if line.split() else ''
        if not dev.startswith('/dev/'):
            continue
        r = run(['smartctl', '-H', dev])
        if r is None:
            continue
        text = r[1]
        if 'FAILED' in text:
            results.append('fail')
        elif 'PASSED' in text or re.search(r'Health Status:\s*OK', text):
            results.append('pass')
        else:
            results.append('unknown')  # typically: permission denied without root
    if 'fail' in results:
        return rec('smart-health', 'fail')
    if results and all(x == 'pass' for x in results):
        return rec('smart-health', 'pass')
    return rec('smart-health', 'unknown')


def check_network():
    if skip_network:
        return rec('network-connectivity', 'unknown', ref=None)
    try:
        socket.create_connection(('opencode.ai', 443), timeout=5).close()
        return rec('network-connectivity', 'pass', ref=None)
    except OSError:
        return rec('network-connectivity', 'fail', ref=None)


encryption = detect_encryption()
enc_check = rec('encryption-status', 'unknown' if encryption == 'unknown' else 'pass')
os_check = rec('os-detection', 'pass' if family != 'unknown' else 'unknown')
checks = [
    os_check,
    check_disk_free(),
    check_failed_units(),
    check_journal_errors(),
    check_kernel_initrd(),
    check_package_state(),
    enc_check,
    # smart-health is a disk check: only within the operator's hardware.disk scope.
    *([check_smart()] if ('all' in scope or 'hardware' in scope or 'hardware.disk' in scope) else []),
    check_network(),
]
if rescue_modules is not None:
    mctx = rescue_modules.Context(mode='host', scope=scope, packages=packages, state_dir=reports,
                                  malware_full_disk=os.environ.get('RESCUE_MALWARE_FULL_DISK') == '1')
    checks += [rec(c['check_id'], c['status'], c.get('kind'), c.get('number'), ref=c.get('target_ref'))
               for c in rescue_modules.collect_system(mctx)]
    rescue_modules.flush_warnings(mctx)
    if mctx.detections:
        try:  # LOCAL list (paths inside, 0600): never evidence, never sent to the cloud
            rescue_modules.malware.write_detection_list(mctx, run_id, lambda ref: REF)
            print('malware: %d detection(s) recorded in the local list on the USB (never sent)' % len(mctx.detections),
                  file=sys.stderr)
        except (OSError, ValueError) as exc:
            print('warning: could not write the local malware detection list: %s' % exc, file=sys.stderr)
checks = checks[:160]


def opaque_seed():
    # /etc/machine-id is hashed and truncated below; it is never emitted raw.
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, encoding='ascii') as f:
                mid = f.read().strip()
            if mid:
                return 'machine-id:' + mid
        except (OSError, UnicodeDecodeError):
            pass
    return 'fallback:' + digest(socket.gethostname() + '|' + platform.release())


if os.path.exists('/sys/firmware/efi'):
    boot_mode = 'uefi'
elif machine in ('x86_64', 'amd64', 'i386', 'i686'):
    boot_mode = 'legacy-bios'
else:
    boot_mode = 'unknown'

compact = json.dumps(checks, sort_keys=True, separators=(',', ':'))
report = {
    'schema_version': '1.2',
    'run_id': run_id,
    'source_platform': 'linux-host',
    'boot_mode': boot_mode,
    'collected_at': now,
    'target_device_opaque_id': 'target-' + digest(opaque_seed())[:16],
    'ventoy_version': None,
    'linux_release': None,
    'target_systems': [{
        'ref': REF, 'family': family, 'release': release, 'architecture': arch,
        'detection': 'host-native', 'encryption': encryption, 'access': 'host-running',
    }],
    'checks': checks,
    'evidence_manifest': {'entry_count': len(checks), 'manifest_sha256': digest(compact), 'storage_class': 'usb-rescue-state'},
    'ai_provider': {'provider_id': 'opencode-go', 'model_id': 'mimo-v2.6-flash', 'authenticated': ready,
                    'destination_class': 'cloud' if ready else 'unknown'},
    'ai_analysis_status': 'not_run',
    'mutation_status': 'none',
    'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
    'classification': 'confidential',
    'source_references': ['opencode-go:provider', 'nist:sp-800-86'],
    'scope': list(scope),
    'repair_policy': policy,
}
if repair_catalog is not None:
    try:
        proposals = repair_catalog.triggered(repair_catalog.load(), report, scope)[:32]
        if proposals:
            report['repair_proposals'] = proposals
    except Exception as exc:
        print('note: repair catalog unusable, no proposals (%s)' % exc.__class__.__name__, file=sys.stderr)

# Structural self-check (the full JSON Schema check runs afterwards when jsonschema is available).
STATUSES = {'pass', 'fail', 'warn', 'not_applicable', 'unknown'}
problems = []
for key in ('schema_version', 'run_id', 'source_platform', 'boot_mode', 'collected_at', 'target_device_opaque_id',
            'checks', 'evidence_manifest', 'ai_provider', 'ai_analysis_status', 'mutation_status',
            'verification', 'classification'):
    if key not in report:
        problems.append('missing ' + key)
if not re.match(r'^target-[A-Za-z0-9][A-Za-z0-9._-]{3,47}$', report['target_device_opaque_id']):
    problems.append('bad opaque id')
for c in checks:
    if c['status'] not in STATUSES or c['source'] != 'host-allowlist':
        problems.append('bad check ' + c['check_id'])
if report['target_systems'][0]['release'] is not None and not re.match(
        r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$', report['target_systems'][0]['release']):
    problems.append('bad release')
if problems:
    print('evidence self-check failed: ' + ', '.join(problems), file=sys.stderr)
    raise SystemExit(2)

# Private atomic write on the USB reports directory.
fd, tmp = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=reports)
try:
    os.fchmod(fd, 0o600)
except OSError:
    pass  # exFAT does not implement modes
try:
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
PY
}
rc=0
collect_evidence "$evidence" "$run_id" || rc=$?
if ((rc == 64)); then usage; fi
if ((rc != 0)); then
  printf 'ERROR: evidence gagal dibuat / evidence could not be created (exit %d).\n' "$rc" >&2
  run_outcome=scan-failed
  finish 2
fi
printf 'Evidence tersimpan / saved: %s\n' "$evidence"

validator="$bundle/scripts/validate-evidence.py"
if ((!have_jsonschema)); then
  printf '\nID: python3-jsonschema tidak ada di komputer ini. Validasi schema, analisis AI, dan perbaikan katalog membutuhkannya.\n'
  printf '    Launcher ini TIDAK memasang apa pun di komputer ini. Evidence tetap dikumpulkan (hanya pemeriksaan struktur internal) dan tersimpan di USB:\n    %s\n' "$evidence"
  printf '    Analisis evidence itu dengan boot dari live USB rescue, atau dari PC lain yang punya python3-jsonschema.\n'
  printf 'EN: python3-jsonschema is not installed on this computer. Schema validation, the AI analysis and catalog repairs need it.\n'
  printf '    This launcher installs NOTHING on this computer. The evidence was still collected (internal structural check only) and is saved on the USB (path above).\n'
  printf '    Analyze it by booting the rescue live USB, or from another PC that has python3-jsonschema.\n'
elif [[ -f $validator ]]; then
  if ! python3 "$validator" "$evidence"; then
    printf 'ERROR: evidence tidak valid terhadap schema; tidak dikirim / evidence failed schema validation; nothing was sent.\n' >&2
    run_outcome='evidence-invalid'
    finish 2
  fi
else
  printf 'Catatan / note: python3-jsonschema atau validator tidak tersedia; hanya pemeriksaan struktur internal yang dilakukan.\n'
fi
run_evidence=$evidence
run_outcome=completed

# Catalog repairs (typed actions only; see docs/repair-framework.md). The journal and every
# result stay on the USB. --list only plans; it never executes or journals.
run_repair() {
  local repairer="$bundle/scripts/rescue-repair.py" rargs
  [[ -f $repairer ]] || return 0
  rargs=(python3 "$repairer" --evidence "$evidence" --policy "$repair_policy" --scope "$scope"
    --journal "$reports/repairs/journal.jsonl")
  [[ -z $packages ]] || rargs+=(--packages "$packages")
  [[ ! -s $analysis ]] || rargs+=(--analysis "$analysis")
  [[ ${1:-} != list ]] || rargs+=(--list)
  printf '\n'
  repair_rc=0
  # The engine decides "interactive" from stdin AND stdout being a terminal: with a terminal its stdout
  # bypasses the log tee (its journal is the record); its stderr (diagnostics) is always logged.
  if ((interactive_tty)); then "${rargs[@]}" 1>&3 || repair_rc=$?; else "${rargs[@]}" || repair_rc=$?; fi
  ((repair_rc == 0)) || printf 'PERINGATAN / WARNING: repair step reported a failure (exit %d); see %s\n' "$repair_rc" "$reports/repairs/journal.jsonl" >&2
  # Outcome precedence: keep the first failure (scan/evidence/key/network/provider/analyzer). Only a run
  # that has not failed yet takes repair-invalid; an unusable journal outranks everything (as in macOS).
  case $repair_rc in
    2) case $run_outcome in completed | evidence-only | dry-run) run_outcome=repair-invalid ;; *) ;; esac ;;
    3) run_outcome=journal-unusable ;;
    *) ;;
  esac
  # Before/after: when an action executed in this run, re-collect with the same scope for the report.
  if [[ ${1:-} != list && -s $reports/repairs/journal.jsonl ]] &&
    ev_run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$evidence" 2>/dev/null) &&
    grep -F -- "\"run_id\":\"$ev_run_id\"" "$reports/repairs/journal.jsonl" | grep -Fq -- '"stage":"execute"'; then
    printf 'Mengumpulkan ulang setelah perbaikan (scope sama) / re-collecting after repairs (same scope)...\n'
    if collect_evidence "$reports/linux-$stamp-evidence-after.json" "$run_id-after"; then
      run_evidence_after="$reports/linux-$stamp-evidence-after.json"
    else
      printf 'PERINGATAN / WARNING: the re-scan failed; no before/after comparison.\n' >&2
    fi
  fi
}

repair_rc=0

if ((evidence_only && !dry_run)); then
  printf 'Mode --evidence-only: tidak ada panggilan jaringan / no network call was made.\n'
  run_outcome='evidence-only'
  if ((have_jsonschema)); then run_repair list; fi   # the repair engine needs python3-jsonschema
  finish 0
fi

if ((!have_jsonschema)); then
  # No analyzer, no repair engine (not even --list): see the note above. The evidence is kept.
  run_outcome='dependency-missing'
  finish 6
fi

analyzer="$bundle/scripts/opencode-go-analyze.py"
if [[ ! -f $analyzer ]]; then
  printf 'ERROR: scripts/opencode-go-analyze.py belum ada di bundle; evidence tetap tersimpan di %s\n' "$evidence" >&2
  printf 'ERROR: scripts/opencode-go-analyze.py is missing from the bundle; the evidence is kept at %s\n' "$evidence" >&2
  run_outcome='analyzer-missing'
  finish 6
fi

args=(python3 "$analyzer" --evidence "$evidence" --output "$analysis" --env-file "$bundle/config/rescue.env")
if ((dry_run)); then args+=(--dry-run); fi
set +e
"${args[@]}"
rc=$?
set -e
case $rc in
  0) if ((dry_run)); then run_outcome=dry-run; else run_outcome=completed; run_analysis=$analysis; fi ;;
  3) run_outcome=no-key ;;
  4) run_outcome=network-error ;;
  5) run_outcome=provider-rejected ;;
  *) run_outcome='analysis-failed' ;;
esac
if ((dry_run)); then run_repair list; else run_repair; fi

# The analyzer failed first: its exit code stands (a repair-engine failure is only recorded in the
# report), except that an unusable repair journal outranks it, as in the macOS launcher.
finish_first_failure() {
  if ((repair_rc == 3)); then finish 5; fi
  finish "$1"
}

case $rc in
  0)
    if ((dry_run)); then
      printf '\nDry-run selesai; tidak ada permintaan dikirim / dry-run finished; nothing was sent.\n'
    else
      printf '\nAnalisis tersimpan / analysis saved: %s\n' "$analysis"
    fi
    # Same repair exit codes as the Windows and macOS launchers.
    case $repair_rc in 0) finish 0 ;; 1) finish 1 ;; 3) finish 5 ;; *) finish 2 ;; esac
    ;;
  3)
    printf '\nID: OPENCODE_GO_API_KEY tidak ditemukan di rescue-omes/config/rescue.env. Evidence tetap tersimpan di:\n    %s\n    Isi kunci pada file itu (satu baris KEY=..., jangan dibagikan) lalu jalankan ulang, atau kirim evidence dari PC lain.\n' "$evidence" >&2
    printf 'EN: OPENCODE_GO_API_KEY was not found in rescue-omes/config/rescue.env. The evidence is kept at the path above.\n    Add the key to that file (one KEY=... line, keep it private) and run again, or analyze the evidence from another PC.\n' >&2
    finish_first_failure 3
    ;;
  4)
    printf '\nID: Gagal menghubungi OpenCode Go (jaringan/HTTP). Evidence tetap tersimpan di:\n    %s\n    Periksa koneksi internet lalu jalankan ulang.\n' "$evidence" >&2
    printf 'EN: Could not reach OpenCode Go (network/HTTP error). The evidence is kept at the path above. Check the connection and run again.\n' >&2
    finish_first_failure 4
    ;;
  5)
    # The provider answered with an HTTP 4xx (not 401/403/408/429): the analyzer already printed the
    # status and the error type. Launcher exit code stays 4, the network/HTTP class.
    printf '\nID: OpenCode Go menolak permintaan (HTTP 4xx, bukan masalah jaringan). Evidence tetap tersimpan di:\n    %s\n    Lihat pesan di atas lalu jalankan ulang; bila berulang, laporkan kode HTTP dan tipe galatnya.\n' "$evidence" >&2
    printf 'EN: OpenCode Go rejected the request (HTTP 4xx, not a network problem). The evidence is kept at the path above.\n    See the message above and run again; if it repeats, report the HTTP status and error type.\n' >&2
    finish_first_failure 4
    ;;
  *)
    printf '\nID: Analyzer berhenti dengan kode %d. Evidence tetap tersimpan di %s\nEN: The analyzer exited with code %d. The evidence is kept at %s\n' "$rc" "$evidence" "$rc" "$evidence" >&2
    finish_first_failure "$rc"
    ;;
esac
