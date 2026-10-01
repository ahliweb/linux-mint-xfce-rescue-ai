#!/usr/bin/env python3
"""Policy-gated repair engine: run typed catalog actions proposed for one evidence file.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Proposals come from three places, and none of them can inject a command:

  catalog-trigger  an evidence check matches an action's trigger (deterministic)
  ai-proposal      an exact catalog action_id in the ```rescue-proposals block of
                   an analysis file (untrusted data, validated against the catalog)
  operator         --select ACTION_ID

Policy (--policy):
  detect-only   list and journal the proposals; never execute anything
  approve-each  (default) every action needs approval: an interactive prompt or
                --approve ACTION_ID; destructive actions need the action_id typed
  auto-safe     opt-in: catalog-trigger actions with risk "safe" and no missing
                parameter run without a prompt; everything else as approve-each

Every stage is appended to a hash-chained journal (rescue-ai/v1/repair-journal.schema.json)
on the USB. Destructive actions require --backup-ref. Every executed action is followed by
its verify step; a failed execute/verify runs the automatic rollback step when the catalog
has one, otherwise the manual rollback doc is printed.

Android actions (domain android) address one phone through the engine-resolved android_device
parameter: at execution time the engine re-reads the USB inventory and ``adb devices -l``, finds the
and-N target of the proposal, requires it to be adb-authorized and to have the opaque id recorded in
the evidence, and only then renders the integer transport id for ``adb -t``. The id is never read from
evidence, model output or the command line and is never journaled.

Flashing (docs/android.md) adds three more engine-provided pieces, all for the Python engine only.
fastboot_device is resolved like android_device and rendered as the ``usb:<port>`` selector that
``fastboot -s`` accepts (never the serial). firmware_file is an operator-supplied absolute path that the
engine opens without following a final symlink, size-bounds, hashes (it must equal the operator-supplied
firmware_sha256) and hands to the child as an inherited file descriptor (/dev/fd/N), so the bytes that were
hashed are the bytes that are flashed; only the SHA-256 reaches the journal, never the path. Catalog
``guards`` (bootloader-unlocked, image-matches-device, single-download-mode-device) are native checks that
run after approval and refuse with a typed reason before anything is sent to the phone.

Printer actions (docs/printer.md) address one printer through the engine-resolved printer_ref parameter: at
execution time the engine runs the printer discovery again (USB sysfs, ``lpstat``, ``ipptool``; network printers
only with ``--printer-network``), finds the prn-N target of the proposal, requires the opaque id recorded in the
evidence, and only then renders the CUPS queue name into the child argv. The queue name is never read from evidence,
model output or the command line, is never shown (the approval card says ``<printer prn-N>``, the output of a printer
tool is not echoed) and is never journaled. The risk class ``irreversible`` (a test page, a head cleaning, cancelled
jobs: nothing stored is lost but it cannot be undone) always asks, like every class but ``safe``.

This Python engine executes on the live-linux and linux-host platforms. Windows and macOS
evidence can be planned here (--list) but is executed by the host launchers' own engines.

Root precheck: an action with ``requires_root`` run by a non-root engine needs non-interactive sudo. The engine probes
``sudo -n true`` once per run (short timeout, cached); when it is unusable the action is never proposed for approval, nothing
is prompted or executed, and the journal gets ``approval unavailable needs-root``. The plan listing shows
"perlu root / needs root". A host launcher never elevates itself, so on a desktop host those actions are skipped.

Batch approval (approve-each, interactive): when two or more ``safe`` actions are pending the engine shows the table of all
proposals and asks once to approve all of them (default yes on Enter); each is then journaled ``approval ok`` with reason
``operator-approved-batch``. reversible, irreversible, destructive and quarantine actions are never part of the batch.

Device picker (live-linux and linux-host, interactive only): a ``block_device`` parameter the operator has not supplied is
chosen from a numbered list of whole disks that the ENGINE reads from lsblk at that moment (the rescue USB, the live media,
loop/rom devices and removable media are left out unless no other disk exists). The value never comes from evidence, the
analysis or the model, and is checked against the same list again.

Exit codes: 0 finished, nothing failed | 1 an action failed or was rolled back, or the
journal chain is broken (--verify-journal) | 2 invalid arguments, evidence, catalog,
or analysis file | 3 journal not writable
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'lib'))
sys.path.insert(0, str(HERE))
import repair_catalog as rc  # noqa: E402
import malware_detections as md  # noqa: E402
from rescue_modules import android, android_flash, printer, usb_devices  # noqa: E402

SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
EXECUTING_PLATFORMS = {'live-linux', 'linux-host'}
DEFAULT_TIMEOUT = {'precondition': 60, 'execute': 300, 'verify': 120, 'rollback': 300}
ZERO_HASH = '0' * 64
EXIT_OK, EXIT_FAILED, EXIT_INVALID, EXIT_JOURNAL = 0, 1, 2, 3
YES = {'ya', 'y', 'yes'}
CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
# After an Android action ran, the verify step waits this long for a restarted phone to show up again as an
# authorized device (a reboot takes tens of seconds; the transport id changes), polling every few seconds.
ANDROID_WAIT_SECONDS = 150
ANDROID_POLL_SECONDS = 3
ANDROID_CHILD_ENV = ('HOME', 'USER', 'TMPDIR')   # adb keeps its RSA key in ~/.android; fastboot needs nothing
# Firmware files (docs/android.md): size bounds per kind, and what a fastboot update zip may not carry.
FIRMWARE_BYTES = {'image': (4096, 2 << 30), 'zip': (1 << 20, 16 << 30)}
MAX_ANDROID_INFO = 64 * 1024
MAX_ZIP_MEMBERS = 2000
OUTER_FACTORY_SCRIPTS = ('flash-all.sh', 'flash-all.bat', 'flash-base.sh')
FORBIDDEN_IMAGE_STEMS = frozenset({'bootloader', 'radio', 'modem', 'persist', 'efs', 'frp', 'devinfo', 'fsg',
                                   'modemst1', 'modemst2', 'userdata'})
ENGINE_TYPES = ('target_root', 'state_dir', 'android_device', 'fastboot_device', 'fastboot_slot', 'printer_ref', 'bundle_root',
                'bundle_config')
SUDO_PROBE_SECONDS = 8
SUDO_CACHE = {}              # search path -> is `sudo -n true` usable (probed at most once per run)
PICKER_MAX = 32              # at most this many disks are offered by the device picker


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def say(text=''):
    print(text, flush=True)


def warn(text):
    print(text, file=sys.stderr, flush=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------------- journal

class JournalError(Exception):
    pass


class Journal:
    """Append-only JSONL with a SHA-256 chain; one record per stage event."""

    def __init__(self, path, run_id, catalog_sha, policy, platform, evidence_sha):
        self.path = Path(path)
        self.base = {'journal_version': '1', 'run_id': run_id, 'catalog_sha256': catalog_sha,
                     'policy': policy, 'platform': platform, 'evidence_sha256': evidence_sha}
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(fd)
        except OSError as exc:
            raise JournalError('cannot open journal %s: %s' % (self.path, exc.strerror or exc)) from exc

    @staticmethod
    def _tail(path):
        """(seq, sha256) of the last record, or (0, zeros)."""
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 65536))
            lines = [ln for ln in handle.read().split(b'\n') if ln.strip()]
        if not lines:
            return 0, ZERO_HASH
        last = lines[-1]
        return int(json.loads(last.decode('utf-8'))['seq']), hashlib.sha256(last).hexdigest()

    def write(self, **fields):
        record = dict(self.base)
        record.update({k: v for k, v in fields.items() if v is not None})
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_APPEND)
            with os.fdopen(fd, 'r+b') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                seq, prev = self._tail(self.path)
                record['seq'] = seq + 1
                record['prev_sha256'] = prev
                record['recorded_at'] = utc_now()
                line = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
                handle.write(line + b'\n')
                handle.flush()
                os.fsync(handle.fileno())
        except (OSError, ValueError, KeyError) as exc:
            raise JournalError('cannot append to journal %s: %s' % (self.path, exc)) from exc
        return record


def verify_journal(path):
    """Problems in *path*: schema, seq continuity, and the hash chain."""
    jsonschema = rc._jsonschema()
    schema = json.loads((rc.ROOT / 'rescue-ai/v1/repair-journal.schema.json').read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    problems, prev, expected = [], ZERO_HASH, 1
    with open(path, 'rb') as handle:
        for n, raw in enumerate(handle, 1):
            line = raw.rstrip(b'\n')
            if not line.strip():
                continue
            try:
                record = json.loads(line.decode('utf-8'))
            except ValueError:
                problems.append('line %d: not JSON' % n)
                prev = hashlib.sha256(line).hexdigest()
                expected += 1
                continue
            for err in validator.iter_errors(record):
                problems.append('line %d: %s' % (n, err.message))
            if record.get('seq') != expected:
                problems.append('line %d: seq %r, expected %d' % (n, record.get('seq'), expected))
            if record.get('prev_sha256') != prev:
                problems.append('line %d: prev_sha256 does not match the previous line' % n)
            prev = hashlib.sha256(line).hexdigest()
            expected = (record.get('seq') if isinstance(record.get('seq'), int) else expected) + 1
    return problems


# ----------------------------------------------------------------------- runtime

def search_path():
    """SAFE_PATH, or the test override (absolute directories only, announced loudly)."""
    override = os.environ.get('RESCUE_REPAIR_TEST_PATH', '')
    if override:
        parts = override.split(':')
        if all(p.startswith('/') and os.path.isdir(p) for p in parts):
            warn('rescue-repair: TEST PATH override active (RESCUE_REPAIR_TEST_PATH)')
            return override
        warn('rescue-repair: ignoring invalid RESCUE_REPAIR_TEST_PATH')
    return SAFE_PATH


def resolve_argv(argv, requires_root, path):
    program = shutil.which(argv[0], path=path)
    if program is None:
        return None
    full = [program] + list(argv[1:])
    if requires_root and os.geteuid() != 0:
        sudo = shutil.which('sudo', path=path)
        if sudo is None:
            return None
        full = [sudo, '-n', '--'] + full
    return full


def sudo_usable(path):
    """Is non-interactive sudo usable? Probed once per run (`sudo -n true`, short timeout) and cached. Root needs none."""
    if os.geteuid() == 0:
        return True
    if path != SAFE_PATH and os.environ.get('RESCUE_REPAIR_TEST_SUDO_PROBE') != '1':
        return True      # offline tests with RESCUE_REPAIR_TEST_PATH only probe when they ask for it (fake sudo)
    if path not in SUDO_CACHE:
        ok = False
        sudo = shutil.which('sudo', path=path)
        if sudo is not None:
            try:
                ok = subprocess.run([sudo, '-n', 'true'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env={'PATH': path, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
                                    timeout=SUDO_PROBE_SECONDS, check=False).returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
        SUDO_CACHE[path] = ok
    return SUDO_CACHE[path]


def lacks_root(action, path):
    """True when *action* needs root, this engine is not root, and non-interactive sudo is not available."""
    return bool(action.get('requires_root')) and os.geteuid() != 0 and not sudo_usable(path)


def human_size(nbytes):
    size = float(nbytes or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1000 or unit == 'TB':
            return ('%d %s' % (size, unit)) if unit == 'B' else ('%.1f %s' % (size, unit))
        size /= 1000.0


def output_has_line(output, expected):
    """Does the combined output contain a line exactly equal to *expected* (control characters stripped)?"""
    for line in output.decode('utf-8', 'replace').splitlines():
        if CONTROL.sub('', line).strip() == expected:
            return True
    return False


def run_step(step, values, requires_root, path, default_timeout, android=False, pass_fds=()):
    """Run one catalog step; returns a result dict (never raises for the command itself)."""
    argv = rc.render(step['argv'], values)
    full = resolve_argv(argv, requires_root, path)
    if full is None:
        return {'outcome': 'unavailable', 'reason': 'program-not-found', 'argv': argv}
    env = {'PATH': path, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'}
    if android:  # adb finds its RSA key below $HOME/.android; no mDNS (no network) for a USB-only tool
        env.update({k: os.environ[k] for k in ANDROID_CHILD_ENV if os.environ.get(k)})
        env.update({'ADB_MDNS': '0', 'ADB_MDNS_OPENSCREEN': '0'})
    timeout = step.get('timeout_seconds', default_timeout)
    started = time.monotonic()
    try:
        proc = subprocess.run(full, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=env, timeout=timeout, check=False, pass_fds=pass_fds)
        output, code = proc.stdout, proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.output or b''
        return {'outcome': 'timeout', 'reason': 'timeout', 'argv': argv, 'output': output,
                'duration': time.monotonic() - started}
    except OSError:
        return {'outcome': 'unavailable', 'reason': 'program-not-found', 'argv': argv}
    ok = code in step.get('expect_exit', [0])
    if ok and step.get('expect_line') is not None and not output_has_line(output, rc.render_expect_line(step['expect_line'], values)):
        return {'outcome': 'fail', 'reason': 'verify-failed', 'argv': argv, 'exit_code': max(-255, min(255, code)),
                'output': output, 'duration': time.monotonic() - started}
    return {'outcome': 'ok' if ok else 'fail', 'reason': None if ok else 'exit-code', 'argv': argv,
            'exit_code': max(-255, min(255, code)), 'output': output, 'duration': time.monotonic() - started}


def show_output(result, limit=15):
    text = (result.get('output') or b'').decode('utf-8', 'replace')
    lines = [CONTROL.sub('', ln)[:200] for ln in text.splitlines() if ln.strip()]
    for line in lines[-limit:]:
        say('    | ' + line)


def result_fields(result):
    fields = {'outcome': result['outcome'], 'reason': result.get('reason')}
    if 'exit_code' in result:
        fields['exit_code'] = result['exit_code']
    if 'duration' in result:
        fields['duration_seconds'] = round(result['duration'], 3)
    if 'output' in result:
        fields['output_bytes'] = len(result['output'])
        fields['output_sha256'] = hashlib.sha256(result['output']).hexdigest()
    return fields


def backup_fingerprint(path):
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size < 1:
        raise ValueError('backup reference must be a non-empty regular file')
    digest = hashlib.sha256(str(st.st_size).encode('ascii') + b'\0')
    with open(path, 'rb') as handle:
        digest.update(handle.read(1 << 20))
        if st.st_size > (1 << 20):
            handle.seek(max(1 << 20, st.st_size - (1 << 20)))
            digest.update(handle.read(1 << 20))
    return {'size_bytes': st.st_size, 'fingerprint_sha256': digest.hexdigest()}


def block_device_eligible(path, allow_removable=False, keep=()):
    """An existing internal disk/partition that is not the rescue USB or other removable media.

    *allow_removable* is only for a path the device picker listed because no internal disk exists: removable media then
    pass, but the live media, the rescue USB, loop/rom devices and Ventoy volumes never do."""
    try:
        if not stat.S_ISBLK(os.stat(path).st_mode):
            return False
    except OSError:
        return False
    scanner = load_module('rescue_scan_target_os', HERE / 'scan-target-os.py')
    res = scanner.run(['lsblk', '-J', '-b', '-o', scanner.LSBLK_COLUMNS], timeout=20)
    if res is None or res[0] != 0:
        return False
    try:
        tree = json.loads(res[1]).get('blockdevices') or []
    except ValueError:
        return False
    records = []
    scanner._flatten(tree, None, records)
    bad = scanner.excluded_disks(records)
    if allow_removable:
        bad = hard_excluded(scanner, records, keep)
    real = os.path.realpath(path)
    return any(r['path'] in (path, real) and r['disk'] not in bad and r['type'] in ('disk', 'part', 'lvm')
               for r in records)


def state_root(args):
    """The USB state directory (``state_dir`` parameters resolve below it): --state-dir (live), else the reports
    directory that holds ``repairs/<journal>`` when only --journal is given (host launcher:
    ``<usb>/rescue-omes/reports/repairs/journal.jsonl`` -> ``<usb>/rescue-omes/reports``). A journal that does not sit in a
    directory named ``repairs`` gives no state directory (None): the engine refuses state_dir actions instead of
    guessing a directory next to an arbitrary file."""
    if args.state_dir:
        return args.state_dir
    if args.journal:
        parent = os.path.dirname(os.path.abspath(args.journal))
        if os.path.basename(parent) == 'repairs':
            return os.path.dirname(parent)
    return None


def hard_excluded(scanner, records, keep=()):
    """Disks that are never a target even when no internal disk exists: loop/rom/zram, the live media, Ventoy
    volumes, and the disk holding the rescue bundle or the USB state (the rescue USB itself)."""
    bad = set()
    here = [str(rc.ROOT)] + [k for k in keep if k]
    for rec in records:
        disk, path = rec['disk'], rec['path'] or ''
        if rec['type'] in ('loop', 'rom') or path.startswith(('/dev/zram', '/dev/loop', '/dev/sr', '/dev/ram')):
            bad.add(disk)
        if any(mp in scanner.LIVE_MOUNTPOINTS or mp.startswith('/run/live/') for mp in rec['mountpoints']):
            bad.add(disk)
        if (rec['label'] or '').lower() in scanner.VENTOY_LABELS:
            bad.add(disk)
        for mp in rec['mountpoints']:
            if mp != '/' and any(h == mp or h.startswith(mp.rstrip('/') + '/') for h in here):
                bad.add(disk)
    return bad


def target_provider():
    """scripts/lib/target_mount.py (open_target(evidence_path, evidence, target_ref, rw) -> context manager)."""
    path = HERE / 'lib' / 'target_mount.py'
    if not path.is_file():
        return None
    module = load_module('rescue_target_mount', path)
    return getattr(module, 'open_target', None)


# ------------------------------------------------------------------------ engine

class Engine:
    def __init__(self, args, evidence, evidence_sha, catalog, platform, journal):
        self.args, self.evidence, self.evidence_sha = args, evidence, evidence_sha
        self.catalog, self.platform, self.journal = catalog, platform, journal
        self.path = search_path()
        self.interactive = sys.stdin.isatty() and sys.stdout.isatty()
        self.params = args.param_map
        self.packages = set(args.packages) if args.packages else None
        self.results = []
        self.state_root = state_root(args)
        self._detections = None
        self._adb = None
        self._fastboot = None
        self.fds = []                # open firmware files handed to the child as /dev/fd/N (closed after each action)
        self.firmware = {}           # param name -> {'kind', 'android_info'} of the bound firmware files
        self.fb_port = None          # USB port of the fastboot device bound for the current action
        self.android_wait = ANDROID_WAIT_SECONDS
        self.printer_network = bool(getattr(args, 'printer_network', False))   # opt-in for this run (docs/printer.md)
        self.batch = set()           # (action_id, target_ref) of the safe proposals the operator approved at once
        self.index, self.total = 0, 0
        self.removable_ok = set()    # picker choices that are removable media (no internal disk existed)
        self.apply_test_hooks()

    def apply_test_hooks(self):
        """Offline-test hooks, announced loudly like RESCUE_REPAIR_TEST_PATH: a fixture /sys + /proc tree for the
        USB inventory, and a shorter wait for a phone that does not come back."""
        root = os.environ.get('RESCUE_REPAIR_TEST_USB_ROOT', '')
        if root:
            if root.startswith('/') and os.path.isdir(root):
                warn('rescue-repair: TEST USB fixture override active (RESCUE_REPAIR_TEST_USB_ROOT)')
                base = Path(root)
                usb_devices.SYSFS_USB = base / 'sys/bus/usb/devices'
                usb_devices.SYS_ROOT = base / 'sys'
                usb_devices.MOUNTINFO = base / 'proc/self/mountinfo'
                usb_devices.BY_LABEL = base / 'dev/disk/by-label'
                printer.IPP_USB_STATE = base / 'var/ipp-usb/dev'
                printer.FIB_TRIE = base / 'proc/net/fib_trie'
            else:
                warn('rescue-repair: ignoring invalid RESCUE_REPAIR_TEST_USB_ROOT')
        wait = os.environ.get('RESCUE_REPAIR_TEST_ANDROID_WAIT', '')
        if wait.isdigit() and int(wait) <= ANDROID_WAIT_SECONDS:
            warn('rescue-repair: TEST Android wait override active (RESCUE_REPAIR_TEST_ANDROID_WAIT)')
            self.android_wait = int(wait)

    # --------------------------------------------------------------- android_device

    @staticmethod
    def android_param(action):
        """Name of the action's android_device parameter, or None."""
        return next((p['name'] for p in action.get('params') or [] if p['type'] == 'android_device'), None)

    def adb(self):
        if self._adb is None:
            program = android.find_adb(self.path)
            self._adb = android.Adb(program, search_path=self.path) if program else False
        return self._adb or None

    def resolve_android(self, proposal):
        """(transport_id, reason): the adb transport id of the phone the proposal names, or a typed refusal.

        Nothing but the proposal's and-N reference and the evidence's opaque id are used; the phone is looked up
        again right now (USB sysfs + ``adb devices -l``), so a swapped, unplugged or re-numbered phone is caught."""
        ref, expected = proposal.get('target_ref'), self.evidence_opaque_id(proposal)
        if not ref or not expected:
            return None, 'device-mismatch'
        usb_list = usb_devices.list_usb_devices()
        adb = self.adb()
        if usb_list is None or adb is None:
            return None, 'device-absent'
        found = android.discover(usb_list, adb, True)
        current = next((t for t in found if t['ref'] == ref), None)
        if current is None:
            return None, 'device-absent'
        if sum(1 for t in found if t['opaque_id'] == expected) > 1:
            return None, 'device-ambiguous'
        if current['opaque_id'] != expected:
            return None, 'device-mismatch'
        if current['adb_state'] != 'device':
            return None, 'device-not-authorized'
        transport = current['transport_id']
        if not isinstance(transport, int) or isinstance(transport, bool) or not 0 < transport < 1 << 31:
            return None, 'device-absent'
        return transport, None

    @staticmethod
    def device_param(action):
        """(name, type) of the action's android_device or fastboot_device parameter, or (None, None)."""
        return next(((p['name'], p['type']) for p in action.get('params') or []
                     if p['type'] in ('android_device', 'fastboot_device')), (None, None))

    def evidence_target_id(self, proposal, family):
        """The opaque id the evidence recorded for the proposal's target of *family*, or None."""
        ref = proposal.get('target_ref')
        target = next((t for t in self.evidence.get('target_systems') or []
                       if t.get('ref') == ref and t.get('family') == family), None)
        return (target or {}).get('opaque_id') if ref else None

    def evidence_opaque_id(self, proposal):
        """The opaque id the evidence recorded for the proposal's and-N target, or None."""
        return self.evidence_target_id(proposal, 'android')

    # --------------------------------------------------------------- printer_ref

    @staticmethod
    def printer_param(action):
        """Name of the action's printer_ref parameter, or None."""
        return next((p['name'] for p in action.get('params') or [] if p['type'] == 'printer_ref'), None)

    def resolve_printer(self, proposal):
        """(CUPS queue name, reason): the queue of the printer the proposal names, or a typed refusal.

        Nothing but the proposal's prn-N reference and the evidence's opaque id are used; the printers are looked up
        again right now (USB sysfs, lpstat, ipptool; mDNS only with --printer-network), so a swapped, unplugged or
        re-numbered printer is caught. The queue name stays in this process and the child argv."""
        ref, expected = proposal.get('target_ref'), self.evidence_target_id(proposal, 'printer')
        if not ref or not expected:
            return None, 'printer-mismatch'
        usb_list = usb_devices.list_usb_devices()
        tools = printer.Tools(self.path)
        if usb_list is None and tools.lpstat_path is None:
            return None, 'printer-absent'
        found, _status = printer.discover(usb_list, tools, network=self.printer_network)
        current = printer.resolve_ref(found, ref)
        if current is None:
            return None, 'printer-absent'
        if sum(1 for r in found if r['opaque_id'] == expected) > 1:
            return None, 'printer-ambiguous'
        if current['opaque_id'] != expected:
            return None, 'printer-mismatch'
        if current['connection'] == 'network' and not self.printer_network:
            warn('  a network printer is only a target when this run is started with --printer-network')
            return None, 'printer-absent'
        queue = current['_private'].get('queue')
        if not printer.valid_queue(queue):
            warn('  this printer has no CUPS queue to address (create one in Printer Settings first)')
            return None, 'printer-absent'
        return queue, None

    def bind_printer(self, action, proposal, values):
        """(values with the printer_ref parameter rendered as the queue name, None) or (None, reason)."""
        name = self.printer_param(action)
        if name is None:
            return values, None
        queue, reason = self.resolve_printer(proposal)
        if reason:
            return None, reason
        return dict(values, **{name: queue}), None

    def fastboot(self):
        if self._fastboot is None:
            program = shutil.which('fastboot', path=self.path)
            self._fastboot = android_flash.Fastboot(program, search_path=self.path) if program else False
        return self._fastboot or None

    def current_targets(self):
        """(usb_list, targets) seen right now from the USB inventory alone (fastboot and download-mode phones need no adb)."""
        usb_list = usb_devices.list_usb_devices()
        return None if usb_list is None else (usb_list, android.discover(usb_list, None, False))

    def resolve_fastboot(self, proposal):
        """(selector 'usb:<port>', reason): the phone the proposal names, in fastboot mode and usable by this user."""
        ref, expected = proposal.get('target_ref'), self.evidence_opaque_id(proposal)
        if not expected:
            return None, 'device-mismatch'
        seen, fb = self.current_targets(), self.fastboot()
        if seen is None or fb is None:
            return None, 'device-absent'
        found = seen[1]
        current = next((t for t in found if t['ref'] == ref), None)
        if current is None:
            return None, 'device-absent'
        if sum(1 for t in found if t['opaque_id'] == expected) > 1:
            return None, 'device-ambiguous'
        if current['opaque_id'] != expected:
            return None, 'device-mismatch'
        res = fb.devices()
        listing = android_flash.parse_devices(res[1]) if res and res[0] == 0 else None
        port = current['port']
        if 'fastboot' not in current['modes'] or listing is None or port not in listing['ports'] or port in listing['denied']:
            return None, 'device-absent'
        if self.fb_value(port, 'product') is None:       # the selector must really reach the device
            return None, 'device-absent'
        self.fb_port = port
        return 'usb:' + port, None

    def fb_value(self, port, name):
        """A fastboot variable of the bound device: a closed value for the status variables, the product string for
        ``product`` (kept in memory only, never printed or journaled), or None."""
        fb = self.fastboot()
        text = fb.getvar(port, name) if fb else None
        if name == 'product':
            m = next((re.match(r'^product: ([A-Za-z0-9._-]{1,64})$', ln.strip()) for ln in (text or '').splitlines()
                      if ln.strip().startswith('product: ')), None)
            return m.group(1) if m else None
        return android_flash.parse_getvar(text, name)

    def bind_device(self, action, proposal, values, wait=0):
        """(values with the device parameter rendered, None) or (None, reason).

        android_device becomes the adb transport id, fastboot_device the ``usb:<port>`` selector. *wait* (seconds)
        keeps polling while the phone is absent or not authorized yet (verify after a reboot)."""
        name, kind = self.device_param(action)
        if name is None:
            return values, None
        deadline = time.monotonic() + wait
        while True:
            got, reason = self.resolve_android(proposal) if kind == 'android_device' else self.resolve_fastboot(proposal)
            if reason is None:
                return dict(values, **{name: str(got)}), None
            if reason not in ('device-absent', 'device-not-authorized') or time.monotonic() >= deadline:
                return None, reason
            time.sleep(min(ANDROID_POLL_SECONDS, max(0.05, deadline - time.monotonic())))

    @staticmethod
    def step_uses_device(action, step):
        name, _ = Engine.device_param(action)
        return name is not None and any('{%s}' % name in element for element in step['argv'])

    # ------------------------------------------------------------ guards, firmware, slot

    def run_guards(self, action, proposal, phase):
        """A typed refusal reason, or None. phase 'device' runs before the firmware is read, 'image' after."""
        for guard in action.get('guards') or []:
            if guard == 'bootloader-unlocked' and phase == 'device':
                if self.fb_value(self.fb_port, 'unlocked') != 'yes':
                    say('  Bootloader terkunci atau status kunci tidak terbaca. Toolkit TIDAK membuka kunci (menghapus semua data); '
                        'buka kunci sendiri dengan prosedur resmi pabrikan lalu ulangi: docs/android.md#bootloader-terkunci')
                    say('  The bootloader is locked or its state cannot be read. This toolkit NEVER unlocks it (it wipes all data); '
                        "unlock it yourself with the manufacturer's official procedure, then run again: docs/android.md#bootloader-terkunci")
                    return 'bootloader-locked'
            elif guard == 'single-download-mode-device' and phase == 'device':
                reason = self.single_download_device(proposal)
                if reason:
                    return reason
            elif guard == 'image-matches-device' and phase == 'image':
                reason = self.image_matches_device(action)
                if reason:
                    return reason
        return None

    def single_download_device(self, proposal):
        """Heimdall addresses whatever download-mode device it finds: exactly one may be attached, and it must be
        the proposal's and-N with the evidence's opaque id."""
        expected, seen = self.evidence_opaque_id(proposal), self.current_targets()
        if seen is None:
            return 'device-absent'
        if not expected:
            return 'device-mismatch'
        download = [t for t in seen[1] if 'samsung-download' in t['modes']]
        if not download:
            return 'device-absent'
        if len(download) > 1:
            return 'device-ambiguous'
        if download[0]['ref'] != proposal.get('target_ref') or download[0]['opaque_id'] != expected:
            return 'device-mismatch'
        return None

    def image_matches_device(self, action):
        """android-info.txt ``require board=`` / ``require product=`` lines against ``fastboot getvar product``."""
        info = next((v['android_info'] for v in self.firmware.values() if v['kind'] == 'zip'), None)
        product = self.fb_value(self.fb_port, 'product')
        if info is None or product is None:
            return 'identity-mismatch'
        required = 0
        for line in info.splitlines():
            m = re.match(r'^\s*require\s+(board|product)\s*=\s*(\S.*?)\s*$', line)
            if m:
                required += 1
                if product not in [alt.strip() for alt in m.group(2).split('|')]:
                    warn('  %s: the image says it is not for this device (android-info.txt require %s); refusing'
                         % (action['action_id'], m.group(1)))
                    return 'identity-mismatch'
        if not required:
            warn('  %s: android-info.txt has no require board/product line, so the image cannot be matched to the device; refusing'
                 % action['action_id'])
            return 'identity-mismatch'
        return None

    def bind_firmware(self, action, values):
        """(values with every firmware_file replaced by /dev/fd/N, None) or (None, reason).

        The file is opened once without following a final symlink, must be a regular file inside the size bounds,
        is hashed through that descriptor (it must equal the operator's SHA-256), and the child later reads the
        same open file. Zips must be a fastboot update image: android-info.txt at the root, no outer factory
        script (flash-all), and no bootloader/radio/modem/persist/efs/frp/devinfo/fsg/userdata member."""
        out = dict(values)
        for p in action.get('params') or []:
            if p['type'] != 'firmware_file':
                continue
            aid, kind, path = action['action_id'], p['values'][0], values[p['name']]
            expected = values[p['name'] + '_sha256']
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            except OSError as exc:
                warn('  %s %s: cannot open the firmware file (%s)' % (aid, p['name'], exc.strerror or 'error'))
                return None, 'firmware-invalid'
            self.fds.append(fd)
            low, high = FIRMWARE_BYTES[kind]
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not low <= st.st_size <= high:
                warn('  %s %s: the firmware must be a regular file (no symlink) of %d..%d bytes' % (aid, p['name'], low, high))
                return None, 'firmware-invalid'
            digest, head = hashlib.sha256(), b''
            with os.fdopen(os.dup(fd), 'rb', closefd=True) as handle:
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    head = head or chunk[:4]
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                warn('  %s %s: the SHA-256 of the file is not the one you supplied; refusing' % (aid, p['name']))
                return None, 'firmware-hash-mismatch'
            after = os.fstat(fd)
            if (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                warn('  %s %s: the firmware file changed while it was being hashed; refusing' % (aid, p['name']))
                return None, 'firmware-invalid'
            info = None
            if kind == 'zip':
                info = self.read_android_info(fd)
                if info is None:
                    warn('  %s %s: not a fastboot update image (needs android-info.txt at the root, no flash-all script, no '
                         'bootloader/radio/modem/persist/efs/frp/userdata image). Use the inner image-*.zip of a factory image.'
                         % (aid, p['name']))
                    return None, 'firmware-invalid'
            elif head == b'PK\x03\x04':
                warn('  %s %s: this is a zip, not a partition image; refusing' % (aid, p['name']))
                return None, 'firmware-invalid'
            self.firmware[p['name']] = {'kind': kind, 'android_info': info}
            out[p['name']] = '/dev/fd/%d' % fd
        return out, None

    @staticmethod
    def read_android_info(fd):
        """The text of android-info.txt of a fastboot update zip (read as data: nothing is extracted or run), or None."""
        try:
            with os.fdopen(os.dup(fd), 'rb', closefd=True) as handle, zipfile.ZipFile(handle) as archive:
                members = archive.infolist()
                names = [m.filename for m in members]
                if len(members) > MAX_ZIP_MEMBERS or 'android-info.txt' not in names:
                    return None
                if any(n.lower() in OUTER_FACTORY_SCRIPTS for n in names):
                    return None
                for n in names:
                    stem = os.path.basename(n).lower().split('.', 1)[0]
                    stem = re.sub(r'[-_][0-9][A-Za-z0-9._-]*$', '', stem)
                    if stem in FORBIDDEN_IMAGE_STEMS or stem.startswith(('bootloader-', 'radio-', 'modem-')):
                        return None
                member = archive.getinfo('android-info.txt')
                if member.file_size > MAX_ANDROID_INFO:
                    return None
                return archive.read(member).decode('utf-8', 'replace')
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
            return None

    def bind_slot(self, action, values):
        """(values with fastboot_slot = the active slot read now, None) or (None, reason)."""
        out = dict(values)
        for p in action.get('params') or []:
            if p['type'] == 'fastboot_slot':
                slot = self.fb_value(self.fb_port, 'current-slot')
                if slot is None:
                    warn('  %s: the active slot cannot be read (not an A/B device?); not run.' % action['action_id'])
                    return None, 'identity-mismatch'
                out[p['name']] = slot
        return out, None

    def bind_all(self, action, proposal, values):
        """Device, guards, firmware and slot, in the cheapest-first order: (values, None) or (None, reason)."""
        values, refusal = self.bind_device(action, proposal, values)
        if refusal:
            return None, refusal
        values, refusal = self.bind_printer(action, proposal, values)
        if refusal:
            return None, refusal
        refusal = self.run_guards(action, proposal, 'device')
        if refusal:
            return None, refusal
        values, refusal = self.bind_firmware(action, values)
        if refusal:
            return None, refusal
        refusal = self.run_guards(action, proposal, 'image')
        if refusal:
            return None, refusal
        return self.bind_slot(action, values)

    def release_fds(self):
        for fd in self.fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds, self.firmware, self.fb_port = [], {}, None

    def close(self):
        """Stop the adb server this run started (live session only; on a host the operator's server is theirs)."""
        if self._adb and self.platform == 'live-linux':
            android.stop_server(self._adb)

    def log(self, action, proposal, stage, outcome, **extra):
        if self.journal is None:
            return
        self.journal.write(action_id=action['action_id'], origin=proposal['origin'], risk=action['risk'],
                           target_ref=proposal.get('target_ref'), stage=stage, outcome=outcome, **extra)

    def detections(self):
        """The LOCAL detection list of this run (paths inside; never journaled, never sent). None + warning if absent."""
        if self._detections is None:
            try:
                if not self.state_root:
                    raise ValueError('no --state-dir or --journal to locate the detection list')
                self._detections = md.load_list(self.state_root, self.evidence.get('run_id'))
            except (ValueError, OSError) as exc:
                warn('  detection list: %s' % exc)
                self._detections = False
        return self._detections or None

    def detection_entry(self, ref, action, proposal):
        """The list entry for *ref* or None (with a warning). It must belong to the proposal's target."""
        doc = self.detections()
        entry = doc['_by_id'].get(ref) if doc else None
        if entry is None:
            if doc:
                warn('  %s is not in the local detection list' % ref)
            return None
        if action.get('target_families') and proposal.get('target_ref') and entry['target_ref'] != proposal['target_ref']:
            warn('  %s belongs to %s, not to %s' % (ref, entry['target_ref'], proposal['target_ref']))
            return None
        return entry

    def show_detections(self, proposal):
        doc = self.detections()
        if not doc:
            return
        say('  Deteksi lokal / local detections (paths stay on this screen and the USB):')
        for entry in doc['detections'][:200]:
            if not proposal.get('target_ref') or entry['target_ref'] == proposal['target_ref']:
                say('    ' + md.display_line(entry))

    def ask(self, prompt):
        try:
            return input(prompt).strip()
        except EOFError:
            return ''

    def ask_yes(self, prompt):
        """A prompt whose empty answer means yes (only the safe-batch question uses it); end of input means no."""
        try:
            answer = input(prompt).strip().lower()
        except EOFError:
            return False
        return answer == '' or answer in YES

    # ------------------------------------------------------------ batch approval

    def batchable(self, proposal):
        """May this proposal be part of the one-question approval? Only a plain `safe` action: never a quarantine, a
        reversible/irreversible/destructive one, one that writes the target, needs a backup, or lacks root."""
        action = self.catalog.get(proposal['action_id'])
        return (action['risk'] == 'safe' and not action['action_id'].startswith('mw.quarantine-')
                and not action.get('requires_target_rw') and not action['backup']['required']
                and action['action_id'] not in self.args.approve and not lacks_root(action, self.path))

    def plan_batch(self, proposals, total=None):
        """approve-each + interactive + two or more pending safe actions: show the table of all proposals, then ask once."""
        self.total = total or len(proposals)
        if self.args.policy != 'approve-each' or not self.interactive:
            return False
        pending = [p for p in proposals if self.batchable(p)]
        if len(pending) < 2:
            return False
        keys = {(p['action_id'], p.get('target_ref')) for p in pending}
        say('')
        say('Menunggu persetujuan / pending approval:')
        for n, p in enumerate(proposals, 1):
            action = self.catalog.get(p['action_id'])
            mark = '*' if (p['action_id'], p.get('target_ref')) in keys else ' '
            say('  %s%2d. %-40s %-11s %s' % (mark, n, p['action_id'], action['risk'], action['title']))
        say('  (* = aman/safe: dapat disetujui sekaligus / can be approved at once; the others always ask)')
        if self.ask_yes('Setujui semua %d aksi aman (safe) sekaligus? / Approve all %d safe actions at once? [Y/n]: '
                        % (len(pending), len(pending))):
            self.batch = keys
            return True
        return False

    # ------------------------------------------------------------ device picker

    def disk_candidates(self):
        """(candidates, removable_fallback): whole disks read from lsblk now, [{'path','size','tran','model'}], or None.

        Left out: the rescue USB (the disk holding the bundle or the USB state), the live media, loop/rom/zram devices and
        removable or USB media - unless no other disk exists, in which case the removable ones (still never the rescue USB)
        are offered and flagged. Model strings are for the screen only."""
        program = shutil.which('lsblk', path=self.path)
        if program is None:
            return None
        scanner = load_module('rescue_scan_target_os', HERE / 'scan-target-os.py')
        try:
            proc = subprocess.run([program, '-J', '-b', '-o', scanner.LSBLK_COLUMNS + ',MODEL'], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'PATH': self.path, 'LC_ALL': 'C.UTF-8'},
                                  timeout=20, check=False)
            tree = json.loads(proc.stdout.decode('utf-8', 'replace')).get('blockdevices') or []
        except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
            return None
        if proc.returncode != 0:
            return None
        models = {n.get('path'): n.get('model') for n in tree if isinstance(n, dict)}
        records = []
        scanner._flatten(tree, None, records)
        keep = (self.state_root,)
        internal = scanner.excluded_disks(records)
        hard = hard_excluded(scanner, records, keep)
        disks = [r for r in records if r['type'] == 'disk' and r['path'] and rc.BLOCK_RE.match(r['path'])]

        def entry(rec):
            model = CONTROL.sub('', str(models.get(rec['path']) or '')).strip()
            return {'path': rec['path'], 'size': human_size(rec['size']), 'tran': (rec['tran'] or '-'), 'model': model[:24]}

        main = [entry(r) for r in disks if r['disk'] not in internal][:PICKER_MAX]
        if main:
            return main, False
        return [entry(r) for r in disks if r['disk'] not in hard][:PICKER_MAX], True

    def pick_block_device(self, action, param):
        """The operator's choice from the engine's own disk list: a /dev path, or None (skipped / nothing to choose)."""
        found = self.disk_candidates()
        if not found or not found[0]:
            warn('  %s %s: no eligible disk found to choose from' % (action['action_id'], param['name']))
            return None
        candidates, removable = found
        say('  Pilih disk untuk / choose the disk for %s %s:' % (action['action_id'], param['name']))
        if removable:
            say('  (tidak ada disk internal; media lepasan ditampilkan / no internal disk, removable media shown)')
        for n, c in enumerate(candidates, 1):
            say('    %2d) %-12s %-10s %-6s %s' % (n, c['path'], c['size'], c['tran'], c['model']))
        answer = self.ask('  Nomor / number (Enter = lewati / skip): ')
        if not answer:
            return None
        if not answer.isdigit() or not 1 <= int(answer) <= len(candidates):
            warn('  %s %s: not one of the listed numbers' % (action['action_id'], param['name']))
            return ''
        choice = candidates[int(answer) - 1]['path']
        if removable:
            self.removable_ok.add(choice)
        return choice

    def resolve_params(self, action, allow_prompt, proposal=None):
        """(values, problem) where problem is None, 'missing-param' or 'invalid-param'."""
        values, aid = {}, action['action_id']
        proposal = proposal or {}
        for p in action.get('params') or []:
            if p['type'] in ENGINE_TYPES:
                continue  # filled by the mount provider / the engine
            raw = proposal.get('detection') if p['type'] == 'detection_ref' and proposal.get('detection') else None
            if raw is None:
                raw = self.params.get((aid, p['name']))
            if raw is None and 'default' in p:
                raw = p['default']
            if raw is None and allow_prompt and p['type'] == 'block_device':
                raw = self.pick_block_device(action, p)
                if raw == '':
                    return None, 'invalid-param'
            elif raw is None and allow_prompt:
                hint = ', '.join(p['values']) if p['type'] == 'enum' else p['type']
                if p['type'] == 'detection_ref':
                    self.show_detections(proposal)
                raw = self.ask('  Nilai untuk / value for %s (%s): ' % (p['name'], hint)) or None
            if raw is None:
                return None, 'missing-param'
            try:
                value = rc.validate_param(p, raw, self.packages)
            except ValueError as exc:
                warn('  %s %s %s' % (aid, p['name'], exc))
                return None, 'invalid-param'
            if p['type'] == 'detection_ref' and self.detection_entry(value, action, proposal) is None:
                return None, 'invalid-param'
            if p['type'] == 'block_device' and not block_device_eligible(value, value in self.removable_ok, (self.state_root,)):
                warn('  %s %s: %s is not an eligible internal block device (rescue USB and removable media '
                     'are never targets)' % (aid, p['name'], value))
                return None, 'invalid-param'
            values[p['name']] = value
        return values, None

    def card(self, action, proposal, values):
        say('')
        say('== %s  [%s]  risk=%s  scope=%s' % (action['action_id'], proposal['origin'], action['risk'],
                                               action['scope']))
        say('   ID: %s' % action['title_id'])
        say('   EN: %s' % action['title'])
        if proposal.get('target_ref'):
            say('   target: %s' % proposal['target_ref'])
        shown = dict(values)
        for p in action.get('params') or []:
            if p['type'] == 'target_root':
                shown[p['name']] = '<target root>'
            elif p['type'] == 'state_dir':
                shown[p['name']] = '<USB state>/' + p['values'][0]
            elif p['type'] == 'android_device':
                shown[p['name']] = '<android %s>' % proposal.get('target_ref', '?')
            elif p['type'] == 'fastboot_device':
                shown[p['name']] = '<fastboot %s>' % proposal.get('target_ref', '?')
            elif p['type'] == 'fastboot_slot':
                shown[p['name']] = '<active slot>'
            elif p['type'] == 'printer_ref':
                shown[p['name']] = '<printer %s>' % proposal.get('target_ref', '?')
            elif p['type'] == 'bundle_root':
                shown[p['name']] = '<bundle>'
            elif p['type'] == 'bundle_config':
                shown[p['name']] = '<bundle>/config/' + p['values'][0]
            elif p['type'] == 'firmware_file':
                shown[p['name']] = '<firmware %s file>' % p['values'][0]
            elif p['type'] == 'detection_ref':
                entry = self.detection_entry(values.get(p['name']), action, proposal)
                if entry is not None:
                    say('   detection: ' + md.display_line(entry))
        say('   execute: %s' % ' '.join(rc.render(action['execute']['argv'], shown)))
        say('   verify:  %s' % ' '.join(rc.render(action['verify']['argv'], shown)))
        rb = action['rollback']
        say('   rollback: %s' % (rb['kind'] if rb['kind'] != 'manual' and rb['kind'] != 'restore-backup'
                                 else '%s (%s)' % (rb['kind'], rb.get('doc'))))
        if action.get('guards'):
            say('   guards: %s (checked after approval, before anything is sent)' % ', '.join(action['guards']))
        if action.get('requires_target_rw'):
            say('   PERINGATAN / WARNING: target akan di-mount read-write / the target will be mounted read-write')
        if action['risk'] == 'irreversible':
            say('   PERINGATAN / WARNING: tidak dapat dibatalkan: memakai kertas atau tinta, atau membuang pekerjaan cetak / '
                'cannot be undone: it uses paper or ink, or discards queued print jobs')
        if action['backup']['required']:
            say('   backup: %s (reference supplied)' % action['backup'].get('what'))
        say('   doc: %s' % action['doc'])

    def approve(self, action, proposal):
        """(values, reason) if approved, else (None, reason) after journaling the decision."""
        aid, risk = action['action_id'], action['risk']
        auto = (self.args.policy == 'auto-safe' and risk == 'safe' and proposal['origin'] == 'catalog-trigger'
                and not action.get('requires_target_rw'))
        cli = aid in self.args.approve
        if auto or cli:
            values, problem = self.resolve_params(action, allow_prompt=False, proposal=proposal)
            if problem is None:
                return values, 'auto-safe' if auto else 'cli-approved'
            if not self.interactive:
                self.log(action, proposal, 'approval', 'skipped', reason=problem)
                return None, problem
        if not self.interactive:
            self.log(action, proposal, 'approval', 'declined', reason='not-interactive')
            return None, 'not-interactive'
        values, problem = self.resolve_params(action, allow_prompt=True, proposal=proposal)
        if problem:
            self.log(action, proposal, 'approval', 'skipped', reason=problem)
            return None, problem
        self.card(action, proposal, values)
        if (aid, proposal.get('target_ref')) in self.batch and risk == 'safe':
            return values, 'operator-approved-batch'     # the operator answered yes for all safe actions (plan_batch)
        if risk == 'destructive':
            answer = self.ask('  Ketik action_id untuk menyetujui / type the action_id to approve: ')
            ok = answer == aid
        else:
            ok = self.ask('  Jalankan? / Run? [ya/yes, default: tidak/no]: ').lower() in YES
        if not ok:
            self.log(action, proposal, 'approval', 'declined', reason='operator-declined')
            return None, 'operator-declined'
        return values, 'operator-approved'

    def process(self, proposal):
        action = self.catalog.get(proposal['action_id'])
        aid = action['action_id']
        self.log(action, proposal, 'proposed', 'ok')
        if self.args.policy == 'detect-only':
            self.log(action, proposal, 'approval', 'skipped', reason='policy-detect-only')
            return 'proposed'
        if lacks_root(action, self.path):
            warn('  %s: perlu root, sudo tanpa kata sandi tidak tersedia; tidak dijalankan / needs root and non-interactive '
                 'sudo is not available; not run (this launcher never elevates).' % aid)
            self.log(action, proposal, 'approval', 'unavailable', reason='needs-root')
            return 'skipped'
        if any(p['type'] == 'state_dir' for p in action.get('params') or []) and not self.state_root:
            warn('  %s needs the USB state directory (--state-dir, or --journal inside a "repairs" directory); not run.' % aid)
            self.log(action, proposal, 'approval', 'unavailable', reason='provider-unavailable')
            return 'skipped'
        backup = None
        if action['backup']['required']:
            if not self.args.backup_ref:
                warn('  %s needs --backup-ref (%s); not run.' % (aid, action['backup'].get('what')))
                self.log(action, proposal, 'backup', 'unavailable', reason='missing-backup')
                return 'skipped'
            try:
                backup = backup_fingerprint(self.args.backup_ref)
            except (OSError, ValueError) as exc:
                warn('  %s: backup reference unusable: %s' % (aid, exc))
                self.log(action, proposal, 'backup', 'fail', reason='missing-backup')
                return 'skipped'
            self.log(action, proposal, 'backup', 'ok', backup=backup)
        needs_target = any(p['type'] == 'target_root' for p in action.get('params') or [])
        provider = target_provider() if needs_target else None
        if needs_target and provider is None:
            self.log(action, proposal, 'target-rw', 'unavailable', reason='provider-unavailable')
            warn('  %s needs the target mount provider (scripts/lib/target_mount.py); not run.' % aid)
            return 'skipped'
        values, reason = self.approve(action, proposal)
        if values is None:
            return 'declined'
        kinds = {p['name']: p['type'] for p in action.get('params') or []}
        # a firmware path is never journaled; its SHA-256 is (it is the sha256 parameter)
        journal_params = {k: v for k, v in values.items() if kinds.get(k) != 'firmware_file'}
        self.log(action, proposal, 'approval', 'ok', reason=reason, params=journal_params or None)
        values = self.engine_values(action, values)
        values, refusal = self.bind_all(action, proposal, values)
        if refusal:
            warn('  %s: refused before anything was sent (%s); not run.' % (aid, refusal))
            self.log(action, proposal, 'precondition', 'fail', reason=refusal)
            return 'skipped'
        if needs_target:
            name = next(p['name'] for p in action['params'] if p['type'] == 'target_root')
            try:
                ctx = provider(self.args.evidence, self.evidence, proposal.get('target_ref'),
                               bool(action.get('requires_target_rw')))
                with ctx as root:
                    self.log(action, proposal, 'target-rw', 'ok',
                             reason='not-applicable' if not action.get('requires_target_rw') else None)
                    bound = self.bind_detections(action, proposal, dict(values, **{name: root}), root)
                    if bound is None:
                        return 'skipped'
                    return self.run_action(action, proposal, bound)
            except Exception as exc:  # provider failures must never leave the engine half-way
                warn('  %s: target mount failed: %s' % (aid, exc))
                self.log(action, proposal, 'target-rw', 'fail', reason='provider-unavailable')
                return 'failed'
        bound = self.bind_detections(action, proposal, values, '/')
        if bound is None:
            return 'skipped'
        return self.run_action(action, proposal, bound)

    def engine_values(self, action, values):
        """Add the engine-provided state_dir values (<state>/clamav or <state>/quarantine) and the bundle directory."""
        out = dict(values)
        for p in action.get('params') or []:
            if p['type'] == 'state_dir':
                out[p['name']] = os.path.join(self.state_root or '', p['values'][0])
            elif p['type'] == 'bundle_root':
                out[p['name']] = str(rc.ROOT)
            elif p['type'] == 'bundle_config':
                out[p['name']] = str(rc.ROOT / 'config' / p['values'][0])
        return out

    def show(self, action, result, limit=15):
        """Echo a step's output, except for a printer action: a CUPS tool names the queue (``request id is Queue-12``)."""
        if self.printer_param(action) is None:
            show_output(result, limit)
        elif result.get('output'):
            say('    | (keluaran tidak ditampilkan karena dapat memuat nama printer / output not shown, it may name the printer)')

    def bind_detections(self, action, proposal, values, root):
        """Replace each detection_ref d-N by the verified absolute path below *root* ('/' on a host).

        The path is the root plus the recorded relative path, no symlink on the way, a regular file, and
        the sha256 must still match the list (a file replaced after detection is refused). Returns the
        render values, or None after journaling precondition fail / invalid-param.
        """
        out = dict(values)
        for p in action.get('params') or []:
            if p['type'] != 'detection_ref':
                continue
            entry = self.detection_entry(values[p['name']], action, proposal)
            path, problem = self.verify_detection(entry, root) if entry else (None, 'missing entry')
            if problem:
                warn('  %s %s: %s' % (action['action_id'], p['name'], problem))
                self.log(action, proposal, 'precondition', 'fail', reason='invalid-param')
                return None
            out[p['name']] = path
        return out

    def verify_detection(self, entry, root):
        """(path, problem). Root-only mount points (live mode, engine not root) are verified by the privileged
        helper through sudo instead of directly."""
        if os.access(root, os.X_OK):
            return md.resolve_entry(entry, root)
        helper = resolve_argv(['rescue-malware-quarantine', 'check', '--target-root=' + root,
                               '--expect-sha256=' + entry['sha256'],
                               '--path=' + os.path.join(root, entry['rel'])], True, self.path)
        if helper is None:
            return None, 'the privileged check helper (rescue-malware-quarantine) is not available'
        try:
            proc = subprocess.run(helper, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  env={'PATH': self.path, 'LC_ALL': 'C.UTF-8'}, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError):
            return None, 'the privileged check failed to run'
        if proc.returncode != 0:
            return None, (proc.stdout.decode('utf-8', 'replace').strip().splitlines() or ['check failed'])[-1][:200]
        return os.path.join(root, entry['rel']), None

    def step(self, action, proposal, stage, step, values):
        base = stage.split('/')[0]
        is_android = self.android_param(action) is not None
        if base in ('verify', 'rollback') and self.step_uses_device(action, step):
            # The phone may have restarted (new transport id) or been unplugged since the last step: look again.
            values, refusal = self.bind_device(action, proposal, values,
                                               self.android_wait if base == 'verify' and is_android else 0)
            if refusal:
                outcome = 'fail' if base == 'verify' else 'unavailable'
                self.log(action, proposal, base, outcome, reason=refusal)
                say('  %-12s %s (%s)' % (stage, outcome, refusal))
                return {'outcome': outcome, 'reason': refusal}
        result = run_step(step, values, action.get('requires_root', False), self.path, DEFAULT_TIMEOUT[base], is_android,
                          tuple(self.fds))
        self.log(action, proposal, base, result['outcome'], **{
            k: v for k, v in result_fields(result).items() if k not in ('outcome',)})
        say('  %-12s %s' % (stage, result['outcome']))
        if result['outcome'] != 'ok':
            self.show(action, result)
        return result

    def run_action(self, action, proposal, values):
        say('')
        say('[%d/%d] %s  risk=%s  menjalankan / running' % (self.index, self.total, action['action_id'], action['risk']))
        for i, pre in enumerate(action.get('preconditions') or []):
            if self.step(action, proposal, 'precondition/%d' % i, pre, values)['outcome'] != 'ok':
                say('  precondition not met; action not run / prasyarat tidak terpenuhi')
                return 'skipped'
        executed = self.step(action, proposal, 'execute', action['execute'], values)
        if executed['outcome'] == 'unavailable':
            return 'skipped'
        if executed['outcome'] == 'ok':
            self.show(action, executed, limit=8)
            if self.step(action, proposal, 'verify', action['verify'], values)['outcome'] == 'ok':
                return 'verified'
        rb = action['rollback']
        if rb['kind'] == 'step':
            rolled = self.step(action, proposal, 'rollback', rb['step'], values)
            return 'rolled-back' if rolled['outcome'] == 'ok' else 'failed'
        if rb['kind'] in ('manual', 'restore-backup'):
            self.log(action, proposal, 'rollback', 'skipped', reason='manual-rollback-required')
            warn('  ROLLBACK MANUAL diperlukan / required: lihat / see %s' % rb.get('doc'))
        return 'failed'


# -------------------------------------------------------------------------- main

def parse_params(items):
    out = {}
    for item in items:
        m = re.match(r'^([a-z0-9.-]+)\.([a-z][a-z0-9_]{0,31})=(.*)$', item)
        if not m:
            raise ValueError('--param must be ACTION_ID.NAME=VALUE: %s' % item[:80])
        out[(m.group(1), m.group(2))] = m.group(3)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--evidence', metavar='FILE')
    ap.add_argument('--analysis', metavar='FILE', help='analysis markdown with an optional ```rescue-proposals block')
    ap.add_argument('--policy', choices=('detect-only', 'approve-each', 'auto-safe'), default='approve-each')
    ap.add_argument('--scope', default='all', help='comma list: %s' % ', '.join(rc.SCOPE_VALUES))
    ap.add_argument('--packages', type=lambda s: [p for p in s.split(',') if p], default=None,
                    help='comma list of packages for scope software.selected')
    ap.add_argument('--state-dir', metavar='DIR', help='journal at DIR/repairs/journal.jsonl')
    ap.add_argument('--journal', metavar='FILE')
    ap.add_argument('--catalog-dir', default=str(rc.CATALOG_DIR))
    ap.add_argument('--select', action='append', default=[], metavar='ACTION_ID')
    ap.add_argument('--approve', action='append', default=[], metavar='ACTION_ID')
    ap.add_argument('--param', action='append', default=[], metavar='ACTION_ID.NAME=VALUE')
    ap.add_argument('--printer-network', action='store_true',
                    help='printer actions may address a network printer in this run (opt-in; default: USB and local queues only)')
    ap.add_argument('--backup-ref', metavar='FILE')
    ap.add_argument('--list', action='store_true', help='print the proposals and exit (nothing is journaled)')
    ap.add_argument('--verify-journal', metavar='FILE')
    args = ap.parse_args(argv)

    if args.verify_journal:
        problems = verify_journal(args.verify_journal)
        for p in problems:
            say('journal: %s' % p)
        say('journal: %s (%s)' % ('INVALID' if problems else 'valid', args.verify_journal))
        return EXIT_FAILED if problems else EXIT_OK
    if not args.evidence:
        ap.error('--evidence is required')
    try:
        scope = rc.normalize_scope(args.scope)
        args.param_map = parse_params(args.param)
    except ValueError as exc:
        warn('rescue-repair: %s' % exc)
        return EXIT_INVALID
    if args.packages is not None:
        bad = [p for p in args.packages if not rc.PACKAGE_RE.match(p)]
        if bad:
            warn('rescue-repair: invalid package name(s): %s' % ', '.join(b[:40] for b in bad))
            return EXIT_INVALID

    validator = load_module('rescue_validate_evidence', HERE / 'validate-evidence.py')
    try:
        raw = Path(args.evidence).read_bytes()
        evidence = json.loads(raw.decode('utf-8'))
    except (OSError, ValueError) as exc:
        warn('rescue-repair: cannot read evidence: %s' % (getattr(exc, 'strerror', None) or exc))
        return EXIT_INVALID
    analyzer = load_module('rescue_opencode_go_analyze', HERE / 'opencode-go-analyze.py')
    problems = analyzer.validation_problems(validator, evidence) if isinstance(evidence, dict) else ['not an object']
    if problems:
        warn('rescue-repair: evidence is INVALID (%s); nothing was run.' % problems[0])
        return EXIT_INVALID
    platform = rc.platform_of(evidence)
    try:
        catalog = rc.load(args.catalog_dir)
    except rc.CatalogError as exc:
        for p in exc.problems:
            warn('rescue-repair: catalog INVALID: %s' % p)
        return EXIT_INVALID

    proposals = rc.triggered(catalog, evidence, scope)
    if args.analysis:
        try:
            text = Path(args.analysis).read_text(encoding='utf-8', errors='replace')
        except OSError as exc:
            warn('rescue-repair: cannot read analysis: %s' % (exc.strerror or exc))
            return EXIT_INVALID
        ai, rejected = rc.parse_ai_proposals(text, catalog, evidence, scope)
        if rejected:
            warn('rescue-repair: %d AI proposal(s) rejected (unknown ID, wrong target, or out of scope)' % rejected)
        proposals += ai
    families = {t['ref']: t['family'] for t in evidence.get('target_systems') or []}
    for item in args.select:
        target = None
        if ':' in item:
            item, target = item.split(':', 1)
        action = catalog.get(item)
        if action is None:
            warn('rescue-repair: --select %s is not a catalog action_id' % item[:64])
            return EXIT_INVALID
        if not action.get('target_families'):
            target = None
        # --select ACTION without :TARGET for a target action means "the targets the evidence already triggers it for"
        # (only those: a selection narrows to what the evidence proposed or names one target explicitly)
        targets = [target]
        if action.get('target_families') and target is None:
            triggered_for = [p.get('target_ref') for p in proposals
                             if p['action_id'] == item and p['origin'] == 'catalog-trigger' and p.get('target_ref')]
            targets = list(dict.fromkeys(triggered_for)) or [None]
        for target in targets:
            ok, why = rc.applicable(action, platform, scope, target, families)
            if not ok:
                warn('rescue-repair: --select %s does not apply here (%s)' % (item, why))
                return EXIT_INVALID
            # a duplicate of a catalog-trigger proposal is dropped below, so that proposal keeps origin catalog-trigger
            # (and auto-safe may run it); an action the evidence does not trigger stays an operator proposal that asks
            proposals.append(dict({'action_id': item, 'origin': 'operator'}, **({'target_ref': target} if target else {})))
    unique, seen = [], set()
    for p in proposals:
        key = (p['action_id'], p.get('target_ref'))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    proposals = []
    for p in unique:  # --param ACTION.detection=d-1,d-3 runs the action once per detection, each with its own approval
        refs = []
        for prm in catalog.get(p['action_id']).get('params') or []:
            if prm['type'] != 'detection_ref':
                continue
            listed = args.param_map.get((p['action_id'], prm['name']))
            refs = list(dict.fromkeys(r.strip() for r in listed.split(',') if r.strip())) if listed and ',' in listed else []
        proposals.extend([dict(p, detection=r) for r in refs] if refs else [p])

    say('Repair plan / rencana perbaikan: policy=%s scope=%s platform=%s catalog=%s' % (
        args.policy, ','.join(scope), platform, catalog.sha256[:12]))
    if not proposals:
        say('  Tidak ada tindakan katalog yang berlaku / no applicable catalog actions.')
    for p in proposals:
        a = catalog.get(p['action_id'])
        root = '  (perlu root / needs root)' if platform in EXECUTING_PLATFORMS and lacks_root(a, search_path()) else ''
        say('  - %-40s %-11s %-15s %s%s' % (p['action_id'], a['risk'], p['origin'], p.get('target_ref', '-'), root))
    if args.list or not proposals:
        return EXIT_OK
    if platform not in EXECUTING_PLATFORMS and args.policy != 'detect-only':
        warn('rescue-repair: %s actions are executed by the host launcher engine, not here; '
             'use --list or --policy detect-only.' % platform)
        return EXIT_INVALID

    journal_path = args.journal or (os.path.join(args.state_dir, 'repairs', 'journal.jsonl') if args.state_dir else None)
    if not journal_path:
        warn('rescue-repair: --journal or --state-dir is required to act on proposals')
        return EXIT_INVALID
    try:
        journal = Journal(journal_path, evidence['run_id'], catalog.sha256, args.policy, platform,
                          hashlib.sha256(raw).hexdigest())
        engine = Engine(args, evidence, hashlib.sha256(raw).hexdigest(), catalog, platform, journal)
        outcomes = []
        try:
            engine.plan_batch(proposals)
            for number, proposal in enumerate(proposals, 1):
                engine.index = number
                try:
                    outcome = engine.process(proposal)
                finally:
                    engine.release_fds()
                outcomes.append((proposal, outcome))
        finally:
            engine.close()
    except JournalError as exc:
        warn('rescue-repair: %s' % exc)
        return EXIT_JOURNAL
    say('')
    say('Ringkasan / summary (journal: %s):' % journal_path)
    for proposal, outcome in outcomes:
        say('  %-40s %s' % (proposal['action_id'], outcome))
    return EXIT_FAILED if any(o in ('failed', 'rolled-back') for _, o in outcomes) else EXIT_OK


if __name__ == '__main__':
    with contextlib.suppress(KeyboardInterrupt):
        sys.exit(main())
    sys.exit(130)
