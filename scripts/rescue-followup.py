#!/usr/bin/env python3
"""Typed READ-ONLY follow-ups for the checks an analysis flagged (warn/fail/unknown).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#69. Contract and privacy rules: docs/hermes-learning-loop.md
("Hermes autorun"), docs/security-model.md; format: rescue-ai/v1/followup.schema.json.

    rescue-followup.py --evidence FILE --reports-dir DIR [--mode live-linux|linux-host]
                       [--state-dir DIR] [--timeout SECONDS]

Writes DIR/followup-<run_id>.json (atomic, 0600 where supported) and prints a short bilingual summary.
Exit 0 even when individual follow-ups are ``unknown``; 2 for invalid input or evidence.

The recipes are fixed in this file and keyed by evidence check_id. Evidence, model output and the command
line never supply an argv element or a parameter value. Output carries only numbers, booleans and members
of closed sets (no serials, models, device paths, journal messages, unit or program names, file names or
signature names); ``privacy_problems`` refuses a document that does not, and nothing is written then.
Disks are the opaque ordinals ``disk-N``. Nothing here mounts read-write, repairs, or follows a symlink
out of a target root. Anything that needs root and runs without it becomes ``unknown`` / ``needs-root``.

Test hooks (announced on stderr): RESCUE_REPAIR_TEST_PATH replaces the command search path (same hook as
the repair engine); RESCUE_FOLLOWUP_PROC_ROOT replaces the root of the /proc files read for persistence.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'lib'))

SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
SCHEMA_FILE = ROOT / 'rescue-ai/v1/followup.schema.json'
EVIDENCE_SCHEMA_FILE = ROOT / 'rescue-ai/v1/rescue-evidence.schema.json'
DEFAULT_TIMEOUT = 120
MIN_TIMEOUT, MAX_TIMEOUT = 10, 900
SMART_TIMEOUT = 25
JOURNAL_TIMEOUT = 40
JOURNAL_MAX_ENTRIES = 20000
MAX_ITEMS = 200
MAX_NUMBER = 10 ** 15

MODES = ('live-linux', 'linux-host', 'windows-host')
LIVE_PLATFORMS = ('linux-mint-xfce-live', 'systemrescue-live', 'other-live-linux')
STATUSES = ('pass', 'warn', 'fail', 'unknown', 'not_applicable')
REASONS = ('ok', 'attention', 'needs-root', 'needs-admin', 'tool-missing', 'no-data', 'in-progress', 'timeout',
           'unsupported', 'not-mounted', 'no-journal', 'not-scanned', 'budget', 'db-missing', 'db-stale',
           'detections', 'incomplete', 'other')
CHECK_IDS = ('smart-health', 'nvme-health', 'linux-journal-errors', 'malware-scan', 'malware-signatures',
             'persistence', 'windows-event-log-errors', 'encryption-status', 'windows-boot-config',
             'windows-restore-points')
FOLLOWUP_IDS = ('disk.attributes', 'disk.selftest-result', 'journal.categories', 'malware.coverage',
                'malware.signatures', 'persistence.active', 'windows.event-log-categories',
                'windows.encryption-state', 'windows.boot-config', 'windows.restore-points')
TARGET_REF = re.compile(r'^(os|disk|and|prn)-[0-9]{1,2}$')
RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$')
TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')

# The fixed journal categories (output value names use underscores).
CATEGORIES = ('kernel', 'storage', 'filesystem', 'network', 'display-gpu', 'audio', 'usb', 'bluetooth',
              'power-acpi', 'systemd', 'security-auth', 'application', 'other')


def _cat_name(category):
    return category.replace('-', '_')


SELFTEST = ('completed-ok', 'in-progress', 'failed', 'aborted', 'none', 'unknown')
COVERAGE = ('complete', 'incomplete', 'stale-signatures', 'not-scanned', 'budget-exhausted', 'detections-found',
            'unknown')
UPPER_BACKING = ('block', 'loop', 'tmpfs', 'unknown')
ENCRYPTION_STATE = ('on', 'off', 'suspended', 'unknown')
BOOT_CONFIG = ('ok', 'missing', 'unreadable', 'unknown')

# name -> 'int' | 'bool' | tuple of allowed strings. This table is the single definition of the closed value
# vocabulary; rescue-ai/v1/followup.schema.json is generated from it (tests keep them equal).
VALUE_SPECS = {
    'reallocated': 'int', 'pending': 'int', 'offline_uncorrectable': 'int', 'power_on_hours': 'int',
    'temperature_c': 'int', 'smart_passed': 'bool',
    'selftest': SELFTEST, 'selftest_percent_remaining': 'int',
    'nvme_percentage_used': 'int', 'nvme_media_errors': 'int', 'nvme_critical_warning': 'int',
    'nvme_available_spare': 'int',
    'total': 'int', 'sampled': 'int', 'truncated': 'bool',
    'coverage': COVERAGE, 'detections': 'int', 'signature_age_days': 'int', 'signature_stale': 'bool',
    'db_present': 'bool',
    'persistence_active': 'bool', 'cmdline_persistent': 'bool', 'upper_backing': UPPER_BACKING,
    'restore_points': 'int', 'encryption_state': ENCRYPTION_STATE, 'boot_config': BOOT_CONFIG,
}
for _c in CATEGORIES:
    VALUE_SPECS[_cat_name(_c)] = 'int'
ITEM_KEYS = ('check_id', 'target_ref', 'followup_id', 'status', 'reason', 'values')
DOC_KEYS = ('schema_version', 'run_id', 'mode', 'generated_at', 'items')

# Thresholds (the same numbers the detection modules use).
SMART_TEMP_WARN_C = 60
NVME_WEAR_WARN, NVME_TEMP_WARN_C = 90, 70
JOURNAL_FAIL_AT = 50
STALE_DAYS = 7


class FollowupError(Exception):
    """Invalid input (exit 2)."""


# ------------------------------------------------------------------------------------------ commands

def search_path():
    override = os.environ.get('RESCUE_REPAIR_TEST_PATH', '')
    if override:
        parts = override.split(':')
        if all(p.startswith('/') and os.path.isdir(p) for p in parts):
            print('rescue-followup: TEST PATH override active (RESCUE_REPAIR_TEST_PATH)', file=sys.stderr)
            return override
    return SAFE_PATH


class Runner:
    """Fixed-argv command runner with a total deadline. Never a shell; output is parsed, never printed."""

    def __init__(self, timeout):
        self.deadline = time.monotonic() + timeout
        self.path = search_path()
        self.timed_out = False

    def remaining(self):
        return self.deadline - time.monotonic()

    def expired(self):
        return self.remaining() < 2

    def run(self, argv, limit):
        """(status, returncode, stdout text); status is ok|missing|timeout|error."""
        program = shutil.which(argv[0], path=self.path)
        if program is None:
            return 'missing', None, ''
        budget = min(limit, self.remaining())
        if budget < 2:
            self.timed_out = True
            return 'timeout', None, ''
        try:
            proc = subprocess.run([program] + list(argv[1:]), stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=budget, env={'PATH': self.path, 'LC_ALL': 'C'}, check=False)
        except subprocess.TimeoutExpired:
            self.timed_out = True
            return 'timeout', None, ''
        except (OSError, subprocess.SubprocessError):
            return 'error', None, ''
        return 'ok', proc.returncode, proc.stdout.decode('utf-8', 'replace')

    def json(self, argv, limit):
        """(status, parsed JSON dict or None, returncode). smartctl prints valid JSON with a non-zero exit."""
        status, rc, text = self.run(argv, limit)
        if status != 'ok':
            return status, None, rc
        try:
            doc = json.loads(text) if text.strip() else None
        except ValueError:
            return 'error', None, rc
        return ('ok' if isinstance(doc, dict) else 'error'), (doc if isinstance(doc, dict) else None), rc

    # hardware.Source compatibility: scripts/rescue_modules/hardware._internal_disks needs json_command()
    def json_command(self, _fixture_name, argv):
        _status, doc, _rc = self.json(argv, 20)
        return doc


# ------------------------------------------------------------------------------------------ items

def item(check_id, followup_id, status, reason, values=None, target_ref=None):
    out = {'check_id': check_id, 'followup_id': followup_id, 'status': status, 'reason': reason,
           'values': {k: v for k, v in (values or {}).items() if v is not None}}
    if target_ref:
        out['target_ref'] = target_ref
    return out


def _int(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or not 0 <= value <= MAX_NUMBER:
        return None
    return int(value)


# ------------------------------------------------------------------------------------------ disks

def parse_smart(doc):
    """(values, status, reason) for one ``smartctl -j -H -A -l selftest`` document, or None when unusable."""
    if not isinstance(doc, dict):
        return None
    smart = doc.get('smart_status') if isinstance(doc.get('smart_status'), dict) else {}
    nvme = doc.get('nvme_smart_health_information_log')
    ata = (doc.get('ata_smart_attributes') or {}).get('table') if isinstance(doc.get('ata_smart_attributes'), dict) \
        else None
    if not isinstance(nvme, dict) and not isinstance(ata, list) and not isinstance(smart.get('passed'), bool):
        return None
    values, attention, failed = {}, False, False
    if isinstance(smart.get('passed'), bool):
        values['smart_passed'] = smart['passed']
        failed = not smart['passed']
    if isinstance(ata, list):
        raw = {}
        for attr in ata:
            if isinstance(attr, dict) and isinstance(attr.get('id'), int):
                raw[attr['id']] = _int((attr.get('raw') or {}).get('value'))
        for aid, name in ((5, 'reallocated'), (197, 'pending'), (198, 'offline_uncorrectable')):
            values[name] = raw.get(aid)
            attention = attention or bool(raw.get(aid))
        values['power_on_hours'] = raw.get(9)
    pot = doc.get('power_on_time')
    if values.get('power_on_hours') is None and isinstance(pot, dict):
        values['power_on_hours'] = _int(pot.get('hours'))
    temp = _int((doc.get('temperature') or {}).get('current')) if isinstance(doc.get('temperature'), dict) else None
    values['temperature_c'] = temp
    if temp is not None and temp >= SMART_TEMP_WARN_C:
        attention = True
    if isinstance(nvme, dict):
        values['nvme_percentage_used'] = _int(nvme.get('percentage_used', nvme.get('percent_used')))
        values['nvme_media_errors'] = _int(nvme.get('media_errors'))
        values['nvme_critical_warning'] = _int(nvme.get('critical_warning'))
        values['nvme_available_spare'] = _int(nvme.get('available_spare', nvme.get('avail_spare')))
        if values['nvme_critical_warning']:
            failed = True
        if values['nvme_media_errors'] or (values['nvme_percentage_used'] or 0) >= NVME_WEAR_WARN:
            attention = True
        if values['temperature_c'] is None:
            values['temperature_c'] = _int(nvme.get('temperature'))
        if values.get('power_on_hours') is None:
            values['power_on_hours'] = _int(nvme.get('power_on_hours'))
        if (values['temperature_c'] or 0) >= NVME_TEMP_WARN_C:
            attention = True
    if failed:
        return values, 'fail', 'attention'
    return values, ('warn' if attention else 'pass'), ('attention' if attention else 'ok')


def parse_selftest(doc):
    """(selftest enum, percent remaining or None) from the same document: the LAST self-test."""
    if not isinstance(doc, dict):
        return 'unknown', None
    data = doc.get('ata_smart_data')
    status = (data or {}).get('self_test_status') if isinstance(data, dict) else None
    if isinstance(status, dict) and isinstance(status.get('value'), int):
        value = status['value']
        if value >> 4 == 15:   # self-test routine in progress
            pct = _int(status.get('remaining_percent'))
            return 'in-progress', pct if pct is not None else (value & 15) * 10
    nvme_log = doc.get('nvme_self_test_log')
    if isinstance(nvme_log, dict):
        op = (nvme_log.get('current_self_test_operation') or {}).get('value') \
            if isinstance(nvme_log.get('current_self_test_operation'), dict) else 0
        if isinstance(op, int) and op:
            done = _int(nvme_log.get('current_self_test_completion_percent'))
            return 'in-progress', (100 - done) if done is not None else None
        table = nvme_log.get('table')
        if isinstance(table, list) and table and isinstance(table[0], dict):
            res = (table[0].get('self_test_result') or {}).get('value') \
                if isinstance(table[0].get('self_test_result'), dict) else None
            if res == 0:
                return 'completed-ok', None
            if res in (1, 2, 3, 4):
                return 'aborted', None
            if isinstance(res, int):
                return 'failed', None
            return 'unknown', None
        return ('none', None) if isinstance(table, list) else ('unknown', None)
    log = doc.get('ata_smart_self_test_log')
    std = (log or {}).get('standard') if isinstance(log, dict) else None
    if isinstance(std, dict):
        table = std.get('table')
        if isinstance(table, list) and table and all(isinstance(t, dict) for t in table):
            latest = min(table, key=lambda t: t.get('num') if isinstance(t.get('num'), int) else 10 ** 6)
            st = latest.get('status') if isinstance(latest.get('status'), dict) else {}
            code = st.get('value') >> 4 if isinstance(st.get('value'), int) else None
            if code == 0:
                return 'completed-ok', None
            if code in (1, 2):
                return 'aborted', None
            if code is not None and 3 <= code <= 8:
                return 'failed', None
            if st.get('passed') is True:
                return 'completed-ok', None
            return ('failed', None) if st.get('passed') is False else ('unknown', None)
        if isinstance(table, list) or std.get('count') == 0:
            return 'none', None
    return 'unknown', None


def disk_items(runner, check_id, disks, wanted, is_root):
    """Items for the disks in *wanted* (names); *disks* is the full ordered list (ordinal = disk-N)."""
    out = []
    for ordinal, name in enumerate(disks[:16]):
        if name not in wanted:
            continue
        ref = 'disk-%d' % ordinal
        if runner.expired():
            out += [item(check_id, 'disk.attributes', 'unknown', 'timeout', target_ref=ref),
                    item(check_id, 'disk.selftest-result', 'unknown', 'timeout', target_ref=ref)]
            continue
        status, doc, rc = runner.json(['smartctl', '-j', '-H', '-A', '-l', 'selftest', '/dev/' + name], SMART_TIMEOUT)
        parsed = parse_smart(doc) if status == 'ok' else None
        if parsed is None:
            if status == 'missing':
                reason = 'tool-missing'
            elif status == 'timeout':
                reason = 'timeout'
            elif isinstance(rc, int) and rc & 2 and not is_root:
                reason = 'needs-root'    # smartctl exit bit 1: the device could not be opened
            else:
                reason = 'no-data'
            out += [item(check_id, 'disk.attributes', 'unknown', reason, target_ref=ref),
                    item(check_id, 'disk.selftest-result', 'unknown', reason, target_ref=ref)]
            continue
        values, st, reason = parsed
        out.append(item(check_id, 'disk.attributes', st, reason, values, ref))
        test, remaining = parse_selftest(doc)
        tvalues = {'selftest': test, 'selftest_percent_remaining': remaining}
        if test == 'completed-ok':
            out.append(item(check_id, 'disk.selftest-result', 'pass', 'ok', tvalues, ref))
        elif test == 'failed':
            out.append(item(check_id, 'disk.selftest-result', 'fail', 'attention', tvalues, ref))
        elif test == 'aborted':
            out.append(item(check_id, 'disk.selftest-result', 'warn', 'attention', tvalues, ref))
        elif test == 'in-progress':
            out.append(item(check_id, 'disk.selftest-result', 'unknown', 'in-progress', tvalues, ref))
        else:
            out.append(item(check_id, 'disk.selftest-result', 'unknown', 'no-data', tvalues, ref))
    return out


def internal_disks(runner):
    from rescue_modules import hardware
    return hardware._internal_disks(runner)


# ------------------------------------------------------------------------------------------ journal

_KERNEL_KEYWORDS = tuple((category, re.compile(pattern)) for category, pattern in (
    ('storage', r'\b(ata\d|nvme|scsi|i/o error|blk_update_request|sd[a-z]\b|ahci|mmc\d|md\d|dm-\d)'),
    ('filesystem', r'\b(ext[234]-fs|xfs|btrfs|fat-fs|ntfs3?|f2fs|squashfs|overlayfs)\b'),
    ('display-gpu', r'\b(i915|amdgpu|nouveau|nvidia|drm|radeon)\b'),
    ('audio', r'\b(snd|hda|sof-audio|alsa)\b'),
    ('bluetooth', r'\b(bluetooth|btusb|btintel|hci\d)\b'),
    ('network', r'\b(wlan\d|iwlwifi|wifi|eth\d|r8169|e1000e?|ath\d+k?|brcm\w*|rtw\w*|link is (up|down))\b'),
    ('usb', r'\b(usb|xhci\w*|ehci\w*)\b'),
    ('power-acpi', r'\b(acpi|thermal|apei|mce|battery)\b'),
))
_IDENT_CATEGORIES = (
    ('security-auth', ('sudo', 'sshd', 'polkit', 'pam', 'gdm-password', 'gdm', 'login', 'su', 'unix_chkpwd',
                       'lightdm', 'audit', 'passwd', 'cron', 'gnome-keyring')),
    ('network', ('networkmanager', 'nm-', 'wpa_supplicant', 'dhclient', 'systemd-networkd', 'avahi', 'dnsmasq',
                 'systemd-resolved', 'modemmanager')),
    ('audio', ('pulseaudio', 'pipewire', 'wireplumber', 'alsa')),
    ('bluetooth', ('bluetoothd', 'obexd')),
    ('display-gpu', ('gnome-shell', 'xorg', 'x11', 'mutter', 'cinnamon', 'xfwm', 'xfce', 'gdm-x', 'wayland',
                     'plasmashell', 'kwin', 'picom', 'lightdm-gtk')),
    ('storage', ('udisksd', 'smartd', 'mdadm', 'multipathd', 'lvm', 'fstrim')),
    ('power-acpi', ('upowerd', 'thermald', 'acpid', 'tlp', 'power-profiles')),
    ('usb', ('usbguard', 'usb_modeswitch', 'fwupd')),
    ('systemd', ('systemd',)),
)


def _field(entry, name):
    value = entry.get(name)
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and all(isinstance(v, int) and 0 <= v < 256 for v in value):
        return bytes(value).decode('utf-8', 'replace')
    return ''


def categorize(entry):
    """Internal allowlist mapping from journal fields to one fixed category. The text is never kept."""
    ident = _field(entry, 'SYSLOG_IDENTIFIER').lower() or _field(entry, '_COMM').lower()
    if _field(entry, '_TRANSPORT') == 'kernel' or ident == 'kernel':
        message = _field(entry, 'MESSAGE').lower()
        for category, pattern in _KERNEL_KEYWORDS:
            if pattern.search(message):
                return category
        return 'kernel'
    if _field(entry, '_TRANSPORT') == 'audit':
        return 'security-auth'
    for category, words in _IDENT_CATEGORIES:
        for w in words:
            if ident == w or (len(w) > 3 and ident.startswith(w)) or (w.endswith('-') and ident.startswith(w)):
                return category
    if ident or _field(entry, '_COMM'):
        return 'application'
    return 'other'


def count_journal(text, limit=JOURNAL_MAX_ENTRIES):
    """(counts by category, entries read, truncated) from ``journalctl -o json`` lines."""
    counts = {c: 0 for c in CATEGORIES}
    read = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        counts[categorize(entry)] += 1
        read += 1
        if read >= limit:
            return counts, read, True
    return counts, read, False


def journal_item(runner, check_id, target_ref, directory=None):
    argv = ['journalctl', '-p', '3', '-b', '-o', 'json', '--no-pager', '-n', str(JOURNAL_MAX_ENTRIES)]
    if directory:
        argv.insert(1, '--directory=' + directory)
    status, rc, text = runner.run(argv, JOURNAL_TIMEOUT)
    if status != 'ok':
        reason = {'missing': 'tool-missing', 'timeout': 'timeout'}.get(status, 'no-data')
        return item(check_id, 'journal.categories', 'unknown', reason, target_ref=target_ref)
    if rc not in (0, None) and not text.strip():
        return item(check_id, 'journal.categories', 'unknown', 'no-data' if directory else 'needs-root',
                    target_ref=target_ref)
    counts, read, truncated = count_journal(text)
    values = {_cat_name(c): n for c, n in counts.items()}
    values.update({'total': read, 'sampled': read, 'truncated': truncated})
    state = 'pass' if read == 0 else 'fail' if read >= JOURNAL_FAIL_AT else 'warn'
    return item(check_id, 'journal.categories', state, 'ok' if read == 0 else 'attention', values, target_ref)


def safe_journal_dir(root):
    """var/log/journal below *root* only if it stays inside the root and holds no symlink."""
    real_root = os.path.realpath(root)
    jdir = os.path.join(real_root, 'var/log/journal')
    if os.path.islink(jdir) or not os.path.isdir(jdir):
        return None
    if os.path.realpath(jdir) != jdir:
        return None
    for base, dirs, files in os.walk(jdir, followlinks=False):
        for name in dirs + files:
            if os.path.islink(os.path.join(base, name)):
                return None
    return jdir


def open_target(evidence_path, evidence, ref):
    import target_mount
    return target_mount.open_target(evidence_path, evidence, ref, False)


def live_journal_items(runner, evidence_path, evidence, check):
    ref = check.get('target_ref')
    cid = check['check_id']
    family = next((t.get('family') for t in evidence.get('target_systems') or [] if t.get('ref') == ref), None)
    if family not in ('linuxmint', 'linux-other'):
        return []
    if runner.expired():
        return [item(cid, 'journal.categories', 'unknown', 'timeout', target_ref=ref)]
    try:
        with open_target(evidence_path, evidence, ref) as root:
            jdir = safe_journal_dir(root)
            if jdir is None:
                return [item(cid, 'journal.categories', 'unknown', 'no-journal', target_ref=ref)]
            return [journal_item(runner, cid, ref, jdir)]
    except Exception:  # TargetMountError, missing mount tools, anything else: unknown, never a guess
        return [item(cid, 'journal.categories', 'unknown', 'not-mounted', target_ref=ref)]


# ------------------------------------------------------------------------------------------ malware

def signature_facts(mode, state_dir):
    """(db_present, age_days or None) from the signature DB on disk (reuses rescue_modules.malware)."""
    from rescue_modules import Context, malware
    ctx = Context(mode='host' if mode == 'linux-host' else 'live', state_dir=state_dir)
    _dir, epoch, has_db = malware.database(ctx)
    return has_db, malware.signature_age_days(epoch)


def malware_items(checks, mode, state_dir, evidence):
    out = []
    has_db, age = signature_facts(mode, state_dir)
    stale = (age is None) or age > STALE_DAYS
    base = {'db_present': has_db, 'signature_age_days': age, 'signature_stale': stale if has_db else None}
    scans = [c for c in evidence.get('checks', []) if c.get('check_id') == 'malware-scan']
    any_scanned = any(c.get('status') != 'unknown' for c in scans)
    for c in checks:
        cid, status, ref = c['check_id'], c['status'], c.get('target_ref')
        if cid == 'malware-signatures':
            if not has_db:
                out.append(item(cid, 'malware.signatures', 'warn', 'db-missing', base, ref))
            else:
                out.append(item(cid, 'malware.signatures', 'warn' if stale else 'pass',
                                'db-stale' if stale else 'ok', base, ref))
            continue
        number = _int((c.get('value') or {}).get('number')) if isinstance(c.get('value'), dict) else None
        values = dict(base, detections=number)
        if status == 'fail':
            values['coverage'], st, reason = 'detections-found', 'fail', 'detections'
        elif status == 'pass':
            values['coverage'], st, reason = 'complete', 'pass', 'ok'
        elif status == 'warn':
            if not has_db or stale:
                values['coverage'], st, reason = 'stale-signatures', 'warn', 'db-stale'
            else:
                values['coverage'], st, reason = 'incomplete', 'warn', 'incomplete'
        else:
            if any_scanned and ref:
                values['coverage'], st, reason = 'budget-exhausted', 'unknown', 'budget'
            else:
                values['coverage'] = 'not-scanned'
                st, reason = 'unknown', ('db-missing' if not has_db else 'not-scanned')
        out.append(item(cid, 'malware.coverage', st, reason, values, ref))
    return out


# ------------------------------------------------------------------------------------------ persistence

PERSISTENT_FS = ('ext2', 'ext3', 'ext4', 'btrfs', 'xfs', 'f2fs')
RAM_FS = ('tmpfs', 'ramfs')
OVERLAY_CANDIDATES = ('/cow', '/run/live/overlay', '/overlay')
_CMDLINE_PERSISTENT = re.compile(r'(?:^|\s)persist(?:ent|ence)(?:=|\s|$)|(?:^|\s)persistent-path=')


def _read(proc_root, rel):
    try:
        with open(os.path.join(proc_root, rel), 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read(1 << 20)
    except OSError:
        return None


def _unescape(field):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), field)


def parse_mounts(text):
    out = []
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append((_unescape(f[0]), _unescape(f[1]), f[2], f[3]))
    return out


def _backing(mount):
    """Classify the filesystem that holds the writable overlay layer."""
    src, _mp, fstype, _opts = mount
    if fstype in RAM_FS:
        return 'tmpfs'
    if fstype in PERSISTENT_FS and src.startswith('/dev/'):
        return 'loop' if src.startswith('/dev/loop') else 'block'
    return 'unknown'


def _containing(mounts, path):
    best = None
    for m in mounts:
        mp = m[1]
        if path == mp or path.startswith(mp.rstrip('/') + '/') or mp == '/':
            if best is None or len(mp) >= len(best[1]):
                best = m
    return best


def detect_persistence(proc_root='/'):
    """(persistence_active True/False/None, upper_backing, cmdline_persistent) from /proc files only."""
    cmdline = _read(proc_root, 'proc/cmdline')
    mounts_text = _read(proc_root, 'proc/mounts')
    if mounts_text is None:
        return None, 'unknown', (bool(_CMDLINE_PERSISTENT.search(cmdline)) if cmdline is not None else None)
    flag = bool(_CMDLINE_PERSISTENT.search(cmdline or ''))
    mounts = parse_mounts(mounts_text)
    root = next((m for m in reversed(mounts) if m[1] == '/'), None)
    backing = 'unknown'
    if root is not None and root[2] in ('overlay', 'aufs'):
        upper = re.search(r'(?:^|,)upperdir=([^,]+)', root[3])
        if upper:
            holder = _containing([m for m in mounts if m is not root], _unescape(upper.group(1)))
            if holder is not None:
                backing = _backing(holder)
    if backing == 'unknown':
        for candidate in OVERLAY_CANDIDATES:
            holder = next((m for m in reversed(mounts) if m[1] == candidate), None)
            if holder is not None:
                backing = _backing(holder)
                break
    if backing in ('block', 'loop'):
        return True, backing, flag
    if backing == 'tmpfs':
        return False, backing, flag
    return None, 'unknown', flag


def persistence_item(proc_root):
    active, backing, flag = detect_persistence(proc_root)
    values = {'persistence_active': active, 'upper_backing': backing, 'cmdline_persistent': flag}
    if active is None:
        return item('persistence', 'persistence.active', 'unknown', 'no-data', values)
    if flag and not active:
        return item('persistence', 'persistence.active', 'warn', 'attention', values)  # requested, not in effect
    return item('persistence', 'persistence.active', 'pass', 'ok', values)


# ------------------------------------------------------------------------------------------ privacy

_LEAKS = (re.compile(r'[/\\]'), re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'),
          re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'), re.compile(r'@'), re.compile(r'\s'),
          re.compile(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{0,4}){3,}'))


def _looks_like_secret_token(text):
    for token in re.findall(r'[A-Za-z0-9]{8,}', text):
        if re.search(r'\d', token) and re.search(r'[A-Za-z]', token):
            return True
    return False


def privacy_problems(doc):
    """Reasons *doc* must not be written (empty list = fine). The closed vocabulary is the allowlist."""
    problems = []
    if not isinstance(doc, dict) or set(doc) != set(DOC_KEYS):
        return ['document keys outside the contract']
    if doc['schema_version'] != '1.0':
        problems.append('schema_version')
    if not isinstance(doc['run_id'], str) or not RUN_ID.match(doc['run_id']):
        problems.append('run_id')
    if doc['mode'] not in MODES:
        problems.append('mode')
    if not isinstance(doc['generated_at'], str) or not TIMESTAMP.match(doc['generated_at']):
        problems.append('generated_at')
    items = doc['items']
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        return problems + ['items']
    for n, it in enumerate(items):
        where = 'items[%d]' % n
        if not isinstance(it, dict) or not set(it) <= set(ITEM_KEYS) \
                or not {'check_id', 'followup_id', 'status', 'reason', 'values'} <= set(it):
            problems.append(where + ': keys')
            continue
        for key, allowed in (('check_id', CHECK_IDS), ('followup_id', FOLLOWUP_IDS), ('status', STATUSES),
                             ('reason', REASONS)):
            if it[key] not in allowed:
                problems.append('%s: %s outside the closed set' % (where, key))
        ref = it.get('target_ref')
        if ref is not None and (not isinstance(ref, str) or not TARGET_REF.match(ref)):
            problems.append(where + ': target_ref')
        values = it['values']
        if not isinstance(values, dict):
            problems.append(where + ': values')
            continue
        for name, value in values.items():
            spec = VALUE_SPECS.get(name)
            if spec is None:
                problems.append('%s: value name %r not allowed' % (where, name[:24]))
            elif spec == 'bool':
                if not isinstance(value, bool):
                    problems.append('%s: %s must be a boolean' % (where, name))
            elif spec == 'int':
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value \
                        or not 0 <= value <= MAX_NUMBER:
                    problems.append('%s: %s must be a bounded number' % (where, name))
            elif value not in spec or not isinstance(value, str):
                problems.append('%s: %s outside the closed set' % (where, name))
    # Belt and braces: no string anywhere may look like a path, address, e-mail, serial or free text.
    for text in _strings(doc, skip_run_id=True):
        if any(p.search(text) for p in _LEAKS) or _looks_like_secret_token(text):
            problems.append('a string looks like a path, address, e-mail, serial or free text')
            break
    return problems


def _strings(node, skip_run_id=False):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            if skip_run_id and key == 'run_id':
                continue
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)
    elif isinstance(node, str):
        yield node


def schema_problems(doc):
    """Validate against followup.schema.json when python3-jsonschema is installed; [] otherwise."""
    try:
        import jsonschema
    except ImportError:
        return []
    schema = json.loads(SCHEMA_FILE.read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    return ['schema: ' + '/'.join(str(p) for p in e.absolute_path) for e in validator.iter_errors(doc)][:5]


# ------------------------------------------------------------------------------------------ driver

def load_evidence(path):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            evidence = json.load(handle)
    except (OSError, ValueError) as exc:
        raise FollowupError('cannot read evidence: %s' % exc.__class__.__name__)
    if not isinstance(evidence, dict) or not isinstance(evidence.get('checks'), list):
        raise FollowupError('evidence has no checks list')
    if not isinstance(evidence.get('run_id'), str) or not RUN_ID.match(evidence['run_id']):
        raise FollowupError('evidence run_id is missing or invalid')
    try:
        import jsonschema
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        schema = json.loads(EVIDENCE_SCHEMA_FILE.read_text(encoding='utf-8'))
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(evidence))
        if errors:
            raise FollowupError('evidence does not match the schema')
    return evidence


def default_mode(evidence):
    platform = evidence.get('source_platform')
    if platform in LIVE_PLATFORMS:
        return 'live-linux'
    if platform == 'linux-host':
        return 'linux-host'
    if platform == 'windows-host':
        return 'windows-host'
    raise FollowupError('no follow-ups for platform %s' % (platform if isinstance(platform, str) else '?'))


def in_scope(evidence, domain):
    scope = evidence.get('scope')
    if not isinstance(scope, list) or 'all' in scope:
        return True
    if domain == 'hardware':
        return any(s == 'hardware' or s.startswith('hardware.') for s in scope if isinstance(s, str))
    return domain in scope


def build(evidence, mode, evidence_path, state_dir, timeout, proc_root='/'):
    """The follow-up document for *evidence*. Pure apart from the fixed read-only commands."""
    runner = Runner(timeout)
    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
    flagged = [c for c in evidence['checks'] if isinstance(c, dict)
               and c.get('status') in ('warn', 'fail', 'unknown')]
    items = []
    wanted = {c['check_id'] for c in flagged}
    wants_disks = [cid for cid in ('smart-health', 'nvme-health') if cid in wanted and in_scope(evidence, 'hardware')]
    if wants_disks:
        disks = internal_disks(runner)
        if disks is None:
            items += [item(cid, 'disk.attributes', 'unknown', 'no-data') for cid in wants_disks]
        else:
            for cid in wants_disks:
                names = {d for d in disks if d.startswith('nvme') == (cid == 'nvme-health')}
                items += disk_items(runner, cid, disks, names, is_root)
    if in_scope(evidence, 'os'):
        for c in flagged:
            if c['check_id'] != 'linux-journal-errors':
                continue
            if mode == 'linux-host':
                items.append(journal_item(runner, 'linux-journal-errors', c.get('target_ref')) if not runner.expired()
                             else item('linux-journal-errors', 'journal.categories', 'unknown', 'timeout',
                                       target_ref=c.get('target_ref')))
            elif c.get('target_ref'):
                items += live_journal_items(runner, evidence_path, evidence, c)
    if in_scope(evidence, 'malware'):
        mw = [c for c in flagged if c['check_id'] in ('malware-scan', 'malware-signatures')]
        if mw:
            items += malware_items(mw, mode, state_dir, evidence)
    if mode == 'live-linux':
        items.append(persistence_item(proc_root))
    return {'schema_version': '1.0', 'run_id': evidence['run_id'], 'mode': mode,
            'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'items': items[:MAX_ITEMS]}


def write_atomic(doc, directory):
    final = os.path.join(directory, 'followup-%s.json' % doc['run_id'])
    fd, tmp = tempfile.mkstemp(prefix='.followup-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(doc, indent=2, sort_keys=True) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, 0o600)
            # Started through `sudo -n` (live USB): hand the file to the desktop user so Hermes can read it.
            uid, gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
            if hasattr(os, 'geteuid') and os.geteuid() == 0 and uid.isdigit() and gid.isdigit():
                os.chown(tmp, int(uid), int(gid))
        except OSError:
            pass
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return final


def summary(doc, filename):
    counts = {s: 0 for s in STATUSES}
    for it in doc['items']:
        counts[it['status']] += 1
    lines = ['rescue-followup: %s -> %s' % (doc['mode'], filename),
             'Tindak lanjut / Follow-ups: %d item (pass %d, warn %d, fail %d, unknown %d)'
             % (len(doc['items']), counts['pass'], counts['warn'], counts['fail'], counts['unknown'])]
    for it in doc['items']:
        lines.append('  - %s %s: %s (%s)' % (it.get('target_ref', '-'), it['followup_id'], it['status'], it['reason']))
    if any(it['reason'] == 'in-progress' for it in doc['items']):
        lines.append('Self-test disk masih berjalan: jalankan ulang rescue-followup setelah selesai. / '
                     'A disk self-test is still running: re-run rescue-followup when it has finished.')
    if any(it['reason'] in ('needs-root', 'needs-admin') for it in doc['items']):
        lines.append('Sebagian butuh hak root/admin dan ditandai unknown (bukan sehat). / '
                     'Some items need root/admin and are unknown (not healthy).')
    lines.append('unknown berarti belum diketahui, bukan sehat. / unknown means not determined, not healthy.')
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--evidence', required=True, metavar='FILE')
    ap.add_argument('--reports-dir', required=True, metavar='DIR')
    ap.add_argument('--mode', choices=MODES)
    ap.add_argument('--state-dir', metavar='DIR')
    ap.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, metavar='SECONDS')
    args = ap.parse_args(argv)
    try:
        if not MIN_TIMEOUT <= args.timeout <= MAX_TIMEOUT:
            raise FollowupError('--timeout must be %d..%d seconds' % (MIN_TIMEOUT, MAX_TIMEOUT))
        if not os.path.isdir(args.reports_dir):
            raise FollowupError('--reports-dir is not a directory')
        evidence = load_evidence(args.evidence)
        mode = args.mode or default_mode(evidence)
        if mode == 'windows-host':
            raise FollowupError('windows-host follow-ups are written natively by the Windows launcher')
        proc_root = os.environ.get('RESCUE_FOLLOWUP_PROC_ROOT') or '/'
        if proc_root != '/':
            print('rescue-followup: TEST PROC ROOT override active (RESCUE_FOLLOWUP_PROC_ROOT)', file=sys.stderr)
        doc = build(evidence, mode, args.evidence, args.state_dir, args.timeout, proc_root)
        problems = privacy_problems(doc) or schema_problems(doc)
        if problems:
            raise FollowupError('refusing to write the follow-up (privacy/schema self-check): %s' % problems[0])
        final = write_atomic(doc, args.reports_dir)
    except FollowupError as exc:
        print('rescue-followup: %s' % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print('rescue-followup: cannot write the follow-up (%s)' % exc.__class__.__name__, file=sys.stderr)
        return 2
    print(summary(doc, os.path.basename(final)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
