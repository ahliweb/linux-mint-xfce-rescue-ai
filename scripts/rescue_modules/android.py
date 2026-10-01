"""Android target detection: read-only ADB checks for a phone or tablet attached over USB.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#48. Contract: scripts/rescue_modules/__init__.py and
docs/android.md. USB enumeration (no phone cooperation needed) lives in usb_devices.py.

Read-only. The only commands are ``adb devices -l``, ``adb kill-server`` (live session only, to
stop the server that this scan started) and, for a device whose state is ``device`` (USB debugging
authorized), the FIXED argv tuples in COMMANDS, each addressed with ``adb -t <transport_id>``:

  * no serial, model or any other device data ever becomes part of an argv: the transport ID is a
    parsed integer and every other argument is a constant;
  * no ``adb root``, ``install``, ``push``, ``pull``, ``reboot``, ``sideload``, ``unlock`` and no
    shell string built from data; ``stdin`` is /dev/null, every call has a timeout, output is read
    with a size cap, and mDNS device discovery is switched off (no network);
  * everything the phone prints is untrusted data: it is parsed for a closed set of states and
    bounded numbers and then dropped. Package names, account names, serials, IMEI, phone numbers,
    Wi-Fi/Bluetooth MACs, model and USB strings never reach a returned value.

A missing ``adb`` binary, a missing permission or an unreadable value gives ``unknown``, never an
exception. Evidence carries statuses and bounded numbers only (kinds count/percent/days/celsius).
"""
import hashlib
import hmac
import os
import re
import select
import shutil
import subprocess
import time
from datetime import date, datetime, timezone

from . import usb_devices

FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
ADB_SEARCH_PATH = FIXED_PATH          # test hook: tests point it at a shim directory
ADB_TIMEOUT = 20                      # seconds per call
MAX_OUTPUT = 4 * 1024 * 1024          # bytes read per call
MAX_TARGETS = 8

STATES = ('device', 'unauthorized', 'offline', 'recovery', 'sideload', 'bootloader', 'rescue',
          'authorizing', 'connecting', 'no-permissions')
CHECK_IDS = (
    'android-connection-mode', 'android-os-version', 'android-security-patch-age',
    'android-verified-boot', 'android-bootloader-lock', 'android-selinux', 'android-storage-free',
    'android-battery-level', 'android-battery-health', 'android-battery-temperature',
    'android-root-indicators', 'android-device-admin-count', 'android-accessibility-services-count',
    'android-unknown-sources-count', 'android-play-protect', 'android-developer-options',
    'android-usb-port-speed',
)

# Thresholds (documented in docs/android.md)
SDK_PASS_MIN, SDK_WARN_MIN = 33, 29                 # Android 13+ pass, 10-12 warn, older fail
PATCH_WARN_DAYS, PATCH_FAIL_DAYS = 90, 365
STORAGE_WARN_PERCENT, STORAGE_FAIL_PERCENT = 10, 3
BATTERY_LOW_PERCENT, BATTERY_CRITICAL_PERCENT = 20, 10
BATTERY_WARN_C, BATTERY_FAIL_C = 40, 45
DEVICE_ADMIN_WARN = 3
FULL_SPEED_MBPS = 480                               # below this the link is a cable/port problem

SU_PATHS = ('/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su', '/vendor/bin/su',
            '/system_ext/bin/su', '/product/bin/su', '/data/local/bin/su', '/data/local/xbin/su')
# Installers that mean "installed from a file, not from a store" (null/empty/adb are added in code).
SIDELOAD_INSTALLERS = frozenset({'null', '', 'adb', 'com.google.android.packageinstaller',
                                 'com.android.packageinstaller'})
PROP_ALLOW = frozenset({
    'ro.build.version.sdk', 'ro.build.version.release', 'ro.build.version.security_patch',
    'ro.boot.verifiedbootstate', 'ro.boot.flash.locked', 'ro.boot.vbmeta.device_state',
    'ro.debuggable', 'ro.product.cpu.abi',
})

# Every shell command that is ever sent to a phone. Constant tuples; the transport is added by run().
COMMANDS = {
    'getprop': ('shell', 'getprop'),
    'getenforce': ('shell', 'getenforce'),
    'df': ('shell', 'df', '/data'),
    'battery': ('shell', 'dumpsys', 'battery'),
    'which_su': ('shell', 'which', 'su'),
    'su_paths': ('shell', 'ls', '-d') + SU_PATHS,
    'device_policy': ('shell', 'dumpsys', 'device_policy'),
    'accessibility': ('shell', 'settings', 'get', 'secure', 'enabled_accessibility_services'),
    'packages': ('shell', 'pm', 'list', 'packages', '-3', '-i'),
    'verifier_consent': ('shell', 'settings', 'get', 'global', 'package_verifier_user_consent'),
    'verifier_enable': ('shell', 'settings', 'get', 'global', 'package_verifier_enable'),
    'development': ('shell', 'settings', 'get', 'global', 'development_settings_enabled'),
}

DEVICE_LINE = re.compile(r'^(\S+)\s+(device|unauthorized|offline|recovery|sideload|bootloader|rescue|'
                         r'authorizing|connecting|no permissions)\b(.*)$')


# --------------------------------------------------------------------------------- running adb

def find_adb(search_path=None):
    """Path of the ``adb`` binary, or None (the check then reports ``unknown``)."""
    return shutil.which('adb', path=search_path or ADB_SEARCH_PATH)


def _environment(search_path):
    env = {'PATH': search_path or ADB_SEARCH_PATH, 'LC_ALL': 'C', 'ADB_MDNS': '0',
           'ADB_MDNS_OPENSCREEN': '0'}
    for key in ('HOME', 'USER', 'TMPDIR'):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _bounded(argv, timeout, env, merge_stderr=False):
    """(returncode, text) of one command with a deadline and an output cap, or None.

    *merge_stderr* is for fastboot and heimdall, which print their answers on stderr."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL, env=env)
    except OSError:
        return None
    chunks, total, ok = [], 0, False
    deadline = time.monotonic() + timeout
    try:
        fd = proc.stdout.fileno()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(left, 1.0))
            if not ready:
                continue
            data = os.read(fd, 65536)
            if not data:
                ok = True
                break
            total += len(data)
            if total > MAX_OUTPUT:
                break
            chunks.append(data)
        if ok:
            try:
                proc.wait(timeout=max(0.2, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                ok = False
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
    if not ok:
        return None
    return proc.returncode, b''.join(chunks).decode('utf-8', 'replace')


class Adb:
    """The only way this module talks to adb: fixed argv, a parsed integer transport, bounded output."""

    def __init__(self, program, search_path=None, timeout=ADB_TIMEOUT):
        self.program = program
        self.env = _environment(search_path)
        self.timeout = timeout

    def devices(self):
        return _bounded([self.program, 'devices', '-l'], self.timeout, self.env)

    def kill_server(self):
        return _bounded([self.program, 'kill-server'], self.timeout, self.env)

    def run(self, transport_id, name):
        """Output text of the constant command COMMANDS[name] on transport *transport_id*, or None."""
        if not isinstance(transport_id, int) or isinstance(transport_id, bool) or not 0 < transport_id < 1 << 31:
            return None
        res = _bounded([self.program, '-t', str(transport_id)] + list(COMMANDS[name]), self.timeout, self.env)
        return None if res is None else res[1]


# ------------------------------------------------------------------------------------ parsing

def parse_devices(text):
    """Entries of ``adb devices -l`` that sit on a USB port: ``{'state', 'transport_id', 'port'}``.

    The serial, model, product and device-name fields are dropped here and never kept. Network
    (``host:port``) and emulator devices carry no ``usb:`` field and are ignored. ``port`` is None
    when adb reports a location that is not a sysfs port path (very old adb versions)."""
    out = []
    started = False
    for line in (text or '').splitlines():
        if line.startswith('List of devices attached'):
            started = True
            continue
        if not started:
            continue
        m = DEVICE_LINE.match(line.strip())
        if not m:
            continue
        state = 'no-permissions' if m.group(2) == 'no permissions' else m.group(2)
        rest = m.group(3)
        usb = re.search(r'(?:^|\s)usb:(\S+)', rest)
        if usb is None:
            continue
        tid = re.search(r'(?:^|\s)transport_id:([0-9]{1,9})(?:\s|$)', rest)
        port = usb.group(1) if usb_devices.valid_port(usb.group(1)) else None
        out.append({'state': state, 'transport_id': int(tid.group(1)) if tid else None, 'port': port})
        if len(out) >= MAX_TARGETS:
            break
    return out


def parse_getprop(text):
    """Allowlisted ``ro.*`` properties from ``getprop`` output; everything else is dropped."""
    props = {}
    for line in (text or '').splitlines():
        m = re.match(r'^\[([A-Za-z0-9._-]{1,64})\]: \[(.{0,128})\]$', line.strip())
        if m and m.group(1) in PROP_ALLOW:
            props[m.group(1)] = m.group(2).strip()
    return props


def _int(text, low, high):
    try:
        value = int(str(text).strip())
    except (TypeError, ValueError):
        return None
    return value if low <= value <= high else None


def parse_battery(text):
    """{'level', 'health', 'status', 'temperature_c'} from ``dumpsys battery`` (None for a missing field)."""
    fields = {}
    for line in (text or '').splitlines():
        m = re.match(r'^\s*([A-Za-z ]{3,24}):\s*(-?[0-9]{1,6})\s*$', line)
        if m:
            fields.setdefault(m.group(1).strip().lower(), int(m.group(2)))
    temp = fields.get('temperature')
    return {'level': fields.get('level'), 'health': fields.get('health'), 'status': fields.get('status'),
            'temperature_c': temp / 10.0 if temp is not None else None}


def parse_df_free_percent(text):
    """Free percent of /data from ``df /data`` (toybox or busybox), or None."""
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == '/data':
            for item in parts:
                m = re.match(r'^([0-9]{1,3})%$', item)
                if m and int(m.group(1)) <= 100:
                    return 100 - int(m.group(1))
    return None


def count_device_admins(text):
    """Number of enabled device-admin components in ``dumpsys device_policy``, or None."""
    if not text or 'Device Admins' not in text:
        return None
    count, base, inside = 0, 0, False
    for line in text.splitlines():
        stripped = line.strip()
        if 'Enabled Device Admins' in line:
            inside, base = True, len(line) - len(line.lstrip())
            continue
        if not inside:
            continue
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base:
            inside = False
            continue
        if re.match(r'^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+:$', stripped):
            count += 1
    return min(count, 99)


def count_list_setting(text):
    """Entries of a ``:``-separated settings value (``null`` or empty is zero), or None."""
    if text is None or not text.strip():
        return None               # an empty answer is a failed read, not "none enabled" (that prints null)
    value = text.strip().splitlines()[0].strip()
    if value == 'null':
        return 0
    if len(value) > 4096 or not re.match(r'^[A-Za-z0-9_.$/:-]+$', value):
        return None
    return min(len([p for p in value.split(':') if p]), 99)


def count_sideloaded(text):
    """Third-party packages not installed by a store, from ``pm list packages -3 -i`` (count only).

    None when the output is not a package list with installer fields (error text, old Android)."""
    listed = with_installer = count = 0
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('package:'):
            continue
        listed += 1
        m = re.match(r'^package:\S+\s+installer=(\S*)$', line)
        if m:
            with_installer += 1
            if m.group(1) in SIDELOAD_INSTALLERS:
                count += 1
    if listed == 0 or with_installer == 0:
        return None
    return min(count, 9999)


def count_su_paths(text):
    """How many of the fixed su locations ``ls -d`` printed (anything else is ignored)."""
    return len([p for p in (text or '').splitlines() if p.strip() in SU_PATHS])


# -------------------------------------------------------------------------------- the checks

def _c(check_id, status, kind=None, number=None):
    item = {'check_id': check_id, 'status': status}
    if kind is not None and number is not None:
        item['kind'] = kind
        item['number'] = max(0, min(int(number), 1000000))
    return item


def _u(check_id):
    return _c(check_id, 'unknown')


def connection_status(target, adb_available):
    """Status of android-connection-mode for one target dict (see docs/android.md)."""
    state, mode = target.get('adb_state'), target.get('mode')
    if state == 'device':
        return 'pass'
    if state in STATES:
        return 'warn'                 # unauthorized, offline, recovery, sideload, bootloader, ...
    if mode in usb_devices.LOW_LEVEL_MODES:
        return 'warn'                 # fastboot / EDL / download: not a running Android
    if not adb_available:
        return 'unknown'              # cannot tell whether USB debugging would work
    return 'warn'                     # seen on USB, but USB debugging is off or not offered


def usb_speed_check(usb):
    if not usb or usb.get('speed_mbps') is None:
        return _u('android-usb-port-speed')
    return _c('android-usb-port-speed', 'warn' if usb['speed_mbps'] < FULL_SPEED_MBPS else 'pass')


def _os_version(props):
    sdk = _int(props.get('ro.build.version.sdk'), 1, 99)
    if sdk is None:
        return _u('android-os-version')
    status = 'pass' if sdk >= SDK_PASS_MIN else 'warn' if sdk >= SDK_WARN_MIN else 'fail'
    return _c('android-os-version', status, 'count', sdk)


def _patch_age(props, today):
    m = re.match(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})$', props.get('ro.build.version.security_patch', ''))
    if not m:
        return _u('android-security-patch-age')
    try:
        days = (today - date(int(m.group(1)), int(m.group(2)), int(m.group(3)))).days
    except ValueError:
        return _u('android-security-patch-age')
    days = max(0, days)                       # a patch date after today's (possibly wrong) clock is age 0
    status = 'fail' if days > PATCH_FAIL_DAYS else 'warn' if days > PATCH_WARN_DAYS else 'pass'
    return _c('android-security-patch-age', status, 'days', days)


def _verified_boot(props):
    state = props.get('ro.boot.verifiedbootstate')
    return _c('android-verified-boot', {'green': 'pass', 'yellow': 'warn', 'orange': 'warn',
                                        'red': 'fail'}.get(state, 'unknown'))


def _bootloader(props):
    locked, vbmeta = props.get('ro.boot.flash.locked'), props.get('ro.boot.vbmeta.device_state')
    if locked == '1' or vbmeta == 'locked':
        return _c('android-bootloader-lock', 'pass')
    if locked == '0' or vbmeta == 'unlocked':
        return _c('android-bootloader-lock', 'warn')
    return _u('android-bootloader-lock')


def _selinux(text):
    word = (text or '').strip().split('\n')[0].strip().lower()
    return _c('android-selinux', {'enforcing': 'pass', 'permissive': 'fail', 'disabled': 'fail'}.get(word, 'unknown'))


def _storage(df_text):
    free = parse_df_free_percent(df_text)
    if free is None:
        return _u('android-storage-free')
    return _c('android-storage-free', 'fail' if free < STORAGE_FAIL_PERCENT else 'warn'
              if free < STORAGE_WARN_PERCENT else 'pass', 'percent', free)


def _battery(battery_text):
    info = parse_battery(battery_text)
    out = []
    level, charging = info['level'], info['status'] in (2, 5)     # 2 charging, 5 full
    if level is None or not 0 <= level <= 100:
        out.append(_u('android-battery-level'))
    else:
        status = 'pass' if charging else 'fail' if level < BATTERY_CRITICAL_PERCENT else \
            'warn' if level < BATTERY_LOW_PERCENT else 'pass'
        out.append(_c('android-battery-level', status, 'percent', level))
    health = {2: 'pass', 3: 'fail', 4: 'fail', 5: 'fail', 6: 'warn', 7: 'warn'}.get(info['health'], 'unknown')
    out.append(_c('android-battery-health', health))
    temp = info['temperature_c']
    if temp is None or not -40 <= temp <= 150:
        out.append(_u('android-battery-temperature'))
    elif temp < 0:
        out.append(_c('android-battery-temperature', 'warn'))      # the schema carries whole non-negative degrees
    else:
        whole = int(temp)
        out.append(_c('android-battery-temperature', 'fail' if whole >= BATTERY_FAIL_C else
                      'warn' if whole >= BATTERY_WARN_C else 'pass', 'celsius', whole))
    return out


def _root(props, which_text, paths_text, props_read):
    if not props_read:
        return _u('android-root-indicators')
    found = count_su_paths(paths_text) + (1 if (which_text or '').strip().startswith('/') else 0)
    if props.get('ro.debuggable') == '1':
        found += 1
    return _c('android-root-indicators', 'warn' if found else 'pass')


def _admins(text):
    count = count_device_admins(text)
    if count is None:
        return _u('android-device-admin-count')
    return _c('android-device-admin-count', 'warn' if count >= DEVICE_ADMIN_WARN else 'pass', 'count', count)


def _accessibility(text):
    count = count_list_setting(text)
    if count is None:
        return _u('android-accessibility-services-count')
    return _c('android-accessibility-services-count', 'warn' if count > 0 else 'pass', 'count', count)


def _sideloaded(text):
    count = count_sideloaded(text) if text is not None else None
    if count is None:
        return _u('android-unknown-sources-count')
    return _c('android-unknown-sources-count', 'warn' if count > 0 else 'pass', 'count', count)


def _play_protect(consent_text, enable_text):
    consent = (consent_text or '').strip().splitlines()[:1]
    enable = (enable_text or '').strip().splitlines()[:1]
    consent, enable = (consent[0].strip() if consent else ''), (enable[0].strip() if enable else '')
    if consent == '-1' or enable == '0':
        return _c('android-play-protect', 'warn')
    if consent == '1' and enable != '0':
        return _c('android-play-protect', 'pass')
    return _u('android-play-protect')


def _developer_options(text):
    value = (text or '').strip().splitlines()[:1]
    value = value[0].strip() if value else ''
    # Developer options are on whenever USB debugging could be authorized: that is how this scan got
    # in, not a finding. not_applicable says exactly that; pass would read as "checked and healthy".
    return _c('android-developer-options', {'1': 'not_applicable', '0': 'pass'}.get(value, 'unknown'))


def evaluate(outputs, today=None):
    """The adb-derived checks (without connection mode and port speed) from raw command output.

    *outputs* maps COMMANDS names to text (None when a command failed). Returns a list of check
    dicts and the parsed allowlisted properties."""
    today = today or datetime.now(timezone.utc).date()
    props = parse_getprop(outputs.get('getprop'))
    props_read = outputs.get('getprop') is not None and bool((outputs.get('getprop') or '').strip())
    out = [_os_version(props), _patch_age(props, today), _verified_boot(props), _bootloader(props),
           _selinux(outputs.get('getenforce')), _storage(outputs.get('df'))]
    out += _battery(outputs.get('battery'))
    out += [_root(props, outputs.get('which_su'), outputs.get('su_paths'), props_read),
            _admins(outputs.get('device_policy')), _accessibility(outputs.get('accessibility')),
            _sideloaded(outputs.get('packages')),
            _play_protect(outputs.get('verifier_consent'), outputs.get('verifier_enable')),
            _developer_options(outputs.get('development'))]
    return out, props


def collect_target_checks(adb, target, adb_available, today=None):
    """Ordered check dicts (CHECK_IDS order) for one target dict, plus the allowlisted properties.

    Without an authorized ADB connection every adb-derived check is ``unknown``."""
    checks = {'android-connection-mode': _c('android-connection-mode', connection_status(target, adb_available)),
              'android-usb-port-speed': usb_speed_check(target.get('usb'))}
    props = {}
    if target.get('adb_state') == 'device' and adb is not None and target.get('transport_id'):
        outputs = {name: adb.run(target['transport_id'], name) for name in COMMANDS}
        derived, props = evaluate(outputs, today)
        checks.update({c['check_id']: c for c in derived})
    return [checks.get(cid) or _u(cid) for cid in CHECK_IDS], props


# ------------------------------------------------------------------------------ discovery

def opaque_seed():
    """Salt for the opaque device ID: the host's machine-id (never emitted), as the collectors do."""
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, encoding='ascii') as handle:
                mid = handle.read().strip()
            if mid:
                return 'machine-id:' + mid
        except (OSError, UnicodeDecodeError):
            pass
    return 'fallback:' + hashlib.sha256(b'rescue-android').hexdigest()


def opaque_id(serial, port, usb, seed=None):
    """``target-`` + 16 hex of HMAC-SHA256 keyed with the host seed over the device serial.

    The serial (or, when the phone exposes none, port plus vendor:product) is never emitted; the
    keyed hash stops anyone from confirming a guessed serial against the evidence, and keeps the
    ID stable for the same phone on the same machine so a before/after scan can be compared."""
    material = serial or '%s|%s:%s' % (port or '-', (usb or {}).get('vendor_id', '-'), (usb or {}).get('product_id', '-'))
    key = (seed or opaque_seed()).encode('utf-8')
    digest = hmac.new(key, b'android-target:' + material.encode('utf-8', 'replace'), hashlib.sha256).hexdigest()
    return 'target-' + digest[:16]


def discover(usb_list, adb, adb_available, seed=None, serial_reader=None):
    """Android targets from the USB inventory and ``adb devices -l``, numbered and-0, and-1, ...

    Each target dict: ref, port, usb (device dict or None), adb_state (or None), transport_id, mode,
    modes, brand, access, detection, opaque_id. Order is by port path, so the numbering is stable
    for as long as the phones stay in their ports. No serial or string is kept in a target."""
    reader = serial_reader or usb_devices.read_serial
    usb_list = usb_list or []
    by_port = {d['port']: d for d in usb_list}
    adb_entries = []
    if adb is not None:
        res = adb.devices()
        adb_entries = parse_devices(res[1]) if res and res[0] == 0 else []
    android_ports = {d['port'] for d in usb_list if d['is_android']}
    claimed, loose = {}, []
    for entry in adb_entries:
        if entry['port'] in by_port:
            claimed[entry['port']] = entry
        else:
            loose.append(entry)
    # Very old adb prints no sysfs port: pair it with the one USB device that offers ADB and is unclaimed.
    free_ports = [d['port'] for d in usb_list if 'adb' in d['android_modes'] and d['port'] not in claimed]
    for entry in list(loose):
        if len(loose) == 1 and len(free_ports) == 1 and entry['port'] is None:
            entry['port'] = free_ports[0]
            claimed[entry['port']] = entry
            loose.remove(entry)

    raw = []
    for port in sorted(android_ports | set(claimed), key=usb_devices.port_key):
        raw.append((port, by_port.get(port), claimed.get(port)))
    raw += [(entry['port'], None, entry) for entry in loose]
    targets = []
    for port, usb, entry in raw[:MAX_TARGETS]:
        state = entry['state'] if entry else None
        access = 'usb-only'
        if state == 'device':
            access = 'adb-authorized'
        elif state == 'unauthorized':
            access = 'adb-unauthorized'
        elif state is not None:
            access = 'adb-unavailable'
        mode = usb['android_mode'] if usb and usb['android_mode'] != 'none' else ('adb' if entry else 'none')
        modes = list(usb['android_modes']) if usb else ['adb']
        serial = reader(port) if port and usb else None
        targets.append({
            'ref': 'and-%d' % len(targets), 'port': port, 'usb': usb, 'adb_state': state,
            'transport_id': entry['transport_id'] if entry else None, 'mode': mode, 'modes': modes,
            'brand': usb['brand'] if usb else 'other', 'access': access,
            'detection': 'usb-adb' if entry else 'usb-enumerated',
            'opaque_id': opaque_id(serial, port, usb, seed),
        })
    return targets


def release_label(props):
    """``Android 14`` from ro.build.version.release (digits and dots only), or None."""
    value = props.get('ro.build.version.release', '')
    return 'Android ' + value if re.match(r'^[0-9]{1,2}(\.[0-9]{1,2}){0,2}$', value) else None


def architecture(props):
    abi = props.get('ro.product.cpu.abi', '')
    return 'arm64' if abi.startswith('arm64') else 'x86_64' if abi == 'x86_64' else 'unknown'


def usb_inventory_checks(usb_list):
    """Environment checks (no target_ref): usb-device-count and usb-android-device-count."""
    if usb_list is None:
        return [_u('usb-device-count'), _u('usb-android-device-count')]
    devices = [d for d in usb_list if not d['is_hub']]
    phones = [d for d in usb_list if d['is_android']]
    return [_c('usb-device-count', 'pass', 'count', len(devices)),
            _c('usb-android-device-count', 'pass' if phones else 'warn', 'count', len(phones))]


def stop_server(adb):
    """Stop the adb server this scan started (live session only; the caller decides)."""
    if adb is not None:
        adb.kill_server()
