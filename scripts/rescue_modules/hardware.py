"""Hardware detection (CPU, memory, disk, GPU, display, network, battery, USB).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#15. Contract: scripts/rescue_modules/__init__.py and
docs/repair-framework.md. Operator documentation: docs/hardware.md.

Read-only. The only sources are /proc/cpuinfo, /proc/meminfo, /sys (thermal, hwmon, power_supply,
net, drm, bus/pci, bus/usb, rfkill, devices/system/edac) and three read-only commands with fixed
argv: ``lsblk -J``, ``smartctl -j -H -A`` and ``nvme smart-log -o json``. A missing tool or missing
permission gives ``unknown``, never an exception. Evidence carries numbers only (percent, count,
bytes, seconds): no model names, serials, MAC addresses, device paths or free text.

Test mode: with ``ctx.fixture_root`` set (scan-target-os.py --fixture-root) or the environment
variable RESCUE_HARDWARE_FIXTURE_ROOT set (Linux host launcher), the module reads DIR/hardware/
(or DIR itself when it contains ``proc`` or ``sys``) instead of the live system and never runs a
command: ``proc/``, ``sys/`` mirror the real trees, and canned command output lives in
``cmd/lsblk.json``, ``cmd/smartctl-<name>.json`` and ``cmd/nvme-<name>.json``. A fixture root
without hardware fixtures yields no hardware checks at all (the live system is never read).
"""
import json
import os
import re
import shutil
import subprocess

FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
FIXTURE_ENV = 'RESCUE_HARDWARE_FIXTURE_ROOT'
DISK_NAME = re.compile(r'^(sd[a-z]{1,2}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,2}|hd[a-z]|mmcblk[0-9]{1,2})$')
COMMAND_TIMEOUT = 20

# Thresholds (documented in docs/hardware.md)
CPU_WARN_C, CPU_FAIL_C = 80, 95
MEM_WARN_BYTES = 2 * 1024 ** 3
BATTERY_LOW_PERCENT, BATTERY_CRITICAL_PERCENT = 20, 10
BATTERY_HEALTH_WARN, BATTERY_HEALTH_FAIL = 60, 40
NVME_WEAR_WARN, NVME_WEAR_FAIL = 90, 100
NVME_TEMP_WARN_C, NVME_TEMP_FAIL_C = 70, 80
SMART_TEMP_WARN_C = 60


RANK = {'pass': 0, 'warn': 1, 'fail': 2}


class Source:
    """Read-only view of /proc, /sys and three fixed commands; a fixture root replaces all of it."""

    def __init__(self, fixture):
        self.fixture = fixture

    def path(self, *parts):
        base = self.fixture or os.sep
        return os.path.join(base, *[p.lstrip('/') for p in parts])

    def read(self, *parts):
        try:
            with open(self.path(*parts), 'r', encoding='utf-8', errors='replace') as handle:
                return handle.read(1 << 20)
        except OSError:
            return None

    def number(self, *parts):
        text = self.read(*parts)
        try:
            return int(text.strip()) if text is not None else None
        except ValueError:
            return None

    def listdir(self, *parts):
        try:
            return sorted(os.listdir(self.path(*parts)))
        except OSError:
            return None

    def exists(self, *parts):
        return os.path.lexists(self.path(*parts))

    def isdir(self, *parts):
        return os.path.isdir(self.path(*parts))

    def json_command(self, fixture_name, argv):
        """Parsed JSON output of a fixed, read-only command, or None (missing tool, no permission)."""
        if self.fixture:
            text = self.read('cmd', fixture_name + '.json')
        else:
            program = shutil.which(argv[0], path=FIXED_PATH)
            if program is None:
                return None
            try:
                proc = subprocess.run([program] + argv[1:], stdin=subprocess.DEVNULL, capture_output=True,
                                      timeout=COMMAND_TIMEOUT, env={'PATH': FIXED_PATH, 'LC_ALL': 'C'})
            except (OSError, subprocess.SubprocessError):
                return None
            # smartctl exits non-zero when it finds problems but still prints valid JSON.
            text = proc.stdout.decode('utf-8', 'replace')
        try:
            value = json.loads(text) if text else None
        except ValueError:
            return None
        return value if isinstance(value, (dict, list)) else None


def _check(check_id, status, kind=None, number=None):
    out = {'check_id': check_id, 'status': status}
    if kind is not None and number is not None:
        out['kind'] = kind
        out['number'] = int(number)
    return out


def _unknown(*ids):
    return [_check(i, 'unknown') for i in ids]


# ------------------------------------------------------------------------- cpu

def _cpu_temperatures(src):
    """Highest temperature in whole degrees Celsius from thermal zones and hwmon, or None."""
    values = []
    for zone in src.listdir('sys/class/thermal') or []:
        if zone.startswith('thermal_zone'):
            v = src.number('sys/class/thermal', zone, 'temp')
            if v is not None:
                values.append(v)
    for mon in src.listdir('sys/class/hwmon') or []:
        for name in src.listdir('sys/class/hwmon', mon) or []:
            if re.fullmatch(r'temp[0-9]+_input', name):
                v = src.number('sys/class/hwmon', mon, name)
                if v is not None:
                    values.append(v)
    values = [v for v in values if -50000 < v < 250000]  # millidegrees; drops bogus sentinels
    return max(values) // 1000 if values else None


def _throttle_events(src):
    total, seen = 0, False
    for cpu in src.listdir('sys/devices/system/cpu') or []:
        if re.fullmatch(r'cpu[0-9]+', cpu):
            for name in ('core_throttle_count', 'package_throttle_count'):
                v = src.number('sys/devices/system/cpu', cpu, 'thermal_throttle', name)
                if v is not None:
                    seen = True
                    total += v
    return total if seen else None


def check_cpu(src):
    text = src.read('proc/cpuinfo')
    count = len(re.findall(r'(?m)^processor\s*:', text)) if text else 0
    cpu = _check('hw-cpu', 'pass', 'count', count) if count else _check('hw-cpu', 'unknown')
    temp, throttle = _cpu_temperatures(src), _throttle_events(src)
    if temp is None:
        thermal = _check('hw-cpu-thermal', 'unknown')
    else:
        status = 'fail' if temp >= CPU_FAIL_C else 'warn' if temp >= CPU_WARN_C or (throttle or 0) > 0 else 'pass'
        thermal = _check('hw-cpu-thermal', status, 'celsius', max(0, temp))
    return [cpu, thermal]


# ---------------------------------------------------------------------- memory

def check_memory(src):
    text = src.read('proc/meminfo')
    values = {}
    for line in (text or '').splitlines():
        m = re.match(r'^(\w+):\s+(\d+)', line)
        if m:
            values[m.group(1)] = int(m.group(2))
    total = values.get('MemTotal')
    if not total:
        memory = _check('hw-memory', 'unknown')
    else:
        size = total * 1024
        status = 'fail' if values.get('HardwareCorrupted', 0) > 0 else 'warn' if size < MEM_WARN_BYTES else 'pass'
        memory = _check('hw-memory', status, 'bytes', size)
    # ECC error counters (EDAC). No EDAC driver/hardware means "not applicable", not "healthy".
    controllers = [n for n in src.listdir('sys/devices/system/edac/mc') or [] if re.fullmatch(r'mc[0-9]+', n)]
    if src.listdir('sys/devices/system/edac/mc') is None:
        # no EDAC driver/hardware (non-ECC RAM) is "not applicable"; unreadable /sys is "unknown"
        errors = _check('hw-memory-errors', 'unknown' if src.listdir('sys/devices/system') is None
                        else 'not_applicable')
    else:
        ce = ue = 0
        readable = False
        for mc in controllers:
            for name in ('ce_count', 'ue_count'):
                v = src.number('sys/devices/system/edac/mc', mc, name)
                if v is not None:
                    readable = True
                    if name == 'ce_count':
                        ce += v
                    else:
                        ue += v
        if not readable:
            errors = _check('hw-memory-errors', 'unknown')
        else:
            errors = _check('hw-memory-errors', 'fail' if ue else 'warn' if ce else 'pass', 'count', ce + ue)
    return [memory, errors]


# ------------------------------------------------------------------------ disk

def _internal_disks(src):
    """Names of internal fixed disks from ``lsblk -J`` (no USB, removable, loop, optical, zram)."""
    data = src.json_command('lsblk', ['lsblk', '-J', '-b', '-d', '-o', 'NAME,TYPE,SIZE,RM,TRAN,RO'])
    if not isinstance(data, dict) or not isinstance(data.get('blockdevices'), list):
        return None
    names = []
    for dev in data['blockdevices']:
        if not isinstance(dev, dict) or dev.get('type') != 'disk':
            continue
        name = dev.get('name')
        removable = str(dev.get('rm')).lower() in ('1', 'true')
        if not isinstance(name, str) or not DISK_NAME.match(name) or removable or dev.get('tran') == 'usb':
            continue
        names.append(name)
    return names


def _smart_problems(data):
    """(assessed, problem) for one smartctl -j -H -A document."""
    smart = data.get('smart_status') if isinstance(data, dict) else None
    if not isinstance(smart, dict) or not isinstance(smart.get('passed'), bool):
        return False, False
    if not smart['passed']:
        return True, True
    table = ((data.get('ata_smart_attributes') or {}).get('table')) or []
    for attr in table:
        if isinstance(attr, dict) and attr.get('id') in (5, 197, 198):  # reallocated, pending, uncorrectable
            raw = (attr.get('raw') or {}).get('value')
            if isinstance(raw, int) and raw > 0:
                return True, True
    temp = (data.get('temperature') or {}).get('current')
    if isinstance(temp, int) and temp >= SMART_TEMP_WARN_C:
        return True, True
    return True, False


def _smart_is_fail(data):
    smart = data.get('smart_status') or {}
    return smart.get('passed') is False


def _nvme_state(data, kelvin):
    """(status, wear_percent) for one nvme smart-log JSON, or (None, None) when it is unusable."""
    if not isinstance(data, dict):
        return None, None
    # smartctl -j nests the same fields under nvme_smart_health_information_log
    log = data.get('nvme_smart_health_information_log', data)
    warning = log.get('critical_warning')
    if not isinstance(warning, int):
        return None, None
    used = log.get('percent_used', log.get('percentage_used'))
    used = used if isinstance(used, int) else 0
    spare, spare_thr = log.get('avail_spare', log.get('available_spare')), \
        log.get('spare_thresh', log.get('available_spare_threshold'))
    media = log.get('media_errors', 0) if isinstance(log.get('media_errors', 0), int) else 0
    temp = log.get('temperature')
    if kelvin and isinstance(temp, int):   # nvme-cli reports Kelvin, smartctl Celsius
        temp -= 273
    status = 'pass'
    if warning or used >= NVME_WEAR_FAIL or (isinstance(temp, int) and temp >= NVME_TEMP_FAIL_C) or (
            isinstance(spare, int) and isinstance(spare_thr, int) and spare < spare_thr):
        status = 'fail'
    elif used >= NVME_WEAR_WARN or media > 0 or (isinstance(temp, int) and temp >= NVME_TEMP_WARN_C):
        status = 'warn'
    return status, min(used, 100)


def check_disk(src, mode):
    disks = _internal_disks(src)
    if disks is None:
        return _unknown('hw-disk', 'smart-health', 'nvme-health')
    out = [_check('hw-disk', 'pass' if disks else 'fail', 'count', len(disks))]
    ata = [d for d in disks if not d.startswith('nvme')]
    nvme = [d for d in disks if d.startswith('nvme')]

    # smart-health: the Linux host launcher already emits its own smart-health, so the module adds
    # it only on the live USB (no duplicate check IDs).
    if mode != 'host':
        if not ata:
            out.append(_check('smart-health', 'not_applicable'))
        else:
            assessed = problems = fails = 0
            for name in ata:
                doc = src.json_command('smartctl-' + name, ['smartctl', '-j', '-H', '-A', '/dev/' + name])
                ok, bad = _smart_problems(doc)
                assessed += ok
                problems += bad
                fails += bool(ok and _smart_is_fail(doc))
            if assessed == 0:
                out.append(_check('smart-health', 'unknown'))
            else:
                out.append(_check('smart-health', 'fail' if fails else 'warn' if problems else 'pass',
                                  'count', problems))

    if not nvme:
        out.append(_check('nvme-health', 'not_applicable'))
    else:
        states, wear = [], 0
        for name in nvme:
            doc = src.json_command('nvme-' + name, ['nvme', 'smart-log', '/dev/' + name, '-o', 'json'])
            state, used = _nvme_state(doc, kelvin=True)
            if state is None:
                doc = src.json_command('smartctl-' + name, ['smartctl', '-j', '-a', '/dev/' + name])
                state, used = _nvme_state(doc, kelvin=False)
            if state is not None:
                states.append(state)
                wear = max(wear, used)
        if not states:
            out.append(_check('nvme-health', 'unknown'))
        else:
            out.append(_check('nvme-health', 'fail' if 'fail' in states else 'warn' if 'warn' in states else 'pass',
                              'percent', wear))  # percent = highest wear (percentage used)
    return out


# ------------------------------------------------------------------- gpu / display

def _pci_devices(src, class_prefix):
    """(total, without_driver) for PCI devices whose class starts with class_prefix; None if no PCI sysfs."""
    names = src.listdir('sys/bus/pci/devices')
    if names is None:
        return None
    total = unbound = 0
    for name in names:
        cls = (src.read('sys/bus/pci/devices', name, 'class') or '').strip().lower()
        if cls.startswith(class_prefix):
            total += 1
            if not src.exists('sys/bus/pci/devices', name, 'driver'):
                unbound += 1
    return total, unbound


def check_gpu(src):
    pci = _pci_devices(src, '0x03')
    if pci is None:
        return _unknown('hw-gpu', 'hw-gpu-driver')
    total, unbound = pci
    if total == 0:
        return [_check('hw-gpu', 'not_applicable'), _check('hw-gpu-driver', 'not_applicable')]
    return [_check('hw-gpu', 'pass', 'count', total),
            _check('hw-gpu-driver', 'fail' if unbound else 'pass', 'count', unbound)]


def check_display(src):
    entries = src.listdir('sys/class/drm')
    if entries is None:
        return _unknown('hw-display')
    connectors = [e for e in entries if re.fullmatch(r'card[0-9]+-.+', e)]
    if not connectors:
        return _unknown('hw-display')
    connected = sum(1 for c in connectors if (src.read('sys/class/drm', c, 'status') or '').strip() == 'connected')
    return [_check('hw-display', 'pass' if connected else 'warn', 'count', connected)]


# --------------------------------------------------------------------- network

def check_network(src):
    names = src.listdir('sys/class/net')
    if names is None:
        return _unknown('hw-network-adapter', 'hw-wifi')
    adapters = [n for n in names if n != 'lo' and src.exists('sys/class/net', n, 'device')]
    wifi = [n for n in adapters if src.exists('sys/class/net', n, 'wireless') or src.exists('sys/class/net', n, 'phy80211')]
    pci = _pci_devices(src, '0x02')
    unbound = pci[1] if pci else 0
    if unbound:
        adapter = _check('hw-network-adapter', 'fail', 'count', unbound)   # count = adapters without a driver
    elif not adapters:
        adapter = _check('hw-network-adapter', 'fail', 'count', 0)
    else:
        carrier = any((src.read('sys/class/net', n, 'carrier') or '').strip() == '1' or
                      (src.read('sys/class/net', n, 'operstate') or '').strip() == 'up' for n in adapters)
        # An idle Wi-Fi adapter is normal (not associated yet); an unplugged wired-only machine is not.
        adapter = _check('hw-network-adapter', 'pass' if carrier or wifi else 'warn', 'count', len(adapters))
    if not wifi:
        wifi_check = _check('hw-wifi', 'not_applicable')
    else:
        blocked = 0
        for rf in src.listdir('sys/class/rfkill') or []:
            if (src.read('sys/class/rfkill', rf, 'type') or '').strip() == 'wlan' and (
                    (src.read('sys/class/rfkill', rf, 'hard') or '0').strip() == '1' or
                    (src.read('sys/class/rfkill', rf, 'soft') or '0').strip() == '1'):
                blocked += 1
        wifi_check = _check('hw-wifi', 'warn' if blocked else 'pass', 'count', blocked)  # count = blocked radios
    return [adapter, wifi_check]


# --------------------------------------------------------------------- battery

def check_battery(src):
    names = src.listdir('sys/class/power_supply')
    if names is None:
        return _unknown('hw-battery')
    batteries = [n for n in names if (src.read('sys/class/power_supply', n, 'type') or '').strip() == 'Battery'
                 and (src.read('sys/class/power_supply', n, 'scope') or '').strip() != 'Device']
    if not batteries:
        return [_check('hw-battery', 'not_applicable')]
    worst_status, charge = 'pass', 100
    for name in batteries:
        cap = src.number('sys/class/power_supply', name, 'capacity')
        state = (src.read('sys/class/power_supply', name, 'status') or '').strip()
        health = (src.read('sys/class/power_supply', name, 'health') or '').strip()
        full = src.number('sys/class/power_supply', name, 'energy_full') or src.number(
            'sys/class/power_supply', name, 'charge_full')
        design = src.number('sys/class/power_supply', name, 'energy_full_design') or src.number(
            'sys/class/power_supply', name, 'charge_full_design')
        wear = 100 * full // design if full and design else None
        status = 'pass'
        if health in ('Dead', 'Overheat', 'Over voltage', 'Cold') or (wear is not None and wear < BATTERY_HEALTH_FAIL):
            status = 'fail'
        elif (wear is not None and wear < BATTERY_HEALTH_WARN) or health in ('Unspecified failure', 'Warm'):
            status = 'warn'
        if cap is not None:
            charge = min(charge, cap)
            if state != 'Charging' and cap < BATTERY_CRITICAL_PERCENT:
                status = 'fail'
            elif state != 'Charging' and cap < BATTERY_LOW_PERCENT and status == 'pass':
                status = 'warn'
        if RANK[status] > RANK[worst_status]:
            worst_status = status
    return [_check('hw-battery', worst_status, 'percent', charge)]  # percent = charge of the emptiest battery


# ------------------------------------------------------------------------- usb

def check_usb(src):
    names = src.listdir('sys/bus/usb/devices')
    if names is None:
        return _unknown('hw-usb')
    devices = unconfigured = 0
    for name in names:
        if not re.fullmatch(r'[0-9]+-[0-9.]+', name):   # skip root hubs (usbN) and interfaces (N-N:1.0)
            continue
        if src.read('sys/bus/usb/devices', name, 'idVendor') is None:
            continue
        devices += 1
        if (src.read('sys/bus/usb/devices', name, 'bDeviceClass') or '').strip() != '09' and \
                not (src.read('sys/bus/usb/devices', name, 'bConfigurationValue') or '').strip():
            unconfigured += 1
    return [_check('hw-usb', 'warn' if unconfigured else 'pass', 'count', devices)]   # count = attached devices


# ------------------------------------------------------------------------ entry

def _fixture(ctx):
    root = getattr(ctx, 'fixture_root', None) or os.environ.get(FIXTURE_ENV)
    if not root:
        return None, False
    for candidate in (os.path.join(root, 'hardware'), root):
        if os.path.isdir(os.path.join(candidate, 'proc')) or os.path.isdir(os.path.join(candidate, 'sys')) \
                or os.path.isdir(os.path.join(candidate, 'cmd')):
            return candidate, True
    return None, True


def collect_system(ctx):
    if not sys_is_linux(ctx):
        return []
    fixture, fixture_mode = _fixture(ctx)
    if fixture_mode and fixture is None:
        return []          # fixture run without hardware fixtures: never read the live machine
    src = Source(fixture)
    out = []
    if ctx.wants('hardware', 'cpu'):
        out += check_cpu(src)
    if ctx.wants('hardware', 'memory'):
        out += check_memory(src)
    if ctx.wants('hardware', 'disk'):
        out += check_disk(src, ctx.mode)
    if ctx.wants('hardware', 'gpu'):
        out += check_gpu(src)
    if ctx.wants('hardware', 'display'):
        out += check_display(src)
    if ctx.wants('hardware', 'network'):
        out += check_network(src)
    if ctx.wants('hardware', 'battery'):
        out += check_battery(src)
    if ctx.wants('hardware', 'usb'):
        out += check_usb(src)
    return out


def sys_is_linux(ctx):
    return bool(getattr(ctx, 'fixture_root', None)) or bool(os.environ.get(FIXTURE_ENV)) or os.name == 'posix' \
        and os.path.isdir('/sys')


def collect_offline_target(ctx, root, target):
    return []   # hardware describes the machine, not an installed OS
