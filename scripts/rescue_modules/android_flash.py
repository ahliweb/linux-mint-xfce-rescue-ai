"""Read-only detection for a phone in fastboot, Samsung download, EDL or BROM mode (flashing support).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#52. Operator documentation: docs/android.md. The repair
actions that use this information live in rescue-ai/v1/catalog/android.json and are executed only by
scripts/rescue-repair.py; nothing here writes to a phone.

The only commands are the FIXED argv tuples below, each with a timeout and a size cap, ``stdin`` from
/dev/null and no shell:

  * ``fastboot devices -l``           which USB ports hold a fastboot device (the ``usb:`` field), and
                                      whether this user may talk to it
  * ``fastboot -s usb:<port> getvar`` for ``unlocked``, ``current-slot``, ``slot-count``, ``is-userspace``
  * ``heimdall detect``               only when exactly one Samsung download-mode device is on USB

``fastboot -s`` accepts the device's USB path as well as its serial (AOSP ``fastboot.cpp``:
``match_fastboot_with_serial`` compares the argument with the serial number or the ``usb:<sysfs name>``
device path), so no serial ever appears in an argv. Everything a phone prints is untrusted data, parsed
for a closed set of values and dropped: the ``product`` variable (a device model name) is never read here
and none of the values is kept except as a status and a small bounded number. EDL (Qualcomm 9008) and
MediaTek BROM/preloader get guidance only: no tool of this repository talks to them.
"""
import re
import shutil

from . import android, usb_devices

FASTBOOT_TIMEOUT = 20
GETVARS = ('unlocked', 'current-slot', 'slot-count', 'is-userspace')
CHECK_IDS = ('android-fastboot-lock-state', 'android-fastboot-slot', 'android-fastboot-userspace',
             'android-heimdall-detect', 'android-low-level-mode')
GUIDANCE_ONLY_MODES = frozenset({'qualcomm-edl', 'mediatek-brom', 'spreadtrum-download'})


def find_tool(name):
    """Path of ``fastboot`` or ``heimdall`` (same search path as adb, so tests can shim both), or None."""
    return shutil.which(name, path=android.ADB_SEARCH_PATH)


class Fastboot:
    """The only way this module talks to fastboot: fixed argv, a validated usb: selector, bounded output."""

    def __init__(self, program, search_path=None, timeout=FASTBOOT_TIMEOUT):
        self.program = program
        self.env = {'PATH': search_path or android.ADB_SEARCH_PATH, 'LC_ALL': 'C'}
        self.timeout = timeout

    def devices(self):
        return android._bounded([self.program, 'devices', '-l'], self.timeout, self.env, merge_stderr=True)

    def getvar(self, port, name):
        """Combined output of ``fastboot -s usb:<port> getvar <name>`` or None (fastboot prints it on stderr)."""
        if not usb_devices.valid_port(port) or name not in GETVARS + ('product',):
            return None
        res = android._bounded([self.program, '-s', 'usb:' + port, 'getvar', name], self.timeout, self.env,
                               merge_stderr=True)
        return None if res is None or res[0] != 0 else res[1]


# ------------------------------------------------------------------------------------ parsing

def parse_devices(text):
    """``{'ports': set of USB port paths, 'denied': set of ports this user may not use}`` from ``devices -l``."""
    ports, denied = set(), set()
    for line in (text or '').splitlines():
        m = re.search(r'\busb:(\S+)\s*$', line)
        if not m or not usb_devices.valid_port(m.group(1)):
            continue
        ports.add(m.group(1))
        if line.lstrip().lower().startswith('no permissions'):
            denied.add(m.group(1))
    return {'ports': ports, 'denied': denied}


def parse_getvar(text, name):
    """The value of ``name`` from fastboot's ``name: value`` line, restricted to the closed sets, or None."""
    for line in (text or '').splitlines():
        m = re.match(r'^%s: ?(.{0,32})$' % re.escape(name), line.strip())
        if not m:
            continue
        value = m.group(1).strip().lower()
        if name in ('unlocked', 'is-userspace'):
            return value if value in ('yes', 'no') else None
        if name == 'current-slot':
            return value if value in ('a', 'b') else None
        if name == 'slot-count':
            return int(value) if re.match(r'^[0-9]{1,2}$', value) else None
    return None


# --------------------------------------------------------------------------------- the checks

def _c(check_id, status, kind=None, number=None):
    return android._c(check_id, status, kind, number)


def lock_state_check(value):
    """locked pass, unlocked warn (flashing is possible), unknown otherwise (docs/android.md)."""
    return _c('android-fastboot-lock-state', {'no': 'pass', 'yes': 'warn'}.get(value, 'unknown'))


def slot_check(current, count):
    if count is not None and count >= 2 and current in ('a', 'b'):
        return _c('android-fastboot-slot', 'pass', 'count', count)
    if count is not None and count < 2:
        return _c('android-fastboot-slot', 'not_applicable')       # not an A/B device: no slot to switch
    return _c('android-fastboot-slot', 'unknown')


def userspace_check(value):
    """The bootloader's fastboot is pass; fastbootd (userspace fastboot) is warn."""
    return _c('android-fastboot-userspace', {'no': 'pass', 'yes': 'warn'}.get(value, 'unknown'))


def fastboot_checks(fb, target, listing):
    """The three fastboot checks for one target; unknown without fastboot, permission, or a listing for its port."""
    port = target.get('port')
    usable = fb is not None and listing is not None and port in listing['ports'] and port not in listing['denied']
    values = {name: parse_getvar(fb.getvar(port, name), name) if usable else None for name in GETVARS}
    return [lock_state_check(values['unlocked']), slot_check(values['current-slot'], values['slot-count']),
            userspace_check(values['is-userspace'])]


def heimdall_check(heimdall, usb_list):
    """``heimdall detect`` is run only when exactly one Samsung download-mode device is attached (Heimdall
    addresses the one device it finds): pass when it sees it, warn when it does not, unknown otherwise."""
    if heimdall is None:
        return _c('android-heimdall-detect', 'unknown')
    download = [d for d in usb_list or [] if 'samsung-download' in d.get('android_modes', ())]
    if len(download) != 1:
        return _c('android-heimdall-detect', 'unknown')
    res = android._bounded([heimdall, 'detect'], FASTBOOT_TIMEOUT, {'PATH': android.ADB_SEARCH_PATH, 'LC_ALL': 'C'},
                           merge_stderr=True)
    if res is None:
        return _c('android-heimdall-detect', 'unknown')
    return _c('android-heimdall-detect', 'pass' if res[0] == 0 else 'warn')


def low_level_check():
    """EDL / BROM / Unisoc download: always warn. No tool here talks to them; see docs/android.md."""
    return _c('android-low-level-mode', 'warn')


def mode_checks(target, usb_list, fb, listing, heimdall):
    """Extra checks for one target dict, by connection mode (none for a running Android)."""
    modes = set(target.get('modes') or []) | {target.get('mode')}
    out = []
    if 'fastboot' in modes:
        out += fastboot_checks(fb, target, listing)
    if 'samsung-download' in modes:
        out.append(heimdall_check(heimdall, usb_list))
    if modes & GUIDANCE_ONLY_MODES:
        out.append(low_level_check())
    return out
