"""Helpers shared by the device scanners that write their own evidence (scripts/scan-printers.py).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

The same functions exist inline in scripts/scan-android.py (they predate this module); a later change can
make that scanner import them. Behavior is identical: 0600 atomic writes, validation with the same schema
and semantic rules as scripts/validate-evidence.py before anything is written, no strings from devices.
"""
import hashlib
import importlib.util
import json
import os
import platform
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]

PANEL_ID = {'left': 'kiri', 'right': 'kanan', 'top': 'atas', 'bottom': 'bawah', 'front': 'depan', 'back': 'belakang'}
HORIZONTAL_ID = {'left': 'kiri', 'center': 'tengah', 'right': 'kanan'}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def live_release():
    try:
        with open('/etc/os-release', encoding='utf-8') as handle:
            for line in handle:
                if line.startswith('PRETTY_NAME='):
                    text = line.split('=', 1)[1].strip().strip('"\'')
                    cleaned = re.sub(r'[^A-Za-z0-9 ._+()/-]', '', text).strip()[:48].rstrip()
                    return cleaned if re.match(r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$', cleaned) else None
    except OSError:
        pass
    return None


def boot_mode():
    if os.path.exists('/sys/firmware/efi'):
        return 'uefi'
    return 'legacy-bios' if platform.machine().lower() in ('x86_64', 'amd64', 'i386', 'i686') else 'unknown'


def write_atomic(report, out):
    directory = os.path.dirname(os.path.abspath(out))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=directory)
    try:
        # mkstemp already creates the file 0600; FAT/exFAT state partitions may reject chmod/chown.
        try:
            os.fchmod(fd, 0o600)
            sudo_uid, sudo_gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
            if os.geteuid() == 0 and sudo_uid.isdigit() and sudo_gid.isdigit():
                os.fchown(fd, int(sudo_uid), int(sudo_gid))
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def validation_problems(report):
    """Schema and semantic problems of *report* (same logic as validate-evidence.py), [] when valid."""
    path = SCRIPTS / 'validate-evidence.py'
    spec = importlib.util.spec_from_file_location('rescue_validate_evidence', path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        return ['python3-jsonschema is not installed; refusing to write unvalidated evidence']
    schema = json.loads(module.SCHEMA_PATH.read_text(encoding='utf-8'))
    validator = module.jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(report), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        return ['%s at %s' % (e.message[:200], module.format_path(e)) for e in errors[:5]]
    return module.semantic_errors(report)


def usb_ports_entries(usb_list):
    """The ``usb_ports`` evidence inventory (closed-set fields only) from ``usb_devices.list_usb_devices``."""
    out = []
    for dev in usb_list[:64]:
        item = {'port': dev['port'], 'is_hub': dev['is_hub'], 'is_boot_media': dev['is_boot_media'],
                'android_mode': dev['android_mode'], 'vendor_brand': dev['brand'], 'hub_depth': dev['hub_depth']}
        if dev['speed_mbps'] is not None:
            item['speed_mbps'] = dev['speed_mbps']
        if dev['usb_version']:
            item['usb_version'] = dev['usb_version']
        if dev['android_modes']:
            item['android_modes'] = list(dev['android_modes'])
        for key in ('panel', 'horizontal_position'):
            if dev.get(key):
                item[key] = dev[key]
        out.append(item)
    return out


def panel_text(dev):
    """(id, en) location of a device's port from the ACPI physical location, or None."""
    if dev.get('panel'):
        text_id, text_en = 'panel %s' % PANEL_ID[dev['panel']], '%s panel' % dev['panel']
        if dev.get('horizontal_position') and dev['horizontal_position'] != 'center':
            text_id += ', sisi %s' % HORIZONTAL_ID[dev['horizontal_position']]
            text_en += ', %s side' % dev['horizontal_position']
        return text_id, text_en
    if dev.get('horizontal_position'):
        return 'sisi %s' % HORIZONTAL_ID[dev['horizontal_position']], '%s side' % dev['horizontal_position']
    return None


def location_cell(dev):
    if dev.get('connect_type') == 'hardwired':
        return 'internal'
    parts = []
    if dev.get('panel'):
        parts.append('%s/%s' % (dev['panel'], PANEL_ID[dev['panel']]))
    if dev.get('horizontal_position'):
        parts.append(dev['horizontal_position'])
    return ' '.join(parts) or '-'
