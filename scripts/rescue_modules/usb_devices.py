"""USB device inventory and Android connection-mode classification (read-only, sysfs only).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#48. Operator documentation: docs/android.md.

Sources: /sys/bus/usb/devices (device and interface attributes, the hub port's ACPI
``physical_location``), /proc/self/mountinfo, /sys/dev/block and /dev/disk/by-label (only to find
the USB device that holds the rescue medium). No command is ever run and nothing is written; a
missing file gives ``None`` or an absent key, never an exception.

Privacy: the returned dicts carry port paths, numbers, hex IDs, closed-set names and booleans
only. The USB serial number (the Android serial) and the manufacturer/product strings are NEVER
read into a returned dict; ``read_serial`` exists only so that the caller can hash it into an
opaque ID. Nothing here puts a string from a device into a result except through a closed set.

Test hooks: SYSFS_USB, SYS_ROOT, MOUNTINFO and BY_LABEL are module attributes that tests (and
``scripts/scan-android.py --fixture-root``) point at a fixture tree.
"""
import os
import re
from pathlib import Path

SYSFS_USB = Path('/sys/bus/usb/devices')
SYS_ROOT = Path('/sys')
MOUNTINFO = Path('/proc/self/mountinfo')
BY_LABEL = Path('/dev/disk/by-label')

PORT_RE = re.compile(r'^[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,6}$')
ROOT_HUB_RE = re.compile(r'^usb([0-9]{1,3})$')
HEX2_RE = re.compile(r'^[0-9a-f]{2}$')
HEX4_RE = re.compile(r'^[0-9a-f]{4}$')
VERSION_RE = re.compile(r'^[1-4]\.[0-9]{2}$')
MAX_ENTRIES = 512

LIVE_MOUNTPOINTS = ('/cdrom', '/run/live/medium', '/isodevice')
VENTOY_LABELS = ('ventoy', 'vtoyefi')

PANELS = frozenset({'top', 'bottom', 'left', 'right', 'front', 'back'})
HORIZONTAL = frozenset({'left', 'center', 'right'})
VERTICAL = frozenset({'upper', 'center', 'lower'})
CONNECT_TYPES = frozenset({'hotplug', 'hardwired', 'not used'})

# Vendor brand by USB vendor ID. Several brands share an ID (OPPO also covers Realme; Tecno,
# Infinix and itel mostly present Google or MediaTek IDs), so this is a hint, not an identity.
VENDOR_BRANDS = {
    '18d1': 'google', '04e8': 'samsung', '2717': 'xiaomi', '22d9': 'oppo', '2d95': 'vivo',
    '12d1': 'huawei', '22b8': 'motorola', '1004': 'lg', '0fce': 'sony', '2a70': 'oneplus',
    '05c6': 'qualcomm', '0e8d': 'mediatek', '17ef': 'lenovo', '0b05': 'asus', '19d2': 'zte',
    '0bb4': 'htc', '2e04': 'hmd-nokia', '0421': 'hmd-nokia', '1782': 'unisoc', '2a45': 'meizu',
}
BRANDS = tuple(sorted(set(VENDOR_BRANDS.values()))) + ('other',)

ANDROID_MODES = ('none', 'adb', 'fastboot', 'mtp-ptp', 'rndis', 'qualcomm-edl', 'mediatek-brom',
                 'samsung-download', 'spreadtrum-download')
# Most specific first: the first match is the primary mode.
MODE_PRIORITY = ('qualcomm-edl', 'mediatek-brom', 'samsung-download', 'spreadtrum-download',
                 'fastboot', 'adb', 'rndis', 'mtp-ptp')
LOW_LEVEL_MODES = frozenset({'qualcomm-edl', 'mediatek-brom', 'samsung-download', 'spreadtrum-download',
                             'fastboot'})
# Download/boot-ROM modes are recognised by vendor:product only (no strings are read).
SPECIAL_IDS = {
    ('05c6', '9008'): 'qualcomm-edl',
    ('0e8d', '2000'): 'mediatek-brom',      # preloader (also shown for a few seconds on every normal start)
    ('0e8d', '0003'): 'mediatek-brom',      # BROM
    ('04e8', '685d'): 'samsung-download',   # Odin / Download mode
    ('1782', '4d00'): 'spreadtrum-download',
}
ADB_TRIPLET = 'ff/42/01'
FASTBOOT_TRIPLET = 'ff/42/03'
MTP_PTP_TRIPLET = '06/01/01'
RNDIS_TRIPLETS = frozenset({'e0/01/03', 'ef/04/01'})

CLASS_NAMES = {
    '01': 'audio', '02': 'comm', '03': 'hid', '05': 'physical', '06': 'imaging', '07': 'printer',
    '08': 'mass-storage', '09': 'hub', '0a': 'cdc-data', '0b': 'smartcard', '0d': 'security',
    '0e': 'video', '0f': 'healthcare', '10': 'av', '11': 'billboard', 'dc': 'diagnostic',
    'e0': 'wireless', 'ef': 'misc', 'fe': 'app-specific', 'ff': 'vendor-specific',
}


# ------------------------------------------------------------------------- low-level reads

def _read(path, limit=256):
    """First *limit* bytes of a sysfs attribute as stripped text, or None."""
    try:
        with open(path, 'r', encoding='ascii', errors='replace') as handle:
            return handle.read(limit).strip()
    except OSError:
        return None


def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return None


def _hex(text, pattern):
    text = (text or '').strip().lower()
    return text if pattern.match(text) else None


def port_key(port):
    """Sort key for a validated port path: (bus, chain)."""
    bus, _, chain = port.partition('-')
    return int(bus), tuple(int(p) for p in chain.split('.'))


def valid_port(value):
    return isinstance(value, str) and bool(PORT_RE.match(value))


def hub_depth(port):
    """Number of hubs between the root hub and the device (0 = directly on a root-hub port)."""
    return port.partition('-')[2].count('.')


def brand_for(vendor_id):
    return VENDOR_BRANDS.get(vendor_id, 'other')


def _speed(text):
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    if not 0 < value <= 100000:
        return None
    return int(value) if value == int(value) else value


def _milliamps(text):
    m = re.match(r'^([0-9]{1,4})\s*mA$', (text or '').strip())
    return int(m.group(1)) if m else None


# ------------------------------------------------------------------------ boot media

def _usb_device_of(path):
    """Port path of the USB device whose interface the sysfs *path* hangs below, or None."""
    owner = None
    for part in str(path).split('/'):
        if PORT_RE.match(part):
            owner = part
    return owner


def _block_roots(sys_root, name, seen):
    """Real sysfs paths of a block device and (for dm/md stacks) everything below it, depth-limited."""
    out = []
    node = Path(sys_root) / 'class' / 'block' / name
    try:
        real = os.path.realpath(node)
    except OSError:
        return out
    out.append(real)
    if len(seen) > 16:
        return out
    slaves = _listdir(os.path.join(real, 'slaves')) or []
    for slave in slaves[:8]:
        if slave not in seen:
            seen.add(slave)
            out.extend(_block_roots(sys_root, slave, seen))
    return out


def _mount_devices(mountinfo, sys_root):
    """Real sysfs paths of the block devices mounted at the live-medium mount points."""
    text = _read(mountinfo, 1 << 20)
    if not text:
        return []
    out = []
    for line in text.splitlines():
        fields = line.split(' ')
        if len(fields) < 6 or fields[4].replace('\\040', ' ') not in LIVE_MOUNTPOINTS:
            continue
        majmin = fields[2]
        if not re.match(r'^[0-9]{1,5}:[0-9]{1,7}$', majmin):
            continue
        node = Path(sys_root) / 'dev' / 'block' / majmin
        try:
            real = os.path.realpath(node)
        except OSError:
            continue
        out.append(real)
        # device-mapper (Ventoy maps the ISO through dm-linear): follow the slaves
        name = os.path.basename(real)
        for slave in _listdir(os.path.join(real, 'slaves')) or []:
            out.extend(_block_roots(sys_root, slave, {name, slave}))
    return out


def _label_devices(by_label, sys_root):
    """Real sysfs paths of the partitions labelled Ventoy / VTOYEFI."""
    out = []
    for label in _listdir(by_label) or []:
        if label.lower() not in VENTOY_LABELS:
            continue
        try:
            target = os.path.realpath(Path(by_label) / label)
        except OSError:
            continue
        out.extend(_block_roots(sys_root, os.path.basename(target), {os.path.basename(target)}))
    return out


def boot_media_ports(mountinfo=None, sys_root=None, by_label=None):
    """Port paths of the USB devices that hold the rescue live medium (empty set when unknown).

    The medium is the device mounted at /cdrom, /run/live/medium or /isodevice (device-mapper
    stacks are followed to the disks below them) plus any Ventoy-labelled partition. Read-only."""
    sys_root = sys_root or SYS_ROOT
    paths = _mount_devices(mountinfo or MOUNTINFO, sys_root) + _label_devices(by_label or BY_LABEL, sys_root)
    ports = set()
    for path in paths:
        port = _usb_device_of(path)
        if port:
            ports.add(port)
    return ports


# ------------------------------------------------------------------------- classification

def classify_android(dev):
    """Android connection mode of one device dict from ``list_usb_devices``.

    Uses only the vendor:product pair and the interface class/subclass/protocol triplets (no
    strings). Returns ``{'mode', 'modes', 'is_android'}``: ``modes`` is every Android mode seen
    (most specific first), ``mode`` the primary one (``none`` when the device is not an Android
    candidate). Honest limits: a class 06 imaging interface is MTP *or* PTP (reported as
    ``mtp-ptp``) and only counts as Android when the vendor is a known phone/SoC brand; RNDIS
    alone never makes a device Android (LTE dongles use it); recovery and sideload ADB look
    like normal ADB; a charge-only phone shows no data interface at all and is invisible."""
    triplets = set(dev.get('interfaces') or ())
    if dev.get('device_triplet'):
        triplets.add(dev['device_triplet'])
    modes = set()
    special = SPECIAL_IDS.get((dev.get('vendor_id'), dev.get('product_id')))
    if special:
        modes.add(special)
    if ADB_TRIPLET in triplets:
        modes.add('adb')
    if FASTBOOT_TRIPLET in triplets:
        modes.add('fastboot')
    if MTP_PTP_TRIPLET in triplets:
        modes.add('mtp-ptp')
    if triplets & RNDIS_TRIPLETS:
        modes.add('rndis')
    known_brand = brand_for(dev.get('vendor_id')) != 'other'
    if not (modes & (set(LOW_LEVEL_MODES) | {'adb'})) and not ('mtp-ptp' in modes and known_brand):
        return {'mode': 'none', 'modes': (), 'is_android': False}
    ordered = tuple(m for m in MODE_PRIORITY if m in modes)
    return {'mode': ordered[0], 'modes': ordered, 'is_android': True}


# ------------------------------------------------------------------------------ enumeration

def _interfaces(device_dir, name):
    triplets, classes = [], []
    for entry in _listdir(device_dir) or []:
        if not entry.startswith(name + ':'):
            continue
        base = os.path.join(device_dir, entry)
        cls = _hex(_read(os.path.join(base, 'bInterfaceClass')), HEX2_RE)
        sub = _hex(_read(os.path.join(base, 'bInterfaceSubClass')), HEX2_RE)
        proto = _hex(_read(os.path.join(base, 'bInterfaceProtocol')), HEX2_RE)
        if cls is None:
            continue
        classes.append(cls)
        if sub is not None and proto is not None:
            triplets.append('%s/%s/%s' % (cls, sub, proto))
    return triplets[:32], classes[:32]


def _location(device_dir):
    base = os.path.join(device_dir, 'port')
    out = {}
    for key, allowed in (('panel', PANELS), ('horizontal_position', HORIZONTAL),
                         ('vertical_position', VERTICAL)):
        value = _read(os.path.join(base, 'physical_location', key))
        out[key] = value if value in allowed else None
    connect = _read(os.path.join(base, 'connect_type'))
    out['connect_type'] = connect if connect in CONNECT_TYPES else None
    return out


def _class_summary(device_class, interface_classes):
    names = []
    for code in ([device_class] if device_class not in (None, '00', 'ef') else []) + list(interface_classes):
        name = CLASS_NAMES.get(code, 'other')
        if name not in names:
            names.append(name)
    return names


def list_usb_devices(sysfs=None, boot_ports=None):
    """All USB devices below *sysfs* (default SYSFS_USB), sorted by bus and port, or None when
    the USB sysfs is unreadable. Root hubs (``usbN``) and interface entries (``N-N:C.I``) are not
    returned; a root hub only provides ``bus_speed_mbps`` for the devices on its bus.

    Each dict: port, bus, hub_depth, speed_mbps, bus_speed_mbps, usb_version, device_class,
    device_triplet, interfaces (class/subclass/protocol triplets), class_summary, vendor_id,
    product_id, brand, is_hub, panel, horizontal_position, vertical_position, connect_type,
    max_power_ma, is_boot_media, android_mode, android_modes, is_android. Never a serial or a
    descriptor string."""
    base = Path(sysfs or SYSFS_USB)
    names = _listdir(base)
    if names is None:
        return None
    boot = boot_media_ports() if boot_ports is None else set(boot_ports)
    bus_speed = {}
    for name in names:
        m = ROOT_HUB_RE.match(name)
        if m:
            bus_speed[int(m.group(1))] = _speed(_read(base / name / 'speed'))
    devices = []
    for name in names[:MAX_ENTRIES]:
        if not PORT_RE.match(name):
            continue
        folder = os.path.join(base, name)
        vendor = _hex(_read(os.path.join(folder, 'idVendor')), HEX4_RE)
        product = _hex(_read(os.path.join(folder, 'idProduct')), HEX4_RE)
        if vendor is None or product is None:
            continue
        bus, _chain = port_key(name)
        device_class = _hex(_read(os.path.join(folder, 'bDeviceClass')), HEX2_RE)
        sub = _hex(_read(os.path.join(folder, 'bDeviceSubClass')), HEX2_RE)
        proto = _hex(_read(os.path.join(folder, 'bDeviceProtocol')), HEX2_RE)
        triplets, classes = _interfaces(folder, name)
        version = (_read(os.path.join(folder, 'version')) or '').strip()
        dev = {
            'port': name, 'bus': bus, 'hub_depth': hub_depth(name),
            'speed_mbps': _speed(_read(os.path.join(folder, 'speed'))),
            'bus_speed_mbps': bus_speed.get(bus),
            'usb_version': version if VERSION_RE.match(version) else None,
            'device_class': device_class,
            'device_triplet': '%s/%s/%s' % (device_class, sub, proto) if device_class and sub and proto else None,
            'interfaces': triplets, 'class_summary': _class_summary(device_class, classes),
            'vendor_id': vendor, 'product_id': product, 'brand': brand_for(vendor),
            'is_hub': device_class == '09' or '09' in classes,
            'max_power_ma': _milliamps(_read(os.path.join(folder, 'bMaxPower'))),
            'is_boot_media': name in boot,
        }
        dev.update(_location(folder))
        verdict = classify_android(dev)
        dev['android_mode'] = verdict['mode']
        dev['android_modes'] = list(verdict['modes'])
        dev['is_android'] = verdict['is_android']
        devices.append(dev)
    devices.sort(key=lambda d: port_key(d['port']))
    return devices


def read_serial(port, sysfs=None):
    """USB serial string of the device at *port* (the Android serial), or None.

    Only for hashing into an opaque ID by the caller. Never store, print or log the result."""
    if not valid_port(port):
        return None
    value = _read(os.path.join(Path(sysfs or SYSFS_USB), port, 'serial'), 128)
    return value or None
