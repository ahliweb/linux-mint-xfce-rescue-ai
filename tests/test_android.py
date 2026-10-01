#!/usr/bin/env python3
"""Offline tests for USB inventory, Android detection and scan-android.py (ahliweb/linux-mint-xfce-rescue-ai#48).

A fake sysfs/proc tree stands in for /sys and /proc, and a fake ``adb`` (a Python script found
through a PATH shim directory) returns canned output for each fixed argv and logs every call. Nothing
touches a real USB device, a real phone or the network. Dummy values only.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
from rescue_modules import android, usb_devices  # noqa: E402

SCAN = SCRIPTS / 'scan-android.py'
VALIDATE = SCRIPTS / 'validate-evidence.py'
FIXTURES = ROOT / 'rescue-ai/v1/fixtures'
HAVE_JSONSCHEMA = importlib.util.find_spec('jsonschema') is not None

SERIAL_A = 'SERIALA0123456789'          # dummy phone serials: must never appear in any output
SERIAL_B = 'SERIALB9876543210'
LEAKS = (SERIAL_A, SERIAL_B, 'com.secret.sideload', 'com.secret.bank', 'Galaxy Secret Model', 'Secret Maker',
         'com.secret.accessibility', 'com.secret.admin', 'user@secret.example')


def put(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class FakeMachine:
    """A fake /sys + /proc + /dev/disk tree (the --fixture-root layout) with USB devices below pci0."""

    def __init__(self, tmp):
        self.root = Path(tmp) / 'fx'
        self.devices = self.root / 'sys/devices/pci0000:00/0000:00:14.0'
        self.bus = self.root / 'sys/bus/usb/devices'
        self.bus.mkdir(parents=True)
        self.mounts = []
        self.add_root_hub(1, 480)
        self.add_root_hub(3, 480)

    def _link(self, name, target):
        link = self.bus / name
        if link.is_symlink():
            link.unlink()
        os.symlink(target, link)

    def add_root_hub(self, bus, speed):
        folder = self.devices / ('usb%d' % bus)
        put(folder / 'speed', '%s\n' % speed)
        put(folder / 'bDeviceClass', '09\n')
        self._link('usb%d' % bus, folder)

    def add_device(self, port, vid, pid, interfaces, speed=480, version=' 2.00', device_class='00', serial=None,
                   panel=None, horizontal=None, connect_type=None, power='500mA', strings=True):
        """interfaces: list of 'cc/ss/pp' triplets. Hubs below hubs: the folder nests under the parent port."""
        bus, _, chain = port.partition('-')
        parts = chain.split('.')
        folder = self.devices / ('usb%s' % bus)
        for i in range(len(parts) - 1):
            folder = folder / ('%s-%s' % (bus, '.'.join(parts[:i + 1])))
        folder = folder / port
        put(folder / 'idVendor', vid + '\n')
        put(folder / 'idProduct', pid + '\n')
        put(folder / 'bDeviceClass', device_class + '\n')
        put(folder / 'bDeviceSubClass', '00\n')
        put(folder / 'bDeviceProtocol', '00\n')
        put(folder / 'speed', '%s\n' % speed)
        put(folder / 'version', '%s\n' % version)
        put(folder / 'bMaxPower', '%s\n' % power)
        if serial:
            put(folder / 'serial', serial + '\n')
        if strings:
            put(folder / 'manufacturer', 'Secret Maker\n')
            put(folder / 'product', 'Galaxy Secret Model\n')
        for i, triplet in enumerate(interfaces):
            cls, sub, proto = triplet.split('/')
            iface = folder / ('%s:1.%d' % (port, i))
            put(iface / 'bInterfaceClass', cls + '\n')
            put(iface / 'bInterfaceSubClass', sub + '\n')
            put(iface / 'bInterfaceProtocol', proto + '\n')
        if panel or horizontal or connect_type:
            put(folder / 'port/physical_location/panel', (panel or 'unknown') + '\n')
            put(folder / 'port/physical_location/horizontal_position', (horizontal or 'unknown') + '\n')
            put(folder / 'port/physical_location/vertical_position', 'unknown\n')
            put(folder / 'port/connect_type', (connect_type or 'unknown') + '\n')
        self._link(port, folder)
        return folder

    def add_storage_block(self, port, name='sdb', mountpoint='/cdrom', majmin='8:17', via_dm=False, label=None):
        """A partition below the USB device *port*, mounted at *mountpoint* (mountinfo) and/or labelled."""
        bus, _, chain = port.partition('-')
        parts = chain.split('.')
        folder = self.devices / ('usb%s' % bus)
        for i in range(len(parts)):
            folder = folder / ('%s-%s' % (bus, '.'.join(parts[:i + 1])))
        part = folder / ('%s:1.0' % port) / 'host4/target4:0:0/4:0:0:0/block' / name / (name + '1')
        part.mkdir(parents=True)
        (self.root / 'sys/class/block').mkdir(parents=True, exist_ok=True)
        os.symlink(part, self.root / 'sys/class/block' / (name + '1'))
        (self.root / 'sys/dev/block').mkdir(parents=True, exist_ok=True)
        if via_dm:
            dm = self.root / 'sys/devices/virtual/block/dm-0'
            (dm / 'slaves').mkdir(parents=True)
            os.symlink(part, dm / 'slaves' / (name + '1'))
            os.symlink(dm, self.root / 'sys/dev/block/253:0')
            majmin = '253:0'
        else:
            os.symlink(part, self.root / 'sys/dev/block' / majmin)
        if mountpoint:
            self.mounts.append('40 28 %s / %s ro - iso9660 /dev/%s1 ro' % (majmin, mountpoint, name))
            put(self.root / 'proc/self/mountinfo', '\n'.join(self.mounts) + '\n')
        if label:
            (self.root / 'dev/disk/by-label').mkdir(parents=True, exist_ok=True)
            os.symlink(part, self.root / 'dev/disk/by-label' / label)

    def hook(self):
        usb_devices.SYSFS_USB = self.bus
        usb_devices.SYS_ROOT = self.root / 'sys'
        usb_devices.MOUNTINFO = self.root / 'proc/self/mountinfo'
        usb_devices.BY_LABEL = self.root / 'dev/disk/by-label'


def standard_machine(tmp, via_dm=False):
    """Rescue USB, a hub with a phone (ADB + MTP, left panel), a fastboot phone, a Qualcomm EDL device,
    a keyboard, and a camera that also speaks PTP (must not be mistaken for a phone)."""
    m = FakeMachine(tmp)
    m.add_device('1-6', '0781', '5567', ['08/06/50'], speed=480, serial='RESCUESERIAL1')
    m.add_storage_block('1-6', via_dm=via_dm)
    m.add_device('3-2', '05e3', '0610', ['09/00/01'], device_class='09', speed=480)
    m.add_device('3-2.1', '04e8', '6860', ['06/01/01', 'ff/42/01'], speed=480, serial=SERIAL_A,
                 panel='left', horizontal='left', connect_type='hotplug')
    m.add_device('1-3', '18d1', '4ee0', ['ff/42/03'], speed=12, serial=SERIAL_B)
    m.add_device('1-4', '05c6', '9008', ['ff/ff/ff'])
    m.add_device('1-5', '046d', 'c31c', ['03/01/01'], speed=12, version='1.10')
    m.add_device('1-7', '054c', '0aa6', ['06/01/01'])
    m.hook()
    return m


def make_adb(directory, devices_text, canned, log_path):
    """Install a fake ``adb`` Python script in *directory*. canned: {transport_id: {'shell ...': text}}."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / 'adb'
    script.write_text('''#!%(python)s
import json, sys
DEVICES = %(devices)r
CANNED = json.loads(%(canned)r)
LOG = %(log)r
argv = sys.argv[1:]
with open(LOG, 'a') as handle:
    handle.write(json.dumps(argv) + '\\n')
if argv == ['devices', '-l']:
    sys.stdout.write(DEVICES)
elif argv == ['kill-server']:
    pass
elif len(argv) >= 3 and argv[0] == '-t' and argv[2] == 'shell':
    out = CANNED.get(argv[1], {}).get(' '.join(argv[2:]))
    if out is None:
        sys.exit(1)
    sys.stdout.write(out)
else:
    sys.exit(2)
''' % {'python': sys.executable, 'devices': devices_text,
       'canned': json.dumps({str(k): v for k, v in canned.items()}), 'log': str(log_path)})
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def patch_date(days_ago, today=None):
    return ((today or date.today()) - timedelta(days=days_ago)).isoformat()


def good_phone_outputs(patch_days=30, sdk=34, today=None, **over):
    props = '\n'.join([
        '[ro.build.version.sdk]: [%d]' % sdk, '[ro.build.version.release]: [14]',
        '[ro.build.version.security_patch]: [%s]' % patch_date(patch_days, today),
        '[ro.boot.verifiedbootstate]: [green]', '[ro.boot.flash.locked]: [1]', '[ro.debuggable]: [0]',
        '[ro.product.cpu.abi]: [arm64-v8a]', '[ro.serialno]: [%s]' % SERIAL_A,
        '[ro.product.model]: [Galaxy Secret Model]', '[persist.sys.timezone]: [Asia/Jakarta]']) + '\n'
    out = {
        'shell getprop': props,
        'shell getenforce': 'Enforcing\n',
        'shell df /data': 'Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/dm-9 100000000 60000000 40000000  60% /data\n',
        'shell dumpsys battery': 'Current Battery Service state:\n  AC powered: false\n  USB powered: true\n  status: 2\n'
                                 '  health: 2\n  present: true\n  level: 85\n  scale: 100\n  temperature: 312\n',
        'shell which su': '',
        'shell ls -d ' + ' '.join(android.SU_PATHS): '',
        'shell dumpsys device_policy': 'Enabled Device Admins (User 0, provisioningState: 0):\n'
                                       '  com.secret.admin/.Receiver:\n    uid=10100\n',
        'shell settings get secure enabled_accessibility_services': 'null\n',
        'shell pm list packages -3 -i': 'package:com.secret.bank  installer=com.android.vending\n'
                                        'package:com.secret.sideload  installer=null\n',
        'shell settings get global package_verifier_user_consent': '1\n',
        'shell settings get global package_verifier_enable': '1\n',
        'shell settings get global development_settings_enabled': '1\n',
    }
    out.update(over)
    return out


DEVICES_AUTHORIZED = ('List of devices attached\n'
                      '%s       device usb:3-2.1 product:secretprod model:Galaxy_Secret_Model device:secretdev transport_id:1\n'
                      % SERIAL_A)


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='android-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.saved = (usb_devices.SYSFS_USB, usb_devices.SYS_ROOT, usb_devices.MOUNTINFO, usb_devices.BY_LABEL,
                      android.ADB_SEARCH_PATH)
        self.addCleanup(self.restore)

    def restore(self):
        (usb_devices.SYSFS_USB, usb_devices.SYS_ROOT, usb_devices.MOUNTINFO, usb_devices.BY_LABEL,
         android.ADB_SEARCH_PATH) = self.saved

    def install_adb(self, devices_text=DEVICES_AUTHORIZED, canned=None):
        self.adb_log = self.tmp / 'adb.log'
        self.adb_dir = self.tmp / 'bin'
        make_adb(self.adb_dir, devices_text, canned if canned is not None else {1: good_phone_outputs()}, self.adb_log)
        android.ADB_SEARCH_PATH = str(self.adb_dir)

    def adb_calls(self):
        if not self.adb_log.exists():
            return []
        return [json.loads(line) for line in self.adb_log.read_text().splitlines()]

    def run_scan(self, *args, machine=None, with_adb=True):
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.tmp), 'LC_ALL': 'C'}
        argv = [sys.executable, str(SCAN), '--fixture-root', str((machine or self.machine).root)]
        if with_adb:
            argv += ['--adb-path', str(self.adb_dir)]
        else:
            argv += ['--adb-path', str(self.tmp / 'no-adb-here')]
        return subprocess.run(argv + list(args), capture_output=True, text=True, env=env, timeout=120)


# --------------------------------------------------------------------------------- USB inventory

class UsbInventoryTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)

    def devices(self):
        return {d['port']: d for d in usb_devices.list_usb_devices()}

    def test_every_device_is_listed_without_root_hubs_or_interfaces(self):
        devs = usb_devices.list_usb_devices()
        self.assertEqual([d['port'] for d in devs], ['1-3', '1-4', '1-5', '1-6', '1-7', '3-2', '3-2.1'])
        for dev in devs:
            self.assertTrue(usb_devices.PORT_RE.match(dev['port']))

    def test_port_speed_version_depth_and_bus(self):
        phone = self.devices()['3-2.1']
        self.assertEqual((phone['bus'], phone['hub_depth'], phone['speed_mbps'], phone['usb_version']),
                         (3, 1, 480, '2.00'))
        self.assertEqual(phone['bus_speed_mbps'], 480)
        self.assertEqual(self.devices()['1-5']['speed_mbps'], 12)
        self.assertEqual(self.devices()['1-5']['usb_version'], '1.10')
        self.assertEqual(self.devices()['3-2']['hub_depth'], 0)
        self.assertEqual(self.devices()['3-2.1']['max_power_ma'], 500)

    def test_physical_location_and_hub_flag(self):
        phone = self.devices()['3-2.1']
        self.assertEqual((phone['panel'], phone['horizontal_position'], phone['connect_type']),
                         ('left', 'left', 'hotplug'))
        self.assertIsNone(phone['vertical_position'])          # "unknown" is dropped
        self.assertIsNone(self.devices()['1-5']['panel'])
        self.assertTrue(self.devices()['3-2']['is_hub'])
        self.assertFalse(self.devices()['3-2.1']['is_hub'])

    def test_classes_and_interface_triplets(self):
        phone = self.devices()['3-2.1']
        self.assertEqual(phone['interfaces'], ['06/01/01', 'ff/42/01'])
        self.assertEqual(phone['class_summary'], ['imaging', 'vendor-specific'])
        self.assertEqual(self.devices()['1-6']['class_summary'], ['mass-storage'])
        self.assertEqual(self.devices()['1-5']['class_summary'], ['hid'])

    def test_vendor_brands(self):
        brands = {p: d['brand'] for p, d in self.devices().items()}
        self.assertEqual(brands['3-2.1'], 'samsung')
        self.assertEqual(brands['1-3'], 'google')
        self.assertEqual(brands['1-4'], 'qualcomm')
        self.assertEqual(brands['1-5'], 'other')
        self.assertEqual(usb_devices.brand_for('2717'), 'xiaomi')
        self.assertEqual(usb_devices.brand_for('22d9'), 'oppo')
        self.assertEqual(usb_devices.brand_for('ffff'), 'other')

    def test_android_modes(self):
        devs = self.devices()
        self.assertEqual((devs['3-2.1']['android_mode'], devs['3-2.1']['android_modes']), ('adb', ['adb', 'mtp-ptp']))
        self.assertEqual(devs['1-3']['android_mode'], 'fastboot')
        self.assertEqual(devs['1-4']['android_mode'], 'qualcomm-edl')
        self.assertEqual(devs['1-5']['android_mode'], 'none')
        self.assertEqual(devs['1-6']['android_mode'], 'none')
        self.assertFalse(devs['1-7']['is_android'], 'a PTP camera from an unknown vendor is not a phone')
        self.assertEqual({p for p, d in devs.items() if d['is_android']}, {'3-2.1', '1-3', '1-4'})

    def test_classify_android_cases(self):
        def mode(vid, pid, *triplets):
            return usb_devices.classify_android({'vendor_id': vid, 'product_id': pid, 'interfaces': list(triplets)})
        self.assertEqual(mode('18d1', '4ee7', 'ff/42/01')['mode'], 'adb')
        self.assertEqual(mode('18d1', '4ee0', 'ff/42/03')['mode'], 'fastboot')
        self.assertEqual(mode('2717', '2008', '06/01/01')['mode'], 'mtp-ptp')
        self.assertEqual(mode('054c', '0001', '06/01/01')['mode'], 'none')        # camera brand not in the table
        self.assertEqual(mode('12d1', '14dc', 'e0/01/03')['mode'], 'none')        # LTE dongle in RNDIS mode
        self.assertEqual(mode('2717', '2008', 'ef/04/01', 'ff/42/01')['modes'], ('adb', 'rndis'))
        self.assertEqual(mode('0e8d', '2000')['mode'], 'mediatek-brom')
        self.assertEqual(mode('0e8d', '0003')['mode'], 'mediatek-brom')
        self.assertEqual(mode('04e8', '685d')['mode'], 'samsung-download')
        self.assertEqual(mode('1782', '4d00')['mode'], 'spreadtrum-download')
        self.assertEqual(mode('05c6', '9008')['mode'], 'qualcomm-edl')
        self.assertEqual(mode('05c6', '9025')['mode'], 'none')
        # fastboot outranks adb; a low-level ID outranks everything
        self.assertEqual(mode('18d1', '4ee0', 'ff/42/01', 'ff/42/03')['mode'], 'fastboot')

    def test_boot_media_from_mountinfo(self):
        devs = self.devices()
        self.assertTrue(devs['1-6']['is_boot_media'])
        self.assertEqual([p for p, d in devs.items() if d['is_boot_media']], ['1-6'])
        self.assertEqual(usb_devices.boot_media_ports(), {'1-6'})

    def test_boot_media_through_device_mapper(self):
        machine = standard_machine(self.tmp / 'dm', via_dm=True)
        machine.hook()
        self.assertEqual(usb_devices.boot_media_ports(), {'1-6'})

    def test_boot_media_by_ventoy_label(self):
        machine = FakeMachine(self.tmp / 'label')
        machine.add_device('3-1', '0781', '5567', ['08/06/50'])
        machine.add_storage_block('3-1', mountpoint=None, label='Ventoy')
        machine.hook()
        self.assertEqual(usb_devices.boot_media_ports(), {'3-1'})
        self.assertTrue(usb_devices.list_usb_devices()[0]['is_boot_media'])

    def test_boot_media_injectable(self):
        devs = usb_devices.list_usb_devices(boot_ports={'3-2.1'})
        self.assertEqual([d['port'] for d in devs if d['is_boot_media']], ['3-2.1'])
        self.assertEqual([d['port'] for d in usb_devices.list_usb_devices(boot_ports=set()) if d['is_boot_media']], [])

    def test_unreadable_sysfs_is_none_and_garbage_is_ignored(self):
        self.assertIsNone(usb_devices.list_usb_devices(self.tmp / 'missing'))
        usb_devices.SYSFS_USB = self.machine.bus
        put(self.machine.bus / '9-9/idVendor', 'zzzz\n')            # not a plain dir name entry? it is, but bad hex
        self.assertNotIn('9-9', {d['port'] for d in usb_devices.list_usb_devices()})
        self.assertFalse(usb_devices.valid_port('1-2.3.4.5.6.7.8.9'))
        self.assertFalse(usb_devices.valid_port('1-2:1.0'))
        self.assertFalse(usb_devices.valid_port('../x'))
        self.assertTrue(usb_devices.valid_port('3-2.1'))

    def test_dicts_carry_no_serial_or_strings(self):
        blob = json.dumps(usb_devices.list_usb_devices())
        for leak in LEAKS + ('RESCUESERIAL1',):
            self.assertNotIn(leak, blob)
        self.assertEqual(usb_devices.read_serial('3-2.1'), SERIAL_A)    # only on explicit request, for hashing
        self.assertIsNone(usb_devices.read_serial('../../etc'))


# ----------------------------------------------------------------------------- ADB parsing

class AdbParsingTests(unittest.TestCase):
    def test_parse_devices_states_and_ports(self):
        text = ('* daemon not running; starting now at tcp:5037\n* daemon started successfully\n'
                'List of devices attached\n'
                '%s device usb:3-2.1 product:p model:m device:d transport_id:4\n'
                'XYZ123 unauthorized usb:1-1 transport_id:5\n'
                'ABC offline usb:1-2.4 transport_id:6\n'
                'DEF recovery usb:1-3 transport_id:7\n'
                'GHI sideload usb:1-4 transport_id:8\n'
                'JKL bootloader usb:1-5 transport_id:9\n'
                'MNO no permissions (user in plugdev group; are your udev rules wrong?); see [x] usb:1-6 transport_id:10\n'
                'emulator-5554 device product:sdk transport_id:11\n'
                '192.168.0.9:5555 device transport_id:12\n' % SERIAL_A)
        parsed = android.parse_devices(text)
        self.assertEqual([(p['state'], p['transport_id'], p['port']) for p in parsed], [
            ('device', 4, '3-2.1'), ('unauthorized', 5, '1-1'), ('offline', 6, '1-2.4'), ('recovery', 7, '1-3'),
            ('sideload', 8, '1-4'), ('bootloader', 9, '1-5'), ('no-permissions', 10, '1-6')])
        self.assertNotIn(SERIAL_A, json.dumps(parsed))

    def test_old_adb_location_is_not_a_port(self):
        parsed = android.parse_devices('List of devices attached\nSER device usb:336592896X transport_id:2\n')
        self.assertEqual(parsed, [{'state': 'device', 'transport_id': 2, 'port': None}])

    def test_getprop_allowlist_only(self):
        props = android.parse_getprop('[ro.build.version.sdk]: [34]\n[ro.serialno]: [%s]\n[ro.boot.wifimacaddr]: [aa:bb]\n'
                                      '[ro.product.model]: [Galaxy Secret Model]\n' % SERIAL_A)
        self.assertEqual(props, {'ro.build.version.sdk': '34'})

    def test_counters(self):
        self.assertEqual(android.count_device_admins(
            'Enabled Device Admins (User 0, provisioningState: 0):\n  com.a/.R:\n    uid=1\n  com.b/.S:\n    uid=2\n\nOther:\n'), 2)
        self.assertEqual(android.count_device_admins('Enabled Device Admins (User 0):\n'), 0)
        self.assertIsNone(android.count_device_admins('Permission Denial\n'))
        self.assertEqual(android.count_list_setting('null\n'), 0)
        self.assertEqual(android.count_list_setting('com.a/.S:com.b/.T\n'), 2)
        self.assertIsNone(android.count_list_setting(''))
        self.assertIsNone(android.count_list_setting('error: not a list!\n'))
        self.assertEqual(android.count_sideloaded('package:a  installer=null\npackage:b  installer=com.android.vending\n'
                                                  'package:c  installer=adb\npackage:d  installer=com.google.android.packageinstaller\n'), 3)
        self.assertIsNone(android.count_sideloaded('package:a\npackage:b\n'))      # no installer field: old Android
        self.assertIsNone(android.count_sideloaded('Error: something\n'))
        self.assertEqual(android.parse_df_free_percent('Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/x 10 9 1 90% /data\n'), 10)
        self.assertIsNone(android.parse_df_free_percent('df: /data: Permission denied\n'))
        self.assertEqual(android.parse_battery('  level: 85\n  health: 2\n  temperature: 312\n  status: 3\n')['temperature_c'], 31.2)


# ----------------------------------------------------------------------------- check thresholds

def status_of(checks, check_id):
    return next(c for c in checks if c['check_id'] == check_id)


class CheckThresholdTests(unittest.TestCase):
    TODAY = date(2026, 10, 1)

    def evaluate(self, **over):
        # The patch date is relative to the same fixed TODAY that evaluate() uses (not the real date).
        outputs = good_phone_outputs(today=self.TODAY, **{k: v for k, v in over.items() if k in ('patch_days', 'sdk')})
        outputs.update({k: v for k, v in over.items() if k not in ('patch_days', 'sdk')})
        names = {' '.join(v): k for k, v in android.COMMANDS.items()}
        checks, props = android.evaluate({names[k]: v for k, v in outputs.items()}, self.TODAY)
        return {c['check_id']: c for c in checks}

    def test_good_phone(self):
        checks = self.evaluate()
        statuses = {k: c['status'] for k, c in checks.items()}
        self.assertEqual(statuses['android-os-version'], 'pass')
        self.assertEqual(checks['android-os-version']['number'], 34)
        self.assertEqual(statuses['android-security-patch-age'], 'pass')
        self.assertEqual(checks['android-security-patch-age']['kind'], 'days')
        for cid in ('android-verified-boot', 'android-bootloader-lock', 'android-selinux', 'android-storage-free',
                    'android-battery-level', 'android-battery-health', 'android-battery-temperature',
                    'android-root-indicators', 'android-device-admin-count', 'android-accessibility-services-count',
                    'android-play-protect'):
            self.assertEqual(statuses[cid], 'pass', cid)
        self.assertEqual(statuses['android-unknown-sources-count'], 'warn')      # one sideloaded app
        self.assertEqual(checks['android-unknown-sources-count']['number'], 1)
        self.assertEqual(statuses['android-developer-options'], 'not_applicable')
        self.assertEqual(checks['android-storage-free']['number'], 40)
        self.assertEqual(checks['android-battery-temperature'], {'check_id': 'android-battery-temperature',
                                                                  'status': 'pass', 'kind': 'celsius', 'number': 31})

    def test_os_version(self):
        self.assertEqual(self.evaluate(sdk=33)['android-os-version']['status'], 'pass')
        self.assertEqual(self.evaluate(sdk=32)['android-os-version']['status'], 'warn')
        self.assertEqual(self.evaluate(sdk=29)['android-os-version']['status'], 'warn')
        self.assertEqual(self.evaluate(sdk=28)['android-os-version']['status'], 'fail')

    def test_patch_age(self):
        for days, expected in ((0, 'pass'), (90, 'pass'), (91, 'warn'), (365, 'warn'), (366, 'fail')):
            with self.subTest(days=days):
                self.assertEqual(self.evaluate(patch_days=days)['android-security-patch-age']['status'], expected)
        # Check the arithmetic directly as well
        props = {'ro.build.version.security_patch': '2026-07-01'}
        self.assertEqual(android._patch_age(props, self.TODAY)['number'], 92)
        self.assertEqual(android._patch_age({'ro.build.version.security_patch': '2027-01-01'}, self.TODAY)['number'], 0)
        self.assertEqual(android._patch_age({'ro.build.version.security_patch': 'garbage'}, self.TODAY)['status'], 'unknown')
        self.assertEqual(android._patch_age({'ro.build.version.security_patch': '2026-02-30'}, self.TODAY)['status'], 'unknown')

    def test_verified_boot_and_bootloader(self):
        def boot(state, locked=None, vbmeta=None):
            lines = ['[ro.boot.verifiedbootstate]: [%s]' % state]
            if locked is not None:
                lines.append('[ro.boot.flash.locked]: [%s]' % locked)
            if vbmeta is not None:
                lines.append('[ro.boot.vbmeta.device_state]: [%s]' % vbmeta)
            return self.evaluate(**{'shell getprop': '\n'.join(lines) + '\n'})
        for state, expected in (('green', 'pass'), ('yellow', 'warn'), ('orange', 'warn'), ('red', 'fail'), ('weird', 'unknown')):
            self.assertEqual(boot(state)['android-verified-boot']['status'], expected, state)
        self.assertEqual(boot('green', locked='1')['android-bootloader-lock']['status'], 'pass')
        self.assertEqual(boot('orange', locked='0')['android-bootloader-lock']['status'], 'warn')
        self.assertEqual(boot('green', vbmeta='locked')['android-bootloader-lock']['status'], 'pass')
        self.assertEqual(boot('orange', vbmeta='unlocked')['android-bootloader-lock']['status'], 'warn')
        self.assertEqual(boot('green')['android-bootloader-lock']['status'], 'unknown')

    def test_selinux(self):
        for word, expected in (('Enforcing', 'pass'), ('Permissive', 'fail'), ('Disabled', 'fail'), ('???', 'unknown')):
            self.assertEqual(self.evaluate(**{'shell getenforce': word + '\n'})['android-selinux']['status'], expected)

    def test_storage(self):
        def df(use):
            return 'Filesystem 1K Used Avail Use% Mounted on\n/dev/x 100 ' + '%d %d %d%%' % (use, 100 - use, use) + ' /data\n'
        for use, expected, free in ((80, 'pass', 20), (90, 'pass', 10), (91, 'warn', 9), (97, 'warn', 3), (98, 'fail', 2)):
            c = self.evaluate(**{'shell df /data': df(use)})['android-storage-free']
            self.assertEqual((c['status'], c['number']), (expected, free), use)

    def test_battery(self):
        def battery(level, health=2, temp=300, status=3):
            return 'level: %d\nhealth: %d\ntemperature: %d\nstatus: %d\n' % (level, health, temp, status)
        run = lambda **kw: self.evaluate(**{'shell dumpsys battery': battery(**kw)})
        self.assertEqual(run(level=50)['android-battery-level']['status'], 'pass')
        self.assertEqual(run(level=19)['android-battery-level']['status'], 'warn')
        self.assertEqual(run(level=9)['android-battery-level']['status'], 'fail')
        self.assertEqual(run(level=9, status=2)['android-battery-level']['status'], 'pass')   # charging
        self.assertEqual(run(level=101)['android-battery-level']['status'], 'unknown')
        for health, expected in ((2, 'pass'), (3, 'fail'), (4, 'fail'), (5, 'fail'), (6, 'warn'), (7, 'warn'), (1, 'unknown')):
            self.assertEqual(run(level=50, health=health)['android-battery-health']['status'], expected)
        for temp, expected, number in ((399, 'pass', 39), (400, 'warn', 40), (449, 'warn', 44), (450, 'fail', 45)):
            c = run(level=50, temp=temp)['android-battery-temperature']
            self.assertEqual((c['status'], c['number']), (expected, number), temp)
        c = run(level=50, temp=-30)['android-battery-temperature']
        self.assertEqual((c['status'], 'number' in c), ('warn', False))

    def test_root_indicators(self):
        paths = 'shell ls -d ' + ' '.join(android.SU_PATHS)
        self.assertEqual(self.evaluate(**{paths: '/system/xbin/su\n'})['android-root-indicators']['status'], 'warn')
        self.assertEqual(self.evaluate(**{'shell which su': '/system/bin/su\n'})['android-root-indicators']['status'], 'warn')
        self.assertEqual(self.evaluate(**{paths: '/home/not/a/known/path\n'})['android-root-indicators']['status'], 'pass')
        debuggable = good_phone_outputs()['shell getprop'].replace('[ro.debuggable]: [0]', '[ro.debuggable]: [1]')
        self.assertEqual(self.evaluate(**{'shell getprop': debuggable})['android-root-indicators']['status'], 'warn')
        self.assertEqual(self.evaluate(**{'shell getprop': None})['android-root-indicators']['status'], 'unknown')

    def test_admin_accessibility_unknown_sources_play_protect(self):
        admins = lambda n: ('Enabled Device Admins (User 0, provisioningState: 0):\n' +
                            ''.join('  com.x%d/.R:\n    uid=1\n' % i for i in range(n)))
        for n, expected in ((0, 'pass'), (2, 'pass'), (3, 'warn')):
            c = self.evaluate(**{'shell dumpsys device_policy': admins(n)})['android-device-admin-count']
            self.assertEqual((c['status'], c['number']), (expected, n))
        acc = 'shell settings get secure enabled_accessibility_services'
        self.assertEqual(self.evaluate(**{acc: 'com.secret.accessibility/.Svc\n'})['android-accessibility-services-count']['status'], 'warn')
        self.assertEqual(self.evaluate(**{acc: 'a/.S:b/.T\n'})['android-accessibility-services-count']['number'], 2)
        self.assertEqual(self.evaluate(**{acc: None})['android-accessibility-services-count']['status'], 'unknown')
        pkg = 'shell pm list packages -3 -i'
        self.assertEqual(self.evaluate(**{pkg: 'package:a  installer=com.android.vending\n'})['android-unknown-sources-count']['status'], 'pass')
        self.assertEqual(self.evaluate(**{pkg: None})['android-unknown-sources-count']['status'], 'unknown')
        consent, enable = ('shell settings get global package_verifier_user_consent',
                           'shell settings get global package_verifier_enable')
        self.assertEqual(self.evaluate(**{consent: '-1\n'})['android-play-protect']['status'], 'warn')
        self.assertEqual(self.evaluate(**{enable: '0\n'})['android-play-protect']['status'], 'warn')
        self.assertEqual(self.evaluate(**{consent: 'null\n', enable: 'null\n'})['android-play-protect']['status'], 'unknown')

    def test_developer_options(self):
        dev = 'shell settings get global development_settings_enabled'
        self.assertEqual(self.evaluate(**{dev: '1\n'})['android-developer-options']['status'], 'not_applicable')
        self.assertEqual(self.evaluate(**{dev: '0\n'})['android-developer-options']['status'], 'pass')
        self.assertEqual(self.evaluate(**{dev: 'null\n'})['android-developer-options']['status'], 'unknown')

    def test_every_value_is_unknown_when_nothing_can_be_read(self):
        outputs = {name: None for name in android.COMMANDS}
        checks, props = android.evaluate(outputs, self.TODAY)
        self.assertEqual({c['status'] for c in checks}, {'unknown'})
        self.assertEqual(props, {})

    def test_numbers_are_bounded(self):
        c = android._c('android-os-version', 'pass', 'count', 10 ** 12)
        self.assertEqual(c['number'], 1000000)
        self.assertEqual(android._c('android-os-version', 'pass', 'count', -5)['number'], 0)

    def test_usb_port_speed(self):
        self.assertEqual(android.usb_speed_check({'speed_mbps': 12})['status'], 'warn')
        self.assertEqual(android.usb_speed_check({'speed_mbps': 1.5})['status'], 'warn')
        self.assertEqual(android.usb_speed_check({'speed_mbps': 480})['status'], 'pass')
        self.assertEqual(android.usb_speed_check({'speed_mbps': 5000})['status'], 'pass')
        self.assertEqual(android.usb_speed_check(None)['status'], 'unknown')

    def test_connection_mode_status(self):
        cm = android.connection_status
        self.assertEqual(cm({'adb_state': 'device', 'mode': 'adb'}, True), 'pass')
        self.assertEqual(cm({'adb_state': 'unauthorized', 'mode': 'adb'}, True), 'warn')
        self.assertEqual(cm({'adb_state': 'offline', 'mode': 'adb'}, True), 'warn')
        self.assertEqual(cm({'adb_state': None, 'mode': 'adb'}, False), 'unknown')       # adb missing
        self.assertEqual(cm({'adb_state': None, 'mode': 'mtp-ptp'}, False), 'unknown')
        self.assertEqual(cm({'adb_state': None, 'mode': 'mtp-ptp'}, True), 'warn')       # USB debugging off
        self.assertEqual(cm({'adb_state': None, 'mode': 'fastboot'}, False), 'warn')
        self.assertEqual(cm({'adb_state': None, 'mode': 'qualcomm-edl'}, True), 'warn')


# --------------------------------------------------------------------- discovery and the adb shim

class DiscoveryTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)

    def discover(self, with_adb=True):
        adb = None
        if with_adb:
            adb = android.Adb(android.find_adb())
        return android.discover(usb_devices.list_usb_devices(), adb, adb is not None, seed='machine-id:test'), adb

    def test_targets_numbered_by_port_with_modes(self):
        self.install_adb()
        targets, _ = self.discover()
        self.assertEqual([(t['ref'], t['port'], t['mode'], t['access'], t['detection']) for t in targets], [
            ('and-0', '1-3', 'fastboot', 'usb-only', 'usb-enumerated'),
            ('and-1', '1-4', 'qualcomm-edl', 'usb-only', 'usb-enumerated'),
            ('and-2', '3-2.1', 'adb', 'adb-authorized', 'usb-adb')])
        self.assertEqual(targets[2]['transport_id'], 1)
        self.assertEqual(targets[2]['brand'], 'samsung')

    def test_opaque_id_is_keyed_and_hides_the_serial(self):
        self.install_adb()
        targets, _ = self.discover()
        ids = [t['opaque_id'] for t in targets]
        self.assertEqual(len(set(ids)), 3)
        for oid in ids:
            self.assertRegex(oid, r'^target-[0-9a-f]{16}$')
            self.assertNotIn(SERIAL_A.lower(), oid)
        again = android.opaque_id(SERIAL_A, '3-2.1', None, 'machine-id:test')
        self.assertEqual(again, targets[2]['opaque_id'])
        self.assertNotEqual(android.opaque_id(SERIAL_A, '3-2.1', None, 'machine-id:other'), again)
        import hashlib
        self.assertNotEqual(again, 'target-' + hashlib.sha256(SERIAL_A.encode()).hexdigest()[:16])
        self.assertNotIn(SERIAL_A, json.dumps(targets, default=str))

    def test_without_adb_everything_is_usb_only(self):
        targets, adb = self.discover(with_adb=False)
        self.assertIsNone(adb)
        self.assertEqual({t['access'] for t in targets}, {'usb-only'})
        self.assertEqual(targets[2]['mode'], 'adb')

    def test_unauthorized_and_unmapped_states(self):
        text = ('List of devices attached\n%s unauthorized usb:3-2.1 transport_id:1\n'
                'EMULATOR device usb:7-7 transport_id:2\n' % SERIAL_A)
        self.install_adb(text)
        targets, _ = self.discover()
        phone = next(t for t in targets if t['port'] == '3-2.1')
        self.assertEqual((phone['access'], phone['adb_state']), ('adb-unauthorized', 'unauthorized'))
        loose = next(t for t in targets if t['port'] == '7-7')
        self.assertIsNone(loose['usb'])
        self.assertEqual(loose['access'], 'adb-authorized')

    def test_old_adb_without_port_pairs_with_the_single_adb_device(self):
        self.install_adb('List of devices attached\nSER device usb:336592896X transport_id:1\n')
        targets, _ = self.discover()
        phone = next(t for t in targets if t['mode'] == 'adb')
        self.assertEqual((phone['port'], phone['access']), ('3-2.1', 'adb-authorized'))

    def test_adb_calls_are_fixed_argv_without_the_serial(self):
        self.install_adb()
        targets, adb = self.discover()
        checks, props = android.collect_target_checks(adb, targets[2], True, today=date.today())
        calls = self.adb_calls()
        allowed = {tuple(['-t', '1'] + list(cmd)) for cmd in android.COMMANDS.values()}
        shell_calls = [tuple(c) for c in calls if c[:1] == ['-t']]
        self.assertEqual(len(shell_calls), len(android.COMMANDS))
        self.assertEqual(set(shell_calls), allowed)
        self.assertIn(['devices', '-l'], calls)
        flat = json.dumps(calls)
        self.assertNotIn(SERIAL_A, flat)
        for forbidden in ('root', 'install', 'push', 'pull', 'reboot', 'sideload', 'unlock', 'flash', 'rm'):
            self.assertTrue(all(forbidden not in cmd for cmd in shell_calls), forbidden)
        self.assertEqual([c['check_id'] for c in checks], list(android.CHECK_IDS))
        self.assertEqual(android.release_label(props), 'Android 14')
        self.assertEqual(android.architecture(props), 'arm64')

    def test_unauthorized_phone_gets_unknown_checks_and_no_shell_calls(self):
        self.install_adb('List of devices attached\n%s unauthorized usb:3-2.1 transport_id:1\n' % SERIAL_A)
        targets, adb = self.discover()
        phone = next(t for t in targets if t['port'] == '3-2.1')
        checks, _ = android.collect_target_checks(adb, phone, True, today=date.today())
        by = {c['check_id']: c['status'] for c in checks}
        self.assertEqual(by['android-connection-mode'], 'warn')
        self.assertEqual(by['android-usb-port-speed'], 'pass')
        self.assertEqual({v for k, v in by.items() if k not in ('android-connection-mode', 'android-usb-port-speed')},
                         {'unknown'})
        self.assertEqual([c for c in self.adb_calls() if c[:1] == ['-t']], [])

    def test_transport_id_must_be_a_positive_int(self):
        self.install_adb()
        adb = android.Adb(android.find_adb())
        self.assertIsNone(adb.run('1; reboot', 'getprop'))
        self.assertIsNone(adb.run(True, 'getprop'))
        self.assertIsNone(adb.run(0, 'getprop'))
        self.assertEqual([c for c in self.adb_calls() if c[:1] == ['-t']], [])

    def test_missing_adb_binary(self):
        android.ADB_SEARCH_PATH = str(self.tmp / 'empty')
        self.assertIsNone(android.find_adb())

    def test_timeout_and_runaway_output_give_none(self):
        directory = self.tmp / 'slow'
        directory.mkdir()
        script = directory / 'adb'
        script.write_text('#!%s\nimport sys, time\nif sys.argv[1:] == ["devices", "-l"]:\n    time.sleep(30)\n'
                          'else:\n    sys.stdout.write("x" * (5 * 1024 * 1024))\n' % sys.executable)
        script.chmod(0o755)
        adb = android.Adb(str(script), search_path=str(directory), timeout=1)
        self.assertIsNone(adb.devices())
        self.assertIsNone(adb.run(1, 'getprop'))

    def test_inventory_checks(self):
        counts = {c['check_id']: c for c in android.usb_inventory_checks(usb_devices.list_usb_devices())}
        self.assertEqual((counts['usb-device-count']['number'], counts['usb-android-device-count']['number']), (6, 3))
        none = {c['check_id']: c for c in android.usb_inventory_checks([])}
        self.assertEqual((none['usb-android-device-count']['status'], none['usb-android-device-count']['number']), ('warn', 0))
        self.assertEqual({c['status'] for c in android.usb_inventory_checks(None)}, {'unknown'})


# ------------------------------------------------------------------------------------ the CLI

class CliTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)
        self.install_adb()

    def scan(self, *extra, **kw):
        out = self.tmp / 'evidence.json'
        result = self.run_scan('--output', str(out), *extra, **kw)
        return result, out

    def test_list_usb_table_markers_and_guidance(self):
        result = self.run_scan('--list-usb')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout
        rescue = next(l for l in text.splitlines() if l.startswith('1-6'))
        self.assertIn('[USB RESCUE]', rescue)
        self.assertNotIn('[USB RESCUE]', next(l for l in text.splitlines() if l.startswith('3-2.1')))
        hub = next(l for l in text.splitlines() if l.startswith('3-2 '))
        self.assertIn('[HUB]', hub)
        phone = next(l for l in text.splitlines() if l.startswith('3-2.1'))
        for part in ('left/kiri', '480 Mbps', '2.00', 'samsung', 'ADB', '[and-2]'):
            self.assertIn(part, phone)
        self.assertIn('LOKASI / LOCATION', text)
        self.assertIn('Ponsel and-2 terdeteksi di port 3-2.1 (panel kiri, sisi kiri, 480 Mbps), merek samsung, mode ADB.', text)
        self.assertIn('Phone and-2 detected on port 3-2.1 (left panel, left side, 480 Mbps), brand samsung, mode ADB.', text)
        self.assertIn('Jangan cabut perangkat bertanda [USB RESCUE] (port 1-6)', text)
        self.assertIn('Qualcomm EDL', text)
        self.assertIn('fastboot', text)
        self.assertIn('Kecepatan hanya 12 Mbps', text)                    # the fastboot phone
        self.assertEqual(self.adb_calls()[-1], ['kill-server'])             # the server this scan started is stopped
        for leak in LEAKS + ('RESCUESERIAL1',):
            self.assertNotIn(leak, result.stdout + result.stderr)

    def test_list_usb_unauthorized_hint(self):
        self.install_adb('List of devices attached\n%s unauthorized usb:3-2.1 transport_id:1\n' % SERIAL_A)
        text = self.run_scan('--list-usb').stdout
        self.assertIn('setujui "Izinkan USB debugging"', text)
        self.assertIn('accept "Allow USB debugging"', text)

    def test_list_usb_with_no_phone(self):
        machine = FakeMachine(self.tmp / 'plain')
        machine.add_device('1-5', '046d', 'c31c', ['03/01/01'])
        machine.hook()
        self.install_adb('List of devices attached\n\n')
        result = self.run_scan('--list-usb', machine=machine)
        self.assertEqual(result.returncode, 0)
        self.assertIn('Tidak ada ponsel/tablet Android terdeteksi.', result.stdout)
        self.assertIn('kabel hanya-pengisi daya', result.stdout)
        self.assertIn('Opsi pengembang', result.stdout)
        self.assertIn('charge-only cable', result.stdout)

    def test_list_usb_without_adb_and_mtp_only(self):
        machine = FakeMachine(self.tmp / 'mtp')
        machine.add_device('1-2', '2717', '2008', ['06/01/01'])
        machine.hook()
        result = self.run_scan('--list-usb', machine=machine, with_adb=False)
        self.assertIn('MTP/PTP', result.stdout)
        self.assertIn('adb belum terpasang', result.stdout)
        result = self.run_scan('--list-usb', machine=machine, with_adb=True)
        self.assertIn('USB debugging belum aktif', result.stdout)

    def test_evidence_validates_and_is_private(self):
        result, out = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        report = json.loads(out.read_text())
        self.assertEqual(report['schema_version'], '1.3')
        self.assertEqual(report['source_platform'], 'linux-mint-xfce-live')
        self.assertEqual([t['ref'] for t in report['target_systems']], ['and-0', 'and-1', 'and-2'])
        self.assertTrue(all(t['family'] == 'android' for t in report['target_systems']))
        phone = report['target_systems'][2]
        self.assertEqual((phone['access'], phone['detection'], phone['usb_port'], phone['release']),
                         ('adb-authorized', 'usb-adb', '3-2.1', 'Android 14'))
        self.assertEqual(phone['architecture'], 'arm64')
        # several phones: the top-level id is the host's, never one phone's
        self.assertNotIn(report['target_device_opaque_id'], [t['opaque_id'] for t in report['target_systems']])
        self.assertRegex(report['target_device_opaque_id'], r'^target-[0-9a-f]{16}$')
        ports = {p['port']: p for p in report['usb_ports']}
        self.assertEqual(len(ports), 7)
        self.assertTrue(ports['1-6']['is_boot_media'])
        self.assertEqual((ports['3-2.1']['android_mode'], ports['3-2.1']['panel'], ports['3-2.1']['speed_mbps'],
                          ports['3-2.1']['hub_depth'], ports['3-2.1']['vendor_brand']), ('adb', 'left', 480, 1, 'samsung'))
        self.assertTrue(ports['3-2']['is_hub'])
        self.assertEqual(ports['1-4']['android_mode'], 'qualcomm-edl')
        env = [c for c in report['checks'] if 'target_ref' not in c]
        self.assertEqual({c['check_id'] for c in env}, {'usb-device-count', 'usb-android-device-count'})
        mine = {c['check_id']: c for c in report['checks'] if c.get('target_ref') == 'and-2'}
        self.assertEqual(set(mine), set(android.CHECK_IDS))
        self.assertEqual(mine['android-connection-mode']['status'], 'pass')
        self.assertEqual(mine['android-os-version']['value'], {'kind': 'count', 'number': 34})
        self.assertEqual(report['evidence_manifest']['entry_count'], len(report['checks']))
        self.assertEqual(report['repair_policy'], 'detect-only')
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_single_android_target_becomes_the_device_id(self):
        result, out = self.scan('--device', 'and-2')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual([t['ref'] for t in report['target_systems']], ['and-2'])
        self.assertEqual(report['target_device_opaque_id'], report['target_systems'][0]['opaque_id'])
        self.assertTrue(report['target_device_opaque_id'].startswith('target-'))
        # all ports are still inventoried
        self.assertEqual(len(report['usb_ports']), 7)

    def test_select_by_port_and_not_found(self):
        result, out = self.scan('--port', '1-3')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([t['ref'] for t in json.loads(out.read_text())['target_systems']], ['and-0'])
        out.unlink()
        result, out = self.scan('--port', '9-9')
        self.assertEqual(result.returncode, 1)
        self.assertFalse(out.exists())
        self.assertEqual(self.run_scan('--device', 'and-9x', '--output', str(out)).returncode, 2)
        self.assertEqual(self.run_scan('--port', '../x', '--output', str(out)).returncode, 2)
        self.assertEqual(self.run_scan().returncode, 2)                    # neither --list-usb nor --output

    def test_host_platform(self):
        result, out = self.scan('--source-platform', 'linux-host')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report['source_platform'], 'linux-host')
        self.assertIsNone(report['linux_release'])
        self.assertNotIn(['kill-server'], self.adb_calls())                # a host's own adb server is left alone

    def test_privacy_nothing_leaks_into_evidence_or_terminal(self):
        result, out = self.scan()
        blob = out.read_text() + result.stdout + result.stderr
        for leak in LEAKS + ('RESCUESERIAL1', 'machine-id'):
            self.assertNotIn(leak, blob)
        # no raw vendor:product IDs either
        for pair in ('04e8', '6860', '18d1', '05c6', '9008'):
            self.assertNotIn('"%s"' % pair, blob)
        # every string value in the evidence is a closed-set token, a timestamp, a hash or an id
        text = json.dumps(json.loads(out.read_text()))
        self.assertNotIn('Galaxy', text)

    def test_unauthorized_scan_still_writes_valid_evidence(self):
        self.install_adb('List of devices attached\n%s unauthorized usb:3-2.1 transport_id:1\n' % SERIAL_A)
        result, out = self.scan('--device', 'and-2')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report['target_systems'][0]['access'], 'adb-unauthorized')
        mine = {c['check_id']: c['status'] for c in report['checks'] if c.get('target_ref') == 'and-2'}
        self.assertEqual(mine['android-connection-mode'], 'warn')
        self.assertEqual(mine['android-os-version'], 'unknown')

    def test_no_adb_binary_gives_unknown_connection_mode(self):
        machine = FakeMachine(self.tmp / 'noadb')
        machine.add_device('1-2', '2717', '2008', ['06/01/01'])
        machine.hook()
        result, out = self.scan(machine=machine, with_adb=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report['target_systems'][0]['access'], 'usb-only')
        mine = {c['check_id']: c['status'] for c in report['checks'] if c.get('target_ref') == 'and-0'}
        self.assertEqual(mine['android-connection-mode'], 'unknown')

    def test_no_phone_still_writes_evidence(self):
        machine = FakeMachine(self.tmp / 'nophone')
        machine.add_device('1-5', '046d', 'c31c', ['03/01/01'])
        machine.hook()
        self.install_adb('List of devices attached\n\n')
        result, out = self.scan(machine=machine)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report['target_systems'], [])
        counts = {c['check_id']: c['status'] for c in report['checks']}
        self.assertEqual(counts['usb-android-device-count'], 'warn')

    def test_unreadable_usb_sysfs_is_fatal(self):
        env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(self.tmp)}
        result = subprocess.run([sys.executable, str(SCAN), '--fixture-root', str(self.tmp / 'nothing'), '--list-usb'],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn('sysfs', result.stderr)


# -------------------------------------------------------------------- schema and validator rules

@unittest.skipUnless(HAVE_JSONSCHEMA, 'jsonschema is not installed')
class SchemaTests(unittest.TestCase):
    def validate(self, *paths):
        return subprocess.run([sys.executable, str(VALIDATE)] + [str(p) for p in paths], capture_output=True, text=True)

    def load(self, name='valid-android-usb.json'):
        return json.loads((FIXTURES / name).read_text())

    def write(self, data):
        path = Path(tempfile.mkdtemp(prefix='android-schema-')) / 'e.json'
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_text(json.dumps(data))
        return path

    def test_valid_fixture(self):
        result = self.validate(FIXTURES / 'valid-android-usb.json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_fixtures_are_rejected_for_the_documented_reason(self):
        for name in ('invalid-android-serial', 'invalid-1.3-fields-in-1.2'):
            with self.subTest(name=name):
                result = self.validate(FIXTURES / (name + '.json'))
                self.assertEqual(result.returncode, 1, result.stdout)
                reason = (FIXTURES / (name + '.reason.txt')).read_text().strip().lower()
                self.assertTrue(any(word in result.stdout.lower() for word in reason.split(';')[0].split('|')),
                                (reason, result.stdout))

    def test_older_versions_still_validate(self):
        result = self.validate(*sorted(FIXTURES.glob('valid-*1.1.json')), FIXTURES / 'valid-live-scoped-1.2.json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_free_strings_are_rejected(self):
        for mutate in (
            lambda d: d['usb_ports'][0].update({'serial': SERIAL_A}),
            lambda d: d['usb_ports'][0].update({'port': SERIAL_A}),
            lambda d: d['usb_ports'][0].update({'vendor_brand': 'Galaxy Secret Model'}),
            lambda d: d['usb_ports'][0].update({'android_mode': 'rooted'}),
            lambda d: d['usb_ports'][0].update({'panel': 'on the desk'}),
            lambda d: d['usb_ports'][0].update({'usb_version': '2.0.0'}),
            lambda d: d['target_systems'][0].update({'usb_port': SERIAL_A}),
            lambda d: d['target_systems'][0].update({'opaque_id': SERIAL_A}),
            lambda d: d['target_systems'][0].update({'model': 'Pixel 9'}),
            lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'android-packages-list'}),
            lambda d: d['checks'][-1].update({'target_ref': 'and-9'}),
        ):
            data = self.load()
            mutate(data)
            data['evidence_manifest']['entry_count'] = len(data['checks'])
            self.assertEqual(self.validate(self.write(data)).returncode, 1)

    def test_semantic_rules(self):
        data = self.load()
        data['target_systems'][0]['usb_port'] = '9-9'
        self.assertEqual(self.validate(self.write(data)).returncode, 1)
        data = self.load()
        data['target_systems'][0]['family'] = 'windows'
        self.assertEqual(self.validate(self.write(data)).returncode, 1)
        data = self.load()
        data['usb_ports'].append(dict(data['usb_ports'][0]))
        self.assertEqual(self.validate(self.write(data)).returncode, 1)
        for version in ('1.0', '1.1', '1.2'):
            data = self.load()
            data['schema_version'] = version
            self.assertEqual(self.validate(self.write(data)).returncode, 1, version)

    def test_mixed_os_and_android_evidence(self):
        data = self.load()
        data['target_systems'].append({'ref': 'os-0', 'family': 'linuxmint', 'release': 'Linux Mint 22.3',
                                       'architecture': 'x86_64', 'detection': 'live-offline', 'encryption': 'none',
                                       'access': 'read-only-mounted'})
        data['checks'].append({**data['checks'][0], 'check_id': 'os-detection', 'target_ref': 'os-0',
                               'source': 'offline-target-scan'})
        data['evidence_manifest']['entry_count'] = len(data['checks'])
        self.assertEqual(self.validate(self.write(data)).returncode, 0)


if __name__ == '__main__':
    unittest.main()
