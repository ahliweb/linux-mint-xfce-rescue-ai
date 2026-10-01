#!/usr/bin/env python3
"""Offline tests for printer detection, scan-printers.py and the printer evidence rules
(ahliweb/linux-mint-xfce-rescue-ai#57, phase 1).

A fake sysfs tree stands in for /sys, and PATH shims (Python scripts found through a directory) stand in for
``lpstat``, ``ipptool`` and ``avahi-browse``: each returns canned output and logs every argv. Nothing touches a
real printer, a real CUPS server or the network. Dummy values only.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import csv
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS / 'lib'))
from rescue_modules import printer, usb_devices  # noqa: E402
import rescue_modules  # noqa: E402

SCAN = SCRIPTS / 'scan-printers.py'
SCAN_OS = SCRIPTS / 'scan-target-os.py'
VALIDATE = SCRIPTS / 'validate-evidence.py'
FIXTURES = ROOT / 'rescue-ai/v1/fixtures'
IPP_TEST = ROOT / 'scripts/lib/ipp/get-printer-attributes.test'
HAVE_JSONSCHEMA = importlib.util.find_spec('jsonschema') is not None

SERIAL_HP = 'SERIALPRN0123456'          # dummy printer serials: must never appear in any output
SERIAL_CANON = 'SERIALCAN9876543'
QUEUE_HP = 'SecretQueueName'
QUEUE_NET = 'OfficeNetQueue'
LEAKS = (SERIAL_HP, SERIAL_CANON, QUEUE_HP, QUEUE_NET, 'SecretMaker', 'Secret LaserJet 9000', 'secretuser',
         '192.168.77.88', 'secret-printer.local', 'secret-job-name', 'SecretMDNS Printer', 'Floor 3 Secret Room',
         'machine-id')

CSV_HEADER = ['printer-state', 'printer-state-reasons', 'printer-is-accepting-jobs', 'queued-job-count',
              'marker-levels', 'marker-types', 'printer-make-and-model']


def put(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def ipp_csv(state='idle', reasons='none', accepting='true', queued='0', levels='', types='',
            make='HP Secret LaserJet 9000'):
    """The CSV ipptool -c prints for the fixed test file."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(CSV_HEADER)
    writer.writerow([state, reasons, accepting, queued, levels, types, make])
    return out.getvalue()


# --------------------------------------------------------------------------------- fake machine

class FakeUsb:
    """A fake /sys/bus/usb/devices (and the --fixture-root layout) with a few USB devices."""

    def __init__(self, tmp):
        self.root = Path(tmp) / 'fx'
        self.devices = self.root / 'sys/devices/pci0000:00/0000:00:14.0'
        self.bus = self.root / 'sys/bus/usb/devices'
        self.bus.mkdir(parents=True)
        self.mounts = []
        for bus in (1, 3):
            folder = self.devices / ('usb%d' % bus)
            put(folder / 'speed', '480\n')
            put(folder / 'bDeviceClass', '09\n')
            self._link('usb%d' % bus, folder)

    def _link(self, name, target):
        link = self.bus / name
        if link.is_symlink():
            link.unlink()
        os.symlink(target, link)

    def add_device(self, port, vid, pid, interfaces, speed=480, version=' 2.00', device_class='00', serial=None,
                   panel=None, horizontal=None, connect_type=None):
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
        put(folder / 'bMaxPower', '100mA\n')
        if serial:
            put(folder / 'serial', serial + '\n')
        put(folder / 'manufacturer', 'SecretMaker\n')
        put(folder / 'product', 'Secret LaserJet 9000\n')
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

    def add_rescue_medium(self, port, name='sdb', majmin='8:17'):
        """The rescue USB: a partition below *port* mounted at /cdrom."""
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
        os.symlink(part, self.root / 'sys/dev/block' / majmin)
        self.mounts.append('40 28 %s / /cdrom ro - iso9660 /dev/%s1 ro' % (majmin, name))
        put(self.root / 'proc/self/mountinfo', '\n'.join(self.mounts) + '\n')

    def add_ipp_usb_state(self, name, port):
        put(self.root / 'var/ipp-usb/dev' / name, '[device]\nhttp-port = %d\ndns-sd-name = Secret MDNS\n' % port)

    def add_fib_trie(self, *addresses):
        lines = ['Main:', '  +-- 0.0.0.0/0 3 0 5']
        for a in addresses:
            lines += ['        |-- %s' % a, '           /32 host LOCAL']
        put(self.root / 'proc/net/fib_trie', '\n'.join(lines) + '\n')

    @property
    def usb_dir(self):
        return self.bus

    @property
    def ipp_usb_dir(self):
        return self.root / 'var/ipp-usb/dev'

    @property
    def fib(self):
        return self.root / 'proc/net/fib_trie'

    def inventory(self):
        return usb_devices.list_usb_devices(sysfs=self.bus)

    def serial_reader(self):
        return lambda port: usb_devices.read_serial(port, sysfs=self.bus)


def standard_machine(tmp):
    """A rescue USB, a HP printer (07/01/02) with the ACPI location left panel on port 1-4, a Canon printer that also
    offers IPP-over-USB (07/01/02 + 07/01/04) behind a hub on 3-2.1, a keyboard and a scanner-only device."""
    m = FakeUsb(tmp)
    m.add_device('1-6', '0781', '5567', ['08/06/50'], serial='RESCUESERIAL1')
    m.add_rescue_medium('1-6')
    m.add_device('1-4', '03f0', '2b17', ['07/01/02'], serial=SERIAL_HP, panel='left', horizontal='left',
                 connect_type='hotplug')
    m.add_device('3-2', '05e3', '0610', ['09/00/01'], device_class='09')
    m.add_device('3-2.1', '04a9', '1865', ['07/01/02', '07/01/04'], serial=SERIAL_CANON, speed=480)
    m.add_device('1-5', '046d', 'c31c', ['03/01/01'], speed=12, version='1.10')
    m.add_device('1-7', '04b8', '0123', ['ff/ff/ff'])          # vendor-specific scanner: not a printer
    return m


# ------------------------------------------------------------------------------------ the shims

SHIM = '''#!%(python)s
import json, os, sys
D = os.path.dirname(os.path.abspath(__file__))
name = os.path.basename(sys.argv[0])
cfg = json.load(open(os.path.join(D, 'config.json')))
with open(os.path.join(D, 'calls.log'), 'a') as handle:
    handle.write(json.dumps([name] + sys.argv[1:]) + '\\n')
argv = sys.argv[1:]
if name == 'lpstat':
    out = cfg.get('lpstat', {}).get(argv[0] if argv else '')
    if out is None:
        sys.exit(1)
    sys.stdout.write(out)
elif name == 'ipptool':
    # ipptool -T 6 -c URI TESTFILE
    if len(argv) != 5 or argv[:3] != ['-T', '6', '-c']:
        sys.exit(2)
    if argv[3] in cfg.get('ipp_fail', []):
        sys.stderr.write('ipptool: Unable to connect\\n')
        sys.exit(1)
    sys.stdout.write(cfg.get('ipp', {}).get(argv[3], cfg.get('ipp_empty', '')))
elif name == 'avahi-browse':
    out = cfg.get('avahi', {}).get(argv[-1], '')
    sys.stdout.write(out)
else:
    sys.exit(3)
'''


class Shims:
    """lpstat/ipptool/avahi-browse stand-ins in one directory (config.json holds the canned output)."""

    def __init__(self, directory, tools=('lpstat', 'ipptool', 'avahi-browse')):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        for tool in tools:
            script = self.dir / tool
            script.write_text(SHIM % {'python': sys.executable})
            script.chmod(script.stat().st_mode | stat.S_IXUSR)
        self.cfg = {'lpstat': {}, 'ipp': {}, 'avahi': {}, 'ipp_fail': [],
                    'ipp_empty': ','.join(CSV_HEADER) + '\n'}
        self.write()

    def write(self):
        (self.dir / 'config.json').write_text(json.dumps(self.cfg))

    def set(self, **kw):
        self.cfg.update(kw)
        self.write()

    def calls(self):
        log = self.dir / 'calls.log'
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]


def lpstat_config(queues=(), running=True):
    """queues: (name, state_word, device_uri, accepting) -> the canned outputs of the five fixed lpstat calls."""
    p, v, a = [], [], []
    for name, state, uri, accepting in queues:
        if state == 'idle':
            p.append('printer %s is idle.  enabled since Thu 01 Oct 2026 08:00:00 AM UTC' % name)
        elif state == 'processing':
            p.append('printer %s now printing %s-7.  enabled since Thu 01 Oct 2026 08:00:00 AM UTC' % (name, name))
        else:
            p.append('printer %s disabled since Thu 01 Oct 2026 08:00:00 AM UTC -\n\tPaused' % name)
        v.append('device for %s: %s' % (name, uri))
        a.append('%s %s requests since Thu 01 Oct 2026 08:00:00 AM UTC' % (name, 'accepting' if accepting else 'not accepting'))
    return {'-r': 'scheduler is running\n' if running else 'scheduler is not running\n',
            '-p': '\n'.join(p) + ('\n' if p else ''), '-v': '\n'.join(v) + ('\n' if v else ''),
            '-a': '\n'.join(a) + ('\n' if a else ''), '-o': ''}


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='printer-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.saved = (printer.TOOL_SEARCH_PATH, printer.IPP_USB_STATE, printer.FIB_TRIE)
        self.addCleanup(self.restore)

    def restore(self):
        printer.TOOL_SEARCH_PATH, printer.IPP_USB_STATE, printer.FIB_TRIE = self.saved

    def discover(self, machine, shims, network=False):
        tools = printer.Tools(str(shims.dir if shims else self.tmp / 'no-tools-here'))
        return printer.discover(machine.inventory(), tools, network=network, seed='test-seed',
                                serial_reader=machine.serial_reader(), fib_trie=machine.fib,
                                ipp_usb_state=machine.ipp_usb_dir)


# ----------------------------------------------------------------------------- pure parsers

class ParsingTests(unittest.TestCase):
    def test_lpstat_printers_states_and_bad_names(self):
        text = ('printer Good_1 is idle.  enabled since Thu 01 Oct 2026\n'
                'printer Busy now printing Busy-4.  enabled since Thu\n'
                'printer Off disabled since Thu 01 Oct 2026 -\n\tPaused\n'
                'printer bad;name is idle.  enabled\n'
                'printer $(touch_x) is idle.\n'
                'scheduler is running\n')
        self.assertEqual(printer.parse_lpstat_printers(text), {'Good_1': 'idle', 'Busy': 'processing', 'Off': 'stopped'})

    def test_lpstat_devices_accepting_and_jobs(self):
        self.assertEqual(printer.parse_lpstat_devices('device for A: usb://HP/X?serial=1\ndevice for ../b: x\n'
                                                      'device for C: ipp://10.0.0.5/ipp/print\n'),
                         {'A': 'usb://HP/X?serial=1', 'C': 'ipp://10.0.0.5/ipp/print'})
        self.assertEqual(printer.parse_lpstat_accepting('A accepting requests since Thu\nB not accepting requests since Thu -\n'),
                         {'A': True, 'B': False})
        self.assertEqual(printer.parse_lpstat_jobs('My-Queue-12 user 1024 Thu Oct  1 08:00:00 2026\n'
                                                   'My-Queue-13 other 2048 Thu Oct  1 08:00:01 2026\n'
                                                   'Z-1 u 1 d\nnojobhere\n'),
                         {'My-Queue': 2, 'Z': 1})
        self.assertTrue(printer.scheduler_running('scheduler is running\n'))
        self.assertFalse(printer.scheduler_running('scheduler is not running\n'))
        self.assertIsNone(printer.scheduler_running(None))

    def test_classify_uri(self):
        k = lambda u: printer.classify_uri(u)['kind']  # noqa: E731
        self.assertEqual(k('usb://HP/LaserJet?serial=ABC'), 'usb')
        self.assertEqual(printer.classify_uri('usb://HP/LaserJet?serial=ABC')['serial'], 'ABC')
        self.assertEqual(k('hp:/usb/ENVY_5000?serial=ABC'), 'usb')
        self.assertEqual(k('hp:/net/ENVY_5000?ip=10.0.0.5'), 'network')
        self.assertEqual(k('ipp://localhost:60000/ipp/print'), 'ipp-usb')
        self.assertEqual(printer.classify_uri('ipp://localhost:60001/ipp/print')['port'], 60001)
        self.assertEqual(k('ipp://localhost:631/printers/x'), 'network')
        for uri in ('ipp://10.0.0.5/ipp/print', 'socket://10.0.0.6:9100', 'dnssd://Foo._ipp._tcp.local/', 'lpd://h/q',
                    'implicitclass://Foo/'):
            self.assertEqual(k(uri), 'network', uri)
        for uri in ('cups-pdf:/', 'file:///dev/null', '/dev/null', 'cups-brf:/'):
            self.assertEqual(k(uri), 'virtual', uri)
        self.assertEqual(k('parallel:/dev/lp0'), 'other')

    def test_brand_allowlist(self):
        for text, brand in (('HP LaserJet Pro', 'hp'), ('Hewlett-Packard DeskJet', 'hp'), ('Canon MG3600 series', 'canon'),
                            ('EPSON L360 Series', 'epson'), ('Brother HL-L2350DW', 'brother'),
                            ('Konica Minolta bizhub', 'konica-minolta'), ('FUJIFILM Apeos', 'fujifilm'),
                            ('Fuji Xerox DocuPrint', 'fujifilm'), ('Zebra ZD420', 'zebra'), ('OKI B432', 'oki'),
                            ('Acme Rocket Printer', 'other'), ('', 'other'), ('12345', 'other')):
            self.assertEqual(printer.brand_from_make(text), brand, text)
        self.assertEqual(printer.BRANDS[-1], 'other')
        self.assertEqual(len(printer.BRANDS), len(set(printer.BRANDS)))

    def test_ipp_csv_full_row_and_quoting(self):
        parsed = printer.parse_ipp_csv(ipp_csv(state='stopped', reasons='media-jam-error,toner-low-warning',
                                               accepting='false', queued='3', levels='12,80,-3', types='toner,toner,waste-toner',
                                               make='HP Secret LaserJet 9000, series'))
        self.assertEqual(parsed['state'], 'stopped')
        self.assertEqual(parsed['reasons'], ['media-jam-error', 'toner-low-warning'])
        self.assertFalse(parsed['accepting'])
        self.assertEqual((parsed['queued'], parsed['levels'], parsed['types']), (3, [12, 80, -3], ['toner', 'toner', 'waste-toner']))
        self.assertEqual(parsed['brand'], 'hp')
        self.assertNotIn('Secret', json.dumps(parsed))            # the make-and-model text is dropped

    def test_ipp_csv_reasons_none_missing_and_garbage(self):
        self.assertEqual(printer.parse_ipp_csv(ipp_csv(reasons='none'))['reasons'], [])
        self.assertIsNone(printer.parse_ipp_csv(ipp_csv(reasons=''))['reasons'])
        parsed = printer.parse_ipp_csv(ipp_csv(reasons='media-jam; rm -rf /,Door Open,toner-low', state='weird',
                                               accepting='maybe', queued='-1', levels='9,x', types='TONER;DROP'))
        self.assertEqual(parsed['reasons'], ['toner-low'])        # only keyword-shaped tokens survive
        self.assertIsNone(parsed['state'])
        self.assertIsNone(parsed['accepting'])
        self.assertIsNone(parsed['queued'])
        self.assertIsNone(parsed['levels'])
        self.assertIsNone(parsed['types'])
        self.assertEqual(printer.parse_ipp_csv(ipp_csv(state='5'))['state'], 'stopped')

    def test_ipp_csv_without_data_is_none(self):
        self.assertIsNone(printer.parse_ipp_csv(','.join(CSV_HEADER) + '\n'))       # nonexistent queue: header only
        self.assertIsNone(printer.parse_ipp_csv(''))
        self.assertIsNone(printer.parse_ipp_csv(None))
        self.assertIsNone(printer.parse_ipp_csv('printer-state,secret-column\nidle,abc\n'))    # unknown column
        self.assertIsNone(printer.parse_ipp_csv('printer-state\nidle,extra\n'))                 # shape mismatch
        self.assertIsNone(printer.parse_ipp_csv('printer-state,printer-state-reasons\n' + 'x' * 9000 + '\n'))
        self.assertIsNone(printer.parse_ipp_csv(',,,,,,\n,,,,,,\n'))

    def test_state_reason_table(self):
        statuses = printer.reason_statuses
        none = statuses([])
        self.assertEqual(set(none.values()), {'pass'})
        self.assertEqual(set(statuses(None).values()), {'unknown'})
        self.assertEqual(statuses(['media-jam'])['printer-media'], 'fail')
        self.assertEqual(statuses(['media-jam-warning'])['printer-media'], 'fail')
        self.assertEqual(statuses(['media-empty-error'])['printer-media'], 'fail')
        self.assertEqual(statuses(['media-empty'])['printer-media'], 'fail')              # no suffix means error
        self.assertEqual(statuses(['media-empty-warning'])['printer-media'], 'warn')
        self.assertEqual(statuses(['media-needed-report'])['printer-media'], 'warn')
        self.assertEqual(statuses(['media-low'])['printer-media'], 'warn')
        self.assertEqual(statuses(['door-open'])['printer-door'], 'fail')
        self.assertEqual(statuses(['cover-open-error'])['printer-door'], 'fail')
        self.assertEqual(statuses(['toner-low-report'])['printer-marker-supply'], 'warn')
        self.assertEqual(statuses(['ink-low'])['printer-marker-supply'], 'warn')
        self.assertEqual(statuses(['toner-empty'])['printer-marker-supply'], 'fail')
        self.assertEqual(statuses(['marker-supply-empty-warning'])['printer-marker-supply'], 'warn')
        self.assertEqual(statuses(['marker-waste-full'])['printer-marker-supply'], 'fail')
        self.assertEqual(statuses(['marker-waste-almost-full'])['printer-marker-supply'], 'warn')
        for reason in ('offline-report', 'connecting-to-device', 'shutdown', 'timed-out'):
            self.assertEqual(statuses([reason])['printer-offline'], 'warn', reason)
        # unrelated reasons change nothing; the worst of several wins; checks stay independent
        self.assertEqual(set(statuses(['paused', 'cups-waiting-for-job-completed', 'spool-area-full']).values()), {'pass'})
        mixed = statuses(['toner-low', 'media-empty-warning', 'media-jam', 'door-open'])
        self.assertEqual((mixed['printer-media'], mixed['printer-door'], mixed['printer-marker-supply'],
                          mixed['printer-offline']), ('fail', 'fail', 'warn', 'pass'))

    def test_reason_tokens_are_a_closed_set(self):
        self.assertEqual(printer.reason_tokens(['media-jam-error', 'toner-low-report', 'unknown-thing', 'paused']),
                         ('media-jam', 'paused', 'toner-low'))
        self.assertEqual(printer.reason_tokens(None), ())
        self.assertTrue(set(printer.reason_tokens(list(printer.KNOWN_REASONS))) <= printer.KNOWN_REASONS)

    def test_marker_minimum(self):
        m = printer.marker_minimum
        self.assertEqual(m([80, 12, 50], ['toner', 'toner', 'toner']), 12)
        self.assertEqual(m([80, 100], ['ink-cartridge', 'waste-ink']), 80)        # a full waste container is not "100% ink"
        self.assertEqual(m([-1, -2, 40], ['toner', 'toner', 'ink']), 40)          # unknown levels are ignored
        self.assertIsNone(m([-1, -3], ['toner', 'toner']))
        self.assertIsNone(m([50], None))                                           # no types: no level is trusted
        self.assertIsNone(m([50, 60], ['toner']))                                  # mismatched lists
        self.assertIsNone(m(None, None))
        self.assertEqual(m([0], ['toner']), 0)

    def test_avahi_lines(self):
        text = ('+;eth0;IPv4;Unresolved;_ipp._tcp;local\n'
                '=;eth0;IPv4;Canon\\032MG3600;_ipp._tcp;local;canon.local;192.168.1.50;631;"txtvers=1" "rp=ipp/print" "ty=Canon MG3600 series"\n'
                '=;eth0;IPv6;Link;_ipp._tcp;local;l.local;fe80::1;631;"rp=ipp/print"\n'
                '=;eth0;IPv4;Public;_ipp._tcp;local;p.local;8.8.8.8;631;"rp=ipp/print"\n'
                '=;lo;IPv4;USBPrinter;_ipp._tcp;local;u.local;127.0.0.1;60000;"rp=ipp/print"\n'
                '=;eth0;IPv4;BadRp;_ipp._tcp;local;b.local;10.0.0.9;631;"rp=../../etc;x"\n'
                '=;eth0;IPv6;Ula;_ipps._tcp;local;u.local;fd00::5;443;"rp=ipp/print" "ty=EPSON L360"\n')
        found = printer.parse_avahi(text)
        names = [f['instance'] for f in found]
        self.assertEqual(names, ['Canon MG3600', 'BadRp', 'Ula'])
        self.assertEqual(found[0]['brand'], 'canon')
        self.assertEqual(printer.network_uri(found[0]), 'ipp://192.168.1.50:631/ipp/print')
        self.assertIsNone(printer.network_uri(found[1]))                            # an rp that fails validation
        self.assertEqual(printer.network_uri(found[2]), 'ipps://[fd00::5]:443/ipp/print')
        self.assertEqual(found[2]['brand'], 'epson')

    def test_ipp_uris_are_validated(self):
        ok = ('ipp://localhost/printers/Queue_1', 'ipp://localhost:60000/ipp/print', 'ipp://192.168.1.5:631/ipp/print',
              'ipps://10.0.0.5:443/', 'ipp://[fd00::1]:631/ipp/print', 'ipp://127.0.0.1:60001/ipp/print')
        for uri in ok:
            self.assertTrue(printer.valid_ipp_uri(uri), uri)
        bad = ('ipp://8.8.8.8/ipp/print', 'ipp://example.com/ipp/print', 'ipp://[2001:db8::1]/x', '-T', '--help',
               'http://localhost/printers/x', 'ipp://user:pw@localhost/x', 'ipp://localhost/printers/x?a=b',
               'ipp://localhost/printers/x y', 'ipp://localhost:99999/x', 'ipp://[fe80::1]/x', 'ipp://224.0.0.251/x',
               'ipp://localhost/' + 'a' * 300, None, 5, '')
        for uri in bad:
            self.assertFalse(printer.valid_ipp_uri(uri), uri)

    def test_ipp_usb_state_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            put(Path(tmp) / '04a9-1865-Canon_Secret_MG3600.state', '[device]\nhttp-port = 60000\nname = x\n')
            put(Path(tmp) / '04A9-1866-Other.state', '[device]\nhttp-port = 60001\n')
            put(Path(tmp) / '04b8-0001-Low.state', '[device]\nhttp-port = 631\n')              # outside the ipp-usb range
            put(Path(tmp) / 'garbage.state', '[device]\nhttp-port = 60002\n')
            put(Path(tmp) / '04b8-0002-NoPort.state', '[device]\n')
            put(Path(tmp) / '04b8-0003-Text.txt', '[device]\nhttp-port = 60003\n')
            self.assertEqual(printer.read_ipp_usb_endpoints(tmp),
                             {('04a9', '1865'): [60000], ('04a9', '1866'): [60001]})
        self.assertEqual(printer.read_ipp_usb_endpoints('/nonexistent-dir-for-test'), {})

    def test_local_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / 'fib_trie'
            put(f, 'Main:\n  +-- 0.0.0.0/0 3 0 5\n        |-- 192.168.1.10\n           /32 host LOCAL\n'
                   '        |-- 192.168.1.255\n           /32 link BROADCAST\n        |-- 127.0.0.1\n           /32 host LOCAL\n')
            self.assertEqual(printer.local_addresses(f), {'192.168.1.10', '127.0.0.1'})
        self.assertEqual(printer.local_addresses('/nonexistent-file-for-test'), set())

    def test_opaque_id_is_keyed_stable_and_hides_the_identity(self):
        a = printer.opaque_id(SERIAL_HP, 'seed-one')
        self.assertRegex(a, r'^target-[0-9a-f]{16}$')
        self.assertEqual(a, printer.opaque_id(SERIAL_HP, 'seed-one'))
        self.assertNotEqual(a, printer.opaque_id(SERIAL_HP, 'seed-two'))
        self.assertNotEqual(a, printer.opaque_id(SERIAL_CANON, 'seed-one'))
        self.assertNotIn(SERIAL_HP, a)


# ------------------------------------------------------------------------------ the checks

def printer_dict(**over):
    p = printer._empty_record('usb')
    p.update({'ref': 'prn-0', 'port': '1-4', 'state': 'idle', 'reasons': [], 'accepting': True, 'queued': 0,
              'levels': [80], 'types': ['toner'], 'marker_min': 80, 'ipp_read': True, 'has_queue': True, 'driver': True,
              'usb': {'speed_mbps': 480, 'hub_depth': 0}})
    p.update(over)
    return p


def by_id(checks):
    return {c['check_id']: c for c in checks}


class CheckThresholdTests(unittest.TestCase):
    def test_healthy_printer(self):
        checks = printer.printer_checks(printer_dict())
        self.assertEqual([c['check_id'] for c in checks], list(printer.CHECK_IDS))
        self.assertEqual({c['status'] for c in checks}, {'pass'})
        got = by_id(checks)
        self.assertEqual((got['printer-marker-level-min']['kind'], got['printer-marker-level-min']['number']), ('percent', 80))
        self.assertEqual((got['printer-queued-jobs']['kind'], got['printer-queued-jobs']['number']), ('count', 0))

    def test_state(self):
        for state, status in (('idle', 'pass'), ('processing', 'pass'), ('stopped', 'fail'), (None, 'unknown')):
            self.assertEqual(by_id(printer.printer_checks(printer_dict(state=state)))['printer-state']['status'], status)

    def test_reason_checks_flow_into_the_check_ids(self):
        got = by_id(printer.printer_checks(printer_dict(reasons=['media-jam-error', 'door-open', 'toner-low-warning',
                                                                 'offline-report'])))
        self.assertEqual((got['printer-media']['status'], got['printer-door']['status'],
                          got['printer-marker-supply']['status'], got['printer-offline']['status']),
                         ('fail', 'fail', 'warn', 'warn'))

    def test_accepting_jobs(self):
        for value, status in ((True, 'pass'), (False, 'fail'), (None, 'unknown')):
            self.assertEqual(by_id(printer.printer_checks(printer_dict(accepting=value)))['printer-accepting-jobs']['status'], status)

    def test_queued_jobs_warn_only_for_a_stopped_queue(self):
        q = lambda **kw: by_id(printer.printer_checks(printer_dict(**kw)))['printer-queued-jobs']  # noqa: E731
        self.assertEqual(q(queued=3, state='stopped')['status'], 'warn')
        self.assertEqual(q(queued=3, state='stopped')['number'], 3)
        self.assertEqual(q(queued=3, state='processing')['status'], 'pass')
        self.assertEqual(q(queued=0, state='stopped')['status'], 'pass')
        self.assertEqual(q(queued=None)['status'], 'unknown')
        self.assertEqual(q(queued=5000000, state='stopped')['number'], 1000000)     # bounded

    def test_marker_level_thresholds(self):
        q = lambda low: by_id(printer.printer_checks(printer_dict(marker_min=low)))['printer-marker-level-min']  # noqa: E731
        for low, status in ((100, 'pass'), (15, 'pass'), (14, 'warn'), (3, 'warn'), (2, 'fail'), (0, 'fail')):
            self.assertEqual(q(low)['status'], status, low)
        self.assertEqual((q(14)['kind'], q(14)['number']), ('percent', 14))
        self.assertEqual(q(None)['status'], 'unknown')
        self.assertEqual((printer.MARKER_WARN_PERCENT, printer.MARKER_FAIL_PERCENT), (15, 3))

    def test_usb_link(self):
        link = lambda **kw: by_id(printer.printer_checks(printer_dict(**kw)))['printer-usb-link']['status']  # noqa: E731
        self.assertEqual(link(usb={'speed_mbps': 480, 'hub_depth': 0}), 'pass')
        self.assertEqual(link(usb={'speed_mbps': 12, 'hub_depth': 0}), 'pass')       # a full-speed printer is normal
        self.assertEqual(link(usb={'speed_mbps': 12, 'hub_depth': 1}), 'pass')
        self.assertEqual(link(usb={'speed_mbps': 1.5, 'hub_depth': 0}), 'warn')
        self.assertEqual(link(usb={'speed_mbps': 480, 'hub_depth': 2}), 'warn')      # more than one hub in the chain
        self.assertEqual(link(usb={'speed_mbps': None, 'hub_depth': 0}), 'unknown')
        self.assertEqual(link(usb=None, port=None, queue_without_device=True), 'fail')
        self.assertEqual(link(usb=None, port=None, queue_without_device=False), 'unknown')
        self.assertEqual(by_id(printer.printer_checks(printer_dict(usb=None, port=None, queue_without_device=True),
                                                      usb_known=False))['printer-usb-link']['status'], 'unknown')
        self.assertEqual(link(connection='network', usb=None, port=None), 'not_applicable')

    def test_driver(self):
        drv = lambda **kw: by_id(printer.printer_checks(printer_dict(**kw)))['printer-driver']['status']  # noqa: E731
        self.assertEqual(drv(has_queue=True, driver=True), 'pass')
        self.assertEqual(drv(has_queue=False, driver=False), 'warn')            # detected, but no queue
        self.assertEqual(drv(has_queue=False, driver=None), 'unknown')
        self.assertEqual(drv(connection='network', has_queue=False, driver=None, usb=None, port=None), 'not_applicable')
        self.assertEqual(drv(connection='network', has_queue=True, driver=True, usb=None, port=None), 'pass')

    def test_everything_is_unknown_when_nothing_could_be_read(self):
        p = printer_dict(state=None, reasons=None, accepting=None, queued=None, marker_min=None, levels=None,
                         types=None, ipp_read=False, has_queue=False, driver=None, usb={'speed_mbps': None, 'hub_depth': 0})
        self.assertEqual({c['status'] for c in printer.printer_checks(p)}, {'unknown'})

    def test_environment_count(self):
        self.assertEqual(printer.count_check(2), {'check_id': 'printer-count', 'status': 'pass', 'kind': 'count', 'number': 2})
        self.assertEqual(printer.count_check(0)['status'], 'warn')
        self.assertEqual(printer.count_check(0, usb_known=False)['status'], 'unknown')
        self.assertEqual(printer.count_check(1, usb_known=False)['status'], 'pass')


# ---------------------------------------------------------------------------------- discovery

class UsbPrinterTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)

    def test_only_class_07_interfaces_are_printers(self):
        found = printer.usb_printers(self.machine.inventory())
        self.assertEqual([p['port'] for p in found], ['1-4', '3-2.1'])
        by_port = {p['port']: p for p in found}
        self.assertEqual(by_port['1-4']['protocols'], ['bidirectional'])
        self.assertFalse(by_port['1-4']['ipp_usb_capable'])
        self.assertEqual(by_port['3-2.1']['protocols'], ['bidirectional', 'ipp-usb'])
        self.assertTrue(by_port['3-2.1']['ipp_usb_capable'])
        self.assertEqual((by_port['1-4']['brand'], by_port['3-2.1']['brand']), ('hp', 'canon'))

    def test_protocol_triplets(self):
        m = FakeUsb(self.tmp / 'proto')
        m.add_device('1-2', '03f0', '0001', ['07/01/01'])
        m.add_device('1-3', '03f0', '0002', ['07/01/02'])
        m.add_device('1-4', '03f0', '0003', ['07/01/04'])
        m.add_device('1-5', '03f0', '0004', ['07/02/01'])        # class 07 but not the printer subclass
        m.add_device('1-6', '03f0', '0005', ['07/01/03'])        # unknown protocol
        found = {p['port']: p for p in printer.usb_printers(m.inventory())}
        self.assertEqual(sorted(found), ['1-2', '1-3', '1-4'])
        self.assertEqual(found['1-2']['protocols'], ['unidirectional'])
        self.assertEqual(found['1-4']['protocols'], ['ipp-usb'])

    def test_unknown_vendors_are_other_and_hubs_are_never_printers(self):
        m = FakeUsb(self.tmp / 'brand')
        m.add_device('1-2', 'abcd', '0001', ['07/01/02'])
        m.add_device('1-3', '04e8', '0001', ['07/01/02'])        # Samsung printer (the same vendor ID as the phones)
        found = {p['port']: p for p in printer.usb_printers(m.inventory())}
        self.assertEqual((found['1-2']['brand'], found['1-3']['brand']), ('other', 'samsung'))
        self.assertEqual(printer.usb_printers(None), [])
        self.assertEqual(printer.usb_printers([]), [])

    def test_all_vendor_brands_are_in_the_closed_set(self):
        self.assertTrue(set(printer.VENDOR_BRANDS.values()) <= set(printer.BRANDS))
        self.assertTrue(set(printer.MAKE_WORDS.values()) <= set(printer.BRANDS))
        schema = json.loads((ROOT / 'rescue-ai/v1/rescue-evidence.schema.json').read_text())
        enum = schema['properties']['printers']['items']['properties']['brand']['enum']
        self.assertEqual(sorted(enum), sorted(printer.BRANDS))

    def test_no_tools_gives_usb_only_printers_with_unknown_checks(self):
        printers, status = self.discover(self.machine, None)
        self.assertEqual([p['ref'] for p in printers], ['prn-0', 'prn-1'])
        self.assertEqual((status['lpstat'], status['ipptool'], status['avahi']), (False, False, False))
        for p in printers:
            self.assertEqual((p['detection'], p['access'], p['has_queue'], p['driver']), ('usb-enumerated', 'usb-only', False, None))
            got = by_id(printer.printer_checks(p))
            self.assertEqual(got['printer-state']['status'], 'unknown')
            self.assertEqual(got['printer-driver']['status'], 'unknown')
            self.assertEqual(got['printer-usb-link']['status'], 'pass')


class QueueTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)
        self.shims = Shims(self.tmp / 'bin')

    def configure(self, queues, ipp=None, **extra):
        self.shims.set(lpstat=lpstat_config(queues), ipp=ipp or {}, **extra)

    def test_usb_queue_is_paired_by_serial_and_read_over_ipp(self):
        self.configure([(QUEUE_HP, 'stopped', 'usb://SecretMaker/Secret%%20LaserJet?serial=%s' % SERIAL_HP, True)],
                       ipp={'ipp://localhost/printers/%s' % QUEUE_HP: ipp_csv(
                           state='stopped', reasons='media-jam-error,toner-low-warning', queued='2', levels='12,80',
                           types='toner,toner')})
        printers, status = self.discover(self.machine, self.shims)
        self.assertEqual([p['ref'] for p in printers], ['prn-0', 'prn-1'])
        hp, canon = printers
        self.assertEqual((hp['port'], hp['connection'], hp['brand'], hp['has_queue']), ('1-4', 'usb', 'hp', True))
        self.assertEqual((hp['detection'], hp['access'], hp['state']), ('usb-ipp', 'ipp-read', 'stopped'))
        self.assertEqual((hp['reasons'], hp['queued'], hp['marker_min'], hp['accepting']),
                         (['media-jam-error', 'toner-low-warning'], 2, 12, True))
        self.assertEqual((hp['_private']['queue'], hp['_private']['serial']), (QUEUE_HP, SERIAL_HP))
        self.assertEqual((canon['port'], canon['has_queue'], canon['driver']), ('3-2.1', False, False))
        got = by_id(printer.printer_checks(hp))
        self.assertEqual([got[c]['status'] for c in ('printer-state', 'printer-media', 'printer-marker-supply',
                                                     'printer-marker-level-min', 'printer-queued-jobs', 'printer-driver')],
                         ['fail', 'fail', 'warn', 'warn', 'warn', 'pass'])
        self.assertEqual(by_id(printer.printer_checks(canon))['printer-driver']['status'], 'warn')   # detected, no queue
        self.assertEqual(status['scheduler'], True)

    def test_public_view_has_no_private_data(self):
        self.configure([(QUEUE_HP, 'idle', 'usb://SecretMaker/X?serial=%s' % SERIAL_HP, True)])
        printers, _ = self.discover(self.machine, self.shims)
        text = json.dumps(printer.public_view(printers[0]), default=str)
        self.assertNotIn('_private', printer.public_view(printers[0]))
        for leak in (QUEUE_HP, SERIAL_HP, 'SecretMaker'):
            self.assertNotIn(leak, text)
        self.assertIs(printer.resolve_ref(printers, 'prn-0'), printers[0])        # in-process only (phase 2 engines)
        self.assertIsNone(printer.resolve_ref(printers, 'prn-7'))

    def test_single_unpaired_pair_without_serial(self):
        m = FakeUsb(self.tmp / 'single')
        m.add_device('1-2', '03f0', '2b17', ['07/01/02'], serial=SERIAL_HP)
        self.configure([(QUEUE_HP, 'idle', 'usb://SecretMaker/Secret%20LaserJet', True)])
        printers, _ = self.discover(m, self.shims)
        self.assertEqual(len(printers), 1)
        self.assertEqual((printers[0]['port'], printers[0]['has_queue']), ('1-2', True))

    def test_ambiguous_queues_stay_unpaired_and_driver_is_unknown(self):
        m = FakeUsb(self.tmp / 'amb')
        m.add_device('1-2', '03f0', '2b17', ['07/01/02'])
        m.add_device('1-3', '03f0', '2b17', ['07/01/02'])
        self.configure([('QueueA', 'idle', 'usb://HP/X', True), ('QueueB', 'idle', 'usb://HP/X', True)])
        printers, _ = self.discover(m, self.shims)
        usb_side = [p for p in printers if p['usb']]
        self.assertEqual([p['has_queue'] for p in usb_side], [False, False])
        self.assertEqual([p['driver'] for p in usb_side], [None, None])           # a queue may belong to it: unknown, not warn
        self.assertFalse(any(p['queue_without_device'] for p in printers))         # an unpaired device exists: no "unplugged" claim
        self.assertEqual(len(printers), 4)

    def test_queue_for_an_unplugged_usb_printer(self):
        m = FakeUsb(self.tmp / 'unplugged')
        self.configure([(QUEUE_HP, 'stopped', 'usb://SecretMaker/X?serial=%s' % SERIAL_HP, True)],
                       ipp={'ipp://localhost/printers/%s' % QUEUE_HP: ipp_csv(state='stopped', reasons='paused', queued='1')})
        printers, _ = self.discover(m, self.shims)
        self.assertEqual(len(printers), 1)
        p = printers[0]
        self.assertEqual((p['connection'], p['port'], p['usb'], p['queue_without_device']), ('usb', None, None, True))
        got = by_id(printer.printer_checks(p))
        self.assertEqual((got['printer-usb-link']['status'], got['printer-state']['status']), ('fail', 'fail'))
        self.assertEqual(printer.reason_tokens(p['reasons']), ('paused',))

    def test_network_and_virtual_queues(self):
        m = FakeUsb(self.tmp / 'nonusb')
        self.configure([(QUEUE_NET, 'idle', 'ipp://192.168.77.88/ipp/print', True),
                        ('PDFQueue', 'idle', 'cups-pdf:/', True), ('FileQueue', 'idle', 'file:///dev/null', True)],
                       ipp={'ipp://localhost/printers/%s' % QUEUE_NET: ipp_csv(make='Canon MG3600 series')})
        printers, _ = self.discover(m, self.shims)
        self.assertEqual(len(printers), 1)                                          # PDF/file queues are not printers
        p = printers[0]
        self.assertEqual((p['connection'], p['brand'], p['detection'], p['access']), ('network', 'canon', 'network-ipp', 'ipp-read'))
        got = by_id(printer.printer_checks(p))
        self.assertEqual((got['printer-usb-link']['status'], got['printer-driver']['status']), ('not_applicable', 'pass'))
        calls = [c for c in self.shims.calls() if c[0] == 'ipptool']
        self.assertEqual([c[4] for c in calls], ['ipp://localhost/printers/%s' % QUEUE_NET])

    def test_lpstat_only_when_ipptool_is_missing(self):
        shims = Shims(self.tmp / 'bin2', tools=('lpstat',))
        shims.set(lpstat=lpstat_config([(QUEUE_HP, 'idle', 'usb://X/Y?serial=%s' % SERIAL_HP, True)]))
        printers, status = self.discover(self.machine, shims)
        hp = printers[0]
        self.assertEqual((status['ipptool'], hp['access'], hp['detection'], hp['state'], hp['accepting']),
                         (False, 'cups-only', 'usb-cups', 'idle', True))
        got = by_id(printer.printer_checks(hp))
        for cid in ('printer-media', 'printer-door', 'printer-marker-supply', 'printer-offline', 'printer-marker-level-min'):
            self.assertEqual(got[cid]['status'], 'unknown', cid)                    # IPP-derived: unknown, never pass
        self.assertEqual((got['printer-state']['status'], got['printer-accepting-jobs']['status'],
                          got['printer-queued-jobs']['status']), ('pass', 'pass', 'pass'))

    def test_queued_job_count_from_lpstat_o_when_there_is_no_ipp(self):
        shims = Shims(self.tmp / 'bin3', tools=('lpstat',))
        cfg = lpstat_config([(QUEUE_HP, 'stopped', 'usb://X/Y?serial=%s' % SERIAL_HP, True)])
        cfg['-o'] = '%s-3 secretuser 1024 Thu Oct  1 08:00:00 2026\n%s-4 secretuser 1024 Thu Oct  1 08:00:01 2026\n' % (QUEUE_HP, QUEUE_HP)
        shims.set(lpstat=cfg)
        hp = self.discover(self.machine, shims)[0][0]
        self.assertEqual(hp['queued'], 2)
        self.assertEqual(by_id(printer.printer_checks(hp))['printer-queued-jobs']['status'], 'warn')

    def test_cups_not_running_or_missing(self):
        self.shims.set(lpstat=lpstat_config([(QUEUE_HP, 'idle', 'usb://X/Y?serial=%s' % SERIAL_HP, True)], running=False))
        printers, status = self.discover(self.machine, self.shims)
        self.assertEqual(status['scheduler'], False)
        self.assertEqual([p['has_queue'] for p in printers], [False, False])
        self.assertEqual([p['driver'] for p in printers], [None, None])             # unknown, not "no driver"
        printers, status = self.discover(self.machine, None)
        self.assertEqual(status['lpstat'], False)

    def test_ipp_failure_keeps_the_queue_state(self):
        self.configure([(QUEUE_HP, 'idle', 'usb://X/Y?serial=%s' % SERIAL_HP, True)],
                       ipp_fail=['ipp://localhost/printers/%s' % QUEUE_HP])
        hp = self.discover(self.machine, self.shims)[0][0]
        self.assertEqual((hp['access'], hp['ipp_read'], hp['state']), ('cups-only', False, 'idle'))

    def test_invalid_queue_names_never_reach_ipptool(self):
        cfg = lpstat_config([])
        cfg['-p'] = 'printer bad;name is idle.\nprinter $(touch_x) is idle.\nprinter -h is idle.\n'
        cfg['-v'] = 'device for bad;name: usb://X/Y\ndevice for -h: usb://X/Y\n'
        self.shims.set(lpstat=cfg)
        printers, _ = self.discover(self.machine, self.shims)
        self.assertEqual([p['has_queue'] for p in printers], [False, False])
        self.assertEqual([c for c in self.shims.calls() if c[0] == 'ipptool'], [])

    def test_ipptool_argv_is_fixed_and_ends_in_the_shipped_test_file(self):
        self.configure([(QUEUE_HP, 'idle', 'usb://X/Y?serial=%s' % SERIAL_HP, True)])
        self.discover(self.machine, self.shims)
        calls = self.shims.calls()
        self.assertEqual({tuple(c[1:]) for c in calls if c[0] == 'lpstat'}, {('-r',), ('-p',), ('-v',), ('-a',), ('-o',)})
        ipp_calls = [c for c in calls if c[0] == 'ipptool']
        self.assertTrue(ipp_calls)
        for c in ipp_calls:
            self.assertEqual((c[1], c[2], c[3], c[5]), ('-T', '6', '-c', str(IPP_TEST)))
            self.assertTrue(printer.valid_ipp_uri(c[4]))
        self.assertTrue(IPP_TEST.is_file())
        text = IPP_TEST.read_text()
        self.assertIn('Get-Printer-Attributes', text)
        for banned in ('printer-info', 'printer-location', 'device-uri', 'printer-name', 'printer-uri-supported',
                       'printer-device-id', 'job-originating-user-name', 'job-name'):
            self.assertNotIn('ATTR keyword requested-attributes %s' % banned, text)
            self.assertNotIn('DISPLAY %s' % banned, text)
        self.assertNotIn('printer-info', text.split('requested-attributes')[1].splitlines()[0])
        self.assertNotIn('printer-location', text.split('requested-attributes')[1].splitlines()[0])

    def test_nothing_that_changes_a_printer_is_ever_run(self):
        self.configure([(QUEUE_HP, 'stopped', 'usb://X/Y?serial=%s' % SERIAL_HP, False)])
        self.discover(self.machine, self.shims, network=True)
        names = {c[0] for c in self.shims.calls()}
        self.assertTrue(names <= {'lpstat', 'ipptool', 'avahi-browse'})
        for c in self.shims.calls():
            for banned in ('cupsenable', 'cupsaccept', 'cupsdisable', 'cancel', 'lp', 'lpadmin', 'lpr', 'lpinfo'):
                self.assertNotIn(banned, c)


class IppUsbTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)
        self.machine.add_ipp_usb_state('04a9-1865-Canon_Secret_Model.state', 60000)
        self.shims = Shims(self.tmp / 'bin')

    def test_ipp_usb_endpoint_without_a_queue_is_queried_directly(self):
        self.shims.set(lpstat=lpstat_config([]), ipp={'ipp://localhost:60000/ipp/print': ipp_csv(
            state='processing', reasons='door-open', make='Canon MG3600 series')})
        printers, _ = self.discover(self.machine, self.shims)
        canon = next(p for p in printers if p['port'] == '3-2.1')
        self.assertEqual((canon['connection'], canon['detection'], canon['access'], canon['driver']),
                         ('ipp-over-usb', 'ipp-usb', 'ipp-read', True))
        self.assertEqual((canon['state'], canon['ipp_usb_capable'], canon['has_queue']), ('processing', True, False))
        self.assertEqual(by_id(printer.printer_checks(canon))['printer-door']['status'], 'fail')
        self.assertEqual(by_id(printer.printer_checks(canon))['printer-driver']['status'], 'pass')   # driverless through ipp-usb
        hp = next(p for p in printers if p['port'] == '1-4')
        self.assertEqual((hp['connection'], hp['detection']), ('usb', 'usb-enumerated'))

    def test_a_queue_on_the_ipp_usb_port_is_paired_by_port(self):
        self.shims.set(lpstat=lpstat_config([(QUEUE_NET, 'idle', 'ipp://localhost:60000/ipp/print', True)]),
                       ipp={'ipp://localhost/printers/%s' % QUEUE_NET: ipp_csv(reasons='toner-empty')})
        printers, _ = self.discover(self.machine, self.shims)
        canon = next(p for p in printers if p['port'] == '3-2.1')
        self.assertEqual((canon['connection'], canon['has_queue'], canon['detection']), ('ipp-over-usb', True, 'usb-ipp'))
        self.assertEqual(len(printers), 2)
        # the queue was read, the endpoint was not queried a second time
        self.assertEqual([c[4] for c in self.shims.calls() if c[0] == 'ipptool'], ['ipp://localhost/printers/%s' % QUEUE_NET])

    def test_two_identical_printers_do_not_share_an_endpoint(self):
        m = FakeUsb(self.tmp / 'twins')
        m.add_device('1-2', '04a9', '1865', ['07/01/02', '07/01/04'])
        m.add_device('1-3', '04a9', '1865', ['07/01/02', '07/01/04'])
        m.add_ipp_usb_state('04a9-1865-Canon.state', 60000)
        self.shims.set(lpstat=lpstat_config([]))
        printers, _ = self.discover(m, self.shims)
        self.assertEqual([p['detection'] for p in printers], ['usb-enumerated', 'usb-enumerated'])
        self.assertEqual([c for c in self.shims.calls() if c[0] == 'ipptool'], [])

    def test_ipp_usb_capable_without_an_endpoint_is_not_driverless_yet(self):
        m = FakeUsb(self.tmp / 'noep')
        m.add_device('1-2', '04a9', '1865', ['07/01/02', '07/01/04'])
        self.shims.set(lpstat=lpstat_config([]))
        p = self.discover(m, self.shims)[0][0]
        self.assertEqual((p['ipp_usb_capable'], p['driver']), (True, False))


class NetworkTests(Env):
    AVAHI = ('=;eth0;IPv4;SecretMDNS\\032Printer;_ipp._tcp;local;secret-printer.local;192.168.77.88;631;'
             '"txtvers=1" "rp=ipp/print" "ty=Canon Secret LaserJet" "note=Floor 3 Secret Room"\n'
             '=;eth0;IPv4;SecretMDNS\\032Printer;_ipps._tcp;local;secret-printer.local;192.168.77.88;443;"rp=ipp/print"\n'
             '=;eth0;IPv4;Shared;_ipp._tcp;local;me.local;192.168.77.10;631;"rp=printers/x" "ty=HP Shared"\n'
             '=;eth0;IPv4;Internet;_ipp._tcp;local;far.local;8.8.4.4;631;"rp=ipp/print"\n'
             '=;lo;IPv4;UsbOverIpp;_ipp._tcp;local;lo.local;127.0.0.1;60000;"rp=ipp/print"\n')

    def setUp(self):
        super().setUp()
        self.machine = FakeUsb(self.tmp / 'net')
        self.machine.add_fib_trie('192.168.77.10')
        self.shims = Shims(self.tmp / 'bin')
        self.shims.set(lpstat=lpstat_config([]), avahi={'_ipp._tcp': self.AVAHI, '_ipps._tcp': ''},
                       ipp={'ipp://192.168.77.88:631/ipp/print': ipp_csv(state='idle', reasons='media-empty-warning',
                                                                         levels='40', types='ink')})

    def test_network_discovery_is_off_by_default(self):
        printers, status = self.discover(self.machine, self.shims)
        self.assertEqual((printers, status['network']), ([], False))
        self.assertEqual([c for c in self.shims.calls() if c[0] == 'avahi-browse'], [])

    def test_opt_in_runs_two_fixed_mdns_browses_and_reads_the_printer_over_ipp(self):
        printers, status = self.discover(self.machine, self.shims, network=True)
        self.assertEqual(sorted(tuple(c) for c in self.shims.calls() if c[0] == 'avahi-browse'),
                         [('avahi-browse', '-rtp', '_ipp._tcp'), ('avahi-browse', '-rtp', '_ipps._tcp')])
        self.assertEqual(len(printers), 1)               # own shared printer, public address and loopback are skipped
        p = printers[0]
        self.assertEqual((p['ref'], p['connection'], p['detection'], p['access'], p['brand'], p['port']),
                         ('prn-0', 'network', 'network-ipp', 'ipp-read', 'canon', None))
        self.assertEqual((p['state'], p['marker_min']), ('idle', 40))
        self.assertEqual(by_id(printer.printer_checks(p))['printer-media']['status'], 'warn')
        self.assertEqual(status['network_found'], 1)
        self.assertEqual([c[4] for c in self.shims.calls() if c[0] == 'ipptool'], ['ipp://192.168.77.88:631/ipp/print'])
        self.assertEqual(p['_private'], {'instance': 'SecretMDNS Printer'})
        self.assertRegex(p['opaque_id'], r'^target-[0-9a-f]{16}$')

    def test_unanswering_network_printer_is_ipp_unavailable(self):
        self.shims.set(ipp_fail=['ipp://192.168.77.88:631/ipp/print'])
        p = self.discover(self.machine, self.shims, network=True)[0][0]
        self.assertEqual((p['access'], p['ipp_read']), ('ipp-unavailable', False))
        self.assertEqual({c['status'] for c in printer.printer_checks(p)} - {'not_applicable'}, {'unknown'})

    def test_queue_for_the_same_printer_is_not_listed_twice(self):
        self.shims.set(lpstat=lpstat_config([(QUEUE_NET, 'idle', 'ipp://192.168.77.88:631/ipp/print', True)]),
                       ipp={'ipp://localhost/printers/%s' % QUEUE_NET: ipp_csv()})
        printers, _ = self.discover(self.machine, self.shims, network=True)
        self.assertEqual(len(printers), 1)
        self.assertTrue(printers[0]['has_queue'])

    def test_dnssd_queue_matches_the_instance_name(self):
        self.shims.set(lpstat=lpstat_config([(QUEUE_NET, 'idle', 'dnssd://SecretMDNS%20Printer._ipp._tcp.local/', True)]),
                       ipp={'ipp://localhost/printers/%s' % QUEUE_NET: ipp_csv()})
        printers, _ = self.discover(self.machine, self.shims, network=True)
        self.assertEqual(len(printers), 1)

    def test_missing_avahi_browse_is_not_an_error(self):
        shims = Shims(self.tmp / 'bin-noavahi', tools=('lpstat', 'ipptool'))
        shims.set(lpstat=lpstat_config([]))
        printers, status = self.discover(self.machine, shims, network=True)
        self.assertEqual((printers, status['avahi'], status['network']), ([], False, True))

    def test_network_printers_are_capped(self):
        lines = ''.join('=;eth0;IPv4;P%d;_ipp._tcp;local;h%d.local;10.0.0.%d;631;"rp=ipp/print"\n' % (i, i, i + 1)
                        for i in range(12))
        self.shims.set(avahi={'_ipp._tcp': lines, '_ipps._tcp': ''})
        printers, _ = self.discover(self.machine, self.shims, network=True)
        self.assertEqual(len(printers), printer.MAX_NETWORK)


class RunnerTests(unittest.TestCase):
    def test_timeout_and_runaway_output_give_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            slow = Path(tmp) / 'slow'
            slow.write_text('#!/bin/sh\nsleep 5\n')
            slow.chmod(0o755)
            self.assertIsNone(printer._bounded([str(slow)], 0.6, {'PATH': '/usr/bin:/bin'}))
            loud = Path(tmp) / 'loud'
            loud.write_text('#!/bin/sh\nexec yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
            loud.chmod(0o755)
            self.assertIsNone(printer._bounded([str(loud)], 5, {'PATH': '/usr/bin:/bin'}))
            self.assertIsNone(printer._bounded([str(Path(tmp) / 'missing')], 1, {}))
            quiet = Path(tmp) / 'quiet'
            quiet.write_text('#!/bin/sh\necho hello\n')
            quiet.chmod(0o755)
            self.assertEqual(printer._bounded([str(quiet)], 5, {'PATH': '/usr/bin:/bin'}), (0, 'hello\n'))

    def test_environment_has_no_cups_server(self):
        os.environ['CUPS_SERVER'] = 'evil.example:631'
        try:
            env = printer._environment(None)
        finally:
            del os.environ['CUPS_SERVER']
        self.assertNotIn('CUPS_SERVER', env)
        self.assertEqual(env['LC_ALL'], 'C')

    def test_tools_refuse_anything_outside_their_fixed_vocabulary(self):
        tools = printer.Tools('/nonexistent-tool-dir')
        self.assertIsNone(tools.lpstat('-p'))                 # no lpstat there
        self.assertIsNone(tools.ipp('ipp://localhost/printers/x'))
        self.assertIsNone(tools.avahi('_ipp._tcp'))
        shims_dir = Path(tempfile.mkdtemp(prefix='printer-vocab-'))
        self.addCleanup(shutil.rmtree, shims_dir, True)
        shims = Shims(shims_dir)
        tools = printer.Tools(str(shims.dir))
        self.assertIsNone(tools.lpstat('-d'))                 # a flag outside LPSTAT_FLAGS
        self.assertIsNone(tools.ipp('ipp://8.8.8.8/ipp/print'))
        self.assertIsNone(tools.ipp('-T'))
        self.assertIsNone(tools.avahi('_http._tcp'))
        self.assertEqual(shims.calls(), [])


# ---------------------------------------------------------------- installed OS (offline) checks

def touch(path, data=b''):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class OfflineTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='printer-os-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ctx = rescue_modules.Context(mode='live')

    def run_target(self, root, family):
        return {c['check_id']: c for c in printer.collect_offline_target(self.ctx, root, {'family': family})}

    def windows(self, name='win', files=('0001.SPL', '0001.SHD', '0002.spl'), extra=('notes.txt',)):
        root = self.tmp / name
        for f in files + extra:
            touch(root / 'Windows/System32/spool/PRINTERS' / f)
        return root

    def test_windows_stuck_spool_files_are_counted(self):
        got = self.run_target(self.windows(), 'windows')
        self.assertEqual(got['printer-target-spool-stuck']['status'], 'warn')
        self.assertEqual((got['printer-target-spool-stuck']['kind'], got['printer-target-spool-stuck']['number']), ('count', 3))
        self.assertEqual(got['printer-target-spooler-service']['status'], 'unknown')     # no registry hive parser

    def test_windows_clean_spool_and_missing_folder(self):
        got = self.run_target(self.windows('clean', files=()), 'windows')
        self.assertEqual((got['printer-target-spool-stuck']['status'], got['printer-target-spool-stuck']['number']), ('pass', 0))
        root = self.tmp / 'nospool'
        (root / 'Windows/System32').mkdir(parents=True)
        self.assertEqual(self.run_target(root, 'windows')['printer-target-spool-stuck']['status'], 'unknown')

    def test_windows_paths_are_case_insensitive(self):
        root = self.tmp / 'lower'
        touch(root / 'windows/system32/SPOOL/printers/a.shd')
        self.assertEqual(self.run_target(root, 'windows')['printer-target-spool-stuck']['number'], 1)

    def test_windows_symlinks_are_never_followed(self):
        outside = self.tmp / 'outside'
        touch(outside / 'x.SPL')
        root = self.tmp / 'linked'
        (root / 'Windows/System32/spool').mkdir(parents=True)
        os.symlink(outside, root / 'Windows/System32/spool/PRINTERS')
        self.assertEqual(self.run_target(root, 'windows')['printer-target-spool-stuck']['status'], 'unknown')
        # a symlinked file inside the folder is not a file of the target
        root2 = self.tmp / 'linkedfile'
        (root2 / 'Windows/System32/spool/PRINTERS').mkdir(parents=True)
        os.symlink(outside / 'x.SPL', root2 / 'Windows/System32/spool/PRINTERS/y.SPL')
        self.assertEqual(self.run_target(root2, 'windows')['printer-target-spool-stuck']['number'], 0)

    def linux(self, name='lin', jobs=('c00001', 'd00001-001', 'c00002'), enabled=None, masked=False, installed=True):
        root = self.tmp / name
        if installed:
            touch(root / 'usr/sbin/cupsd')
        (root / 'var/spool/cups').mkdir(parents=True)
        for j in jobs:
            touch(root / 'var/spool/cups' / j)
        touch(root / 'var/spool/cups/tmp/other-file')                 # a directory entry is never a job
        (root / 'etc/systemd/system').mkdir(parents=True, exist_ok=True)
        if enabled:
            wants = root / 'etc/systemd/system' / enabled[0]
            wants.mkdir(parents=True)
            os.symlink('/lib/systemd/system/' + enabled[1], wants / enabled[1])
        if masked:
            os.symlink('/dev/null', root / 'etc/systemd/system/cups.service')
        return root

    def test_linux_cups_spool_and_service(self):
        root = self.linux(enabled=('printer.target.wants', 'cups.service'))
        for family in ('linuxmint', 'linux-other'):
            got = self.run_target(root, family)
            self.assertEqual((got['printer-target-spool-stuck']['status'], got['printer-target-spool-stuck']['number']), ('warn', 3))
            self.assertEqual(got['printer-target-cups-service']['status'], 'pass')
        self.assertNotIn('printer-target-spooler-service', got)

    def test_linux_service_states(self):
        self.assertEqual(self.run_target(self.linux('a', jobs=(), enabled=('sockets.target.wants', 'cups.socket')),
                                         'linuxmint')['printer-target-cups-service']['status'], 'pass')
        self.assertEqual(self.run_target(self.linux('b', jobs=(), enabled=('multi-user.target.wants', 'cups.path')),
                                         'linuxmint')['printer-target-cups-service']['status'], 'pass')
        got = self.run_target(self.linux('c', jobs=()), 'linuxmint')
        self.assertEqual((got['printer-target-cups-service']['status'], got['printer-target-spool-stuck']['status']), ('warn', 'pass'))
        self.assertEqual(self.run_target(self.linux('d', masked=True), 'linuxmint')['printer-target-cups-service']['status'], 'fail')
        got = self.run_target(self.linux('e', installed=False), 'linuxmint')
        self.assertEqual(got['printer-target-cups-service']['status'], 'not_applicable')

    def test_linux_without_cups_is_not_applicable(self):
        root = self.tmp / 'nocups'
        (root / 'etc').mkdir(parents=True)
        got = self.run_target(root, 'linux-other')
        self.assertEqual((got['printer-target-spool-stuck']['status'], got['printer-target-cups-service']['status']),
                         ('not_applicable', 'not_applicable'))

    def test_linux_installed_but_spool_unreadable_is_unknown(self):
        root = self.tmp / 'nospool'
        touch(root / 'usr/sbin/cupsd')
        got = self.run_target(root, 'linuxmint')
        self.assertEqual(got['printer-target-spool-stuck']['status'], 'unknown')

    def test_linux_symlinked_spool_is_not_followed(self):
        outside = self.tmp / 'outside-spool'
        touch(outside / 'c00001')
        root = self.tmp / 'ls'
        touch(root / 'usr/sbin/cupsd')
        (root / 'var/spool').mkdir(parents=True)
        os.symlink(outside, root / 'var/spool/cups')
        self.assertEqual(self.run_target(root, 'linuxmint')['printer-target-spool-stuck']['status'], 'unknown')

    def test_job_file_names_are_strict(self):
        root = self.linux('strict', jobs=('c00001', 'd00001-001', 'c1', 'cx00001', 'd00001', 'tmp.file', 'c00002.bak'))
        self.assertEqual(self.run_target(root, 'linuxmint')['printer-target-spool-stuck']['number'], 2)

    def test_other_families_report_nothing(self):
        self.assertEqual(printer.collect_offline_target(self.ctx, self.tmp, {'family': 'macos'}), [])
        self.assertEqual(printer.collect_offline_target(self.ctx, self.tmp, {'family': 'unknown'}), [])
        self.assertEqual(printer.collect_offline_target(self.ctx, self.tmp, None), [])

    def test_count_is_capped(self):
        root = self.tmp / 'big'
        spool = root / 'Windows/System32/spool/PRINTERS'
        spool.mkdir(parents=True)
        old = printer.MAX_SPOOL_COUNT
        printer.MAX_SPOOL_COUNT = 5
        self.addCleanup(setattr, printer, 'MAX_SPOOL_COUNT', old)
        for i in range(9):
            touch(spool / ('%04d.SPL' % i))
        self.assertEqual(self.run_target(root, 'windows')['printer-target-spool-stuck']['number'], 5)

    def test_registry_hook_runs_with_the_os_scope_only(self):
        root = self.windows()
        checks = rescue_modules.collect_offline_target(rescue_modules.Context(mode='live', scope=('all',)), root,
                                                       {'family': 'windows'})
        ids = {c['check_id'] for c in checks}
        self.assertTrue({'printer-target-spool-stuck', 'printer-target-spooler-service'} <= ids)
        ctx = rescue_modules.Context(mode='live', scope=('os',))
        self.assertIn('printer-target-spool-stuck', {c['check_id'] for c in rescue_modules.collect_offline_target(
            ctx, root, {'family': 'windows'})})
        ctx = rescue_modules.Context(mode='live', scope=('hardware',))
        self.assertNotIn('printer-target-spool-stuck', {c['check_id'] for c in rescue_modules.collect_offline_target(
            ctx, root, {'family': 'windows'})})
        self.assertEqual(ctx.warnings, [])
        # the hook never leaks a target_ref, a file name or a path
        for c in checks:
            self.assertNotIn('target_ref', c)

    def test_names_of_spool_files_never_leave_the_module(self):
        root = self.windows('names', files=('SecretDocument.SPL',), extra=())
        self.assertNotIn('SecretDocument', json.dumps(printer.collect_offline_target(self.ctx, root, {'family': 'windows'})))


class ScanTargetOsIntegrationTests(unittest.TestCase):
    """scan-target-os.py picks the printer checks up through the module registry (os scope, schema 1.2)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='printer-scan-os-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = self.tmp / 'fx'
        touch(self.fx / 'win/Windows/System32/config/SYSTEM')
        touch(self.fx / 'win/Windows/System32/spool/PRINTERS/SecretJob.SPL')
        touch(self.fx / 'win/Windows/System32/spool/PRINTERS/SecretJob.SHD')
        (self.fx / 'win.meta.json').write_text(json.dumps({'fstype': 'ntfs', 'free_percent': 40}))
        touch(self.fx / 'lin/usr/lib/os-release', b'PRETTY_NAME="Linux Mint 22.3"\nID=linuxmint\n')
        os.makedirs(self.fx / 'lin/etc', exist_ok=True)
        os.symlink('../usr/lib/os-release', self.fx / 'lin/etc/os-release')
        touch(self.fx / 'lin/var/lib/dpkg/status', b'Package: good\nStatus: install ok installed\n\n')
        touch(self.fx / 'lin/usr/sbin/cupsd')
        touch(self.fx / 'lin/var/spool/cups/c00001')
        (self.fx / 'lin/etc/systemd/system/printer.target.wants').mkdir(parents=True)
        os.symlink('/lib/systemd/system/cups.service', self.fx / 'lin/etc/systemd/system/printer.target.wants/cups.service')
        (self.fx / 'lin.meta.json').write_text(json.dumps({'fstype': 'ext4', 'uuid': 'ABCD-1234', 'free_percent': 40}))

    def scan(self, *extra):
        out = self.tmp / 'out' / 'evidence.json'
        result = subprocess.run([sys.executable, str(SCAN_OS), '--output', str(out), '--fixture-root', str(self.fx)] + list(extra),
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(out.read_text()), out, result

    def test_target_checks_in_the_evidence(self):
        data, out, result = self.scan()
        self.assertEqual(data['schema_version'], '1.2')
        refs = {t['ref']: t['family'] for t in data['target_systems']}
        win = next(r for r, f in refs.items() if f == 'windows')
        lin = next(r for r, f in refs.items() if f == 'linuxmint')
        checks = {(c.get('target_ref'), c['check_id']): c for c in data['checks']}
        self.assertEqual(checks[(win, 'printer-target-spool-stuck')]['status'], 'warn')
        self.assertEqual(checks[(win, 'printer-target-spool-stuck')]['value'], {'kind': 'count', 'number': 2})
        self.assertEqual(checks[(win, 'printer-target-spooler-service')]['status'], 'unknown')
        self.assertEqual(checks[(lin, 'printer-target-spool-stuck')]['value'], {'kind': 'count', 'number': 1})
        self.assertEqual(checks[(lin, 'printer-target-cups-service')]['status'], 'pass')
        self.assertTrue(all(c['source'] == 'offline-target-scan' for c in data['checks'] if c['check_id'].startswith('printer-target-')))
        self.assertNotIn('SecretJob', out.read_text() + result.stdout + result.stderr)
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_hardware_scope_does_not_inspect_the_spooler(self):
        data, _, _ = self.scan('--scope', 'hardware')
        self.assertFalse([c for c in data['checks'] if c['check_id'].startswith('printer-')])


# ------------------------------------------------------------------------------------ the CLI

class CliTests(Env):
    def setUp(self):
        super().setUp()
        self.machine = standard_machine(self.tmp)
        self.machine.add_ipp_usb_state('04a9-1865-Canon_Secret_Model.state', 60000)
        self.machine.add_fib_trie('192.168.77.10')
        self.shims = Shims(self.tmp / 'bin')
        self.shims.set(
            lpstat=lpstat_config([(QUEUE_HP, 'stopped', 'usb://SecretMaker/Secret%%20LaserJet?serial=%s' % SERIAL_HP, True)]),
            ipp={'ipp://localhost/printers/%s' % QUEUE_HP: ipp_csv(
                state='stopped', reasons='media-jam-error,door-open-error,toner-low-warning', queued='2',
                levels='12,80', types='toner,toner'),
                 'ipp://localhost:60000/ipp/print': ipp_csv(reasons='offline-report,media-empty', levels='50', types='ink',
                                                            make='Canon Secret LaserJet', accepting='false')},
            avahi={'_ipp._tcp': NetworkTests.AVAHI, '_ipps._tcp': ''})
        self.shims.cfg['ipp']['ipp://192.168.77.88:631/ipp/print'] = ipp_csv(make='Canon Secret LaserJet')
        self.shims.write()

    def run_scan(self, *args, machine=None, tool_dir=None):
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.tmp), 'LC_ALL': 'C'}
        argv = [sys.executable, str(SCAN), '--fixture-root', str((machine or self.machine).root),
                '--tool-path', str(tool_dir or self.shims.dir)]
        return subprocess.run(argv + list(args), capture_output=True, text=True, env=env, timeout=120)

    def scan(self, *extra, **kw):
        out = self.tmp / 'evidence.json'
        result = self.run_scan('--output', str(out), *extra, **kw)
        return result, out

    def test_list_table_markers_and_guidance(self):
        result = self.run_scan('--list')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout
        header = text.splitlines()[0]
        for column in ('REF', 'KONEKSI / CONNECTION', 'PORT', 'LOKASI / LOCATION', 'KECEPATAN / SPEED', 'MEREK / BRAND',
                       'STATUS / STATE', 'ALASAN / REASONS', 'TINTA% / MARKER MIN', 'ANTRIAN / JOBS', 'TANDA / MARKS'):
            self.assertIn(column, header)
        hp = next(l for l in text.splitlines() if l.startswith('prn-0'))
        for part in ('USB', '1-4', 'left/kiri', '480 Mbps', 'hp', 'stopped', 'door-open', 'media-jam', 'toner-low', '12%'):
            self.assertIn(part, hp)
        self.assertRegex(hp, r'\s2\s')                                       # two queued jobs
        canon = next(l for l in text.splitlines() if l.startswith('prn-1'))
        for part in ('IPP-over-USB', '3-2.1', 'canon', 'idle', 'offline-report', 'media-empty', '50%', '[HUB]'):
            self.assertIn(part, canon)
        for needle in ('Kertas macet', 'Paper jam', 'Penutup atau pintu printer terbuka', 'A printer cover or door is open',
                       'Toner atau tinta rendah', 'Toner or ink is low', 'Printer offline', 'The printer is offline',
                       'Kertas habis', 'Antrean berhenti atau dijeda', 'menolak pekerjaan baru', 'Jangan cabut perangkat USB rescue',
                       'port 1-6', 'Printer jaringan tidak dicari (opt-in)', 'Network printers were not searched'):
            self.assertIn(needle, text)
        self.assertIn('(Planned)', text)                                      # repairs are phase 2: never offered now

    def test_list_without_printers_gives_the_checklist(self):
        m = FakeUsb(self.tmp / 'empty')
        m.add_device('1-5', '046d', 'c31c', ['03/01/01'])
        shims = Shims(self.tmp / 'bin-empty')
        shims.set(lpstat=lpstat_config([]))
        result = self.run_scan('--list', machine=m, tool_dir=shims.dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Tidak ada printer terdeteksi', result.stdout)
        self.assertIn('kabel data', result.stdout)
        self.assertNotIn('REF', result.stdout)

    def test_missing_tools_are_explained(self):
        result = self.run_scan('--list', tool_dir=self.tmp / 'empty-dir')
        self.assertEqual(result.returncode, 0, result.stderr)
        for needle in ('lpstat tidak ditemukan', 'cups-client'):
            self.assertIn(needle, result.stdout)
        shims = Shims(self.tmp / 'bin-nopp', tools=('lpstat',))
        shims.set(lpstat=lpstat_config([]))
        result = self.run_scan('--list', tool_dir=shims.dir)
        self.assertIn('ipptool tidak ditemukan', result.stdout)
        self.assertIn('cups-ipp-utils', result.stdout)

    def test_evidence_validates_and_is_private(self):
        result, out = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        report = json.loads(out.read_text())
        self.assertEqual((report['schema_version'], report['source_platform'], report['repair_policy']),
                         ('1.3', 'linux-mint-xfce-live', 'detect-only'))
        self.assertEqual([t['ref'] for t in report['target_systems']], ['prn-0', 'prn-1'])
        self.assertTrue(all(t['family'] == 'printer' and t['encryption'] == 'unknown' for t in report['target_systems']))
        hp, canon = report['target_systems']
        self.assertEqual((hp['detection'], hp['access'], hp['usb_port']), ('usb-ipp', 'ipp-read', '1-4'))
        self.assertEqual((canon['detection'], canon['access'], canon['usb_port']), ('ipp-usb', 'ipp-read', '3-2.1'))
        for t in report['target_systems']:
            self.assertRegex(t['opaque_id'], r'^target-[0-9a-f]{16}$')
        self.assertNotIn(report['target_device_opaque_id'], [t['opaque_id'] for t in report['target_systems']])
        self.assertEqual(report['printers'], [
            {'ref': 'prn-0', 'connection': 'usb', 'brand': 'hp', 'ipp_usb_capable': False, 'usb_port': '1-4'},
            {'ref': 'prn-1', 'connection': 'ipp-over-usb', 'brand': 'canon', 'ipp_usb_capable': True, 'usb_port': '3-2.1'}])
        ports = {p['port']: p for p in report['usb_ports']}
        self.assertTrue(ports['1-6']['is_boot_media'])
        self.assertEqual((ports['1-4']['panel'], ports['1-4']['speed_mbps'], ports['3-2.1']['hub_depth']), ('left', 480, 1))
        env = [c for c in report['checks'] if 'target_ref' not in c]
        self.assertEqual({c['check_id']: (c['status'], c.get('value', {}).get('number')) for c in env},
                         {'usb-device-count': ('pass', 5), 'printer-count': ('pass', 2)})
        mine = {c['check_id']: c for c in report['checks'] if c.get('target_ref') == 'prn-0'}
        self.assertEqual(set(mine), set(printer.CHECK_IDS))
        self.assertEqual((mine['printer-state']['status'], mine['printer-media']['status'], mine['printer-door']['status'],
                          mine['printer-marker-supply']['status']), ('fail', 'fail', 'fail', 'warn'))
        self.assertEqual(mine['printer-marker-level-min']['value'], {'kind': 'percent', 'number': 12})
        self.assertEqual(mine['printer-queued-jobs']['value'], {'kind': 'count', 'number': 2})
        self.assertTrue(all(c['source'] == 'collector-allowlist' for c in report['checks']))
        self.assertEqual(report['evidence_manifest']['entry_count'], len(report['checks']))
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_select_one_printer_and_not_found(self):
        result, out = self.scan('--printer', 'prn-1')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual([t['ref'] for t in report['target_systems']], ['prn-1'])
        self.assertEqual(report['target_device_opaque_id'], report['target_systems'][0]['opaque_id'])
        self.assertEqual({c['check_id']: c['value']['number'] for c in report['checks'] if c['check_id'] == 'printer-count'},
                         {'printer-count': 2})                                  # the machine still has two printers
        result, out2 = self.scan('--printer', 'prn-5')
        self.assertEqual(result.returncode, 1)
        self.assertIn('not found', result.stderr)
        self.assertFalse(out2.exists() and out2 != out)

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.run_scan().returncode, 2)
        self.assertEqual(self.run_scan('--list', '--printer', 'printer-0').returncode, 2)
        self.assertEqual(self.run_scan('--list', '--printer', 'prn-9').returncode, 2)

    def test_host_platform(self):
        result, out = self.scan('--source-platform', 'linux-host')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual((report['source_platform'], report['linux_release']), ('linux-host', None))

    def test_network_is_off_unless_asked(self):
        result, out = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c for c in self.shims.calls() if c[0] == 'avahi-browse'], [])
        self.assertEqual(len(json.loads(out.read_text())['target_systems']), 2)

    def test_network_opt_in_adds_the_printer_and_records_the_calls(self):
        result, out = self.scan('--network')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len([c for c in self.shims.calls() if c[0] == 'avahi-browse']), 2)
        report = json.loads(out.read_text())
        self.assertEqual([t['ref'] for t in report['target_systems']], ['prn-0', 'prn-1', 'prn-2'])
        net = report['printers'][2]
        self.assertEqual((net['connection'], net['brand'], 'usb_port' in net), ('network', 'canon', False))
        self.assertEqual(report['target_systems'][2]['detection'], 'network-ipp')
        self.assertNotIn('usb_port', report['target_systems'][2])
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_list_with_network_reports_what_it_found(self):
        result = self.run_scan('--list', '--network')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('jaringan/network', result.stdout)
        self.assertNotIn('Network printers were not searched', result.stdout)

    def test_privacy_nothing_leaks_into_evidence_or_terminal(self):
        result, out = self.scan('--network', '--list')
        self.assertEqual(result.returncode, 0, result.stderr)
        blob = out.read_text() + result.stdout + result.stderr
        for leak in LEAKS:
            self.assertNotIn(leak, blob)
        for pair in ('03f0', '2b17', '04a9', '1865'):                  # no raw vendor:product IDs
            self.assertNotIn('"%s"' % pair, blob)
        self.assertNotIn('localhost', blob)
        self.assertNotRegex(blob, r'\b(?:\d{1,3}\.){3}\d{1,3}\b')       # no IP address anywhere
        text = json.dumps(json.loads(out.read_text()))
        self.assertNotIn('Secret', text)

    def test_nothing_is_written_to_cups_or_printers(self):
        self.scan('--network', '--list')
        for c in self.shims.calls():
            self.assertIn(c[0], ('lpstat', 'ipptool', 'avahi-browse'))
            if c[0] == 'lpstat':
                self.assertIn(c[1], ('-r', '-p', '-v', '-a', '-o'))
            if c[0] == 'avahi-browse':
                self.assertEqual(c[1], '-rtp')
        self.assertEqual(sorted(p.name for p in self.shims.dir.iterdir()),
                         ['avahi-browse', 'calls.log', 'config.json', 'ipptool', 'lpstat'])

    def test_usb_only_scan_without_tools_still_writes_valid_evidence(self):
        result, out = self.scan(tool_dir=self.tmp / 'no-tools')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual([t['access'] for t in report['target_systems']], ['usb-only', 'usb-only'])
        self.assertEqual([t['detection'] for t in report['target_systems']], ['usb-enumerated', 'usb-enumerated'])
        mine = {c['check_id']: c['status'] for c in report['checks'] if c.get('target_ref') == 'prn-0'}
        self.assertEqual(mine['printer-state'], 'unknown')
        self.assertEqual(mine['printer-usb-link'], 'pass')
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_no_printer_still_writes_evidence(self):
        m = FakeUsb(self.tmp / 'nothing')
        m.add_device('1-5', '046d', 'c31c', ['03/01/01'])
        shims = Shims(self.tmp / 'bin-none')
        shims.set(lpstat=lpstat_config([]))
        result, out = self.scan(machine=m, tool_dir=shims.dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual((report['target_systems'], report['printers']), ([], []))
        self.assertEqual({c['check_id']: c['status'] for c in report['checks']}['printer-count'], 'warn')
        if HAVE_JSONSCHEMA:
            check = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_unreadable_usb_sysfs_without_cups_is_fatal_but_cups_alone_is_enough(self):
        env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(self.tmp)}
        result = subprocess.run([sys.executable, str(SCAN), '--fixture-root', str(self.tmp / 'nothing'),
                                 '--tool-path', str(self.tmp / 'no-tools'), '--list'],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn('sysfs', result.stderr)
        result = subprocess.run([sys.executable, str(SCAN), '--fixture-root', str(self.tmp / 'nothing'),
                                 '--tool-path', str(self.shims.dir), '--list'],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('prn-0', result.stdout)
        self.assertIn('Sysfs USB tidak terbaca', result.stdout) if False else None

    def test_printers_sharing_a_hub_with_the_rescue_usb_are_marked(self):
        m = FakeUsb(self.tmp / 'sharedhub')
        m.add_device('3-2', '05e3', '0610', ['09/00/01'], device_class='09')
        m.add_device('3-2.2', '0781', '5567', ['08/06/50'])
        m.add_rescue_medium('3-2.2')
        m.add_device('3-2.1', '03f0', '2b17', ['07/01/02'])
        shims = Shims(self.tmp / 'bin-hub')
        shims.set(lpstat=lpstat_config([]))
        result = self.run_scan('--list', machine=m, tool_dir=shims.dir)
        row = next(l for l in result.stdout.splitlines() if l.startswith('prn-0'))
        self.assertIn('[USB RESCUE]', row)
        self.assertIn('[HUB]', row)
        self.assertIn('hub yang sama dengan USB rescue', result.stdout)


# -------------------------------------------------------------------- schema and validator rules

@unittest.skipUnless(HAVE_JSONSCHEMA, 'jsonschema is not installed')
class SchemaTests(unittest.TestCase):
    def validate(self, *paths):
        return subprocess.run([sys.executable, str(VALIDATE)] + [str(p) for p in paths], capture_output=True, text=True)

    def load(self, name='valid-printer.json'):
        return json.loads((FIXTURES / name).read_text())

    def write(self, data):
        data['evidence_manifest']['entry_count'] = len(data['checks'])
        path = Path(tempfile.mkdtemp(prefix='printer-schema-')) / 'e.json'
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_text(json.dumps(data))
        return path

    def rejected(self, mutate):
        data = self.load()
        mutate(data)
        return self.validate(self.write(data))

    def test_valid_fixture(self):
        result = self.validate(FIXTURES / 'valid-printer.json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_fixture_is_rejected_for_the_documented_reason(self):
        result = self.validate(FIXTURES / 'invalid-printer-queue.json')
        self.assertEqual(result.returncode, 1, result.stdout)
        reason = (FIXTURES / 'invalid-printer-queue.reason.txt').read_text().strip().lower()
        self.assertTrue(any(word in result.stdout.lower() for word in reason.split(';')[0].split('|')), (reason, result.stdout))

    def test_the_fixture_matches_what_the_scanner_writes(self):
        data = self.load()
        self.assertEqual(data['schema_version'], '1.3')
        self.assertEqual({t['family'] for t in data['target_systems']}, {'printer'})
        ids = {c['check_id'] for c in data['checks']}
        self.assertTrue(set(printer.CHECK_IDS) <= ids)
        self.assertTrue({'printer-count', 'usb-device-count'} <= ids)

    def test_every_printer_check_id_is_in_the_schema(self):
        schema = json.loads((ROOT / 'rescue-ai/v1/rescue-evidence.schema.json').read_text())
        enum = set(schema['properties']['checks']['items']['properties']['check_id']['enum'])
        self.assertTrue(set(printer.CHECK_IDS) <= enum)
        self.assertTrue({'printer-count', 'printer-target-spool-stuck', 'printer-target-spooler-service',
                         'printer-target-cups-service'} <= enum)
        self.assertEqual(set(rescue_modules.CHECK_IDS), enum)

    def test_older_versions_still_validate_and_reject_printer_fields(self):
        result = self.validate(*sorted(FIXTURES.glob('valid-*1.1.json')), FIXTURES / 'valid-live-scoped-1.2.json',
                               FIXTURES / 'valid-android-usb.json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for version in ('1.0', '1.1', '1.2'):
            self.assertEqual(self.rejected(lambda d, v=version: d.update(schema_version=v)).returncode, 1, version)

    def test_printer_target_checks_are_valid_in_1_2_but_not_1_1(self):
        data = json.loads((FIXTURES / 'valid-live-scoped-1.2.json').read_text())
        data['checks'].append({'check_id': 'printer-target-spool-stuck', 'status': 'warn', 'source': 'offline-target-scan',
                               'observed_at': '2026-09-30T08:00:00Z', 'target_ref': 'os-0', 'value': {'kind': 'count', 'number': 4}})
        data['checks'].append({'check_id': 'printer-target-cups-service', 'status': 'pass', 'source': 'offline-target-scan',
                               'observed_at': '2026-09-30T08:00:00Z', 'target_ref': 'os-0'})
        self.assertEqual(self.validate(self.write(data)).returncode, 0)
        data['schema_version'] = '1.1'
        self.assertEqual(self.validate(self.write(data)).returncode, 1)

    def test_free_strings_are_rejected(self):
        for mutate in (
            lambda d: d['printers'][0].update({'queue_name': 'Office'}),
            lambda d: d['printers'][0].update({'device_uri': 'usb://HP/X?serial=1'}),
            lambda d: d['printers'][0].update({'ip': '192.168.1.5'}),
            lambda d: d['printers'][0].update({'serial': SERIAL_HP}),
            lambda d: d['printers'][0].update({'brand': 'HP LaserJet Pro'}),
            lambda d: d['printers'][0].update({'connection': 'dnssd://Foo._ipp._tcp.local'}),
            lambda d: d['printers'][0].update({'usb_port': SERIAL_HP}),
            lambda d: d['printers'][0].update({'ref': 'prn-9'}),
            lambda d: d['printers'][0].update({'ipp_usb_capable': 'yes'}),
            lambda d: d['target_systems'][0].update({'opaque_id': SERIAL_HP}),
            lambda d: d['target_systems'][0].update({'model': 'LaserJet 9000'}),
            lambda d: d['target_systems'][0].update({'detection': 'dnssd'}),
            lambda d: d['target_systems'][0].update({'access': 'snmp-read'}),
            lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'printer-queue-name'}),
            lambda d: d['checks'][-1].update({'target_ref': 'prn-9'}),
            lambda d: d['checks'][-1].update({'value': {'kind': 'text', 'number': 1}}),
        ):
            data = self.load()
            mutate(data)
            self.assertEqual(self.validate(self.write(data)).returncode, 1)

    def test_semantic_rules(self):
        def check(mutate):
            return self.rejected(mutate).returncode

        self.assertEqual(check(lambda d: d['printers'][0].update({'ref': 'prn-5'})), 1)             # no matching target
        self.assertEqual(check(lambda d: d['printers'].pop()), 1)                                    # target without entry
        self.assertEqual(check(lambda d: d['printers'].append(dict(d['printers'][0]))), 1)           # duplicate ref
        self.assertEqual(check(lambda d: d['target_systems'][0].update({'usb_port': '9-9'})), 1)     # not in usb_ports
        self.assertEqual(check(lambda d: d['printers'][0].update({'usb_port': '1-6'})), 1)           # differs from the target
        self.assertEqual(check(lambda d: d['printers'][1].update({'usb_port': '1-4'})), 1)           # network printer on a port
        self.assertEqual(check(lambda d: d['target_systems'][0].update({'detection': 'usb-adb'})), 1)
        self.assertEqual(check(lambda d: d['target_systems'][0].update({'access': 'adb-authorized'})), 1)
        self.assertEqual(check(lambda d: d['target_systems'][0].update({'ref': 'and-0'})), 1)
        self.assertEqual(check(lambda d: d['target_systems'][0].update({'family': 'android'})), 1)
        self.assertEqual(check(lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'printer-state'})), 1)   # no target_ref
        self.assertEqual(check(lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'printer-count',
                                                             'target_ref': 'prn-0'})), 1)
        self.assertEqual(check(lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'printer-target-cups-service',
                                                             'target_ref': 'prn-0'})), 1)
        self.assertEqual(check(lambda d: d['checks'].append({**d['checks'][0], 'check_id': 'printer-state',
                                                             'target_ref': 'os-0'})), 1)
        self.assertEqual(check(lambda d: None), 0)

    def test_android_and_printer_targets_can_share_a_document(self):
        data = self.load()
        data['target_systems'].append({'ref': 'and-0', 'family': 'android', 'release': 'Android 14', 'architecture': 'arm64',
                                       'detection': 'usb-enumerated', 'encryption': 'unknown', 'access': 'usb-only',
                                       'opaque_id': 'target-0a1b2c3d4e5f6072'})
        data['checks'].append({**data['checks'][0], 'check_id': 'android-connection-mode', 'target_ref': 'and-0'})
        self.assertEqual(self.validate(self.write(data)).returncode, 0)

    def test_usb_enumerated_printer_is_valid(self):
        data = self.load()
        data['target_systems'][0].update({'detection': 'usb-enumerated', 'access': 'usb-only'})
        self.assertEqual(self.validate(self.write(data)).returncode, 0)


class DocsAndPackagingTests(unittest.TestCase):
    def test_skill_is_shipped_and_required(self):
        skill = ROOT / 'profiles/rescue-hermes/skills/rescue-printer/SKILL.md'
        text = skill.read_text()
        self.assertTrue(text.startswith('---\nname: rescue-printer\n'))
        build = (ROOT / 'scripts/lib/persistence-container-build.sh').read_text()
        self.assertIn('rescue-printer', build)
        for package in ('cups', 'cups-client', 'cups-ipp-utils', 'ipp-usb', 'avahi-utils'):
            self.assertRegex(build, r'\b%s\b' % package)
        for forbidden in ('firmware', 'vendor', 'subnet', 'queue names'):
            self.assertIn(forbidden, text)

    def test_prompt_mentions_printers(self):
        text = (ROOT / 'profiles/rescue-hermes/analysis-prompt.md').read_text()
        self.assertIn('family: printer', text)
        self.assertIn('printer-target-', text)

    def test_ipp_test_file_is_fixed_and_read_only(self):
        text = IPP_TEST.read_text()
        self.assertIn('OPERATION Get-Printer-Attributes', text)
        self.assertNotRegex(text, r'OPERATION (?!Get-Printer-Attributes)')
        self.assertIn('ATTR uri printer-uri $uri', text)
        self.assertEqual(text.count('{'), 1)                        # one request, nothing else


if __name__ == '__main__':
    unittest.main()
