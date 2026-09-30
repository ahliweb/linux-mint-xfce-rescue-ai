#!/usr/bin/env python3
"""Offline tests for hardware detection and its catalog actions (ahliweb/linux-mint-xfce-rescue-ai#15).

Fixture-root trees stand in for /proc, /sys and canned lsblk/smartctl/nvme output, so nothing here
touches a real block device or runs smartctl/nvme. PowerShell and zsh module tests run when pwsh /
zsh are installed (make check installs them in CI). Dummy values only.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
import rescue_modules  # noqa: E402
from rescue_modules import hardware  # noqa: E402

PWSH = shutil.which('pwsh')
ZSH = shutil.which('zsh')
PS_MODULE = ROOT / 'host/modules/windows/hardware.ps1'
ZSH_MODULE = ROOT / 'host/modules/macos/hardware.zsh'
HW_IDS = {'hw-cpu', 'hw-cpu-thermal', 'hw-memory', 'hw-memory-errors', 'hw-disk', 'hw-gpu', 'hw-gpu-driver',
          'hw-display', 'hw-network-adapter', 'hw-wifi', 'hw-battery', 'hw-usb', 'smart-health', 'nvme-health'}
ITEM_IDS = {
    'cpu': {'hw-cpu', 'hw-cpu-thermal'}, 'memory': {'hw-memory', 'hw-memory-errors'},
    'disk': {'hw-disk', 'smart-health', 'nvme-health'}, 'gpu': {'hw-gpu', 'hw-gpu-driver'},
    'display': {'hw-display'}, 'network': {'hw-network-adapter', 'hw-wifi'}, 'battery': {'hw-battery'},
    'usb': {'hw-usb'},
}
DUMMY_LEAK = 'SECRET-SERIAL-9931'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load('rescue_validate_evidence_hw', SCRIPTS / 'validate-evidence.py')
analyzer = load('rescue_analyzer_hw', SCRIPTS / 'opencode-go-analyze.py')


def put(base, rel, text=''):
    path = Path(base) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if isinstance(text, str) else json.dumps(text), encoding='utf-8')


class Machine:
    """Build a fixture tree (root/hardware/{proc,sys,cmd}) for one fake machine."""

    def __init__(self, tmp, name='m'):
        self.root = Path(tmp) / name
        self.base = self.root / 'hardware'
        (self.base / 'proc').mkdir(parents=True)
        (self.base / 'sys').mkdir()
        (self.base / 'cmd').mkdir()

    def w(self, rel, text=''):
        put(self.base, rel, text)
        return self

    def cpu(self, n=4, temp_mc=45000, throttle=None):
        self.w('proc/cpuinfo', ''.join('processor\t: %d\nmodel name\t: %s\n\n' % (i, DUMMY_LEAK) for i in range(n)))
        if temp_mc is not None:
            self.w('sys/class/thermal/thermal_zone0/temp', '%d\n' % temp_mc)
            self.w('sys/class/thermal/thermal_zone0/type', 'x86_pkg_temp\n')
        if throttle is not None:
            self.w('sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count', '%d\n' % throttle)
        return self

    def memory(self, total_kb=16 * 1024 * 1024, corrupted_kb=None, ce=None, ue=None):
        text = 'MemTotal:       %d kB\nMemAvailable:   1000 kB\n' % total_kb
        if corrupted_kb is not None:
            text += 'HardwareCorrupted: %d kB\n' % corrupted_kb
        self.w('proc/meminfo', text)
        self.w('sys/devices/system/cpu/cpu0/online', '1\n')   # /sys is readable; EDAC may be absent
        if ce is not None or ue is not None:
            self.w('sys/devices/system/edac/mc/mc0/ce_count', '%d\n' % (ce or 0))
            self.w('sys/devices/system/edac/mc/mc0/ue_count', '%d\n' % (ue or 0))
        return self

    def disks(self, *devices):
        """devices: dicts with name, tran (optional), rm."""
        self.w('cmd/lsblk.json', {'blockdevices': [
            {'name': d['name'], 'type': d.get('type', 'disk'), 'size': 500107862016, 'rm': d.get('rm', False),
             'tran': d.get('tran', 'sata'), 'ro': False, 'model': DUMMY_LEAK, 'serial': DUMMY_LEAK}
            for d in devices]})
        return self

    def smart(self, name, passed=True, realloc=0, temp=35):
        self.w('cmd/smartctl-%s.json' % name, {
            'smart_status': {'passed': passed}, 'temperature': {'current': temp},
            'serial_number': DUMMY_LEAK,
            'ata_smart_attributes': {'table': [{'id': 5, 'raw': {'value': realloc}},
                                               {'id': 9, 'raw': {'value': 12000}}]}})
        return self

    def nvme(self, name, used=5, warning=0, spare=100, spare_thr=10, media=0, temp=40):
        self.w('cmd/nvme-%s.json' % name, {
            'critical_warning': warning, 'percent_used': used, 'avail_spare': spare, 'spare_thresh': spare_thr,
            'media_errors': media, 'temperature': temp + 273})
        return self

    def pci(self, slot, cls, driver=True):
        self.w('sys/bus/pci/devices/%s/class' % slot, cls + '\n')
        if driver:
            self.w('sys/bus/pci/devices/%s/driver' % slot, '')
        return self

    def display(self, connected=1):
        self.w('sys/class/drm/card0/uevent', '')
        for i in range(2):
            self.w('sys/class/drm/card0-HDMI-A-%d/status' % (i + 1), 'connected\n' if i < connected else 'disconnected\n')
        return self

    def net(self, name, up=True, wifi=False, virtual=False):
        base = 'sys/class/net/%s/' % name
        self.w(base + 'operstate', 'up\n' if up else 'down\n')
        self.w(base + 'carrier', '1\n' if up else '0\n')
        self.w(base + 'address', '00:11:22:33:44:55\n')
        if not virtual:
            self.w(base + 'device/vendor', '0x8086\n')
        if wifi:
            self.w(base + 'wireless/status', '0x0\n')
        return self

    def rfkill(self, soft=False, hard=False):
        self.w('sys/class/rfkill/rfkill0/type', 'wlan\n')
        self.w('sys/class/rfkill/rfkill0/soft', '1\n' if soft else '0\n')
        self.w('sys/class/rfkill/rfkill0/hard', '1\n' if hard else '0\n')
        return self

    def battery(self, capacity=80, status='Discharging', full=48000000, design=50000000, health=None):
        base = 'sys/class/power_supply/BAT0/'
        self.w(base + 'type', 'Battery\n')
        self.w(base + 'capacity', '%d\n' % capacity)
        self.w(base + 'status', status + '\n')
        self.w(base + 'energy_full', '%d\n' % full)
        self.w(base + 'energy_full_design', '%d\n' % design)
        self.w(base + 'serial_number', DUMMY_LEAK + '\n')
        if health:
            self.w(base + 'health', health + '\n')
        return self

    def ac_only(self):
        self.w('sys/class/power_supply/AC/type', 'Mains\n')
        return self

    def usb(self, count=2, unconfigured=0):
        self.w('sys/bus/usb/devices/usb1/idVendor', '1d6b\n')  # root hub, never counted
        for i in range(count):
            base = 'sys/bus/usb/devices/1-%d/' % (i + 1)
            self.w(base + 'idVendor', '046d\n')
            self.w(base + 'bDeviceClass', '00\n')
            self.w(base + 'bConfigurationValue', '' if i < unconfigured else '1\n')
            self.w(base + 'serial', DUMMY_LEAK + '\n')
        self.w('sys/bus/usb/devices/1-1:1.0/bInterfaceClass', '03\n')  # interface, never counted
        return self

    def healthy_desktop(self):
        (self.cpu(8).memory(ce=0, ue=0)
         .disks({'name': 'sda'}, {'name': 'nvme0n1', 'tran': 'nvme'}, {'name': 'sdb', 'tran': 'usb', 'rm': True})
         .smart('sda').nvme('nvme0n1').pci('0000:00:02.0', '0x030000').pci('0000:03:00.0', '0x020000')
         .display(1).net('lo', virtual=True).net('eno1').ac_only().usb(2))
        return self


def collect(machine, scope=('all',), mode='live'):
    ctx = rescue_modules.Context(mode=mode, scope=tuple(scope), fixture_root=str(machine.root))
    checks = hardware.collect_system(ctx)
    assert not ctx.warnings, ctx.warnings
    return {c['check_id']: c for c in checks}


def status(checks, cid):
    return checks[cid]['status']


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='hw-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def machine(self, name='m'):
        return Machine(self.tmp, name)

    def test_healthy_desktop_passes_everything(self):
        checks = collect(self.machine().healthy_desktop())
        self.assertEqual(set(checks), HW_IDS)
        for cid, c in checks.items():
            with self.subTest(check=cid):
                self.assertIn(c['status'], ('pass', 'not_applicable'), (cid, c))
        self.assertEqual(checks['hw-cpu']['number'], 8)
        self.assertEqual(checks['hw-cpu-thermal']['number'], 45)
        self.assertEqual(checks['hw-memory']['kind'], 'bytes')
        self.assertEqual(checks['hw-disk']['number'], 2)            # USB/removable excluded
        self.assertEqual((checks['hw-gpu']['number'], checks['hw-gpu-driver']['number']), (1, 0))
        self.assertEqual(status(checks, 'hw-battery'), 'not_applicable')
        self.assertEqual(status(checks, 'hw-wifi'), 'not_applicable')
        self.assertEqual(checks['hw-usb']['number'], 2)
        self.assertEqual(checks['nvme-health'], {'check_id': 'nvme-health', 'status': 'pass', 'kind': 'percent', 'number': 5})

    def test_overheating_cpu(self):
        self.assertEqual(status(collect(self.machine('a').cpu(4, 82000)), 'hw-cpu-thermal'), 'warn')
        self.assertEqual(status(collect(self.machine('b').cpu(4, 97000)), 'hw-cpu-thermal'), 'fail')
        self.assertEqual(status(collect(self.machine('c').cpu(4, 50000, throttle=12)), 'hw-cpu-thermal'), 'warn')
        hot = collect(self.machine('d').cpu(4, None).w('sys/class/hwmon/hwmon2/temp1_input', '91000\n'))
        self.assertEqual((hot['hw-cpu-thermal']['status'], hot['hw-cpu-thermal']['number']), ('warn', 91))

    def test_memory_and_edac(self):
        c = collect(self.machine('a').memory(1024 * 1024, ce=0, ue=0))
        self.assertEqual((status(c, 'hw-memory'), status(c, 'hw-memory-errors')), ('warn', 'pass'))   # 1 GiB
        c = collect(self.machine('b').memory(ce=3, ue=0))
        self.assertEqual((status(c, 'hw-memory-errors'), c['hw-memory-errors']['number']), ('warn', 3))
        c = collect(self.machine('c').memory(ce=3, ue=1))
        self.assertEqual((status(c, 'hw-memory-errors'), c['hw-memory-errors']['number']), ('fail', 4))
        self.assertEqual(status(collect(self.machine('d').memory(corrupted_kb=4)), 'hw-memory'), 'fail')
        self.assertEqual(status(collect(self.machine('e').memory()), 'hw-memory-errors'), 'not_applicable')  # no EDAC

    def test_failing_smart_and_reallocated_sectors(self):
        base = lambda n: self.machine(n).disks({'name': 'sda'})  # noqa: E731
        self.assertEqual(status(collect(base('a').smart('sda', passed=False)), 'smart-health'), 'fail')
        c = collect(base('b').smart('sda', realloc=8))
        self.assertEqual((status(c, 'smart-health'), c['smart-health']['number']), ('warn', 1))
        self.assertEqual(status(collect(base('c').smart('sda', temp=65)), 'smart-health'), 'warn')
        self.assertEqual(status(collect(base('d').smart('sda')), 'smart-health'), 'pass')
        bare = collect(base('e'))
        self.assertEqual(status(bare, 'smart-health'), 'unknown')        # smartctl gave nothing
        self.assertEqual(status(bare, 'nvme-health'), 'not_applicable')  # no NVMe disk

    def test_nvme_wear_and_critical_warning(self):
        base = lambda n: self.machine(n).disks({'name': 'nvme0n1', 'tran': 'nvme'})  # noqa: E731
        c = collect(base('a').nvme('nvme0n1', used=93))
        self.assertEqual((status(c, 'nvme-health'), c['nvme-health']['number']), ('warn', 93))
        self.assertEqual(status(collect(base('b').nvme('nvme0n1', warning=4)), 'nvme-health'), 'fail')
        self.assertEqual(status(collect(base('c').nvme('nvme0n1', used=100)), 'nvme-health'), 'fail')
        self.assertEqual(status(collect(base('d').nvme('nvme0n1', spare=5, spare_thr=10)), 'nvme-health'), 'fail')
        self.assertEqual(status(collect(base('e').nvme('nvme0n1', media=2)), 'nvme-health'), 'warn')
        bare = collect(base('f'))
        self.assertEqual(status(bare, 'nvme-health'), 'unknown')
        self.assertEqual(status(bare, 'smart-health'), 'not_applicable')

    def test_no_disks_and_no_lsblk(self):
        self.assertEqual(status(collect(self.machine('a').disks()), 'hw-disk'), 'fail')
        c = collect(self.machine('b').cpu())          # lsblk missing: everything disk-related is unknown
        self.assertEqual({status(c, i) for i in ITEM_IDS['disk']}, {'unknown'})

    def test_host_mode_leaves_smart_health_to_the_launcher(self):
        m = self.machine().disks({'name': 'sda'}).smart('sda')
        self.assertNotIn('smart-health', collect(m, mode='host'))
        self.assertIn('smart-health', collect(m, mode='live'))

    def test_gpu_without_driver_and_headless(self):
        c = collect(self.machine('a').pci('0000:00:02.0', '0x030000', driver=False))
        self.assertEqual((status(c, 'hw-gpu'), status(c, 'hw-gpu-driver'), c['hw-gpu-driver']['number']),
                         ('pass', 'fail', 1))
        self.assertEqual(status(c, 'hw-display'), 'unknown')            # no DRM connectors without a driver
        c = collect(self.machine('b').pci('0000:00:1f.0', '0x060100'))
        self.assertEqual((status(c, 'hw-gpu'), status(c, 'hw-gpu-driver')), ('not_applicable', 'not_applicable'))

    def test_display_counts_connected_outputs(self):
        self.assertEqual(collect(self.machine('a').display(2))['hw-display']['number'], 2)
        self.assertEqual(status(collect(self.machine('b').display(0)), 'hw-display'), 'warn')

    def test_network_and_wifi(self):
        c = collect(self.machine('a').net('lo', virtual=True).net('docker0', virtual=True).net('eno1', up=False))
        self.assertEqual((status(c, 'hw-network-adapter'), c['hw-network-adapter']['number']), ('warn', 1))
        self.assertEqual(status(c, 'hw-wifi'), 'not_applicable')
        c = collect(self.machine('b').net('lo', virtual=True))
        self.assertEqual((status(c, 'hw-network-adapter'), c['hw-network-adapter']['number']), ('fail', 0))
        c = collect(self.machine('c').net('wlan0', up=False, wifi=True).rfkill(soft=True))
        self.assertEqual((status(c, 'hw-network-adapter'), status(c, 'hw-wifi'), c['hw-wifi']['number']),
                         ('pass', 'warn', 1))
        c = collect(self.machine('d').net('wlan0', wifi=True).rfkill())
        self.assertEqual((status(c, 'hw-wifi'), c['hw-wifi']['number']), ('pass', 0))
        c = collect(self.machine('e2').net('eno1').pci('0000:02:00.0', '0x020000', driver=False))
        self.assertEqual(status(c, 'hw-network-adapter'), 'fail')

    def test_laptop_low_battery(self):
        c = collect(self.machine('a').battery(capacity=8))
        self.assertEqual((status(c, 'hw-battery'), c['hw-battery']['number'], c['hw-battery']['kind']), ('fail', 8, 'percent'))
        self.assertEqual(status(collect(self.machine('b').battery(capacity=15)), 'hw-battery'), 'warn')
        self.assertEqual(status(collect(self.machine('c').battery(capacity=15, status='Charging')), 'hw-battery'), 'pass')
        self.assertEqual(status(collect(self.machine('d').battery(capacity=90, full=27000000)), 'hw-battery'), 'warn')  # 54 % health
        self.assertEqual(status(collect(self.machine('e').battery(capacity=90, full=15000000)), 'hw-battery'), 'fail')  # 30 % health
        self.assertEqual(status(collect(self.machine('f').battery(capacity=90, health='Dead')), 'hw-battery'), 'fail')
        self.assertEqual(status(collect(self.machine('g').battery(capacity=90)), 'hw-battery'), 'pass')

    def test_usb_counts_devices_not_hubs_or_interfaces(self):
        c = collect(self.machine('a').usb(3, unconfigured=1))
        self.assertEqual((status(c, 'hw-usb'), c['hw-usb']['number']), ('warn', 3))
        self.assertEqual(collect(self.machine('b').usb(0))['hw-usb']['number'], 0)

    def test_unreadable_sources_degrade_to_unknown(self):
        m = self.machine()          # an empty hardware fixture: every source is missing
        m.w('proc/.keep')
        checks = collect(m)
        self.assertEqual(set(checks), HW_IDS)
        for cid, c in checks.items():
            with self.subTest(check=cid):
                self.assertEqual(c['status'], 'unknown')
                self.assertNotIn('number', c)

    def test_garbage_sources_never_raise(self):
        m = self.machine()
        m.w('proc/cpuinfo', '\x00\xff garbage').w('proc/meminfo', 'MemTotal: lots kB\n')
        m.w('cmd/lsblk.json', 'not json').w('sys/class/thermal/thermal_zone0/temp', 'hot\n')
        m.w('sys/class/power_supply/BAT0/type', 'Battery\n').w('sys/class/power_supply/BAT0/capacity', 'full\n')
        checks = collect(m)
        self.assertEqual(status(checks, 'hw-cpu'), 'unknown')
        self.assertEqual(status(checks, 'hw-memory'), 'unknown')
        self.assertEqual(status(checks, 'hw-disk'), 'unknown')
        self.assertEqual(status(checks, 'hw-cpu-thermal'), 'unknown')
        self.assertEqual(status(checks, 'hw-battery'), 'pass')

    def test_scope_filtering_per_item(self):
        m = self.machine().healthy_desktop()
        for item, ids in ITEM_IDS.items():
            with self.subTest(item=item):
                self.assertEqual(set(collect(m, ('hardware.' + item,))), ids)
        self.assertEqual(set(collect(m, ('hardware.cpu', 'hardware.usb'))), ITEM_IDS['cpu'] | ITEM_IDS['usb'])
        self.assertEqual(set(collect(m, ('hardware',))), HW_IDS)
        self.assertEqual(set(collect(m, ('all',))), HW_IDS)
        for scope in (('os',), ('software',), ('software.selected',)):
            self.assertEqual(collect(m, scope), {})

    def test_fixture_root_without_hardware_fixtures_never_reads_the_live_machine(self):
        empty = Path(self.tmp) / 'empty'
        (empty / 'some-partition').mkdir(parents=True)
        ctx = rescue_modules.Context(mode='live', fixture_root=str(empty))
        self.assertEqual(hardware.collect_system(ctx), [])

    def test_offline_target_returns_nothing(self):
        ctx = rescue_modules.Context(mode='live')
        self.assertEqual(hardware.collect_offline_target(ctx, '/nonexistent', {'family': 'linuxmint'}), [])

    def test_no_identifiers_in_output(self):
        m = self.machine().healthy_desktop().battery(30).net('wlan0', wifi=True).rfkill()
        m.w('proc/cpuinfo', 'processor : 0\nmodel name : %s\nserial : %s\n' % (DUMMY_LEAK, DUMMY_LEAK))
        text = json.dumps(list(collect(m).values()))
        for needle in (DUMMY_LEAK, '00:11:22', 'sda', 'nvme0n1', '/dev', 'eno1', 'wlan0', 'BAT0', '046d'):
            self.assertNotIn(needle, text)
        for c in collect(m).values():
            self.assertLessEqual(set(c), {'check_id', 'status', 'kind', 'number'})
            self.assertIn(c['check_id'], HW_IDS)
            if 'number' in c:
                self.assertIsInstance(c['number'], int)
                self.assertIn(c['kind'], ('percent', 'count', 'bytes', 'days', 'seconds', 'celsius'))

    def test_every_emitted_check_survives_the_contract_sanitizer(self):
        m = self.machine().healthy_desktop()
        ctx = rescue_modules.Context(mode='live', fixture_root=str(m.root))
        self.assertEqual(len(rescue_modules.collect_system(ctx)), len(hardware.collect_system(ctx)))
        self.assertEqual(ctx.warnings, [])

    def test_live_commands_use_a_fixed_path_and_no_shell(self):
        text = (SCRIPTS / 'rescue_modules/hardware.py').read_text(encoding='utf-8')
        self.assertNotIn('shell=True', text)
        self.assertNotIn('os.system', text)
        self.assertNotIn('eval(', text)
        self.assertNotIn('open(', text.replace('with open(self.path(*parts)', ''))
        # the only external programs are the read-only ones named in the module docstring
        for program in re.findall(r"\['(\w+)', '-", text):
            self.assertIn(program, ('lsblk', 'smartctl'))
        self.assertIn("['nvme', 'smart-log'", text)
        for verb in ('-t', 'selftest', 'device-self-test', 'format', 'sanitize', 'fw-'):
            self.assertNotIn("'%s'" % verb, text)


# ---------------------------------------------------------------- scanner and launcher

class EvidenceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='hw-int-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def problems(self, path):
        data = json.loads(Path(path).read_text())
        return data, analyzer.validation_problems(validator, data)

    def test_scanner_evidence_validates_and_respects_scope(self):
        m = Machine(self.tmp / 'fx').healthy_desktop().battery(9)
        out = self.tmp / 'evidence.json'
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'scan-target-os.py'), '--output', str(out),
                               '--fixture-root', str(m.root)], capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data, problems = self.problems(out)
        self.assertEqual(problems, [])
        checks = {c['check_id']: c for c in data['checks']}
        self.assertTrue(HW_IDS <= set(checks), HW_IDS - set(checks))
        self.assertEqual(checks['hw-battery']['status'], 'fail')
        self.assertTrue(all('target_ref' not in checks[i] for i in HW_IDS))
        self.assertNotIn(DUMMY_LEAK, out.read_text())
        # trigger proposals come from the shipped catalog
        ids = {p['action_id'] for p in data.get('repair_proposals', [])}
        self.assertNotIn('hw.smart-short-selftest', ids)      # smart-health passes on this machine

        out2 = self.tmp / 'scoped.json'
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'scan-target-os.py'), '--output', str(out2),
                               '--fixture-root', str(m.root), '--scope', 'hardware.battery,hardware.usb'],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data, problems = self.problems(out2)
        self.assertEqual(problems, [])
        self.assertEqual({c['check_id'] for c in data['checks']} & HW_IDS, {'hw-battery', 'hw-usb'})
        self.assertEqual(data['scope'], ['hardware.battery', 'hardware.usb'])

    def test_failing_smart_produces_a_catalog_trigger_proposal(self):
        m = Machine(self.tmp / 'fx').healthy_desktop().smart('sda', passed=False)
        out = self.tmp / 'evidence.json'
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'scan-target-os.py'), '--output', str(out),
                               '--fixture-root', str(m.root), '--scope', 'hardware.disk'],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data, problems = self.problems(out)
        self.assertEqual(problems, [])
        self.assertEqual([p for p in data['repair_proposals'] if p['origin'] == 'catalog-trigger'],
                         [{'action_id': 'hw.smart-short-selftest', 'origin': 'catalog-trigger',
                           'trigger_check_id': 'smart-health'}])

    @unittest.skipUnless(shutil.which('bash'), 'bash needed')
    def test_linux_host_launcher_evidence_validates(self):
        usb = self.tmp / 'usb' / 'rescue-omes'
        for name in ('scripts', 'profiles', 'rescue-ai', 'host'):
            shutil.copytree(ROOT / name, usb / name, ignore=shutil.ignore_patterns('__pycache__', 'rescue.env'))
        m = Machine(self.tmp / 'fx').healthy_desktop().battery(12)
        env = {k: v for k, v in os.environ.items() if k != 'OPENCODE_GO_API_KEY'}
        env['RESCUE_HARDWARE_FIXTURE_ROOT'] = str(m.root)
        proc = subprocess.run([str(usb / 'host/rescue-linux.sh'), '--evidence-only', '--scope', 'hardware',
                               '--repair-policy', 'detect-only'], capture_output=True, text=True, env=env,
                              cwd=self.tmp, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        reports = sorted((usb / 'reports').glob('linux-*-evidence.json'))
        self.assertEqual(len(reports), 1)
        data, problems = self.problems(reports[0])
        self.assertEqual(problems, [])
        checks = {c['check_id']: c for c in data['checks']}
        self.assertEqual(checks['hw-battery']['status'], 'warn')
        self.assertEqual(checks['hw-cpu']['value'], {'kind': 'count', 'number': 8})
        self.assertNotIn('target_ref', checks['hw-cpu'])
        self.assertNotIn(DUMMY_LEAK, reports[0].read_text())


# ---------------------------------------------------------------------------- catalog

class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = rc.load()
        cls.actions = {a: v for a, v in cls.catalog.actions.items() if a.startswith('hw.')}
        cls.evidence_ids = rc.evidence_check_ids(rc.EVIDENCE_SCHEMA)

    def test_expected_actions(self):
        self.assertEqual(set(self.actions), {'hw.smart-short-selftest', 'hw.nvme-short-selftest',
                                             'hw.network-service-restart', 'hw.wifi-rfkill-unblock'})

    def test_only_safe_or_reversible_and_no_disk_writes(self):
        for aid, a in self.actions.items():
            with self.subTest(action=aid):
                self.assertIn(a['risk'], ('safe', 'reversible'))
                self.assertFalse(a['backup']['required'])
                self.assertFalse(a.get('requires_target_rw'))
                self.assertNotIn(a['execute']['argv'][0], ('dd', 'mkfs', 'fdisk', 'parted', 'flashrom', 'fwupdmgr'))

    def test_triggers_reference_emitted_check_ids(self):
        for aid, a in self.actions.items():
            for t in a['triggers']:
                with self.subTest(action=aid):
                    self.assertIn(t['check_id'], HW_IDS)
                    self.assertIn(t['check_id'], self.evidence_ids)

    def test_scopes_docs_and_platforms(self):
        docs = (ROOT / 'docs/hardware.md').read_text(encoding='utf-8')
        anchors = set()
        for line in docs.splitlines():
            m = re.match(r'^#{1,6}\s+(.*)$', line)
            if m:
                anchors.add(re.sub(r'[^a-z0-9 -]', '', m.group(1).lower()).strip().replace(' ', '-'))
        for aid, a in self.actions.items():
            with self.subTest(action=aid):
                self.assertTrue(a['scope'].startswith('hardware.'))
                self.assertEqual(set(a['platforms']), {'live-linux', 'linux-host'})
                self.assertTrue(a['requires_root'])
                path, _, anchor = a['doc'].partition('#')
                self.assertEqual(path, 'docs/hardware.md')
                self.assertIn(anchor, anchors, (anchor, sorted(anchors)))
                self.assertIn(aid, docs)

    def test_reversible_action_has_rollback_step(self):
        a = self.actions['hw.wifi-rfkill-unblock']
        self.assertEqual(a['rollback']['kind'], 'step')
        self.assertEqual(a['rollback']['step']['argv'], ['rfkill', 'block', 'wlan'])

    def test_argv_rendering(self):
        a = self.actions['hw.smart-short-selftest']
        self.assertEqual([x.replace('{device}', '/dev/sda') for x in a['execute']['argv']],
                         ['smartctl', '-t', 'short', '/dev/sda'])
        n = self.actions['hw.nvme-short-selftest']
        self.assertEqual([x.replace('{device}', '/dev/nvme0n1') for x in n['execute']['argv']],
                         ['nvme', 'device-self-test', '/dev/nvme0n1', '-s', '1'])
        s = self.actions['hw.network-service-restart']
        self.assertEqual(s['params'][0]['values'], ['NetworkManager', 'systemd-networkd'])
        self.assertEqual(s['params'][0]['default'], 'NetworkManager')

    def test_triggered_proposals_from_evidence(self):
        evidence = json.loads((ROOT / 'rescue-ai/v1/fixtures/valid-live-scoped-1.2.json').read_text())
        ev = copy.deepcopy(evidence)
        ev['scope'] = ['all']
        ev['checks'] = [{'check_id': 'smart-health', 'status': 'warn', 'source': 'live-allowlist'},
                        {'check_id': 'hw-wifi', 'status': 'warn', 'source': 'live-allowlist'},
                        {'check_id': 'nvme-health', 'status': 'pass', 'source': 'live-allowlist'}]
        for c in ev['checks']:
            c.setdefault('value', None)
        ids = {p['action_id'] for p in rc.triggered(self.catalog, ev, ('all',))}
        self.assertEqual(ids, {'hw.smart-short-selftest', 'hw.wifi-rfkill-unblock'})
        ids = {p['action_id'] for p in rc.triggered(self.catalog, ev, ('hardware.disk',))}
        self.assertEqual(ids, {'hw.smart-short-selftest'})

    def test_engine_refuses_auto_safe_for_the_reversible_action(self):
        # only safe catalog-trigger actions may run without a prompt
        self.assertEqual(self.actions['hw.wifi-rfkill-unblock']['risk'], 'reversible')
        self.assertEqual(self.actions['hw.network-service-restart']['risk'], 'safe')


# ------------------------------------------------------------------------ pwsh / zsh

@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellModuleTests(unittest.TestCase):
    def pwsh(self, script, **env):
        e = {k: v for k, v in os.environ.items()}
        e.update(env)
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command', script], capture_output=True,
                              text=True, env=e, timeout=120)

    def test_parses_and_is_ascii(self):
        PS_MODULE.read_bytes().decode('ascii')
        proc = self.pwsh("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                         "'%s',[ref]$t,[ref]$e); $e.Count" % PS_MODULE)
        self.assertEqual(proc.stdout.strip(), '0', proc.stdout + proc.stderr)

    def test_off_windows_emits_nothing_and_exits_cleanly(self):
        proc = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(PS_MODULE)],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, ''), proc.stdout + proc.stderr)

    def facts(self, facts_ps, scope="@('all')"):
        script = ("$env:RESCUE_PS_LIBRARY_ONLY='1'; . '%s'; $f = %s; "
                  "$r = ConvertTo-HwChecks -Facts $f -Scope %s; "
                  "$r | ForEach-Object { $s = $_['check_id'] + ' ' + $_['status']; "
                  "if ($_.ContainsKey('kind')) { $s += ' ' + $_['kind'] + ' ' + $_['number'] }; $s }"
                  % (PS_MODULE, facts_ps, scope))
        proc = self.pwsh(script)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return [line for line in proc.stdout.splitlines() if line]

    def test_healthy_facts(self):
        lines = self.facts("@{ CpuLogical=8; CpuBad=0; TempC=50; MemBytes=17179869184; WheaTotal=0; WheaErrors=0;"
                           " DiskCount=2; DiskBad=0; NvmeCount=1; Nvme=@(@{Wear=4;Temp=40;Uncorrected=0});"
                           " GpuCount=1; GpuBad=0; PnpDisplayBad=0; Monitors=1; AdapterCount=2; AdapterUp=1;"
                           " PnpNetBad=0; WifiCount=1; WifiDisabled=0; BatteryPresent=$true; BatteryCharge=88;"
                           " BatteryDischarging=$false; BatteryHealth=91; UsbCount=3; PnpUsbBad=0 }")
        self.assertEqual(lines, [
            'hw-cpu pass count 8', 'hw-cpu-thermal pass celsius 50', 'hw-memory pass bytes 17179869184',
            'hw-memory-errors pass count 0', 'hw-disk pass count 2', 'nvme-health pass percent 4',
            'hw-gpu pass count 1', 'hw-gpu-driver pass count 0', 'hw-display pass count 1',
            'hw-network-adapter pass count 2', 'hw-wifi pass count 0', 'hw-battery pass percent 88',
            'hw-usb pass count 3'])

    def test_problem_facts(self):
        lines = self.facts("@{ CpuLogical=4; CpuBad=0; TempC=97; MemBytes=1073741824; WheaTotal=5; WheaErrors=2;"
                           " DiskCount=0; NvmeCount=0; GpuCount=1; GpuBad=0; PnpDisplayBad=1; Monitors=0;"
                           " AdapterCount=1; AdapterUp=0; PnpNetBad=0; WifiCount=1; WifiDisabled=1;"
                           " BatteryPresent=$true; BatteryCharge=7; BatteryDischarging=$true; UsbCount=1; PnpUsbBad=1 }")
        self.assertEqual(lines, [
            'hw-cpu pass count 4', 'hw-cpu-thermal fail celsius 97', 'hw-memory warn bytes 1073741824',
            'hw-memory-errors fail count 5', 'hw-disk fail count 0', 'nvme-health not_applicable',
            'hw-gpu pass count 1', 'hw-gpu-driver fail count 1', 'hw-display warn count 0',
            'hw-network-adapter warn count 1', 'hw-wifi warn count 1', 'hw-battery fail percent 7',
            'hw-usb warn count 1'])

    def test_unknown_when_nothing_is_readable_and_scope_filters(self):
        lines = self.facts('@{}')
        self.assertEqual({l.split()[1] for l in lines}, {'unknown'})
        self.assertEqual({l.split()[0] for l in lines},
                         HW_IDS - {'smart-health'})   # the launcher itself emits smart-health
        lines = self.facts('@{}', "@('hardware.battery','hardware.usb')")
        self.assertEqual([l.split()[0] for l in lines], ['hw-battery', 'hw-usb'])
        self.assertEqual(self.facts('@{}', "@('os')"), [])

    def test_no_battery_and_all_ids_are_in_the_contract(self):
        lines = self.facts('@{ BatteryPresent=$false }', "@('hardware.battery')")
        self.assertEqual(lines, ['hw-battery not_applicable'])
        text = PS_MODULE.read_text(encoding='ascii')
        for cid in set(re.findall(r"'((?:hw-|smart-|nvme-)[a-z-]+)'", text)):
            self.assertIn(cid, rescue_modules.CHECK_IDS)
        text = '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#')).replace('Set-StrictMode', '')
        for forbidden in ('Invoke-Expression', 'iex ', 'Set-', 'Remove-', 'Restart-', 'Start-Process', 'Enable-',
                          'Disable-', 'New-Item', 'Out-File', 'Add-Content'):
            self.assertNotIn(forbidden, text)


@unittest.skipUnless(ZSH, 'zsh not installed')
class MacModuleTests(unittest.TestCase):
    SHIMS = {
        'pmset': '''#!/bin/bash
case "$*" in
  "-g therm") printf 'Note: No thermal warning level has been recorded\\nCPU_Speed_Limit = %s\\n' "${FAKE_SPEED:-100}" ;;
  "-g batt") if [ "${FAKE_BATT:-1}" = 1 ]; then printf "Now drawing from 'Battery Power'\\n -InternalBattery-0 (id=1234)\\t%s%%; discharging; 3:00 remaining present: true\\n" "${FAKE_CHARGE:-80}"; else printf "Now drawing from 'AC Power'\\n"; fi ;;
esac
''',
        'sysctl': '#!/bin/bash\ncase "$2" in hw.logicalcpu) echo 10 ;; hw.memsize) echo 17179869184 ;; esac\n',
        'diskutil': '''#!/bin/bash
if [ "$1" = list ]; then printf '/dev/disk0 (internal, physical):\\n   #: TYPE NAME\\n'; exit 0; fi
printf '   Device Identifier: disk0\\n   Protocol: Apple Fabric\\n   SMART Status: %s\\n' "${FAKE_SMART:-Verified}"
''',
        'system_profiler': '#!/bin/bash\nprintf \'{"SPDisplaysDataType":[{"sppci_model":"X","spdisplays_ndrvs":[{"_spdisplays_resolution":"1x1"}]}]}\'\n',
        'networksetup': '''#!/bin/bash
case "$1" in
  -listallhardwareports) printf 'Hardware Port: Wi-Fi\\nDevice: en0\\nEthernet Address: 00:11:22:33:44:55\\n\\nHardware Port: Thunderbolt Bridge\\nDevice: bridge0\\n' ;;
  -getairportpower) echo "Wi-Fi Power ($2): ${FAKE_WIFI:-On}" ;;
esac
''',
        'ifconfig': '#!/bin/bash\nprintf "en0: flags=8863\\n\\tstatus: active\\n"\n',
        'ioreg': '''#!/bin/bash
case "$*" in
  *AppleSmartBattery*) printf '    "AppleRawMaxCapacity" = %s\\n    "DesignCapacity" = 6000\\n' "${FAKE_RAW:-5700}" ;;
  *IOUSB*) printf '+-o Root  <class IOUSBRootHubDevice>\\n  +-o Hub <class AppleUSBDevice>\\n  +-o Key <class AppleUSBDevice>\\n' ;;
esac
''',
    }

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='hw-mac-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name, body in self.SHIMS.items():
            path = self.tmp / name
            path.write_text(body)
            path.chmod(0o755)

    def run_module(self, scope='all', **env):
        # the module resets PATH to the system directories like a Mac; the shims win through the
        # RESCUE_TEST_SHIMS-free trick below: run it with the shim directory as the only PATH source
        e = {'HOME': str(self.tmp), 'RESCUE_SCOPE': scope, 'PATH': str(self.tmp) + ':/usr/bin:/bin'}
        e.update(env)
        script = ZSH_MODULE.read_text(encoding='utf-8').replace('export PATH=/usr/sbin:/usr/bin:/bin:/sbin',
                                                                'export PATH=%s:/usr/bin:/bin' % self.tmp)
        module = self.tmp / 'hardware-under-test.zsh'
        module.write_text(script)
        proc = subprocess.run([ZSH, '-f', str(module)], capture_output=True, text=True, env=e, timeout=120,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout.splitlines()

    def test_syntax_and_static_rules(self):
        proc = subprocess.run([ZSH, '-n', str(ZSH_MODULE)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = '\n'.join(l for l in ZSH_MODULE.read_text(encoding='utf-8').splitlines() if not l.lstrip().startswith('#'))
        for pattern in (r'\bpython3?\b', r'\bsource\s', r'^\s*\.\s+\S', r'\beval\b', r'\bsudo\b', r'\bosascript\b',
                        r'\bdd\b', r'>\s*/(?!dev/null)', r'\bmktemp\b'):
            self.assertIsNone(re.search(pattern, text, re.M), pattern)

    def test_healthy_mac(self):
        lines = self.run_module()
        self.assertEqual(lines, [
            'hw-cpu pass count 10', 'hw-cpu-thermal pass percent 100', 'hw-memory pass bytes 17179869184',
            'hw-memory-errors not_applicable', 'hw-disk pass count 1', 'smart-health not_applicable',
            'nvme-health pass', 'hw-gpu pass count 1', 'hw-gpu-driver pass count 0', 'hw-display pass count 1',
            'hw-network-adapter pass count 2', 'hw-wifi pass count 0', 'hw-battery pass percent 80',
            'hw-usb pass count 2'])
        for line in lines:
            self.assertRegex(line, r'^[a-z0-9]+(-[a-z0-9]+)* (pass|fail|warn|not_applicable|unknown)'
                                   r'( (percent|count|bytes|days|seconds|celsius) [0-9]+)?$')
            self.assertIn(line.split()[0], HW_IDS)
        self.assertNotIn('00:11:22', '\n'.join(lines))

    def test_problems(self):
        lines = self.run_module(FAKE_SPEED='60', FAKE_CHARGE='7', FAKE_SMART='Failing', FAKE_WIFI='Off', FAKE_RAW='2000')
        got = dict(l.split(' ', 1) for l in lines)
        self.assertEqual(got['hw-cpu-thermal'], 'warn percent 60')
        self.assertEqual(got['hw-battery'], 'fail percent 7')
        self.assertEqual(got['nvme-health'], 'fail')
        self.assertEqual(got['hw-wifi'], 'warn count 1')
        lines = self.run_module(FAKE_SPEED='30', FAKE_CHARGE='15', FAKE_RAW='5700')
        got = dict(l.split(' ', 1) for l in lines)
        self.assertEqual(got['hw-cpu-thermal'], 'fail percent 30')
        self.assertEqual(got['hw-battery'], 'warn percent 15')

    def test_desktop_mac_has_no_battery(self):
        got = dict(l.split(' ', 1) for l in self.run_module('hardware.battery', FAKE_BATT='0'))
        self.assertEqual(got, {'hw-battery': 'not_applicable'})

    def test_scope_filtering(self):
        self.assertEqual([l.split()[0] for l in self.run_module('hardware.cpu')], ['hw-cpu', 'hw-cpu-thermal'])
        self.assertEqual([l.split()[0] for l in self.run_module('hardware.gpu,hardware.display')],
                         ['hw-gpu', 'hw-gpu-driver', 'hw-display'])
        self.assertEqual(self.run_module('os'), [])
        self.assertEqual(self.run_module('software'), [])

    def test_missing_tools_degrade_to_unknown(self):
        (self.tmp / 'system_profiler').write_text('#!/bin/bash\nexit 1\n')
        (self.tmp / 'networksetup').write_text('#!/bin/bash\nexit 1\n')
        (self.tmp / 'diskutil').write_text('#!/bin/bash\nexit 1\n')
        (self.tmp / 'ioreg').write_text('#!/bin/bash\nexit 1\n')
        got = dict(l.split(' ', 1) for l in self.run_module())
        for cid in ('hw-gpu', 'hw-display', 'hw-network-adapter', 'hw-wifi', 'hw-disk', 'smart-health', 'nvme-health', 'hw-usb'):
            self.assertEqual(got[cid], 'unknown', cid)

    def test_not_a_mac_prints_nothing(self):
        (self.tmp / 'pmset').unlink()
        proc = subprocess.run([ZSH, '-f', str(ZSH_MODULE)], capture_output=True, text=True, timeout=60,
                              env={'PATH': '/usr/bin:/bin', 'RESCUE_SCOPE': 'all'}, stdin=subprocess.DEVNULL)
        self.assertEqual((proc.returncode, proc.stdout), (0, ''))

    def test_slow_tool_is_bounded(self):
        (self.tmp / 'system_profiler').write_text('#!/bin/bash\nexec sleep 60\n')
        script = ZSH_MODULE.read_text(encoding='utf-8').replace('bounded 20 system_profiler', 'bounded 1 system_profiler') \
            .replace('export PATH=/usr/sbin:/usr/bin:/bin:/sbin', 'export PATH=%s:/usr/bin:/bin' % self.tmp)
        module = self.tmp / 'slow.zsh'
        module.write_text(script)
        import time
        started = time.time()
        proc = subprocess.run([ZSH, '-f', str(module)], capture_output=True, text=True, timeout=60,
                              env={'PATH': '/usr/bin:/bin', 'RESCUE_SCOPE': 'hardware.gpu'}, stdin=subprocess.DEVNULL)
        self.assertLess(time.time() - started, 20)
        self.assertEqual(proc.stdout.splitlines(), ['hw-gpu unknown', 'hw-gpu-driver unknown'])


if __name__ == '__main__':
    unittest.main()
