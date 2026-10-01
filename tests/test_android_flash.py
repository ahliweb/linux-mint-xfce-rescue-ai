#!/usr/bin/env python3
"""Offline tests for Android flashing and unbricking support (ahliweb/linux-mint-xfce-rescue-ai#52).

A fake sysfs tree stands in for /sys (RESCUE_REPAIR_TEST_USB_ROOT) and fake ``fastboot`` and ``heimdall``
programs, found only through RESCUE_REPAIR_TEST_PATH, answer from state files and log every call. The fake
fastboot also reads the firmware file it is handed (``/dev/fd/N``) and logs its SHA-256, so the tests prove
that the bytes that were hashed are the bytes that get flashed. Nothing touches a real phone, a real
bootloader or the network. Dummy values only.

* catalog: the shipped fastboot/Heimdall actions and the invariants that keep flashing confined (closed
  sub-command lists, partition allowlists, guards, no trigger, destructive, host platforms refused);
* detection: fastboot/Heimdall/EDL checks in the evidence (closed values, no product string, no serial);
* engine: fastboot_device (``usb:<port>``), firmware_file/sha256, partition and slot, guards (locked
  bootloader, product mismatch, one download-mode device), destructive policy, journal privacy;
* run report: the new refusal reasons in the Python, JXA (node) and PowerShell (static) generators.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_android as TA  # noqa: E402
import test_android_repair as AR  # noqa: E402
import test_host_repair as HR  # noqa: E402
import test_run_report as TR  # noqa: E402

REPO = HR.REPO
SCRIPTS = REPO / 'scripts'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
from rescue_modules import android, android_flash  # noqa: E402

NODE = AR.NODE
PRODUCT = 'sunfishtest'
LEAKS = AR.SERIAL_LEAKS + (PRODUCT, 'usb:3-2.1', '3-2.1')

FAKE_FASTBOOT = '''#!%(python)s
import hashlib, json, sys
DIR = %(dir)r
argv = sys.argv[1:]
state = json.load(open(DIR + '/fb_state.json'))
rec = {'argv': argv}
for a in argv:
    if a.startswith('/dev/fd/'):
        try:
            data = open(a, 'rb').read()
            rec['fw'] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        except OSError as exc:
            rec['fw'] = {'error': str(exc)}
with open(DIR + '/fb_calls.log', 'a') as handle:
    handle.write(json.dumps(rec) + '\\n')


def save():
    json.dump(state, open(DIR + '/fb_state.json', 'w'))


def done(text, code=0):
    sys.stderr.write(text)        # real fastboot prints its answers on stderr
    sys.exit(code)


if argv == ['devices', '-l']:
    sys.stdout.write(state['devices_l'])
    sys.exit(0)
if argv == ['devices']:
    sys.stdout.write(state.get('devices', ''))
    sys.exit(0)
if len(argv) >= 3 and argv[0] == '-s':
    if argv[1] != state['selector']:
        done('< waiting for %%s >\\nFAILED\\n' %% argv[1], 1)
    rest = argv[2:]
    if rest[0] == 'getvar':
        value = state['vars'].get(rest[1])
        if value is None:
            done('getvar:%%s FAILED (remote: GetVar Variable Not found)\\n' %% rest[1], 1)
        done('%%s: %%s\\nFinished. Total time: 0.001s\\n' %% (rest[1], value))
    if rest[0].startswith('--set-active='):
        if not state.get('sticky_slot'):
            state['vars']['current-slot'] = rest[0].split('=', 1)[1]
            save()
        done('Setting current slot to ... OKAY\\n')
    if rest[0] in ('flash', 'update'):
        if state.get('fail_' + rest[0]):
            done('FAILED (remote: not allowed in locked state)\\n', 1)
        done('Sending ... OKAY\\nFinished. Total time: 1.000s\\n')
    if rest[0] == 'reboot':
        state['devices_l'] = ''
        save()
        done('Rebooting ... OKAY\\n')
sys.exit(2)
'''

FAKE_HEIMDALL = '''#!%(python)s
import hashlib, json, sys
DIR = %(dir)r
argv = sys.argv[1:]
state = json.load(open(DIR + '/hm_state.json'))
rec = {'argv': argv}
for a in argv:
    if a.startswith('/dev/fd/'):
        rec['fw'] = {'sha256': hashlib.sha256(open(a, 'rb').read()).hexdigest()}
with open(DIR + '/hm_calls.log', 'a') as handle:
    handle.write(json.dumps(rec) + '\\n')
if argv == ['detect']:
    if state.get('detect_fails'):
        sys.stderr.write('Failed to detect compatible download-mode device.\\n')
        sys.exit(1)
    sys.stdout.write('Device detected\\n')
    sys.exit(0)
if argv == ['print-pit', '--no-reboot']:
    for i, name in enumerate(state['pit']):
        sys.stdout.write('--- Entry #%%d ---\\nBinary Type: 0 (AP)\\nIdentifier: %%d\\nPartition Name: %%s\\nFlash Filename: x.img\\n\\n' %% (i, i + 1, name))
    sys.exit(0)
if len(argv) == 4 and argv[0] == 'flash' and argv[3] == '--no-reboot':
    sys.stdout.write('Uploading %%s\\n%%s upload successful\\n' %% (argv[1], argv[1]))
    sys.exit(0)
sys.exit(2)
'''


def make_zip(path, android_info='require board=%s|%s_x\nrequire version-bootloader=1.0\n' % (PRODUCT, PRODUCT),
             members=(('boot.img', b'B' * 4096), ('system.img', b'S' * 4096)), pad=(1 << 20) + 1):
    """A fastboot-update-like zip of at least 1 MiB (the minimum the engine accepts), stored uncompressed."""
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
        if android_info is not None:
            archive.writestr('android-info.txt', android_info)
        for name, data in members:
            archive.writestr(name, data)
        archive.writestr('vendor.img', b'V' * pad)
    return path


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fastboot_line(serial, port):
    return '%-22s fastboot usb:%s\n' % (serial, port)


class FlashCase(AR.AndroidRepairCase):
    """A phone in fastboot mode (3-2.1, vendor Google, serial A), fake fastboot/heimdall, evidence from the real scanner."""

    def setUp(self):
        self.build()

    def build(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='android-flash-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / 'home'
        self.home.mkdir()
        self.machines = 0
        self.machine = self.fb_machine(TA.SERIAL_A)
        self.adb_dir = self.tmp / 'bin'
        self.adb_dir.mkdir()
        for name, template in (('adb', AR.FAKE_ADB), ('fastboot', FAKE_FASTBOOT), ('heimdall', FAKE_HEIMDALL)):
            (self.adb_dir / name).write_text(template % {'python': sys.executable, 'dir': str(self.adb_dir)})
            (self.adb_dir / name).chmod(0o755)
        (self.adb_dir / 'state.json').write_text(json.dumps({'devices': AR.HEADER, 'commands': {}}))
        self.set_fb(devices_l=fastboot_line(TA.SERIAL_A, '3-2.1'), devices=TA.SERIAL_A + '\tfastboot\n', selector='usb:3-2.1',
                    vars={'product': PRODUCT, 'unlocked': 'yes', 'current-slot': 'a', 'slot-count': '2', 'is-userspace': 'no'})
        (self.adb_dir / 'hm_state.json').write_text(json.dumps({'pit': ['BOOT', 'RECOVERY', 'VBMETA', 'DTBO', 'SYSTEM']}))
        self.journal = self.tmp / 'state' / 'repairs' / 'journal.jsonl'
        self.evidence = self.tmp / 'evidence.json'
        proc = self.scan(self.evidence, '--repair-policy', 'approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.ev = json.loads(self.evidence.read_text())
        self.assertEqual([t['ref'] for t in self.ev['target_systems']], ['and-0'])
        self.proof = self.tmp / 'backup.img'
        self.proof.write_bytes(b'backup reference' * 64)
        self.image = self.tmp / 'boot.img'
        self.image.write_bytes(os.urandom(8192))
        self.image_sha = sha256_of(self.image)
        self.zip = make_zip(self.tmp / 'image-test.zip')
        self.zip_sha = sha256_of(self.zip)
        for log in ('fb_calls.log', 'hm_calls.log', 'calls.log'):
            if (self.adb_dir / log).exists():
                (self.adb_dir / log).unlink()

    # ---------------------------------------------------------------- fixtures
    def fb_machine(self, serial, vid='18d1', pid='4ee0', interface='ff/42/03', port='3-2.1'):
        self.machines += 1
        sub = self.tmp / ('m-%d' % self.machines)
        sub.mkdir(parents=True, exist_ok=True)
        machine = TA.FakeMachine(sub)
        machine.add_device(port, vid, pid, [interface], speed=480, serial=serial)
        return machine

    def set_fb(self, **fields):
        path = self.adb_dir / 'fb_state.json'
        state = json.loads(path.read_text()) if path.exists() else {}
        for key, value in fields.items():
            if key == 'vars':
                state.setdefault('vars', {})
                state['vars'] = dict(state['vars'], **value) if state['vars'] else value
            else:
                state[key] = value
        path.write_text(json.dumps(state))

    def del_var(self, name):
        path = self.adb_dir / 'fb_state.json'
        state = json.loads(path.read_text())
        state['vars'].pop(name, None)
        path.write_text(json.dumps(state))

    def set_hm(self, **fields):
        path = self.adb_dir / 'hm_state.json'
        state = json.loads(path.read_text())
        state.update(fields)
        path.write_text(json.dumps(state))

    def fb_calls(self):
        path = self.adb_dir / 'fb_calls.log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def hm_calls(self):
        path = self.adb_dir / 'hm_calls.log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def writes(self, calls):
        """Calls that change the phone: flash, update, --set-active, reboot."""
        out = []
        for c in calls:
            a = c['argv']
            if a[:1] == ['-s'] and (a[2] in ('flash', 'update', 'reboot') or a[2].startswith('--set-active=')):
                out.append(a)
            if a[:1] == ['flash']:
                out.append(a)
        return out

    def flash_args(self, partition='boot', image=None, sha=None, aid='android.fastboot-flash-partition'):
        return ['--select', '%s:and-0' % aid, '--approve', aid, '--backup-ref', str(self.proof),
                '--param', '%s.partition=%s' % (aid, partition),
                '--param', '%s.firmware=%s' % (aid, image or self.image),
                '--param', '%s.firmware_sha256=%s' % (aid, sha or self.image_sha)]

    def update_args(self, image=None, sha=None, aid='android.fastboot-update-image'):
        return ['--select', '%s:and-0' % aid, '--approve', aid, '--backup-ref', str(self.proof),
                '--param', '%s.firmware=%s' % (aid, image or self.zip),
                '--param', '%s.firmware_sha256=%s' % (aid, sha or self.zip_sha)]

    def assert_refused(self, proc, reason, aid, writes=True):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        stages = self.stages(aid)
        self.assertEqual(stages[-1], ('precondition', 'fail', reason), stages)
        self.assertNotIn('execute', [s[0] for s in stages])
        if writes:
            self.assertEqual(self.writes(self.fb_calls()), [], 'nothing may be flashed after a refusal')
            self.assertEqual(self.writes(self.hm_calls()), [])
        self.assertIn('skipped', proc.stdout)
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def assert_private(self, text):
        for leak in LEAKS + (str(self.image), str(self.zip)):
            self.assertNotIn(leak, text)


# ----------------------------------------------------------------------------------------
# Catalog
# ----------------------------------------------------------------------------------------
def fb_action(**over):
    base = {
        'action_id': 'android.test-flash', 'title': 'Test flash', 'title_id': 'Uji flash', 'scope': 'android',
        'platforms': ['live-linux', 'linux-host'], 'target_families': ['android'], 'risk': 'destructive', 'triggers': [],
        'guards': ['bootloader-unlocked'],
        'params': [{'name': 'device', 'type': 'fastboot_device'},
                   {'name': 'partition', 'type': 'enum', 'values': ['boot', 'dtbo']},
                   {'name': 'firmware', 'type': 'firmware_file', 'values': ['image']},
                   {'name': 'firmware_sha256', 'type': 'sha256'}],
        'execute': {'argv': ['fastboot', '-s', '{device}', 'flash', '{partition}', '{firmware}']},
        'verify': {'argv': ['fastboot', '-s', '{device}', 'getvar', 'product']},
        'rollback': {'kind': 'manual', 'doc': 'docs/android.md'}, 'backup': {'required': True, 'what': 'partition-image'},
        'doc': 'docs/android.md',
    }
    base.update(over)
    return base


def hm_action(**over):
    base = {
        'action_id': 'android.test-heimdall', 'title': 'Test heimdall', 'title_id': 'Uji heimdall', 'scope': 'android',
        'platforms': ['live-linux'], 'target_families': ['android'], 'risk': 'destructive', 'triggers': [],
        'guards': ['single-download-mode-device'],
        'params': [{'name': 'partition', 'type': 'enum', 'values': ['BOOT', 'RECOVERY']},
                   {'name': 'firmware', 'type': 'firmware_file', 'values': ['image']},
                   {'name': 'firmware_sha256', 'type': 'sha256'}],
        'execute': {'argv': ['heimdall', 'flash', '--{partition}', '{firmware}', '--no-reboot']},
        'verify': {'argv': ['heimdall', 'detect']},
        'rollback': {'kind': 'manual', 'doc': 'docs/android.md'}, 'backup': {'required': True, 'what': 'partition-image'},
        'doc': 'docs/android.md',
    }
    base.update(over)
    return base


def swap(act, **steps):
    """Copy of *act* whose execute/verify argv is replaced."""
    import copy
    out = copy.deepcopy(act)
    out.update(steps)
    return out


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = rc.load()
        cls.actions = {a: v for a, v in cls.catalog.actions.items() if v['_domain'] == 'android'}

    def assertRejected(self, act, needle):
        errs = AR.errors_of(act)
        self.assertTrue(any(needle in e for e in errs), errs)

    def test_examples_load(self):
        self.assertEqual(AR.errors_of(fb_action()), [])
        self.assertEqual(AR.errors_of(hm_action()), [])

    def test_shipped_flashing_actions(self):
        table = {a: (v['risk'], v.get('guards', []), [p['type'] for p in v['params']], v['triggers'])
                 for a, v in self.actions.items() if 'fastboot' in a or 'heimdall' in a}
        self.assertEqual(table, {
            'android.fastboot-set-active-slot': ('reversible', [], ['fastboot_device', 'enum', 'fastboot_slot'], []),
            'android.fastboot-reboot': ('safe', [], ['fastboot_device'], []),
            'android.fastboot-flash-partition': ('destructive', ['bootloader-unlocked'],
                                                 ['fastboot_device', 'enum', 'firmware_file', 'sha256'], []),
            'android.fastboot-update-image': ('destructive', ['bootloader-unlocked', 'image-matches-device'],
                                              ['fastboot_device', 'firmware_file', 'sha256'], []),
            'android.heimdall-flash-partition': ('destructive', ['single-download-mode-device'],
                                                 ['enum', 'firmware_file', 'sha256'], [])})

    def test_destructive_flashing_requires_backup_manual_rollback_and_python_platforms(self):
        for aid, act in self.actions.items():
            if act['risk'] != 'destructive':
                continue
            with self.subTest(action=aid):
                self.assertTrue(act['backup']['required'])
                self.assertEqual(act['rollback']['kind'], 'manual')
                self.assertTrue(act['rollback']['doc'].startswith('docs/android.md#'))
                self.assertEqual(act['triggers'], [])
                self.assertEqual(set(act['platforms']), {'live-linux', 'linux-host'})

    def test_flash_partition_allowlist_in_the_shipped_catalog(self):
        values = {p['name']: p for p in self.actions['android.fastboot-flash-partition']['params']}['partition']['values']
        self.assertEqual(set(values), {'boot', 'init_boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'recovery'})
        for bad in ('bootloader', 'radio', 'modem', 'persist', 'frp', 'devinfo', 'modemst1', 'modemst2', 'fsg', 'efs', 'userdata'):
            self.assertNotIn(bad, values)
        hvalues = {p['name']: p for p in self.actions['android.heimdall-flash-partition']['params']}['partition']['values']
        self.assertEqual(set(hvalues), {'BOOT', 'RECOVERY', 'VBMETA', 'DTBO'})

    def test_no_forbidden_flashing_word_in_the_catalog(self):
        text = json.dumps([v for a, v in self.actions.items() if 'fastboot' in a or 'heimdall' in a])
        for word in ('erase', 'format', '-w', 'oem', 'flashing', 'unlock', 'lock', 'reboot-bootloader', 'flashall', 'flash-all',
                     '--slot', '--disable-verity', '--disable-verification', 'sh', 'bash', 'continue', 'snapshot-update'):
            self.assertIsNone(re.search(r'"%s"' % re.escape(word), text), word)

    def test_fastboot_subcommands_are_a_closed_list(self):
        base = ['fastboot', '-s', '{device}']
        for tail in (['erase', '{partition}'], ['format', 'userdata'], ['-w'], ['flashing', 'unlock'], ['flashing', 'lock'],
                     ['oem', 'unlock'], ['reboot', 'bootloader'], ['reboot-bootloader'], ['continue'], ['flashall'],
                     ['--slot=all', 'flash', '{partition}', '{firmware}'], ['getvar', 'serialno'], ['getvar', 'all'],
                     ['getvar'], ['update', '-w', '{firmware}'], ['--set-active'], ['set_active', 'a'], ['--disable-verity', 'flash']):
            with self.subTest(tail=tail):
                self.assertRejected(swap(fb_action(), verify={'argv': base + tail}), 'fastboot')
                self.assertRejected(swap(fb_action(), execute={'argv': base + tail}), 'fastboot')

    def test_fastboot_must_be_addressed_to_the_device(self):
        self.assertRejected(swap(fb_action(), verify={'argv': ['fastboot', 'getvar', 'product']}), 'addressed as -s')
        self.assertRejected(swap(fb_action(), verify={'argv': ['fastboot', '-s', '1234', 'getvar', 'product']}), 'addressed as -s')
        self.assertRejected(swap(fb_action(), verify={'argv': ['fastboot', '-s', '{device}', 'getvar', 'product', 'x']}), 'getvar')
        self.assertEqual(AR.errors_of(swap(fb_action(), verify={'argv': ['fastboot', 'devices']})), [])
        self.assertRejected(swap(fb_action(), verify={'argv': ['fastboot', 'devices', '-l']}), 'addressed as -s')

    def test_flash_partition_must_be_an_allowlisted_enum(self):
        for bad in ('bootloader', 'radio', 'modem', 'persist', 'efs', 'frp', 'userdata', 'devinfo', 'system'):
            params = [dict(p, values=['boot', bad]) if p['name'] == 'partition' else p for p in fb_action()['params']]
            with self.subTest(partition=bad):
                self.assertRejected(fb_action(params=params), 'allowlist' if False else 'partitions must be an enum within')
        params = [p for p in fb_action()['params'] if p['name'] != 'partition'] + [{'name': 'partition', 'type': 'package_name'}]
        self.assertRejected(fb_action(params=params), 'partitions must be an enum within')
        self.assertRejected(swap(fb_action(), execute={'argv': ['fastboot', '-s', '{device}', 'flash', 'bootloader', '{firmware}']}),
                            'partitions must be an enum within')

    def test_firmware_parameters(self):
        no_sha = [p for p in fb_action()['params'] if p['type'] != 'sha256']
        self.assertRejected(fb_action(params=no_sha), 'needs a sha256 parameter named firmware_sha256')
        update = [{'name': 'device', 'type': 'fastboot_device'}, {'name': 'firmware', 'type': 'firmware_file', 'values': ['zip']},
                  {'name': 'firmware_sha256', 'type': 'sha256'}, {'name': 'other_sha256', 'type': 'sha256'}]
        self.assertRejected(fb_action(params=update, guards=['bootloader-unlocked', 'image-matches-device'],
                                      execute={'argv': ['fastboot', '-s', '{device}', 'update', '{firmware}']}),
                            'must be named <firmware_file name>_sha256')
        no_fastboot = [p for p in fb_action()['params'] if p['type'] != 'fastboot_device']
        self.assertRejected(fb_action(params=no_fastboot), 'exactly one fastboot_device')
        zip_kind = [dict(p, values=['zip']) if p['name'] == 'firmware' else p for p in fb_action()['params']]
        self.assertRejected(fb_action(params=zip_kind), 'firmware_file parameter of kind image')
        bad_kind = [dict(p, values=['tar']) if p['name'] == 'firmware' else p for p in fb_action()['params']]
        self.assertRejected(fb_action(params=bad_kind), 'needs exactly one value')
        self.assertRejected(fb_action(params=[dict(p, default='/x') if p['name'] == 'firmware' else p for p in fb_action()['params']]),
                            'cannot have a default')

    def test_flashing_needs_destructive_no_trigger_and_the_guards(self):
        self.assertRejected(fb_action(risk='reversible', rollback={'kind': 'step', 'step': {'argv': ['fastboot', 'devices']}},
                                      backup={'required': False}), 'flashing actions are destructive')
        self.assertRejected(fb_action(triggers=[{'check_id': 'android-storage-free', 'status': ['fail']}]), 'never proposed by a trigger')
        self.assertRejected(fb_action(guards=[]), 'needs the bootloader-unlocked guard')
        self.assertRejected(hm_action(guards=[]), 'single-download-mode-device')
        update = fb_action(params=[{'name': 'device', 'type': 'fastboot_device'},
                                   {'name': 'firmware', 'type': 'firmware_file', 'values': ['zip']},
                                   {'name': 'firmware_sha256', 'type': 'sha256'}],
                           execute={'argv': ['fastboot', '-s', '{device}', 'update', '{firmware}']})
        self.assertRejected(update, 'needs the image-matches-device guard')
        self.assertEqual(AR.errors_of(swap(update, guards=['bootloader-unlocked', 'image-matches-device'])), [])
        self.assertRejected(swap(update, guards=['image-matches-device']), 'bootloader-unlocked')
        self.assertRejected(swap(update, guards=['bootloader-unlocked', 'image-matches-device'],
                                 execute={'argv': ['fastboot', '-s', '{device}', 'update', '-w', '{firmware}']}), 'fastboot')

    def test_guards_and_new_fields_exist_only_on_the_python_engine_platforms(self):
        for platforms in (['windows-host'], ['macos-host'], ['live-linux', 'windows-host']):
            self.assertRejected(fb_action(platforms=platforms), 'platforms must be within')
        host_domain = fb_action(action_id='os-windows.test', scope='os', target_families=['windows'], platforms=['windows-host'])
        errs = AR.errors_of(host_domain, 'os-windows')
        self.assertTrue(any('guards exist only on' in e for e in errs), errs)
        self.assertTrue(any('fastboot_device parameters exist only on' in e for e in errs), errs)
        act = AR.android_action(verify={'argv': ['adb', '-t', '{device}', 'shell', 'settings', 'get', 'global', 'k'], 'expect_line': '1'})
        self.assertEqual(AR.errors_of(act), [])
        host_line = dict(AR.android_action(), action_id='os-windows.line', scope='os', target_families=['windows'], platforms=['windows-host'],
                         params=[], execute={'argv': ['rescuefake', 'x']}, verify={'argv': ['rescuefake', 'y'], 'expect_line': '1'})
        self.assertTrue(any('expect_line exists only on' in e for e in AR.errors_of(host_line, 'os-windows')))

    def test_expect_line_rules(self):
        for line in ('x{', '{a}b', 'a {b} {c}', 'a\nb', '', '$(id)', 'a;b', '`x`'):
            act = AR.android_action(verify={'argv': ['adb', '-t', '{device}', 'get-state'], 'expect_line': line})
            with self.subTest(line=line):
                self.assertTrue(AR.errors_of(act))
        act = AR.android_action(verify={'argv': ['adb', '-t', '{device}', 'get-state'], 'expect_line': 'current-slot: {slot}'})
        self.assertRejected(act, 'must be a declared enum parameter')
        self.assertEqual(rc.render_expect_line('current-slot: {slot}', {'slot': 'b'}), 'current-slot: b')
        self.assertEqual(rc.render_expect_line('Partition Name: {partition}', {'partition': 'BOOT'}), 'Partition Name: BOOT')
        self.assertEqual(rc.render_expect_line('unlocked: yes', {}), 'unlocked: yes')

    def test_set_active_rules(self):
        slot = [{'name': 'device', 'type': 'fastboot_device'}, {'name': 'slot', 'type': 'enum', 'values': ['a', 'b']}]
        ok = fb_action(risk='reversible', guards=[], params=slot, backup={'required': False},
                       execute={'argv': ['fastboot', '-s', '{device}', '--set-active={slot}']},
                       verify={'argv': ['fastboot', '-s', '{device}', 'getvar', 'current-slot'], 'expect_line': 'current-slot: {slot}'},
                       rollback={'kind': 'step', 'step': {'argv': ['fastboot', '-s', '{device}', '--set-active={slot}']}})
        self.assertEqual(AR.errors_of(ok), [])
        wide = [slot[0], {'name': 'slot', 'type': 'enum', 'values': ['a', 'b', 'c']}]
        self.assertRejected(swap(ok, params=wide), 'limited to a/b')
        self.assertRejected(swap(ok, params=[slot[0], {'name': 'slot', 'type': 'package_name'}]), 'limited to a/b')
        extra = slot + [{'name': 'previous_slot', 'type': 'fastboot_slot'}]
        self.assertRejected(swap(ok, params=extra), 'declared but never used')
        stray = swap(ok, params=extra, verify={'argv': ['fastboot', '-s', '{device}', 'getvar', 'current-slot'],
                                              'expect_line': 'current-slot: {slot}'},
                     rollback={'kind': 'step', 'step': {'argv': ['fastboot', '-s', '{device}', 'getvar', 'product']}})
        self.assertRejected(stray, 'declared but never used')

    def test_option_placeholder_is_for_enums_only(self):
        self.assertEqual(rc.render(['heimdall', 'flash', '--{partition}', '{firmware}', '--no-reboot'],
                                   {'partition': 'BOOT', 'firmware': '/dev/fd/9'}),
                         ['heimdall', 'flash', '--BOOT', '/dev/fd/9', '--no-reboot'])
        bad = [{'name': 'partition', 'type': 'package_name'} if p['name'] == 'partition' else p for p in hm_action()['params']]
        self.assertRejected(hm_action(params=bad), '--{name} is only allowed for an enum')

    def test_heimdall_commands_are_a_closed_list(self):
        for argv in (['heimdall', 'print-pit'], ['heimdall', 'print-pit', '--file', 'x'], ['heimdall', 'download-pit', '--output', 'x'],
                     ['heimdall', 'flash', '--{partition}', '{firmware}'], ['heimdall', 'flash', '--PIT', '{firmware}', '--no-reboot'],
                     ['heimdall', 'flash', '--{partition}', '{firmware}', '--no-reboot', '--repartition'],
                     ['heimdall', 'close-pc-screen'], ['heimdall', 'flash', '--repartition', '--pit', '{firmware}']):
            with self.subTest(argv=argv):
                self.assertRejected(swap(hm_action(), verify={'argv': argv}), 'heimdall')
        for argv in (['heimdall', 'detect'], ['heimdall', 'print-pit', '--no-reboot']):
            self.assertEqual(AR.errors_of(swap(hm_action(), verify={'argv': argv})), [])
        wide = [dict(p, values=['BOOT', 'SBL1']) if p['name'] == 'partition' else p for p in hm_action()['params']]
        self.assertRejected(hm_action(params=wide), 'partitions must be an enum within')

    def test_guard_dependencies(self):
        self.assertRejected(AR.android_action(guards=['bootloader-unlocked']), 'needs a fastboot_device')
        self.assertRejected(AR.android_action(guards=['image-matches-device']), 'needs a fastboot_device and a firmware_file')
        self.assertRejected(hm_action(params=hm_action()['params'] + [{'name': 'device', 'type': 'fastboot_device'}],
                                      verify={'argv': ['fastboot', '-s', '{device}', 'getvar', 'product']}), 'replaces a device parameter')
        self.assertRejected(fb_action(guards=['made-up']), 'is not one of')

    def test_validate_param_for_the_operator_types(self):
        fw = {'name': 'firmware', 'type': 'firmware_file', 'values': ['image']}
        sha = {'name': 'firmware_sha256', 'type': 'sha256'}
        self.assertEqual(rc.validate_param(fw, '/media/usb/boot.img'), '/media/usb/boot.img')
        for bad in ('boot.img', './boot.img', '/media/../etc/x', '/media//x', '/media/x/', '/x\x00y', '/x\ny', '/' + 'a' * 1100,
                    '', 'C:\\x', '~/x'):
            with self.subTest(path=bad):
                with self.assertRaises(ValueError):
                    rc.validate_param(fw, bad)
        self.assertEqual(rc.validate_param(sha, 'AB' * 32), 'ab' * 32)
        for bad in ('ab' * 31, 'ab' * 33, 'zz' * 32, '', ' ' + 'ab' * 32, 'ab' * 32 + '\n'):
            with self.subTest(sha=bad):
                with self.assertRaises(ValueError):
                    rc.validate_param(sha, bad)
        for kind in ('fastboot_device', 'fastboot_slot'):
            with self.assertRaises(ValueError):
                rc.validate_param({'name': 'x', 'type': kind}, 'usb:3-2.1')

    def test_prompt_summary_never_carries_argv_or_paths(self):
        rows = rc.prompt_summary(self.catalog, {'source_platform': 'linux-mint-xfce-live'}, ('all',))
        text = json.dumps(rows)
        self.assertIn('android.fastboot-flash-partition', text)
        for word in ('argv', '/dev/fd', 'usb:'):
            self.assertNotIn(word, text)

    def test_ai_may_propose_a_flashing_action_but_it_is_never_auto_run(self):
        text = ('```rescue-proposals\n{"proposed_actions":[{"action_id":"android.fastboot-flash-partition","target_ref":"and-0"}]}\n```')
        ev = {'source_platform': 'linux-mint-xfce-live', 'target_systems': [{'ref': 'and-0', 'family': 'android'}], 'checks': []}
        accepted, rejected = rc.parse_ai_proposals(text, self.catalog, ev, ('all',))
        self.assertEqual([(p['action_id'], p['origin']) for p in accepted], [('android.fastboot-flash-partition', 'ai-proposal')])
        self.assertEqual(rejected, 0)


# ----------------------------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------------------------
class ParsingTests(unittest.TestCase):
    def test_devices_list_maps_to_ports(self):
        text = ('SERIALA0123456789        fastboot usb:3-2.1\n'
                'SERIALB                  Android Fastboot usb:1-4\n'
                'no permissions (user in plugdev group; are your udev rules wrong?); see [x] fastboot usb:1-5\n'
                'junk line\n'
                'SERIALC fastboot usb:../../etc\n')
        got = android_flash.parse_devices(text)
        self.assertEqual(got['ports'], {'3-2.1', '1-4', '1-5'})
        self.assertEqual(got['denied'], {'1-5'})
        self.assertEqual(android_flash.parse_devices('')['ports'], set())
        self.assertEqual(android_flash.parse_devices(None)['ports'], set())

    def test_getvar_values_are_closed_sets(self):
        p = android_flash.parse_getvar
        self.assertEqual(p('unlocked: yes\nFinished. Total time: 0.001s', 'unlocked'), 'yes')
        self.assertEqual(p('unlocked: no', 'unlocked'), 'no')
        self.assertIsNone(p('unlocked: maybe', 'unlocked'))
        self.assertIsNone(p('unlocked: yes please', 'unlocked'))
        self.assertEqual(p('current-slot: a', 'current-slot'), 'a')
        self.assertIsNone(p('current-slot: _a', 'current-slot'))
        self.assertIsNone(p('current-slot: c', 'current-slot'))
        self.assertEqual(p('slot-count: 2', 'slot-count'), 2)
        self.assertIsNone(p('slot-count: 999', 'slot-count'))
        self.assertIsNone(p('slot-count: two', 'slot-count'))
        self.assertEqual(p('is-userspace: yes', 'is-userspace'), 'yes')
        self.assertIsNone(p('product: sunfish', 'unlocked'))
        self.assertIsNone(p('getvar:unlocked FAILED (remote: x)', 'unlocked'))
        self.assertIsNone(p(None, 'unlocked'))

    def test_checks(self):
        c = android_flash
        self.assertEqual(c.lock_state_check('no')['status'], 'pass')
        self.assertEqual(c.lock_state_check('yes')['status'], 'warn')
        self.assertEqual(c.lock_state_check(None)['status'], 'unknown')
        self.assertEqual(c.slot_check('a', 2), {'check_id': 'android-fastboot-slot', 'status': 'pass', 'kind': 'count', 'number': 2})
        self.assertEqual(c.slot_check(None, 1)['status'], 'not_applicable')
        self.assertEqual(c.slot_check(None, None)['status'], 'unknown')
        self.assertEqual(c.slot_check('a', None)['status'], 'unknown')
        self.assertEqual(c.userspace_check('no')['status'], 'pass')
        self.assertEqual(c.userspace_check('yes')['status'], 'warn')
        self.assertEqual(c.low_level_check()['status'], 'warn')
        for check in (c.lock_state_check('no'), c.slot_check('a', 2), c.userspace_check('no'), c.low_level_check()):
            self.assertIn(check['check_id'], c.CHECK_IDS)

    def test_new_check_ids_are_in_the_evidence_schema(self):
        schema = json.loads((REPO / 'rescue-ai/v1/rescue-evidence.schema.json').read_text())
        ids = set(schema['properties']['checks']['items']['properties']['check_id']['enum'])
        self.assertTrue(set(android_flash.CHECK_IDS) <= ids)


class DetectionTests(FlashCase):
    def checks(self, ev=None):
        return {c['check_id']: c for c in (ev or self.ev)['checks'] if c.get('target_ref') == 'and-0'}

    def test_fastboot_phone_gets_lock_slot_and_userspace_checks(self):
        got = self.checks()
        self.assertEqual(got['android-connection-mode']['status'], 'warn')
        self.assertEqual(got['android-fastboot-lock-state']['status'], 'warn')          # unlocked
        self.assertEqual((got['android-fastboot-slot']['status'], got['android-fastboot-slot']['value']),
                         ('pass', {'kind': 'count', 'number': 2}))
        self.assertEqual(got['android-fastboot-userspace']['status'], 'pass')
        self.assertNotIn('android-heimdall-detect', got)
        self.assertNotIn('android-low-level-mode', got)
        self.assertEqual(got['android-os-version']['status'], 'unknown')               # no adb for a fastboot phone
        self.assertEqual(self.ev['target_systems'][0]['access'], 'usb-only')

    def test_locked_and_non_ab_and_fastbootd(self):
        self.set_fb(vars={'unlocked': 'no', 'is-userspace': 'yes'})
        self.del_var('current-slot')
        self.del_var('slot-count')
        out = self.tmp / 'ev2.json'
        self.assertEqual(self.scan(out).returncode, 0)
        got = self.checks(json.loads(out.read_text()))
        self.assertEqual(got['android-fastboot-lock-state']['status'], 'pass')
        self.assertEqual(got['android-fastboot-slot']['status'], 'unknown')
        self.assertEqual(got['android-fastboot-userspace']['status'], 'warn')

    def test_evidence_carries_no_product_serial_or_selector(self):
        self.assertEqual(self.scan(self.evidence).returncode, 0)
        text = self.evidence.read_text()
        for leak in (TA.SERIAL_A, TA.SERIAL_B, PRODUCT, 'usb:', 'Galaxy Secret Model'):   # usb_port (3-2.1) is allowed evidence
            self.assertNotIn(leak, text)
        calls = self.fb_calls()
        self.assertEqual(calls[0]['argv'], ['devices', '-l'])
        self.assertEqual([c['argv'] for c in calls[1:]], [['-s', 'usb:3-2.1', 'getvar', v] for v in android_flash.GETVARS])
        self.assertNotIn('product', [c['argv'][-1] for c in calls])

    def test_without_fastboot_or_without_permission_the_checks_are_unknown(self):
        (self.adb_dir / 'fastboot').unlink()
        out = self.tmp / 'ev3.json'
        self.assertEqual(self.scan(out).returncode, 0)
        got = self.checks(json.loads(out.read_text()))
        self.assertEqual([got[c]['status'] for c in ('android-fastboot-lock-state', 'android-fastboot-slot', 'android-fastboot-userspace')],
                         ['unknown'] * 3)
        (self.adb_dir / 'fastboot').write_text(FAKE_FASTBOOT % {'python': sys.executable, 'dir': str(self.adb_dir)})
        (self.adb_dir / 'fastboot').chmod(0o755)
        self.set_fb(devices_l='no permissions (user in plugdev group; are your udev rules wrong?) fastboot usb:3-2.1\n')
        self.assertEqual(self.scan(out).returncode, 0)
        got = self.checks(json.loads(out.read_text()))
        self.assertEqual(got['android-fastboot-lock-state']['status'], 'unknown')
        self.assertEqual([c['argv'][0] for c in self.fb_calls()[-1:]], ['devices'])

    def test_unreadable_values_and_hostile_output_stay_unknown(self):
        self.set_fb(vars={'unlocked': 'rm -rf /', 'current-slot': '$(id)', 'slot-count': '9999999', 'is-userspace': 'maybe'})
        out = self.tmp / 'ev4.json'
        self.assertEqual(self.scan(out).returncode, 0)
        got = self.checks(json.loads(out.read_text()))
        self.assertEqual([got[c]['status'] for c in ('android-fastboot-lock-state', 'android-fastboot-slot', 'android-fastboot-userspace')],
                         ['unknown'] * 3)
        self.assertNotIn('rm -rf', out.read_text())

    def test_evidence_validates_and_guidance_mentions_the_manual_unlock(self):
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'validate-evidence.py'), str(self.evidence)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        argv = [sys.executable, str(SCRIPTS / 'scan-android.py'), '--fixture-root', str(self.machine.root), '--adb-path',
                str(self.adb_dir), '--list-usb']
        out = subprocess.run(argv, capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('TIDAK dilakukan toolkit', out.stdout)
        self.assertIn('NOT done by this toolkit', out.stdout)
        for leak in (TA.SERIAL_A, PRODUCT, 'usb:'):                # the table may show the port and brand, never these
            self.assertNotIn(leak, out.stdout)

    def test_samsung_download_mode_gets_the_heimdall_check_when_one_device_is_attached(self):
        machine = self.fb_machine(TA.SERIAL_B, vid='04e8', pid='685d', interface='ff/ff/ff')
        out = self.tmp / 'ev5.json'
        argv = [sys.executable, str(SCRIPTS / 'scan-android.py'), '--fixture-root', str(machine.root), '--adb-path', str(self.adb_dir),
                '--output', str(out)]
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}
        self.assertEqual(subprocess.run(argv, capture_output=True, text=True, env=env).returncode, 0)
        got = self.checks(json.loads(out.read_text()))
        self.assertEqual(got['android-heimdall-detect']['status'], 'pass')
        self.assertNotIn('android-fastboot-lock-state', got)
        self.assertEqual(self.hm_calls()[-1]['argv'], ['detect'])
        self.set_hm(detect_fails=True)
        subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(self.checks(json.loads(out.read_text()))['android-heimdall-detect']['status'], 'warn')
        # two download-mode devices: heimdall could not tell which one it would touch, so it is not even run
        machine.add_device('3-2.2', '04e8', '685d', ['ff/ff/ff'], serial='OTHERDL')
        self.hm_calls_before = len(self.hm_calls())
        subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(self.checks(json.loads(out.read_text()))['android-heimdall-detect']['status'], 'unknown')
        self.assertEqual(len(self.hm_calls()), self.hm_calls_before)

    def test_edl_and_brom_are_guidance_only(self):
        for vid, pid, label in (('05c6', '9008', 'EDL'), ('0e8d', '0003', 'BROM'), ('0e8d', '2000', 'preloader')):
            with self.subTest(mode=label):
                machine = self.fb_machine(TA.SERIAL_B, vid=vid, pid=pid, interface='ff/ff/ff')
                out = self.tmp / ('ev-%s.json' % label)
                base = [sys.executable, str(SCRIPTS / 'scan-android.py'), '--fixture-root', str(machine.root), '--adb-path',
                        str(self.adb_dir)]
                env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}
                self.assertEqual(subprocess.run(base + ['--output', str(out)], capture_output=True, text=True, env=env).returncode, 0)
                got = self.checks(json.loads(out.read_text()))
                self.assertEqual(got['android-low-level-mode']['status'], 'warn')
                self.assertNotIn('android-fastboot-lock-state', got)
                self.assertNotIn('android-heimdall-detect', got)
                table = subprocess.run(base + ['--list-usb'], capture_output=True, text=True, env=env).stdout
                self.assertIn('pusat servis resmi', table)
                self.assertIn('authorized service center', table)
        # no fastboot, heimdall, adb or any other program was asked to talk to them
        self.assertEqual([c['argv'] for c in self.hm_calls()], [])


# ----------------------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------------------
class FlashEngineTests(FlashCase):
    def test_flash_partition_runs_on_the_usb_selector_with_the_hashed_bytes(self):
        proc = self.engine(*self.flash_args())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        aid = 'android.fastboot-flash-partition'
        self.assertEqual([s[:2] for s in self.stages(aid)],
                         [('proposed', 'ok'), ('backup', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        flashes = [c for c in self.fb_calls() if c['argv'][2:3] == ['flash']]
        self.assertEqual(len(flashes), 1)
        argv = flashes[0]['argv']
        self.assertEqual(argv[:4], ['-s', 'usb:3-2.1', 'flash', 'boot'])
        self.assertRegex(argv[4], r'^/dev/fd/[0-9]+$')
        self.assertEqual(flashes[0]['fw'], {'sha256': self.image_sha, 'size': 8192})        # what fastboot read is what was hashed
        self.assertIn('verified', proc.stdout)
        verify = [c for c in self.fb_calls() if c['argv'][2:] == ['getvar', 'product']]
        self.assertTrue(verify)

    def test_journal_has_the_sha256_but_not_the_path_the_serial_or_the_selector(self):
        proc = self.engine(*self.flash_args())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.journal_text()
        approval = [r for r in read_journal(self.journal) if r['stage'] == 'approval'][0]
        self.assertEqual(approval['params'], {'partition': 'boot', 'firmware_sha256': self.image_sha})
        self.assertIn(self.image_sha, text)
        self.assertNotIn('firmware"', text)
        self.assert_private(text + proc.stdout + proc.stderr)
        self.assertNotIn(str(self.proof), text)
        chain = subprocess.run([sys.executable, str(AR.REPAIR), '--verify-journal', str(self.journal)], capture_output=True, text=True)
        self.assertEqual(chain.returncode, 0, chain.stdout)

    def test_destructive_needs_backup_ref_and_never_runs_without_it(self):
        args = [a for a in self.flash_args() if a not in ('--backup-ref', str(self.proof))]
        proc = self.engine(*args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.fastboot-flash-partition'), [('proposed', 'ok', None), ('backup', 'unavailable', 'missing-backup')])
        self.assertEqual(self.fb_calls(), [])
        empty = self.tmp / 'empty.bin'
        empty.write_bytes(b'')
        proc = self.engine(*self.flash_args(), '--backup-ref', str(empty))
        self.assertEqual(self.writes(self.fb_calls()), [])

    def test_destructive_needs_the_typed_action_id_when_interactive(self):
        aid = 'android.fastboot-flash-partition'
        argv = [sys.executable, str(AR.REPAIR), '--evidence', str(self.evidence), '--journal', str(self.journal),
                '--select', aid + ':and-0', '--backup-ref', str(self.proof),
                '--param', aid + '.partition=boot', '--param', aid + '.firmware=' + str(self.image),
                '--param', aid + '.firmware_sha256=' + self.image_sha]
        code, out = HR.run_pty(argv, self.env(), self.tmp, ['yes'])
        self.assertEqual(code, 0, out)
        self.assertIn('type the action_id to approve', out)
        self.assertEqual(self.stages(aid)[-1], ('approval', 'declined', 'operator-declined'))
        self.assertEqual(self.writes(self.fb_calls()), [])
        self.assertIn('<fastboot and-0>', out)
        self.assertIn('<firmware image file>', out)
        self.assertIn('guards: bootloader-unlocked', out)
        self.assert_private(out)
        self.journal.unlink()
        code, out = HR.run_pty(argv, self.env(), self.tmp, [aid])
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stages(aid)[-1], ('verify', 'ok', None))
        self.assertEqual(len(self.writes(self.fb_calls())), 1)

    def test_auto_safe_and_detect_only_never_run_flashing(self):
        for policy in ('auto-safe', 'detect-only'):
            with self.subTest(policy=policy):
                if self.journal.exists():
                    self.journal.unlink()
                proc = self.engine('--policy', policy, '--select', 'android.fastboot-flash-partition:and-0',
                                   '--select', 'android.fastboot-update-image:and-0', '--select', 'android.heimdall-flash-partition:and-0',
                                   '--backup-ref', str(self.proof))
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(self.writes(self.fb_calls()) + self.writes(self.hm_calls()), [])
                self.assertEqual({r['stage'] for r in read_journal(self.journal)} - {'proposed', 'approval', 'backup'}, set())
        # nothing in the evidence proposes a flashing action by itself
        self.assertEqual([p['action_id'] for p in self.ev.get('repair_proposals', [])], [])
        proc = self.engine('--policy', 'auto-safe', '--list')
        self.assertNotIn('flash', proc.stdout)

    def test_locked_bootloader_is_refused_with_manual_unlock_guidance(self):
        self.set_fb(vars={'unlocked': 'no'})
        proc = self.engine(*self.flash_args())
        self.assert_refused(proc, 'bootloader-locked', 'android.fastboot-flash-partition')
        self.assertIn('docs/android.md#bootloader-terkunci', proc.stderr + proc.stdout)
        self.assertIn('NEVER unlocks', proc.stdout)
        # no unlock command exists anywhere
        self.assertEqual([c['argv'] for c in self.fb_calls() if 'flashing' in c['argv'] or 'oem' in c['argv']], [])

    def test_unreadable_lock_state_is_treated_as_locked(self):
        self.del_var('unlocked')
        self.assert_refused(self.engine(*self.flash_args()), 'bootloader-locked', 'android.fastboot-flash-partition')

    def test_sha256_mismatch_is_refused_before_anything_is_flashed(self):
        proc = self.engine(*self.flash_args(sha='0' * 64))
        self.assert_refused(proc, 'firmware-hash-mismatch', 'android.fastboot-flash-partition')
        self.assertIn('not the one you supplied', proc.stderr)

    def test_sha256_is_case_insensitive_and_must_be_64_hex(self):
        proc = self.engine(*self.flash_args(sha=self.image_sha.upper()))
        self.assertEqual(self.stages('android.fastboot-flash-partition')[-1], ('verify', 'ok', None), proc.stdout + proc.stderr)
        self.journal.unlink()
        proc = self.engine(*self.flash_args(sha='abc'))
        self.assertEqual(self.stages('android.fastboot-flash-partition')[-1], ('approval', 'skipped', 'invalid-param'))
        self.assertEqual(len(self.writes(self.fb_calls())), 1)

    def test_relative_and_non_normalized_paths_are_refused(self):
        for path in ('boot.img', 'a/../boot.img', './boot.img'):
            with self.subTest(path=path):
                if self.journal.exists():
                    self.journal.unlink()
                proc = self.engine(*self.flash_args(image=path))
                self.assertEqual(self.stages('android.fastboot-flash-partition')[-1], ('approval', 'skipped', 'invalid-param'))
                self.assertEqual(self.writes(self.fb_calls()), [])

    def test_symlink_directory_and_fifo_are_refused(self):
        link = self.tmp / 'link.img'
        link.symlink_to(self.image)
        self.assert_refused(self.engine(*self.flash_args(image=str(link))), 'firmware-invalid', 'android.fastboot-flash-partition')
        self.journal.unlink()
        self.assert_refused(self.engine(*self.flash_args(image=str(self.tmp))), 'firmware-invalid', 'android.fastboot-flash-partition')
        self.journal.unlink()
        fifo = self.tmp / 'fifo.img'
        os.mkfifo(fifo)
        self.assert_refused(self.engine(*self.flash_args(image=str(fifo))), 'firmware-invalid', 'android.fastboot-flash-partition')
        self.journal.unlink()
        self.assert_refused(self.engine(*self.flash_args(image=str(self.tmp / 'missing.img'))), 'firmware-invalid',
                            'android.fastboot-flash-partition')

    def test_size_bounds_and_zip_in_place_of_an_image(self):
        tiny = self.tmp / 'tiny.img'
        tiny.write_bytes(b'x' * 100)
        self.assert_refused(self.engine(*self.flash_args(image=str(tiny), sha=sha256_of(tiny))), 'firmware-invalid',
                            'android.fastboot-flash-partition')
        self.journal.unlink()
        self.assert_refused(self.engine(*self.flash_args(image=str(self.zip), sha=self.zip_sha)), 'firmware-invalid',
                            'android.fastboot-flash-partition')
        self.assertIn('this is a zip', ''.join(self.engine(*self.flash_args(image=str(self.zip), sha=self.zip_sha)).stderr))

    def test_a_partition_outside_the_allowlist_is_refused(self):
        for bad in ('bootloader', 'radio', 'modem', 'persist', 'efs', 'frp', 'userdata', 'devinfo', 'system', 'BOOT', 'boot_a', '../boot'):
            with self.subTest(partition=bad):
                if self.journal.exists():
                    self.journal.unlink()
                self.engine(*self.flash_args(partition=bad))
                self.assertEqual(self.stages('android.fastboot-flash-partition')[-1], ('approval', 'skipped', 'invalid-param'))
        self.assertEqual(self.writes(self.fb_calls()), [])
        for good in ('init_boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'recovery'):
            with self.subTest(partition=good):
                self.journal.unlink()
                self.engine(*self.flash_args(partition=good))
                self.assertEqual(self.stages('android.fastboot-flash-partition')[-1], ('verify', 'ok', None))
        self.assertEqual([c['argv'][3] for c in self.fb_calls() if c['argv'][2:3] == ['flash']],
                         ['init_boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'recovery'])

    def test_a_failing_flash_is_journaled_and_needs_manual_rollback(self):
        self.set_fb(fail_flash=True)
        proc = self.engine(*self.flash_args())
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.fastboot-flash-partition')[-2:],
                         [('execute', 'fail', 'exit-code'), ('rollback', 'skipped', 'manual-rollback-required')])
        self.assertIn('docs/android.md#rollback-flash', proc.stderr)

    # ------------------------------------------------------------------ update image
    def test_update_image_flashes_the_hashed_zip_without_wipe_and_never_runs_scripts(self):
        marker = self.tmp / 'script-ran'
        zip_path = make_zip(self.tmp / 'with-script.zip', members=(('boot.img', b'B' * 4096),
                                                                  ('evil.sh', ('#!/bin/sh\ntouch %s\n' % marker).encode())))
        proc = self.engine(*self.update_args(image=str(zip_path), sha=sha256_of(zip_path)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        updates = [c for c in self.fb_calls() if c['argv'][2:3] == ['update']]
        self.assertEqual(len(updates), 1)
        argv = updates[0]['argv']
        self.assertEqual((argv[:3], len(argv)), (['-s', 'usb:3-2.1', 'update'], 4))
        self.assertRegex(argv[3], r'^/dev/fd/[0-9]+$')
        self.assertNotIn('-w', argv)
        self.assertEqual(updates[0]['fw']['sha256'], sha256_of(zip_path))
        self.assertFalse(marker.exists())
        self.assertEqual(self.stages('android.fastboot-update-image')[-1], ('verify', 'ok', None))
        self.assertEqual([s[0] for s in self.stages('android.fastboot-update-image')],
                         ['proposed', 'backup', 'approval', 'execute', 'verify'])
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def test_flash_all_scripts_are_never_executed_and_the_outer_factory_zip_is_refused(self):
        marker = self.tmp / 'flashall-ran'
        outer = make_zip(self.tmp / 'factory.zip', android_info=None,
                         members=(('flash-all.sh', ('#!/bin/sh\ntouch %s\n' % marker).encode()), ('image-test.zip', b'PK')))
        self.assert_refused(self.engine(*self.update_args(image=str(outer), sha=sha256_of(outer))), 'firmware-invalid',
                            'android.fastboot-update-image')
        self.journal.unlink()
        both = make_zip(self.tmp / 'both.zip', members=(('boot.img', b'B' * 4096), ('flash-all.sh', b'#!/bin/sh\n')))
        self.assert_refused(self.engine(*self.update_args(image=str(both), sha=sha256_of(both))), 'firmware-invalid',
                            'android.fastboot-update-image')
        self.assertFalse(marker.exists())
        self.assertEqual([c for c in self.fb_calls() if c['argv'][2:3] == ['update']], [])

    def test_a_zip_with_critical_partition_images_is_refused(self):
        for name in ('bootloader-sunfish-1.0.img', 'radio-sunfish-2.0.img', 'bootloader.img', 'modem.img', 'persist.img', 'efs.img',
                     'userdata.img', 'frp.img', 'devinfo.img', 'fsg.img', 'RADIO.IMG'):
            with self.subTest(member=name):
                if self.journal.exists():
                    self.journal.unlink()
                z = make_zip(self.tmp / 'crit.zip', members=(('boot.img', b'B' * 4096), (name, b'X' * 4096)))
                self.assert_refused(self.engine(*self.update_args(image=str(z), sha=sha256_of(z))), 'firmware-invalid',
                                    'android.fastboot-update-image')

    def test_a_product_mismatch_is_refused(self):
        z = make_zip(self.tmp / 'other.zip', android_info='require board=otherphone\nrequire version-bootloader=1\n')
        proc = self.engine(*self.update_args(image=str(z), sha=sha256_of(z)))
        self.assert_refused(proc, 'identity-mismatch', 'android.fastboot-update-image')
        self.assertIn('not for this device', proc.stderr)
        self.assertNotIn('otherphone', proc.stdout + proc.stderr)

    def test_android_info_without_a_require_line_or_with_any_failing_line_is_refused(self):
        for info in ('require version-bootloader=1\n', '', 'require board=sunfishtest\nrequire product=otherphone\n'):
            with self.subTest(info=info):
                if self.journal.exists():
                    self.journal.unlink()
                z = make_zip(self.tmp / 'info.zip', android_info=info)
                self.assert_refused(self.engine(*self.update_args(image=str(z), sha=sha256_of(z))), 'identity-mismatch',
                                    'android.fastboot-update-image')

    def test_alternatives_and_product_lines_match(self):
        for info in ('require board=a|%s|b\n' % PRODUCT, 'require product=%s\nrequire board=x|%s\n' % (PRODUCT, PRODUCT)):
            with self.subTest(info=info):
                if self.journal.exists():
                    self.journal.unlink()
                z = make_zip(self.tmp / 'ok.zip', android_info=info)
                self.engine(*self.update_args(image=str(z), sha=sha256_of(z)))
                self.assertEqual(self.stages('android.fastboot-update-image')[-1], ('verify', 'ok', None))

    def test_a_non_zip_or_corrupt_zip_is_refused(self):
        bad = self.tmp / 'bad.zip'
        bad.write_bytes(b'not a zip' * 200000)
        self.assert_refused(self.engine(*self.update_args(image=str(bad), sha=sha256_of(bad))), 'firmware-invalid',
                            'android.fastboot-update-image')

    def test_update_on_a_locked_bootloader_is_refused_before_the_file_is_read(self):
        self.set_fb(vars={'unlocked': 'no'})
        proc = self.engine(*self.update_args())
        self.assert_refused(proc, 'bootloader-locked', 'android.fastboot-update-image')
        self.assertEqual([c for c in self.fb_calls() if c['argv'][2:3] == ['update']], [])

    # ------------------------------------------------------------------ slot, reboot
    def test_slot_switch_captures_the_previous_slot_and_reads_it_back(self):
        aid = 'android.fastboot-set-active-slot'
        proc = self.engine('--select', aid + ':and-0', '--approve', aid, '--param', aid + '.slot=b')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([s[:2] for s in self.stages(aid)], [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        self.assertEqual(self.writes(self.fb_calls()), [['-s', 'usb:3-2.1', '--set-active=b']])
        approval = [r for r in read_journal(self.journal) if r['stage'] == 'approval'][0]
        self.assertEqual(approval['params'], {'slot': 'b'})
        self.assertIn('verified', proc.stdout)

    def test_slot_switch_that_does_not_stick_is_rolled_back_to_the_previous_slot(self):
        aid = 'android.fastboot-set-active-slot'
        self.set_fb(sticky_slot=True)
        proc = self.engine('--select', aid + ':and-0', '--approve', aid, '--param', aid + '.slot=b')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual([s[:3] for s in self.stages(aid)][2:], [('execute', 'ok', None), ('verify', 'fail', 'verify-failed'),
                                                                 ('rollback', 'ok', None)])
        self.assertEqual(self.writes(self.fb_calls()), [['-s', 'usb:3-2.1', '--set-active=b'], ['-s', 'usb:3-2.1', '--set-active=a']])
        self.assertIn('rolled-back', proc.stdout)

    def test_slot_switch_needs_an_ab_device_and_an_explicit_slot(self):
        aid = 'android.fastboot-set-active-slot'
        self.del_var('current-slot')
        self.assert_refused(self.engine('--select', aid + ':and-0', '--approve', aid, '--param', aid + '.slot=b'),
                            'identity-mismatch', aid)
        self.journal.unlink()
        self.engine('--select', aid + ':and-0', '--approve', aid)
        self.assertEqual(self.stages(aid)[-1], ('approval', 'skipped', 'missing-param'))
        self.journal.unlink()
        self.engine('--select', aid + ':and-0', '--approve', aid, '--param', aid + '.slot=c')
        self.assertEqual(self.stages(aid)[-1], ('approval', 'skipped', 'invalid-param'))
        self.assertEqual(self.writes(self.fb_calls()), [])

    def test_fastboot_reboot_is_safe_and_operator_only(self):
        aid = 'android.fastboot-reboot'
        proc = self.engine('--policy', 'auto-safe', '--select', aid + ':and-0')
        self.assertEqual(self.writes(self.fb_calls()), [])
        self.journal.unlink()
        proc = self.engine('--select', aid + ':and-0', '--approve', aid)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.writes(self.fb_calls()), [['-s', 'usb:3-2.1', 'reboot']])
        self.assertEqual(self.fb_calls()[-1]['argv'], ['devices'])               # verify does not need the (gone) device
        self.assertEqual([s[:2] for s in self.stages(aid)][-2:], [('execute', 'ok'), ('verify', 'ok')])

    # ------------------------------------------------------------------ device identity
    def test_selector_is_the_usb_path_never_the_serial(self):
        self.engine(*self.flash_args())
        for call in self.fb_calls():
            for part in call['argv']:
                self.assertNotIn(TA.SERIAL_A, part)
        selectors = {c['argv'][1] for c in self.fb_calls() if c['argv'][:1] == ['-s']}
        self.assertEqual(selectors, {'usb:3-2.1'})

    def test_a_swapped_phone_in_the_port_is_refused(self):
        other = self.fb_machine('OTHERSERIAL000111')
        self.assert_refused(self.engine(*self.flash_args(), machine=other), 'device-mismatch', 'android.fastboot-flash-partition')

    def test_a_phone_that_left_fastboot_mode_or_vanished_is_refused(self):
        adb_mode = self.fb_machine(TA.SERIAL_A, vid='04e8', pid='6860', interface='ff/42/01')
        self.assert_refused(self.engine(*self.flash_args(), machine=adb_mode), 'device-absent', 'android.fastboot-flash-partition')
        self.journal.unlink()
        gone = TA.FakeMachine(self.tmp / 'gone')
        self.assert_refused(self.engine(*self.flash_args(), machine=gone), 'device-absent', 'android.fastboot-flash-partition')

    def test_missing_fastboot_missing_permission_and_unusable_selector_are_refused(self):
        (self.tmp / 'nobin').mkdir()
        self.assert_refused(self.engine(*self.flash_args(), adb_dir=self.tmp / 'nobin'), 'device-absent', 'android.fastboot-flash-partition')
        self.journal.unlink()
        self.set_fb(devices_l='no permissions (user in plugdev group; are your udev rules wrong?) fastboot usb:3-2.1\n')
        self.assert_refused(self.engine(*self.flash_args()), 'device-absent', 'android.fastboot-flash-partition')
        self.journal.unlink()
        self.set_fb(devices_l=fastboot_line(TA.SERIAL_A, '3-2.1'), selector='usb:9-9')       # the device does not answer to usb:3-2.1
        self.assert_refused(self.engine(*self.flash_args()), 'device-absent', 'android.fastboot-flash-partition')

    def test_ambiguous_identity_is_refused(self):
        twin = self.fb_machine(TA.SERIAL_A)
        twin.add_device('3-2.2', '18d1', '4ee0', ['ff/42/03'], serial=TA.SERIAL_A)
        self.assert_refused(self.engine(*self.flash_args(), machine=twin), 'device-ambiguous', 'android.fastboot-flash-partition')

    def test_wait_is_not_applied_to_fastboot_verify(self):
        self.set_fb(fail_flash=False)
        proc = self.engine(*self.flash_args(), wait='1')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    # ------------------------------------------------------------------ heimdall
    def download_machine(self, extra=False):
        machine = self.fb_machine(TA.SERIAL_B, vid='04e8', pid='685d', interface='ff/ff/ff')
        if extra:
            machine.add_device('3-2.2', '04e8', '685d', ['ff/ff/ff'], serial='OTHERDL')
        out = self.tmp / ('ev-dl-%d.json' % self.machines)
        argv = [sys.executable, str(AR.SCAN), '--fixture-root', str(machine.root), '--adb-path', str(self.adb_dir), '--output', str(out)]
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}
        subprocess.run(argv, capture_output=True, text=True, env=env, check=True)
        for log in ('hm_calls.log', 'fb_calls.log'):          # the scan above is not part of the engine run under test
            if (self.adb_dir / log).exists():
                (self.adb_dir / log).unlink()
        return machine, out

    def heimdall_args(self, evidence, partition='BOOT'):
        aid = 'android.heimdall-flash-partition'
        return ['--select', aid + ':and-0', '--approve', aid, '--backup-ref', str(self.proof),
                '--param', aid + '.partition=' + partition, '--param', aid + '.firmware=' + str(self.image),
                '--param', aid + '.firmware_sha256=' + self.image_sha], dict(evidence=evidence)

    def test_heimdall_flashes_one_allowlisted_partition_after_detect_and_pit(self):
        machine, ev = self.download_machine()
        args, kw = self.heimdall_args(ev)
        proc = self.engine(*args, machine=machine, **kw)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        aid = 'android.heimdall-flash-partition'
        self.assertEqual([s[:2] for s in self.stages(aid)],
                         [('proposed', 'ok'), ('backup', 'ok'), ('approval', 'ok'), ('precondition', 'ok'), ('precondition', 'ok'),
                          ('execute', 'ok'), ('verify', 'ok')])
        calls = self.hm_calls()
        self.assertEqual([c['argv'][:1] + ([c['argv'][-1]] if c['argv'][0] == 'flash' else []) for c in calls],
                         [['detect'], ['print-pit'], ['flash', '--no-reboot'], ['detect']])
        flash = calls[2]
        self.assertEqual(flash['argv'][1], '--BOOT')
        self.assertRegex(flash['argv'][2], r'^/dev/fd/[0-9]+$')
        self.assertEqual(flash['fw']['sha256'], self.image_sha)
        self.assertEqual(self.fb_calls(), [])
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def test_heimdall_refuses_unless_exactly_one_download_mode_device_is_attached(self):
        machine, ev = self.download_machine(extra=True)
        args, kw = self.heimdall_args(ev)
        # the evidence was made with two devices: and-0 is the first; heimdall could still pick the other one
        self.assert_refused(self.engine(*args, machine=machine, **kw), 'device-ambiguous', 'android.heimdall-flash-partition')
        self.journal.unlink()
        solo, ev1 = self.download_machine()
        args, kw = self.heimdall_args(ev1)
        self.assert_refused(self.engine(*args, machine=TA.FakeMachine(self.tmp / 'nodl'), **kw), 'device-absent',
                            'android.heimdall-flash-partition')
        self.journal.unlink()
        other = self.fb_machine('OTHERDL999', vid='04e8', pid='685d', interface='ff/ff/ff')
        self.assert_refused(self.engine(*args, machine=other, **kw), 'device-mismatch', 'android.heimdall-flash-partition')
        self.assertEqual(self.hm_calls(), [])

    def test_heimdall_partition_must_exist_in_the_pit_and_the_device_must_be_detected(self):
        machine, ev = self.download_machine()
        self.set_hm(pit=['BOOT', 'SYSTEM'])
        args, kw = self.heimdall_args(ev, partition='RECOVERY')
        proc = self.engine(*args, machine=machine, **kw)
        aid = 'android.heimdall-flash-partition'
        self.assertEqual(self.stages(aid)[-1], ('precondition', 'fail', 'verify-failed'))
        self.assertEqual(self.writes(self.hm_calls()), [])
        self.assertIn('skipped', proc.stdout)
        self.journal.unlink()
        self.set_hm(detect_fails=True)
        args, kw = self.heimdall_args(ev)
        self.engine(*args, machine=machine, **kw)
        self.assertEqual(self.stages(aid)[-1], ('precondition', 'fail', 'exit-code'))
        self.assertEqual(self.writes(self.hm_calls()), [])

    def test_heimdall_partitions_outside_the_allowlist_are_refused(self):
        machine, ev = self.download_machine()
        for bad in ('PIT', 'SBL1', 'SYSTEM', 'MODEM', 'boot', 'EFS', 'BOOT --repartition'):
            with self.subTest(partition=bad):
                if self.journal.exists():
                    self.journal.unlink()
                args, kw = self.heimdall_args(ev, partition=bad)
                self.engine(*args, machine=machine, **kw)
                self.assertEqual(self.stages('android.heimdall-flash-partition')[-1], ('approval', 'skipped', 'invalid-param'))
        self.assertEqual(self.hm_calls(), [])

    def test_heimdall_needs_the_backup_and_never_auto_runs(self):
        machine, ev = self.download_machine()
        args, kw = self.heimdall_args(ev)
        self.engine(*[a for a in args if a not in ('--backup-ref', str(self.proof))], machine=machine, **kw)
        self.assertEqual(self.hm_calls(), [])
        self.journal.unlink()
        self.engine('--policy', 'auto-safe', '--select', 'android.heimdall-flash-partition:and-0', '--backup-ref', str(self.proof),
                    machine=machine, **kw)
        self.assertEqual(self.hm_calls(), [])

    def test_the_engine_never_runs_an_unlock_erase_or_wipe_command(self):
        self.engine(*self.flash_args())
        self.engine(*self.update_args())
        for call in self.fb_calls():
            for forbidden in ('erase', 'format', '-w', 'oem', 'flashing', 'unlock', 'lock', 'flashall', 'continue', 'reboot-bootloader'):
                self.assertNotIn(forbidden, call['argv'])


def read_journal(path):
    return HR.read_journal(path)


class ExpectLineTests(AR.AndroidRepairCase):
    """The phase 2 verifier action now reads its value back (expect_line); a wrong value fails verify and rolls back."""

    def test_verify_passes_only_when_the_line_is_exactly_1(self):
        aid = 'android.enable-package-verifier'
        proc = self.run_one(aid)
        self.assertEqual(self.stages(aid)[-1], ('verify', 'ok', None), proc.stdout + proc.stderr)

    def test_a_wrong_or_missing_value_fails_verify_with_a_typed_reason_and_rolls_back(self):
        aid = 'android.enable-package-verifier'
        for value in ('0\n', '', '10\n', 'null\n', '1 \n2\n3', 'x1\n'):
            with self.subTest(value=value):
                if self.journal.exists():
                    self.journal.unlink()
                self.command('shell settings get global package_verifier_enable', 0, value)
                proc = self.run_one(aid)
                stages = self.stages(aid)
                if value == '1 \n2\n3':
                    self.assertEqual(stages[-1], ('verify', 'ok', None))       # a line "1" (trimmed) is present
                    continue
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual([s[:3] for s in stages][-2:], [('verify', 'fail', 'verify-failed'), ('rollback', 'ok', None)])


# ----------------------------------------------------------------------------------------
# Run report + host engines
# ----------------------------------------------------------------------------------------
class ReportTests(FlashCase):
    def produce(self):
        self.set_fb(vars={'unlocked': 'no'})
        self.assertEqual(self.engine(*self.flash_args()).returncode, 0)
        self.set_fb(vars={'unlocked': 'yes'})
        self.assertEqual(self.engine(*self.flash_args(sha='f' * 64)).returncode, 0)
        self.assertEqual(self.engine(*self.flash_args()).returncode, 0)
        inp = self.tmp / 'in'
        inp.mkdir()
        shutil.copy(self.evidence, inp / 'evidence.json')
        shutil.copy(self.journal, inp / 'journal.jsonl')
        return {'evidence': inp / 'evidence.json', 'journal': inp / 'journal.jsonl'}

    def test_python_report_lists_the_typed_refusals_and_never_the_path_or_serial(self):
        paths = self.produce()
        gen = TR.Generators(self.tmp)
        out, proc = gen.python(paths, mode='live-linux', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md, _ = TR.read_report(out)
        TR.validate(self, doc)
        reasons = [s.get('reason') for a in doc['remediation']['actions'] for s in a['stages'] if s['stage'] == 'precondition']
        self.assertEqual(reasons, ['bootloader-locked', 'firmware-hash-mismatch'])
        self.assertEqual([a['final_outcome'] for a in doc['remediation']['actions']], ['skipped', 'skipped', 'verified'])
        for action in doc['remediation']['actions']:
            self.assertEqual(set(action['params']) - {'partition', 'firmware_sha256'}, set())
            self.assertTrue(all(v in ('boot', '<value>') for v in action['params'].values()), action['params'])
        text = json.dumps(doc) + md
        for leak in LEAKS + (str(self.image),):
            self.assertNotIn(leak, text)
        self.assertEqual(doc['privacy_check'], {'status': 'passed', 'findings': []})

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_report_equals_the_python_report(self):
        paths = self.produce()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        js_dir, proc = gen.jxa(paths, mode='live-linux', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(TR.read_report(py_dir), TR.read_report(js_dir))

    @unittest.skipUnless(AR.PWSH, 'pwsh not installed')
    def test_powershell_report_equals_the_python_report(self):
        paths = self.produce()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', scope='android', policy='approve-each')
        ps_dir, proc = gen.powershell(paths, mode='live-linux', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(TR.read_report(py_dir), TR.read_report(ps_dir))

    def test_reason_lists_agree_everywhere(self):
        journal = json.loads((REPO / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        report = json.loads((REPO / 'rescue-ai/v1/run-report.schema.json').read_text())
        approval = report['properties']['remediation']['properties']['actions']['items']['properties']
        for new in ('bootloader-locked', 'identity-mismatch', 'firmware-invalid', 'firmware-hash-mismatch'):
            self.assertIn(new, journal['properties']['reason']['enum'])
            self.assertIn(new, approval['approval']['properties']['reason']['enum'])
            self.assertIn(new, approval['stages']['items']['properties']['reason']['enum'])
            self.assertIn("'%s'" % new, (REPO / 'host/rescue-windows.ps1').read_text())
            self.assertIn("'%s'" % new, (REPO / 'host/RESCUE-MACOS.command').read_text())
        AR.ReportTests.test_rr_enums_match_the_schema(self)


class HostEngineTests(unittest.TestCase):
    def test_both_engines_keep_every_new_type_unsupported_and_accept_the_catalog(self):
        AR.HostEngineTests.test_every_host_catalog_parameter_type_is_in_the_closed_lists_of_both_engines(self)
        ps = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
        mac = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
        for kind in ('fastboot_device', 'fastboot_slot', 'firmware_file', 'sha256'):
            self.assertIn("$_.type -ceq '%s'" % kind, ps)
            self.assertIn(kind, re.search(r'\(block_device\|target_root[^)]*\) \]\] && unsupported=1', mac).group(0))

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_loads_the_full_shipped_catalog_and_refuses_to_select_flashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = {'source_platform': 'macos-host', 'scope': ['all'],
                        'target_systems': [{'ref': 'os-0', 'family': 'macos'}, {'ref': 'and-0', 'family': 'android'}], 'checks': []}
            for aid in ('android.fastboot-flash-partition', 'android.fastboot-update-image', 'android.heimdall-flash-partition',
                        'android.fastboot-set-active-slot', 'android.fastboot-reboot'):
                proc, lines = AR.jxa_plan(rc.CATALOG_DIR, evidence, select=aid + ':and-0', tmp=tmp)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual([l for l in lines if l[0] == 'ERR'], [], proc.stdout)
                self.assertIn(['SELERR', aid + ' does not apply here'], lines)
                self.assertEqual([l for l in lines if l[0] == 'ACT'], [])

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_still_rejects_an_unknown_parameter_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            only = Path(tmp) / 'cat'
            only.mkdir()
            doc = json.loads((rc.CATALOG_DIR / 'android.json').read_text())
            for act in doc['actions']:
                for p in act.get('params', []):
                    if p['type'] == 'firmware_file':
                        p['type'] = 'firmware_files'
            (only / 'android.json').write_text(json.dumps(doc))
            proc, lines = AR.jxa_plan(only, {'source_platform': 'macos-host', 'scope': ['android'], 'target_systems': [], 'checks': []},
                                      scope='android', tmp=tmp)
            self.assertTrue([l for l in lines if l[0] == 'ERR'], proc.stdout)


class PackageTests(unittest.TestCase):
    def test_persistence_image_installs_fastboot_and_heimdall(self):
        text = (SCRIPTS / 'lib/persistence-container-build.sh').read_text()
        line = next(l for l in text.splitlines() if l.startswith('optional=('))
        for package in ('adb', 'android-sdk-platform-tools-common', 'fastboot', 'heimdall-flash'):
            self.assertIn(' %s' % package, line)
        self.assertNotIn('mtkclient', text)
        self.assertNotIn('edl', text.lower().replace('needle', ''))
        self.assertIsNone(re.search(r'\bpip3?\b', text))


if __name__ == '__main__':
    unittest.main()
