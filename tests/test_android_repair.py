#!/usr/bin/env python3
"""Offline tests for the Android repair actions (ahliweb/linux-mint-xfce-rescue-ai#48, phase 2).

A fake sysfs/proc tree stands in for /sys and /proc (RESCUE_REPAIR_TEST_USB_ROOT), and a fake ``adb``
found only through RESCUE_REPAIR_TEST_PATH answers ``adb devices -l`` from a state file, validates the
transport id of every ``-t`` call, logs every call, and can change the device list when the phone
"reboots". Nothing touches a real USB device, a real phone or the network. Dummy values only.

* catalog: the shipped android.json and the invariants that confine an Android action to
  ``adb -t {android_device}`` plus a closed list of sub-commands;
* engine: android_device resolution at execution time (refusals are journaled with a typed reason), policy
  behaviour, journal privacy, the verify step after a reboot, the Linux-host path;
* generators: the run report accepts and-N / android in the Python, JXA (node) and PowerShell generators;
* host engines: both native engines accept the catalog and keep the new parameter type unsupported.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import copy
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_android as TA  # noqa: E402
import test_host_repair as HR  # noqa: E402
import test_run_report as TR  # noqa: E402

REPO = HR.REPO
SCRIPTS = REPO / 'scripts'
REPAIR = SCRIPTS / 'rescue-repair.py'
SCAN = SCRIPTS / 'scan-android.py'
sys.path.insert(0, str(SCRIPTS / 'lib'))
import repair_catalog as rc  # noqa: E402
import run_report as rr  # noqa: E402

NODE = shutil.which('node')
PWSH = HR.PWSH
SERIAL_LEAKS = (TA.SERIAL_A, TA.SERIAL_B, 'Galaxy Secret Model', 'Secret Maker', 'com.secret.sideload')
LOW_STORAGE = ('Filesystem 1K-blocks Used Available Use% Mounted on\n'
               '/dev/block/dm-9 100000000 94000000 6000000  94% /data\n')

FAKE_ADB = '''#!%(python)s
import json, os, re, sys
DIR = %(dir)r
argv = sys.argv[1:]
state = json.load(open(DIR + '/state.json'))
with open(DIR + '/calls.log', 'a') as handle:
    handle.write(json.dumps({'argv': argv, 'env': {k: os.environ.get(k) for k in ('HOME', 'ADB_MDNS', 'OPENCODE_GO_API_KEY')}}) + '\\n')


def finish(code, out=''):
    sys.stdout.write(out)
    sys.exit(code)


if argv == ['devices', '-l']:
    finish(0, state['devices'])
if argv == ['kill-server']:
    finish(0)
if len(argv) >= 3 and argv[0] == '-t':
    ids = re.findall(r'transport_id:([0-9]+)', state['devices'])
    if argv[1] not in ids:
        sys.stderr.write("adb: device with transport id '%%s' not found\\n" %% argv[1])
        sys.exit(1)
    rest = argv[2:]
    if rest == ['reboot'] and state.get('after_reboot') is not None:
        state['devices'] = state.pop('after_reboot')
        for path, text in state.pop('on_reboot_write', []):
            open(path, 'w').write(text)
        json.dump(state, open(DIR + '/state.json', 'w'))
        finish(0)
    code, out = state['commands'].get(' '.join(rest), [0, ''])
    finish(code, out)
sys.exit(2)
'''

HEADER = 'List of devices attached\n'


def device_line(serial, port, transport, state='device'):
    return '%s       %s usb:%s product:secretprod model:Galaxy_Secret_Model device:secretdev transport_id:%d\n' % (
        serial, state, port, transport)


def read_journal(path):
    return HR.read_journal(path)


class AndroidRepairCase(unittest.TestCase):
    """A fake machine with one phone (3-2.1, ADB, serial A), a fake adb, evidence made by the real scanner."""

    storage_free_low = False
    verifier_off = False

    def setUp(self):
        self.build()

    def rebuild(self, **flags):
        """Start over with a different phone (storage_free_low / verifier_off) and a clean journal."""
        shutil.rmtree(self.tmp, True)
        for name, value in flags.items():
            setattr(self, name, value)
        self.build()

    def build(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='android-repair-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / 'home'
        self.home.mkdir()
        self.machine = self.make_machine(TA.SERIAL_A)
        self.adb_dir = self.tmp / 'bin'
        self.adb_dir.mkdir()
        (self.adb_dir / 'adb').write_text(FAKE_ADB % {'python': sys.executable, 'dir': str(self.adb_dir)})
        (self.adb_dir / 'adb').chmod(0o755)
        outputs = TA.good_phone_outputs()
        if self.storage_free_low:
            outputs['shell df /data'] = LOW_STORAGE
        if self.verifier_off:
            outputs['shell settings get global package_verifier_enable'] = '0\n'
        self.commands = {k: [0, v] for k, v in outputs.items()}
        self.set_state(devices=HEADER + device_line(TA.SERIAL_A, '3-2.1', 1))
        self.journal = self.tmp / 'state' / 'repairs' / 'journal.jsonl'
        self.evidence = self.tmp / 'evidence.json'
        proc = self.scan(self.evidence, '--repair-policy', 'approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.ev = json.loads(self.evidence.read_text())
        self.assertEqual([t['ref'] for t in self.ev['target_systems']], ['and-0'])
        (self.adb_dir / 'calls.log').unlink()

    # ------------------------------------------------------------------ fixtures
    def make_machine(self, serial, second_serial=None):
        self.machines = getattr(self, 'machines', 0) + 1
        sub = self.tmp / ('m-%d' % self.machines)
        sub.mkdir(parents=True, exist_ok=True)
        machine = TA.FakeMachine(sub)
        machine.add_device('3-2.1', '04e8', '6860', ['06/01/01', 'ff/42/01'], speed=480, serial=serial)
        if second_serial:
            machine.add_device('3-2.2', '04e8', '6860', ['06/01/01', 'ff/42/01'], speed=480, serial=second_serial)
        return machine

    def set_state(self, **fields):
        path = self.adb_dir / 'state.json'
        state = json.loads(path.read_text()) if path.exists() else {'commands': {}}
        state.setdefault('commands', {})
        if 'commands' not in fields and not state['commands']:
            state['commands'] = self.commands
        state.update(fields)
        path.write_text(json.dumps(state))

    def command(self, key, code, out=''):
        state = json.loads((self.adb_dir / 'state.json').read_text())
        state['commands'][key] = [code, out]
        (self.adb_dir / 'state.json').write_text(json.dumps(state))

    def env(self, machine=None, adb_dir=None, wait='1', **extra):
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'LC_ALL': 'C',
               'RESCUE_REPAIR_TEST_PATH': str(adb_dir or self.adb_dir),
               'RESCUE_REPAIR_TEST_USB_ROOT': str((machine or self.machine).root),
               'RESCUE_REPAIR_TEST_ANDROID_WAIT': wait}
        env.update(extra)
        return env

    def scan(self, out, *args):
        argv = [sys.executable, str(SCAN), '--fixture-root', str(self.machine.root), '--adb-path', str(self.adb_dir),
                '--output', str(out)] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=120,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'LC_ALL': 'C'})

    def engine(self, *args, evidence=None, machine=None, adb_dir=None, wait='1', **extra):
        argv = [sys.executable, str(REPAIR), '--evidence', str(evidence or self.evidence), '--journal', str(self.journal)]
        return subprocess.run(argv + list(args), capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                              env=self.env(machine, adb_dir, wait, **extra))

    def calls(self):
        path = self.adb_dir / 'calls.log'
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def target_calls(self):
        return [c['argv'] for c in self.calls() if c['argv'][:1] == ['-t']]

    def stages(self, aid):
        return HR.stages(read_journal(self.journal), aid)

    def journal_text(self):
        return self.journal.read_text(encoding='utf-8') if self.journal.exists() else ''

    def assert_private(self, text):
        for leak in SERIAL_LEAKS + ('3-2.1', '3-2.2', 'usb:'):
            self.assertNotIn(leak, text)

    def run_one(self, aid, *args, **kwargs):
        return self.engine('--select', '%s:and-0' % aid, '--approve', aid, *args, **kwargs)


# ----------------------------------------------------------------------------------------
# Catalog
# ----------------------------------------------------------------------------------------
def android_action(**over):
    base = {
        'action_id': 'android.test-action', 'title': 'Test action', 'title_id': 'Tindakan uji', 'scope': 'android',
        'platforms': ['live-linux', 'linux-host'], 'target_families': ['android'], 'risk': 'safe', 'triggers': [],
        'params': [{'name': 'device', 'type': 'android_device'}],
        'execute': {'argv': ['adb', '-t', '{device}', 'shell', 'pm', 'trim-caches', '999G']},
        'verify': {'argv': ['adb', '-t', '{device}', 'get-state']},
        'rollback': {'kind': 'none'}, 'backup': {'required': False}, 'doc': 'docs/android.md',
    }
    base.update(over)
    return base


def errors_of(act, domain='android'):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / (domain + '.json')).write_text(json.dumps({'catalog_version': '1', 'domain': domain, 'actions': [act]}))
        try:
            rc.load(d)
        except rc.CatalogError as exc:
            return exc.problems
    return []


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = rc.load()
        cls.all_actions = {a: v for a, v in cls.catalog.actions.items() if v['_domain'] == 'android'}
        # the adb actions of phase 2; the fastboot and Heimdall actions are covered by tests/test_android_flash.py
        cls.actions = {a: v for a, v in cls.all_actions.items()
                       if any(p['type'] == 'android_device' for p in v['params'])}

    def test_shipped_android_actions(self):
        self.assertEqual({a: (v['risk'], len(v['triggers'])) for a, v in self.actions.items()},
                         {'android.trim-caches': ('safe', 1), 'android.enable-package-verifier': ('reversible', 1),
                          'android.reboot': ('safe', 0)})

    def test_every_action_is_confined_to_one_phone_and_the_python_engine(self):
        for aid, act in self.actions.items():
            with self.subTest(action=aid):
                self.assertEqual(act['scope'], 'android')
                self.assertEqual(act['target_families'], ['android'])
                self.assertEqual(set(act['platforms']), {'live-linux', 'linux-host'})
                self.assertFalse(act.get('requires_root'))
                self.assertEqual([p['type'] for p in act['params']], ['android_device'])
                steps = [act['execute'], act['verify']] + ([act['rollback']['step']] if act['rollback']['kind'] == 'step' else [])
                for step in steps:
                    self.assertEqual(step['argv'][:3], ['adb', '-t', '{%s}' % act['params'][0]['name']])

    def test_no_dangerous_adb_word_anywhere_in_the_android_catalog(self):
        text = json.dumps([a for a in self.actions.values()])
        for word in ('root', 'install', 'push', 'pull', 'sideload', 'remount', 'bootloader', 'recovery', 'wipe', 'factory',
                     'rm', 'fastboot', 'unlock', 'su', 'sh', 'disable-verity', 'pm uninstall', 'uninstall'):
            self.assertIsNone(re.search(r'"%s"' % re.escape(word), text), word)

    def test_trigger_check_ids_and_the_reboot_is_operator_only(self):
        self.assertEqual([t['check_id'] for t in self.actions['android.trim-caches']['triggers']], ['android-storage-free'])
        self.assertEqual(self.actions['android.trim-caches']['triggers'][0]['status'], ['warn', 'fail'])
        self.assertEqual([t['check_id'] for t in self.actions['android.enable-package-verifier']['triggers']],
                         ['android-play-protect'])
        self.assertEqual(self.actions['android.reboot']['triggers'], [])

    def test_reversible_action_has_an_automatic_rollback_step(self):
        act = self.actions['android.enable-package-verifier']
        self.assertEqual(act['rollback']['kind'], 'step')
        self.assertEqual(act['rollback']['step']['argv'][-4:], ['settings', 'delete', 'global', 'package_verifier_enable'])

    def test_a_valid_example_loads(self):
        self.assertEqual(errors_of(android_action()), [])

    def assertRejected(self, act, needle, domain='android'):
        errs = errors_of(act, domain)
        self.assertTrue(any(needle in e for e in errs), errs)

    def test_adb_must_be_addressed_to_the_android_device(self):
        self.assertRejected(android_action(execute={'argv': ['adb', 'shell', 'pm', 'trim-caches', '999G']}), 'addressed as -t')
        self.assertRejected(android_action(execute={'argv': ['adb', '-s', '{device}', 'reboot']}), 'addressed as -t')
        self.assertRejected(android_action(execute={'argv': ['adb', '-t', '1', 'reboot']}), 'addressed as -t')
        self.assertRejected(android_action(params=[]), 'exactly one android_device')

    def test_adb_subcommands_are_a_closed_list(self):
        for tail in (['root'], ['unroot'], ['install', 'x.apk'], ['push', 'a', 'b'], ['pull', 'a'], ['sideload', 'x.zip'],
                     ['remount'], ['disable-verity'], ['usb'], ['tcpip', '5555'], ['forward', 'tcp:1', 'tcp:2'], ['shell']):
            with self.subTest(tail=tail):
                self.assertRejected(android_action(execute={'argv': ['adb', '-t', '{device}'] + tail}), 'not allowed')
        for tail in (['reboot', 'bootloader'], ['reboot', 'recovery'], ['reboot', 'sideload'], ['get-state', 'x']):
            with self.subTest(tail=tail):
                self.assertRejected(android_action(execute={'argv': ['adb', '-t', '{device}'] + tail}), 'takes no arguments')

    def test_adb_shell_programs_are_a_closed_list(self):
        for tail, needle in ((['sh', '-c', 'x'], 'program'), (['rm', '-rf', '/data'], 'program'), (['su', '0', 'id'], 'program'),
                             (['pm', 'uninstall', 'x'], 'may only use'), (['pm', 'clear', 'x'], 'may only use'),
                             (['settings', 'put', 'secure', 'x', '1'], 'global namespace'), (['settings', 'put', 'global'], 'global namespace'),
                             (['am', 'start', 'x'], 'program'), (['input', 'text', 'x'], 'program'), (['wipe', 'data'], 'program')):
            with self.subTest(tail=tail):
                self.assertRejected(android_action(execute={'argv': ['adb', '-t', '{device}', 'shell'] + tail}), needle)

    def test_no_placeholder_after_adb_shell(self):
        params = [{'name': 'device', 'type': 'android_device'}, {'name': 'mode', 'type': 'enum', 'values': ['1', '0']}]
        self.assertRejected(android_action(params=params, execute={'argv': [
            'adb', '-t', '{device}', 'shell', 'settings', 'put', 'global', 'k', '{mode}']}), 'no placeholder')

    def test_android_device_rules(self):
        self.assertRejected(android_action(platforms=['live-linux', 'linux-host', 'windows-host']), 'exist only on')
        self.assertRejected(android_action(platforms=['macos-host']), 'exist only on')
        self.assertRejected(android_action(params=[{'name': 'device', 'type': 'android_device', 'default': '1'}]), 'cannot have a default')
        self.assertRejected(android_action(params=[{'name': 'device', 'type': 'android_device'},
                                                   {'name': 'other', 'type': 'android_device'}],
                                           verify={'argv': ['adb', '-t', '{other}', 'get-state']}), 'at most one')
        self.assertRejected(android_action(target_families=['linuxmint']), 'target_families')
        no_families = android_action()
        del no_families['target_families']
        self.assertRejected(no_families, 'need target_families')
        self.assertRejected(android_action(scope='os'), "use scope 'android'")
        self.assertRejected(android_action(action_id='hw.test-action'), 'prefix')
        # other domains cannot use the type on a host platform either
        act = android_action(action_id='os-windows.test-action', scope='os', target_families=['windows'],
                             platforms=['windows-host'])
        self.assertRejected(act, 'exist only on', domain='os-windows')

    def test_android_family_actions_need_the_android_domain_platforms(self):
        self.assertRejected(android_action(platforms=['windows-host']), 'platforms must be within')

    def test_adb_outside_the_android_domain_still_needs_the_device_parameter(self):
        act = {'action_id': 'hw.adb-sneak', 'title': 'Sneak', 'title_id': 'Sneak', 'scope': 'hardware.usb',
               'platforms': ['live-linux'], 'risk': 'safe', 'triggers': [], 'execute': {'argv': ['adb', 'devices']},
               'verify': {'argv': ['adb', 'devices']}, 'rollback': {'kind': 'none'}, 'backup': {'required': False},
               'doc': 'docs/android.md'}
        self.assertRejected(act, 'needs an android_device', domain='hardware')

    def test_validate_param_refuses_every_operator_value(self):
        param = {'name': 'device', 'type': 'android_device'}
        for value in ('1', '7', 'SERIAL', '-1', ''):
            with self.assertRaises(ValueError):
                rc.validate_param(param, value)

    def test_scope_android(self):
        self.assertIn('android', rc.SCOPE_VALUES)
        self.assertEqual(rc.normalize_scope('android'), ('android',))
        self.assertEqual(rc.normalize_scope('os,android'), ('os', 'android'))
        self.assertTrue(rc.in_scope(('android',), 'android'))
        self.assertTrue(rc.in_scope(('all',), 'android'))
        self.assertFalse(rc.in_scope(('os', 'malware'), 'android'))
        self.assertFalse(rc.in_scope(('android',), 'os'))
        self.assertEqual(rc.normalize_scope('hardware.cpu,android'), ('hardware.cpu', 'android'))
        self.assertEqual(len(rc.SCOPE_VALUES), len(set(rc.SCOPE_VALUES)))

    def evidence(self, **over):
        ev = {'source_platform': 'linux-mint-xfce-live', 'target_systems': [
            {'ref': 'os-0', 'family': 'linuxmint'}, {'ref': 'and-0', 'family': 'android'}],
            'checks': [{'check_id': 'android-storage-free', 'status': 'warn', 'target_ref': 'and-0'},
                       {'check_id': 'android-play-protect', 'status': 'warn', 'target_ref': 'and-0'},
                       {'check_id': 'android-storage-free', 'status': 'fail', 'target_ref': 'os-0'}]}
        ev.update(over)
        return ev

    def test_triggered_carries_and_refs_and_never_mixes_families(self):
        got = rc.triggered(self.catalog, self.evidence(), ('all',))
        self.assertEqual([(p['action_id'], p['target_ref'], p['origin']) for p in got],
                         [('android.trim-caches', 'and-0', 'catalog-trigger'),
                          ('android.enable-package-verifier', 'and-0', 'catalog-trigger')])
        self.assertEqual(rc.triggered(self.catalog, self.evidence(), ('os',)), [])
        self.assertEqual(len(rc.triggered(self.catalog, self.evidence(), ('android',))), 2)
        # an Android check on an OS ref (or the reverse) never proposes the action
        ev = self.evidence(checks=[{'check_id': 'android-storage-free', 'status': 'warn', 'target_ref': 'os-0'}])
        self.assertEqual(rc.triggered(self.catalog, ev, ('all',)), [])

    def test_applicable_needs_the_android_family_and_the_python_platforms(self):
        act = self.catalog.get('android.reboot')
        fams = {'os-0': 'linuxmint', 'and-0': 'android'}
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), 'and-0', fams), (True, None))
        self.assertEqual(rc.applicable(act, 'linux-host', ('android',), 'and-0', fams), (True, None))
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), 'os-0', fams), (False, 'target-family'))
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), None, fams), (False, 'target-family'))
        self.assertEqual(rc.applicable(act, 'windows-host', ('all',), 'and-0', fams), (False, 'platform'))
        self.assertEqual(rc.applicable(act, 'macos-host', ('all',), 'and-0', fams), (False, 'platform'))
        self.assertEqual(rc.applicable(act, 'live-linux', ('os',), 'and-0', fams), (False, 'scope'))

    def test_ai_proposals_are_ids_only_and_need_an_android_target(self):
        text = ('```rescue-proposals\n{"proposed_actions":[{"action_id":"android.reboot","target_ref":"and-0"},'
                '{"action_id":"android.reboot","target_ref":"os-0"},{"action_id":"android.reboot"},'
                '{"action_id":"android.reboot","target_ref":"and-0","device":"1"},'
                '{"action_id":"android.trim-caches","target_ref":"and-0"}]}\n```')
        accepted, rejected = rc.parse_ai_proposals(text, self.catalog, self.evidence(), ('all',))
        self.assertEqual([(p['action_id'], p['target_ref']) for p in accepted],
                         [('android.reboot', 'and-0'), ('android.trim-caches', 'and-0')])
        self.assertEqual(rejected, 3)

    def test_prompt_summary_lists_the_android_actions_without_argv(self):
        rows = rc.prompt_summary(self.catalog, {'source_platform': 'linux-mint-xfce-live'}, ('all',))
        ids = {r['action_id'] for r in rows}
        self.assertIn('android.reboot', ids)
        self.assertNotIn('argv', json.dumps(rows))
        self.assertEqual(rc.prompt_summary(self.catalog, {'source_platform': 'windows-host'}, ('all',)) and
                         {r['action_id'] for r in rc.prompt_summary(self.catalog, {'source_platform': 'windows-host'}, ('all',))
                          if r['action_id'].startswith('android.')}, set())

    def test_os_only_validators_still_reject_android_refs(self):
        import malware_detections as md
        import target_mount
        self.assertIsNone(md.TARGET_REF_RE.match('and-0'))
        self.assertIsNone(target_mount.REF_RE.match('and-0'))
        self.assertIsNotNone(md.TARGET_REF_RE.match('os-0'))
        self.assertIsNotNone(target_mount.REF_RE.match('os-0'))

    def test_schema_and_journal_accept_android_ids(self):
        import jsonschema
        journal = json.loads((REPO / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        record = {'journal_version': '1', 'seq': 1, 'prev_sha256': '0' * 64, 'recorded_at': '2026-10-01T08:00:00Z',
                  'run_id': 'rescue-20261001-080000', 'action_id': 'android.reboot', 'catalog_sha256': 'c' * 64,
                  'policy': 'approve-each', 'origin': 'operator', 'risk': 'safe', 'stage': 'precondition',
                  'outcome': 'fail', 'target_ref': 'and-0', 'reason': 'device-mismatch'}
        validator = jsonschema.Draft202012Validator(journal)
        self.assertEqual(list(validator.iter_errors(record)), [])
        for reason in ('device-absent', 'device-not-authorized', 'device-ambiguous', 'device-mismatch'):
            self.assertEqual(list(validator.iter_errors(dict(record, reason=reason))), [])
        self.assertTrue(list(validator.iter_errors(dict(record, reason='device-removed'))))
        self.assertTrue(list(validator.iter_errors(dict(record, target_ref='and-8'))))
        self.assertTrue(list(validator.iter_errors(dict(record, params={'device': 'SERIAL:1 2'}))))


# ----------------------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------------------
class EngineTests(AndroidRepairCase):
    def test_trim_caches_runs_on_the_resolved_transport_id_and_is_verified(self):
        proc = self.run_one('android.trim-caches')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.trim-caches'),
                         [('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'), ('execute', 'ok', None),
                          ('verify', 'ok', None)])
        self.assertEqual(self.target_calls(), [['-t', '1', 'shell', 'pm', 'trim-caches', '999G'],
                                               ['-t', '1', 'shell', 'df', '/data']])
        self.assertIn('verified', proc.stdout)
        # the engine looked the phone up (adb devices -l) before each use and stopped the live session's server
        self.assertEqual([c['argv'] for c in self.calls()].count(['devices', '-l']), 2)
        self.assertEqual(self.calls()[-1]['argv'], ['kill-server'])

    def test_the_transport_id_is_never_taken_from_the_command_line(self):
        proc = self.run_one('android.reboot', '--param', 'android.reboot.device=9', '--param', 'android.reboot.device=-s')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.target_calls()[0], ['-t', '1', 'reboot'])
        self.assertNotIn(['-t', '9', 'reboot'], self.target_calls())

    def test_child_environment_has_home_and_no_mdns_and_no_api_key(self):
        proc = self.run_one('android.trim-caches', OPENCODE_GO_API_KEY=HR.HL.DUMMY_KEY)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        envs = [c['env'] for c in self.calls() if c['argv'][:1] == ['-t']]
        self.assertTrue(envs)
        for env in envs:
            self.assertEqual((env['HOME'], env['ADB_MDNS'], env['OPENCODE_GO_API_KEY']), (str(self.home), '0', None))

    def test_journal_has_no_serial_port_or_device_parameter(self):
        proc = self.run_one('android.trim-caches')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.journal_text()
        self.assert_private(text)
        self.assert_private(proc.stdout + proc.stderr)
        for record in read_journal(self.journal):
            self.assertNotIn('params', record)
            self.assertEqual(record['target_ref'], 'and-0')
            self.assertNotIn('argv', record)
        chain = subprocess.run([sys.executable, str(REPAIR), '--verify-journal', str(self.journal)], capture_output=True, text=True)
        self.assertEqual(chain.returncode, 0, chain.stdout)

    def test_policy_auto_safe_runs_only_the_triggered_safe_action(self):
        self.rebuild(storage_free_low=True, verifier_off=True)
        proc = self.engine('--policy', 'auto-safe')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.trim-caches'),
                         [('proposed', 'ok', None), ('approval', 'ok', 'auto-safe'), ('execute', 'ok', None), ('verify', 'ok', None)])
        # reversible: still needs an approval (none without a terminal), and nothing was sent to the phone for it
        self.assertEqual(self.stages('android.enable-package-verifier'),
                         [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.stages('android.reboot'), [])
        sent = [c for c in self.target_calls()]
        self.assertTrue(all(c[2:4] != ['settings', 'put'] and c[2] != 'reboot' for c in sent), sent)

    def test_auto_safe_never_runs_operator_selected_or_reversible_actions(self):
        proc = self.engine('--policy', 'auto-safe', '--select', 'android.reboot:and-0')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.reboot'), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.target_calls(), [])

    def test_detect_only_and_list_never_touch_the_phone(self):
        self.rebuild(storage_free_low=True)
        for args in (['--policy', 'detect-only'], ['--list']):
            with self.subTest(args=args):
                proc = self.engine(*args, '--select', 'android.reboot:and-0')
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn('android.reboot', proc.stdout)
                self.assertEqual(self.calls(), [])
        self.assertEqual({r['stage'] for r in read_journal(self.journal)}, {'proposed', 'approval'})

    def test_catalog_trigger_proposal_comes_from_the_scanner_evidence(self):
        self.rebuild(storage_free_low=True, verifier_off=True)
        self.assertEqual([(p['action_id'], p['origin']) for p in self.ev['repair_proposals']],
                         [('android.trim-caches', 'catalog-trigger'), ('android.enable-package-verifier', 'catalog-trigger')])
        self.assertEqual(self.ev['scope'], ['android'])
        self.assertEqual(self.ev['repair_policy'], 'approve-each')

    def test_reversible_action_verifies_and_leaves_the_setting_on(self):
        proc = self.run_one('android.enable-package-verifier')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([s[:2] for s in self.stages('android.enable-package-verifier')],
                         [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        self.assertEqual([c[2:] for c in self.target_calls()],
                         [['shell', 'settings', 'put', 'global', 'package_verifier_enable', '1'],
                          ['shell', 'settings', 'get', 'global', 'package_verifier_enable']])

    def test_failed_verify_runs_the_rollback_step(self):
        self.command('shell settings get global package_verifier_enable', 1)
        proc = self.run_one('android.enable-package-verifier')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        stages = self.stages('android.enable-package-verifier')
        self.assertEqual([s[:2] for s in stages], [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'),
                                                   ('verify', 'fail'), ('rollback', 'ok')])
        self.assertEqual(self.target_calls()[-1][2:], ['shell', 'settings', 'delete', 'global', 'package_verifier_enable'])
        self.assertIn('rolled-back', proc.stdout)

    def test_failed_execute_is_journaled_and_rolled_back(self):
        self.command('shell pm trim-caches 999G', 1, 'Failure\n')
        proc = self.run_one('android.trim-caches')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.trim-caches')[2:], [('execute', 'fail', 'exit-code')])
        self.assertIn('failed', proc.stdout)

    # -------------------------------------------------------------- refusals
    def assert_refused(self, proc, reason, aid='android.reboot'):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages(aid), [('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'),
                                            ('precondition', 'fail', reason)])
        self.assertEqual(self.target_calls(), [], 'nothing may be sent to a phone that was refused')
        record = [r for r in read_journal(self.journal) if r['stage'] == 'precondition'][0]
        self.assertEqual((record['outcome'], record['reason'], record['target_ref']), ('fail', reason, 'and-0'))
        self.assertIn('skipped', proc.stdout)
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def test_refused_when_the_phone_is_not_authorized(self):
        for state in ('unauthorized', 'offline', 'recovery', 'sideload', 'bootloader'):
            with self.subTest(state=state):
                if self.journal.exists():
                    self.journal.unlink()
                self.set_state(devices=HEADER + device_line(TA.SERIAL_A, '3-2.1', 1, state))
                self.assert_refused(self.run_one('android.reboot'), 'device-not-authorized')

    def test_refused_when_adb_does_not_list_the_phone(self):
        self.set_state(devices=HEADER)
        self.assert_refused(self.run_one('android.reboot'), 'device-not-authorized')

    def test_refused_when_the_phone_is_gone_from_usb(self):
        gone = TA.FakeMachine(self.tmp / 'empty')
        self.set_state(devices=HEADER)
        self.assert_refused(self.run_one('android.reboot', machine=gone), 'device-absent')

    def test_refused_when_adb_is_not_installed(self):
        (self.tmp / 'nobin').mkdir()
        self.assert_refused(self.run_one('android.reboot', adb_dir=self.tmp / 'nobin'), 'device-absent')

    def test_refused_when_another_phone_sits_in_the_port(self):
        other = self.make_machine('OTHERSERIAL000111')
        self.set_state(devices=HEADER + device_line('OTHERSERIAL000111', '3-2.1', 1))
        self.assert_refused(self.run_one('android.reboot', machine=other), 'device-mismatch')

    def test_refused_when_two_phones_share_the_identity(self):
        twin = self.make_machine(TA.SERIAL_A, TA.SERIAL_A)
        self.set_state(devices=HEADER + device_line(TA.SERIAL_A, '3-2.1', 1) + device_line(TA.SERIAL_A, '3-2.2', 2))
        self.assert_refused(self.run_one('android.reboot', machine=twin), 'device-ambiguous')

    def test_refused_when_the_evidence_has_no_opaque_id(self):
        ev = json.loads(self.evidence.read_text())
        del ev['target_systems'][0]['opaque_id']
        bare = self.tmp / 'bare.json'
        bare.write_text(json.dumps(ev))
        self.assert_refused(self.run_one('android.reboot', evidence=bare), 'device-mismatch')

    def test_refused_when_the_evidence_opaque_id_was_edited(self):
        ev = json.loads(self.evidence.read_text())
        ev['target_systems'][0]['opaque_id'] = 'target-0123456789abcdef'
        edited = self.tmp / 'edited.json'
        edited.write_text(json.dumps(ev))
        self.assert_refused(self.run_one('android.reboot', evidence=edited), 'device-mismatch')

    def test_renumbered_phone_is_not_silently_substituted(self):
        # a second phone now sorts first (port 1-2): and-0 is that one, whose identity differs from the evidence
        m = self.make_machine(TA.SERIAL_A)
        m.add_device('1-2', '18d1', '4ee7', ['ff/42/01'], serial=TA.SERIAL_B)
        self.set_state(devices=HEADER + device_line(TA.SERIAL_B, '1-2', 3) + device_line(TA.SERIAL_A, '3-2.1', 1))
        self.assert_refused(self.run_one('android.reboot', machine=m), 'device-mismatch')

    def test_select_needs_an_android_target(self):
        proc = self.engine('--select', 'android.reboot:os-0')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn('does not apply here', proc.stderr)
        proc = self.engine('--select', 'android.reboot')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_android_actions_do_not_run_on_a_windows_or_macos_host_evidence(self):
        ev = json.loads(self.evidence.read_text())
        ev['source_platform'] = 'windows-host'
        win = self.tmp / 'win.json'
        win.write_text(json.dumps(ev))
        proc = self.engine('--select', 'android.reboot:and-0', evidence=win)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.calls(), [])

    # -------------------------------------------------------------- reboot
    def test_reboot_verify_waits_for_the_phone_and_uses_its_new_transport_id(self):
        self.set_state(after_reboot=HEADER + device_line(TA.SERIAL_A, '3-2.1', 5))
        self.command('get-state', 0, 'device\n')
        proc = self.run_one('android.reboot')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.target_calls(), [['-t', '1', 'reboot'], ['-t', '5', 'get-state']])
        self.assertEqual([s[:2] for s in self.stages('android.reboot')],
                         [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        self.assert_private(self.journal_text())

    def test_reboot_verify_fails_when_the_phone_does_not_come_back_authorized(self):
        self.set_state(after_reboot=HEADER + device_line(TA.SERIAL_A, '3-2.1', 5, 'unauthorized'))
        started = time.monotonic()
        proc = self.run_one('android.reboot')
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.reboot')[2:], [('execute', 'ok', None), ('verify', 'fail', 'device-not-authorized')])
        self.assertEqual(self.target_calls(), [['-t', '1', 'reboot']])

    def test_reboot_verify_does_not_accept_a_different_phone(self):
        # while the phone restarts, another phone ends up in the same port (its USB serial replaces the old one)
        serial_file = self.machine.devices / 'usb3' / '3-2' / '3-2.1' / 'serial'
        self.assertTrue(serial_file.is_file())
        self.set_state(after_reboot=HEADER + device_line('OTHERSERIAL000111', '3-2.1', 5),
                       on_reboot_write=[[str(serial_file), 'OTHERSERIAL000111\n']])
        proc = self.run_one('android.reboot')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.reboot')[2:], [('execute', 'ok', None), ('verify', 'fail', 'device-mismatch')])
        self.assertEqual(self.target_calls(), [['-t', '1', 'reboot']])
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def test_wait_override_is_bounded_and_announced(self):
        engine = HR.load_engine()
        self.assertEqual(engine.ANDROID_WAIT_SECONDS, 150)
        proc = self.run_one('android.trim-caches', wait='99999')
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn('Android wait override', proc.stderr)
        proc = self.run_one('android.trim-caches', wait='1')
        self.assertIn('TEST Android wait override', proc.stderr)

    # -------------------------------------------------------------- interactive + host
    def test_interactive_card_shows_a_placeholder_never_the_transport_id_or_serial(self):
        argv = [sys.executable, str(REPAIR), '--evidence', str(self.evidence), '--journal', str(self.journal),
                '--select', 'android.reboot:and-0']
        self.command('get-state', 0, 'device\n')
        rc_, out = HR.run_pty(argv, self.env(), self.tmp, ['ya'])
        self.assertEqual(rc_, 0, out)
        self.assertIn('target: and-0', out)
        self.assertIn('execute: adb -t <android and-0> reboot', out)
        self.assertIn('verify:  adb -t <android and-0> get-state', out)
        self.assert_private(out)
        self.assertEqual(self.target_calls()[0], ['-t', '1', 'reboot'])

    def test_linux_host_platform_runs_and_keeps_the_operators_adb_server(self):
        ev = json.loads(self.evidence.read_text())
        ev['source_platform'] = 'linux-host'
        host = self.tmp / 'host.json'
        host.write_text(json.dumps(ev))
        proc = self.run_one('android.trim-caches', evidence=host)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('android.trim-caches')[-1], ('verify', 'ok', None))
        self.assertNotIn(['kill-server'], [c['argv'] for c in self.calls()])
        self.assertIn('platform=linux-host', proc.stdout)


# ----------------------------------------------------------------------------------------
# scan-android.py additions
# ----------------------------------------------------------------------------------------
class ScanAdditionsTests(AndroidRepairCase):
    def test_count_android_prints_only_the_number(self):
        argv = [sys.executable, str(SCAN), '--fixture-root', str(self.machine.root), '--adb-path', str(self.adb_dir), '--count-android']
        proc = subprocess.run(argv, capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)})
        self.assertEqual((proc.returncode, proc.stdout), (0, '1\n'), proc.stderr)
        self.assertEqual(self.calls(), [], 'counting must not start adb')
        empty = TA.FakeMachine(self.tmp / 'nothing')
        proc = subprocess.run(argv[:3] + [str(empty.root)] + argv[4:], capture_output=True, text=True,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)})
        self.assertEqual((proc.returncode, proc.stdout), (0, '0\n'))

    def test_count_android_stands_alone(self):
        proc = subprocess.run([sys.executable, str(SCAN), '--count-android', '--list-usb'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_evidence_records_scope_policy_and_validates(self):
        self.assertEqual((self.ev['scope'], self.ev['repair_policy'], self.ev['schema_version']), (['android'], 'approve-each', '1.3'))
        self.assertTrue(self.ev['target_systems'][0]['opaque_id'].startswith('target-'))
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'validate-evidence.py'), str(self.evidence)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


# ----------------------------------------------------------------------------------------
# Run report: and-N / android in every generator
# ----------------------------------------------------------------------------------------
class ReportInputs(AndroidRepairCase):
    def produce_run(self):
        """A real journal: trim-caches verified, then reboot refused because another phone sits in the port."""
        self.assertEqual(self.run_one('android.trim-caches').returncode, 0)
        other = self.make_machine('OTHERSERIAL000111')
        self.set_state(devices=HEADER + device_line('OTHERSERIAL000111', '3-2.1', 1))
        proc = self.run_one('android.reboot', machine=other)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        paths = {}
        inp = self.tmp / 'in'
        inp.mkdir()
        shutil.copy(self.evidence, inp / 'evidence.json')
        shutil.copy(self.journal, inp / 'journal.jsonl')
        paths['evidence'], paths['journal'] = inp / 'evidence.json', inp / 'journal.jsonl'
        return paths


class ReportTests(ReportInputs):
    def test_python_report_accepts_android_targets_actions_and_reasons(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        out, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md, _ = TR.read_report(out)
        TR.validate(self, doc)
        self.assertEqual(doc['detection']['targets'][0]['family'], 'android')
        self.assertEqual(doc['detection']['targets'][0]['ref'], 'and-0')
        self.assertEqual(doc['detection']['targets'][0]['access'], 'adb-authorized')
        self.assertEqual(doc['header']['scope'], ['android'])
        actions = {(a['action_id'], a.get('target_ref')): a for a in doc['remediation']['actions']}
        self.assertEqual(actions[('android.trim-caches', 'and-0')]['final_outcome'], 'verified')
        reboot = actions[('android.reboot', 'and-0')]
        self.assertEqual((reboot['final_outcome'], reboot['stages']), ('skipped', [
            {'stage': 'precondition', 'outcome': 'fail', 'reason': 'device-mismatch'}]))
        self.assertEqual(doc['privacy_check'], {'status': 'passed', 'findings': []})
        text = json.dumps(doc) + md
        for leak in SERIAL_LEAKS:
            self.assertNotIn(leak, text)
        self.assertNotIn('3-2.1', text)

    def test_the_unchanged_run_report_still_refuses_a_leak(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        out, proc = gen.python(paths, mode='live-linux', run_id='run-10.20.30.40')
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(TR.read_report(out)[0]['privacy_check']['status'], 'refused')

    def test_rr_enums_match_the_schema(self):
        schema = json.loads((REPO / 'rescue-ai/v1/run-report.schema.json').read_text())
        targets = schema['properties']['detection']['properties']['targets']['items']['properties']
        for key, values in rr.TARGET_ENUMS.items():
            self.assertEqual(list(values), targets[key]['enum'], key)
        self.assertEqual(list(rr.SCOPE_VALUES), schema['properties']['header']['properties']['scope']['items']['enum'])
        journal = json.loads((REPO / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        self.assertEqual(list(rr.REASONS), journal['properties']['reason']['enum'])
        self.assertEqual(rr.ACTION_RE.pattern, journal['properties']['action_id']['pattern'])
        self.assertEqual(rr.TARGET_RE.pattern, journal['properties']['target_ref']['pattern'])


@unittest.skipUnless(NODE, 'node not installed')
class JxaReportTests(ReportInputs):
    def test_jxa_report_equals_the_python_report_for_the_android_run(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        js_dir, proc = gen.jxa(paths, mode='live-linux', outcome='completed', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, js = TR.read_report(py_dir), TR.read_report(js_dir)
        TR.validate(self, js[0])
        self.assertEqual(py[0], js[0])
        self.assertEqual(py[1], js[1])
        self.assertEqual(py[2], js[2])
        self.assertEqual(js[0]['detection']['targets'][0]['family'], 'android')
        self.assertTrue(any(a.get('target_ref') == 'and-0' for a in js[0]['remediation']['actions']))

    def test_jxa_still_drops_a_malformed_android_ref(self):
        paths = self.produce_run()
        ev = json.loads(paths['evidence'].read_text())
        ev['target_systems'][0]['ref'] = 'and-9'
        paths['evidence'].write_text(json.dumps(ev))
        gen = TR.Generators(self.tmp)
        py_dir, _ = gen.python(paths, mode='live-linux')
        js_dir, proc = gen.jxa(paths, mode='live-linux')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(TR.read_report(js_dir)[0]['detection']['available'])
        self.assertEqual(TR.read_report(py_dir)[0], TR.read_report(js_dir)[0])


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellReportTests(ReportInputs):
    def test_powershell_report_equals_the_python_report_for_the_android_run(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        ps_dir, proc = gen.powershell(paths, mode='live-linux', outcome='completed', scope='android', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, ps = TR.read_report(py_dir), TR.read_report(ps_dir)
        TR.validate(self, ps[0])
        self.assertEqual(py, ps)


class GeneratorStaticTests(unittest.TestCase):
    """The PowerShell generator cannot run here without pwsh: its closed lists must match the Python ones."""

    def test_powershell_lists_match_the_python_generator(self):
        text = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')

        def ps_list(name):
            m = re.search(r'\$script:%s = @\((.*?)\)\n' % name, text, re.S)
            return re.findall(r"'([^']+)'", m.group(1))
        self.assertEqual(ps_list('RrScopeValues'), list(rr.SCOPE_VALUES))
        self.assertEqual(ps_list('RrReasons'), list(rr.REASONS))
        m = re.search(r'\$script:RrTargetEnums = @\{(.*?)\n\}', text, re.S)
        for key, values in rr.TARGET_ENUMS.items():
            line = re.search(r'%s = @\((.*?)\)' % key, m.group(1)).group(1)
            self.assertEqual(re.findall(r"'([^']+)'", line), list(values), key)
        self.assertIn("'^(os|and|prn)-[0-7]$'", text)
        self.assertIn("$script:RrActionRe = '%s'" % rr.ACTION_RE.pattern, text)

    def test_javascript_lists_match_the_python_generator(self):
        text = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')

        def js_list(name):
            m = re.search(r'var %s = \[(.*?)\];' % name, text, re.S)
            return re.findall(r"'([^']+)'", m.group(1))
        self.assertEqual(js_list('SCOPE_VALUES'), list(rr.SCOPE_VALUES))
        self.assertEqual(js_list('REASONS'), list(rr.REASONS))
        m = re.search(r'var TARGET_ENUMS = \{(.*?)\n\};', text, re.S)
        for key, values in rr.TARGET_ENUMS.items():
            line = re.search(r'%s: \[(.*?)\]' % key, m.group(1), re.S).group(1)
            self.assertEqual(re.findall(r"'([^']+)'", line), list(values), key)
        self.assertIn('var ACTION_RE = /%s/;' % rr.ACTION_RE.pattern.replace('/', '\\/'), text)


# ----------------------------------------------------------------------------------------
# Host engines: the catalog (with the Android domain) must stay loadable; the type stays unsupported there
# ----------------------------------------------------------------------------------------
def jxa_plan(catalog_dir, evidence, select='', scope='all', analysis=None, tmp=None):
    files = sorted(Path(catalog_dir).glob('*.json'))
    ev = Path(tmp) / 'plan-evidence.json'
    ev.write_text(json.dumps(evidence))
    env = dict(os.environ, RESCUE_PLAN_MODE='plan', RESCUE_CATALOG_FILES='\n'.join(map(str, files)),
               RESCUE_EVIDENCE_FILE=str(ev), RESCUE_ANALYSIS_FILE=str(analysis or ''), RESCUE_SCOPE=scope,
               RESCUE_SELECT=select, RESCUE_FORBIDDEN=','.join(sorted(rc.FORBIDDEN_PROGRAMS)))
    proc = subprocess.run(['node', str(HR.SHIM_JS), '-l', 'JavaScript', '-e', HR.planner_source()], capture_output=True,
                          text=True, env=env)
    return proc, [line.split('\t') for line in proc.stdout.splitlines()]


class HostEngineTests(unittest.TestCase):
    def test_powershell_engine_knows_the_android_names_statically(self):
        text = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
        self.assertIn("'state_dir', 'android_device', 'fastboot_device', 'fastboot_slot', 'firmware_file', 'sha256', 'printer_ref', 'bundle_root') -cnotcontains $pt", text)
        self.assertIn("'software', 'malware', 'android', 'printer') -cnotcontains $domain", text)
        self.assertIn('(hw|os-linux|os-windows|os-macos|sw|mw|android|printer)', text)
        self.assertRegex(text, r"\$unsupported = @\(\$action\.params \| Where-Object \{[^}]*android_device")
        self.assertIn("-or $_.type -ceq 'sha256' -or $_.type -ceq 'printer_ref' -or $_.type -ceq 'bundle_root' }).Count -gt 0", text)

    def test_macos_engine_knows_the_android_names_statically(self):
        text = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
        self.assertIn("'state_dir', 'android_device', 'fastboot_device', 'fastboot_slot', 'firmware_file', 'sha256', 'printer_ref', 'bundle_root'].indexOf(p.type)", text)
        self.assertIn("'software', 'malware', 'android', 'printer'].indexOf(doc.domain)", text)
        self.assertIn('(hw|os-linux|os-windows|os-macos|sw|mw|android|printer)', text)
        self.assertIn('[[ ${P_type[$pk]} == (block_device|target_root|android_device|fastboot_device|fastboot_slot|firmware_file|sha256|printer_ref|bundle_root) ]] && unsupported=1', text)
        self.assertIn('hardware.usb|os|software|software.selected|malware|android|printer) ;;', text)

    def test_every_host_catalog_parameter_type_is_in_the_closed_lists_of_both_engines(self):
        schema = json.loads((REPO / 'rescue-ai/v1/repair-catalog.schema.json').read_text())
        types = set(schema['$defs']['param']['properties']['type']['enum'])
        ps = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
        mac = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
        ps_types = set(re.findall(r"'([a-z0-9_]+)'", re.search(r"@\('enum', 'integer'[^)]*\) -cnotcontains \$pt", ps).group(0)))
        mac_types = set(re.findall(r"'([a-z0-9_]+)'", re.search(r"\['enum', 'integer'[^\]]*\]\.indexOf\(p\.type\)", mac).group(0)))
        self.assertEqual(ps_types, types)
        self.assertEqual(mac_types, types)

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_loads_the_shipped_catalog_and_proposes_no_android_action_on_macos(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = {'source_platform': 'macos-host', 'scope': ['all'],
                        'target_systems': [{'ref': 'os-0', 'family': 'macos'}, {'ref': 'and-0', 'family': 'android'}],
                        'checks': [{'check_id': 'android-storage-free', 'status': 'fail', 'target_ref': 'and-0'},
                                   {'check_id': 'android-play-protect', 'status': 'warn', 'target_ref': 'and-0'}]}
            proc, lines = jxa_plan(rc.CATALOG_DIR, evidence, tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual([l for l in lines if l[0] == 'ERR'], [], proc.stdout)
            self.assertEqual([l for l in lines if l[0] in ('PROP', 'ACT')], [])
            # selecting one is refused as "does not apply here" (platform), never run
            proc, lines = jxa_plan(rc.CATALOG_DIR, evidence, select='android.reboot:and-0', tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(['SELERR', 'android.reboot does not apply here'], lines)
            # the planner agrees with the Python engine about the same evidence
            catalog = rc.load()
            evidence['source_platform'] = 'macos-host'
            self.assertEqual([p for p in rc.triggered(catalog, evidence, ('all',)) if p['action_id'].startswith('android.')], [])

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_accepts_the_android_domain_and_scope_in_a_catalog(self):
        # same catalog under the macOS platform name: the planner must at least parse the Android domain file
        with tempfile.TemporaryDirectory() as tmp:
            only = Path(tmp) / 'cat'
            only.mkdir()
            shutil.copy(rc.CATALOG_DIR / 'android.json', only / 'android.json')
            proc, lines = jxa_plan(only, {'source_platform': 'macos-host', 'scope': ['android'],
                                          'target_systems': [{'ref': 'os-0', 'family': 'macos'}], 'checks': []},
                                   scope='android', tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual([l for l in lines if l[0] == 'ERR'], [], proc.stdout)
            # a typo in a parameter type is still caught (the closed list is real)
            doc = json.loads((only / 'android.json').read_text())
            doc['actions'][0]['params'][0]['type'] = 'android_devices'
            (only / 'android.json').write_text(json.dumps(doc))
            proc, lines = jxa_plan(only, {'source_platform': 'macos-host', 'scope': ['android'], 'target_systems': [], 'checks': []},
                                   scope='android', tmp=tmp)
            self.assertTrue([l for l in lines if l[0] == 'ERR'], proc.stdout)


# ----------------------------------------------------------------------------------------
# Launcher wiring
# ----------------------------------------------------------------------------------------
class LauncherStaticTests(unittest.TestCase):
    def test_launcher_offers_the_phone_scan_after_the_os_scan(self):
        text = (SCRIPTS / 'launch-hermes-rescue.sh').read_text()
        self.assertIn('android_phase || true', text)
        self.assertLess(text.index('python3 "$root/scripts/rescue-repair.py" "${repair_args[@]}"'), text.index('android_phase || true'))
        self.assertLess(text.index('android_phase || true'), text.index('emit_report\n\nif ((offline))'))
        body = text[text.index('android_phase() {'):text.index('android_phase || true')]
        self.assertIn('[[ -t 0 ]] || return 0', body)
        self.assertIn('--count-android', body)
        self.assertIn('--list-usb', body)
        self.assertIn('read -r -t 300 answer', body)
        self.assertNotIn('sudo', body)
        self.assertIn('--scope android', body)
        self.assertIn('android-evidence-$ts.json', body)


STUB_SCAN_ANDROID = """#!/usr/bin/env python3
import json, shutil, sys
args = sys.argv[1:]
with open({log!r}, 'a') as handle:
    handle.write(json.dumps(args) + '\\n')
if '--count-android' in args:
    print({count})
    sys.exit(0)
if '--list-usb' in args:
    print('PORT TABLE FOR THE TEST')
    sys.exit(0)
if {fail}:
    sys.exit(1)
shutil.copy({fixture!r}, args[args.index('--output') + 1])
"""


class LauncherPhaseTests(unittest.TestCase):
    """scripts/launch-hermes-rescue.sh with stub scanners; the real repair engine and report generator run."""

    setUpClass = classmethod(TR.LiveLauncherReportTests.setUpClass.__func__)
    setUp = TR.LiveLauncherReportTests.setUp
    launch = TR.LiveLauncherReportTests.launch
    reports_dir = TR.LiveLauncherReportTests.reports_dir

    def stub_android(self, count=1, fail=False):
        c = self.case
        self.android_log = c.tmp / 'android.log'
        stub = c.src / 'scripts' / 'scan-android.py'
        stub.write_text(STUB_SCAN_ANDROID.format(log=str(self.android_log), count=count, fail=fail,
                                                 fixture=str(c.src / 'rescue-ai/v1/fixtures/valid-android-usb.json')))
        os.chmod(stub, 0o755)
        c._open(stub)
        os.chmod(stub, 0o755)

    def android_calls(self):
        if not self.android_log.exists():
            return []
        return [json.loads(line) for line in self.android_log.read_text().splitlines()]

    def tty_launch(self, answer, *extra, timeout=90):
        c = self.case
        cmd = 'exec %s --state-dir %s %s' % (shlex.quote(str(c.src / 'scripts' / 'launch-hermes-rescue.sh')),
                                              shlex.quote(str(c.state)), ' '.join(shlex.quote(a) for a in extra))
        env = dict(HOME=str(c.home), PATH='%s:/usr/bin:/bin' % c.shims, LANG='C', RESCUE_NET_WAIT_SECONDS='0',
                   RESCUE_TEST_BASE_URL=c.provider.base, RESCUE_REPAIR_TEST_PATH=str(self.fake),
                   RESCUE_TARGET_MOUNT_FIXTURE_ROOT=str(c.tmp), OPENCODE_GO_API_KEY=TR.DUMMY_KEY)
        argv = ['script', '-qec', cmd, '/dev/null']
        if os.geteuid() == 0:
            argv = ['setpriv', '--reuid=%s' % self.THS.UNPRIV_ID, '--regid=%s' % self.THS.UNPRIV_ID, '--clear-groups'] + argv
        proc = subprocess.run(argv, env=env, input=answer, capture_output=True, text=True, timeout=timeout, cwd=str(c.tmp))
        return proc.stdout + proc.stderr

    def android_reports(self):
        found = []
        for path in sorted(self.reports_dir().glob('run-*/report.json')):
            doc = json.loads(path.read_text(encoding='utf-8'))
            if doc['run_id'].endswith('-android'):
                found.append(doc)
        return found

    def test_a_non_interactive_run_never_offers_or_scans_the_phone(self):
        self.stub_android()
        proc = self.launch('--repair-policy', 'detect-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('HERMES-RAN', proc.stdout)
        self.assertEqual(self.android_calls(), [])
        self.assertEqual(list(self.reports_dir().glob('android-evidence-*.json')), [])
        self.assertEqual(self.android_reports(), [])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_yes_scans_the_phone_runs_the_engine_and_writes_its_own_report(self):
        self.stub_android()
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertIn('PORT TABLE FOR THE TEST', out)
        self.assertIn('Pindai ponsel/tablet ini', out)
        self.assertIn('HERMES-RAN', out)
        self.assertEqual(self.android_calls()[0], ['--count-android'])
        self.assertEqual(self.android_calls()[1], ['--list-usb'])
        scan = self.android_calls()[2]
        self.assertEqual(scan[scan.index('--source-platform') + 1], 'live-linux')
        self.assertEqual(scan[scan.index('--repair-policy') + 1], 'detect-only')
        self.assertIn('--provider-ready', scan)
        files = list(self.reports_dir().glob('android-evidence-*.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        reports = self.android_reports()
        self.assertEqual(len(reports), 1)
        TR.validate(self, reports[0])
        self.assertEqual((reports[0]['header']['mode'], reports[0]['header']['scope'], reports[0]['header']['outcome']),
                         ('live-linux', ['android'], 'completed'))
        self.assertEqual(reports[0]['detection']['targets'][0]['family'], 'android')
        self.assertEqual(reports[0]['header']['evidence_run_id'], json.loads(files[0].read_text())['run_id'])
        # the OS run keeps its own report, evidence and journal filter
        self.assertTrue(list(self.reports_dir().glob('target-evidence-*.json')))
        self.assertEqual(len([d for d in self.reports_dir().glob('run-*/report.json')]), 2)
        self.assertNotIn(TR.DUMMY_KEY, ''.join(p.read_text(encoding='utf-8', errors='replace')
                                              for p in self.reports_dir().rglob('*') if p.is_file() and p.suffix in ('.md', '.json')))

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_default_answer_is_no(self):
        self.stub_android()
        for answer in ('\n', 'n\n', 'maybe\n', ''):
            with self.subTest(answer=answer):
                out = self.tty_launch(answer, '--repair-policy', 'detect-only')
                self.assertIn('Phone scan skipped', out)
                self.assertNotIn(['--output'], [c[:1] for c in self.android_calls()])
                self.assertEqual(list(self.reports_dir().glob('android-evidence-*.json')), [])
                self.assertEqual(self.android_reports(), [])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_no_phone_means_no_prompt(self):
        self.stub_android(count=0)
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertNotIn('Pindai ponsel/tablet ini', out)
        self.assertEqual(self.android_calls(), [['--count-android']])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_scope_without_android_and_no_target_scan_skip_the_phone(self):
        self.stub_android()
        for extra in (('--scope', 'os'), ('--no-target-scan',)):
            with self.subTest(extra=extra):
                self.tty_launch('y\n', '--repair-policy', 'detect-only', *extra)
                self.assertEqual(self.android_calls(), [])
        self.tty_launch('y\n', '--repair-policy', 'detect-only', '--scope', 'os,android')
        self.assertEqual(self.android_calls()[0], ['--count-android'])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_a_failed_phone_scan_is_reported_and_does_not_block_hermes(self):
        self.stub_android(fail=True)
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertIn('HERMES-RAN', out)
        self.assertIn('pemindaian ponsel gagal', out)
        reports = self.android_reports()
        self.assertEqual([r['header']['outcome'] for r in reports], ['scan-failed'])
        self.assertFalse(reports[0]['detection']['available'])
        self.assertEqual(list(self.reports_dir().glob('android-evidence-*.json')), [])


if __name__ == '__main__':
    unittest.main()
