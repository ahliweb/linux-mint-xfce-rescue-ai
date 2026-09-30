#!/usr/bin/env python3
"""Tests for the Windows and macOS host repair engines (ahliweb/linux-mint-xfce-rescue-ai#25).

* Windows (host/rescue-windows.ps1): run under pwsh on Linux with fake programs.
* macOS (host/RESCUE-MACOS.command): run under zsh with the macOS command shims; the JXA
  (osascript -l JavaScript) planner is emulated by running the SAME JavaScript source in node
  behind a tiny ObjC facade (tests/host_osascript_shim.js), so the real plan logic is tested.
* Every fixture catalog is private to a bundle copy; the shipped catalogs are never used.
* Cross-checks against the Python engine: journals verify with rescue-repair.py --verify-journal,
  the backup fingerprint and catalog hash are identical, proposals and AI-proposal parsing match
  repair_catalog.triggered / parse_ai_proposals.

Real Windows and macOS behavior is Hardware-required and NOT tested here.
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import hashlib
import importlib.util
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_host_launchers as HL  # noqa: E402

REPO = HL.REPO
PWSH, ZSH = HL.PWSH, HL.ZSH
NODE = shutil.which('node')
PS1 = REPO / 'host' / 'rescue-windows.ps1'
MAC = REPO / 'host' / 'RESCUE-MACOS.command'
SHIM_JS = HERE / 'host_osascript_shim.js'

sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
import repair_catalog as rc  # noqa: E402


def load_engine():
    spec = importlib.util.spec_from_file_location('rescue_repair_engine', REPO / 'scripts' / 'rescue-repair.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENGINE = load_engine()

FAKE_PROGRAM = '''#!/bin/sh
d=${0%/*}
{ for a in "$@"; do printf '[%s]' "$a"; done; printf '\\n'; } >> "$d/calls.log"
case "$1" in
  fail) echo failing; exit 3 ;;
  sleep) exec /bin/sleep 30 ;;
  *) echo "out:$1"; exit 0 ;;
esac
'''


def step(*argv, **extra):
    return dict({'argv': list(argv)}, **extra)


def action(aid, title, scope, risk, execute, verify, families=None, platforms=None, triggers=None, **extra):
    doc = {
        'action_id': aid, 'title': title, 'title_id': title + ' (id)', 'scope': scope,
        'platforms': platforms, 'risk': risk, 'triggers': triggers or [],
        'execute': execute, 'verify': verify, 'rollback': {'kind': 'none'},
        'backup': {'required': False}, 'doc': 'docs/host-repair.md',
    }
    if families:
        doc['target_families'] = families
    doc.update(extra)
    return doc


TRICKY = ['a b', 'say "hi"', 'trail\\', 'q"\\"', 'C:\\Program Files\\x y\\', '--k=v w', 'plain', '\\\\']


def fixture_catalog(osp, family, platform, c1, c2, c3):
    """Catalog files for one host platform. c1/c2 fail-checks, c3 warn-check, all emitted by stub modules."""
    fake = 'rescuefake'
    ok = step(fake, 'ok')
    rollback = {'kind': 'step', 'step': step(fake, 'rollback')}
    plats = [platform]
    p = osp + '.'
    os_actions = [
        action(p + 'safe-ok', 'Safe ok', 'os', 'safe', ok, ok, [family], plats, [{'check_id': c1, 'status': ['fail']}]),
        action(p + 'safe-param', 'Safe param', 'os', 'safe', step(fake, 'run', '--mode={mode}', '{n}'), ok, [family], plats,
               [{'check_id': c1, 'status': ['fail']}],
               params=[{'name': 'mode', 'type': 'enum', 'values': ['a', 'b'], 'default': 'a'},
                       {'name': 'n', 'type': 'integer', 'minimum': 1, 'maximum': 9}]),
        action(p + 'rev-fail', 'Reversible failing', 'os', 'reversible', step(fake, 'fail'), ok, [family], plats,
               [{'check_id': c2, 'status': ['fail']}], rollback=rollback),
        action(p + 'rev-verify-fail', 'Reversible verify fails', 'os', 'reversible', ok, step(fake, 'fail'), [family], plats,
               [{'check_id': c2, 'status': ['fail']}], rollback=rollback),
        action(p + 'destructive', 'Destructive', 'os', 'destructive', step(fake, 'wipe'), ok, [family], plats,
               [{'check_id': c3, 'status': ['warn']}], rollback={'kind': 'manual', 'doc': 'docs/host-repair.md'},
               backup={'required': True, 'what': 'file-copy'}),
        action(p + 'needs-root', 'Needs root', 'os', 'safe', ok, ok, [family], plats,
               [{'check_id': c1, 'status': ['fail']}], requires_root=True),
        action(p + 'slow', 'Slow', 'os', 'safe', step(fake, 'sleep', timeout_seconds=1), ok, [family], plats),
        action(p + 'quote-test', 'Quote test', 'os', 'safe', step(fake, 'args', *TRICKY), ok, [family], plats),
        action(p + 'missing-program', 'Missing program', 'os', 'safe', step('nosuchprogramxyz'), ok, [family], plats),
        action(p + 'precond', 'Precondition fails', 'os', 'safe', ok, ok, [family], plats,
               preconditions=[step(fake, 'fail')]),
    ]
    hw_actions = [
        action('hw.disk-fake', 'Disk fake', 'hardware.disk', 'safe', step(fake, 'disk', '{device}'), ok,
               platforms=[platform], triggers=[{'check_id': 'hw-disk', 'status': ['fail']}],
               params=[{'name': 'device', 'type': 'block_device'}]),
        action('hw.cpu-fake', 'Cpu fake', 'hardware.cpu', 'safe', ok, ok, platforms=[platform],
               triggers=[{'check_id': 'hw-cpu', 'status': ['warn']}]),
    ]
    sw_actions = [
        action('sw.fake-pkg', 'Package fake', 'software', 'reversible', step(fake, 'pkg', '{pkg}'), ok, [family], plats,
               params=[{'name': 'pkg', 'type': 'package_name'}], rollback=rollback),
        action('sw.fake-svc', 'Service fake', 'software', 'reversible', step(fake, 'svc', '--name={svc}'), ok, [family],
               plats, params=[{'name': 'svc', 'type': 'service_name'}], rollback=rollback),
    ]
    return {
        'hardware.json': {'catalog_version': '1', 'domain': 'hardware', 'actions': hw_actions},
        osp + '.json': {'catalog_version': '1', 'domain': osp, 'actions': os_actions},
        'software.json': {'catalog_version': '1', 'domain': 'software', 'actions': sw_actions},
    }


def install_catalog(bundle, files):
    cat = Path(bundle) / 'rescue-ai' / 'v1' / 'catalog'
    for old in cat.glob('*.json'):
        old.unlink()
    for name, doc in files.items():
        (cat / name).write_text(json.dumps(doc, indent=1) + '\n', encoding='utf-8')
    return cat


def read_journal(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding='utf-8').splitlines() if line.strip()]


def stages(records, aid):
    return [(r['stage'], r['outcome'], r.get('reason')) for r in records if r['action_id'] == aid]


def verify_with_python(testcase, path):
    proc = subprocess.run([sys.executable, str(REPO / 'scripts' / 'rescue-repair.py'), '--verify-journal', str(path)],
                          capture_output=True, text=True)
    testcase.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


def run_pty(cmd, env, cwd, answers, timeout=180):
    """Run cmd with a real terminal (stdin and stdout are ttys); feed one answer per prompt."""
    master, slave = os.openpty()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=cwd, close_fds=True,
                            start_new_session=True)
    os.close(slave)
    out, fed = b'', 0
    prompt = re.compile(rb'(Jalankan\? / Run\?|type the action_id to approve: |value for [a-z_]+ \([^)]*\): )')
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            seen = len(prompt.findall(out))
            while fed < seen:
                os.write(master, (answers[fed] if fed < len(answers) else '').encode() + b'\n')
                fed += 1
        elif proc.poll() is not None:
            break
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    os.close(master)
    return proc.returncode, out.decode('utf-8', 'replace')


class HostRepairCase(unittest.TestCase):
    """Shared: a USB bundle copy with a fixture catalog and stub detection modules."""
    OSP = None
    FAMILY = None
    PLATFORM = None
    CHECKS = None  # (c1, c2, c3)

    def make_bundle(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-repair-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = HL.make_usb(self.tmp, launcher_at_root='RESCUE-MACOS.command')
        self.catalog_files = fixture_catalog(self.OSP, self.FAMILY, self.PLATFORM, *self.CHECKS)
        install_catalog(self.bundle, self.catalog_files)
        self.fakebin = self.tmp / 'fakebin'
        self.fakebin.mkdir()
        fake = self.fakebin / 'rescuefake'
        fake.write_text(FAKE_PROGRAM)
        fake.chmod(0o755)
        self.calls = self.fakebin / 'calls.log'
        self.journal = self.bundle / 'reports' / 'repairs' / 'journal.jsonl'

    def read_calls(self):
        if not self.calls.exists():
            return []
        return self.calls.read_text(encoding='utf-8').splitlines()

    def evidence_file(self):
        found = sorted((self.bundle / 'reports').glob('*-evidence.json'))
        return found[-1]

    def load_python_catalog(self):
        return rc.load(self.bundle / 'rescue-ai' / 'v1' / 'catalog')


# ----------------------------------------------------------------------------------------
# Scenarios shared by both host engines (each runs once per platform)
# ----------------------------------------------------------------------------------------
class Scenarios:
    """Mixin: same contract on Windows and macOS. Subclasses provide repair(), plan(), interactive()."""
    F = {}

    def p(self, name):
        return self.OSP + '.' + name

    def flag(self, name):
        return self.F[name]

    def records(self):
        return read_journal(self.journal)

    def stage_list(self, name):
        return stages(self.records(), self.p(name))

    # -- planning ---------------------------------------------------------------------
    def test_fixture_catalog_is_valid_for_the_python_loader(self):
        catalog = self.load_python_catalog()
        self.assertIn(self.OSP + '.safe-ok', catalog.actions)
        self.assertEqual(len(catalog.sha256), 64)

    def test_plan_only_modes_do_not_execute_or_journal(self):
        for flag in (self.flag('evidence_only'), self.flag('dry_run')):
            with self.subTest(flag=flag):
                proc = self.plan(flag)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn(self.p('safe-ok'), proc.stdout)
                self.assertIn('catalog-trigger', proc.stdout)
                self.assertFalse(self.journal.exists())
                self.assertEqual(self.read_calls(), [])
                time.sleep(1.05)

    def test_list_repairs_plans_only_but_still_reaches_the_no_key_exit(self):
        time.sleep(0.1)
        proc = self.run_args(self.flag('list'))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn(self.p('safe-ok'), proc.stdout)
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.read_calls(), [])

    def test_scope_limits_the_plan(self):
        proc = self.plan(self.flag('evidence_only'), self.flag('scope'), 'hardware.disk')
        self.assertIn('hw.disk-fake', proc.stdout)
        self.assertNotIn(self.OSP + '.safe-ok', proc.stdout)
        self.assertNotIn('hw.cpu-fake', proc.stdout)

    def test_only_this_platforms_actions_are_selected(self):
        other = {'os-windows': ('os-macos', 'macos', 'macos-host', 'macos-disk-verify', 'macos-software-update', 'sw-inventory'),
                 'os-macos': ('os-windows', 'windows', 'windows-host', 'windows-system-files', 'windows-boot-config', 'sw-inventory')}[self.OSP]
        extra = fixture_catalog(*other)
        files = dict(self.catalog_files)
        files[other[0] + '.json'] = extra[other[0] + '.json']
        install_catalog(self.bundle, files)
        proc = self.plan(self.flag('evidence_only'))
        self.assertNotIn(other[0] + '.', proc.stdout)
        self.assertIn(self.OSP + '.', proc.stdout)

    def test_plan_matches_the_python_triggers(self):
        proc = self.plan(self.flag('evidence_only'))
        catalog = self.load_python_catalog()
        evidence = json.loads(self.evidence_file().read_text(encoding='utf-8'))
        expected = rc.triggered(catalog, evidence, ('all',))
        listed = re.findall(r'^  - (\S+)\s+(\S+)\s+(\S+)\s+(\S+)$', proc.stdout, re.M)
        self.assertEqual([(a, o, t) for a, _r, o, t in listed],
                         [(e['action_id'], e['origin'], e.get('target_ref', '-')) for e in expected])
        self.assertGreaterEqual(len(expected), 6)

    def test_invalid_catalog_bad_select_and_bad_param_flag(self):
        cat = self.bundle / 'rescue-ai' / 'v1' / 'catalog' / (self.OSP + '.json')
        good = cat.read_text()
        doc = json.loads(good)
        doc['actions'][0]['execute']['argv'][0] = 'powershell.exe'
        cat.write_text(json.dumps(doc))
        proc = self.plan(self.flag('evidence_only'))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn('INVALID', proc.stdout + proc.stderr)
        cat.write_text(good)
        proc = self.plan(self.flag('evidence_only'), self.flag('select'), self.p('nope'))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        proc = self.plan(self.flag('evidence_only'), self.flag('select'), 'os-linux.safe-ok')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.run_args(self.flag('param'), 'nonsense').returncode, 64)

    def test_select_defaults_to_the_only_target_and_accepts_an_explicit_one(self):
        for sel in (self.p('slow'), self.p('slow') + ':os-0'):
            proc = self.plan(self.flag('evidence_only'), self.flag('select'), sel)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertRegex(proc.stdout, self.OSP + r'\.slow\s+safe\s+operator\s+os-0')

    # -- policies ---------------------------------------------------------------------
    def test_detect_only_journals_proposals_and_runs_nothing(self):
        self.repair(self.flag('policy'), 'detect-only', self.flag('approve'), self.p('safe-ok'))
        self.assertEqual(self.stage_list('safe-ok'), [('proposed', 'ok', None), ('approval', 'skipped', 'policy-detect-only')])
        self.assertEqual(self.read_calls(), [])
        verify_with_python(self, self.journal)

    def test_approve_each_without_terminal_declines(self):
        self.repair()
        self.assertEqual(self.stage_list('safe-ok'), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.read_calls(), [])

    def test_cli_approve_runs_and_journal_verifies_with_python(self):
        proc = self.repair(self.flag('approve'), self.p('safe-ok'))
        records = self.records()
        self.assertEqual(self.stage_list('safe-ok'), [
            ('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'), ('execute', 'ok', None), ('verify', 'ok', None)])
        self.assertEqual(self.read_calls(), ['[ok]', '[ok]'])
        self.assertIn('verified', proc.stdout)
        verify_with_python(self, self.journal)
        first = records[0]
        self.assertEqual(first['platform'], self.PLATFORM)
        self.assertEqual(first['policy'], 'approve-each')
        self.assertEqual(first['journal_version'], '1')
        self.assertEqual(first['catalog_sha256'], self.load_python_catalog().sha256)
        self.assertEqual(first['evidence_sha256'], hashlib.sha256(self.evidence_file().read_bytes()).hexdigest())
        self.assertEqual(first['run_id'], json.loads(self.evidence_file().read_text())['run_id'])
        self.assertEqual([r['seq'] for r in records], list(range(1, len(records) + 1)))
        exec_rec = next(r for r in records if r['stage'] == 'execute')
        self.assertEqual(exec_rec['output_sha256'], hashlib.sha256(b'out:ok\n').hexdigest())
        self.assertEqual((exec_rec['output_bytes'], exec_rec['exit_code']), (7, 0))
        for line in self.journal.read_text(encoding='utf-8').splitlines():  # compact, sorted keys, like the Python engine
            self.assertEqual(line, json.dumps(json.loads(line), sort_keys=True, separators=(',', ':')))
        text = self.journal.read_text(encoding='utf-8')
        self.assertNotIn(str(self.tmp), text)
        self.assertNotIn('out:ok', text)
        if self.PLATFORM == 'macos-host':
            self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def test_journal_is_append_only_across_runs(self):
        self.repair(self.flag('approve'), self.p('safe-ok'))
        n = len(self.records())
        self.repair(self.flag('policy'), 'detect-only')
        records = self.records()
        self.assertGreater(len(records), n)
        self.assertEqual([r['seq'] for r in records], list(range(1, len(records) + 1)))
        verify_with_python(self, self.journal)

    def test_auto_safe_runs_only_safe_triggers_without_missing_params(self):
        self.repair(self.flag('policy'), 'auto-safe')
        self.assertEqual(self.stage_list('safe-ok')[1], ('approval', 'ok', 'auto-safe'))
        self.assertEqual(stages(self.records(), 'hw.cpu-fake')[1], ('approval', 'ok', 'auto-safe'))
        self.assertEqual(self.stage_list('safe-param')[1], ('approval', 'skipped', 'missing-param'))  # never prompted
        self.assertEqual(self.stage_list('rev-fail')[1], ('approval', 'declined', 'not-interactive'))
        self.assertEqual(self.stage_list('destructive')[1], ('backup', 'unavailable', 'missing-backup'))
        self.assertEqual(self.stage_list('needs-root')[1], ('approval', 'unavailable', 'not-applicable'))
        self.assertEqual(stages(self.records(), 'hw.disk-fake')[1], ('target-rw', 'unavailable', 'provider-unavailable'))
        verify_with_python(self, self.journal)

    def test_auto_safe_never_runs_ai_or_operator_proposals(self):
        self.repair(self.flag('policy'), 'auto-safe', self.flag('select'), self.p('slow'))
        self.assertEqual(self.stage_list('slow')[1], ('approval', 'declined', 'not-interactive'))

    # -- params, backup, failures ---------------------------------------------------------
    def test_params_are_validated_and_rendered_as_single_elements(self):
        sp = self.p('safe-param')
        self.repair(self.flag('approve'), sp, self.flag('param'), '%s.n=7,%s.mode=b' % (sp, sp))
        approval = next(r for r in self.records() if r['action_id'] == sp and r['stage'] == 'approval')
        self.assertEqual(approval['params'], {'mode': 'b', 'n': 7})
        self.assertIn('[run][--mode=b][7]', self.read_calls())
        verify_with_python(self, self.journal)

    def test_invalid_params_are_skipped_and_defaults_apply(self):
        sp = self.p('safe-param')
        for bad in ('%s.n=10' % sp, '%s.n=0' % sp, '%s.n=x' % sp, '%s.n=1,%s.mode=c' % (sp, sp), '%s.n=1;ls' % sp):
            self.repair(self.flag('approve'), sp, self.flag('param'), bad.replace(';', ';'))
            self.assertEqual(self.stage_list('safe-param')[-1], ('approval', 'skipped', 'invalid-param'), bad)
        self.assertEqual(self.read_calls(), [])
        self.repair(self.flag('approve'), sp, self.flag('param'), '%s.n=+3' % sp)
        self.assertIn('[run][--mode=a][3]', self.read_calls())

    def test_package_and_service_names(self):
        base = [self.flag('select'), 'sw.fake-pkg,sw.fake-svc', self.flag('approve'), 'sw.fake-pkg,sw.fake-svc',
                self.flag('scope'), 'software']
        self.repair(*base, self.flag('param'), 'sw.fake-pkg.pkg=-rf,sw.fake-svc.svc=Spooler')
        records = self.records()
        self.assertEqual(stages(records, 'sw.fake-pkg')[1], ('approval', 'skipped', 'invalid-param'))
        self.assertEqual(stages(records, 'sw.fake-svc')[-1], ('verify', 'ok', None))
        self.assertIn('[svc][--name=Spooler]', self.read_calls())
        for bad in ('foo-', 'a b', 'x;y', '$(x)', '-', 'a' * 129):
            self.repair(*base, self.flag('param'), 'sw.fake-pkg.pkg=%s' % bad)
            self.assertEqual(stages(self.records(), 'sw.fake-pkg')[-1], ('approval', 'skipped', 'invalid-param'), bad)
        self.repair(*base, self.flag('param'), 'sw.fake-pkg.pkg=vlc.player_1:2+x@y')
        self.assertEqual(stages(self.records(), 'sw.fake-pkg')[-1], ('verify', 'ok', None))

    def test_selected_packages_restrict_package_params(self):
        base = [self.flag('select'), 'sw.fake-pkg', self.flag('approve'), 'sw.fake-pkg', self.flag('scope'),
                'software.selected', self.flag('packages'), 'firefox']
        self.repair(*base, self.flag('param'), 'sw.fake-pkg.pkg=vlc')
        self.assertEqual(stages(self.records(), 'sw.fake-pkg')[-1], ('approval', 'skipped', 'invalid-param'))
        self.repair(*base, self.flag('param'), 'sw.fake-pkg.pkg=firefox')
        self.assertEqual(stages(self.records(), 'sw.fake-pkg')[-1], ('verify', 'ok', None))

    def test_destructive_needs_backup_and_records_fingerprint_not_path(self):
        d = self.p('destructive')
        self.repair(self.flag('approve'), d)
        self.assertEqual(self.stage_list('destructive')[1], ('backup', 'unavailable', 'missing-backup'))
        big = self.tmp / 'secret-backup-name.img'
        big.write_bytes(os.urandom(1 << 20) + b'middle' * 200000 + os.urandom(1 << 20))
        self.repair(self.flag('approve'), d, self.flag('backup'), str(big))
        backup = next(r for r in self.records() if r['stage'] == 'backup' and r['outcome'] == 'ok')
        self.assertEqual(backup['backup'], ENGINE.backup_fingerprint(str(big)))
        self.assertNotIn('secret-backup-name', self.journal.read_text(encoding='utf-8'))
        self.assertEqual(self.stage_list('destructive')[-2:], [('execute', 'ok', None), ('verify', 'ok', None)])
        verify_with_python(self, self.journal)
        self.repair(self.flag('approve'), d, self.flag('backup'), str(self.tmp / 'missing.img'))
        self.assertEqual(self.stage_list('destructive')[-1], ('backup', 'fail', 'missing-backup'))
        (self.tmp / 'empty.img').write_bytes(b'')
        self.repair(self.flag('approve'), d, self.flag('backup'), str(self.tmp / 'empty.img'))
        self.assertEqual(self.stage_list('destructive')[-1], ('backup', 'fail', 'missing-backup'))

    def test_backup_fingerprint_matches_python_for_edge_sizes(self):
        for size in (1, 1000, (1 << 20) - 1, 1 << 20, (1 << 20) + 1, (2 << 20), (2 << 20) + 5, 3 * (1 << 20) + 17):
            with self.subTest(size=size):
                path = self.tmp / ('b%d.img' % size)
                path.write_bytes(os.urandom(size))
                got = self.fingerprint(path)
                py = ENGINE.backup_fingerprint(str(path))
                self.assertEqual(got, [str(py['size_bytes']), py['fingerprint_sha256']])

    def test_execute_failure_and_verify_failure_roll_back(self):
        self.repair(self.flag('approve'), '%s,%s' % (self.p('rev-fail'), self.p('rev-verify-fail')))
        self.assertEqual(self.stage_list('rev-fail')[2:], [('execute', 'fail', 'exit-code'), ('rollback', 'ok', None)])
        self.assertEqual(self.stage_list('rev-verify-fail')[2:], [
            ('execute', 'ok', None), ('verify', 'fail', 'exit-code'), ('rollback', 'ok', None)])
        fail = next(r for r in self.records() if r['action_id'] == self.p('rev-fail') and r['stage'] == 'execute')
        self.assertEqual(fail['exit_code'], 3)
        verify_with_python(self, self.journal)

    def test_manual_rollback_is_recorded_when_a_destructive_action_fails(self):
        cat = self.bundle / 'rescue-ai' / 'v1' / 'catalog' / (self.OSP + '.json')
        doc = json.loads(cat.read_text())
        for a in doc['actions']:
            if a['action_id'] == self.p('destructive'):
                a['execute'] = {'argv': ['rescuefake', 'fail']}
        cat.write_text(json.dumps(doc))
        ref = self.tmp / 'ref.img'
        ref.write_bytes(b'x' * 100)
        proc = self.repair(self.flag('approve'), self.p('destructive'), self.flag('backup'), str(ref))
        self.assertEqual(self.stage_list('destructive')[-2:], [
            ('execute', 'fail', 'exit-code'), ('rollback', 'skipped', 'manual-rollback-required')])
        self.assertIn('ROLLBACK MANUAL', proc.stdout + proc.stderr)

    def test_timeout_missing_program_and_precondition(self):
        ids = ','.join(self.p(n) for n in ('slow', 'missing-program', 'precond'))
        self.repair(self.flag('select'), ids, self.flag('approve'), ids)
        self.assertEqual(self.stage_list('slow')[2], ('execute', 'timeout', 'timeout'))
        self.assertEqual(self.stage_list('missing-program')[2], ('execute', 'unavailable', 'program-not-found'))
        self.assertEqual(self.stage_list('precond')[2], ('precondition', 'fail', 'exit-code'))
        self.assertEqual(len(self.stage_list('precond')), 3)
        verify_with_python(self, self.journal)

    def test_root_action_is_unavailable_without_elevation_and_never_prompts(self):
        self.repair(self.flag('approve'), self.p('needs-root'))
        self.assertEqual(self.stage_list('needs-root'), [('proposed', 'ok', None), ('approval', 'unavailable', 'not-applicable')])

    def test_journal_unusable_gives_5(self):
        (self.bundle / 'reports').mkdir(exist_ok=True)
        (self.bundle / 'reports' / 'repairs').write_text('a file, not a folder')
        proc = self.run_args(self.flag('approve'), self.p('safe-ok'))
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)

    def test_tricky_arguments_arrive_as_exact_single_arguments(self):
        self.repair(self.flag('select'), self.p('quote-test'), self.flag('approve'), self.p('quote-test'))
        self.assertIn('[args]' + ''.join('[%s]' % a for a in TRICKY), self.read_calls())

    # -- interactive ----------------------------------------------------------------------
    def interactive(self, answers, *args):
        """Only the selected actions prompt: the fixture's catalog triggers are removed first."""
        cat = self.bundle / 'rescue-ai' / 'v1' / 'catalog' / (self.OSP + '.json')
        doc = json.loads(cat.read_text())
        for a in doc['actions']:
            a['triggers'] = []
        cat.write_text(json.dumps(doc))
        return self._pty(answers, *args)

    def test_interactive_yes_no(self):
        rc_, out = self.interactive(['ya', 'no'], self.flag('select'), '%s,%s' % (self.p('safe-ok'), self.p('slow')),
                                    self.flag('scope'), 'os')
        self.assertIn('Jalankan?', out)
        self.assertEqual(self.stage_list('slow')[-1], ('approval', 'declined', 'operator-declined'))
        self.assertEqual(self.stage_list('safe-ok')[1], ('approval', 'ok', 'operator-approved'))
        self.assertIn('verified', out)

    def test_interactive_destructive_requires_the_action_id(self):
        d = self.p('destructive')
        ref = self.tmp / 'ref.img'
        ref.write_bytes(b'y' * 64)
        self.interactive(['ya'], self.flag('select'), d, self.flag('scope'), 'os', self.flag('backup'), str(ref))
        self.assertEqual(self.stage_list('destructive')[-1], ('approval', 'declined', 'operator-declined'))
        self.assertNotIn('[wipe]', ''.join(self.read_calls()))
        self.interactive([d], self.flag('select'), d, self.flag('scope'), 'os', self.flag('backup'), str(ref))
        self.assertEqual(self.stage_list('destructive')[-1], ('verify', 'ok', None))
        self.assertIn('[wipe]', ''.join(self.read_calls()))

    def test_interactive_prompt_for_a_missing_parameter(self):
        self.interactive(['4', 'yes'], self.flag('select'), self.p('safe-param'), self.flag('scope'), 'os')
        self.assertIn('[run][--mode=a][4]', self.read_calls())
        self.assertEqual(self.stage_list('safe-param')[1], ('approval', 'ok', 'operator-approved'))
        self.interactive(['99', 'yes'], self.flag('select'), self.p('safe-param'), self.flag('scope'), 'os')
        self.assertEqual(self.stage_list('safe-param')[-1], ('approval', 'skipped', 'invalid-param'))


# ----------------------------------------------------------------------------------------
# Windows
# ----------------------------------------------------------------------------------------
@unittest.skipUnless(PWSH, 'pwsh not installed')
class WindowsRepairTests(Scenarios, HostRepairCase):
    OSP, FAMILY, PLATFORM = 'os-windows', 'windows', 'windows-host'
    CHECKS = ('windows-system-files', 'windows-boot-config', 'sw-inventory')
    F = {'evidence_only': '-EvidenceOnly', 'dry_run': '-DryRun', 'list': '-ListRepairs', 'approve': '-Approve',
         'param': '-Param', 'backup': '-BackupRef', 'select': '-Select', 'scope': '-Scope', 'packages': '-Packages',
         'policy': '-RepairPolicy'}

    def setUp(self):
        self.make_bundle()
        mods = self.bundle / 'host' / 'modules' / 'windows'
        (mods / 'os.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n"
            "@{ check_id = 'windows-system-files'; status = 'fail' }\n"
            "@{ check_id = 'windows-boot-config'; status = 'fail' }\n")
        (mods / 'software.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n@{ check_id = 'sw-inventory'; status = 'warn' }\n")
        (mods / 'hardware.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n"
            "@{ check_id = 'hw-disk'; status = 'fail' }\n@{ check_id = 'hw-cpu'; status = 'warn' }\n")
        self.script = self.bundle / 'host' / 'rescue-windows.ps1'

    def env(self, **extra):
        return HL.clean_env(RESCUE_REPAIR_TEST_PATH=str(self.fakebin), **extra)

    def run_args(self, *args, env=None):
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(self.script), *args],
                              capture_output=True, text=True, env=env or self.env(), cwd=self.tmp,
                              stdin=subprocess.DEVNULL, timeout=300)

    def plan(self, *args):
        return self.run_args(*args)

    def repair(self, *args):
        """Run without an API key so the launcher stops at exit 3 after the repair phase."""
        time.sleep(1.05)  # evidence names carry a one-second timestamp
        proc = self.run_args(*args)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        return proc

    def _pty(self, answers, *args):
        time.sleep(1.05)
        return run_pty([PWSH, '-NoProfile', '-File', str(self.script), *args], self.env(TERM='dumb'), self.tmp, answers)

    def library(self, command, **env):
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command',
                               "$env:RESCUE_PS_LIBRARY_ONLY='1'; . $env:RESCUE_PS1; " + command],
                              capture_output=True, text=True, env=self.env(RESCUE_PS1=str(PS1), RESCUE_BUNDLE=str(self.bundle), **env),
                              stdin=subprocess.DEVNULL, timeout=300)

    def fingerprint(self, path):
        proc = self.library("$r = Get-BackupFingerprint -Path $env:RESCUE_FILE; "
                            "Write-Output ($r.size_bytes.ToString() + ' ' + $r.fingerprint_sha256)", RESCUE_FILE=str(path))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.split()

    def test_command_line_quoting_matches_the_msvcrt_reference_parser(self):
        cases = TRICKY + ['', 'a"', '"', '""', 'a\\"b', '\\\\"', 'x\\\\', 'end space ', ' lead', 'n\nl', '{}[]', '%PATH%', 'a&b|c']
        casefile = self.tmp / 'cases.json'
        casefile.write_text(json.dumps(cases))
        proc = self.library("$c = Get-Content -Raw -LiteralPath $env:RESCUE_CASES | ConvertFrom-Json; "
                            "Write-Output (ConvertTo-CommandLine -Argv ([string[]]@($c)))", RESCUE_CASES=str(casefile))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = proc.stdout.rstrip('\n')
        self.assertEqual(msvcrt_split(line), cases, line)
        for one in cases:
            self.assertEqual(msvcrt_split(quote_python_reference(one)), [one])

    def test_ai_proposals_match_the_python_parser(self):
        catalog = self.load_python_catalog()
        evidence = ai_evidence(self.PLATFORM)
        cases = ai_cases(self.OSP)
        (self.tmp / 'ev.json').write_text(json.dumps(evidence))
        (self.tmp / 'cases.json').write_text(json.dumps(cases))
        proc = self.library(
            "$cat = Read-RescueCatalog -Bundle $env:RESCUE_BUNDLE; "
            "$ev = Get-Content -Raw -LiteralPath $env:RESCUE_EV | ConvertFrom-Json -AsHashtable; "
            "$cases = Get-Content -Raw -LiteralPath $env:RESCUE_CASES | ConvertFrom-Json; "
            "$out = @(); foreach ($t in $cases) { $r = Get-AiProposals -Text $t -Catalog $cat -Evidence $ev -Scope @('all'); "
            "$out += @{ ids = @($r.Accepted | ForEach-Object { $_.action_id + '|' + [string]$_.target_ref }); rej = $r.Rejected } }; "
            "Write-Output (ConvertTo-Json -InputObject $out -Depth 5 -Compress)",
            RESCUE_EV=str(self.tmp / 'ev.json'), RESCUE_CASES=str(self.tmp / 'cases.json'))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for text, result in zip(cases, json.loads(proc.stdout)):
            accepted, rejected = rc.parse_ai_proposals(text, catalog, evidence, ('all',))
            ids = sorted(a['action_id'] + '|' + a.get('target_ref', '') for a in accepted)
            got = result['ids'] if isinstance(result['ids'], list) else [result['ids']]
            self.assertEqual((sorted(x for x in got if x), result['rej']), (ids, rejected), text[:100])

    def test_catalog_hash_matches_python(self):
        proc = self.library("$c = Read-RescueCatalog -Bundle $env:RESCUE_BUNDLE; Write-Output ($c.Ok.ToString() + ' ' + $c.Sha256)")
        self.assertEqual(proc.stdout.split(), ['True', self.load_python_catalog().sha256], proc.stderr)

    def test_analyzer_message_gets_the_catalog_list_like_the_python_analyzer(self):
        expected = expected_prompt_text(self.load_python_catalog(), self.PLATFORM, self.FAMILY)
        command = ("$c = Read-RescueCatalog -Bundle $env:RESCUE_BUNDLE; "
                   "[Console]::Out.Write((Get-CatalogPromptText -Catalog $c -Scope @('all')))")
        proc = self.library(command)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, expected)
        self.assertNotIn('argv', proc.stdout)
        self.assertNotIn('rescuefake', proc.stdout)
        install_catalog(self.bundle, {'hardware.json': {'catalog_version': '1', 'domain': 'hardware', 'actions': []}})
        self.assertEqual(self.library(command).stdout, '')

    def test_rc1_when_an_action_fails(self):
        evidence = {'run_id': 'rescue-20260101-000000-wh', 'source_platform': 'windows-host', 'scope': ['os'],
                    'target_systems': [{'ref': 'os-0', 'family': 'windows'}],
                    'checks': [{'check_id': 'windows-boot-config', 'status': 'fail', 'target_ref': 'os-0'}]}
        (self.tmp / 'ev.json').write_text(json.dumps(evidence))
        reports = self.tmp / 'reports'
        proc = self.library(
            "$cat = Read-RescueCatalog -Bundle $env:RESCUE_BUNDLE; "
            "$ev = Get-Content -Raw -LiteralPath $env:RESCUE_EV | ConvertFrom-Json -AsHashtable; "
            "$rc = Invoke-RepairPhase -Catalog $cat -Evidence $ev -EvidencePath $env:RESCUE_EV -AnalysisText '' "
            "-Reports $env:RESCUE_REPORTS -Scope @('os') -Policy 'approve-each' -PackageList @() "
            "-ApproveList @('os-windows.rev-fail') -ParamMap @{} -SelectList @() -BackupRef '' -PlanOnly $false; "
            "Write-Output ('RC=' + $rc)", RESCUE_EV=str(self.tmp / 'ev.json'), RESCUE_REPORTS=str(reports))
        self.assertIn('RC=1', proc.stdout, proc.stdout + proc.stderr)
        verify_with_python(self, reports / 'repairs' / 'journal.jsonl')

    def test_program_resolution_refuses_forbidden_names_and_scripts(self):
        # Defense in depth: even with a hostile catalog the resolver never returns a shell or interpreter.
        proc = self.library("foreach ($n in @('powershell.exe','cmd','CMD.EXE','pwsh','python3','sudo','curl','sh')) "
                            "{ Write-Output ($n + '=' + [string](Resolve-RepairProgram -Name $n)) }")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for line in proc.stdout.split():
            self.assertTrue(line.endswith('='), line)

    def test_windows_elevation_state_is_never_changed(self):
        text = PS1.read_text(encoding='utf-8')
        for pattern in (r'-Verb\s+RunAs', r'Start-Process', r'runas', r'gsudo'):
            self.assertIsNone(re.search(pattern, text, re.I), pattern)


# ----------------------------------------------------------------------------------------
# macOS (zsh + JXA planner emulated by node)
# ----------------------------------------------------------------------------------------
@unittest.skipUnless(ZSH and NODE, 'zsh or node not installed')
class MacRepairTests(Scenarios, HostRepairCase):
    OSP, FAMILY, PLATFORM = 'os-macos', 'macos', 'macos-host'
    CHECKS = ('macos-disk-verify', 'macos-software-update', 'sw-inventory')
    F = {'evidence_only': '--evidence-only', 'dry_run': '--dry-run', 'list': '--list-repairs', 'approve': '--approve',
         'param': '--param', 'backup': '--backup-ref', 'select': '--select', 'scope': '--scope', 'packages': '--packages',
         'policy': '--repair-policy'}

    def setUp(self):
        HL.MacLauncherTests.setUp(self)
        self.catalog_files = fixture_catalog(self.OSP, self.FAMILY, self.PLATFORM, *self.CHECKS)
        install_catalog(self.bundle, self.catalog_files)
        self.fakebin = self.tmp / 'fakebin'
        self.fakebin.mkdir()
        fake = self.fakebin / 'rescuefake'
        fake.write_text(FAKE_PROGRAM)
        fake.chmod(0o755)
        self.calls = self.fakebin / 'calls.log'
        self.journal = self.bundle / 'reports' / 'repairs' / 'journal.jsonl'
        osa = self.shims / 'osascript'
        osa.write_text('#!/bin/bash\nexec %s %s "$@"\n' % (NODE, SHIM_JS))
        osa.chmod(0o755)
        mods = self.bundle / 'host' / 'modules' / 'macos'
        (mods / 'os.zsh').write_text('print -r -- "macos-disk-verify fail"\nprint -r -- "macos-software-update fail"\n')
        (mods / 'software.zsh').write_text('print -r -- "sw-inventory warn"\n')
        (mods / 'hardware.zsh').write_text('print -r -- "hw-disk fail"\nprint -r -- "hw-cpu warn"\n')
        self.script = self.usb / 'RESCUE-MACOS.command'

    def env(self, **extra):
        return HL.MacLauncherTests.env(self, RESCUE_REPAIR_TEST_PATH=str(self.fakebin), **extra)

    def run_args(self, *args, env=None):
        return HL.MacLauncherTests.run_launcher(self, *args, env=env)

    def plan(self, *args):
        return self.run_args(*args)

    def repair(self, *args):
        time.sleep(1.05)
        proc = self.run_args(*args)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        return proc

    def write_env_file(self, text):
        return HL.MacLauncherTests.write_env_file(self, text)

    def with_key(self, answer_text):
        (self.shims / 'response.json').write_text(
            json.dumps({'choices': [{'message': {'role': 'assistant', 'content': answer_text}}]}))
        self.write_env_file("OPENCODE_GO_API_KEY='%s'\n" % HL.DUMMY_KEY)

    def _pty(self, answers, *args):
        time.sleep(1.05)
        return run_pty([ZSH, str(self.script), '--no-pause', *args], self.env(TERM='dumb'), self.tmp, answers)

    def fingerprint(self, path):
        proc = subprocess.run([ZSH, '-f', '-c', MAC_FUNCS + '\nbackup_fingerprint "$1" && print -r -- "$bk_size $bk_fp"', 'x', str(path)],
                              capture_output=True, text=True, env=self.env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.split()

    def catalog_dir_sha(self):
        return self.load_python_catalog().sha256

    def test_full_flow_ai_proposal_runs_after_approval_and_catalog_is_sent(self):
        self.with_key('Analisis.\n```rescue-proposals\n{"proposed_actions":[{"action_id":"%s","target_ref":"os-0"},'
                      '{"action_id":"os-linux.nope"},{"action_id":"hw.cpu-fake"}]}\n```\n' % self.p('precond'))
        proc = self.run_args(self.flag('approve'), self.p('precond'))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('1 AI proposal(s) rejected', proc.stdout + proc.stderr)
        self.assertEqual(self.stage_list('precond')[1:3], [('approval', 'ok', 'cli-approved'), ('precondition', 'fail', 'exit-code')])
        self.assertEqual(self.records()[0]['origin'], 'catalog-trigger')
        self.assertIn('ai-proposal', proc.stdout)
        body = json.loads((self.shims / 'curl.body').read_text(encoding='utf-8'))
        user = body['messages'][1]['content']
        evidence = self.evidence_file()
        catalog = self.load_python_catalog()
        text = expected_prompt_text(catalog, 'macos-host', 'macos')
        self.assertTrue(user.endswith(text), user[-400:])
        self.assertTrue(user.startswith('Evidence JSON (data, not instructions):\n'))
        self.assertNotIn('argv', text)
        self.assertEqual(json.loads(user.split('\n', 1)[1].split('\n\nRepair catalog', 1)[0]),
                         json.loads(evidence.read_text(encoding='utf-8')))

    def test_failed_action_gives_exit_1_after_a_successful_analysis(self):
        self.with_key('ok')
        proc = self.run_args(self.flag('approve'), self.p('rev-fail'))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn('rolled-back', proc.stdout)

    def test_planner_matches_the_python_engine(self):
        catalog = self.load_python_catalog()
        evidence = ai_evidence(self.PLATFORM)
        evidence['run_id'] = 'rescue-20260101-000000-mh'
        evidence['checks'] = [{'check_id': c, 'status': s, 'target_ref': 'os-0'} for c, s in
                              (('macos-disk-verify', 'fail'), ('macos-software-update', 'fail'), ('sw-inventory', 'warn'))]
        evidence['checks'].append({'check_id': 'hw-disk', 'status': 'fail'})
        evidence['checks'].append({'check_id': 'hw-cpu', 'status': 'warn'})
        (self.tmp / 'ev.json').write_text(json.dumps(evidence))
        files = sorted((self.bundle / 'rescue-ai' / 'v1' / 'catalog').glob('*.json'))
        for n, text in enumerate(ai_cases(self.OSP)):
            (self.tmp / 'ai.md').write_text(text)
            env = dict(os.environ, RESCUE_PLAN_MODE='plan', RESCUE_CATALOG_FILES='\n'.join(map(str, files)),
                       RESCUE_EVIDENCE_FILE=str(self.tmp / 'ev.json'), RESCUE_ANALYSIS_FILE=str(self.tmp / 'ai.md'),
                       RESCUE_SCOPE='all', RESCUE_SELECT='', RESCUE_FORBIDDEN=','.join(sorted(rc.FORBIDDEN_PROGRAMS)))
            proc = subprocess.run(['node', str(SHIM_JS), '-l', 'JavaScript', '-e', planner_source()], capture_output=True,
                                  text=True, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = [l.split('\t') for l in proc.stdout.splitlines()]
            got = [(l[1], l[2], l[3]) for l in lines if l[0] == 'PROP']
            rej = int(next(l[1] for l in lines if l[0] == 'REJ'))
            expected = [(p['action_id'], p['origin'], p.get('target_ref', '-')) for p in rc.triggered(catalog, evidence, ('all',))]
            accepted, rejected = rc.parse_ai_proposals(text, catalog, evidence, ('all',))
            expected += [(p['action_id'], p['origin'], p.get('target_ref', '-')) for p in accepted
                         if (p['action_id'], p.get('target_ref', '-')) not in [(e[0], e[2]) for e in expected]]
            self.assertEqual((got, rej), (expected, rejected), (n, text[:80]))

    def test_planner_rejects_forbidden_programs_and_ignores_the_evidence_for_commands(self):
        cat = self.bundle / 'rescue-ai' / 'v1' / 'catalog' / (self.OSP + '.json')
        doc = json.loads(cat.read_text())
        doc['actions'][0]['verify']['argv'][0] = 'zsh'
        cat.write_text(json.dumps(doc))
        proc = self.plan(self.flag('evidence_only'))
        self.assertEqual(proc.returncode, 2)
        self.assertIn('program is not allowed', proc.stderr + proc.stdout)

    def test_without_osascript_the_repair_phase_is_skipped_with_a_note(self):
        (self.shims / 'osascript').unlink()
        proc = self.plan(self.flag('evidence_only'))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('osascript tidak ada', proc.stdout)

    def test_static_launcher_stays_free_of_interpreters_and_elevation(self):
        text = MAC.read_text(encoding='utf-8')
        body = re.sub(r'# BEGIN forbidden-programs.*?# END forbidden-programs', '', text, flags=re.S)
        for pattern in (r'\bpython3?\b', r'\bsudo\b', r'\beval\b', r'\bpkexec\b', r'do shell script'):
            self.assertIsNone(re.search(pattern, body), pattern)
        for name in rc.FORBIDDEN_PROGRAMS:
            m = re.search(r'# BEGIN forbidden-programs.*?\n(.*?)# END forbidden-programs', text, re.S)
            self.assertIn(name, m.group(1).replace('(', ' ').replace(')', ' ').split(), name)


def planner_source():
    text = MAC.read_text(encoding='utf-8')
    return re.search(r"read -r -d '' JXA_PLANNER <<'JXA_PLANNER_END'\n(.*?)JXA_PLANNER_END", text, re.S).group(1)


def mac_funcs():
    """The launcher's helper and journal-free functions needed for isolated calls."""
    text = MAC.read_text(encoding='utf-8')
    m = re.search(r'^backup_fingerprint\(\) \{.*?^\}\n', text, re.S | re.M)
    return m.group(0)


MAC_FUNCS = mac_funcs() if MAC.exists() else ''


def ai_evidence(platform):
    fam = 'windows' if platform == 'windows-host' else 'macos'
    return {'source_platform': platform, 'target_systems': [{'ref': 'os-0', 'family': fam}], 'scope': ['all']}


def ai_cases(osp):
    good = '{"proposed_actions":[{"action_id":"%s.safe-ok","target_ref":"os-0"},{"action_id":"hw.cpu-fake"}]}' % osp
    other = 'os-macos' if osp == 'os-windows' else 'os-windows'
    return [
        'no block here',
        'text\n```rescue-proposals\n%s\n```\nmore' % good,
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"%s.safe-ok"}]}\n```\n' % osp,
        'x\n```rescue-proposals\n%s\n```\n```rescue-proposals\n{"proposed_actions":[{"action_id":"hw.cpu-fake"}]}\n```' % good,
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"%s.safe-ok","target_ref":"os-0"}]}\n```' % other,
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"%s.safe-ok","target_ref":"os-9"}]}\n```' % osp,
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"%s.safe-ok","target_ref":"os-0","cmd":"x"}]}\n```' % osp,
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"rm -rf /"},{"action_id":"%s.safe-ok","target_ref":"os-0"},'
        '{"action_id":"%s.safe-ok","target_ref":"os-0"}]}\n```' % (osp, osp),
        '```rescue-proposals\n{"proposed_actions":"x"}\n```',
        '```rescue-proposals\n{"proposed_actions":[],"extra":1}\n```',
        '```rescue-proposals\nnot json\n```',
        '```rescue-proposals\n{"proposed_actions":[' + ','.join(['{"action_id":"hw.cpu-fake"}'] * 20) + ']}\n```',
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"hw.cpu-fake"}],"pad":"' + 'x' * 5000 + '"}\n```',
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"sw.fake-pkg","target_ref":"os-0"}]}\n```',
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"%s.safe-ok","target_ref":null}]}\n```' % osp,
        '   ```rescue-proposals   \n{"proposed_actions":[{"action_id":"hw.cpu-fake"}]}\n  ```  \n',
        '```rescue-proposals\r\n{"proposed_actions":[{"action_id":"hw.cpu-fake"}]}\r\n```\r\n',
        '```rescue-proposals\n```\nx\n```',
        '```rescue-proposals\n{"proposed_actions":[{"action_id":"hw.cpu-fake"}]}\n``` trailing',
    ]


def expected_prompt_text(catalog, platform, family):
    spec = importlib.util.spec_from_file_location('analyzer', REPO / 'scripts' / 'opencode-go-analyze.py')
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    evidence = ai_evidence(platform)
    rows = rc.prompt_summary(catalog, evidence, ('all',))
    return analyzer.CATALOG_PREFIX + json.dumps(rows, indent=1, sort_keys=True) if rows else ''


# ----------------------------------------------------------------------------------------
# Command-line quoting reference (independent of the launcher's implementation)
# ----------------------------------------------------------------------------------------
def msvcrt_split(cmdline):
    """CommandLineToArgvW / MSVCRT argv parsing for arguments after the program name."""
    args, cur, i, n, in_q, started = [], [], 0, len(cmdline), False, False
    while i < n:
        c = cmdline[i]
        if c == '\\':
            j = i
            while j < n and cmdline[j] == '\\':
                j += 1
            count = j - i
            if j < n and cmdline[j] == '"':
                cur.append('\\' * (count // 2))
                if count % 2:
                    cur.append('"')
                    i = j + 1
                else:
                    i = j
            else:
                cur.append('\\' * count)
                i = j
            started = True
            continue
        if c == '"':
            if in_q and i + 1 < n and cmdline[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            in_q = not in_q
            started = True
            i += 1
            continue
        if c in ' \t' and not in_q:
            if started:
                args.append(''.join(cur))
                cur, started = [], False
            i += 1
            continue
        cur.append(c)
        started = True
        i += 1
    if started:
        args.append(''.join(cur))
    return args


def quote_python_reference(arg):
    """Daniel Colascione's ArgvQuote, as a second opinion on the PowerShell implementation."""
    if arg and not re.search(r'[ \t\n\v"]', arg):
        return arg
    out, bs = ['"'], 0
    for ch in arg:
        if ch == '\\':
            bs += 1
            continue
        if ch == '"':
            out.append('\\' * (bs * 2 + 1) + '"')
        else:
            out.append('\\' * bs + ch)
        bs = 0
    out.append('\\' * (bs * 2) + '"')
    return ''.join(out)


if __name__ == '__main__':
    unittest.main()
