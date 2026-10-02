"""Offline tests for the repair engine UX of ahliweb/linux-mint-xfce-rescue-ai#70.

Root precheck (needs-root), the non-root ClamAV update for linux-host, the operator device picker, batch approval of
safe actions, the [i/N] header, --select under auto-safe, and the cross-engine parity of the new reason codes and
prompts. No root, no real disks, no network: programs are fakes in a temporary directory reached only through
RESCUE_REPAIR_TEST_PATH.
"""
import copy
import importlib.util
import json
import os
import pathlib
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
FIXTURES = ROOT / 'rescue-ai/v1/fixtures'
LIVE_12 = FIXTURES / 'valid-live-scoped-1.2.json'
REPAIR = SCRIPTS / 'rescue-repair.py'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
import run_report as rr  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine_mod = load('rescue_repair_ux', REPAIR)
CATALOG = rc.load()


def action(**over):
    base = {
        'action_id': 'hw.test-safe', 'title': 'Test safe action', 'title_id': 'Tindakan uji aman',
        'scope': 'hardware.disk', 'platforms': ['live-linux', 'linux-host'], 'risk': 'safe',
        'triggers': [{'check_id': 'smart-health', 'status': ['warn', 'fail']}],
        'execute': {'argv': ['rescue-test-fix', 'safe']},
        'verify': {'argv': ['rescue-test-check', 'safe']},
        'rollback': {'kind': 'none'}, 'backup': {'required': False},
        'doc': 'docs/repair-framework.md',
    }
    base.update(over)
    return base


def write_catalog(directory, domain, actions):
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (domain + '.json')).write_text(json.dumps(
        {'catalog_version': '1', 'domain': domain, 'actions': actions}), encoding='utf-8')


def catalog_errors(domain, act):
    with tempfile.TemporaryDirectory() as tmp:
        write_catalog(tmp, domain, [act])
        try:
            rc.load(tmp)
        except rc.CatalogError as exc:
            return exc.problems
    return []


# ------------------------------------------------------------------------ catalog

class CatalogTests(unittest.TestCase):
    def test_clamav_update_is_live_only_and_there_is_no_host_variant(self):
        root_action = CATALOG.get('mw.clamav-update-signatures')
        self.assertEqual(root_action['platforms'], ['live-linux'])
        self.assertTrue(root_action['requires_root'])
        self.assertIsNone(CATALOG.get('mw.clamav-update-signatures-user'))
        self.assertFalse((rc.ROOT / 'config' / 'freshclam-user.conf').exists())
        # on a Linux host the stale-signatures trigger proposes nothing: a host never gets an update that cannot work
        host_ev = json.loads(LIVE_12.read_text())
        host_ev['source_platform'] = 'linux-host'
        host_ev['checks'].append({'check_id': 'malware-signatures', 'status': 'warn', 'source': 'host-allowlist',
                                  'observed_at': '2026-10-01T08:00:00Z'})
        self.assertEqual([p for p in rc.triggered(CATALOG, host_ev, ('all',)) if p['action_id'].startswith('mw.clamav')], [])
        live_ev = json.loads(LIVE_12.read_text())
        live_ev['checks'].append({'check_id': 'malware-signatures', 'status': 'warn', 'source': 'collector-allowlist',
                                  'observed_at': '2026-09-30T08:00:00Z'})
        self.assertEqual([p['action_id'] for p in rc.triggered(CATALOG, live_ev, ('all',)) if p['action_id'].startswith('mw.clamav')],
                         ['mw.clamav-update-signatures'])

    def test_bundle_config_no_longer_exists(self):
        self.assertTrue(catalog_errors('malware', action(action_id='mw.test-x', scope='malware', platforms=['linux-host'],
                                                         params=[{'name': 'c', 'type': 'bundle_config', 'values': ['x']}],
                                                         execute={'argv': ['freshclam', '--config-file={c}']})))

    def test_new_reasons_are_everywhere(self):
        journal = json.loads((ROOT / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        self.assertEqual(list(rr.REASONS), journal['properties']['reason']['enum'])
        self.assertEqual(list(rr.REASONS)[-2:], ['needs-root', 'operator-approved-batch'])
        schema = json.loads((ROOT / 'rescue-ai/v1/run-report.schema.json').read_text())
        found = []

        def walk(node):
            if isinstance(node, dict):
                if 'needs-root' in (node.get('enum') or []):
                    found.append(node['enum'])
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(schema)
        self.assertEqual(len(found), 2)
        for enum in found:
            self.assertEqual(enum, list(rr.REASONS))


# ------------------------------------------------------------------------- state dir

class StateRootTests(unittest.TestCase):
    def args(self, **kw):
        return types.SimpleNamespace(state_dir=kw.get('state_dir'), journal=kw.get('journal'))

    def test_state_dir_wins(self):
        self.assertEqual(engine_mod.state_root(self.args(state_dir='/s', journal='/x/repairs/journal.jsonl')), '/s')

    def test_host_mode_uses_the_reports_directory_above_repairs(self):
        j = '/media/u/rescue-omes/reports/repairs/journal.jsonl'
        self.assertEqual(engine_mod.state_root(self.args(journal=j)), '/media/u/rescue-omes/reports')

    def test_a_journal_outside_a_repairs_directory_gives_no_state(self):
        self.assertIsNone(engine_mod.state_root(self.args(journal='/tmp/journal.jsonl')))
        self.assertIsNone(engine_mod.state_root(self.args()))


# ------------------------------------------------------------------------- harness

class EngineBase(unittest.TestCase):
    """Fake programs, a throw-away catalog and the shipped catalog, a USB-shaped state directory."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='repair-ux-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.log = self.tmp / 'calls.log'
        self.usb = self.tmp / 'usb'
        self.reports = self.usb / 'rescue-omes' / 'reports'
        self.journal = self.reports / 'repairs' / 'journal.jsonl'
        self.env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(self.bin), RESCUE_REPAIR_TEST_SUDO_PROBE='1')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o755)

    def logging_tool(self, name, code=0):
        self.tool(name, 'echo "%s $*" >> "%s"\nexit %d\n' % (name, self.log, code))

    def sudo(self, usable=True):
        self.tool('sudo', 'echo "sudo $*" >> "%s"\n[ "$1" = -n ] && [ "$2" = true ] && exit %d\nshift 2\nexec "$@"\n'
                  % (self.log, 0 if usable else 1))

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def records(self):
        if not self.journal.exists():
            return []
        return [json.loads(ln) for ln in self.journal.read_text().splitlines() if ln.strip()]

    def stages(self, action_id):
        return [(r['stage'], r['outcome'], r.get('reason')) for r in self.records() if r['action_id'] == action_id]

    def run_engine(self, *args, evidence=LIVE_12, catalog=None, journal=True, env=None):
        cmd = [sys.executable, str(REPAIR), '--evidence', str(evidence)]
        if catalog:
            cmd += ['--catalog-dir', str(catalog)]
        if journal:
            cmd += ['--journal', str(self.journal)]
        cmd += [str(a) for a in args]
        return subprocess.run(cmd, capture_output=True, text=True, env=env or self.env, stdin=subprocess.DEVNULL, timeout=90)

    def pty_engine(self, answers, *args, evidence=LIVE_12, catalog=None):
        """Run on a pseudo-terminal and type one answer per prompt (a prompt ends with ': ')."""
        cmd = [sys.executable, str(REPAIR), '--evidence', str(evidence), '--journal', str(self.journal)]
        if catalog:
            cmd += ['--catalog-dir', str(catalog)]
        cmd += [str(a) for a in args]
        master, slave = pty.openpty()
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=self.env, close_fds=True)
        os.close(slave)
        out, pending, deadline = b'', list(answers), time.time() + 60
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
                if pending and out.endswith(b': '):
                    os.write(master, (pending.pop(0) + '\n').encode())
            elif proc.poll() is not None:
                break
        proc.wait(timeout=10)
        os.close(master)
        return proc.returncode, out.decode('utf-8', 'replace')

    def host_evidence(self, checks):
        ev = json.loads(LIVE_12.read_text())
        ev.pop('repair_proposals', None)
        ev.update(source_platform='linux-host', run_id='rescue-20261001-080000-ux', scope=['all'],
                  target_systems=[{'ref': 'os-0', 'family': 'linuxmint', 'release': 'Linux Mint 22', 'architecture': 'x86_64',
                                   'detection': 'host-native', 'encryption': 'none', 'access': 'host-running'}])
        ev['checks'] = [{'check_id': c, 'status': s, 'source': 'host-allowlist', 'observed_at': '2026-10-01T08:00:00Z'}
                        for c, s in checks]
        ev['evidence_manifest']['entry_count'] = len(checks)
        path = self.tmp / 'host-ev.json'
        path.write_text(json.dumps(ev))
        return path


# ----------------------------------------------------------------- needs-root precheck

@unittest.skipIf(os.geteuid() == 0, 'running as root')
class NeedsRootTests(EngineBase):
    def setUp(self):
        super().setUp()
        self.logging_tool('smartctl')
        self.logging_tool('rescue-test-fix')
        self.logging_tool('rescue-test-check')
        self.cat = self.tmp / 'catalog'
        write_catalog(self.cat, 'hardware', [
            action(action_id='hw.test-root', requires_root=True),
            action(action_id='hw.test-root-two', requires_root=True),
            action(action_id='hw.test-user')])

    def test_unusable_sudo_skips_without_prompt_or_execution(self):
        self.sudo(usable=False)
        r = self.run_engine('--approve', 'hw.test-root', '--approve', 'hw.test-root-two', '--approve', 'hw.test-user',
                            catalog=self.cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.stages('hw.test-root'), [('proposed', 'ok', None), ('approval', 'unavailable', 'needs-root')])
        self.assertEqual(self.stages('hw.test-root-two')[-1], ('approval', 'unavailable', 'needs-root'))
        self.assertEqual(self.stages('hw.test-user')[-1][:2], ('verify', 'ok'))
        self.assertEqual([c for c in self.calls() if not c.startswith('rescue-test')], ['sudo -n true'])   # probed once
        self.assertIn('perlu root / needs root', r.stdout)
        self.assertNotIn('Jalankan?', r.stdout)

    def test_missing_sudo_is_the_same(self):
        r = self.run_engine('--approve', 'hw.test-root', catalog=self.cat)
        self.assertEqual(self.stages('hw.test-root')[-1], ('approval', 'unavailable', 'needs-root'))
        self.assertEqual(self.calls(), [])
        self.assertEqual(r.returncode, 0)

    def test_usable_sudo_runs_the_action_through_sudo_n(self):
        self.sudo(usable=True)
        r = self.run_engine('--approve', 'hw.test-root', catalog=self.cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls()[0], 'sudo -n true')
        self.assertTrue(self.calls()[1].startswith('sudo -n -- '), self.calls())
        self.assertEqual(self.stages('hw.test-root')[1], ('approval', 'ok', 'cli-approved'))

    def test_detect_only_never_probes_or_changes(self):
        self.sudo(usable=False)
        self.run_engine('--policy', 'detect-only', catalog=self.cat)
        self.assertEqual(self.stages('hw.test-root')[-1], ('approval', 'skipped', 'policy-detect-only'))
        self.assertEqual([c for c in self.calls() if not c.startswith('sudo')], [])

    def test_interactive_run_does_not_prompt_for_a_root_action(self):
        self.sudo(usable=False)
        code, out = self.pty_engine(['ya', 'ya', 'ya'], '--scope', 'hardware', catalog=self.cat)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stages('hw.test-root')[-1], ('approval', 'unavailable', 'needs-root'))
        self.assertNotIn('== hw.test-root ', out)

    def test_the_catalog_keeps_the_root_variant_on_live_only(self):
        for aid in ('hw.smart-short-selftest', 'mw.clamav-update-signatures'):
            self.assertTrue(CATALOG.get(aid)['requires_root'])


class StateDirActionTests(EngineBase):
    def test_a_journal_outside_a_repairs_directory_refuses_a_state_dir_action(self):
        self.logging_tool('rescue-test-fix')
        self.logging_tool('rescue-test-check')
        cat = self.tmp / 'catalog'
        write_catalog(cat, 'malware', [action(
            action_id='mw.test-state', scope='malware', params=[{'name': 'dbdir', 'type': 'state_dir', 'values': ['clamav']}],
            execute={'argv': ['rescue-test-fix', '--db={dbdir}']}, verify={'argv': ['rescue-test-check']})])
        self.journal = self.tmp / 'elsewhere' / 'journal.jsonl'
        r = self.run_engine('--approve', 'mw.test-state', catalog=cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stages('mw.test-state')[-1], ('approval', 'unavailable', 'provider-unavailable'))
        self.journal = self.reports / 'repairs' / 'journal.jsonl'
        self.run_engine('--approve', 'mw.test-state', catalog=cat)
        self.assertEqual(self.calls()[0], 'rescue-test-fix --db=%s' % (self.reports / 'clamav'))


# --------------------------------------------------------------------- device picker

LSBLK = {'blockdevices': [
    {'path': '/dev/sda', 'type': 'disk', 'size': 500107862016, 'rm': False, 'tran': 'sata', 'model': 'Samsung SSD 860 EVO',
     'children': [{'path': '/dev/sda1', 'type': 'part', 'size': 500000000000, 'mountpoints': ['/'], 'pkname': 'sda'}]},
    {'path': '/dev/nvme0n1', 'type': 'disk', 'size': 1000204886016, 'rm': False, 'tran': 'nvme', 'model': 'WD Black SN770'},
    {'path': '/dev/sdb', 'type': 'disk', 'size': 31914983424, 'rm': True, 'tran': 'usb', 'model': 'Ventoy USB'},
    {'path': '/dev/sdc', 'type': 'disk', 'size': 15000000000, 'rm': False, 'tran': 'usb', 'model': 'Live Media',
     'children': [{'path': '/dev/sdc1', 'type': 'part', 'size': 15000000000, 'mountpoints': ['/run/live/medium']}]},
    {'path': '/dev/sr0', 'type': 'rom', 'size': 1073741312, 'rm': True, 'tran': 'sata', 'model': 'DVD'},
    {'path': '/dev/loop0', 'type': 'loop', 'size': 1000000000, 'rm': False, 'tran': None, 'model': None},
]}


class PickerTests(EngineBase):
    def make_engine(self, tree=None, answers=()):
        eng = engine_mod.Engine.__new__(engine_mod.Engine)
        eng.path = str(self.bin)
        eng.state_root = str(self.reports)
        eng.removable_ok = set()
        eng.params, eng.packages, eng.evidence = {}, None, {}
        eng.args = types.SimpleNamespace(approve=[], policy='approve-each')
        queue = list(answers)
        eng.ask = lambda prompt: queue.pop(0) if queue else ''
        self.tool('lsblk', "echo '%s'\n" % json.dumps(tree or LSBLK))
        return eng

    def device_action(self):
        return CATALOG.get('hw.smart-short-selftest')

    def test_candidates_are_internal_whole_disks_only(self):
        eng = self.make_engine()
        candidates, removable = eng.disk_candidates()
        self.assertEqual([c['path'] for c in candidates], ['/dev/sda', '/dev/nvme0n1'])
        self.assertFalse(removable)
        self.assertEqual(candidates[0]['size'], '500.1 GB')
        self.assertEqual(candidates[0]['tran'], 'sata')
        self.assertEqual(candidates[0]['model'], 'Samsung SSD 860 EVO')

    def test_the_model_is_truncated_for_the_screen(self):
        tree = copy.deepcopy(LSBLK)
        tree['blockdevices'][0]['model'] = 'M' * 80
        candidates, _ = self.make_engine(tree).disk_candidates()
        self.assertEqual(len(candidates[0]['model']), 24)

    def test_removable_disks_are_a_fallback_but_never_live_media_or_the_rescue_usb(self):
        tree = {'blockdevices': [d for d in LSBLK['blockdevices'] if d['path'] in ('/dev/sdb', '/dev/sdc', '/dev/sr0')]}
        eng = self.make_engine(tree)
        candidates, removable = eng.disk_candidates()
        self.assertTrue(removable)
        self.assertEqual([c['path'] for c in candidates], ['/dev/sdb'])
        # the disk that holds the bundle / the USB state is never offered
        tree['blockdevices'][0]['children'] = [{'path': '/dev/sdb1', 'type': 'part', 'size': 1, 'mountpoints': [str(self.usb)]}]
        eng = self.make_engine(tree)
        eng.state_root = str(self.usb / 'rescue-omes' / 'reports')
        candidates, _ = eng.disk_candidates()
        self.assertEqual(candidates, [])

    def test_a_picked_number_becomes_the_validated_value(self):
        eng = self.make_engine(answers=['2'])
        seen = []
        with mock.patch.object(engine_mod, 'block_device_eligible',
                               lambda path, allow_removable=False, keep=(): seen.append((path, allow_removable)) or True):
            values, problem = eng.resolve_params(self.device_action(), allow_prompt=True, proposal={})
        self.assertIsNone(problem)
        self.assertEqual(values, {'device': '/dev/nvme0n1'})
        self.assertEqual(seen, [('/dev/nvme0n1', False)])

    def test_a_value_outside_the_list_is_rejected(self):
        for answer in ('9', '0', '-1', '/dev/sdb', 'sdb', '1;reboot'):
            eng = self.make_engine(answers=[answer])
            with mock.patch.object(engine_mod, 'block_device_eligible', lambda *a, **k: True):
                values, problem = eng.resolve_params(self.device_action(), allow_prompt=True, proposal={})
            self.assertEqual((values, problem), (None, 'invalid-param'), answer)

    def test_enter_skips_and_a_param_wins_over_the_picker(self):
        eng = self.make_engine(answers=[''])
        self.assertEqual(eng.resolve_params(self.device_action(), True, {}), (None, 'missing-param'))
        eng = self.make_engine(answers=['1'])
        eng.params = {('hw.smart-short-selftest', 'device'): '/dev/sda'}
        with mock.patch.object(engine_mod, 'block_device_eligible', lambda *a, **k: True):
            self.assertEqual(eng.resolve_params(self.device_action(), True, {}), ({'device': '/dev/sda'}, None))

    def test_no_lsblk_means_no_choice(self):
        eng = self.make_engine()
        (self.bin / 'lsblk').unlink()
        self.assertEqual(eng.resolve_params(self.device_action(), True, {}), (None, 'missing-param'))

    @unittest.skipIf(os.geteuid() == 0, 'running as root')
    def test_interactive_run_lists_picks_and_never_journals_the_model(self):
        self.tool('lsblk', "echo '%s'\n" % json.dumps(LSBLK).replace('/dev/sda', '/dev/sdx9'))
        self.sudo(usable=True)
        self.logging_tool('smartctl')
        code, out = self.pty_engine(['ya', '1'], '--scope', 'hardware.disk', '--select', 'hw.smart-short-selftest')
        self.assertEqual(code, 0, out)
        self.assertIn('/dev/sdx9', out)
        self.assertIn('Samsung SSD 860 EVO', out)
        self.assertNotIn('/dev/sdb ', out)
        self.assertNotIn('Ventoy', out)
        text = self.journal.read_text()
        self.assertNotIn('Samsung', text)
        self.assertNotIn('Live Media', text)
        # the fake /dev/sdx9 is not a real block device: the unchanged eligibility check refuses it, nothing runs
        self.assertEqual(self.stages('hw.smart-short-selftest')[-1], ('approval', 'skipped', 'invalid-param'))
        self.assertNotIn('smartctl', ' '.join(self.calls()))

    @unittest.skipIf(os.geteuid() == 0, 'running as root')
    def test_non_interactive_runs_keep_missing_param(self):
        self.sudo(usable=True)
        self.tool('lsblk', "echo '%s'\n" % json.dumps(LSBLK))
        r = self.run_engine('--scope', 'hardware.disk', '--select', 'hw.smart-short-selftest',
                            '--approve', 'hw.smart-short-selftest')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.stages('hw.smart-short-selftest')[-1], ('approval', 'skipped', 'missing-param'))
        self.assertNotIn('Pilih disk', r.stdout)


# --------------------------------------------------------------------- failed-unit picker

FAILED = (
    '\u25cf nginx.service loaded failed failed A high performance web server\n'
    'cups.service loaded failed failed CUPS Scheduler\n'
    'bad;name.service loaded failed failed injected\n'
    '-rf.service loaded failed failed option-like\n'
    'user@1000.service loaded failed failed User Manager\n'
    'cups.service loaded failed failed duplicate\n')


class UnitPickerTests(EngineBase):
    UNIT = 'os-linux.restart-failed-units'
    make_engine = PickerTests.make_engine

    def make_units(self, output=FAILED, answers=(), code=0):
        eng = self.make_engine(answers=answers)
        self.tool('systemctl', 'echo "systemctl $*" >> "%s"\n/bin/cat <<\'EOT\'\n%sEOT\nexit %d\n' % (self.log, output, code))
        return eng

    def units_evidence(self):
        path = self.host_evidence([('linux-failed-units', 'warn')])
        ev = json.loads(path.read_text())
        ev['checks'][0]['target_ref'] = 'os-0'
        path.write_text(json.dumps(ev))
        return path

    def unit_action(self):
        return CATALOG.get(self.UNIT)

    def test_only_valid_failed_services_are_listed_and_the_call_is_read_only(self):
        eng = self.make_units()
        self.assertEqual(eng.failed_units(self.unit_action()), ['nginx.service', 'cups.service', 'user@1000.service'])
        self.assertEqual(self.calls(), ['systemctl --failed --no-legend --plain --type=service'])

    def test_the_list_is_capped(self):
        out = ''.join('u%d.service loaded failed failed x\n' % n for n in range(60))
        self.assertEqual(len(self.make_units(out).failed_units(self.unit_action())), engine_mod.UNIT_PICKER_MAX)

    def test_a_picked_number_becomes_the_validated_value(self):
        eng = self.make_units(answers=['2'])
        self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), ({'unit': 'cups.service'}, None))

    def test_a_value_outside_the_list_is_rejected(self):
        for answer in ('9', '0', '-1', 'sshd.service', 'bad;name.service', '1;reboot'):
            eng = self.make_units(answers=[answer])
            self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), (None, 'invalid-param'), answer)

    def test_enter_skips_and_a_param_wins_over_the_picker(self):
        eng = self.make_units(answers=[''])
        self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), (None, 'missing-param'))
        eng = self.make_units(answers=['1'])
        eng.params = {(self.UNIT, 'unit'): 'sshd.service'}
        self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), ({'unit': 'sshd.service'}, None))

    def test_an_empty_or_unavailable_list_keeps_the_free_text_prompt(self):
        for eng in (self.make_units(''), self.make_units(code=1)):
            eng.ask = lambda prompt: 'sshd.service' if 'value for unit' in prompt else ''
            self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), ({'unit': 'sshd.service'}, None))
        eng = self.make_engine()
        eng.ask = lambda prompt: 'sshd.service'
        self.assertEqual(eng.resolve_params(self.unit_action(), True, {}), ({'unit': 'sshd.service'}, None))

    def test_an_action_with_a_target_root_never_lists_the_host(self):
        eng = self.make_units()
        act = copy.deepcopy(self.unit_action())
        act['params'].append({'name': 'root', 'type': 'target_root'})
        self.assertIsNone(eng.failed_units(act))
        self.assertEqual(self.calls(), [])

    @unittest.skipIf(os.geteuid() == 0, 'running as root')
    def test_interactive_run_lists_picks_runs_and_journals_only_the_chosen_value(self):
        self.sudo(usable=True)
        self.tool('systemctl', 'echo "systemctl $*" >> "%s"\n[ "$1" = --failed ] && printf \'%%s\\n\' '
                  '"secretsvc.service loaded failed failed Secret Description" "othersvc.service loaded failed failed x" && exit 0\n[ "$1" = is-failed ] && exit 1\nexit 0\n' % self.log)
        ev = self.units_evidence()
        code, out = self.pty_engine(['1', 'ya'], '--policy', 'approve-each', evidence=ev)
        self.assertEqual(code, 0, out)
        self.assertIn('secretsvc.service', out)
        self.assertNotIn('Secret Description', out)
        self.assertIn('systemctl restart secretsvc.service', ' '.join(self.calls()))
        self.assertEqual(self.stages(self.UNIT)[-1], ('verify', 'ok', None))
        # the journal keeps what it has always kept for a parameter (the chosen, validated value, as for --param):
        # not the other listed units, not the description
        text = self.journal.read_text()
        self.assertEqual([r['params'] for r in self.records() if r.get('params')], [{'unit': 'secretsvc.service'}])
        self.assertNotIn('othersvc', text)
        self.assertNotIn('Secret Description', text)

    @unittest.skipIf(os.geteuid() == 0, 'running as root')
    def test_interactive_skip_is_missing_param(self):
        self.sudo(usable=True)
        self.tool('systemctl', 'echo "systemctl $*" >> "%s"\necho "nginx.service loaded failed failed x"\n' % self.log)
        ev = self.units_evidence()
        code, out = self.pty_engine([''], '--policy', 'approve-each', evidence=ev)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stages(self.UNIT)[-1], ('approval', 'skipped', 'missing-param'))
        self.assertNotIn('restart', ' '.join(self.calls()))

    @unittest.skipIf(os.geteuid() == 0, 'running as root')
    def test_non_interactive_runs_keep_missing_param(self):
        self.sudo(usable=True)
        self.tool('systemctl', 'echo "systemctl $*" >> "%s"\necho "nginx.service loaded failed failed x"\n' % self.log)
        ev = self.units_evidence()
        r = self.run_engine('--approve', self.UNIT, evidence=ev)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.stages(self.UNIT)[-1], ('approval', 'skipped', 'missing-param'))
        self.assertNotIn('Pilih unit', r.stdout)
        self.assertEqual([c for c in self.calls() if c.startswith('systemctl')], [])


# --------------------------------------------------------------------- batch approval

class BatchTests(EngineBase):
    def setUp(self):
        super().setUp()
        for name in ('rescue-test-fix', 'rescue-test-check', 'rescue-test-undo'):
            self.logging_tool(name)
        self.cat = self.tmp / 'catalog'
        trig = [{'check_id': 'smart-health', 'status': ['warn']}]
        write_catalog(self.cat, 'hardware', [
            action(action_id='hw.safe-one', triggers=trig, execute={'argv': ['rescue-test-fix', 'one']}),
            action(action_id='hw.safe-two', triggers=trig, execute={'argv': ['rescue-test-fix', 'two']}),
            action(action_id='hw.rev-one', risk='reversible', triggers=trig, execute={'argv': ['rescue-test-fix', 'rev']},
                   rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}}),
        ])
        write_catalog(self.cat, 'malware', [
            action(action_id='mw.quarantine-test', scope='malware', triggers=trig, execute={'argv': ['rescue-test-fix', 'q']})])

    def approvals(self):
        return {r['action_id']: (r['outcome'], r.get('reason')) for r in self.records() if r['stage'] == 'approval'}

    def test_yes_approves_every_safe_action_at_once_and_only_those(self):
        code, out = self.pty_engine(['', 'tidak', 'tidak'], '--scope', 'all', catalog=self.cat)
        self.assertEqual(code, 0, out)
        self.assertIn('Setujui semua 2 aksi aman (safe) sekaligus? / Approve all 2 safe actions at once? [Y/n]: ', out)
        for aid in ('hw.safe-one', 'hw.safe-two', 'hw.rev-one', 'mw.quarantine-test'):
            self.assertIn(aid, out.split('Menunggu persetujuan')[1].split('Setujui semua')[0])
        approvals = self.approvals()
        self.assertEqual(approvals['hw.safe-one'], ('ok', 'operator-approved-batch'))
        self.assertEqual(approvals['hw.safe-two'], ('ok', 'operator-approved-batch'))
        self.assertEqual(approvals['hw.rev-one'], ('declined', 'operator-declined'))
        self.assertEqual(approvals['mw.quarantine-test'], ('declined', 'operator-declined'))
        self.assertEqual(self.calls(), ['rescue-test-fix one', 'rescue-test-check safe', 'rescue-test-fix two',
                                        'rescue-test-check safe'])
        self.assertIn('[1/4] hw.safe-one', out)
        self.assertIn('[2/4] hw.safe-two', out)
        self.assertNotIn('[3/4]', out)         # declined actions are not "executed"

    def test_no_falls_back_to_the_per_action_prompt(self):
        code, out = self.pty_engine(['n', 'ya', 'tidak', 'tidak', 'tidak'], '--scope', 'all', catalog=self.cat)
        self.assertEqual(code, 0, out)
        approvals = self.approvals()
        self.assertEqual(approvals['hw.safe-one'], ('ok', 'operator-approved'))
        self.assertEqual(approvals['hw.safe-two'], ('declined', 'operator-declined'))
        self.assertEqual(self.calls(), ['rescue-test-fix one', 'rescue-test-check safe'])

    def test_a_single_safe_action_is_asked_on_its_own(self):
        write_catalog(self.cat, 'hardware', [action(action_id='hw.safe-one', triggers=[{'check_id': 'smart-health', 'status': ['warn']}])])
        code, out = self.pty_engine(['ya', 'tidak', 'tidak'], '--scope', 'all', catalog=self.cat)
        self.assertNotIn('sekaligus', out)
        self.assertEqual(self.approvals()['hw.safe-one'], ('ok', 'operator-approved'))

    def test_no_batch_for_detect_only_auto_safe_or_without_a_terminal(self):
        code, out = self.pty_engine([], '--scope', 'all', '--policy', 'detect-only', catalog=self.cat)
        self.assertNotIn('sekaligus', out)
        code, out = self.pty_engine(['tidak', 'tidak'], '--scope', 'all', '--policy', 'auto-safe', catalog=self.cat)
        self.assertNotIn('sekaligus', out)
        self.assertEqual(self.approvals()['hw.safe-one'], ('ok', 'auto-safe'))
        r = self.run_engine('--scope', 'all', catalog=self.cat)
        self.assertNotIn('sekaligus', r.stdout)

    def test_cli_approved_actions_are_not_part_of_the_batch(self):
        code, out = self.pty_engine(['', 'tidak', 'tidak'], '--scope', 'all', '--approve', 'hw.safe-one', catalog=self.cat)
        self.assertNotIn('sekaligus', out)           # only one safe action is left
        self.assertEqual(self.approvals()['hw.safe-one'], ('ok', 'cli-approved'))

    def test_end_of_input_at_the_batch_question_is_no(self):
        engine = engine_mod.Engine.__new__(engine_mod.Engine)
        with mock.patch('builtins.input', side_effect=EOFError):
            self.assertFalse(engine.ask_yes('? '))
        with mock.patch('builtins.input', return_value=''):
            self.assertTrue(engine.ask_yes('? '))
        with mock.patch('builtins.input', return_value='tidak'):
            self.assertFalse(engine.ask_yes('? '))

    def test_the_real_catalog_never_batches_quarantine_or_non_safe_actions(self):
        engine = engine_mod.Engine.__new__(engine_mod.Engine)
        engine.catalog, engine.path, engine.args = CATALOG, str(self.bin), types.SimpleNamespace(approve=[])
        for aid, a in CATALOG.actions.items():
            got = engine.batchable({'action_id': aid})
            if a['risk'] != 'safe' or aid.startswith('mw.quarantine-') or a.get('requires_target_rw') or a['backup']['required']:
                self.assertFalse(got, aid)


# ----------------------------------------------------- --select under auto-safe

class SelectAutoSafeTests(EngineBase):
    def setUp(self):
        super().setUp()
        for name in ('rescue-test-fix', 'rescue-test-check', 'rescue-test-undo'):
            self.logging_tool(name)
        self.cat = self.tmp / 'catalog'
        write_catalog(self.cat, 'hardware', [
            action(action_id='hw.triggered-safe', execute={'argv': ['rescue-test-fix', 'triggered']}),
            action(action_id='hw.untriggered-safe', triggers=[{'check_id': 'hw-memory', 'status': ['fail']}],
                   execute={'argv': ['rescue-test-fix', 'untriggered']}),
            action(action_id='hw.triggered-rev', risk='reversible', execute={'argv': ['rescue-test-fix', 'rev']},
                   rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}}),
        ])

    def approvals(self):
        return {r['action_id']: (r['outcome'], r.get('reason')) for r in self.records() if r['stage'] == 'approval'}

    def proposals(self):
        return {r['action_id']: r['origin'] for r in self.records() if r['stage'] == 'proposed'}

    def test_selected_and_triggered_safe_action_runs_without_a_prompt(self):
        r = self.run_engine('--policy', 'auto-safe', '--select', 'hw.triggered-safe', catalog=self.cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.proposals()['hw.triggered-safe'], 'catalog-trigger')
        self.assertEqual(self.approvals()['hw.triggered-safe'], ('ok', 'auto-safe'))
        self.assertIn('rescue-test-fix triggered', self.calls())

    def test_selected_but_not_triggered_is_not_auto_run(self):
        r = self.run_engine('--policy', 'auto-safe', '--select', 'hw.untriggered-safe', catalog=self.cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.proposals()['hw.untriggered-safe'], 'operator')
        self.assertEqual(self.approvals()['hw.untriggered-safe'], ('declined', 'not-interactive'))
        self.assertNotIn('rescue-test-fix untriggered', self.calls())

    def test_selected_and_triggered_but_not_safe_is_not_auto_run(self):
        r = self.run_engine('--policy', 'auto-safe', '--select', 'hw.triggered-rev', catalog=self.cat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.approvals()['hw.triggered-rev'], ('declined', 'not-interactive'))
        self.assertNotIn('rescue-test-fix rev', self.calls())

    def test_a_target_action_selected_without_a_target_uses_the_triggered_targets_only(self):
        write_catalog(self.cat, 'os-linux', [action(
            action_id='os-linux.safe-t', scope='os', target_families=['linuxmint'],
            triggers=[{'check_id': 'linux-package-state', 'status': ['fail']}],
            execute={'argv': ['rescue-test-fix', 'target']})])
        for select in ('os-linux.safe-t', 'os-linux.safe-t:os-0'):
            with self.subTest(select=select):
                if self.journal.exists():
                    self.journal.unlink()
                self.log.unlink() if self.log.exists() else None
                r = self.run_engine('--policy', 'auto-safe', '--select', select, '--scope', 'os', catalog=self.cat)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.proposals()['os-linux.safe-t'], 'catalog-trigger')
                self.assertEqual(self.approvals()['os-linux.safe-t'], ('ok', 'auto-safe'))
                self.assertIn('rescue-test-fix target', self.calls())
        # an action the evidence does not trigger for any target still cannot be selected without a target
        write_catalog(self.cat, 'os-linux', [action(
            action_id='os-linux.safe-t', scope='os', target_families=['linuxmint'],
            triggers=[{'check_id': 'linux-grub-config', 'status': ['fail']}],
            execute={'argv': ['rescue-test-fix', 'target']})])
        self.assertEqual(self.run_engine('--policy', 'auto-safe', '--select', 'os-linux.safe-t', '--scope', 'os',
                                         catalog=self.cat).returncode, 2)
        r = self.run_engine('--policy', 'auto-safe', '--select', 'os-linux.safe-t:os-0', '--scope', 'os', catalog=self.cat)
        self.assertEqual(self.approvals()['os-linux.safe-t'], ('declined', 'not-interactive'))     # operator origin: asks

    def test_an_interactive_selection_of_an_untriggered_action_still_prompts(self):
        code, out = self.pty_engine(['tidak', 'tidak', 'tidak'], '--policy', 'auto-safe', '--select', 'hw.untriggered-safe',
                                    '--scope', 'hardware.disk', catalog=self.cat)
        self.assertIn('Jalankan?', out)
        self.assertEqual(self.approvals()['hw.untriggered-safe'], ('declined', 'operator-declined'))


# ------------------------------------------------------------- cross-engine parity

PS1 = (ROOT / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
JXA = (ROOT / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
PY = REPAIR.read_text(encoding='utf-8')
BATCH_QUESTION = 'aksi aman (safe) sekaligus? / Approve all '


class ParityTests(unittest.TestCase):
    def test_all_three_engines_know_the_new_reasons(self):
        for reason in ('needs-root', 'operator-approved-batch'):
            for name, text in (('python', PY), ('powershell', PS1), ('zsh', JXA)):
                self.assertIn("'%s'" % reason if name != 'zsh' else reason, text, (name, reason))
        self.assertIn("'needs-root', 'operator-approved-batch')", PS1)
        self.assertIn("'needs-root', 'operator-approved-batch'];", JXA)

    def test_the_run_report_generators_list_the_same_reasons(self):
        ps = re.search(r"\$script:RrReasons = @\((.*?)\)", PS1).group(1)
        self.assertEqual(re.findall(r"'([^']+)'", ps), list(rr.REASONS))
        js = re.search(r"var REASONS = \[(.*?)\];", JXA).group(1)
        self.assertEqual(re.findall(r"'([^']+)'", js), list(rr.REASONS))

    def test_the_batch_question_is_the_same_everywhere(self):
        self.assertIn('Setujui semua ', PY)
        self.assertIn(BATCH_QUESTION, PS1)
        self.assertIn('[Y/n]', PS1)
        self.assertIn('Setujui semua $n aksi aman (safe) sekaligus? / Approve all $n safe actions at once? [Y/n]: ', JXA)
        self.assertIn(' safe actions at once? [Y/n]: ', PY)

    def test_the_batch_never_includes_other_classes_in_any_engine(self):
        self.assertIn("action['risk'] == 'safe' and not action['action_id'].startswith('mw.quarantine-')", PY)
        self.assertIn("$Action.risk -cne 'safe'", PS1)
        self.assertIn("'mw.quarantine-'", PS1)
        self.assertIn('[[ ${A_risk[$aid]} == safe ]] || return 1', JXA)
        self.assertIn('mw.quarantine-*', JXA)
        for text in (PS1, JXA):
            self.assertIn('requires_target_rw' if text is PS1 else 'A_trw', text)

    def test_the_header_and_root_marker_exist_in_all_engines(self):
        self.assertIn("'[%d/%d] %s  risk=%s  menjalankan / running'", PY)
        self.assertIn("'[' + $script:RepairIndex + '/' + $script:RepairTotal + '] ' + $Action.id + '  risk=' + $Action.risk + '  menjalankan / running'", PS1)
        self.assertIn('"[$cur_index/${#prop_id}] $aid  risk=$cur_risk  menjalankan / running"', JXA)
        for text in (PY, PS1, JXA):
            self.assertIn('(perlu root / needs root)', text)

    def test_native_engines_treat_missing_root_as_needs_root(self):
        self.assertIn("reason = 'needs-root'", PS1)
        self.assertIn("""ex[reason]='"needs-root"'""", JXA)
        self.assertNotIn("reason = 'not-applicable' }", PS1.split('function Invoke-RepairProposal')[1].split('function ConvertTo-RepairParamMap')[0])

    def test_batch_decisions_are_journaled_by_every_engine(self):
        self.assertIn("'operator-approved-batch'", PS1)
        self.assertIn('approved_reason=operator-approved-batch', JXA)
        self.assertIn("'operator-approved-batch'", PY)


if __name__ == '__main__':
    unittest.main()
