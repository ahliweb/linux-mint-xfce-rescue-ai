"""Offline tests for the repair contract: schema 1.2, typed catalog, policy engine, journal, module hooks.

No root, no block devices, no network. Catalog commands point at fake programs in a
temporary directory that the engine only uses through RESCUE_REPAIR_TEST_PATH.
"""
import copy
import importlib.util
import json
import os
import pathlib
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
FIXTURES = ROOT / 'rescue-ai/v1/fixtures'
LIVE_12 = FIXTURES / 'valid-live-scoped-1.2.json'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
import rescue_modules  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load('rescue_validate_evidence_t', SCRIPTS / 'validate-evidence.py')
analyzer = load('rescue_analyzer_t', SCRIPTS / 'opencode-go-analyze.py')


def problems(data):
    return analyzer.validation_problems(validator, data)


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


# ------------------------------------------------------------------ evidence 1.2

class EvidenceSchema12Tests(unittest.TestCase):
    def setUp(self):
        self.ev = json.loads(LIVE_12.read_text())

    def test_fixture_is_valid(self):
        self.assertEqual(problems(self.ev), [])

    def test_12_fields_are_rejected_in_older_versions(self):
        for field in ('scope', 'repair_policy', 'repair_proposals'):
            ev = copy.deepcopy(self.ev)
            ev['schema_version'] = '1.1'
            for other in ('scope', 'repair_policy', 'repair_proposals'):
                if other != field:
                    ev.pop(other)
            ev['checks'] = [c for c in ev['checks'] if not c['check_id'].startswith(('hw-', 'sw-'))
                            and c['check_id'] not in validator.V12_CHECK_IDS]
            ev['evidence_manifest']['entry_count'] = len(ev['checks'])
            with self.subTest(field=field):
                self.assertTrue(any('1.2 fields' in p for p in problems(ev)), problems(ev))

    def test_12_check_ids_and_statuses_are_rejected_in_11(self):
        ev = copy.deepcopy(self.ev)
        for k in ('scope', 'repair_policy', 'repair_proposals'):
            ev.pop(k)
        ev['schema_version'] = '1.1'
        self.assertTrue(problems(ev))
        ev['checks'] = [c for c in ev['checks'] if c['check_id'] in ('os-detection', 'block-device-discovery')]
        ev['evidence_manifest']['entry_count'] = len(ev['checks'])
        self.assertEqual(problems(ev), [])
        ev['mutation_status'] = 'rolled_back'
        self.assertTrue(problems(ev))

    def test_more_than_64_checks_only_in_12(self):
        ev = copy.deepcopy(self.ev)
        ev['checks'] = [dict(ev['checks'][0]) for _ in range(100)]
        ev['evidence_manifest']['entry_count'] = 100
        ev.pop('repair_proposals')
        self.assertEqual(problems(ev), [])
        for k in ('scope', 'repair_policy'):
            ev.pop(k)
        ev['schema_version'] = '1.1'
        self.assertTrue(any('at most 64' in p for p in problems(ev)))

    def test_scope_rules(self):
        for scope, ok in ((['all'], True), (['hardware.cpu', 'os'], True), (['all', 'os'], False),
                          (['hardware', 'hardware.cpu'], False), (['software', 'software.selected'], False),
                          (['bogus'], False)):
            ev = copy.deepcopy(self.ev)
            ev['scope'] = scope
            with self.subTest(scope=scope):
                self.assertEqual(problems(ev) == [], ok, problems(ev))

    def test_proposal_rules(self):
        cases = [
            ({'action_id': 'hw.x', 'origin': 'ai-proposal', 'target_ref': 'os-7'}, 'target_ref'),
            ({'action_id': 'hw.x', 'origin': 'catalog-trigger', 'trigger_check_id': 'hw-cpu'}, 'trigger_check_id'),
            ({'action_id': 'rm -rf /', 'origin': 'ai-proposal'}, 'does not match'),
            ({'action_id': 'hw.x', 'origin': 'model'}, 'is not one of'),
            ({'action_id': 'hw.x', 'origin': 'operator', 'argv': ['x']}, 'Additional properties'),
        ]
        for proposal, needle in cases:
            ev = copy.deepcopy(self.ev)
            ev['repair_proposals'] = [proposal]
            with self.subTest(proposal=proposal):
                self.assertTrue(any(needle in p for p in problems(ev)), problems(ev))
        ev = copy.deepcopy(self.ev)
        ev['repair_proposals'] = [{'action_id': 'hw.x', 'origin': 'operator'}] * 2
        self.assertTrue(any('duplicates' in p for p in problems(ev)))

    def test_cli_validates_fixtures(self):
        r = subprocess.run([sys.executable, SCRIPTS / 'validate-evidence.py', LIVE_12], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, SCRIPTS / 'validate-evidence.py',
                            FIXTURES / 'invalid-1.2-fields-in-1.1.json'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


# ---------------------------------------------------------------------- catalog

class CatalogInvariantTests(unittest.TestCase):
    def test_shipped_catalogs_are_valid(self):
        catalog = rc.load()
        self.assertEqual(sorted(catalog.files),
                         ['hardware.json', 'os-linux.json', 'os-macos.json', 'os-windows.json', 'software.json'])
        self.assertRegex(catalog.sha256, '^[a-f0-9]{64}$')

    def test_valid_examples_of_each_risk_class(self):
        self.assertEqual(catalog_errors('hardware', action()), [])
        self.assertEqual(catalog_errors('os-linux', action(
            action_id='os-linux.x', scope='os', risk='reversible', target_families=['linuxmint'],
            triggers=[], rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}})), [])
        self.assertEqual(catalog_errors('software', action(
            action_id='sw.x', scope='software', risk='destructive', target_families=['linuxmint'], triggers=[],
            backup={'required': True, 'what': 'package-state'},
            rollback={'kind': 'manual', 'doc': 'docs/repair-framework.md#rollback'})), [])

    def assertRejected(self, domain, act, needle):
        errs = catalog_errors(domain, act)
        self.assertTrue(any(needle in e for e in errs), errs)

    def test_forbidden_programs_anywhere(self):
        for prog in ('sh', 'bash', 'python3', 'sudo', 'env', 'powershell.exe', 'cmd', 'dd', 'curl', 'xargs', 'osascript'):
            with self.subTest(prog=prog):
                self.assertRejected('hardware', action(execute={'argv': [prog, 'x']}), 'not allowed')
                self.assertRejected('hardware', action(verify={'argv': [prog]}), 'not allowed')

    def test_placeholders(self):
        dev = [{'name': 'device', 'type': 'block_device'}]
        self.assertEqual(catalog_errors('hardware', action(params=dev, execute={'argv': ['x', '--dev={device}']},
                                                           verify={'argv': ['y', '{device}']})), [])
        self.assertRejected('hardware', action(execute={'argv': ['x', '{device}']}), 'not declared')
        self.assertRejected('hardware', action(params=dev, execute={'argv': ['x', 'pre{device}']},
                                               verify={'argv': ['y', '{device}']}), 'placeholders must be')
        self.assertRejected('hardware', action(params=dev, execute={'argv': ['x', '{device}/etc']},
                                               verify={'argv': ['y']}), 'only allowed after a target_root')
        self.assertRejected('hardware', action(params=dev), 'never used')
        self.assertRejected('hardware', action(execute={'argv': ['{device}']}), 'does not match')

    def test_risk_rules(self):
        self.assertRejected('hardware', action(backup={'required': True, 'what': 'file-copy'}), 'safe actions cannot')
        self.assertRejected('hardware', action(rollback={'kind': 'manual', 'doc': 'docs/x.md'}), 'safe actions roll back')
        self.assertRejected('hardware', action(risk='reversible'), 'automatic rollback step')
        self.assertRejected('hardware', action(risk='destructive', rollback={'kind': 'manual', 'doc': 'docs/x.md'}),
                            'require a backup')
        self.assertRejected('hardware', action(risk='destructive', backup={'required': True, 'what': 'disk-image'},
                                               rollback={'kind': 'none'}), 'restore-backup or a manual')
        self.assertRejected('hardware', action(rollback={'kind': 'step'}), 'needs a step')
        self.assertRejected('hardware', action(backup={'required': True}), 'must say what')

    def test_domain_rules(self):
        self.assertRejected('os-linux', action(), "prefix must be 'os-linux'")
        self.assertRejected('os-linux', action(action_id='os-linux.x', scope='os'), 'need target_families')
        self.assertRejected('os-windows', action(action_id='os-windows.x', scope='os', target_families=['linuxmint'],
                                                 platforms=['windows-host']), 'target_families must be within')
        self.assertRejected('os-windows', action(action_id='os-windows.x', scope='os', target_families=['windows'],
                                                 platforms=['macos-host']), 'platforms must be within')
        self.assertRejected('hardware', action(target_families=['windows']), 'take no target_families')
        self.assertRejected('software', action(action_id='sw.x', scope='os', target_families=['windows']), "use scope 'software'")
        self.assertRejected('hardware', action(triggers=[{'check_id': 'no-such-check', 'status': ['fail']}]),
                            'not in the evidence schema')

    def test_target_root_and_rw_rules(self):
        root = [{'name': 'root', 'type': 'target_root'}]
        good = action(action_id='os-linux.x', scope='os', target_families=['linuxmint'], platforms=['live-linux'],
                      params=root, risk='reversible', requires_root=True, requires_target_rw=True,
                      execute={'argv': ['dpkg', '--root={root}', '--configure', '-a']},
                      verify={'argv': ['dpkg', '--root={root}', '--audit']},
                      rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo', '{root}/var/lib/dpkg']}})
        self.assertEqual(catalog_errors('os-linux', good), [])
        self.assertRejected('os-linux', dict(good, platforms=['live-linux', 'linux-host']), 'only on the live-linux')
        self.assertRejected('os-linux', dict(good, params=[]), 'not declared')
        self.assertRejected('os-linux', dict(good, rollback={'kind': 'step', 'step': {'argv': ['u', '{root}/../x']}}),
                            'placeholders must be')
        self.assertRejected('hardware', action(requires_target_rw=True), 'cannot require')
        self.assertRejected('os-linux', dict(good, execute={'argv': ['chroot', '{root}', 'update-grub']}, risk='safe',
                                             requires_target_rw=False, rollback={'kind': 'none'}), 'chroot needs')

    def test_duplicates_and_schema_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(tmp, 'hardware', [action(), action()])
            with self.assertRaises(rc.CatalogError) as ctx:
                rc.load(tmp)
            self.assertTrue(any('duplicate action_id' in p for p in ctx.exception.problems))
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(tmp, 'hardware', [dict(action(), shell='rm -rf /')])
            with self.assertRaises(rc.CatalogError):
                rc.load(tmp)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(rc.CatalogError):
                rc.load(tmp)


class MatchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        write_catalog(cls.tmp.name, 'hardware', [action()])
        write_catalog(cls.tmp.name, 'os-linux', [action(
            action_id='os-linux.test-reversible', scope='os', risk='reversible', target_families=['linuxmint'],
            triggers=[{'check_id': 'linux-package-state', 'status': ['fail']}],
            rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}})])
        write_catalog(cls.tmp.name, 'os-windows', [action(
            action_id='os-windows.test-host-only', scope='os', target_families=['windows'], platforms=['windows-host'],
            triggers=[{'check_id': 'windows-system-files', 'status': ['unknown']}])])
        cls.catalog = rc.load(cls.tmp.name)
        cls.ev = json.loads(LIVE_12.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_normalize_and_in_scope(self):
        self.assertEqual(rc.normalize_scope(''), ('all',))
        self.assertEqual(rc.normalize_scope('os, hardware.cpu,os'), ('os', 'hardware.cpu'))
        for bad in ('all,os', 'hardware,hardware.disk', 'nope'):
            with self.assertRaises(ValueError):
                rc.normalize_scope(bad)
        self.assertTrue(rc.in_scope(('hardware',), 'hardware.disk'))
        self.assertFalse(rc.in_scope(('hardware.cpu',), 'hardware.disk'))
        self.assertTrue(rc.in_scope(('software.selected',), 'software'))
        self.assertFalse(rc.in_scope(('os',), 'software'))

    def test_triggered_respects_platform_family_and_scope(self):
        got = rc.triggered(self.catalog, self.ev, ('all',))
        self.assertEqual(got, [
            {'action_id': 'hw.test-safe', 'origin': 'catalog-trigger', 'trigger_check_id': 'smart-health'},
            {'action_id': 'os-linux.test-reversible', 'origin': 'catalog-trigger',
             'trigger_check_id': 'linux-package-state', 'target_ref': 'os-0'}])
        self.assertEqual([p['action_id'] for p in rc.triggered(self.catalog, self.ev, ('os',))],
                         ['os-linux.test-reversible'])
        self.assertEqual(rc.triggered(self.catalog, self.ev, ('hardware.cpu',)), [])

    def test_ai_proposals_are_validated_data(self):
        text = ('analysis...\n```rescue-proposals\n{"proposed_actions": ['
                '{"action_id": "hw.test-safe"},'
                '{"action_id": "os-linux.test-reversible", "target_ref": "os-1"},'
                '{"action_id": "os-linux.test-reversible", "target_ref": "os-0"},'
                '{"action_id": "os-windows.test-host-only", "target_ref": "os-1"},'
                '{"action_id": "hw.nope"},'
                '{"action_id": "hw.test-safe", "argv": ["sh"]},'
                '"rm -rf /"]}\n```\n')
        accepted, rejected = rc.parse_ai_proposals(text, self.catalog, self.ev, ('all',))
        self.assertEqual(accepted, [{'action_id': 'hw.test-safe', 'origin': 'ai-proposal'},
                                    {'action_id': 'os-linux.test-reversible', 'origin': 'ai-proposal',
                                     'target_ref': 'os-0'}])
        self.assertEqual(rejected, 5)
        for bad in ('```rescue-proposals\nnot json\n```', '```rescue-proposals\n[1]\n```',
                    '```rescue-proposals\n{"proposed_actions": [], "extra": 1}\n```',
                    '```rescue-proposals\n{"proposed_actions": ["%s"]}\n```' % ('x' * 5000)):
            self.assertEqual(rc.parse_ai_proposals(bad, self.catalog, self.ev, ('all',))[0], [])
        self.assertEqual(rc.parse_ai_proposals('no block', self.catalog, self.ev, ('all',)), ([], 0))
        indented = '  ```rescue-proposals\n  {"proposed_actions": [{"action_id": "hw.test-safe"}]}\n  ```'
        self.assertEqual(len(rc.parse_ai_proposals(indented, self.catalog, self.ev, ('all',))[0]), 1)

    def test_prompt_summary_has_no_argv(self):
        rows = rc.prompt_summary(self.catalog, self.ev, ('all',))
        self.assertEqual([r['action_id'] for r in rows], ['hw.test-safe', 'os-linux.test-reversible'])
        self.assertNotIn('rescue-test-fix', json.dumps(rows))

    def test_params_and_render(self):
        self.assertEqual(rc.validate_param({'type': 'enum', 'values': ['a', 'b']}, 'b'), 'b')
        self.assertEqual(rc.validate_param({'type': 'integer', 'minimum': 1, 'maximum': 9}, '7'), 7)
        for p, v in (({'type': 'enum', 'values': ['a']}, 'c'), ({'type': 'integer', 'minimum': 1, 'maximum': 9}, '10'),
                     ({'type': 'package_name'}, '-rf'), ({'type': 'package_name'}, 'a b'),
                     ({'type': 'package_name'}, 'vim-'),
                     ({'type': 'service_name'}, '--now'), ({'type': 'block_device'}, '/dev/../etc/passwd'),
                     ({'type': 'block_device'}, 'sda'), ({'type': 'target_root'}, '/')):
            with self.subTest(param=p, value=v):
                with self.assertRaises(ValueError):
                    rc.validate_param(p, v)
        with self.assertRaises(ValueError):
            rc.validate_param({'type': 'package_name'}, 'vim', packages={'nano'})
        self.assertEqual(rc.render(['a', '{x}', '--o={x}', '{r}/etc', 'lit{'], {'x': 'v; rm', 'r': '/mnt/t'}),
                         ['a', 'v; rm', '--o=v; rm', '/mnt/t/etc', 'lit{'])


# ----------------------------------------------------------------------- engine

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='repair-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.log = self.tmp / 'calls.log'
        self.fail = self.tmp / 'fail'  # files named here make a fake program fail
        self.fail.mkdir()
        for name in ('rescue-test-fix', 'rescue-test-check', 'rescue-test-undo', 'rescue-test-pre'):
            (self.bin / name).write_text(
                '#!/bin/sh\necho "%s $*" >> "%s"\necho "RAW-OUTPUT-MARKER from %s"\n'
                '[ -e "%s/%s" ] && exit 3\nexit 0\n' % (name, self.log, name, self.fail, name))
            (self.bin / name).chmod(0o755)
        (self.bin / 'sudo').write_text('#!/bin/sh\necho "sudo $*" >> "%s"\nshift 2\nexec "$@"\n' % self.log)
        (self.bin / 'sudo').chmod(0o755)
        self.catalog = self.tmp / 'catalog'
        write_catalog(self.catalog, 'hardware', [
            action(),
            action(action_id='hw.test-param', triggers=[], params=[
                {'name': 'level', 'type': 'enum', 'values': ['low', 'high'], 'default': 'low'}],
                execute={'argv': ['rescue-test-fix', '--level={level}']}, verify={'argv': ['rescue-test-check']}),
            action(action_id='hw.test-root', triggers=[], requires_root=True),
        ])
        write_catalog(self.catalog, 'os-linux', [action(
            action_id='os-linux.test-reversible', scope='os', risk='reversible', target_families=['linuxmint'],
            triggers=[{'check_id': 'linux-package-state', 'status': ['fail']}],
            preconditions=[{'argv': ['rescue-test-pre']}],
            execute={'argv': ['rescue-test-fix', 'reversible']}, verify={'argv': ['rescue-test-check', 'reversible']},
            rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo', 'reversible']}}),
            action(action_id='os-linux.test-mount', scope='os', risk='reversible', target_families=['linuxmint'],
                   platforms=['live-linux'], triggers=[], requires_target_rw=True, requires_root=True,
                   params=[{'name': 'root', 'type': 'target_root'}],
                   execute={'argv': ['rescue-test-fix', '--root={root}']}, verify={'argv': ['rescue-test-check']},
                   rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}})])
        write_catalog(self.catalog, 'software', [action(
            action_id='sw.test-destructive', scope='software', risk='destructive', target_families=['linuxmint'],
            triggers=[{'check_id': 'sw-broken-dependencies', 'status': ['warn']}],
            execute={'argv': ['rescue-test-fix', 'destructive']}, verify={'argv': ['rescue-test-check', 'destructive']},
            backup={'required': True, 'what': 'package-state'},
            rollback={'kind': 'manual', 'doc': 'docs/repair-framework.md#rollback'})])
        self.journal = self.tmp / 'state' / 'repairs' / 'journal.jsonl'
        provider_fixture = self.tmp / 'no-targets'
        provider_fixture.mkdir()
        # The mount provider never looks at real disks in tests.
        self.env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(self.bin),
                        RESCUE_TARGET_MOUNT_FIXTURE_ROOT=str(provider_fixture))

    def engine(self, *args, evidence=LIVE_12):
        cmd = [sys.executable, SCRIPTS / 'rescue-repair.py', '--evidence', evidence, '--catalog-dir', self.catalog,
               '--state-dir', self.tmp / 'state', *args]
        return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, env=self.env,
                              stdin=subprocess.DEVNULL, timeout=60)

    def records(self):
        if not self.journal.exists():
            return []
        return [json.loads(ln) for ln in self.journal.read_text().splitlines() if ln.strip()]

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stages(self, action_id):
        return [(r['stage'], r['outcome']) for r in self.records() if r['action_id'] == action_id]

    def verify_chain(self):
        r = subprocess.run([sys.executable, SCRIPTS / 'rescue-repair.py', '--verify-journal', self.journal],
                           capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_list_plans_without_executing_or_journaling(self):
        r = self.engine('--list')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('hw.test-safe', r.stdout)
        self.assertIn('os-linux.test-reversible', r.stdout)
        self.assertIn('sw.test-destructive', r.stdout)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.journal.exists())

    def test_detect_only_journals_but_never_executes(self):
        r = self.engine('--policy', 'detect-only', '--approve', 'hw.test-safe')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stages('hw.test-safe'), [('proposed', 'ok'), ('approval', 'skipped')])
        self.assertEqual(self.verify_chain()[0], 0)

    def test_approve_each_without_terminal_declines(self):
        r = self.engine()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])
        reasons = {r['action_id']: r.get('reason') for r in self.records() if r['stage'] in ('approval', 'backup')}
        self.assertEqual(reasons['hw.test-safe'], 'not-interactive')
        self.assertEqual(reasons['sw.test-destructive'], 'missing-backup')

    def test_cli_approval_executes_and_verifies(self):
        r = self.engine('--approve', 'hw.test-safe')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), ['rescue-test-fix safe', 'rescue-test-check safe'])
        self.assertEqual(self.stages('hw.test-safe'), [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'),
                                                       ('verify', 'ok')])
        rec = [r for r in self.records() if r['stage'] == 'execute'][0]
        self.assertEqual(rec['exit_code'], 0)
        self.assertRegex(rec['output_sha256'], '^[a-f0-9]{64}$')
        self.assertNotIn('RAW-OUTPUT-MARKER', self.journal.read_text())
        self.assertEqual(self.verify_chain(), (0, 'journal: valid (%s)\n' % self.journal))
        self.assertIn('verified', r.stdout)

    def test_verify_failure_runs_the_rollback_step(self):
        (self.fail / 'rescue-test-check').touch()
        r = self.engine('--approve', 'os-linux.test-reversible')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.calls(), ['rescue-test-pre ', 'rescue-test-fix reversible',
                                        'rescue-test-check reversible', 'rescue-test-undo reversible'])
        self.assertEqual(self.stages('os-linux.test-reversible')[-2:], [('verify', 'fail'), ('rollback', 'ok')])
        self.assertIn('rolled-back', r.stdout)

    def test_failed_precondition_stops_the_action(self):
        (self.fail / 'rescue-test-pre').touch()
        r = self.engine('--approve', 'os-linux.test-reversible')
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.calls(), ['rescue-test-pre '])

    def test_destructive_needs_backup_and_records_its_fingerprint(self):
        r = self.engine('--approve', 'sw.test-destructive')
        self.assertEqual(self.calls(), [])
        backup = self.tmp / 'backup.img'
        backup.write_bytes(b'x' * (3 << 20))
        r = self.engine('--approve', 'sw.test-destructive', '--backup-ref', backup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), ['rescue-test-fix destructive', 'rescue-test-check destructive'])
        rec = [r for r in self.records() if r['stage'] == 'backup' and r['outcome'] == 'ok'][0]
        self.assertEqual(rec['backup']['size_bytes'], 3 << 20)
        self.assertNotIn(str(backup), self.journal.read_text())

    def test_destructive_failure_asks_for_manual_rollback(self):
        backup = self.tmp / 'backup.img'
        backup.write_bytes(b'x')
        (self.fail / 'rescue-test-fix').touch()
        r = self.engine('--approve', 'sw.test-destructive', '--backup-ref', backup)
        self.assertEqual(r.returncode, 1)
        self.assertIn('docs/repair-framework.md#rollback', r.stderr)
        self.assertEqual(self.stages('sw.test-destructive')[-1], ('rollback', 'skipped'))

    def test_auto_safe_runs_only_safe_catalog_triggers(self):
        analysis = self.tmp / 'analysis.md'
        analysis.write_text('```rescue-proposals\n{"proposed_actions": [{"action_id": "hw.test-param"}]}\n```\n')
        r = self.engine('--policy', 'auto-safe', '--analysis', analysis)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), ['rescue-test-fix safe', 'rescue-test-check safe'])
        approvals = {r['action_id']: (r['outcome'], r.get('reason')) for r in self.records() if r['stage'] == 'approval'}
        self.assertEqual(approvals['hw.test-safe'], ('ok', 'auto-safe'))
        self.assertEqual(approvals['hw.test-param'], ('declined', 'not-interactive'))   # AI-proposed: prompt
        self.assertEqual(approvals['os-linux.test-reversible'], ('declined', 'not-interactive'))

    def test_params_defaults_cli_values_and_invalid_values(self):
        r = self.engine('--select', 'hw.test-param', '--approve', 'hw.test-param', '--scope', 'hardware')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('rescue-test-fix --level=low', self.calls())
        self.log.unlink()
        self.engine('--select', 'hw.test-param', '--approve', 'hw.test-param', '--param', 'hw.test-param.level=high',
                    '--scope', 'hardware')
        self.assertIn('rescue-test-fix --level=high', self.calls())
        self.log.unlink()
        self.engine('--select', 'hw.test-param', '--approve', 'hw.test-param',
                    '--param', 'hw.test-param.level=high;reboot', '--scope', 'hardware')
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.records()[-1]['reason'], 'invalid-param')

    def test_requires_root_goes_through_sudo_n(self):
        if os.geteuid() == 0:
            self.skipTest('running as root')
        r = self.engine('--select', 'hw.test-root', '--approve', 'hw.test-root', '--scope', 'hardware.disk')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.calls()[0].startswith('sudo -n -- '), self.calls())

    def test_target_root_provider_refusal_is_journaled_and_nothing_runs(self):
        # scripts/lib/target_mount.py exists (ahliweb/linux-mint-xfce-rescue-ai#16): with an empty provider
        # fixture it cannot re-identify the evidence's target, so the action must fail before running.
        r = self.engine('--select', 'os-linux.test-mount:os-0', '--approve', 'os-linux.test-mount', '--scope', 'os')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stages('os-linux.test-mount')[-1], ('target-rw', 'fail'))

    def test_select_is_validated(self):
        self.assertEqual(self.engine('--select', 'hw.nope').returncode, 2)
        self.assertEqual(self.engine('--select', 'hw.test-safe', '--scope', 'os').returncode, 2)
        self.assertEqual(self.engine('--scope', 'all,os').returncode, 2)
        self.assertEqual(self.engine('--param', 'bad').returncode, 2)

    def test_unknown_program_is_unavailable_not_failed(self):
        write_catalog(self.catalog, 'hardware', [action(execute={'argv': ['rescue-test-missing']})])
        r = self.engine('--approve', 'hw.test-safe', '--scope', 'hardware')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.stages('hw.test-safe')[-1], ('execute', 'unavailable'))

    def test_windows_evidence_is_planned_but_not_executed_here(self):
        ev = json.loads((FIXTURES / 'valid-windows-host-1.1.json').read_text())
        path = self.tmp / 'win.json'
        path.write_text(json.dumps(ev))
        self.assertEqual(self.engine('--list', evidence=path).returncode, 0)

    def test_invalid_evidence_and_catalog(self):
        bad = self.tmp / 'bad.json'
        bad.write_text('{"schema_version": "1.2"}')
        self.assertEqual(self.engine(evidence=bad).returncode, 2)
        write_catalog(self.catalog, 'hardware', [action(execute={'argv': ['bash', '-c', 'x']})])
        r = self.engine()
        self.assertEqual(r.returncode, 2)
        self.assertIn('not allowed', r.stderr)

    def test_journal_tampering_is_detected(self):
        self.engine('--approve', 'hw.test-safe')
        lines = self.journal.read_text().splitlines()
        self.assertGreaterEqual(len(lines), 4)
        tampered = json.loads(lines[1])
        tampered['outcome'] = 'declined'
        lines[1] = json.dumps(tampered, sort_keys=True, separators=(',', ':'))
        self.journal.write_text('\n'.join(lines) + '\n')
        code, out = self.verify_chain()
        self.assertEqual(code, 1)
        self.assertIn('prev_sha256', out)
        self.journal.write_text('\n'.join(lines[:1] + lines[2:]) + '\n')
        self.assertIn('seq', self.verify_chain()[1])

    def test_journal_chain_spans_runs_and_file_is_private(self):
        self.engine('--approve', 'hw.test-safe')
        self.engine('--policy', 'detect-only')
        seqs = [r['seq'] for r in self.records()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        self.assertEqual(self.verify_chain()[0], 0)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def interactive(self, answers, *args):
        """Run the engine on a pseudo-terminal and type *answers* (one per prompt)."""
        cmd = [sys.executable, str(SCRIPTS / 'rescue-repair.py'), '--evidence', str(LIVE_12),
               '--catalog-dir', str(self.catalog), '--state-dir', str(self.tmp / 'state'), *map(str, args)]
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
                if pending and out.endswith(b': '):  # a prompt is waiting for input
                    os.write(master, (pending.pop(0) + '\n').encode())
            elif proc.poll() is not None:
                break
        proc.wait(timeout=10)
        os.close(master)
        return proc.returncode, out.decode('utf-8', 'replace')

    def test_interactive_yes_runs_and_no_declines(self):
        code, out = self.interactive(['ya'], '--scope', 'hardware')
        self.assertEqual(code, 0, out)
        self.assertIn('rescue-test-fix safe', self.calls())
        self.assertIn('execute: ', out)
        self.log.unlink()
        code, out = self.interactive(['tidak'], '--scope', 'hardware')
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.records()[-1]['reason'], 'operator-declined')

    def test_interactive_destructive_needs_the_typed_action_id(self):
        backup = self.tmp / 'b.img'
        backup.write_bytes(b'b')
        self.interactive(['yes'], '--scope', 'software', '--backup-ref', backup)
        self.assertEqual(self.calls(), [])
        self.interactive(['sw.test-destructive'], '--scope', 'software', '--backup-ref', backup)
        self.assertEqual(self.calls(), ['rescue-test-fix destructive', 'rescue-test-check destructive'])


# ---------------------------------------------------------------------- modules

class ModuleHookTests(unittest.TestCase):
    def test_sanitize_drops_everything_outside_the_contract(self):
        ctx = rescue_modules.Context(mode='live')
        good = [{'check_id': 'hw-cpu', 'status': 'pass'},
                {'check_id': 'hw-battery', 'status': 'warn', 'kind': 'percent', 'number': 70}]
        bad = [{'check_id': 'hw-cpu', 'status': 'ok'}, {'check_id': 'bogus', 'status': 'pass'},
               {'check_id': 'hw-cpu', 'status': 'pass', 'kind': 'text', 'number': 1},
               {'check_id': 'hw-cpu', 'status': 'pass', 'kind': 'count', 'number': -1},
               {'check_id': 'hw-cpu', 'status': 'pass', 'kind': 'count', 'number': True},
               {'check_id': 'hw-cpu', 'status': 'pass', 'target_ref': 'os-0'}, 'not a dict', None]
        out = rescue_modules.sanitize(good + bad, 'test', ctx, allow_target_ref=False)
        self.assertEqual(out, [{'check_id': 'hw-cpu', 'status': 'pass'},
                               {'check_id': 'hw-battery', 'status': 'warn', 'kind': 'percent', 'number': 70}])
        self.assertEqual(len(ctx.warnings), len(bad))

    def test_context_scope(self):
        ctx = rescue_modules.Context(mode='live', scope=('hardware.cpu',))
        self.assertTrue(ctx.wants('hardware'))
        self.assertTrue(ctx.wants('hardware', 'cpu'))
        self.assertFalse(ctx.wants('hardware', 'disk'))
        self.assertFalse(ctx.wants('os'))
        self.assertTrue(rescue_modules.Context(mode='host', scope=('software.selected',)).wants('software'))

    def test_broken_module_does_not_break_collection(self):
        ctx = rescue_modules.Context(mode='host')
        self.assertEqual(rescue_modules._call(ctx, 'x', lambda c: 1 / 0), [])
        self.assertIn('failed', ctx.warnings[0])

    def test_shipped_modules_never_raise_and_only_emit_valid_checks(self):
        # The stubs of #15-#17 used to return nothing; filled modules must still never warn or break.
        for mode in ('live', 'host'):
            ctx = rescue_modules.Context(mode=mode)
            checks = rescue_modules.collect_system(ctx)
            checks += rescue_modules.collect_offline_target(ctx, '/nonexistent', {'family': 'linuxmint'})
            self.assertEqual(ctx.warnings, [])
            self.assertTrue(all(c['check_id'] in rescue_modules.CHECK_IDS for c in checks))


class ScannerAndAnalyzerTests(unittest.TestCase):
    def test_build_evidence_drops_whole_targets_at_160_checks(self):
        scan = load('rescue_scan_t', SCRIPTS / 'scan-target-os.py')
        from datetime import datetime, timezone
        many = [scan.check('os-detection', 'pass')] * 70
        targets = [{'family': 'linuxmint', 'release': None, 'encryption': 'none', 'access': 'read-only-mounted',
                    'checks': list(many)} for _ in range(3)]
        ev = scan.build_evidence(targets, [scan.check('block-device-discovery', 'pass')],
                                 datetime(2026, 9, 30, tzinfo=timezone.utc), 'uefi', ('os',), 'detect-only')
        self.assertEqual(len(ev['target_systems']), 2)
        self.assertEqual(len(ev['checks']), 141)
        self.assertEqual((ev['schema_version'], ev['scope'], ev['repair_policy']), ('1.2', ['os'], 'detect-only'))
        self.assertEqual(problems(ev), [])

    def test_scanner_records_scope_policy_and_catalog_proposals(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = pathlib.Path(tmp, 'fx')
            (fx / 'root/etc').mkdir(parents=True)
            (fx / 'root/etc/os-release').write_text('ID=linuxmint\nNAME="Linux Mint"\nVERSION_ID="22.3"\n')
            (fx / 'root/var/lib/dpkg').mkdir(parents=True)
            (fx / 'root/var/lib/dpkg/status').write_text('Package: a\nStatus: install ok half-configured\n\n')
            (fx / 'root.meta.json').write_text(json.dumps({'fstype': 'ext4', 'size': 50 * 1024 ** 3}))
            cat = pathlib.Path(tmp, 'cat')
            write_catalog(cat, 'os-linux', [action(
                action_id='os-linux.test-reversible', scope='os', risk='reversible', target_families=['linuxmint'],
                triggers=[{'check_id': 'linux-package-state', 'status': ['fail']}],
                rollback={'kind': 'step', 'step': {'argv': ['rescue-test-undo']}})])
            out = pathlib.Path(tmp, 'ev.json')
            r = subprocess.run([sys.executable, SCRIPTS / 'scan-target-os.py', '--output', out, '--fixture-root', fx,
                                '--scope', 'os', '--repair-policy', 'detect-only', '--catalog-dir', cat],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            ev = json.loads(out.read_text())
            self.assertEqual(problems(ev), [])
            self.assertEqual((ev['scope'], ev['repair_policy']), (['os'], 'detect-only'))
            self.assertEqual(ev['repair_proposals'], [{'action_id': 'os-linux.test-reversible',
                                                       'origin': 'catalog-trigger',
                                                       'trigger_check_id': 'linux-package-state',
                                                       'target_ref': 'os-0'}])
            r = subprocess.run([sys.executable, SCRIPTS / 'scan-target-os.py', '--output', out, '--fixture-root', fx,
                                '--scope', 'all,os'], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)

    def test_analyzer_catalog_text_lists_ids_and_metadata_never_argv(self):
        text = analyzer.catalog_text(json.loads(LIVE_12.read_text()))
        for row in (json.loads(text) if text else []):
            self.assertLessEqual(set(row), {'action_id', 'title', 'scope', 'risk', 'target_families', 'triggers'})
        for word in ('argv', 'execute', 'rollback'):
            self.assertNotIn(word, text)

    def test_prompt_documents_the_proposal_block(self):
        text = (ROOT / 'profiles/rescue-hermes/analysis-prompt.md').read_text()
        self.assertIn('```rescue-proposals', text)
        self.assertIn('Never write commands', text)


if __name__ == '__main__':
    unittest.main()
