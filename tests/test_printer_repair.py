#!/usr/bin/env python3
"""Offline tests for the printer repair actions (ahliweb/linux-mint-xfce-rescue-ai#57, phase 2).

A fake sysfs/proc tree stands in for /sys and /proc (RESCUE_REPAIR_TEST_USB_ROOT), and one stateful PATH shim
(found only through RESCUE_REPAIR_TEST_PATH) stands in for ``lpstat``, ``ipptool``, ``cupsenable``, ``cupsaccept``,
``cancel``, ``lp``, ``sudo`` and ``avahi-browse``: it answers from a state file, mutates the queue like CUPS would,
checks that every fixed file it is handed exists, logs every call and carries the dummy queue name that must never
reach the journal, a report or the screen. Nothing touches a real printer, a real CUPS server or the network.

* catalog: the shipped printer.json and the invariants that confine a printer action to a closed list of programs,
  fixed argv forms, fixed bundle files and one engine-resolved printer (or one installed OS spooler);
* engine: printer_ref resolution at execution time (typed refusals), the risk class ``irreversible`` (always asks),
  policy behaviour, privacy of the screen and the journal, network opt-in;
* spool: the reversible quarantine of the stuck spool files of an installed OS, helper and engine, round trip;
* generators: the run report accepts prn-N, scope printer, the printer domain and the new reasons and risk in the
  Python, JXA (node) and PowerShell generators;
* host engines: both native engines accept the catalog and keep the new parameter types unsupported;
* launcher: the offer after the OS scan and the Android offer.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import copy
import csv
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_android_repair as AR  # noqa: E402
import test_host_repair as HR  # noqa: E402
import test_printer as TP  # noqa: E402
import test_run_report as TR  # noqa: E402

REPO = HR.REPO
SCRIPTS = REPO / 'scripts'
REPAIR = SCRIPTS / 'rescue-repair.py'
SCAN = SCRIPTS / 'scan-printers.py'
SCAN_OS = SCRIPTS / 'scan-target-os.py'
HELPER = SCRIPTS / 'malware-quarantine.py'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import quarantine_store as qs  # noqa: E402
import repair_catalog as rc  # noqa: E402
import run_report as rr  # noqa: E402
from rescue_modules import printer  # noqa: E402

NODE = shutil.which('node')
PWSH = HR.PWSH
ROOT_USER = os.geteuid() == 0
QUEUE = TP.QUEUE_HP                       # the dummy queue name: it must stay out of every output
NET_QUEUE = TP.QUEUE_NET
SERIAL = TP.SERIAL_HP
USB_URI = 'usb://SecretMaker/Secret%%20LaserJet?serial=%s' % SERIAL
NET_URI = 'ipp://192.168.77.88:631/ipp/print'
LEAKS = (QUEUE, NET_QUEUE, SERIAL, '192.168.77.88', 'secret-printer.local', 'SecretMDNS', 'SecretMaker', 'Secret LaserJet',
         'request id is', 'secretuser', 'machine-id')
BUNDLE = str(rc.ROOT)

SHIM = r'''#!PYTHON
import csv, io, json, os, sys
D = os.path.dirname(os.path.abspath(__file__))
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
with open(os.path.join(D, 'calls.log'), 'a') as handle:
    handle.write(json.dumps({'tool': name, 'argv': argv, 'env': {k: os.environ.get(k) for k in (
        'CUPS_SERVER', 'OPENCODE_GO_API_KEY', 'HOME', 'LC_ALL')}}) + '\n')
path = os.path.join(D, 'state.json')
st = json.load(open(path))
Q = st['queues']


def save():
    json.dump(st, open(path, 'w'))


def die(code, message=''):
    sys.stderr.write(message)
    sys.exit(code)


def pline(n, q):
    if q['state'] == 'idle':
        return 'printer %s is idle.  enabled since Thu 01 Oct 2026 08:00:00 AM UTC\n' % n
    if q['state'] == 'processing':
        return 'printer %s now printing %s-7.  enabled since Thu 01 Oct 2026 08:00:00 AM UTC\n' % (n, n)
    return 'printer %s disabled since Thu 01 Oct 2026 08:00:00 AM UTC -\n\tPaused\n' % n


if name in st.get('fail', {}):
    die(st['fail'][name], '%s: forced failure %s\n' % (name, ' '.join(Q)))

if name == 'sudo':
    if argv[:2] != ['-n', '--'] or len(argv) < 3:
        die(2, 'sudo: unexpected arguments\n')
    os.execv(argv[2], argv[2:])

if name == 'lpstat':
    flag = argv[0] if argv else ''
    if len(argv) == 2 and flag == '-p':
        if argv[1] not in Q:
            die(1, 'lpstat: Invalid destination name\n')
        sys.stdout.write(pline(argv[1], Q[argv[1]]))
        sys.exit(0)
    if flag == '-r':
        sys.stdout.write('scheduler is running\n' if st.get('running', True) else 'scheduler is not running\n')
    elif flag == '-p':
        sys.stdout.write(''.join(pline(n, q) for n, q in Q.items()))
    elif flag == '-v':
        sys.stdout.write(''.join('device for %s: %s\n' % (n, q['uri']) for n, q in Q.items()))
    elif flag == '-a':
        sys.stdout.write(''.join('%s %s requests since Thu 01 Oct 2026 08:00:00 AM UTC\n' % (
            n, 'accepting' if q['accepting'] else 'not accepting') for n, q in Q.items()))
    elif flag == '-o':
        for n, q in Q.items():
            for i in range(q['jobs']):
                sys.stdout.write('%s-%d  secretuser  1024  Thu 01 Oct 2026 08:00:00 AM UTC\n' % (n, i + 1))
    else:
        die(2)
    sys.exit(0)

if name == 'ipptool':
    if argv[:3] == ['-T', '6', '-c']:               # the read-only discovery of the scan
        uri = argv[3]
        prefix = 'ipp://localhost/printers/'
        if uri.startswith(prefix) and uri[len(prefix):] in Q:
            q = Q[uri[len(prefix):]]
        elif uri in st.get('ipp', {}):
            q = st['ipp'][uri]
        else:
            die(1, 'ipptool: Unable to connect\n')
        out = io.StringIO()
        writer = csv.writer(out, lineterminator='\n')
        writer.writerow(['printer-state', 'printer-state-reasons', 'printer-is-accepting-jobs', 'queued-job-count',
                         'marker-levels', 'marker-types', 'printer-make-and-model'])
        writer.writerow([q['state'], 'none', 'true' if q['accepting'] else 'false', q['jobs'], '', '',
                         'HP Secret LaserJet 9000'])
        sys.stdout.write(out.getvalue())
        sys.exit(0)
    if len(argv) == 5 and argv[:3] == ['-q', '-T', '10']:
        uri, test = argv[3], argv[4]
        prefix = 'ipp://localhost/printers/'
        if not uri.startswith(prefix) or uri[len(prefix):] not in Q:
            die(1, 'ipptool: the printer does not exist\n')
        if not os.path.isfile(test):
            die(2, 'ipptool: test file missing\n')
        q = Q[uri[len(prefix):]]
        base = os.path.basename(test)
        ok = {'identify-printer.test': st.get('identify', True),
              'verify-queue-ready.test': q['state'] != 'stopped',
              'verify-accepting.test': q['accepting'],
              'verify-no-jobs.test': q['jobs'] == 0}.get(base)
        if ok is None:
            die(2, 'ipptool: unknown test file\n')
        sys.exit(0 if ok else 1)
    die(2, 'ipptool: unexpected arguments\n')

if name in ('cupsenable', 'cupsaccept'):
    if len(argv) != 1 or argv[0] not in Q:
        die(1, '%s: The printer or class does not exist.\n' % name)
    if name == 'cupsenable' and not st.get('enable_noop'):
        Q[argv[0]]['state'] = 'idle'
    if name == 'cupsaccept':
        Q[argv[0]]['accepting'] = True
    save()
    sys.exit(0)

if name == 'cancel':
    if len(argv) != 2 or argv[0] != '-a' or argv[1] not in Q:
        die(1, 'cancel: unexpected arguments\n')
    if not st.get('cancel_noop'):
        Q[argv[1]]['jobs'] = 0
    save()
    sys.exit(0)

if name == 'lp':
    if argv[:1] != ['-d'] or argv[1] not in Q or not os.path.isfile(argv[-1]):
        die(1, 'lp: Error - bad arguments or file\n')
    sys.stdout.write('request id is %s-12 (1 file(s))\n' % argv[1])
    st.setdefault('printed', []).append(os.path.basename(argv[-1]))
    save()
    sys.exit(0)

if name == 'avahi-browse':
    sys.stdout.write(st.get('avahi', {}).get(argv[-1], ''))
    sys.exit(0)

die(3)
'''
TOOLS = ('lpstat', 'ipptool', 'cupsenable', 'cupsaccept', 'cancel', 'lp', 'sudo', 'avahi-browse')


def queue(uri=USB_URI, state='idle', accepting=True, jobs=0):
    return {'uri': uri, 'state': state, 'accepting': accepting, 'jobs': jobs}


def read_journal(path):
    return HR.read_journal(path)


def make_machine(root, serial=SERIAL, second_serial=None, with_printer=True):
    """The rescue USB on 1-6 and, when asked, the HP printer on 1-4 (and an identical-looking twin on 1-5)."""
    m = TP.FakeUsb(root)
    m.add_device('1-6', '0781', '5567', ['08/06/50'], serial='RESCUESERIAL1')
    m.add_rescue_medium('1-6')
    if with_printer:
        m.add_device('1-4', '03f0', '2b17', ['07/01/02'], serial=serial, panel='left', horizontal='left',
                     connect_type='hotplug')
    if second_serial:
        m.add_device('1-5', '03f0', '2b17', ['07/01/02'], serial=second_serial)
    return m


class PrinterRepairCase(unittest.TestCase):
    """A fake machine with one USB printer and a CUPS queue for it; evidence made by the real scanner."""

    queues = None          # overrides the default state of the queue (see defaults below)
    network = False

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix='printer-repair-')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / 'home'
        self.home.mkdir()
        self.machines = 0
        self.build()

    def rebuild(self, **flags):
        shutil.rmtree(self.tmp, True)
        self.tmp.mkdir()
        self.home.mkdir()
        for name, value in flags.items():
            setattr(self, name, value)
        self.build()

    def build(self):
        self.machine = self.new_machine()
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for tool in TOOLS:
            (self.bin / tool).write_text(SHIM.replace('PYTHON', sys.executable))
            (self.bin / tool).chmod(0o755)
        self.state = {'queues': self.queues if self.queues is not None else {QUEUE: queue(state='stopped', accepting=False, jobs=2)},
                      'ipp': {}, 'avahi': {}, 'fail': {}}
        self.write_state()
        self.journal = self.tmp / 'state' / 'repairs' / 'journal.jsonl'
        self.evidence = self.tmp / 'evidence.json'
        proc = self.scan(self.evidence, '--repair-policy', 'approve-each', *(['--network'] if self.network else []))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.ev = json.loads(self.evidence.read_text())
        (self.bin / 'calls.log').unlink(missing_ok=True)

    def new_machine(self, **kw):
        self.machines += 1
        return make_machine(self.tmp / ('m%d' % self.machines), **kw)

    # ------------------------------------------------------------------ fixtures
    def write_state(self):
        (self.bin / 'state.json').write_text(json.dumps(self.state))

    def set_state(self, **fields):
        self.state.update(fields)
        self.write_state()

    def queue_state(self, name=QUEUE):
        return json.loads((self.bin / 'state.json').read_text())['queues'][name]

    def env(self, machine=None, bin_dir=None, **extra):
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'LC_ALL': 'C',
               'RESCUE_REPAIR_TEST_PATH': str(bin_dir or self.bin),
               'RESCUE_REPAIR_TEST_USB_ROOT': str((machine or self.machine).root)}
        env.update(extra)
        return env

    def scan(self, out, *args):
        argv = [sys.executable, str(SCAN), '--fixture-root', str(self.machine.root), '--tool-path', str(self.bin),
                '--output', str(out)] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=120,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'LC_ALL': 'C'})

    def engine(self, *args, evidence=None, machine=None, bin_dir=None, **extra):
        argv = [sys.executable, str(REPAIR), '--evidence', str(evidence or self.evidence), '--journal', str(self.journal)]
        return subprocess.run(argv + list(args), capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                              env=self.env(machine, bin_dir, **extra))

    def calls(self):
        path = self.bin / 'calls.log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def action_calls(self):
        """The mutating or verifying calls of an action (not the discovery: lpstat, ipptool -c, avahi-browse, sudo)."""
        out = []
        for c in self.calls():
            if c['tool'] in ('cupsenable', 'cupsaccept', 'cancel', 'lp') or (
                    c['tool'] == 'ipptool' and c['argv'][:1] == ['-q']) or (c['tool'] == 'lpstat' and len(c['argv']) == 2):
                out.append((c['tool'], c['argv']))
        return out

    def stages(self, aid):
        return HR.stages(read_journal(self.journal), aid)

    def journal_text(self):
        return self.journal.read_text(encoding='utf-8') if self.journal.exists() else ''

    def assert_private(self, text):
        for leak in LEAKS + ('1-4',):
            self.assertNotIn(leak, text)

    def run_one(self, aid, *args, ref='prn-0', **kwargs):
        return self.engine('--select', '%s:%s' % (aid, ref), '--approve', aid, '--scope', 'printer', *args, **kwargs)

    def uri(self, name=QUEUE):
        return 'ipp://localhost/printers/%s' % name

    def bundle_file(self, rel):
        return '%s/%s' % (BUNDLE, rel)


# ----------------------------------------------------------------------------------------
# Catalog
# ----------------------------------------------------------------------------------------
def printer_action(**over):
    base = {
        'action_id': 'printer.test-action', 'title': 'Test action', 'title_id': 'Tindakan uji', 'scope': 'printer',
        'platforms': ['live-linux', 'linux-host'], 'target_families': ['printer'], 'risk': 'safe', 'triggers': [],
        'params': [{'name': 'printer', 'type': 'printer_ref'}, {'name': 'bundle', 'type': 'bundle_root'}],
        'execute': {'argv': ['cupsenable', '{printer}']},
        'verify': {'argv': ['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/{printer}',
                            '{bundle}/scripts/lib/ipp/verify-queue-ready.test']},
        'rollback': {'kind': 'none'}, 'backup': {'required': False}, 'doc': 'docs/printer.md',
    }
    base.update(over)
    return base


def spool_action(**over):
    base = {
        'action_id': 'printer.test-spool', 'title': 'Test spool', 'title_id': 'Uji spool', 'scope': 'printer',
        'platforms': ['live-linux'], 'target_families': ['windows', 'linuxmint'], 'risk': 'reversible',
        'requires_root': True, 'requires_target_rw': True, 'triggers': [],
        'params': [{'name': 'target_root', 'type': 'target_root'}, {'name': 'quarantine', 'type': 'state_dir', 'values': ['quarantine']}],
        'preconditions': [{'argv': ['rescue-malware-quarantine', 'spool-check', '--target-root={target_root}']}],
        'execute': {'argv': ['rescue-malware-quarantine', 'spool-quarantine', '--target-root={target_root}', '--quarantine-dir={quarantine}']},
        'verify': {'argv': ['rescue-malware-quarantine', 'spool-verify', '--target-root={target_root}', '--quarantine-dir={quarantine}']},
        'rollback': {'kind': 'step', 'step': {'argv': ['rescue-malware-quarantine', 'spool-restore', '--target-root={target_root}', '--quarantine-dir={quarantine}']}},
        'backup': {'required': False}, 'doc': 'docs/printer.md',
    }
    base.update(over)
    return base


errors_of = AR.errors_of


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = rc.load()
        cls.actions = {a: v for a, v in cls.catalog.actions.items() if v['_domain'] == 'printer'}

    def test_shipped_printer_actions(self):
        self.assertEqual({a: (v['risk'], [t['check_id'] for t in v['triggers']]) for a, v in self.actions.items()}, {
            'printer.resume-queue': ('safe', ['printer-state']),
            'printer.accept-jobs': ('safe', ['printer-accepting-jobs']),
            'printer.cancel-stuck-jobs': ('irreversible', ['printer-queued-jobs']),
            'printer.identify': ('safe', []),
            'printer.print-test-page': ('irreversible', []),
            'printer.clean-print-heads': ('irreversible', []),
            'printer.target-quarantine-spool': ('reversible', ['printer-target-spool-stuck'])})

    def test_trigger_statuses(self):
        self.assertEqual(self.actions['printer.resume-queue']['triggers'][0]['status'], ['fail'])
        self.assertEqual(self.actions['printer.accept-jobs']['triggers'][0]['status'], ['fail'])
        self.assertEqual(self.actions['printer.cancel-stuck-jobs']['triggers'][0]['status'], ['warn'])
        self.assertEqual(self.actions['printer.target-quarantine-spool']['triggers'][0]['status'], ['warn'])

    def test_every_printer_action_is_confined_to_one_printer_or_one_spooler(self):
        for aid, act in self.actions.items():
            with self.subTest(action=aid):
                self.assertEqual(act['scope'], 'printer')
                self.assertTrue(aid.startswith('printer.'))
                kinds = [p['type'] for p in act['params']]
                if aid == 'printer.target-quarantine-spool':
                    self.assertEqual(act['platforms'], ['live-linux'])
                    self.assertEqual(act['target_families'], ['windows', 'linuxmint', 'linux-other'])
                    self.assertEqual(kinds, ['target_root', 'state_dir'])
                    self.assertTrue(act['requires_target_rw'] and act['requires_root'])
                    continue
                self.assertEqual(set(act['platforms']), {'live-linux', 'linux-host'})
                self.assertEqual(act['target_families'], ['printer'])
                self.assertEqual(kinds, ['printer_ref', 'bundle_root'])
                self.assertFalse(act.get('requires_target_rw'))

    def test_programs_are_a_closed_list_in_fixed_forms(self):
        allowed = {'cupsenable', 'cupsaccept', 'cancel', 'lp', 'ipptool', 'lpstat', 'rescue-malware-quarantine'}
        self.assertEqual(set(rc.PRINTER_PROGRAMS) | {rc.SPOOL_HELPER}, allowed)
        used = set()
        for aid, act in self.actions.items():
            steps = [act['execute'], act['verify']] + list(act.get('preconditions') or []) + (
                [act['rollback']['step']] if act['rollback']['kind'] == 'step' else [])
            for step in steps:
                used.add(step['argv'][0])
                self.assertIn(step['argv'][0], allowed, aid)
        self.assertEqual(used, allowed)

    def test_the_uri_is_only_the_local_queue_built_by_the_engine(self):
        for aid, act in self.actions.items():
            for step in (act['execute'], act['verify']):
                for element in step['argv']:
                    if '://' in element:
                        self.assertEqual(step['argv'][0], 'ipptool', aid)
                        self.assertEqual(element, 'ipp://localhost/printers/{printer}', aid)
        text = json.dumps(self.actions)
        for word in ('lpadmin', 'lpoptions', 'cupsctl', 'lprm', 'http://', 'https://', 'ipps://', 'socket://', '192.168', 'firmware'):
            self.assertNotIn(word, text)

    def test_consumables_are_irreversible_operator_only_and_use_fixed_files(self):
        for aid, fixed in (('printer.print-test-page', 'scripts/lib/printer/test-page.txt'),
                           ('printer.clean-print-heads', 'scripts/lib/printer/clean-heads.cupscmd')):
            act = self.actions[aid]
            self.assertEqual((act['risk'], act['triggers'], act['rollback']['kind'], act['backup']['required']),
                             ('irreversible', [], 'none', False))
            self.assertEqual(act['execute']['argv'][0], 'lp')
            self.assertEqual(act['execute']['argv'][-1], '{bundle}/' + fixed)
            self.assertTrue((REPO / fixed).is_file())
        self.assertEqual((REPO / 'scripts/lib/printer/clean-heads.cupscmd').read_bytes(), b'#CUPS-COMMAND\nClean all\n')

    def test_shipped_fixed_files_exist_and_carry_no_identifier(self):
        for rel in sorted(rc.BUNDLE_FILES):
            path = REPO / rel
            self.assertTrue(path.is_file(), rel)
            text = path.read_text(encoding='utf-8')
            for word in ('/home/', 'secret', '192.168', 'user:'):
                self.assertNotIn(word, text.lower(), rel)
        for rel in rc.IPP_TEST_FILES:
            text = (REPO / rel).read_text()
            self.assertIn('$uri', text)                       # the printer URI is the only variable
            self.assertNotIn('printer-name', text)
            self.assertNotIn('printer-info', text)

    def test_the_closed_lists_match_the_shipped_files(self):
        shipped = {str(p.relative_to(REPO)) for p in (REPO / 'scripts/lib/ipp').glob('*.test')} - {'scripts/lib/ipp/get-printer-attributes.test'}
        self.assertEqual(shipped, set(rc.IPP_TEST_FILES))
        printer_dir = {str(p.relative_to(REPO)) for p in (REPO / 'scripts/lib/printer').iterdir()}
        self.assertEqual(printer_dir, set(rc.LP_FILES))

    def test_a_valid_example_loads(self):
        self.assertEqual(errors_of(printer_action(), 'printer'), [])
        self.assertEqual(errors_of(spool_action(), 'printer'), [])

    def assertRejected(self, act, needle, domain='printer'):
        errs = errors_of(act, domain)
        self.assertTrue(any(needle in e for e in errs), errs)

    def test_programs_outside_the_closed_list_are_refused(self):
        for program in ('lpadmin', 'lpoptions', 'cupsctl', 'lprm', 'lpr', 'systemctl', 'sh', 'ipptool2', 'rm', 'cupsdisable', 'cupsreject'):
            with self.subTest(program=program):
                self.assertRejected(printer_action(execute={'argv': [program, '{printer}']}), 'not allowed')

    def test_cups_programs_are_printer_domain_only(self):
        act = {'action_id': 'hw.cups-sneak', 'title': 'Sneak', 'title_id': 'Sneak', 'scope': 'hardware.usb',
               'platforms': ['live-linux'], 'risk': 'safe', 'triggers': [], 'execute': {'argv': ['cupsenable', 'x']},
               'verify': {'argv': ['lpstat', '-p']}, 'rollback': {'kind': 'none'}, 'backup': {'required': False},
               'doc': 'docs/printer.md'}
        self.assertRejected(act, 'only allowed in the printer domain', domain='hardware')

    def test_fixed_forms_only(self):
        bad = {
            'cupsenable with an option': ['cupsenable', '--release', '{printer}'],
            'cupsenable without a printer': ['cupsenable'],
            'cupsenable with a literal': ['cupsenable', 'LiteralQueue'],
            'cancel without -a': ['cancel', '{printer}'],
            'cancel with other flags': ['cancel', '-a', '-x', '{printer}'],
            'cancel all queues': ['cancel', '-a'],
            'lpstat -W': ['lpstat', '-W', 'completed', '-o', '{printer}'],
            'lpstat -t': ['lpstat', '-t'],
            'lp without -d': ['lp', '{printer}', '{bundle}/scripts/lib/printer/test-page.txt'],
            'lp with another option': ['lp', '-d', '{printer}', '-o', 'media=A4', '{bundle}/scripts/lib/printer/test-page.txt'],
            'lp copies': ['lp', '-d', '{printer}', '-n', '9', '{bundle}/scripts/lib/printer/test-page.txt'],
            'lp a free title': ['lp', '-d', '{printer}', '-t', 'anything', '{bundle}/scripts/lib/printer/test-page.txt'],
            'lp stdin': ['lp', '-d', '{printer}', '-'],
            'lp a pdf': ['lp', '-d', '{printer}', '{bundle}/scripts/lib/printer/other.pdf'],
            'ipptool without -q': ['ipptool', '-T', '10', 'ipp://localhost/printers/{printer}', '{bundle}/scripts/lib/ipp/verify-queue-ready.test'],
            'ipptool verbose': ['ipptool', '-q', '-T', '10', '-v', 'ipp://localhost/printers/{printer}', '{bundle}/scripts/lib/ipp/verify-queue-ready.test'],
            'ipptool a huge timeout': ['ipptool', '-q', '-T', '999', 'ipp://localhost/printers/{printer}', '{bundle}/scripts/lib/ipp/verify-queue-ready.test'],
            'ipptool another host': ['ipptool', '-q', '-T', '10', 'ipp://printer.example/printers/{printer}', '{bundle}/scripts/lib/ipp/verify-queue-ready.test'],
            'ipptool another path': ['ipptool', '-q', '-T', '10', 'ipp://localhost/admin/{printer}', '{bundle}/scripts/lib/ipp/verify-queue-ready.test'],
            'ipptool another test file': ['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/{printer}', '{bundle}/scripts/lib/ipp/get-printer-attributes.test'],
        }
        for label, argv in bad.items():
            with self.subTest(label):
                errs = errors_of(printer_action(execute={'argv': argv}), 'printer')
                self.assertTrue(errs, label)

    def test_the_helper_is_limited_to_the_spool_commands(self):
        for tail in (['check', '--target-root={target_root}'], ['quarantine', '--target-root={target_root}', '--quarantine-dir={quarantine}'],
                     ['restore', '--target-root={target_root}', '--quarantine-dir={quarantine}'], ['spool-restore'],
                     ['spool-restore', '--target-root={target_root}'], ['list', '--quarantine-dir={quarantine}']):
            with self.subTest(tail=tail):
                self.assertRejected(spool_action(execute={'argv': ['rescue-malware-quarantine'] + tail}), 'rescue-malware-quarantine')
        self.assertRejected(spool_action(execute={'argv': ['rescue-malware-quarantine', 'spool-quarantine', '--target-root={target_root}',
                                                           '--quarantine-dir={quarantine}', '--path=/etc/passwd']}), 'must be exactly')
        self.assertRejected(spool_action(params=[{'name': 'quarantine', 'type': 'state_dir', 'values': ['quarantine']}]), 'target_root')

    def test_a_printer_action_has_one_printer_or_one_spooler_never_both_or_neither(self):
        self.assertRejected(printer_action(params=[{'name': 'bundle', 'type': 'bundle_root'}],
                                           execute={'argv': ['cupsenable', 'x']}), 'never both or neither')
        both = printer_action(params=[{'name': 'printer', 'type': 'printer_ref'}, {'name': 'bundle', 'type': 'bundle_root'},
                                      {'name': 'target_root', 'type': 'target_root'}], platforms=['live-linux'],
                              verify={'argv': ['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/{printer}',
                                               '{bundle}/scripts/lib/ipp/verify-queue-ready.test', '{target_root}/x']})
        self.assertRejected(both, 'never both or neither')
        two = printer_action(params=[{'name': 'printer', 'type': 'printer_ref'}, {'name': 'other', 'type': 'printer_ref'},
                                     {'name': 'bundle', 'type': 'bundle_root'}])
        self.assertRejected(two, 'at most one printer_ref')

    def test_printer_ref_rules(self):
        self.assertRejected(printer_action(params=[{'name': 'printer', 'type': 'printer_ref', 'default': 'x'},
                                                   {'name': 'bundle', 'type': 'bundle_root'}]), 'cannot have a default')
        self.assertRejected(printer_action(platforms=['live-linux', 'linux-host', 'windows-host']), 'exist only on')
        self.assertRejected(printer_action(platforms=['macos-host']), 'exist only on')
        self.assertRejected(printer_action(target_families=['android']), 'target_families')
        self.assertRejected(printer_action(target_families=['linuxmint']), 'target_families ["printer"]')
        self.assertRejected(printer_action(scope='os'), "use scope 'printer'")
        self.assertRejected(printer_action(action_id='android.test-action'), 'prefix')
        # another domain cannot use the types at all
        act = printer_action(action_id='hw.printer-sneak', scope='hardware.usb', target_families=None)
        del act['target_families']
        self.assertRejected(act, 'printer domain', domain='hardware')

    def test_bundle_root_only_names_the_shipped_files(self):
        for path in ('{bundle}/scripts/lib/ipp/other.test', '{bundle}/etc/passwd', '{bundle}/scripts/lib/printer/test-page.txt.bak',
                     '{bundle}/scripts/lib/ipp/../../../etc/passwd'):
            with self.subTest(path=path):
                argv = ['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/{printer}', path]
                self.assertTrue(errors_of(printer_action(verify={'argv': argv}), 'printer'))
        self.assertRejected(printer_action(params=[{'name': 'printer', 'type': 'printer_ref'}, {'name': 'bundle', 'type': 'bundle_root', 'default': '/'}]),
                            'cannot have a default')
        self.assertRejected(printer_action(platforms=['windows-host']), 'exist only on')

    def test_queue_uri_form_needs_a_printer_ref_parameter(self):
        act = printer_action(params=[{'name': 'printer', 'type': 'enum', 'values': ['a']}, {'name': 'bundle', 'type': 'bundle_root'}])
        self.assertRejected(act, 'only allowed for a printer_ref')

    def test_irreversible_has_no_rollback_no_backup_and_no_rw_target(self):
        base = dict(risk='irreversible', execute={'argv': ['cancel', '-a', '{printer}']})
        self.assertEqual(errors_of(printer_action(**base), 'printer'), [])
        self.assertRejected(printer_action(rollback={'kind': 'step', 'step': {'argv': ['cupsenable', '{printer}']}}, **base), 'no rollback')
        self.assertRejected(printer_action(rollback={'kind': 'manual', 'doc': 'docs/printer.md'}, **base), 'no rollback')
        self.assertRejected(printer_action(backup={'required': True, 'what': 'file-copy'}, **base), 'no rollback')

    def test_lp_actions_are_irreversible_and_never_triggered(self):
        lp = {'argv': ['lp', '-d', '{printer}', '-t', 'rescue-test-page', '{bundle}/scripts/lib/printer/test-page.txt']}
        self.assertRejected(printer_action(execute=lp), 'consume paper or ink')
        self.assertRejected(printer_action(execute=lp, risk='reversible', rollback={'kind': 'step', 'step': {'argv': ['cupsenable', '{printer}']}}), 'consume paper')
        self.assertRejected(printer_action(execute=lp, risk='irreversible', triggers=[{'check_id': 'printer-state', 'status': ['fail']}]),
                            'never proposed by a trigger')
        self.assertEqual(errors_of(printer_action(execute=lp, risk='irreversible'), 'printer'), [])

    def test_a_non_printer_irreversible_action_may_have_a_trigger_but_still_asks(self):
        act = self.actions['printer.cancel-stuck-jobs']
        self.assertTrue(act['triggers'])
        self.assertEqual(act['risk'], 'irreversible')

    def test_validate_param_refuses_every_operator_value(self):
        for kind in ('printer_ref', 'bundle_root'):
            for value in ('Queue', 'prn-0', '/', '-d', ''):
                with self.assertRaises(ValueError):
                    rc.validate_param({'name': 'x', 'type': kind}, value)

    def test_render_builds_the_uri_from_one_element(self):
        values = {'printer': 'Queue_1', 'bundle': '/opt/b'}
        argv = rc.render(['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/{printer}', '{bundle}/scripts/lib/ipp/identify-printer.test'], values)
        self.assertEqual(argv, ['ipptool', '-q', '-T', '10', 'ipp://localhost/printers/Queue_1', '/opt/b/scripts/lib/ipp/identify-printer.test'])
        self.assertEqual(rc.render(['lp', '-d', '{printer}'], values), ['lp', '-d', 'Queue_1'])

    def test_scope_printer(self):
        self.assertIn('printer', rc.SCOPE_VALUES)
        self.assertEqual(rc.normalize_scope('printer'), ('printer',))
        self.assertEqual(rc.normalize_scope('os,printer'), ('os', 'printer'))
        self.assertTrue(rc.in_scope(('printer',), 'printer'))
        self.assertTrue(rc.in_scope(('all',), 'printer'))
        self.assertFalse(rc.in_scope(('os', 'malware', 'android'), 'printer'))
        self.assertFalse(rc.in_scope(('printer',), 'os'))
        self.assertEqual(len(rc.SCOPE_VALUES), len(set(rc.SCOPE_VALUES)))

    def test_module_domain_scope_is_printer(self):
        import rescue_modules
        self.assertEqual(rescue_modules.DOMAIN_SCOPE['printer'], 'printer')
        self.assertEqual(rr.domain_of('printer-target-spool-stuck'), 'printer')
        self.assertEqual(rr.domain_of('printer-state'), 'printer')
        self.assertEqual(rr.domain_of('printer-count'), 'printer')
        self.assertEqual(rr.domain_of('usb-device-count'), 'os')
        self.assertEqual(rr.domain_of('android-battery'), 'os')

    def evidence(self, **over):
        ev = {'source_platform': 'linux-mint-xfce-live', 'target_systems': [
            {'ref': 'os-0', 'family': 'windows'}, {'ref': 'os-1', 'family': 'linuxmint'}, {'ref': 'os-2', 'family': 'macos'},
            {'ref': 'prn-0', 'family': 'printer'}, {'ref': 'and-0', 'family': 'android'}],
            'checks': [{'check_id': 'printer-state', 'status': 'fail', 'target_ref': 'prn-0'},
                       {'check_id': 'printer-accepting-jobs', 'status': 'fail', 'target_ref': 'prn-0'},
                       {'check_id': 'printer-queued-jobs', 'status': 'warn', 'target_ref': 'prn-0'},
                       {'check_id': 'printer-target-spool-stuck', 'status': 'warn', 'target_ref': 'os-0'},
                       {'check_id': 'printer-target-spool-stuck', 'status': 'warn', 'target_ref': 'os-1'},
                       {'check_id': 'printer-target-spool-stuck', 'status': 'warn', 'target_ref': 'os-2'},
                       {'check_id': 'printer-state', 'status': 'fail', 'target_ref': 'and-0'}]}
        ev.update(over)
        return ev

    def test_triggered_carries_prn_and_os_refs_and_never_mixes_families(self):
        got = rc.triggered(self.catalog, self.evidence(), ('all',))
        self.assertEqual([(p['action_id'], p['target_ref']) for p in got], [
            ('printer.resume-queue', 'prn-0'), ('printer.accept-jobs', 'prn-0'), ('printer.cancel-stuck-jobs', 'prn-0'),
            ('printer.target-quarantine-spool', 'os-0'), ('printer.target-quarantine-spool', 'os-1')])
        self.assertEqual(len(rc.triggered(self.catalog, self.evidence(), ('printer',))), 5)
        self.assertEqual(rc.triggered(self.catalog, self.evidence(), ('os', 'android')), [])

    def test_applicable_needs_the_family_the_platform_and_the_scope(self):
        fams = {'os-0': 'windows', 'prn-0': 'printer', 'and-0': 'android'}
        act = self.catalog.get('printer.identify')
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), 'prn-0', fams), (True, None))
        self.assertEqual(rc.applicable(act, 'linux-host', ('printer',), 'prn-0', fams), (True, None))
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), 'os-0', fams), (False, 'target-family'))
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), 'and-0', fams), (False, 'target-family'))
        self.assertEqual(rc.applicable(act, 'live-linux', ('all',), None, fams), (False, 'target-family'))
        self.assertEqual(rc.applicable(act, 'windows-host', ('all',), 'prn-0', fams), (False, 'platform'))
        self.assertEqual(rc.applicable(act, 'macos-host', ('all',), 'prn-0', fams), (False, 'platform'))
        self.assertEqual(rc.applicable(act, 'live-linux', ('os',), 'prn-0', fams), (False, 'scope'))
        spool = self.catalog.get('printer.target-quarantine-spool')
        self.assertEqual(rc.applicable(spool, 'live-linux', ('all',), 'os-0', fams), (True, None))
        self.assertEqual(rc.applicable(spool, 'linux-host', ('all',), 'os-0', fams), (False, 'platform'))
        self.assertEqual(rc.applicable(spool, 'live-linux', ('all',), 'prn-0', fams), (False, 'target-family'))

    def test_ai_proposals_never_name_a_consumable(self):
        text = ('```rescue-proposals\n{"proposed_actions":[{"action_id":"printer.resume-queue","target_ref":"prn-0"},'
                '{"action_id":"printer.print-test-page","target_ref":"prn-0"},{"action_id":"printer.clean-print-heads","target_ref":"prn-0"},'
                '{"action_id":"printer.cancel-stuck-jobs","target_ref":"prn-0"},{"action_id":"printer.identify","target_ref":"prn-0"},'
                '{"action_id":"printer.resume-queue","target_ref":"os-0"},{"action_id":"printer.resume-queue","target_ref":"prn-0","printer":"Q"}]}\n```')
        accepted, rejected = rc.parse_ai_proposals(text, self.catalog, self.evidence(), ('all',))
        self.assertEqual([(p['action_id'], p['target_ref']) for p in accepted],
                         [('printer.resume-queue', 'prn-0'), ('printer.cancel-stuck-jobs', 'prn-0'), ('printer.identify', 'prn-0')])
        self.assertEqual(rejected, 4)
        self.assertTrue(all(p['origin'] == 'ai-proposal' for p in accepted))

    def test_prompt_summary_lists_printer_actions_without_argv_and_without_consumables(self):
        rows = rc.prompt_summary(self.catalog, {'source_platform': 'linux-mint-xfce-live'}, ('all',))
        ids = {r['action_id'] for r in rows}
        for aid in ('printer.resume-queue', 'printer.accept-jobs', 'printer.cancel-stuck-jobs', 'printer.identify',
                    'printer.target-quarantine-spool'):
            self.assertIn(aid, ids)
        self.assertNotIn('printer.print-test-page', ids)
        self.assertNotIn('printer.clean-print-heads', ids)
        self.assertNotIn('argv', json.dumps(rows))
        self.assertFalse({r['action_id'] for r in rc.prompt_summary(self.catalog, {'source_platform': 'windows-host'}, ('all',))
                          if r['action_id'].startswith('printer.')})

    def test_os_only_validators_still_reject_printer_refs(self):
        import malware_detections as md
        import target_mount
        self.assertIsNone(md.TARGET_REF_RE.match('prn-0'))
        self.assertIsNone(target_mount.REF_RE.match('prn-0'))

    def test_schemas_accept_printer_ids(self):
        import jsonschema
        journal = json.loads((REPO / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        record = {'journal_version': '1', 'seq': 1, 'prev_sha256': '0' * 64, 'recorded_at': '2026-10-01T08:00:00Z',
                  'run_id': 'rescue-20261001-080000', 'action_id': 'printer.print-test-page', 'catalog_sha256': 'c' * 64,
                  'policy': 'approve-each', 'origin': 'operator', 'risk': 'irreversible', 'stage': 'precondition',
                  'outcome': 'fail', 'target_ref': 'prn-0', 'reason': 'printer-mismatch'}
        validator = jsonschema.Draft202012Validator(journal)
        self.assertEqual(list(validator.iter_errors(record)), [])
        for reason in ('printer-absent', 'printer-mismatch', 'printer-ambiguous'):
            self.assertEqual(list(validator.iter_errors(dict(record, reason=reason))), [])
        for bad in (dict(record, reason='printer-removed'), dict(record, target_ref='prn-8'), dict(record, risk='consumable'),
                    dict(record, params={'printer': 'Queue Name'}), dict(record, action_id='printer.Bad_Id')):
            self.assertTrue(list(validator.iter_errors(bad)), bad)
        evidence = json.loads((REPO / 'rescue-ai/v1/rescue-evidence.schema.json').read_text())
        item = evidence['properties']['repair_proposals']['items']
        self.assertIn('printer', evidence['properties']['scope']['items']['enum'])
        self.assertRegex('printer.resume-queue', item['properties']['action_id']['pattern'])
        self.assertRegex('prn-0', item['properties']['target_ref']['pattern'])
        self.assertIsNone(re.match(item['properties']['target_ref']['pattern'], 'prn-9'))
        catalog = json.loads((REPO / 'rescue-ai/v1/repair-catalog.schema.json').read_text())
        self.assertIn('printer', catalog['properties']['domain']['enum'])
        self.assertIn('irreversible', catalog['$defs']['action']['properties']['risk']['enum'])
        self.assertIn('printer_ref', catalog['$defs']['param']['properties']['type']['enum'])
        self.assertIn('bundle_root', catalog['$defs']['param']['properties']['type']['enum'])


# ----------------------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------------------
class EngineTests(PrinterRepairCase):
    def test_evidence_proposes_the_triggered_actions_for_the_printer(self):
        self.assertEqual(self.ev['scope'], ['printer'])
        self.assertEqual(self.ev['repair_policy'], 'approve-each')
        self.assertEqual([(p['action_id'], p['origin'], p['target_ref']) for p in self.ev['repair_proposals']],
                         [('printer.resume-queue', 'catalog-trigger', 'prn-0'), ('printer.accept-jobs', 'catalog-trigger', 'prn-0'),
                          ('printer.cancel-stuck-jobs', 'catalog-trigger', 'prn-0')])
        check = subprocess.run([sys.executable, str(SCRIPTS / 'validate-evidence.py'), str(self.evidence)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_resume_queue_runs_cupsenable_on_the_resolved_queue_and_is_verified(self):
        proc = self.run_one('printer.resume-queue')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('printer.resume-queue'),
                         [('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'), ('execute', 'ok', None), ('verify', 'ok', None)])
        self.assertEqual(self.action_calls(), [
            ('cupsenable', [QUEUE]),
            ('ipptool', ['-q', '-T', '10', self.uri(), self.bundle_file('scripts/lib/ipp/verify-queue-ready.test')])])
        self.assertEqual(self.queue_state()['state'], 'idle')
        self.assertIn('verified', proc.stdout)

    def test_accept_jobs(self):
        proc = self.run_one('printer.accept-jobs')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls(), [
            ('cupsaccept', [QUEUE]),
            ('ipptool', ['-q', '-T', '10', self.uri(), self.bundle_file('scripts/lib/ipp/verify-accepting.test')])])
        self.assertTrue(self.queue_state()['accepting'])
        self.assertEqual(self.stages('printer.accept-jobs')[-1], ('verify', 'ok', None))

    def test_cancel_stuck_jobs(self):
        proc = self.run_one('printer.cancel-stuck-jobs')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls(), [
            ('cancel', ['-a', QUEUE]),
            ('ipptool', ['-q', '-T', '10', self.uri(), self.bundle_file('scripts/lib/ipp/verify-no-jobs.test')])])
        self.assertEqual(self.queue_state()['jobs'], 0)
        self.assertEqual([s[:2] for s in self.stages('printer.cancel-stuck-jobs')],
                         [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        records = [r for r in read_journal(self.journal) if r['action_id'] == 'printer.cancel-stuck-jobs']
        self.assertTrue(all(r['risk'] == 'irreversible' for r in records))

    def test_identify(self):
        self.rebuild(queues={QUEUE: queue()})
        proc = self.run_one('printer.identify')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls(), [
            ('ipptool', ['-q', '-T', '10', self.uri(), self.bundle_file('scripts/lib/ipp/identify-printer.test')]),
            ('lpstat', ['-p', QUEUE])])
        self.assertEqual(self.stages('printer.identify')[-1], ('verify', 'ok', None))

    def test_identify_not_supported_is_a_failed_step_and_nothing_else(self):
        self.rebuild(queues={QUEUE: queue()})
        self.set_state(identify=False)
        proc = self.run_one('printer.identify')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('printer.identify')[2:], [('execute', 'fail', 'exit-code')])
        self.assertIn('failed', proc.stdout)
        self.assertEqual([t for t, _ in self.action_calls()], ['ipptool'])

    def test_print_test_page_prints_the_fixed_file(self):
        self.rebuild(queues={QUEUE: queue()})
        proc = self.run_one('printer.print-test-page')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls()[0], ('lp', ['-d', QUEUE, '-t', 'rescue-test-page', self.bundle_file('scripts/lib/printer/test-page.txt')]))
        self.assertEqual(self.action_calls()[1][0], 'ipptool')
        self.assertEqual(json.loads((self.bin / 'state.json').read_text())['printed'], ['test-page.txt'])
        self.assertEqual(self.stages('printer.print-test-page')[-1], ('verify', 'ok', None))

    def test_clean_print_heads_sends_the_fixed_cups_command_file_raw(self):
        self.rebuild(queues={QUEUE: queue()})
        proc = self.run_one('printer.clean-print-heads')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls()[0], ('lp', ['-d', QUEUE, '-o', 'raw', self.bundle_file('scripts/lib/printer/clean-heads.cupscmd')]))
        self.assertEqual(json.loads((self.bin / 'state.json').read_text())['printed'], ['clean-heads.cupscmd'])

    def test_failed_verify_is_a_failure_and_there_is_nothing_to_roll_back(self):
        self.set_state(enable_noop=True)
        proc = self.run_one('printer.resume-queue')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual([s[:2] for s in self.stages('printer.resume-queue')],
                         [('proposed', 'ok'), ('approval', 'ok'), ('execute', 'ok'), ('verify', 'fail')])
        self.assertIn('failed', proc.stdout)

    def test_failed_execute_is_journaled(self):
        self.set_state(fail={'cupsenable': 1})
        proc = self.run_one('printer.resume-queue')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('printer.resume-queue')[2:], [('execute', 'fail', 'exit-code')])
        self.assertNotIn('ipptool', [t for t, _ in self.action_calls()])
        self.assert_private(proc.stdout + proc.stderr + self.journal_text())

    def test_the_queue_name_is_never_taken_from_the_command_line(self):
        proc = self.run_one('printer.resume-queue', '--param', 'printer.resume-queue.printer=EvilQueue',
                            '--param', 'printer.resume-queue.bundle=/etc')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls()[0], ('cupsenable', [QUEUE]))
        self.assertNotIn('EvilQueue', json.dumps(self.calls()))

    def test_root_actions_go_through_sudo_and_the_others_do_not(self):
        self.rebuild(queues={QUEUE: queue(state='stopped', accepting=False, jobs=1)})
        for aid in ('printer.resume-queue', 'printer.accept-jobs', 'printer.cancel-stuck-jobs'):
            self.assertEqual(self.run_one(aid).returncode, 0)
        self.run_one('printer.identify')
        sudo = [c['argv'][2:3] for c in self.calls() if c['tool'] == 'sudo']
        if ROOT_USER:
            self.assertEqual(sudo, [])
            return
        # requires_root applies to every step of the action (its verify ipptool too); identify, lp and lpstat run as the user
        self.assertEqual([Path(a[0]).name for a in sudo], ['cupsenable', 'ipptool', 'cupsaccept', 'ipptool', 'cancel', 'ipptool'])
        self.assertTrue(all(c['argv'][:2] == ['-n', '--'] for c in self.calls() if c['tool'] == 'sudo'))

    def test_child_environment_has_no_cups_server_and_no_api_key(self):
        proc = self.run_one('printer.resume-queue', OPENCODE_GO_API_KEY=HR.HL.DUMMY_KEY, CUPS_SERVER='evil.example:631')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        envs = [c['env'] for c in self.calls() if c['tool'] in ('cupsenable', 'ipptool')]
        self.assertTrue(envs)
        for env in envs:
            self.assertEqual((env['CUPS_SERVER'], env['OPENCODE_GO_API_KEY']), (None, None))
        self.assertNotIn(HR.HL.DUMMY_KEY, proc.stdout + proc.stderr + self.journal_text())

    # ---------------------------------------------------------------- privacy
    def test_nothing_private_reaches_the_screen_the_journal_or_a_report(self):
        proc = self.run_one('printer.cancel-stuck-jobs')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assert_private(proc.stdout + proc.stderr)
        self.assert_private(self.journal_text())
        for record in read_journal(self.journal):
            self.assertNotIn('params', record)
            self.assertNotIn('argv', record)
            self.assertEqual(record['target_ref'], 'prn-0')
        chain = subprocess.run([sys.executable, str(REPAIR), '--verify-journal', str(self.journal)], capture_output=True, text=True)
        self.assertEqual(chain.returncode, 0, chain.stdout)

    def test_the_output_of_a_printer_tool_is_not_echoed(self):
        self.rebuild(queues={QUEUE: queue()})
        proc = self.run_one('printer.print-test-page')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('output not shown', proc.stdout)
        self.assertNotIn('request id is', proc.stdout + proc.stderr)
        self.assertNotIn(QUEUE, proc.stdout + proc.stderr)
        records = [r for r in read_journal(self.journal) if r['stage'] == 'execute']
        self.assertTrue(records[0]['output_bytes'] > 0 and re.match('^[a-f0-9]{64}$', records[0]['output_sha256']))

    def test_a_failure_output_naming_the_queue_is_not_echoed_either(self):
        self.set_state(fail={'cupsenable': 1})
        proc = self.run_one('printer.resume-queue')
        self.assertNotIn(QUEUE, proc.stdout + proc.stderr)
        self.assertIn('output not shown', proc.stdout)

    def test_other_domains_still_echo_their_output(self):
        engine = HR.load_engine()
        shown = []
        original = engine.say
        engine.say = shown.append
        try:
            e = engine.Engine.__new__(engine.Engine)
            e.show({'params': []}, {'output': b'line one\n'})
            e.show({'params': [{'name': 'printer', 'type': 'printer_ref'}]}, {'output': b'secret queue\n'})
        finally:
            engine.say = original
        self.assertEqual(shown[0], '    | line one')
        self.assertIn('output not shown', shown[1])
        self.assertNotIn('secret', shown[1])

    # ---------------------------------------------------------------- policy
    def test_auto_safe_runs_the_triggered_safe_actions_only(self):
        proc = self.engine('--policy', 'auto-safe', '--scope', 'printer')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('printer.resume-queue'),
                         [('proposed', 'ok', None), ('approval', 'ok', 'auto-safe'), ('execute', 'ok', None), ('verify', 'ok', None)])
        self.assertEqual(self.stages('printer.accept-jobs'),
                         [('proposed', 'ok', None), ('approval', 'ok', 'auto-safe'), ('execute', 'ok', None), ('verify', 'ok', None)])
        # irreversible: still needs an approval, and nothing is cancelled
        self.assertEqual(self.stages('printer.cancel-stuck-jobs'), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.queue_state()['jobs'], 2)
        self.assertNotIn('cancel', [t for t, _ in self.action_calls()])

    def test_auto_safe_never_runs_operator_selected_or_consumable_actions(self):
        self.rebuild(queues={QUEUE: queue()})
        for aid in ('printer.print-test-page', 'printer.clean-print-heads', 'printer.identify'):
            with self.subTest(aid=aid):
                if self.journal.exists():
                    self.journal.unlink()
                proc = self.engine('--policy', 'auto-safe', '--select', aid + ':prn-0')
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(self.stages(aid), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.action_calls(), [])
        self.assertNotIn('printed', json.loads((self.bin / 'state.json').read_text()))

    def test_consumables_are_never_proposed_by_a_trigger(self):
        proc = self.engine('--list', '--scope', 'printer')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('printer.cancel-stuck-jobs', proc.stdout)
        self.assertNotIn('printer.print-test-page', proc.stdout)
        self.assertNotIn('printer.clean-print-heads', proc.stdout)
        self.assertNotIn('printer.identify', proc.stdout)

    def test_an_ai_proposed_consumable_is_rejected(self):
        analysis = self.tmp / 'analysis.md'
        analysis.write_text('```rescue-proposals\n{"proposed_actions":[{"action_id":"printer.print-test-page","target_ref":"prn-0"},'
                            '{"action_id":"printer.identify","target_ref":"prn-0"}]}\n```\n')
        proc = self.engine('--list', '--scope', 'printer', '--analysis', str(analysis))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('1 AI proposal(s) rejected', proc.stderr)
        self.assertIn('printer.identify', proc.stdout)
        self.assertNotIn('printer.print-test-page', proc.stdout)

    def test_detect_only_and_list_never_touch_cups(self):
        for args in (['--policy', 'detect-only'], ['--list']):
            with self.subTest(args=args):
                proc = self.engine(*args, '--scope', 'printer', '--select', 'printer.print-test-page:prn-0')
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn('printer.print-test-page', proc.stdout)
                self.assertEqual(self.calls(), [])
        self.assertEqual({r['stage'] for r in read_journal(self.journal)}, {'proposed', 'approval'})

    def test_without_a_terminal_and_without_approve_nothing_runs(self):
        proc = self.engine('--select', 'printer.print-test-page:prn-0', '--scope', 'printer')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages('printer.print-test-page'), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        self.assertEqual(self.action_calls(), [])

    def pty(self, aid, answers, *extra, ref='prn-0'):
        argv = [sys.executable, str(REPAIR), '--evidence', str(self.evidence), '--journal', str(self.journal),
                '--select', '%s:%s' % (aid, ref), '--scope', 'printer'] + list(extra)
        return HR.run_pty(argv, self.env(), self.tmp, answers)

    def test_a_consumable_asks_every_time_and_the_default_is_no(self):
        self.rebuild(queues={QUEUE: queue()})
        for answer in ('', 'n', 'maybe'):
            with self.subTest(answer=answer):
                code, out = self.pty('printer.print-test-page', [answer])
                self.assertEqual(code, 0, out)
                self.assertIn('Jalankan? / Run?', out)
                self.assertIn('PERINGATAN / WARNING', out)
                self.assertIn('paper or ink', out)
                self.assertEqual(self.action_calls(), [])
        self.assertEqual(self.stages('printer.print-test-page')[-1], ('approval', 'declined', 'operator-declined'))

    def test_the_card_shows_placeholders_never_the_queue(self):
        self.rebuild(queues={QUEUE: queue()})
        code, out = self.pty('printer.print-test-page', ['ya'])
        self.assertEqual(code, 0, out)
        self.assertIn('target: prn-0', out)
        self.assertIn('execute: lp -d <printer prn-0> -t rescue-test-page <bundle>/scripts/lib/printer/test-page.txt', out)
        self.assertIn('verify:  ipptool -q -T 10 ipp://localhost/printers/<printer prn-0> <bundle>/scripts/lib/ipp/verify-queue-ready.test', out)
        self.assertIn('risk=irreversible', out)
        self.assertIn('rollback: none', out)
        self.assert_private(out)
        self.assertEqual(self.action_calls()[0][0], 'lp')
        self.assertEqual(self.stages('printer.print-test-page')[1], ('approval', 'ok', 'operator-approved'))

    def test_auto_safe_still_asks_for_a_triggered_irreversible_action(self):
        code, out = self.pty('printer.cancel-stuck-jobs', [''], '--policy', 'auto-safe')
        self.assertEqual(code, 0, out)
        self.assertIn('Jalankan? / Run?', out)
        self.assertIn('printer.resume-queue', out)        # the safe ones ran without a prompt
        self.assertEqual(self.queue_state()['jobs'], 2)
        self.assertEqual(self.stages('printer.cancel-stuck-jobs')[-1], ('approval', 'declined', 'operator-declined'))
        self.assertEqual(self.stages('printer.resume-queue')[1], ('approval', 'ok', 'auto-safe'))

    # ---------------------------------------------------------------- refusals
    def assert_refused(self, proc, reason, aid='printer.identify'):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.stages(aid), [('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'), ('precondition', 'fail', reason)])
        self.assertEqual(self.action_calls(), [], 'nothing may be run for a refused printer')
        record = [r for r in read_journal(self.journal) if r['stage'] == 'precondition'][0]
        self.assertEqual((record['outcome'], record['reason'], record['target_ref']), ('fail', reason, 'prn-0'))
        self.assertIn('skipped', proc.stdout)
        self.assert_private(self.journal_text() + proc.stdout + proc.stderr)

    def test_refused_when_the_printer_is_gone(self):
        self.rebuild(queues={QUEUE: queue()})
        gone = self.new_machine(with_printer=False)
        self.set_state(queues={})
        self.assert_refused(self.run_one('printer.identify', machine=gone), 'printer-absent')

    def test_refused_when_cups_has_no_queue_for_the_printer(self):
        self.set_state(queues={})
        proc = self.run_one('printer.identify')
        self.assert_refused(proc, 'printer-absent')
        self.assertIn('no CUPS queue', proc.stderr)

    def test_refused_when_cups_is_not_running(self):
        self.set_state(running=False)
        self.assert_refused(self.run_one('printer.identify'), 'printer-absent')

    def test_refused_when_the_tools_are_not_installed(self):
        (self.tmp / 'nobin').mkdir()
        gone = self.new_machine(with_printer=False)
        self.assert_refused(self.run_one('printer.identify', bin_dir=self.tmp / 'nobin', machine=gone), 'printer-absent')

    def test_refused_when_another_printer_sits_in_the_port(self):
        other = self.new_machine(serial='OTHERSERIAL000111')
        self.set_state(queues={'OtherQ': queue(uri='usb://Other/Printer?serial=OTHERSERIAL000111')})
        proc = self.run_one('printer.identify', machine=other)
        self.assert_refused(proc, 'printer-mismatch')
        self.assertNotIn('OTHERSERIAL000111', proc.stdout + proc.stderr + self.journal_text())

    def test_refused_when_two_printers_share_the_identity(self):
        twin = self.new_machine(second_serial=SERIAL)
        self.assert_refused(self.run_one('printer.identify', machine=twin), 'printer-ambiguous')

    def test_refused_when_the_evidence_has_no_opaque_id(self):
        ev = json.loads(self.evidence.read_text())
        del ev['target_systems'][0]['opaque_id']
        bare = self.tmp / 'bare.json'
        bare.write_text(json.dumps(ev))
        self.assert_refused(self.run_one('printer.identify', evidence=bare), 'printer-mismatch')

    def test_refused_when_the_evidence_opaque_id_was_edited(self):
        ev = json.loads(self.evidence.read_text())
        ev['target_systems'][0]['opaque_id'] = 'target-0123456789abcdef'
        edited = self.tmp / 'edited.json'
        edited.write_text(json.dumps(ev))
        self.assert_refused(self.run_one('printer.identify', evidence=edited), 'printer-mismatch')

    def test_a_renumbered_printer_is_not_silently_substituted(self):
        # a second printer now sorts first (port 1-2): prn-0 is that one, whose identity differs from the evidence
        m = self.new_machine()
        m.add_device('1-2', '04a9', '1865', ['07/01/02'], serial='CANONSERIAL98765')
        self.set_state(queues={QUEUE: queue(state='idle'), 'CanonQ': queue(uri='usb://Canon/Model?serial=CANONSERIAL98765')})
        self.assert_refused(self.run_one('printer.identify', machine=m), 'printer-mismatch')

    def test_select_needs_a_printer_target(self):
        proc = self.engine('--select', 'printer.identify:os-0', '--scope', 'printer')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn('does not apply here', proc.stderr)
        proc = self.engine('--select', 'printer.identify', '--scope', 'printer')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        proc = self.engine('--select', 'printer.identify:prn-0', '--scope', 'os')
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_printer_actions_do_not_run_on_a_windows_or_macos_host_evidence(self):
        ev = json.loads(self.evidence.read_text())
        for platform in ('windows-host', 'macos-host'):
            ev['source_platform'] = platform
            other = self.tmp / (platform + '.json')
            other.write_text(json.dumps(ev))
            proc = self.engine('--select', 'printer.identify:prn-0', '--scope', 'printer', evidence=other)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.calls(), [])

    def test_linux_host_platform_runs(self):
        self.rebuild(queues={QUEUE: queue()})
        ev = json.loads(self.evidence.read_text())
        ev['source_platform'] = 'linux-host'
        host = self.tmp / 'host.json'
        host.write_text(json.dumps(ev))
        proc = self.run_one('printer.identify', evidence=host)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('platform=linux-host', proc.stdout)
        self.assertEqual(self.stages('printer.identify')[-1], ('verify', 'ok', None))


class NetworkEngineTests(PrinterRepairCase):
    """A CUPS queue for a network printer, and a printer found only by mDNS (docs/printer.md: opt-in per run)."""

    queues = {NET_QUEUE: queue(uri=NET_URI, state='idle')}

    def build(self):
        self.machine = None
        super().build()

    def new_machine(self, **kw):
        return super().new_machine(with_printer=False)

    def test_a_network_queue_is_a_target_only_with_printer_network(self):
        self.assertEqual([(t['ref'], t['family'], t['detection']) for t in self.ev['target_systems']], [('prn-0', 'printer', 'network-ipp')])
        proc = self.run_one('printer.identify')
        self.assertEqual(self.stages('printer.identify'), [('proposed', 'ok', None), ('approval', 'ok', 'cli-approved'), ('precondition', 'fail', 'printer-absent')])
        self.assertEqual(self.action_calls(), [])
        self.assertIn('--printer-network', proc.stderr)
        self.assert_private(proc.stdout + proc.stderr + self.journal_text())

    def test_with_printer_network_the_same_queue_is_addressed(self):
        proc = self.run_one('printer.identify', '--printer-network')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.action_calls()[0], ('ipptool', ['-q', '-T', '10', self.uri(NET_QUEUE),
                                                              self.bundle_file('scripts/lib/ipp/identify-printer.test')]))
        self.assertEqual(self.stages('printer.identify')[-1], ('verify', 'ok', None))
        self.assert_private(proc.stdout + proc.stderr + self.journal_text())

    def test_printer_network_is_a_flag_not_a_default(self):
        proc = self.engine('--help')
        self.assertIn('--printer-network', proc.stdout)
        avahi = [c for c in self.calls() if c['tool'] == 'avahi-browse']
        self.assertEqual(avahi, [])
        self.run_one('printer.identify')
        self.assertEqual([c for c in self.calls() if c['tool'] == 'avahi-browse'], [], 'no mDNS without the opt-in')
        self.run_one('printer.identify', '--printer-network')
        self.assertEqual(sorted(tuple(c['argv']) for c in self.calls() if c['tool'] == 'avahi-browse'),
                         [('-rtp', '_ipp._tcp'), ('-rtp', '_ipps._tcp')])


class MdnsOnlyEngineTests(PrinterRepairCase):
    network = True
    queues = {}
    AVAHI = ('=;eth0;IPv4;SecretMDNS\\032Printer;_ipp._tcp;local;secret-printer.local;192.168.77.88;631;'
             '"txtvers=1" "rp=ipp/print" "ty=Canon Secret LaserJet"\n')

    def new_machine(self, **kw):
        return super().new_machine(with_printer=False)

    def build(self):
        self.machine = None
        self.state_pre = {'avahi': {'_ipp._tcp': self.AVAHI, '_ipps._tcp': ''}}
        super().build()

    def write_state(self):
        if hasattr(self, 'state_pre'):
            self.state.update(self.state_pre)
            self.state['ipp'] = {NET_URI: queue(uri=NET_URI, state='idle')}
        super().write_state()

    def test_a_printer_found_only_by_mdns_has_no_queue_to_address(self):
        self.assertEqual([t['family'] for t in self.ev['target_systems']], ['printer'])
        proc = self.run_one('printer.identify', '--printer-network')
        self.assertEqual(self.stages('printer.identify')[-1], ('precondition', 'fail', 'printer-absent'))
        self.assertEqual(self.action_calls(), [])
        self.assertIn('no CUPS queue', proc.stderr)
        self.assert_private(proc.stdout + proc.stderr + self.journal_text())


# ----------------------------------------------------------------------------------------
# Target spool quarantine (the helper and the engine)
# ----------------------------------------------------------------------------------------
def touch(path, data=b'', mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def run_helper(*args):
    return subprocess.run([sys.executable, str(HELPER)] + [str(a) for a in args], capture_output=True, text=True, timeout=60)


class SpoolHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix='spool-helper-')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.q = self.tmp / 'quarantine'
        self.win = self.tmp / 'win'
        self.files = {
            'Windows/System32/spool/PRINTERS/00001.SPL': b'spool-one' * 100,
            'Windows/System32/spool/PRINTERS/00001.SHD': b'shadow-one',
            'Windows/System32/spool/PRINTERS/00002.spl': b'spool-two',
        }
        for rel, data in self.files.items():
            touch(self.win / rel, data, 0o640)
        self.keep = {'Windows/System32/spool/PRINTERS/notes.txt': b'not a job', 'Windows/System32/spool/drivers/x.dll': b'driver',
                     'Users/secretuser/Documents/doc.docx': b'document'}
        for rel, data in self.keep.items():
            touch(self.win / rel, data)

    def helper(self, command, root=None, quarantine=True):
        args = [command, '--target-root=%s' % (root or self.win)]
        if quarantine:
            args.append('--quarantine-dir=%s' % self.q)
        return run_helper(*args)

    def manifest(self):
        return qs.events(str(self.q))

    def test_round_trip_on_a_windows_tree(self):
        check = self.helper('spool-check', quarantine=False)
        self.assertEqual((check.returncode, check.stdout.strip()), (0, 'ok: 3 stuck spool file(s)'), check.stderr)
        moved = self.helper('spool-quarantine')
        self.assertEqual(moved.returncode, 0, moved.stderr)
        self.assertRegex(moved.stdout, r'^quarantined 3 spool file\(s\) batch s-[a-f0-9]{12}$')
        for rel in self.files:
            self.assertFalse((self.win / rel).exists(), rel)
        for rel in self.keep:
            self.assertEqual((self.win / rel).read_bytes(), self.keep[rel], rel)      # nothing else is touched
        events = self.manifest()
        self.assertEqual(len(events), 3)
        self.assertEqual({e['kind'] for e in events}, {'spool'})
        self.assertEqual(len({e['batch'] for e in events}), 1)
        self.assertTrue(all(qs.BATCH_RE.match(e['batch']) and e['root_kind'] == 'target' for e in events))
        self.assertEqual({e['rel'] for e in events}, set(self.files))
        verified = self.helper('spool-verify')
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertRegex(verified.stdout, r'^verified batch s-[a-f0-9]{12}: 3 spool file\(s\)$')
        self.assertEqual(qs.count_active(str(self.q)), 0, 'spool files are not malware')
        self.assertEqual(len(qs.active(str(self.q))), 3)
        back = self.helper('spool-restore')
        self.assertEqual(back.returncode, 0, back.stderr)
        self.assertRegex(back.stdout, r'^restored 3 spool file\(s\) of batch s-[a-f0-9]{12}$')
        for rel, data in self.files.items():
            self.assertEqual((self.win / rel).read_bytes(), data, rel)
            self.assertEqual(stat.S_IMODE((self.win / rel).stat().st_mode), 0o640)
        self.assertEqual(qs.active(str(self.q)), [])
        again = self.helper('spool-restore')
        self.assertEqual((again.returncode, again.stdout.strip()), (0, 'nothing to restore: no active spool batch'))

    def test_linux_cups_tree(self):
        lin = self.tmp / 'lin'
        jobs = {'var/spool/cups/c00001': b'control', 'var/spool/cups/d00001-001': b'data', 'var/spool/cups/c123456': b'control2'}
        for rel, data in jobs.items():
            touch(lin / rel, data)
        touch(lin / 'var/spool/cups/tmp/other', b'not a job')
        touch(lin / 'var/spool/cups/notajob', b'not a job')
        self.assertEqual(self.helper('spool-quarantine', lin).returncode, 0)
        self.assertEqual(sorted(os.listdir(lin / 'var/spool/cups')), ['notajob', 'tmp'])
        self.assertEqual(self.helper('spool-verify', lin).returncode, 0)
        self.assertEqual(self.helper('spool-restore', lin).returncode, 0)
        for rel, data in jobs.items():
            self.assertEqual((lin / rel).read_bytes(), data)

    def test_only_the_files_the_detection_counts_are_listed(self):
        lin = self.tmp / 'lin2'
        touch(lin / 'var/spool/cups/c00001')
        touch(lin / 'Windows/System32/spool/PRINTERS/9.shd')
        self.assertEqual(printer.list_spool_files(str(lin)), ['Windows/System32/spool/PRINTERS/9.shd', 'var/spool/cups/c00001'])
        root = self.win
        self.assertEqual(len(printer.list_spool_files(str(root))), 3)
        self.assertEqual(len(printer.list_spool_files(str(root), limit=2)), 2)
        # the module counts exactly these (one source of truth)
        ctx = __import__('rescue_modules').Context(mode='live')
        got = {c['check_id']: c for c in printer.collect_offline_target(ctx, str(root), {'family': 'windows'})}
        self.assertEqual(got['printer-target-spool-stuck']['number'], 3)

    def test_nothing_to_move(self):
        empty = self.tmp / 'empty'
        (empty / 'Windows/System32/spool/PRINTERS').mkdir(parents=True)
        for command in ('spool-check', 'spool-quarantine'):
            proc = self.helper(command, empty)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn('no stuck spool file found', proc.stderr)
        self.assertEqual(self.manifest(), [])

    def test_the_running_system_is_never_touched(self):
        for command in ('spool-check', 'spool-quarantine', 'spool-verify', 'spool-restore'):
            proc = self.helper(command, '/')
            self.assertEqual(proc.returncode, 1, command)
            self.assertIn('below another directory', proc.stderr)
        self.assertEqual(run_helper('spool-check').returncode, 1)
        self.assertEqual(run_helper('spool-check', '--target-root=relative/path').returncode, 1)
        self.assertEqual(run_helper('spool-quarantine', '--target-root=%s' % self.win).returncode, 2)          # needs --quarantine-dir

    def test_no_file_name_or_path_can_be_given(self):
        proc = run_helper('spool-quarantine', '--target-root=%s' % self.win, '--quarantine-dir=%s' % self.q, '--path=%s/Users/secretuser/Documents/doc.docx' % self.win)
        self.assertEqual(proc.returncode, 0, proc.stderr)               # accepted by the parser but ignored: only the spool files move
        self.assertTrue((self.win / 'Users/secretuser/Documents/doc.docx').exists())
        self.assertEqual(len(self.manifest()), 3)

    def test_symlinks_are_never_followed_or_moved(self):
        outside = touch(self.tmp / 'outside/x.SPL', b'outside')
        root = self.tmp / 'linked'
        (root / 'Windows/System32/spool').mkdir(parents=True)
        os.symlink(self.tmp / 'outside', root / 'Windows/System32/spool/PRINTERS')
        self.assertEqual(self.helper('spool-quarantine', root).returncode, 1)
        self.assertTrue(outside.exists())
        root2 = self.tmp / 'linked2'
        (root2 / 'Windows/System32/spool/PRINTERS').mkdir(parents=True)
        os.symlink(outside, root2 / 'Windows/System32/spool/PRINTERS/y.SPL')
        touch(root2 / 'Windows/System32/spool/PRINTERS/z.SPL', b'real')
        self.assertEqual(self.helper('spool-quarantine', root2).returncode, 0)
        self.assertTrue(outside.exists())
        self.assertTrue(os.path.islink(root2 / 'Windows/System32/spool/PRINTERS/y.SPL'))
        self.assertEqual([e['rel'] for e in self.manifest()], ['Windows/System32/spool/PRINTERS/z.SPL'])

    def test_restore_never_overwrites_a_file(self):
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        target = self.win / 'Windows/System32/spool/PRINTERS/00001.SPL'
        touch(target, b'a new job')
        proc = self.helper('spool-restore')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('refusing to overwrite', proc.stderr)
        self.assertEqual(target.read_bytes(), b'a new job')

    def test_verify_fails_while_a_spool_file_remains_or_a_copy_is_damaged(self):
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        touch(self.win / 'Windows/System32/spool/PRINTERS/00099.SPL', b'new')
        proc = self.helper('spool-verify')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('still in the spool directory', proc.stderr)
        (self.win / 'Windows/System32/spool/PRINTERS/00099.SPL').unlink()
        blob = next((self.q / qs.BLOBS).glob('q-*'))
        blob.write_bytes(b'tampered')
        proc = self.helper('spool-verify')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('sha256', proc.stderr)
        proc = self.helper('spool-restore')
        self.assertEqual(proc.returncode, 1)

    def test_a_batch_from_another_mount_is_refused(self):
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        manifest = self.q / qs.MANIFEST
        lines = [json.loads(line) for line in manifest.read_text().splitlines()]
        for line in lines:
            line['dev'] = line['dev'] + 1
        manifest.write_text(''.join(json.dumps(line) + '\n' for line in lines))
        for command in ('spool-verify', 'spool-restore'):
            proc = self.helper(command)
            self.assertEqual(proc.returncode, 1)
            self.assertIn('different target mount', proc.stderr)
        self.assertFalse((self.win / 'Windows/System32/spool/PRINTERS/00001.SPL').exists())

    @unittest.skipIf(ROOT_USER, 'file permissions do not stop root')
    def test_a_failure_half_way_leaves_a_restorable_batch(self):
        spool = self.win / 'Windows/System32/spool/PRINTERS'
        (spool / '00002.spl').chmod(0)             # unreadable: the second file in sorted order cannot be copied
        proc = self.helper('spool-quarantine')
        (spool / '00002.spl').chmod(0o644)
        self.assertEqual(proc.returncode, 1)
        self.assertIn('stopped after', proc.stderr)
        self.assertTrue((spool / '00002.spl').exists())
        moved = [e['rel'] for e in self.manifest()]
        self.assertTrue(moved and all(not (self.win / rel).exists() for rel in moved))
        back = self.helper('spool-restore')
        self.assertEqual(back.returncode, 0, back.stderr)
        for rel, data in self.files.items():
            self.assertEqual((self.win / rel).read_bytes(), data)

    def test_second_batch_restores_the_latest_one_only(self):
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        first = {e['batch'] for e in self.manifest()}
        touch(self.win / 'Windows/System32/spool/PRINTERS/00007.SPL', b'newer')
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        second = {e['batch'] for e in self.manifest()} - first
        self.assertEqual(len(second), 1)
        back = self.helper('spool-restore')
        self.assertEqual(back.returncode, 0, back.stderr)
        self.assertEqual(back.stdout.split()[1:3], ['1', 'spool'])
        self.assertTrue((self.win / 'Windows/System32/spool/PRINTERS/00007.SPL').exists())
        self.assertFalse((self.win / 'Windows/System32/spool/PRINTERS/00001.SPL').exists())
        self.assertEqual(len(qs.active(str(self.q))), 3)

    def test_the_quarantine_directory_may_not_be_inside_the_target(self):
        proc = run_helper('spool-quarantine', '--target-root=%s' % self.win, '--quarantine-dir=%s' % (self.win / 'q'))
        self.assertEqual(proc.returncode, 1)
        self.assertIn('inside the target', proc.stderr)

    def test_the_old_commands_still_work_and_malware_counts_are_unchanged(self):
        victim = touch(self.win / 'Users/secretuser/bad.exe', b'bad bytes')
        proc = run_helper('quarantine', '--target-root=%s' % self.win, '--quarantine-dir=%s' % self.q, '--path=%s' % victim)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.helper('spool-quarantine').returncode, 0)
        self.assertEqual(qs.count_active(str(self.q)), 1)
        self.assertEqual(len(qs.active(str(self.q))), 4)
        proc = run_helper('restore', '--target-root=%s' % self.win, '--quarantine-dir=%s' % self.q, '--path=%s' % victim)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(victim.read_bytes(), b'bad bytes')
        self.assertEqual(self.helper('spool-restore').returncode, 0)


class SpoolEngineTests(unittest.TestCase):
    """printer.target-quarantine-spool through the scanner and the engine, with the target mount fixture."""

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix='spool-engine-')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = self.tmp / 'fx'
        self.win_files = {'win/Windows/System32/spool/PRINTERS/%s' % n: (n * 50).encode() for n in ('A.SPL', 'A.SHD')}
        for rel, data in self.win_files.items():
            touch(self.fx / rel, data)
        touch(self.fx / 'win/Windows/System32/config/SYSTEM')
        (self.fx / 'win.meta.json').write_text(json.dumps({'fstype': 'ntfs', 'free_percent': 40}))
        touch(self.fx / 'lin/usr/lib/os-release', b'PRETTY_NAME="Linux Mint 22.3"\nID=linuxmint\n')
        os.makedirs(self.fx / 'lin/etc', exist_ok=True)
        os.symlink('../usr/lib/os-release', self.fx / 'lin/etc/os-release')
        touch(self.fx / 'lin/var/lib/dpkg/status', b'Package: good\nStatus: install ok installed\n\n')
        touch(self.fx / 'lin/usr/sbin/cupsd')
        self.lin_files = {'lin/var/spool/cups/c00001': b'control', 'lin/var/spool/cups/d00001-001': b'data'}
        for rel, data in self.lin_files.items():
            touch(self.fx / rel, data)
        (self.fx / 'lin.meta.json').write_text(json.dumps({'fstype': 'ext4', 'uuid': 'ABCD-1234', 'free_percent': 40}))
        self.evidence = self.tmp / 'evidence.json'
        proc = subprocess.run([sys.executable, str(SCAN_OS), '--output', str(self.evidence), '--fixture-root', str(self.fx)],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.ev = json.loads(self.evidence.read_text())
        refs = {t['family']: t['ref'] for t in self.ev['target_systems']}
        self.win, self.lin = refs['windows'], refs['linuxmint']
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.faildir = self.tmp / 'fail'
        self.faildir.mkdir()
        self.log = self.bin / 'calls.log'
        sudo = self.bin / 'sudo'
        sudo.write_text('#!/bin/sh\necho "sudo $*" >> "%s"\nshift 2\nexec "$@"\n' % self.log)
        helper = self.bin / 'rescue-malware-quarantine'
        helper.write_text('#!/bin/sh\necho "helper $1" >> "%s"\n'
                          '[ "$1" = spool-verify ] && [ -e "%s/verify" ] && { echo forced verify failure >&2; exit 3; }\n'
                          'exec %s %s "$@"\n' % (self.log, self.faildir, sys.executable, HELPER))
        for f in (sudo, helper):
            f.chmod(0o755)
        self.state = self.tmp / 'state'
        self.state.mkdir()
        self.journal = self.state / 'repairs' / 'journal.jsonl'
        self.env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(self.bin), RESCUE_TARGET_MOUNT_FIXTURE_ROOT=str(self.fx))

    def engine(self, *args, evidence=None):
        argv = [sys.executable, str(REPAIR), '--evidence', str(evidence or self.evidence), '--state-dir', str(self.state),
                '--scope', 'printer'] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, env=self.env, stdin=subprocess.DEVNULL, timeout=120)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stages(self, ref):
        return [(r['stage'], r['outcome'], r.get('reason')) for r in read_journal(self.journal)
                if r['action_id'] == 'printer.target-quarantine-spool' and r.get('target_ref') == ref]

    def test_the_scan_proposes_the_action_for_each_target_with_stuck_files(self):
        self.assertEqual(sorted((p['action_id'], p['target_ref'], p['origin']) for p in self.ev['repair_proposals']),
                         sorted([('printer.target-quarantine-spool', self.win, 'catalog-trigger'),
                                 ('printer.target-quarantine-spool', self.lin, 'catalog-trigger')]))
        self.assertEqual(self.ev['scope'], ['all'])

    def test_it_asks_even_under_auto_safe(self):
        proc = self.engine('--policy', 'auto-safe')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for ref in (self.win, self.lin):
            self.assertEqual(self.stages(ref), [('proposed', 'ok', None), ('approval', 'declined', 'not-interactive')])
        for rel in list(self.win_files) + list(self.lin_files):
            self.assertTrue((self.fx / rel).exists())
        self.assertEqual(self.calls(), [])

    def test_quarantine_verify_and_the_journal_for_both_families(self):
        proc = self.engine('--approve', 'printer.target-quarantine-spool')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for ref in (self.win, self.lin):
            self.assertEqual([s[:2] for s in self.stages(ref)], [
                ('proposed', 'ok'), ('approval', 'ok'), ('target-rw', 'ok'), ('precondition', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        for rel in list(self.win_files) + list(self.lin_files):
            self.assertFalse((self.fx / rel).exists(), rel)
        self.assertEqual(len(qs.active(str(self.state / 'quarantine'))), 4)
        self.assertEqual(qs.count_active(str(self.state / 'quarantine')), 0)
        self.assertEqual([c.split()[1] for c in self.calls() if c.startswith('helper')],
                         ['spool-check', 'spool-quarantine', 'spool-verify'] * 2)
        if not ROOT_USER:
            self.assertEqual(len([c for c in self.calls() if c.startswith('sudo')]), 6)
        text = self.journal.read_text() + proc.stdout + proc.stderr
        for leak in ('A.SPL', 'A.SHD', 'c00001', 'd00001', 'PRINTERS', 'spool/cups'):
            self.assertNotIn(leak, text)
        chain = subprocess.run([sys.executable, str(REPAIR), '--verify-journal', str(self.journal)], capture_output=True, text=True)
        self.assertEqual(chain.returncode, 0, chain.stdout)

    def test_a_failed_verify_rolls_the_files_back(self):
        (self.faildir / 'verify').write_text('x')
        proc = self.engine('--approve', 'printer.target-quarantine-spool')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        for ref in (self.win, self.lin):
            self.assertEqual([s[:2] for s in self.stages(ref)][-3:], [('execute', 'ok'), ('verify', 'fail'), ('rollback', 'ok')])
        for rel, data in list(self.win_files.items()) + list(self.lin_files.items()):
            self.assertEqual((self.fx / rel).read_bytes(), data, rel)
        self.assertEqual(qs.active(str(self.state / 'quarantine')), [])
        self.assertIn('rolled-back', proc.stdout)

    def test_no_stuck_files_means_the_precondition_skips_the_action(self):
        for rel in self.win_files:
            (self.fx / rel).unlink()
        proc = self.engine('--approve', 'printer.target-quarantine-spool')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([s[:2] for s in self.stages(self.win)][-2:], [('target-rw', 'ok'), ('precondition', 'fail')])
        self.assertNotIn('execute', [s[0] for s in self.stages(self.win)])

    def test_the_target_is_mounted_read_write_only_for_the_approved_action(self):
        proc = self.engine('--list')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('printer.target-quarantine-spool', proc.stdout)
        self.assertEqual(self.calls(), [])
        action = rc.load().get('printer.target-quarantine-spool')
        self.assertTrue(action['requires_target_rw'])
        self.assertEqual(action['risk'], 'reversible')


# ----------------------------------------------------------------------------------------
# Run report: prn-N, scope printer, the printer domain, the new reasons and risk in every generator
# ----------------------------------------------------------------------------------------
class ReportInputs(PrinterRepairCase):
    queues = {QUEUE: queue(state='stopped', accepting=False, jobs=2)}

    def produce_run(self):
        """A real journal: resume-queue verified, cancel-stuck-jobs refused because another printer sits in the port."""
        self.assertEqual(self.run_one('printer.resume-queue').returncode, 0)
        other = self.new_machine(serial='OTHERSERIAL000111')
        self.set_state(queues={'OtherQ': queue(uri='usb://Other/Printer?serial=OTHERSERIAL000111', state='stopped', jobs=1)})
        proc = self.run_one('printer.cancel-stuck-jobs', machine=other)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        inp = self.tmp / 'in'
        inp.mkdir()
        shutil.copy(self.evidence, inp / 'evidence.json')
        shutil.copy(self.journal, inp / 'journal.jsonl')
        return {'evidence': inp / 'evidence.json', 'journal': inp / 'journal.jsonl'}


class ReportTests(ReportInputs):
    def test_python_report_accepts_printer_targets_actions_reasons_and_the_domain(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        out, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='printer', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md, _ = TR.read_report(out)
        TR.validate(self, doc)
        self.assertEqual(doc['detection']['available'], True)
        self.assertEqual(doc['detection']['targets'][0]['family'], 'printer')
        self.assertEqual(doc['detection']['targets'][0]['ref'], 'prn-0')
        self.assertEqual(doc['detection']['targets'][0]['access'], 'ipp-read')
        self.assertEqual(doc['detection']['targets'][0]['detection'], 'usb-ipp')
        self.assertEqual(doc['header']['scope'], ['printer'])
        domain = doc['detection']['domains']['printer']
        self.assertIn(('printer-state', 'prn-0'), [(c['check_id'], c.get('target_ref')) for c in domain])
        self.assertIn('printer-count', [c['check_id'] for c in domain])
        self.assertNotIn('printer-state', [c['check_id'] for c in doc['detection']['domains']['os']])
        self.assertIn('### printer (', md)
        by_id = {}
        for a in doc['remediation']['actions']:
            self.assertEqual(a['target_ref'], 'prn-0')
            by_id.setdefault(a['action_id'], []).append(a)
        self.assertIn('verified', [a['final_outcome'] for a in by_id['printer.resume-queue']])
        cancel = [a for a in by_id['printer.cancel-stuck-jobs'] if a['stages']][-1]
        self.assertEqual((cancel['risk'], cancel['final_outcome'], cancel['stages'][-1]),
                         ('irreversible', 'skipped', {'stage': 'precondition', 'outcome': 'fail', 'reason': 'printer-mismatch'}))
        self.assertEqual(doc['privacy_check'], {'status': 'passed', 'findings': []})
        text = json.dumps(doc) + md
        for leak in LEAKS + ('OTHERSERIAL000111', '1-4'):
            self.assertNotIn(leak, text)

    def test_the_unchanged_run_report_still_refuses_a_leak(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        out, proc = gen.python(paths, mode='live-linux', run_id='run-10.20.30.40')
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(TR.read_report(out)[0]['privacy_check']['status'], 'refused')

    def test_rr_enums_match_the_schemas(self):
        schema = json.loads((REPO / 'rescue-ai/v1/run-report.schema.json').read_text())
        targets = schema['properties']['detection']['properties']['targets']['items']['properties']
        for key, values in rr.TARGET_ENUMS.items():
            self.assertEqual(list(values), targets[key]['enum'], key)
        self.assertEqual(list(rr.SCOPE_VALUES), schema['properties']['header']['properties']['scope']['items']['enum'])
        domains = schema['properties']['detection']['properties']['domains']
        self.assertEqual(list(rr.DOMAINS), list(domains['properties']))
        self.assertEqual(list(rr.DOMAINS), domains['required'])
        journal = json.loads((REPO / 'rescue-ai/v1/repair-journal.schema.json').read_text())
        self.assertEqual(list(rr.REASONS), journal['properties']['reason']['enum'])
        self.assertEqual(list(rr.RISKS), journal['properties']['risk']['enum'])
        self.assertEqual(rr.ACTION_RE.pattern, journal['properties']['action_id']['pattern'])
        self.assertEqual(rr.TARGET_RE.pattern, journal['properties']['target_ref']['pattern'])
        actions = schema['properties']['remediation']['properties']['actions']['items']['properties']
        self.assertEqual(list(rr.RISKS), actions['risk']['enum'])
        self.assertEqual(rr.ACTION_RE.pattern, actions['action_id']['pattern'])
        self.assertEqual(rr.TARGET_RE.pattern, actions['target_ref']['pattern'])

    def test_a_printer_free_run_report_still_validates_with_an_empty_printer_domain(self):
        doc = json.loads((REPO / 'rescue-ai/v1/fixtures/run-report-valid-full.json').read_text())
        self.assertEqual(doc['detection']['domains']['printer'], [])


@unittest.skipUnless(NODE, 'node not installed')
class JxaReportTests(ReportInputs):
    def test_jxa_report_equals_the_python_report_for_the_printer_run(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='printer', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        js_dir, proc = gen.jxa(paths, mode='live-linux', outcome='completed', scope='printer', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, js = TR.read_report(py_dir), TR.read_report(js_dir)
        TR.validate(self, js[0])
        self.assertEqual(py[0], js[0])
        self.assertEqual(py[1], js[1])
        self.assertEqual(py[2], js[2])
        self.assertEqual(js[0]['detection']['targets'][0]['family'], 'printer')
        self.assertTrue(js[0]['detection']['domains']['printer'])
        self.assertTrue(any(a.get('target_ref') == 'prn-0' and a['risk'] == 'irreversible' for a in js[0]['remediation']['actions']))

    def test_jxa_still_drops_a_malformed_printer_ref(self):
        paths = self.produce_run()
        ev = json.loads(paths['evidence'].read_text())
        ev['target_systems'][0]['ref'] = 'prn-9'
        paths['evidence'].write_text(json.dumps(ev))
        gen = TR.Generators(self.tmp)
        py_dir, _ = gen.python(paths, mode='live-linux')
        js_dir, proc = gen.jxa(paths, mode='live-linux')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(TR.read_report(js_dir)[0]['detection']['available'])
        self.assertEqual(TR.read_report(py_dir)[0], TR.read_report(js_dir)[0])


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellReportTests(ReportInputs):
    def test_powershell_report_equals_the_python_report_for_the_printer_run(self):
        paths = self.produce_run()
        gen = TR.Generators(self.tmp)
        py_dir, proc = gen.python(paths, mode='live-linux', outcome='completed', scope='printer', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        ps_dir, proc = gen.powershell(paths, mode='live-linux', outcome='completed', scope='printer', policy='approve-each')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, ps = TR.read_report(py_dir), TR.read_report(ps_dir)
        TR.validate(self, ps[0])
        self.assertEqual(py, ps)


class GeneratorStaticTests(unittest.TestCase):
    """pwsh and zsh may be missing here: the closed lists of the host generators must still match the Python ones."""

    def test_powershell_lists_match_the_python_generator(self):
        text = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')

        def ps_list(name):
            m = re.search(r'\$script:%s = @\((.*?)\)\n' % name, text, re.S)
            return re.findall(r"'([^']+)'", m.group(1))
        self.assertEqual(ps_list('RrScopeValues'), list(rr.SCOPE_VALUES))
        self.assertEqual(ps_list('RrReasons'), list(rr.REASONS))
        self.assertEqual(ps_list('RrRisks'), list(rr.RISKS))
        self.assertEqual(ps_list('RrDomains'), list(rr.DOMAINS))
        m = re.search(r'\$script:RrTargetEnums = @\{(.*?)\n\}', text, re.S)
        for key, values in rr.TARGET_ENUMS.items():
            line = re.search(r'%s = @\((.*?)\)' % key, m.group(1)).group(1)
            self.assertEqual(re.findall(r"'([^']+)'", line), list(values), key)
        self.assertEqual(text.count("'^(os|and|prn)-[0-7]$'"), 3)
        self.assertNotIn("'^(os|and)-[0-7]$'", text)
        self.assertIn("$script:RrActionRe = '%s'" % rr.ACTION_RE.pattern, text)
        self.assertIn("if ($Id.StartsWith('printer-')) { return 'printer' }", text)

    def test_javascript_lists_match_the_python_generator(self):
        text = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')

        def js_list(name):
            m = re.search(r'var %s = \[(.*?)\];' % name, text, re.S)
            return re.findall(r"'([^']+)'", m.group(1))
        self.assertEqual(js_list('SCOPE_VALUES'), list(rr.SCOPE_VALUES))
        self.assertEqual(js_list('REASONS'), list(rr.REASONS))
        self.assertEqual(js_list('RISKS'), list(rr.RISKS))
        self.assertEqual(js_list('DOMAINS'), list(rr.DOMAINS))
        m = re.search(r'var TARGET_ENUMS = \{(.*?)\n\};', text, re.S)
        for key, values in rr.TARGET_ENUMS.items():
            line = re.search(r'%s: \[(.*?)\]' % key, m.group(1), re.S).group(1)
            self.assertEqual(re.findall(r"'([^']+)'", line), list(values), key)
        self.assertIn('var ACTION_RE = /%s/;' % rr.ACTION_RE.pattern.replace('/', '\\/'), text)
        self.assertEqual(text.count('^(os|and|prn)-[0-7]$'), 3)
        self.assertIn("if (id.indexOf('printer-') === 0) { return 'printer'; }", text)


# ----------------------------------------------------------------------------------------
# Host engines: the catalog (with the printer domain) must stay loadable; the new types stay unsupported there
# ----------------------------------------------------------------------------------------
class HostEngineTests(unittest.TestCase):
    def test_powershell_engine_knows_the_printer_names_statically(self):
        text = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
        self.assertIn("'firmware_file', 'sha256', 'printer_ref', 'bundle_root') -cnotcontains $pt", text)
        self.assertIn("'malware', 'android', 'printer') -cnotcontains $domain", text)
        self.assertIn("'safe', 'reversible', 'irreversible', 'destructive') -cnotcontains $risk", text)
        self.assertIn('(hw|os-linux|os-windows|os-macos|sw|mw|android|printer)', text)
        self.assertRegex(text, r"\$unsupported = @\(\$action\.params \| Where-Object \{[^}]*printer_ref[^}]*bundle_root")

    def test_macos_engine_knows_the_printer_names_statically(self):
        text = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
        self.assertIn("'firmware_file', 'sha256', 'printer_ref', 'bundle_root'].indexOf(p.type)", text)
        self.assertIn("'malware', 'android', 'printer'].indexOf(doc.domain)", text)
        self.assertIn("['safe', 'reversible', 'irreversible', 'destructive'].indexOf(raw.risk)", text)
        self.assertIn('(hw|os-linux|os-windows|os-macos|sw|mw|android|printer)', text)
        self.assertIn('(block_device|target_root|android_device|fastboot_device|fastboot_slot|firmware_file|sha256|printer_ref|bundle_root)', text)
        self.assertIn('software.selected|malware|android|printer) ;;', text)

    def test_every_catalog_parameter_type_and_risk_is_in_the_closed_lists_of_both_engines(self):
        schema = json.loads((REPO / 'rescue-ai/v1/repair-catalog.schema.json').read_text())
        types = set(schema['$defs']['param']['properties']['type']['enum'])
        ps = (REPO / 'host/rescue-windows.ps1').read_text(encoding='utf-8')
        mac = (REPO / 'host/RESCUE-MACOS.command').read_text(encoding='utf-8')
        ps_types = set(re.findall(r"'([a-z0-9_]+)'", re.search(r"@\('enum', 'integer'[^)]*\) -cnotcontains \$pt", ps).group(0)))
        mac_types = set(re.findall(r"'([a-z0-9_]+)'", re.search(r"\['enum', 'integer'[^\]]*\]\.indexOf\(p\.type\)", mac).group(0)))
        self.assertEqual(ps_types, types)
        self.assertEqual(mac_types, types)
        risks = set(schema['$defs']['action']['properties']['risk']['enum'])
        self.assertEqual(risks, set(rr.RISKS))

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_loads_the_shipped_catalog_and_proposes_no_printer_action_on_macos(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = {'source_platform': 'macos-host', 'scope': ['all'],
                        'target_systems': [{'ref': 'os-0', 'family': 'macos'}, {'ref': 'prn-0', 'family': 'printer'}],
                        'checks': [{'check_id': 'printer-state', 'status': 'fail', 'target_ref': 'prn-0'},
                                   {'check_id': 'printer-queued-jobs', 'status': 'warn', 'target_ref': 'prn-0'},
                                   {'check_id': 'printer-target-spool-stuck', 'status': 'warn', 'target_ref': 'os-0'}]}
            proc, lines = AR.jxa_plan(rc.CATALOG_DIR, evidence, tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual([l for l in lines if l[0] == 'ERR'], [], proc.stdout)
            self.assertEqual([l for l in lines if l[0] in ('PROP', 'ACT')], [])
            proc, lines = AR.jxa_plan(rc.CATALOG_DIR, evidence, select='printer.identify:prn-0', tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(['SELERR', 'printer.identify does not apply here'], lines)
            catalog = rc.load()
            self.assertEqual([p for p in rc.triggered(catalog, evidence, ('all',)) if p['action_id'].startswith('printer.')], [])

    @unittest.skipUnless(NODE, 'node not installed')
    def test_jxa_planner_accepts_the_printer_domain_scope_and_irreversible_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            only = Path(tmp) / 'cat'
            only.mkdir()
            shutil.copy(rc.CATALOG_DIR / 'printer.json', only / 'printer.json')
            evidence = {'source_platform': 'macos-host', 'scope': ['printer'], 'target_systems': [{'ref': 'os-0', 'family': 'macos'}], 'checks': []}
            proc, lines = AR.jxa_plan(only, evidence, scope='printer', tmp=tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual([l for l in lines if l[0] == 'ERR'], [], proc.stdout)
            doc = json.loads((only / 'printer.json').read_text())
            doc['actions'][0]['params'][0]['type'] = 'printer_refs'
            (only / 'printer.json').write_text(json.dumps(doc))
            proc, lines = AR.jxa_plan(only, evidence, scope='printer', tmp=tmp)
            self.assertTrue([l for l in lines if l[0] == 'ERR'], proc.stdout)
            doc = json.loads(json.dumps(doc))
            doc['actions'][0]['params'][0]['type'] = 'printer_ref'
            doc['actions'][0]['risk'] = 'consumable'
            (only / 'printer.json').write_text(json.dumps(doc))
            proc, lines = AR.jxa_plan(only, evidence, scope='printer', tmp=tmp)
            self.assertTrue([l for l in lines if l[0] == 'ERR'], proc.stdout)


# ----------------------------------------------------------------------------------------
# scan-printers.py additions and the launcher wiring
# ----------------------------------------------------------------------------------------
class ScanAdditionsTests(PrinterRepairCase):
    def run_scan(self, *args):
        argv = [sys.executable, str(SCAN), '--fixture-root', str(self.machine.root), '--tool-path', str(self.bin)] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=60,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'LC_ALL': 'C'})

    def test_count_prints_only_the_number(self):
        proc = self.run_scan('--count')
        self.assertEqual((proc.returncode, proc.stdout), (0, '1\n'), proc.stderr)
        empty = self.new_machine(with_printer=False)
        self.set_state(queues={})
        argv = [sys.executable, str(SCAN), '--fixture-root', str(empty.root), '--tool-path', str(self.bin), '--count']
        proc = subprocess.run(argv, capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((proc.returncode, proc.stdout), (0, '0\n'), proc.stderr)

    def test_count_stands_alone_and_network_is_opt_in(self):
        for extra in ('--list', '--printer'):
            proc = self.run_scan('--count', extra, *(['prn-0'] if extra == '--printer' else []))
            self.assertEqual(proc.returncode, 2)
        self.assertEqual(self.run_scan('--count', '--output', str(self.tmp / 'x.json')).returncode, 2)
        self.run_scan('--count')
        self.assertEqual([c for c in self.calls() if c['tool'] == 'avahi-browse'], [])
        self.run_scan('--count', '--network')
        self.assertEqual(len([c for c in self.calls() if c['tool'] == 'avahi-browse']), 2)

    def test_guidance_names_the_actions_and_keeps_the_private_data_out(self):
        proc = self.run_scan('--list')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for aid in ('printer.resume-queue', 'printer.accept-jobs', 'printer.cancel-stuck-jobs'):
            self.assertIn(aid, proc.stdout)
        for leak in LEAKS:
            self.assertNotIn(leak, proc.stdout + proc.stderr)

    def test_the_scan_writes_scope_policy_and_validates(self):
        self.assertEqual((self.ev['scope'], self.ev['repair_policy'], self.ev['schema_version']), (['printer'], 'approve-each', '1.3'))
        self.assertTrue(self.ev['target_systems'][0]['opaque_id'].startswith('target-'))

    def test_repair_policy_defaults_to_detect_only(self):
        out = self.tmp / 'default.json'
        self.assertEqual(self.scan(out).returncode, 0)
        self.assertEqual(json.loads(out.read_text())['repair_policy'], 'detect-only')


class LauncherStaticTests(unittest.TestCase):
    def test_launcher_offers_the_printer_scan_after_the_os_scan_and_the_android_offer(self):
        text = (SCRIPTS / 'launch-hermes-rescue.sh').read_text()
        self.assertIn('printer_phase || true', text)
        self.assertLess(text.index('android_phase || true'), text.index('printer_phase || true'))
        self.assertLess(text.index('python3 "$root/scripts/rescue-repair.py" "${repair_args[@]}"'), text.index('printer_phase || true'))
        self.assertLess(text.index('printer_phase || true'), text.index('emit_report\n\nif ((offline))'))
        body = text[text.index('printer_phase() {'):text.index('printer_phase || true')]
        self.assertIn('[[ -t 0 ]] || return 0', body)
        self.assertIn('scan-printers.py" --count', body)
        self.assertIn('scan-printers.py" --list', body)
        self.assertIn('read -r -t 300 answer', body)
        self.assertNotIn('sudo', body)
        self.assertIn('--scope printer', body)
        self.assertIn('printer-evidence-$ts.json', body)
        self.assertIn('--printer-network', body)
        self.assertIn('[y/N, default: no]', body)

    def test_the_option_is_documented_in_the_usage_and_off_by_default(self):
        text = (SCRIPTS / 'launch-hermes-rescue.sh').read_text()
        self.assertIn('[--printer-network]', text)
        self.assertIn('printer_network=0', text)
        self.assertIn('--printer-network) printer_network=1; shift ;;', text)


STUB_SCAN_PRINTERS = """#!/usr/bin/env python3
import json, shutil, sys
args = sys.argv[1:]
with open({log!r}, 'a') as handle:
    handle.write(json.dumps(args) + '\\n')
if '--count' in args:
    print({count})
    sys.exit(0)
if '--list' in args:
    print('PRINTER TABLE FOR THE TEST')
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

    def stub_printers(self, count=1, fail=False):
        AR.LauncherPhaseTests.stub_android(self, count=0)           # a real phone on this machine must not matter
        c = self.case
        self.printer_log = c.tmp / 'printers.log'
        stub = c.src / 'scripts' / 'scan-printers.py'
        stub.write_text(STUB_SCAN_PRINTERS.format(log=str(self.printer_log), count=count, fail=fail,
                                                  fixture=str(c.src / 'rescue-ai/v1/fixtures/valid-printer.json')))
        os.chmod(stub, 0o755)
        c._open(stub)
        os.chmod(stub, 0o755)

    def printer_calls(self):
        if not self.printer_log.exists():
            return []
        return [json.loads(line) for line in self.printer_log.read_text().splitlines()]

    def tty_launch(self, answer, *extra, timeout=90):
        return AR.LauncherPhaseTests.tty_launch(self, answer, *extra, timeout=timeout)

    def printer_reports(self):
        found = []
        for path in sorted(self.reports_dir().glob('run-*/report.json')):
            doc = json.loads(path.read_text(encoding='utf-8'))
            if doc['run_id'].endswith('-printer'):
                found.append(doc)
        return found

    def test_a_non_interactive_run_never_offers_or_scans_a_printer(self):
        self.stub_printers()
        proc = self.launch('--repair-policy', 'detect-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.printer_calls(), [])
        self.assertEqual(list(self.reports_dir().glob('printer-evidence-*.json')), [])
        self.assertEqual(self.printer_reports(), [])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_yes_scans_the_printer_runs_the_engine_and_writes_its_own_report(self):
        self.stub_printers()
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertIn('PRINTER TABLE FOR THE TEST', out)
        self.assertIn('Pindai printer ini', out)
        self.assertEqual(self.printer_calls()[0], ['--count'])
        self.assertEqual(self.printer_calls()[1], ['--list'])
        scan = self.printer_calls()[2]
        self.assertEqual(scan[scan.index('--source-platform') + 1], 'live-linux')
        self.assertEqual(scan[scan.index('--repair-policy') + 1], 'detect-only')
        self.assertIn('--provider-ready', scan)
        self.assertNotIn('--network', scan)
        files = list(self.reports_dir().glob('printer-evidence-*.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        reports = self.printer_reports()
        self.assertEqual(len(reports), 1)
        TR.validate(self, reports[0])
        self.assertEqual((reports[0]['header']['mode'], reports[0]['header']['scope'], reports[0]['header']['outcome']),
                         ('live-linux', ['printer'], 'completed'))
        self.assertEqual(reports[0]['detection']['targets'][0]['family'], 'printer')
        self.assertEqual(reports[0]['header']['evidence_run_id'], json.loads(files[0].read_text())['run_id'])
        self.assertTrue(list(self.reports_dir().glob('target-evidence-*.json')))
        self.assertNotIn(TR.DUMMY_KEY, ''.join(p.read_text(encoding='utf-8', errors='replace')
                                              for p in self.reports_dir().rglob('*') if p.is_file() and p.suffix in ('.md', '.json')))

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_default_answer_is_no(self):
        self.stub_printers()
        for answer in ('\n', 'n\n', 'maybe\n', ''):
            with self.subTest(answer=answer):
                out = self.tty_launch(answer, '--repair-policy', 'detect-only')
                self.assertIn('Printer scan skipped', out)
                self.assertNotIn(['--output'], [c[:1] for c in self.printer_calls()])
                self.assertEqual(list(self.reports_dir().glob('printer-evidence-*.json')), [])
                self.assertEqual(self.printer_reports(), [])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_no_printer_means_no_prompt(self):
        self.stub_printers(count=0)
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertNotIn('Pindai printer ini', out)
        self.assertEqual(self.printer_calls(), [['--count']])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_scope_without_printer_and_no_target_scan_skip_the_offer(self):
        self.stub_printers()
        for extra in (('--scope', 'os'), ('--no-target-scan',)):
            with self.subTest(extra=extra):
                self.tty_launch('y\n', '--repair-policy', 'detect-only', *extra)
                self.assertEqual(self.printer_calls(), [])
        self.tty_launch('y\n', '--repair-policy', 'detect-only', '--scope', 'os,printer')
        self.assertEqual(self.printer_calls()[0], ['--count'])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_printer_network_is_passed_to_the_scan_and_the_engine(self):
        self.stub_printers()
        self.tty_launch('y\n', '--repair-policy', 'detect-only', '--printer-network')
        calls = self.printer_calls()
        self.assertEqual(calls[0], ['--count', '--network'])
        self.assertEqual(calls[1], ['--list', '--network'])
        self.assertIn('--network', calls[2])
        self.assertIn('--output', calls[2])

    @unittest.skipUnless(shutil.which('script'), 'util-linux script(1) needed to give the launcher a tty')
    def test_a_failed_printer_scan_is_reported_and_does_not_block_hermes(self):
        self.stub_printers(fail=True)
        out = self.tty_launch('y\n', '--repair-policy', 'detect-only')
        self.assertIn('HERMES-RAN', out)
        self.assertIn('pemindaian printer gagal', out)
        reports = self.printer_reports()
        self.assertEqual([r['header']['outcome'] for r in reports], ['scan-failed'])
        self.assertFalse(reports[0]['detection']['available'])
        self.assertEqual(list(self.reports_dir().glob('printer-evidence-*.json')), [])


if __name__ == '__main__':
    unittest.main()
