#!/usr/bin/env python3
"""Tests for the host launchers in host/ (Windows, macOS, Linux). Stdlib only.

* Linux launcher: run for real in a temp copy of the bundle (evidence-only, dry-run through the
  real scripts/opencode-go-analyze.py, and a loopback fake OpenCode Go server).
* PowerShell launcher: parse check and pure-function tests through pwsh when it is installed
  (skipped otherwise; GitHub ubuntu-24.04 runners have pwsh).
* macOS launcher: zsh syntax check and a functional run with PATH shims that emulate the
  macOS tools (skipped without zsh). Real macOS behavior is Hardware-required and NOT tested here.
* Static tests: no key on argv, nothing written outside the USB reports folder, no dynamic code.

No real network, dummy secrets only. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import getpass
import hashlib
import http.server
import json
import os
import pty
import re
import select
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOST = REPO / 'host'
DUMMY_KEY = 'dummy-test-key-123'
BUNDLE_DIRS = ('scripts', 'profiles', 'rescue-ai', 'host')
CANNED_ANSWER = '**Fakta**\n- semua ok "dikutip" \\ backslash \u00e9\n'

try:
    import jsonschema  # noqa: F401
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

PWSH = shutil.which('pwsh')
ZSH = shutil.which('zsh')
BASH = shutil.which('bash') or '/bin/bash'


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if k not in ('OPENCODE_GO_API_KEY', 'RESCUE_TEST_BASE_URL', 'RESCUE_PS_LIBRARY_ONLY')}
    # hardware detection reads a (nonexistent) fixture root, never the machine running the tests
    env.setdefault('RESCUE_HARDWARE_FIXTURE_ROOT', '/nonexistent-hardware-fixture')
    env.setdefault('RESCUE_MALWARE_FIXTURE_ROOT', '/nonexistent-malware-fixture')
    env.update(extra)
    return env


def make_usb(tmp, launcher_at_root=None):
    """Create <tmp>/usb/rescue-omes with a private copy of the bundle. Returns (usb, bundle)."""
    usb = Path(tmp) / 'usb'
    bundle = usb / 'rescue-omes'
    bundle.mkdir(parents=True)
    for name in BUNDLE_DIRS:
        shutil.copytree(REPO / name, bundle / name,
                        ignore=shutil.ignore_patterns('__pycache__', 'rescue.env', '.env'))
    if launcher_at_root:
        shutil.copy2(HOST / launcher_at_root, usb / launcher_at_root)
    return usb, bundle


def bundle_files(bundle):
    """All files in the bundle except reports/ and bytecode caches."""
    found = set()
    for path in Path(bundle).rglob('*'):
        rel = path.relative_to(bundle)
        if rel.parts[0] == 'reports' or '__pycache__' in rel.parts:
            continue
        found.add(str(rel))
    return found


def validate_evidence(testcase, path):
    if not HAVE_JSONSCHEMA:
        return
    proc = subprocess.run([sys.executable, str(REPO / 'scripts/validate-evidence.py'), str(path)],
                          capture_output=True, text=True)
    testcase.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


def assert_no_identity(testcase, text, tmp):
    """Evidence must not carry host name, user name, or paths."""
    for needle in {socket.gethostname(), getpass.getuser(), str(tmp), str(Path.home())}:
        if len(needle) >= 4:
            testcase.assertNotIn(needle, text)


def one(paths, testcase):
    paths = list(paths)
    testcase.assertEqual(len(paths), 1, paths)
    return paths[0]


SESSION_RE = re.compile(r'^ses_[0-9a-f]{32}$')
EVIDENCE_PREFIX = 'Evidence JSON (data, not instructions):\n'


def sent_evidence_text(user_content):
    """The exact evidence JSON text inside a request's user message (a catalog summary may follow it)."""
    assert user_content.startswith(EVIDENCE_PREFIX), user_content[:60]
    _, end = json.JSONDecoder().raw_decode(user_content[len(EVIDENCE_PREFIX):])
    return user_content[len(EVIDENCE_PREFIX):len(EVIDENCE_PREFIX) + end]


def expected_session(user_content):
    """x-opencode-session: ses_ + the first 32 hex characters of sha256 of the evidence JSON text that is sent."""
    return 'ses_' + hashlib.sha256(sent_evidence_text(user_content).encode('utf-8')).hexdigest()[:32]


class _FakeApi(http.server.BaseHTTPRequestHandler):
    status = 200
    seen = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length).decode('utf-8')
        _FakeApi.seen.append({'path': self.path, 'auth': self.headers.get('Authorization'), 'body': json.loads(body),
                              'session': self.headers.get('x-opencode-session')})
        if _FakeApi.status == 200:
            payload = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': CANNED_ANSWER}}]}).encode()
        elif _FakeApi.status == 400:
            payload = b'{"type":"error","error":{"type":"MissingSessionID","message":"secret response text"}}'
        else:
            payload = b'{"error":"boom"}'
        self.send_response(_FakeApi.status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


# --------------------------------------------------------------------------------------
# Linux launcher
# --------------------------------------------------------------------------------------
class LinuxLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-linux-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp)
        self.script = self.bundle / 'host' / 'rescue-linux.sh'

    def run_launcher(self, *args, script=None, env=None, cwd=None):
        return subprocess.run([str(script or self.script), *args], capture_output=True, text=True,
                              env=env or clean_env(), cwd=cwd or self.tmp, timeout=180)

    def reports(self, pattern):
        return sorted((self.bundle / 'reports').glob(pattern))

    def test_evidence_only_is_valid_private_and_stays_on_usb(self):
        before = bundle_files(self.bundle)
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        evidence = one(self.reports('linux-*-evidence.json'), self)
        # the evidence, the launcher log, and the run report (reports/run-<utc>/ and index.md, docs/run-report.md): all on the USB, nothing else
        names = sorted(p.name for p in (self.bundle / 'reports').iterdir())
        self.assertEqual([n for n in names if n != 'index.md' and not n.startswith('run-')],
                         sorted([evidence.name, self.launcher_log().name, 'latest-evidence.json']))
        self.assertEqual((self.bundle / 'reports' / 'latest-evidence.json').read_text(encoding='utf-8'),
                         evidence.read_text(encoding='utf-8'))
        self.assertEqual(len([n for n in names if n.startswith('run-')]), 1, names)
        self.assertIn('index.md', names)
        self.assertEqual(bundle_files(self.bundle), before)
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        data = json.loads(text)
        assert_no_identity(self, text, self.tmp)
        self.assertEqual(data['schema_version'], '1.2')
        self.assertEqual(data['source_platform'], 'linux-host')
        self.assertEqual(data['classification'], 'confidential')
        self.assertEqual(data['evidence_manifest']['entry_count'], len(data['checks']))
        self.assertEqual(data['evidence_manifest']['storage_class'], 'usb-rescue-state')
        self.assertEqual(len(data['target_systems']), 1)
        self.assertEqual(data['target_systems'][0]['detection'], 'host-native')
        self.assertEqual(data['target_systems'][0]['access'], 'host-running')
        ids = {c['check_id']: c for c in data['checks']}
        for required in ('os-detection', 'disk-free-space', 'linux-failed-units', 'linux-journal-errors',
                         'linux-kernel-initrd', 'linux-package-state', 'encryption-status', 'smart-health',
                         'network-connectivity'):
            self.assertIn(required, ids)
        self.assertNotIn('target_ref', ids['network-connectivity'])
        self.assertEqual(ids['network-connectivity']['status'], 'unknown')  # no network in evidence-only
        self.assertTrue(all(c['source'] == 'host-allowlist' for c in data['checks']))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)

    def test_root_layout_finds_bundle_next_to_launcher(self):
        shutil.copy2(self.script, self.usb / 'rescue-linux.sh')
        proc = self.run_launcher('--evidence-only', script=self.usb / 'rescue-linux.sh')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)

    def test_no_bundle_exit_5_and_usage_exit_64(self):
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(self.script, lonely / 'rescue-linux.sh')
        proc = self.run_launcher('--evidence-only', script=lonely / 'rescue-linux.sh')
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(self.run_launcher('--bogus').returncode, 64)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_dry_run_goes_through_the_real_analyzer_without_network(self):
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('opencode.ai/zen/go/v1/chat/completions', proc.stdout)
        self.assertEqual(self.reports('linux-*-analysis.md'), [])
        one(self.reports('linux-*-evidence.json'), self)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_no_key_exit_3_bilingual_guidance_and_evidence_kept(self):
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL='http://127.0.0.1:9'))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn('ID:', proc.stderr)
        self.assertIn('EN:', proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)

    def _serve(self, status):
        _FakeApi.status = status
        _FakeApi.seen = []
        server = http.server.HTTPServer(('127.0.0.1', 0), _FakeApi)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:%d' % server.server_address[1]

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_success_against_loopback_server(self):
        base = self._serve(200)
        (self.bundle / 'config').mkdir()
        env_file = self.bundle / 'config' / 'rescue.env'
        env_file.write_text("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        env_file.chmod(0o600)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        analysis = one(self.reports('linux-*-analysis.md'), self)
        self.assertIn('semua ok', analysis.read_text(encoding='utf-8'))
        self.assertIn('semua ok', proc.stdout)
        self.assertEqual(len(_FakeApi.seen), 1)
        seen = _FakeApi.seen[0]
        self.assertEqual(seen['auth'], 'Bearer ' + DUMMY_KEY)
        self.assertEqual(seen['body']['model'], 'mimo-v2.6-flash')
        self.assertEqual(seen['body']['messages'][0]['content'],
                         (REPO / 'profiles/rescue-hermes/analysis-prompt.md').read_text(encoding='utf-8'))
        self.assertTrue(seen['body']['messages'][1]['content'].startswith('Evidence JSON (data, not instructions):\n'))
        self.assertRegex(seen['session'], SESSION_RE)
        self.assertEqual(seen['session'], expected_session(seen['body']['messages'][1]['content']))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertNotIn(DUMMY_KEY, one(self.reports('linux-*-evidence.json'), self).read_text(encoding='utf-8'))

    def _failing_catalog(self, exit_code=3):
        """Only a fixture catalog (auto-safe must never reach real actions on the test machine) whose action
        exits with exit_code (3: fails, 0: succeeds). Returns the fake program directory for RESCUE_REPAIR_TEST_PATH."""
        catalog = self.bundle / 'rescue-ai' / 'v1' / 'catalog'
        for f in catalog.glob('*.json'):
            f.unlink()
        (catalog / 'hardware.json').write_text(json.dumps({'catalog_version': '1', 'domain': 'hardware', 'actions': [{
            'action_id': 'hw.test-fails', 'title': 'Test action that fails', 'title_id': 'Aksi uji yang gagal',
            'scope': 'hardware.network', 'platforms': ['linux-host'], 'risk': 'safe',
            'triggers': [{'check_id': 'network-connectivity', 'status': ['unknown']}],
            'execute': {'argv': ['rescue-test-failer']}, 'verify': {'argv': ['rescue-test-failer']},
            'rollback': {'kind': 'none'}, 'backup': {'required': False}, 'doc': 'docs/hardware.md'}]}))
        fakebin = self.tmp / 'fakebin'
        fakebin.mkdir()
        (fakebin / 'rescue-test-failer').write_text('#!/bin/sh\nexit %d\n' % exit_code)
        (fakebin / 'rescue-test-failer').chmod(0o755)
        return fakebin

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_failed_repair_exits_1_like_the_windows_and_macos_launchers(self):
        fakebin = self._failing_catalog()
        base = self._serve(200)
        proc = self.run_launcher('--repair-policy', 'auto-safe', env=clean_env(
            RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY, RESCUE_REPAIR_TEST_PATH=str(fakebin)))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        journal = self.bundle / 'reports' / 'repairs' / 'journal.jsonl'
        stages = [(r['stage'], r['outcome']) for r in map(json.loads, journal.read_text().splitlines())]
        self.assertIn(('execute', 'fail'), stages)
        # a failed action no longer triggers the (5 minute) re-collect
        self.assertEqual(self.reports('linux-*-evidence-after.json'), [])
        self.assertIn('re-collect skipped', proc.stdout)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_http_error_exit_4(self):
        base = self._serve(500)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertIn('EN:', proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_provider_rejection_exit_4_and_bilingual_message_without_the_response_body(self):
        base = self._serve(400)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertIn('HTTP 400 (MissingSessionID)', proc.stderr)
        self.assertIn('ID: OpenCode Go menolak permintaan', proc.stderr)
        self.assertIn('EN: OpenCode Go rejected the request', proc.stderr)
        self.assertNotIn('secret response text', proc.stdout + proc.stderr)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)
        reports = sorted((self.bundle / 'reports').glob('run-*/report.json'))
        self.assertEqual(json.loads(one(reports, self).read_text(encoding='utf-8'))['header']['outcome'], 'provider-rejected')

    def test_missing_analyzer_keeps_evidence_and_exits_6(self):
        (self.bundle / 'scripts' / 'opencode-go-analyze.py').unlink()
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)

    # ---- #49: diagnostics (log, one run id, catalog hash, outcome precedence) ----------------------
    def last_report(self):
        reports = sorted((self.bundle / 'reports').glob('run-*/report.json'))
        return json.loads(one(reports, self).read_text(encoding='utf-8'))

    def launcher_log(self):
        return one(self.reports('launcher-linux-*.log'), self)

    def break_catalog(self):
        """A catalog file that is not JSON: the repair engine refuses it (exit 2, 'catalog INVALID')."""
        (self.bundle / 'rescue-ai' / 'v1' / 'catalog' / 'zz-broken.json').write_text('{not json')

    def no_jsonschema_env(self, **extra):
        """PYTHONPATH with a jsonschema stub that cannot be imported: the host has no python3-jsonschema."""
        stub = self.tmp / 'nojsonschema'
        (stub / 'jsonschema').mkdir(parents=True, exist_ok=True)
        (stub / 'jsonschema' / '__init__.py').write_text("raise ImportError('stub: python3-jsonschema is not installed')\n")
        return clean_env(PYTHONPATH=str(stub) + os.pathsep + os.environ.get('PYTHONPATH', ''), **extra)

    def open_items(self):
        return [(i['kind'], i.get('ref')) for i in self.last_report()['open_items']]

    def test_launcher_log_is_on_the_usb_private_complete_and_never_holds_the_key(self):
        proc = self.run_launcher('--evidence-only', env=clean_env(OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        log = self.launcher_log()
        self.assertTrue(log.resolve().is_relative_to(self.bundle.resolve() / 'reports'))
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        text = log.read_text(encoding='utf-8')
        self.assertIn('Rescue host launcher (Linux)', text)
        self.assertIn('Evidence tersimpan / saved:', text)
        self.assertIn('Laporan tersimpan / report saved:', text)   # the EXIT-trap report line is logged too
        self.assertIn('Repair plan / rencana perbaikan:', text)    # a child tool's stdout
        self.assertNotIn(DUMMY_KEY, text)
        for path in (self.bundle / 'reports').rglob('*'):
            if path.is_file():
                self.assertNotIn(DUMMY_KEY, path.read_text(encoding='utf-8', errors='replace'), path)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_launcher_log_has_stdout_and_stderr_of_the_children_but_not_the_key_or_response_body(self):
        base = self._serve(400)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        text = self.launcher_log().read_text(encoding='utf-8')
        self.assertIn('HTTP 400 (MissingSessionID)', text)           # analyzer stderr
        self.assertIn('EN: OpenCode Go rejected the request', text)  # launcher stderr
        self.assertIn('Repair plan / rencana perbaikan:', text)      # repair engine stdout (not a terminal)
        self.assertNotIn(DUMMY_KEY, text)
        self.assertNotIn('secret response text', text)

    def test_one_run_id_for_the_report_and_the_evidence(self):
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        evidence = json.loads(one(self.reports('linux-*-evidence.json'), self).read_text(encoding='utf-8'))
        doc = self.last_report()
        self.assertRegex(evidence['run_id'], r'^rescue-\d{8}-\d{6}-lh$')
        self.assertEqual(doc['run_id'], evidence['run_id'])
        self.assertEqual(doc['header']['evidence_run_id'], evidence['run_id'])

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_the_after_evidence_derives_its_run_id_from_the_same_base(self):
        fakebin = self._failing_catalog(exit_code=0)   # the action succeeds: this is what justifies the re-collect
        base = self._serve(200)
        proc = self.run_launcher('--repair-policy', 'auto-safe', env=clean_env(
            RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY, RESCUE_REPAIR_TEST_PATH=str(fakebin)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        before = json.loads(one(self.reports('linux-*-evidence.json'), self).read_text(encoding='utf-8'))
        after_path = one(self.reports('linux-*-evidence-after.json'), self)
        after = json.loads(after_path.read_text(encoding='utf-8'))
        self.assertEqual(after['run_id'], before['run_id'] + '-after')
        validate_evidence(self, after_path)
        self.assertEqual(self.last_report()['run_id'], before['run_id'])

    def test_collector_only_accepts_the_launchers_own_run_id(self):
        text = self.script.read_text(encoding='utf-8')
        self.assertIn("^rescue-[0-9]{8}-[0-9]{6}-lh(-after)?$", text)
        self.assertNotIn('run_suffix', text)

    def test_report_header_has_the_catalog_hash_when_there_is_no_journal(self):
        sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
        import repair_catalog
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((self.bundle / 'reports' / 'repairs' / 'journal.jsonl').exists())
        sha = self.last_report()['header']['catalog_sha256']
        self.assertRegex(sha, r'^[0-9a-f]{64}$')
        self.assertEqual(sha, repair_catalog.directory_sha256(self.bundle / 'rescue-ai' / 'v1' / 'catalog'))
        if HAVE_JSONSCHEMA:
            self.assertEqual(sha, repair_catalog.load(self.bundle / 'rescue-ai' / 'v1' / 'catalog').sha256)

    def assert_dependency_note(self, text):
        self.assertIn('ID: python3-jsonschema tidak ada di komputer ini', text)
        self.assertIn('EN: python3-jsonschema is not installed on this computer', text)
        self.assertIn('TIDAK memasang apa pun', text)
        self.assertIn('installs NOTHING', text)

    def test_without_python3_jsonschema_the_launcher_says_so_and_runs_neither_analyzer_nor_engine(self):
        # The field failure of #49: no python3-jsonschema on the host. Nothing is installed; the evidence is kept.
        sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
        import repair_catalog
        base = self._serve(200)
        proc = self.run_launcher(env=self.no_jsonschema_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        self.assert_dependency_note(proc.stdout)
        self.assertEqual(_FakeApi.seen, [])                      # the analyzer never ran: no request reached the server
        self.assertNotIn('Repair plan', proc.stdout + proc.stderr)  # the repair engine never ran (not even --list)
        self.assertNotIn('rescue-repair', proc.stdout + proc.stderr)
        self.assertEqual(self.reports('linux-*-analysis.md'), [])
        self.assertFalse((self.bundle / 'reports' / 'repairs').exists())
        evidence = json.loads(one(self.reports('linux-*-evidence.json'), self).read_text(encoding='utf-8'))
        self.assertEqual(evidence['source_platform'], 'linux-host')
        self.assertFalse(evidence['ai_provider']['authenticated'])  # nothing was or will be sent
        doc = self.last_report()
        self.assertEqual(doc['header']['outcome'], 'dependency-missing')
        if HAVE_JSONSCHEMA:  # the report validates against the schema (checked here, where jsonschema exists)
            report = one(sorted((self.bundle / 'reports').glob('run-*/report.json')), self)
            check = subprocess.run([sys.executable, str(REPO / 'scripts/rescue-report.py'), '--validate', str(report)],
                                   capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(doc['run_id'], evidence['run_id'])
        self.assertIn('host-dependency-missing', doc['honesty']['environment_blocked'])
        self.assertNotIn('repair-engine-failed', [i for i, _ in self.open_items()])
        self.assertEqual(doc['header']['catalog_sha256'],
                         repair_catalog.directory_sha256(self.bundle / 'rescue-ai' / 'v1' / 'catalog'))
        log = self.launcher_log().read_text(encoding='utf-8')
        self.assert_dependency_note(log)
        self.assertNotIn(DUMMY_KEY, log)
        self.assertIn('dependency-missing', (self.bundle / 'reports' / 'index.md').read_text(encoding='utf-8'))

    def test_without_python3_jsonschema_and_without_key_it_is_still_dependency_missing(self):
        proc = self.run_launcher(env=self.no_jsonschema_env())
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        self.assert_dependency_note(proc.stdout)
        self.assertEqual(self.last_report()['header']['outcome'], 'dependency-missing')
        one(self.reports('linux-*-evidence.json'), self)

    def test_without_python3_jsonschema_dry_run_and_evidence_only(self):
        proc = self.run_launcher('--dry-run', env=self.no_jsonschema_env())
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        self.assertEqual(self.last_report()['header']['outcome'], 'dependency-missing')
        shutil.rmtree(self.bundle / 'reports')
        proc = self.run_launcher('--evidence-only', env=self.no_jsonschema_env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)  # the operator asked for evidence only: it exists
        self.assert_dependency_note(proc.stdout)
        self.assertNotIn('Repair plan', proc.stdout + proc.stderr)
        self.assertEqual(self.last_report()['header']['outcome'], 'evidence-only')

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_a_repair_engine_failure_keeps_the_analyzer_outcome_and_exit_code(self):
        for status, outcome in ((400, 'provider-rejected'), (500, 'network-error')):
            with self.subTest(status=status):
                shutil.rmtree(self.bundle / 'reports', True)
                self.break_catalog()
                base = self._serve(status)
                proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
                self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)  # the analyzer's code, not the engine's 2
                doc = self.last_report()
                self.assertEqual(doc['header']['outcome'], outcome)
                self.assertIn(('repair-engine-failed', 'exit-2'), self.open_items())
                log = self.launcher_log().read_text(encoding='utf-8')
                self.assertIn('catalog INVALID', log)
                self.assertNotIn(DUMMY_KEY, log)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_no_key_outcome_and_exit_survive_a_repair_engine_failure(self):
        self.break_catalog()
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL='http://127.0.0.1:9'))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(self.last_report()['header']['outcome'], 'no-key')
        self.assertIn(('repair-engine-failed', 'exit-2'), self.open_items())

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_a_repair_engine_failure_alone_is_repair_invalid_with_the_open_item(self):
        self.break_catalog()
        base = self._serve(200)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.last_report()['header']['outcome'], 'repair-invalid')
        self.assertIn(('repair-engine-failed', 'exit-2'), self.open_items())

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_an_unusable_journal_outranks_the_analyzer_outcome_and_exits_5(self):
        fakebin = self._failing_catalog()
        (self.bundle / 'reports').mkdir(exist_ok=True)
        (self.bundle / 'reports' / 'repairs').write_text('not a directory')  # the journal cannot be opened
        base = self._serve(500)
        proc = self.run_launcher('--repair-policy', 'auto-safe', env=clean_env(
            RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY, RESCUE_REPAIR_TEST_PATH=str(fakebin)))
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)
        self.assertEqual(self.last_report()['header']['outcome'], 'journal-unusable')
        self.assertIn(('repair-engine-failed', 'exit-3'), self.open_items())


# --------------------------------------------------------------------------------------
# Key parser parity: bash reference (scripts/lib/rescue-env.sh) vs the other implementations
# --------------------------------------------------------------------------------------
FAKE_HERMES = r'''#!/usr/bin/env python3
import glob, json, os, sys
bundle = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
reports = os.path.join(bundle, 'reports')
key = os.environ.get('OPENCODE_GO_API_KEY')
rec = {
    'argv': sys.argv[1:], 'cwd': os.getcwd(),
    'env': {n: os.environ.get(n) for n in ('HERMES_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME',
                                           'XDG_CONFIG_HOME', 'TMPDIR', 'PYTHONDONTWRITEBYTECODE', 'PYTHONNOUSERSITE',
                                           'PYTHONSAFEPATH', 'HOME')},
    'key_matches': key == os.environ.get('FAKE_EXPECTED_KEY'),
    'github_token_present': 'RESCUE_GITHUB_ISSUES_TOKEN' in os.environ,
    'key_in_argv': any((os.environ.get('FAKE_EXPECTED_KEY') or '\0') in a for a in sys.argv),
    'stdin_tty': os.isatty(0), 'stdout_tty': os.isatty(1),
    'report_before': bool(glob.glob(os.path.join(reports, 'run-*', 'report.md'))) and os.path.isfile(os.path.join(reports, 'index.md')),
    'latest_evidence': os.path.isfile(os.path.join(reports, 'latest-evidence.json')),
    'followup': bool(glob.glob(os.path.join(reports, 'followup-*.json'))),
    'seeded': sorted(os.listdir(os.environ['HERMES_HOME'])),
}
with open(os.environ['FAKE_HERMES_OUT'], 'a') as f:
    f.write(json.dumps(rec) + '\n')
raise SystemExit(int(os.environ.get('FAKE_HERMES_EXIT', '0')))
'''


def run_in_pty(argv, env, cwd, timeout=240):
    """Run argv with a real pseudo-terminal as stdin/stdout/stderr. Returns (returncode, output text)."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=cwd, close_fds=True)
    os.close(slave)
    chunks = []
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            proc.kill()
            break
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b''
            if not data:
                break
            chunks.append(data)
        elif proc.poll() is not None:
            break
    os.close(master)
    proc.wait(timeout=30)
    return proc.returncode, b''.join(chunks).decode('utf-8', 'replace')


@unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
class LinuxHermesTests(unittest.TestCase):
    """The Linux host launcher opens the portable Hermes (ahliweb/linux-mint-xfce-rescue-ai#71) with a fake runtime."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-hermes-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp)
        self.script = self.bundle / 'host' / 'rescue-linux.sh'
        (self.bundle / 'config').mkdir()
        shutil.copy2(REPO / 'config' / 'hermes-rescue.config.yaml', self.bundle / 'config' / 'hermes-rescue.config.yaml')
        self.out = self.tmp / 'hermes-record.jsonl'
        self.home = self.tmp / 'home'
        self.home.mkdir()
        _FakeApi.status = 200
        _FakeApi.seen = []
        server = http.server.HTTPServer(('127.0.0.1', 0), _FakeApi)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base = 'http://127.0.0.1:%d' % server.server_address[1]

    def add_runtime(self):
        py = self.bundle / 'hermes-portable' / 'linux-x86_64' / 'python' / 'bin' / 'python3'
        py.parent.mkdir(parents=True)
        py.write_text(FAKE_HERMES)
        py.chmod(0o755)

    def env(self, **extra):
        values = dict(RESCUE_TEST_BASE_URL=self.base, OPENCODE_GO_API_KEY=DUMMY_KEY, FAKE_EXPECTED_KEY=DUMMY_KEY,
                      FAKE_HERMES_OUT=str(self.out), HOME=str(self.home), RESCUE_PROGRESS='0',
                      RESCUE_GITHUB_ISSUES_TOKEN='dummy-gh-token-value')
        values.update(extra)
        return clean_env(**values)

    def records(self):
        return [json.loads(line) for line in self.out.read_text().splitlines()] if self.out.exists() else []

    def pty_run(self, *args, **extra):
        # detect-only: these tests are about Hermes, not repairs. On a CI runner with passwordless sudo the engine would
        # otherwise offer root actions and wait at its approval prompt on the pseudo-terminal until the timeout.
        # A narrow scope keeps the real host collection short on slow CI runners (package inventory, large journals).
        return run_in_pty([str(self.script), '--repair-policy', 'detect-only', '--scope', 'hardware.cpu', *args],
                          self.env(**extra), self.tmp, timeout=480)

    def test_hermes_starts_on_a_terminal_with_the_fixed_argv_cwd_and_environment(self):
        self.add_runtime()
        rc, output = self.pty_run()
        self.assertEqual(rc, 0, output)
        (rec,) = self.records()
        reports = self.bundle / 'reports'
        hh = self.bundle / 'hermes-home'
        self.assertEqual(rec['argv'], ['-m', 'hermes_cli.main', 'chat', '--cli', '--provider', 'custom', '--model',
                                       'mimo-v2.6-flash', '-s', 'rescue-autorun', '--query-file',
                                       str(self.bundle / 'profiles' / 'rescue-hermes' / 'kickoff.md')])
        self.assertEqual(os.path.realpath(rec['cwd']), os.path.realpath(reports))
        env = rec['env']
        self.assertEqual(env['HERMES_HOME'], str(hh))
        self.assertEqual(env['XDG_CACHE_HOME'], str(hh / 'xdg' / 'cache'))
        self.assertEqual(env['XDG_DATA_HOME'], str(hh / 'xdg' / 'data'))
        self.assertEqual(env['XDG_STATE_HOME'], str(hh / 'xdg' / 'state'))
        self.assertEqual(env['XDG_CONFIG_HOME'], str(hh / 'xdg' / 'config'))
        self.assertEqual(env['TMPDIR'], str(reports))
        self.assertEqual((env['PYTHONDONTWRITEBYTECODE'], env['PYTHONNOUSERSITE'], env['PYTHONSAFEPATH']), ('1', '1', '1'))
        self.assertEqual(env['HOME'], str(self.home))   # unchanged: Hermes writes nothing to HOME with HERMES_HOME set
        self.assertTrue(rec['key_matches'])
        self.assertFalse(rec['key_in_argv'])
        self.assertFalse(rec['github_token_present'])
        self.assertTrue(rec['stdin_tty'] and rec['stdout_tty'])   # the real terminal, not the log tee
        self.assertEqual(os.listdir(self.home), [])
        self.assertIn('Ctrl+D', output)
        self.assertNotIn(DUMMY_KEY, output)
        self.assertNotIn(DUMMY_KEY, next(reports.glob('launcher-linux-*.log')).read_text())

    def test_report_follow_up_and_latest_evidence_exist_before_hermes_starts(self):
        self.add_runtime()
        rc, output = self.pty_run()
        self.assertEqual(rc, 0, output)
        (rec,) = self.records()
        self.assertTrue(rec['report_before'])
        self.assertTrue(rec['latest_evidence'])
        self.assertTrue(rec['followup'])
        evidence = next((self.bundle / 'reports').glob('linux-*-evidence.json'))
        self.assertEqual((self.bundle / 'reports' / 'latest-evidence.json').read_text(), evidence.read_text())
        for step in ('[1/8]', '[2/8]', '[3/8]', '[4/8]', '[5/8]', '[6/8]', '[7/8]'):
            self.assertIn(step, output)

    def test_hermes_home_is_seeded_and_refreshed_but_user_state_is_kept(self):
        self.add_runtime()
        hh = self.bundle / 'hermes-home'
        (hh / 'memories').mkdir(parents=True)
        (hh / 'memories' / 'keep.txt').write_text('mine')
        (hh / 'SOUL.md').write_text('stale')
        rc, output = self.pty_run()
        self.assertEqual(rc, 0, output)
        prof = REPO / 'profiles' / 'rescue-hermes'
        self.assertEqual((hh / 'SOUL.md').read_text(), (prof / 'SOUL.md').read_text())
        self.assertEqual((hh / 'AGENTS.md').read_text(), (prof / 'AGENTS.md').read_text())
        self.assertEqual((hh / 'config.yaml').read_text(), (REPO / 'config' / 'hermes-rescue.config.yaml').read_text())
        for skill in (prof / 'skills').iterdir():
            self.assertEqual((hh / 'skills' / skill.name / 'SKILL.md').read_text(), (skill / 'SKILL.md').read_text())
        self.assertEqual((hh / 'memories' / 'keep.txt').read_text(), 'mine')
        self.assertEqual(stat.S_IMODE((hh / 'config.yaml').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(hh.stat().st_mode), 0o700)

    def test_the_key_comes_from_rescue_env_as_data_and_the_github_token_stays_out(self):
        self.add_runtime()
        env_file = self.bundle / 'config' / 'rescue.env'
        env_file.write_text("OPENCODE_GO_API_KEY='%s'\nRESCUE_GITHUB_ISSUES_TOKEN=dummy-gh-from-file\n" % DUMMY_KEY)
        env_file.chmod(0o600)
        env = self.env()
        del env['OPENCODE_GO_API_KEY'], env['RESCUE_GITHUB_ISSUES_TOKEN']
        rc, output = run_in_pty([str(self.script)], env, self.tmp)
        self.assertEqual(rc, 0, output)
        (rec,) = self.records()
        self.assertTrue(rec['key_matches'])
        self.assertFalse(rec['key_in_argv'])
        self.assertFalse(rec['github_token_present'])

    def test_hermes_exit_code_is_logged_but_never_changes_the_launcher_exit_code(self):
        self.add_runtime()
        rc, output = self.pty_run(FAKE_HERMES_EXIT='7')
        self.assertEqual(rc, 0, output)
        self.assertIn('exit code 7', output)

    def test_hermes_is_not_started_with_no_hermes_evidence_only_dry_run_or_without_a_terminal(self):
        self.add_runtime()
        for args in (('--no-hermes',), ('--evidence-only',), ('--dry-run',)):
            rc, output = self.pty_run(*args)
            self.assertEqual(rc, 0, (args, output))
        self.assertEqual(self.records(), [])
        proc = subprocess.run([str(self.script)], capture_output=True, text=True, env=self.env(), cwd=self.tmp, timeout=240)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('no interactive terminal', proc.stdout)
        self.assertEqual(self.records(), [])
        self.assertFalse((self.bundle / 'hermes-home').exists())

    def test_without_a_key_hermes_is_not_started_and_the_exit_code_is_3(self):
        self.add_runtime()
        env = self.env()
        del env['OPENCODE_GO_API_KEY']
        rc, output = run_in_pty([str(self.script)], env, self.tmp)
        self.assertEqual(rc, 3, output)
        self.assertEqual(self.records(), [])

    def test_a_missing_runtime_gets_a_bilingual_note_and_the_exit_code_is_unchanged(self):
        rc, output = self.pty_run()
        self.assertEqual(rc, 0, output)
        self.assertIn('--hermes-portable', output)
        self.assertIn('docs/hermes-portable.md', output)
        self.assertEqual(self.records(), [])

    def test_another_architecture_gets_the_note_not_a_failure(self):
        self.add_runtime()
        shim = self.tmp / 'shim'
        shim.mkdir()
        (shim / 'uname').write_text('#!/bin/sh\necho aarch64\n')
        (shim / 'uname').chmod(0o755)
        rc, output = self.pty_run(PATH=str(shim) + os.pathsep + os.environ['PATH'])
        self.assertEqual(rc, 0, output)
        self.assertIn('architecture is not on the USB', output)
        self.assertEqual(self.records(), [])

    def test_hermes_only_opens_hermes_on_the_existing_reports_without_scanning(self):
        self.add_runtime()
        rc, output = self.pty_run('--hermes-only')
        self.assertEqual(rc, 5, output)   # no reports yet
        self.assertEqual(self.records(), [])
        rc, output = self.pty_run('--no-hermes')
        self.assertEqual(rc, 0, output)
        before = sorted(p.name for p in (self.bundle / 'reports').iterdir() if not p.name.startswith('launcher-linux-'))
        seen = len(_FakeApi.seen)
        rc, output = self.pty_run('--hermes-only')
        self.assertEqual(rc, 0, output)
        (rec,) = self.records()
        self.assertEqual(rec['argv'][2:4], ['chat', '--cli'])
        self.assertEqual(len(_FakeApi.seen), seen)   # no analysis call
        after = sorted(p.name for p in (self.bundle / 'reports').iterdir() if not p.name.startswith('launcher-linux-'))
        self.assertEqual(after, before)
        for args in (('--hermes-only', '--no-hermes'), ('--hermes-only', '--dry-run'), ('--hermes-only', '--evidence-only')):
            rc, _ = self.pty_run(*args)
            self.assertEqual(rc, 64, args)

    def test_hermes_only_without_a_runtime_exits_6_with_the_note(self):
        rc, _ = self.pty_run('--no-hermes')
        self.assertEqual(rc, 0)
        rc, output = self.pty_run('--hermes-only')
        self.assertEqual(rc, 6, output)
        self.assertIn('--hermes-portable', output)


KEY_CASES = [
    "OPENCODE_GO_API_KEY=abc123\n",
    "export OPENCODE_GO_API_KEY=abc123\n",
    "OPENCODE_GO_API_KEY='abc$HOME`x`'\n",
    'OPENCODE_GO_API_KEY="abc def"\n',
    'OPENCODE_GO_API_KEY="abc$HOME"\n',
    'OPENCODE_GO_API_KEY="a\\"b\\\\c\\$d"\n',
    "OPENCODE_GO_API_KEY=abc$HOME\n",
    "OPENCODE_GO_API_KEY=`id`\n",
    "OPENCODE_GO_API_KEY=abc def\n",
    "OPENCODE_GO_API_KEY=abc # trailing comment\n",
    "# OPENCODE_GO_API_KEY=commented\n",
    "OPENCODE_GO_API_KEY=''\nOPENCODE_GO_API_KEY=second\n",
    "OPENCODE_GO_API_KEY='it'\\''s'\n",
    "OTHER=1\nOPENCODE_GO_API_KEY=abc\r\n",
    "  OPENCODE_GO_API_KEY = spaced  \n",
    "OPENCODE_GO_API_KEY=a\\ b\n",
    'OPENCODE_GO_API_KEY="unterminated\n',
    "OPENCODE_GO_API_KEY=first\nOPENCODE_GO_API_KEY=second\n",
    'OPENCODE_GO_API_KEY="$(id)"\n',
    "opencode_go_api_key=lower\n",
    "OPENCODE_GO_API_KEY=abc\"def\"'g h'\n",
    'OPENCODE_GO_API_KEY="bad$x"\nOPENCODE_GO_API_KEY=good\n',
]


def bash_reference_key(tmp, text):
    path = Path(tmp) / 'ref.env'
    path.write_bytes(text.encode('utf-8'))
    path.chmod(0o600)
    proc = subprocess.run(
        [BASH, '-c', 'source "$1"; rescue_load_env "$2" 2>/dev/null; printf %s "${OPENCODE_GO_API_KEY:-}"',
         '_', str(REPO / 'scripts/lib/rescue-env.sh'), str(path)],
        capture_output=True, text=True, env=clean_env())
    return proc.stdout


# --------------------------------------------------------------------------------------
# PowerShell launcher
# --------------------------------------------------------------------------------------
PS1 = HOST / 'rescue-windows.ps1'

PS_DRIVER = r'''
$ErrorActionPreference = 'Stop'
$env:RESCUE_PS_LIBRARY_ONLY = '1'
. $env:RESCUE_PS1
$work = $env:RESCUE_WORK
$res = @{}
$keys = @{}
foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $work 'cases') -Filter '*.env')) {
    $k = Get-ApiKeyFromEnvFile -Path $f.FullName
    if ($null -eq $k) { $k = '' }
    $keys[$f.Name] = $k
}
$res['keys'] = $keys
$inputs = Get-Content -Raw -LiteralPath (Join-Path $work 'release_in.json') | ConvertFrom-Json
$rel = @{}
$i = 0
foreach ($s in $inputs) { $rel[[string]$i] = (ConvertTo-SafeRelease -Text $s); $i++ }
$res['release'] = $rel
$res['sha_abc'] = Get-Sha256Hex -Text 'abc'
$res['session_abc'] = Get-SessionId -EvidenceJson 'abc'
function New-FakeErrorRecord([string]$Body) {
    $er = New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception('x')), 'id', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($Body)
    return $er
}
$res['etype_nested'] = Get-ProviderErrorType -ErrorRecord (New-FakeErrorRecord '{"type":"error","error":{"type":"MissingSessionID","message":"x"}}')
$res['etype_bad'] = Get-ProviderErrorType -ErrorRecord (New-FakeErrorRecord '{"error":{"type":"not a token!"}}')
$res['etype_html'] = Get-ProviderErrorType -ErrorRecord (New-FakeErrorRecord '<html>nope</html>')
$rej = @{}
foreach ($c in @(0, 200, 301, 400, 401, 402, 403, 404, 408, 422, 429, 500, 503)) { $rej[[string]$c] = [bool](Test-ProviderRejection -Code $c) }
$res['rejection'] = $rej
$res['opaque'] = Get-OpaqueTargetId -Seed 'machine-guid:SECRET-SEED'
$res['opaque_again'] = Get-OpaqueTargetId -Seed 'machine-guid:SECRET-SEED'
$res['opaque_other'] = Get-OpaqueTargetId -Seed 'machine-guid:OTHER'
try { [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('id-ID') } catch { }
$tricky = 'q"b\c' + "`n" + "`t" + "`r" + [string][char]1 + [string][char]0x00e9 + '$x`y'
$struct = [ordered]@{ s = $tricky; f = 18.6; i = 5; z = 0; l = [long]123456789012; t = $true; fa = $false; n = $null;
    arr1 = @('x'); arr0 = @(); d0 = [ordered]@{}; nested = @([ordered]@{ a = 1 }, [ordered]@{ b = @(1, 2) }) }
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $work 'ser.json'), (ConvertTo-RescueJson -Value $struct), $utf8)
[System.IO.File]::WriteAllText((Join-Path $work 'ser_pretty.json'), (ConvertTo-RescueJson -Value $struct -Indent 2), $utf8)
function New-Sample {
    $checks = @(
        (New-Check -Id 'os-detection' -Status 'pass'),
        (New-Check -Id 'disk-free-space' -Status 'warn' -Kind 'percent' -Number 12.5),
        (New-Check -Id 'windows-event-log-errors' -Status 'fail' -Kind 'count' -Number 60),
        (New-Check -Id 'network-connectivity' -Status 'unknown' -TargetRef '')
    )
    New-RescueEvidence -Checks $checks -Release (ConvertTo-SafeRelease -Text 'Microsoft Windows 11 Pro 23H2') `
        -Architecture 'x86_64' -Encryption 'bitlocker' -BootMode 'uefi' -OpaqueSeed 'machine-guid:SECRET-SEED'
}
function Get-ProblemCount($e) { $p = Test-RescueEvidence -Evidence $e; return [int]$p.Count }
$ev = New-Sample
$res['problems_ok'] = (Get-ProblemCount $ev)
[System.IO.File]::WriteAllText((Join-Path $work 'evidence.json'), (ConvertTo-RescueJson -Value $ev -Indent 2), $utf8)
$bad = New-Sample
$bad['checks'][0]['status'] = 'bogus'
$res['problems_status'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['evidence_manifest']['entry_count'] = 99
$res['problems_count'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['checks'][0]['check_id'] = 'made-up-check'
$res['problems_id'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['target_device_opaque_id'] = 'target-x'
$res['problems_opaque'] = (Get-ProblemCount $bad)
[System.IO.File]::WriteAllText((Join-Path $work 'result.json'), ($res | ConvertTo-Json -Depth 6), $utf8)
'''


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-ps-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def pwsh(self, *args, env=None):
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', *args], capture_output=True, text=True,
                              env=env or clean_env(), cwd=self.tmp, timeout=300)

    def test_script_parses_without_errors(self):
        script = ('$e = $null; $t = $null; '
                  '[void][System.Management.Automation.Language.Parser]::ParseFile($env:RESCUE_PS1, [ref]$t, [ref]$e); '
                  'if ($e -and $e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }')
        proc = self.pwsh('-Command', script, env=clean_env(RESCUE_PS1=str(PS1)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_pure_functions(self):
        work = self.tmp / 'work'
        (work / 'cases').mkdir(parents=True)
        for n, text in enumerate(KEY_CASES):
            (work / 'cases' / ('case%02d.env' % n)).write_bytes(text.encode('utf-8'))
        releases = ['Windows 11 Pro 23H2', 'Microsoft\u00ae Windows\u00ae 11', '', '  !!! ', '(x) Windows 10',
                    'A' * 100, 'Windows 11 <script>"x"</script>']
        (work / 'release_in.json').write_text(json.dumps(releases), encoding='utf-8')
        driver = work / 'driver.ps1'
        driver.write_text(PS_DRIVER, encoding='utf-8')
        proc = self.pwsh('-File', str(driver), env=clean_env(RESCUE_PS1=str(PS1), RESCUE_WORK=str(work)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        res = json.loads((work / 'result.json').read_text(encoding='utf-8'))

        # env parser parity with the bash reference implementation
        for n, text in enumerate(KEY_CASES):
            expected = bash_reference_key(self.tmp, text)
            self.assertEqual(res['keys']['case%02d.env' % n], expected, repr(text))

        # release sanitizer
        pattern = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$')
        rel = res['release']
        self.assertEqual(rel['0'], 'Windows 11 Pro 23H2')
        self.assertEqual(rel['1'], 'Microsoft Windows 11')
        self.assertIsNone(rel['2'])
        self.assertIsNone(rel['3'])
        self.assertEqual(rel['4'], 'x) Windows 10')
        for key in ('0', '1', '4', '5', '6'):
            self.assertRegex(rel[key], pattern)
        self.assertLessEqual(len(rel['5']), 64)

        # hashing and opaque id
        self.assertEqual(res['sha_abc'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        # x-opencode-session derivation equals the Python analyzer's; the provider error type is a token or nothing
        self.assertEqual(res['session_abc'], 'ses_ba7816bf8f01cfea414140de5dae2223')
        self.assertEqual(res['etype_nested'], 'MissingSessionID')
        self.assertIn(res['etype_bad'], ('', None))
        self.assertIn(res['etype_html'], ('', None))
        self.assertEqual({k for k, v in res['rejection'].items() if v}, {'400', '402', '404', '422'})
        self.assertRegex(res['opaque'], r'^target-[a-f0-9]{16}$')
        self.assertEqual(res['opaque'], res['opaque_again'])
        self.assertNotEqual(res['opaque'], res['opaque_other'])
        self.assertNotIn('SECRET-SEED', res['opaque'])

        # serializer: round-trips through a real JSON parser, culture-independent
        expected = {
            's': 'q"b\\c\n\t\r\x01\u00e9$x`y', 'f': 18.6, 'i': 5, 'z': 0, 'l': 123456789012, 't': True, 'fa': False,
            'n': None, 'arr1': ['x'], 'arr0': [], 'd0': {}, 'nested': [{'a': 1}, {'b': [1, 2]}],
        }
        self.assertEqual(json.loads((work / 'ser.json').read_text(encoding='utf-8')), expected)
        self.assertEqual(json.loads((work / 'ser_pretty.json').read_text(encoding='utf-8')), expected)
        self.assertNotIn('\n', (work / 'ser.json').read_text(encoding='utf-8'))

        # evidence builder + self-check
        self.assertEqual(res['problems_ok'], 0)
        for key in ('problems_status', 'problems_count', 'problems_id', 'problems_opaque'):
            self.assertGreater(res[key], 0, key)
        evidence = work / 'evidence.json'
        validate_evidence(self, evidence)
        data = json.loads(evidence.read_text(encoding='utf-8'))
        self.assertEqual(data['source_platform'], 'windows-host')
        self.assertEqual(data['classification'], 'confidential')
        self.assertEqual(data['target_systems'][0]['detection'], 'host-native')
        self.assertNotIn('target_ref', data['checks'][-1])
        self.assertNotIn('SECRET-SEED', evidence.read_text(encoding='utf-8'))

    def test_evidence_only_end_to_end_on_any_platform(self):
        """On Linux pwsh every Windows-only check degrades to 'unknown'; the output must still be valid."""
        usb, bundle = make_usb(self.tmp)
        script = bundle / 'host' / 'rescue-windows.ps1'
        proc = self.pwsh('-File', str(script), '-EvidenceOnly')  # layout: <bundle>/host/ -> ../
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        reports = sorted((bundle / 'reports').iterdir())
        # evidence + the run report (run-<utc>/ and index.md, docs/run-report.md); nothing else on the USB
        self.assertEqual([p.name for p in reports if not p.name.startswith('run-') and p.name != 'index.md'],
                         [p.name for p in reports if p.name.startswith('windows-')])
        evidence = one(bundle.joinpath('reports').glob('windows-*-evidence.json'), self)
        self.assertEqual(len([p for p in reports if p.name.startswith('run-')]), 1, [p.name for p in reports])
        self.assertEqual(len(reports), 3, [p.name for p in reports])
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        assert_no_identity(self, text, self.tmp)
        data = json.loads(text)
        self.assertEqual(data['evidence_manifest']['entry_count'], len(data['checks']))
        self.assertEqual(data['ai_provider']['authenticated'], False)

    def test_dry_run_and_missing_bundle(self):
        usb, bundle = make_usb(self.tmp)
        script = bundle / 'host' / 'rescue-windows.ps1'
        proc = self.pwsh('-File', str(script), '-DryRun',
                         env=clean_env(OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('API key found : yes', proc.stdout)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(script, lonely / 'rescue-windows.ps1')
        proc = self.pwsh('-File', str(lonely / 'rescue-windows.ps1'), '-EvidenceOnly')
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)


# --------------------------------------------------------------------------------------
# macOS launcher (zsh)
# --------------------------------------------------------------------------------------
MAC = HOST / 'RESCUE-MACOS.command'

PLIST = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>APFSContainerReference</key>
\t<string>disk3</string>
\t<key>FilesystemType</key>
\t<string>apfs</string>
\t<key>Internal</key>
\t<true/>
</dict>
</plist>
'''

SHIMS = {
    'uname': '''#!/bin/bash
case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) exec /usr/bin/uname "$@" ;; esac
''',
    'sw_vers': '#!/bin/bash\n[ "$1" = -productVersion ] && echo 14.5\n',
    'sysctl': '#!/bin/bash\necho 1\n',
    'fdesetup': '#!/bin/bash\necho "FileVault is On."\n',
    'csrutil': '#!/bin/bash\necho "System Integrity Protection status: enabled."\n',
    'bless': '#!/bin/bash\necho /dev/disk3s1\n',
    'ioreg': '#!/bin/bash\necho \'    "IOPlatformUUID" = "11111111-2222-3333-4444-555555555555"\'\n',
    'nc': '#!/bin/bash\nexit 0\n',
    'diskutil': '#!/bin/bash\ncat "$(dirname "$0")/fixture.plist"\n',
    # Only the JSON-file form used for the answer; the stdin-plist form fails so the awk fallback is exercised.
    'plutil': '''#!/bin/bash
last=${!#}
if [ "$1" = -extract ] && [ "$2" = choices.0.message.content ] && [ -f "$last" ]; then
  /usr/bin/env python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["choices"][0]["message"]["content"])' "$last"
else exit 1; fi
''',
    # Fake curl: records argv, stdin config and request body; never touches the network.
    'curl': '''#!/bin/bash
dir=$(dirname "$0")
printf '%s\\n' "$@" > "$dir/curl.argv"
cat > "$dir/curl.stdin"
out=''; body=''
while [ $# -gt 0 ]; do
  case "$1" in --output) out=$2; shift 2 ;; --data-binary) body=${2#@}; shift 2 ;; *) shift ;; esac
done
[ -n "$body" ] && cp "$body" "$dir/curl.body"
mode=$(cat "$dir/curl.mode" 2>/dev/null || echo ok)
if [ "$mode" = ok ]; then
  cp "$dir/response.json" "$out"
  printf 200
elif [ "$mode" = reject ]; then
  printf '%s' '{"type":"error","error":{"type":"MissingSessionID","message":"secret response text"}}' > "$out"
  printf 400
else
  printf '{}' > "$out"
  printf 500
fi
''',
}


class MacLauncherStaticTests(unittest.TestCase):
    def setUp(self):
        # The repair engine's list of refused program names (a mirror of FORBIDDEN_PROGRAMS) names the
        # very words this test forbids; it is fenced by markers and checked in tests/test_host_repair.py.
        self.text = re.sub(r'# BEGIN forbidden-programs.*?# END forbidden-programs', '',
                           MAC.read_text(encoding='utf-8'), flags=re.S)

    def test_forbidden_constructs_absent(self):
        for pattern in (r'\bpython3?\b', r'\bsource\s', r'^\s*\.\s+\S', r'\beval\b', r'\bsudo\b', r'\bosascript\b.*\bdo shell script\b',
                        r'\bhostname\b', r'\bwhoami\b', r'scutil', r'\bid -un\b'):
            self.assertIsNone(re.search(pattern, self.text, re.M), 'forbidden pattern: ' + pattern)

    def test_key_only_in_curl_stdin_config(self):
        lines = [l for l in self.text.splitlines() if 'Authorization' in l]
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(re.search(r'^http=\$\(print -r -- "header = .*Authorization: Bearer \$qkey.*\| curl --config - \\$', lines[0]), lines[0])
        self.assertIsNone(re.search(r'(-H|--header)\s+["\']?Authorization', self.text))
        self.assertIn('--data-binary @"$req"', self.text)


@unittest.skipUnless(ZSH, 'zsh not installed')
class MacLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-mac-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp, launcher_at_root='RESCUE-MACOS.command')
        self.shims = self.tmp / 'shims'
        self.shims.mkdir()
        for name, body in SHIMS.items():
            path = self.shims / name
            path.write_text(body)
            path.chmod(0o755)
        (self.shims / 'fixture.plist').write_text(PLIST)
        (self.shims / 'response.json').write_text(
            json.dumps({'choices': [{'message': {'role': 'assistant', 'content': CANNED_ANSWER}}]}))
        self.home = self.tmp / 'home'
        crash = self.home / 'Library/Logs/DiagnosticReports'
        crash.mkdir(parents=True)
        for name in ('a.crash', 'b.ips'):
            (crash / name).write_text('x')
        old = crash / 'old.crash'
        old.write_text('x')
        os.utime(old, (1_000_000_000, 1_000_000_000))
        self.script = self.usb / 'RESCUE-MACOS.command'

    def env(self, **extra):
        return clean_env(PATH=str(self.shims) + os.pathsep + os.environ.get('PATH', ''), HOME=str(self.home), **extra)

    def run_launcher(self, *args, script=None, env=None):
        return subprocess.run([ZSH, str(script or self.script), '--no-pause', *args], capture_output=True, text=True,
                              env=env or self.env(), cwd=self.tmp, stdin=subprocess.DEVNULL, timeout=120)

    def reports(self, pattern):
        return sorted((self.bundle / 'reports').glob(pattern))

    def write_env_file(self, text):
        (self.bundle / 'config').mkdir(exist_ok=True)
        path = self.bundle / 'config' / 'rescue.env'
        path.write_bytes(text.encode('utf-8'))
        path.chmod(0o600)

    def test_syntax(self):
        proc = subprocess.run([ZSH, '-n', str(MAC)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_evidence_only_valid_and_expected_checks(self):
        before = bundle_files(self.bundle)
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        evidence = one(self.reports('macos-*-evidence.json'), self)
        self.assertEqual([p.name for p in (self.bundle / 'reports').iterdir()], [evidence.name])
        self.assertEqual(bundle_files(self.bundle), before)
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        assert_no_identity(self, text, self.tmp)
        self.assertNotIn('11111111-2222', text)  # IOPlatformUUID is hashed, never emitted
        data = json.loads(text)
        self.assertEqual(data['source_platform'], 'macos-host')
        self.assertEqual(data['classification'], 'confidential')
        target = data['target_systems'][0]
        self.assertEqual((target['family'], target['release'], target['architecture'], target['encryption']),
                         ('macos', 'macOS 14.5', 'arm64', 'filevault'))
        checks = {c['check_id']: c for c in data['checks']}
        # Detection modules (hw-*, sw-*) add their own checks; they are tested in their own test files.
        self.assertEqual([c for c in checks if not c.startswith(('hw-', 'sw-', 'malware-'))], ['os-detection', 'macos-apfs-container', 'macos-filevault', 'macos-sip-status',
                                        'macos-crash-reports', 'macos-startup-disk', 'disk-free-space',
                                        'network-connectivity', 'macos-disk-verify'])
        for name in ('os-detection', 'macos-apfs-container', 'macos-filevault', 'macos-sip-status', 'macos-startup-disk'):
            self.assertEqual(checks[name]['status'], 'pass', name)
        self.assertEqual(checks['macos-crash-reports']['status'], 'warn')
        self.assertEqual(checks['macos-crash-reports']['value'], {'kind': 'count', 'number': 2})
        self.assertEqual(checks['disk-free-space']['value']['kind'], 'percent')
        self.assertEqual(checks['network-connectivity']['status'], 'unknown')
        self.assertNotIn('target_ref', checks['network-connectivity'])
        self.assertEqual(data['evidence_manifest']['entry_count'], len(data['checks']))

    def test_layout_from_rescue_omes_host_folder(self):
        proc = self.run_launcher('--evidence-only', script=self.bundle / 'host' / 'RESCUE-MACOS.command')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        one(self.reports('macos-*-evidence.json'), self)

    def test_refuses_non_darwin_and_missing_bundle(self):
        (self.shims / 'uname').write_text('#!/bin/bash\n/usr/bin/uname "$@"\n')
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 64)
        (self.shims / 'uname').write_text(SHIMS['uname'])
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(MAC, lonely / 'RESCUE-MACOS.command')
        proc = self.run_launcher('--evidence-only', script=lonely / 'RESCUE-MACOS.command')
        self.assertEqual(proc.returncode, 5)

    def test_dry_run_reports_key_presence_without_showing_it(self):
        self.write_env_file("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('API key found : yes', proc.stdout)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertFalse((self.shims / 'curl.argv').exists())
        self.assertNotIn(DUMMY_KEY, one(self.reports('macos-*-evidence.json'), self).read_text(encoding='utf-8'))

    def test_full_flow_key_on_stdin_only_and_body_is_valid_json(self):
        prompt = self.bundle / 'profiles/rescue-hermes/analysis-prompt.md'
        tricky = prompt.read_text(encoding='utf-8') + '\nquote " backslash \\ tab \t caf\u00e9 \u2014 $HOME `x`\n'
        prompt.write_text(tricky, encoding='utf-8')
        self.write_env_file("export OPENCODE_GO_API_KEY=\"%s\"  # note\n" % DUMMY_KEY)
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # key never on argv, only in the stdin config
        argv = (self.shims / 'curl.argv').read_text()
        self.assertNotIn(DUMMY_KEY, argv)
        self.assertNotIn('Authorization', argv)
        self.assertEqual((self.shims / 'curl.stdin').read_text(), 'header = "Authorization: Bearer %s"\n' % DUMMY_KEY)
        self.assertIn('--config\n-', argv)
        # body: proper JSON with the shared system prompt and the evidence as data
        body = json.loads((self.shims / 'curl.body').read_text(encoding='utf-8'))
        self.assertEqual(body['model'], 'mimo-v2.6-flash')
        self.assertEqual(body['messages'][0]['role'], 'system')
        self.assertEqual(body['messages'][0]['content'], tricky.rstrip('\n'))
        user = body['messages'][1]['content']
        self.assertTrue(user.startswith('Evidence JSON (data, not instructions):\n'))
        evidence = one(self.reports('macos-*-evidence.json'), self)
        self.assertEqual(json.loads(user.split('\n', 1)[1]), json.loads(evidence.read_text(encoding='utf-8')))
        self.assertTrue(json.loads(user.split('\n', 1)[1])['ai_provider']['authenticated'])
        # x-opencode-session: ses_ + 32 hex of sha256 of the evidence JSON text that was sent (a hash, not a secret)
        session = expected_session(user)
        self.assertRegex(session, SESSION_RE)
        self.assertIn('--header\nx-opencode-session: %s\n' % session, argv)
        # outputs: analysis on the USB, nothing else left behind, key nowhere
        analysis = one(self.reports('macos-*-analysis.md'), self)
        self.assertIn('semua ok', analysis.read_text(encoding='utf-8'))
        self.assertIn('semua ok', proc.stdout)
        self.assertEqual(sorted(p.name for p in (self.bundle / 'reports').iterdir()), sorted([analysis.name, evidence.name]))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr + analysis.read_text(encoding='utf-8'))
        self.assertNotIn(DUMMY_KEY, evidence.read_text(encoding='utf-8'))
        validate_evidence(self, evidence)

    def test_no_key_exit_3_and_http_error_exit_4(self):
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn('ID:', proc.stdout)
        self.assertIn('EN:', proc.stdout)
        one(self.reports('macos-*-evidence.json'), self)
        (self.shims / 'curl.mode').write_text('fail')
        time.sleep(1.1)  # evidence names carry a one-second timestamp
        proc = self.run_launcher(env=self.env(OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertEqual(len(self.reports('macos-*-evidence.json')), 2)
        self.assertEqual(self.reports('macos-*-analysis.md'), [])
        self.assertEqual([p.name for p in (self.bundle / 'reports').iterdir() if p.name.startswith('.')], [])

    def test_provider_rejection_exit_4_outcome_and_message_without_the_response_body(self):
        self.write_env_file("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        (self.shims / 'curl.mode').write_text('reject')
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        text = proc.stdout + proc.stderr
        self.assertIn('HTTP 400 (MissingSessionID)', text)
        self.assertIn('ID: OpenCode Go menolak permintaan', text)
        self.assertIn('EN: OpenCode Go rejected the request', text)
        self.assertNotIn('secret response text', text)
        self.assertNotIn(DUMMY_KEY, text)
        self.assertEqual([p.name for p in (self.bundle / 'reports').iterdir() if p.name.startswith('.')], [])
        # The run report outcome is covered in tests/test_run_report.py (MacReportTests): the macOS launcher
        # writes a report only when osascript exists, and this class has no osascript shim.

    def test_key_parser_matches_bash_reference(self):
        for text in KEY_CASES:
            expected = bash_reference_key(self.tmp, text)
            for leftover in (self.shims / 'curl.stdin', self.shims / 'curl.argv'):
                leftover.unlink(missing_ok=True)
            self.write_env_file(text)
            proc = self.run_launcher()
            if not expected:
                self.assertEqual(proc.returncode, 3, (text, proc.stdout, proc.stderr))
                continue
            self.assertEqual(proc.returncode, 0, (text, proc.stdout, proc.stderr))
            config = (self.shims / 'curl.stdin').read_text(encoding='utf-8')
            match = re.fullmatch(r'header = "Authorization: Bearer (.*)"\n', config, re.S)
            self.assertIsNotNone(match, text)
            sent = match.group(1).replace('\\"', '"').replace('\\\\', '\\')
            self.assertEqual(sent, expected, repr(text))


# --------------------------------------------------------------------------------------
# Static tests over all launchers
# --------------------------------------------------------------------------------------
class StaticTests(unittest.TestCase):
    LAUNCHERS = ('RESCUE-WINDOWS.cmd', 'rescue-windows.ps1', 'RESCUE-MACOS.command', 'rescue-linux.sh')

    def text(self, name):
        return (HOST / name).read_text(encoding='utf-8')

    def test_no_host_temp_or_host_writes(self):
        forbidden = (r'/tmp\b', r'\bmktemp\b', r'\$env:TEMP', r'\$env:TMP\b', r'%TEMP%', r'%TMP%', r'GetTempPath',
                     r'GetTempFileName', r'New-TemporaryFile', r'\bOut-File\b', r'\bSet-Content\b', r'\bAdd-Content\b',
                     r'\$\{?TMPDIR', r'\bsetx\b', r'\breg\s+add\b', r'\bSet-ItemProperty\b', r'\bNew-ItemProperty\b',
                     r'\bdefaults\s+write\b', r'\bcrontab\b')
        for name in self.LAUNCHERS:
            text = self.text(name)
            for pattern in forbidden:
                self.assertIsNone(re.search(pattern, text), '%s: %s' % (name, pattern))
        # Python temp files in the Linux launcher must live in the reports folder.
        for line in self.text('rescue-linux.sh').splitlines():
            if 'tempfile.' in line and 'import' not in line:
                self.assertIn('dir=reports', line)

    def test_no_dynamic_code_or_elevation(self):
        ps = self.text('rescue-windows.ps1')
        for pattern in (r'Invoke-Expression', r'\biex\b', r'^\s*\.\s+[\$"\']', r'Start-Process', r'RunAs', r'Add-Type',
                        r'\bUSERNAME\b', r'\bCOMPUTERNAME\b', r'MachineName', r'\bUserName\b', r'\bwhoami\b'):
            self.assertIsNone(re.search(pattern, ps, re.M | re.I), pattern)
        sh = self.text('rescue-linux.sh')
        # the only sourced files are the bundle's own libraries (progress.sh, rescue-env.sh: the key parser)
        own = re.compile(r'^\s*source "\$bundle/scripts/lib/(progress|rescue-env)\.sh"$', re.M)
        self.assertEqual(len(own.findall(sh)), 2)
        sh = own.sub('', sh)
        for pattern in (r'\beval\b', r'\bsudo\b', r'\bsource\s', r'^\s*\.\s+\S', r'\bwhoami\b', r'\bpkexec\b'):
            self.assertIsNone(re.search(pattern, sh, re.M), pattern)

    def test_every_native_engine_sends_the_session_header_derived_from_the_evidence_it_sends(self):
        # OpenCode Go refuses a request without x-opencode-session (HTTP 400 MissingSessionID). All engines derive
        # the same value: ses_ + the first 32 hex characters of sha256 of the evidence JSON text in the request.
        py = (REPO / 'scripts' / 'opencode-go-analyze.py').read_text(encoding='utf-8')
        self.assertIn("SESSION_HEADER = 'x-opencode-session'", py)
        self.assertIn("'ses_' + hashlib.sha256(evidence_text.encode('utf-8')).hexdigest()[:32]", py)
        self.assertIn('SESSION_HEADER: session_id_for(evidence_text)', py)
        ps = self.text('rescue-windows.ps1')
        self.assertIn("'ses_' + (Get-Sha256Hex -Text $EvidenceJson).Substring(0, 32)", ps)
        self.assertIn("'x-opencode-session' = (Get-SessionId -EvidenceJson $EvidenceJson)", ps)
        mac = self.text('RESCUE-MACOS.command')
        self.assertIn('session_id=ses_$(sha256_str "$ev")', mac)
        self.assertIn('session_id=${session_id[1,36]}', mac)  # 'ses_' + 32 hex
        self.assertIn('--header "x-opencode-session: $session_id"', mac)
        # the body carries the same $ev text that is hashed
        self.assertIn('user_text="Evidence JSON (data, not instructions):"$\'\\n\'$ev', mac)

    def test_every_engine_maps_an_http_4xx_answer_to_provider_rejected(self):
        # Same classification everywhere: 4xx except 401/403/408/429 is provider-rejected; the rest stays network-error.
        self.assertIn('NOT_REJECTION_CODES = frozenset((401, 403, 408, 429))',
                      (REPO / 'scripts' / 'opencode-go-analyze.py').read_text(encoding='utf-8'))
        self.assertIn("@(401, 403, 408, 429) -notcontains $Code", self.text('rescue-windows.ps1'))
        self.assertIn("rr_outcome=provider-rejected", self.text('RESCUE-MACOS.command'))
        self.assertIn('$http != (401|403|408|429)', self.text('RESCUE-MACOS.command'))
        self.assertIn("$script:Rep.Outcome = 'provider-rejected'", self.text('rescue-windows.ps1'))
        for name in ('rescue-linux.sh',):
            self.assertIn('run_outcome=provider-rejected', self.text(name))
        self.assertIn('run_outcome=provider-rejected', (REPO / 'scripts' / 'launch-hermes-rescue.sh').read_text(encoding='utf-8'))
        for name in ('rescue-windows.ps1', 'RESCUE-MACOS.command'):
            text = self.text(name)
            self.assertIn('provider-rejected-request', text)
            # the response body is never echoed: only a token of at most 64 characters
            self.assertIn('[A-Za-z][A-Za-z0-9_]{0,63}', text)

    def test_every_launcher_keeps_the_first_failure_and_hands_the_repair_exit_to_its_report(self):
        # #56: repair-invalid only replaces completed/evidence-only/dry-run; journal-unusable outranks; the engine failure
        # reaches the generator (Python --repair-exit, PowerShell -RepairExit, JXA RESCUE_RR_REPAIR_EXIT) as an open item.
        win, mac = self.text('rescue-windows.ps1'), self.text('RESCUE-MACOS.command')
        lin = self.text('rescue-linux.sh')
        live = (REPO / 'scripts' / 'launch-hermes-rescue.sh').read_text(encoding='utf-8')
        self.assertNotIn("if ($rc -eq 2) { $script:Rep.Outcome = 'repair-invalid' }", win)
        self.assertIn("@('completed', 'evidence-only', 'dry-run') -ccontains $script:Rep.Outcome", win)
        self.assertIn("$script:Rep.Outcome = 'journal-unusable'", win)
        self.assertIn('-RepairExit ([int]$r.RepairExit)', win)
        self.assertNotIn('(( repair_rc == 2 )) && rr_outcome=repair-invalid', mac)
        self.assertIn('case $rr_outcome in completed|evidence-only|dry-run) rr_outcome=repair-invalid ;; esac', mac)
        self.assertIn('(( repair_rc == 5 )) && rr_outcome=journal-unusable', mac)
        self.assertIn('RESCUE_RR_REPAIR_EXIT', mac)
        self.assertNotIn('2) run_outcome=repair-invalid ;;', live)
        self.assertIn('2) case $run_outcome in completed) run_outcome=repair-invalid ;; *) ;; esac ;;', live)
        self.assertIn('3) run_outcome=journal-unusable ;;', live)
        self.assertIn('--repair-exit "$repair_rc"', live)
        self.assertIn('--repair-exit "$repair_rc"', lin)
        for text in (win, mac):  # the same open item in the native generators (equality: tests/test_run_report.py)
            self.assertIn("repair-engine-failed", text)

    def test_windows_wrapper(self):
        raw = (HOST / 'RESCUE-WINDOWS.cmd').read_bytes()
        self.assertNotIn(b'\n', raw.replace(b'\r\n', b''))  # CRLF only
        text = raw.decode('ascii')
        self.assertIn('-NoProfile -ExecutionPolicy Bypass -File', text)
        self.assertIn('rescue-omes\\host\\rescue-windows.ps1', text)
        self.assertRegex(text, r'(?im)^pause\b')
        self.assertNotRegex(text, r'(?i)runas|Start-Process|-Verb')

    def test_powershell_is_ascii_for_windows_powershell_5_1(self):
        # Windows PowerShell 5.1 reads a BOM-less script as the ANSI code page.
        (HOST / 'rescue-windows.ps1').read_bytes().decode('ascii')

    def test_launchers_are_executable_where_needed(self):
        for name in ('RESCUE-MACOS.command', 'rescue-linux.sh'):
            self.assertTrue(os.access(HOST / name, os.X_OK), name)
            self.assertTrue(stat.S_IMODE((HOST / name).stat().st_mode) & 0o100, name)

    def test_api_key_is_not_hardcoded_or_logged(self):
        for name in self.LAUNCHERS:
            text = self.text(name)
            self.assertNotIn(DUMMY_KEY, text)
            for line in text.splitlines():
                if re.search(r'(?i)(write-host|echo|printf|\bprint\b)', line):
                    self.assertIsNone(re.search(r'(?i)\$\{?(apiKey|api_key)\b', line), name + ': ' + line.strip()[:80])



# ---------------------------------------------------------------------------------------
# Detection module hooks and scope/policy flags (repair contract, schema 1.2)
# ---------------------------------------------------------------------------------------

def checks_by_id(data):
    return {c['check_id']: c for c in data['checks']}


class LinuxModuleHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-linux-mod-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp)
        mods = self.bundle / 'scripts' / 'rescue_modules'
        (mods / 'hardware.py').write_text(
            "def collect_system(ctx):\n"
            "    return [{'check_id': 'hw-cpu', 'status': 'pass'}, {'check_id': 'bogus', 'status': 'pass'},\n"
            "            {'check_id': 'hw-battery', 'status': 'warn', 'kind': 'percent', 'number': 55}]\n")
        (mods / 'software.py').write_text(
            "def collect_system(ctx):\n"
            "    return [{'check_id': 'sw-inventory', 'status': 'pass', 'kind': 'count', 'number': len(ctx.packages) or 7}]\n")
        (mods / 'operating_system.py').write_text("def collect_system(ctx):\n    raise RuntimeError('boom')\n")

    def run_launcher(self, *args):
        return subprocess.run([str(self.bundle / 'host' / 'rescue-linux.sh'), '--evidence-only', *args],
                              capture_output=True, text=True, env=clean_env(), cwd=self.tmp, timeout=180)

    def evidence(self):
        return json.loads(one(sorted((self.bundle / 'reports').glob('linux-*-evidence.json')), self).read_text())

    def test_modules_add_validated_checks_and_scope_is_recorded(self):
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        checks = checks_by_id(data)
        self.assertNotIn('target_ref', checks['hw-cpu'])            # hardware describes the machine
        self.assertEqual(checks['hw-battery']['value'], {'kind': 'percent', 'number': 55})
        self.assertEqual(checks['sw-inventory']['target_ref'], 'os-0')  # software of the running OS
        self.assertNotIn('bogus', checks)
        self.assertIn('dropped a check', proc.stderr)
        self.assertIn('operating_system.collect_system failed', proc.stderr)
        self.assertEqual((data['scope'], data['repair_policy']), (['all'], 'approve-each'))
        self.assertIn('Repair plan', proc.stdout)                    # --evidence-only still lists the plan
        validate_evidence(self, one(sorted((self.bundle / 'reports').glob('linux-*-evidence.json')), self))

    def test_scope_selects_modules(self):
        proc = self.run_launcher('--scope', 'hardware.cpu', '--repair-policy', 'detect-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        self.assertIn('hw-cpu', checks_by_id(data))
        self.assertNotIn('sw-inventory', checks_by_id(data))
        self.assertEqual((data['scope'], data['repair_policy']), (['hardware.cpu'], 'detect-only'))

    def test_invalid_flags_are_usage_errors(self):
        for args in (('--scope', 'all,os'), ('--scope', 'x;y'), ('--repair-policy', 'always'),
                     ('--packages', '-rf')):
            with self.subTest(args=args):
                self.assertEqual(self.run_launcher(*args).returncode, 64)


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellModuleHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-ps-mod-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp)
        mods = self.bundle / 'host' / 'modules' / 'windows'
        (mods / 'hardware.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n"
            "@{ check_id = 'hw-cpu'; status = 'pass' }\n"
            "@{ check_id = 'bogus'; status = 'pass' }\n"
            "@{ check_id = 'hw-battery'; status = 'warn'; kind = 'percent'; number = 55 }\n"
            "'just a string'\n")
        (mods / 'software.ps1').write_text("param([string[]]$Scope, [string[]]$Packages)\nthrow 'boom'\n")
        (mods / 'os.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n@{ check_id = 'windows-system-files'; status = 'unknown' }\n")

    def run_ps(self, *args):
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File',
                               str(self.bundle / 'host' / 'rescue-windows.ps1'), '-EvidenceOnly', *args],
                              capture_output=True, text=True, env=clean_env(), cwd=self.tmp, timeout=300)

    def evidence(self):
        return json.loads(one(sorted((self.bundle / 'reports').glob('windows-*-evidence.json')), self).read_text())

    def test_modules_add_validated_checks(self):
        proc = self.run_ps()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        checks = checks_by_id(data)
        self.assertNotIn('target_ref', checks['hw-cpu'])
        self.assertEqual(checks['hw-battery']['value'], {'kind': 'percent', 'number': 55})
        self.assertEqual(checks['windows-system-files']['target_ref'], 'os-0')
        self.assertNotIn('bogus', checks)
        self.assertIn('module software failed', proc.stdout)
        self.assertEqual((data['schema_version'], data['scope'], data['repair_policy']), ('1.2', ['all'], 'approve-each'))
        validate_evidence(self, one(sorted((self.bundle / 'reports').glob('windows-*-evidence.json')), self))

    def test_scope_and_policy(self):
        proc = self.run_ps('-Scope', 'os', '-RepairPolicy', 'detect-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        self.assertNotIn('hw-cpu', checks_by_id(data))
        self.assertIn('windows-system-files', checks_by_id(data))
        self.assertEqual((data['scope'], data['repair_policy']), (['os'], 'detect-only'))
        self.assertEqual(self.run_ps('-Scope', 'all,os').returncode, 64)
        self.assertEqual(self.run_ps('-Packages', '-rf').returncode, 64)


@unittest.skipUnless(ZSH, 'zsh not installed')
class MacModuleHookTests(unittest.TestCase):
    """Reuses the macOS shims and helpers of MacLauncherTests; only the module hook tests run here."""
    env = MacLauncherTests.env
    run_launcher = MacLauncherTests.run_launcher
    reports = MacLauncherTests.reports

    def setUp(self):
        MacLauncherTests.setUp(self)
        mods = self.bundle / 'host' / 'modules' / 'macos'
        (mods / 'hardware.zsh').write_text(
            'print -r -- "hw-cpu pass"\nprint -r -- "hw-battery warn percent 55"\n'
            'print -r -- "bogus-id pass"\nprint -r -- "hw-cpu pass; rm -rf /"\nprint -r -- "scope=$RESCUE_SCOPE"\n')
        (mods / 'software.zsh').write_text('print -r -- "sw-inventory pass count 42"\n')
        (mods / 'os.zsh').write_text('exit 3\n')

    def evidence(self):
        return json.loads(one(self.reports('macos-*-evidence.json'), self).read_text())

    def test_modules_add_validated_checks(self):
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        checks = checks_by_id(data)
        self.assertNotIn('target_ref', checks['hw-cpu'])
        self.assertEqual(checks['hw-battery']['value'], {'kind': 'percent', 'number': 55})
        self.assertEqual(checks['sw-inventory']['target_ref'], 'os-0')
        self.assertNotIn('bogus-id', checks)
        self.assertEqual(proc.stdout.count('emitted an invalid check'), 3)
        self.assertIn('module os failed', proc.stdout)
        self.assertEqual((data['schema_version'], data['scope'], data['repair_policy']), ('1.2', ['all'], 'approve-each'))
        validate_evidence(self, one(self.reports('macos-*-evidence.json'), self))

    def test_scope_and_policy(self):
        proc = self.run_launcher('--evidence-only', '--scope', 'software', '--repair-policy', 'auto-safe')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = self.evidence()
        self.assertNotIn('hw-cpu', checks_by_id(data))
        self.assertIn('sw-inventory', checks_by_id(data))
        self.assertEqual((data['scope'], data['repair_policy']), (['software'], 'auto-safe'))
        for args in (('--scope', 'all,os'), ('--scope', 'hardware,hardware.cpu'), ('--repair-policy', 'x')):
            with self.subTest(args=args):
                self.assertEqual(self.run_launcher('--evidence-only', *args).returncode, 64)


if __name__ == '__main__':
    unittest.main()
