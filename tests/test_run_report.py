#!/usr/bin/env python3
"""Tests for the comprehensive run report (ahliweb/linux-mint-xfce-rescue-ai#22).

* Model + renderer (scripts/lib/run_report.py) from synthetic evidence, analysis, hash-chained journal,
  readiness: sections, redaction, privacy self-check, tamper case, schema validation.
* CLI (scripts/rescue-report.py): files, modes, exit codes, end-to-end with the real repair engine.
* Cross-check: for the same inputs the PowerShell generator (host/rescue-windows.ps1, pwsh) and the JXA
  generator (host/RESCUE-MACOS.command, run by node behind tests/host_osascript_shim.js) produce a
  report.json / report.md / index.md equal to the Python generator's.
* Launcher wiring: Linux host, live-USB, Windows and macOS launchers write the report at their exit paths
  (including failed runs), and re-scan after an executed action so the before/after list is filled.

Offline: fixtures and fakes only. Real Windows and macOS behavior is Hardware-required and NOT tested.
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import getpass
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import jsonschema
except ImportError:  # the suite needs python3-jsonschema like the catalog and evidence tests
    raise unittest.SkipTest('python3-jsonschema is required')

import test_host_launchers as HL  # noqa: E402
import test_host_repair as HR  # noqa: E402

REPO = HL.REPO
sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
import repair_catalog as rc  # noqa: E402
import run_report as rr  # noqa: E402

CLI = REPO / 'scripts' / 'rescue-report.py'
SCHEMA = json.loads((REPO / 'rescue-ai/v1/run-report.schema.json').read_text(encoding='utf-8'))
PS1 = REPO / 'host' / 'rescue-windows.ps1'
MAC = REPO / 'host' / 'RESCUE-MACOS.command'
SHIM_JS = HERE / 'host_osascript_shim.js'
NODE = shutil.which('node')
PWSH, ZSH = HL.PWSH, HL.ZSH
DUMMY_KEY = HL.DUMMY_KEY

RUN = 'rescue-20260930-080000-live'
STARTED, ENDED = '2026-09-30T08:00:00Z', '2026-09-30T08:05:30Z'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI_MODULE = load('rescue_report_cli', CLI)
SHIPPED = rc.load()
INFO = CLI_MODULE.action_info(SHIPPED)


def validate(testcase, doc):
    errors = sorted(jsonschema.Draft202012Validator(SCHEMA).iter_errors(doc), key=lambda e: list(e.path))
    testcase.assertEqual([], [e.message + ' @' + '/'.join(map(str, e.path)) for e in errors][:5])


# ----------------------------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------------------------
def check(cid, status, ref=None, kind=None, number=None):
    item = {'check_id': cid, 'status': status, 'source': 'offline-target-scan', 'observed_at': STARTED}
    if ref:
        item['target_ref'] = ref
    if kind:
        item['value'] = {'kind': kind, 'number': number}
    return item


def evidence_doc(after=False):
    checks = [
        check('hw-cpu', 'pass'), check('hw-memory', 'pass', None, 'bytes', 8589934592),
        check('hw-disk', 'fail'), check('smart-health', 'unknown'), check('hw-cpu-thermal', 'warn', None, 'celsius', 82.5),
        check('block-device-discovery', 'pass'), check('network-connectivity', 'pass'),
        check('os-detection', 'pass', 'os-0'), check('linux-package-state', 'pass' if after else 'fail', 'os-0'),
        check('linux-grub-config', 'warn', 'os-0'), check('encryption-status', 'unknown', 'os-1'),
        check('windows-system-files', 'unknown', 'os-1'), check('sw-inventory', 'pass', 'os-0', 'count', 1874),
        check('sw-broken-dependencies', 'fail' if after else 'warn', 'os-0', 'count', 2),
        check('malware-scan', 'warn', 'os-0', 'count', 1),
        check('malware-signatures', 'pass' if after else 'warn', 'os-0', 'days', 1 if after else 45),
        check('malware-quarantine', 'pass', 'os-0', 'count', 0),
    ]
    if after:
        checks.append(check('hw-usb', 'pass'))
    else:
        checks.insert(4, check('hw-battery', 'warn', None, 'percent', 41))
    return {
        'schema_version': '1.2', 'run_id': RUN, 'source_platform': 'linux-mint-xfce-live', 'boot_mode': 'uefi',
        'collected_at': STARTED, 'target_device_opaque_id': 'target-abcdef123456', 'checks': checks,
        'evidence_manifest': {'entry_count': len(checks), 'manifest_sha256': 'a' * 64, 'storage_class': 'usb-rescue-state'},
        'ai_provider': {'provider_id': 'opencode-go', 'model_id': 'mimo-v2.6-flash', 'authenticated': True,
                        'destination_class': 'cloud'},
        'ai_analysis_status': 'not_run', 'mutation_status': 'none',
        'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
        'classification': 'confidential', 'scope': ['all'], 'repair_policy': 'approve-each',
        'target_systems': [
            {'ref': 'os-0', 'family': 'linuxmint', 'release': 'Linux Mint 21.3', 'architecture': 'x86_64',
             'detection': 'live-offline', 'encryption': 'none', 'access': 'read-only-mounted'},
            {'ref': 'os-1', 'family': 'windows', 'release': 'Windows 11', 'architecture': 'x86_64',
             'detection': 'live-offline', 'encryption': 'bitlocker', 'access': 'not-mounted-encrypted'}],
    }


ANALYSIS = (
    '# Analisis rescue\r\n\r\n> Keluaran model.\r\n\x1b[31mFakta\x1b[0m: baterai lemah.\u200b\r\n'
    'Hipotesis: paket rusak.\x00\x07\n'
    '```rescue-proposals\n{"proposed_actions":[{"action_id":"hw.smart-short-selftest"},'
    '{"action_id":"os-linux.update-grub","target_ref":"os-0"},{"action_id":"os-windows.sfc-verify","target_ref":"os-0"},'
    '{"action_id":"bogus.action"}]}\n```\n')

READINESS = {
    'report_version': '1.0', 'report_type': 'hardware-readiness', 'run_id': 'hardware-20260930-075900', 'mode': 'auto',
    'collected_at': STARTED,
    'checks': [
        {'check_id': 'cpu', 'status': 'pass', 'required': True, 'observed': '8 logical CPU(s); Secret CPU Model', 'minimum': '>= 2',
         'note': '', 'observed_at': STARTED},
        {'check_id': 'ram', 'status': 'pass', 'required': True, 'observed': '15.5 GiB', 'minimum': '>= 4.0 GiB', 'note': '',
         'observed_at': STARTED},
        {'check_id': 'usb-boot-media', 'status': 'warn', 'required': True, 'observed': 'USB 14.9 GiB (/dev/sdz)',
         'minimum': '>= 8', 'note': '', 'observed_at': STARTED},
        {'check_id': 'internet-connectivity', 'status': 'pass', 'required': True, 'observed': 'default-route=yes, dns=yes',
         'minimum': 'x', 'note': '', 'observed_at': STARTED}],
    'summary': {'overall': 'ready_with_warnings', 'failures': 0, 'unknown_required': 0, 'warnings': 1},
}


class Chain:
    """Builds a hash-chained journal like scripts/rescue-repair.py (same key order and compact JSON)."""

    def __init__(self, run_id=RUN):
        self.lines, self.seq, self.prev, self.run_id = [], 0, '0' * 64, run_id

    def add(self, action, stage, outcome, origin='catalog-trigger', risk='safe', policy='approve-each', **extra):
        record = {'journal_version': '1', 'run_id': self.run_id, 'catalog_sha256': 'c' * 64, 'policy': policy,
                  'platform': 'live-linux', 'evidence_sha256': 'e' * 64, 'action_id': action, 'origin': origin,
                  'risk': risk, 'stage': stage, 'outcome': outcome, 'recorded_at': '2026-09-30T08:02:00Z'}
        record.update(extra)
        self.seq += 1
        record['seq'], record['prev_sha256'] = self.seq, self.prev
        line = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.prev = hashlib.sha256(line).hexdigest()
        self.lines.append(line)
        return self


def sample_journal():
    j = Chain()
    a = 'hw.smart-short-selftest'  # verified, parameter is a block device
    j.add(a, 'proposed', 'ok').add(a, 'approval', 'ok', reason='auto-safe', params={'device': '/dev/sdb'})
    j.add(a, 'precondition', 'ok', exit_code=0, duration_seconds=0.01)
    j.add(a, 'execute', 'ok', exit_code=0, duration_seconds=1.5, output_bytes=12, output_sha256='1' * 64)
    j.add(a, 'verify', 'ok', exit_code=0, duration_seconds=0.2)
    b = 'os-linux.update-grub'  # destructive: backup, execute fails, manual rollback
    j.add(b, 'proposed', 'ok', origin='ai-proposal', risk='destructive', target_ref='os-0')
    j.add(b, 'backup', 'ok', origin='ai-proposal', risk='destructive', target_ref='os-0',
          backup={'size_bytes': 123456, 'fingerprint_sha256': 'ab' * 32})
    j.add(b, 'approval', 'ok', origin='ai-proposal', risk='destructive', target_ref='os-0', reason='operator-approved')
    j.add(b, 'target-rw', 'ok', origin='ai-proposal', risk='destructive', target_ref='os-0')
    j.add(b, 'execute', 'fail', origin='ai-proposal', risk='destructive', target_ref='os-0', reason='exit-code', exit_code=1,
          duration_seconds=3.25)
    j.add(b, 'rollback', 'skipped', origin='ai-proposal', risk='destructive', target_ref='os-0', reason='manual-rollback-required')
    c = 'sw.apt-reinstall-package'  # program missing -> skipped, parameter is a package name
    j.add(c, 'proposed', 'ok', origin='operator', risk='destructive', target_ref='os-0')
    j.add(c, 'approval', 'ok', origin='operator', risk='destructive', target_ref='os-0', reason='cli-approved',
          params={'package': 'firefox-esr'})
    j.add(c, 'execute', 'unavailable', origin='operator', risk='destructive', target_ref='os-0', reason='program-not-found')
    d = 'hw.wifi-rfkill-unblock'  # verify fails, automatic rollback ok
    j.add(d, 'proposed', 'ok', risk='reversible').add(d, 'approval', 'ok', risk='reversible', reason='cli-approved')
    j.add(d, 'execute', 'ok', risk='reversible', exit_code=0).add(d, 'verify', 'fail', risk='reversible', reason='exit-code', exit_code=3)
    j.add(d, 'rollback', 'ok', risk='reversible', exit_code=0)
    e = 'mw.quarantine-detection'  # detection reference is shown as a placeholder
    j.add(e, 'proposed', 'ok', origin='operator', risk='reversible')
    j.add(e, 'approval', 'ok', origin='operator', risk='reversible', reason='operator-approved', params={'detection': 'd-3'})
    j.add(e, 'execute', 'ok', origin='operator', risk='reversible', exit_code=0)
    j.add(e, 'verify', 'ok', origin='operator', risk='reversible', exit_code=0)
    f = 'sw.dpkg-configure-pending'
    j.add(f, 'proposed', 'ok', risk='destructive').add(f, 'approval', 'declined', risk='destructive', reason='not-interactive')
    g = 'os-linux.apt-fix-broken'
    j.add(g, 'proposed', 'ok', risk='destructive').add(g, 'approval', 'declined', risk='destructive', reason='operator-declined')
    h = 'hw.nvme-short-selftest'
    j.add(h, 'proposed', 'ok', policy='detect-only').add(h, 'approval', 'skipped', policy='detect-only', reason='policy-detect-only')
    i = 'sw.apt-fix-broken'
    j.add(i, 'proposed', 'ok', risk='destructive').add(i, 'backup', 'unavailable', risk='destructive', reason='missing-backup')
    other = Chain(run_id='rescue-20250101-000000-live')  # another run in the same file: ignored
    other.seq, other.prev = j.seq, j.prev
    other.add('hw.nvme-short-selftest', 'proposed', 'ok')
    return j.lines + other.lines


def make_inputs(**over):
    evidence_raw = json.dumps(evidence_doc()).encode()
    inp = {
        'run_id': RUN, 'mode': 'live-linux', 'outcome': 'completed', 'started_at': STARTED, 'ended_at': ENDED,
        'version': '0.3.0', 'catalog_sha256': SHIPPED.sha256, 'scope': None, 'repair_policy': None, 'key_present': True,
        'evidence': evidence_doc(), 'evidence_sha256': hashlib.sha256(evidence_raw).hexdigest(),
        'evidence_after': evidence_doc(after=True), 'analysis_text': ANALYSIS, 'ai_counts': None,
        'journal_lines': sample_journal(), 'readiness': READINESS, 'action_info': INFO,
    }
    accepted, rejected = rc.parse_ai_proposals(ANALYSIS, SHIPPED, inp['evidence'], ('all',))
    inp['ai_counts'] = (len(accepted), rejected)
    inp.update(over)
    return inp


def report_of(**over):
    return rr.build_report(make_inputs(**over))


# ----------------------------------------------------------------------------------------
# Model and renderer
# ----------------------------------------------------------------------------------------
class ReportModelTests(unittest.TestCase):
    def setUp(self):
        self.report = report_of()
        self.md = rr.render_markdown(self.report)
        self.actions = {a['action_id']: a for a in self.report['remediation']['actions']}

    def test_json_is_schema_valid_deterministic_and_closed(self):
        validate(self, self.report)
        self.assertEqual(json.dumps(self.report), json.dumps(report_of()))
        self.assertEqual(self.report['classification'], 'confidential')
        self.assertEqual(self.report['privacy_check'], {'status': 'passed', 'findings': []})

    def test_header(self):
        h = self.report['header']
        self.assertEqual((h['started_at'], h['ended_at'], h['mode'], h['toolkit_version']), (STARTED, ENDED, 'live-linux', '0.3.0'))
        self.assertEqual((h['catalog_sha256'], h['scope'], h['repair_policy']), (SHIPPED.sha256, ['all'], 'approve-each'))
        self.assertEqual((h['provider_key_present'], h['evidence_run_id']), (True, RUN))
        self.assertEqual(h['outcome'], 'completed-with-failures')  # sample journal has a failed and a rolled-back action
        self.assertIn('| Run ID | %s |' % RUN, self.md)
        self.assertNotIn(DUMMY_KEY, json.dumps(self.report))

    def test_markdown_has_the_eight_sections_in_order(self):
        headings = re.findall(r'^## (\d)\. ', self.md, re.M)
        self.assertEqual(headings, list('12345678'))
        for label in ('Header', 'Hardware readiness', 'Detection', 'AI analysis', 'Remediation', 'Before-after', 'Open items', 'Honesty'):
            self.assertIn(label, self.md)
        self.assertTrue(self.md.startswith('# Laporan Proses Rescue / Rescue Run Report'))
        self.assertIn('> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.', self.md)

    def test_readiness_section_shows_the_gate_and_no_observed_text(self):
        rd = self.report['readiness']
        self.assertEqual((rd['performed'], rd['gate'], rd['overall']), (True, 'passed', 'ready_with_warnings'))
        self.assertEqual([c['check_id'] for c in rd['checks']], ['cpu', 'ram', 'usb-boot-media', 'internet-connectivity'])
        self.assertNotIn('Secret CPU Model', self.md + json.dumps(self.report))
        self.assertNotIn('/dev/sdz', self.md + json.dumps(self.report))
        failed = report_of(readiness=dict(READINESS, summary={'overall': 'not_ready'}), outcome='preflight-failed')
        self.assertEqual(failed['readiness']['gate'], 'failed')
        self.assertIn('Gerbang / Gate: **FAILED**', rr.render_markdown(failed))
        host = report_of(readiness=None, mode='linux-host')
        self.assertEqual(host['readiness'], {'performed': False, 'gate': 'not_applicable', 'overall': None, 'checks': []})

    def test_detection_groups_units_and_the_unknown_legend(self):
        det = self.report['detection']
        groups = {d: [c['check_id'] for c in det['domains'][d]] for d in rr.DOMAINS}
        self.assertEqual(groups['hardware'], ['hw-cpu', 'hw-memory', 'hw-disk', 'smart-health', 'hw-battery', 'hw-cpu-thermal'])
        self.assertEqual(groups['software'], ['sw-inventory', 'sw-broken-dependencies'])
        self.assertEqual(groups['malware'], ['malware-scan', 'malware-signatures', 'malware-quarantine'])
        self.assertEqual(groups['environment'], ['block-device-discovery', 'network-connectivity'])
        self.assertIn('linux-package-state', groups['os'])
        self.assertEqual(det['totals']['unknown'], 3)
        self.assertEqual([t['ref'] for t in det['targets']], ['os-0', 'os-1'])
        self.assertIn('`unknown` = tidak dapat ditentukan (BUKAN sehat) / could not be determined (NOT healthy)', self.md)
        self.assertIn('| hw-memory | - | pass | 8589934592 B |', self.md)
        self.assertIn('| hw-cpu-thermal | - | warn | 82.5 C |', self.md)
        self.assertIn('| hw-battery | - | warn | 41% |', self.md)
        self.assertIn('| malware-signatures | os-0 | warn | 45 hari |', self.md)
        self.assertIn('- os-1: family=windows arch=x86_64 detection=live-offline encryption=bitlocker access=not-mounted-encrypted', self.md)
        self.assertNotIn('Linux Mint 21.3', self.md)  # release text is not carried

    def test_analysis_is_verbatim_but_sanitized_and_marked_as_never_executed(self):
        ai = self.report['analysis']
        self.assertEqual((ai['status'], ai['model_id']), ('completed', 'mimo-v2.6-flash'))
        self.assertEqual(ai['evidence_sha256'], self.report['header']['evidence_sha256'])
        self.assertNotRegex(ai['text'], '[\x00-\x08\x0b-\x1f\x7f\u200b\r]')
        self.assertIn('Hipotesis: paket rusak.', ai['text'])
        self.assertNotIn('\x1b', self.md)
        self.assertIn('MODEL OUTPUT, read-only; never executed.', self.md)
        self.assertIn('> Hipotesis: paket rusak.', self.md)
        self.assertEqual((ai['proposals']['accepted'], ai['proposals']['rejected']), (2, 2))
        self.assertIn('| Usulan diterima / accepted | 2 |', self.md)
        self.assertIn('| Usulan ditolak / rejected | 2 |', self.md)
        long = report_of(analysis_text='x' * (rr.MAX_ANALYSIS_CHARS + 5))
        self.assertTrue(long['analysis']['text_truncated'])
        self.assertEqual(len(long['analysis']['text']), rr.MAX_ANALYSIS_CHARS)
        validate(self, long)
        none = report_of(analysis_text=None, ai_counts=None)
        self.assertEqual((none['analysis']['status'], none['analysis']['text']), ('not_run', None))
        self.assertIn('Tidak ada analisis AI pada run ini', rr.render_markdown(none))

    def test_every_action_has_origin_approval_backup_stages_and_outcome(self):
        a = self.actions
        self.assertEqual(len(a), 9)
        self.assertEqual(a['hw.smart-short-selftest']['approval'], {'decision': 'auto-safe', 'reason': 'auto-safe'})
        self.assertEqual([s['stage'] for s in a['hw.smart-short-selftest']['stages']], ['precondition', 'execute', 'verify'])
        self.assertEqual(a['hw.smart-short-selftest']['stages'][1]['exit_code'], 0)
        grub = a['os-linux.update-grub']
        self.assertEqual((grub['origin'], grub['risk'], grub['target_ref']), ('ai-proposal', 'destructive', 'os-0'))
        self.assertEqual(grub['approval']['decision'], 'operator-interactive')
        self.assertEqual(grub['backup'], {'size_bytes': 123456, 'fingerprint': 'ab' * 6})
        self.assertEqual(a['sw.apt-reinstall-package']['approval']['decision'], 'cli')
        self.assertEqual(a['sw.dpkg-configure-pending']['approval'], {'decision': 'not-interactive', 'reason': 'not-interactive'})
        self.assertEqual(a['os-linux.apt-fix-broken']['approval']['decision'], 'declined')
        self.assertEqual(a['hw.nvme-short-selftest']['approval']['decision'], 'policy-detect-only')
        self.assertEqual(a['sw.apt-fix-broken']['approval']['decision'], 'not-reached')
        self.assertEqual({k: v['final_outcome'] for k, v in a.items()}, {
            'hw.smart-short-selftest': 'verified', 'os-linux.update-grub': 'failed', 'sw.apt-reinstall-package': 'skipped',
            'hw.wifi-rfkill-unblock': 'rolled-back', 'mw.quarantine-detection': 'verified', 'sw.dpkg-configure-pending': 'declined',
            'os-linux.apt-fix-broken': 'declined', 'hw.nvme-short-selftest': 'proposed', 'sw.apt-fix-broken': 'skipped'})
        self.assertEqual(self.report['summary']['actions'], {'total': 9, 'verified': 2, 'rolled_back': 1, 'failed': 1,
                                                             'skipped': 2, 'declined': 2, 'proposed': 1})
        self.assertIn('| Backup | 123456 B, fingerprint abababababab |', self.md)
        self.assertIn('| Persetujuan / Approval | otomatis (auto-safe) [auto-safe] |', self.md)

    def test_parameters_are_placeholders_never_raw_values(self):
        a = self.actions
        self.assertEqual(a['hw.smart-short-selftest']['params'], {'device': '<device>'})
        self.assertEqual(a['sw.apt-reinstall-package']['params'], {'package': '<package>'})
        self.assertEqual(a['mw.quarantine-detection']['params'], {'detection': '<detection d-3>'})
        text = self.md + json.dumps(self.report)
        for raw in ('/dev/sdb', 'firefox-esr'):
            self.assertNotIn(raw, text)
        self.assertIn('device=<device>', self.md)
        # enum and integer parameters keep their values when the catalog says so; unknown types fail closed
        j = Chain()
        j.add('hw.network-service-restart', 'proposed', 'ok')
        j.add('hw.network-service-restart', 'approval', 'ok', reason='cli-approved', params={'service': 'NetworkManager', 'n': 3, 'x': 'raw'})
        rep = report_of(journal_lines=j.lines)
        self.assertEqual(rep['remediation']['actions'][0]['params'], {'service': 'NetworkManager', 'n': 3, 'x': '<value>'})
        validate(self, rep)

    def test_manual_rollback_doc_link_and_open_items(self):
        grub = self.actions['os-linux.update-grub']
        self.assertTrue(grub['manual_rollback_required'])
        self.assertEqual(grub['manual_rollback_doc'], 'docs/os-repair.md#rollback-linux')
        self.assertIn('manual rollback required: `docs/os-repair.md#rollback-linux`', self.md)
        self.assertNotIn('../../', self.md)
        self.assertIn('`/usr/local/lib/rescue-omes/docs/` di live USB, `rescue-omes/docs/` di USB pada mode host', self.md)
        kinds = [(i['kind'], i.get('ref')) for i in self.report['open_items']]
        self.assertIn(('action-failed', 'os-linux.update-grub'), kinds)
        self.assertIn(('manual-rollback', 'os-linux.update-grub'), kinds)
        self.assertIn(('action-rolled-back', 'hw.wifi-rfkill-unblock'), kinds)
        self.assertIn(('action-declined', 'os-linux.apt-fix-broken'), kinds)
        self.assertIn(('action-skipped', 'sw.apt-fix-broken'), kinds)
        self.assertIn(('action-not-run', 'hw.nvme-short-selftest'), kinds)
        for kind in ('escalate-encrypted-disk', 'escalate-hardware-fault', 'stale-signatures', 'review-malware-detections',
                     'unknown-checks', 'regression-after-repair'):
            self.assertIn(kind, [k for k, _ in kinds])
        self.assertIn(('regression-after-repair', 'sw-broken-dependencies'), kinds)  # warn -> fail after the repair

    def test_before_after_lists_changed_checks(self):
        cmp_ = self.report['comparison']
        self.assertEqual((cmp_['performed'], cmp_['reason']), (True, 'executed'))
        self.assertEqual(cmp_['changed'], [
            {'check_id': 'linux-package-state', 'target_ref': 'os-0', 'before': 'fail', 'after': 'pass'},
            {'check_id': 'sw-broken-dependencies', 'target_ref': 'os-0', 'before': 'warn', 'after': 'fail'},
            {'check_id': 'malware-signatures', 'target_ref': 'os-0', 'before': 'warn', 'after': 'pass'}])
        self.assertEqual((cmp_['only_before'], cmp_['only_after'], cmp_['unchanged'], cmp_['compared']), (1, 1, 14, 17))
        self.assertIn('| linux-package-state | os-0 | fail | pass |', self.md)

    def test_no_action_and_missing_rescan_are_stated(self):
        none = report_of(journal_lines=None, evidence_after=None)
        self.assertEqual((none['comparison']['performed'], none['comparison']['reason']), (False, 'no-action-executed'))
        self.assertEqual(none['remediation']['journal']['chain'], 'absent')
        self.assertIn('Tidak ada aksi yang dijalankan, jadi tidak ada pemindaian ulang', rr.render_markdown(none))
        self.assertIn('Tidak ada aksi perbaikan pada run ini', rr.render_markdown(none))
        missing = report_of(evidence_after=None)
        self.assertEqual(missing['comparison']['reason'], 'rescan-missing')
        self.assertIn('rescan-not-completed', missing['honesty']['environment_blocked'])
        self.assertIn('pemindaian ulang tidak tersedia', rr.render_markdown(missing))
        validate(self, none)
        validate(self, missing)

    def test_honesty_section_variants(self):
        h = self.report['honesty']
        self.assertEqual(h['hardware_required'], ['physical-boot-and-reboot', 'disk-repair-read-back'])
        self.assertEqual(h['environment_blocked'], [])
        self.assertIn('BUKAN bukti kesehatan', self.md)
        self.assertIn('A clean result is not proof of health.', self.md)
        cases = {'no-key': ('provider-key-missing', False), 'network-error': ('network-unreachable', True),
                 'evidence-only': ('analysis-not-run-offline-mode', True), 'dry-run': ('analysis-not-run-offline-mode', True),
                 'analysis-failed': ('analysis-failed', True), 'scan-failed': ('scan-not-completed', True),
                 'preflight-failed': ('hardware-preflight-failed', True), 'scan-skipped': ('scan-not-completed', True)}
        for outcome, (expected, key) in cases.items():
            with self.subTest(outcome=outcome):
                rep = report_of(outcome=outcome, key_present=key, journal_lines=None, evidence_after=None)
                self.assertIn(expected, rep['honesty']['environment_blocked'])
                validate(self, rep)
        no_key = report_of(key_present=False, journal_lines=None, evidence_after=None)
        self.assertIn('provider-key-missing', no_key['honesty']['environment_blocked'])
        self.assertIn('Environment-blocked: tidak ada kunci provider', rr.render_markdown(no_key))
        mac = report_of(mode='macos-host')
        self.assertIn('host-os-native-behavior', mac['honesty']['hardware_required'])
        limited = report_of(evidence=dict(evidence_doc(), scope=['hardware.disk']))
        self.assertTrue(limited['honesty']['scope_limited'])
        self.assertIn('Scope dibatasi (hardware.disk)', rr.render_markdown(limited))

    def test_failed_run_without_evidence_still_gets_a_valid_report(self):
        rep = report_of(evidence=None, evidence_sha256=None, evidence_after=None, analysis_text=None, ai_counts=None,
                        journal_lines=None, outcome='preflight-failed', scope=['os'], repair_policy='detect-only',
                        readiness=dict(READINESS, summary={'overall': 'not_ready'}))
        validate(self, rep)
        md = rr.render_markdown(rep)
        self.assertFalse(rep['detection']['available'])
        self.assertEqual((rep['header']['scope'], rep['header']['repair_policy']), (['os'], 'detect-only'))
        self.assertIn('Tidak ada evidence: pemindaian tidak selesai', md)
        self.assertIn('hardware-preflight-failed', rep['honesty']['environment_blocked'])
        self.assertIn('Gerbang / Gate: **FAILED**', md)

    def test_tampered_journal_is_shown_as_invalid(self):
        good = sample_journal()
        cases = {
            'edited line': [good[0], good[1].replace(b'"outcome":"ok"', b'"outcome":"fail"', 1)] + good[2:],
            'deleted line': good[:3] + good[4:],
            'garbage line': good[:2] + [b'not json'] + good[2:],
            'reordered': [good[1], good[0]] + good[2:],
        }
        self.assertEqual(rr.chain_problems(good), [])
        for name, lines in cases.items():
            with self.subTest(name):
                rep = report_of(journal_lines=lines)
                self.assertEqual(rep['remediation']['journal']['chain'], 'INVALID')
                self.assertIn('journal-invalid', [i['kind'] for i in rep['open_items']])
                md = rr.render_markdown(rep)
                self.assertIn('**PERINGATAN: RANTAI HASH JOURNAL INVALID / JOURNAL HASH CHAIN INVALID.**', md)
                self.assertIn('journal-invalid', md)
                validate(self, rep)
        self.assertEqual(report_of()['remediation']['journal']['chain'], 'valid')

    def test_hostile_fields_never_reach_the_report(self):
        evil = evidence_doc()
        evil['checks'][0]['check_id'] = '../../etc/passwd'
        self.assertFalse(rr.sane_evidence(evil))
        rep = report_of(evidence=evil)
        self.assertFalse(rep['detection']['available'])  # unusable evidence is treated as absent, not half-trusted
        j = Chain()
        j.add('hw.smart-short-selftest', 'proposed', 'ok')
        j.add('../evil', 'proposed', 'ok')
        j.add('hw.smart-short-selftest', 'approval', 'ok', reason='rm -rf /')
        rep = report_of(journal_lines=j.lines)
        self.assertEqual([a['action_id'] for a in rep['remediation']['actions']], ['hw.smart-short-selftest'])
        self.assertNotIn('rm -rf', json.dumps(rep) + rr.render_markdown(rep))
        validate(self, rep)

    def test_no_identifiers_from_this_machine(self):
        text = json.dumps(self.report) + self.md
        for needle in (getpass.getuser(), socket.gethostname(), str(Path.home()), str(REPO), tempfile.gettempdir() + '/'):
            if len(needle) >= 4:
                self.assertNotIn(needle, text)
        self.assertEqual(rr.privacy_findings(text), [])


class PrivacySelfCheckTests(unittest.TestCase):
    STRUCTURAL = {
        'unix-home-path': 'x/home/alice/z',
        'macos-user-path': 'x/Users/Bob/z',
        'windows-user-path': r'x-C:\Users\carol\z',
        'mac-address': 'x aa:bb:cc:dd:ee:ff z',
        'ipv4-address': 'run-192.168.1.10',
        'ipv6-address': 'x-2001:0db8:0000:0000:0000:ff00:0042:8329-z',
    }
    MODEL_TEXT = ('Analisis: kernel 5.15.0.91, router 192.168.1.10, lihat /home/alice/rahasia/x.txt dan /Users/Bob/Documents/a.pdf, '
                  'C:\\Users\\carol\\Desktop\\b.doc, adapter aa:bb:cc:dd:ee:ff, host 2001:0db8:0000:0000:0000:ff00:0042:8329, versi 1.2.3.')

    def test_identifiers_in_the_model_text_are_redacted_and_the_report_is_not_refused(self):
        report, json_text, markdown = rr.render_checked(make_inputs(analysis_text=self.MODEL_TEXT))
        self.assertEqual(report['privacy_check'], {'status': 'passed', 'findings': []})
        ai = report['analysis']
        self.assertEqual(ai['redactions'], 7)
        self.assertEqual(ai['text'], 'Analisis: kernel <ip>, router <ip>, lihat <path> dan <path>, <path>, adapter <mac>, host <ip>, versi 1.2.3.')
        self.assertIn('7 bagian yang menyerupai pengenal', markdown)
        for original in ('5.15.0.91', '192.168.1.10', 'alice', 'Bob', 'carol', 'aa:bb:cc', '2001:0db8'):
            self.assertNotIn(original, json_text + markdown)
        self.assertTrue(report['detection']['available'])
        self.assertEqual(len(report['remediation']['actions']), 9)
        validate(self, report)

    def test_the_configured_key_value_in_the_model_text_is_redacted(self):
        report, json_text, markdown = rr.render_checked(make_inputs(analysis_text='kunci ' + DUMMY_KEY + ' dan ' + DUMMY_KEY),
                                                        secrets=[DUMMY_KEY])
        self.assertEqual(report['privacy_check']['status'], 'passed')
        self.assertEqual((report['analysis']['redactions'], report['analysis']['text']), (2, 'kunci <redacted> dan <redacted>'))
        self.assertNotIn(DUMMY_KEY, json_text + markdown)
        validate(self, report)

    def test_a_structural_leak_still_refuses_the_full_report_and_writes_a_minimal_one(self):
        for rule, text in self.STRUCTURAL.items():
            with self.subTest(rule=rule):
                report, json_text, markdown = rr.render_checked(make_inputs(run_id=text))
                self.assertEqual(report['privacy_check'], {'status': 'refused', 'findings': [rule]})
                self.assertFalse(report['detection']['available'])
                self.assertEqual(report['remediation']['actions'], [])
                self.assertEqual(report['header']['outcome'], 'report-privacy-refused')
                self.assertIsNone(report['analysis']['text'])
                self.assertEqual(report['analysis']['redactions'], 0)
                self.assertNotIn(text, json_text + markdown)
                self.assertIn('LAPORAN DITOLAK OLEH PEMERIKSAAN PRIVASI', markdown)
                validate(self, report)
                self.assertEqual(rr.privacy_findings(json_text + markdown), [])

    def test_the_key_value_in_a_structural_field_is_refused(self):
        report, json_text, markdown = rr.render_checked(make_inputs(run_id='run-' + DUMMY_KEY), secrets=[DUMMY_KEY])
        self.assertEqual(report['privacy_check']['findings'], ['configured-key-value'])
        self.assertNotIn(DUMMY_KEY, json_text + markdown)
        validate(self, report)

    def test_ordinary_numbers_and_versions_are_left_alone(self):
        clean = 'kernel 5.15.0, versi 1.2.3, 2026-09-30T08:00:00Z, sha 0123456789abcdef, dokumen docs/os-repair.md'
        report, json_text, markdown = rr.render_checked(make_inputs(analysis_text=clean))
        self.assertEqual((report['privacy_check']['status'], report['analysis']['redactions'], report['analysis']['text']), ('passed', 0, clean))


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='run-report-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_index_lists_every_run_newest_first_and_same_second_runs_do_not_collide(self):
        older = make_inputs(started_at='2026-09-29T10:00:00Z', ended_at='2026-09-29T10:01:00Z', outcome='no-key')
        rr.write_run(str(self.tmp), older)
        first, _ = rr.write_run(str(self.tmp), make_inputs())
        second, _ = rr.write_run(str(self.tmp), make_inputs())
        self.assertEqual((first, second), ('run-20260930T080000Z', 'run-20260930T080000Z-2'))
        (self.tmp / 'run-garbage').mkdir()
        (self.tmp / 'run-20200101T000000Z').mkdir()
        (self.tmp / 'run-20200101T000000Z' / 'report.json').write_text('{not json')
        rr.write_run(str(self.tmp), make_inputs(started_at='2026-09-30T09:00:00Z', ended_at='2026-09-30T09:01:00Z', mode='linux-host',
                                                journal_lines=None, evidence_after=None))
        index = (self.tmp / 'index.md').read_text(encoding='utf-8')
        rows = [line for line in index.splitlines() if line.startswith('| 20')]
        self.assertEqual([r.split(' | ')[0][2:] for r in rows],
                         ['2026-09-30T09:00:00Z', '2026-09-30T08:00:00Z', '2026-09-30T08:00:00Z', '2026-09-29T10:00:00Z'])
        self.assertIn('[run-20260930T080000Z-2/report.md](run-20260930T080000Z-2/report.md)', index)
        self.assertIn('| linux-host | completed |', rows[0])
        self.assertIn('| live-linux | no-key |', rows[3])
        self.assertNotIn('garbage', index)

    def test_write_run_is_private_and_atomic(self):
        name, _ = rr.write_run(str(self.tmp), make_inputs())
        files = sorted(p.name for p in self.tmp.iterdir())
        self.assertEqual(files, ['index.md', name])
        self.assertEqual(sorted(p.name for p in (self.tmp / name).iterdir()), ['report.json', 'report.md'])
        for path in (self.tmp / 'index.md', self.tmp / name / 'report.json', self.tmp / name / 'report.md'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        self.assertEqual(stat.S_IMODE((self.tmp / name).stat().st_mode) & 0o077, 0)
        validate(self, json.loads((self.tmp / name / 'report.json').read_text(encoding='utf-8')))


# ----------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------
class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='run-report-cli-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.reports = self.tmp / 'usb' / 'reports'
        (self.tmp / 'evidence.json').write_text(json.dumps(evidence_doc()))
        (self.tmp / 'after.json').write_text(json.dumps(evidence_doc(after=True)))
        (self.tmp / 'analysis.md').write_text(ANALYSIS, encoding='utf-8')
        (self.tmp / 'journal.jsonl').write_bytes(b'\n'.join(sample_journal()) + b'\n')
        (self.tmp / 'readiness.json').write_text(json.dumps(READINESS))

    def run_cli(self, *args, env=None, run_id=RUN):
        base = {k: v for k, v in os.environ.items() if k != 'OPENCODE_GO_API_KEY'}
        base.update(env or {})
        return subprocess.run([sys.executable, str(CLI), '--reports-dir', str(self.reports), '--run-id', run_id, *args],
                              capture_output=True, text=True, env=base, cwd=self.tmp, timeout=120)

    def full_args(self):
        t = self.tmp
        return ['--mode', 'live-linux', '--evidence', str(t / 'evidence.json'), '--evidence-after', str(t / 'after.json'),
                '--analysis', str(t / 'analysis.md'), '--journal', str(t / 'journal.jsonl'), '--readiness', str(t / 'readiness.json'),
                '--started-at', STARTED, '--ended-at', ENDED]

    def only_run(self):
        runs = [p for p in self.reports.iterdir() if p.name.startswith('run-')]
        self.assertEqual(len(runs), 1, runs)
        return runs[0]

    def test_writes_report_and_index_only_inside_the_reports_folder(self):
        before = sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob('*'))
        proc = self.run_cli(*self.full_args())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        run = self.only_run()
        after = sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob('*'))
        created = [p for p in after if p not in before]
        self.assertTrue(all(p == 'usb' or p.startswith('usb/reports') for p in created), created)
        self.assertEqual(sorted(p.name for p in self.reports.iterdir()), ['index.md', run.name])
        self.assertEqual(sorted(p.name for p in run.iterdir()), ['report.json', 'report.md'])
        for path in (run / 'report.json', run / 'report.md', self.reports / 'index.md'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        doc = json.loads((run / 'report.json').read_text(encoding='utf-8'))
        validate(self, doc)
        self.assertEqual(doc['header']['outcome'], 'completed-with-failures')
        self.assertEqual(doc['remediation']['journal']['chain'], 'valid')
        self.assertEqual((doc['analysis']['proposals']['accepted'], doc['analysis']['proposals']['rejected']), (2, 2))
        self.assertEqual(doc['header']['evidence_sha256'], hashlib.sha256((self.tmp / 'evidence.json').read_bytes()).hexdigest())
        self.assertEqual(doc['header']['catalog_sha256'], SHIPPED.sha256)
        self.assertEqual(doc['header']['toolkit_version'], (REPO / 'VERSION').read_text().strip())
        self.assertFalse(doc['header']['provider_key_present'])
        self.assertIn(run.name, (self.reports / 'index.md').read_text())

    def test_every_input_is_optional(self):
        proc = self.run_cli('--mode', 'linux-host', '--outcome', 'scan-failed', '--scope', 'os,software')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc = json.loads((self.only_run() / 'report.json').read_text())
        validate(self, doc)
        self.assertEqual((doc['header']['outcome'], doc['header']['scope'], doc['detection']['available']), ('scan-failed', ['os', 'software'], False))
        proc = self.run_cli('--mode', 'linux-host', '--evidence', str(self.tmp / 'missing.json'), '--journal', str(self.tmp / 'missing.jsonl'))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        (self.tmp / 'broken.json').write_text('{"not": "evidence"')
        proc = self.run_cli('--mode', 'linux-host', '--evidence', str(self.tmp / 'broken.json'))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_key_presence_comes_from_env_or_flag_and_the_value_is_never_written(self):
        proc = self.run_cli(*self.full_args(), env={'OPENCODE_GO_API_KEY': DUMMY_KEY})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc = json.loads((self.only_run() / 'report.json').read_text())
        self.assertTrue(doc['header']['provider_key_present'])
        blob = ''.join(p.read_text(encoding='utf-8') for p in self.reports.rglob('*') if p.is_file())
        self.assertNotIn(DUMMY_KEY, blob + proc.stdout + proc.stderr)
        shutil.rmtree(self.reports)
        proc = self.run_cli(*self.full_args(), '--key-present', 'yes')
        self.assertTrue(json.loads((self.only_run() / 'report.json').read_text())['header']['provider_key_present'])

    def test_key_value_in_the_analysis_is_redacted_not_refused(self):
        (self.tmp / 'analysis.md').write_text('Kunci saya ' + DUMMY_KEY, encoding='utf-8')
        proc = self.run_cli(*self.full_args(), env={'OPENCODE_GO_API_KEY': DUMMY_KEY})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        blob = ''.join(p.read_text(encoding='utf-8') for p in self.reports.rglob('*') if p.is_file())
        self.assertNotIn(DUMMY_KEY, blob)
        doc = json.loads((self.only_run() / 'report.json').read_text())
        validate(self, doc)
        self.assertEqual((doc['privacy_check']['status'], doc['analysis']['redactions'], doc['analysis']['text']), ('passed', 1, 'Kunci saya <redacted>'))

    def test_key_from_an_env_file_is_redacted_too(self):
        env_file = self.tmp / 'rescue.env'
        env_file.write_text("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        env_file.chmod(0o600)
        (self.tmp / 'analysis.md').write_text('echo ' + DUMMY_KEY, encoding='utf-8')
        proc = self.run_cli(*self.full_args(), '--env-file', str(env_file))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads((self.only_run() / 'report.json').read_text())['analysis']['text'], 'echo <redacted>')

    def test_a_structural_leak_gives_exit_1_and_a_minimal_report(self):
        proc = self.run_cli(*self.full_args(), env={'OPENCODE_GO_API_KEY': DUMMY_KEY}, run_id='run-10.20.30.40')
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn('privacy self-check refused', proc.stderr)
        doc = json.loads((self.only_run() / 'report.json').read_text())
        validate(self, doc)
        self.assertEqual((doc['privacy_check']['status'], doc['header']['outcome']), ('refused', 'report-privacy-refused'))

    def test_exit_codes_2_and_3(self):
        proc = subprocess.run([sys.executable, str(CLI), '--reports-dir', str(self.reports), '--run-id', 'x', '--mode', 'live-linux'],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.run_cli('--mode', 'nonsense').returncode, 2)
        self.assertEqual(self.run_cli('--mode', 'live-linux', '--started-at', 'yesterday').returncode, 2)
        self.assertEqual(self.run_cli('--mode', 'live-linux', '--scope', 'bogus').returncode, 2)
        blocker = self.tmp / 'blocker'
        blocker.write_text('a file where the reports folder should be')
        proc = subprocess.run([sys.executable, str(CLI), '--reports-dir', str(blocker / 'reports'), '--run-id', RUN, '--mode', 'live-linux'],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_a_tampered_journal_shows_invalid_through_the_cli(self):
        path = self.tmp / 'journal.jsonl'
        lines = path.read_bytes().split(b'\n')
        lines[2] = lines[2].replace(b'"outcome":"ok"', b'"outcome":"fail"')
        path.write_bytes(b'\n'.join(lines))
        self.assertEqual(self.run_cli(*self.full_args()).returncode, 0)
        run = self.only_run()
        self.assertEqual(json.loads((run / 'report.json').read_text())['remediation']['journal']['chain'], 'INVALID')
        self.assertIn('JOURNAL HASH CHAIN INVALID', (run / 'report.md').read_text(encoding='utf-8'))

    def test_journal_from_the_real_engine_is_reported_end_to_end(self):
        work = self.tmp / 'engine'
        work.mkdir()
        bin_dir = work / 'bin'
        bin_dir.mkdir()
        for name, code in (('rescue-ok', 0), ('rescue-bad', 3)):
            (bin_dir / name).write_text('#!/bin/sh\necho RAW-OUTPUT-MARKER\nexit %d\n' % code)
            (bin_dir / name).chmod(0o755)
        catalog = work / 'catalog'
        catalog.mkdir()
        step = lambda *a: {'argv': list(a)}  # noqa: E731
        (catalog / 'hardware.json').write_text(json.dumps({'catalog_version': '1', 'domain': 'hardware', 'actions': [
            {'action_id': 'hw.test-ok', 'title': 'Test ok action', 'title_id': 'Aksi uji ok', 'scope': 'hardware.battery',
             'platforms': ['live-linux', 'linux-host'], 'risk': 'safe', 'triggers': [{'check_id': 'hw-battery', 'status': ['warn']}],
             'execute': step('rescue-ok'), 'verify': step('rescue-ok'), 'rollback': {'kind': 'none'},
             'backup': {'required': False}, 'doc': 'docs/repair-framework.md'},
            {'action_id': 'hw.test-bad', 'title': 'Test bad action', 'title_id': 'Aksi uji gagal', 'scope': 'hardware.disk',
             'platforms': ['live-linux', 'linux-host'], 'risk': 'reversible', 'triggers': [{'check_id': 'hw-disk', 'status': ['fail']}],
             'execute': step('rescue-ok'), 'verify': step('rescue-bad'),
             'rollback': {'kind': 'step', 'step': step('rescue-ok')}, 'backup': {'required': False}, 'doc': 'docs/repair-framework.md'}]}))
        (work / 'catalog' / 'os-linux.json').write_text(json.dumps({'catalog_version': '1', 'domain': 'os-linux', 'actions': [
            {'action_id': 'os-linux.test-destructive', 'title': 'Test destructive', 'title_id': 'Aksi uji destruktif', 'scope': 'os', 'platforms': ['live-linux'],
             'target_families': ['linuxmint'], 'risk': 'destructive', 'triggers': [{'check_id': 'linux-grub-config', 'status': ['warn']}],
             'execute': step('rescue-bad'), 'verify': step('rescue-ok'), 'rollback': {'kind': 'manual', 'doc': 'docs/os-repair.md#rollback-linux'},
             'backup': {'required': True, 'what': 'file-copy'}, 'doc': 'docs/os-repair.md'}]}))
        backup = work / 'backup.img'
        backup.write_bytes(b'z' * 4096)
        ev = evidence_doc()
        ev['run_id'] = 'rescue-20260930-090000-live'
        (work / 'ev.json').write_text(json.dumps(ev))
        env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(bin_dir), RESCUE_TARGET_MOUNT_FIXTURE_ROOT=str(work / 'none'))
        (work / 'none').mkdir()
        (work / 'state').mkdir()
        engine = subprocess.run([sys.executable, str(REPO / 'scripts/rescue-repair.py'), '--evidence', str(work / 'ev.json'),
                                 '--catalog-dir', str(catalog), '--state-dir', str(work / 'state'), '--policy', 'approve-each',
                                 '--approve', 'hw.test-ok', '--approve', 'hw.test-bad', '--approve', 'os-linux.test-destructive',
                                 '--backup-ref', str(backup)], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(engine.returncode, 1, engine.stdout + engine.stderr)
        journal = work / 'state' / 'repairs' / 'journal.jsonl'
        proc = self.run_cli('--mode', 'live-linux', '--evidence', str(work / 'ev.json'), '--journal', str(journal),
                            '--catalog-dir', str(catalog), '--started-at', STARTED, '--ended-at', ENDED)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc = json.loads((self.only_run() / 'report.json').read_text())
        validate(self, doc)
        finals = {a['action_id']: a['final_outcome'] for a in doc['remediation']['actions']}
        self.assertEqual(finals['hw.test-ok'], 'verified')
        self.assertEqual(finals['hw.test-bad'], 'rolled-back')
        self.assertEqual(doc['remediation']['journal']['chain'], 'valid')
        text = json.dumps(doc) + (self.only_run() / 'report.md').read_text(encoding='utf-8')
        self.assertNotIn('RAW-OUTPUT-MARKER', text)
        self.assertNotIn(str(work), text)
        self.assertEqual(doc['remediation']['journal']['records_run'], doc['remediation']['journal']['records_total'])
        destructive = [a for a in doc['remediation']['actions'] if a['action_id'] == 'os-linux.test-destructive']
        if destructive:  # only reachable when the mount provider fixture allows it; the journal is what matters
            self.assertIn(destructive[0]['final_outcome'], ('failed', 'skipped'))
        # tamper: the report says INVALID
        lines = journal.read_bytes().split(b'\n')
        lines[1] = lines[1].replace(b'"outcome":"ok"', b'"outcome":"fail"')
        journal.write_bytes(b'\n'.join(lines))
        shutil.rmtree(self.reports)
        self.assertEqual(self.run_cli('--mode', 'live-linux', '--evidence', str(work / 'ev.json'), '--journal', str(journal),
                                      '--catalog-dir', str(catalog)).returncode, 0)
        self.assertEqual(json.loads((self.only_run() / 'report.json').read_text())['remediation']['journal']['chain'], 'INVALID')


# ----------------------------------------------------------------------------------------
# Cross-check: PowerShell and JXA generators equal the Python generator
# ----------------------------------------------------------------------------------------
def action_info_lines():
    out = []
    for aid, entry in INFO.items():
        out.append('%s\t%s\t%s' % (aid, entry['doc'] or '-', ','.join('%s:%s' % kv for kv in entry['params'].items()) or '-'))
    return '\n'.join(out)


def jxa_source():
    text = MAC.read_text(encoding='utf-8')
    match = re.search(r"read -r -d '' JXA_REPORT <<'JXA_REPORT_END'\n(.*?)\nJXA_REPORT_END\n", text, re.S)
    assert match, 'JXA_REPORT heredoc not found'
    return match.group(1)


class Generators:
    """Runs the three generators on the same input files. Directories are per generator."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)

    def files(self, evidence=True, after=True, analysis=ANALYSIS, journal=True, readiness=True, journal_lines=None):
        t = self.tmp / 'in'
        t.mkdir(exist_ok=True)
        paths = {}
        if evidence:
            (t / 'evidence.json').write_text(json.dumps(evidence_doc() if evidence is True else evidence))
            paths['evidence'] = t / 'evidence.json'
        if after:
            (t / 'after.json').write_text(json.dumps(evidence_doc(after=True)))
            paths['after'] = t / 'after.json'
        if analysis is not None:
            (t / 'analysis.md').write_text(analysis, encoding='utf-8')
            paths['analysis'] = t / 'analysis.md'
        if journal:
            (t / 'journal.jsonl').write_bytes(b'\n'.join(journal_lines or sample_journal()) + b'\n')
            paths['journal'] = t / 'journal.jsonl'
        if readiness:
            (t / 'readiness.json').write_text(json.dumps(READINESS))
            paths['readiness'] = t / 'readiness.json'
        return paths

    def counts(self, paths):
        if 'analysis' not in paths or 'evidence' not in paths:
            return None
        text = paths['analysis'].read_text(encoding='utf-8')
        ev = json.loads(paths['evidence'].read_text())
        if not rr.sane_evidence(ev):
            return None
        accepted, rejected = rc.parse_ai_proposals(text, SHIPPED, ev, rc.normalize_scope(ev.get('scope') or ['all']))
        return len(accepted), rejected

    def common(self, **over):
        c = {'run_id': RUN, 'mode': 'linux-host', 'outcome': 'completed', 'started': STARTED, 'ended': ENDED,
             'version': '0.3.0', 'scope': '', 'policy': '', 'key_present': True}
        c.update(over)
        return c

    def python(self, paths, name='py', **over):
        c = self.common(**over)
        out = self.tmp / name
        args = [sys.executable, str(CLI), '--reports-dir', str(out), '--run-id', c['run_id'], '--mode', c['mode'], '--outcome', c['outcome'],
                '--started-at', c['started'], '--ended-at', c['ended'], '--key-present', 'yes' if c['key_present'] else 'no',
                '--version-file', str(self.tmp / 'VERSION')]
        (self.tmp / 'VERSION').write_text(c['version'] + '\n')
        if c['scope']:
            args += ['--scope', c['scope']]
        if c['policy']:
            args += ['--repair-policy', c['policy']]
        for flag, key in (('--evidence', 'evidence'), ('--evidence-after', 'after'), ('--analysis', 'analysis'), ('--journal', 'journal'),
                          ('--readiness', 'readiness')):
            if key in paths:
                args += [flag, str(paths[key])]
        env = {k: v for k, v in os.environ.items() if k != 'OPENCODE_GO_API_KEY'}
        if c.get('secret'):
            env['OPENCODE_GO_API_KEY'] = c['secret']
        proc = subprocess.run(args, capture_output=True, text=True, env=env)
        return out, proc

    def powershell(self, paths, name='ps', **over):
        c = self.common(**over)
        out = self.tmp / name
        cfg = {'reports': str(out), 'run_id': c['run_id'], 'mode': c['mode'], 'outcome': c['outcome'], 'version': c['version'], 'catalog_sha': SHIPPED.sha256,
               'scope': [s for s in c['scope'].split(',') if s], 'policy': c['policy'], 'key_present': c['key_present'],
               'evidence': str(paths.get('evidence', '')), 'after': str(paths.get('after', '')),
               'analysis': str(paths.get('analysis', '')), 'journal': str(paths.get('journal', '')),
               'readiness': str(paths.get('readiness', '')), 'action_info': INFO, 'ai_counts': self.counts(paths),
               'secret': c.get('secret', '')}
        (self.tmp / 'cfg.json').write_text(json.dumps(cfg))
        script = (
            "$env:RESCUE_PS_LIBRARY_ONLY='1'; . $env:RR_PS1; "
            "$cfg = Get-Content -Raw -LiteralPath $env:RR_CFG | ConvertFrom-Json; "
            "$info = @{}; foreach ($p in $cfg.action_info.PSObject.Properties) { $pm = @{}; "
            "foreach ($q in $p.Value.params.PSObject.Properties) { $pm[$q.Name] = [string]$q.Value }; "
            "$info[$p.Name] = @{ doc = $p.Value.doc; params = $pm } }; "
            "$rd = $null; if ($cfg.readiness) { $rd = Get-Content -Raw -LiteralPath $cfg.readiness | ConvertFrom-Json }; "
            "$counts = $null; if ($cfg.ai_counts) { $counts = @([int]$cfg.ai_counts[0], [int]$cfg.ai_counts[1]) }; "
            "$ok = Invoke-RunReport -Reports $cfg.reports -RunId $cfg.run_id -Mode $cfg.mode -Outcome $cfg.outcome -Started $env:RR_STARTED "
            "-Ended $env:RR_ENDED -Version $cfg.version -CatalogSha $cfg.catalog_sha -Scope @($cfg.scope) -Policy $cfg.policy "
            "-KeyPresent ([bool]$cfg.key_present) -EvidencePath $cfg.evidence -EvidenceAfterPath $cfg.after -AnalysisPath $cfg.analysis "
            "-JournalPath $cfg.journal -ActionInfo $info -AiCounts $counts -Readiness $rd -Secrets @($cfg.secret); "
            "Write-Output ('OK=' + $ok)")
        proc = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command', script], capture_output=True, text=True,
                              env=HL.clean_env(RR_PS1=str(PS1), RR_CFG=str(self.tmp / 'cfg.json'), RR_STARTED=c['started'], RR_ENDED=c['ended']), stdin=subprocess.DEVNULL, timeout=300)
        return out, proc

    def jxa(self, paths, name='js', existing=None, **over):
        """Runs the JXA generator like the zsh glue does (json, md, then index) and writes the files."""
        c = self.common(**over)
        out = self.tmp / name
        out.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, RESCUE_RR_RUN_ID=c['run_id'], RESCUE_RR_MODE=c['mode'], RESCUE_RR_OUTCOME=c['outcome'],
                   RESCUE_RR_STARTED=c['started'], RESCUE_RR_ENDED=c['ended'], RESCUE_RR_VERSION=c['version'],
                   RESCUE_RR_CATALOG_SHA=SHIPPED.sha256, RESCUE_RR_SCOPE=c['scope'], RESCUE_RR_POLICY=c['policy'],
                   RESCUE_RR_KEY_PRESENT='yes' if c['key_present'] else 'no', RESCUE_RR_ACTION_INFO=action_info_lines(),
                   RESCUE_RR_EVIDENCE=str(paths.get('evidence', '')), RESCUE_RR_EVIDENCE_AFTER=str(paths.get('after', '')),
                   RESCUE_RR_ANALYSIS=str(paths.get('analysis', '')), RESCUE_RR_JOURNAL=str(paths.get('journal', '')),
                   RESCUE_RR_READINESS=str(paths.get('readiness', '')), RESCUE_RR_FORCE_REFUSE=c.get('force_refuse', ''), RESCUE_RR_KEY_REDACTIONS=str(c.get('key_redactions', 0)))
        counts = self.counts(paths)
        if counts and 'analysis' in paths:
            env['RESCUE_RR_AI_ACCEPTED'], env['RESCUE_RR_AI_REJECTED'] = str(counts[0]), str(counts[1])
        results = {}
        for what in ('json', 'md'):
            proc = subprocess.run([NODE, str(SHIM_JS), '-e', jxa_source()], capture_output=True, text=True,
                                  env=dict(env, RESCUE_RR_OUT=what))
            if proc.returncode != 0:
                return out, proc
            results[what] = proc.stdout.rstrip('\n') + '\n'
        stamp = c['started'].replace('-', '').replace(':', '')
        run_dir = out / ('run-' + stamp)
        run_dir.mkdir()
        (run_dir / 'report.json').write_text(results['json'], encoding='utf-8')
        (run_dir / 'report.md').write_text(results['md'], encoding='utf-8')
        runs = sorted(str(p) for p in out.glob('run-*/report.json'))
        proc = subprocess.run([NODE, str(SHIM_JS), '-e', jxa_source()], capture_output=True, text=True,
                              env=dict(env, RESCUE_RR_OUT='index', RESCUE_RR_RUNS='\n'.join(runs)))
        (out / 'index.md').write_text(proc.stdout.rstrip('\n') + '\n', encoding='utf-8')
        return out, proc


def read_report(out):
    run = sorted(out.glob('run-*'))[-1]
    return json.loads((run / 'report.json').read_text(encoding='utf-8')), (run / 'report.md').read_text(encoding='utf-8'), \
        (out / 'index.md').read_text(encoding='utf-8')


class CrossCheckMixin:
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='run-report-x-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.gen = Generators(self.tmp)

    def other(self, paths, name, **over):
        raise NotImplementedError

    def assert_same(self, paths, **over):
        py_dir, proc = self.gen.python(paths, **over)
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        other_dir, proc = self.other(paths, **over)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, other = read_report(py_dir), read_report(other_dir)
        validate(self, other[0])
        self.assertEqual(py[0], other[0])
        self.assertEqual(py[1], other[1])
        self.assertEqual(py[2], other[2])
        return py, other

    def test_full_report_is_equal(self):
        (py, other) = self.assert_same(self.gen.files())
        self.assertEqual(py[0]['remediation']['journal']['chain'], 'valid')
        self.assertEqual(len(py[0]['remediation']['actions']), 9)

    def test_other_platform_modes_and_outcomes(self):
        paths = self.gen.files()
        for mode, outcome, key in (('windows-host', 'no-key', False), ('macos-host', 'network-error', True), ('live-linux', 'dry-run', True)):
            with self.subTest(mode=mode):
                shutil.rmtree(self.tmp / 'py', ignore_errors=True)
                shutil.rmtree(self.tmp / self.NAME, ignore_errors=True)
                self.assert_same(paths, mode=mode, outcome=outcome, key_present=key)

    def test_failed_run_without_artifacts_is_equal(self):
        paths = self.gen.files(evidence=False, after=False, analysis=None, journal=False, readiness=True)
        self.assert_same(paths, mode='live-linux', outcome='preflight-failed', scope='os', policy='detect-only')

    def test_minimal_run_and_no_action(self):
        paths = self.gen.files(after=False, journal=False, readiness=False)
        py, _ = self.assert_same(paths, mode='linux-host', outcome='completed')
        self.assertFalse(py[0]['comparison']['performed'])

    def test_tampered_journal_is_equal_and_invalid(self):
        lines = sample_journal()
        lines[3] = lines[3].replace(b'"outcome":"ok"', b'"outcome":"fail"')
        paths = self.gen.files(journal_lines=lines)
        py, _ = self.assert_same(paths)
        self.assertEqual(py[0]['remediation']['journal']['chain'], 'INVALID')
        self.assertIn('JOURNAL HASH CHAIN INVALID', py[1])

    def test_sanitizing_is_equal(self):
        text = 'Analisis \x1b[31mmerah\x1b[0m\r\nbaris\u202e dua\x00\x07\n\n\ttab\n' + 'y' * 40000
        paths = self.gen.files(analysis=text)
        py, _ = self.assert_same(paths)
        self.assertTrue(py[0]['analysis']['text_truncated'])

    MODEL_TEXT = PrivacySelfCheckTests.MODEL_TEXT

    def test_model_text_redaction_is_equal(self):
        py, _ = self.assert_same(self.gen.files(analysis=self.MODEL_TEXT))
        self.assertEqual(py[0]['privacy_check']['status'], 'passed')
        self.assertEqual(py[0]['analysis']['redactions'], 7)
        self.assertIn('kernel <ip>, router <ip>', py[0]['analysis']['text'])

    def test_structural_privacy_refusal_is_equal(self):
        py, _ = self.assert_same(self.gen.files(), run_id='run-10.20.30.40')
        self.assertEqual(py[0]['privacy_check'], {'status': 'refused', 'findings': ['ipv4-address']})
        self.assertEqual(py[0]['header']['outcome'], 'report-privacy-refused')

    def test_hostile_inputs_are_dropped_equally(self):
        evil = evidence_doc()
        evil['checks'][0]['check_id'] = '../../etc/passwd'
        paths = self.gen.files(evidence=evil, after=False)
        py, _ = self.assert_same(paths)
        self.assertFalse(py[0]['detection']['available'])
        j = Chain()
        j.add('hw.smart-short-selftest', 'proposed', 'ok')
        j.add('../evil', 'proposed', 'ok')
        j.add('hw.smart-short-selftest', 'approval', 'ok', reason='rm -rf /')
        # Only the Python generator also checks the journal against its JSON schema (INVALID); the hash chain
        # is intact here, so PS/JXA say valid. Everything they DO report about the hostile records must be safe.
        shutil.rmtree(self.tmp / self.NAME, ignore_errors=True)
        other_dir, proc = self.other(self.gen.files(journal_lines=j.lines))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md, _ = read_report(other_dir)
        validate(self, doc)
        self.assertEqual([a['action_id'] for a in doc['remediation']['actions']], ['hw.smart-short-selftest'])
        self.assertNotIn('rm -rf', json.dumps(doc) + md)
        self.assertNotIn('evil', json.dumps(doc) + md)

    def test_two_runs_index_is_equal(self):
        paths = self.gen.files()
        for stamp in ('2026-09-29T10:00:00Z', STARTED):
            self.assert_same(paths, started=stamp, ended=stamp)
        py = read_report(self.tmp / 'py')[2]
        self.assertEqual(len([l for l in py.splitlines() if l.startswith('| 2026')]), 2)


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellCrossCheck(CrossCheckMixin, unittest.TestCase):
    NAME = 'ps'

    def other(self, paths, **over):
        return self.gen.powershell(paths, name='ps', **over)

    def test_key_value_is_redacted_or_refused_like_python(self):
        paths = self.gen.files(analysis='mengulang ' + DUMMY_KEY)
        py_dir, proc = self.gen.python(paths, secret=DUMMY_KEY)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        ps_dir, proc = self.gen.powershell(paths, secret=DUMMY_KEY)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        py, ps = read_report(py_dir), read_report(ps_dir)
        self.assertEqual(py[:2], ps[:2])
        self.assertEqual((ps[0]['analysis']['text'], ps[0]['analysis']['redactions']), ('mengulang <redacted>', 1))
        self.assertNotIn(DUMMY_KEY, json.dumps(ps[0]) + ps[1])
        shutil.rmtree(py_dir)
        shutil.rmtree(ps_dir)
        paths = self.gen.files()
        py_dir, _ = self.gen.python(paths, secret=DUMMY_KEY, run_id='run-' + DUMMY_KEY)
        ps_dir, proc = self.gen.powershell(paths, secret=DUMMY_KEY, run_id='run-' + DUMMY_KEY)
        self.assertEqual(read_report(py_dir)[0], read_report(ps_dir)[0])
        self.assertEqual(read_report(ps_dir)[0]['privacy_check']['findings'], ['configured-key-value'])

    def test_ps_files_are_private_where_the_platform_allows(self):
        out, proc = self.gen.powershell(self.gen.files())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for path in list(out.rglob('*')):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        self.assertEqual([p.name for p in out.glob('.*')], [])


@unittest.skipUnless(NODE, 'node not installed')
class JxaCrossCheck(CrossCheckMixin, unittest.TestCase):
    NAME = 'js'

    def other(self, paths, **over):
        return self.gen.jxa(paths, name='js', **over)

    def test_key_value_redaction_by_the_shell_and_structural_refusal_match_python(self):
        # The zsh glue redacts the key in a copy of the analysis and passes the count (the key never reaches osascript).
        paths = self.gen.files(analysis='mengulang ' + DUMMY_KEY)
        py_dir, proc = self.gen.python(paths, secret=DUMMY_KEY)
        redacted = self.tmp / 'in' / 'analysis-redacted.md'
        redacted.write_text('mengulang <redacted>', encoding='utf-8')
        js_dir, proc = self.gen.jxa(dict(paths, analysis=redacted), key_redactions=1)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(read_report(py_dir)[:2], read_report(js_dir)[:2])
        shutil.rmtree(py_dir)
        shutil.rmtree(js_dir)
        paths = self.gen.files()
        py_dir, _ = self.gen.python(paths, secret=DUMMY_KEY, run_id='run-' + DUMMY_KEY)
        js_dir, proc = self.gen.jxa(paths, force_refuse='configured-key-value', run_id='run-' + DUMMY_KEY)
        self.assertEqual(read_report(py_dir)[0], read_report(js_dir)[0])

    def test_jxa_source_avoids_lookbehind_and_shell_out(self):
        src = jxa_source()
        self.assertNotIn('(?<', src)
        for forbidden in ('doShellScript', 'NSTask', 'eval(', 'Function(', 'require(', 'system('):
            self.assertNotIn(forbidden, src)

    def test_sha256_matches_hashlib(self):
        src = jxa_source().replace('main();', 'sha256(utf8Bytes(envv("RESCUE_RR_TEXT")));')
        for text in ('', 'abc', 'a' * 55, 'a' * 56, 'a' * 64, 'a' * 1000, 'caf\u00e9 \u4e2d\u6587 \U0001F600'):
            proc = subprocess.run([NODE, str(SHIM_JS), '-e', src], capture_output=True, text=True, env=dict(os.environ, RESCUE_RR_TEXT=text))
            self.assertEqual(proc.stdout.strip(), hashlib.sha256(text.encode('utf-8')).hexdigest(), text[:20])


# ----------------------------------------------------------------------------------------
# Launcher wiring
# ----------------------------------------------------------------------------------------
def run_dirs(reports):
    return sorted(p for p in Path(reports).glob('run-*') if p.is_dir())


def load_report(reports, index=-1):
    run = run_dirs(reports)[index]
    return json.loads((run / 'report.json').read_text(encoding='utf-8')), (run / 'report.md').read_text(encoding='utf-8')


class LinuxHostReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='report-linux-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = HL.make_usb(self.tmp)
        shutil.copy2(REPO / 'VERSION', self.bundle / 'VERSION')
        self.script = self.bundle / 'host' / 'rescue-linux.sh'
        self.reports = self.bundle / 'reports'
        self.fakebin = self.tmp / 'fakebin'
        self.fakebin.mkdir()
        self.flag = self.tmp / 'flag'
        # `dpkg --audit` prints something until the fake repair program has touched the flag
        (self.fakebin / 'dpkg').write_text('#!/bin/sh\n[ -e "%s" ] || echo "half-configured"\nexit 0\n' % self.flag)
        (self.fakebin / 'rescuefake').write_text('#!/bin/sh\n: > "%s"\necho ok\n' % self.flag)
        for name in ('dpkg', 'rescuefake'):
            (self.fakebin / name).chmod(0o755)
        step = {'argv': ['rescuefake', 'ok']}
        HR.install_catalog(self.bundle, {'os-linux.json': {'catalog_version': '1', 'domain': 'os-linux', 'actions': [{
            'action_id': 'os-linux.report-fix', 'title': 'Report test fix', 'title_id': 'Perbaikan uji laporan', 'scope': 'os', 'platforms': ['linux-host'],
            'target_families': ['linuxmint', 'linux-other'], 'risk': 'safe',
            'triggers': [{'check_id': 'linux-package-state', 'status': ['warn']}], 'execute': step, 'verify': step,
            'rollback': {'kind': 'none'}, 'backup': {'required': False}, 'doc': 'docs/os-repair.md'}]}})

    def env(self, **extra):
        return HL.clean_env(PATH=str(self.fakebin) + os.pathsep + os.environ.get('PATH', ''), RESCUE_REPAIR_TEST_PATH=str(self.fakebin),
                            RESCUE_TEST_BASE_URL='http://127.0.0.1:9', **extra)

    def run_launcher(self, *args, env=None):
        return subprocess.run([str(self.script), *args], capture_output=True, text=True, env=env or self.env(), cwd=self.tmp,
                              stdin=subprocess.DEVNULL, timeout=300)

    def test_evidence_only_writes_report_and_index_to_the_usb_only(self):
        before = HL.bundle_files(self.bundle)
        proc = self.run_launcher('--evidence-only', '--scope', 'os')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(HL.bundle_files(self.bundle), before)
        names = sorted(p.name for p in self.reports.iterdir())
        self.assertEqual(len(names), 3, names)
        self.assertIn('index.md', names)
        doc, md = load_report(self.reports)
        validate(self, doc)
        self.assertEqual((doc['header']['mode'], doc['header']['outcome']), ('linux-host', 'evidence-only'))
        self.assertEqual(doc['header']['scope'], ['os'])
        self.assertTrue(doc['detection']['available'])
        self.assertIn('analysis-not-run-offline-mode', doc['honesty']['environment_blocked'])
        self.assertEqual(doc['readiness']['gate'], 'not_applicable')
        HL.assert_no_identity(self, md + json.dumps(doc), self.tmp)
        for path in self.reports.rglob('*'):
            if path.is_file() and path.name != 'journal.jsonl':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        self.assertIn('run-', (self.reports / 'index.md').read_text())

    def test_no_key_run_is_reported_with_the_guidance_outcome(self):
        proc = self.run_launcher('--scope', 'os')
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        doc, md = load_report(self.reports)
        validate(self, doc)
        self.assertEqual(doc['header']['outcome'], 'no-key')
        self.assertFalse(doc['header']['provider_key_present'])
        self.assertIn('provider-key-missing', doc['honesty']['environment_blocked'])
        self.assertEqual(doc['analysis']['status'], 'not_run')

    def test_analysis_repair_and_rescan_are_in_the_report(self):
        base_env = self.env()
        server = HL._FakeApi
        import http.server
        import threading
        server.status, server.seen = 200, []
        httpd = http.server.HTTPServer(('127.0.0.1', 0), server)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        (self.bundle / 'config').mkdir(exist_ok=True)
        env_file = self.bundle / 'config' / 'rescue.env'
        env_file.write_text("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        env_file.chmod(0o600)
        env = dict(base_env, RESCUE_TEST_BASE_URL='http://127.0.0.1:%d' % httpd.server_address[1])
        proc = self.run_launcher('--scope', 'os', '--repair-policy', 'auto-safe', env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md = load_report(self.reports)
        validate(self, doc)
        self.assertEqual(doc['header']['outcome'], 'completed')
        self.assertEqual(doc['header']['toolkit_version'], (REPO / 'VERSION').read_text().strip())
        self.assertTrue(doc['header']['provider_key_present'])
        self.assertEqual(doc['analysis']['status'], 'completed')
        self.assertIn('semua ok', doc['analysis']['text'])
        self.assertIn('MODEL OUTPUT, read-only; never executed.', md)
        actions = doc['remediation']['actions']
        self.assertEqual([(a['action_id'], a['final_outcome'], a['approval']['decision']) for a in actions],
                         [('os-linux.report-fix', 'verified', 'auto-safe')])
        self.assertEqual(doc['remediation']['journal']['chain'], 'valid')
        cmp_ = doc['comparison']
        self.assertEqual((cmp_['performed'], cmp_['reason']), (True, 'executed'))
        self.assertIn({'check_id': 'linux-package-state', 'target_ref': 'os-0', 'before': 'warn', 'after': 'pass'}, cmp_['changed'])
        self.assertTrue(list(self.reports.glob('linux-*-evidence-after.json')))
        self.assertNotIn(DUMMY_KEY, ''.join(p.read_text(encoding='utf-8', errors='replace') for p in self.reports.rglob('*')
                                            if p.is_file()))

    def test_declined_repairs_and_no_rescan(self):
        proc = self.run_launcher('--scope', 'os')  # approve-each without a terminal: declined
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports)
        self.assertEqual([(a['final_outcome'], a['approval']['decision']) for a in doc['remediation']['actions']],
                         [('declined', 'not-interactive')])
        self.assertEqual((doc['comparison']['performed'], doc['comparison']['reason']), (False, 'no-action-executed'))
        self.assertFalse(self.flag.exists())
        kinds = [i['kind'] for i in doc['open_items']]
        self.assertIn('action-declined', kinds)

    def test_failed_and_partial_paths_still_write_a_report(self):
        (self.bundle / 'scripts' / 'opencode-go-analyze.py').unlink()
        proc = self.run_launcher('--dry-run', '--scope', 'os')
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports)
        self.assertEqual(doc['header']['outcome'], 'analyzer-missing')
        self.assertIn('analysis-failed', doc['honesty']['environment_blocked'])
        # a run whose evidence cannot be created (bad scope is a usage error and writes nothing; a missing python module does)
        self.assertEqual(self.run_launcher('--scope', 'BAD SCOPE').returncode, 64)
        self.assertEqual(len(run_dirs(self.reports)), 1)

    def test_two_runs_are_both_listed(self):
        self.assertEqual(self.run_launcher('--evidence-only', '--scope', 'os').returncode, 0)
        time.sleep(1.1)
        self.assertEqual(self.run_launcher('--evidence-only', '--scope', 'hardware.cpu').returncode, 0)
        rows = [l for l in (self.reports / 'index.md').read_text().splitlines() if l.startswith('| 20')]
        self.assertEqual(len(rows), 2)
        self.assertLess(rows[1].split(' | ')[0], rows[0].split(' | ')[0])  # newest first


@unittest.skipUnless(PWSH, 'pwsh not installed')
class WindowsReportTests(HR.HostRepairCase):
    OSP, FAMILY, PLATFORM = 'os-windows', 'windows', 'windows-host'
    CHECKS = ('windows-system-files', 'windows-boot-config', 'sw-inventory')

    def setUp(self):
        HR.WindowsRepairTests.setUp(self)
        shutil.copy2(REPO / 'VERSION', self.bundle / 'VERSION')  # a real USB bundle carries VERSION
        self.flag = self.fakebin / 'flag'
        (self.fakebin / 'rescuefake').write_text('#!/bin/sh\nd=${0%/*}\ncase "$1" in ok) : > "$d/flag" ;; esac\nexit 0\n')
        (self.bundle / 'host' / 'modules' / 'windows' / 'os.ps1').write_text(
            "param([string[]]$Scope, [string[]]$Packages)\n"
            "$st = 'fail'; if (Test-Path -LiteralPath $env:RESCUE_FLAG) { $st = 'pass' }\n"
            "@{ check_id = 'windows-system-files'; status = $st }\n@{ check_id = 'windows-boot-config'; status = 'fail' }\n")

    def env(self, **extra):
        return HL.clean_env(RESCUE_REPAIR_TEST_PATH=str(self.fakebin), RESCUE_FLAG=str(self.flag), **extra)

    def run_args(self, *args):
        return HR.WindowsRepairTests.run_args(self, *args)

    def test_report_covers_repairs_rescan_and_the_no_key_path(self):
        proc = self.run_args('-Approve', 'os-windows.safe-ok', '-Scope', 'os')
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        reports = self.bundle / 'reports'
        doc, md = load_report(reports)
        validate(self, doc)
        self.assertEqual((doc['header']['mode'], doc['header']['outcome']), ('windows-host', 'no-key'))
        finals = {a['action_id']: (a['final_outcome'], a['approval']['decision']) for a in doc['remediation']['actions']}
        self.assertEqual(finals['os-windows.safe-ok'], ('verified', 'cli'))
        self.assertEqual(finals['os-windows.rev-fail'], ('declined', 'not-interactive'))
        self.assertEqual(doc['remediation']['journal']['chain'], 'valid')
        cmp_ = doc['comparison']
        self.assertEqual((cmp_['performed'], cmp_['reason']), (True, 'executed'))
        self.assertEqual([c for c in cmp_['changed'] if c['check_id'] == 'windows-system-files'],
                         [{'check_id': 'windows-system-files', 'target_ref': 'os-0', 'before': 'fail', 'after': 'pass'}])
        self.assertTrue(list(reports.glob('windows-*-evidence-after.json')))
        self.assertTrue((reports / 'index.md').exists())
        self.assertEqual(doc['header']['catalog_sha256'], self.load_python_catalog().sha256)
        self.assertEqual(doc['header']['toolkit_version'], (REPO / 'VERSION').read_text().strip())
        # the bundle's journal verifies with the Python engine and the report agrees
        HR.verify_with_python(self, self.journal)

    def test_evidence_only_and_detect_only_write_reports_without_actions(self):
        for flags, outcome in ((('-EvidenceOnly',), 'evidence-only'), (('-DryRun',), 'dry-run')):
            with self.subTest(outcome=outcome):
                shutil.rmtree(self.bundle / 'reports', ignore_errors=True)
                proc = self.run_args(*flags, '-Scope', 'os')
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                doc, _ = load_report(self.bundle / 'reports')
                validate(self, doc)
                self.assertEqual(doc['header']['outcome'], outcome)
                self.assertEqual(doc['remediation']['actions'], [])
                time.sleep(1.05)

    def test_bad_flags_and_missing_bundle_write_no_report(self):
        self.assertEqual(self.run_args('-Scope', 'bogus').returncode, 64)
        self.assertEqual(run_dirs(self.bundle / 'reports'), [])


@unittest.skipUnless(ZSH and NODE, 'zsh or node not installed')
class MacReportTests(HR.HostRepairCase):
    OSP, FAMILY, PLATFORM = 'os-macos', 'macos', 'macos-host'
    CHECKS = ('macos-disk-verify', 'macos-software-update', 'sw-inventory')

    def setUp(self):
        HR.MacRepairTests.setUp(self)
        shutil.copy2(REPO / 'VERSION', self.bundle / 'VERSION')
        self.flag = self.fakebin / 'flag'
        (self.fakebin / 'rescuefake').write_text('#!/bin/sh\nd=${0%/*}\ncase "$1" in ok) : > "$d/flag" ;; esac\nexit 0\n')
        (self.bundle / 'host' / 'modules' / 'macos' / 'os.zsh').write_text(
            'if [[ -e $RESCUE_FLAG ]]; then print -r -- "macos-disk-verify pass"; else print -r -- "macos-disk-verify fail"; fi\n'
            'print -r -- "macos-software-update fail"\n')

    def env(self, **extra):
        return HR.MacRepairTests.env(self, RESCUE_FLAG=str(self.flag), **extra)

    def run_args(self, *args, env=None):
        return HR.MacRepairTests.run_args(self, *args, env=env)

    def write_env_file(self, text):
        return HR.MacRepairTests.write_env_file(self, text)

    def with_key(self, text):
        return HR.MacRepairTests.with_key(self, text)

    def test_report_covers_repairs_rescan_and_the_no_key_path(self):
        proc = self.run_args('--approve', 'os-macos.safe-ok', '--scope', 'os')
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        reports = self.bundle / 'reports'
        doc, md = load_report(reports)
        validate(self, doc)
        self.assertEqual((doc['header']['mode'], doc['header']['outcome']), ('macos-host', 'no-key'))
        finals = {a['action_id']: (a['final_outcome'], a['approval']['decision']) for a in doc['remediation']['actions']}
        self.assertEqual(finals['os-macos.safe-ok'], ('verified', 'cli'))
        self.assertEqual(finals['os-macos.rev-fail'], ('declined', 'not-interactive'))
        cmp_ = doc['comparison']
        self.assertEqual((cmp_['performed'], cmp_['reason']), (True, 'executed'))
        self.assertEqual([c for c in cmp_['changed'] if c['check_id'] == 'macos-disk-verify'],
                         [{'check_id': 'macos-disk-verify', 'target_ref': 'os-0', 'before': 'fail', 'after': 'pass'}])
        self.assertEqual(doc['header']['catalog_sha256'], self.load_python_catalog().sha256)
        self.assertEqual(doc['remediation']['journal']['chain'], 'valid')
        self.assertTrue((reports / 'index.md').exists())
        self.assertEqual(doc['header']['toolkit_version'], (REPO / 'VERSION').read_text().strip())
        for path in reports.rglob('*'):
            if path.is_file() and path.name != 'journal.jsonl':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)

    def test_analysis_key_and_ai_counts(self):
        self.with_key('Analisis.\n```rescue-proposals\n{"proposed_actions":[{"action_id":"os-macos.slow","target_ref":"os-0"},'
                      '{"action_id":"os-macos.nope"}]}\n```\n')
        proc = self.run_args('--scope', 'os')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, md = load_report(self.bundle / 'reports')
        validate(self, doc)
        self.assertEqual(doc['header']['outcome'], 'completed')
        self.assertEqual(doc['analysis']['status'], 'completed')
        self.assertEqual((doc['analysis']['proposals']['accepted'], doc['analysis']['proposals']['rejected']), (1, 1))
        self.assertIn('MODEL OUTPUT, read-only; never executed.', md)
        blob = ''.join(p.read_text(encoding='utf-8', errors='replace') for p in (self.bundle / 'reports').rglob('*') if p.is_file())
        self.assertNotIn(HL.DUMMY_KEY, blob)

    def test_the_key_value_in_the_answer_is_redacted(self):
        self.with_key('Kunci: ' + HL.DUMMY_KEY)
        proc = self.run_args('--scope', 'os')
        doc, md = load_report(self.bundle / 'reports')
        validate(self, doc)
        self.assertEqual(doc['privacy_check']['status'], 'passed')
        self.assertEqual(doc['analysis']['redactions'], 1)
        self.assertTrue(doc['analysis']['text'].rstrip().endswith('Kunci: <redacted>'))
        blob = ''.join(p.read_text(encoding='utf-8', errors='replace') for p in (self.bundle / 'reports').rglob('*')
                       if p.is_file() and p.name != 'journal.jsonl' and not p.name.endswith('-analysis.md'))
        self.assertNotIn(HL.DUMMY_KEY, blob)
        self.assertEqual([p.name for p in (self.bundle / 'reports').glob('.report-*')], [])

    def test_without_osascript_the_launcher_says_so_and_still_exits_normally(self):
        (self.shims / 'osascript').unlink()
        proc = self.run_args('--evidence-only', '--scope', 'os')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('run report skipped', proc.stdout)
        self.assertEqual(run_dirs(self.bundle / 'reports'), [])


class LiveLauncherReportTests(unittest.TestCase):
    """scripts/launch-hermes-rescue.sh with a stub scanner (see tests/test_target_scan.py TestLauncherWiring)."""

    @classmethod
    def setUpClass(cls):
        import test_target_scan as TS
        import test_hermes_scripts as THS
        cls.TS, cls.THS = TS, THS

    def setUp(self):
        if not self.THS._can_run_unprivileged():
            self.skipTest('need a non-root user or setpriv')
        base = self.THS.HermesScriptTestCase
        self.case = base()
        base.setUp(self.case)
        self.addCleanup(shutil.rmtree, self.case.tmp, True)
        self.assertEqual(self.case.install().returncode, 0)
        c = self.case
        c.marker = c.tmp / 'scan-marker'
        shutil.copy2(REPO / 'VERSION', c.src / 'VERSION')
        c.write_shim('hermes', "printf 'HERMES-RAN %s\\n' \"$*\"\n")
        c.write_shim('sudo', '[ "$1" = -n ] && shift\nexec "$@"\n')
        hw = c.src / 'scripts' / 'check-hardware-readiness.py'
        hw.write_text('#!/usr/bin/env python3\nimport json, sys\n'
                      'out = sys.argv[sys.argv.index("--output") + 1]\n'
                      'json.dump(%r, open(out, "w"))\nsys.exit(0)\n' % dict(READINESS))
        os.chmod(hw, 0o755)
        c._open(hw)
        c.provider = self.TS.FakeProvider(content='Fakta: aman.\x1b[31m merah\nHipotesis: tidak ada.')
        self.addCleanup(c.provider.close)
        # a private catalog whose safe action flips a stub-scanner check, executed by a fake program
        self.flagfile = c.tmp / 'flag'
        self.fake = c.tmp / 'fakebin'
        self.fake.mkdir()
        (self.fake / 'rescuefake').write_text('#!/bin/sh\n: > "%s"\necho ok\n' % self.flagfile)
        (self.fake / 'rescuefake').chmod(0o755)
        c._open(self.fake, recursive=True)
        step = {'argv': ['rescuefake', 'ok']}
        cat = c.src / 'rescue-ai' / 'v1' / 'catalog'
        for old in cat.glob('*.json'):
            old.unlink()
        (cat / 'hardware.json').write_text(json.dumps({'catalog_version': '1', 'domain': 'hardware', 'actions': [{
            'action_id': 'hw.report-fix', 'title': 'Report test fix', 'title_id': 'Perbaikan uji laporan', 'scope': 'hardware.cpu',
            'platforms': ['live-linux'], 'risk': 'safe', 'triggers': [{'check_id': 'hw-cpu', 'status': ['warn']}],
            'execute': step, 'verify': step, 'rollback': {'kind': 'none'}, 'backup': {'required': False}, 'doc': 'docs/hardware.md'}]}))
        c._open(cat, recursive=True)
        self.stub = c.src / 'scripts' / 'scan-target-os.py'
        self.stub.write_text(
            '#!/usr/bin/env python3\nimport json, os, sys\nargs = sys.argv[1:]\nout = args[args.index("--output") + 1]\n'
            'flag = %r\ndoc = json.load(open(%r))\n'
            'doc["run_id"] = "rescue-20260930-08%%s-live" %% ("1200" if os.path.exists(flag) else "0000")\n'
            'doc["checks"] = [c for c in doc["checks"] if c["check_id"] != "hw-cpu"] + [{"check_id": "hw-cpu", "status": "pass" if os.path.exists(flag) else "warn", '
            '"source": "offline-target-scan", "observed_at": "2026-09-30T08:00:00Z"}]\n'
            'doc["evidence_manifest"]["entry_count"] = len(doc["checks"])\ndoc["schema_version"] = "1.2"\ndoc["scope"] = ["all"]\ndoc["repair_policy"] = "approve-each"\n'
            'json.dump(doc, open(out, "w"))\n' % (str(self.flagfile), str(c.src / 'rescue-ai' / 'v1' / 'fixtures' / 'valid-live-multi-os-1.1.json')))
        os.chmod(self.stub, 0o755)
        c._open(self.stub)
        os.chmod(self.stub, 0o755)

    def launch(self, *extra, key=DUMMY_KEY, path_extra=None):
        c = self.case
        env = {'RESCUE_TEST_BASE_URL': c.provider.base, 'RESCUE_REPAIR_TEST_PATH': str(self.fake), 'RESCUE_TARGET_MOUNT_FIXTURE_ROOT': str(c.tmp)}
        if key:
            env['OPENCODE_GO_API_KEY'] = key
        return c.run_cmd([c.src / 'scripts' / 'launch-hermes-rescue.sh', '--state-dir', c.state, *extra], env_extra=env,
                         path=f'{c.shims}:/usr/bin:/bin')

    def reports_dir(self):
        return self.case.state / 'reports'

    def test_successful_run_report_before_hermes(self):
        proc = self.launch('--repair-policy', 'auto-safe')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('HERMES-RAN', proc.stdout)
        self.assertLess(proc.stdout.index('report saved'), proc.stdout.index('HERMES-RAN'))
        doc, md = load_report(self.reports_dir())
        validate(self, doc)
        self.assertEqual((doc['header']['mode'], doc['header']['outcome']), ('live-linux', 'completed'), proc.stdout + proc.stderr)
        self.assertEqual(doc['readiness'], {'performed': True, 'gate': 'passed', 'overall': 'ready_with_warnings',
                                            'checks': [{'check_id': 'cpu', 'status': 'pass', 'required': True},
                                                       {'check_id': 'ram', 'status': 'pass', 'required': True},
                                                       {'check_id': 'usb-boot-media', 'status': 'warn', 'required': True},
                                                       {'check_id': 'internet-connectivity', 'status': 'pass', 'required': True}]})
        self.assertEqual(doc['analysis']['status'], 'completed')
        self.assertIn('Fakta: aman.', doc['analysis']['text'])
        self.assertNotIn('\x1b', md)
        self.assertEqual([(a['action_id'], a['final_outcome'], a['approval']['decision']) for a in doc['remediation']['actions']],
                         [('hw.report-fix', 'verified', 'auto-safe')])
        cmp_ = doc['comparison']
        self.assertEqual((cmp_['performed'], cmp_['reason']), (True, 'executed'))
        self.assertEqual([c for c in cmp_['changed'] if c['check_id'] == 'hw-cpu'],
                         [{'check_id': 'hw-cpu', 'before': 'warn', 'after': 'pass'}])
        self.assertEqual(doc['header']['catalog_sha256'], rc.load(self.case.src / 'rescue-ai' / 'v1' / 'catalog').sha256)
        self.assertEqual(doc['header']['toolkit_version'], (REPO / 'VERSION').read_text().strip())
        self.assertTrue(list(self.reports_dir().glob('target-evidence-*-after.json')))
        self.assertNotIn(DUMMY_KEY, ''.join(p.read_text(encoding='utf-8', errors='replace') for p in self.reports_dir().rglob('*')
                                            if p.is_file() and p.suffix in ('.md', '.json')))
        self.assertTrue((self.reports_dir() / 'index.md').exists())

    def test_declined_repair_means_no_rescan(self):
        proc = self.launch()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports_dir())
        self.assertEqual([(a['final_outcome'], a['approval']['decision']) for a in doc['remediation']['actions']], [('declined', 'not-interactive')])
        self.assertEqual((doc['comparison']['performed'], doc['comparison']['reason']), (False, 'no-action-executed'))
        self.assertFalse(list(self.reports_dir().glob('*-after.json')))

    def test_preflight_failure_is_reported(self):
        hw = self.case.src / 'scripts' / 'check-hardware-readiness.py'
        hw.write_text('#!/usr/bin/env python3\nimport json, sys\nout = sys.argv[sys.argv.index("--output") + 1]\n'
                      'doc = %r\ndoc["summary"] = {"overall": "not_ready"}\ndoc["checks"][0]["status"] = "fail"\n'
                      'json.dump(doc, open(out, "w"))\nsys.exit(1)\n' % dict(READINESS))
        proc = self.launch()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertNotIn('HERMES-RAN', proc.stdout)
        doc, md = load_report(self.reports_dir())
        validate(self, doc)
        self.assertEqual(doc['header']['outcome'], 'preflight-failed')
        self.assertEqual(doc['readiness']['gate'], 'failed')
        self.assertFalse(doc['detection']['available'])
        self.assertIn('hardware-preflight-failed', doc['honesty']['environment_blocked'])

    def test_scan_failure_no_key_and_no_scan_are_reported(self):
        self.stub.write_text('#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n')
        proc = self.launch()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports_dir())
        self.assertEqual(doc['header']['outcome'], 'scan-failed')
        self.assertFalse(doc['detection']['available'])
        time.sleep(1.05)
        proc = self.launch('--no-target-scan')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports_dir())
        self.assertEqual(doc['header']['outcome'], 'scan-skipped')
        self.assertEqual(len(run_dirs(self.reports_dir())), 2)

    def test_no_key_is_reported_as_such(self):
        proc = self.launch(key=None)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc, _ = load_report(self.reports_dir())
        self.assertEqual(doc['header']['outcome'], 'no-key')
        self.assertFalse(doc['header']['provider_key_present'])
        self.assertEqual(doc['analysis']['status'], 'not_run')
        self.assertTrue(doc['detection']['available'])


class StaticTests(unittest.TestCase):
    def test_schema_is_closed_and_has_no_free_text_except_the_analysis(self):
        text_fields = []

        def walk(node, path):
            if isinstance(node, dict):
                if node.get('type') == 'string' or node.get('type') == ['string', 'null']:
                    if not any(k in node for k in ('pattern', 'enum', 'const')):
                        text_fields.append(path)
                if node.get('type') == 'object':
                    self.assertIs(node.get('additionalProperties'), False if 'properties' in node else node.get('additionalProperties'), path)
                for k, v in node.items():
                    walk(v, path + '/' + k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, '%s/%d' % (path, i))
        walk(SCHEMA, '')
        self.assertEqual(text_fields, ['/properties/analysis/properties/text'])

    def test_fixture_schema_check_via_validator_object(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    def test_launchers_write_no_report_outside_the_usb_and_never_source_the_generator_state(self):
        for path in (HL.REPO / 'scripts' / 'launch-hermes-rescue.sh', HL.REPO / 'host' / 'rescue-linux.sh'):
            text = path.read_text(encoding='utf-8')
            self.assertIn('rescue-report.py', text)
            self.assertNotRegex(text, r'--key-present\s+"?\$OPENCODE_GO_API_KEY')  # presence only, never the value
        mac = MAC.read_text(encoding='utf-8')
        self.assertNotRegex(mac, r'python3?\b\s+.*rescue-report')
        self.assertNotIn('rescue-report.py', mac)
        ps = PS1.read_text(encoding='utf-8')
        self.assertNotIn('rescue-report.py', ps)

    def test_skill_reads_the_latest_report_first(self):
        skill = (REPO / 'profiles/rescue-hermes/skills/rescue-target-os/SKILL.md').read_text(encoding='utf-8')
        self.assertIn('report.md', skill)
        self.assertLess(skill.index('report.md'), skill.index('latest-evidence.json'))


if __name__ == '__main__':
    unittest.main()
