#!/usr/bin/env python3
"""Tests for scripts/rescue-followup.py, its schema, the Hermes kickoff/skills and the approvals deny list.

Fake smartctl/lsblk/journalctl are shell scripts found through RESCUE_REPAIR_TEST_PATH (the repair engine's
hook); /proc is replaced through RESCUE_FOLLOWUP_PROC_ROOT. No root, no real disks, no network, no Hermes
needed (the deny-list test runs only where a Hermes checkout exists and skips cleanly otherwise).
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import contextlib
import copy
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import jsonschema
except ImportError:  # CI installs it; a skip is not a pass
    jsonschema = None

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'scripts' / 'rescue-followup.py'
SCHEMA = REPO / 'rescue-ai' / 'v1' / 'followup.schema.json'
FIXTURES = REPO / 'rescue-ai' / 'v1' / 'fixtures'
EVIDENCE_FIXTURE = FIXTURES / 'valid-live-multi-os-1.1.json'
PROFILE = REPO / 'profiles' / 'rescue-hermes'
CONFIG = REPO / 'config' / 'hermes-rescue.config.yaml'
HERMES_DIR = Path(os.environ.get('HERMES_AGENT_DIR') or Path.home() / '.hermes' / 'hermes-agent')

LEAK_TOKENS = ('SECRETMODEL', 'SN12345678', 'LEAKMSG', 'secretunit', '/dev/', 'WDC-WD10')


def load_module():
    spec = importlib.util.spec_from_file_location('rescue_followup', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rf = load_module()

LSBLK = {'blockdevices': [
    {'name': 'sda', 'type': 'disk', 'size': 1, 'rm': False, 'tran': 'sata', 'ro': False},
    {'name': 'nvme0n1', 'type': 'disk', 'size': 1, 'rm': False, 'tran': 'nvme', 'ro': False},
    {'name': 'sdb', 'type': 'disk', 'size': 1, 'rm': True, 'tran': 'usb', 'ro': False}]}

SMART_ATA = {
    'smartctl': {'exit_status': 64}, 'model_name': 'SECRETMODEL', 'serial_number': 'SN12345678',
    'smart_status': {'passed': True},
    'ata_smart_attributes': {'table': [
        {'id': 5, 'raw': {'value': 24}}, {'id': 9, 'raw': {'value': 18234}},
        {'id': 197, 'raw': {'value': 8}}, {'id': 198, 'raw': {'value': 0}}]},
    'temperature': {'current': 41},
    'ata_smart_data': {'self_test_status': {'value': 249, 'remaining_percent': 90}},
}
SMART_NVME = {
    'smart_status': {'passed': True}, 'serial_number': 'SN12345678',
    'nvme_smart_health_information_log': {'critical_warning': 0, 'temperature': 38, 'available_spare': 100,
                                          'percentage_used': 3, 'media_errors': 0, 'power_on_hours': 912},
    'nvme_self_test_log': {'current_self_test_operation': {'value': 0},
                           'table': [{'self_test_code': {'value': 1}, 'self_test_result': {'value': 0}}]},
}


def journal_lines():
    rows = [
        {'_TRANSPORT': 'kernel', 'MESSAGE': 'ata1.00: failed command: READ LEAKMSG'},
        {'_TRANSPORT': 'kernel', 'MESSAGE': 'EXT4-fs error LEAKMSG'},
        {'_TRANSPORT': 'kernel', 'MESSAGE': 'something unrecognised LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'NetworkManager', 'MESSAGE': 'LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'sudo', 'MESSAGE': 'LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'systemd', '_SYSTEMD_UNIT': 'secretunit.service', 'MESSAGE': 'LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'systemd-networkd', 'MESSAGE': 'LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'firefox', 'MESSAGE': 'LEAKMSG'},
        {'SYSLOG_IDENTIFIER': 'firefox', 'MESSAGE': [76, 69, 65, 75]},
        {'MESSAGE': 'LEAKMSG'},
    ]
    return '\n'.join(json.dumps(r) for r in rows) + '\n'


def make_evidence(platform='linux-mint-xfce-live', checks=(), scope=None, run_id='rescue-20261001-093000'):
    doc = json.loads(EVIDENCE_FIXTURE.read_text(encoding='utf-8'))
    doc['run_id'] = run_id
    doc['source_platform'] = platform
    doc['checks'] = []
    for cid, status, ref in (checks or [('os-detection', 'pass', None)]):
        entry = {'check_id': cid, 'status': status, 'source': 'collector-allowlist',
                 'observed_at': '2026-10-01T09:30:00Z'}
        if ref:
            entry['target_ref'] = ref
        doc['checks'].append(entry)
    if scope:
        doc['scope'] = scope
    return doc


class FollowupCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='followup-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.reports = self.tmp / 'reports'
        self.reports.mkdir()
        self.proc = self.tmp / 'proc-root'

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def data(self, name, content):
        path = self.tmp / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding='utf-8')
        return path

    def fake_disks(self, ata=SMART_ATA, nvme=SMART_NVME, smart_exit=4):
        self.tool('lsblk', '/bin/cat %s\n' % self.data('lsblk.json', LSBLK))
        a, n = self.data('smart-sda.json', ata), self.data('smart-nvme.json', nvme)
        self.tool('smartctl', 'case "$*" in\n  *nvme0n1*) /bin/cat %s ;;\n  *sda*) /bin/cat %s ;;\nesac\nexit %d\n'
                  % (n, a, smart_exit))

    def fake_journal(self):
        self.tool('journalctl', '/bin/cat %s\n' % self.data('journal.ndjson', journal_lines()))

    def write_proc(self, mounts, cmdline='quiet splash'):
        (self.proc / 'proc').mkdir(parents=True, exist_ok=True)
        (self.proc / 'proc/mounts').write_text(mounts, encoding='utf-8')
        (self.proc / 'proc/cmdline').write_text(cmdline, encoding='utf-8')
        return str(self.proc)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith('RESCUE_')}
        env['RESCUE_REPAIR_TEST_PATH'] = str(self.bin)
        env['RESCUE_FOLLOWUP_PROC_ROOT'] = str(self.proc)
        env.update(extra)
        return env

    def cli(self, evidence, *args, **extra_env):
        path = self.data('evidence.json', evidence)
        return subprocess.run([sys.executable, str(SCRIPT), '--evidence', str(path), '--reports-dir',
                               str(self.reports), *args], capture_output=True, text=True,
                              env=self.env(**extra_env), timeout=60)

    def result(self, proc):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        files = sorted(self.reports.glob('followup-*.json'))
        self.assertEqual(len(files), 1)
        return json.loads(files[0].read_text(encoding='utf-8'))

    def find(self, doc, followup_id, ref=None, check_id=None):
        hits = [i for i in doc['items'] if i['followup_id'] == followup_id and i.get('target_ref') == ref
                and (check_id is None or i['check_id'] == check_id)]
        self.assertEqual(len(hits), 1, (followup_id, ref, [i['followup_id'] for i in doc['items']]))
        return hits[0]

    def assert_no_leaks(self, doc):
        text = json.dumps(doc)
        for token in LEAK_TOKENS:
            self.assertNotIn(token, text)
        self.assertEqual(rf.privacy_problems(doc), [])


class TestDiskRecipes(FollowupCase):
    def test_smart_and_nvme_attributes_and_selftest(self):
        self.fake_disks()
        ev = make_evidence(checks=[('smart-health', 'warn', None), ('nvme-health', 'unknown', None)])
        doc = self.result(self.cli(ev))
        attrs = self.find(doc, 'disk.attributes', 'disk-0', 'smart-health')
        self.assertEqual((attrs['status'], attrs['reason']), ('warn', 'attention'))
        self.assertEqual(attrs['values'], {'smart_passed': True, 'reallocated': 24, 'pending': 8,
                                           'offline_uncorrectable': 0, 'power_on_hours': 18234,
                                           'temperature_c': 41})
        test = self.find(doc, 'disk.selftest-result', 'disk-0')
        self.assertEqual((test['status'], test['reason']), ('unknown', 'in-progress'))
        self.assertEqual(test['values'], {'selftest': 'in-progress', 'selftest_percent_remaining': 90})
        nvme = self.find(doc, 'disk.attributes', 'disk-1', 'nvme-health')
        self.assertEqual(nvme['status'], 'pass')
        self.assertEqual(nvme['values']['nvme_percentage_used'], 3)
        self.assertEqual(self.find(doc, 'disk.selftest-result', 'disk-1')['values']['selftest'], 'completed-ok')
        self.assertTrue(all(i['target_ref'].startswith('disk-') for i in doc['items'] if i['check_id'] != 'persistence'))
        self.assert_no_leaks(doc)
        self.assertEqual(sorted(i['target_ref'] for i in doc['items'] if 'target_ref' in i),
                         ['disk-0', 'disk-0', 'disk-1', 'disk-1'])  # sdb is USB: never listed

    def test_only_flagged_checks_run(self):
        self.fake_disks()
        doc = self.result(self.cli(make_evidence(checks=[('smart-health', 'pass', None)])))
        self.assertEqual([i['check_id'] for i in doc['items']], ['persistence'])

    def test_scope_without_hardware_skips_disk_recipes(self):
        self.fake_disks()
        ev = make_evidence(checks=[('smart-health', 'warn', None)], scope=['malware'])
        self.assertEqual([i['check_id'] for i in self.result(self.cli(ev))['items']], ['persistence'])

    def test_missing_smartctl_is_unknown_never_pass(self):
        self.tool('lsblk', '/bin/cat %s\n' % self.data('lsblk.json', LSBLK))
        doc = self.result(self.cli(make_evidence(checks=[('smart-health', 'warn', None)])))
        for i in doc['items']:
            if i['check_id'] == 'smart-health':
                self.assertEqual((i['status'], i['reason']), ('unknown', 'tool-missing'))

    @unittest.skipIf(os.geteuid() == 0, 'needs a non-root user')
    def test_permission_denied_without_root_is_needs_root(self):
        self.fake_disks(ata={'smartctl': {'exit_status': 2}}, smart_exit=2)
        doc = self.result(self.cli(make_evidence(checks=[('smart-health', 'unknown', None)])))
        item = self.find(doc, 'disk.attributes', 'disk-0')
        self.assertEqual((item['status'], item['reason']), ('unknown', 'needs-root'))

    def test_failed_health_and_critical_warning_fail(self):
        ata = dict(SMART_ATA, smart_status={'passed': False})
        nvme = copy.deepcopy(SMART_NVME)
        nvme['nvme_smart_health_information_log']['critical_warning'] = 4
        self.assertEqual(rf.parse_smart(ata)[1], 'fail')
        self.assertEqual(rf.parse_smart(nvme)[1], 'fail')

    def test_selftest_parsing(self):
        ata_ok = {'ata_smart_self_test_log': {'standard': {'count': 1, 'table': [
            {'num': 2, 'status': {'value': 0, 'passed': True}}, {'num': 1, 'status': {'value': 112, 'passed': False}}]}}}
        self.assertEqual(rf.parse_selftest(ata_ok), ('failed', None))   # num 1 is the most recent
        ata_ok['ata_smart_self_test_log']['standard']['table'][1]['num'] = 3
        self.assertEqual(rf.parse_selftest(ata_ok), ('completed-ok', None))
        self.assertEqual(rf.parse_selftest({'ata_smart_self_test_log': {'standard': {'count': 0}}}), ('none', None))
        aborted = {'ata_smart_self_test_log': {'standard': {'table': [{'num': 1, 'status': {'value': 32}}]}}}
        self.assertEqual(rf.parse_selftest(aborted), ('aborted', None))
        running = {'nvme_self_test_log': {'current_self_test_operation': {'value': 1},
                                          'current_self_test_completion_percent': 30}}
        self.assertEqual(rf.parse_selftest(running), ('in-progress', 70))
        nvme_failed = {'nvme_self_test_log': {'current_self_test_operation': {'value': 0},
                                              'table': [{'self_test_result': {'value': 7}}]}}
        self.assertEqual(rf.parse_selftest(nvme_failed), ('failed', None))
        self.assertEqual(rf.parse_selftest({}), ('unknown', None))
        self.assertEqual(rf.parse_selftest(None), ('unknown', None))


class TestJournal(FollowupCase):
    def test_host_categories_are_counts_only(self):
        self.fake_journal()
        ev = make_evidence('linux-host', [('linux-journal-errors', 'fail', 'os-0')])
        doc = self.result(self.cli(ev))
        item = self.find(doc, 'journal.categories', 'os-0')
        v = item['values']
        self.assertEqual((item['status'], v['total']), ('fail' if v['total'] >= 50 else 'warn', 10))
        self.assertEqual((v['storage'], v['filesystem'], v['kernel'], v['network'], v['security_auth']),
                         (1, 1, 1, 2, 1))
        self.assertEqual((v['systemd'], v['application'], v['other']), (1, 2, 1))
        self.assertEqual(sum(v[rf._cat_name(c)] for c in rf.CATEGORIES), v['total'])
        self.assertNotIn('persistence.active', [i['followup_id'] for i in doc['items']])  # host mode
        self.assert_no_leaks(doc)

    def test_threshold_and_truncation(self):
        counts, read, truncated = rf.count_journal('{"SYSLOG_IDENTIFIER":"x"}\n' * 5, limit=3)
        self.assertEqual((sum(counts.values()), read, truncated), (3, 3, True))
        counts, read, truncated = rf.count_journal('not json\n[1]\n\n')
        self.assertEqual((read, truncated), (0, False))

    def test_live_target_journal_via_readonly_mount(self):
        root = self.tmp / 'target-root'
        (root / 'var/log/journal/abc').mkdir(parents=True)
        (root / 'var/log/journal/abc/system.journal').write_bytes(b'x')
        self.fake_journal()
        self.tool('journalctl', 'case "$1" in --directory=*) /bin/cat %s ;; *) exit 9 ;; esac\n'
                  % self.data('journal.ndjson', journal_lines()))

        @contextlib.contextmanager
        def fake_open(_path, _evidence, ref):
            self.assertEqual(ref, 'os-1')
            yield str(root)

        ev = make_evidence(checks=[('linux-journal-errors', 'unknown', 'os-1')])
        with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': str(self.bin)}), \
                mock.patch.object(rf, 'open_target', fake_open):
            doc = rf.build(ev, 'live-linux', 'ev.json', None, 60, str(self.tmp / 'none'))
        item = self.find(doc, 'journal.categories', 'os-1')
        self.assertEqual(item['values']['total'], 10)
        # Windows targets and symlinked journal directories are not read.
        ev2 = make_evidence(checks=[('linux-journal-errors', 'unknown', 'os-0')])
        with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': str(self.bin)}), \
                mock.patch.object(rf, 'open_target', fake_open):
            doc2 = rf.build(ev2, 'live-linux', 'ev.json', None, 60, str(self.tmp / 'none'))
        self.assertEqual([i for i in doc2['items'] if i['check_id'] == 'linux-journal-errors'], [])

    def test_journal_dir_with_symlink_or_outside_link_is_refused(self):
        root = self.tmp / 'target-root2'
        (root / 'var/log').mkdir(parents=True)
        outside = self.tmp / 'outside'
        outside.mkdir()
        (root / 'var/log/journal').symlink_to(outside)
        self.assertIsNone(rf.safe_journal_dir(str(root)))
        (root / 'var/log/journal').unlink()
        (root / 'var/log/journal/m').mkdir(parents=True)
        (root / 'var/log/journal/m/leak.journal').symlink_to('/etc/hostname')
        self.assertIsNone(rf.safe_journal_dir(str(root)))

    def test_unmountable_target_is_unknown(self):
        @contextlib.contextmanager
        def broken_open(_p, _e, _r):
            raise RuntimeError('cannot mount')
            yield  # pragma: no cover

        ev = make_evidence(checks=[('linux-journal-errors', 'unknown', 'os-1')])
        with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': str(self.bin)}), \
                mock.patch.object(rf, 'open_target', broken_open):
            doc = rf.build(ev, 'live-linux', 'ev.json', None, 60, str(self.tmp / 'none'))
        item = self.find(doc, 'journal.categories', 'os-1')
        self.assertEqual((item['status'], item['reason']), ('unknown', 'not-mounted'))


class TestMalware(FollowupCase):
    def state_with_db(self, age_days):
        state = self.tmp / 'state'
        (state / 'clamav').mkdir(parents=True, exist_ok=True)
        db = state / 'clamav' / 'daily.cvd'
        db.write_bytes(b'not a vdb header')
        stamp = time.time() - age_days * 86400
        os.utime(db, (stamp, stamp))
        return str(state)

    def test_coverage_facts(self):
        state = self.state_with_db(9)
        ev = make_evidence(checks=[('malware-scan', 'warn', 'os-0'), ('malware-scan', 'unknown', 'os-1'),
                                   ('malware-signatures', 'warn', None)])
        ev['checks'][0]['value'] = {'kind': 'count', 'number': 0}
        import rescue_modules.malware as mw
        with mock.patch.object(mw, 'SYSTEM_DB_DIRS', ()):
            doc = rf.build(ev, 'linux-host', 'ev.json', state, 60)
        first = self.find(doc, 'malware.coverage', 'os-0')
        self.assertEqual((first['status'], first['reason']), ('warn', 'db-stale'))
        self.assertEqual(first['values']['coverage'], 'stale-signatures')
        self.assertEqual((first['values']['signature_age_days'], first['values']['detections']), (9, 0))
        second = self.find(doc, 'malware.coverage', 'os-1')
        self.assertEqual((second['status'], second['reason'], second['values']['coverage']),
                         ('unknown', 'budget', 'budget-exhausted'))
        sig = self.find(doc, 'malware.signatures')
        self.assertEqual((sig['status'], sig['reason'], sig['values']['signature_stale']), ('warn', 'db-stale', True))
        self.assertEqual(rf.privacy_problems(doc), [])

    def test_fresh_db_incomplete_and_detections(self):
        state = self.state_with_db(1)
        ev = make_evidence(checks=[('malware-scan', 'warn', 'os-0'), ('malware-scan', 'fail', 'os-1')])
        ev['checks'][1]['value'] = {'kind': 'count', 'number': 3}
        import rescue_modules.malware as mw
        with mock.patch.object(mw, 'SYSTEM_DB_DIRS', ()):
            doc = rf.build(ev, 'linux-host', 'ev.json', state, 60)
        self.assertEqual(self.find(doc, 'malware.coverage', 'os-0')['values']['coverage'], 'incomplete')
        bad = self.find(doc, 'malware.coverage', 'os-1')
        self.assertEqual((bad['status'], bad['values']['coverage'], bad['values']['detections']),
                         ('fail', 'detections-found', 3))

    def test_no_database(self):
        import rescue_modules.malware as mw
        ev = make_evidence(checks=[('malware-signatures', 'unknown', None), ('malware-scan', 'unknown', None)])
        with mock.patch.object(mw, 'SYSTEM_DB_DIRS', ()):
            doc = rf.build(ev, 'linux-host', 'ev.json', str(self.tmp / 'empty'), 60)
        self.assertEqual(self.find(doc, 'malware.signatures')['reason'], 'db-missing')
        self.assertEqual(self.find(doc, 'malware.coverage')['values']['coverage'], 'not-scanned')


class TestPersistence(FollowupCase):
    LIVE = ('/dev/loop0 /rofs squashfs ro,noatime 0 0\n/dev/sdc1 /cdrom iso9660 ro 0 0\n')

    def detect(self, mounts, cmdline):
        return rf.detect_persistence(self.write_proc(mounts, cmdline))

    def test_overlay_on_persistence_image_is_active(self):
        mounts = self.LIVE + ('/dev/loop3 /cow ext4 rw,relatime 0 0\n'
                              'overlay / overlay rw,lowerdir=/rofs,upperdir=/cow/upper,workdir=/cow/work 0 0\n')
        self.assertEqual(self.detect(mounts, 'boot=casper persistent quiet'), (True, 'loop', True))

    def test_overlay_on_block_device_is_active(self):
        mounts = self.LIVE + ('/dev/sdc3 /cow ext4 rw 0 0\n'
                              'overlay / overlay rw,lowerdir=/rofs,upperdir=/cow/upper,workdir=/cow/work 0 0\n')
        self.assertEqual(self.detect(mounts, 'boot=casper'), (True, 'block', False))

    def test_tmpfs_overlay_is_not_persistent_even_with_cow(self):
        mounts = self.LIVE + ('tmpfs /cow tmpfs rw,size=4g 0 0\n'
                              'overlay / overlay rw,lowerdir=/rofs,upperdir=/cow/upper,workdir=/cow/work 0 0\n')
        self.assertEqual(self.detect(mounts, 'boot=casper quiet'), (False, 'tmpfs', False))

    def test_cow_fallback_without_upperdir_option(self):
        mounts = self.LIVE + 'tmpfs /cow tmpfs rw 0 0\naufs / aufs rw,br:/cow=rw 0 0\n'
        self.assertEqual(self.detect(mounts, ''), (False, 'tmpfs', False))

    def test_unknown_inputs_are_unknown(self):
        self.assertEqual(rf.detect_persistence(str(self.tmp / 'nothing')), (None, 'unknown', None))
        self.assertEqual(self.detect('/dev/sda2 / ext4 rw 0 0\n', 'quiet'), (None, 'unknown', False))

    def test_cli_item_and_mismatch_warning(self):
        self.write_proc(self.LIVE + 'tmpfs /cow tmpfs rw 0 0\n'
                        'overlay / overlay rw,lowerdir=/rofs,upperdir=/cow/upper,workdir=/cow/w 0 0\n',
                        'boot=casper persistent')
        doc = self.result(self.cli(make_evidence()))
        item = self.find(doc, 'persistence.active', None, 'persistence')
        self.assertEqual((item['status'], item['reason']), ('warn', 'attention'))  # requested, not in effect
        self.assertEqual(item['values'], {'persistence_active': False, 'upper_backing': 'tmpfs',
                                          'cmdline_persistent': True})

    def test_escaped_mount_fields(self):
        self.assertEqual(rf.parse_mounts('/dev/sdb1 /mnt/with\\040space ext4 rw 0 0\n')[0][1], '/mnt/with space')


class TestCliContract(FollowupCase):
    def test_exit_2_on_invalid_input(self):
        ev = make_evidence()
        self.assertEqual(self.cli(ev, '--timeout', '3').returncode, 2)
        self.assertEqual(self.cli(ev, '--timeout', '100000').returncode, 2)
        bad = self.data('bad.json', '{not json')
        proc = subprocess.run([sys.executable, str(SCRIPT), '--evidence', str(bad), '--reports-dir',
                               str(self.reports)], capture_output=True, text=True, env=self.env())
        self.assertEqual(proc.returncode, 2)
        proc = subprocess.run([sys.executable, str(SCRIPT), '--evidence', str(self.data('e.json', make_evidence())),
                               '--reports-dir', str(self.tmp / 'missing')], capture_output=True, text=True,
                              env=self.env())
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(self.cli({'checks': []}).returncode, 2)
        self.assertEqual(list(self.reports.glob('followup-*')), [])

    def test_windows_host_is_written_by_the_launcher(self):
        proc = self.cli(make_evidence('windows-host'))
        self.assertEqual(proc.returncode, 2)
        self.assertIn('Windows launcher', proc.stderr)
        self.assertEqual(self.cli(make_evidence(), '--mode', 'windows-host').returncode, 2)

    def test_mode_defaults_from_platform_and_can_be_overridden(self):
        self.assertEqual(rf.default_mode({'source_platform': 'linux-host'}), 'linux-host')
        self.assertEqual(rf.default_mode({'source_platform': 'systemrescue-live'}), 'live-linux')
        with self.assertRaises(rf.FollowupError):
            rf.default_mode({'source_platform': 'macos-host'})
        self.write_proc('tmpfs /cow tmpfs rw 0 0\noverlay / overlay rw,upperdir=/cow/u 0 0\n')
        doc = self.result(self.cli(make_evidence('linux-host'), '--mode', 'live-linux'))
        self.assertEqual(doc['mode'], 'live-linux')

    def test_output_file_atomic_private_and_summary_bilingual(self):
        self.fake_disks()
        proc = self.cli(make_evidence(checks=[('smart-health', 'warn', None)]))
        doc = self.result(proc)
        path = self.reports / 'followup-rescue-20261001-093000.json'
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(list(self.reports.glob('.followup-*')), [])
        self.assertEqual(doc['schema_version'], '1.0')
        self.assertIn('Tindak lanjut / Follow-ups', proc.stdout)
        self.assertIn('re-run rescue-followup', proc.stdout)
        self.assertNotIn('/dev/', proc.stdout)
        self.assertNotIn('SN12345678', proc.stdout + proc.stderr)
        # A second run replaces the file atomically.
        self.assertEqual(self.cli(make_evidence(checks=[('smart-health', 'warn', None)])).returncode, 0)
        self.assertEqual(len(list(self.reports.glob('followup-*.json'))), 1)

    def test_unknown_items_still_exit_0(self):
        proc = self.cli(make_evidence(checks=[('smart-health', 'unknown', None)]))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_runner_total_deadline(self):
        runner = rf.Runner(1)
        self.assertTrue(runner.expired())
        self.assertEqual(runner.run(['lsblk'], 5)[0], 'missing' if shutil.which('lsblk', path=runner.path) is None
                         else 'timeout')
        self.assertTrue(rf.Runner(1).json_command('x', ['lsblk']) is None)

    def test_command_timeout_is_reported(self):
        self.tool('slowtool', 'exec /bin/sleep 30\n')
        with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': str(self.bin)}):
            runner = rf.Runner(60)
        started = time.monotonic()
        self.assertEqual(runner.run(['slowtool'], 2)[0], 'timeout')
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(runner.timed_out)

    def test_runner_search_path_ignores_invalid_override(self):
        with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': 'relative:/nonexistent'}):
            self.assertEqual(rf.search_path(), rf.SAFE_PATH)


class TestPrivacyAndSchema(FollowupCase):
    def valid_doc(self):
        return json.loads((FIXTURES / 'followup-valid-live.json').read_text(encoding='utf-8'))

    def test_fixtures_pass_both_checks(self):
        for name in ('followup-valid-live.json', 'followup-valid-windows-host.json'):
            doc = json.loads((FIXTURES / name).read_text(encoding='utf-8'))
            self.assertEqual(rf.privacy_problems(doc), [], name)
            if jsonschema is not None:
                self.assertEqual(rf.schema_problems(doc), [], name)

    def test_self_check_refuses_leaks(self):
        cases = {
            'path in a run id-like string': lambda d: d['items'][0].update(target_ref='/dev/sda'),
            'path as value': lambda d: d['items'][0]['values'].update(selftest='/dev/sda'),
            'serial as enum': lambda d: d['items'][1]['values'].update(selftest='WDC-WD10EZEX-00BN5A0'),
            'unknown value name': lambda d: d['items'][0]['values'].update(model='Samsung'),
            'extra item key': lambda d: d['items'][0].update(message='kernel: oops'),
            'extra doc key': lambda d: d.update(hostname='mint'),
            'unknown check id': lambda d: d['items'][0].update(check_id='secret-check'),
            'free text reason': lambda d: d['items'][0].update(reason='disk /dev/sda failing'),
            'bool as number': lambda d: d['items'][0]['values'].update(pending=True),
            'string as number': lambda d: d['items'][0]['values'].update(pending='8'),
            'number as bool': lambda d: d['items'][0]['values'].update(smart_passed=1),
            'negative': lambda d: d['items'][0]['values'].update(pending=-1),
            'huge': lambda d: d['items'][0]['values'].update(pending=10 ** 20),
            'ip as ref': lambda d: d['items'][0].update(target_ref='192.168.1.5'),
            'bad mode': lambda d: d.update(mode='macos-host'),
            'bad run id': lambda d: d.update(run_id='../../etc/passwd'),
        }
        for name, mutate in cases.items():
            doc = self.valid_doc()
            mutate(doc)
            self.assertNotEqual(rf.privacy_problems(doc), [], name)

    def test_strings_that_look_like_leaks(self):
        for text in ('/home/mint/x', 'C:\\Users\\a', 'aa:bb:cc:dd:ee:ff', '10.0.0.1', 'a@b.c', 'SN12345678', 'two words'):
            self.assertTrue(any(p.search(text) for p in rf._LEAKS) or rf._looks_like_secret_token(text), text)
        for text in ('completed-ok', 'disk-0', 'budget-exhausted', 'display_gpu'):
            self.assertFalse(any(p.search(text) for p in rf._LEAKS) or rf._looks_like_secret_token(text), text)

    def test_refused_document_is_not_written(self):
        self.fake_disks()
        with mock.patch.object(rf, 'item', lambda *a, **k: {'check_id': 'persistence', 'followup_id': 'persistence.active',
                                                            'status': 'pass', 'reason': 'ok', 'values': {'x': 1}}):
            with mock.patch.dict(os.environ, {'RESCUE_REPAIR_TEST_PATH': str(self.bin),
                                              'RESCUE_FOLLOWUP_PROC_ROOT': str(self.proc)}):
                ev = self.data('ev.json', make_evidence())
                code = rf.main(['--evidence', str(ev), '--reports-dir', str(self.reports)])
        self.assertEqual(code, 2)
        self.assertEqual(list(self.reports.glob('followup-*')), [])

    @unittest.skipIf(jsonschema is None, 'python3-jsonschema is not installed (CI has it)')
    def test_schema_rejects_what_the_self_check_rejects(self):
        validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding='utf-8')))
        self.assertEqual(list(validator.iter_errors(self.valid_doc())), [])
        for mutate in (lambda d: d['items'][0]['values'].update(model='x'),
                       lambda d: d['items'][0].update(message='x'),
                       lambda d: d['items'][0].update(status='great'),
                       lambda d: d['items'][0]['values'].update(selftest='whatever'),
                       lambda d: d.update(schema_version='2.0'),
                       lambda d: d['items'][0].update(target_ref='disk-x')):
            doc = self.valid_doc()
            mutate(doc)
            self.assertNotEqual(list(validator.iter_errors(doc)), [])

    def test_schema_is_generated_from_the_script_tables(self):
        schema = json.loads(SCHEMA.read_text(encoding='utf-8'))
        props = schema['properties']['items']['items']['properties']
        self.assertEqual(props['check_id']['enum'], list(rf.CHECK_IDS))
        self.assertEqual(props['followup_id']['enum'], list(rf.FOLLOWUP_IDS))
        self.assertEqual(props['status']['enum'], list(rf.STATUSES))
        self.assertEqual(props['reason']['enum'], list(rf.REASONS))
        self.assertEqual(schema['properties']['mode']['enum'], list(rf.MODES))
        self.assertEqual(sorted(props['values']['properties']), sorted(rf.VALUE_SPECS))
        for name, spec in rf.VALUE_SPECS.items():
            got = props['values']['properties'][name]
            if spec == 'int':
                self.assertEqual(got['type'], 'number')
            elif spec == 'bool':
                self.assertEqual(got['type'], 'boolean')
            else:
                self.assertEqual(got['enum'], list(spec))
        self.assertFalse(props['values']['additionalProperties'])
        self.assertFalse(schema['additionalProperties'])

    @unittest.skipIf(jsonschema is None, 'python3-jsonschema is not installed (CI has it)')
    def test_generated_documents_validate(self):
        self.fake_disks()
        self.fake_journal()
        ev = make_evidence(checks=[('smart-health', 'warn', None), ('nvme-health', 'warn', None),
                                   ('malware-scan', 'unknown', 'os-1')])
        self.write_proc('tmpfs /cow tmpfs rw 0 0\noverlay / overlay rw,upperdir=/cow/u 0 0\n')
        doc = self.result(self.cli(ev))
        self.assertEqual(rf.schema_problems(doc), [])
        self.assert_no_leaks(doc)


class TestHermesProfile(unittest.TestCase):
    SKILLS = sorted((PROFILE / 'skills').glob('*/SKILL.md'))

    def test_every_skill_has_valid_front_matter(self):
        self.assertIn('rescue-autorun', [p.parent.name for p in self.SKILLS])
        for path in self.SKILLS:
            text = path.read_text(encoding='utf-8')
            m = re.match(r'^---\n(.*?)\n---\n', text, re.S)
            self.assertIsNotNone(m, path)
            fields = dict(line.split(': ', 1) for line in m.group(1).splitlines() if ': ' in line)
            self.assertEqual(set(fields), {'name', 'description'}, path)
            self.assertEqual(fields['name'], path.parent.name)
            self.assertTrue(re.match(r'^[a-z][a-z0-9-]{2,63}$', fields['name']))
            self.assertGreater(len(fields['description']), 20)

    def autorun(self):
        return (PROFILE / 'skills/rescue-autorun/SKILL.md').read_text(encoding='utf-8')

    def test_autorun_never_allows_approval_flags(self):
        text = self.autorun()
        allowed = text.split('## Allowed commands', 1)[1].split('## Never', 1)[0]
        for flag in ('--approve', '--param', '--backup-ref'):
            self.assertNotIn(flag, allowed)
            for line in text.splitlines():
                if flag in line:   # only ever mentioned as forbidden
                    self.assertTrue(line.lstrip().startswith('- Never') or 'Never' in line, line)
        # every command line in the skill is one of the two typed commands
        commands = re.findall(r'^- `(?:live-linux|linux-host)`: `([^`]+)`$|^- (?:`live-linux`|`linux-host`): `([^`]+)`',
                              text, re.M)
        commands = [c for pair in commands for c in pair if c]
        self.assertEqual(len(commands), 4)
        for cmd in commands:
            self.assertRegex(cmd, r'rescue-followup|rescue-repair\.py')
            if 'rescue-repair.py' in cmd:
                self.assertIn('--policy auto-safe --select ACTION_ID', cmd)
            self.assertNotRegex(cmd, r'--(approve|param|backup-ref)')
        self.assertEqual(len(re.findall(r'^\d\. `(?:rescue-followup|rescue-repair\.py)', allowed, re.M)), 2)

    def test_autorun_covers_the_plan(self):
        text = self.autorun()
        for needle in ('followup-*.json', 'persistence.active', 'selftest', '--policy auto-safe --select',
                       'windows-host', 'live-linux', 'linux-host', 'sudo -n rescue-followup',
                       '../scripts/rescue-followup.py', 'unknown'):
            self.assertIn(needle, text)

    def test_kickoff_uses_relative_paths_only(self):
        text = (PROFILE / 'kickoff.md').read_text(encoding='utf-8')
        for ref in ('index.md', 'run-*/report.md', 'followup-*.json', 'analysis-*.md', 'rescue-autorun'):
            self.assertIn(ref, text)
        self.assertIn('English:', text)
        for token in re.findall(r'`([^`]+)`', text):
            self.assertFalse(token.startswith(('/', '~', '\\')) or re.match(r'^[A-Za-z]:\\', token), token)
        self.assertNotRegex(text, r'(?<![\w.])/(?:home|usr|etc|var|tmp|media|run|mnt)\b')
        self.assertNotRegex(text, r'~|\\Users|[A-Za-z]:\\')
        self.assertLess(len(text), 1500)

    def test_agents_and_soul_name_the_two_commands(self):
        for name in ('AGENTS.md', 'SOUL.md'):
            text = (PROFILE / name).read_text(encoding='utf-8')
            self.assertIn('rescue-followup', text, name)
            self.assertIn('--policy auto-safe --select', text, name)
            self.assertIn('rescue-autorun', text, name)

    def test_target_os_skill_has_the_field_lessons(self):
        text = (PROFILE / 'skills/rescue-target-os/SKILL.md').read_text(encoding='utf-8')
        for needle in ('persistence.active', '/cow', 'exFAT', '--malware-target os-N', 'needs-root', 'power-acpi',
                       'selftest'):
            self.assertIn(needle, text)
        boot = (PROFILE / 'skills/rescue-boot-diagnosis/SKILL.md').read_text(encoding='utf-8')
        self.assertIn('rescue-autorun', boot)


class TestApprovalsConfig(unittest.TestCase):
    REQUIRED = ('*--approve*', '*--backup-ref*', '*--param*', 'dd *', '*mkfs*', '*wipefs*', '*parted*', '*fdisk*',
                '*sgdisk*', '*grub-install*', '*efibootmgr*', '*bcdedit*', '*diskpart*', '*format-volume*',
                '*cryptsetup*', '*dislocker*', '*ntfsfix*', '*chkdsk*', '*fsck*', '*rescue.env*', '*hermes/env*',
                '*rescue_github_issues_token*', '*malware-detections-*', '*/quarantine/*', 'rm -rf *',
                '*remove-item*-recurse*')
    DENIED = ('python3 rescue-repair.py --approve hw.smart-short-selftest',
              'python3 rescue-repair.py --policy auto-safe --select x --PARAM a.b=1',
              'python3 rescue-repair.py --backup-ref backup.tar', 'dd if=/dev/zero of=/dev/sda', 'sudo mkfs.ext4 /dev/sda1',
              'wipefs -a /dev/sda', 'sudo parted /dev/sda', 'sfdisk /dev/sda; fdisk -l', 'grub-install /dev/sda',
              'efibootmgr -B', 'cryptsetup open /dev/sda1 x', 'ntfsfix /dev/sda1', 'fsck -y /dev/sda1',
              'cat ../config/rescue.env', 'cat ~/.local/share/rescue-omes/hermes/env',
              'cat malware-detections-rescue-1.json', 'ls ../quarantine/blobs/x', 'rm -rf /home/mint',
              'Remove-Item C:\\x -Recurse -Force', 'diskpart', 'bcdedit /set x')
    HARMLESS = ('python3 ../scripts/rescue-followup.py --evidence x --reports-dir .',
                'sudo -n rescue-followup --evidence latest-evidence.json --reports-dir . --state-dir ..',
                'python3 /usr/local/lib/rescue-omes/scripts/rescue-repair.py --state-dir .. --evidence latest-evidence.json'
                ' --policy auto-safe --select hw.smart-short-selftest',
                'python3 ../scripts/rescue-repair.py --journal repairs/journal.jsonl --evidence latest-evidence.json'
                ' --policy auto-safe --select os-linux.update-grub', 'cat index.md', 'ls run-*/report.md')

    @staticmethod
    def deny_list():
        text = CONFIG.read_text(encoding='utf-8')
        block = text.split('\napprovals:\n', 1)[1]
        self_mode = re.search(r'^  mode: (\w+)$', block, re.M).group(1)
        return self_mode, re.findall(r'^    - "([^"]+)"$', block, re.M)

    def test_config_declares_manual_mode_and_deny_list(self):
        mode, deny = self.deny_list()
        self.assertEqual(mode, 'manual')
        for pattern in self.REQUIRED:
            self.assertIn(pattern, deny)
        self.assertIn('provider: custom', CONFIG.read_text(encoding='utf-8'))
        self.assertIn('default: mimo-v2.6-flash', CONFIG.read_text(encoding='utf-8'))

    def test_deny_list_matches_with_fnmatch(self):
        import fnmatch
        _mode, deny = self.deny_list()

        def hit(cmd):
            return any(fnmatch.fnmatchcase(cmd.lower().strip(), p.lower()) for p in deny)

        for cmd in self.DENIED:
            self.assertTrue(hit(cmd), cmd)
        for cmd in self.HARMLESS:
            self.assertFalse(hit(cmd), cmd)

    @unittest.skipUnless((HERMES_DIR / 'tools' / 'approval.py').is_file()
                         and (HERMES_DIR / 'venv' / 'bin' / 'python').is_file(),
                         'no local Hermes checkout (CI has none)')
    def test_installed_hermes_denies_and_allows(self):
        with tempfile.TemporaryDirectory(prefix='hermes-home-') as home:
            shutil.copy(CONFIG, Path(home) / 'config.yaml')
            code = ('import json,sys\nsys.path.insert(0, %r)\nfrom tools import approval\n'
                    'print(json.dumps({c: approval._match_user_deny_rule(c) for c in json.loads(sys.stdin.read())}))\n'
                    % str(HERMES_DIR))
            env = {'HERMES_HOME': home, 'PATH': os.environ.get('PATH', ''), 'OPENCODE_GO_API_KEY': 'dummy-test-key'}
            proc = subprocess.run([str(HERMES_DIR / 'venv' / 'bin' / 'python'), '-c', code], input=json.dumps(
                list(self.DENIED + self.HARMLESS)), capture_output=True, text=True, env=env, timeout=120)
            if proc.returncode != 0:
                self.skipTest('Hermes checkout cannot be imported here: ' + proc.stderr[-200:])
            matched = json.loads(proc.stdout.strip().splitlines()[-1])
            for cmd in self.DENIED:
                self.assertIsNotNone(matched[cmd], cmd)
            for cmd in self.HARMLESS:
                self.assertIsNone(matched[cmd], cmd)
            check = subprocess.run([str(HERMES_DIR / 'venv' / 'bin' / 'python'), '-m', 'hermes_cli.main', 'config',
                                    'check'], capture_output=True, text=True, env=dict(env), cwd=str(HERMES_DIR),
                                   timeout=120)
            self.assertEqual(check.returncode, 0, check.stderr[-300:])


class TestInstallerWiring(unittest.TestCase):
    def test_installer_and_container_build_link_the_helper_and_require_the_skill(self):
        installer = (REPO / 'scripts/install-hermes-rescue.sh').read_text(encoding='utf-8')
        self.assertIn('scripts/rescue-followup.py" "$bin_dir/rescue-followup"', installer)
        build = (REPO / 'scripts/lib/persistence-container-build.sh').read_text(encoding='utf-8')
        self.assertIn('rescue-printer rescue-autorun; do', build)
        self.assertIn('scripts/rescue-followup.py" "$bin_dir/rescue-followup"', build)


if __name__ == '__main__':
    unittest.main()
