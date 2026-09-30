"""Offline tests for OS detection and repair (ahliweb/linux-mint-xfce-rescue-ai#16).

Fixture trees stand in for installed Linux Mint / Windows / macOS systems. No root, no real
mounts, no block devices, no network: the target mount provider runs in its fixture mode (or
with a recording fake for privileged commands) and the engine runs fake programs through
RESCUE_REPAIR_TEST_PATH. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
SCAN = SCRIPTS / 'scan-target-os.py'
REPAIR = SCRIPTS / 'rescue-repair.py'
VALIDATE = SCRIPTS / 'validate-evidence.py'
CATALOG = ROOT / 'rescue-ai/v1/catalog'
DOC = ROOT / 'docs/os-repair.md'
PWSH = shutil.which('pwsh')
ZSH = shutil.which('zsh')
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
import rescue_modules  # noqa: E402
import target_mount as tm  # noqa: E402
from rescue_modules import operating_system as osm  # noqa: E402


def touch(path, data=b''):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def meta(fx, name, **kw):
    (fx / (name + '.meta.json')).write_text(json.dumps(kw))


def linux_tree(root, initrd=True, dpkg='ok', grub='ok', apt=True, updates=0, fstab_boot=None, kernels=('6.8.0-1-generic',)):
    touch(root / 'usr/lib/os-release', 'PRETTY_NAME="Linux Mint 22.3"\nID=linuxmint\n')
    (root / 'etc').mkdir(parents=True, exist_ok=True)
    if not (root / 'etc/os-release').exists():
        os.symlink('../usr/lib/os-release', root / 'etc/os-release')
    fstab = 'UUID=ABCD-1234 / ext4 defaults 0 1\n'
    if fstab_boot:
        fstab += 'UUID=%s /boot ext4 defaults 0 2\n' % fstab_boot
    touch(root / 'etc/fstab', fstab)
    for k in kernels:
        touch(root / ('boot/vmlinuz-' + k))
        if initrd:
            touch(root / ('boot/initrd.img-' + k))
    status = 'Package: good\nStatus: install ok installed\n\n'
    if dpkg == 'half':
        status += 'Package: bad\nStatus: install ok half-configured\n\n'
    touch(root / 'var/lib/dpkg/status', status)
    (root / 'var/lib/dpkg/updates').mkdir(parents=True, exist_ok=True)
    for i in range(updates):
        touch(root / ('var/lib/dpkg/updates/%04d' % i), 'x')
    touch(root / 'etc/default/grub', 'GRUB_TIMEOUT=5\n')
    if grub == 'ok':
        cfg = ''.join('menuentry "Mint %s" {\n  linux /boot/vmlinuz-%s root=/dev/sda1\n}\n' % (k, k) for k in kernels)
        touch(root / 'boot/grub/grub.cfg', cfg)
    elif grub == 'empty':
        touch(root / 'boot/grub/grub.cfg', '')
    elif grub == 'stale':
        touch(root / 'boot/grub/grub.cfg', 'menuentry "Old" {\n  linux /boot/vmlinuz-5.15.0-99-generic\n}\n')
    elif grub == 'nomenu':
        touch(root / 'boot/grub/grub.cfg', '# empty config\nset timeout=5\n')
    if apt:
        touch(root / 'etc/apt/sources.list', '# none\n')
        touch(root / 'etc/apt/sources.list.d/mint.sources',
              'Types: deb\nURIs: http://packages.linuxmint.com\nSuites: zara\nComponents: main\n\n'
              'Types: deb\nURIs: http://example.invalid\nEnabled: no\n')
    else:
        (root / 'etc/apt').mkdir(parents=True, exist_ok=True)
    for d in ('dev/pts', 'proc', 'sys'):
        (root / d).mkdir(parents=True, exist_ok=True)


def windows_tree(root, hiber=False, bcd=True, cbs=None, restore=0, pending=False):
    touch(root / 'Windows/System32/config/SYSTEM')
    if hiber:
        touch(root / 'hiberfil.sys', b'hibr-data')
    if bcd:
        touch(root / 'Boot/BCD', b'bcd')
    elif bcd is False:
        touch(root / 'Boot/bootstat.dat', b'x')  # a Boot directory without a BCD store
    if cbs is not None:
        touch(root / 'Windows/Logs/CBS/CBS.log', cbs)
    if restore is not None:
        (root / 'System Volume Information').mkdir(parents=True, exist_ok=True)
        for i in range(restore):
            touch(root / ('System Volume Information/{%08d-0000-0000-0000-000000000000}'
                          '{%08d-0000-0000-0000-000000000001}' % (i, i)), 'x')
    if pending:
        touch(root / 'Windows/WinSxS/pending.xml')


def scan(fx, out):
    result = subprocess.run([sys.executable, str(SCAN), '--output', str(out), '--fixture-root', str(fx)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(Path(out).read_text())


def checks_of(evidence, ref):
    return {c['check_id']: c for c in evidence['checks'] if c.get('target_ref') == ref}


def ref_of(evidence, family):
    return next(t['ref'] for t in evidence['target_systems'] if t['family'] == family)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='os-repair-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = self.tmp / 'fx'
        self.fx.mkdir()


# ------------------------------------------------------------ catalog + docs

class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = rc.load()
        self.emitted = self.scanner_ids() | {'linux-failed-units', 'linux-package-state', 'linux-kernel-initrd',
                                            'windows-system-files'}

    @staticmethod
    def scanner_ids():
        text = SCAN.read_text() + (SCRIPTS / 'rescue_modules/operating_system.py').read_text()
        return set(re.findall(r"'([a-z]+(?:-[a-z]+)+)'", text)) & rc.evidence_check_ids()

    def os_actions(self):
        return [a for a in self.catalog.actions.values() if a['_domain'].startswith('os-')]

    def test_catalog_is_valid_and_has_the_planned_actions(self):
        ids = {a['action_id'] for a in self.os_actions()}
        for wanted in ('os-linux.dpkg-configure-pending', 'os-linux.initramfs-create', 'os-linux.update-initramfs',
                       'os-linux.update-grub', 'os-linux.dpkg-configure-host', 'os-linux.apt-fix-broken',
                       'os-linux.restart-failed-units', 'os-windows.sfc-verify', 'os-windows.sfc-scannow',
                       'os-windows.dism-restorehealth', 'os-windows.chkdsk-scan'):
            self.assertIn(wanted, ids)

    def test_triggers_reference_checks_that_are_emitted(self):
        for action in self.os_actions():
            for trigger in action['triggers']:
                self.assertIn(trigger['check_id'], self.emitted, action['action_id'])

    def test_offline_actions_are_never_safe_and_always_need_approval_material(self):
        for action in self.os_actions():
            if action.get('requires_target_rw'):
                self.assertEqual(action['risk'], 'destructive', action['action_id'])
                self.assertTrue(action['backup']['required'])
                self.assertEqual(action['rollback']['kind'], 'restore-backup')
                self.assertEqual(action['platforms'], ['live-linux'])
                self.assertEqual(action['execute']['argv'][0], 'chroot')

    def test_no_windows_or_macos_offline_repair_and_no_bootloader_or_bitlocker_tools(self):
        for action in self.os_actions():
            if action['_domain'] in ('os-windows', 'os-macos'):
                self.assertNotIn('live-linux', action['platforms'])
            text = json.dumps(action['execute']) + json.dumps(action['verify'])
            for forbidden in ('ntfsfix', 'grub-install', 'efibootmgr', 'bcdedit', 'cryptsetup', 'dislocker', 'fsck',
                              'bootrec', 'powershell', 'cmd.exe'):
                self.assertNotIn(forbidden, text, action['action_id'])

    def test_doc_anchors_exist_in_the_operator_doc(self):
        text = DOC.read_text()
        slugs = set()
        for heading in re.findall(r'^#{1,6}\s+(.+?)\s*$', text, re.M):
            slugs.add(re.sub(r'[^a-z0-9 -]', '', heading.lower()).replace(' ', '-'))
        for action in self.os_actions():
            for ref in (action['doc'], action['rollback'].get('doc')):
                if ref:
                    self.assertTrue(ref.startswith('docs/os-repair.md#'), ref)
                    self.assertIn(ref.split('#', 1)[1], slugs, ref)

    def test_doc_mentions_every_action_and_check_and_has_attribution_and_diagram(self):
        text = DOC.read_text()
        self.assertIn('> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.', text)
        self.assertIn('```mermaid', text)
        for action in self.os_actions():
            self.assertIn(action['action_id'], text)
        for check in ('linux-boot-partition-space', 'linux-grub-config', 'linux-apt-sources', 'linux-dpkg-lock',
                      'windows-boot-config', 'windows-system-files', 'windows-restore-points', 'macos-disk-verify'):
            self.assertIn(check, text)


# ------------------------------------------------------------- detection modules

def Ctx(mode='live', fixture_root=None):
    return rescue_modules.Context(mode=mode, fixture_root=fixture_root)


class LinuxChecks(Base):
    def run_checks(self, **kw):
        root = self.fx / 'mint'
        linux_tree(root, **{k: v for k, v in kw.items() if k != 'pct'})
        if 'pct' in kw:
            fake = types.SimpleNamespace(f_blocks=1000, f_bavail=int(kw['pct'] * 10))
            self.addCleanup(setattr, osm, '_statvfs', osm._statvfs)
            osm._statvfs = lambda _p: fake
        return {c['check_id']: c for c in
                rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linuxmint', 'release': None})}

    def test_healthy_system(self):
        c = self.run_checks(pct=60)
        self.assertEqual(c['linux-boot-partition-space']['status'], 'pass')
        self.assertEqual(c['linux-grub-config'], {'check_id': 'linux-grub-config', 'status': 'pass', 'kind': 'count', 'number': 1})
        self.assertEqual((c['linux-apt-sources']['status'], c['linux-apt-sources']['number']), ('pass', 1))
        self.assertEqual((c['linux-dpkg-lock']['status'], c['linux-dpkg-lock']['number']), ('pass', 0))

    def test_full_boot_partition(self):
        self.assertEqual(self.run_checks(pct=12)['linux-boot-partition-space']['status'], 'warn')
        c = self.run_checks(pct=2)['linux-boot-partition-space']
        self.assertEqual((c['status'], c['number']), ('fail', 2.0))

    def test_separate_boot_that_was_not_examined_is_unknown(self):
        root = self.fx / 'mint'
        linux_tree(root, kernels=())
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linuxmint'})}
        self.assertEqual(c['linux-boot-partition-space']['status'], 'unknown')
        self.assertEqual(c['linux-grub-config']['status'], 'fail')  # boot/grub exists but has no grub.cfg

    def test_grub_config_variants(self):
        self.assertEqual(self.run_checks(grub='empty')['linux-grub-config']['status'], 'fail')
        self.assertEqual(self.run_checks(grub='nomenu')['linux-grub-config']['status'], 'fail')
        c = self.run_checks(grub='stale')['linux-grub-config']
        self.assertEqual((c['status'], c['number']), ('warn', 1))

    def test_missing_grub_config_with_grub_defaults_fails(self):
        c = self.run_checks(grub='missing')['linux-grub-config']
        self.assertEqual((c['status'], c['number']), ('fail', 0))

    def test_apt_sources_none_enabled_and_not_apt(self):
        c = self.run_checks(apt=False)['linux-apt-sources']
        self.assertEqual(c['status'], 'unknown')  # apt directory exists but nothing readable
        root = self.fx / 'mint'
        shutil.rmtree(root / 'etc/apt')
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linuxmint'})}
        self.assertEqual(c['linux-apt-sources']['status'], 'not_applicable')

    def test_apt_sources_disabled_only_is_warn(self):
        root = self.fx / 'mint'
        linux_tree(root)
        touch(root / 'etc/apt/sources.list.d/mint.sources', 'Types: deb\nURIs: http://x.invalid\nEnabled: no\n')
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linuxmint'})}
        self.assertEqual((c['linux-apt-sources']['status'], c['linux-apt-sources']['number']), ('warn', 0))

    def test_interrupted_dpkg_is_a_warning_with_a_count(self):
        c = self.run_checks(updates=2)['linux-dpkg-lock']
        self.assertEqual((c['status'], c['number']), ('warn', 2))

    def test_symlinks_in_the_target_never_reach_the_live_system(self):
        root = self.fx / 'mint'
        linux_tree(root, grub='missing')
        (root / 'boot/grub').mkdir(parents=True, exist_ok=True)
        os.symlink('/etc/hostname', root / 'boot/grub/grub.cfg')
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linuxmint'})}
        self.assertEqual(c['linux-grub-config']['status'], 'fail')

    def test_non_debian_linux_is_not_applicable(self):
        root = self.fx / 'other'
        touch(root / 'usr/lib/os-release', 'ID=fedora\n')
        (root / 'boot').mkdir()
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'linux-other'})}
        self.assertEqual(c['linux-apt-sources']['status'], 'not_applicable')
        self.assertEqual(c['linux-dpkg-lock']['status'], 'not_applicable')
        self.assertEqual(c['linux-grub-config']['status'], 'unknown')

    def test_live_mode_collect_system_is_empty_and_host_mode_reads_the_running_tree(self):
        root = self.fx / 'host'
        linux_tree(root, updates=1)
        self.assertEqual(rescue_modules.collect_system(Ctx('live', str(root))), [])
        self.addCleanup(setattr, osm, '_proc_locks_text', osm._proc_locks_text)
        ino = os.stat(root / 'var/lib/dpkg/updates').st_ino
        touch(root / 'var/lib/dpkg/lock-frontend', '')
        ino = os.stat(root / 'var/lib/dpkg/lock-frontend').st_ino
        osm._proc_locks_text = lambda: '1: FLOCK  ADVISORY  WRITE 4242 08:01:%d 0 EOF\n2: POSIX ADVISORY READ 1 08:01:99999 0 EOF\n' % ino
        ctx = Ctx('host', str(root))
        out = {c['check_id']: c for c in rescue_modules.collect_system(ctx)}
        self.assertEqual(ctx.warnings, [])
        self.assertEqual((out['linux-dpkg-lock']['status'], out['linux-dpkg-lock']['number']), ('warn', 2))
        for c in out.values():
            self.assertEqual(c['target_ref'], 'os-0')

    def test_unreadable_proc_locks_degrades(self):
        root = self.fx / 'host'
        linux_tree(root)
        self.addCleanup(setattr, osm, '_proc_locks_text', osm._proc_locks_text)
        osm._proc_locks_text = lambda: None
        out = {c['check_id']: c for c in rescue_modules.collect_system(Ctx('host', str(root)))}
        self.assertEqual(out['linux-dpkg-lock']['status'], 'unknown')


class WindowsMacChecks(Base):
    def checks(self, **kw):
        root = self.fx / 'win'
        windows_tree(root, **kw)
        return {c['check_id']: c for c in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'windows'})}

    def test_healthy_windows(self):
        c = self.checks(cbs='all fine\n', restore=2)
        self.assertEqual(c['windows-boot-config']['status'], 'pass')
        self.assertEqual((c['windows-system-files']['status'], c['windows-system-files']['number']), ('pass', 0))
        self.assertEqual((c['windows-restore-points']['status'], c['windows-restore-points']['number']), ('pass', 2))

    def test_bcd_missing(self):
        self.assertEqual(self.checks(bcd=False)['windows-boot-config']['status'], 'fail')  # Boot dir without BCD
        root = self.fx / 'win2'
        touch(root / 'Windows/System32/config/SYSTEM')
        c = {x['check_id']: x for x in rescue_modules.collect_offline_target(Ctx(), str(root), {'family': 'windows'})}
        self.assertEqual(c['windows-boot-config']['status'], 'unknown')  # UEFI store lives on the ESP
        self.assertEqual(c['windows-system-files']['status'], 'unknown')
        self.assertEqual(c['windows-restore-points']['status'], 'unknown')

    def test_component_store_corruption_markers(self):
        cbs = '2024 CSI Payload Corrupt (0x2)\nCannot repair member file [l:20]"x"\nnormal\n'
        c = self.checks(cbs=cbs, restore=0)
        self.assertEqual((c['windows-system-files']['status'], c['windows-system-files']['number']), ('warn', 2))
        self.assertEqual(c['windows-restore-points']['status'], 'warn')

    def test_pending_xml_is_reported_by_the_scanner_not_duplicated_here(self):
        c = self.checks(pending=True)
        self.assertNotIn('windows-pending-updates', c)

    def test_macos_offline_verify_is_unknown(self):
        out = rescue_modules.collect_offline_target(Ctx(), str(self.fx), {'family': 'macos'})
        self.assertEqual(out, [{'check_id': 'macos-disk-verify', 'status': 'unknown'}])


class ScannerIntegration(Base):
    def test_scanner_emits_new_checks_and_catalog_proposals(self):
        linux_tree(self.fx / 'mint', initrd=False, dpkg='half', grub='missing', updates=1)
        meta(self.fx, 'mint', fstype='ext4', uuid='ABCD-1234')
        windows_tree(self.fx / 'win', hiber=True, bcd=False, cbs='Cannot repair member file\n', restore=0)
        meta(self.fx, 'win', fstype='ntfs')
        out = self.tmp / 'ev.json'
        evidence = scan(self.fx, out)
        result = subprocess.run([sys.executable, str(VALIDATE), str(out)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        mint, win = ref_of(evidence, 'linuxmint'), ref_of(evidence, 'windows')
        lin = checks_of(evidence, mint)
        self.assertEqual(lin['linux-grub-config']['status'], 'fail')
        self.assertEqual(lin['linux-dpkg-lock']['status'], 'warn')
        self.assertEqual(lin['linux-kernel-initrd']['status'], 'fail')
        self.assertEqual(lin['linux-package-state']['status'], 'fail')
        self.assertEqual(checks_of(evidence, win)['windows-system-files']['status'], 'warn')
        proposed = {(p['action_id'], p.get('target_ref')) for p in evidence['repair_proposals']}
        for aid in ('os-linux.dpkg-configure-pending', 'os-linux.initramfs-create', 'os-linux.update-grub'):
            self.assertIn((aid, mint), proposed)
        self.assertFalse([p for p in proposed if p[0].startswith('os-windows.')])  # host-only actions
        text = json.dumps(evidence)
        for leak in ('grub.cfg', 'menuentry', 'Cannot repair'):
            self.assertNotIn(leak, text)


# ------------------------------------------------------------------ provider

class Provider(Base):
    def setUp(self):
        super().setUp()
        linux_tree(self.fx / 'mint', fstab_boot=None)
        meta(self.fx, 'mint', fstype='ext4', uuid='ABCD-1234')
        windows_tree(self.fx / 'win', hiber=False)
        meta(self.fx, 'win', fstype='ntfs', dirty=False)
        self.evidence = scan(self.fx, self.tmp / 'ev.json')
        self.mint, self.win = ref_of(self.evidence, 'linuxmint'), ref_of(self.evidence, 'windows')
        self.env(str(self.fx))

    def env(self, value):
        old = os.environ.get(tm.FIXTURE_ENV)
        self.addCleanup(lambda: os.environ.__setitem__(tm.FIXTURE_ENV, old) if old is not None
                        else os.environ.pop(tm.FIXTURE_ENV, None))
        os.environ[tm.FIXTURE_ENV] = value

    def open(self, ref, rw, evidence=None):
        return tm.open_target(str(self.tmp / 'ev.json'), evidence or self.evidence, ref, rw)

    def refuses(self, ref, rw, evidence=None, text=None):
        with self.assertRaises(tm.TargetMountError) as cm:
            with self.open(ref, rw, evidence):
                self.fail('must not be provided')
        if text:
            self.assertIn(text, str(cm.exception))

    def test_read_only_and_read_write_yield_the_target_directory(self):
        with self.open(self.mint, False) as root:
            self.assertTrue(os.path.isfile(os.path.join(root, 'etc/fstab')))
        with self.open(self.mint, True) as root:
            self.assertEqual(os.path.realpath(root), os.path.realpath(self.fx / 'mint'))
        with self.open(self.win, True) as root:
            self.assertTrue(os.path.isdir(os.path.join(root, 'Windows')))

    def test_unknown_or_malformed_ref(self):
        self.refuses('os-5', False, text='not in the evidence')
        for bad in (None, '../etc', 'os-9', 'os-0; rm'):
            self.refuses(bad, False, text='unknown target reference')

    def test_family_mismatch_is_refused(self):
        ev = json.loads(json.dumps(self.evidence))
        for t in ev['target_systems']:
            if t['ref'] == self.mint:
                t['family'] = 'linux-other'
        self.refuses(self.mint, True, ev, 'evidence says')
        ev = json.loads(json.dumps(self.evidence))
        for t in ev['target_systems']:
            if t['ref'] == self.mint:
                t['family'] = 'windows'
        self.refuses(self.mint, False, ev, 'evidence says')

    def test_encrypted_and_uninspected_targets_are_refused(self):
        ev = json.loads(json.dumps(self.evidence))
        for t in ev['target_systems']:
            if t['ref'] == self.mint:
                t['encryption'], t['access'] = 'luks', 'not-mounted-encrypted'
        self.refuses(self.mint, False, ev, 'never unlocked')
        ev = json.loads(json.dumps(self.evidence))
        ev['target_systems'][0]['access'] = 'not-mounted-unsupported'
        self.refuses(ev['target_systems'][0]['ref'], False, ev, 'never unlocked')

    def test_encrypted_partition_found_on_disk_is_refused(self):
        meta(self.fx, 'aaa-locked', fstype='BitLocker')
        ev = scan(self.fx, self.tmp / 'ev2.json')
        locked = next(t for t in ev['target_systems'] if t['encryption'] == 'bitlocker')
        self.assertEqual(locked['access'], 'not-mounted-encrypted')
        self.refuses(locked['ref'], False, ev, 'never unlocked')
        # a target that turned encrypted after the scan: evidence says none, disk says LUKS
        stale = json.loads(json.dumps(ev))
        for t in stale['target_systems']:
            if t['ref'] == locked['ref']:
                t['encryption'], t['access'] = 'none', 'read-only-mounted'
        self.refuses(locked['ref'], False, stale, 'no longer readable')

    def test_host_native_target_is_refused(self):
        ev = json.loads(json.dumps(self.evidence))
        ev['target_systems'][0]['detection'] = 'host-native'
        self.refuses(ev['target_systems'][0]['ref'], False, ev, 'offline')

    def test_hibernated_windows_is_refused_read_write_but_readable(self):
        touch(self.fx / 'win/hiberfil.sys', b'hibr')
        self.refuses(self.win, True, text='hibernated')
        with self.open(self.win, False) as root:
            self.assertTrue(os.path.isdir(root))

    def test_dirty_ntfs_and_failing_rw_mount_are_refused(self):
        meta(self.fx, 'win', fstype='ntfs', dirty=True)
        self.refuses(self.win, True, text='dirty')
        meta(self.fx, 'win', fstype='ntfs', dirty=False, mount_rw='fail')
        self.refuses(self.win, True, text='failed')

    def test_macos_is_never_mounted_read_write(self):
        (self.fx / 'zmac/System/Library/CoreServices').mkdir(parents=True)
        touch(self.fx / 'zmac/System/Library/CoreServices/SystemVersion.plist',
              b'<?xml version="1.0"?><plist version="1.0"><dict><key>ProductName</key><string>macOS</string>'
              b'<key>ProductVersion</key><string>12.7</string></dict></plist>')
        meta(self.fx, 'zmac', fstype='apfs')
        ev = scan(self.fx, self.tmp / 'ev3.json')
        mac = ref_of(ev, 'macos')
        with self.open(mac, False, ev) as root:
            self.assertTrue(os.path.isdir(root))
        self.refuses(mac, True, ev, 'APFS')

    def test_unresolved_separate_boot_is_refused_and_resolved_one_is_accepted(self):
        linux_tree(self.fx / 'mint', fstab_boot='BOOT-1111')
        ev = scan(self.fx, self.tmp / 'ev4.json')
        mint = ref_of(ev, 'linuxmint')
        # the fstab names a /boot whose partition is not on this machine: the mount would write to the wrong place
        touch(self.fx / 'mint/etc/fstab', 'UUID=BOOT-9999 /boot ext4 defaults 0 2\n')
        self.refuses(mint, True, ev, '/boot')
        (self.fx / 'bootp').mkdir()
        meta(self.fx, 'bootp', fstype='ext4', uuid='BOOT-9999')
        ev2 = scan(self.fx, self.tmp / 'ev5.json')
        with self.open(ref_of(ev2, 'linuxmint'), True) as root:
            self.assertTrue(os.path.isdir(root))

    def test_target_that_disappeared_is_refused(self):
        shutil.rmtree(self.fx / 'win')
        (self.fx / 'win.meta.json').unlink()
        self.refuses(self.win, False)

    def test_fixture_run_never_calls_privileged_commands(self):
        calls = []
        self.addCleanup(setattr, tm, 'PRIV_RUN', tm.PRIV_RUN)
        tm.PRIV_RUN = lambda cmd, timeout=60: calls.append(cmd) or (0, '')
        with self.open(self.mint, True):
            pass
        self.assertEqual(calls, [])


class RecordingTarget(tm.TargetMount):
    """Real (non-fixture) read-write path with every privileged command recorded instead of run."""

    def __init__(self, parts, *args):
        super().__init__(*args)
        self.parts = parts

    def _enumerate(self, scanner):
        return self.parts, self.parts

    def _make_mounter(self, scanner):
        return scanner.FixtureMounter()


class RealPathWithFakeMount(Base):
    def setUp(self):
        super().setUp()
        linux_tree(self.fx / 'mint', fstab_boot='BOOT-1')
        meta(self.fx, 'mint', fstype='ext4', uuid='ABCD-1234')
        (self.fx / 'bootp').mkdir()
        meta(self.fx, 'bootp', fstype='ext4', uuid='BOOT-1')
        windows_tree(self.fx / 'win')
        meta(self.fx, 'win', fstype='ntfs', dirty=False)
        self.evidence = scan(self.fx, self.tmp / 'ev.json')
        self.scanner = tm.load_scanner()
        self.parts = self.scanner.load_fixtures(str(self.fx))
        self.calls = []
        self.fail_on = None
        self.addCleanup(setattr, tm, 'PRIV_RUN', tm.PRIV_RUN)
        tm.PRIV_RUN = self.fake
        self.addCleanup(setattr, tempfile, 'tempdir', tempfile.tempdir)
        tempfile.tempdir = str(self.tmp)
        os.environ.pop(tm.FIXTURE_ENV, None)

    def fake(self, cmd, timeout=60):
        self.calls.append(list(cmd))
        if self.fail_on and self.fail_on in cmd:
            return 32, 'mount: wrong fs type'
        if cmd[0] == 'umount':
            for entry in os.listdir(cmd[-1]) if os.path.isdir(cmd[-1]) else []:
                shutil.rmtree(os.path.join(cmd[-1], entry), True)
        if cmd[:2] == ['mount', '-t']:
            for d in ('dev/pts', 'proc', 'sys', 'boot'):
                os.makedirs(os.path.join(cmd[-1], d), exist_ok=True)
        return 0, ''

    def target(self, family, rw=True, parts=None):
        return RecordingTarget(parts or self.parts, str(self.tmp / 'ev.json'), self.evidence,
                               ref_of(self.evidence, family), rw)

    def test_linux_rw_mounts_boot_and_binds_and_unmounts_in_reverse(self):
        with self.target('linuxmint') as root:
            self.assertTrue(os.path.isdir(root))
            base = os.path.dirname(root)
            self.assertEqual(oct(os.stat(base).st_mode & 0o777), '0o700')
            mounts = [c for c in self.calls if c[0] == 'mount' and c[1] in ('-t', '--bind')]
            self.assertEqual(mounts[0][:6], ['mount', '-t', 'ext4', '-o', 'rw,nosuid,nodev', '--'])
            self.assertEqual(mounts[0][6], '/dev/fixture-mint')
            self.assertEqual(mounts[1][6], '/dev/fixture-bootp')
            self.assertTrue(mounts[1][-1].endswith('/root/boot'))
            self.assertEqual([m[3] for m in mounts[2:]], ['/dev', '/dev/pts', '/proc', '/sys'])
            self.assertNotIn('noexec', ','.join(c[4] for c in mounts[:2]))
            self.calls.clear()
        umounts = [c[-1] for c in self.calls if c[0] == 'umount']
        self.assertEqual([os.path.basename(u) for u in umounts], ['sys', 'proc', 'pts', 'dev', 'boot', 'root'])
        self.assertFalse(os.path.exists(base))

    def test_windows_rw_uses_noexec_and_no_binds(self):
        with self.target('windows'):
            mounts = [c for c in self.calls if c[0] == 'mount']
            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0][2:5], ['ntfs3', '-o', 'rw,noexec,nosuid,nodev'])

    def test_exception_in_the_body_still_unmounts(self):
        with self.assertRaises(RuntimeError):
            with self.target('linuxmint'):
                self.calls.clear()
                raise RuntimeError('action failed')
        self.assertEqual(len([c for c in self.calls if c[0] == 'umount']), 6)

    def test_failed_bind_unmounts_what_was_mounted(self):
        self.fail_on = '--bind'
        with self.assertRaises(tm.TargetMountError):
            with self.target('linuxmint'):
                self.fail('unreachable')
        self.assertEqual(len([c for c in self.calls if c[0] == 'umount']), 2)  # root + boot

    def test_failed_root_mount_is_reported_without_unmount(self):
        self.fail_on = 'ext4'
        with self.assertRaises(tm.TargetMountError) as cm:
            with self.target('linuxmint'):
                self.fail('unreachable')
        self.assertIn('read-write mount failed', str(cm.exception))
        self.assertEqual([c for c in self.calls if c[0] == 'umount'], [])

    def test_sigterm_cleans_up_then_redelivers_the_signal(self):
        seen = []
        old = signal.signal(signal.SIGTERM, lambda s, f: seen.append(s))
        self.addCleanup(signal.signal, signal.SIGTERM, old)
        with self.assertRaises(tm.Terminated):
            with self.target('linuxmint'):
                self.calls.clear()
                os.kill(os.getpid(), signal.SIGTERM)
                for _ in range(1000):
                    pass
        self.assertEqual(len([c for c in self.calls if c[0] == 'umount']), 6)
        self.assertEqual(seen, [signal.SIGTERM])

    def test_already_mounted_target_is_refused_read_write_only(self):
        parts = self.scanner.load_fixtures(str(self.fx))
        for p in parts:
            if p['path'].endswith('mint'):
                p['mountpoints'] = ['/media/mint/disk']
        with self.assertRaises(tm.TargetMountError) as cm:
            with self.target('linuxmint', True, parts):
                self.fail('unreachable')
        self.assertIn('already mounted', str(cm.exception))

    def test_read_only_never_binds_or_mounts_read_write(self):
        with self.target('linuxmint', rw=False) as root:
            self.assertTrue(os.path.isdir(root))
        self.assertEqual([c for c in self.calls if c[0] == 'mount'], [])

    def test_btrfs_subvolume_and_xfs_options(self):
        parts = self.scanner.load_fixtures(str(self.fx))
        for p in parts:
            if p['path'].endswith('mint'):
                p['fstype'] = 'xfs'
        with self.target('linuxmint', True, parts):
            self.assertIn('rw,nosuid,nodev,nouuid', [c[4] for c in self.calls if c[:2] == ['mount', '-t']])


# ------------------------------------------------------------- engine end to end

class EngineWithProvider(Base):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.log = self.tmp / 'calls.log'
        for name in ('chroot', 'rescue-test-fix'):
            (self.bin / name).write_text('#!/bin/sh\necho "%s $*" >> "%s"\n[ -e "%s/fail-${2:-$1}" ] && exit 3\nexit 0\n'
                                         % (name, self.log, self.tmp))
            (self.bin / name).chmod(0o755)
        (self.bin / 'sudo').write_text('#!/bin/sh\nshift 2\nexec "$@"\n')
        (self.bin / 'sudo').chmod(0o755)
        self.backup = self.tmp / 'backup.tar'
        self.backup.write_bytes(b'x' * 2048)
        linux_tree(self.fx / 'mint', initrd=False, dpkg='half', grub='missing')
        meta(self.fx, 'mint', fstype='ext4', uuid='ABCD-1234')
        windows_tree(self.fx / 'win', hiber=True)
        meta(self.fx, 'win', fstype='ntfs', dirty=False)
        self.evidence_path = self.tmp / 'ev.json'
        self.evidence = scan(self.fx, self.evidence_path)
        self.journal = self.tmp / 'state/repairs/journal.jsonl'
        self.env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(self.bin), **{tm.FIXTURE_ENV: str(self.fx)})

    def engine(self, *args, catalog=None):
        cmd = [sys.executable, str(REPAIR), '--evidence', str(self.evidence_path), '--state-dir',
               str(self.tmp / 'state'), '--catalog-dir', str(catalog or CATALOG), *args]
        return subprocess.run(cmd, capture_output=True, text=True, env=self.env, stdin=subprocess.DEVNULL, timeout=120)

    def stages(self, aid):
        recs = [json.loads(x) for x in self.journal.read_text().splitlines() if x.strip()]
        return [(r['stage'], r['outcome']) for r in recs if r['action_id'] == aid]

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_list_plans_the_offline_linux_repairs(self):
        r = self.engine('--list')
        self.assertEqual(r.returncode, 0, r.stderr)
        for aid in ('os-linux.dpkg-configure-pending', 'os-linux.initramfs-create', 'os-linux.update-grub'):
            self.assertIn(aid, r.stdout)
        self.assertNotIn('os-linux.dpkg-configure-host', r.stdout)
        self.assertNotIn('os-windows', r.stdout)

    def test_approved_update_grub_runs_in_the_chroot_with_backup_and_verify(self):
        r = self.engine('--approve', 'os-linux.update-grub', '--backup-ref', str(self.backup))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.stages('os-linux.update-grub'), [
            ('proposed', 'ok'), ('backup', 'ok'), ('approval', 'ok'), ('target-rw', 'ok'),
            ('precondition', 'ok'), ('execute', 'ok'), ('verify', 'ok')])
        calls = self.calls()
        self.assertEqual(len(calls), 3)  # precondition, execute, verify
        self.assertTrue(calls[1].startswith('chroot %s update-grub' % (self.fx / 'mint')), calls[1])
        self.assertEqual(calls[2].split()[-2:], ['grub-script-check', '/boot/grub/grub.cfg'][-2:])
        self.assertNotIn(str(self.fx), self.journal.read_text())  # paths never reach the journal

    def test_without_backup_or_approval_nothing_is_mounted_or_run(self):
        r = self.engine('--approve', 'os-linux.update-grub')
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stages('os-linux.update-grub'), [('proposed', 'ok'), ('backup', 'unavailable')])
        r = self.engine('--backup-ref', str(self.backup))
        self.assertEqual(self.calls(), [])
        self.assertIn(('approval', 'declined'), self.stages('os-linux.update-grub'))

    def test_failed_verify_of_a_destructive_action_requires_manual_rollback(self):
        (self.tmp / 'fail-grub-script-check').write_text('')
        r = self.engine('--approve', 'os-linux.update-grub', '--backup-ref', str(self.backup))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.stages('os-linux.update-grub')[-2:], [('verify', 'fail'), ('rollback', 'skipped')])
        self.assertIn('docs/os-repair.md#rollback-linux', r.stderr)

    def test_detect_only_never_touches_the_target(self):
        r = self.engine('--policy', 'detect-only', '--approve', 'os-linux.update-grub')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])

    def test_auto_safe_never_runs_offline_target_actions(self):
        r = self.engine('--policy', 'auto-safe', '--backup-ref', str(self.backup))
        self.assertEqual(self.calls(), [])

    def custom_catalog(self):
        catalog = self.tmp / 'catalog'
        catalog.mkdir(exist_ok=True)
        (catalog / 'os-windows.json').write_text(json.dumps({'catalog_version': '1', 'domain': 'os-windows', 'actions': [{
            'action_id': 'os-windows.test-rw', 'title': 'Test rw', 'title_id': 'Uji rw', 'scope': 'os',
            'platforms': ['live-linux'], 'target_families': ['windows'], 'risk': 'reversible',
            'requires_root': True, 'requires_target_rw': True, 'triggers': [],
            'params': [{'name': 'target_root', 'type': 'target_root'}],
            'execute': {'argv': ['rescue-test-fix', '{target_root}']}, 'verify': {'argv': ['rescue-test-fix', 'v']},
            'rollback': {'kind': 'step', 'step': {'argv': ['rescue-test-fix', 'undo']}}, 'backup': {'required': False},
            'doc': 'docs/os-repair.md#rollback-windows'}]}))
        return catalog

    def test_hibernated_windows_read_write_is_refused_by_the_provider(self):
        win = ref_of(self.evidence, 'windows')
        r = self.engine('--select', 'os-windows.test-rw:' + win, '--approve', 'os-windows.test-rw',
                        catalog=self.custom_catalog())
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.calls(), [])
        self.assertIn(('target-rw', 'fail'), self.stages('os-windows.test-rw'))
        self.assertIn('hibernated', r.stderr)
        os.unlink(self.fx / 'win/hiberfil.sys')
        r = self.engine('--select', 'os-windows.test-rw:' + win, '--approve', 'os-windows.test-rw',
                        catalog=self.custom_catalog())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.calls()[0].startswith('rescue-test-fix %s' % (self.fx / 'win')))


# ------------------------------------------------------------- host modules

@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellOsModule(Base):
    MODULE = ROOT / 'host/modules/windows/os.ps1'

    def run_module(self, bcd='pass', restore='2', cbs=None):
        sysroot = self.tmp / 'SystemRoot'
        sysroot.mkdir(exist_ok=True)
        if cbs is not None:
            touch(sysroot / 'Logs/CBS/CBS.log', cbs)
        driver = self.tmp / 'driver.ps1'
        driver.write_text(r'''
param([string]$Module)
$env:SystemRoot = $env:T_SYSROOT
if ($env:T_BCD -ne 'none') {
  function bcdedit {
    if ($env:T_BCD -eq 'pass') { $global:LASTEXITCODE = 0; 'Windows Boot Loader'; 'identifier {current}'; 'path                    \Windows\system32\winload.efi' }
    elseif ($env:T_BCD -eq 'empty') { $global:LASTEXITCODE = 0; 'Windows Boot Manager' }
    else { $global:LASTEXITCODE = 1; 'Access is denied.' }
  }
}
if ($env:T_RP -ne 'none') {
  function Get-ComputerRestorePoint {
    [CmdletBinding()] param()
    if ($env:T_RP -eq 'deny') { throw 'Access denied' }
    for ($i = 0; $i -lt [int]$env:T_RP; $i++) { [pscustomobject]@{ n = $i } }
  }
}
$r = @(& $Module -Scope 'all' -Packages @())
ConvertTo-Json -Compress -InputObject $r
''')
        env = dict(os.environ, T_SYSROOT=str(sysroot), T_BCD=bcd, T_RP=restore)
        proc = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(driver), '-Module', str(self.MODULE)],
                              capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return {c['check_id']: c for c in json.loads(proc.stdout)}

    def test_all_three_checks_with_shims(self):
        out = self.run_module(cbs='ok\nCannot repair member file\nCSI Payload Corrupt\n')
        self.assertEqual(out['windows-boot-config']['status'], 'pass')
        self.assertEqual(out['windows-system-files']['status'], 'warn')
        self.assertEqual(out['windows-system-files']['number'], 2)
        self.assertEqual((out['windows-restore-points']['status'], out['windows-restore-points']['number']), ('pass', 2))

    def test_clean_log_and_no_restore_points(self):
        out = self.run_module(bcd='empty', restore='0', cbs='all good\n')
        self.assertEqual(out['windows-boot-config']['status'], 'fail')
        self.assertEqual((out['windows-system-files']['status'], out['windows-system-files']['number']), ('pass', 0))
        self.assertEqual(out['windows-restore-points']['status'], 'warn')

    def test_everything_degrades_to_unknown_without_elevation_or_tools(self):
        out = self.run_module(bcd='deny', restore='deny')
        for cid in ('windows-boot-config', 'windows-system-files', 'windows-restore-points'):
            self.assertEqual(out[cid], {'check_id': cid, 'status': 'unknown'})
        out = self.run_module(bcd='none', restore='none')
        self.assertEqual(out['windows-boot-config']['status'], 'unknown')
        self.assertEqual(out['windows-restore-points']['status'], 'unknown')

    def test_output_only_holds_contract_fields(self):
        out = self.run_module(cbs='x\n')
        allowed = rc.evidence_check_ids()
        for cid, c in out.items():
            self.assertIn(cid, allowed)
            self.assertLessEqual(set(c), {'check_id', 'status', 'kind', 'number'})


@unittest.skipUnless(ZSH, 'zsh not installed')
class ZshOsModule(Base):
    MODULE = ROOT / 'host/modules/macos/os.zsh'

    def run_module(self, info, apfs='container', with_tool=True):
        shim = self.tmp / 'shim'
        shim.mkdir(exist_ok=True)
        if with_tool:
            (self.tmp / 'info.txt').write_text(info)
            (self.tmp / 'apfs.txt').write_text(apfs)
            (shim / 'diskutil').write_text('#!/bin/sh\nif [ "$1" = info ]; then cat "%s"; [ -s "%s" ]; else cat "%s"; fi\n'
                                           % (self.tmp / 'info.txt', self.tmp / 'info.txt', self.tmp / 'apfs.txt'))
            (shim / 'diskutil').chmod(0o755)
        env = {'PATH': '%s:/usr/bin:/bin' % shim, 'RESCUE_SCOPE': 'os', 'RESCUE_PACKAGES': ''}
        proc = subprocess.run([ZSH, '-f', '--', str(self.MODULE)], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()

    def test_pass_warn_fail_unknown(self):
        self.assertEqual(self.run_module('   Mounted:  Yes\n   SMART Status:  Verified\n'), 'macos-disk-verify pass')
        self.assertEqual(self.run_module('   Mounted:  Yes\n', apfs=''), 'macos-disk-verify warn')
        self.assertEqual(self.run_module('   Mounted:  Yes\n   SMART Status:  Failing\n'), 'macos-disk-verify fail')
        self.assertEqual(self.run_module('   Mounted:  No\n'), 'macos-disk-verify unknown')
        self.assertEqual(self.run_module('', with_tool=False), 'macos-disk-verify unknown')

    def test_never_runs_a_verify_or_repair_verb(self):
        text = self.MODULE.read_text()
        code = '\n'.join(ln for ln in text.splitlines() if not ln.lstrip().startswith('#'))
        for verb in ('verifyVolume', 'repairVolume', 'verifyDisk', 'repairDisk', 'sudo'):
            self.assertNotIn(verb, code)



class RealDiskNtfsProbeTests(unittest.TestCase):
    """Without fixture metadata the provider must read the raw NTFS dirty flag, and refuse when it cannot."""

    def probe(self, raw_dirty):
        root = tempfile.mkdtemp(prefix='ntfs-probe-')
        self.addCleanup(shutil.rmtree, root, True)
        scanner = tm.load_scanner()

        class FakeMounter:
            def mount(self, part, kind):
                return types.SimpleNamespace(status='ok', root=root)

            def release(self, res):
                pass

        mount = tm.TargetMount(None, {}, 'os-0', True)
        mount._mounter = FakeMounter()
        part = scanner.make_part(path='/dev/sdz9', fstype='ntfs', meta=None)
        original = scanner.raw_ntfs_dirty
        scanner.raw_ntfs_dirty = lambda dev: raw_dirty
        try:
            return mount._probe(scanner, part, 'ntfs', 'windows', [])
        finally:
            scanner.raw_ntfs_dirty = original

    def test_unreadable_or_dirty_flag_refuses_and_clean_passes(self):
        for value, needle in ((None, 'cannot confirm'), (True, 'dirty')):
            with self.subTest(raw=value):
                with self.assertRaises(tm.TargetMountError) as ctx:
                    self.probe(value)
                self.assertIn(needle, str(ctx.exception))
        self.assertEqual(self.probe(False), {'subvol': None, 'boot': None})


if __name__ == '__main__':
    unittest.main()
