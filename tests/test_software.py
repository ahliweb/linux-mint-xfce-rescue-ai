"""Offline tests for the installed-software module (ahliweb/linux-mint-xfce-rescue-ai#17).

Fixture dpkg status files and fixture macOS/Windows trees; no root, no real package changes,
no network. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Covered: healthy / half-configured / broken-dependency / held / reinstreq / missing-list databases,
selected-package filtering (including not-installed), evidence that never carries a package name,
symlink safety, scanner and Linux launcher evidence validating against the schema, the typed
catalog (validation, parameter rules), the policy engine end to end with fake programs, and the
pwsh and zsh host modules through shims (skipped when pwsh/zsh are absent).
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS / 'lib'))
sys.path.insert(0, str(SCRIPTS))
import repair_catalog as rc  # noqa: E402
import rescue_modules  # noqa: E402
from rescue_modules import software  # noqa: E402

PWSH = shutil.which('pwsh')
ZSH = shutil.which('zsh')

try:
    import jsonschema  # noqa: F401
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load('rescue_validate_evidence_sw', SCRIPTS / 'validate-evidence.py')
analyzer = load('rescue_analyzer_sw', SCRIPTS / 'opencode-go-analyze.py')

SECRET_NAMES = ('zebra-tool', 'quokka-lib', 'ocelot-app', 'narwhal-dev', 'lemur-base')


def stanza(name, state='install ok installed', depends=None, provides=None, arch='amd64'):
    lines = ['Package: %s' % name, 'Status: %s' % state, 'Architecture: %s' % arch, 'Version: 1.0']
    if depends:
        lines.append('Depends: %s' % depends)
    if provides:
        lines.append('Provides: %s' % provides)
    lines.append('Description: fixture')
    return '\n'.join(lines) + '\n'


def make_dpkg_root(base, stanzas, lists=True, skip_lists=()):
    base = Path(base)
    (base / 'var/lib/dpkg/info').mkdir(parents=True, exist_ok=True)
    (base / 'var/lib/dpkg/status').write_text('\n'.join(stanzas))
    if lists:
        for s in stanzas:
            name = [ln for ln in s.splitlines() if ln.startswith('Package: ')][0][9:]
            if name not in skip_lists:
                (base / 'var/lib/dpkg/info' / (name + '.list')).write_text('/usr/bin/x\n')
    (base / 'etc/xdg/autostart').mkdir(parents=True, exist_ok=True)
    return base


def run_target(root, family='linuxmint', scope=('all',), packages=()):
    ctx = rescue_modules.Context(mode='live', scope=scope, packages=packages)
    checks = rescue_modules.collect_offline_target(ctx, str(root), {'family': family, 'release': 'x'})
    return {c['check_id']: c for c in checks}, ctx


def number(checks, cid):
    return checks[cid].get('number')


class DpkgChecksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_healthy_database(self):
        make_dpkg_root(self.tmp, [
            stanza('zebra-tool', depends='quokka-lib (>= 1.0), ocelot-app | lemur-base'),
            stanza('quokka-lib'), stanza('lemur-base'),
            stanza('narwhal-dev', 'deinstall ok config-files')])
        checks, ctx = run_target(self.tmp)
        self.assertEqual(ctx.warnings, [])
        self.assertEqual((checks['sw-inventory']['status'], number(checks, 'sw-inventory')), ('pass', 3))
        for cid in ('sw-package-health', 'sw-pending-config', 'sw-broken-dependencies', 'sw-held-packages',
                    'sw-package-integrity'):
            self.assertEqual((checks[cid]['status'], number(checks, cid)), ('pass', 0), cid)
        self.assertEqual(checks['sw-app-health']['status'], 'not_applicable')
        self.assertEqual((checks['sw-startup-items']['status'], number(checks, 'sw-startup-items')), ('pass', 0))
        self.assertEqual({c['check_id'] for c in checks.values()} - rescue_modules.CHECK_IDS, set())

    def test_half_configured_reinstreq_unpacked_and_triggers(self):
        make_dpkg_root(self.tmp, [
            stanza('zebra-tool', 'install ok half-configured'),
            stanza('quokka-lib', 'install reinstreq half-installed'),
            stanza('ocelot-app', 'install ok unpacked'),
            stanza('narwhal-dev', 'install ok triggers-pending'),
            stanza('lemur-base')])
        checks, _ = run_target(self.tmp)
        self.assertEqual((checks['sw-pending-config']['status'], number(checks, 'sw-pending-config')), ('fail', 3))
        self.assertEqual((checks['sw-package-health']['status'], number(checks, 'sw-package-health')), ('fail', 1))

    def test_unpacked_only_is_a_warning(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool', 'install ok unpacked'), stanza('lemur-base')])
        checks, _ = run_target(self.tmp)
        self.assertEqual((checks['sw-pending-config']['status'], number(checks, 'sw-pending-config')), ('warn', 1))

    def test_broken_dependencies_alternatives_and_provides(self):
        make_dpkg_root(self.tmp, [
            stanza('zebra-tool', depends='missing-one'),                      # broken
            stanza('quokka-lib', depends='missing-two | lemur-base'),         # satisfied by alternative
            stanza('ocelot-app', depends='virtual-thing'),                    # satisfied by Provides
            stanza('narwhal-dev', provides='virtual-thing (= 1)'),
            stanza('lemur-base', depends='libx:any (>= 2)')])                 # broken: libx absent
        checks, _ = run_target(self.tmp)
        self.assertEqual((checks['sw-broken-dependencies']['status'], number(checks, 'sw-broken-dependencies')),
                         ('fail', 2))

    def test_held_and_missing_file_lists(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool', 'hold ok installed'), stanza('quokka-lib'),
                                  stanza('lemur-base')], skip_lists=('quokka-lib',))
        checks, _ = run_target(self.tmp)
        self.assertEqual((checks['sw-held-packages']['status'], number(checks, 'sw-held-packages')), ('warn', 1))
        self.assertEqual((checks['sw-package-integrity']['status'], number(checks, 'sw-package-integrity')),
                         ('fail', 1))

    def test_large_info_directory_is_not_truncated(self):
        make_dpkg_root(self.tmp, [stanza('zzz-last-package')])
        for i in range(software.MAX_ENTRIES + 200):
            (self.tmp / 'var/lib/dpkg/info' / ('a%d.md5sums' % i)).write_text('x')
        checks, _ = run_target(self.tmp)
        self.assertEqual((checks['sw-package-integrity']['status'], number(checks, 'sw-package-integrity')), ('pass', 0))

    def test_multiarch_list_names_count(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool')], lists=False)
        (self.tmp / 'var/lib/dpkg/info/zebra-tool:amd64.list').write_text('x')
        checks, _ = run_target(self.tmp)
        self.assertEqual(number(checks, 'sw-package-integrity'), 0)

    def test_selected_filters_and_reports_missing_as_a_count(self):
        make_dpkg_root(self.tmp, [
            stanza('zebra-tool', 'install ok half-configured', depends='gone-dep'),
            stanza('quokka-lib', 'install ok half-configured', depends='gone-dep'),   # not selected
            stanza('ocelot-app'), stanza('lemur-base')])
        checks, _ = run_target(self.tmp, scope=('software.selected',),
                               packages=('zebra-tool', 'ocelot-app', 'not-installed-pkg', 'also-missing'))
        self.assertEqual((checks['sw-inventory']['status'], number(checks, 'sw-inventory')), ('warn', 2))
        self.assertEqual(number(checks, 'sw-pending-config'), 1)          # quokka-lib is ignored
        self.assertEqual(number(checks, 'sw-broken-dependencies'), 1)
        self.assertEqual((checks['sw-app-health']['status'], number(checks, 'sw-app-health')), ('warn', 2))

    def test_selected_all_present_is_pass(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool'), stanza('quokka-lib')])
        checks, _ = run_target(self.tmp, scope=('software.selected',), packages=('zebra-tool:amd64',))
        self.assertEqual((checks['sw-inventory']['status'], number(checks, 'sw-inventory')), ('pass', 1))
        self.assertEqual((checks['sw-app-health']['status'], number(checks, 'sw-app-health')), ('pass', 0))

    def test_no_package_name_ever_reaches_the_checks(self):
        names = SECRET_NAMES
        make_dpkg_root(self.tmp, [stanza(names[0], 'install ok half-configured', depends=names[1]),
                                  stanza(names[2], 'hold ok installed'), stanza(names[3])],
                       skip_lists=(names[3],))
        for scope, packages in ((('all',), ()), (('software.selected',), (names[0], names[4]))):
            checks, ctx = run_target(self.tmp, scope=scope, packages=packages)
            text = json.dumps(checks) + json.dumps(ctx.warnings)
            for name in names:
                self.assertNotIn(name, text)
            for c in checks.values():
                self.assertEqual(set(c) - {'check_id', 'status', 'kind', 'number'}, set())

    def test_not_a_dpkg_system_is_unknown(self):
        (self.tmp / 'etc').mkdir()
        checks, _ = run_target(self.tmp, family='linux-other')
        self.assertEqual(checks['sw-inventory']['status'], 'unknown')
        self.assertNotIn('number', checks['sw-inventory'])

    def test_symlinked_status_is_never_followed(self):
        outside = self.tmp / 'outside'
        outside.mkdir()
        (outside / 'status').write_text(stanza('zebra-tool'))
        target = self.tmp / 'target'
        (target / 'var/lib/dpkg').mkdir(parents=True)
        (target / 'var/lib/dpkg/status').symlink_to(outside / 'status')
        checks, _ = run_target(target)
        self.assertEqual(checks['sw-inventory']['status'], 'unknown')
        # A symlinked directory component is refused as well.
        target2 = self.tmp / 'target2'
        target2.mkdir()
        (target2 / 'var').symlink_to(outside)
        (outside / 'lib/dpkg').mkdir(parents=True)
        (outside / 'lib/dpkg/status').write_text(stanza('zebra-tool'))
        checks, _ = run_target(target2)
        self.assertEqual(checks['sw-inventory']['status'], 'unknown')

    def test_startup_items_threshold(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool')])
        for i in range(software.STARTUP_WARN + 1):
            (self.tmp / 'etc/xdg/autostart' / ('a%d.desktop' % i)).write_text('x')
        checks, _ = run_target(self.tmp)
        self.assertEqual(checks['sw-startup-items']['status'], 'warn')
        self.assertEqual(number(checks, 'sw-startup-items'), software.STARTUP_WARN + 1)

    def test_scope_excludes_software_module(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool')])
        ctx = rescue_modules.Context(mode='live', scope=('hardware.cpu',))
        self.assertEqual(rescue_modules.collect_offline_target(ctx, str(self.tmp), {'family': 'linuxmint'}), [])

    def test_live_collect_system_is_empty_and_host_uses_fixture_root(self):
        make_dpkg_root(self.tmp, [stanza('zebra-tool', 'install ok half-configured')])
        self.assertEqual(rescue_modules.collect_system(rescue_modules.Context(mode='live', scope=('software',))), [])
        ctx = rescue_modules.Context(mode='host', scope=('software',), fixture_root=str(self.tmp))
        got = {c['check_id']: c for c in rescue_modules.collect_system(ctx)}
        self.assertEqual(got['sw-pending-config']['status'], 'fail')
        self.assertEqual(got['sw-pending-config']['target_ref'], 'os-0')
        empty = tempfile.mkdtemp(prefix='sw-empty-')
        self.addCleanup(shutil.rmtree, empty, True)
        got = rescue_modules.collect_system(rescue_modules.Context(mode='host', scope=('software',), fixture_root=empty))
        self.assertEqual([(c['check_id'], c['status']) for c in got], [('sw-inventory', 'unknown')])


class OtherTargetsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-os-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_macos_counts_apps_and_receipts(self):
        (self.tmp / 'Applications/Safari.app').mkdir(parents=True)
        (self.tmp / 'Applications/Zebra Tool.app').mkdir()
        (self.tmp / 'Applications/readme.txt').write_text('x')
        (self.tmp / 'private/var/db/receipts').mkdir(parents=True)
        for n in ('com.a.pkg.plist', 'com.a.pkg.bom', 'com.b.pkg.plist'):
            (self.tmp / 'private/var/db/receipts' / n).write_text('x')
        (self.tmp / 'var').symlink_to('private/var')     # as on a real macOS volume
        checks, _ = run_target(self.tmp, family='macos')
        self.assertEqual((checks['sw-inventory']['status'], number(checks, 'sw-inventory')), ('pass', 2))
        self.assertEqual((checks['sw-package-health']['status'], number(checks, 'sw-package-health')), ('pass', 2))
        text = json.dumps(checks)
        self.assertNotIn('Safari', text)
        self.assertNotIn('Zebra', text)

    def test_macos_selected(self):
        (self.tmp / 'Applications/Safari.app').mkdir(parents=True)
        checks, _ = run_target(self.tmp, family='macos', scope=('software.selected',),
                               packages=('Safari', 'Missing'))
        self.assertEqual((checks['sw-inventory']['status'], number(checks, 'sw-inventory')), ('warn', 1))
        self.assertEqual((checks['sw-app-health']['status'], number(checks, 'sw-app-health')), ('warn', 1))

    def test_macos_without_applications_is_unknown(self):
        checks, _ = run_target(self.tmp, family='macos')
        self.assertEqual(checks['sw-inventory']['status'], 'unknown')

    def test_windows_target_is_honestly_unknown(self):
        (self.tmp / 'Windows').mkdir()
        checks, _ = run_target(self.tmp, family='windows')
        self.assertEqual({k: v['status'] for k, v in checks.items()}, {'sw-inventory': 'unknown'})


class ScannerAndLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-scan-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def scan(self, *args):
        fx = self.tmp / 'fx'
        (fx / 'root/etc').mkdir(parents=True)
        (fx / 'root/etc/os-release').write_text('ID=linuxmint\nNAME="Linux Mint"\nVERSION_ID="22.3"\n')
        make_dpkg_root(fx / 'root', [stanza('zebra-tool', 'install ok half-configured', depends='quokka-lib'),
                                     stanza('ocelot-app'), stanza('lemur-base', 'hold ok installed')])
        (fx / 'root.meta.json').write_text(json.dumps({'fstype': 'ext4', 'size': 50 * 1024 ** 3}))
        out = self.tmp / 'ev.json'
        r = subprocess.run([sys.executable, SCRIPTS / 'scan-target-os.py', '--output', out, '--fixture-root', fx,
                            '--repair-policy', 'detect-only', *map(str, args)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(out.read_text()), out

    def test_fixture_scan_validates_and_proposes_catalog_actions(self):
        ev, path = self.scan('--scope', 'software')
        self.assertEqual(analyzer.validation_problems(validator, ev), [])
        by_id = {c['check_id']: c for c in ev['checks']}
        self.assertEqual(by_id['sw-pending-config']['status'], 'fail')
        self.assertEqual(by_id['sw-pending-config']['value'], {'kind': 'count', 'number': 1})
        self.assertEqual(by_id['sw-broken-dependencies']['value']['number'], 1)
        self.assertEqual(by_id['sw-held-packages']['value']['number'], 1)
        self.assertEqual(by_id['sw-pending-config']['target_ref'], 'os-0')
        ids = {p['action_id'] for p in ev['repair_proposals']}
        self.assertIn('sw.dpkg-configure-target', ids)
        text = path.read_text()
        for name in ('zebra-tool', 'ocelot-app', 'lemur-base', 'quokka-lib'):
            self.assertNotIn(name, text)

    def test_fixture_scan_selected_scope(self):
        ev, path = self.scan('--scope', 'software.selected', '--packages', 'ocelot-app,absent-pkg')
        self.assertEqual(analyzer.validation_problems(validator, ev), [])
        by_id = {c['check_id']: c for c in ev['checks']}
        self.assertEqual(ev['scope'], ['software.selected'])
        self.assertEqual(by_id['sw-inventory']['value']['number'], 1)
        self.assertEqual(by_id['sw-app-health']['value']['number'], 1)
        self.assertEqual(by_id['sw-pending-config']['status'], 'pass')
        self.assertNotIn('absent-pkg', path.read_text())
        self.assertNotIn('ocelot-app', path.read_text())

    def test_os_only_scope_skips_software(self):
        ev, _ = self.scan('--scope', 'os')
        self.assertFalse([c for c in ev['checks'] if c['check_id'].startswith('sw-')])

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'python3-jsonschema required')
    def test_linux_launcher_evidence_validates(self):
        usb = self.tmp / 'usb'
        bundle = usb / 'rescue-omes'
        bundle.mkdir(parents=True)
        for name in ('scripts', 'profiles', 'rescue-ai', 'host'):
            shutil.copytree(ROOT / name, bundle / name, ignore=shutil.ignore_patterns('__pycache__', 'rescue.env', '.env'))
        env = {k: v for k, v in os.environ.items() if k != 'OPENCODE_GO_API_KEY'}
        proc = subprocess.run([str(bundle / 'host/rescue-linux.sh'), '--evidence-only', '--scope', 'software',
                               '--repair-policy', 'detect-only'], capture_output=True, text=True, env=env,
                              cwd=self.tmp, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        files = sorted((bundle / 'reports').glob('linux-*-evidence.json'))
        self.assertEqual(len(files), 1)
        ev = json.loads(files[0].read_text())
        self.assertEqual(analyzer.validation_problems(validator, ev), [])
        sw = {c['check_id']: c for c in ev['checks'] if c['check_id'].startswith('sw-')}
        self.assertIn('sw-inventory', sw)
        self.assertTrue(all(c['target_ref'] == 'os-0' for c in sw.values()))
        if not Path('/var/lib/dpkg/status').exists():
            self.assertEqual(sw['sw-inventory']['status'], 'unknown')


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = rc.load()
        cls.software = {k: v for k, v in cls.catalog.actions.items() if v['_domain'] == 'software'}

    def test_actions_exist_and_are_valid(self):
        self.assertEqual(set(self.software), {
            'sw.dpkg-configure-pending', 'sw.apt-fix-broken', 'sw.apt-reinstall-package',
            'sw.dpkg-configure-target', 'sw.winget-repair-package', 'sw.winget-upgrade-package'})
        self.assertEqual(subprocess.run([sys.executable, SCRIPTS / 'lib/repair_catalog.py'],
                                        capture_output=True).returncode, 0)

    def test_every_action_is_destructive_with_backup_and_a_doc_anchor(self):
        docs = (ROOT / 'docs/software.md').read_text()
        for aid, a in self.software.items():
            self.assertEqual(a['risk'], 'destructive', aid)
            self.assertTrue(a['backup']['required'], aid)
            self.assertEqual(a['rollback']['kind'], 'manual', aid)
            for ref in (a['doc'], a['rollback']['doc']):
                path, _, anchor = ref.partition('#')
                self.assertEqual(path, 'docs/software.md')
                self.assertIn('id="%s"' % anchor, docs, '%s: %s' % (aid, ref))

    def test_triggers_reference_emitted_ids_and_platforms_are_consistent(self):
        emitted = {'sw-inventory', 'sw-package-health', 'sw-broken-dependencies', 'sw-pending-config',
                   'sw-held-packages', 'sw-package-integrity', 'sw-app-health', 'sw-startup-items'}
        for aid, a in self.software.items():
            for t in a['triggers']:
                self.assertIn(t['check_id'], emitted, aid)
        self.assertEqual(self.software['sw.dpkg-configure-target']['platforms'], ['live-linux'])
        self.assertTrue(self.software['sw.dpkg-configure-target']['requires_target_rw'])
        self.assertEqual(self.software['sw.winget-repair-package']['platforms'], ['windows-host'])

    def test_package_parameter_validation(self):
        param = self.software['sw.apt-reinstall-package']['params'][0]
        self.assertEqual(rc.validate_param(param, 'zebra-tool', packages=('zebra-tool',)), 'zebra-tool')
        for bad in ('-rf', '--reinstall', 'a b', 'a;b', '$(x)', 'a/b', '', 'x=1'):
            with self.assertRaises(ValueError, msg=bad):
                rc.validate_param(param, bad)
        with self.assertRaises(ValueError):
            rc.validate_param(param, 'other', packages=('zebra-tool',))

    def test_rendered_argv_keeps_the_package_as_one_element(self):
        a = self.software['sw.apt-reinstall-package']
        argv = rc.render(a['execute']['argv'], {'package': 'zebra-tool'})
        self.assertEqual(argv[-1], 'zebra-tool')
        self.assertEqual(argv[:3], ['apt-get', 'install', '--reinstall'])


class EngineTests(unittest.TestCase):
    """The shipped software catalog through the real engine, with fake programs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-engine-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.log = self.tmp / 'calls.log'
        self.failmarks = self.tmp / 'fail'
        self.failmarks.mkdir()
        for name in ('dpkg', 'apt-get', 'winget.exe'):
            (self.bin / name).write_text('#!/bin/sh\necho "%s $*" >> "%s"\n[ -e "%s/%s" ] && exit 3\n[ -e "%s/%s.$1" ] && exit 3\nexit 0\n'
                                         % (name, self.log, self.failmarks, name, self.failmarks, name))
            (self.bin / name).chmod(0o755)
        (self.bin / 'sudo').write_text('#!/bin/sh\necho "sudo $*" >> "%s"\nshift 2\nexec "$@"\n' % self.log)
        (self.bin / 'sudo').chmod(0o755)
        (self.tmp / 'catalog').mkdir()
        shutil.copy(ROOT / 'rescue-ai/v1/catalog/software.json', self.tmp / 'catalog/software.json')
        self.backup = self.tmp / 'pkgstate.tar'
        self.backup.write_bytes(b'x' * 2048)
        self.journal = self.tmp / 'state/repairs/journal.jsonl'
        self.env = dict(os.environ, RESCUE_REPAIR_TEST_PATH=str(self.bin))
        self.host_evidence = self.make_host_evidence()

    def make_host_evidence(self):
        """A linux-host evidence file derived from a fixture scan (same schema, different platform)."""
        fx = self.tmp / 'fx'
        (fx / 'root/etc').mkdir(parents=True)
        (fx / 'root/etc/os-release').write_text('ID=linuxmint\nNAME="Linux Mint"\nVERSION_ID="22.3"\n')
        make_dpkg_root(fx / 'root', [stanza('zebra-tool', 'install ok half-configured', depends='gone'),
                                     stanza('ocelot-app')])
        (fx / 'root.meta.json').write_text(json.dumps({'fstype': 'ext4', 'size': 50 * 1024 ** 3}))
        out = self.tmp / 'live.json'
        r = subprocess.run([sys.executable, SCRIPTS / 'scan-target-os.py', '--output', out, '--fixture-root', fx,
                            '--scope', 'software', '--repair-policy', 'detect-only',
                            '--catalog-dir', self.tmp / 'catalog'], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        self.live_evidence = out
        ev = json.loads(out.read_text())
        ev['source_platform'] = 'linux-host'
        ev['repair_proposals'] = []
        host = self.tmp / 'host.json'
        host.write_text(json.dumps(ev))
        return host

    def engine(self, *args, evidence=None):
        cmd = [sys.executable, SCRIPTS / 'rescue-repair.py', '--evidence', evidence or self.host_evidence,
               '--catalog-dir', self.tmp / 'catalog', '--state-dir', self.tmp / 'state', *args]
        return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, env=self.env,
                              stdin=subprocess.DEVNULL, timeout=60)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def plain(self):
        """Fake-program calls without the sudo wrapper and the temp bin directory."""
        return [c.replace(str(self.bin) + '/', '') for c in self.calls() if not c.startswith('sudo ')]

    def records(self):
        return [json.loads(ln) for ln in self.journal.read_text().splitlines()] if self.journal.exists() else []

    def test_triggered_configure_needs_approval_and_a_backup(self):
        r = self.engine('--list')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('sw.dpkg-configure-pending', r.stdout)
        self.assertIn('sw.apt-fix-broken', r.stdout)
        r = self.engine()                                     # approve-each, no terminal: declined
        self.assertEqual(self.calls(), [])
        r = self.engine('--approve', 'sw.dpkg-configure-pending')   # destructive: no backup, still nothing
        self.assertEqual(self.calls(), [])
        r = self.engine('--approve', 'sw.dpkg-configure-pending', '--backup-ref', self.backup)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertTrue(calls[0].startswith('sudo -n -- ') or os.geteuid() == 0, calls)
        self.assertEqual(self.plain()[-2:], ['dpkg --configure -a', 'dpkg --configure -a'])
        stages = [(x['stage'], x['outcome']) for x in self.records() if x['action_id'] == 'sw.dpkg-configure-pending'
                  and x['outcome'] == 'ok']
        self.assertIn(('execute', 'ok'), stages)
        self.assertIn(('verify', 'ok'), stages)

    def test_auto_safe_never_runs_software_actions(self):
        r = self.engine('--policy', 'auto-safe')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])

    def test_apt_fix_broken_simulates_first_and_verifies(self):
        r = self.engine('--approve', 'sw.apt-fix-broken', '--backup-ref', self.backup)
        self.assertEqual(r.returncode, 0, r.stderr)
        plain = self.plain()
        self.assertEqual([c for c in plain if c.startswith('apt-get')],
                         ['apt-get -s -f install', 'apt-get -y -f install -o Dpkg::Options::=--force-confold',
                          'apt-get check'])

    def test_reinstall_needs_a_selected_package_and_valid_name(self):
        common = ['--select', 'sw.apt-reinstall-package:os-0', '--approve', 'sw.apt-reinstall-package',
                  '--backup-ref', self.backup]
        # Not in --packages while scope is software.selected: refused, nothing runs.
        r = self.engine(*common, '--scope', 'software.selected', '--packages', 'ocelot-app',
                        '--param', 'sw.apt-reinstall-package.package=zebra-tool')
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.records()[-1]['reason'], 'invalid-param')
        for bad in ('-oAPT::Get::Assume-Yes=true', '--purge', 'a;b'):
            self.engine(*common, '--scope', 'software.selected', '--packages', 'ocelot-app',
                        '--param', 'sw.apt-reinstall-package.package=' + bad)
            self.assertEqual(self.calls(), [])
        r = self.engine(*common, '--scope', 'software.selected', '--packages', 'ocelot-app',
                        '--param', 'sw.apt-reinstall-package.package=ocelot-app')
        self.assertEqual(r.returncode, 0, r.stderr)
        plain = self.plain()
        self.assertIn('apt-get install --reinstall -y -o Dpkg::Options::=--force-confold ocelot-app', plain)
        self.assertEqual(plain[-1], 'dpkg --verify ocelot-app')
        # The operator-supplied name is journaled only as the approval's parameter, nowhere else.
        holders = [x['stage'] for x in self.records() if 'ocelot-app' in json.dumps(x)]
        self.assertEqual(set(holders), {'approval'})

    def test_failed_verify_asks_for_manual_rollback(self):
        (self.failmarks / 'apt-get.check').touch()
        r = self.engine('--approve', 'sw.apt-fix-broken', '--backup-ref', self.backup)
        self.assertEqual(r.returncode, 1)
        self.assertIn('docs/software.md#rollback-dpkg', r.stderr + r.stdout)

    def test_target_action_is_unavailable_until_the_mount_provider_exists(self):
        r = self.engine('--select', 'sw.dpkg-configure-target:os-0', '--approve', 'sw.dpkg-configure-target',
                        '--backup-ref', self.backup, evidence=self.live_evidence)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])
        last = [x for x in self.records() if x['action_id'] == 'sw.dpkg-configure-target'][-1]
        self.assertEqual((last['stage'], last['outcome']), ('target-rw', 'unavailable'))

    def test_detect_only_never_executes(self):
        r = self.engine('--policy', 'detect-only', '--approve', 'sw.apt-fix-broken', '--backup-ref', self.backup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])

    def test_windows_actions_are_planned_only_on_this_engine(self):
        ev = json.loads(self.host_evidence.read_text())
        ev['source_platform'] = 'windows-host'
        ev['target_systems'][0]['family'] = 'windows'
        ev['target_systems'][0]['release'] = 'Windows'
        ev['checks'] = [c for c in ev['checks'] if c['check_id'] != 'os-detection'] + [{
            'check_id': 'sw-app-health', 'status': 'warn', 'source': 'offline-target-scan',
            'observed_at': ev['collected_at'], 'target_ref': 'os-0', 'value': {'kind': 'count', 'number': 1}}]
        path = self.tmp / 'win.json'
        path.write_text(json.dumps(ev))
        r = self.engine('--list', evidence=path)
        self.assertIn('sw.winget-repair-package', r.stdout, r.stdout + r.stderr)
        self.assertNotIn('sw.apt-fix-broken', r.stdout)
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-ps-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.module = ROOT / 'host/modules/windows/software.ps1'

    def run_module(self, scope, packages, fixture=None, path=None):
        args = [PWSH, '-NoProfile', '-NonInteractive', '-Command',
                "$r = & '%s' -Scope %s -Packages @(%s)%s; $r | ForEach-Object { '{0}|{1}|{2}|{3}' -f "
                "$_['check_id'], $_['status'], $_['kind'], $_['number'] }"
                % (self.module, ','.join("'%s'" % s for s in scope), ','.join("'%s'" % p for p in packages),
                   (" -FixtureFile '%s'" % fixture) if fixture else '')]
        env = dict(os.environ)
        if path:
            env['PATH'] = path + os.pathsep + env['PATH']
        proc = subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = {}
        for line in proc.stdout.splitlines():
            cid, status, kind, num = line.split('|')
            out[cid] = (status, kind, num)
        return out, proc.stdout

    def fixture(self, **data):
        path = self.tmp / 'fx.json'
        path.write_text(json.dumps(data))
        return path

    def test_without_registry_everything_degrades_to_unknown(self):
        out, _ = self.run_module(['all'], [])
        self.assertEqual(out['sw-inventory'][0], 'unknown')
        self.assertEqual(out['sw-package-health'][0], 'unknown')
        self.assertEqual(out['sw-startup-items'][0], 'unknown')

    def test_inventory_orphans_and_startup_counts_without_names(self):
        fx = self.fixture(uninstall=[
            {'name': 'Zebra Tool', 'location': 'C:\\Zebra', 'location_exists': True},
            {'name': 'Quokka', 'location': 'C:\\Quokka', 'location_exists': False},
            {'name': 'Ocelot', 'location': '', 'location_exists': False}], startup_items=3)
        out, raw = self.run_module(['all'], [], fixture=fx)
        self.assertEqual(out['sw-inventory'], ('pass', 'count', '3'))
        self.assertEqual(out['sw-package-health'], ('warn', 'count', '1'))
        self.assertEqual(out['sw-startup-items'], ('pass', 'count', '3'))
        self.assertEqual(out['sw-app-health'][0], 'not_applicable')
        for word in ('Zebra', 'Quokka', 'Ocelot', 'C:'):
            self.assertNotIn(word, raw)

    def test_startup_threshold(self):
        out, _ = self.run_module(['all'], [], fixture=self.fixture(uninstall=[], startup_items=51))
        self.assertEqual(out['sw-startup-items'], ('warn', 'count', '51'))

    def test_selected_packages_counts_missing_only(self):
        fx = self.fixture(uninstall=[], startup_items=0, winget_installed=['Vendor.Present'])
        out, raw = self.run_module(['software.selected'], ['Vendor.Present', 'Vendor.Absent'], fixture=fx)
        self.assertEqual(out['sw-inventory'], ('warn', 'count', '1'))
        self.assertEqual(out['sw-app-health'], ('warn', 'count', '1'))
        self.assertNotIn('Vendor', raw)

    def test_selected_without_winget_is_unknown(self):
        out, _ = self.run_module(['software.selected'], ['Vendor.Present'],
                                 fixture=self.fixture(uninstall=[], startup_items=0))
        self.assertEqual(out['sw-app-health'][0], 'unknown')

    def test_emitted_ids_are_in_the_evidence_contract(self):
        out, _ = self.run_module(['all'], [], fixture=self.fixture(uninstall=[], startup_items=0))
        self.assertLessEqual(set(out), rescue_modules.CHECK_IDS)


@unittest.skipUnless(ZSH, 'zsh not installed')
class MacModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sw-mac-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.module = ROOT / 'host/modules/macos/software.zsh'
        self.shims = self.tmp / 'shims'
        self.shims.mkdir()
        self.home = self.tmp / 'home'
        self.home.mkdir()
        self.root = self.tmp / 'root'
        (self.root / 'Applications').mkdir(parents=True)
        self.calls = self.tmp / 'calls.log'
        self.shim('pkgutil', 'printf "com.a.one\\ncom.a.two\\ncom.a.three\\n"')
        self.shim('codesign', 'echo "codesign $*" >> "%s"\ncase "$4" in *Bad.app) exit 3;; esac\nexit 0' % self.calls)

    def shim(self, name, body):
        p = self.shims / name
        p.write_text('#!/bin/sh\n%s\n' % body)
        p.chmod(0o755)

    def run_module(self, scope='all', packages=''):
        env = dict(os.environ, PATH=str(self.shims) + os.pathsep + os.environ['PATH'], HOME=str(self.home),
                   RESCUE_TEST_ROOT=str(self.root), RESCUE_SCOPE=scope, RESCUE_PACKAGES=packages)
        proc = subprocess.run([ZSH, '-f', str(self.module)], capture_output=True, text=True, env=env,
                              stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            self.assertIn(len(parts), (2, 4), line)
            out[parts[0]] = tuple(parts[1:])
        return out, proc.stdout

    def test_inventory_receipts_and_startup(self):
        for a in ('Alpha.app', 'Beta.app'):
            (self.root / 'Applications' / a).mkdir()
        (self.home / 'Applications').mkdir()
        (self.home / 'Applications/Gamma.app').mkdir()
        (self.root / 'Library/LaunchAgents').mkdir(parents=True)
        (self.root / 'Library/LaunchAgents/x.plist').write_text('x')
        (self.home / 'Library/LaunchAgents').mkdir(parents=True)
        (self.home / 'Library/LaunchAgents/y.plist').write_text('x')
        out, raw = self.run_module()
        self.assertEqual(out['sw-inventory'], ('pass', 'count', '3'))
        self.assertEqual(out['sw-package-health'], ('pass', 'count', '3'))
        self.assertEqual(out['sw-startup-items'], ('pass', 'count', '2'))
        self.assertEqual(out['sw-app-health'], ('not_applicable',))
        for word in ('Alpha', 'Beta', 'Gamma', 'com.a'):
            self.assertNotIn(word, raw)
        self.assertLessEqual(set(out), rescue_modules.CHECK_IDS)

    def test_selected_apps_signature_and_missing(self):
        for a in ('Good.app', 'Bad.app'):
            (self.root / 'Applications' / a).mkdir()
        out, raw = self.run_module('software.selected', 'Good,Bad,Absent')
        self.assertEqual(out['sw-inventory'], ('warn', 'count', '2'))
        self.assertEqual(out['sw-app-health'], ('fail', 'count', '2'))    # one bad signature + one missing
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)      # only installed selected apps
        self.assertNotIn('Bad', raw)

    def test_selected_all_good(self):
        (self.root / 'Applications/Good.app').mkdir()
        out, _ = self.run_module('software.selected', 'Good')
        self.assertEqual(out['sw-app-health'], ('pass', 'count', '0'))

    def test_invalid_package_names_are_ignored_and_selection_is_bounded(self):
        for i in range(15):
            (self.root / 'Applications' / ('App%d.app' % i)).mkdir()
        names = ','.join(['../x', '-rf', 'a b'] + ['App%d' % i for i in range(15)])
        self.run_module('software.selected', names)
        self.assertEqual(len(self.calls.read_text().splitlines()), 10)

    def test_missing_tools_degrade_to_unknown(self):
        (self.shims / 'pkgutil').unlink()
        out, _ = self.run_module()
        self.assertEqual(out['sw-inventory'][0], 'warn')          # empty /Applications
        self.assertEqual(out['sw-startup-items'], ('unknown',))
        self.assertIn(out['sw-package-health'][0], ('unknown', 'pass'))

    def test_module_is_read_only_and_uses_no_forbidden_constructs(self):
        text = self.module.read_text()
        code = '\n'.join(ln for ln in text.splitlines() if not ln.lstrip().startswith('#'))
        for word in ('sudo', 'python', 'eval', 'source ', 'osascript', 'rm -', 'curl', 'defaults write'):
            self.assertNotIn(word, code, word)


if __name__ == '__main__':
    unittest.main()
