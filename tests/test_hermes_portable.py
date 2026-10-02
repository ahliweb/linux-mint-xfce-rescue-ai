"""Offline tests for scripts/build-hermes-portable.py and the --hermes-portable
option of scripts/prepare-ventoy-usb.sh (no downloads, no network, no real device).

The real build (uv, python-build-standalone, the Hermes checkout) is Environment-
blocked here and runs in CI (.github/workflows/package.yml); these tests cover the
pure functions and the archive/USB safety rules around it.
"""
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'build-hermes-portable.py'
PREPARE = ROOT / 'scripts' / 'prepare-ventoy-usb.sh'

_spec = importlib.util.spec_from_file_location('build_hermes_portable', SCRIPT)
hp = importlib.util.module_from_spec(_spec)
sys.modules['build_hermes_portable'] = hp
_spec.loader.exec_module(hp)

# Secret-shaped strings are assembled at run time so this file is not itself a hit.
FAKE_GH = 'gh' + 'p_' + 'a1B2c3D4' * 5
FAKE_SK = 'sk' + '-' + 'Ab12' * 8


def run(args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120, **kw)


def write(path, data=b'x', mode=None):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    if mode:
        path.chmod(mode)
    return path


def make_tree(base, platform='linux-x86_64', extra=None):
    """A tiny <platform> tree with a valid MANIFEST.json; returns the platform dir."""
    plat = pathlib.Path(base) / platform
    exe = 'python/python.exe' if platform.startswith('windows') else 'python/bin/python3'
    write(plat / exe, b'#!interp\n', 0o755)
    write(plat / 'python/hermes-agent/hermes_cli/main.py', 'print("hi")\n')
    write(plat / 'python/hermes-agent/skills/readme.md', 'docs\n')
    for rel, data in (extra or {}).items():
        write(plat / rel, data)
    entries, count, total = hp.hash_tree(plat)
    manifest = hp.build_manifest(platform, hp.HERMES_REF, '0.0.1', '3.11.0', entries, total, '2026-01-01T00:00:00Z')
    (plat / hp.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return plat


class TreeHashTests(unittest.TestCase):
    def test_tree_sha256_matches_the_documented_definition(self):
        entries = [('b/x', 'b' * 64), ('a.txt', 'a' * 64)]
        expected = hashlib.sha256(b'a.txt\0' + b'a' * 64 + b'\n' + b'b/x\0' + b'b' * 64 + b'\n').hexdigest()
        self.assertEqual(hp.tree_sha256(entries), expected)
        self.assertEqual(hp.tree_sha256(reversed(entries)), expected)

    def test_hash_tree_excludes_the_manifest_and_counts(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            entries, count, total = hp.hash_tree(plat)
            self.assertEqual(count, 3)
            self.assertNotIn(hp.MANIFEST_NAME, [e[0] for e in entries])
            self.assertEqual(total, sum(os.path.getsize(plat / e[0]) for e in entries))

    def test_manifest_has_the_contract_fields_and_no_machine_data(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            manifest = json.loads((plat / hp.MANIFEST_NAME).read_text())
            self.assertEqual(set(manifest), {'platform', 'hermes_ref', 'hermes_version', 'python_version',
                                             'built_at', 'file_count', 'total_bytes', 'tree_sha256'})
            text = (plat / hp.MANIFEST_NAME).read_text()
            self.assertNotIn(td, text)
            self.assertNotIn(os.path.expanduser('~'), text)

    def test_verify_tree_detects_changes_additions_and_removals(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            self.assertTrue(hp.verify_tree(plat)[0])
            write(plat / 'python/hermes-agent/skills/readme.md', 'tampered\n')
            self.assertFalse(hp.verify_tree(plat)[0])
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            write(plat / 'extra.txt', 'new')
            self.assertFalse(hp.verify_tree(plat)[0])
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            (plat / 'python/hermes-agent/skills/readme.md').unlink()
            self.assertFalse(hp.verify_tree(plat)[0])

    def test_hermes_ref_constant_is_a_full_commit(self):
        self.assertRegex(hp.HERMES_REF, r'^[0-9a-f]{40}$')


class SymlinkTests(unittest.TestCase):
    def test_symlinks_are_found_and_make_verification_fail(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            try:
                os.symlink('main.py', plat / 'python/hermes-agent/hermes_cli/link.py')
                os.symlink('python', plat / 'pylink')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')
            self.assertEqual(hp.find_symlinks(plat), ['pylink', 'python/hermes-agent/hermes_cli/link.py'])
            ok, msg = hp.verify_tree(plat)
            self.assertFalse(ok)
            self.assertIn('symlink', msg)

    def test_a_clean_tree_has_no_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(hp.find_symlinks(make_tree(td)), [])


class NameTests(unittest.TestCase):
    def check(self, rel, **kw):
        with tempfile.TemporaryDirectory() as td:
            write(pathlib.Path(td) / rel, 'x')
            return hp.check_names(td, **kw)

    def test_valid_names_pass(self):
        self.assertEqual(self.check('python/Lib/site-packages/pkg/__init__.py'), [])

    def test_exfat_invalid_characters_and_endings(self):
        for rel in ('a<b.txt', 'a?b', 'a|b', 'dir./x.txt', 'trailing '):
            with self.subTest(rel=rel):
                self.assertTrue(self.check(rel), rel)

    def test_reserved_windows_device_names(self):
        for rel in ('aux', 'NUL.txt', 'com1', 'pkg/con.py'):
            with self.subTest(rel=rel):
                self.assertTrue(self.check(rel), rel)

    def test_long_paths_are_refused(self):
        self.assertTrue(self.check('d/' + 'a' * 60 + '/' + 'b' * 60 + '/' + 'c' * 60 + '/f.py', max_rel=150))

    def test_case_insensitive_collisions(self):
        with tempfile.TemporaryDirectory() as td:
            write(pathlib.Path(td) / 'Q', 'x')
            write(pathlib.Path(td) / 'q', 'y')
            if len(os.listdir(td)) < 2:
                self.skipTest('case-insensitive filesystem')
            self.assertTrue(any('collision' in p for p in hp.check_names(td)))


class SecretScanTests(unittest.TestCase):
    def scan(self, files, **kw):
        with tempfile.TemporaryDirectory() as td:
            for rel, data in files.items():
                write(pathlib.Path(td) / rel, data)
            return hp.scan_secrets(td, **kw)

    def test_clean_tree_passes(self):
        self.assertEqual(self.scan({'python/x.py': 'print(1)\n', 'python/y.bin': b'\x00\x01\x02'}), [])

    def test_token_shapes_are_found_in_text_and_binary_without_printing_values(self):
        out = self.scan({'a.py': 'T = "%s"\n' % FAKE_GH, 'b.pyc': b'\x00' + FAKE_SK.encode() + b'\x00'})
        self.assertEqual(len(out), 2)
        self.assertTrue(all(FAKE_GH not in line and FAKE_SK not in line for line in out))

    def test_credential_file_names_are_refused(self):
        for name in ('.env', '.env.local', 'prod.env', 'rescue.env', 'auth.json', 'AUTH.JSON'):
            with self.subTest(name=name):
                self.assertTrue(self.scan({'python/' + name: 'x'}))
        self.assertEqual(self.scan({'python/config.env.example': 'x', 'python/.env.example': 'x'}), [])

    def test_git_directory_is_refused(self):
        self.assertTrue(self.scan({'python/hermes-agent/.git/HEAD': 'ref'}))

    def test_build_machine_paths_are_refused(self):
        out = self.scan({'python/x.py': 'P = "/home/builder/work"\n'}, extra_literals=['/home/builder/work'])
        self.assertEqual(len(out), 1)
        self.assertIn('build-machine path', out[0])

    def test_allowlist_is_precise(self):
        placeholder = 'Authorization: "Bearer sk-%s"\n' % ('x' * 20)
        path = 'python/hermes-agent/skills/a/guide.md'
        self.assertEqual(self.scan({path: placeholder}), [])
        # Same placeholder outside the allowlisted tree, or a real-looking key inside it: refused.
        self.assertTrue(self.scan({'python/lib/other.md': placeholder}))
        self.assertTrue(self.scan({path: 'Authorization: "Bearer %s"\n' % FAKE_SK}))
        self.assertTrue(self.scan({path: placeholder + 'k = "%s"\n' % FAKE_SK}))

    def test_allowlist_entries_are_fully_anchored_and_documented_cases_only(self):
        for path_re, label, spec in hp.SECRET_ALLOWLIST:
            self.assertTrue(path_re.startswith('^') and path_re.endswith('$'), path_re)
            self.assertIn(label, [l for l, _ in hp.SECRET_PATTERNS])
            self.assertNotIn('.*', spec)
            if spec.startswith('sha256:'):
                self.assertRegex(spec[7:], r'^[0-9a-f]{64}$')

    def test_source_holds_no_secret_shaped_literal(self):
        # The bundle's own credential scan (package.yml) runs over this very file.
        data = SCRIPT.read_bytes()
        for label, pattern in hp.SECRET_PATTERNS:
            self.assertIsNone(pattern.search(data), label)

    def test_hash_allowlist_matches_only_the_exact_value_and_path(self):
        value = 'eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ' + 'zb21lIjoicGF5bG9hZCJ9.'
        rel = 'python/lib/python3.11/site-packages/pyjwt-2.13.0.dist-info/METADATA'
        self.assertTrue(hp.allowlisted(hp.SECRET_ALLOWLIST, rel, 'JWT', value))
        self.assertFalse(hp.allowlisted(hp.SECRET_ALLOWLIST, rel, 'JWT', value + 'x'))
        self.assertFalse(hp.allowlisted(hp.SECRET_ALLOWLIST, 'python/other/METADATA', 'JWT', value))


class BuildPathTests(unittest.TestCase):
    def test_generic_ci_homes_are_not_build_paths(self):
        for home in ('/home/runner', 'C:\\Users\\runneradmin', '/root', '/home/runner/'):
            with self.subTest(home=home):
                self.assertEqual(hp.build_path_literals('/o/out', '/t/work', home), ['/o/out', '/t/work'])

    def test_a_personal_home_and_this_builds_paths_are_checked(self):
        lits = hp.build_path_literals('/o/out', '/t/work', '/home/alice', '/src/checkout')
        self.assertEqual(lits, ['/o/out', '/t/work', '/src/checkout', '/home/alice'])

    def test_third_party_runner_paths_do_not_fail_but_this_builds_paths_do(self):
        with tempfile.TemporaryDirectory() as td:
            write(pathlib.Path(td) / 'python/pkg/sbom.json', '{"p": "/home/runner/work/x"}')
            lits = hp.build_path_literals('/build/out', '/tmp/hp-build-abc', '/home/runner')
            self.assertEqual(hp.scan_secrets(td, extra_literals=lits), [])
            write(pathlib.Path(td) / 'python/pkg/leak.py', 'P = "/tmp/hp-build-abc/uv"')
            out = hp.scan_secrets(td, extra_literals=lits)
            self.assertEqual(len(out), 1)
            self.assertIn('build-machine path', out[0])


class InterpreterPickTests(unittest.TestCase):
    def test_links_and_minor_version_directories_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            (base / 'cpython-3.11.15-windows-x86_64-none').mkdir()
            (base / 'cpython-3.11-windows-x86_64-none').mkdir()          # no patch version
            (base / 'other').mkdir()
            self.assertEqual(hp.pick_interpreter_dirs(td), ['cpython-3.11.15-windows-x86_64-none'])

    def test_symlinked_patch_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            (base / 'cpython-3.11.15-linux-x86_64-gnu').mkdir()
            try:
                os.symlink('cpython-3.11.15-linux-x86_64-gnu', base / 'cpython-3.11.14-linux-x86_64-gnu')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')
            self.assertTrue(hp.is_link_or_junction(str(base / 'cpython-3.11.14-linux-x86_64-gnu')))
            self.assertFalse(hp.is_link_or_junction(str(base / 'cpython-3.11.15-linux-x86_64-gnu')))
            self.assertEqual(hp.pick_interpreter_dirs(td), ['cpython-3.11.15-linux-x86_64-gnu'])


class ArchiveValidationTests(unittest.TestCase):
    def names(self, *names):
        return [(n, 'dir' if n.endswith('/') else 'file') for n in names]

    def problems(self, *names):
        return hp.validate_member_names(self.names(*names))[1]

    def test_good_layout(self):
        plat, problems = hp.validate_member_names(self.names(
            'linux-x86_64/', 'linux-x86_64/MANIFEST.json', 'linux-x86_64/python/bin/python3'))
        self.assertEqual((plat, problems), ('linux-x86_64', []))

    def test_absolute_parent_and_odd_paths_are_refused(self):
        base = ['linux-x86_64/MANIFEST.json']
        for bad in ('/etc/passwd', '../x', 'linux-x86_64/../../x', 'linux-x86_64/./x', 'linux-x86_64//x',
                    'C:/x', 'C:evil', 'linux-x86_64\\x', '\\abs'):
            with self.subTest(name=bad):
                self.assertTrue(self.problems(*(base + [bad])), bad)

    def test_platform_rules(self):
        self.assertTrue(self.problems('macos/MANIFEST.json'))
        self.assertTrue(self.problems('linux-x86_64/MANIFEST.json', 'windows-x86_64/x'))
        self.assertTrue(self.problems('linux-x86_64/python/x'))          # no manifest
        self.assertTrue(self.problems('MANIFEST.json'))                  # top-level file
        self.assertTrue(self.problems())                                  # empty

    def test_credential_names_duplicates_and_exfat_names_are_refused(self):
        base = 'linux-x86_64/MANIFEST.json'
        self.assertTrue(self.problems(base, 'linux-x86_64/python/.env'))
        self.assertTrue(self.problems(base, 'linux-x86_64/config/auth.json'))
        self.assertTrue(self.problems(base, 'linux-x86_64/a', 'linux-x86_64/A'))
        self.assertTrue(self.problems(base, 'linux-x86_64/a:b'))
        self.assertTrue(self.problems(base, 'linux-x86_64/nul'))

    def test_archive_names(self):
        self.assertEqual(hp.platform_from_archive_name('/x/rescue-omes-hermes-portable-linux-x86_64.tar.gz'), 'linux-x86_64')
        self.assertEqual(hp.platform_from_archive_name('rescue-omes-hermes-portable-windows-x86_64.zip'), 'windows-x86_64')
        for bad in ('rescue-omes-hermes-portable-linux-x86_64.zip', 'rescue-omes-hermes-portable-windows-x86_64.tar.gz',
                    'rescue-omes-hermes-portable-macos-arm64.tar.gz', 'other.tar.gz'):
            self.assertIsNone(hp.platform_from_archive_name(bad), bad)
        self.assertEqual(hp.archive_name('windows-x86_64'), 'rescue-omes-hermes-portable-windows-x86_64.zip')


class ArchiveRoundTripTests(unittest.TestCase):
    def build(self, td, platform):
        tree = make_tree(pathlib.Path(td) / 'src', platform)
        archive = pathlib.Path(td) / hp.archive_name(platform)
        hp.write_archive(tree, platform, str(archive), 1700000000)
        return tree, archive

    def test_round_trip_both_formats_and_swap_in(self):
        for platform in hp.PLATFORMS:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as td:
                tree, archive = self.build(td, platform)
                self.assertEqual(hp.inspect_archive(str(archive)), (platform, []))
                dest = pathlib.Path(td) / 'usb' / 'rescue-omes' / 'hermes-portable'
                write(dest / platform / 'stale.txt', 'old')
                plat, msg = hp.extract_archive(str(archive), str(dest))
                self.assertEqual(plat, platform)
                self.assertIn('tree_sha256', msg)
                self.assertFalse((dest / platform / 'stale.txt').exists())
                self.assertTrue(hp.verify_tree(dest / platform)[0])
                self.assertEqual([p.name for p in dest.iterdir()], [platform], 'no staging leftovers')
                self.assertEqual(hp.read_manifest(dest / platform), hp.read_manifest(tree))

    def test_archive_is_deterministic_and_has_one_top_level_directory(self):
        with tempfile.TemporaryDirectory() as td:
            tree, first = self.build(td, 'linux-x86_64')
            second = pathlib.Path(td) / 'second.tar.gz'
            hp.write_archive(tree, 'linux-x86_64', str(second), 1700000000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as tf:
                self.assertEqual({m.name.split('/')[0] for m in tf.getmembers()}, {'linux-x86_64'})
                self.assertTrue(all(m.isreg() for m in tf.getmembers()))

    def test_extract_refuses_a_tampered_member(self):
        with tempfile.TemporaryDirectory() as td:
            tree, archive = self.build(td, 'linux-x86_64')
            tampered = pathlib.Path(td) / 'rescue-omes-hermes-portable-linux-x86_64.tar.gz'
            with tarfile.open(archive) as src:
                members = [(m, src.extractfile(m).read()) for m in src.getmembers()]
            with tarfile.open(tampered, 'w:gz') as dst:
                for m, data in members:
                    if m.name.endswith('skills/readme.md'):
                        data = b'tampered'
                        m.size = len(data)
                    dst.addfile(m, io.BytesIO(data))
            dest = pathlib.Path(td) / 'out'
            with self.assertRaises(hp.BuildError):
                hp.extract_archive(str(tampered), str(dest))
            self.assertFalse((dest / 'linux-x86_64').exists())
            self.assertEqual(list(dest.iterdir()) if dest.exists() else [], [], 'staging cleaned up')

    def test_tar_symlink_hardlink_and_traversal_members_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            for kind in ('symlink', 'hardlink', 'traversal', 'absolute'):
                with self.subTest(kind=kind):
                    path = pathlib.Path(td) / ('rescue-omes-hermes-portable-linux-x86_64.tar.gz')
                    with tarfile.open(path, 'w:gz') as tf:
                        info = tarfile.TarInfo('linux-x86_64/MANIFEST.json')
                        info.size = 2
                        tf.addfile(info, io.BytesIO(b'{}'))
                        bad = tarfile.TarInfo('linux-x86_64/python/evil')
                        if kind == 'symlink':
                            bad.type, bad.linkname = tarfile.SYMTYPE, '/etc/passwd'
                        elif kind == 'hardlink':
                            bad.type, bad.linkname = tarfile.LNKTYPE, 'linux-x86_64/MANIFEST.json'
                        elif kind == 'traversal':
                            bad.name = 'linux-x86_64/../../evil'
                        else:
                            bad.name = '/tmp/evil'
                        if kind in ('symlink', 'hardlink'):
                            tf.addfile(bad)
                        else:
                            bad.size = 1
                            tf.addfile(bad, io.BytesIO(b'x'))
                    plat, problems = hp.inspect_archive(str(path))
                    self.assertTrue(problems, kind)
                    with self.assertRaises(hp.BuildError):
                        hp.extract_archive(str(path), str(pathlib.Path(td) / 'out'))

    def test_zip_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / 'rescue-omes-hermes-portable-windows-x86_64.zip'
            with zipfile.ZipFile(path, 'w') as zf:
                zf.writestr('windows-x86_64/MANIFEST.json', '{}')
                info = zipfile.ZipInfo('windows-x86_64/python/link')
                info.external_attr = 0o120777 << 16
                zf.writestr(info, 'python.exe')
            _, problems = hp.inspect_archive(str(path))
            self.assertTrue(any('symlink' in p for p in problems))

    def test_archive_name_must_match_content(self):
        with tempfile.TemporaryDirectory() as td:
            tree = make_tree(pathlib.Path(td) / 'src', 'linux-x86_64')
            archive = pathlib.Path(td) / 'rescue-omes-hermes-portable-windows-x86_64.zip'
            hp.write_archive(tree, 'linux-x86_64', str(archive), 1700000000)
            self.assertTrue(hp.inspect_archive(str(archive))[1])
            junk = pathlib.Path(td) / 'whatever.tar.gz'
            junk.write_bytes(b'not an archive')
            self.assertTrue(hp.inspect_archive(str(junk))[1])


class CompileAllExclusionTests(unittest.TestCase):
    def test_compileall_exclude_regex_matches_tcl_tk_data_paths(self):
        """Verify that Tcl/Tk data directories are excluded from byte-compilation."""
        regex_pattern = hp._compileall_exclude_regex()
        regex = re.compile(regex_pattern)

        # Paths that SHOULD be excluded (Tcl/Tk data directories)
        excluded_paths = [
            'python/tcl/tix8.4.3/pref/WmDefault.py',
            'python/tcl8.6.11/library/init.tcl',
            'python/tk/button.tcl',
            'python/lib/tcl/x.py',
            'python\\tcl\\8.6\\init.tcl',  # Windows path
            'python\\tcl8.6.11\\library\\test.py',
            'python/lib/python3.11/tcl8.6/x.py',
        ]
        for path in excluded_paths:
            with self.subTest(path=path):
                self.assertTrue(regex.match(path), f"Pattern should exclude {path}")

        # Paths that should NOT be excluded (normal Python files)
        included_paths = [
            'python/Lib/site-packages/x.py',
            'python/lib/python3.11/site-packages/module.py',
            'python/bin/python3',
            'python/hermes-agent/hermes_cli/main.py',
            'python/Lib/collections/__init__.py',
            'python/lib/python3.11/asyncio/tasks.py',
        ]
        for path in included_paths:
            with self.subTest(path=path):
                self.assertFalse(regex.match(path), f"Pattern should include {path}")


class CliTests(unittest.TestCase):
    def test_verify_tree_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            self.assertEqual(run([sys.executable, SCRIPT, '--verify-tree', plat]).returncode, 0)
            write(plat / 'python/hermes-agent/skills/readme.md', 'changed\n')
            r = run([sys.executable, SCRIPT, '--verify-tree', plat])
            self.assertEqual(r.returncode, 1)
            self.assertIn('FAIL', r.stdout)

    def test_scan_tree_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            plat = make_tree(td)
            self.assertEqual(run([sys.executable, SCRIPT, '--scan-tree', plat]).returncode, 0)
            write(plat / 'python/.env', 'X=1')
            r = run([sys.executable, SCRIPT, '--scan-tree', plat])
            self.assertEqual(r.returncode, 1)
            self.assertIn('.env', r.stderr)

    def test_cross_builds_and_bad_refs_are_refused(self):
        other = 'windows-x86_64' if hp.running_platform() != 'windows-x86_64' else 'linux-x86_64'
        with tempfile.TemporaryDirectory() as td:
            r = run([sys.executable, SCRIPT, '--platform', other, '--out', td])
            self.assertEqual(r.returncode, 1)
            self.assertIn('cross-builds are refused', r.stderr)
            here = hp.running_platform()
            if here:
                r = run([sys.executable, SCRIPT, '--platform', here, '--hermes-ref', 'main', '--out', td])
                self.assertEqual(r.returncode, 1)
                self.assertIn('40-hex', r.stderr)

    def test_build_needs_platform_and_out(self):
        self.assertEqual(run([sys.executable, SCRIPT]).returncode, 2)

    def test_source_has_no_credentials_or_shell_strings(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertNotIn('shell=True', text)
        self.assertNotIn('os.system', text)
        self.assertNotRegex(text, r'(?i)api[_-]?key\s*=')


@unittest.skipUnless(hp.running_platform(), 'platform has no portable Hermes build')
class PrepareVentoyHermesPortableTests(unittest.TestCase):
    """prepare-ventoy-usb.sh --hermes-portable pre-flight rules (nothing reaches a device)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.mnt = self.base / 'mnt'
        self.mnt.mkdir()
        self.iso = write(self.base / 'x.iso', 'iso')
        tree = make_tree(self.base / 'src', 'linux-x86_64')
        self.archive = self.base / 'rescue-omes-hermes-portable-linux-x86_64.tar.gz'
        hp.write_archive(tree, 'linux-x86_64', str(self.archive), 1700000000)
        self.sidecar(self.archive)

    def tearDown(self):
        self.tmp.cleanup()

    def sidecar(self, archive, digest=None):
        digest = digest or hp.sha256_file(archive)
        pathlib.Path(str(archive) + '.sha256').write_text('%s  %s\n' % (digest, pathlib.Path(archive).name))

    def prepare(self, *portable, env=None):
        args = [PREPARE, '--ventoy-mount', self.mnt, '--mint-iso', self.iso, '--sha256sums', self.iso,
                '--signature', self.iso, '--no-provision-secrets']
        for item in portable:
            args += ['--hermes-portable', item]
        return run(args, env=env)

    def test_usage_documents_the_option(self):
        r = run([PREPARE, '--bogus'])
        self.assertEqual(r.returncode, 2)
        self.assertIn('--hermes-portable ARCHIVE', r.stderr)
        self.assertIn('.sha256', r.stderr)

    def test_option_requires_a_value(self):
        self.assertNotEqual(run([PREPARE, '--hermes-portable']).returncode, 0)

    def test_missing_archive_is_refused(self):
        r = self.prepare(self.base / 'nope.tar.gz')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not found', r.stderr)

    def test_sidecar_is_required(self):
        pathlib.Path(str(self.archive) + '.sha256').unlink()
        r = self.prepare(self.archive)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('sidecar', r.stderr)

    def test_checksum_mismatch_and_malformed_sidecar_are_refused(self):
        self.sidecar(self.archive, '0' * 64)
        r = self.prepare(self.archive)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('checksum mismatch', r.stderr)
        pathlib.Path(str(self.archive) + '.sha256').write_text('not a checksum\n')
        r = self.prepare(self.archive)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('is not', r.stderr)
        pathlib.Path(str(self.archive) + '.sha256').write_text('%s  other-name.tar.gz\n' % hp.sha256_file(self.archive))
        self.assertNotEqual(self.prepare(self.archive).returncode, 0)

    def test_unexpected_archive_name_is_refused(self):
        odd = self.base / 'portable.tar.gz'
        odd.write_bytes(self.archive.read_bytes())
        self.sidecar(odd)
        r = self.prepare(odd)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('unexpected Hermes portable archive name', r.stderr)

    def test_unsafe_archive_content_is_refused_before_anything_is_written(self):
        evil = self.base / 'evil' / 'rescue-omes-hermes-portable-linux-x86_64.tar.gz'
        evil.parent.mkdir()
        with tarfile.open(evil, 'w:gz') as tf:
            info = tarfile.TarInfo('linux-x86_64/MANIFEST.json')
            info.size = 2
            tf.addfile(info, io.BytesIO(b'{}'))
            link = tarfile.TarInfo('linux-x86_64/python/bin/python3')
            link.type, link.linkname = tarfile.SYMTYPE, '/usr/bin/python3'
            tf.addfile(link)
        self.sidecar(evil)
        r = self.prepare(evil)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('failed archive validation', r.stderr)
        self.assertEqual(list(self.mnt.iterdir()), [])

    def test_same_platform_twice_is_refused(self):
        r = self.prepare(self.archive, self.archive)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('given twice', r.stderr)

    def test_valid_archive_passes_preflight_and_stops_later_at_the_iso(self):
        bindir = self.base / 'bin'
        bindir.mkdir()
        for name, body in (('mountpoint', 'exit 0'), ('findmnt', 'echo /dev/null'),
                           ('lsblk', 'echo Ventoy')):
            stub = bindir / name
            stub.write_text('#!/bin/sh\n' + body + '\n')
            stub.chmod(0o755)
        (self.mnt / 'ventoy').mkdir()
        env = dict(os.environ, PATH='%s:%s' % (bindir, os.environ['PATH']))
        r = self.prepare(self.archive, env=env)
        self.assertNotEqual(r.returncode, 0)                    # the bogus ISO fails verification
        for text in ('sidecar', 'checksum mismatch', 'unexpected Hermes', 'failed archive validation'):
            self.assertNotIn(text, r.stderr)
        self.assertFalse((self.mnt / 'rescue-omes').exists(), 'nothing is copied before the ISO is verified')

    def test_script_unpacks_through_the_validated_tool_and_reads_back(self):
        text = PREPARE.read_text(encoding='utf-8')
        self.assertIn('--check-archive', text)
        self.assertIn('--extract-archive', text)
        self.assertIn('--verify-tree', text)
        self.assertIn('hermes-portable', text)
        self.assertLess(text.index('--check-archive'), text.index('verify-mint-iso.sh" "${verify_args[@]}"'))
        self.assertLess(text.index('--extract-archive'), text.index('Host launchers for Windows'))

    def test_cli_extract_into_a_usb_style_path_and_verify(self):
        dest = self.mnt / 'rescue-omes' / 'hermes-portable'
        r = run([sys.executable, SCRIPT, '--extract-archive', self.archive, '--dest', dest])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run([sys.executable, SCRIPT, '--verify-tree', dest / 'linux-x86_64'])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(run([sys.executable, SCRIPT, '--check-archive', self.archive]).returncode, 0)


if __name__ == '__main__':
    unittest.main()
