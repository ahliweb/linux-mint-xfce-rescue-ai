#!/usr/bin/env python3
"""Tests for the signed skills bundle (scripts/build-skills-bundle.py, scripts/lib/skills_bundle.py,
scripts/sign-skills-bundle.sh, config/skills-allowed-signers).

Signing keys exist only inside these tests: each test creates a throwaway ed25519 key in a temporary
directory that is removed afterwards. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILD = REPO / 'scripts' / 'build-skills-bundle.py'
SIGN = REPO / 'scripts' / 'sign-skills-bundle.sh'
SKILLS = REPO / 'profiles' / 'rescue-hermes' / 'skills'
sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
import skills_bundle as sb  # noqa: E402

HAVE_SSH = shutil.which('ssh-keygen') is not None


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in ('CI', 'GITHUB_ACTIONS')}
    env.update(extra)
    return env


def skill(name, body='Body.\n'):
    return f'---\nname: {name}\ndescription: Test skill {name}.\n---\n\n{body}'.encode()


class TempCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or None)
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)

    def make_skills(self, names=('alpha', 'beta')):
        d = self.tmp / 'skills-src'
        for n in names:
            (d / n).mkdir(parents=True, exist_ok=True)
            (d / n / 'SKILL.md').write_bytes(skill(n))
        return d

    def build(self, skills_dir, out, version='1.2.3', min_toolkit='1.0.0'):
        return sb.build(skills_dir, version, min_toolkit, out)

    def run_build(self, *args):
        return subprocess.run([sys.executable, str(BUILD), *args], capture_output=True, text=True)


class BuildTests(TempCase):
    def test_same_input_gives_identical_bytes_even_with_different_mtimes(self):
        src = self.make_skills()
        t1, m1 = self.build(src, self.tmp / 'o1')
        for p in src.rglob('*'):
            os.utime(p, (1_900_000_000, 1_900_000_000))
        t2, m2 = self.build(src, self.tmp / 'o2')
        self.assertEqual(t1.read_bytes(), t2.read_bytes())
        self.assertEqual(m1.read_bytes(), m2.read_bytes())

    def test_make_target_twice_is_byte_identical(self):
        out1, out2 = self.tmp / 'a', self.tmp / 'b'
        for out in (out1, out2):
            r = self.run_build('build', '--output-dir', str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
        for f in sorted(p.name for p in out1.iterdir()):
            self.assertEqual((out1 / f).read_bytes(), (out2 / f).read_bytes(), f)
        self.assertEqual(len(list(out1.iterdir())), 2)

    def test_tarball_header_is_fixed_and_contains_only_skill_files(self):
        t, _ = self.build(self.make_skills(), self.tmp / 'o')
        data = t.read_bytes()
        self.assertEqual(data[:2], b'\x1f\x8b')
        self.assertEqual(data[4:8], b'\x00\x00\x00\x00', 'gzip mtime must be zero')
        self.assertEqual(data[3] & 0x08, 0, 'gzip header must carry no file name')
        with tarfile.open(t) as tar:
            members = tar.getmembers()
        self.assertEqual([m.name for m in members], ['skills/alpha/SKILL.md', 'skills/beta/SKILL.md'])
        for m in members:
            self.assertTrue(m.isreg())
            self.assertEqual((m.mode, m.uid, m.gid, m.mtime, m.uname, m.gname), (0o644, 0, 0, 0, '', ''))

    def test_manifest_hashes_match_the_files_and_the_tarball(self):
        t, m = self.build(self.make_skills(), self.tmp / 'o')
        man = json.loads(m.read_text())
        self.assertEqual(man['schema'], sb.SCHEMA)
        self.assertEqual((man['bundle_version'], man['min_toolkit_version']), ('1.2.3', '1.0.0'))
        self.assertEqual(man['tarball'], {'name': t.name, 'sha256': hashlib.sha256(t.read_bytes()).hexdigest(),
                                          'size': t.stat().st_size})
        for entry in man['files']:
            data = (self.tmp / 'skills-src' / entry['path'].split('/')[1] / 'SKILL.md').read_bytes()
            self.assertEqual(entry['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry['size'], len(data))
        sb.check_bundle(m, t)

    def test_real_skills_build_and_check(self):
        out = self.tmp / 'real'
        self.assertEqual(self.run_build('build', '--output-dir', str(out)).returncode, 0)
        man = next(out.glob('*.manifest.json'))
        r = self.run_build('check', '--manifest', str(man))
        self.assertEqual(r.returncode, 0, r.stderr)
        names = {e['path'] for e in json.loads(man.read_text())['files']}
        self.assertEqual(names, {f'skills/{p.parent.name}/SKILL.md' for p in SKILLS.glob('*/SKILL.md')})

    def test_min_toolkit_is_in_the_repo_and_not_above_the_version(self):
        mt = (REPO / 'config' / 'skills-min-toolkit').read_text().strip()
        self.assertLessEqual(sb.version_tuple(mt), sb.version_tuple((REPO / 'VERSION').read_text().strip()))
        with self.assertRaises(sb.BundleError):
            self.build(self.make_skills(), self.tmp / 'o', version='1.0.0', min_toolkit='1.0.1')

    def test_build_refuses_extra_files_symlinks_and_bad_skills(self):
        src = self.make_skills()
        (src / 'alpha' / 'extra.sh').write_text('#!/bin/sh\n')
        with self.assertRaises(sb.BundleError):
            self.build(src, self.tmp / 'o')
        (src / 'alpha' / 'extra.sh').unlink()
        (src / 'beta' / 'SKILL.md').unlink()
        (src / 'beta' / 'SKILL.md').symlink_to(src / 'alpha' / 'SKILL.md')
        with self.assertRaises(sb.BundleError):
            self.build(src, self.tmp / 'o')
        (src / 'beta' / 'SKILL.md').unlink()
        (src / 'beta' / 'SKILL.md').write_bytes(skill('not-beta'))
        with self.assertRaises(sb.BundleError):
            self.build(src, self.tmp / 'o')
        (src / 'beta' / 'SKILL.md').write_bytes(b'x' * (sb.MAX_FILE_BYTES + 1))
        with self.assertRaises(sb.BundleError):
            self.build(src, self.tmp / 'o')
        (src / 'Bad_Name').mkdir()
        with self.assertRaises(sb.BundleError):
            self.build(src, self.tmp / 'o')


class CheckTests(TempCase):
    def setUp(self):
        super().setUp()
        self.tar_path, self.man_path = self.build(self.make_skills(), self.tmp / 'o')

    def hostile(self, build_tar, mutate_manifest=None):
        """Write a tarball made by build_tar(tar) with a manifest that matches it exactly."""
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz') as tar:
            build_tar(tar)
        data = raw.getvalue()
        man = json.loads(self.man_path.read_text())
        man['tarball']['sha256'] = hashlib.sha256(data).hexdigest()
        man['tarball']['size'] = len(data)
        if mutate_manifest:
            mutate_manifest(man)
        out = self.tmp / 'h'
        out.mkdir(exist_ok=True)
        (out / self.tar_path.name).write_bytes(data)
        mp = out / self.man_path.name
        mp.write_bytes(sb.manifest_bytes(man))
        return mp, out / self.tar_path.name

    def good_members(self, tar, mode=0o644, kind=tarfile.REGTYPE, uid=0):
        for e in json.loads(self.man_path.read_text())['files']:
            data = (self.tmp / 'skills-src' / e['path'].split('/')[1] / 'SKILL.md').read_bytes()
            info = tarfile.TarInfo(e['path'])
            info.size, info.mode, info.uid = len(data), mode, uid
            if kind != tarfile.REGTYPE:
                info.type, info.linkname, info.size = kind, '/etc/passwd', 0
                tar.addfile(info)
            else:
                tar.addfile(info, io.BytesIO(data))

    def test_baseline_passes(self):
        sb.check_bundle(self.man_path, self.tar_path)

    def test_one_changed_byte_in_the_tarball_is_refused(self):
        data = bytearray(self.tar_path.read_bytes())
        data[len(data) // 2] ^= 0x01
        self.tar_path.write_bytes(bytes(data))
        with self.assertRaises(sb.BundleError):
            sb.check_bundle(self.man_path, self.tar_path)

    def test_wrong_file_hash_in_manifest_is_refused(self):
        man = json.loads(self.man_path.read_text())
        man['files'][0]['sha256'] = '0' * 64
        self.man_path.write_bytes(sb.manifest_bytes(man))
        with self.assertRaises(sb.BundleError):
            sb.check_bundle(self.man_path, self.tar_path)

    def test_hostile_tarballs_with_matching_manifest_are_refused(self):
        def extra(tar):
            self.good_members(tar)
            info = tarfile.TarInfo('../../etc/cron.d/x')
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
        cases = {
            'path traversal member': (extra, None),
            'executable mode': (lambda t: self.good_members(t, mode=0o755), None),
            'setuid mode': (lambda t: self.good_members(t, mode=0o4644), None),
            'symlink member': (lambda t: self.good_members(t, kind=tarfile.SYMTYPE), None),
            'hardlink member': (lambda t: self.good_members(t, kind=tarfile.LNKTYPE), None),
            'owner not zero': (lambda t: self.good_members(t, uid=1000), None),
        }
        for label, (builder, mutate) in cases.items():
            with self.subTest(label):
                mp, tp = self.hostile(builder, mutate)
                with self.assertRaises(sb.BundleError):
                    sb.check_bundle(mp, tp)

    def test_manifest_shape_violations_are_refused(self):
        def tweak(fn):
            man = json.loads(self.man_path.read_text())
            fn(man)
            p = self.tmp / 'm.json'
            p.write_bytes(sb.manifest_bytes(man))
            with self.assertRaises(sb.BundleError):
                sb.parse_manifest(p.read_bytes())
        tweak(lambda m: m.update(extra=1))
        tweak(lambda m: m.update(schema='rescue-skills-manifest/2'))
        tweak(lambda m: m.update(bundle_version='1.2'))
        tweak(lambda m: m.update(min_toolkit_version='9.0.0'))
        tweak(lambda m: m['files'].reverse())
        tweak(lambda m: m['files'][0].update(path='skills/alpha/../x/SKILL.md'))
        tweak(lambda m: m['files'][0].update(path='skills/alpha/run.sh'))
        tweak(lambda m: m['tarball'].update(name='other.tar.gz'))
        with self.assertRaises(sb.BundleError):
            sb.parse_manifest(b'not json')


class SignersTests(unittest.TestCase):
    KEY = 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UrUYrxcKtZRb2cHUQ+u1ExampleExampleEx'

    def test_repo_file_is_a_placeholder_or_valid_never_invalid(self):
        text = (REPO / 'config' / 'skills-allowed-signers').read_text()
        state, _ = sb.allowed_signers_state(text)
        self.assertIn(state, ('placeholder', 'pinned'))
        if state == 'pinned':
            self.assertNotIn(sb.PLACEHOLDER_MARKER, text)

    def test_states(self):
        entry = f'owner namespaces="rescue-skills" ssh-ed25519 {self.KEY} owner laptop\n'
        self.assertEqual(sb.allowed_signers_state('')[0], 'placeholder')
        self.assertEqual(sb.allowed_signers_state('# only comments\n\n')[0], 'placeholder')
        self.assertEqual(sb.allowed_signers_state(f'# {sb.PLACEHOLDER_MARKER}\n' + entry)[0], 'placeholder')
        state, detail = sb.allowed_signers_state(entry)
        self.assertEqual(state, 'pinned')
        self.assertTrue(detail.startswith('SHA256:'))
        for bad in (f'owner ssh-ed25519 {self.KEY}\n',
                    f'owner namespaces="file" ssh-ed25519 {self.KEY}\n',
                    f'owner namespaces="rescue-skills,file" ssh-ed25519 {self.KEY}\n',
                    f'owner namespaces="rescue-skills" ssh-rsa {self.KEY}\n',
                    entry + 'garbage line\n'):
            self.assertEqual(sb.allowed_signers_state(bad)[0], 'invalid', bad)

    def test_cli_exit_codes(self):
        d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR') or None)
        try:
            f = Path(d) / 'as'
            f.write_text(f'owner namespaces="rescue-skills" ssh-ed25519 {self.KEY}\n')
            run = lambda: subprocess.run([sys.executable, str(BUILD), 'signers-status', '--file', str(f)],  # noqa: E731
                                         capture_output=True, text=True).returncode
            self.assertEqual(run(), 0)
            f.write_text('junk\n')
            self.assertEqual(run(), 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(HAVE_SSH, 'ssh-keygen is not installed')
class SigningTests(TempCase):
    """Real ssh-keygen, throwaway key made inside the test and removed with the temp directory."""

    def setUp(self):
        super().setUp()
        self.keydir = self.tmp / 'keys'
        self.keydir.mkdir(mode=0o700)
        self.key = self.make_key('owner')
        self.tar_path, self.man_path = self.build(self.make_skills(), self.tmp / 'dist')

    def make_key(self, name):
        path = self.keydir / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test-only', '-f', str(path)],
                       check=True, capture_output=True)
        return path

    def pinned_file(self, key, name='allowed'):
        pub = key.with_name(key.name + '.pub').read_text().split()
        p = self.tmp / name
        p.write_text(f'test-owner namespaces="rescue-skills" {pub[0]} {pub[1]}\n')
        return p

    def sign(self, *extra, key=None, env=None):
        return subprocess.run(
            [str(SIGN), '--key', str(key or self.key), '--manifest', str(self.man_path), *extra],
            capture_output=True, text=True, env=env or clean_env())

    def ssh_verify(self, allowed, sig, data, namespace='rescue-skills'):
        return subprocess.run(
            ['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'test-owner', '-n', namespace, '-s', str(sig)],
            input=data, capture_output=True).returncode

    def test_sign_then_verify_passes_and_one_changed_byte_fails(self):
        allowed = self.pinned_file(self.key)
        r = self.sign('--allowed-signers', str(allowed))
        self.assertEqual(r.returncode, 0, r.stderr)
        sig = Path(str(self.man_path) + '.sig')
        data = self.man_path.read_bytes()
        self.assertEqual(self.ssh_verify(allowed, sig, data), 0)
        flipped = bytearray(data)
        flipped[10] ^= 0x01
        self.assertNotEqual(self.ssh_verify(allowed, sig, bytes(flipped)), 0)
        self.assertNotEqual(self.ssh_verify(allowed, sig, data, namespace='file'), 0)
        self.assertNotEqual(self.ssh_verify(allowed, sig, data, namespace='git'), 0)
        other = self.pinned_file(self.make_key('other'), 'other-allowed')
        self.assertNotEqual(self.ssh_verify(other, sig, data), 0)
        self.assertIn('gh release upload v1.2.3', r.stdout)
        self.assertIn(str(sig), r.stdout)

    def test_changed_tarball_byte_breaks_the_signed_manifest_link(self):
        r = self.sign('--allowed-signers', str(self.pinned_file(self.key)))
        self.assertEqual(r.returncode, 0, r.stderr)
        data = bytearray(self.tar_path.read_bytes())
        data[len(data) // 2] ^= 0x01
        self.tar_path.write_bytes(bytes(data))
        with self.assertRaises(sb.BundleError):
            sb.check_bundle(self.man_path, self.tar_path)

    def test_placeholder_state_warns_but_still_signs_with_public_key_readback(self):
        placeholder = REPO / 'config' / 'skills-allowed-signers'
        state, _ = sb.allowed_signers_state(placeholder.read_text())
        if state != 'placeholder':
            self.skipTest('the repository already pins a key')
        r = self.sign()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('not pinned yet', r.stdout)

    def test_refuses_in_ci(self):
        for var in ('CI', 'GITHUB_ACTIONS'):
            with self.subTest(var):
                r = self.sign(env=clean_env(**{var: 'true'}))
                self.assertEqual(r.returncode, 1)
                self.assertIn('refusing to sign in CI', r.stderr)
                self.assertFalse(Path(str(self.man_path) + '.sig').exists())

    def test_requires_explicit_key_and_manifest(self):
        r = subprocess.run([str(SIGN), '--manifest', str(self.man_path)], capture_output=True, text=True, env=clean_env())
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([str(SIGN), '--key', str(self.key)], capture_output=True, text=True, env=clean_env())
        self.assertEqual(r.returncode, 2)
        r = self.sign(key=self.keydir / 'missing')
        self.assertEqual(r.returncode, 1)

    def test_refuses_a_broken_bundle_and_an_existing_signature(self):
        data = bytearray(self.tar_path.read_bytes())
        data[len(data) // 2] ^= 0x01
        self.tar_path.write_bytes(bytes(data))
        r = self.sign()
        self.assertEqual(r.returncode, 1)
        self.assertFalse(Path(str(self.man_path) + '.sig').exists())
        self.tar_path, self.man_path = self.build(self.make_skills(), self.tmp / 'dist2')
        sig = Path(str(self.man_path) + '.sig')
        sig.write_text('keep me')
        r = self.sign()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(sig.read_text(), 'keep me')

    def test_wrong_key_against_the_pinned_file_removes_the_signature(self):
        pinned_to_other = self.pinned_file(self.make_key('other'))
        r = self.sign('--allowed-signers', str(pinned_to_other))
        self.assertEqual(r.returncode, 1)
        self.assertFalse(Path(str(self.man_path) + '.sig').exists())

    def test_key_is_never_printed_copied_or_changed(self):
        before = self.key.read_bytes()
        body = [ln for ln in before.decode().splitlines() if ln and not ln.startswith('-----')]
        r = self.sign('--allowed-signers', str(self.pinned_file(self.key)))
        self.assertEqual(r.returncode, 0, r.stderr)
        for line in body:
            self.assertNotIn(line, r.stdout + r.stderr)
        self.assertEqual(self.key.read_bytes(), before)
        for p in (self.tmp / 'dist').iterdir():
            self.assertNotIn(b'PRIVATE KEY', p.read_bytes())

    def test_public_key_argument_without_agent_fails_cleanly(self):
        # A .pub path means "the private half is in ssh-agent". With no agent and no private file it must
        # fail and leave no signature behind (nothing is guessed or searched for).
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy(self.key.with_name('owner.pub'), lonely / 'owner.pub')
        r = self.sign(key=lonely / 'owner.pub', env=clean_env(SSH_AUTH_SOCK=''))
        self.assertEqual(r.returncode, 1)
        self.assertFalse(Path(str(self.man_path) + '.sig').exists())


class RepositoryRuleTests(unittest.TestCase):
    def test_no_private_key_in_the_repository(self):
        needle = b'-----BEGIN ' + b'OPENSSH PRIVATE KEY-----'
        needle2 = b'-----BEGIN ' + b'PRIVATE KEY-----'
        listing = subprocess.run(['git', '-C', str(REPO), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                                 capture_output=True, check=True).stdout.split(b'\0')
        self.assertGreater(len(listing), 10)
        for rel in filter(None, listing):
            path = REPO / rel.decode()
            if not path.is_file() or path.is_symlink():
                continue
            data = path.read_bytes()
            self.assertNotIn(needle, data, str(path))
            self.assertNotIn(needle2, data, str(path))

    def test_ci_builds_but_never_signs(self):
        for wf in sorted((REPO / '.github' / 'workflows').glob('*.yml')):
            text = wf.read_text()
            self.assertNotIn('ssh-keygen -Y sign', text, wf.name)
            self.assertNotIn('sign-skills-bundle', text, wf.name)
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
        self.assertIn('build-skills-bundle.py', ci)

    def test_make_target_exists(self):
        self.assertRegex((REPO / 'Makefile').read_text(), r'(?m)^skills-bundle:')


if __name__ == '__main__':
    unittest.main()
