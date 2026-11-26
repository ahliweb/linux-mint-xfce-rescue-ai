#!/usr/bin/env python3
"""Tests for the verified skill updater (scripts/update-skills.py, scripts/lib/skills_update.py).

No real network: a loopback HTTP server plays the release host. Signing keys exist only inside these tests
(throwaway ed25519 keys in a temporary directory that is removed afterwards).
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import http.server
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
import skills_bundle as sb  # noqa: E402
import skills_update as su  # noqa: E402

HAVE_SSH = shutil.which('ssh-keygen') is not None
CLI = REPO / 'scripts' / 'update-skills.py'
REPO_PATH = f'/{su.SOURCE_REPO}'


def skill(name, body='Body.\n'):
    return f'---\nname: {name}\ndescription: Test skill {name}.\n---\n\n{body}'.encode()


class FakeRelease:
    """Loopback release host. routes: {path: (status, bytes[, headers])}; `requests` records every path asked for."""

    def __init__(self):
        self.routes = {}
        self.requests = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                owner.requests.append(self.path)
                route = owner.routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                status, body = route[0], route[1]
                headers = route[2] if len(route) > 2 else {}
                if headers.get('X-Sleep'):
                    time.sleep(float(headers['X-Sleep']))
                self.send_response(status)
                for k, v in headers.items():
                    if k != 'X-Sleep':
                        self.send_header(k, v)
                if 'Content-Length' not in headers:
                    self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def fetcher(self, **kw):
        return su.Fetcher(api_base=self.base, download_base=self.base, environ={}, **kw)

    def publish(self, version, manifest, sig, tarball, tag=None, assets=True):
        tag = tag or f'v{version}'
        release = {'tag_name': tag, 'draft': False, 'prerelease': False}
        if assets:
            release['assets'] = [{'name': n} for n in (
                f'rescue-skills-{version}.tar.gz', f'rescue-skills-{version}.manifest.json',
                f'rescue-skills-{version}.manifest.json.sig')]
        self.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'] = (200, json.dumps(release).encode())
        base = f'{REPO_PATH}/releases/download/{tag}/rescue-skills-{version}'
        self.routes[f'{base}.manifest.json'] = (200, manifest)
        self.routes[f'{base}.manifest.json.sig'] = (200, sig)
        self.routes[f'{base}.tar.gz'] = (200, tarball)


@unittest.skipUnless(HAVE_SSH, 'ssh-keygen is not installed')
class UpdaterCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or None)
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.key = self.make_key('owner')
        self.other_key = self.make_key('other')
        self.release = FakeRelease()
        self.addCleanup(self.release.close)
        # toolkit root 1.0.0 shipping alpha and beta
        self.root = self.tmp / 'toolkit'
        (self.root / 'config').mkdir(parents=True)
        (self.root / 'VERSION').write_text('1.0.0\n')
        for n in ('alpha', 'beta'):
            (self.root / 'profiles/rescue-hermes/skills' / n).mkdir(parents=True)
            (self.root / 'profiles/rescue-hermes/skills' / n / 'SKILL.md').write_bytes(skill(n, 'Bundled.\n'))
        self.set_signers(self.key)
        # Hermes home seeded with the bundled skills (what every launcher does)
        self.hh = self.tmp / 'hermes'
        for n in ('alpha', 'beta'):
            (self.hh / 'skills' / n).mkdir(parents=True)
            (self.hh / 'skills' / n / 'SKILL.md').write_bytes(skill(n, 'Bundled.\n'))
        self.reports = self.tmp / 'reports'

    # -- helpers
    def make_key(self, name):
        path = self.tmp / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test-only', '-f', str(path)], check=True)
        return path

    def pub(self, key):
        return Path(f'{key}.pub').read_text().split()

    def set_signers(self, *keys, text=None):
        lines = [f'{"owner"} namespaces="rescue-skills" {self.pub(k)[0]} {self.pub(k)[1]}' for k in keys]
        (self.root / 'config' / 'skills-allowed-signers').write_text(text if text is not None else '\n'.join(lines) + '\n')

    def fingerprint(self, key):
        return sb.fingerprint(self.pub(key)[1])

    def sign(self, manifest_bytes, key=None, namespace='rescue-skills'):
        d = Path(tempfile.mkdtemp(dir=self.tmp))
        (d / 'm.json').write_bytes(manifest_bytes)
        subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-f', str(key or self.key), '-n', namespace, str(d / 'm.json')], check=True)
        return (d / 'm.json.sig').read_bytes()

    def build(self, version='1.2.0', names=('alpha', 'beta'), body='Updated.\n', min_toolkit='1.0.0'):
        src = Path(tempfile.mkdtemp(dir=self.tmp))
        for n in names:
            (src / n).mkdir()
            (src / n / 'SKILL.md').write_bytes(skill(n, body))
        out = Path(tempfile.mkdtemp(dir=self.tmp))
        tar_path, man_path = sb.build(src, version, min_toolkit, out)
        return man_path.read_bytes(), tar_path.read_bytes()

    def serve(self, version='1.2.0', **kw):
        manifest, tarball = self.build(version, **{k: v for k, v in kw.items() if k in ('names', 'body', 'min_toolkit')})
        sig = self.sign(manifest)
        self.release.publish(version, manifest, sig, tarball)
        return manifest, sig, tarball

    def run_update(self, **kw):
        kw.setdefault('fetcher', self.release.fetcher())
        kw.setdefault('environ', {})
        return su.run_update(self.root, self.hh, self.reports, **kw)

    def text(self, name):
        return (self.hh / 'skills' / name / 'SKILL.md').read_bytes()

    def assert_untouched(self):
        for n in ('alpha', 'beta'):
            self.assertEqual(self.text(n), skill(n, 'Bundled.\n'), n)
        self.assertFalse((self.hh / 'skill-update' / 'state.json').exists())

    def journal(self):
        return [json.loads(x) for x in (self.reports / su.JOURNAL_NAME).read_text().splitlines()]


class TestInstall(UpdaterCase):
    def test_newer_signed_bundle_is_installed_and_recorded(self):
        self.serve('1.2.0')
        (self.hh / 'skills' / 'alpha' / 'extra.json').write_text('{}')   # not skill text: must stay
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('updated', 'updated'), r.message)
        self.assertEqual(r.bundle_version, '1.2.0')
        self.assertEqual(r.signer, self.fingerprint(self.key))
        for n in ('alpha', 'beta'):
            self.assertEqual(self.text(n), skill(n, 'Updated.\n'))
        self.assertTrue((self.hh / 'skills' / 'alpha' / 'extra.json').exists())
        self.assertIn('1.2.0', r.message)
        self.assertIn(self.fingerprint(self.key), r.message)
        entry = self.journal()[-1]
        self.assertEqual((entry['status'], entry['bundle_version'], entry['signer'], entry['skills']),
                         ('updated', '1.2.0', self.fingerprint(self.key), 2))
        self.assertEqual(oct((self.reports / su.JOURNAL_NAME).stat().st_mode & 0o777), '0o600')
        # the toolkit's own (fallback) skills were not touched
        self.assertEqual((self.root / 'profiles/rescue-hermes/skills/alpha/SKILL.md').read_bytes(), skill('alpha', 'Bundled.\n'))
        self.assertEqual(list((self.hh / 'skills').glob('**/.*.new')) + list((self.hh / 'skills').glob('**/*.new')), [])

    def test_second_run_is_current_and_reseed_is_reinstalled(self):
        self.serve('1.2.0')
        self.assertEqual(self.run_update().reason, 'updated')
        self.assertEqual(self.run_update().reason, 'current')
        # a launcher re-seeds the bundled text: same signed version is installed again, not refused
        (self.hh / 'skills' / 'alpha' / 'SKILL.md').write_bytes(skill('alpha', 'Bundled.\n'))
        self.assertEqual(self.run_update().reason, 'updated')
        self.assertEqual(self.text('alpha'), skill('alpha', 'Updated.\n'))

    def test_only_skills_the_toolkit_ships_are_written(self):
        self.serve('1.2.0', names=('alpha', 'gamma'))
        r = self.run_update()
        self.assertEqual(r.reason, 'updated')
        self.assertEqual(r.skills, 1)
        self.assertEqual(r.skipped_names, ['gamma'])
        self.assertFalse((self.hh / 'skills' / 'gamma').exists())
        self.assertEqual(self.text('beta'), skill('beta', 'Bundled.\n'))

    def test_failure_midway_restores_every_file(self):
        self.serve('1.2.0')
        calls = {'n': 0}
        real = su._write_atomic

        def flaky(path, data):
            calls['n'] += 1
            if calls['n'] == 2:
                raise OSError('disk full')
            return real(path, data)
        su._write_atomic = flaky
        self.addCleanup(setattr, su, '_write_atomic', real)
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('failed', 'install-error'))
        self.assert_untouched()


class TestRejections(UpdaterCase):
    def assert_refused(self, r, reason, status='refused'):
        self.assertEqual((r.status, r.reason), (status, reason), r.message)
        self.assert_untouched()
        self.assertEqual(self.journal()[-1]['reason'], reason)
        self.assertFalse(r.ok if status in ('refused', 'failed') else not r.ok)

    def test_bad_signature_garbage(self):
        manifest, _sig, tarball = self.serve()
        self.release.publish('1.2.0', manifest, b'-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n', tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_signature_missing_header(self):
        manifest, _sig, tarball = self.serve()
        self.release.publish('1.2.0', manifest, b'not a signature', tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_wrong_namespace(self):
        manifest, tarball = self.build()
        self.release.publish('1.2.0', manifest, self.sign(manifest, namespace='file'), tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_unpinned_key(self):
        manifest, tarball = self.build()
        self.release.publish('1.2.0', manifest, self.sign(manifest, key=self.other_key), tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_signature_of_another_manifest(self):
        manifest, tarball = self.build()
        other, _ = self.build('1.3.0')
        self.release.publish('1.2.0', manifest, self.sign(other), tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_changed_byte_in_manifest(self):
        manifest, sig, tarball = self.serve()
        tampered = manifest.replace(b'"min_toolkit_version": "1.0.0"', b'"min_toolkit_version": "0.0.1"')
        self.assertNotEqual(tampered, manifest)
        self.release.publish('1.2.0', tampered, sig, tarball)
        self.assert_refused(self.run_update(), 'bad-signature')

    def test_changed_byte_in_tarball(self):
        manifest, sig, tarball = self.serve()
        evil = bytearray(tarball)
        evil[len(evil) // 2] ^= 0x01
        self.release.publish('1.2.0', manifest, sig, bytes(evil))
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_tarball_with_other_content_of_the_same_size(self):
        manifest, sig, _tarball = self.serve()
        _m2, tar2 = self.build(body='Evil!!!\n')
        self.release.publish('1.2.0', manifest, sig, tar2)
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_equal_version_is_not_newer(self):
        self.serve('1.0.0')
        self.assert_refused(self.run_update(), 'not-newer', status='current')

    def test_older_version_is_not_newer(self):
        self.serve('0.9.0', min_toolkit='0.9.0')
        self.assert_refused(self.run_update(), 'not-newer', status='current')

    def test_rollback_below_the_installed_version(self):
        self.serve('1.5.0')
        self.assertEqual(self.run_update().reason, 'updated')
        self.serve('1.2.0')
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('refused', 'rollback'))
        self.assertEqual(self.text('alpha'), skill('alpha', 'Updated.\n'))
        # a launcher re-seed does not lower the high-water mark either
        (self.hh / 'skills' / 'alpha' / 'SKILL.md').write_bytes(skill('alpha', 'Bundled.\n'))
        self.assertEqual(self.run_update().reason, 'rollback')

    def test_toolkit_too_old(self):
        self.serve('1.2.0', min_toolkit='1.1.0')
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('skipped', 'toolkit-too-old'))
        self.assertIn('1.1.0', r.message)
        self.assert_untouched()

    def test_manifest_version_differs_from_release(self):
        manifest, tarball = self.build('1.3.0')
        self.release.publish('1.2.0', manifest, self.sign(manifest), tarball)   # served under v1.2.0, says 1.3.0
        self.assert_refused(self.run_update(), 'version-mismatch')

    def signed_custom(self, members, files_entries=None):
        """Sign a hand-made manifest and serve the matching hand-made tarball (the 'attacker has the key' shape)."""
        raw = io.BytesIO()
        import gzip
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for info, data in members:
                    tar.addfile(info, io.BytesIO(data) if data is not None else None)
        tarball = raw.getvalue()
        entries = files_entries
        if entries is None:
            entries = [{'path': i.name, 'sha256': sb.sha256_hex(d), 'size': len(d)} for i, d in members if d is not None]
        doc = {'schema': sb.SCHEMA, 'bundle_version': '1.2.0', 'min_toolkit_version': '1.0.0',
               'tarball': {'name': 'rescue-skills-1.2.0.tar.gz', 'sha256': sb.sha256_hex(tarball), 'size': len(tarball)},
               'files': entries}
        manifest = sb.manifest_bytes(doc)
        self.release.publish('1.2.0', manifest, self.sign(manifest), tarball)

    @staticmethod
    def member(name, size=0, mode=0o644, type_=tarfile.REGTYPE, linkname=''):
        info = tarfile.TarInfo(name)
        info.size = size
        info.mode = mode
        info.type = type_
        info.linkname = linkname
        return info

    def test_path_outside_skills_name_skill_md_in_manifest(self):
        data = skill('alpha')
        for bad in ('skills/../escape/SKILL.md', '/etc/passwd', 'scripts/evil.py', 'skills/alpha/extra.sh', 'skills/alpha/../SKILL.md'):
            self.signed_custom([(self.member(bad, len(data)), data)])
            self.assert_refused(self.run_update(), 'bad-manifest')

    def test_extra_member_in_tarball_not_in_manifest(self):
        data = skill('alpha')
        evil = b'#!/bin/sh\n'
        entries = [{'path': 'skills/alpha/SKILL.md', 'sha256': sb.sha256_hex(data), 'size': len(data)}]
        self.signed_custom([(self.member('skills/alpha/SKILL.md', len(data)), data),
                            (self.member('skills/alpha/run.sh', len(evil)), evil)], entries)
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_symlink_member_in_tarball(self):
        data = skill('alpha')
        entries = [{'path': 'skills/alpha/SKILL.md', 'sha256': sb.sha256_hex(data), 'size': len(data)}]
        self.signed_custom([(self.member('skills/alpha/SKILL.md', type_=tarfile.SYMTYPE, linkname='/etc/passwd'), None)], entries)
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_executable_member_in_tarball(self):
        data = skill('alpha')
        self.signed_custom([(self.member('skills/alpha/SKILL.md', len(data), mode=0o755), data)])
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_oversized_file_in_manifest(self):
        big = skill('alpha', 'x' * (sb.MAX_FILE_BYTES + 10))
        self.signed_custom([(self.member('skills/alpha/SKILL.md', len(big)), big)])
        self.assert_refused(self.run_update(), 'bad-manifest')

    def test_oversized_tarball_download(self):
        manifest, sig, tarball = self.serve()
        self.release.publish('1.2.0', manifest, sig, tarball + b'0' * 5000)
        self.assert_refused(self.run_update(), 'too-large')

    def test_oversized_manifest(self):
        self.serve()
        base = f'{REPO_PATH}/releases/download/v1.2.0/rescue-skills-1.2.0'
        self.release.routes[f'{base}.manifest.json'] = (200, b'{' + b' ' * (sb.MAX_MANIFEST_BYTES + 10))
        self.assert_refused(self.run_update(), 'too-large')

    def test_skill_without_valid_frontmatter(self):
        bad = b'no frontmatter\n'
        self.signed_custom([(self.member('skills/alpha/SKILL.md', len(bad)), bad)])
        self.assert_refused(self.run_update(), 'bad-bundle')

    def test_symlinked_skill_folder_in_hermes_home_is_refused(self):
        self.serve()
        shutil.rmtree(self.hh / 'skills' / 'beta')
        outside = self.tmp / 'outside'
        outside.mkdir()
        (self.hh / 'skills' / 'beta').symlink_to(outside, target_is_directory=True)
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('refused', 'unsafe-target'))
        self.assertEqual(self.text('alpha'), skill('alpha', 'Bundled.\n'))   # nothing was written before the check
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_skill_file_is_refused(self):
        self.serve()
        outside = self.tmp / 'victim.md'
        outside.write_text('victim')
        (self.hh / 'skills' / 'alpha' / 'SKILL.md').unlink()
        (self.hh / 'skills' / 'alpha' / 'SKILL.md').symlink_to(outside)
        r = self.run_update()
        self.assertEqual(r.reason, 'unsafe-target')
        self.assertEqual(outside.read_text(), 'victim')

    def test_placeholder_signers_make_no_request(self):
        self.serve()
        self.set_signers(text=(REPO / 'config' / 'skills-allowed-signers').read_text())
        self.assert_refused(self.run_update(), 'placeholder-signers')
        self.assertEqual(self.release.requests, [])

    def test_invalid_signers_make_no_request(self):
        self.serve()
        for text in ('owner namespaces="*" ssh-ed25519 AAAA\n', 'garbage line\n', 'owner ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA\n'):
            self.set_signers(text=text)
            self.assert_refused(self.run_update(), 'invalid-signers')
        self.assertEqual(self.release.requests, [])

    def test_missing_signers_file(self):
        self.serve()
        (self.root / 'config' / 'skills-allowed-signers').unlink()
        self.assert_refused(self.run_update(), 'invalid-signers')

    def test_downloaded_signers_are_never_used(self):
        manifest, tarball = self.build()
        self.release.publish('1.2.0', manifest, self.sign(manifest, key=self.other_key), tarball)
        base = f'{REPO_PATH}/releases/download/v1.2.0/'
        self.release.routes[base + 'skills-allowed-signers'] = (200, f'owner namespaces="rescue-skills" {self.pub(self.other_key)[0]} {self.pub(self.other_key)[1]}\n'.encode())
        self.assert_refused(self.run_update(), 'bad-signature')
        self.assertFalse(any('allowed-signers' in p for p in self.release.requests))

    def test_no_ssh_keygen_is_skipped_with_a_reason(self):
        self.serve()
        old = os.environ.get('PATH', '')
        os.environ['PATH'] = str(self.tmp / 'nowhere')
        self.addCleanup(os.environ.__setitem__, 'PATH', old)
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('skipped', 'no-ssh-keygen'))
        self.assertIn('ssh-keygen', r.message)
        self.assert_untouched()
        self.assertEqual(self.release.requests, [])

    def test_bad_release_documents(self):
        latest = f'/repos/{su.SOURCE_REPO}/releases/latest'
        for body in (b'not json', b'[]', json.dumps({'tag_name': '1.2.0'}).encode(),
                     json.dumps({'tag_name': 'v1.2'}).encode(), json.dumps({'tag_name': 'v1.2.0', 'draft': True}).encode(),
                     json.dumps({'tag_name': 'v1.2.0', 'prerelease': True}).encode(),
                     json.dumps({'tag_name': 'v../../x'}).encode()):
            self.release.routes[latest] = (200, body)
            self.assert_refused(self.run_update(), 'bad-release')

    def test_release_without_bundle_assets(self):
        manifest, tarball = self.build()
        self.release.publish('1.2.0', manifest, self.sign(manifest), tarball, assets=False)
        self.release.routes.pop(f'{REPO_PATH}/releases/download/v1.2.0/rescue-skills-1.2.0.manifest.json')
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('skipped', 'no-bundle'))
        self.assert_untouched()
        self.release.publish('1.2.0', manifest, self.sign(manifest), tarball)
        latest = json.loads(self.release.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'][1])
        latest['assets'] = [{'name': 'other.zip'}]
        self.release.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'] = (200, json.dumps(latest).encode())
        self.assertEqual(self.run_update().reason, 'no-bundle')

    def test_state_file_corrupt_refuses(self):
        self.serve()
        (self.hh / 'skill-update').mkdir()
        (self.hh / 'skill-update' / 'state.json').write_text('{"schema": "x"}')
        self.assert_refused_state()

    def assert_refused_state(self):
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('refused', 'state-invalid'))
        self.assertEqual(self.text('alpha'), skill('alpha', 'Bundled.\n'))


class TestNetworkAndSwitch(UpdaterCase):
    def test_connection_refused_is_offline_and_fast(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        base = f'http://127.0.0.1:{port}'
        start = time.monotonic()
        r = self.run_update(fetcher=su.Fetcher(api_base=base, download_base=base, environ={}))
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual((r.status, r.reason), ('offline', 'offline'))
        self.assertTrue(r.ok)           # startup continues
        self.assert_untouched()

    def test_slow_server_times_out_within_the_budget(self):
        self.release.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'] = (200, b'{}', {'X-Sleep': '3'})
        start = time.monotonic()
        r = self.run_update(fetcher=self.release.fetcher(timeout=0.5, budget=2))
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(r.reason, 'offline')
        self.assert_untouched()

    def test_api_error_status(self):
        self.release.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'] = (500, b'oops')
        r = self.run_update()
        self.assertEqual((r.status, r.reason), ('offline', 'http-error'))
        self.assert_untouched()
        self.release.routes[f'/repos/{su.SOURCE_REPO}/releases/latest'] = (403, b'rate limited')
        self.assertEqual(self.run_update().reason, 'http-error')

    def test_offline_flag_makes_no_request(self):
        self.serve()
        r = self.run_update(offline=True)
        self.assertEqual(r.status, 'offline')
        self.assertEqual(self.release.requests, [])

    def test_off_makes_no_request_and_no_state(self):
        self.serve()
        for kw in ({'mode': 'off'}, {'environ': {'RESCUE_SKILLS_UPDATE': 'off'}}):
            r = self.run_update(**kw)
            self.assertEqual((r.status, r.reason), ('skipped', 'disabled'))
        (self.root / 'config' / 'rescue.env').write_text("OPENCODE_GO_API_KEY=''\nRESCUE_SKILLS_UPDATE='off'\n")
        self.assertEqual(self.run_update().reason, 'disabled')
        self.assertEqual(self.release.requests, [])
        self.assert_untouched()

    def test_default_is_auto_and_invalid_value_is_skipped(self):
        self.serve()
        self.assertEqual(su.read_mode(self.root, None, {}), 'auto')
        self.assertEqual(self.run_update(environ={'RESCUE_SKILLS_UPDATE': 'AUTO'}).reason, 'updated')
        self.assertEqual(su.read_mode(self.root, None, {'RESCUE_SKILLS_UPDATE': 'sometimes'}), 'invalid')
        r = self.run_update(environ={'RESCUE_SKILLS_UPDATE': 'sometimes'})
        self.assertEqual((r.status, r.reason), ('skipped', 'config-invalid'))

    def test_url_rules(self):
        su._check_url('https://api.github.com/x')
        su._check_url('http://127.0.0.1:1/x')
        for bad in ('http://api.github.com/x', 'ftp://example.com/x', 'file:///etc/passwd', 'https://user:pw@github.com/x',
                    'https:///x', 'http://example.com/x'):
            with self.assertRaises(su.Stop, msg=bad):
                su._check_url(bad)
        self.assertEqual(su.Fetcher().api_base, 'https://api.github.com')

    def test_redirect_to_other_host_is_refused(self):
        h = su._SafeRedirect()
        with self.assertRaises(su.Stop):
            h.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/x')
        with self.assertRaises(su.Stop):
            h.redirect_request(None, None, 302, 'Found', {}, 'http://objects.githubusercontent.com/x')
        with self.assertRaises(su.Stop):
            h.redirect_request(None, None, 302, 'Found', {}, 'https://notgithub.com/x')

    def test_proxy_environment_is_filtered(self):
        self.assertIsNone(su._safe_proxy({}))
        self.assertIsNone(su._safe_proxy({'HTTPS_PROXY': 'socks5://127.0.0.1:1080'}))
        self.assertIsNone(su._safe_proxy({'HTTPS_PROXY': 'javascript:alert(1)'}))
        self.assertEqual(su._safe_proxy({'https_proxy': 'http://proxy.local:3128'}), 'http://proxy.local:3128')

    def test_journal_has_closed_fields_and_no_paths(self):
        self.serve()
        self.run_update()
        raw = (self.reports / su.JOURNAL_NAME).read_text()
        self.assertNotIn(str(self.tmp), raw)
        self.assertEqual(set(json.loads(raw.splitlines()[0])), {
            'schema', 'at', 'status', 'reason', 'toolkit_version', 'installed_version', 'bundle_version', 'signer', 'skills'})


class TestCli(UpdaterCase):
    def cli(self, *extra, env_extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith('RESCUE_')}
        env.update(env_extra or {})
        return subprocess.run([sys.executable, '-I', str(CLI), '--toolkit-root', str(self.root), '--hermes-home', str(self.hh),
                               '--reports-dir', str(self.reports), *extra], capture_output=True, text=True, env=env, timeout=60)

    def test_cli_updates_and_prints_the_operator_message(self):
        self.serve()
        r = self.cli('--release-api-base', self.release.base, '--release-download-base', self.release.base)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Skill Hermes diperbarui ke versi 1.2.0', r.stdout)
        self.assertEqual(self.text('alpha'), skill('alpha', 'Updated.\n'))
        j = self.cli('--json', '--release-api-base', self.release.base, '--release-download-base', self.release.base)
        self.assertEqual(json.loads(j.stdout)['reason'], 'current')

    def test_cli_refusal_exit_code_and_message(self):
        manifest, tarball = self.build()
        self.release.publish('1.2.0', manifest, self.sign(manifest, key=self.other_key), tarball)
        r = self.cli('--release-api-base', self.release.base, '--release-download-base', self.release.base)
        self.assertEqual(r.returncode, 1)
        self.assertIn('DITOLAK', r.stdout)
        self.assert_untouched()

    def test_cli_off_and_offline(self):
        self.serve()
        r = self.cli('--mode', 'off', '--release-api-base', self.release.base, '--release-download-base', self.release.base)
        self.assertEqual((r.returncode, self.release.requests), (0, []))
        r = self.cli('--offline')
        self.assertEqual(r.returncode, 0)
        self.assertIn('tidak ada jaringan', r.stdout)

    def test_cli_env_off(self):
        self.serve()
        r = self.cli('--release-api-base', self.release.base, '--release-download-base', self.release.base,
                     env_extra={'RESCUE_SKILLS_UPDATE': 'off'})
        self.assertIn('dimatikan', r.stdout)
        self.assertEqual(self.release.requests, [])

    def test_shipped_signers_file_is_still_a_placeholder_and_the_cli_refuses_it(self):
        shutil.copy(REPO / 'config' / 'skills-allowed-signers', self.root / 'config' / 'skills-allowed-signers')
        r = self.cli()
        self.assertEqual(r.returncode, 1)
        self.assertIn('placeholder', r.stdout)

    def test_cli_requires_hermes_home(self):
        r = subprocess.run([sys.executable, '-I', str(CLI)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


class TestWiring(unittest.TestCase):
    """Static checks that every distribution path carries the pinned file and every launcher calls the updater."""

    def read(self, rel):
        return (REPO / rel).read_text(encoding='utf-8')

    def test_pinned_signers_reach_usb_image_and_installed_bundle(self):
        self.assertIn('"config/skills-allowed-signers"', self.read('scripts/prepare-ventoy-usb.sh'))
        installer = self.read('scripts/install-hermes-rescue.sh')
        self.assertIn('config/skills-allowed-signers', installer)

    def test_launchers_call_the_updater_before_hermes(self):
        live = self.read('scripts/launch-hermes-rescue.sh')
        self.assertIn('update-skills.py', live)
        self.assertLess(live.index('update-skills.py'), live.index('opencode-go-analyze.py'))
        self.assertIn('--offline', live)
        host = self.read('host/rescue-linux.sh')
        self.assertIn('update-skills.py', host)
        self.assertLess(host.index('seed_hermes_home "$hh"'), host.index('update-skills.py'))
        win = self.read('host/rescue-windows.ps1')
        self.assertIn('update-skills.py', win)
        self.assertLess(win.index('Initialize-HermesHome -Bundle $Bundle -Launch $launch'), win.index('Invoke-SkillUpdate -Bundle $Bundle -Reports'))

    def test_no_launcher_passes_a_trust_override(self):
        for rel in ('scripts/launch-hermes-rescue.sh', 'host/rescue-linux.sh', 'host/rescue-windows.ps1',
                    'host/RESCUE-MACOS.command'):
            text = self.read(rel)
            for opt in ('--allowed-signers', '--release-api-base', '--release-download-base'):
                self.assertNotIn(opt, text, rel)

    def test_updater_only_writes_skill_md(self):
        code = self.read('scripts/lib/skills_update.py')
        for banned in ('subprocess.run([sys.executable', 'exec(', 'eval(', 'os.system', 'shell=True', 'extractall', 'pip '):
            self.assertNotIn(banned, code)
        self.assertEqual(code.count('subprocess.run('), 1)   # only ssh-keygen verify

    def test_container_build_requires_all_eleven_skills(self):
        build = self.read('scripts/lib/persistence-container-build.sh')
        names = sorted(p.parent.name for p in (REPO / 'profiles/rescue-hermes/skills').glob('*/SKILL.md'))
        self.assertEqual(len(names), 11)
        for n in names:
            self.assertIn(n, build.split('for required in', 1)[1].split('; do', 1)[0], n)


if __name__ == '__main__':
    unittest.main()
