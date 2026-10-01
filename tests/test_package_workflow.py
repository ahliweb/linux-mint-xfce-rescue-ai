"""Static checks for .github/workflows/package.yml (stdlib only, text based).

The workflow publishes credential-free packages to ghcr.io. These tests pin the
properties that keep it safe: only GITHUB_TOKEN, least privilege, pinned
actions, no publishing on pull requests, and a credential-free build.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'package.yml'
PR_GATE = "if: github.event_name != 'pull_request'"


def split_jobs(text):
    """Return {job name: block text} for the top-level `jobs:` mapping."""
    _, _, tail = text.partition('\njobs:\n')
    jobs, name, buf = {}, None, []
    for line in tail.splitlines():
        match = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if match:
            if name:
                jobs[name] = '\n'.join(buf)
            name, buf = match.group(1), []
        elif name:
            buf.append(line)
    if name:
        jobs[name] = '\n'.join(buf)
    return jobs


class PackageWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding='utf-8')
        cls.jobs = split_jobs(cls.text)

    def test_expected_jobs_exist(self):
        self.assertEqual(set(self.jobs), {'bundle', 'bundle-publish', 'persistence', 'persistence-publish',
                                          'hermes-portable-linux', 'hermes-portable-windows'})

    def test_triggers(self):
        head = self.text.split('\npermissions:', 1)[0]
        self.assertRegex(head, r'(?m)^on:\n  push:\n    tags: \["v\*"\]')
        self.assertIn('workflow_dispatch:', head)
        self.assertRegex(head, r'(?s)workflow_dispatch:.*?tag:.*?required: true')
        for path in ('.github/workflows/package.yml', 'scripts/build-persistence.sh',
                     'scripts/lib/persistence-container-build.sh', 'scripts/prepare-ventoy-usb.sh',
                     'scripts/build-hermes-portable.py',
                     'scripts/verify-mint-iso.sh', 'Makefile'):
            self.assertIn('- "%s"' % path, head)
        self.assertRegex(head, r'(?m)^  pull_request:\n    paths:')

    def test_only_github_token_secret(self):
        refs = re.findall(r'secrets\.([A-Za-z0-9_]+)', self.text)
        self.assertTrue(refs, 'the workflow should use GITHUB_TOKEN to publish')
        self.assertEqual(set(refs), {'GITHUB_TOKEN'})
        self.assertNotIn('secrets[', self.text)
        self.assertNotRegex(self.text, r'secrets:\s*inherit')
        self.assertNotRegex(self.text, r'OPENCODE_GO_API_KEY=[A-Za-z0-9]')

    def test_build_passes_no_provision_secrets(self):
        build_lines = [l for l in self.text.splitlines() if 'build-persistence.sh' in l and not l.lstrip().startswith('#')]
        self.assertTrue(build_lines)
        block = self.jobs['persistence']
        call = re.search(r'\./scripts/build-persistence\.sh(?:[^\n]*\\\n)*[^\n]*', block)
        self.assertIsNotNone(call)
        self.assertIn('--no-provision-secrets', call.group(0))
        self.assertNotIn('--env-file', block)

    def test_every_uses_is_pinned_to_a_full_sha(self):
        uses = re.findall(r'(?m)^\s*-?\s*uses:\s*(\S+)(.*)$', self.text)
        self.assertTrue(uses)
        for ref, rest in uses:
            with self.subTest(ref=ref):
                self.assertRegex(ref, r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$')
                self.assertRegex(rest, r'#\s*v\d+\.\d+\.\d+', 'pinned action needs a version comment')

    def test_top_level_permissions_are_read_only(self):
        match = re.search(r'(?m)^permissions:\n((?:  .+\n)+)', self.text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1).strip(), 'contents: read')

    def test_write_permissions_only_on_publish_jobs_gated_off_for_pull_requests(self):
        for name, block in self.jobs.items():
            writes = re.findall(r'(?m)^\s+(contents|packages): write', block)
            publishes = name.endswith('-publish')
            with self.subTest(job=name):
                if publishes:
                    self.assertIn(PR_GATE, block)
                    self.assertIn('packages: write', block)
                    self.assertNotIn('id-token', block)
                else:
                    self.assertEqual(writes, [], 'build jobs must stay read-only')
                # Anything that pushes or releases lives only in a gated job.
                for marker in ('oras push', 'oras login', 'gh release'):
                    if marker in block:
                        self.assertTrue(publishes and PR_GATE in block, marker)
        self.assertNotIn('packages: write', self.jobs['bundle'] + self.jobs['persistence'])

    def test_artifact_upload_is_gated_off_for_pull_requests(self):
        for name in ('bundle', 'persistence', 'hermes-portable-linux', 'hermes-portable-windows'):
            block = self.jobs[name]
            step = block.split('actions/upload-artifact@', 1)[0].rsplit('- name:', 1)[1]
            self.assertIn(PR_GATE, step, name)

    def test_pull_request_persistence_skips_compression(self):
        block = self.jobs['persistence']
        self.assertRegex(block, r"if \[\[ \$IS_PR == true \]\]; then[\s\S]*?exit 0\n\s+fi\n\s+zstd ")

    def test_ref_and_version_handling(self):
        self.assertIn("github.event.pull_request.head.sha", self.text)
        self.assertIn("refs/tags/{0}", self.text)
        self.assertIn('inputs.tag', self.text)
        self.assertIn('persist-credentials: false', self.text)
        self.assertIn('Tag $tag does not match VERSION $version', self.text)
        # The tag is validated before use and only reaches the shell through env.
        self.assertNotRegex(self.text, r'run:[^\n]*\$\{\{\s*inputs\.tag')
        self.assertNotRegex(self.text, r'(?m)^\s+(echo|oras|gh|curl)[^\n]*\$\{\{\s*(inputs|github\.ref_name|github\.head_ref)')

    def test_iso_verification_is_pinned_and_never_skipped(self):
        self.assertIn('27DEB15644C6B3CF3BD7D291300F846BA25BAE09', self.text)
        self.assertIn('scripts/verify-mint-iso.sh', self.text)
        self.assertIn('--signer-fingerprint', self.text)
        self.assertIn('--gpg-homedir', self.text)
        self.assertIn('https://mirrors.kernel.org/linuxmint/stable/22.3', self.text)
        verify = self.text.index('verify-mint-iso.sh')
        build = self.text.index('./scripts/build-persistence.sh')
        self.assertLess(verify, build)
        self.assertNotRegex(self.text, r'continue-on-error:\s*true')

    def test_credential_free_assertion_precedes_publishing(self):
        block = self.jobs['persistence']
        self.assertIn('debugfs', block)
        self.assertIn('OPENCODE_GO_API_KEY', block)
        self.assertLess(block.index('debugfs -R'), block.index('zstd -T0'))
        publish = self.jobs['persistence-publish']
        self.assertIn('application/vnd.ahliweb.rescue-omes.persistence.v1', publish)
        self.assertIn('org.ahliweb.rescue-omes.credential-free=true', publish)
        self.assertIn('org.ahliweb.rescue-omes.dat.sha256', publish)

    def test_bundle_publish_details(self):
        publish = self.jobs['bundle-publish']
        self.assertIn('application/vnd.ahliweb.rescue-omes.bundle.v1', publish)
        for key in ('source', 'version', 'revision', 'description', 'licenses'):
            self.assertIn('org.opencontainers.image.%s=' % key, publish)
        self.assertIn('--clobber', publish)
        self.assertIn('--password-stdin', publish)
        self.assertNotRegex(publish, r'--password[ =](?!-stdin)')
        self.assertIn('${GITHUB_REPOSITORY,,}', publish)

    def test_bundle_is_deterministic_and_checked(self):
        block = self.jobs['bundle']
        for needle in ('--sort=name', '--owner=0', '--group=0', '--numeric-owner', 'gzip -n',
                       '--mtime="@$EPOCH"', '--bundle-only', 'RESCUE-WINDOWS.cmd',
                       'RESCUE-MACOS.command', 'rescue-linux.sh', 'sha256sum'):
            self.assertIn(needle, block)

    def test_portable_hermes_jobs(self):
        for name, runner, plat, archive, entry in (
                ('hermes-portable-linux', 'ubuntu-24.04', 'linux-x86_64',
                 'rescue-omes-hermes-portable-linux-x86_64.tar.gz', 'python/bin/python3'),
                ('hermes-portable-windows', 'windows-2022', 'windows-x86_64',
                 'rescue-omes-hermes-portable-windows-x86_64.zip', 'python/python.exe')):
            block = self.jobs[name]
            with self.subTest(job=name):
                self.assertIn('runs-on: %s' % runner, block)
                self.assertIn('--platform %s' % plat, block)
                self.assertRegex(block, r'build-hermes-portable\.py --platform %s --out [^\n]*--archive' % plat)
                for needle in ('--check-archive', '--extract-archive', '--scan-tree', '--verify-tree',
                               'hermes_cli.main --version', 'chat --cli --help', 'HERMES_HOME=', archive + '.sha256',
                               entry):
                    self.assertIn(needle, block)
                # read-only build job, no token, no publishing, artifact only outside pull requests
                self.assertRegex(block, r'(?m)^    permissions:\n      contents: read\n')
                self.assertNotIn('write', block.split('steps:', 1)[0])
                self.assertNotRegex(block, r'secrets\.|GITHUB_TOKEN|GH_TOKEN')
                for marker in ('oras ', 'gh release', 'docker login'):
                    self.assertNotIn(marker, block)
                self.assertIn('name: hermes-portable-%s' % name.rsplit('-', 1)[1], block)
                # smoke test and credential scan happen before the upload
                self.assertLess(block.index('--scan-tree'), block.index('actions/upload-artifact@'))
                self.assertLess(block.index('--version'), block.index('actions/upload-artifact@'))

    def test_uv_is_bootstrapped_from_a_pinned_hashed_wheel_without_new_actions(self):
        for name, wheel in (('hermes-portable-linux', 'manylinux'), ('hermes-portable-windows', 'win_amd64')):
            block = self.jobs[name]
            with self.subTest(job=name):
                self.assertRegex(block, r'uv==\d+\.\d+\.\d+ --hash=sha256:[0-9a-f]{64}')
                self.assertIn('--require-hashes', block)
                self.assertIn('--only-binary :all:', block)
        used = set(re.findall(r'uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@', self.text))
        self.assertEqual(used, {'actions/checkout', 'actions/upload-artifact', 'actions/download-artifact',
                                'oras-project/setup-oras'})

    def test_release_publish_attaches_both_portable_archives(self):
        publish = self.jobs['bundle-publish']
        self.assertIn(PR_GATE, publish)
        needs = re.search(r'(?m)^    needs: \[([^\]]*)\]', publish)
        self.assertIsNotNone(needs)
        self.assertEqual({n.strip() for n in needs.group(1).split(',')},
                         {'bundle', 'hermes-portable-linux', 'hermes-portable-windows'})
        self.assertIn('pattern: hermes-portable-*', publish)
        upload = re.search(r'gh release upload[\s\S]*?(?=\n          \{)', publish)
        self.assertIsNotNone(upload)
        for asset in ('rescue-omes-hermes-portable-linux-x86_64.tar.gz', 'rescue-omes-hermes-portable-linux-x86_64.tar.gz.sha256',
                      'rescue-omes-hermes-portable-windows-x86_64.zip', 'rescue-omes-hermes-portable-windows-x86_64.zip.sha256'):
            self.assertIn(asset, upload.group(0))
            if asset.endswith('.sha256'):
                self.assertIn('sha256sum --check ' + asset, publish)
        # the portable archives are Release assets only: no OCI package is pushed for them
        self.assertNotIn('hermes-portable', publish.split('oras push', 1)[1].split('oras tag', 1)[0])

    def test_runner_disk_cleanup_is_present(self):
        block = self.jobs['persistence']
        for path in ('/usr/share/dotnet', '/usr/local/lib/android', '/opt/ghc', '/opt/hostedtoolcache/CodeQL'):
            self.assertIn(path, block)
        self.assertIn('docker system prune -af', block)
        self.assertIn('timeout-minutes: 120', block)


if __name__ == '__main__':
    unittest.main()
