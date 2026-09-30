#!/usr/bin/env python3
"""Offline tests for candidate-skill submission (scripts/submit-skill.py, scripts/lib/skill_sanitize.py).

No real network: GitHub is a fake http.server on 127.0.0.1 reached through the test-only
RESCUE_TEST_GITHUB_BASE_URL hook. Secret-looking strings are assembled at runtime and the
dummy token has no real-secret prefix. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import http.server
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'scripts' / 'submit-skill.py'
sys.path.insert(0, str(REPO / 'scripts' / 'lib'))
import skill_sanitize as ss  # noqa: E402

DUMMY_TOKEN = 'dummy-issues-token-value'
DEAD_BASE = 'http://127.0.0.1:9'
GOOD_BODY = (
    '# Diagnose a dirty NTFS volume\n\n'
    '1. Read the saved evidence and note `windows-ntfs-dirty`.\n'
    '2. Ask the operator to shut Windows down fully; never run repair tools from Linux.\n'
    '3. Verify by read-back after the operator restarts Windows.\n')


def skill_text(body=GOOD_BODY, name='ntfs-dirty-volume', description='Guide a read-only check of a dirty NTFS volume.'):
    return '---\nname: %s\ndescription: %s\n---\n\n%s' % (name, description, body)


def load_submit():
    spec = importlib.util.spec_from_file_location('submit_skill_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeGitHub:
    """Minimal GitHub Issues API: search, list, label lookup, create. Records requests."""

    def __init__(self, label_exists=True, search_lag=False, fail_create=False):
        self.label_exists = label_exists
        self.search_lag = search_lag
        self.fail_create = fail_create
        self.issues = []
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _record(self, body=None):
                outer.requests.append({'method': self.command, 'path': self.path,
                                       'auth': self.headers.get('Authorization'), 'body': body})

            def do_GET(self):
                self._record()
                url = urllib.parse.urlsplit(self.path)
                if url.path == '/search/issues':
                    items = [] if outer.search_lag else list(outer.issues)
                    self._send(200, {'items': items})
                elif url.path == '/repos/ahliweb/linux-mint-xfce-rescue-ai/issues':
                    page = int(urllib.parse.parse_qs(url.query).get('page', ['1'])[0])
                    self._send(200, list(outer.issues) if page == 1 else [])
                elif url.path == '/repos/ahliweb/linux-mint-xfce-rescue-ai/labels/skill-candidate':
                    self._send(200 if outer.label_exists else 404, {'name': 'skill-candidate'})
                else:
                    self._send(404, {})

            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                body = json.loads(self.rfile.read(length).decode())
                self._record(body)
                if outer.fail_create:
                    self._send(500, {'message': 'boom'})
                    return
                number = 100 + len(outer.issues)
                outer.issues.append({'number': number, 'body': body['body'], 'title': body['title']})
                self._send(201, {'number': number, 'html_url': 'https://example.invalid/%d' % number})

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def posts(self):
        return [r for r in self.requests if r['method'] == 'POST']


class SanitizerTests(unittest.TestCase):
    def sanitize(self, text):
        return ss.sanitize_text(text)[0]

    def test_paths_are_replaced(self):
        out = self.sanitize('see /home/budi/Documents/x.txt and /Users/Ana/Library and C:\\Users\\Ana\\Desktop\\f.doc ok')
        self.assertNotIn('budi', out)
        self.assertNotIn('Ana', out)
        self.assertEqual(out.count('<PATH>'), 3)

    def test_removable_media_paths(self):
        out = self.sanitize('mounted at /run/media/budi/MYDISK and /media/budi/DATA now')
        self.assertNotIn('budi', out)
        self.assertNotIn('MYDISK', out)

    def test_email_ip_mac_uuid(self):
        text = ('mail budi@example.com from 192.168.1.20 and fe80:0:0:0:1:2:3:4 mac aa:bb:cc:dd:ee:ff '
                'uuid 123e4567-e89b-12d3-a456-426614174000 fat 1A2B-3C4D')
        out = self.sanitize(text)
        for leaked in ('budi', '192.168', 'fe80', 'aa:bb', '123e4567', '1A2B'):
            self.assertNotIn(leaked, out)
        for placeholder in ('<EMAIL>', '<IP>', '<MAC>', '<UUID>'):
            self.assertIn(placeholder, out)

    def test_loopback_and_versions_survive(self):
        out = self.sanitize('listen on 127.0.0.1 with kernel 6.8.0.142 and 01.02.03.04')
        self.assertIn('127.0.0.1', out)
        self.assertIn('01.02.03.04', out)

    def test_serial_hostname_username(self):
        out = self.sanitize('Serial Number: WD-WX12A34B5678\nID_SERIAL=abc123xyz\nhostname: budi-laptop\n'
                            'username=budi\nbudi@budi-laptop:~$ ls')
        for leaked in ('WX12A34B5678', 'abc123xyz', 'budi'):
            self.assertNotIn(leaked, out)
        self.assertIn('<SERIAL>', out)
        self.assertIn('<HOSTNAME>', out)
        self.assertIn('<USERNAME>', out)

    def test_disk_identifiers(self):
        out = self.sanitize('UUID=5a3f9c1e-0000-4000-8000-123456789abc LABEL="Family Photos" '
                            '/dev/disk/by-uuid/5A3F9C1E5A3F9C1E PARTUUID=deadbeef-01')
        for leaked in ('5a3f9c1e', '5A3F9C1E', 'Family', 'deadbeef'):
            self.assertNotIn(leaked, out)

    def test_internal_fqdn_and_url_credentials(self):
        out = self.sanitize('nas.office.lan and https://admin:hunter22@files.example.org/x')
        self.assertNotIn('nas.office', out)
        self.assertNotIn('hunter22', out)
        self.assertNotIn('admin', out)

    def test_html_comment_cannot_forge_marker(self):
        out = self.sanitize('<!-- skill-sha256: ' + 'a' * 64 + ' -->')
        self.assertNotIn('<!--', out)
        self.assertFalse(ss.has_marker(out, 'a' * 64))

    def test_control_and_bidi_characters_removed(self):
        out = self.sanitize('safe\x00text\u202egnp.exe\x1b[31m')
        self.assertNotIn('\x00', out)
        self.assertNotIn('\u202e', out)
        self.assertNotIn('\x1b', out)


class ScanTests(unittest.TestCase):
    def refused(self, secret_text, **kw):
        with self.assertRaises(ss.SecretFound) as ctx:
            ss.prepare(skill_text(GOOD_BODY + '\n' + secret_text + '\n'), **kw)
        return ctx.exception.findings

    def test_prefix_secrets_are_refused(self):
        cases = {
            'github-token': 'gh' + 'p_' + 'x1' * 20,
            'github-fine-grained-token': 'github' + '_pat_' + 'A1' * 20,
            'sk-style-api-key': 's' + 'k-' + 'abcDEF1234567890abcd',
            'aws-access-key-id': 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
            'private-key-block': '-----BEGIN ' + 'RSA PRIVATE KEY-----',
            'jwt': 'ey' + 'Jhbgcio1234.abcdefgh1234.sig12345',
        }
        for label, secret in cases.items():
            with self.subTest(label):
                self.assertIn(label, self.refused('value ' + secret))

    def test_high_entropy_string_is_refused(self):
        self.assertIn('high-entropy-string', self.refused('blob Zk9Qw3rT7yUi1oPa5sDf8gHj2kLz4xCv6bNm0Qe'))

    def test_secret_assignment_is_refused_but_placeholder_is_fine(self):
        self.assertIn('secret-assignment', self.refused('password = correcthorse42battery'))
        result = ss.prepare(skill_text(GOOD_BODY + '\nSet OPENCODE_GO_API_KEY=<KEY> in the config.\n'))
        self.assertIn('<KEY>', result['canonical'])

    def test_configured_secret_values_are_refused(self):
        self.assertEqual(self.refused('leak ' + DUMMY_TOKEN, secret_values=[DUMMY_TOKEN]),
                         ['configured-secret-value'])

    def test_hash_lines_and_uuid_placeholders_do_not_trip_the_scan(self):
        body = GOOD_BODY + '\nsha256 ' + '0123456789abcdef' * 4 + ' at /home/budi/x uuid 123e4567-e89b-12d3-a456-426614174000\n'
        result = ss.prepare(skill_text(body))
        self.assertNotIn('budi', result['canonical'])


class PrepareTests(unittest.TestCase):
    def test_hash_is_stable_across_formatting_noise(self):
        a = ss.prepare(skill_text())
        b = ss.prepare(skill_text().replace('\n', '  \r\n'))
        self.assertEqual(a['sha256'], b['sha256'])
        self.assertRegex(a['sha256'], r'^[0-9a-f]{64}$')

    def test_hash_changes_with_content_and_covers_sanitized_text(self):
        a = ss.prepare(skill_text())
        b = ss.prepare(skill_text(GOOD_BODY + '4. One more read-only check.\n'))
        self.assertNotEqual(a['sha256'], b['sha256'])
        c = ss.prepare(skill_text(GOOD_BODY + 'host 10.0.0.5\n'))
        d = ss.prepare(skill_text(GOOD_BODY + 'host 10.9.9.9\n'))
        self.assertEqual(c['sha256'], d['sha256'])  # identical after sanitizing
        self.assertEqual(c['replacements'], {'IP': 1})

    def test_front_matter_validation(self):
        bad = [
            'no front matter here, just a long enough body text',
            skill_text(name='Bad Name'),
            skill_text(name='ab'),
            skill_text(description=''),
            '---\nname: good-name\ndescription: ok\nowner: budi\n---\n\n' + GOOD_BODY,
            '---\nname: good-name\ndescription: ok\n---\n\nshort',
            skill_text(GOOD_BODY + 'x' * (ss.MAX_BODY_BYTES + 1)),
        ]
        for text in bad:
            with self.subTest(text[:40]):
                with self.assertRaises(ss.SkillError):
                    ss.prepare(text)

    def test_description_is_sanitized_too(self):
        result = ss.prepare(skill_text(description='Fix for budi@example.com disk at /home/budi/x'))
        self.assertNotIn('budi', result['canonical'])

    def test_marker_helpers(self):
        sha = 'b' * 64
        self.assertEqual(ss.marker(sha), '<!-- skill-sha256: %s -->' % sha)
        self.assertTrue(ss.has_marker('text\n' + ss.marker(sha) + '\n', sha))
        self.assertFalse(ss.has_marker('quoted ' + ss.marker(sha), sha))
        self.assertFalse(ss.has_marker(None, sha))

    def test_issue_body_contains_marker_hash_template_and_safe_fence(self):
        module = load_submit()
        prepared = ss.prepare(skill_text(GOOD_BODY + '\n````\ninner fence\n````\n'))
        body = module.issue_body(prepared)
        self.assertTrue(ss.has_marker(body, prepared['sha256']))
        self.assertIn(prepared['sha256'], body)
        self.assertIn('merged PR', body)
        self.assertIn('`````markdown', body)  # fence longer than the body's longest backtick run


class CliBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        self.skill_dir = self.state / 'learning' / 'candidates' / 'ntfs-dirty-volume'
        self.skill_dir.mkdir(parents=True)
        self.skill = self.skill_dir / 'SKILL.md'
        self.skill.write_text(skill_text(), encoding='utf-8')
        self.expected_sha = ss.prepare(skill_text())['sha256']

    def run_cli(self, *extra, base=DEAD_BASE, token=None, skill=None, env_extra=None, state=None):
        env = {k: v for k, v in os.environ.items()
               if k not in ('RESCUE_GITHUB_ISSUES_TOKEN', 'OPENCODE_GO_API_KEY')}
        env['RESCUE_TEST_GITHUB_BASE_URL'] = base
        if token:
            env['RESCUE_GITHUB_ISSUES_TOKEN'] = token
        env.update(env_extra or {})
        argv = [sys.executable, str(SCRIPT), '--state-dir', str(state or self.state),
                '--skill', str(skill or self.skill)] + list(extra)
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)
        return proc, argv


class DryRunAndRefusalTests(CliBase):
    def test_dry_run_without_token_previews_and_skips_dedupe(self):
        proc, _ = self.run_cli('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(self.expected_sha, proc.stdout)
        self.assertIn('ahliweb/linux-mint-xfce-rescue-ai', proc.stdout)
        self.assertIn('skill-sha256: %s' % self.expected_sha, proc.stdout)
        self.assertIn('duplicate check skipped', proc.stdout)

    def test_dry_run_with_token_checks_duplicates_and_never_creates(self):
        with FakeGitHub() as gh:
            proc, _ = self.run_cli('--dry-run', base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('none found', proc.stdout)
            self.assertEqual(gh.posts(), [])
            self.assertTrue(gh.requests)

    def test_secret_in_skill_is_refused_with_exit_2_and_not_echoed(self):
        secret = 'gh' + 'p_' + 'z9' * 20
        self.skill.write_text(skill_text(GOOD_BODY + '\nkey ' + secret + '\n'), encoding='utf-8')
        proc, _ = self.run_cli('--dry-run')
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(secret, proc.stdout + proc.stderr)
        self.assertIn('github-token', proc.stderr)

    def test_configured_token_value_in_skill_is_refused(self):
        self.skill.write_text(skill_text(GOOD_BODY + '\nleaked ' + DUMMY_TOKEN + '\n'), encoding='utf-8')
        proc, _ = self.run_cli('--dry-run', token=DUMMY_TOKEN)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(DUMMY_TOKEN, proc.stdout + proc.stderr)

    def test_skill_outside_allowed_directories_is_usage_error(self):
        other = self.state / 'elsewhere'
        other.mkdir()
        (other / 'SKILL.md').write_text(skill_text(), encoding='utf-8')
        proc, _ = self.run_cli('--dry-run', skill=other / 'SKILL.md')
        self.assertEqual(proc.returncode, 64)

    def test_usage_error_exit_64(self):
        proc = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 64)

    def test_bad_confirm_hash_format_is_usage_error(self):
        proc, _ = self.run_cli('--confirm-sha256', 'nothex')
        self.assertEqual(proc.returncode, 64)

    def test_sanitized_output_has_no_case_data(self):
        self.skill.write_text(skill_text(GOOD_BODY + '\nDisk at /home/budi/x on 192.168.1.9 owned by budi@example.com\n'),
                              encoding='utf-8')
        proc, _ = self.run_cli('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for leaked in ('budi', '192.168.1.9', 'example.com'):
            self.assertNotIn(leaked, proc.stdout)


class FallbackTests(CliBase):
    def test_no_token_prints_prefilled_url_exit_3(self):
        proc, _ = self.run_cli()
        self.assertEqual(proc.returncode, 3)
        urls = [l for l in proc.stdout.splitlines() if l.startswith('https://github.com/')]
        self.assertEqual(len(urls), 1)
        url = urls[0]
        self.assertTrue(url.startswith('https://github.com/ahliweb/linux-mint-xfce-rescue-ai/issues/new?'))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(query['labels'], ['skill-candidate'])
        self.assertEqual(query['title'], ['Skill candidate: ntfs-dirty-volume'])
        self.assertIn('skill-sha256: %s' % self.expected_sha, query['body'][0])
        self.assertLessEqual(len(url), load_submit().MAX_URL_CHARS)

    def test_long_body_is_saved_private_and_url_has_no_body(self):
        long_body = GOOD_BODY + ''.join('- check number %d of the read-only list\n' % i for i in range(400))
        self.skill.write_text(skill_text(long_body), encoding='utf-8')
        sha = ss.prepare(skill_text(long_body))['sha256']
        proc, _ = self.run_cli()
        self.assertEqual(proc.returncode, 3, proc.stderr)
        saved = self.state / 'reports' / ('skill-candidate-%s.md' % sha[:12])
        self.assertTrue(saved.is_file())
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
        self.assertIn('skill-sha256: %s' % sha, saved.read_text(encoding='utf-8'))
        urls = [l for l in proc.stdout.splitlines() if l.startswith('https://github.com/')]
        self.assertEqual(len(urls), 1)
        self.assertNotIn('body=', urls[0])
        self.assertIn('labels=skill-candidate', urls[0])

    def test_unusable_token_falls_back(self):
        proc, _ = self.run_cli(token='has space')
        self.assertEqual(proc.returncode, 3)
        self.assertNotIn('has space', proc.stdout + proc.stderr)


class SubmitTests(CliBase):
    def test_confirmed_submission_creates_labelled_issue_and_hides_token(self):
        with FakeGitHub() as gh:
            proc, argv = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('https://github.com/ahliweb/linux-mint-xfce-rescue-ai/issues/100', proc.stdout)
            posts = gh.posts()
            self.assertEqual(len(posts), 1)
            payload = posts[0]['body']
            self.assertEqual(payload['labels'], ['skill-candidate'])
            self.assertTrue(ss.has_marker(payload['body'], self.expected_sha))
            self.assertEqual(posts[0]['auth'], 'Bearer ' + DUMMY_TOKEN)
            self.assertNotIn(DUMMY_TOKEN, proc.stdout + proc.stderr)
            self.assertNotIn(DUMMY_TOKEN, ' '.join(argv))
            self.assertNotIn(DUMMY_TOKEN, payload['body'] + payload['title'])

    def test_missing_label_creates_issue_without_it_and_says_so(self):
        with FakeGitHub(label_exists=False) as gh:
            proc, _ = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn('labels', gh.posts()[0]['body'])
            self.assertIn('label "skill-candidate" does not exist', proc.stdout)

    def test_non_tty_without_confirmation_is_declined(self):
        with FakeGitHub() as gh:
            proc, _ = self.run_cli(base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 5)
            self.assertIn(self.expected_sha, proc.stderr)
            self.assertEqual(gh.posts(), [])

    def test_confirmation_bound_to_hash(self):
        with FakeGitHub() as gh:
            proc, _ = self.run_cli('--confirm-sha256', '0' * 64, base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(gh.posts(), [])

    def test_duplicate_prints_existing_url_and_does_not_create(self):
        for lag in (False, True):  # found via search, and via the direct listing when search lags
            with self.subTest(search_lag=lag), FakeGitHub(search_lag=lag) as gh:
                gh.issues.append({'number': 7, 'body': 'earlier\n' + ss.marker(self.expected_sha) + '\n'})
                proc, _ = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base, token=DUMMY_TOKEN)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn('issues/7', proc.stdout)
                self.assertEqual(gh.posts(), [])

    def test_partial_or_quoted_marker_is_not_a_duplicate(self):
        with FakeGitHub() as gh:
            gh.issues.append({'number': 8, 'body': 'see ' + ss.marker(self.expected_sha) + ' quoted inline'})
            proc, _ = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(gh.posts()), 1)

    def test_http_error_exit_4_without_leaking_token(self):
        with FakeGitHub(fail_create=True) as gh:
            proc, _ = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base, token=DUMMY_TOKEN)
            self.assertEqual(proc.returncode, 4)
            self.assertIn('HTTP 500', proc.stderr)
            self.assertNotIn(DUMMY_TOKEN, proc.stdout + proc.stderr)

    def test_unreachable_server_exit_4(self):
        proc, _ = self.run_cli('--confirm-sha256', self.expected_sha, base=DEAD_BASE, token=DUMMY_TOKEN)
        self.assertEqual(proc.returncode, 4)

    def test_token_from_env_file_parsed_as_data(self):
        env_file = self.state / 'hermes' / 'env'
        env_file.parent.mkdir(parents=True)
        env_file.write_text("RESCUE_GITHUB_ISSUES_TOKEN='%s'\nOTHER=$(touch %s/pwned)\n" % (DUMMY_TOKEN, self.state))
        env_file.chmod(0o600)
        with FakeGitHub() as gh:
            proc, argv = self.run_cli('--confirm-sha256', self.expected_sha, base=gh.base)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(gh.posts()[0]['auth'], 'Bearer ' + DUMMY_TOKEN)
            self.assertNotIn(DUMMY_TOKEN, ' '.join(argv))
            self.assertFalse((self.state / 'pwned').exists())

    def test_non_loopback_override_is_ignored(self):
        module = load_submit()
        for value in ('https://evil.example', 'http://127.0.0.1@evil.example:80', 'http://localhost:1234', ''):
            with self.subTest(value), mock.patch.dict(os.environ, {'RESCUE_TEST_GITHUB_BASE_URL': value}):
                self.assertEqual(module.resolve_base(), ('https://api.github.com', False))

    def test_interactive_confirmation_words(self):
        module = load_submit()
        for answer, expected in (('kirim', 0), ('SUBMIT', 0), ('no', 5), ('', 5)):
            with self.subTest(answer), FakeGitHub() as gh:
                env = {'RESCUE_TEST_GITHUB_BASE_URL': gh.base, 'RESCUE_GITHUB_ISSUES_TOKEN': DUMMY_TOKEN}
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.dict(os.environ, env), mock.patch.object(module, 'is_interactive', return_value=True), \
                        mock.patch('builtins.input', return_value=answer), redirect_stdout(out), redirect_stderr(err):
                    code = module.main(['--state-dir', str(self.state), '--skill', str(self.skill)])
                self.assertEqual(code, expected, err.getvalue())
                self.assertEqual(len(gh.posts()), 1 if expected == 0 else 0)
                self.assertNotIn(DUMMY_TOKEN, out.getvalue() + err.getvalue())


class StaticTests(unittest.TestCase):
    def test_no_subprocess_or_browser_and_token_only_in_header(self):
        for path in (SCRIPT, REPO / 'scripts' / 'lib' / 'skill_sanitize.py'):
            text = path.read_text(encoding='utf-8')
            self.assertNotRegex(text, r'\b(subprocess|webbrowser|os\.system|eval|exec)\b\s*[.(]')
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertIn("API_BASE = 'https://api.github.com'", text)
        self.assertNotIn('argv', re.sub(r'#.*', '', text).split('def api')[1].split('def issue_url')[0])

    def test_launcher_keeps_the_issues_token_out_of_the_hermes_environment(self):
        # rescue_load_env exports allowlisted keys; Hermes must not inherit the GitHub token.
        text = (REPO / 'scripts' / 'launch-hermes-rescue.sh').read_text(encoding='utf-8')
        unset_at = text.index('unset RESCUE_GITHUB_ISSUES_TOKEN')
        self.assertLess(unset_at, text.index('exec hermes'))
        self.assertLess(text.rindex('rescue_load_env'), unset_at)


class RescueEnvTests(unittest.TestCase):
    def test_rescue_env_accepts_the_new_key_and_still_ignores_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / 'rescue.env'
            env_file.write_text("RESCUE_GITHUB_ISSUES_TOKEN='%s'\nNOT_ALLOWED=1\n" % DUMMY_TOKEN)
            env_file.chmod(0o600)
            script = ('source "$1"; rescue_load_env "$2"; printf "%s|%s" "${RESCUE_GITHUB_ISSUES_TOKEN-}" "${NOT_ALLOWED-}"')
            env = {k: v for k, v in os.environ.items() if k != 'RESCUE_GITHUB_ISSUES_TOKEN'}
            proc = subprocess.run(['bash', '-c', script, 'bash', str(REPO / 'scripts/lib/rescue-env.sh'), str(env_file)],
                                  capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, DUMMY_TOKEN + '|')

    def test_example_config_documents_the_key_empty(self):
        text = (REPO / 'config' / 'rescue.env.example').read_text(encoding='utf-8')
        self.assertIn("RESCUE_GITHUB_ISSUES_TOKEN=''", text)

    def test_skill_file_has_matching_front_matter(self):
        text = (REPO / 'profiles/rescue-hermes/skills/rescue-skill-submission/SKILL.md').read_text(encoding='utf-8')
        self.assertTrue(text.startswith('---\nname: rescue-skill-submission\ndescription: '))
        self.assertIn('--dry-run', text)
        self.assertIn('--confirm-sha256', text)


if __name__ == '__main__':
    unittest.main()
