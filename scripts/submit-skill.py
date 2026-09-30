#!/usr/bin/env python3
"""Submit a sanitized candidate skill to GitHub Issues, only after operator confirmation.

Usage:
  submit-skill.py --skill PATH/SKILL.md --state-dir DIR [--env-file FILE]... [--dry-run]
                  [--confirm-sha256 HEX]

Contract:
  * The skill must be a SKILL.md under <state-dir>/hermes/skills/ or
    <state-dir>/learning/candidates/. Front matter: name and description only.
  * It is sanitized (hostnames, usernames, paths under /home /Users C:\\Users, serials,
    MAC/IP/e-mail, disk UUIDs become placeholders), then secret-scanned. If the scan still
    finds anything the run is refused (exit 2); nothing is "fixed and sent".
  * The full sanitized issue body, its SHA-256 and the target repository are always shown.
    The hash is embedded as `<!-- skill-sha256: HEX -->`; existing issues (open and closed)
    are searched for that exact marker first. A duplicate prints the existing URL, creates nothing.
  * Confirmation: interactive terminal -> type `kirim` or `submit`. Without a terminal the
    run is refused unless --confirm-sha256 equals the previewed hash (binds the approval to
    exactly the content the operator saw). There is no --yes.
  * RESCUE_GITHUB_ISSUES_TOKEN (fine-grained token, Issues read/write on this repository
    only) comes from the environment, otherwise from the env files, parsed as DATA with the
    rules of scripts/lib/rescue-env.sh. It is only sent in the Authorization header by
    urllib inside this process (HTTPS, api.github.com only, redirects refused); it is never
    on a command line, in output, in logs or in the issue.
  * No token: a pre-filled https://github.com/<repo>/issues/new?... URL is printed
    (or the sanitized body is written 0600 under <state-dir>/reports when it is too long
    for a URL). A browser is never opened.
  * The `skill-candidate` label is applied only if it already exists (an Issues-only token
    cannot create labels); otherwise the issue is created without it and this is reported.
  * Test hook: RESCUE_TEST_GITHUB_BASE_URL is honored only when it is an
    http://127.0.0.1:PORT URL.
  * --dry-run: sanitize, scan, preview; the read-only duplicate check runs only when a
    token is present; nothing is ever created.

Exit codes: 0 submitted, duplicate found, or dry-run ok; 1 local I/O error; 2 refused by the
sanitizer or secret scan (or unusable skill content); 3 no usable token (fallback printed);
4 network or HTTP error; 5 operator declined or confirmation missing/mismatched; 64 usage.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'lib'))
import skill_sanitize as ss  # noqa: E402

REPO = 'ahliweb/linux-mint-xfce-rescue-ai'
API_BASE = 'https://api.github.com'
LABEL = 'skill-candidate'
TOKEN_NAME = 'RESCUE_GITHUB_ISSUES_TOKEN'
OTHER_SECRET_NAMES = ('OPENCODE_GO_API_KEY',)
USER_AGENT = 'rescue-omes-submit-skill/1'
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_URL_CHARS = 7000
TIMEOUT = 30
LIST_PAGES = 3
CONFIRM_WORDS = ('kirim', 'submit')

EXIT_OK, EXIT_IO, EXIT_REFUSED, EXIT_NO_TOKEN, EXIT_NETWORK, EXIT_DECLINED, EXIT_USAGE = 0, 1, 2, 3, 4, 5, 64


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print('submit-skill: %s' % message, file=sys.stderr)
        sys.exit(EXIT_USAGE)


def load_env_reader():
    """Reuse the DATA-only env parser of opencode-go-analyze.py (port of rescue-env.sh)."""
    path = Path(__file__).resolve().with_name('opencode-go-analyze.py')
    spec = importlib.util.spec_from_file_location('rescue_env_reader', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_value(reader, name, env_files):
    value = os.environ.get(name, '')
    if value:
        return value
    reader.KEY_NAME = name
    for path in env_files:
        value = reader.key_from_env_file(path)
        if value:
            return value
    return ''


def token_usable(token):
    return bool(token) and len(token) <= 255 and not re.search(r'[\x00-\x20\x7f]', token)


# ------------------------------------------------------------------ GitHub transport

def resolve_base():
    base = os.environ.get('RESCUE_TEST_GITHUB_BASE_URL', '')
    if base.startswith('http://127.0.0.1:'):
        parsed = urllib.parse.urlsplit(base)
        try:
            port_ok = parsed.port is not None
        except ValueError:
            port_ok = False
        if parsed.hostname == '127.0.0.1' and port_ok and '@' not in parsed.netloc:
            return base.rstrip('/'), True
    return API_BASE, False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(method, path, token, base, loopback, payload=None):
    """One GitHub API call. Returns (status, parsed JSON or None). Raises URLError/HTTPError."""
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Authorization': 'Bearer ' + token,
        'User-Agent': USER_AGENT,
    }
    if data is not None:
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    handlers = [_NoRedirect()]
    if loopback:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(request, timeout=TIMEOUT) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        status = response.status
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('response too large')
    return status, json.loads(raw.decode('utf-8')) if raw.strip() else None


def issue_url(number):
    return 'https://github.com/%s/issues/%d' % (REPO, int(number))


def find_duplicate(sha, token, base, loopback):
    """Return an existing issue number whose body has the exact marker, else None."""
    query = '"skill-sha256: %s" repo:%s in:body is:issue' % (sha, REPO)
    _, found = api('GET', '/search/issues?' + urllib.parse.urlencode({'q': query, 'per_page': 10}),
                   token, base, loopback)
    for item in (found or {}).get('items', []):
        if isinstance(item, dict) and 'pull_request' not in item and ss.has_marker(item.get('body'), sha):
            return int(item['number'])
    # Search indexing lags; also walk the newest issues (open and closed) directly.
    for page in range(1, LIST_PAGES + 1):
        _, items = api('GET', '/repos/%s/issues?state=all&per_page=100&page=%d' % (REPO, page),
                       token, base, loopback)
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if isinstance(item, dict) and 'pull_request' not in item and ss.has_marker(item.get('body'), sha):
                return int(item['number'])
        if len(items) < 100:
            break
    return None


def label_exists(token, base, loopback):
    try:
        api('GET', '/repos/%s/labels/%s' % (REPO, urllib.parse.quote(LABEL)), token, base, loopback)
        return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise


# --------------------------------------------------------------------- issue content

def issue_title(name):
    return 'Skill candidate: %s' % name


def issue_body(prepared):
    canonical = prepared['canonical']
    longest = max([len(m) for m in re.findall(r'`+', canonical)] + [3])
    fence = '`' * max(4, longest + 1)
    return (
        '## Kandidat skill / Candidate skill\n\n'
        'Ini hanya **kandidat**. Promosi ke skill global tetap melalui tes, review, dan PR yang '
        'di-merge; issue ini bukan persetujuan.\n'
        'This is a **candidate** only. Promotion to a global skill still goes through tests, '
        'review, and a merged PR; this issue is not an approval.\n\n'
        '- Disanitasi dan di-scan rahasia oleh `scripts/submit-skill.py`; tanpa data kasus. / '
        'Sanitized and secret-scanned by `scripts/submit-skill.py`; no case data.\n'
        '- SHA-256: `%s`\n\n'
        '%smarkdown\n%s%s\n\n'
        '%s\n' % (prepared['sha256'], fence, canonical.rstrip('\n') + '\n', fence,
                  ss.marker(prepared['sha256'])))


def fallback_url(title, body, with_body=True):
    params = [('title', title)]
    if with_body:
        params.append(('body', body))
    params.append(('labels', LABEL))
    return 'https://github.com/%s/issues/new?%s' % (
        REPO, urllib.parse.urlencode(params, quote_via=urllib.parse.quote))


def write_private(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.skill-', suffix='.tmp', dir=directory)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass  # FAT/exFAT state partitions may reject chmod; mkstemp created it 0600 already
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- main

def is_interactive():
    return sys.stdin.isatty()


def skill_location_ok(skill, state_dir):
    roots = [(state_dir / 'hermes' / 'skills').resolve(), (state_dir / 'learning' / 'candidates').resolve()]
    return skill.name == 'SKILL.md' and any(root in skill.parents for root in roots)


def main(argv=None):
    parser = _Parser(description=__doc__.splitlines()[0])
    parser.add_argument('--skill', required=True, metavar='PATH/SKILL.md')
    parser.add_argument('--state-dir', required=True, metavar='DIR')
    parser.add_argument('--env-file', action='append', default=[], metavar='FILE')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--confirm-sha256', metavar='HEX')
    args = parser.parse_args(argv)

    if args.confirm_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', args.confirm_sha256):
        print('submit-skill: --confirm-sha256 must be 64 lowercase hex characters.', file=sys.stderr)
        return EXIT_USAGE
    state_dir = Path(args.state_dir).resolve()
    skill = Path(args.skill).resolve()
    if not skill_location_ok(skill, state_dir):
        print('submit-skill: --skill must be a SKILL.md under <state-dir>/hermes/skills/ or '
              '<state-dir>/learning/candidates/.\n'
              'submit-skill: --skill harus SKILL.md di bawah <state-dir>/hermes/skills/ atau '
              '<state-dir>/learning/candidates/.', file=sys.stderr)
        return EXIT_USAGE
    try:
        raw = skill.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        print('submit-skill: cannot read skill: %s' % (getattr(exc, 'strerror', None) or 'not valid UTF-8'),
              file=sys.stderr)
        return EXIT_IO

    reader = load_env_reader()
    env_files = list(args.env_file) + [str(state_dir / 'hermes' / 'env'), str(ROOT / 'config' / 'rescue.env')]
    token = find_value(reader, TOKEN_NAME, env_files)
    secret_values = [token] + [find_value(reader, n, env_files) for n in OTHER_SECRET_NAMES]

    try:
        prepared = ss.prepare(raw, secret_values)
    except ss.SecretFound as exc:
        print('submit-skill: REFUSED; the secret scan still found: %s. Nothing was sent or written.\n'
              'submit-skill: DITOLAK; scan rahasia masih menemukan: %s. Tidak ada yang dikirim.'
              % (', '.join(exc.findings), ', '.join(exc.findings)), file=sys.stderr)
        return EXIT_REFUSED
    except ss.SkillError as exc:
        print('submit-skill: REFUSED; %s.\nsubmit-skill: DITOLAK; skill tidak dapat dipakai.' % exc,
              file=sys.stderr)
        return EXIT_REFUSED

    sha = prepared['sha256']
    title = issue_title(prepared['name'])
    body = issue_body(prepared)
    replaced = ', '.join('%s x%d' % kv for kv in sorted(prepared['replacements'].items())) or 'none'

    print('== Preview / Pratinjau (persis yang akan dikirim / exactly what would be sent) ==')
    print('repository: %s' % REPO)
    print('title: %s' % title)
    print('label: %s (only if it exists / hanya jika sudah ada)' % LABEL)
    print('skill_sha256: %s' % sha)
    print('placeholders: %s' % replaced)
    print('-' * 60)
    print(body)
    print('-' * 60)

    usable = token_usable(token)
    if token and not usable:
        print('submit-skill: %s is set but not usable (whitespace/control characters or too long); '
              'ignoring it.' % TOKEN_NAME, file=sys.stderr)
    base, loopback = resolve_base()

    def network_error(exc):
        if isinstance(exc, urllib.error.HTTPError):
            print('GitHub request failed: HTTP %d / permintaan ke GitHub gagal.' % exc.code, file=sys.stderr)
        elif isinstance(exc, (urllib.error.URLError, OSError, TimeoutError)):
            print('GitHub request failed (network/timeout) / permintaan ke GitHub gagal '
                  '(jaringan/timeout).', file=sys.stderr)
        else:
            print('GitHub returned an unusable response / respons GitHub tidak dapat dipakai.',
                  file=sys.stderr)
        return EXIT_NETWORK

    net_errors = (urllib.error.URLError, OSError, TimeoutError, ValueError, KeyError, TypeError)

    if args.dry_run:
        print('DRY RUN: nothing is created / tidak ada issue yang dibuat.')
        if usable:
            try:
                dup = find_duplicate(sha, token, base, loopback)
            except net_errors as exc:
                return network_error(exc)
            if dup:
                print('duplicate: already submitted / sudah pernah dikirim: %s' % issue_url(dup))
            else:
                print('duplicate: none found / tidak ada duplikat.')
        else:
            print('duplicate check skipped: no %s / pengecekan duplikat dilewati: tidak ada token.' % TOKEN_NAME)
        return EXIT_OK

    if not usable:
        return print_fallback(state_dir, sha, title, body)

    try:
        dup = find_duplicate(sha, token, base, loopback)
    except net_errors as exc:
        return network_error(exc)
    if dup:
        print('DUPLICATE: this exact skill was already submitted / skill ini sudah pernah dikirim: %s'
              % issue_url(dup))
        return EXIT_OK

    if args.confirm_sha256 is not None and args.confirm_sha256 != sha:
        print('submit-skill: --confirm-sha256 does not match the previewed hash %s; nothing was sent.\n'
              'submit-skill: --confirm-sha256 tidak cocok dengan hash pratinjau; tidak ada yang dikirim.' % sha,
              file=sys.stderr)
        return EXIT_DECLINED
    if is_interactive():
        try:
            answer = input('Ketik "kirim" atau "submit" untuk mengirim ke %s / type "kirim" or "submit" '
                           'to send (anything else cancels): ' % REPO)
        except EOFError:
            answer = ''
        if answer.strip().lower() not in CONFIRM_WORDS:
            print('Declined; nothing was sent / dibatalkan; tidak ada yang dikirim.')
            return EXIT_DECLINED
    elif args.confirm_sha256 != sha:
        print('No terminal and no matching --confirm-sha256; nothing was sent.\n'
              'Tanpa terminal dan tanpa --confirm-sha256 yang cocok; tidak ada yang dikirim.\n'
              'To confirm exactly this content / untuk mengonfirmasi persis isi ini: '
              'rerun with --confirm-sha256 %s' % sha, file=sys.stderr)
        return EXIT_DECLINED

    try:
        payload = {'title': title, 'body': body}
        if label_exists(token, base, loopback):
            payload['labels'] = [LABEL]
            labelled = True
        else:
            labelled = False
        status, created = api('POST', '/repos/%s/issues' % REPO, token, base, loopback, payload)
        number = int(created['number'])
    except net_errors as exc:
        return network_error(exc)
    print('SUBMITTED / terkirim: %s' % issue_url(number))
    if not labelled:
        print('Note: label "%s" does not exist, so the issue was created without it; a maintainer '
              'should create the label and apply it.\nCatatan: label "%s" belum ada; issue dibuat '
              'tanpa label, maintainer perlu membuat label lalu memasangnya.' % (LABEL, LABEL))
    return EXIT_OK


def print_fallback(state_dir, sha, title, body):
    print('No usable %s; nothing was sent. Open the link yourself after reviewing the preview.\n'
          'Tidak ada %s yang dapat dipakai; tidak ada yang dikirim. Buka tautan sendiri setelah '
          'meninjau pratinjau.' % (TOKEN_NAME, TOKEN_NAME))
    url = fallback_url(title, body)
    if len(url) <= MAX_URL_CHARS:
        print('Pre-filled issue link (not opened automatically) / tautan issue terisi (tidak dibuka otomatis):')
        print(url)
        return EXIT_NO_TOKEN
    path = state_dir / 'reports' / ('skill-candidate-%s.md' % sha[:12])
    try:
        write_private(str(path), body)
    except OSError as exc:
        print('submit-skill: cannot write %s: %s' % (path, exc.strerror or exc), file=sys.stderr)
        return EXIT_IO
    print('The body is too long for a URL. The sanitized body was saved (mode 0600) to:\n  %s\n'
          'Open the link below, then paste that file\'s content as the issue body.\n'
          'Isi terlalu panjang untuk URL. Isi yang sudah disanitasi disimpan ke berkas di atas; '
          'buka tautan di bawah lalu tempel isi berkas sebagai isi issue.' % path)
    print(fallback_url(title, body, with_body=False))
    return EXIT_NO_TOKEN


if __name__ == '__main__':
    sys.exit(main())
