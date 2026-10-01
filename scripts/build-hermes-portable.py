#!/usr/bin/env python3
"""Build the portable, credential-free Hermes Agent runtime for the rescue USB.

Layout (a fixed contract; host launchers depend on it):

    DIR/<platform>/python/        relocatable CPython (python-build-standalone via
                                  uv) with Hermes and its dependencies installed in
                                  that interpreter's own site-packages (no venv, no
                                  symlinks)
    DIR/<platform>/MANIFEST.json  platform, hermes_ref, hermes_version,
                                  python_version, built_at, file_count,
                                  total_bytes, tree_sha256

Entry points (run from the USB, nothing is installed on the host):

    linux-x86_64    python/bin/python3 -m hermes_cli.main
    windows-x86_64  python\\python.exe -m hermes_cli.main

Modes:
    build (default)        --platform P --hermes-ref SHA --out DIR [--archive]
    --verify-tree DIR      recompute the tree hash of a <platform> directory and
                           compare it with its MANIFEST.json
    --scan-tree DIR        credential-free / symlink / exFAT-name self-check of a <platform> directory
    --check-archive FILE   validate an archive (paths, types, platform) only
    --extract-archive FILE --dest DIR
                           validate, unpack into DIR/<platform> and read back

Standard library only. The build never embeds credentials: the child processes
get an allowlisted environment and the result is scanned for secret-shaped
strings, credential file names and the build machine's own paths.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import platform as platform_mod
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

# Upstream NousResearch/hermes-agent commit this build was tested with.
HERMES_REF = '178c23fb27c3c5ded9f6a3e096203c60cee6f235'  # v0.20.6; later main locks Python >=3.14 only
HERMES_URL = 'https://github.com/NousResearch/hermes-agent'
DEFAULT_PYTHON = '3.11'
PYTHON_CHOICES = ('3.11', '3.12')
PLATFORMS = ('linux-x86_64', 'windows-x86_64')
ARCHIVE_PREFIX = 'rescue-omes-hermes-portable-'
MANIFEST_NAME = 'MANIFEST.json'
HEX40 = re.compile(r'^[0-9a-f]{40}$')

# exFAT/Windows: names must avoid these; the full path stays under MAX_PATH-ish
# limits once the USB path (about 60 chars) is prepended on a Windows host.
INVALID_NAME_CHARS = re.compile(r'[\x00-\x1f"*:<>?\\|]')
RESERVED_NAMES = re.compile(r'^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$', re.I)
MAX_NAME = 200
MAX_REL_PATH = 190

# Credential-looking file names that must never ship.
FORBIDDEN_NAMES = ('rescue.env', 'auth.json')
# Same token shapes as scripts/check-docs.py (prefixes concatenated so this file
# is not itself a hit). Applied to bytes, so compiled files are covered too.
SECRET_PATTERNS = [
    ('GitHub token', re.compile(('gh' + r'[pousr]_[A-Za-z0-9]{30,}').encode())),
    ('GitHub fine-grained token', re.compile(('github' + r'_pat_[A-Za-z0-9_]{20,}').encode())),
    ('API key (sk- style)', re.compile((r'\bsk' + r'-[A-Za-z0-9_-]{20,}').encode())),
    ('AWS access key id', re.compile((r'\bAK' + r'IA[0-9A-Z]{16}\b').encode())),
    ('private key block', re.compile(('-----BEGIN [A-Z ]*PRIV' + 'ATE KEY-----').encode())),
    ('JWT', re.compile((r'\bey' + r'J[A-Za-z0-9_-]{8,}\.ey' + r'J[A-Za-z0-9_-]{8,}\.').encode())),
]
# Precise allowlist for verified false positives in the shipped files. Each
# entry: (path regex relative to the platform dir, finding label, regex the WHOLE
# matched value must fullmatch). Reviewed against the first real build:
#   - Hermes' skill guides show `Bearer sk-xxxxxxxxxxxxxxxxxxxx` placeholders.
#   - agent/redact.py (a secret REDACTOR) documents `sk-proj-abcdef1234567890`
#     and quotes the RSA private key header in a comment.
#   - cryptography's ssh.py holds the OpenSSH key header as a parsing constant.
#   - PyJWT's METADATA shows the public jwt.io example token
#     (header {"alg":"HS256","typ":"JWT"}, payload {"some":"payload"}).
# The compiled .pyc of those exact modules carry the same strings.
SECRET_ALLOWLIST = [
    (r'^python/hermes-agent/(?:skills|optional-skills)/.+\.md$', 'API key (sk- style)', r'sk-[xX]+'),
    (r'^python/hermes-agent/agent/(?:__pycache__/)?redact\.(?:py|cpython-3\d+\.pyc)$',
     'API key (sk- style)', r'sk-proj-abcdef1234567890'),
    (r'^python/hermes-agent/agent/(?:__pycache__/)?redact\.(?:py|cpython-3\d+\.pyc)$',
     'private key block', r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    (r'^python/(?:lib/python3\.\d+|Lib)/site-packages/cryptography/hazmat/primitives/serialization/'
     r'(?:__pycache__/)?ssh\.(?:py|cpython-3\d+\.pyc)$',
     'private key block', r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    (r'^python/(?:lib/python3\.\d+|Lib)/site-packages/pyjwt-[0-9.]+\.dist-info/METADATA$', 'JWT',
     r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzb21lIjoicGF5bG9hZCJ9\.'),
]

# Directories removed from the interpreter to save space; none is imported by
# `hermes chat --cli` (the smoke test imports the CLI afterwards).
STDLIB_STRIP = ('test', 'idlelib', 'turtledemo')

ENV_KEEP = ('PATH', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'SystemDrive', 'COMSPEC', 'PATHEXT',
            'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL', 'LOCALAPPDATA', 'APPDATA',
            'GIT_EXEC_PATH', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData',
            'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE')


class BuildError(Exception):
    pass


def _chmod_retry(func, path, _exc):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    func(path)


def rmtree(path, ignore_errors=False):
    """shutil.rmtree that also removes read-only files (git objects on Windows)."""
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, ignore_errors=ignore_errors, onexc=_chmod_retry)
    else:
        shutil.rmtree(path, ignore_errors=ignore_errors, onerror=_chmod_retry)


# --------------------------------------------------------------- pure helpers

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def list_files(root, skip_manifest=True):
    """Sorted posix relative paths of every regular file under root."""
    out = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in files:
            rel = os.path.relpath(os.path.join(cur, name), root).replace(os.sep, '/')
            if skip_manifest and rel == MANIFEST_NAME:
                continue
            out.append(rel)
    return sorted(out, key=lambda r: r.encode('utf-8'))


def tree_sha256(entries):
    """entries: iterable of (relpath, sha256 hex). sha256 over sorted 'relpath\\0sha256\\n'."""
    digest = hashlib.sha256()
    for rel, sha in sorted(entries, key=lambda e: e[0].encode('utf-8')):
        digest.update(rel.encode('utf-8') + b'\0' + sha.encode('ascii') + b'\n')
    return digest.hexdigest()


def hash_tree(root):
    """Return (entries, file_count, total_bytes) for root, excluding MANIFEST.json."""
    entries, total = [], 0
    for rel in list_files(root):
        path = os.path.join(root, *rel.split('/'))
        entries.append((rel, sha256_file(path)))
        total += os.path.getsize(path)
    return entries, len(entries), total


def build_manifest(platform, hermes_ref, hermes_version, python_version, entries, total_bytes, built_at):
    return {
        'platform': platform,
        'hermes_ref': hermes_ref,
        'hermes_version': hermes_version,
        'python_version': python_version,
        'built_at': built_at,
        'file_count': len(entries),
        'total_bytes': total_bytes,
        'tree_sha256': tree_sha256(entries),
    }


def find_symlinks(root):
    found = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = os.path.join(cur, name)
            if os.path.islink(path):
                found.append(os.path.relpath(path, root).replace(os.sep, '/'))
    return sorted(found)


def check_names(root, max_rel=MAX_REL_PATH):
    """exFAT/Windows suitability: invalid characters, trailing dot/space, lengths, case collisions."""
    problems = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        seen = {}
        for name in dirs + files:
            rel = os.path.relpath(os.path.join(cur, name), root).replace(os.sep, '/')
            if INVALID_NAME_CHARS.search(name) or name.endswith(('.', ' ')) or RESERVED_NAMES.match(name):
                problems.append('%s: name invalid on exFAT/Windows' % rel)
            if len(name) > MAX_NAME:
                problems.append('%s: name longer than %d' % (rel, MAX_NAME))
            if len(rel) > max_rel:
                problems.append('%s...: path longer than %d' % (rel[:60], max_rel))
            key = name.lower()
            if key in seen and seen[key] != name:
                problems.append('%s: case-insensitive collision with %s' % (rel, seen[key]))
            seen[key] = name
    return problems


def forbidden_name(name):
    low = name.lower()
    if low in FORBIDDEN_NAMES or low == '.env' or low.startswith('.env.'):
        return not low.endswith('.example')
    return low.endswith('.env') and not low.endswith('.example')


def scan_secrets(root, allowlist=None, extra_literals=()):
    """Return findings (never the matched value). extra_literals: str paths that must not appear."""
    allowlist = SECRET_ALLOWLIST if allowlist is None else allowlist
    problems = []
    literals = [s.encode('utf-8') for s in extra_literals if s and len(s) > 3]
    literals += [s.replace('\\', '/').encode('utf-8') for s in extra_literals if s and len(s) > 3]
    for cur, dirs, files in os.walk(root, followlinks=False):
        if '.git' in dirs:
            problems.append('%s: .git directory' % os.path.relpath(os.path.join(cur, '.git'), root))
        for name in files:
            path = os.path.join(cur, name)
            rel = os.path.relpath(path, root).replace(os.sep, '/')
            if forbidden_name(name):
                problems.append('%s: credential-style file name' % rel)
            if os.path.islink(path):
                problems.append('%s: symlink' % rel)
                continue
            try:
                with open(path, 'rb') as fh:
                    data = fh.read()
            except OSError:
                problems.append('%s: unreadable' % rel)
                continue
            for label, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(data):
                    value = match.group(0).decode('utf-8', 'replace')
                    if any(re.search(p, rel) and label == l and re.fullmatch(v, value)
                           for p, l, v in allowlist):
                        continue
                    problems.append('%s: %s' % (rel, label))
                    break
            for lit in literals:
                if lit in data:
                    problems.append('%s: contains a build-machine path' % rel)
                    break
    return sorted(set(problems))


# ------------------------------------------------------------------- archives

def archive_name(platform):
    return '%s%s.%s' % (ARCHIVE_PREFIX, platform, 'zip' if platform.startswith('windows') else 'tar.gz')


def platform_from_archive_name(name):
    m = re.match(r'^' + re.escape(ARCHIVE_PREFIX) + r'(linux-x86_64|windows-x86_64)\.(tar\.gz|zip)$',
                 os.path.basename(name))
    if not m:
        return None
    plat, ext = m.groups()
    return plat if (ext == 'zip') == plat.startswith('windows') else None


def validate_member_names(names):
    """names: list of (name, kind) with kind 'file' or 'dir'. Returns (platform, problems)."""
    problems, platform, seen = [], None, set()
    for name, kind in names:
        label = name[:80]
        if not name or name.startswith('/') or name.startswith('\\') or re.match(r'^[A-Za-z]:', name):
            problems.append('%s: absolute path' % label)
            continue
        if '\\' in name or '\0' in name:
            problems.append('%s: backslash or NUL in name' % label)
            continue
        parts = name.rstrip('/').split('/')
        if any(p in ('', '.', '..') for p in parts):
            problems.append('%s: empty, "." or ".." component' % label)
            continue
        if any(INVALID_NAME_CHARS.search(p) or p.endswith(('.', ' ')) or len(p) > MAX_NAME
               or RESERVED_NAMES.match(p) for p in parts):
            problems.append('%s: name invalid on exFAT/Windows' % label)
            continue
        if len(name) > MAX_REL_PATH + 40:
            problems.append('%s: path too long' % label)
            continue
        if parts[0] not in PLATFORMS:
            problems.append('%s: top-level directory is not a known platform' % label)
            continue
        if platform is None:
            platform = parts[0]
        elif parts[0] != platform:
            problems.append('%s: mixed platforms in one archive' % label)
            continue
        key = '/'.join(parts).lower()
        if key in seen:
            problems.append('%s: duplicate member' % label)
        seen.add(key)
        if forbidden_name(parts[-1]):
            problems.append('%s: credential-style file name' % label)
        if kind == 'file' and len(parts) == 1:
            problems.append('%s: file at archive top level' % label)
    if platform and (platform + '/' + MANIFEST_NAME).lower() not in seen:
        problems.append('%s is missing' % MANIFEST_NAME)
    if not names:
        problems.append('archive is empty')
    return platform, problems


def _tar_members(tf):
    problems, names = [], []
    for info in tf.getmembers():
        if info.isdir():
            names.append((info.name, 'dir'))
        elif info.isreg():
            names.append((info.name, 'file'))
        else:
            problems.append('%s: not a regular file or directory (symlink, hardlink or device)' % info.name[:80])
    return names, problems


def _zip_members(zf):
    problems, names = [], []
    for info in zf.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            problems.append('%s: symlink' % info.filename[:80])
        elif info.is_dir():
            names.append((info.filename, 'dir'))
        else:
            names.append((info.filename, 'file'))
    return names, problems


def inspect_archive(path):
    """Return (platform, problems) without extracting anything."""
    expected = platform_from_archive_name(path)
    if expected is None:
        return None, ['archive name must be %s<platform>.tar.gz|zip' % ARCHIVE_PREFIX]
    try:
        if path.endswith('.zip'):
            with zipfile.ZipFile(path) as zf:
                names, problems = _zip_members(zf)
        else:
            with tarfile.open(path, 'r:gz') as tf:
                names, problems = _tar_members(tf)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        return None, ['cannot read archive: %s' % type(exc).__name__]
    platform, more = validate_member_names(names)
    problems += more
    if platform and platform != expected:
        problems.append('archive name says %s but content is %s' % (expected, platform))
    return platform, problems


def _write_member(dest_root, rel, reader, executable):
    target = os.path.join(dest_root, *rel.split('/'))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'wb') as out:
        shutil.copyfileobj(reader, out, 1 << 20)
        out.flush()
        os.fsync(out.fileno())
    if executable and os.name == 'posix':
        try:
            os.chmod(target, 0o755)
        except OSError:
            pass  # exFAT has no modes


def read_manifest(plat_dir):
    with open(os.path.join(plat_dir, MANIFEST_NAME), 'r', encoding='utf-8') as fh:
        return json.load(fh)


def verify_tree(plat_dir):
    """Recompute and compare with MANIFEST.json. Returns (ok, message)."""
    try:
        manifest = read_manifest(plat_dir)
    except (OSError, ValueError) as exc:
        return False, 'cannot read %s: %s' % (MANIFEST_NAME, type(exc).__name__)
    links = find_symlinks(plat_dir)
    if links:
        return False, 'symlinks present (%d)' % len(links)
    entries, count, total = hash_tree(plat_dir)
    actual = tree_sha256(entries)
    if actual != manifest.get('tree_sha256'):
        return False, 'tree_sha256 mismatch (manifest %s, actual %s)' % (manifest.get('tree_sha256'), actual)
    if count != manifest.get('file_count') or total != manifest.get('total_bytes'):
        return False, 'file_count/total_bytes mismatch'
    return True, 'tree_sha256 %s (%d files, %d bytes)' % (actual, count, total)


def extract_archive(path, dest_parent):
    """Validate, unpack into dest_parent/<platform> via a temporary sibling, read back, swap in."""
    platform, problems = inspect_archive(path)
    if problems:
        raise BuildError('refusing archive: ' + '; '.join(problems[:5]))
    os.makedirs(dest_parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix='.%s.new-' % platform, dir=dest_parent)
    try:
        if path.endswith('.zip'):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    with zf.open(info) as fh:
                        _write_member(staging, info.filename, fh, False)
        else:
            with tarfile.open(path, 'r:gz') as tf:
                for info in tf.getmembers():
                    if not info.isreg():
                        continue
                    fh = tf.extractfile(info)
                    _write_member(staging, info.name, fh, bool(info.mode & 0o111))
        new_dir = os.path.join(staging, platform)
        ok, msg = verify_tree(new_dir)
        if not ok:
            raise BuildError('read-back failed: ' + msg)
        if read_manifest(new_dir).get('platform') != platform:
            raise BuildError('MANIFEST.json platform does not match the archive')
        final = os.path.join(dest_parent, platform)
        if os.path.lexists(final):
            rmtree(final)
        os.rename(new_dir, final)
        return platform, msg
    finally:
        rmtree(staging, ignore_errors=True)


def write_archive(plat_dir, platform, out_path, epoch):
    """Deterministic archive with a single top-level <platform>/ directory."""
    rels = list_files(plat_dir, skip_manifest=False)
    if out_path.endswith('.zip'):
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            stamp = time.gmtime(max(epoch, 315532800))[:6]
            for rel in rels:
                info = zipfile.ZipInfo('%s/%s' % (platform, rel), date_time=stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                with open(os.path.join(plat_dir, *rel.split('/')), 'rb') as fh:
                    zf.writestr(info, fh.read(), zipfile.ZIP_DEFLATED, 9)
        return
    with open(out_path, 'wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tf:
                for rel in rels:
                    full = os.path.join(plat_dir, *rel.split('/'))
                    info = tarfile.TarInfo('%s/%s' % (platform, rel))
                    info.size = os.path.getsize(full)
                    info.mtime = epoch
                    info.mode = 0o755 if os.access(full, os.X_OK) and os.name == 'posix' else 0o644
                    with open(full, 'rb') as fh:
                        tf.addfile(info, fh)


# ---------------------------------------------------------------- build steps

def running_platform():
    machine = platform_mod.machine().lower()
    if machine not in ('x86_64', 'amd64'):
        return None
    if sys.platform.startswith('linux'):
        return 'linux-x86_64'
    if sys.platform == 'win32':
        return 'windows-x86_64'
    return None


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k in ENV_KEEP}
    env.update({'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
                'GIT_TERMINAL_PROMPT': '0', 'UV_NO_CONFIG': '1'})
    env.update(extra or {})
    return env


def run(cmd, env, **kw):
    print('+ ' + ' '.join(cmd[:4]) + (' ...' if len(cmd) > 4 else ''), flush=True)
    proc = subprocess.run(cmd, env=env, **kw)
    if proc.returncode != 0:
        raise BuildError('command failed (exit %d): %s' % (proc.returncode, cmd[0]))
    return proc


def entry_command(platform, plat_dir):
    if platform == 'windows-x86_64':
        return [os.path.join(plat_dir, 'python', 'python.exe'), '-m', 'hermes_cli.main']
    return [os.path.join(plat_dir, 'python', 'bin', 'python3'), '-m', 'hermes_cli.main']


def python_exe(platform, plat_dir):
    return entry_command(platform, plat_dir)[0]


def copy_dereferenced(src, dst):
    shutil.copytree(src, dst, symlinks=False)


def install_python(uv, version, work, env):
    install_dir = os.path.join(work, 'uv-python')
    run([uv, 'python', 'install', version, '--install-dir', install_dir, '--no-bin', '--no-registry'], env)
    candidates = [d for d in sorted(os.listdir(install_dir))
                  if os.path.isdir(os.path.join(install_dir, d)) and not os.path.islink(os.path.join(install_dir, d))
                  and d.startswith('cpython-')]
    if len(candidates) != 1:
        raise BuildError('expected exactly one installed interpreter, found %d' % len(candidates))
    return os.path.join(install_dir, candidates[0])


# Hermes is not installable as a wheel (its setup.py refuses; assets such as
# skills/, locales/ and plugin manifests are resolved from the source-checkout
# layout). So the pinned commit's source tree is copied next to the interpreter
# and put on sys.path with a RELATIVE .pth file; the dependencies come from the
# upstream uv.lock (exact versions and hashes).
SOURCE_DIRNAME = 'hermes-agent'
SOURCE_STRIP = ('.git', '.github', 'tests', 'tests-js', 'apps', 'website', 'docs', 'ui-tui', 'web',
                'contributors', 'evals', 'nix', 'docker', 'datagen-config-examples', 'node_modules',
                'venv', '.venv', '__pycache__')


def fetch_source(ref, work, env):
    """Fetch exactly `ref` (shallow) and return a directory without VCS data or dev-only trees."""
    repo = os.path.join(work, 'src')
    os.makedirs(repo)
    flags = ['-c', 'core.autocrlf=false', '-c', 'core.longpaths=true']
    run(['git', 'init', '-q', repo], env)
    run(['git'] + flags + ['-C', repo, 'fetch', '-q', '--depth', '1', HERMES_URL, ref], env)
    run(['git'] + flags + ['-C', repo, 'checkout', '-q', '--detach', 'FETCH_HEAD'], env)
    head = subprocess.run(['git', '-C', repo, 'rev-parse', 'HEAD'], env=env, capture_output=True, text=True)
    if head.stdout.strip() != ref:
        raise BuildError('fetched commit does not match --hermes-ref')
    shutil.copy(os.path.join(repo, 'uv.lock'), os.path.join(work, 'uv.lock'))
    shutil.copy(os.path.join(repo, 'pyproject.toml'), os.path.join(work, 'pyproject.toml'))
    for name in SOURCE_STRIP:
        path = os.path.join(repo, name)
        if os.path.isdir(path):
            rmtree(path)
    for name in os.listdir(repo):
        if name.upper().startswith(('README.', 'CONTRIBUTING.', 'SECURITY.')) and name.endswith('.md') \
                and name != 'README.md':
            os.remove(os.path.join(repo, name))
    return repo


def source_version(src):
    text = open(os.path.join(src, 'pyproject.toml'), encoding='utf-8').read()
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text.split('[project.', 1)[0])
    if not m:
        raise BuildError('cannot read the hermes-agent version from pyproject.toml')
    return m.group(1)


def install_dependencies(uv, py, src, work, env):
    """Install the locked, hashed core dependencies (no extras, no dev group) into py."""
    req = os.path.join(work, 'requirements.txt')
    proj = os.path.join(work, 'lockproj')
    os.makedirs(proj)
    shutil.copy(os.path.join(work, 'uv.lock'), proj)
    shutil.copy(os.path.join(work, 'pyproject.toml'), proj)
    for name in ('setup.py', 'README.md', 'LICENSE'):
        if os.path.exists(os.path.join(src, name)):
            shutil.copy(os.path.join(src, name), proj)
    run([uv, 'export', '--project', proj, '--frozen', '--no-dev', '--no-emit-project', '--no-header',
         '--format', 'requirements-txt', '--output-file', req], env, stdout=subprocess.DEVNULL)
    run([uv, 'pip', 'install', '--python', py, '--break-system-packages', '--no-cache', '--require-hashes',
         '--no-deps', '-r', req], env)


def site_packages(platform, python_dir, python_version):
    if platform == 'windows-x86_64':
        return os.path.join(python_dir, 'Lib', 'site-packages')
    return os.path.join(python_dir, 'lib', 'python' + python_version, 'site-packages')


def link_source(platform, python_dir, src, python_version):
    """Relative .pth so the source tree is importable from wherever the USB is mounted."""
    site = site_packages(platform, python_dir, python_version)
    rel = os.path.relpath(src, site).replace(os.sep, '/')
    with open(os.path.join(site, 'hermes-agent.pth'), 'w', encoding='ascii', newline='\n') as fh:
        fh.write(rel + '\n')


def strip_tree(python_dir, platform):
    """Remove files that do not belong in a relocatable, read-mostly runtime."""
    removed = 0

    def rm(path):
        nonlocal removed
        if os.path.isdir(path) and not os.path.islink(path):
            rmtree(path)
        elif os.path.lexists(path):
            os.remove(path)
        else:
            return
        removed += 1

    if platform == 'windows-x86_64':
        rm(os.path.join(python_dir, 'Scripts'))       # console exes embed absolute interpreter paths
        lib = os.path.join(python_dir, 'Lib')
        site = os.path.join(lib, 'site-packages')
    else:
        bindir = os.path.join(python_dir, 'bin')
        for name in os.listdir(bindir):
            if name != 'python3':
                rm(os.path.join(bindir, name))         # pip/etc. shebangs with absolute paths; python/python3.X are duplicates
        libs = [d for d in os.listdir(os.path.join(python_dir, 'lib')) if re.match(r'^python3\.\d+$', d)]
        lib = os.path.join(python_dir, 'lib', libs[0])
        site = os.path.join(lib, 'site-packages')
    rm(os.path.join(python_dir, 'include'))
    if platform != 'windows-x86_64':
        pylib = os.path.join(python_dir, 'lib')
        for name in os.listdir(pylib):
            if name.endswith('.a'):
                rm(os.path.join(pylib, name))          # static libpython, only needed to link extensions
        for libdir in [d for d in os.listdir(pylib) if re.match(r'^python3\.\d+$', d)]:
            for name in os.listdir(os.path.join(pylib, libdir)):
                if name.startswith('config-'):
                    rm(os.path.join(pylib, libdir, name))
    rm(os.path.join(python_dir, 'share'))              # terminfo/Q vs q collide on case-insensitive exFAT
    for name in STDLIB_STRIP:
        rm(os.path.join(lib, name))
    for cur, dirs, files in os.walk(site):
        for d in list(dirs):
            if d in ('test', 'tests') or d == '__pycache__':
                rm(os.path.join(cur, d))
                dirs.remove(d)
    for cur, dirs, files in os.walk(python_dir):
        for d in list(dirs):
            if d == '__pycache__':
                rm(os.path.join(cur, d))
                dirs.remove(d)
    return removed


def neutralize_paths(python_dir, install_path):
    """uv patches the interpreter's sysconfig data with its install path; put PBS's own placeholder back."""
    needle = install_path.encode('utf-8')
    changed = 0
    for cur, dirs, files in os.walk(python_dir):
        for name in files:
            path = os.path.join(cur, name)
            if os.path.islink(path) or os.path.getsize(path) > 8 << 20:
                continue
            with open(path, 'rb') as fh:
                data = fh.read()
            if needle not in data or data[:4] == b'\x7fELF' or data[:2] == b'MZ':
                continue
            with open(path, 'wb') as fh:
                fh.write(data.replace(needle, b'/install'))
            changed += 1
    return changed


def compile_all(py, python_dir, env):
    # unchecked-hash: no mtime comparison (exFAT timestamps differ) and no source
    # read at import time. -s/-p replace the build-machine prefix in co_filename.
    run([py, '-m', 'compileall', '-q', '-j', '0', '-f', '--invalidation-mode', 'unchecked-hash',
         '-s', python_dir, '-p', 'hermes-portable/python', python_dir], env)


def smoke(platform, plat_dir):
    """Run `--version` and import the chat CLI with an empty HERMES_HOME. Returns the version line."""
    with tempfile.TemporaryDirectory() as home:
        env = clean_env({'HERMES_HOME': home})
        cmd = entry_command(platform, plat_dir)
        proc = subprocess.run(cmd + ['--version'], env=env, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise BuildError('smoke test failed: --version exit %d: %s' % (proc.returncode, proc.stderr[-400:]))
        line = (proc.stdout.strip().splitlines() or [''])[0]
        proc = subprocess.run(cmd + ['chat', '--cli', '--help'], env=env, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise BuildError('smoke test failed: chat --cli --help exit %d: %s' % (proc.returncode, proc.stderr[-400:]))
        return line


def build(args):
    plat = args.platform
    if plat != running_platform():
        raise BuildError('cross-builds are refused: running on %s, asked for %s' % (running_platform(), plat))
    if not HEX40.match(args.hermes_ref):
        raise BuildError('--hermes-ref must be a 40-hex git commit')
    uv = shutil.which('uv')
    if not uv:
        raise BuildError('uv is required (python -m pip install uv, or https://docs.astral.sh/uv/)')
    out = os.path.abspath(args.out)
    plat_dir = os.path.join(out, plat)
    if os.path.lexists(plat_dir):
        raise BuildError('refusing: %s already exists' % plat_dir)
    os.makedirs(out, exist_ok=True)
    started = time.time()
    work = tempfile.mkdtemp(prefix='hp-build-')
    try:
        env = clean_env({'UV_CACHE_DIR': os.path.join(work, 'uv-cache')})
        src = install_python(uv, args.python, work, env)
        interp_src = src
        python_dir = os.path.join(plat_dir, 'python')
        os.makedirs(plat_dir)
        copy_dereferenced(src, python_dir)
        py = python_exe(plat, plat_dir)
        source = fetch_source(args.hermes_ref, work, env)
        hermes_src = os.path.join(python_dir, SOURCE_DIRNAME)
        shutil.copytree(source, hermes_src, symlinks=False)
        install_dependencies(uv, py, hermes_src, work, env)
        link_source(plat, python_dir, hermes_src, args.python)
        removed = strip_tree(python_dir, plat)
        neutralize_paths(python_dir, interp_src)
        compile_all(py, python_dir, env)
        links = find_symlinks(plat_dir)
        if links:
            raise BuildError('symlinks remain in the output (%d), first: %s' % (len(links), links[0]))
        problems = check_names(plat_dir)
        if problems:
            raise BuildError('names unsuitable for exFAT/Windows: ' + '; '.join(problems[:5]))
        probe = subprocess.run(
            [py, '-c', 'import sys;print("%d.%d.%d" % sys.version_info[:3])'],
            env=clean_env(), capture_output=True, text=True)
        if probe.returncode != 0:
            raise BuildError('cannot run the bundled interpreter')
        python_version = probe.stdout.split()[-1]
        hermes_version = source_version(hermes_src)
        findings = scan_secrets(plat_dir, extra_literals=[out, work, os.path.expanduser('~')])
        if findings:
            raise BuildError('credential/path self-check failed (values not printed):\n  ' + '\n  '.join(findings[:30]))
        entries, count, total = hash_tree(plat_dir)
        before = tree_sha256(entries)
        version_line = smoke(plat, plat_dir)
        entries2, _, _ = hash_tree(plat_dir)
        if tree_sha256(entries2) != before:
            raise BuildError('the smoke test modified the tree (bytecode or state was written)')
        built_at = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        manifest = build_manifest(plat, args.hermes_ref, hermes_version, python_version, entries, total, built_at)
        with open(os.path.join(plat_dir, MANIFEST_NAME), 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write('\n')
        ok, msg = verify_tree(plat_dir)
        if not ok:
            raise BuildError('manifest self-verification failed: ' + msg)
        print('hermes --version: %s' % version_line)
        print('platform %s | hermes %s (%s) | python %s | %d files | %.1f MiB | stripped %d paths | %.0fs'
              % (plat, hermes_version, args.hermes_ref[:12], python_version, count, total / 1048576.0,
                 removed, time.time() - started))
        print('tree_sha256 %s' % manifest['tree_sha256'])
        if args.archive:
            name = archive_name(plat)
            archive = os.path.join(out, name)
            epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
            write_archive(plat_dir, plat, archive, epoch)
            digest = sha256_file(archive)
            with open(archive + '.sha256', 'w', encoding='ascii', newline='\n') as fh:
                fh.write('%s  %s\n' % (digest, name))
            _, issues = inspect_archive(archive)
            if issues:
                raise BuildError('produced archive failed validation: ' + '; '.join(issues[:3]))
            print('archive %s (%d bytes) sha256 %s' % (name, os.path.getsize(archive), digest))
    except BaseException:
        if not args.keep_failed:
            rmtree(plat_dir, ignore_errors=True)
        raise
    finally:
        rmtree(work, ignore_errors=True)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--platform', choices=PLATFORMS)
    ap.add_argument('--hermes-ref', default=HERMES_REF, help='40-hex hermes-agent commit (default: pinned HERMES_REF)')
    ap.add_argument('--python', default=DEFAULT_PYTHON, choices=PYTHON_CHOICES)
    ap.add_argument('--out', help='output directory; the tree lands in OUT/<platform>')
    ap.add_argument('--archive', action='store_true', help='also write the .tar.gz/.zip and its .sha256')
    ap.add_argument('--keep-failed', action='store_true', help='debugging: keep the tree of a failed build')
    ap.add_argument('--verify-tree', metavar='DIR')
    ap.add_argument('--scan-tree', metavar='DIR', help='credential-free self-check of a <platform> directory')
    ap.add_argument('--check-archive', metavar='FILE')
    ap.add_argument('--extract-archive', metavar='FILE')
    ap.add_argument('--dest', help='parent directory for --extract-archive')
    args = ap.parse_args(argv)
    try:
        if args.verify_tree:
            ok, msg = verify_tree(args.verify_tree)
            print(('PASS ' if ok else 'FAIL ') + msg)
            return 0 if ok else 1
        if args.scan_tree:
            problems = scan_secrets(args.scan_tree) + find_symlinks(args.scan_tree)
            problems += check_names(args.scan_tree)
            if problems:
                for item in sorted(set(problems))[:50]:
                    print('finding: ' + item, file=sys.stderr)
                return 1
            print('credential-free: no secret-shaped strings, credential file names, symlinks or invalid names')
            return 0
        if args.check_archive:
            plat, problems = inspect_archive(args.check_archive)
            if problems:
                for p in problems[:20]:
                    print('refused: ' + p, file=sys.stderr)
                return 1
            print('archive ok: %s' % plat)
            return 0
        if args.extract_archive:
            if not args.dest:
                ap.error('--extract-archive needs --dest')
            plat, msg = extract_archive(args.extract_archive, args.dest)
            print('extracted %s: %s' % (plat, msg))
            return 0
        if not args.platform or not args.out:
            ap.error('build needs --platform and --out')
        return build(args)
    except BuildError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
