"""Verified skill update for Hermes: fetch the newest signed skills bundle and replace skill TEXT only.

Standard library only. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Trust model (docs/skill-update.md, docs/security-model.md):

* The signer is the owner's SSH key. The updater verifies `ssh-keygen -Y verify -n rescue-skills` against
  `config/skills-allowed-signers` of the INSTALLED toolkit (pinned on the USB or in the image). A downloaded
  allowed_signers file is never used, and there is no option to fetch one.
* Fail closed: placeholder or invalid signers, no ssh-keygen, no network, bad signature, bad manifest,
  rollback, a toolkit that is too old, or a bundle that is not newer all end in "keep the skills you have".
* Order of work: signers state, ssh-keygen present, release lookup, manifest + signature, signature check,
  manifest semantics (version, anti-rollback, min_toolkit_version), and only then the tarball, which must match
  the signed sha256 and size and pass skills_bundle.check_bundle.
* Only skills/<name>/SKILL.md of skills the toolkit already ships are written. Scripts, catalog, policy and
  config are never touched, and nothing from the bundle is ever executed or extracted to disk.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import skills_bundle as sb

SOURCE_REPO = 'ahliweb/linux-mint-xfce-rescue-ai'     # pinned in code on purpose
DEFAULT_API_BASE = 'https://api.github.com'
DEFAULT_DOWNLOAD_BASE = 'https://github.com'
ALLOWED_REDIRECT_SUFFIXES = ('.github.com', '.githubusercontent.com')
ALLOWED_REDIRECT_HOSTS = ('github.com', 'githubusercontent.com')

REQUEST_TIMEOUT = 10          # seconds per request (connect and read)
TOTAL_BUDGET = 60             # seconds for all network work together
MAX_RELEASE_JSON_BYTES = 256 * 1024
MAX_SIG_BYTES = 8 * 1024
MAX_REDIRECTS = 5
VERIFY_TIMEOUT = 20

STATE_SCHEMA = 'rescue-skill-update-state/1'
JOURNAL_SCHEMA = 'rescue-skill-update/1'
STATE_DIR_NAME = 'skill-update'
JOURNAL_NAME = 'skill-update-journal.jsonl'
TAG_RE = re.compile(r'^v(\d+\.\d+\.\d+)$')
FINGERPRINT_RE = re.compile(r'\bkey (SHA256:[A-Za-z0-9+/]{43})(?![A-Za-z0-9+/=])')

# status values (closed set, journal-safe) and reason codes (closed set); the operator text is MESSAGES[reason].
STATUSES = ('updated', 'current', 'skipped', 'refused', 'offline', 'failed')
MESSAGES = {
    'updated': 'Skill Hermes diperbarui ke versi {bundle_version}. Tanda tangan pemilik terverifikasi (kunci {signer}); {skills} skill diganti.',
    'current': 'Skill Hermes sudah versi terbaru ({bundle_version}); tidak ada yang diganti.',
    'not-newer': 'Rilis skill {bundle_version} tidak lebih baru dari skill yang terpasang; skill bawaan atau sebelumnya tetap dipakai.',
    'disabled': 'Pembaruan skill otomatis dimatikan (RESCUE_SKILLS_UPDATE=off); skill bawaan atau sebelumnya tetap dipakai.',
    'config-invalid': 'Nilai RESCUE_SKILLS_UPDATE tidak dikenal (hanya auto atau off); pembaruan dilewati dan skill yang ada tetap dipakai.',
    'no-ssh-keygen': 'Pembaruan skill dilewati: ssh-keygen tidak tersedia, jadi tanda tangan tidak dapat diverifikasi. Skill yang ada tetap dipakai.',
    'placeholder-signers': 'Pembaruan skill ditolak: kunci publik pemilik belum dipasang (berkas allowed_signers masih placeholder). Skill yang ada tetap dipakai.',
    'invalid-signers': 'Pembaruan skill ditolak: berkas allowed_signers di USB tidak valid. Skill yang ada tetap dipakai.',
    'offline': 'Pembaruan skill dilewati: tidak ada jaringan atau server rilis tidak terjangkau. Skill yang ada tetap dipakai.',
    'http-error': 'Pembaruan skill dilewati: server rilis menjawab dengan galat. Skill yang ada tetap dipakai.',
    'no-bundle': 'Pembaruan skill dilewati: rilis terbaru tidak memuat bundel skill bertanda tangan. Skill yang ada tetap dipakai.',
    'bad-release': 'Pembaruan skill ditolak: jawaban rilis tidak sesuai format. Skill yang ada tetap dipakai.',
    'too-large': 'Pembaruan skill ditolak: unduhan melebihi batas ukuran. Skill yang ada tetap dipakai.',
    'bad-signature': 'Pembaruan skill DITOLAK: tanda tangan manifest tidak cocok dengan kunci pemilik yang dipasang di USB. Skill yang ada tetap dipakai.',
    'bad-manifest': 'Pembaruan skill ditolak: manifest tidak sesuai format. Skill yang ada tetap dipakai.',
    'version-mismatch': 'Pembaruan skill ditolak: versi di manifest berbeda dari versi rilis. Skill yang ada tetap dipakai.',
    'rollback': 'Pembaruan skill ditolak: versi bundel {bundle_version} lebih lama dari yang pernah terpasang (anti-rollback). Skill yang ada tetap dipakai.',
    'toolkit-too-old': 'Pembaruan skill dilewati: bundel butuh toolkit minimal {min_toolkit}, sedangkan yang terpasang {toolkit_version}. Perbarui USB lebih dulu.',
    'bad-bundle': 'Pembaruan skill ditolak: isi bundel tidak cocok dengan manifest yang ditandatangani. Skill yang ada tetap dipakai.',
    'state-invalid': 'Pembaruan skill ditolak: catatan versi lokal (folder skill-update di HERMES_HOME) rusak. Hapus folder itu secara manual bila yakin, lalu jalankan ulang.',
    'toolkit-version-unreadable': 'Pembaruan skill ditolak: berkas VERSION toolkit tidak terbaca. Skill yang ada tetap dipakai.',
    'unsafe-target': 'Pembaruan skill ditolak: folder skill di HERMES_HOME berisi symlink atau tidak dapat ditulis. Skill yang ada tetap dipakai.',
    'install-error': 'Pembaruan skill gagal saat memasang; semua berkas dikembalikan ke keadaan semula. Skill yang ada tetap dipakai.',
}
STATUS_OF = {
    'current': 'current', 'not-newer': 'current',
    'disabled': 'skipped', 'config-invalid': 'skipped', 'no-ssh-keygen': 'skipped', 'no-bundle': 'skipped',
    'toolkit-too-old': 'skipped',
    'offline': 'offline', 'http-error': 'offline',
    'placeholder-signers': 'refused', 'invalid-signers': 'refused', 'bad-release': 'refused', 'too-large': 'refused',
    'bad-signature': 'refused', 'bad-manifest': 'refused', 'version-mismatch': 'refused', 'rollback': 'refused',
    'bad-bundle': 'refused', 'state-invalid': 'refused', 'toolkit-version-unreadable': 'refused',
    'unsafe-target': 'refused',
    'install-error': 'failed',
}


class Stop(Exception):
    """Internal: end the run with a reason code (always fail closed)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Result:
    status: str
    reason: str
    message: str
    toolkit_version: str | None = None
    installed_version: str | None = None
    bundle_version: str | None = None
    signer: str | None = None
    skills: int | None = None
    skipped_names: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing went wrong: updated, current, or deliberately skipped (off, no ssh-keygen, offline...)."""
        return self.status in ('updated', 'current', 'skipped', 'offline')


# --- small helpers ---------------------------------------------------------------------------------------

def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def read_mode(root: Path, cli_mode: str | None, environ=None) -> str:
    """auto | off | invalid. Order: CLI, environment, RESCUE_SKILLS_UPDATE in config/rescue.env (parsed as data), default auto."""
    environ = os.environ if environ is None else environ
    value = cli_mode or environ.get('RESCUE_SKILLS_UPDATE') or ''
    if not value:
        try:
            for raw in (root / 'config' / 'rescue.env').read_text(encoding='utf-8').splitlines():
                line = raw.strip()
                if line.startswith('export '):
                    line = line[7:].strip()
                key, sep, rest = line.partition('=')
                if sep and key.strip() == 'RESCUE_SKILLS_UPDATE':
                    value = rest.strip().strip('\'"').strip()
        except OSError:
            pass
    value = (value or 'auto').lower()
    return value if value in ('auto', 'off') else 'invalid'


def read_toolkit_version(root: Path) -> str:
    try:
        text = (root / 'VERSION').read_text(encoding='utf-8').strip()
        sb.version_tuple(text)
    except (OSError, UnicodeDecodeError, sb.BundleError) as exc:
        raise Stop('toolkit-version-unreadable') from exc
    return text


def pinned_signers(text: str) -> dict:
    """{principal: set(fingerprint)} of a file that allowed_signers_state calls pinned. Reuses skills_bundle's grammar."""
    out: dict[str, set] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = sb.SIGNER_LINE_RE.match(line)
        if m:
            out.setdefault(m.group('principal'), set()).add(sb.fingerprint(m.group('key')))
    return out


def sha_of_file(path: Path) -> str | None:
    try:
        return sb.sha256_hex(path.read_bytes())
    except OSError:
        return None


# --- network ---------------------------------------------------------------------------------------------

def _is_loopback(host: str | None) -> bool:
    return host in ('127.0.0.1', '::1', 'localhost')


def _check_url(url: str) -> None:
    """https only; plain http only for loopback (the local mock release server of the tests)."""
    p = urllib.parse.urlsplit(url)
    if p.scheme == 'https' and p.hostname and not p.username and not p.password:
        return
    if p.scheme == 'http' and _is_loopback(p.hostname):
        return
    raise Stop('bad-release')


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        p = urllib.parse.urlsplit(newurl)
        host = (p.hostname or '').lower()
        if not _is_loopback(host) and not (host in ALLOWED_REDIRECT_HOSTS or host.endswith(ALLOWED_REDIRECT_SUFFIXES)):
            raise Stop('bad-release')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_proxy(environ) -> str | None:
    """HTTPS proxy from the environment only if it is a plain http(s) URL with a host. Never logged (may carry credentials)."""
    value = environ.get('HTTPS_PROXY') or environ.get('https_proxy') or ''
    p = urllib.parse.urlsplit(value)
    return value if p.scheme in ('http', 'https') and p.hostname else None


class Fetcher:
    """Short-timeout, size-capped GET with certificate verification. Sends no credentials of any kind."""

    def __init__(self, api_base=DEFAULT_API_BASE, download_base=DEFAULT_DOWNLOAD_BASE, environ=None,
                 timeout=REQUEST_TIMEOUT, budget=TOTAL_BUDGET):
        self.api_base = api_base.rstrip('/')
        self.download_base = download_base.rstrip('/')
        self.timeout = timeout
        self.deadline = time.monotonic() + budget
        environ = os.environ if environ is None else environ
        self._environ = environ

    def _opener(self, url):
        handlers = [_SafeRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())]
        proxy = None if _is_loopback(urllib.parse.urlsplit(url).hostname) else _safe_proxy(self._environ)
        handlers.append(urllib.request.ProxyHandler({'https': proxy} if proxy else {}))
        return urllib.request.build_opener(*handlers)

    def get(self, url: str, limit: int, accept='application/octet-stream') -> bytes:
        _check_url(url)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Stop('offline')
        req = urllib.request.Request(url, headers={
            'Accept': accept, 'User-Agent': 'rescue-skills-updater', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self._opener(url).open(req, timeout=min(self.timeout, remaining)) as resp:
                _check_url(resp.geturl())
                length = resp.headers.get('Content-Length')
                if length is not None and length.isdigit() and int(length) > limit:
                    raise Stop('too-large')
                chunks, total = [], 0
                while True:
                    if time.monotonic() > self.deadline:
                        raise Stop('offline')
                    chunk = resp.read(min(65536, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise Stop('too-large')
                    chunks.append(chunk)
                return b''.join(chunks)
        except Stop:
            raise
        except urllib.error.HTTPError as exc:
            raise Stop('no-bundle' if exc.code == 404 else 'http-error') from exc
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
            raise Stop('offline') from exc

    def latest_tag(self) -> str:
        data = self.get(f'{self.api_base}/repos/{SOURCE_REPO}/releases/latest', MAX_RELEASE_JSON_BYTES,
                        accept='application/vnd.github+json')
        try:
            doc = json.loads(data.decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as exc:
            raise Stop('bad-release') from exc
        if not isinstance(doc, dict) or doc.get('draft') is True or doc.get('prerelease') is True:
            raise Stop('bad-release')
        tag = doc.get('tag_name')
        m = TAG_RE.match(tag) if isinstance(tag, str) else None
        if not m:
            raise Stop('bad-release')
        assets = doc.get('assets')
        if isinstance(assets, list):
            names = {a.get('name') for a in assets if isinstance(a, dict)}
            need = {f'rescue-skills-{m.group(1)}.manifest.json', f'rescue-skills-{m.group(1)}.manifest.json.sig'}
            if not need <= names:
                raise Stop('no-bundle')
        return m.group(1)

    def asset(self, version: str, name: str, limit: int) -> bytes:
        # Built from the pinned repo and the validated version; never taken from the release JSON.
        return self.get(f'{self.download_base}/{SOURCE_REPO}/releases/download/v{version}/{name}', limit)


# --- signature -------------------------------------------------------------------------------------------

def verify_signature(ssh_keygen: str, signers: Path, pins: dict, manifest: bytes, sig: bytes, workdir: Path) -> str:
    """Return the fingerprint of the pinned key that signed `manifest`. Raises Stop('bad-signature')."""
    if not sig or len(sig) > MAX_SIG_BYTES or not sig.startswith(b'-----BEGIN SSH SIGNATURE-----'):
        raise Stop('bad-signature')
    sig_path = workdir / 'manifest.sig'
    sig_path.write_bytes(sig)
    env = {'LC_ALL': 'C', 'PATH': os.environ.get('PATH', '')}
    for k in ('SystemRoot', 'TEMP', 'TMP'):      # Windows needs these for ssh-keygen.exe to start
        if k in os.environ:
            env[k] = os.environ[k]
    for principal in sorted(pins):
        try:
            proc = subprocess.run(
                [ssh_keygen, '-Y', 'verify', '-f', str(signers), '-I', principal, '-n', sb.NAMESPACE, '-s', str(sig_path)],
                input=manifest, capture_output=True, timeout=VERIFY_TIMEOUT, env=env, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0:
            continue
        m = FINGERPRINT_RE.search(proc.stdout.decode('utf-8', 'replace'))
        if m and m.group(1) in pins[principal]:
            return m.group(1)
    raise Stop('bad-signature')


# --- local state and install -----------------------------------------------------------------------------

def load_state(hermes_home: Path) -> dict | None:
    path = hermes_home / STATE_DIR_NAME / 'state.json'
    if path.is_symlink():
        raise Stop('state-invalid')
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(doc, dict) or set(doc) != {'schema', 'bundle_version', 'signer', 'installed_at', 'files'}
                or doc['schema'] != STATE_SCHEMA or not isinstance(doc['files'], dict)):
            raise ValueError
        sb.version_tuple(doc['bundle_version'])
        for name, digest in doc['files'].items():
            if not sb.NAME_RE.match(name) or not isinstance(digest, str) or not sb.SHA_RE.match(digest):
                raise ValueError
    except (OSError, ValueError, UnicodeDecodeError, sb.BundleError, TypeError) as exc:
        raise Stop('state-invalid') from exc
    return doc


def state_is_active(hermes_home: Path, state: dict) -> bool:
    """True when every skill file the state recorded is still byte-identical (a launcher re-seed makes this False)."""
    for name, digest in state['files'].items():
        if sha_of_file(hermes_home / 'skills' / name / 'SKILL.md') != digest:
            return False
    return True


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def install_skills(hermes_home: Path, files: dict, state_doc: dict) -> None:
    """Replace skills/<name>/SKILL.md for every name in `files` ({name: bytes}); all or nothing (rollback on error).

    Per file: stage next to the target, then os.replace (atomic). The previous bytes are kept in memory for the
    rollback, and state.json is written last. Other files in a skill folder are never touched.
    """
    skills_dir = hermes_home / 'skills'
    state_dir = hermes_home / STATE_DIR_NAME
    for p in (hermes_home, skills_dir, state_dir):
        if p.is_symlink():
            raise Stop('unsafe-target')
    skills_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    targets = {}
    for name in files:
        folder = skills_dir / name
        target = folder / 'SKILL.md'
        if folder.is_symlink() or target.is_symlink() or (folder.exists() and not folder.is_dir()) or target.is_dir():
            raise Stop('unsafe-target')
        targets[name] = target
    previous: dict[str, bytes | None] = {}
    created_dirs: list[Path] = []
    done: list[str] = []
    try:
        for name, target in targets.items():
            previous[name] = target.read_bytes() if target.exists() else None
            if not target.parent.exists():
                target.parent.mkdir(mode=0o700)
                created_dirs.append(target.parent)
        for name, target in targets.items():
            _write_atomic(target, files[name])
            done.append(name)
        _write_atomic(state_dir / 'state.json', json.dumps(state_doc, indent=2, sort_keys=True).encode('ascii') + b'\n')
    except Exception as exc:
        for name in done:
            target = targets[name]
            try:
                if previous[name] is None:
                    target.unlink()
                else:
                    _write_atomic(target, previous[name])
            except OSError:
                pass
        for folder in reversed(created_dirs):
            try:
                folder.rmdir()
            except OSError:
                pass
        raise Stop('install-error') from exc


def shipped_skill_names(root: Path) -> set:
    base = root / 'profiles' / 'rescue-hermes' / 'skills'
    try:
        return {p.name for p in base.iterdir() if p.is_dir() and not p.is_symlink() and (p / 'SKILL.md').is_file()}
    except OSError:
        return set()


# --- journal ---------------------------------------------------------------------------------------------

def write_journal(reports_dir: Path | None, result: Result) -> bool:
    """Append one closed-field JSON line (no paths, names or secrets). Returns False when it could not be written."""
    if reports_dir is None:
        return False
    record = {
        'schema': JOURNAL_SCHEMA, 'at': _now(), 'status': result.status, 'reason': result.reason,
        'toolkit_version': result.toolkit_version, 'installed_version': result.installed_version,
        'bundle_version': result.bundle_version, 'signer': result.signer, 'skills': result.skills,
    }
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / JOURNAL_NAME
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a', encoding='ascii') as fh:
            fh.write(json.dumps(record, sort_keys=True) + '\n')
        return True
    except OSError:
        return False


# --- orchestration ---------------------------------------------------------------------------------------

def _finish(reason: str, **info) -> Result:
    status = 'updated' if reason == 'updated' else STATUS_OF[reason]
    fmt = {'bundle_version': '', 'min_toolkit': '', 'toolkit_version': '', 'signer': '', 'skills': 0}
    fmt.update({k: v for k, v in info.items() if v is not None})
    return Result(status=status, reason=reason, message=MESSAGES[reason].format(**fmt),
                  **{k: v for k, v in info.items() if k in ('toolkit_version', 'installed_version', 'bundle_version', 'signer', 'skills', 'skipped_names')})


def run_update(root: Path, hermes_home: Path, reports_dir: Path | None = None, *, mode: str | None = None,
               offline: bool = False, fetcher: Fetcher | None = None, signers_path: Path | None = None,
               ssh_keygen: str | None = None, environ=None) -> Result:
    """Run one update attempt. Never raises for an expected failure; always returns a fail-closed Result."""
    root, hermes_home = Path(root), Path(hermes_home)
    info: dict = {}
    try:
        result = _run(root, hermes_home, mode, offline, fetcher, signers_path, ssh_keygen, environ, info)
    except Stop as stop:
        result = _finish(stop.reason, **info)
    except Exception:  # defensive: a bug in the updater must never stop Hermes from starting
        result = _finish('install-error', **info)
    write_journal(reports_dir, result)
    return result


def _run(root, hermes_home, mode, offline, fetcher, signers_path, ssh_keygen, environ, info) -> Result:
    chosen = read_mode(root, mode, environ)
    if chosen == 'off':
        raise Stop('disabled')
    if chosen == 'invalid':
        raise Stop('config-invalid')
    info['toolkit_version'] = toolkit = read_toolkit_version(root)

    signers = Path(signers_path) if signers_path else root / 'config' / 'skills-allowed-signers'
    try:
        signers_text = signers.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        raise Stop('invalid-signers') from None
    state_kind, _detail = sb.allowed_signers_state(signers_text)
    if state_kind == 'placeholder':
        raise Stop('placeholder-signers')
    if state_kind != 'pinned':
        raise Stop('invalid-signers')
    pins = pinned_signers(signers_text)

    keygen = ssh_keygen or shutil.which('ssh-keygen')
    if not keygen:
        raise Stop('no-ssh-keygen')

    state = load_state(hermes_home)
    if state is not None:
        info['installed_version'] = state['bundle_version'] if state_is_active(hermes_home, state) else None
    if offline:
        raise Stop('offline')

    fetcher = fetcher or Fetcher(environ=environ)
    with tempfile.TemporaryDirectory(prefix='rescue-skill-update-') as tmp:
        work = Path(tmp)
        os.chmod(work, 0o700)
        version = fetcher.latest_tag()
        info['bundle_version'] = version
        manifest_bytes = fetcher.asset(version, f'rescue-skills-{version}.manifest.json', sb.MAX_MANIFEST_BYTES)
        sig_bytes = fetcher.asset(version, f'rescue-skills-{version}.manifest.json.sig', MAX_SIG_BYTES)

        info['signer'] = verify_signature(keygen, signers, pins, manifest_bytes, sig_bytes, work)

        try:
            manifest = sb.parse_manifest(manifest_bytes)
        except sb.BundleError as exc:
            raise Stop('bad-manifest') from exc
        if manifest['bundle_version'] != version:
            raise Stop('version-mismatch')

        newest = sb.version_tuple(version)
        if sb.version_tuple(manifest['min_toolkit_version']) > sb.version_tuple(toolkit):
            info['min_toolkit'] = manifest['min_toolkit_version']
            raise Stop('toolkit-too-old')
        if newest <= sb.version_tuple(toolkit):
            raise Stop('not-newer')
        if state is not None:
            high = sb.version_tuple(state['bundle_version'])
            if newest < high:
                raise Stop('rollback')
            if newest == high and state_is_active(hermes_home, state):
                raise Stop('current')

        tar_name = manifest['tarball']['name']
        tarball = fetcher.asset(version, tar_name, manifest['tarball']['size'])
        (work / 'manifest.json').write_bytes(manifest_bytes)
        (work / tar_name).write_bytes(tarball)
        try:
            checked = sb.check_bundle(work / 'manifest.json', work / tar_name)
        except sb.BundleError as exc:
            raise Stop('bad-bundle') from exc

        wanted = shipped_skill_names(root)
        files, digests, skipped = {}, {}, []
        for entry in checked['files']:
            name = sb.PATH_RE.match(entry['path']).group(1)
            if name not in wanted:
                skipped.append(name)
                continue
            files[name] = _member_bytes(tarball, entry['path'])
            digests[name] = entry['sha256']
        if not files:
            raise Stop('bad-bundle')
        install_skills(hermes_home, files, {
            'schema': STATE_SCHEMA, 'bundle_version': version, 'signer': info['signer'],
            'installed_at': _now(), 'files': digests})
        info['skills'] = len(files)
        info['skipped_names'] = skipped
        info['installed_version'] = version
    return _finish('updated', **info)


def _member_bytes(tarball: bytes, path: str) -> bytes:
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(tarball), mode='r:gz') as tar:
        return tar.extractfile(path).read(sb.MAX_FILE_BYTES + 1)
