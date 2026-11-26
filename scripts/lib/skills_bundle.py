"""Signed skills bundle: deterministic build, strict format check, allowed_signers state.

Standard library only. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Format "rescue-skills-manifest/1" (see docs/skill-update.md):

  rescue-skills-<V>.tar.gz            only skills/<name>/SKILL.md regular files
  rescue-skills-<V>.manifest.json     bundle version, minimum toolkit version, tarball sha256 and size,
                                      every file with sha256 and size  <- the thing the owner signs
  rescue-skills-<V>.manifest.json.sig `ssh-keygen -Y sign -n rescue-skills` over the manifest bytes

The tarball is never extracted to disk here: members are read in memory and checked one by one.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

NAMESPACE = 'rescue-skills'
SCHEMA = 'rescue-skills-manifest/1'
PLACEHOLDER_MARKER = 'RESCUE-SKILLS-ALLOWED-SIGNERS-PLACEHOLDER'

# Format limits (the updater applies the same numbers; change them only together with the schema).
MAX_FILES = 64
MAX_FILE_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_TARBALL_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024

NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')
PATH_RE = re.compile(r'^skills/([a-z0-9][a-z0-9-]{0,62})/SKILL\.md$')
VERSION_RE = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
TARBALL_RE = re.compile(r'^rescue-skills-(\d+\.\d+\.\d+)\.tar\.gz$')

SIGNER_LINE_RE = re.compile(
    r'^(?P<principal>[A-Za-z0-9._@-]+)\s+namespaces="' + re.escape(NAMESPACE) + r'"\s+'
    r'(?P<type>ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+(?P<key>[A-Za-z0-9+/]+={0,2})(?:\s+\S.*)?$')


class BundleError(Exception):
    """The bundle, manifest or input does not meet the format."""


def version_tuple(text: str) -> tuple[int, int, int]:
    m = VERSION_RE.match(text or '')
    if not m:
        raise BundleError(f'not a MAJOR.MINOR.PATCH version: {text!r}')
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_skill_text(name: str, data: bytes) -> None:
    """Skill file rules shared by build and check: UTF-8, size, frontmatter name equals the directory."""
    if not data or len(data) > MAX_FILE_BYTES:
        raise BundleError(f'skills/{name}/SKILL.md is empty or larger than {MAX_FILE_BYTES} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise BundleError(f'skills/{name}/SKILL.md is not UTF-8') from exc
    if '\x00' in text or '\r' in text:
        raise BundleError(f'skills/{name}/SKILL.md contains NUL or CR characters')
    if not text.startswith('---\n') or '\n---\n' not in text[4:]:
        raise BundleError(f'skills/{name}/SKILL.md has no frontmatter')
    front = text[4:text.index('\n---\n', 4)]
    fields = {}
    for line in front.splitlines():
        key, sep, value = line.partition(':')
        if sep and key.strip() in ('name', 'description'):
            fields[key.strip()] = value.strip()
    if fields.get('name') != name:
        raise BundleError(f'skills/{name}/SKILL.md frontmatter name must equal the directory name')
    if not fields.get('description'):
        raise BundleError(f'skills/{name}/SKILL.md frontmatter has no description')


def collect_skills(skills_dir: Path) -> list[tuple[str, bytes]]:
    """Return [(skills/<name>/SKILL.md, content)] sorted by path. Anything else in the tree is an error."""
    if not skills_dir.is_dir() or skills_dir.is_symlink():
        raise BundleError(f'skills directory missing: {skills_dir}')
    out = []
    for entry in sorted(skills_dir.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_dir() or not NAME_RE.match(entry.name):
            raise BundleError(f'unexpected entry in the skills directory: {entry.name}')
        children = sorted(p.name for p in entry.iterdir())
        if children != ['SKILL.md']:
            raise BundleError(f'skills/{entry.name} must contain exactly SKILL.md, found {children}')
        skill = entry / 'SKILL.md'
        if skill.is_symlink() or not skill.is_file():
            raise BundleError(f'skills/{entry.name}/SKILL.md is not a regular file')
        data = skill.read_bytes()
        check_skill_text(entry.name, data)
        out.append((f'skills/{entry.name}/SKILL.md', data))
    if not out:
        raise BundleError('no skills found')
    if len(out) > MAX_FILES or sum(len(d) for _, d in out) > MAX_TOTAL_BYTES:
        raise BundleError('too many skills or too many bytes for the bundle limits')
    return out


def build_tarball(files: list[tuple[str, bytes]]) -> bytes:
    """Deterministic tar.gz: sorted order, ustar, mtime 0, uid/gid 0, no names, mode 0644, no dirs, gzip mtime 0."""
    raw = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for path, data in files:
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mtime = 0
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.type = tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def build(skills_dir: Path, version: str, min_toolkit: str, out_dir: Path) -> tuple[Path, Path]:
    """Write the tarball and manifest into out_dir (created). Returns their paths."""
    if version_tuple(min_toolkit) > version_tuple(version):
        raise BundleError(f'minimum toolkit version {min_toolkit} is above the bundle version {version}')
    files = collect_skills(skills_dir)
    tarball = build_tarball(files)
    if len(tarball) > MAX_TARBALL_BYTES:
        raise BundleError('tarball exceeds the size limit')
    name = f'rescue-skills-{version}.tar.gz'
    manifest = {
        'schema': SCHEMA,
        'bundle_version': version,
        'min_toolkit_version': min_toolkit,
        'tarball': {'name': name, 'sha256': sha256_hex(tarball), 'size': len(tarball)},
        'files': [{'path': p, 'sha256': sha256_hex(d), 'size': len(d)} for p, d in files],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir / name
    man_path = out_dir / f'rescue-skills-{version}.manifest.json'
    tar_path.write_bytes(tarball)
    man_path.write_bytes(manifest_bytes(manifest))
    return tar_path, man_path


def parse_manifest(data: bytes) -> dict:
    """Strict manifest parse: size, exact keys and types. Raises BundleError."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise BundleError('manifest too large')
    try:
        m = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleError('manifest is not valid JSON') from exc

    def keys(obj, expected, what):
        if not isinstance(obj, dict) or set(obj) != set(expected):
            raise BundleError(f'{what}: unexpected or missing keys')

    keys(m, ['schema', 'bundle_version', 'min_toolkit_version', 'tarball', 'files'], 'manifest')
    if m['schema'] != SCHEMA:
        raise BundleError('unsupported manifest schema')
    for field in ('bundle_version', 'min_toolkit_version'):
        if not isinstance(m[field], str):
            raise BundleError(f'{field} must be a string')
        version_tuple(m[field])
    if version_tuple(m['min_toolkit_version']) > version_tuple(m['bundle_version']):
        raise BundleError('min_toolkit_version is above bundle_version')
    t = m['tarball']
    keys(t, ['name', 'sha256', 'size'], 'tarball')
    if t['name'] != f"rescue-skills-{m['bundle_version']}.tar.gz":
        raise BundleError('tarball name does not match the bundle version')
    if not isinstance(t['sha256'], str) or not SHA_RE.match(t['sha256']):
        raise BundleError('tarball sha256 malformed')
    if not isinstance(t['size'], int) or isinstance(t['size'], bool) or not 0 < t['size'] <= MAX_TARBALL_BYTES:
        raise BundleError('tarball size out of range')
    files = m['files']
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise BundleError('files must be a non-empty list within the limit')
    seen = []
    total = 0
    for f in files:
        keys(f, ['path', 'sha256', 'size'], 'file entry')
        if not isinstance(f['path'], str) or not PATH_RE.match(f['path']):
            raise BundleError('file path is not skills/<name>/SKILL.md')
        if not isinstance(f['sha256'], str) or not SHA_RE.match(f['sha256']):
            raise BundleError('file sha256 malformed')
        if not isinstance(f['size'], int) or isinstance(f['size'], bool) or not 0 < f['size'] <= MAX_FILE_BYTES:
            raise BundleError('file size out of range')
        seen.append(f['path'])
        total += f['size']
    if seen != sorted(seen) or len(set(seen)) != len(seen):
        raise BundleError('files are not sorted and unique')
    if total > MAX_TOTAL_BYTES:
        raise BundleError('total file size exceeds the limit')
    return m


def check_bundle(manifest_path: Path, tarball_path: Path) -> dict:
    """Validate manifest and tarball against each other, in memory. Returns the manifest. Raises BundleError."""
    manifest = parse_manifest(Path(manifest_path).read_bytes())
    tarball = Path(tarball_path).read_bytes()
    t = manifest['tarball']
    if len(tarball) != t['size'] or sha256_hex(tarball) != t['sha256']:
        raise BundleError('tarball does not match the manifest sha256 or size')
    expected = {f['path']: f for f in manifest['files']}
    order = []
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball), mode='r:gz') as tar:
            for member in tar:
                if not member.isreg():
                    raise BundleError(f'{member.name!r} is not a regular file')
                if member.name not in expected or member.name in order:
                    raise BundleError(f'{member.name!r} is not allowed or is duplicated')
                if member.mode & 0o7111 or member.uid or member.gid:
                    raise BundleError(f'{member.name!r} has unexpected mode or owner')
                if member.size > MAX_FILE_BYTES:
                    raise BundleError(f'{member.name!r} is too large')
                data = tar.extractfile(member).read(MAX_FILE_BYTES + 1)
                entry = expected[member.name]
                if len(data) != entry['size'] or sha256_hex(data) != entry['sha256']:
                    raise BundleError(f'{member.name!r} does not match the manifest')
                check_skill_text(PATH_RE.match(member.name).group(1), data)
                order.append(member.name)
                total += len(data)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise BundleError(f'tarball is not a readable tar.gz: {exc}') from exc
    if order != [f['path'] for f in manifest['files']]:
        raise BundleError('tarball members differ from the manifest list or order')
    if total > MAX_TOTAL_BYTES:
        raise BundleError('uncompressed size exceeds the limit')
    return manifest


def fingerprint(key_b64: str) -> str:
    blob = base64.b64decode(key_b64 + '=' * (-len(key_b64) % 4))
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def allowed_signers_state(text: str) -> tuple[str, str]:
    """Classify an allowed_signers file: ('placeholder'|'pinned'|'invalid', detail).

    placeholder: the marker appears anywhere, or there is no entry at all. The updater must refuse.
    pinned: at least one entry, every entry is `<principal> namespaces="rescue-skills" <ed25519 type> <key> [comment]`.
    invalid: anything else (fail closed, same as placeholder).
    """
    if PLACEHOLDER_MARKER in text:
        return 'placeholder', 'placeholder marker present'
    prints = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = SIGNER_LINE_RE.match(line)
        if not m:
            return 'invalid', 'an entry is not <principal> namespaces="rescue-skills" <ed25519 key>'
        try:
            prints.append(fingerprint(m.group('key')))
        except ValueError:
            return 'invalid', 'an entry has an undecodable key'
    if not prints:
        return 'placeholder', 'no entries'
    return 'pinned', ' '.join(prints)
