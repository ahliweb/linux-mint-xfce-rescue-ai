"""Additional OS detection (Linux Mint, other Linux, Windows, macOS) beyond scan-target-os.py and the host launchers.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com. Owned by
ahliweb/linux-mint-xfce-rescue-ai#16. Contract: see scripts/rescue_modules/__init__.py and
docs/repair-framework.md. Read-only; every check degrades to 'unknown' when a file, tool or
permission is missing. Only numbers and status codes leave this module: no file names, paths,
package names or log text.

  collect_offline_target(ctx, root, target)  live USB: one installed OS mounted read-only at *root*
  collect_system(ctx)                        Linux host mode: the same Linux checks on the running system
                                             (nothing in live mode: the live session is not the target)

Files below a target root are read without following symlinks (a hostile target can never point
a check at the live system) and with case-insensitive lookups (NTFS semantics).
"""
import os
import re
import stat

PROC_LOCKS = '/proc/locks'
BOOT_WARN_PERCENT = 15.0
BOOT_FAIL_PERCENT = 5.0
MAX_LOG_TAIL = 4 * 1024 * 1024
MAX_TEXT = 4 * 1024 * 1024
MAX_FILES = 200

_statvfs = os.statvfs  # test seam


def _check(check_id, status, kind=None, number=None):
    item = {'check_id': check_id, 'status': status}
    if kind is not None:
        item['kind'], item['number'] = kind, number
    return item


# ------------------------------------------------------------ confined file access

def _lookup(cur, name):
    if os.path.lexists(os.path.join(cur, name)):
        return name
    try:
        entries = os.listdir(cur)
    except OSError:
        return None
    wanted = name.casefold()
    for entry in entries:
        if entry.casefold() == wanted:
            return entry
    return None


def _path(root, rel):
    """REL below ROOT, case-insensitive, or None. Any symlink on the way makes it None."""
    cur = os.path.realpath(root)
    for part in [p for p in rel.split('/') if p]:
        name = _lookup(cur, part)
        if name is None:
            return None
        cur = os.path.join(cur, name)
        if os.path.islink(cur):
            return None
    return cur


def _read(root, rel, limit=MAX_TEXT, tail=False):
    """Text of a regular file (at most *limit* bytes, the end of it when *tail*), or None."""
    path = _path(root, rel)
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if tail and st.st_size > limit:
            os.lseek(fd, st.st_size - limit, os.SEEK_SET)
        data = os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data.decode('utf-8', 'replace')


def _names(root, rel):
    path = _path(root, rel)
    if path is None:
        return None
    try:
        return os.listdir(path)
    except OSError:
        return None


def _size(root, rel):
    path = _path(root, rel)
    if path is None:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_size if stat.S_ISREG(st.st_mode) else None


# ------------------------------------------------------------------------ Linux

def _boot_space(root):
    names = _names(root, 'boot')
    if not names or not any(n.startswith('vmlinuz-') for n in names):
        return _check('linux-boot-partition-space', 'unknown')  # separate /boot that was not examined
    try:
        st = _statvfs(_path(root, 'boot'))
    except (OSError, TypeError):
        return _check('linux-boot-partition-space', 'unknown')
    if not st.f_blocks:
        return _check('linux-boot-partition-space', 'unknown')
    pct = round(st.f_bavail * 100.0 / st.f_blocks, 1)
    status = 'fail' if pct < BOOT_FAIL_PERCENT else 'warn' if pct < BOOT_WARN_PERCENT else 'pass'
    return _check('linux-boot-partition-space', status, 'percent', pct)


def _grub_config(root):
    grub_dir = None
    for rel in ('boot/grub', 'boot/grub2'):
        if _path(root, rel) is not None:
            grub_dir = rel
            break
    if grub_dir is None and _path(root, 'etc/default/grub') is None:
        names = _names(root, 'boot')
        if not names:
            return _check('linux-grub-config', 'unknown')      # separate /boot that was not examined
        return _check('linux-grub-config', 'not_applicable')   # another boot loader
    if grub_dir is None:
        names = _names(root, 'boot')
        if not names:
            return _check('linux-grub-config', 'unknown')
        return _check('linux-grub-config', 'fail', 'count', 0)  # GRUB is configured but grub.cfg is gone
    size = _size(root, grub_dir + '/grub.cfg')
    if not size:
        return _check('linux-grub-config', 'fail', 'count', 0)
    text = _read(root, grub_dir + '/grub.cfg')
    if text is None:
        return _check('linux-grub-config', 'unknown')
    entries = len(re.findall(r'^\s*menuentry\s', text, re.M))
    if entries == 0:
        return _check('linux-grub-config', 'fail', 'count', 0)
    names = _names(root, 'boot') or []
    stale = 0
    if any(n.startswith('vmlinuz-') for n in names):
        have = {n.casefold() for n in names}
        for m in re.finditer(r'^\s*linux(?:efi|16)?\s+(\S+)', text, re.M):
            base = m.group(1).rsplit('/', 1)[-1].casefold()
            if base.startswith('vmlinuz-') and base not in have:
                stale += 1
    if stale:
        return _check('linux-grub-config', 'warn', 'count', stale)
    return _check('linux-grub-config', 'pass', 'count', entries)


def _apt_sources(root):
    if _path(root, 'etc/apt') is None:
        return _check('linux-apt-sources', 'not_applicable')
    enabled, readable = 0, False
    text = _read(root, 'etc/apt/sources.list', limit=256 * 1024)
    if text is not None:
        readable = True
        enabled += sum(1 for ln in text.splitlines() if re.match(r'^\s*deb(\s|\[)', ln))
    for name in sorted(_names(root, 'etc/apt/sources.list.d') or [])[:MAX_FILES]:
        low = name.lower()
        body = _read(root, 'etc/apt/sources.list.d/' + name, limit=256 * 1024)
        if body is None:
            continue
        readable = True
        if low.endswith('.list'):
            enabled += sum(1 for ln in body.splitlines() if re.match(r'^\s*deb(\s|\[)', ln))
        elif low.endswith('.sources'):
            for stanza in re.split(r'\n\s*\n', body):
                if re.search(r'^Types:\s*.*\bdeb\b', stanza, re.M) and re.search(r'^URIs:', stanza, re.M) \
                        and not re.search(r'^Enabled:\s*(no|false)\b', stanza, re.M | re.I):
                    enabled += 1
    if not readable:
        return _check('linux-apt-sources', 'unknown')
    return _check('linux-apt-sources', 'pass' if enabled else 'warn', 'count', enabled)


def _proc_locks_text():
    try:
        with open(PROC_LOCKS, encoding='ascii', errors='replace') as handle:
            return handle.read(1024 * 1024)
    except OSError:
        return None


def _held_locks(root):
    """Number of advisory locks held on the dpkg/apt lock files of the running system."""
    text = _proc_locks_text()
    if text is None:
        return None
    inodes = set()
    for rel in ('var/lib/dpkg/lock', 'var/lib/dpkg/lock-frontend', 'var/lib/apt/lists/lock',
                'var/cache/apt/archives/lock'):
        path = _path(root, rel)
        if path:
            try:
                inodes.add(os.stat(path).st_ino)
            except OSError:
                pass
    held = 0
    for line in text.splitlines():
        fields = line.split()
        for field in fields:
            parts = field.split(':')
            if len(parts) == 3 and parts[2].isdigit() and int(parts[2]) in inodes:
                held += 1
                break
    return held


def _dpkg_lock(root, host):
    if _path(root, 'var/lib/dpkg') is None:
        return _check('linux-dpkg-lock', 'not_applicable')
    updates = _names(root, 'var/lib/dpkg/updates')
    if updates is None:
        return _check('linux-dpkg-lock', 'unknown')
    pending = len([n for n in updates if not n.startswith('.')])
    held = _held_locks(root) if host else 0
    if host and held is None:
        return _check('linux-dpkg-lock', 'warn', 'count', pending) if pending else _check('linux-dpkg-lock', 'unknown')
    total = pending + (held or 0)
    return _check('linux-dpkg-lock', 'warn' if total else 'pass', 'count', total)


def _linux_checks(root, host):
    return [_boot_space(root), _grub_config(root), _apt_sources(root), _dpkg_lock(root, host)]


# ---------------------------------------------------------------------- Windows

CBS_MARKERS = re.compile(r'cannot repair member file|csi payload corrupt|store corruption|component store is repairable',
                         re.I)
VSS_NAME = re.compile(r'^\{[0-9a-fA-F-]{36}\}\{[0-9a-fA-F-]{36}\}$')


def _windows_checks(root):
    checks = []
    # BCD: on UEFI systems the store lives on the ESP (not on this volume); only a BIOS-style
    # Boot\BCD or a Boot directory without one is conclusive here.
    if _size(root, 'Boot/BCD'):
        checks.append(_check('windows-boot-config', 'pass'))
    elif _path(root, 'Boot') is not None:
        checks.append(_check('windows-boot-config', 'fail'))
    else:
        checks.append(_check('windows-boot-config', 'unknown'))
    log = _read(root, 'Windows/Logs/CBS/CBS.log', limit=MAX_LOG_TAIL, tail=True)
    if log is None:
        checks.append(_check('windows-system-files', 'unknown'))
    else:
        n = len(CBS_MARKERS.findall(log))
        checks.append(_check('windows-system-files', 'warn' if n else 'pass', 'count', n))
    names = _names(root, 'System Volume Information')
    if names is None:
        checks.append(_check('windows-restore-points', 'unknown'))
    else:
        n = len([x for x in names if VSS_NAME.match(x)])
        checks.append(_check('windows-restore-points', 'pass' if n else 'warn', 'count', n))
    return checks


# ----------------------------------------------------------------------- hooks

def collect_system(ctx):
    """Linux host mode only; the live session is not the target, and Windows/macOS hosts use host/modules."""
    if ctx.mode != 'host':
        return []
    root = ctx.fixture_root or '/'
    if not ctx.fixture_root and (not hasattr(os, 'uname') or os.uname().sysname != 'Linux'):
        return []
    return _linux_checks(root, host=True)


def collect_offline_target(ctx, root, target):
    family = (target or {}).get('family')
    if family in ('linuxmint', 'linux-other'):
        return _linux_checks(root, host=False)
    if family == 'windows':
        return _windows_checks(root)
    if family == 'macos':
        # APFS cannot be verified from Linux; verification is a macOS Recovery (Disk Utility) step.
        return [_check('macos-disk-verify', 'unknown')]
    return []
