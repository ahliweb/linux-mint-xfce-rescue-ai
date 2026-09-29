#!/usr/bin/env python3
"""Read-only scan of the operating systems installed on the PC's internal disks.

Runs inside the Linux Mint XFCE live session (as root, via `sudo -n`), detects
Windows, Linux Mint / other Linux and macOS partitions, inspects each strictly
read-only and writes schema 1.1 evidence (rescue-ai/v1) containing only bounded
status codes and numbers: no usernames, hostnames, file names, paths, serials or
raw text.

Safety properties (see docs/target-os-scan.md and docs/security-model.md):
  * every target is mounted read-only (ro,noexec,nosuid,nodev + no journal replay)
    under a private 0700 temp directory and always unmounted in `finally`;
  * BitLocker, LUKS and FileVault volumes are never unlocked;
  * no fsck, chkdsk, ntfsfix or any other mutating tool is ever run;
  * the rescue USB (/cdrom, /run/live/medium, /isodevice, Ventoy, removable/USB
    disks), loop, rom and zram devices are excluded;
  * symlinks inside a target are resolved inside that target's root, never
    against the live system.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Usage: scan-target-os.py --output FILE [--fixture-root DIR]
  --fixture-root is a TEST hook: every subdirectory NAME of DIR is treated as an
  already-mounted partition root, described by the sidecar DIR/NAME.meta.json
  (fstype, label, parttype, uuid, partuuid, size, encryption, ...). A
  NAME.meta.json without a directory is a partition that cannot be mounted.
Exit codes: 0 evidence written, 1 fatal error, 2 usage error.
"""
import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

SOURCE = 'offline-target-scan'
ENV_SOURCE = 'collector-allowlist'
MODEL_ID = 'mimo-v2.6-flash'
MAX_TARGETS = 8
MAX_CHECKS = 64
MIN_UNMOUNTABLE_BYTES = 8 * 1024 ** 3

LSBLK_COLUMNS = 'PATH,TYPE,FSTYPE,PARTTYPE,LABEL,SIZE,MOUNTPOINTS,RM,TRAN,PKNAME,UUID,PARTUUID,PARTLABEL'
LIVE_MOUNTPOINTS = ('/cdrom', '/run/live/medium', '/isodevice')
VENTOY_LABELS = ('ventoy', 'vtoyefi')
ESP_PARTTYPE = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
APFS_PARTTYPE = '7c3457ef-0000-11aa-aa11-00306543ecac'
# Windows recovery, Microsoft reserved, Apple recovery/boot helper containers.
SKIP_PARTTYPES = (
    'de94bba4-06d1-4d40-a16a-bfd50179d6ac',
    'e3c9e316-0b5c-4db8-817d-f92df00215ae',
    '52637672-7900-11aa-aa11-00306543ecac',
    '69646961-6700-11aa-aa11-00306543ecac',
)
DEVICE_RE = re.compile(r'^/dev/[A-Za-z0-9/_.+-]+$')
RELEASE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$')


class Terminated(BaseException):
    """Raised from a signal handler so that `finally` blocks unmount everything."""


def _on_signal(signum, _frame):
    raise Terminated(signum)


# --------------------------------------------------------------------------- helpers

def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def run(cmd, timeout=8):
    """Run an allowlisted command (argv list, never a shell). Returns (rc, stdout, stderr) or None."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, proc.stdout, proc.stderr


def sanitize_release(text, limit=48):
    """Reduce text to the schema's release pattern; None when nothing usable remains."""
    if not text:
        return None
    cleaned = re.sub(r'[^A-Za-z0-9 ._+()/-]', '', str(text)).strip()
    cleaned = re.sub(r'^[^A-Za-z0-9]+', '', cleaned)[:limit].rstrip()
    return cleaned if cleaned and RELEASE_RE.match(cleaned) else None


def truthy(value):
    return value in (True, 1, '1', 'true', 'True')


def check(check_id, status, kind=None, number=None):
    return {'id': check_id, 'status': status, 'kind': kind, 'number': number}


# ------------------------------------------------- confined, case-insensitive file access

def _lookup(cur, name):
    path = os.path.join(cur, name)
    if os.path.lexists(path):
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


def resolve(root, rel, max_links=40):
    """Resolve REL below ROOT, following symlinks inside ROOT only.

    Absolute symlinks are re-rooted at ROOT and `..` never leaves it, so a hostile
    or ordinary link (e.g. etc/os-release -> ../usr/lib/os-release) can never read
    the live system. Lookups are case-insensitive (NTFS semantics). Returns the
    real path or None."""
    root = os.path.realpath(root)
    cur = root
    links = 0
    stack = [p for p in reversed(rel.split('/')) if p]
    while stack:
        part = stack.pop()
        if part == '.':
            continue
        if part == '..':
            if cur != root:
                cur = os.path.dirname(cur)
            continue
        name = _lookup(cur, part)
        if name is None:
            return None
        nxt = os.path.join(cur, name)
        if os.path.islink(nxt):
            links += 1
            if links > max_links:
                return None
            try:
                target = os.readlink(nxt)
            except OSError:
                return None
            if target.startswith('/'):
                cur = root
            stack.extend(p for p in reversed(target.split('/')) if p)
            continue
        cur = nxt
    return cur


def exists(root, rel):
    return resolve(root, rel) is not None


def file_size(root, rel):
    path = resolve(root, rel)
    if path is None:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_size if stat.S_ISREG(st.st_mode) else None


def read_lines(root, rel, max_bytes=64 * 1024 * 1024):
    """Yield decoded lines of a regular file below ROOT (bounded); yields nothing if unreadable."""
    path = resolve(root, rel)
    if path is None:
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            total = 0
            for raw in handle:
                total += len(raw)
                if total > max_bytes:
                    return
                yield raw.decode('utf-8', 'replace').rstrip('\r\n')
    except OSError:
        return
    finally:
        os.close(fd)


def list_names(root, rel):
    path = resolve(root, rel)
    if path is None:
        return None
    try:
        return os.listdir(path)
    except OSError:
        return None


def count_files(root, rel, suffix=None, cap=100000):
    path = resolve(root, rel)
    if path is None:
        return None
    n = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False) and (
                        suffix is None or entry.name.lower().endswith(suffix)):
                    n += 1
                    if n >= cap:
                        break
    except OSError:
        return None
    return n


def parse_os_release(root):
    values = {}
    for rel in ('etc/os-release', 'usr/lib/os-release'):
        lines = list(read_lines(root, rel, max_bytes=65536))
        if not lines:
            continue
        for line in lines:
            m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
            if m:
                values[m.group(1)] = m.group(2).strip().strip('"\'')
        return values
    return None


def free_space_check(root, override=None):
    if override is not None:
        pct = float(override)
    else:
        try:
            st = os.statvfs(root)
        except OSError:
            return check('disk-free-space', 'unknown')
        if not st.f_blocks:
            return check('disk-free-space', 'unknown')
        pct = round(st.f_bavail * 100.0 / st.f_blocks, 1)
    status = 'fail' if pct < 5 else 'warn' if pct < 10 else 'pass'
    return check('disk-free-space', status, 'percent', pct)


# ------------------------------------------------------------------ NTFS dirty flag

def ntfs_volume_dirty(handle):
    """Read the $Volume dirty flag from a raw NTFS volume (read-only, bounded).

    Returns True/False, or None when the layout cannot be parsed cheaply."""
    try:
        boot = handle.read(512)
        if len(boot) < 512 or boot[3:11] != b'NTFS    ':
            return None
        bps = struct.unpack_from('<H', boot, 0x0B)[0]
        spc = boot[0x0D]
        mft_lcn = struct.unpack_from('<Q', boot, 0x30)[0]
        cpr = struct.unpack_from('<b', boot, 0x40)[0]
        if bps not in (512, 1024, 2048, 4096) or spc == 0:
            return None
        cluster = bps * spc
        rec_size = cpr * cluster if cpr > 0 else 1 << -cpr
        if not 256 <= rec_size <= 65536:
            return None
        handle.seek(mft_lcn * cluster + 3 * rec_size)
        rec = bytearray(handle.read(rec_size))
        if len(rec) != rec_size or rec[:4] != b'FILE':
            return None
        usa_off, usa_cnt = struct.unpack_from('<HH', rec, 4)
        usn = bytes(rec[usa_off:usa_off + 2])
        for i in range(1, usa_cnt):
            end = i * 512 - 2
            if end + 2 > len(rec):
                break
            if bytes(rec[end:end + 2]) != usn:
                return None
            rec[end:end + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
        off = struct.unpack_from('<H', rec, 0x14)[0]
        while off + 24 <= len(rec):
            atype, alen = struct.unpack_from('<II', rec, off)
            if atype == 0xFFFFFFFF or alen < 24 or off + alen > len(rec):
                return None
            if atype == 0x70 and rec[off + 8] == 0:  # resident $VOLUME_INFORMATION
                voff = struct.unpack_from('<H', rec, off + 0x14)[0]
                flags = struct.unpack_from('<H', rec, off + voff + 10)[0]
                return bool(flags & 1)
            off += alen
    except (OSError, struct.error, ValueError):
        return None
    return None


def raw_ntfs_dirty(dev_path):
    if not DEVICE_RE.match(dev_path or ''):
        return None
    try:
        with open(dev_path, 'rb') as handle:
            return ntfs_volume_dirty(handle)
    except OSError:
        return None


# ---------------------------------------------------------------------- partitions

def make_part(**kw):
    part = {'path': None, 'type': 'part', 'fstype': None, 'parttype': None, 'label': None,
            'size': 0, 'mountpoints': [], 'rm': False, 'tran': None, 'disk': None,
            'uuid': None, 'partuuid': None, 'partlabel': None, 'meta': None, 'fixture_dir': None}
    part.update(kw)
    return part


def _flatten(nodes, disk, out):
    for node in nodes:
        top = disk if disk is not None else node.get('path')
        mps = node.get('mountpoints')
        if mps is None and node.get('mountpoint'):
            mps = [node.get('mountpoint')]
        try:
            size = int(node.get('size') or 0)
        except (TypeError, ValueError):
            size = 0
        out.append(make_part(
            path=node.get('path'), type=node.get('type'),
            fstype=node.get('fstype'), parttype=(node.get('parttype') or '').lower() or None,
            label=node.get('label'), size=size,
            mountpoints=[m for m in (mps or []) if m], rm=truthy(node.get('rm')),
            tran=node.get('tran'), disk=top,
            uuid=node.get('uuid'), partuuid=node.get('partuuid'), partlabel=node.get('partlabel')))
        _flatten(node.get('children') or [], top, out)


def excluded_disks(records):
    """Disks that must never be scanned: rescue USB, removable/USB, loop/rom/zram/ram."""
    bad = set()
    for rec in records:
        disk = rec['disk']
        path = rec['path'] or ''
        top = path == disk
        if rec['type'] in ('loop', 'rom') or path.startswith(('/dev/zram', '/dev/loop', '/dev/sr', '/dev/ram')):
            bad.add(disk)
        if top and (rec['rm'] or (rec['tran'] or '').lower() == 'usb'):
            bad.add(disk)
        if any(mp in LIVE_MOUNTPOINTS or mp.startswith('/run/live/') for mp in rec['mountpoints']):
            bad.add(disk)
        if (rec['label'] or '').lower() in VENTOY_LABELS:
            bad.add(disk)
    return bad


def enumerate_real():
    res = run(['lsblk', '-J', '-b', '-o', LSBLK_COLUMNS], timeout=20)
    if res is None or res[0] != 0:
        return None, None
    try:
        tree = json.loads(res[1]).get('blockdevices') or []
    except ValueError:
        return None, None
    records = []
    _flatten(tree, None, records)
    bad = excluded_disks(records)
    candidates = [r for r in records
                  if r['disk'] not in bad and r['type'] in ('part', 'lvm', 'disk')
                  and r['fstype'] and r['path'] and DEVICE_RE.match(r['path'])]
    return records, candidates


def load_fixtures(root):
    """Build partitions from a fixture directory (test hook, no block devices)."""
    names = set()
    for entry in os.listdir(root):
        if entry.endswith('.meta.json'):
            names.add(entry[:-len('.meta.json')])
        elif os.path.isdir(os.path.join(root, entry)):
            names.add(entry)
    parts = []
    for name in sorted(names):
        meta = {}
        meta_path = os.path.join(root, name + '.meta.json')
        if os.path.isfile(meta_path):
            with open(meta_path, encoding='utf-8') as handle:
                meta = json.load(handle)
        directory = os.path.join(root, name)
        directory = directory if os.path.isdir(directory) else None
        fstype = meta.get('fstype')
        if fstype is None and directory:
            fstype = 'ntfs' if exists(directory, 'Windows') else 'ext4'
        parts.append(make_part(
            path='/dev/fixture-' + re.sub(r'[^A-Za-z0-9]', '', name), fstype=fstype,
            parttype=(meta.get('parttype') or '').lower() or None, label=meta.get('label'),
            size=int(meta.get('size', 100 * 1024 ** 3)), uuid=meta.get('uuid'),
            partuuid=meta.get('partuuid'), partlabel=meta.get('partlabel'),
            disk=meta.get('disk', '/dev/fixture-disk0'), meta=meta, fixture_dir=directory))
    return parts


def classify(part):
    fs = (part['fstype'] or '').lower()
    pt = part['parttype'] or ''
    enc = ((part['meta'] or {}).get('encryption') or '').lower()
    if pt in SKIP_PARTTYPES:
        return None
    if fs == 'bitlocker' or enc == 'bitlocker':
        return 'bitlocker'
    if fs == 'crypto_luks' or enc == 'luks':
        return 'luks'
    if fs == 'apfs' or pt == APFS_PARTTYPE:
        return 'apfs'
    if fs == 'vfat' and pt == ESP_PARTTYPE:
        return 'esp'
    if fs == 'ntfs':
        return 'ntfs'
    if fs in ('ext2', 'ext3', 'ext4', 'btrfs', 'xfs'):
        return 'linuxfs'
    return None


# ------------------------------------------------------------------------- mounting

class MountResult:
    def __init__(self, root=None, status='failed', hint=None, handle=None):
        self.root = root      # directory holding the files, or None
        self.status = status  # ok | encrypted | unsupported | failed
        self.hint = hint      # small internal hint: 'dirty', 'filevault'
        self.handle = handle


class FixtureMounter:
    """Test hook: fixture directories are already 'mounted'; nothing is ever mounted."""

    def mount(self, part, kind):
        meta = part['meta'] or {}
        if kind == 'apfs':
            mode = meta.get('apfs')
            if mode == 'filevault':
                return MountResult(None, 'encrypted', 'filevault')
            if mode == 'unsupported' or not part['fixture_dir']:
                return MountResult(None, 'unsupported')
        if not part['fixture_dir']:
            return MountResult(None, 'failed')
        if meta.get('mount') == 'fail':
            return MountResult(None, 'failed', 'dirty' if meta.get('dirty') else None)
        return MountResult(part['fixture_dir'], 'ok')

    def release(self, result):
        pass

    def close(self):
        pass


class RealMounter:
    """Read-only mounts below a private 0700 temp directory; always unmounted."""

    RO = 'ro,noexec,nosuid,nodev'

    def __init__(self):
        self.base = tempfile.mkdtemp(prefix='rescue-scan-')
        os.chmod(self.base, 0o700)
        self.active = []
        self.counter = 0

    def _new_mountpoint(self):
        self.counter += 1
        mp = os.path.join(self.base, 'm%d' % self.counter)
        os.mkdir(mp, 0o700)
        return mp

    def _plain_mount(self, fstype, options, dev, mp):
        try:
            res = subprocess.run(['mount', '-t', fstype, '-o', options, '--', dev, mp],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                                 timeout=90, check=False)
        except subprocess.TimeoutExpired:
            self._umount(mp)
            return False, ''
        except OSError:
            return False, ''
        if res.returncode == 0:
            self.active.append({'mp': mp, 'fuse': False})
            return True, ''
        return False, (res.stderr or '').lower()

    def _ntfs_3g(self, dev, mp):
        exe = shutil.which('ntfs-3g') or shutil.which('mount.ntfs-3g')
        if not exe:
            return False, ''
        try:
            proc = subprocess.run([exe, '-o', 'ro,noexec,nosuid,nodev', dev, mp],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                                  timeout=90, check=False)
        except (OSError, subprocess.SubprocessError):
            self._umount(mp)
            return False, ''
        if proc.returncode == 0:
            self.active.append({'mp': mp, 'fuse': True})
            return True, ''
        return False, (proc.stderr or '').lower()

    def _apfs(self, dev, mp):
        exe = shutil.which('fsapfsmount')
        if not exe:
            return MountResult(None, 'unsupported')
        errfile = os.path.join(self.base, 'apfs-%d.err' % self.counter)
        err = open(errfile, 'wb')
        try:
            proc = subprocess.Popen([exe, dev, mp], stdout=subprocess.DEVNULL, stderr=err)
        except OSError:
            err.close()
            return MountResult(None, 'unsupported')
        entry = {'mp': mp, 'fuse': True, 'proc': proc, 'errfile': errfile}
        self.active.append(entry)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            rc = proc.poll()
            if os.path.ismount(mp) or (rc == 0 and os.listdir(mp)):
                err.close()
                return MountResult(mp, 'ok')
            if rc is not None and rc != 0:
                break
            time.sleep(0.25)
        err.close()
        try:
            with open(errfile, 'rb') as handle:
                text = handle.read(65536).decode('utf-8', 'replace').lower()
        except OSError:
            text = ''
        self._release_entry(entry)
        self.active = [e for e in self.active if e is not entry]
        if re.search(r'encrypt|password|unlock|recovery key|wrapped key|keybag', text):
            return MountResult(None, 'encrypted', 'filevault')
        return MountResult(None, 'failed')

    def mount(self, part, kind):
        dev = part['path']
        existing = [m for m in part['mountpoints'] if m.startswith('/') and not m.startswith('[')]
        if existing and kind != 'apfs':
            # Already mounted by the live session: only read from it, never unmount it.
            return MountResult(existing[0], 'ok')
        if not DEVICE_RE.match(dev or ''):
            return MountResult(None, 'failed')
        fs = (part['fstype'] or '').lower()
        mp = self._new_mountpoint()
        try:
            if kind == 'apfs':
                return self._apfs(dev, mp)
            if kind == 'esp':
                ok, _ = self._plain_mount('vfat', self.RO, dev, mp)
            elif kind == 'ntfs':
                ok, err = self._plain_mount('ntfs3', self.RO, dev, mp)
                hint_text = err
                if not ok:
                    ok, err2 = self._ntfs_3g(dev, mp)
                    hint_text += ' ' + err2
                if not ok:
                    hint = 'dirty' if re.search(r'dirty|hibernat|unclean|not cleanly|unsafe|fast restart',
                                                hint_text) else None
                    return MountResult(None, 'failed', hint)
            elif fs in ('ext2', 'ext3', 'ext4'):
                ok, _ = self._plain_mount('ext4', self.RO + ',noload', dev, mp)
            elif fs == 'xfs':
                ok, _ = self._plain_mount('xfs', self.RO + ',norecovery,nouuid', dev, mp)
            elif fs == 'btrfs':
                ok, _ = self._plain_mount('btrfs', self.RO + ',rescue=nologreplay', dev, mp)
            else:
                return MountResult(None, 'unsupported')
            return MountResult(mp, 'ok') if ok else MountResult(None, 'failed')
        except BaseException:
            self.release(MountResult(mp, 'ok'))
            raise

    def _umount(self, mp):
        if not os.path.ismount(mp):
            return True
        for cmd in (['umount', '--', mp], ['fusermount3', '-u', mp], ['fusermount', '-u', mp],
                    ['umount', '-l', '--', mp]):
            res = run(cmd, timeout=30)
            if res is not None and res[0] == 0 and not os.path.ismount(mp):
                return True
        return not os.path.ismount(mp)

    def _release_entry(self, entry):
        ok = self._umount(entry['mp'])
        proc = entry.get('proc')
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        if ok:
            for extra in (entry.get('errfile'),):
                if extra:
                    try:
                        os.unlink(extra)
                    except OSError:
                        pass
            try:
                os.rmdir(entry['mp'])
            except OSError:
                pass
        else:
            print('WARNING/PERINGATAN: could not unmount a scan mount; unmount manually before '
                  'removing disks / tidak dapat unmount mount pemindaian.', file=sys.stderr)

    def release(self, result):
        if result is None or result.root is None:
            # The mountpoint may exist even if the mount failed; tidy up below in close().
            return
        for entry in list(self.active):
            if entry['mp'] == result.root:
                self._release_entry(entry)
                self.active.remove(entry)
                return

    def close(self):
        for entry in list(reversed(self.active)):
            self._release_entry(entry)
        self.active = []
        try:
            for name in os.listdir(self.base):
                path = os.path.join(self.base, name)
                # Safety net for a mount that completed while a signal interrupted its bookkeeping.
                if os.path.isdir(path) and os.path.ismount(path):
                    self._umount(path)
                # rmdir only: never recursive, so a mount that failed to release can never be walked.
                try:
                    if os.path.isdir(path) and not os.path.ismount(path):
                        os.rmdir(path)
                    elif os.path.isfile(path):
                        os.unlink(path)
                except OSError:
                    pass
            os.rmdir(self.base)
        except OSError:
            pass


# ------------------------------------------------------------- per-family inspection

def scan_esp(root):
    info = {'ms': False, 'distros': set(), 'fallback': False}
    efi = resolve(root, 'EFI')
    if efi is None:
        return info
    try:
        names = os.listdir(efi)
    except OSError:
        return info
    for name in names:
        low = name.casefold()
        if low == 'microsoft':
            info['ms'] = exists(root, 'EFI/%s/Boot/bootmgfw.efi' % name)
        elif low == 'boot':
            info['fallback'] = exists(root, 'EFI/%s/bootx64.efi' % name)
        elif low != 'apple':
            if exists(root, 'EFI/%s/grubx64.efi' % name) or exists(root, 'EFI/%s/shimx64.efi' % name):
                info['distros'].add(low)
    return info


def boot_loader_check(family, esps, boot_mode):
    if family == 'macos':
        return check('boot-loader-files', 'not_applicable')
    if not esps:
        return check('boot-loader-files', 'unknown')
    if family == 'windows':
        return check('boot-loader-files', 'pass' if any(e['ms'] for e in esps) else 'fail')
    if family in ('linuxmint', 'linux-other'):
        distros = set().union(*(e['distros'] for e in esps))
        fallback = any(e['fallback'] for e in esps)
        if family == 'linuxmint' and distros & {'linuxmint', 'ubuntu'}:
            return check('boot-loader-files', 'pass')
        if family == 'linux-other' and distros:
            return check('boot-loader-files', 'pass')
        return check('boot-loader-files', 'warn' if (distros or fallback) else 'fail')
    return check('boot-loader-files', 'unknown')


def host_arch():
    machine = platform.machine().lower()
    return {'x86_64': 'x86_64', 'amd64': 'x86_64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, 'unknown')


def inspect_windows(root, part, mres):
    if resolve(root, 'Windows/System32/config/SYSTEM') is None:
        return None
    meta = part['meta'] or {}
    checks = [check('os-detection', 'pass'), check('encryption-status', 'pass'),
              free_space_check(root, meta.get('free_percent'))]
    hiber = file_size(root, 'hiberfil.sys')
    checks.append(check('windows-fast-startup', 'warn' if hiber else 'pass'))
    if 'dirty' in meta and meta['dirty'] is not None:
        dirty = bool(meta['dirty'])
    elif part['meta'] is None:
        dirty = raw_ntfs_dirty(part['path'])
    else:
        dirty = None
    checks.append(check('windows-ntfs-dirty', 'unknown' if dirty is None else 'warn' if dirty else 'pass'))
    checks.append(check('windows-pending-updates',
                        'warn' if exists(root, 'Windows/WinSxS/pending.xml') else 'pass'))
    dumps = count_files(root, 'Windows/Minidump')
    if dumps is None:
        checks.append(check('windows-crash-dumps', 'pass', 'count', 0))
    else:
        checks.append(check('windows-crash-dumps', 'warn' if dumps else 'pass', 'count', dumps))
    checks.append(check('windows-event-log-errors', 'unknown'))
    return {'family': 'windows', 'release': 'Windows', 'checks': checks}


def _fstab_entries(root):
    for line in read_lines(root, 'etc/fstab', max_bytes=1024 * 1024):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        yield fields[0], fields[2], (fields[3] if len(fields) > 3 else '')


def fstab_check(root, idents, locked_present):
    if resolve(root, 'etc/fstab') is None:
        return check('linux-fstab-consistency', 'unknown')
    unresolved = hard = 0
    for spec, fstype, options in _fstab_entries(root):
        tokens = options.split(',')
        if 'noauto' in tokens or 'nofail' in tokens:
            continue
        m = re.match(r'^(UUID|PARTUUID|LABEL|PARTLABEL)=(.*)$', spec)
        if not m:
            continue
        key = m.group(1)
        value = m.group(2).strip('"\'').lower()
        if value and value in idents[key]:
            continue
        unresolved += 1
        if fstype != 'swap':
            hard += 1
    if hard:
        # Volumes hidden behind locked LUKS/BitLocker cannot be resolved: do not call that a failure.
        return check('linux-fstab-consistency', 'warn' if locked_present else 'fail', 'count', unresolved)
    return check('linux-fstab-consistency', 'warn' if unresolved else 'pass', 'count', unresolved)


def kernel_check(root):
    names = list_names(root, 'boot')
    if names is None:
        return check('linux-kernel-initrd', 'unknown')
    lower = {n.casefold() for n in names}
    kernels = sorted(n for n in names if re.match(r'^vmlinuz-[A-Za-z0-9._+~-]+$', n)
                     and not n.endswith(('.sig', '.old')))
    if not kernels:
        # Empty /boot usually means a separate boot partition that is not the one examined.
        return check('linux-kernel-initrd', 'unknown')
    missing = 0
    for name in kernels:
        version = name[len('vmlinuz-'):].casefold()
        candidates = ('initrd.img-' + version, 'initrd-' + version, 'initramfs-%s.img' % version,
                      'initramfs-' + version)
        if not any(c in lower for c in candidates):
            missing += 1
    return check('linux-kernel-initrd', 'fail' if missing else 'pass', 'count', missing)


def package_check(root):
    path = resolve(root, 'var/lib/dpkg/status')
    if path is None:
        return check('linux-package-state', 'unknown')
    broken = unpacked = 0
    for line in read_lines(root, 'var/lib/dpkg/status'):
        if line.startswith('Status:'):
            words = line.split()
            state = words[-1] if words else ''
            if state in ('half-installed', 'half-configured'):
                broken += 1
            elif state == 'unpacked':
                unpacked += 1
    if broken:
        return check('linux-package-state', 'fail', 'count', broken + unpacked)
    if unpacked:
        return check('linux-package-state', 'warn', 'count', unpacked)
    return check('linux-package-state', 'pass', 'count', 0)


def inspect_linux(root, part, idents, locked_present):
    base = None
    for rel in ('', '@'):
        candidate = root if not rel else resolve(root, rel)
        if candidate and parse_os_release(candidate) is not None:
            base = candidate
            break
    if base is None:
        return None
    osr = parse_os_release(base) or {}
    family = 'linuxmint' if osr.get('ID', '').lower() == 'linuxmint' else 'linux-other'
    release = sanitize_release(osr.get('PRETTY_NAME') or osr.get('NAME'))
    meta = part['meta'] or {}
    checks = [check('os-detection', 'pass'), check('encryption-status', 'pass'),
              free_space_check(base, meta.get('free_percent')),
              fstab_check(base, idents, locked_present), kernel_check(base), package_check(base),
              check('linux-journal-errors', 'unknown')]
    return {'family': family, 'release': release, 'checks': checks}


def _apfs_volumes(root):
    names = list_names(root, '') or []
    vols = [os.path.join(root, n) for n in sorted(names) if re.match(r'^apfs\d+$', n)]
    return vols or [root]


def inspect_macos(root, part):
    volumes = _apfs_volumes(root)
    release = None
    found = False
    panics = 0
    seen_panics = False
    for vol in volumes:
        plist = resolve(vol, 'System/Library/CoreServices/SystemVersion.plist')
        if plist:
            found = True
            try:
                if os.path.getsize(plist) < 1024 * 1024:
                    with open(plist, 'rb') as handle:
                        data = plistlib.load(handle)
                    release = sanitize_release('%s %s' % (data.get('ProductName') or 'macOS',
                                                         data.get('ProductVersion') or ''))
            except (OSError, ValueError, plistlib.InvalidFileException):
                pass
        elif exists(vol, 'Users') and exists(vol, 'Library'):
            found = True
        count = count_files(vol, 'Library/Logs/DiagnosticReports', suffix='.panic')
        if count is not None:
            seen_panics = True
            panics += count
    meta = part['meta'] or {}
    checks = [check('os-detection', 'pass' if found else 'warn'), check('encryption-status', 'pass'),
              free_space_check(root, meta.get('free_percent')),
              check('macos-apfs-container', 'pass'), check('macos-filevault', 'pass')]
    if seen_panics:
        checks.append(check('macos-crash-reports', 'warn' if panics else 'pass', 'count', panics))
    else:
        checks.append(check('macos-crash-reports', 'unknown'))
    return {'family': 'macos', 'release': release or 'macOS', 'checks': checks}


def encrypted_target(kind, part):
    """Targets that are never unlocked: report what can be known without a key."""
    if kind == 'bitlocker':
        return {'family': 'windows', 'release': None, 'encryption': 'bitlocker',
                'access': 'not-mounted-encrypted',
                'checks': [check('os-detection', 'warn'), check('encryption-status', 'warn')]}
    if kind == 'luks':
        return {'family': 'linux-other', 'release': None, 'encryption': 'luks',
                'access': 'not-mounted-encrypted',
                'checks': [check('os-detection', 'warn'), check('encryption-status', 'warn')]}
    return None


def inspect_partition(part, kind, mounter, esps_for, idents, locked_present, boot_mode):
    """Return a target dict {family, release, encryption, access, arch, checks} or None."""
    enc = encrypted_target(kind, part)
    if enc is not None:
        enc['checks'].append(boot_loader_check(enc['family'], esps_for(part), boot_mode))
        return enc

    result = mounter.mount(part, kind)
    try:
        if kind == 'apfs':
            if result.status == 'encrypted':
                return {'family': 'macos', 'release': None, 'encryption': 'filevault',
                        'access': 'not-mounted-encrypted',
                        'checks': [check('os-detection', 'warn'), check('encryption-status', 'warn'),
                                   check('macos-apfs-container', 'pass'), check('macos-filevault', 'warn'),
                                   check('boot-loader-files', 'not_applicable')]}
            if result.status != 'ok':
                unsupported = result.status == 'unsupported'
                return {'family': 'macos', 'release': None, 'encryption': 'unknown',
                        'access': 'not-mounted-unsupported' if unsupported else 'unknown',
                        'checks': [check('os-detection', 'warn'), check('encryption-status', 'unknown'),
                                   check('macos-apfs-container', 'unknown' if unsupported else 'fail'),
                                   check('macos-filevault', 'unknown'),
                                   check('boot-loader-files', 'not_applicable')]}
            info = inspect_macos(result.root, part)
            info['checks'].append(boot_loader_check('macos', [], boot_mode))
            info.update({'encryption': 'none', 'access': 'read-only-mounted'})
            return info

        if result.status != 'ok':
            if part['size'] < MIN_UNMOUNTABLE_BYTES:
                return None
            checks = [check('os-detection', 'unknown'), check('encryption-status', 'unknown')]
            if kind == 'ntfs':
                checks.append(check('windows-ntfs-dirty', 'fail'))
            return {'family': 'unknown', 'release': None, 'encryption': 'unknown',
                    'access': 'unknown', 'checks': checks}

        info = None
        if kind == 'ntfs':
            info = inspect_windows(result.root, part, result)
        elif kind == 'linuxfs':
            info = inspect_linux(result.root, part, idents, locked_present)
        if info is None:
            return None  # a data partition, not an operating system
        info['checks'].append(boot_loader_check(info['family'], esps_for(part), boot_mode))
        info.update({'encryption': 'none', 'access': 'read-only-mounted'})
        return info
    finally:
        mounter.release(result)


# ----------------------------------------------------------------- environment checks

def network_status():
    res = run(['ip', 'route', 'show', 'default'])
    if res is None or res[0] != 0:
        return 'unknown'
    if res[1].strip():
        return 'pass'
    links = run(['ip', '-brief', 'link'])
    if links is None or links[0] != 0:
        return 'unknown'
    non_loopback = [ln for ln in links[1].splitlines() if ln.split() and ln.split()[0] != 'lo']
    return 'warn' if non_loopback else 'unknown'


def opaque_seed():
    try:
        with open('/etc/machine-id', encoding='ascii') as handle:
            mid = handle.read().strip()
        if mid:
            return 'machine-id:' + mid
    except (OSError, UnicodeDecodeError):
        pass
    return 'hostname:' + socket.gethostname() + '|' + platform.release()


def live_release():
    try:
        with open('/etc/os-release', encoding='utf-8') as handle:
            for line in handle:
                if line.startswith('PRETTY_NAME='):
                    return sanitize_release(line.split('=', 1)[1].strip().strip('"\''))
    except OSError:
        pass
    return sanitize_release(platform.platform())


# ------------------------------------------------------------------------ evidence

def build_evidence(targets, env_checks, now, boot_mode):
    stamp = iso(now)

    def emit(c, ref=None):
        item = {'check_id': c['id'], 'status': c['status'], 'source': SOURCE if ref else ENV_SOURCE,
                'observed_at': stamp}
        if ref:
            item['target_ref'] = ref
        if c['kind'] is not None:
            item['value'] = {'kind': c['kind'], 'number': c['number']}
        return item

    checks = [emit(c) for c in env_checks]
    target_systems = []
    for target in targets:
        if len(target_systems) >= MAX_TARGETS or len(checks) + len(target['checks']) > MAX_CHECKS:
            break
        ref = 'os-%d' % len(target_systems)
        target_systems.append({
            'ref': ref, 'family': target['family'], 'release': target['release'],
            'architecture': host_arch(), 'detection': 'live-offline',
            'encryption': target['encryption'], 'access': target['access']})
        checks.extend(emit(c, ref) for c in target['checks'])
    return {
        'schema_version': '1.1',
        'run_id': 'rescue-' + now.strftime('%Y%m%d-%H%M%S'),
        'source_platform': 'linux-mint-xfce-live',
        'boot_mode': boot_mode,
        'collected_at': stamp,
        'target_device_opaque_id': 'target-' + digest(opaque_seed())[:16],
        'ventoy_version': None,
        'linux_release': live_release(),
        'target_systems': target_systems,
        'checks': checks,
        'evidence_manifest': {
            'entry_count': len(checks),
            'manifest_sha256': digest(json.dumps(checks, sort_keys=True)),
            'storage_class': 'usb-rescue-state'},
        'ai_provider': {'provider_id': 'opencode-go', 'model_id': MODEL_ID,
                        'authenticated': False, 'destination_class': 'unknown'},
        'ai_analysis_status': 'not_run',
        'mutation_status': 'none',
        'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
        'classification': 'confidential',
        'source_references': ['opencode-go:provider', 'nist:sp-800-86'],
    }


def write_atomic(report, out):
    directory = os.path.dirname(os.path.abspath(out))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=directory)
    try:
        # mkstemp already creates the file 0600; FAT/exFAT state partitions may reject chmod/chown.
        try:
            os.fchmod(fd, 0o600)
            sudo_uid, sudo_gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
            if os.geteuid() == 0 and sudo_uid.isdigit() and sudo_gid.isdigit():
                os.fchown(fd, int(sudo_uid), int(sudo_gid))
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------------------ main

def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only multi-OS scan of internal disks (live USB).')
    parser.add_argument('--output', required=True, metavar='FILE')
    parser.add_argument('--fixture-root', metavar='DIR', help='test hook: directories treated as mounted partitions')
    args = parser.parse_args(argv)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _on_signal)

    now = utc_now()
    boot_mode = 'uefi' if os.path.exists('/sys/firmware/efi') else 'legacy-bios'

    if args.fixture_root:
        try:
            parts = load_fixtures(args.fixture_root)
        except (OSError, ValueError) as exc:
            print('scan-target-os: cannot read fixture root: %s' % exc, file=sys.stderr)
            return 1
        records = parts
        candidates = parts
        mounter = FixtureMounter()
        discovery = 'pass'
    else:
        if os.geteuid() != 0:
            print('scan-target-os: must run as root (sudo -n) to mount read-only.\n'
                  'scan-target-os: harus dijalankan sebagai root (sudo -n).', file=sys.stderr)
            return 1
        records, candidates = enumerate_real()
        if records is None:
            print('scan-target-os: lsblk failed; cannot enumerate disks / lsblk gagal.', file=sys.stderr)
            return 1
        mounter = RealMounter()
        discovery = 'pass' if candidates is not None else 'unknown'

    idents = {'UUID': set(), 'PARTUUID': set(), 'LABEL': set(), 'PARTLABEL': set()}
    for rec in records:
        for key, field in (('UUID', 'uuid'), ('PARTUUID', 'partuuid'), ('LABEL', 'label'),
                           ('PARTLABEL', 'partlabel')):
            if rec.get(field):
                idents[key].add(str(rec[field]).lower())
    # Volumes hidden behind locked LUKS/LVM cannot be resolved by UUID (BitLocker holds no Linux volumes).
    locked_present = any(classify(r) == 'luks' or (r['fstype'] or '') == 'LVM2_member' for r in candidates)

    targets = []
    try:
        esp_infos = []  # list of (disk, info)
        for part in candidates:
            if classify(part) == 'esp':
                res = mounter.mount(part, 'esp')
                try:
                    if res.status == 'ok':
                        esp_infos.append((part['disk'], scan_esp(res.root)))
                finally:
                    mounter.release(res)

        def esps_for(part):
            same = [info for disk, info in esp_infos if disk == part['disk']]
            return same or [info for _, info in esp_infos]

        for part in candidates:
            kind = classify(part)
            if kind in (None, 'esp'):
                continue
            target = inspect_partition(part, kind, mounter, esps_for, idents, locked_present, boot_mode)
            if target is not None:
                target.setdefault('encryption', 'none')
                targets.append(target)
    finally:
        mounter.close()

    env_checks = [check('block-device-discovery', discovery), check('network-connectivity', network_status())]
    if not targets:
        env_checks.append(check('os-detection', 'warn'))
    report = build_evidence(targets, env_checks, now, boot_mode)
    write_atomic(report, args.output)
    print(args.output)
    print('scan-target-os: %d operating system(s) examined, %d checks / sistem operasi diperiksa: %d'
          % (len(report['target_systems']), len(report['checks']), len(report['target_systems'])))
    for system in report['target_systems']:
        print('  %s %s access=%s encryption=%s' % (system['ref'], system['family'], system['access'],
                                                   system['encryption']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Terminated as exc:
        sys.exit(128 + int(exc.args[0]))
