"""Target mount provider for offline (live USB) OS repairs.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Contract (docs/repair-framework.md, "Target mount provider"):

    open_target(evidence_path, evidence, target_ref, rw) -> context manager
        with open_target(...) as root:      # root: mount point (str) of target *target_ref*

The engine (scripts/rescue-repair.py) calls it after the operator approved an action that has a
``target_root`` parameter. This module never decides *whether* to repair; it only makes the
approved target reachable, and always puts the machine back:

* The target is **re-identified** with the scanner's own code (scripts/scan-target-os.py is
  loaded with importlib and its ``enumerate_real`` / ``classify`` / ``inspect_partition`` are
  reused, so the exclusion rules for the rescue USB, removable media, loop and zram devices are
  not duplicated). ``os-N`` is the N-th target the scanner reports, exactly as in the evidence.
* It refuses when the re-identified family differs from ``target_systems[].family`` of the
  evidence, when the evidence says the target is encrypted or was not mounted, when the ref is
  unknown, or when the OS is macOS and a read-write mount is requested (APFS read-write from
  Linux is never supported). BitLocker, LUKS and FileVault are never unlocked.
* ``rw=False``: the scanner's read-only mount (ro,noexec,nosuid,nodev, no journal replay).
* ``rw=True`` (only for actions with ``requires_target_rw``): a read-write mount under a private
  0700 ``tempfile.mkdtemp`` directory with ``nosuid,nodev``. ``noexec`` is dropped for Linux
  targets because the approved action may ``chroot`` into it. Windows keeps ``noexec``. NTFS
  refuses read-write when ``hiberfil.sys`` is present (fast startup / hibernation) or the
  volume is flagged dirty. A Linux target that is already mounted somewhere (for example by
  the desktop) is refused: unmount it first. btrfs root subvolume ``@`` is honoured. A separate
  ``/boot`` from the target's fstab is mounted at ``<root>/boot`` too; if the fstab names a
  ``/boot`` that cannot be found, the mount is refused so nothing is ever written into the wrong
  directory.
* Chroot support: for a read-write Linux target ``/dev``, ``/dev/pts``, ``/proc`` and ``/sys`` are
  bind-mounted (private propagation) below the root so ``chroot {target_root} ...`` works. The
  ESP is not mounted (update-grub, update-initramfs and dpkg do not need it). A read-only
  target never gets bind mounts.
* Every mount is undone in reverse order in ``__exit__``, also on exceptions and on
  SIGINT/SIGTERM/SIGHUP (the signal is re-delivered after the cleanup). A mount that cannot be
  unmounted is reported loudly and never walked or deleted.
* Mount and umount run through ``sudo -n`` when the engine is not root. Only fixed argv lists
  are used; no shell.

Test hook: ``RESCUE_TARGET_MOUNT_FIXTURE_ROOT=/abs/dir`` (announced on stderr) makes the provider
use the scanner's fixture layout (NAME/ directories with NAME.meta.json sidecars) instead of block
devices. Nothing is mounted in that mode; the fixture directory itself is yielded. The refusal
rules are applied in the same way (using the sidecar metadata).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
FIXTURE_ENV = 'RESCUE_TARGET_MOUNT_FIXTURE_ROOT'
REF_RE = re.compile(r'^os-[0-7]$')
BINDS = ('/dev', '/dev/pts', '/proc', '/sys')
RW_LINUX = 'rw,nosuid,nodev'
RW_WINDOWS = 'rw,noexec,nosuid,nodev'


class TargetMountError(Exception):
    """The target cannot be provided safely; the message is shown to the operator."""


class Terminated(BaseException):
    """Raised from a signal handler so that cleanup runs; re-delivered after cleanup."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


# --------------------------------------------------------------------- privileged runner

def _priv_run(cmd, timeout=60):
    """Run a fixed argv as root (sudo -n when needed). Returns (returncode, stderr_lower) or None."""
    exe = shutil.which(cmd[0], path=SAFE_PATH)
    if exe is None:
        return None
    full = [exe] + list(cmd[1:])
    if os.geteuid() != 0:
        sudo = shutil.which('sudo', path=SAFE_PATH)
        if sudo is None:
            return None
        full = [sudo, '-n', '--'] + full
    env = {'PATH': SAFE_PATH, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    try:
        proc = subprocess.run(full, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, env=env, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, (proc.stderr or b'').decode('utf-8', 'replace').lower()


PRIV_RUN = _priv_run  # test seam: tests replace this so nothing is ever mounted


def _run(cmd, timeout=60):
    return PRIV_RUN(cmd, timeout)


_SCANNER = None


def load_scanner():
    """scripts/scan-target-os.py as a module (the single source of the exclusion/detection logic)."""
    global _SCANNER
    if _SCANNER is None:
        spec = importlib.util.spec_from_file_location('rescue_scan_target_os_mount', SCRIPTS / 'scan-target-os.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SCANNER = module
    return _SCANNER


def _sudo_mounter_class(scanner):
    """RealMounter with every mount/umount going through the privileged runner."""

    class SudoMounter(scanner.RealMounter):
        def _plain_mount(self, fstype, options, dev, mp):
            res = _run(['mount', '-t', fstype, '-o', options, '--', dev, mp], timeout=90)
            if res is None:
                return False, ''
            if res[0] == 0:
                self.active.append({'mp': mp, 'fuse': False})
                return True, ''
            return False, res[1]

        def _ntfs_3g(self, dev, mp):
            res = _run(['ntfs-3g', '-o', self.RO, dev, mp], timeout=90)
            if res is None:
                return False, ''
            if res[0] == 0:
                self.active.append({'mp': mp, 'fuse': True})
                return True, ''
            return False, res[1]

        def _umount(self, mp):
            if not os.path.ismount(mp):
                return True
            for cmd in (['umount', '--', mp], ['fusermount3', '-u', mp], ['fusermount', '-u', mp],
                        ['umount', '-l', '--', mp]):
                res = _run(cmd, timeout=30)
                if res is not None and res[0] == 0 and not os.path.ismount(mp):
                    return True
            return not os.path.ismount(mp)

    return SudoMounter


# ------------------------------------------------------------------------ the provider

class TargetMount:
    """Context manager yielding the mount point of one approved target."""

    def __init__(self, evidence_path, evidence, target_ref, rw):
        self.evidence_path = evidence_path
        self.evidence = evidence or {}
        self.ref = target_ref
        self.rw = bool(rw)
        self.fixture_root = self._fixture_root()
        self.base = None
        self._mounts = []       # own mount points (rw root, /boot, binds), in mount order
        self._mounter = None
        self._old_handlers = {}
        self.root = None
        self.info = {}

    # ---- seams for tests -------------------------------------------------------------
    @staticmethod
    def _fixture_root():
        value = os.environ.get(FIXTURE_ENV, '')
        if not value:
            return None
        if not value.startswith('/') or os.path.realpath(value) == '/' or not os.path.isdir(value):
            print('target_mount: ignoring invalid %s' % FIXTURE_ENV, file=sys.stderr)
            return None
        print('target_mount: TEST fixture mode active (%s); nothing is mounted' % FIXTURE_ENV, file=sys.stderr)
        return value

    def _enumerate(self, scanner):
        if self.fixture_root:
            parts = scanner.load_fixtures(self.fixture_root)
            return parts, parts
        records, candidates = scanner.enumerate_real()
        if records is None or candidates is None:
            raise TargetMountError('lsblk failed; cannot re-identify the target / lsblk gagal')
        return records, candidates

    def _make_mounter(self, scanner):
        if self.fixture_root:
            return scanner.FixtureMounter()
        return _sudo_mounter_class(scanner)()

    # ---- context manager ------------------------------------------------------------------
    def __enter__(self):
        self._install_signals()
        try:
            self.root = self._open()
            return self.root
        except BaseException:
            self._cleanup()
            self._restore_signals()
            raise

    def __exit__(self, exc_type, exc, tb):
        self._cleanup()
        signum = exc.signum if isinstance(exc, Terminated) else None
        self._restore_signals()
        if signum is not None:
            signal.raise_signal(signum)  # default action (or the caller's handler) after cleanup
        return False

    # ---- signals ------------------------------------------------------------------------------
    def _install_signals(self):
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(signum, _frame):
            raise Terminated(signum)

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            self._old_handlers[sig] = signal.signal(sig, handler)

    def _restore_signals(self):
        for sig, old in self._old_handlers.items():
            signal.signal(sig, old)
        self._old_handlers = {}

    # ---- identification ---------------------------------------------------------------------
    def _evidence_target(self):
        if not isinstance(self.ref, str) or not REF_RE.match(self.ref):
            raise TargetMountError('unknown target reference / referensi target tidak dikenal')
        for target in self.evidence.get('target_systems') or []:
            if target.get('ref') == self.ref:
                return target
        raise TargetMountError('target %s is not in the evidence / tidak ada di evidence' % self.ref)

    def _identify(self, scanner, wanted):
        """(part, kind, target_dict, records) of the ref-th target, using the scanner's own logic."""
        records, candidates = self._enumerate(scanner)
        idents = {'UUID': set(), 'PARTUUID': set(), 'LABEL': set(), 'PARTLABEL': set()}
        for rec in records:
            for key, field in (('UUID', 'uuid'), ('PARTUUID', 'partuuid'), ('LABEL', 'label'),
                               ('PARTLABEL', 'partlabel')):
                if rec.get(field):
                    idents[key].add(str(rec[field]).lower())
        locked = any(scanner.classify(r) == 'luks' or (r['fstype'] or '') == 'LVM2_member' for r in candidates)
        index, seen = int(self.ref[3:]), 0
        for part in candidates:
            kind = scanner.classify(part)
            if kind in (None, 'esp'):
                continue
            target = scanner.inspect_partition(part, kind, self._mounter, lambda _p: [], idents, locked, 'uefi')
            if target is None:
                continue
            if seen == index:
                target.setdefault('encryption', 'none')
                return part, kind, target, records
            seen += 1
        raise TargetMountError('target %s was not found again on the disks / tidak ditemukan lagi' % self.ref)

    def _open(self):
        wanted = self._evidence_target()
        if wanted.get('detection') != 'live-offline':
            raise TargetMountError('only offline (live USB) targets can be mounted / hanya target offline')
        if wanted.get('family') in (None, 'unknown'):
            raise TargetMountError('the target family is unknown; refusing / keluarga OS tidak diketahui')
        if wanted.get('encryption') != 'none' or wanted.get('access') != 'read-only-mounted':
            raise TargetMountError('the target is encrypted or was not inspected; it is never unlocked '
                                   '/ target terenkripsi atau tidak diperiksa, tidak pernah dibuka')
        scanner = load_scanner()
        self._mounter = self._make_mounter(scanner)
        part, kind, target, records = self._identify(scanner, wanted)
        if target['family'] != wanted['family']:
            raise TargetMountError('the target now looks like %s, the evidence says %s; refusing '
                                   '/ keluarga OS berbeda dari evidence' % (target['family'], wanted['family']))
        if target.get('encryption') != 'none' or target.get('access') != 'read-only-mounted':
            raise TargetMountError('the target is no longer readable/unencrypted; refusing / target tidak dapat dibaca')
        family = target['family']
        self.info = {'family': family, 'kind': kind}

        if not self.rw:
            res = self._mounter.mount(part, kind)
            if res.status != 'ok' or not res.root:
                raise TargetMountError('cannot mount the target read-only / mount read-only gagal')
            return res.root

        if family == 'macos':
            raise TargetMountError('read-write mounting of APFS from Linux is not supported / '
                                   'APFS read-write dari Linux tidak didukung')
        if family not in ('windows', 'linuxmint', 'linux-other'):
            raise TargetMountError('unsupported target family for read-write')
        if [m for m in part['mountpoints'] if m.startswith('/')]:
            raise TargetMountError('the target is already mounted by this session; unmount it first '
                                   '/ target sudah ter-mount, unmount lebih dulu')
        probe = self._probe(scanner, part, kind, family, records)
        return self._mount_rw(part, kind, family, probe)

    # ---- read-only probe before a read-write mount -------------------------------------------
    def _probe(self, scanner, part, kind, family, records):
        res = self._mounter.mount(part, kind)
        try:
            if res.status != 'ok' or not res.root:
                raise TargetMountError('cannot probe the target read-only before the read-write mount')
            root = res.root
            probe = {'subvol': None, 'boot': None}
            if family == 'windows':
                if scanner.file_size(root, 'hiberfil.sys'):
                    raise TargetMountError('Windows is hibernated or uses fast startup (hiberfil.sys); a read-write '
                                           'mount could corrupt it. Shut Windows down fully first '
                                           '/ Windows hibernasi atau fast startup; matikan penuh dulu')
                meta = part['meta'] or {}
                dirty = meta.get('dirty') if part['meta'] is not None else None
                if dirty:
                    raise TargetMountError('the NTFS volume is flagged dirty; refusing read-write '
                                           '/ volume NTFS dirty, read-write ditolak')
                if meta.get('mount_rw') == 'fail':
                    raise TargetMountError('read-write mount failed / mount read-write gagal')
                return probe
            base = root
            if scanner.parse_os_release(root) is None:
                at = scanner.resolve(root, '@')
                if at and scanner.parse_os_release(at) is not None:
                    base = at
                    probe['subvol'] = '@'
            probe['boot'] = self._boot_partition(scanner, base, records)
            if (part['meta'] or {}).get('mount_rw') == 'fail':
                raise TargetMountError('read-write mount failed / mount read-write gagal')
            return probe
        finally:
            self._mounter.release(res)

    @staticmethod
    def _boot_partition(scanner, base, records):
        """The record for a separate /boot named by the target's fstab, None when /boot is not separate."""
        for line in scanner.read_lines(base, 'etc/fstab', max_bytes=1024 * 1024):
            fields = line.split()
            if len(fields) < 4 or fields[0].startswith('#') or fields[1] != '/boot':
                continue
            if 'noauto' in fields[3].split(','):
                continue
            m = re.match(r'^(UUID|PARTUUID|LABEL|PARTLABEL)=(.*)$', fields[0])
            if not m:
                raise TargetMountError('the target /boot is not identified by UUID/LABEL; refusing '
                                       '/ /boot target tidak dapat diidentifikasi')
            field = {'UUID': 'uuid', 'PARTUUID': 'partuuid', 'LABEL': 'label', 'PARTLABEL': 'partlabel'}[m.group(1)]
            value = m.group(2).strip('"\'').lower()
            for rec in records:
                if str(rec.get(field) or '').lower() == value and rec.get('fstype'):
                    return rec
            raise TargetMountError('the target has a separate /boot that was not found; refusing so nothing is '
                                   'written to the wrong place / /boot terpisah tidak ditemukan')
        return None

    # ---- read-write mount ------------------------------------------------------------------
    def _fs_args(self, part, family, subvol=None):
        fs = (part['fstype'] or '').lower()
        if family == 'windows':
            return 'ntfs3', RW_WINDOWS
        if fs in ('ext2', 'ext3', 'ext4'):
            return 'ext4', RW_LINUX
        if fs == 'xfs':
            return 'xfs', RW_LINUX + ',nouuid'
        if fs == 'btrfs':
            return 'btrfs', RW_LINUX + (',subvol=' + subvol if subvol else '')
        raise TargetMountError('unsupported filesystem for a read-write mount')

    def _mount_one(self, part, family, mp, subvol=None):
        dev = part['path']
        if not scanner_device_ok(dev):
            raise TargetMountError('invalid device path')
        fstype, options = self._fs_args(part, family, subvol)
        res = _run(['mount', '-t', fstype, '-o', options, '--', dev, mp], timeout=120)
        ok = res is not None and res[0] == 0
        if not ok and family == 'windows':
            res = _run(['ntfs-3g', '-o', RW_WINDOWS, dev, mp], timeout=120)  # refuses hibernated volumes itself
            ok = res is not None and res[0] == 0
        if not ok:
            detail = (res[1].strip().splitlines() or [''])[-1][:160] if res else 'mount unavailable'
            raise TargetMountError('read-write mount failed: %s / mount read-write gagal' % detail)
        self._mounts.append(mp)

    def _mount_rw(self, part, kind, family, probe):
        self.base = tempfile.mkdtemp(prefix='rescue-target-')
        os.chmod(self.base, 0o700)
        root = os.path.join(self.base, 'root')
        os.mkdir(root, 0o700)
        if self.fixture_root:
            return part['fixture_dir']  # nothing is mounted in fixture mode
        self._mount_one(part, family, root, probe['subvol'])
        if family != 'windows':
            if probe['boot'] is not None:
                boot = os.path.join(root, 'boot')
                if not os.path.isdir(boot):
                    raise TargetMountError('the target has no /boot directory to mount on')
                self._mount_one(probe['boot'], family, boot)
            for src in BINDS:
                dst = os.path.join(root, src.lstrip('/'))
                if not os.path.isdir(dst):
                    raise TargetMountError('the target has no %s; cannot prepare a chroot' % src)
                res = _run(['mount', '--bind', '--', src, dst], timeout=30)
                if res is None or res[0] != 0:
                    raise TargetMountError('bind mount of %s failed' % src)
                self._mounts.append(dst)
                _run(['mount', '--make-private', '--', dst], timeout=30)
        return root

    # ---- cleanup ---------------------------------------------------------------------------------
    def _umount(self, mp):
        for cmd in (['umount', '--', mp], ['umount', '-l', '--', mp]):
            res = _run(cmd, timeout=60)
            if res is not None and res[0] == 0:
                return True
        return not os.path.ismount(mp)

    def _cleanup(self):
        failed = False
        for mp in reversed(self._mounts):
            if not self._umount(mp):
                failed = True
                print('WARNING/PERINGATAN: could not unmount a target mount; unmount it manually before '
                      'removing disks / tidak dapat unmount mount target.', file=sys.stderr)
        self._mounts = []
        if self._mounter is not None:
            try:
                self._mounter.close()
            except Exception:  # cleanup must never hide the original error
                pass
            self._mounter = None
        if self.base and not failed:
            for path in (os.path.join(self.base, 'root'), self.base):
                try:
                    os.rmdir(path)  # never recursive: a mount that stayed can never be walked
                except OSError:
                    pass
        self.base = None


def scanner_device_ok(dev):
    return bool(dev) and bool(load_scanner().DEVICE_RE.match(dev))


def open_target(evidence_path, evidence, target_ref, rw):
    """Context manager yielding the mount point of *target_ref* (see the module docstring)."""
    return TargetMount(evidence_path, evidence, target_ref, rw)
