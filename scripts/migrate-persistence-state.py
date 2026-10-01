#!/usr/bin/env python3
"""Carry the operator's rescue state from an old persistence image into a new one.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Upgrading the USB means replacing ``persistence/rescue-omes-casper-rw.dat`` with a newer image, which
would lose the Hermes state (sessions, memories, learned skills), the provider key in ``hermes/env``,
and the case history (reports, journal, audit, learning, ClamAV signatures). This tool copies an
allowlist of those paths from OLD into NEW, both ext4 *image files*, with ``debugfs`` - no mount, no
root, no block device:

  * only paths under ``upper/home/mint/.local/share/rescue-omes/`` that are on the allowlist below;
    program files (Hermes itself, its tools and caches, the rescue profile and the bundled skills) always
    come from NEW, so the upgrade really upgrades;
  * regular files and directories only (symlinks, devices and other types are reported and skipped);
  * mode, uid, gid and mtime of every carried entry are kept; NEW entries with the same path are replaced;
  * afterwards ``e2fsck -fn`` must be clean and every carried file is read back from NEW and compared by
    SHA-256 with OLD.

NEW is modified in place: work on a copy, keep OLD as the rollback. Nothing is ever printed from a file's
content (``hermes/env`` holds the provider key); only paths, counts and hashes. Staging files live in a
private temporary directory that is removed at the end.

Exit codes: 0 migrated and verified | 1 verification failed (NEW must not be used) | 2 usage or refused input
| 3 debugfs/e2fsck missing or failed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import PurePosixPath

STATE_ROOT = '/upper/home/mint/.local/share/rescue-omes'

# Relative to STATE_ROOT. A directory entry carries its whole subtree.
CARRY = (
    'hermes/env',                      # provider key (allowlisted dotenv, read by scripts/lib/rescue-env.sh)
    'hermes/config.yaml',              # Hermes settings incl. onboarding flags
    'hermes/state.db', 'hermes/state.db-wal', 'hermes/state.db-shm',   # sessions and messages
    'hermes/projects.db',
    'hermes/.hermes_history',
    'hermes/memories', 'hermes/sessions', 'hermes/logs', 'hermes/cron', 'hermes/hooks', 'hermes/pairing',
    'hermes/backups', 'hermes/.curator_backups',
    'hermes/skills/.curator_ledger.jsonl', 'hermes/skills/.usage.json',
    'cases', 'learning', 'reports', 'repairs', 'audit', 'clamav',
)
# Skills that NEW does not ship (learned in the field) are carried too; bundled ones come from NEW.
SKILLS_DIR = 'hermes/skills'
SKIP_NAMES = {'.locks'}
SKIP_SUFFIXES = ('.lock',)

EXIT_OK, EXIT_VERIFY, EXIT_USAGE, EXIT_TOOL = 0, 1, 2, 3


def warn(msg):
    print(msg, file=sys.stderr)


def debugfs(image, request, write=False):
    """stdout of one debugfs request (read-only unless WRITE)."""
    argv = [DEBUGFS] + (['-w'] if write else []) + ['-R', request, image]
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=600, check=False)
    return proc.returncode, proc.stdout.decode('utf-8', 'surrogateescape'), proc.stderr.decode('utf-8', 'replace')


def list_dir(image, path):
    """[(name, mode, uid, gid, size)] of PATH, or None when PATH is not a directory in IMAGE."""
    rc, out, _ = debugfs(image, 'ls -p "%s"' % path)
    if rc != 0:
        return None
    entries = []
    for line in out.splitlines():
        # /inode/mode/uid/gid/name/size/
        parts = line.split('/')
        if len(parts) < 7 or parts[0] != '':
            continue
        name = '/'.join(parts[5:-2]) if len(parts) > 7 else parts[5]
        if name in ('.', '..', ''):
            continue
        try:
            entries.append((name, int(parts[2], 8), int(parts[3]), int(parts[4]), int(parts[-2] or 0)))
        except ValueError:
            continue
    return entries


def inode_info(image, path):
    """(mode, uid, gid, mtime) of PATH in IMAGE, or None when it does not exist."""
    rc, out, _ = debugfs(image, 'stat "%s"' % path)
    if rc != 0 or 'Inode:' not in out:
        return None
    mode = uid = gid = mtime = None
    types = {'regular': stat.S_IFREG, 'directory': stat.S_IFDIR, 'symlink': stat.S_IFLNK}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Inode:') and 'Mode:' in line and 'Type:' in line:
            # "Mode:" shows permission bits only; the file type is the "Type:" word. sif needs both.
            kind = types.get(line.split('Type:')[1].split()[0], 0)
            mode = kind | int(line.split('Mode:')[1].split()[0], 8)
        elif line.startswith('User:'):
            bits = line.replace(':', ' ').split()
            uid, gid = int(bits[1]), int(bits[3])
        elif line.startswith('mtime:'):
            mtime = int(line.split()[1].split(':')[0], 16)
    if None in (mode, uid, gid, mtime):
        return None
    return mode, uid, gid, mtime


def exists(image, path):
    rc, out, _ = debugfs(image, 'stat "%s"' % path)
    return rc == 0 and 'Inode:' in out


def walk(image, rel, plan, skipped):
    """Append (rel, kind) to PLAN for REL and, for a directory, its subtree."""
    path = STATE_ROOT + '/' + rel
    info = inode_info(image, path)
    if info is None:
        return
    kind = stat.S_IFMT(info[0])
    if kind == stat.S_IFREG:
        plan.append((rel, 'file', info))
    elif kind == stat.S_IFDIR:
        plan.append((rel, 'dir', info))
        for name, mode, _uid, _gid, _size in sorted(list_dir(image, path) or []):
            if name in SKIP_NAMES or name.endswith(SKIP_SUFFIXES):
                skipped.append(rel + '/' + name)
                continue
            if stat.S_IFMT(mode) in (stat.S_IFREG, stat.S_IFDIR):
                walk(image, rel + '/' + name, plan, skipped)
            else:
                skipped.append(rel + '/' + name)
    else:
        skipped.append(rel)


def build_plan(old, new):
    plan, skipped = [], []
    for rel in CARRY:
        walk(old, rel, plan, skipped)
    new_skills = {n for n, *_ in (list_dir(new, STATE_ROOT + '/' + SKILLS_DIR) or [])}
    for name, mode, *_ in sorted(list_dir(old, STATE_ROOT + '/' + SKILLS_DIR) or []):
        if stat.S_ISDIR(mode) and not name.startswith('.') and name not in new_skills:
            walk(old, SKILLS_DIR + '/' + name, plan, skipped)
    return plan, skipped


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def quote(path):
    if '"' in path or '\n' in path:
        raise ValueError('unsupported character in path')
    return '"%s"' % path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--from', dest='old', required=True, help='old persistence image (read only)')
    ap.add_argument('--to', dest='new', required=True, help='new persistence image (modified in place)')
    ap.add_argument('--dry-run', action='store_true', help='print the plan and change nothing')
    args = ap.parse_args(argv)

    global DEBUGFS
    DEBUGFS = shutil.which('debugfs') or ('/sbin/debugfs' if os.path.exists('/sbin/debugfs') else None)
    e2fsck = shutil.which('e2fsck') or ('/sbin/e2fsck' if os.path.exists('/sbin/e2fsck') else None)
    if not DEBUGFS or not e2fsck:
        warn('debugfs and e2fsck (e2fsprogs) are required')
        return EXIT_TOOL
    for label, image in (('--from', args.old), ('--to', args.new)):
        try:
            st = os.stat(image)
        except OSError as exc:
            warn('%s %s: %s' % (label, image, exc.strerror))
            return EXIT_USAGE
        if not stat.S_ISREG(st.st_mode):
            warn('%s must be a regular image file, never a block device: %s' % (label, image))
            return EXIT_USAGE
    if os.path.samefile(args.old, args.new):
        warn('--from and --to are the same file')
        return EXIT_USAGE
    for image in (args.old, args.new):
        if not exists(image, STATE_ROOT):
            warn('not a rescue persistence image (no %s): %s' % (STATE_ROOT, image))
            return EXIT_USAGE

    plan, skipped = build_plan(args.old, args.new)
    files = [p for p in plan if p[1] == 'file']
    print('Plan: %d directories, %d files from %s' % (len(plan) - len(files), len(files), os.path.basename(args.old)))
    for rel in skipped:
        print('  skipped (lock or not a regular file/directory): %s' % rel)
    if args.dry_run:
        for rel, kind, _info in plan:
            print('  %s %s' % ('d' if kind == 'dir' else 'f', rel))
        return EXIT_OK

    staging = tempfile.mkdtemp(prefix='rescue-migrate-')
    os.chmod(staging, 0o700)
    try:
        hashes, script = {}, []
        for index, (rel, kind, info) in enumerate(plan):
            path = STATE_ROOT + '/' + rel
            mode, uid, gid, mtime = info
            if kind == 'dir':
                if not exists(args.new, path):
                    script.append('mkdir %s' % quote(path))
            else:
                local = os.path.join(staging, '%06d' % index)
                rc, _out, err = debugfs(args.old, 'dump %s %s' % (quote(path), quote(local)))
                if rc != 0 or not os.path.isfile(local):
                    warn('cannot read %s from the old image: %s' % (rel, err.strip()[:200]))
                    return EXIT_TOOL
                hashes[rel] = sha256_file(local)
                if exists(args.new, path):
                    script.append('rm %s' % quote(path))
                script.append('write %s %s' % (quote(local), quote(path)))
            script.append('sif %s mode 0%o' % (quote(path), mode))
            script.append('sif %s uid %d' % (quote(path), uid))
            script.append('sif %s gid %d' % (quote(path), gid))
            script.append('sif %s mtime @%d' % (quote(path), mtime))  # '@' = epoch seconds (a bare number is read as YYYYMMDD)
        cmdfile = os.path.join(staging, 'commands')
        with open(cmdfile, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(script) + '\n')
        proc = subprocess.run([DEBUGFS, '-w', '-f', cmdfile, args.new], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=3600, check=False)
        errors = [l for l in proc.stderr.decode('utf-8', 'replace').splitlines()
                  if l.strip() and not l.startswith('debugfs ')]
        if proc.returncode != 0 or errors:
            for line in errors[:20]:
                warn('debugfs: %s' % line[:200])
            return EXIT_TOOL
        fsck = subprocess.run([e2fsck, '-fn', args.new], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=1800, check=False)
        if fsck.returncode != 0:
            warn('e2fsck -fn reported problems on the new image (exit %d); do not use it' % fsck.returncode)
            return EXIT_VERIFY
        bad = 0
        for rel, kind, info in plan:
            path = STATE_ROOT + '/' + rel
            now = inode_info(args.new, path)
            if now is None or now != info:
                warn('metadata differs after migration: %s' % rel)
                bad += 1
                continue
            if kind == 'file':
                back = os.path.join(staging, 'readback')
                debugfs(args.new, 'dump %s %s' % (quote(path), quote(back)))
                ok = os.path.isfile(back) and sha256_file(back) == hashes[rel]
                if os.path.exists(back):
                    os.unlink(back)
                if not ok:
                    warn('content differs after migration: %s' % rel)
                    bad += 1
        if bad:
            warn('%d entries failed verification; do not use the new image' % bad)
            return EXIT_VERIFY
        print('Migrated and verified: %d directories, %d files; e2fsck clean.' % (len(plan) - len(files), len(files)))
        return EXIT_OK
    finally:
        shutil.rmtree(staging, ignore_errors=True)


DEBUGFS = None

if __name__ == '__main__':
    sys.exit(main())
