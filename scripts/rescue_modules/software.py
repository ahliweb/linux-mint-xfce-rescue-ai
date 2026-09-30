"""Installed software inventory and health (all packages, or the operator-selected list).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#17. Contract: scripts/rescue_modules/__init__.py and
docs/repair-framework.md. Details and thresholds: docs/software.md.

Read-only. Evidence carries NUMBERS ONLY: never a package name, path, version or vendor. Package
names exist only as operator-supplied parameters of catalog repair actions. Every path below the
target root is walked component by component without following symlinks, so a hostile target can
never make the collector read the rescue system (or anything outside the mounted root).

Selected mode (scope software.selected, ctx.packages): only those packages are checked. A selected
package that is not installed is reported as a COUNT in sw-app-health, never by name.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess

MAX_STATUS_BYTES = 128 * 1024 * 1024
MAX_STANZAS = 200000
MAX_ENTRIES = 5000          # directory entries counted (autostart, applications, receipts)
MAX_INFO_ENTRIES = 1000000  # dpkg info directory: several files per package
STARTUP_WARN = 50           # more autostart entries than this is a warn
DEBSUMS_MAX_PACKAGES = 20
DEBSUMS_TIMEOUT = 60
APT_TIMEOUT = 60

PENDING_STATES = ('half-configured', 'unpacked', 'triggers-awaited', 'triggers-pending')
PRESENT_STATES = ('installed', 'half-installed') + PENDING_STATES
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$')


# --------------------------------------------------------------------- safe file access

def _walk(root, rel):
    """Resolve *rel* below *root* without following any symlink; None if missing or a link."""
    cur = os.path.realpath(root)
    trusted = cur == '/'  # the running host itself: its own symlinks (e.g. /var) are legitimate
    for part in [p for p in rel.split('/') if p]:
        if part in ('.', '..'):
            return None
        cur = os.path.join(cur, part)
        if trusted:
            cur = os.path.realpath(cur)
            continue
        try:
            st = os.lstat(cur)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            return None
    return cur


def _read_lines(root, rel, max_bytes=MAX_STATUS_BYTES):
    path = _walk(root, rel)
    if path is None:
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        total = 0
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            for raw in handle:
                total += len(raw)
                if total > max_bytes:
                    return
                yield raw.decode('utf-8', 'replace').rstrip('\n')
    except OSError:
        return
    finally:
        os.close(fd)


def _listdir(root, rel, limit=MAX_ENTRIES):
    """Sorted entry names of a real directory below *root* (bounded); None when unreadable."""
    path = _walk(root, rel)
    if path is None:
        return None
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return None
        with os.scandir(path) as it:
            names = []
            for entry in it:
                names.append(entry.name)
                if len(names) >= limit:
                    break
        return sorted(names)
    except OSError:
        return None


# --------------------------------------------------------------------- dpkg database

def _norm_name(name):
    return name.split(':', 1)[0]


def parse_dpkg_status(root):
    """Parse var/lib/dpkg/status below *root*. Returns a list of package dicts or None if unreadable.

    Each dict: name, arch, want, eflag, state, depends (list of alternative-name lists), provides.
    """
    packages, stanza, last, count, seen = [], {}, None, 0, False

    def flush():
        nonlocal stanza
        if stanza.get('Package') and stanza.get('Status'):
            words = stanza['Status'].split()
            if len(words) == 3:
                deps = []
                for field in ('Pre-Depends', 'Depends'):
                    for group in stanza.get(field, '').split(','):
                        alts = []
                        for alt in group.split('|'):
                            alt = alt.strip().split('(')[0].split('[')[0].split('<')[0].strip()
                            if alt:
                                alts.append(_norm_name(alt.split()[0]))
                        if alts:
                            deps.append(alts)
                provides = [_norm_name(p.strip().split('(')[0].strip().split()[0])
                            for p in stanza.get('Provides', '').split(',') if p.strip().split('(')[0].strip()]
                packages.append({'name': _norm_name(stanza['Package']), 'arch': stanza.get('Architecture', ''),
                                 'want': words[0], 'eflag': words[1], 'state': words[2],
                                 'depends': deps, 'provides': provides})
        stanza = {}

    for line in _read_lines(root, 'var/lib/dpkg/status'):
        seen = True
        if not line.strip():
            flush()
            last = None
            count += 1
            if count > MAX_STANZAS:
                return None
            continue
        if line[0] in ' \t':
            if last in ('Depends', 'Pre-Depends', 'Provides'):
                stanza[last] += ' ' + line.strip()
            continue
        key, sep, value = line.partition(':')
        if not sep:
            last = None
            continue
        last = key
        if key in ('Package', 'Status', 'Architecture', 'Depends', 'Pre-Depends', 'Provides'):
            stanza[key] = value.strip()
    flush()
    return packages if seen else None


def _selected_filter(packages, selected):
    if not selected:
        return packages, 0
    wanted = {_norm_name(p) for p in selected}
    installed = {p['name'] for p in packages if p['state'] in PRESENT_STATES}
    missing = len(wanted - installed)
    return [p for p in packages if p['name'] in wanted], missing


def _count_broken_dependencies(all_packages, scope_packages):
    """Installed packages in *scope_packages* with a Depends/Pre-Depends group that nothing installed
    satisfies. Versions are not compared (documented limitation), so this can only under-report."""
    provided = set()
    for p in all_packages:
        if p['state'] in ('installed', 'unpacked', 'half-configured', 'triggers-awaited', 'triggers-pending'):
            provided.add(p['name'])
            provided.update(p['provides'])
    broken = 0
    for p in scope_packages:
        if p['state'] not in ('installed', 'unpacked', 'half-configured', 'triggers-awaited', 'triggers-pending'):
            continue
        if any(not any(alt in provided for alt in group) for group in p['depends']):
            broken += 1
    return broken


def _info_names(root):
    names = _listdir(root, 'var/lib/dpkg/info', MAX_INFO_ENTRIES)
    return None if names is None else {n[:-5] for n in names if n.endswith('.list')}


def _count_missing_lists(root, scope_packages):
    names = _info_names(root)
    if names is None:
        return None
    missing = 0
    for p in scope_packages:
        if p['state'] not in PRESENT_STATES:
            continue
        if p['name'] not in names and '%s:%s' % (p['name'], p['arch']) not in names:
            missing += 1
    return missing


def _chk(check_id, status, kind=None, number=None):
    item = {'check_id': check_id, 'status': status}
    if kind is not None:
        item['kind'], item['number'] = kind, number
    return item


def dpkg_checks(root, selected=(), host_extra=False):
    """The eight sw-* checks for a dpkg based system whose root is *root*."""
    packages = parse_dpkg_status(root)
    if packages is None:
        return [_chk('sw-inventory', 'unknown')]
    scoped, missing_selected = _selected_filter(packages, selected)
    present = [p for p in scoped if p['state'] in PRESENT_STATES]
    out = []
    if selected:
        out.append(_chk('sw-inventory', 'warn' if missing_selected else 'pass', 'count', len(present)))
    else:
        out.append(_chk('sw-inventory', 'pass' if present else 'warn', 'count', len(present)))

    unhealthy = sum(1 for p in scoped if p['state'] == 'half-installed' or 'reinstreq' in p['eflag'])
    out.append(_chk('sw-package-health', 'fail' if unhealthy else 'pass', 'count', unhealthy))

    halfconf = sum(1 for p in scoped if p['state'] == 'half-configured')
    pending = sum(1 for p in scoped if p['state'] in PENDING_STATES)
    out.append(_chk('sw-pending-config', 'fail' if halfconf else ('warn' if pending else 'pass'), 'count', pending))

    broken = _count_broken_dependencies(packages, scoped)
    broken_status = 'fail' if broken else 'pass'
    held = sum(1 for p in scoped if p['want'] == 'hold')
    out.append(_chk('sw-held-packages', 'warn' if held else 'pass', 'count', held))

    missing_lists = _count_missing_lists(root, scoped)
    if missing_lists is None:
        integrity = _chk('sw-package-integrity', 'unknown')
    else:
        integrity = _chk('sw-package-integrity', 'fail' if missing_lists else 'pass', 'count', missing_lists)

    if host_extra:
        broken_status, broken = _apt_simulated_check(broken_status, broken)
        integrity = _debsums(selected, integrity)
    out.append(_chk('sw-broken-dependencies', broken_status, 'count', broken))
    out.append(integrity)

    if selected:
        out.append(_chk('sw-app-health', 'warn' if missing_selected else 'pass', 'count', missing_selected))
    else:
        out.append(_chk('sw-app-health', 'not_applicable'))
    out.append(_startup_check(root, 'etc/xdg/autostart', suffix='.desktop'))
    return out


def _startup_check(root, rel, suffix=None):
    names = _listdir(root, rel)
    if names is None:
        return _chk('sw-startup-items', 'unknown')
    n = sum(1 for x in names if suffix is None or x.endswith(suffix))
    return _chk('sw-startup-items', 'warn' if n > STARTUP_WARN else 'pass', 'count', n)


# --------------------------------------------------------------------- host-only probes

def _run(argv, timeout):
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        return proc.returncode, proc.stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError):
        return None, ''


def _apt_simulated_check(status, number):
    """apt-get -s check is a simulation: read-only, needs no root. Non-zero means broken dependencies."""
    code, _ = _run(['apt-get', '-s', 'check'], APT_TIMEOUT)
    if code is not None and code != 0:
        return 'fail', max(number, 1)
    return status, number


def _debsums(selected, current):
    """debsums -s on at most DEBSUMS_MAX_PACKAGES selected packages, only when debsums is installed."""
    if not selected or len(selected) > DEBSUMS_MAX_PACKAGES or not all(_ID.match(p) for p in selected):
        return current
    code, out = _run(['debsums', '-s'] + [_norm_name(p) for p in selected], DEBSUMS_TIMEOUT)
    if code is None:
        return current
    bad = sum(1 for ln in out.splitlines() if ln.strip())
    if bad:
        return _chk('sw-package-integrity', 'fail', 'count', bad)
    return current


# --------------------------------------------------------------------- macOS / Windows targets

def _macos_checks(root, selected):
    apps = _listdir(root, 'Applications')
    receipts = _listdir(root, 'private/var/db/receipts')
    if receipts is None:
        receipts = _listdir(root, 'var/db/receipts')
    out = []
    app_names = None if apps is None else [a for a in apps if a.endswith('.app')]
    if app_names is None:
        out.append(_chk('sw-inventory', 'unknown'))
    elif selected:
        wanted = {p for p in selected}
        present = sum(1 for p in wanted if p + '.app' in app_names)
        out.append(_chk('sw-inventory', 'warn' if present < len(wanted) else 'pass', 'count', present))
        out.append(_chk('sw-app-health', 'warn' if present < len(wanted) else 'pass', 'count', len(wanted) - present))
    else:
        out.append(_chk('sw-inventory', 'pass' if app_names else 'warn', 'count', len(app_names)))
    if receipts is None:
        out.append(_chk('sw-package-health', 'unknown'))
    else:
        out.append(_chk('sw-package-health', 'pass', 'count', sum(1 for r in receipts if r.endswith('.plist'))))
    if not selected:
        out.append(_chk('sw-app-health', 'not_applicable'))
    return out


def _windows_checks():
    # A Windows target's installed programs live in the SOFTWARE registry hive. Reading it needs a
    # hive parser (a dependency this project does not take), so the answer is honestly unknown.
    return [_chk('sw-inventory', 'unknown')]


# --------------------------------------------------------------------- hooks

def collect_offline_target(ctx, root, target):
    family = (target or {}).get('family')
    selected = tuple(ctx.packages) if 'software.selected' in ctx.scope else ()
    if family == 'windows':
        return _windows_checks()
    if family == 'macos':
        return _macos_checks(root, selected)
    if family in ('linuxmint', 'linux-other'):
        return dpkg_checks(root, selected)
    return []


def collect_system(ctx):
    """Host mode only: the running Linux system. In live mode the machine is the rescue USB, whose
    software says nothing about the customer's installed OS (that is collect_offline_target)."""
    if ctx.mode != 'host':
        return []
    selected = tuple(ctx.packages) if 'software.selected' in ctx.scope else ()
    root = ctx.fixture_root or '/'
    if _walk(root, 'var/lib/dpkg/status') is None:
        return [_chk('sw-inventory', 'unknown')]
    return dpkg_checks(root, selected, host_extra=ctx.fixture_root is None)
