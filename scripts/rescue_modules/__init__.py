"""Detection module hooks for the Python collectors (live USB scanner and Linux host launcher).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Each domain module in this package is owned by one workstream and exposes two
optional, read-only hooks:

  collect_system(ctx) -> list[dict]
      Checks about the machine the collector runs on: hardware in both modes,
      and in host mode also the running OS and its software.
  collect_offline_target(ctx, root, target) -> list[dict]
      Live USB only: checks about one installed OS that the scanner has mounted
      read-only at *root* (``target`` has ``family``, ``release``, ``access``).

A check dict is ``{'check_id', 'status'}`` plus optional ``'kind'``/``'number'``
(a bounded numeric value) and, in host mode only, ``'target_ref'``. Modules must
never write, mount, unlock, or repair; repairs are catalog actions run by
scripts/rescue-repair.py. They must not raise for missing tools or permissions:
report ``unknown`` instead. This package validates every returned check and drops
(with a warning) anything outside the evidence contract, so one module bug never
breaks the scan.
"""
from __future__ import annotations

import importlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOMAINS = ('hardware', 'operating_system', 'software', 'malware', 'printer')
DOMAIN_SCOPE = {'hardware': 'hardware', 'operating_system': 'os', 'software': 'software', 'malware': 'malware',
                'printer': 'printer'}  # printer.py: the spooler of an installed OS (offline only) is scope printer too (docs/printer.md)
HARDWARE_ITEMS = ('cpu', 'memory', 'disk', 'gpu', 'display', 'network', 'battery', 'usb')
STATUSES = {'pass', 'fail', 'warn', 'not_applicable', 'unknown'}
KINDS = {'percent', 'count', 'bytes', 'days', 'seconds', 'celsius'}
MAX_NUMBER = 1e15


def _check_ids():
    schema = json.loads((ROOT / 'rescue-ai/v1/rescue-evidence.schema.json').read_text(encoding='utf-8'))
    return frozenset(schema['properties']['checks']['items']['properties']['check_id']['enum'])


CHECK_IDS = _check_ids()


@dataclass
class Context:
    mode: str                       # 'live' (scanner on the rescue USB) or 'host' (running OS)
    scope: tuple = ('all',)         # normalized scope from scripts/lib/repair_catalog.normalize_scope
    packages: tuple = ()            # operator-selected packages for scope software.selected
    fixture_root: str | None = None  # test hook: modules read fixture files instead of the system
    warnings: list = field(default_factory=list)
    # Malware module (docs/malware.md). state_dir: USB state (signature DB at state_dir/clamav, quarantine at
    # state_dir/quarantine); detections: LOCAL findings (paths, never evidence) collected during the run.
    state_dir: str | None = None
    malware_full_disk: bool = False
    # Time budget sharing (docs/malware.md): malware_pending = targets still to scan in this run, the current one
    # included (the scanner sets it before each partition); malware_target = 'os-N' restricts the scan to that
    # target (the others report malware-scan unknown), None scans every target. Target dicts carry 'os_ref'.
    malware_target: str | None = None
    malware_pending: int = 1
    detections: list = field(default_factory=list)
    cache: dict = field(default_factory=dict)

    def wants(self, domain, item=None):
        """Is *domain* (hardware/os/software), or hardware *item*, in the operator's scope?"""
        s = self.scope
        if 'all' in s:
            return True
        if domain == 'hardware':
            return 'hardware' in s or (item is not None and 'hardware.' + item in s) or (
                item is None and any(x.startswith('hardware.') for x in s))
        if domain == 'software':
            return 'software' in s or 'software.selected' in s
        return domain in s  # os, malware


def sanitize(checks, where, ctx, allow_target_ref):
    out = []
    for c in checks or []:
        try:
            cid, status = c['check_id'], c['status']
            if cid not in CHECK_IDS or status not in STATUSES:
                raise ValueError('check_id/status outside the contract')
            item = {'check_id': cid, 'status': status}
            if c.get('kind') is not None or c.get('number') is not None:
                kind, number = c.get('kind'), c.get('number')
                if kind not in KINDS or isinstance(number, bool) or not isinstance(number, (int, float)) \
                        or not 0 <= number <= MAX_NUMBER:
                    raise ValueError('value outside the contract')
                item['kind'], item['number'] = kind, number
            ref = c.get('target_ref')
            if ref is not None:
                if not allow_target_ref or not isinstance(ref, str) or ref != 'os-0':
                    raise ValueError('target_ref not allowed here')
                item['target_ref'] = ref
            out.append(item)
        except (KeyError, TypeError, ValueError) as exc:
            ctx.warnings.append('%s: dropped a check (%s)' % (where, exc))
    return out


def _modules(ctx):
    for name in DOMAINS:
        if not ctx.wants(DOMAIN_SCOPE[name]):
            continue
        try:
            yield name, importlib.import_module('%s.%s' % (__name__, name))
        except Exception as exc:  # a broken module must not break the scan
            ctx.warnings.append('rescue_modules.%s: cannot import (%s)' % (name, exc.__class__.__name__))


def _call(ctx, name, fn, *args):
    try:
        return fn(ctx, *args) or []
    except Exception as exc:
        ctx.warnings.append('rescue_modules.%s.%s failed (%s)' % (name, fn.__name__, exc.__class__.__name__))
        return []


def collect_system(ctx):
    out = []
    for name, module in _modules(ctx):
        fn = getattr(module, 'collect_system', None)
        if fn is None:
            continue
        checks = sanitize(_call(ctx, name, fn), 'rescue_modules.%s' % name, ctx, allow_target_ref=ctx.mode == 'host')
        if ctx.mode == 'host' and name != 'hardware':
            # In host mode the running OS is target os-0; hardware describes the machine itself.
            for c in checks:
                c.setdefault('target_ref', 'os-0')
        out += checks
    return out


def collect_offline_target(ctx, root, target):
    out = []
    for name, module in _modules(ctx):
        fn = getattr(module, 'collect_offline_target', None)
        if fn is not None:
            out += sanitize(_call(ctx, name, fn, root, dict(target)), 'rescue_modules.%s' % name, ctx,
                            allow_target_ref=False)
    return out


def flush_warnings(ctx, stream=None):
    for w in ctx.warnings:
        print('warning: %s' % w, file=stream or sys.stderr)
    ctx.warnings.clear()
