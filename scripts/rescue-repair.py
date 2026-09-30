#!/usr/bin/env python3
"""Policy-gated repair engine: run typed catalog actions proposed for one evidence file.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Proposals come from three places, and none of them can inject a command:

  catalog-trigger  an evidence check matches an action's trigger (deterministic)
  ai-proposal      an exact catalog action_id in the ```rescue-proposals block of
                   an analysis file (untrusted data, validated against the catalog)
  operator         --select ACTION_ID

Policy (--policy):
  detect-only   list and journal the proposals; never execute anything
  approve-each  (default) every action needs approval: an interactive prompt or
                --approve ACTION_ID; destructive actions need the action_id typed
  auto-safe     opt-in: catalog-trigger actions with risk "safe" and no missing
                parameter run without a prompt; everything else as approve-each

Every stage is appended to a hash-chained journal (rescue-ai/v1/repair-journal.schema.json)
on the USB. Destructive actions require --backup-ref. Every executed action is followed by
its verify step; a failed execute/verify runs the automatic rollback step when the catalog
has one, otherwise the manual rollback doc is printed.

This Python engine executes on the live-linux and linux-host platforms. Windows and macOS
evidence can be planned here (--list) but is executed by the host launchers' own engines.

Exit codes: 0 finished, nothing failed | 1 an action failed or was rolled back, or the
journal chain is broken (--verify-journal) | 2 invalid arguments, evidence, catalog,
or analysis file | 3 journal not writable
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'lib'))
import repair_catalog as rc  # noqa: E402

SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
EXECUTING_PLATFORMS = {'live-linux', 'linux-host'}
DEFAULT_TIMEOUT = {'precondition': 60, 'execute': 300, 'verify': 120, 'rollback': 300}
ZERO_HASH = '0' * 64
EXIT_OK, EXIT_FAILED, EXIT_INVALID, EXIT_JOURNAL = 0, 1, 2, 3
YES = {'ya', 'y', 'yes'}
CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def say(text=''):
    print(text, flush=True)


def warn(text):
    print(text, file=sys.stderr, flush=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------------- journal

class JournalError(Exception):
    pass


class Journal:
    """Append-only JSONL with a SHA-256 chain; one record per stage event."""

    def __init__(self, path, run_id, catalog_sha, policy, platform, evidence_sha):
        self.path = Path(path)
        self.base = {'journal_version': '1', 'run_id': run_id, 'catalog_sha256': catalog_sha,
                     'policy': policy, 'platform': platform, 'evidence_sha256': evidence_sha}
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(fd)
        except OSError as exc:
            raise JournalError('cannot open journal %s: %s' % (self.path, exc.strerror or exc)) from exc

    @staticmethod
    def _tail(path):
        """(seq, sha256) of the last record, or (0, zeros)."""
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 65536))
            lines = [ln for ln in handle.read().split(b'\n') if ln.strip()]
        if not lines:
            return 0, ZERO_HASH
        last = lines[-1]
        return int(json.loads(last.decode('utf-8'))['seq']), hashlib.sha256(last).hexdigest()

    def write(self, **fields):
        record = dict(self.base)
        record.update({k: v for k, v in fields.items() if v is not None})
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_APPEND)
            with os.fdopen(fd, 'r+b') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                seq, prev = self._tail(self.path)
                record['seq'] = seq + 1
                record['prev_sha256'] = prev
                record['recorded_at'] = utc_now()
                line = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
                handle.write(line + b'\n')
                handle.flush()
                os.fsync(handle.fileno())
        except (OSError, ValueError, KeyError) as exc:
            raise JournalError('cannot append to journal %s: %s' % (self.path, exc)) from exc
        return record


def verify_journal(path):
    """Problems in *path*: schema, seq continuity, and the hash chain."""
    jsonschema = rc._jsonschema()
    schema = json.loads((rc.ROOT / 'rescue-ai/v1/repair-journal.schema.json').read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    problems, prev, expected = [], ZERO_HASH, 1
    with open(path, 'rb') as handle:
        for n, raw in enumerate(handle, 1):
            line = raw.rstrip(b'\n')
            if not line.strip():
                continue
            try:
                record = json.loads(line.decode('utf-8'))
            except ValueError:
                problems.append('line %d: not JSON' % n)
                prev = hashlib.sha256(line).hexdigest()
                expected += 1
                continue
            for err in validator.iter_errors(record):
                problems.append('line %d: %s' % (n, err.message))
            if record.get('seq') != expected:
                problems.append('line %d: seq %r, expected %d' % (n, record.get('seq'), expected))
            if record.get('prev_sha256') != prev:
                problems.append('line %d: prev_sha256 does not match the previous line' % n)
            prev = hashlib.sha256(line).hexdigest()
            expected = (record.get('seq') if isinstance(record.get('seq'), int) else expected) + 1
    return problems


# ----------------------------------------------------------------------- runtime

def search_path():
    """SAFE_PATH, or the test override (absolute directories only, announced loudly)."""
    override = os.environ.get('RESCUE_REPAIR_TEST_PATH', '')
    if override:
        parts = override.split(':')
        if all(p.startswith('/') and os.path.isdir(p) for p in parts):
            warn('rescue-repair: TEST PATH override active (RESCUE_REPAIR_TEST_PATH)')
            return override
        warn('rescue-repair: ignoring invalid RESCUE_REPAIR_TEST_PATH')
    return SAFE_PATH


def resolve_argv(argv, requires_root, path):
    program = shutil.which(argv[0], path=path)
    if program is None:
        return None
    full = [program] + list(argv[1:])
    if requires_root and os.geteuid() != 0:
        sudo = shutil.which('sudo', path=path)
        if sudo is None:
            return None
        full = [sudo, '-n', '--'] + full
    return full


def run_step(step, values, requires_root, path, default_timeout):
    """Run one catalog step; returns a result dict (never raises for the command itself)."""
    argv = rc.render(step['argv'], values)
    full = resolve_argv(argv, requires_root, path)
    if full is None:
        return {'outcome': 'unavailable', 'reason': 'program-not-found', 'argv': argv}
    env = {'PATH': path, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'}
    timeout = step.get('timeout_seconds', default_timeout)
    started = time.monotonic()
    try:
        proc = subprocess.run(full, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=env, timeout=timeout, check=False)
        output, code = proc.stdout, proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.output or b''
        return {'outcome': 'timeout', 'reason': 'timeout', 'argv': argv, 'output': output,
                'duration': time.monotonic() - started}
    except OSError:
        return {'outcome': 'unavailable', 'reason': 'program-not-found', 'argv': argv}
    ok = code in step.get('expect_exit', [0])
    return {'outcome': 'ok' if ok else 'fail', 'reason': None if ok else 'exit-code', 'argv': argv,
            'exit_code': max(-255, min(255, code)), 'output': output, 'duration': time.monotonic() - started}


def show_output(result, limit=15):
    text = (result.get('output') or b'').decode('utf-8', 'replace')
    lines = [CONTROL.sub('', ln)[:200] for ln in text.splitlines() if ln.strip()]
    for line in lines[-limit:]:
        say('    | ' + line)


def result_fields(result):
    fields = {'outcome': result['outcome'], 'reason': result.get('reason')}
    if 'exit_code' in result:
        fields['exit_code'] = result['exit_code']
    if 'duration' in result:
        fields['duration_seconds'] = round(result['duration'], 3)
    if 'output' in result:
        fields['output_bytes'] = len(result['output'])
        fields['output_sha256'] = hashlib.sha256(result['output']).hexdigest()
    return fields


def backup_fingerprint(path):
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size < 1:
        raise ValueError('backup reference must be a non-empty regular file')
    digest = hashlib.sha256(str(st.st_size).encode('ascii') + b'\0')
    with open(path, 'rb') as handle:
        digest.update(handle.read(1 << 20))
        if st.st_size > (1 << 20):
            handle.seek(max(1 << 20, st.st_size - (1 << 20)))
            digest.update(handle.read(1 << 20))
    return {'size_bytes': st.st_size, 'fingerprint_sha256': digest.hexdigest()}


def block_device_eligible(path):
    """An existing internal disk/partition that is not the rescue USB or other removable media."""
    try:
        if not stat.S_ISBLK(os.stat(path).st_mode):
            return False
    except OSError:
        return False
    scanner = load_module('rescue_scan_target_os', HERE / 'scan-target-os.py')
    res = scanner.run(['lsblk', '-J', '-b', '-o', scanner.LSBLK_COLUMNS], timeout=20)
    if res is None or res[0] != 0:
        return False
    try:
        tree = json.loads(res[1]).get('blockdevices') or []
    except ValueError:
        return False
    records = []
    scanner._flatten(tree, None, records)
    bad = scanner.excluded_disks(records)
    real = os.path.realpath(path)
    return any(r['path'] in (path, real) and r['disk'] not in bad and r['type'] in ('disk', 'part', 'lvm')
               for r in records)


def target_provider():
    """scripts/lib/target_mount.py (open_target(evidence_path, evidence, target_ref, rw) -> context manager)."""
    path = HERE / 'lib' / 'target_mount.py'
    if not path.is_file():
        return None
    module = load_module('rescue_target_mount', path)
    return getattr(module, 'open_target', None)


# ------------------------------------------------------------------------ engine

class Engine:
    def __init__(self, args, evidence, evidence_sha, catalog, platform, journal):
        self.args, self.evidence, self.evidence_sha = args, evidence, evidence_sha
        self.catalog, self.platform, self.journal = catalog, platform, journal
        self.path = search_path()
        self.interactive = sys.stdin.isatty() and sys.stdout.isatty()
        self.params = args.param_map
        self.packages = set(args.packages) if args.packages else None
        self.results = []

    def log(self, action, proposal, stage, outcome, **extra):
        if self.journal is None:
            return
        self.journal.write(action_id=action['action_id'], origin=proposal['origin'], risk=action['risk'],
                           target_ref=proposal.get('target_ref'), stage=stage, outcome=outcome, **extra)

    def ask(self, prompt):
        try:
            return input(prompt).strip()
        except EOFError:
            return ''

    def resolve_params(self, action, allow_prompt):
        """(values, problem) where problem is None, 'missing-param' or 'invalid-param'."""
        values, aid = {}, action['action_id']
        for p in action.get('params') or []:
            if p['type'] == 'target_root':
                continue  # filled by the mount provider
            raw = self.params.get((aid, p['name']))
            if raw is None and 'default' in p:
                raw = p['default']
            if raw is None and allow_prompt:
                hint = ', '.join(p['values']) if p['type'] == 'enum' else p['type']
                raw = self.ask('  Nilai untuk / value for %s (%s): ' % (p['name'], hint)) or None
            if raw is None:
                return None, 'missing-param'
            try:
                value = rc.validate_param(p, raw, self.packages)
            except ValueError as exc:
                warn('  %s %s %s' % (aid, p['name'], exc))
                return None, 'invalid-param'
            if p['type'] == 'block_device' and not block_device_eligible(value):
                warn('  %s %s: %s is not an eligible internal block device (rescue USB and removable media '
                     'are never targets)' % (aid, p['name'], value))
                return None, 'invalid-param'
            values[p['name']] = value
        return values, None

    def card(self, action, proposal, values):
        say('')
        say('== %s  [%s]  risk=%s  scope=%s' % (action['action_id'], proposal['origin'], action['risk'],
                                               action['scope']))
        say('   ID: %s' % action['title_id'])
        say('   EN: %s' % action['title'])
        if proposal.get('target_ref'):
            say('   target: %s' % proposal['target_ref'])
        shown = dict(values, **{p['name']: '<target root>' for p in action.get('params') or []
                                if p['type'] == 'target_root'})
        say('   execute: %s' % ' '.join(rc.render(action['execute']['argv'], shown)))
        say('   verify:  %s' % ' '.join(rc.render(action['verify']['argv'], shown)))
        rb = action['rollback']
        say('   rollback: %s' % (rb['kind'] if rb['kind'] != 'manual' and rb['kind'] != 'restore-backup'
                                 else '%s (%s)' % (rb['kind'], rb.get('doc'))))
        if action.get('requires_target_rw'):
            say('   PERINGATAN / WARNING: target akan di-mount read-write / the target will be mounted read-write')
        if action['backup']['required']:
            say('   backup: %s (reference supplied)' % action['backup'].get('what'))
        say('   doc: %s' % action['doc'])

    def approve(self, action, proposal):
        """(values, reason) if approved, else (None, reason) after journaling the decision."""
        aid, risk = action['action_id'], action['risk']
        auto = (self.args.policy == 'auto-safe' and risk == 'safe' and proposal['origin'] == 'catalog-trigger'
                and not action.get('requires_target_rw'))
        cli = aid in self.args.approve
        if auto or cli:
            values, problem = self.resolve_params(action, allow_prompt=False)
            if problem is None:
                return values, 'auto-safe' if auto else 'cli-approved'
            if not self.interactive:
                self.log(action, proposal, 'approval', 'skipped', reason=problem)
                return None, problem
        if not self.interactive:
            self.log(action, proposal, 'approval', 'declined', reason='not-interactive')
            return None, 'not-interactive'
        values, problem = self.resolve_params(action, allow_prompt=True)
        if problem:
            self.log(action, proposal, 'approval', 'skipped', reason=problem)
            return None, problem
        self.card(action, proposal, values)
        if risk == 'destructive':
            answer = self.ask('  Ketik action_id untuk menyetujui / type the action_id to approve: ')
            ok = answer == aid
        else:
            ok = self.ask('  Jalankan? / Run? [ya/yes, default: tidak/no]: ').lower() in YES
        if not ok:
            self.log(action, proposal, 'approval', 'declined', reason='operator-declined')
            return None, 'operator-declined'
        return values, 'operator-approved'

    def process(self, proposal):
        action = self.catalog.get(proposal['action_id'])
        aid = action['action_id']
        self.log(action, proposal, 'proposed', 'ok')
        if self.args.policy == 'detect-only':
            self.log(action, proposal, 'approval', 'skipped', reason='policy-detect-only')
            return 'proposed'
        backup = None
        if action['backup']['required']:
            if not self.args.backup_ref:
                warn('  %s needs --backup-ref (%s); not run.' % (aid, action['backup'].get('what')))
                self.log(action, proposal, 'backup', 'unavailable', reason='missing-backup')
                return 'skipped'
            try:
                backup = backup_fingerprint(self.args.backup_ref)
            except (OSError, ValueError) as exc:
                warn('  %s: backup reference unusable: %s' % (aid, exc))
                self.log(action, proposal, 'backup', 'fail', reason='missing-backup')
                return 'skipped'
            self.log(action, proposal, 'backup', 'ok', backup=backup)
        needs_target = any(p['type'] == 'target_root' for p in action.get('params') or [])
        provider = target_provider() if needs_target else None
        if needs_target and provider is None:
            self.log(action, proposal, 'target-rw', 'unavailable', reason='provider-unavailable')
            warn('  %s needs the target mount provider (scripts/lib/target_mount.py); not run.' % aid)
            return 'skipped'
        values, reason = self.approve(action, proposal)
        if values is None:
            return 'declined'
        journal_params = {k: v for k, v in values.items()}
        self.log(action, proposal, 'approval', 'ok', reason=reason, params=journal_params or None)
        if needs_target:
            name = next(p['name'] for p in action['params'] if p['type'] == 'target_root')
            try:
                ctx = provider(self.args.evidence, self.evidence, proposal.get('target_ref'),
                               bool(action.get('requires_target_rw')))
                with ctx as root:
                    self.log(action, proposal, 'target-rw', 'ok',
                             reason='not-applicable' if not action.get('requires_target_rw') else None)
                    return self.run_action(action, proposal, dict(values, **{name: root}))
            except Exception as exc:  # provider failures must never leave the engine half-way
                warn('  %s: target mount failed: %s' % (aid, exc))
                self.log(action, proposal, 'target-rw', 'fail', reason='provider-unavailable')
                return 'failed'
        return self.run_action(action, proposal, values)

    def step(self, action, proposal, stage, step, values):
        result = run_step(step, values, action.get('requires_root', False), self.path,
                          DEFAULT_TIMEOUT[stage.split('/')[0]])
        self.log(action, proposal, stage.split('/')[0], result['outcome'], **{
            k: v for k, v in result_fields(result).items() if k not in ('outcome',)})
        say('  %-12s %s' % (stage, result['outcome']))
        if result['outcome'] != 'ok':
            show_output(result)
        return result

    def run_action(self, action, proposal, values):
        for i, pre in enumerate(action.get('preconditions') or []):
            if self.step(action, proposal, 'precondition/%d' % i, pre, values)['outcome'] != 'ok':
                say('  precondition not met; action not run / prasyarat tidak terpenuhi')
                return 'skipped'
        executed = self.step(action, proposal, 'execute', action['execute'], values)
        if executed['outcome'] == 'unavailable':
            return 'skipped'
        if executed['outcome'] == 'ok':
            show_output(executed, limit=8)
            if self.step(action, proposal, 'verify', action['verify'], values)['outcome'] == 'ok':
                return 'verified'
        rb = action['rollback']
        if rb['kind'] == 'step':
            rolled = self.step(action, proposal, 'rollback', rb['step'], values)
            return 'rolled-back' if rolled['outcome'] == 'ok' else 'failed'
        if rb['kind'] in ('manual', 'restore-backup'):
            self.log(action, proposal, 'rollback', 'skipped', reason='manual-rollback-required')
            warn('  ROLLBACK MANUAL diperlukan / required: lihat / see %s' % rb.get('doc'))
        return 'failed'


# -------------------------------------------------------------------------- main

def parse_params(items):
    out = {}
    for item in items:
        m = re.match(r'^([a-z0-9.-]+)\.([a-z][a-z0-9_]{0,31})=(.*)$', item)
        if not m:
            raise ValueError('--param must be ACTION_ID.NAME=VALUE: %s' % item[:80])
        out[(m.group(1), m.group(2))] = m.group(3)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--evidence', metavar='FILE')
    ap.add_argument('--analysis', metavar='FILE', help='analysis markdown with an optional ```rescue-proposals block')
    ap.add_argument('--policy', choices=('detect-only', 'approve-each', 'auto-safe'), default='approve-each')
    ap.add_argument('--scope', default='all', help='comma list: %s' % ', '.join(rc.SCOPE_VALUES))
    ap.add_argument('--packages', type=lambda s: [p for p in s.split(',') if p], default=None,
                    help='comma list of packages for scope software.selected')
    ap.add_argument('--state-dir', metavar='DIR', help='journal at DIR/repairs/journal.jsonl')
    ap.add_argument('--journal', metavar='FILE')
    ap.add_argument('--catalog-dir', default=str(rc.CATALOG_DIR))
    ap.add_argument('--select', action='append', default=[], metavar='ACTION_ID')
    ap.add_argument('--approve', action='append', default=[], metavar='ACTION_ID')
    ap.add_argument('--param', action='append', default=[], metavar='ACTION_ID.NAME=VALUE')
    ap.add_argument('--backup-ref', metavar='FILE')
    ap.add_argument('--list', action='store_true', help='print the proposals and exit (nothing is journaled)')
    ap.add_argument('--verify-journal', metavar='FILE')
    args = ap.parse_args(argv)

    if args.verify_journal:
        problems = verify_journal(args.verify_journal)
        for p in problems:
            say('journal: %s' % p)
        say('journal: %s (%s)' % ('INVALID' if problems else 'valid', args.verify_journal))
        return EXIT_FAILED if problems else EXIT_OK
    if not args.evidence:
        ap.error('--evidence is required')
    try:
        scope = rc.normalize_scope(args.scope)
        args.param_map = parse_params(args.param)
    except ValueError as exc:
        warn('rescue-repair: %s' % exc)
        return EXIT_INVALID
    if args.packages is not None:
        bad = [p for p in args.packages if not rc.PACKAGE_RE.match(p)]
        if bad:
            warn('rescue-repair: invalid package name(s): %s' % ', '.join(b[:40] for b in bad))
            return EXIT_INVALID

    validator = load_module('rescue_validate_evidence', HERE / 'validate-evidence.py')
    try:
        raw = Path(args.evidence).read_bytes()
        evidence = json.loads(raw.decode('utf-8'))
    except (OSError, ValueError) as exc:
        warn('rescue-repair: cannot read evidence: %s' % (getattr(exc, 'strerror', None) or exc))
        return EXIT_INVALID
    analyzer = load_module('rescue_opencode_go_analyze', HERE / 'opencode-go-analyze.py')
    problems = analyzer.validation_problems(validator, evidence) if isinstance(evidence, dict) else ['not an object']
    if problems:
        warn('rescue-repair: evidence is INVALID (%s); nothing was run.' % problems[0])
        return EXIT_INVALID
    platform = rc.platform_of(evidence)
    try:
        catalog = rc.load(args.catalog_dir)
    except rc.CatalogError as exc:
        for p in exc.problems:
            warn('rescue-repair: catalog INVALID: %s' % p)
        return EXIT_INVALID

    proposals = rc.triggered(catalog, evidence, scope)
    if args.analysis:
        try:
            text = Path(args.analysis).read_text(encoding='utf-8', errors='replace')
        except OSError as exc:
            warn('rescue-repair: cannot read analysis: %s' % (exc.strerror or exc))
            return EXIT_INVALID
        ai, rejected = rc.parse_ai_proposals(text, catalog, evidence, scope)
        if rejected:
            warn('rescue-repair: %d AI proposal(s) rejected (unknown ID, wrong target, or out of scope)' % rejected)
        proposals += ai
    families = {t['ref']: t['family'] for t in evidence.get('target_systems') or []}
    for item in args.select:
        target = None
        if ':' in item:
            item, target = item.split(':', 1)
        action = catalog.get(item)
        if action is None:
            warn('rescue-repair: --select %s is not a catalog action_id' % item[:64])
            return EXIT_INVALID
        if not action.get('target_families'):
            target = None
        ok, why = rc.applicable(action, platform, scope, target, families)
        if not ok:
            warn('rescue-repair: --select %s does not apply here (%s)' % (item, why))
            return EXIT_INVALID
        proposals.append(dict({'action_id': item, 'origin': 'operator'}, **({'target_ref': target} if target else {})))
    unique, seen = [], set()
    for p in proposals:
        key = (p['action_id'], p.get('target_ref'))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    proposals = unique

    say('Repair plan / rencana perbaikan: policy=%s scope=%s platform=%s catalog=%s' % (
        args.policy, ','.join(scope), platform, catalog.sha256[:12]))
    if not proposals:
        say('  Tidak ada tindakan katalog yang berlaku / no applicable catalog actions.')
    for p in proposals:
        a = catalog.get(p['action_id'])
        say('  - %-40s %-11s %-15s %s' % (p['action_id'], a['risk'], p['origin'], p.get('target_ref', '-')))
    if args.list or not proposals:
        return EXIT_OK
    if platform not in EXECUTING_PLATFORMS and args.policy != 'detect-only':
        warn('rescue-repair: %s actions are executed by the host launcher engine, not here; '
             'use --list or --policy detect-only.' % platform)
        return EXIT_INVALID

    journal_path = args.journal or (os.path.join(args.state_dir, 'repairs', 'journal.jsonl') if args.state_dir else None)
    if not journal_path:
        warn('rescue-repair: --journal or --state-dir is required to act on proposals')
        return EXIT_INVALID
    try:
        journal = Journal(journal_path, evidence['run_id'], catalog.sha256, args.policy, platform,
                          hashlib.sha256(raw).hexdigest())
        engine = Engine(args, evidence, hashlib.sha256(raw).hexdigest(), catalog, platform, journal)
        outcomes = []
        for proposal in proposals:
            outcome = engine.process(proposal)
            outcomes.append((proposal, outcome))
    except JournalError as exc:
        warn('rescue-repair: %s' % exc)
        return EXIT_JOURNAL
    say('')
    say('Ringkasan / summary (journal: %s):' % journal_path)
    for proposal, outcome in outcomes:
        say('  %-40s %s' % (proposal['action_id'], outcome))
    return EXIT_FAILED if any(o in ('failed', 'rolled-back') for _, o in outcomes) else EXIT_OK


if __name__ == '__main__':
    with contextlib.suppress(KeyboardInterrupt):
        sys.exit(main())
    sys.exit(130)
