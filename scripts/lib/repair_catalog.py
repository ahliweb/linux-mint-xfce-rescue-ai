#!/usr/bin/env python3
"""Load, validate and match the typed repair action catalog (rescue-ai/v1/catalog/*.json).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

The catalog is reviewed code: every command is a fixed argv array. Nothing that
comes from evidence, logs, filenames or model output ever becomes a command;
the AI can only name an ``action_id`` and the engine decides, under the repair
policy, whether that action runs. This module is pure Python (plus
python3-jsonschema) so it can be unit-tested without root, disks or network.

Placeholders inside argv elements take exactly one of three forms:

  ``{name}``                 the whole element is the parameter value
  ``--opt={name}``           a literal option prefix, then the value
  ``{target_root}/lit/path`` only for target_root parameters, a literal path suffix

Engine-provided parameter types (never operator input): ``target_root`` (mount point of the target
OS) and ``state_dir`` (one fixed subdirectory, ``clamav`` or ``quarantine``, of the USB state).
``detection_ref`` (``d-N``) is an operator-chosen opaque reference to one entry of the local
malware detection list; the engine resolves it to a verified regular-file path.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIR = ROOT / 'rescue-ai/v1/catalog'
CATALOG_SCHEMA = ROOT / 'rescue-ai/v1/repair-catalog.schema.json'
EVIDENCE_SCHEMA = ROOT / 'rescue-ai/v1/rescue-evidence.schema.json'

DOMAIN_PREFIX = {'hardware': 'hw', 'os-linux': 'os-linux', 'os-windows': 'os-windows',
                 'os-macos': 'os-macos', 'software': 'sw', 'malware': 'mw'}
DOMAIN_FAMILIES = {'os-linux': {'linuxmint', 'linux-other'}, 'os-windows': {'windows'}, 'os-macos': {'macos'}}
DOMAIN_PLATFORMS = {'os-linux': {'live-linux', 'linux-host'}, 'os-windows': {'live-linux', 'windows-host'},
                    'os-macos': {'live-linux', 'macos-host'}}
DETECTION_RE = re.compile(r'^d-[0-9]{1,4}$')
LIVE_PLATFORMS = {'linux-mint-xfce-live': 'live-linux', 'systemrescue-live': 'live-linux',
                  'other-live-linux': 'live-linux', 'linux-host': 'linux-host',
                  'windows-host': 'windows-host', 'macos-host': 'macos-host'}
SCOPE_ITEMS = ('hardware.cpu', 'hardware.memory', 'hardware.disk', 'hardware.gpu', 'hardware.display',
               'hardware.network', 'hardware.battery', 'hardware.usb', 'os', 'software', 'malware')
SCOPE_VALUES = ('all', 'hardware') + SCOPE_ITEMS[:-1] + ('software.selected', 'malware')

# Programs that would turn a fixed argv back into "run anything": shells,
# interpreters, privilege wrappers (the engine adds `sudo -n` itself), command
# runners, and raw block writers. Backups are made by the operator, not by dd.
FORBIDDEN_PROGRAMS = frozenset("""
sh bash dash zsh ksh mksh csh tcsh fish busybox env sudo su doas pkexec runuser setpriv
python python2 python3 perl ruby node nodejs php lua tclsh osascript expect script
cmd cmd.exe powershell powershell.exe pwsh pwsh.exe wscript wscript.exe cscript cscript.exe
mshta mshta.exe rundll32 rundll32.exe regsvr32 regsvr32.exe
xargs find awk gawk mawk nawk sed eval exec nohup timeout nice ionice setsid watch
dd ssh scp curl wget nc ncat socat docker podman
""".split())

PLACEHOLDER = re.compile(r'\{([a-z][a-z0-9_]{0,31})\}')
WHOLE = re.compile(r'^\{([a-z][a-z0-9_]{0,31})\}$')
PREFIXED = re.compile(r'^(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*=)\{([a-z][a-z0-9_]{0,31})\}$')
ROOTED = re.compile(r'^\{([a-z][a-z0-9_]{0,31})\}((?:/[A-Za-z0-9._+-]+)+)$')

PACKAGE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$')
SERVICE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$')
BLOCK_RE = re.compile(r'^/dev/[A-Za-z0-9][A-Za-z0-9_-]{0,31}(/[A-Za-z0-9][A-Za-z0-9_-]{0,31}){0,2}$')
ENUM_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$')

PROPOSAL_FENCE = re.compile(r'^[ \t]*```rescue-proposals[ \t]*\n(.*?)\n[ \t]*```[ \t]*$', re.S | re.M)
MAX_PROPOSAL_BLOCK = 4096
MAX_AI_PROPOSALS = 16


class CatalogError(Exception):
    """The catalog is unusable; .problems lists every reason."""

    def __init__(self, problems):
        super().__init__(problems[0] if problems else 'invalid catalog')
        self.problems = list(problems)


def _jsonschema():
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CatalogError(['python3-jsonschema is required: sudo apt install python3-jsonschema']) from exc
    return jsonschema


def evidence_check_ids(schema_path=EVIDENCE_SCHEMA):
    schema = json.loads(Path(schema_path).read_text(encoding='utf-8'))
    return set(schema['properties']['checks']['items']['properties']['check_id']['enum'])


# ------------------------------------------------------------------ invariants

def _steps(action):
    steps = [('execute', action['execute']), ('verify', action['verify'])]
    steps += [('preconditions/%d' % i, s) for i, s in enumerate(action.get('preconditions') or [])]
    rollback = action['rollback']
    if rollback.get('step'):
        steps.append(('rollback', rollback['step']))
    return steps


def _placeholder_errors(where, argv, params):
    errors, used = [], set()
    for i, element in enumerate(argv):
        if '{' not in element and '}' not in element:
            continue
        m = WHOLE.match(element) or PREFIXED.match(element)
        name = None
        if m:
            name = m.group(m.lastindex)
        else:
            r = ROOTED.match(element)
            if r and '..' not in r.group(2).split('/'):
                name = r.group(1)
                if params.get(name, {}).get('type') != 'target_root':
                    errors.append('%s argv[%d]: a path suffix is only allowed after a target_root parameter'
                                  % (where, i))
            else:
                errors.append('%s argv[%d]: placeholders must be {name}, --opt={name}, or {target_root}/path'
                              % (where, i))
                continue
        if i == 0:
            errors.append('%s argv[0] must be a literal program name' % where)
        if name not in params:
            errors.append('%s argv[%d]: parameter {%s} is not declared' % (where, i, name))
        used.add(name)
    return errors, used


def action_errors(action, domain, check_ids):
    """Cross-field rules the JSON Schema cannot express for one action."""
    aid = action['action_id']
    errors = []
    say = errors.append
    if aid.split('.', 1)[0] != DOMAIN_PREFIX[domain]:
        say('%s: action_id prefix must be %r in domain %s' % (aid, DOMAIN_PREFIX[domain], domain))

    params = {}
    for p in action.get('params') or []:
        if p['name'] in params:
            say('%s: duplicate parameter %s' % (aid, p['name']))
        params[p['name']] = p
        kind = p['type']
        if kind == 'enum':
            if not p.get('values'):
                say('%s: enum parameter %s needs values' % (aid, p['name']))
            elif 'default' in p and p['default'] not in p['values']:
                say('%s: default of %s is not one of its values' % (aid, p['name']))
        elif kind == 'state_dir':
            if p.get('values') not in (['clamav'], ['quarantine']):
                say('%s: state_dir parameter %s needs exactly one value: clamav or quarantine' % (aid, p['name']))
        elif 'values' in p:
            say('%s: only enum and state_dir parameters take values (%s)' % (aid, p['name']))
        if kind == 'integer':
            lo, hi = p.get('minimum'), p.get('maximum')
            if lo is None or hi is None or lo > hi:
                say('%s: integer parameter %s needs minimum <= maximum' % (aid, p['name']))
            elif 'default' in p and not (isinstance(p['default'], int) and lo <= p['default'] <= hi):
                say('%s: default of %s is outside minimum..maximum' % (aid, p['name']))
        elif 'minimum' in p or 'maximum' in p:
            say('%s: only integer parameters take minimum/maximum (%s)' % (aid, p['name']))
        if kind in ('block_device', 'target_root', 'detection_ref', 'state_dir') and 'default' in p:
            say('%s: %s parameters cannot have a default (%s)' % (aid, kind, p['name']))
        if kind == 'target_root' and set(action['platforms']) != {'live-linux'}:
            say('%s: target_root parameters exist only on the live-linux platform' % aid)

    used = set()
    for where, step in _steps(action):
        argv = step['argv']
        if argv[0].lower() in FORBIDDEN_PROGRAMS:
            say('%s %s: program %r is not allowed in the catalog' % (aid, where, argv[0]))
        if argv[0] == 'chroot' and (action['risk'] == 'safe' or not action.get('requires_root')):
            say('%s %s: chroot needs requires_root and a non-safe risk class' % (aid, where))
        errs, names = _placeholder_errors('%s %s' % (aid, where), argv, params)
        errors.extend(errs)
        used |= names
    for name in params:
        if name not in used:
            say('%s: parameter %s is declared but never used' % (aid, name))

    risk, rollback, backup = action['risk'], action['rollback'], action['backup']
    kind = rollback['kind']
    if kind == 'step' and not rollback.get('step'):
        say('%s: rollback kind step needs a step' % aid)
    if kind != 'step' and rollback.get('step'):
        say('%s: rollback step given but kind is %s' % (aid, kind))
    if kind in ('manual', 'restore-backup') and not rollback.get('doc'):
        say('%s: rollback kind %s needs a doc reference' % (aid, kind))
    if backup['required'] and not backup.get('what'):
        say('%s: a required backup must say what is backed up' % aid)
    if risk == 'safe':
        if kind not in ('none', 'step'):
            say('%s: safe actions roll back automatically or not at all' % aid)
        if backup['required'] or action.get('requires_target_rw'):
            say('%s: safe actions cannot require a backup or a read-write target' % aid)
    elif risk == 'reversible':
        if kind != 'step':
            say('%s: reversible actions need an automatic rollback step' % aid)
    elif risk == 'destructive':
        if not backup['required']:
            say('%s: destructive actions require a backup' % aid)
        if kind not in ('restore-backup', 'manual'):
            say('%s: destructive actions roll back by restore-backup or a manual procedure' % aid)
    if action.get('requires_target_rw'):
        if set(action['platforms']) != {'live-linux'}:
            say('%s: requires_target_rw exists only on the live-linux platform' % aid)
        if not any(p['type'] == 'target_root' for p in params.values()):
            say('%s: requires_target_rw needs a target_root parameter' % aid)

    families = action.get('target_families')
    if domain == 'hardware':
        if families:
            say('%s: hardware actions are about the machine and take no target_families' % aid)
        if not action['scope'].startswith('hardware.'):
            say('%s: hardware actions need a hardware.* scope' % aid)
    else:
        if not families and domain != 'malware':  # malware actions may be about the scanner, not one OS
            say('%s: %s actions need target_families' % (aid, domain))
        expected_scope = {'software': 'software', 'malware': 'malware'}.get(domain, 'os')
        if action['scope'] != expected_scope:
            say('%s: %s actions use scope %r' % (aid, domain, expected_scope))
    if domain in DOMAIN_FAMILIES and families and not set(families) <= DOMAIN_FAMILIES[domain]:
        say('%s: target_families must be within %s' % (aid, sorted(DOMAIN_FAMILIES[domain])))
    if domain in DOMAIN_PLATFORMS and not set(action['platforms']) <= DOMAIN_PLATFORMS[domain]:
        say('%s: platforms must be within %s' % (aid, sorted(DOMAIN_PLATFORMS[domain])))
    for t in action['triggers']:
        if t['check_id'] not in check_ids:
            say('%s: trigger check_id %r is not in the evidence schema' % (aid, t['check_id']))
    return errors


# ---------------------------------------------------------------------- loading

class Catalog:
    def __init__(self, actions, sha256, files):
        self.actions = actions      # action_id -> action dict (with '_domain')
        self.sha256 = sha256        # SHA-256 over every file name + content, sorted
        self.files = files

    def get(self, action_id):
        return self.actions.get(action_id)


def directory_sha256(catalog_dir=CATALOG_DIR):
    """The catalog SHA-256 (every file name + content, sorted) WITHOUT validating it (no python3-jsonschema needed).

    None when the directory has no catalog files. Equals load(...).sha256 for a catalog that loads.
    """
    paths = sorted(Path(catalog_dir).glob('*.json'))
    if not paths:
        return None
    digest = hashlib.sha256()
    try:
        for path in paths:
            digest.update(path.name.encode('utf-8') + b'\0' + path.read_bytes() + b'\0')
    except OSError:
        return None
    return digest.hexdigest()


def load(catalog_dir=CATALOG_DIR, schema_path=CATALOG_SCHEMA, evidence_schema=EVIDENCE_SCHEMA):
    """Load and validate every *.json catalog; raise CatalogError with all problems."""
    jsonschema = _jsonschema()
    schema = json.loads(Path(schema_path).read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    check_ids = evidence_check_ids(evidence_schema)
    problems, actions, files = [], {}, []
    digest = hashlib.sha256()
    paths = sorted(Path(catalog_dir).glob('*.json'))
    if not paths:
        raise CatalogError(['no catalog files in %s' % catalog_dir])
    domains = {}
    for path in paths:
        raw = path.read_bytes()
        digest.update(path.name.encode('utf-8') + b'\0' + raw + b'\0')
        files.append(path.name)
        try:
            doc = json.loads(raw.decode('utf-8'))
        except ValueError as exc:
            problems.append('%s: invalid JSON: %s' % (path.name, exc))
            continue
        errs = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
        if errs:
            best = jsonschema.exceptions.best_match(errs)
            where = '/'.join(str(p) for p in best.absolute_path) or '<root>'
            problems.append('%s: %s at %s' % (path.name, best.message, where))
            continue
        domain = doc['domain']
        if domain in domains:
            problems.append('%s: domain %s is already defined by %s' % (path.name, domain, domains[domain]))
        domains[domain] = path.name
        for action in doc['actions']:
            problems.extend('%s: %s' % (path.name, e) for e in action_errors(action, domain, check_ids))
            if action['action_id'] in actions:
                problems.append('%s: duplicate action_id %s' % (path.name, action['action_id']))
            actions[action['action_id']] = dict(action, _domain=domain)
    if problems:
        raise CatalogError(problems)
    return Catalog(actions, digest.hexdigest(), files)


# ---------------------------------------------------------------------- matching

def normalize_scope(scope):
    """Validate a scope list (or comma string); returns a tuple. Default: ('all',)."""
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.split(',') if s.strip()]
    scope = tuple(dict.fromkeys(scope or ['all']))
    bad = [s for s in scope if s not in SCOPE_VALUES]
    if bad:
        raise ValueError('unknown scope item(s): %s (allowed: %s)' % (', '.join(bad), ', '.join(SCOPE_VALUES)))
    if 'all' in scope and len(scope) > 1:
        raise ValueError('scope "all" must be used alone')
    for group in ('hardware', 'software'):
        if group in scope and any(s.startswith(group + '.') for s in scope):
            raise ValueError('scope "%s" already covers its %s.* items' % (group, group))
    return scope


def in_scope(scope, item):
    """Is catalog scope *item* selected by the normalized operator *scope*?"""
    if 'all' in scope or item in scope:
        return True
    if item.startswith('hardware.'):
        return 'hardware' in scope
    if item == 'software':
        return 'software.selected' in scope
    return False


def platform_of(evidence):
    return LIVE_PLATFORMS.get(evidence.get('source_platform'))


def _families(evidence):
    return {t['ref']: t['family'] for t in evidence.get('target_systems') or []}


def applicable(action, platform, scope, target_ref, families):
    """(ok, reason) for running *action* against *target_ref* on *platform*."""
    if platform not in action['platforms']:
        return False, 'platform'
    if not in_scope(scope, action['scope']):
        return False, 'scope'
    wanted = action.get('target_families')
    if wanted:
        if target_ref is None or families.get(target_ref) not in wanted:
            return False, 'target-family'
    return True, None


def triggered(catalog, evidence, scope):
    """Catalog-trigger proposals for *evidence*: list of dicts, evidence order, de-duplicated."""
    platform, families = platform_of(evidence), _families(evidence)
    out, seen = [], set()
    for check in evidence.get('checks') or []:
        for aid, action in catalog.actions.items():
            for trig in action['triggers']:
                if trig['check_id'] != check['check_id'] or check['status'] not in trig['status']:
                    continue
                ref = check.get('target_ref') if action.get('target_families') else None
                ok, _ = applicable(action, platform, scope, ref, families)
                key = (aid, ref)
                if ok and key not in seen:
                    seen.add(key)
                    item = {'action_id': aid, 'origin': 'catalog-trigger', 'trigger_check_id': check['check_id']}
                    if ref:
                        item['target_ref'] = ref
                    out.append(item)
    return out


def parse_ai_proposals(text, catalog, evidence, scope):
    """Extract the last ```rescue-proposals block from model *text*.

    Returns (accepted, rejected_count). The block is untrusted data: only exact
    catalog IDs that are applicable to this evidence survive, as proposals with
    origin ai-proposal. Anything malformed is rejected, never repaired.
    """
    blocks = PROPOSAL_FENCE.findall(text or '')
    if not blocks:
        return [], 0
    block = blocks[-1]
    if len(block.encode('utf-8')) > MAX_PROPOSAL_BLOCK:
        return [], 1
    try:
        doc = json.loads(block)
    except ValueError:
        return [], 1
    items = doc.get('proposed_actions') if isinstance(doc, dict) and set(doc) == {'proposed_actions'} else None
    if not isinstance(items, list):
        return [], 1
    platform, families = platform_of(evidence), _families(evidence)
    accepted, rejected, seen = [], 0, set()
    for item in items[:MAX_AI_PROPOSALS]:
        if not isinstance(item, dict) or not set(item) <= {'action_id', 'target_ref'}:
            rejected += 1
            continue
        aid, ref = item.get('action_id'), item.get('target_ref')
        action = catalog.get(aid) if isinstance(aid, str) else None
        if action is None or (ref is not None and (not isinstance(ref, str) or ref not in families)):
            rejected += 1
            continue
        if not action.get('target_families'):
            ref = None
        ok, _ = applicable(action, platform, scope, ref, families)
        if not ok or (aid, ref) in seen:
            rejected += 1
            continue
        seen.add((aid, ref))
        out = {'action_id': aid, 'origin': 'ai-proposal'}
        if ref:
            out['target_ref'] = ref
        accepted.append(out)
    rejected += max(0, len(items) - MAX_AI_PROPOSALS)
    return accepted, rejected


def prompt_summary(catalog, evidence, scope):
    """Compact list of applicable actions for the analysis prompt (IDs and metadata only, no argv)."""
    platform = platform_of(evidence)
    rows = []
    for aid in sorted(catalog.actions):
        a = catalog.actions[aid]
        if platform not in a['platforms'] or not in_scope(scope, a['scope']):
            continue
        rows.append({'action_id': aid, 'title': a['title'], 'scope': a['scope'], 'risk': a['risk'],
                     'target_families': a.get('target_families', []),
                     'triggers': sorted({t['check_id'] for t in a['triggers']})})
    return rows


# ---------------------------------------------------------------------- params

def validate_param(param, value, packages=None):
    """Return the typed value or raise ValueError. block_device/target_root get extra runtime checks."""
    kind = param['type']
    if kind == 'enum':
        if value not in param['values']:
            raise ValueError('must be one of: %s' % ', '.join(param['values']))
        return value
    if kind == 'integer':
        try:
            number = int(str(value), 10)
        except ValueError:
            raise ValueError('must be an integer') from None
        if not param['minimum'] <= number <= param['maximum']:
            raise ValueError('must be between %d and %d' % (param['minimum'], param['maximum']))
        return number
    text = str(value)
    if kind == 'package_name':
        if not PACKAGE_RE.match(text):
            raise ValueError('is not a valid package name')
        if text.endswith('-'):
            # apt reads a trailing '-' as "remove this package": `install --reinstall vim-` removes vim.
            raise ValueError('must not end with "-" (apt would treat it as a removal)')
        if packages is not None and text not in packages:
            raise ValueError('is not in the operator-selected package list')
        return text
    if kind == 'service_name':
        if not SERVICE_RE.match(text):
            raise ValueError('is not a valid service name')
        return text
    if kind == 'detection_ref':
        if not DETECTION_RE.match(text):
            raise ValueError('is not a detection reference (d-N)')
        return text
    if kind == 'block_device':
        if not BLOCK_RE.match(text) or '..' in text.split('/'):
            raise ValueError('is not a /dev/ block device path')
        return text
    if kind == 'target_root':
        raise ValueError('is provided by the target mount provider, never by the operator')
    if kind == 'state_dir':
        raise ValueError('is provided by the engine (the USB state directory), never by the operator')
    raise ValueError('unknown parameter type %s' % kind)


def render(argv, values):
    """Substitute validated *values* into a catalog argv; every element stays one argument."""
    out = []
    for element in argv:
        m = WHOLE.match(element) or PREFIXED.match(element) or ROOTED.match(element)
        if m is None:
            out.append(element)
            continue
        out.append(PLACEHOLDER.sub(lambda mm: str(values[mm.group(1)]), element, count=1))
    return out


def _main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(description='Validate the repair catalog.')
    ap.add_argument('--catalog-dir', default=str(CATALOG_DIR))
    args = ap.parse_args(argv)
    try:
        catalog = load(args.catalog_dir)
    except CatalogError as exc:
        for problem in exc.problems:
            print('catalog: INVALID: %s' % problem, file=sys.stderr)
        return 1
    print('catalog: valid (%d actions in %d files, sha256 %s)' % (len(catalog.actions), len(catalog.files),
                                                                     catalog.sha256))
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
