#!/usr/bin/env python3
"""Validate rescue evidence JSON files against rescue-ai/v1/rescue-evidence.schema.json.

Exit codes: 0 all valid, 1 at least one invalid, 2 usage/unreadable/parse error/missing jsonschema.
"""
import argparse
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print('jsonschema is required: sudo apt install python3-jsonschema', file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / 'rescue-ai/v1/rescue-evidence.schema.json'


def format_path(error):
    parts = list(error.absolute_path)
    return '/' + '/'.join(str(p) for p in parts) if parts else '<root>'


V11_ONLY_PLATFORMS = {'linux-host', 'windows-host', 'macos-host'}
V12_FIELDS = ('scope', 'repair_policy', 'repair_proposals')
V12_CHECK_IDS = {
    'linux-boot-partition-space', 'linux-grub-config', 'linux-apt-sources', 'linux-dpkg-lock',
    'windows-boot-config', 'windows-system-files', 'windows-restore-points', 'macos-disk-verify',
}
V12_MUTATION_STATUSES = {'failed', 'rolled_back'}
V12_VALUE_KINDS = {'celsius'}
PRE_V12_MAX_CHECKS = 64
SCOPE_GROUPS = {'hardware': 'hardware.', 'software': 'software.'}


def is_v12_check(check_id):
    return check_id in V12_CHECK_IDS or check_id.startswith(('hw-', 'sw-', 'malware-'))


def scope_errors(scope):
    errors = []
    if 'all' in scope and len(scope) > 1:
        errors.append('scope "all" must be the only entry')
    for group, prefix in SCOPE_GROUPS.items():
        if group in scope and any(s.startswith(prefix) for s in scope):
            errors.append(f'scope "{group}" already covers its {prefix}* items; list one or the other')
    return errors


def semantic_errors(data):
    """Cross-field rules JSON Schema cannot express; only run on schema-valid data."""
    errors = []
    targets = data.get('target_systems') or []
    refs = [t['ref'] for t in targets]
    if len(refs) != len(set(refs)):
        errors.append('target_systems[].ref values must be unique')
    for i, c in enumerate(data['checks']):
        ref = c.get('target_ref')
        if ref is not None and ref not in refs:
            errors.append(f'checks/{i}/target_ref {ref!r} does not match any target_systems[].ref')
    if data['schema_version'] == '1.0':
        if 'target_systems' in data or data['source_platform'] in V11_ONLY_PLATFORMS or any(
                'target_ref' in c or 'value' in c for c in data['checks']):
            errors.append('schema_version 1.0 must not use 1.1 fields (target_systems, target_ref, value, host platforms)')
    if data['schema_version'] in ('1.0', '1.1'):
        if any(field in data for field in V12_FIELDS) or any(is_v12_check(c['check_id']) for c in data['checks']) \
                or data['mutation_status'] in V12_MUTATION_STATUSES \
                or any((c.get('value') or {}).get('kind') in V12_VALUE_KINDS for c in data['checks']):
            errors.append('schema_version %s must not use 1.2 fields (scope, repair_policy, repair_proposals, '
                          'hw-*/sw-*/malware-* and new OS check IDs, failed/rolled_back, celsius)' % data['schema_version'])
        if len(data['checks']) > PRE_V12_MAX_CHECKS:
            errors.append('schema_version %s allows at most %d checks' % (data['schema_version'], PRE_V12_MAX_CHECKS))
    errors.extend(scope_errors(data.get('scope') or []))
    seen = set()
    for i, p in enumerate(data.get('repair_proposals') or []):
        ref = p.get('target_ref')
        if ref is not None and ref not in refs:
            errors.append(f'repair_proposals/{i}/target_ref {ref!r} does not match any target_systems[].ref')
        trig = p.get('trigger_check_id')
        if trig is not None and trig not in {c['check_id'] for c in data['checks']}:
            errors.append(f'repair_proposals/{i}/trigger_check_id {trig!r} does not match any checks[].check_id')
        key = (p['action_id'], ref)
        if key in seen:
            errors.append(f'repair_proposals/{i} duplicates action {p["action_id"]!r} for the same target')
        seen.add(key)
    ai = data['ai_provider']
    if ai['destination_class'] == 'cloud' and not ai['authenticated']:
        errors.append('ai_provider.destination_class "cloud" requires authenticated true')
    if data['evidence_manifest']['entry_count'] != len(data['checks']):
        errors.append('evidence_manifest.entry_count must equal the number of checks')
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('files', nargs='+', metavar='FILE', help='evidence JSON file(s) to validate')
    args = parser.parse_args(argv)

    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(f'evidence: cannot load schema {SCHEMA_PATH}: {exc}', file=sys.stderr)
        return 2

    validator_cls = jsonschema.Draft202012Validator
    try:
        validator_cls.check_schema(schema)
    except jsonschema.SchemaError as exc:
        print(f'evidence: schema is invalid: {exc.message}', file=sys.stderr)
        return 2
    try:
        validator = validator_cls(schema, format_checker=jsonschema.FormatChecker())
    except Exception:
        validator = validator_cls(schema)

    any_invalid = False
    for name in args.files:
        try:
            data = json.loads(Path(name).read_text(encoding='utf-8'))
        except OSError as exc:
            print(f'evidence: cannot read {name}: {exc.strerror or exc}', file=sys.stderr)
            return 2
        except ValueError as exc:  # includes JSONDecodeError and UnicodeDecodeError
            print(f'evidence: cannot parse JSON in {name}: {exc}', file=sys.stderr)
            return 2
        errors = sorted(validator.iter_errors(data), key=lambda e: [str(p) for p in e.absolute_path])
        if not errors:
            problems = semantic_errors(data)
            if not problems:
                print(f'evidence: valid ({name})')
                continue
            any_invalid = True
            print(f'evidence: INVALID ({name}): {problems[0]}')
            for problem in problems[1:]:
                print(f'  - {problem}')
            continue
        any_invalid = True
        best = jsonschema.exceptions.best_match(errors)
        print(f'evidence: INVALID ({name}): {best.message} at {format_path(best)}')
        if len(errors) > 1:
            for err in errors:
                print(f'  - {err.message} at {format_path(err)}')
    return 1 if any_invalid else 0


if __name__ == '__main__':
    raise SystemExit(main())
