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
            print(f'evidence: valid ({name})')
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
