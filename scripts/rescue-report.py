#!/usr/bin/env python3
"""Write the comprehensive run report (report.md + report.json + index.md) to the rescue USB.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com. See docs/run-report.md.

Generated from artifacts that already exist: the evidence, the optional post-repair evidence, the
model analysis, the hash-chained repair journal, and the hardware-readiness JSON. Every input is
optional: a failed or partial run still gets a report that says what was not verified. The report
never contains usernames, hostnames, serials, IP/MAC addresses, paths, file names, malware signature
names, package names, or raw command output, and a privacy self-check refuses to write a full
report that does (a minimal error report is written instead).

  <reports>/run-<utc-stamp>/report.md    Bahasa Indonesia with English headings
  <reports>/run-<utc-stamp>/report.json  validated by rescue-ai/v1/run-report.schema.json
  <reports>/index.md                     one row per run, newest first

  rescue-report.py --validate FILE...   check report.json files against rescue-ai/v1/run-report.schema.json

Exit codes: 0 report written (or --validate: every file valid) | 1 the privacy self-check refused the
full report (minimal report written), or --validate found an invalid file | 2 invalid arguments |
3 reports directory not writable
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'lib'))
import run_report as rr  # noqa: E402
import repair_catalog as rc  # noqa: E402

EXIT_OK, EXIT_PRIVACY, EXIT_INVALID, EXIT_IO = 0, 1, 2, 3


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_bytes(path):
    if not path:
        return None
    try:
        return Path(path).read_bytes()
    except OSError:
        return None


def read_json(path):
    raw = read_bytes(path)
    if raw is None:
        return None, None
    try:
        return json.loads(raw.decode('utf-8')), raw
    except ValueError:
        return None, raw


def journal_lines(path):
    raw = read_bytes(path)
    if raw is None:
        return None
    return [line for line in raw.split(b'\n') if line.strip()]


def schema_problems(journal_path, lines):
    """Journal contract violations (schema + chain) via the repair engine's own verifier; [] if unavailable."""
    try:
        engine = load_module('rescue_repair_engine', HERE / 'rescue-repair.py')
        return engine.verify_journal(journal_path)
    except SystemExit:
        return []
    except Exception:  # jsonschema missing etc.: the built-in chain check still runs
        return []


def action_info(catalog):
    info = {}
    for aid, action in catalog.actions.items():
        info[aid] = {'doc': (action.get('rollback') or {}).get('doc'),
                     'params': {p['name']: p['type'] for p in action.get('params') or []}}
    return info


def validate_files(paths):
    """Schema check of report.json files (part of make check for the fixtures)."""
    try:
        import jsonschema
    except ImportError:
        print('rescue-report: python3-jsonschema is required: sudo apt install python3-jsonschema', file=sys.stderr)
        return EXIT_INVALID
    schema = json.loads((rc.ROOT / 'rescue-ai/v1/run-report.schema.json').read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    bad = 0
    for path in paths:
        doc, _ = read_json(path)
        errors = sorted(validator.iter_errors(doc), key=lambda e: [str(x) for x in e.absolute_path]) if doc is not None else None
        if errors is None or errors:
            bad += 1
            where = '/'.join(str(x) for x in errors[0].absolute_path) if errors else ''
            print('%s: INVALID (%s)' % (path, errors[0].message[:120] + (' at ' + where if where else '') if errors else 'not JSON'))
        else:
            print('%s: valid' % path)
    return EXIT_PRIVACY if bad else EXIT_OK


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--reports-dir', metavar='DIR')
    ap.add_argument('--run-id', help='report run id (the evidence run_id is used for the journal filter)')
    ap.add_argument('--mode', choices=rr.MODES)
    ap.add_argument('--validate', nargs='+', metavar='FILE', help='validate report.json files against the schema and exit')
    ap.add_argument('--outcome', default='completed', choices=[o for o in rr.OUTCOMES if o != 'report-privacy-refused'])
    ap.add_argument('--evidence', metavar='FILE')
    ap.add_argument('--evidence-after', metavar='FILE')
    ap.add_argument('--analysis', metavar='FILE')
    ap.add_argument('--journal', metavar='FILE')
    ap.add_argument('--readiness', metavar='FILE')
    ap.add_argument('--scope', default='', help='fallback scope when there is no evidence')
    ap.add_argument('--repair-policy', choices=rr.POLICIES, help='fallback policy when there is no evidence')
    ap.add_argument('--started-at', metavar='UTC')
    ap.add_argument('--ended-at', metavar='UTC')
    ap.add_argument('--key-present', choices=('yes', 'no'), help='default: an API key is found in the environment or --env-file')
    ap.add_argument('--env-file', action='append', default=[], metavar='FILE', help='rescue.env/hermes env, parsed as data')
    ap.add_argument('--catalog-dir', default=str(rc.CATALOG_DIR))
    ap.add_argument('--version-file', default=str(rc.ROOT / 'VERSION'))
    args = ap.parse_args(argv)

    if args.validate:
        return validate_files(args.validate)
    if not (args.reports_dir and args.run_id and args.mode):
        ap.error('--reports-dir, --run-id and --mode are required')
    if not rr.RUN_RE.match(args.run_id):
        print('rescue-report: invalid --run-id', file=sys.stderr)
        return EXIT_INVALID
    now = utc_now()
    started, ended = args.started_at or now, args.ended_at or now
    if not (rr.STAMP_RE.match(started) and rr.STAMP_RE.match(ended)):
        print('rescue-report: --started-at/--ended-at must be UTC like 2026-09-30T08:00:00Z', file=sys.stderr)
        return EXIT_INVALID
    scope = [s for s in args.scope.split(',') if s]
    if any(s not in rr.SCOPE_VALUES for s in scope):
        print('rescue-report: invalid --scope', file=sys.stderr)
        return EXIT_INVALID

    secrets = []
    try:  # the same data-only key parser as the analyzer; the report must not depend on that script being present
        key = load_module('rescue_opencode_go_analyze', HERE / 'opencode-go-analyze.py').find_api_key(args.env_file)
    except Exception:
        key = os.environ.get('OPENCODE_GO_API_KEY') or None
    if key:
        secrets.append(key)
    key_present = (args.key_present == 'yes') if args.key_present else bool(key)

    evidence, evidence_raw = read_json(args.evidence)
    after, _ = read_json(args.evidence_after)
    readiness, _ = read_json(args.readiness)
    analysis_raw = read_bytes(args.analysis)
    analysis_text = analysis_raw.decode('utf-8', 'replace') if analysis_raw is not None else None
    lines = journal_lines(args.journal)
    version = None
    try:
        text = Path(args.version_file).read_text(encoding='utf-8').strip()
        version = text if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$', text) else None
    except OSError:
        pass
    catalog = info = None
    try:
        catalog = rc.load(args.catalog_dir)
        info = action_info(catalog)
    except (rc.CatalogError, Exception):  # catalog problems never block the report
        catalog = None

    counts = None
    if not analysis_text or not analysis_text.strip():
        counts = (0, 0)
    elif catalog is not None and rr.sane_evidence(evidence):
        try:
            ai, rejected = rc.parse_ai_proposals(analysis_text, catalog, evidence,
                                                 rc.normalize_scope(evidence.get('scope') or ['all']))
            counts = (len(ai), rejected)
        except (ValueError, KeyError, TypeError):
            counts = None

    inp = {
        'run_id': args.run_id, 'mode': args.mode, 'outcome': args.outcome, 'started_at': started, 'ended_at': ended,
        'version': version, 'catalog_sha256': catalog.sha256 if catalog is not None else None,
        'scope': scope or None, 'repair_policy': args.repair_policy, 'key_present': key_present,
        'evidence': evidence, 'evidence_sha256': hashlib.sha256(evidence_raw).hexdigest() if evidence_raw else None,
        'evidence_after': after, 'analysis_text': analysis_text, 'ai_counts': counts,
        'journal_lines': lines, 'readiness': readiness, 'action_info': info or {},
    }
    if lines is not None:
        inp['journal_extra_problems'] = schema_problems(args.journal, lines)
    try:
        name, report = rr.write_run(args.reports_dir, inp, secrets)
    except OSError as exc:
        print('rescue-report: cannot write the report: %s' % (exc.strerror or exc), file=sys.stderr)
        return EXIT_IO
    print('Laporan tersimpan / report saved: %s/%s/report.md' % (args.reports_dir, name))
    if report['privacy_check']['status'] == 'refused':
        print('PERINGATAN / WARNING: privacy self-check refused the full report (%s); a minimal report was written.'
              % ', '.join(report['privacy_check']['findings']), file=sys.stderr)
        return EXIT_PRIVACY
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
