"""Comprehensive run report: model builder, Markdown renderer, privacy self-check, atomic writer.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com. See docs/run-report.md.

The report is generated from artifacts that already exist (evidence, analysis, hash-chained repair
journal, hardware-readiness JSON). It never contains usernames, hostnames, serials, MAC/IP addresses,
file paths or file names, malware signature names, package names, or raw command output. The only free
text is the model analysis, included verbatim and clearly marked as never executed.

The Windows (host/rescue-windows.ps1) and macOS (host/RESCUE-MACOS.command, JXA) generators follow
the same construction rules; tests/test_run_report.py asserts that all three produce equal JSON.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile

REPORT_VERSION = '1.0'
ZERO_HASH = '0' * 64
MODES = ('live-linux', 'linux-host', 'windows-host', 'macos-host')
STATUSES = ('pass', 'fail', 'warn', 'not_applicable', 'unknown')
DOMAINS = ('hardware', 'os', 'software', 'malware', 'environment')
OUTCOMES = ('completed', 'completed-with-failures', 'evidence-only', 'dry-run', 'preflight-failed', 'scan-failed',
            'evidence-invalid', 'no-key', 'network-error', 'analysis-failed', 'analyzer-missing', 'repair-invalid',
            'journal-unusable', 'scan-skipped', 'interrupted', 'report-privacy-refused')
READINESS_IDS = ('cpu', 'ram', 'vga-display', 'internet-connectivity', 'usb-boot-media')
MAX_ANALYSIS_CHARS = 32768
ENVIRONMENT_CHECKS = frozenset('''network-connectivity iso-integrity block-device-discovery filesystem-discovery
lvm-or-raid-discovery firmware-boot-entry kernel-log system-journal'''.split())
HARDWARE_HEALTH = frozenset(['smart-health', 'nvme-health', 'hw-memory-errors', 'hw-disk'])
UNITS = {'percent': '%', 'count': '', 'bytes': ' B', 'days': ' hari', 'seconds': ' s', 'celsius': ' C'}
FINALS = ('verified', 'rolled-back', 'failed', 'skipped', 'declined', 'proposed')
CONTROL = re.compile('[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]')
DOC_RE = re.compile(r'^docs/[A-Za-z0-9._/-]+(#[A-Za-z0-9._-]+)?$')
STAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')

PRIVACY_RULES = (
    ('unix-home-path', re.compile(r'/home/[^/\s]+')),
    ('macos-user-path', re.compile(r'/Users/[^/\s]+')),
    ('windows-user-path', re.compile(r'[A-Za-z]:\\Users\\', re.I)),
    ('mac-address', re.compile(r'(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:-])')),
    ('ipv4-address', re.compile(r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])')),
    ('ipv6-address', re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])')),
)


# ----------------------------------------------------------------------------- helpers

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def clean_text(text):
    """Control characters (except newline and tab) and bidi/zero-width controls removed; CRLF folded to LF."""
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return CONTROL.sub('', text)


def domain_of(check_id):
    if check_id.startswith('hw-') or check_id in ('smart-health', 'nvme-health'):
        return 'hardware'
    if check_id.startswith('sw-'):
        return 'software'
    if check_id.startswith('malware-'):
        return 'malware'
    if check_id in ENVIRONMENT_CHECKS:
        return 'environment'
    return 'os'


def fmt_num(value):
    if isinstance(value, bool):
        return str(value).lower()
    if float(value) == int(value):
        return str(int(value))
    return ('%.3f' % value).rstrip('0').rstrip('.')


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def stamp_of(started_at):
    return started_at.replace('-', '').replace(':', '')


def check_key(check):
    return '%s|%s' % (check['check_id'], check.get('target_ref', ''))


# ----------------------------------------------------------------------------- input sanity

RUN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$')
CHECK_ID_RE = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')
TARGET_RE = re.compile(r'^os-[0-7]$')
ACTION_RE = re.compile(r'^(hw|os-linux|os-windows|os-macos|sw|mw)\.[a-z0-9]+(-[a-z0-9]+)*$')
MODEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$')
SCOPE_VALUES = ('all', 'hardware', 'hardware.cpu', 'hardware.memory', 'hardware.disk', 'hardware.gpu', 'hardware.display',
                'hardware.network', 'hardware.battery', 'hardware.usb', 'os', 'software', 'software.selected', 'malware')
POLICIES = ('detect-only', 'approve-each', 'auto-safe')
TARGET_ENUMS = {
    'family': ('linuxmint', 'linux-other', 'windows', 'macos', 'unknown'),
    'architecture': ('x86_64', 'arm64', 'unknown'), 'detection': ('live-offline', 'host-native'),
    'encryption': ('none', 'bitlocker', 'filevault', 'luks', 'unknown'),
    'access': ('read-only-mounted', 'not-mounted-encrypted', 'not-mounted-unsupported', 'host-running', 'unknown'),
}
ORIGINS = ('catalog-trigger', 'ai-proposal', 'operator')
RISKS = ('safe', 'reversible', 'destructive')
STAGES = ('proposed', 'approval', 'precondition', 'backup', 'target-rw', 'execute', 'verify', 'rollback')
RECORD_OUTCOMES = ('ok', 'fail', 'declined', 'skipped', 'timeout', 'unavailable')
REASONS = ('policy-detect-only', 'not-interactive', 'operator-declined', 'operator-approved', 'cli-approved', 'auto-safe',
           'missing-param', 'invalid-param', 'missing-backup', 'provider-unavailable', 'exit-code', 'timeout',
           'program-not-found', 'verify-failed', 'rolled-back', 'manual-rollback-required', 'not-applicable')


def _is_str(value, pattern):
    return isinstance(value, str) and bool(pattern.match(value))


def _is_num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def sane_evidence(doc):
    """Only the fields the report uses, checked against the evidence contract's patterns and enums."""
    if not isinstance(doc, dict) or not _is_str(doc.get('run_id'), RUN_RE):
        return False
    checks = doc.get('checks')
    if not isinstance(checks, list) or len(checks) > 160:
        return False
    for check in checks:
        if not isinstance(check, dict) or not _is_str(check.get('check_id'), CHECK_ID_RE) or len(check['check_id']) > 64:
            return False
        if check.get('status') not in STATUSES:
            return False
        if 'target_ref' in check and not _is_str(check['target_ref'], TARGET_RE):
            return False
        if 'value' in check:
            value = check['value']
            if not isinstance(value, dict) or value.get('kind') not in UNITS or not _is_num(value.get('number')) \
                    or not 0 <= value['number'] <= 1e15:
                return False
    scope = doc.get('scope')
    if scope is not None and (not isinstance(scope, list) or not scope or len(scope) > 14
                              or any(s not in SCOPE_VALUES for s in scope)):
        return False
    if doc.get('repair_policy') is not None and doc['repair_policy'] not in POLICIES:
        return False
    targets = doc.get('target_systems')
    if targets is not None:
        if not isinstance(targets, list) or len(targets) > 8:
            return False
        for target in targets:
            if not isinstance(target, dict) or not _is_str(target.get('ref'), TARGET_RE):
                return False
            if any(k in target and target[k] not in vals for k, vals in TARGET_ENUMS.items()):
                return False
    provider = doc.get('ai_provider')
    if provider is not None and (not isinstance(provider, dict) or not _is_str(provider.get('model_id'), MODEL_RE)):
        return False
    return True


def record_ok(record):
    """A journal record whose reportable fields are all inside the journal contract."""
    if not _is_str(record.get('action_id'), ACTION_RE) or len(record['action_id']) > 64:
        return False
    if record.get('origin') not in ORIGINS or record.get('risk') not in RISKS or record.get('policy') not in POLICIES:
        return False
    if record.get('stage') not in STAGES or record.get('outcome') not in RECORD_OUTCOMES:
        return False
    if 'reason' in record and record['reason'] not in REASONS:
        return False
    if 'target_ref' in record and not _is_str(record['target_ref'], TARGET_RE):
        return False
    backup = record.get('backup')
    if backup is not None and (not isinstance(backup, dict) or not is_int(backup.get('size_bytes')) or backup['size_bytes'] < 1
                               or not _is_str(backup.get('fingerprint_sha256'), re.compile(r'^[a-f0-9]{64}$'))):
        return False
    return True


# ----------------------------------------------------------------------------- journal

def chain_problems(lines):
    """Hash-chain problems in raw journal *lines* (bytes, no newline, blanks already dropped)."""
    problems, prev, expected = [], ZERO_HASH, 1
    for n, line in enumerate(lines, 1):
        try:
            record = json.loads(line.decode('utf-8'))
        except ValueError:
            problems.append('record %d: not JSON' % n)
            prev = sha256_hex(line)
            expected += 1
            continue
        if not isinstance(record, dict):
            problems.append('record %d: not an object' % n)
            prev = sha256_hex(line)
            expected += 1
            continue
        if record.get('seq') != expected:
            problems.append('record %d: seq' % n)
        if record.get('prev_sha256') != prev:
            problems.append('record %d: prev_sha256' % n)
        prev = sha256_hex(line)
        expected = (record['seq'] if is_int(record.get('seq')) else expected) + 1
    return problems


def journal_records(lines):
    out = []
    for line in lines:
        try:
            record = json.loads(line.decode('utf-8'))
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def redact_param(action_id, name, value, info):
    if is_int(value):
        return value
    kind = (info.get(action_id) or {}).get('params', {}).get(name)
    text = str(value)
    if kind == 'enum' and re.match(r'^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$', text):
        return text
    if kind == 'integer' and re.match(r'^[0-9]{1,15}$', text):
        return int(text)
    if kind == 'detection_ref' and re.match(r'^d-[0-9]{1,4}$', text):
        return '<detection %s>' % text
    if kind == 'package_name':
        return '<package>'
    if kind == 'service_name':
        return '<service>'
    if kind == 'block_device':
        return '<device>'
    return '<value>'


def approval_decision(record):
    if record is None:
        return 'not-reached', None
    outcome, reason = record.get('outcome'), record.get('reason')
    if outcome == 'ok':
        return {'auto-safe': 'auto-safe', 'cli-approved': 'cli'}.get(reason, 'operator-interactive'), reason
    if outcome == 'declined':
        return ('not-interactive' if reason == 'not-interactive' else 'declined'), reason
    if reason == 'policy-detect-only':
        return 'policy-detect-only', reason
    return 'skipped', reason


def final_outcome(by_stage):
    def last(stage):
        return (by_stage.get(stage) or [None])[-1]
    rollback = last('rollback')
    if rollback:
        return 'rolled-back' if rollback.get('outcome') == 'ok' else 'failed'
    execute = last('execute')
    if execute:
        if execute.get('outcome') == 'unavailable':
            return 'skipped'
        verify = last('verify')
        return 'verified' if execute.get('outcome') == 'ok' and verify and verify.get('outcome') == 'ok' else 'failed'
    if any(r.get('outcome') != 'ok' for r in by_stage.get('precondition', [])):
        return 'skipped'
    rw = last('target-rw')
    if rw and rw.get('outcome') == 'fail':
        return 'failed'
    if rw and rw.get('outcome') != 'ok':
        return 'skipped'
    backup = last('backup')
    if backup and backup.get('outcome') != 'ok':
        return 'skipped'
    approval = last('approval')
    if approval:
        if approval.get('outcome') == 'declined':
            return 'declined'
        if approval.get('outcome') == 'skipped':
            return 'proposed' if approval.get('reason') == 'policy-detect-only' else 'skipped'
    return 'skipped'


def build_actions(records, run_id, info):
    groups = []
    for record in records:
        if record.get('run_id') != run_id or not record_ok(record):
            continue
        if record.get('stage') == 'proposed' or not groups:
            groups.append([])
        groups[-1].append(record)
    actions = []
    for group in groups:
        first = group[0]
        by_stage = {}
        for record in group:
            by_stage.setdefault(record.get('stage'), []).append(record)
        approval = (by_stage.get('approval') or [None])[-1]
        decision, reason = approval_decision(approval)
        item = {'action_id': first.get('action_id'), 'origin': first.get('origin'), 'risk': first.get('risk')}
        if first.get('target_ref'):
            item['target_ref'] = first['target_ref']
        item['policy'] = first.get('policy')
        params = {}
        for rec in by_stage.get('approval', []):
            if rec.get('outcome') == 'ok' and isinstance(rec.get('params'), dict):
                for name, value in list(rec['params'].items())[:4]:
                    params[name] = redact_param(item['action_id'], name, value, info)
        item['params'] = params
        approval_doc = {'decision': decision}
        if reason:
            approval_doc['reason'] = reason
        item['approval'] = approval_doc
        backup = (by_stage.get('backup') or [{}])[-1].get('backup')
        item['backup'] = ({'size_bytes': backup['size_bytes'], 'fingerprint': backup['fingerprint_sha256'][:12]}
                          if isinstance(backup, dict) and is_int(backup.get('size_bytes')) else None)
        stages = []
        for record in group:
            if record.get('stage') in ('proposed', 'approval'):
                continue
            entry = {'stage': record.get('stage'), 'outcome': record.get('outcome')}
            if record.get('reason'):
                entry['reason'] = record['reason']
            if is_int(record.get('exit_code')):
                entry['exit_code'] = record['exit_code']
            if isinstance(record.get('duration_seconds'), (int, float)) and not isinstance(record.get('duration_seconds'), bool):
                entry['duration_seconds'] = record['duration_seconds']
            stages.append(entry)
        item['stages'] = stages
        item['final_outcome'] = final_outcome(by_stage)
        manual = any(s['stage'] == 'rollback' and s.get('reason') == 'manual-rollback-required' for s in stages)
        doc = (info.get(item['action_id']) or {}).get('doc') if manual else None
        doc = doc if isinstance(doc, str) and DOC_RE.match(doc) else None
        item['manual_rollback_required'] = manual
        item['manual_rollback_doc'] = doc
        actions.append(item)
    return actions[:500]


# ----------------------------------------------------------------------------- sections

def build_detection(evidence):
    if not isinstance(evidence, dict):
        return {'available': False, 'totals': {s: 0 for s in STATUSES}, 'targets': [],
                'domains': {d: [] for d in DOMAINS}}
    domains = {d: [] for d in DOMAINS}
    totals = {s: 0 for s in STATUSES}
    for check in evidence.get('checks') or []:
        item = {'check_id': check['check_id'], 'status': check['status']}
        if check.get('target_ref'):
            item['target_ref'] = check['target_ref']
        value = check.get('value')
        if isinstance(value, dict):
            item['value'] = {'kind': value['kind'], 'number': value['number']}
        domains[domain_of(item['check_id'])].append(item)
        totals[item['status']] += 1
    targets = []
    for target in evidence.get('target_systems') or []:
        targets.append({k: target[k] for k in ('ref', 'family', 'architecture', 'detection', 'encryption', 'access')
                        if k in target})
    return {'available': True, 'totals': totals, 'targets': targets, 'domains': domains}


def build_comparison(evidence, after, actions):
    executed = sum(1 for a in actions if any(s['stage'] == 'execute' for s in a['stages']))
    if after is None:
        reason = 'no-action-executed' if executed == 0 else 'rescan-missing'
        return {'performed': False, 'reason': reason, 'compared': 0, 'unchanged': 0, 'only_before': 0,
                'only_after': 0, 'changed': []}
    before = {check_key(c): c for c in (evidence or {}).get('checks') or []}
    later = {check_key(c): c for c in after.get('checks') or []}
    changed, unchanged = [], 0
    for key, old in before.items():
        new = later.get(key)
        if new is None:
            continue
        if new['status'] == old['status']:
            unchanged += 1
            continue
        item = {'check_id': old['check_id']}
        if old.get('target_ref'):
            item['target_ref'] = old['target_ref']
        item['before'] = old['status']
        item['after'] = new['status']
        changed.append(item)
    return {'performed': True, 'reason': 'executed' if executed else 'rescan-without-action',
            'compared': len(changed) + unchanged, 'unchanged': unchanged,
            'only_before': sum(1 for k in before if k not in later),
            'only_after': sum(1 for k in later if k not in before), 'changed': changed}


def build_readiness(readiness):
    if not isinstance(readiness, dict):
        return {'performed': False, 'gate': 'not_applicable', 'overall': None, 'checks': []}
    checks = []
    for check in readiness.get('checks') or []:
        if check.get('check_id') in READINESS_IDS and check.get('status') in ('pass', 'fail', 'warn', 'unknown'):
            checks.append({'check_id': check['check_id'], 'status': check['status'], 'required': bool(check.get('required'))})
    overall = (readiness.get('summary') or {}).get('overall')
    if overall not in ('ready', 'ready_with_warnings', 'not_ready'):
        overall = 'not_ready' if any(c['status'] == 'fail' and c['required'] for c in checks) else 'ready'
    return {'performed': True, 'gate': 'failed' if overall == 'not_ready' else 'passed', 'overall': overall,
            'checks': checks}


def build_open_items(detection, actions, comparison, chain):
    items = []
    for action in actions:
        aid = action['action_id']
        final = action['final_outcome']
        ref = {'ref': aid}
        if action.get('target_ref'):
            ref['target_ref'] = action['target_ref']
        if final == 'failed' or final == 'rolled-back':
            items.append(dict(kind='action-failed' if final == 'failed' else 'action-rolled-back', **ref))
        elif final == 'declined':
            items.append(dict(kind='action-declined', **ref))
        elif final == 'skipped':
            items.append(dict(kind='action-skipped', **ref))
        elif final == 'proposed':
            items.append(dict(kind='action-not-run', **ref))
        if action['manual_rollback_required']:
            entry = dict(kind='manual-rollback', **ref)
            if action['manual_rollback_doc']:
                entry['doc'] = action['manual_rollback_doc']
            items.append(entry)
    if chain == 'INVALID':
        items.append({'kind': 'journal-invalid'})
    if any(t.get('access') == 'not-mounted-encrypted' or t.get('encryption') in ('bitlocker', 'filevault', 'luks')
           and t.get('access') not in ('read-only-mounted', 'host-running') for t in detection['targets']):
        items.append({'kind': 'escalate-encrypted-disk'})
    hardware = detection['domains']['hardware']
    if any(c['status'] == 'fail' or (c['status'] == 'warn' and c['check_id'] in HARDWARE_HEALTH) for c in hardware):
        items.append({'kind': 'escalate-hardware-fault'})
    if any(c['check_id'] == 'malware-signatures' and c['status'] in ('warn', 'fail') for c in detection['domains']['malware']):
        items.append({'kind': 'stale-signatures'})
    if any(c['check_id'] == 'malware-scan' and c['status'] in ('warn', 'fail') for c in detection['domains']['malware']):
        items.append({'kind': 'review-malware-detections'})
    if detection['totals']['unknown'] > 0:
        items.append({'kind': 'unknown-checks'})
    for change in comparison['changed']:
        if change['after'] == 'fail' and change['before'] != 'fail':
            entry = {'kind': 'regression-after-repair', 'ref': change['check_id']}
            if change.get('target_ref'):
                entry['target_ref'] = change['target_ref']
            items.append(entry)
    return items


def build_honesty(mode, outcome, key_present, actions, comparison, scope):
    hardware = []
    if mode == 'live-linux':
        hardware.append('physical-boot-and-reboot')
    if mode in ('windows-host', 'macos-host'):
        hardware.append('host-os-native-behavior')
    if any(a['final_outcome'] in ('verified', 'rolled-back', 'failed') and any(s['stage'] == 'execute' for s in a['stages'])
           for a in actions):
        hardware.append('disk-repair-read-back')
    blocked = []
    table = {'no-key': 'provider-key-missing', 'network-error': 'network-unreachable',
             'evidence-only': 'analysis-not-run-offline-mode', 'dry-run': 'analysis-not-run-offline-mode',
             'analysis-failed': 'analysis-failed', 'scan-failed': 'scan-not-completed',
             'evidence-invalid': 'scan-not-completed', 'scan-skipped': 'scan-not-completed',
             'interrupted': 'scan-not-completed', 'preflight-failed': 'hardware-preflight-failed',
             'analyzer-missing': 'analysis-failed'}
    if outcome in table:
        blocked.append(table[outcome])
    if not key_present and 'provider-key-missing' not in blocked and outcome not in ('preflight-failed',):
        blocked.append('provider-key-missing')
    if comparison['reason'] == 'rescan-missing':
        blocked.append('rescan-not-completed')
    limited = list(scope or []) not in (['all'], [])
    return {'hardware_required': hardware, 'environment_blocked': blocked, 'scope_limited': limited}


def build_summary(detection, actions, comparison):
    counts = {name: 0 for name in FINALS}
    for action in actions:
        counts[action['final_outcome']] += 1
    return {'checks': dict(detection['totals']),
            'actions': dict({'total': len(actions)}, **{k.replace('-', '_'): v for k, v in counts.items()}),
            'status_changes': len(comparison['changed'])}


def build_report(inp):
    """Build the report dict from *inp* (see tests/test_run_report.py and scripts/rescue-report.py)."""
    evidence, after = inp.get('evidence'), inp.get('evidence_after')
    evidence_sha = inp.get('evidence_sha256')
    if not sane_evidence(evidence):
        evidence, evidence_sha = None, None
    if not sane_evidence(after):
        after = None
    info = inp.get('action_info') or {}
    lines = inp.get('journal_lines')
    evidence_run = evidence.get('run_id') if isinstance(evidence, dict) else None
    journal_run = evidence_run or inp['run_id']
    if lines is None:
        chain, records, run_records = 'absent', [], []
        problems = []
    else:
        problems = list(inp.get('journal_extra_problems') or []) + chain_problems(lines)
        chain = 'INVALID' if problems else 'valid'
        records = journal_records(lines)
        run_records = [r for r in records if r.get('run_id') == journal_run]
    actions = build_actions(records, journal_run, info)
    detection = build_detection(evidence)
    comparison = build_comparison(evidence, after, actions)
    text = inp.get('analysis_text')
    truncated = False
    if text is not None:
        text = clean_text(text)
        if len(text) > MAX_ANALYSIS_CHARS:
            text, truncated = text[:MAX_ANALYSIS_CHARS], True
    if text is not None and not text.strip():
        text = None
    ai = evidence.get('ai_provider') if isinstance(evidence, dict) else None
    counts = inp.get('ai_counts')
    outcome = inp['outcome']
    if outcome == 'completed' and any(a['final_outcome'] in ('failed', 'rolled-back') for a in actions):
        outcome = 'completed-with-failures'
    scope = (evidence.get('scope') if isinstance(evidence, dict) and evidence.get('scope') else None) or inp.get('scope') or ['all']
    policy = (evidence.get('repair_policy') if isinstance(evidence, dict) else None) or inp.get('repair_policy')
    header = {
        'started_at': inp['started_at'], 'ended_at': inp['ended_at'], 'mode': inp['mode'],
        'toolkit_version': inp.get('version'), 'catalog_sha256': inp.get('catalog_sha256'),
        'scope': list(scope), 'repair_policy': policy, 'provider_key_present': bool(inp.get('key_present')),
        'outcome': outcome, 'evidence_run_id': evidence_run, 'evidence_sha256': evidence_sha,
    }
    report = {
        'report_version': REPORT_VERSION, 'report_type': 'rescue-run-report', 'run_id': inp['run_id'],
        'classification': 'confidential', 'header': header,
        'readiness': build_readiness(inp.get('readiness')),
        'detection': detection,
        'analysis': {
            'status': 'completed' if text else 'not_run',
            'model_id': ai.get('model_id') if isinstance(ai, dict) else None,
            'evidence_sha256': evidence_sha,
            'text': text, 'text_truncated': truncated,
            'proposals': {'accepted': counts[0] if counts else None, 'rejected': counts[1] if counts else None},
        },
        'remediation': {
            'journal': {'chain': chain, 'records_total': len(records), 'records_run': len(run_records)},
            'actions': actions,
        },
        'comparison': comparison,
    }
    report['open_items'] = build_open_items(detection, actions, comparison, chain)
    report['honesty'] = build_honesty(inp['mode'], outcome, bool(inp.get('key_present')), actions, comparison, scope)
    report['summary'] = build_summary(detection, actions, comparison)
    report['privacy_check'] = {'status': 'passed', 'findings': []}
    return report


def minimal_report(inp, findings):
    """The report written instead when the privacy self-check refuses the full one: header + refusal only."""
    stripped = {k: inp[k] for k in ('run_id', 'mode', 'started_at', 'ended_at', 'version', 'key_present', 'scope',
                                     'repair_policy') if k in inp}
    stripped['outcome'] = 'report-privacy-refused'
    report = build_report(stripped)
    report['privacy_check'] = {'status': 'refused', 'findings': sorted(set(findings))}
    return report


# ----------------------------------------------------------------------------- rendering

def _table(header, rows):
    out = ['| ' + ' | '.join(header) + ' |', '|' + '|'.join('---' for _ in header) + '|']
    out += ['| ' + ' | '.join(str(c) for c in row) + ' |' for row in rows]
    return out


def _value(value):
    if not value:
        return ''
    return fmt_num(value['number']) + UNITS.get(value['kind'], '')


def _yes_no(flag):
    return 'ya / yes' if flag else 'tidak / no'


DECISION_TEXT = {
    'operator-interactive': 'operator (interaktif)', 'cli': 'operator (CLI --approve)', 'auto-safe': 'otomatis (auto-safe)',
    'declined': 'ditolak operator', 'not-interactive': 'ditolak (tanpa terminal)', 'policy-detect-only': 'tidak dijalankan (detect-only)',
    'skipped': 'dilewati', 'not-reached': 'tidak sampai persetujuan',
}
OPEN_TEXT = {
    'action-failed': 'Aksi GAGAL; periksa tahap di bagian 5 dan pertimbangkan bantuan teknisi.',
    'action-rolled-back': 'Aksi dibatalkan otomatis (rollback); kondisi awal dipulihkan, masalah belum selesai.',
    'action-declined': 'Aksi ditolak; masalah terkait belum diperbaiki.',
    'action-skipped': 'Aksi dilewati (prasyarat, parameter, atau backup tidak terpenuhi).',
    'action-not-run': 'Aksi hanya diusulkan (kebijakan detect-only); belum dijalankan.',
    'manual-rollback': 'Rollback MANUAL diperlukan; ikuti dokumen yang ditautkan.',
    'journal-invalid': 'Rantai hash journal TIDAK VALID; jangan percaya bagian remediasi sebelum diperiksa.',
    'escalate-encrypted-disk': 'Disk terenkripsi tidak dapat dipindai penuh; buka kunci dengan kunci pemulihan milik pemilik, lalu jalankan ulang.',
    'escalate-hardware-fault': 'Indikasi kerusakan perangkat keras; cadangkan data sekarang dan bawa ke teknisi.',
    'stale-signatures': 'Signature antivirus kedaluwarsa; perbarui signature lalu pindai ulang.',
    'review-malware-detections': 'Ada temuan/pemindaian malware yang perlu ditinjau di daftar deteksi lokal (bukan di laporan ini).',
    'unknown-checks': 'Ada pemeriksaan berstatus unknown (tidak dapat ditentukan, BUKAN sehat); jalankan dengan hak akses yang sesuai.',
    'regression-after-repair': 'Status pemeriksaan memburuk sesudah perbaikan; periksa aksi yang dijalankan.',
}
HONESTY_TEXT = {
    'physical-boot-and-reboot': 'Hardware-required: boot fisik dan reboot dari USB tidak dibuktikan oleh laporan ini.',
    'host-os-native-behavior': 'Hardware-required: perilaku pada Windows/macOS nyata tidak dibuktikan oleh laporan ini.',
    'disk-repair-read-back': 'Hardware-required: hasil perbaikan pada disk fisik harus dikonfirmasi dengan pemeriksaan ulang di mesin nyata.',
    'provider-key-missing': 'Environment-blocked: tidak ada kunci provider, sehingga analisis AI tidak dijalankan.',
    'network-unreachable': 'Environment-blocked: jaringan/HTTP ke provider gagal, analisis AI tidak dijalankan.',
    'analysis-not-run-offline-mode': 'Environment-blocked: mode offline (evidence-only/dry-run), analisis AI tidak dijalankan.',
    'analysis-failed': 'Environment-blocked: analisis AI gagal atau analyzer tidak tersedia.',
    'scan-not-completed': 'Environment-blocked: pemindaian tidak selesai, dilewati, atau evidence tidak valid.',
    'hardware-preflight-failed': 'Environment-blocked: preflight perangkat keras gagal; pemindaian tidak dijalankan.',
    'rescan-not-completed': 'Environment-blocked: pemindaian ulang setelah perbaikan tidak selesai; hasil perbaikan belum dibandingkan.',
}


def render_markdown(report):
    h, det, ai = report['header'], report['detection'], report['analysis']
    rem, cmp_, rd = report['remediation'], report['comparison'], report['readiness']
    out = ['# Laporan Proses Rescue / Rescue Run Report', '',
           '> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.',
           '> RAHASIA / CONFIDENTIAL: berkas ini ada di USB rescue. Tidak memuat nama pengguna, nama komputer, serial, IP/MAC, '
           'path, nama file, nama signature malware, nama paket, atau log mentah. Jangan dibagikan tanpa ditinjau.', '']
    if report['privacy_check']['status'] == 'refused':
        out += ['## LAPORAN DITOLAK OLEH PEMERIKSAAN PRIVASI / REPORT REFUSED BY THE PRIVACY SELF-CHECK', '',
                'Laporan lengkap tidak ditulis karena isinya mengandung pola pengenal (%s). Hanya laporan minimal ini yang disimpan. '
                'Periksa artefak sumber (evidence, analisis, journal) di USB secara manual.' % ', '.join(report['privacy_check']['findings']),
                '']
    out += ['## 1. Header / Ringkasan Proses', '']
    out += _table(['Field', 'Nilai / Value'], [
        ['Run ID', report['run_id']], ['Mulai (UTC) / Started', h['started_at']], ['Selesai (UTC) / Ended', h['ended_at']],
        ['Mode', h['mode']], ['Versi toolkit / Toolkit version', h['toolkit_version'] or 'unknown'],
        ['Catalog SHA-256', h['catalog_sha256'] or 'unavailable'], ['Scope', ', '.join(h['scope'])],
        ['Repair policy', h['repair_policy'] or 'unknown'],
        ['Kunci provider ada / Provider key present (nilai tidak pernah dicatat)', _yes_no(h['provider_key_present'])],
        ['Hasil / Outcome', h['outcome']], ['Evidence SHA-256', h['evidence_sha256'] or 'none']])
    out += ['', '## 2. Preflight perangkat keras / Hardware readiness', '']
    if rd['performed']:
        out.append('Gerbang / Gate: **%s** (overall: %s)' % (rd['gate'].upper(), rd['overall']))
        out.append('')
        out += _table(['Check', 'Status', 'Required'], [[c['check_id'], c['status'], _yes_no(c['required'])] for c in rd['checks']])
        out += ['', 'Diverifikasi: hasil pemeriksaan perangkat lunak saat boot. TIDAK diverifikasi: boot fisik dari firmware, reboot.']
    else:
        out.append('Tidak dijalankan pada mode ini / Not performed in this mode (hanya mode live-linux).')
    out += ['', '## 3. Deteksi / Detection', '']
    if not det['available']:
        out.append('Tidak ada evidence: pemindaian tidak selesai / No evidence: the scan did not complete. Tidak ada yang diverifikasi.')
    else:
        t = det['totals']
        out.append('Legenda / Legend: `unknown` = tidak dapat ditentukan (BUKAN sehat) / could not be determined (NOT healthy). '
                   '`not_applicable` = tidak berlaku. Hanya kode status dan angka terbatas.')
        out.append('')
        out.append('Total: pass=%d fail=%d warn=%d unknown=%d not_applicable=%d' % (t['pass'], t['fail'], t['warn'], t['unknown'], t['not_applicable']))
        for domain in DOMAINS:
            items = det['domains'][domain]
            out += ['', '### %s (%d)' % (domain, len(items)), '']
            if domain == 'os':
                for target in det['targets']:
                    out.append('- %s: family=%s arch=%s detection=%s encryption=%s access=%s' % (
                        target['ref'], target.get('family', '-'), target.get('architecture', '-'), target.get('detection', '-'),
                        target.get('encryption', '-'), target.get('access', '-')))
                if det['targets']:
                    out.append('')
            if not items:
                out.append('Tidak ada pemeriksaan di domain ini pada run ini / No checks in this domain in this run (scope: %s).' % ', '.join(h['scope']))
                continue
            out += _table(['Check', 'Target', 'Status', 'Nilai / Value'],
                          [[c['check_id'], c.get('target_ref', '-'), c['status'], _value(c.get('value'))] for c in items])
    out += ['', '## 4. Analisis AI / AI analysis', '']
    out += _table(['Field', 'Nilai / Value'], [
        ['Status', ai['status']], ['Model', ai['model_id'] or 'none'], ['Evidence SHA-256', ai['evidence_sha256'] or 'none'],
        ['Usulan diterima / accepted', 'unknown' if ai['proposals']['accepted'] is None else ai['proposals']['accepted']],
        ['Usulan ditolak / rejected', 'unknown' if ai['proposals']['rejected'] is None else ai['proposals']['rejected']]])
    out.append('')
    if ai['text'] is None:
        out.append('Tidak ada analisis AI pada run ini / No AI analysis in this run.')
    else:
        out += ['KELUARAN MODEL, hanya untuk dibaca; TIDAK PERNAH dijalankan sebagai perintah. / MODEL OUTPUT, read-only; never executed. '
                'Karakter kontrol dihapus. Kebenarannya tidak diverifikasi.', '']
        if ai['text_truncated']:
            out += ['(dipotong pada %d karakter / truncated at %d characters)' % (MAX_ANALYSIS_CHARS, MAX_ANALYSIS_CHARS), '']
        out += [('> ' + line).rstrip() for line in ai['text'].split('\n')]
    out += ['', '## 5. Remediasi / Remediation', '']
    chain = rem['journal']['chain']
    if chain == 'INVALID':
        out += ['**PERINGATAN: RANTAI HASH JOURNAL INVALID / JOURNAL HASH CHAIN INVALID.** '
                'Isi journal mungkin diubah atau rusak; jangan dipercaya sebelum diperiksa dengan `rescue-repair.py --verify-journal`.', '']
    elif chain == 'valid':
        out += ['Rantai hash journal: valid (%d catatan total, %d untuk run ini). Diverifikasi: urutan dan hash berantai; '
                'bukan bukti bahwa perintah benar-benar mengubah disk.' % (rem['journal']['records_total'], rem['journal']['records_run']), '']
    else:
        out += ['Journal: tidak ada / absent (tidak ada aksi yang dicatat).', '']
    if not rem['actions']:
        out.append('Tidak ada aksi perbaikan pada run ini / No repair actions in this run.')
    for a in rem['actions']:
        out += ['', '### %s%s' % (a['action_id'], '' if not a.get('target_ref') else ' (%s)' % a['target_ref']), '']
        rows = [['Origin', a['origin']], ['Risk', a['risk']], ['Policy', a['policy']],
                ['Persetujuan / Approval', '%s%s' % (DECISION_TEXT[a['approval']['decision']],
                                                     '' if not a['approval'].get('reason') else ' [%s]' % a['approval']['reason'])],
                ['Parameter', ('`' + ', '.join('%s=%s' % (k, v) for k, v in a['params'].items()) + '`') if a['params'] else '-'],
                ['Backup', '-' if a['backup'] is None else '%d B, fingerprint %s' % (a['backup']['size_bytes'], a['backup']['fingerprint'])],
                ['Hasil akhir / Final outcome', '**%s**' % a['final_outcome']]]
        out += _table(['Field', 'Nilai / Value'], rows)
        if a['stages']:
            out.append('')
            out += _table(['Tahap / Stage', 'Outcome', 'Alasan / Reason', 'Exit'],
                          [[s['stage'], s['outcome'], s.get('reason', '-'), s.get('exit_code', '-')] for s in a['stages']])
        if a['manual_rollback_required']:
            out += ['', 'Rollback MANUAL diperlukan / manual rollback required: %s' % (
                '[%s](../../%s)' % (a['manual_rollback_doc'], a['manual_rollback_doc']) if a['manual_rollback_doc'] else 'lihat katalog')]
    out += ['', '## 6. Sebelum/sesudah / Before-after', '']
    if not cmp_['performed']:
        if cmp_['reason'] == 'no-action-executed':
            out.append('Tidak ada aksi yang dijalankan, jadi tidak ada pemindaian ulang / No action ran, so no re-scan was made.')
        else:
            out.append('Aksi dijalankan tetapi pemindaian ulang tidak tersedia / An action ran but the re-scan is missing: hasil belum dibandingkan.')
    else:
        out.append('Pemindaian ulang dengan scope yang sama / Re-scan with the same scope. Dibandingkan: %d, tidak berubah: %d, berubah: %d, '
                   'hanya sebelum: %d, hanya sesudah: %d.' % (cmp_['compared'], cmp_['unchanged'], len(cmp_['changed']),
                                                            cmp_['only_before'], cmp_['only_after']))
        if cmp_['changed']:
            out.append('')
            out += _table(['Check', 'Target', 'Sebelum / Before', 'Sesudah / After'],
                          [[c['check_id'], c.get('target_ref', '-'), c['before'], c['after']] for c in cmp_['changed']])
        out += ['', 'Pemindaian ulang hanya membuktikan status pada saat itu; bukan bukti kesehatan.']
    out += ['', '## 7. Butir terbuka / Open items', '']
    if not report['open_items']:
        out.append('Tidak ada butir terbuka yang terdeteksi / No open items detected (bukan jaminan sistem sehat).')
    for item in report['open_items']:
        label = item['kind'] + ('' if 'ref' not in item else ' ' + item['ref'] + ('' if 'target_ref' not in item else ' (' + item['target_ref'] + ')'))
        doc = '' if 'doc' not in item else ' Dokumen: [%s](../../%s).' % (item['doc'], item['doc'])
        out.append('- **%s**: %s%s' % (label, OPEN_TEXT[item['kind']], doc))
    out += ['', '## 8. Kejujuran / Honesty', '']
    hon = report['honesty']
    for key in hon['hardware_required'] + hon['environment_blocked']:
        out.append('- ' + HONESTY_TEXT[key])
    if hon['scope_limited']:
        out.append('- Scope dibatasi (%s): area di luar scope tidak dipindai dan tidak boleh dianggap sehat.' % ', '.join(h['scope']))
    out += ['- Hasil bersih BUKAN bukti kesehatan: pemeriksaan hanya mencakup yang tercantum di bagian 3, `unknown` berarti tidak diketahui, '
            'dan kerusakan yang tidak diperiksa tidak terlihat. / A clean result is not proof of health.',
            '- Laporan ini dibuat dari artefak yang ada (evidence, analisis, journal); ia tidak menjalankan pemeriksaan sendiri.']
    return '\n'.join(out) + '\n'


def summary_line(report):
    s = report['summary']
    return {'checks': '%d/%d/%d' % (s['checks']['fail'], s['checks']['warn'], s['checks']['unknown']),
            'actions': '%d/%d/%d' % (s['actions']['verified'], s['actions']['failed'] + s['actions']['rolled_back'],
                                     s['actions']['declined'] + s['actions']['skipped'] + s['actions']['proposed'])}


def render_index(entries):
    """entries: list of (dir_name, report dict); newest first."""
    out = ['# Indeks laporan rescue / Rescue report index', '',
           '> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.',
           '> Satu baris per run, terbaru dulu. Kolom checks = fail/warn/unknown; actions = verified/failed/tidak-dijalankan.', '']
    rows = []
    for name, report in entries:
        line = summary_line(report)
        rows.append([report['header']['started_at'], report['header']['mode'], report['header']['outcome'], line['checks'],
                     line['actions'], '[%s/report.md](%s/report.md)' % (name, name)])
    if not rows:
        out.append('Belum ada run / No runs yet.')
    else:
        out += _table(['Mulai (UTC) / Started', 'Mode', 'Hasil / Outcome', 'Checks F/W/U', 'Actions V/F/O', 'Laporan / Report'], rows)
    return '\n'.join(out) + '\n'


def sort_entries(entries):
    return sorted(entries, key=lambda e: (e[1]['header']['started_at'], e[0]), reverse=True)


# ----------------------------------------------------------------------------- privacy + writing

def privacy_findings(text, secrets=()):
    found = [name for name, rule in PRIVACY_RULES if rule.search(text)]
    if any(len(s) >= 8 and s in text for s in secrets):
        found.append('configured-key-value')
    return found


def write_private(path, text):
    """Atomic private write: temp file in the same directory (0600 from creation), then replace."""
    directory = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.report-', suffix='.tmp', dir=directory)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass  # exFAT does not implement modes
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def render_checked(inp, secrets=()):
    """(report, json_text, markdown). Refuses the full report (minimal one instead) on a privacy finding."""
    report = build_report(inp)
    json_text = json.dumps(report, indent=2, sort_keys=False) + '\n'
    markdown = render_markdown(report)
    findings = privacy_findings(json_text + markdown, secrets)
    if findings:
        report = minimal_report(inp, findings)
        json_text = json.dumps(report, indent=2) + '\n'
        markdown = render_markdown(report)
    return report, json_text, markdown


def unique_dir_name(reports_dir, started_at):
    base = 'run-' + stamp_of(started_at)
    name, n = base, 1
    while os.path.exists(os.path.join(reports_dir, name)):
        n += 1
        name = '%s-%d' % (base, n)
    return name


def load_entries(reports_dir):
    entries = []
    try:
        names = sorted(os.listdir(reports_dir))
    except OSError:
        return entries
    for name in names:
        if not re.match(r'^run-\d{8}T\d{6}Z(-\d+)?$', name):
            continue
        try:
            with open(os.path.join(reports_dir, name, 'report.json'), encoding='utf-8') as handle:
                doc = json.load(handle)
            if doc.get('report_type') == 'rescue-run-report' and STAMP_RE.match(doc['header']['started_at']):
                summary_line(doc)
                doc['header']['outcome']
                entries.append((name, doc))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sort_entries(entries)


def write_run(reports_dir, inp, secrets=()):
    """Write <reports>/run-<stamp>/report.{json,md} and index.md. Returns (dir_name, report)."""
    os.makedirs(reports_dir, mode=0o700, exist_ok=True)
    report, json_text, markdown = render_checked(inp, secrets)
    name = unique_dir_name(reports_dir, inp['started_at'])
    run_dir = os.path.join(reports_dir, name)
    os.makedirs(run_dir, mode=0o700)
    write_private(os.path.join(run_dir, 'report.json'), json_text)
    write_private(os.path.join(run_dir, 'report.md'), markdown)
    write_private(os.path.join(reports_dir, 'index.md'), render_index(load_entries(reports_dir)))
    return name, report
