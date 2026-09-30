#!/usr/bin/env python3
"""Pure helpers to turn a local candidate SKILL.md into a sanitized, hashable submission.

No network, no file I/O, no environment access: every function takes and returns data.
Used by scripts/submit-skill.py; unit-tested offline.

Pipeline: parse_skill -> sanitize_text (replace sensitive tokens with placeholders)
-> scan_secrets (refuse when anything secret-like is still there) -> canonical_skill
-> sha256_hex. The hash covers the canonical sanitized skill (front matter rebuilt from
the validated name and description, then the normalized body).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import hashlib
import math
import re
import unicodedata

MAX_BODY_BYTES = 32 * 1024
MAX_RAW_BYTES = 64 * 1024
MAX_DESCRIPTION_CHARS = 400
NAME_RE = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
MARKER_PREFIX = '<!-- skill-sha256: '
MARKER_SUFFIX = ' -->'


class SkillError(ValueError):
    """The skill file cannot be used (malformed, too large, or fails validation)."""


# ------------------------------------------------------------------ normalization

def strip_unsafe_chars(text):
    """Drop control and format characters (incl. bidi overrides); keep newline and tab."""
    return ''.join(ch for ch in text
                   if ch in '\n\t' or unicodedata.category(ch) not in ('Cc', 'Cf'))


def normalize_text(text):
    """NFC, LF endings, no control chars, no trailing spaces, at most one blank line in a row."""
    text = unicodedata.normalize('NFC', text.replace('\r\n', '\n').replace('\r', '\n'))
    text = strip_unsafe_chars(text).replace('\t', '    ')
    lines = [line.rstrip() for line in text.split('\n')]
    out, blank = [], 0
    for line in lines:
        blank = blank + 1 if not line else 0
        if blank <= 1:
            out.append(line)
    return '\n'.join(out).strip('\n') + '\n'


# ------------------------------------------------------------------- parsing

def parse_skill(raw):
    """Return (name, description, body) from SKILL.md text. Only name/description are allowed."""
    if len(raw.encode('utf-8')) > MAX_RAW_BYTES:
        raise SkillError('skill file is larger than %d bytes' % MAX_RAW_BYTES)
    text = raw.replace('\r\n', '\n').replace('\r', '\n')
    if text.startswith('﻿'):
        text = text[1:]
    text = '\n'.join('---' if line.rstrip() == '---' else line for line in text.split('\n'))
    if not text.startswith('---\n'):
        raise SkillError('missing front matter (file must start with ---)')
    end = text.find('\n---\n', 3)
    if end < 0:
        raise SkillError('unterminated front matter')
    header, body = text[4:end], text[end + 5:]
    fields = {}
    for line in header.split('\n'):
        if not line.strip():
            continue
        match = re.match(r'^([A-Za-z_-]+):[ \t]*(.*)$', line)
        if not match:
            raise SkillError('front matter line is not "key: value"')
        key, value = match.group(1), match.group(2).strip()
        if key not in ('name', 'description'):
            raise SkillError('front matter key not allowed: %s (only name and description)' % key[:32])
        if key in fields:
            raise SkillError('duplicate front matter key: %s' % key)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        fields[key] = value
    name, description = fields.get('name', ''), fields.get('description', '')
    if not (3 <= len(name) <= 64) or not NAME_RE.match(name):
        raise SkillError('name must match ^[a-z0-9]+(-[a-z0-9]+)*$ and be 3-64 characters')
    description = normalize_text(description).strip()
    if not description or len(description) > MAX_DESCRIPTION_CHARS or '\n' in description:
        raise SkillError('description must be one line of 1-%d characters' % MAX_DESCRIPTION_CHARS)
    if len(body.encode('utf-8')) > MAX_BODY_BYTES:
        raise SkillError('skill body is larger than %d bytes' % MAX_BODY_BYTES)
    if len(body.strip()) < 20:
        raise SkillError('skill body is empty or too short')
    return name, description, body


# ---------------------------------------------------------------- sanitizing

_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+')
_URL_CRED = re.compile(r'(://)[^/\s:@]+(?::[^/\s@]*)?@')
_USER_AT_HOST = re.compile(r'(?<![\w@.-])[A-Za-z_][\w.-]{0,31}@[A-Za-z0-9][A-Za-z0-9-]{0,62}\b')
_MAC = re.compile(r'(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])')
_IPV6 = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])')
_IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_UUID = re.compile(r'\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b')
_FAT_ID = re.compile(r'\b[0-9A-F]{4}-[0-9A-F]{4}\b')
_BY_ID = re.compile(r'/dev/disk/by-(uuid|partuuid|label|id|path|partlabel)/\S+')
_PATH_UNIX = re.compile(r'''(?<![\w.-])/(?:home|Users|root|media|run/media)/[^\s'"`<>)\]},;]*''')
_PATH_WIN = re.compile(r'''(?i)\b[A-Z]:[\\/]+Users[\\/][^\s'"`<>)\]},;]*''')
_TILDE_USER = re.compile(r'(?<![\w/])~[a-z_][a-z0-9_-]*(?=/|\s|$)')
_DEV_ATTR = re.compile(r'(?i)\b((?:ID_)?(?:serial(?:[ _-]?(?:number|short))?|s/n|wwn)|volume[ _-]?serial(?:[ _-]?number)?)'
                       r'\s*[:=]\s*[^\s,;]+')
_HOST_ATTR = re.compile(r'(?i)\b(hostname|host[ _-]?name|computer[ _-]?name|nodename|machine[ _-]?name)'
                        r'\s*[:=]\s*[^\s,;]+')
_USER_ATTR = re.compile(r'(?i)\b(username|user[ _-]?name|logname|login[ _-]?name|account[ _-]?name)'
                        r'\s*[:=]\s*[^\s,;]+')
_FS_ATTR = re.compile(r'\b(UUID|PARTUUID|PTUUID)\s*=\s*"?[^\s",;]+"?', re.I)
_LABEL_ATTR = re.compile(r'\b(LABEL|PARTLABEL)\s*=\s*"?[^\s",;]+"?', re.I)
_INTERNAL_FQDN = re.compile(r'(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:local|lan|home|internal|corp|intranet|localdomain)\b')
_HTML_COMMENT = re.compile(r'<!--|-->')


def _is_sensitive_ipv4(text):
    parts = text.split('.')
    if any(len(p) > 1 and p.startswith('0') for p in parts) or any(int(p) > 255 for p in parts):
        return False  # not an address (version string, leading zeros)
    return text not in ('127.0.0.1', '0.0.0.0')


def sanitize_text(text):
    """Replace identifying or environment-specific tokens. Returns (text, {placeholder: count})."""
    counts = {}

    def bump(name):
        counts[name] = counts.get(name, 0) + 1

    def rule(pattern, repl, name):
        nonlocal text

        def fn(match):
            out = match.expand(repl) if isinstance(repl, str) else repl(match)
            if out != match.group(0):
                bump(name)
            return out
        text = pattern.sub(fn, text)

    text = strip_unsafe_chars(text)
    rule(_HTML_COMMENT, lambda m: '&lt;!--' if m.group(0) == '<!--' else '--&gt;', 'HTML-COMMENT')
    rule(_URL_CRED, r'\1<CREDENTIALS>@', 'CREDENTIALS')
    rule(_EMAIL, '<EMAIL>', 'EMAIL')
    rule(_BY_ID, r'/dev/disk/by-\1/<ID>', 'DISK-ID')
    rule(_PATH_UNIX, '<PATH>', 'PATH')
    rule(_PATH_WIN, '<PATH>', 'PATH')
    rule(_TILDE_USER, '<PATH>', 'PATH')
    rule(_MAC, '<MAC>', 'MAC')
    rule(_UUID, '<UUID>', 'UUID')
    rule(_FS_ATTR, r'\1=<UUID>', 'UUID')
    rule(_LABEL_ATTR, r'\1=<LABEL>', 'LABEL')
    rule(_FAT_ID, '<UUID>', 'UUID')
    rule(_DEV_ATTR, r'\1: <SERIAL>', 'SERIAL')
    rule(_HOST_ATTR, r'\1: <HOSTNAME>', 'HOSTNAME')
    rule(_USER_ATTR, r'\1: <USERNAME>', 'USERNAME')
    rule(_IPV6, '<IP>', 'IP')
    rule(_IPV4, lambda m: '<IP>' if _is_sensitive_ipv4(m.group(0)) else m.group(0), 'IP')
    rule(_USER_AT_HOST, '<USERNAME>@<HOSTNAME>', 'HOSTNAME')
    rule(_INTERNAL_FQDN, '<HOSTNAME>', 'HOSTNAME')
    return text, counts


# ------------------------------------------------------------------- secret scan

_SECRET_PATTERNS = (
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}')),
    ('github-fine-grained-token', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}')),
    ('sk-style-api-key', re.compile(r'(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}')),
    ('aws-access-key-id', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('private-key-block', re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY')),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}')),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ('google-api-key', re.compile(r'\bAIza[0-9A-Za-z_-]{30,}')),
    ('bearer-credential', re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}')),
    ('url-credentials', re.compile(r'://[^/\s:@<]+:[^/\s@<]+@')),
    ('secret-assignment', re.compile(
        r'''(?i)\b(?:api[_-]?key|token|secret|passw(?:or)?d|passphrase|private[_-]?key)\b["']?\s*[:=]\s*["']?'''
        r'''(?=[^\s"'<>$]{12,})(?=[^\s"'<>$]*\d)[^\s"'<>$]+''')),
)
_TOKENISH = re.compile(r'[A-Za-z0-9+/_=-]{32,}')


def shannon_entropy(text):
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in
                (text.count(ch) for ch in set(text)))


def scan_secrets(text, secret_values=(), entropy=True):
    """Return a list of finding labels (never the matched text). Empty list means clean."""
    findings = []
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    for value in secret_values:
        if value and len(value) >= 8 and value in text:
            findings.append('configured-secret-value')
            break
    if entropy:
        for token in _TOKENISH.findall(text):
            if (re.search(r'\d', token) and re.search(r'[A-Za-z]', token)
                    and not re.fullmatch(r'[0-9A-Fa-f]+', token)
                    and shannon_entropy(token) >= 4.0):
                findings.append('high-entropy-string')
                break
    return findings


# ---------------------------------------------------------------- canonical form

def canonical_skill(name, description, body):
    """Canonical sanitized skill text that is hashed, previewed and submitted."""
    return '---\nname: %s\ndescription: %s\n---\n\n%s' % (name, description, normalize_text(body))


def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def marker(sha):
    return MARKER_PREFIX + sha + MARKER_SUFFIX


def has_marker(text, sha):
    """Exact marker match (line-anchored) so quoted or partial hashes do not count."""
    if not isinstance(text, str):
        return False
    return re.search(r'(?m)^' + re.escape(marker(sha)) + r'\s*$', text.replace('\r\n', '\n')) is not None


def prepare(raw, secret_values=()):
    """Full pipeline. Returns dict(name, description, canonical, sha256, replacements).

    Raises SkillError for malformed input and SecretFound (a SkillError) if the scan
    still finds something after sanitizing; the caller must refuse, not "fix and send".
    """
    name, description, body = parse_skill(raw)
    # Raw-side check for known secrets and prefix patterns: refuse before any rewriting.
    raw_findings = scan_secrets(raw, secret_values, entropy=False)
    if raw_findings:
        raise SecretFound(raw_findings)
    body_s, c1 = sanitize_text(body)
    desc_s, c2 = sanitize_text(description)
    name_s, c3 = sanitize_text(name)
    if name_s != name:
        raise SecretFound(['identifying-name'])
    counts = dict(c1)
    for k, v in list(c2.items()) + list(c3.items()):
        counts[k] = counts.get(k, 0) + v
    desc_s = normalize_text(desc_s).strip()
    canonical = canonical_skill(name, desc_s, body_s)
    if len(normalize_text(body_s).encode('utf-8')) > MAX_BODY_BYTES:
        raise SkillError('sanitized skill body is larger than %d bytes' % MAX_BODY_BYTES)
    findings = scan_secrets(canonical, secret_values)
    if findings:
        raise SecretFound(findings)
    return {'name': name, 'description': desc_s, 'canonical': canonical,
            'sha256': sha256_hex(canonical), 'replacements': counts}


class SecretFound(SkillError):
    def __init__(self, findings):
        super().__init__('secret scan refused the skill: ' + ', '.join(sorted(set(findings))))
        self.findings = sorted(set(findings))
