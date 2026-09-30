#!/usr/bin/env python3
"""Documentation checker (standard library only). Part of `make check` (target: docs).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Checks README.md, AGENTS.md, CHANGELOG.md, docs/*.md and profiles/**/*.md:

  links        relative links point to existing files and `#anchors` exist (GitHub heading slugs,
               explicit <a id="..."> anchors; Bahasa Indonesia headings are plain Unicode text)
  mermaid      every ```mermaid block starts with a known diagram type and has balanced quotes per
               line (and balanced brackets per line for flowchart/graph/state/class/ER diagrams)
  attribution  README.md, CHANGELOG.md and every docs/*.md carries the management attribution line
  secrets      no fenced block contains an obvious secret pattern
  doc refs     backticked `docs/NAME.md` and `docs/NAME.md#anchor` references, and the `doc` field
               of every action in rescue-ai/v1/catalog/*.json, resolve

Usage: python3 scripts/check-docs.py [--root DIR]
Exit codes: 0 no problems | 1 problems found (printed as FILE:LINE: message) | 2 usage error
"""
import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ATTRIBUTION = '> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.'

MERMAID_TYPES = re.compile(
    r'^(?:flowchart|graph)(?:\s+(?:TB|TD|BT|RL|LR))?\b'
    r'|^(?:sequenceDiagram|classDiagram|erDiagram|journey|gantt|pie)\b'
    r'|^stateDiagram(?:-v2)?\b')
BRACKET_TYPES = re.compile(r'^(?:flowchart|graph|stateDiagram|classDiagram|erDiagram)')
PAIRS = {')': '(', ']': '[', '}': '{'}

# Prefixes are built by concatenation so that this file does not trip secret scanning itself.
SECRET_PATTERNS = [
    ('GitHub token', re.compile('gh' + r'[pousr]_[A-Za-z0-9]{30,}')),
    ('GitHub fine-grained token', re.compile('github' + r'_pat_[A-Za-z0-9_]{20,}')),
    ('API key (sk- style)', re.compile(r'\bsk' + r'-[A-Za-z0-9_-]{20,}')),
    ('AWS access key id', re.compile(r'\bAK' + r'IA[0-9A-Z]{16}\b')),
    ('private key block', re.compile('-----BEGIN [A-Z ]*PRIV' + 'ATE KEY-----')),
    ('JWT', re.compile(r'\bey' + r'J[A-Za-z0-9_-]{8,}\.ey' + r'J[A-Za-z0-9_-]{8,}\.')),
]
ASSIGNMENT = re.compile(
    r'(?i)\b[A-Z0-9_]*(?:API_?KEY|TOKEN|PASSWORD|PASSWD|SECRET)[A-Z0-9_]*\s*[=:]\s*[\'"]?([A-Za-z0-9+/_=.-]{24,})')
PLACEHOLDER_WORDS = ('operator', 'example', 'dummy', 'placeholder', 'secret', 'xxx', 'your', 'hex', 'redacted',
                     'changeme', 'token-value', 'from-')

FENCE = re.compile(r'^\s*(`{3,}|~{3,})\s*([^`\s]*)')
HEADING = re.compile(r'^ {0,3}(#{1,6})\s+(.*?)\s*$')
HTML_ANCHOR = re.compile(r'<a\s+[^>]*?\b(?:id|name)\s*=\s*["\']([^"\']+)["\']', re.I)
INLINE_LINK = re.compile(r'!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)')
REF_DEF = re.compile(r'^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$')
CODE_SPAN = re.compile(r'(`+)(.+?)\1')
DOC_REF = re.compile(r'`(docs/[A-Za-z0-9_.-]+\.md)(?:#([A-Za-z0-9_-]+))?`')
SCHEME = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*:')


def slugify(text):
    """GitHub-style heading slug: lowercase, letters/digits/marks/underscore/hyphen kept, spaces to hyphens."""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'!?\[([^\]]*)\]\([^)]*\)', r'\1', text)
    out = []
    for ch in text.strip().lower():
        if ch in '_-' or unicodedata.category(ch)[0] in 'LNM':
            out.append(ch)
        elif ch.isspace():
            out.append('-')
    return ''.join(out)


def split_fences(lines):
    """Yield (lineno, line, fence_info): fence_info is None outside fences, else the info string ('' if none).
    Fence delimiter lines themselves are reported with fence_info 'DELIM'."""
    fence = None  # (char, length, info)
    for number, line in enumerate(lines, 1):
        match = FENCE.match(line)
        if fence is None:
            if match:
                fence = (match.group(1)[0], len(match.group(1)), match.group(2))
                yield number, line, 'DELIM'
                continue
            yield number, line, None
        else:
            stripped = line.strip()
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1] and stripped == match.group(1):
                fence = None
                yield number, line, 'DELIM'
                continue
            yield number, line, fence[2]


def anchors_of(text):
    """Set of valid anchors of a Markdown document (lowercase)."""
    anchors = set()
    seen = {}
    lines = text.splitlines()
    for _, line, info in split_fences(lines):
        if info is not None:
            continue
        for name in HTML_ANCHOR.findall(line):
            anchors.add(name.lower())
        match = HEADING.match(line)
        if match:
            title = re.sub(r'\s+#+\s*$', '', match.group(2))
            slug = slugify(title)
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            anchors.add(slug if count == 0 else '%s-%d' % (slug, count))
    return anchors


class Checker:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.errors = []
        self._anchor_cache = {}

    def error(self, path, line, message):
        try:
            shown = Path(path).resolve().relative_to(self.root)
        except ValueError:
            shown = path
        self.errors.append('%s:%s: %s' % (shown, line, message))

    def anchors(self, path):
        path = Path(path).resolve()
        if path not in self._anchor_cache:
            try:
                self._anchor_cache[path] = anchors_of(path.read_text(encoding='utf-8'))
            except OSError:
                self._anchor_cache[path] = set()
        return self._anchor_cache[path]

    def files(self):
        found = []
        for name in ('README.md', 'AGENTS.md', 'CHANGELOG.md'):
            if (self.root / name).is_file():
                found.append(self.root / name)
        found += sorted((self.root / 'docs').glob('*.md'))
        found += sorted((self.root / 'profiles').rglob('*.md'))
        return found

    # -- individual rules ------------------------------------------------------------------------
    def check_links(self, path, lines):
        for number, line, info in split_fences(lines):
            if info is not None:
                continue
            plain = CODE_SPAN.sub(' ', line)
            targets = INLINE_LINK.findall(plain)
            ref = REF_DEF.match(plain)
            if ref:
                targets.append(ref.group(1))
            for target in targets:
                if SCHEME.match(target) or target.startswith('//'):
                    continue
                self.check_target(path, number, target)

    def check_target(self, path, number, target):
        raw_path, _, anchor = target.partition('#')
        raw_path = unquote(raw_path)
        anchor = unquote(anchor)
        if raw_path == '':
            dest = Path(path)
        else:
            dest = (Path(path).parent / raw_path)
            if not dest.exists():
                self.error(path, number, 'broken link: %s does not exist' % target)
                return
        if anchor and dest.is_file() and dest.suffix.lower() == '.md':
            if anchor.lower() not in self.anchors(dest):
                self.error(path, number, 'broken anchor: %s has no heading or id "%s"' % (
                    dest.name if raw_path else 'this file', anchor))

    def check_mermaid(self, path, lines):
        block = None
        for number, line, info in split_fences(lines):
            if info == 'DELIM':
                if block is None and FENCE.match(line) and FENCE.match(line).group(2) == 'mermaid':
                    block = {'start': number, 'kind': None}
                else:
                    block = None
                continue
            if block is None or info != 'mermaid':
                continue
            text = line.strip()
            if not text or text.startswith('%%'):
                continue
            if block['kind'] is None:
                if not MERMAID_TYPES.match(text):
                    self.error(path, number, 'mermaid block does not start with a known diagram type: %r' % text[:40])
                    block['kind'] = 'unknown'
                else:
                    block['kind'] = text
                continue
            self.check_mermaid_line(path, number, text, block['kind'])

    def check_mermaid_line(self, path, number, text, kind):
        if text.count('"') % 2:
            self.error(path, number, 'mermaid: unbalanced double quotes: %s' % text[:60])
            return
        if not BRACKET_TYPES.match(kind):
            return
        unquoted = re.sub(r'"[^"]*"', '""', text)
        stack = []
        for ch in unquoted:
            if ch in '([{':
                stack.append(ch)
            elif ch in PAIRS:
                if not stack or stack.pop() != PAIRS[ch]:
                    self.error(path, number, 'mermaid: unbalanced brackets: %s' % text[:60])
                    return
        if stack:
            self.error(path, number, 'mermaid: unbalanced brackets: %s' % text[:60])

    def check_attribution(self, path, lines):
        rel = Path(path).resolve().relative_to(self.root)
        if rel.parts[0] != 'docs' and rel.name not in ('README.md', 'CHANGELOG.md'):
            return
        if not any(line.rstrip() == ATTRIBUTION for line in lines):
            self.error(path, 1, 'missing attribution line: %s' % ATTRIBUTION)

    def check_secrets(self, path, lines):
        for number, line, info in split_fences(lines):
            if info is None or info == 'DELIM':
                continue
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    self.error(path, number, 'possible secret in a fenced block (%s)' % label)
            match = ASSIGNMENT.search(line)
            if match:
                value = match.group(1)
                lowered = value.lower()
                if (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)
                        and not any(word in lowered for word in PLACEHOLDER_WORDS)):
                    self.error(path, number, 'possible secret assignment in a fenced block')

    def check_doc_refs(self, path, lines):
        for number, line in enumerate(lines, 1):
            for name, anchor in DOC_REF.findall(line):
                self.check_doc_ref(path, number, name, anchor)

    def check_doc_ref(self, path, number, name, anchor):
        target = self.root / name
        if not target.is_file():
            self.error(path, number, 'doc reference to a missing file: %s' % name)
        elif anchor and anchor.lower() not in self.anchors(target):
            self.error(path, number, 'doc reference to a missing anchor: %s#%s' % (name, anchor))

    def check_catalogs(self):
        for catalog in sorted((self.root / 'rescue-ai' / 'v1' / 'catalog').glob('*.json')):
            try:
                data = json.loads(catalog.read_text(encoding='utf-8'))
            except (OSError, ValueError) as exc:
                self.error(catalog, 1, 'cannot read catalog: %s' % exc)
                continue
            actions = data.get('actions', []) if isinstance(data, dict) else data
            for action in actions:
                ref = action.get('doc') if isinstance(action, dict) else None
                if not ref:
                    continue
                name, _, anchor = ref.partition('#')
                if not re.match(r'^docs/[A-Za-z0-9_.-]+\.md$', name):
                    self.error(catalog, 1, '%s: doc field is not docs/NAME.md[#anchor]: %s' % (action.get('action_id'), ref))
                    continue
                self._catalog_ref(catalog, action, name, anchor)

    def _catalog_ref(self, catalog, action, name, anchor):
        target = self.root / name
        if not target.is_file():
            self.error(catalog, 1, '%s: doc file missing: %s' % (action.get('action_id'), name))
        elif anchor and anchor.lower() not in self.anchors(target):
            self.error(catalog, 1, '%s: doc anchor missing: %s#%s' % (action.get('action_id'), name, anchor))

    # -- driver ----------------------------------------------------------------------------------
    def run(self):
        for path in self.files():
            try:
                lines = path.read_text(encoding='utf-8').splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                self.error(path, 1, 'cannot read: %s' % exc)
                continue
            self.check_links(path, lines)
            self.check_mermaid(path, lines)
            self.check_attribution(path, lines)
            self.check_secrets(path, lines)
            self.check_doc_refs(path, lines)
        self.check_catalogs()
        return self.errors


def main(argv=None):
    parser = argparse.ArgumentParser(description='Check repository documentation (links, anchors, Mermaid, attribution, secrets).')
    parser.add_argument('--root', default=str(Path(__file__).resolve().parent.parent), help='repository root (default: this checkout)')
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print('not a directory: %s' % root, file=sys.stderr)
        return 2
    checker = Checker(root)
    errors = checker.run()
    for message in errors:
        print(message)
    files = len(checker.files())
    if errors:
        print('docs check FAILED: %d problem(s) in %d file(s) checked' % (len(errors), files), file=sys.stderr)
        return 1
    print('docs check: ok (%d files: links, anchors, mermaid, attribution, secrets, doc references)' % files)
    return 0


if __name__ == '__main__':
    sys.exit(main())
