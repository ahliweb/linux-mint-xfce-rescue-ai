"""Tests for scripts/check-docs.py: good and bad fixture Markdown in a temp directory.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'check-docs.py'

spec = importlib.util.spec_from_file_location('check_docs', SCRIPT)
check_docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_docs)

ATTR = check_docs.ATTRIBUTION

GOOD_DOC = ATTR + '''

# Judul dokumen

Lihat [bagian dua](#bagian-dua-bahasa) dan [lainnya](other.md#anchor-eksplisit) atau [README](../README.md#tujuan).
Tautan luar [contoh](https://example.com/x#y) dan `[bukan](tautan.md)` di dalam kode diabaikan.

## Bagian dua (Bahasa)

<a id="anchor-eksplisit"></a>

```mermaid
flowchart LR
    A[Mulai] --> B{Pilih?}
    B -- ya --> C["Teks (dengan) kurung ["]
    B -- tidak --> D((Selesai))
```

```mermaid
sequenceDiagram
    participant A as Operator
    A->>A: catatan (tidak seimbang boleh di sini
```

Rujukan `docs/other.md#anchor-eksplisit` dan `docs/other.md`.

```bash
OPENCODE_GO_API_KEY='operator-provided-secret'
export TOKEN=<isi-token-anda>
```
'''

OTHER_DOC = ATTR + '''

# Other

<a id="anchor-eksplisit"></a>
### Ada Duplikat
### Ada Duplikat
'''

README = ATTR + '''

# Tujuan

Lihat [docs](docs/good.md#bagian-dua-bahasa) dan [duplikat kedua](docs/other.md#ada-duplikat-1).
'''

CATALOG = {'actions': [{'action_id': 'hw.x', 'doc': 'docs/other.md#anchor-eksplisit'}]}


def make_tree(root, docs=None, readme=README, catalog=CATALOG, extra=None):
    root = Path(root)
    (root / 'docs').mkdir(parents=True, exist_ok=True)
    (root / 'README.md').write_text(readme, encoding='utf-8')
    for name, text in (docs if docs is not None else {'good.md': GOOD_DOC, 'other.md': OTHER_DOC}).items():
        (root / 'docs' / name).write_text(text, encoding='utf-8')
    if catalog is not None:
        (root / 'rescue-ai' / 'v1' / 'catalog').mkdir(parents=True, exist_ok=True)
        (root / 'rescue-ai' / 'v1' / 'catalog' / 'hardware.json').write_text(json.dumps(catalog), encoding='utf-8')
    for rel, text in (extra or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    return root


class CheckDocsTests(unittest.TestCase):
    def check(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, **kwargs)
            return check_docs.Checker(tmp).run()

    def assert_error(self, errors, fragment):
        self.assertTrue(any(fragment in e for e in errors), 'expected %r in %r' % (fragment, errors))

    def test_good_tree_passes(self):
        self.assertEqual(self.check(), [])

    def test_slug_rules(self):
        s = check_docs.slugify
        self.assertEqual(s('Bagian dua (Bahasa)'), 'bagian-dua-bahasa')
        self.assertEqual(s('Yang dilakukan pemindai (Implemented)'), 'yang-dilakukan-pemindai-implemented')
        self.assertEqual(s('`scripts/rescue-repair.py` engine'), 'scriptsrescue-repairpy-engine')
        self.assertEqual(s('Kode keluar / Exit codes'), 'kode-keluar--exit-codes')
        self.assertEqual(s('Untuk operator (Bahasa Indonesia)'), 'untuk-operator-bahasa-indonesia')
        self.assertEqual(s('[Link](x.md) teks'), 'link-teks')

    def test_duplicate_heading_suffix(self):
        self.assertEqual(check_docs.anchors_of('# A\n## A\n## A\n'), {'a', 'a-1', 'a-2'})

    def test_headings_in_fences_do_not_count(self):
        self.assertNotIn('kode', check_docs.anchors_of('```\n# kode\n```\n'))

    def test_broken_file_link(self):
        errors = self.check(docs={'good.md': GOOD_DOC + '\n[x](missing.md)\n', 'other.md': OTHER_DOC})
        self.assert_error(errors, 'broken link: missing.md')

    def test_broken_anchor(self):
        errors = self.check(docs={'good.md': GOOD_DOC + '\n[x](other.md#tidak-ada)\n', 'other.md': OTHER_DOC})
        self.assert_error(errors, 'broken anchor')

    def test_broken_same_file_anchor(self):
        errors = self.check(docs={'good.md': GOOD_DOC + '\n[x](#tidak-ada)\n', 'other.md': OTHER_DOC})
        self.assert_error(errors, 'this file has no heading or id "tidak-ada"')

    def test_link_to_directory_is_fine(self):
        errors = self.check(extra={'profiles/rescue-hermes/AGENTS.md': '# P\n'},
                            readme=README + '\n[profil](profiles/rescue-hermes/)\n')
        self.assertEqual(errors, [])

    def test_reference_style_link(self):
        errors = self.check(readme=README + '\n[ref]: docs/missing.md\n')
        self.assert_error(errors, 'broken link: docs/missing.md')

    def test_unknown_mermaid_type(self):
        bad = GOOD_DOC + '\n```mermaid\nnotadiagram\n    A --> B\n```\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'known diagram type')

    def test_mermaid_all_known_types_accepted(self):
        for first in ('flowchart TD', 'graph LR', 'sequenceDiagram', 'stateDiagram-v2', 'classDiagram',
                      'erDiagram', 'journey', 'gantt', 'pie title X'):
            text = GOOD_DOC + '\n```mermaid\n%s\n```\n' % first
            self.assertEqual(self.check(docs={'good.md': text, 'other.md': OTHER_DOC}), [], first)

    def test_mermaid_unbalanced_bracket(self):
        bad = GOOD_DOC + '\n```mermaid\nflowchart LR\n    A[Mulai --> B\n```\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'unbalanced brackets')

    def test_mermaid_mismatched_bracket(self):
        bad = GOOD_DOC + '\n```mermaid\nflowchart LR\n    A[Mulai) --> B\n```\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'unbalanced brackets')

    def test_mermaid_unbalanced_quote(self):
        bad = GOOD_DOC + '\n```mermaid\nflowchart LR\n    A["Mulai] --> B\n```\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'unbalanced double quotes')

    def test_mermaid_comment_and_directive_lines_skipped(self):
        text = GOOD_DOC + '\n```mermaid\n%% komentar [\nflowchart LR\n    A --> B\n```\n'
        self.assertEqual(self.check(docs={'good.md': text, 'other.md': OTHER_DOC}), [])

    def test_missing_attribution_in_docs(self):
        errors = self.check(docs={'good.md': '# Tanpa atribusi\n', 'other.md': OTHER_DOC})
        self.assert_error(errors, 'good.md:1: missing attribution line')

    def test_attribution_not_required_for_agents_or_profiles(self):
        errors = self.check(extra={'AGENTS.md': '# A\n', 'profiles/rescue-hermes/SOUL.md': '# S\n'})
        self.assertEqual(errors, [])

    def test_attribution_required_for_readme(self):
        errors = self.check(readme='# Tujuan\n')
        self.assert_error(errors, 'README.md:1: missing attribution line')

    def test_secret_in_fenced_block(self):
        fake = 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'
        bad = GOOD_DOC + '\n```bash\nexport X=%s\n```\n' % fake
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'possible secret')

    def test_secret_patterns(self):
        cases = ['github' + '_pat_' + 'A' * 30, 'sk' + '-' + 'a1' * 15, 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
                 '-----BEGIN ' + 'PRIVATE KEY-----', 'ey' + 'Jhbgciohsz.ey' + 'Jzdwiioixmjm0.sig']
        for value in cases:
            bad = GOOD_DOC + '\n```\n%s\n```\n' % value
            self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'possible secret')

    def test_secret_assignment_real_looking_value(self):
        bad = GOOD_DOC + "\n```bash\nOPENCODE_GO_API_KEY='0123456789abcdefABCDEF0123456789'\n```\n"
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'secret assignment')

    def test_secret_outside_fence_is_not_flagged(self):
        text = GOOD_DOC + '\nPrefix `ghp_` dan `github_pat_` disebut di teks.\n'
        self.assertEqual(self.check(docs={'good.md': text, 'other.md': OTHER_DOC}), [])

    def test_doc_ref_missing_file(self):
        bad = GOOD_DOC + '\nLihat `docs/hilang.md#x`.\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'missing file: docs/hilang.md')

    def test_doc_ref_missing_anchor(self):
        bad = GOOD_DOC + '\nLihat `docs/other.md#tidak-ada`.\n'
        self.assert_error(self.check(docs={'good.md': bad, 'other.md': OTHER_DOC}), 'missing anchor: docs/other.md#tidak-ada')

    def test_catalog_doc_field_missing_anchor(self):
        errors = self.check(catalog={'actions': [{'action_id': 'hw.bad', 'doc': 'docs/other.md#nope'}]})
        self.assert_error(errors, 'hw.bad: doc anchor missing')

    def test_catalog_doc_field_missing_file(self):
        errors = self.check(catalog={'actions': [{'action_id': 'hw.bad', 'doc': 'docs/none.md'}]})
        self.assert_error(errors, 'hw.bad: doc file missing')

    def test_catalog_doc_field_wrong_shape(self):
        errors = self.check(catalog={'actions': [{'action_id': 'hw.bad', 'doc': 'https://x.example/y'}]})
        self.assert_error(errors, 'doc field is not docs/NAME.md')

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp)
            ok = subprocess.run([sys.executable, str(SCRIPT), '--root', tmp], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn('docs check: ok', ok.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, docs={'good.md': '# Tanpa atribusi\n[x](nope.md)\n', 'other.md': OTHER_DOC})
            bad = subprocess.run([sys.executable, str(SCRIPT), '--root', tmp], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1)
            self.assertIn('broken link', bad.stdout)
            self.assertIn('FAILED', bad.stderr)
        missing = subprocess.run([sys.executable, str(SCRIPT), '--root', '/nonexistent-dir-for-test'], capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)

    def test_this_repository_passes(self):
        """The real documentation must satisfy its own checker (same as `make docs`)."""
        errors = check_docs.Checker(ROOT).run()
        self.assertEqual(errors, [], '\n'.join(errors))


if __name__ == '__main__':
    unittest.main()
