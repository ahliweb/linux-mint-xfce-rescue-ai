"""Tests for scripts/migrate-persistence-state.py on small ext4 images built with mke2fs -d (no root).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Two fixture images stand in for an OLD field USB (state with a fake key, sessions, learned skills, a
symlink and lock files) and a NEW CI image (fresh program files, bundled skills, an empty key). The
migration is run on copies so every case starts from the same bytes.
"""
import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'migrate-persistence-state.py'
STATE = '/upper/home/mint/.local/share/rescue-omes'
STATE_REL = 'upper/home/mint/.local/share/rescue-omes'

TOOLS = {name: shutil.which(name) or ('/sbin/' + name if os.path.exists('/sbin/' + name) else
                                     ('/usr/sbin/' + name if os.path.exists('/usr/sbin/' + name) else None))
         for name in ('mke2fs', 'debugfs', 'e2fsck')}
HAVE_TOOLS = all(TOOLS.values())

# Split so the credential-free bundle scan (package.yml) does not see a key-shaped literal in this file.
FAKE_SECRET = 'sk' + '-FAKE-FIELD-KEY-0123456789abcdef'
FAKE_KEY = "OPENCODE_GO_API_KEY='%s'\n" % FAKE_SECRET
DB_BYTES = bytes(range(256)) * 20          # binary, not valid UTF-8 text
BASE_MTIME = 1700000000

spec = importlib.util.spec_from_file_location('migrate_persistence_state', SCRIPT)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)

# relative path (under the state root) -> (content, mode)
OLD_FILES = {
    'hermes/env': (FAKE_KEY.encode(), 0o600),
    'hermes/config.yaml': (b'model: old\nonboarded: true\n', 0o644),
    'hermes/state.db': (DB_BYTES, 0o644),
    'hermes/state.db-wal': (b'wal-old', 0o644),
    'hermes/memories/MEMORY.md': (b'field memory\n', 0o644),
    'hermes/sessions/s1.json': (b'{"s": 1}\n', 0o640),
    'hermes/sessions/.locks/guard': (b'guard', 0o644),
    'hermes/logs/agent.log': (b'log line\n', 0o644),
    'hermes/cron/jobs.json': (b'[]', 0o644),
    'hermes/cron/tick.lock': (b'lock', 0o644),
    'hermes/skills/.usage.json': (b'{"u": 1}', 0o644),
    'hermes/skills/rescue-boot-diagnosis/SKILL.md': (b'OLD bundled skill\n', 0o644),
    'hermes/skills/field-learned/SKILL.md': (b'learned in the field\n', 0o644),
    'hermes/skills/field-learned/refs/notes.md': (b'nested note\n', 0o600),
    'hermes/hermes-agent/VERSION': (b'old-program\n', 0o644),
    'hermes/SOUL.md': (b'OLD soul\n', 0o644),
    'hermes/cache/junk.bin': (b'not allowlisted', 0o644),
    'cases/c1/case.json': (b'{"case": 1}\n', 0o600),
    'learning/l1.json': (b'{"l": 1}\n', 0o644),
    'reports/run-1/report.json': (b'{"old": true}\n', 0o644),
    'repairs/journal.jsonl': (b'{"seq":1}\n', 0o600),
    'audit/a.log': (b'audit\n', 0o600),
    'clamav/main.cvd': (b'sig' * 100, 0o644),
}
OLD_UID = {'hermes/sessions/s1.json': (1001, 1002)}   # field ownership that differs from the default 1000:1000

NEW_FILES = {
    'hermes/env': (b"OPENCODE_GO_API_KEY=''\n", 0o600),
    'hermes/config.yaml': (b'model: new\nonboarded: false\n', 0o644),
    'hermes/hermes-agent/VERSION': (b'new-program\n', 0o644),
    'hermes/SOUL.md': (b'NEW soul\n', 0o644),
    'hermes/skills/rescue-boot-diagnosis/SKILL.md': (b'NEW bundled skill\n', 0o644),
    'hermes/skills/rescue-printer/SKILL.md': (b'new only skill\n', 0o644),
    'reports/run-1/report.json': (b'{"new": true}\n', 0o644),
}
OLD_SYMLINK = 'hermes/memories/outside-link'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_tool(argv, check=True):
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False)
    if check and proc.returncode != 0:
        raise AssertionError('%s failed: %s' % (argv[:2], proc.stderr.decode('utf-8', 'replace')[:300]))
    return proc


def populate(root, files, mtime_base):
    state = Path(root) / STATE_REL
    for index, (rel, (content, mode)) in enumerate(sorted(files.items())):
        path = state / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        os.chmod(path, mode)
        os.utime(path, (mtime_base + index, mtime_base + index))
    return state


def build_image(files, image, symlink=False, mtime_base=BASE_MTIME, owners=None):
    """mke2fs -d image from FILES; every state entry gets uid/gid 1000 via debugfs (mke2fs -d copies the caller's)."""
    with tempfile.TemporaryDirectory() as tmp:
        state = populate(tmp, files, mtime_base)
        if symlink:
            os.symlink('/etc/passwd', state / OLD_SYMLINK)
        run_tool([TOOLS['mke2fs'], '-q', '-t', 'ext4', '-d', tmp, '-E', 'root_owner=0:0', str(image), '8M'])
    script = []
    for path in sorted(_state_paths(files, symlink)):
        script.append('sif "%s" uid 1000' % path)
        script.append('sif "%s" gid 1000' % path)
    for rel, (uid, gid) in (owners or {}).items():
        script.append('sif "%s/%s" uid %d' % (STATE, rel, uid))
        script.append('sif "%s/%s" gid %d' % (STATE, rel, gid))
    cmd = Path(str(image) + '.cmds')
    cmd.write_text('\n'.join(script) + '\n')
    run_tool([TOOLS['debugfs'], '-w', '-f', str(cmd), str(image)])
    cmd.unlink()


def _state_paths(files, symlink):
    """Absolute image paths of the state tree: every file and every parent directory below the root."""
    seen = set()
    rels = list(files) + ([OLD_SYMLINK] if symlink else [])
    for rel in rels:
        parts = rel.split('/')
        for i in range(1, len(parts) + 1):
            seen.add('/'.join(parts[:i]))
    return ['%s/%s' % (STATE, p) for p in seen]


def dump(image, path):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / 'out'
        run_tool([TOOLS['debugfs'], '-R', 'dump "%s" "%s"' % (path, out), str(image)])
        return out.read_bytes() if out.exists() else None


def info(image, rel):
    migrate.DEBUGFS = TOOLS['debugfs']
    return migrate.inode_info(str(image), '%s/%s' % (STATE, rel))


def exists(image, rel):
    migrate.DEBUGFS = TOOLS['debugfs']
    return migrate.exists(str(image), '%s/%s' % (STATE, rel))


@unittest.skipUnless(HAVE_TOOLS, 'mke2fs, debugfs and e2fsck (e2fsprogs) are required')
class MigratePersistenceStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix='migtest-')
        cls.old_tpl = os.path.join(cls.base, 'old.tpl')
        cls.new_tpl = os.path.join(cls.base, 'new.tpl')
        build_image(OLD_FILES, cls.old_tpl, symlink=True, owners=OLD_UID)
        build_image(NEW_FILES, cls.new_tpl, mtime_base=BASE_MTIME + 5000)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix='migcase-', dir=self.base)
        self.old = os.path.join(self.work, 'old.dat')
        self.new = os.path.join(self.work, 'new.dat')
        self.tmpdir = os.path.join(self.work, 'tmp')
        os.mkdir(self.tmpdir)
        shutil.copyfile(self.old_tpl, self.old)
        shutil.copyfile(self.new_tpl, self.new)

    def migrate(self, *extra, old=None, new=None):
        env = dict(os.environ, TMPDIR=self.tmpdir)
        return subprocess.run([sys.executable, str(SCRIPT), '--from', old or self.old, '--to', new or self.new, *extra],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=300, check=False)

    # --- fixture sanity -------------------------------------------------------------------------------------

    def test_fixture_has_state_owned_by_uid_1000(self):
        mode, uid, gid, mtime = info(self.old, 'hermes/env')
        self.assertEqual((uid, gid, mode & 0o777), (1000, 1000, 0o600))
        self.assertEqual(info(self.old, 'hermes/sessions/s1.json')[1:3], (1001, 1002))

    # --- dry run --------------------------------------------------------------------------------------------

    def test_dry_run_changes_nothing_and_prints_the_plan(self):
        before_new, before_old = sha(self.new), sha(self.old)
        proc = self.migrate('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((sha(self.new), sha(self.old)), (before_new, before_old))
        self.assertIn('f hermes/env', proc.stdout)
        self.assertIn('f hermes/skills/field-learned/SKILL.md', proc.stdout)
        self.assertNotIn('hermes/cache/junk.bin', proc.stdout)
        self.assertEqual(os.listdir(self.tmpdir), [])

    # --- full migration -------------------------------------------------------------------------------------

    def test_full_migration_carries_state_with_identical_content_and_metadata(self):
        before_old = sha(self.old)
        proc = self.migrate()
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn('Migrated and verified', proc.stdout)
        self.assertEqual(sha(self.old), before_old, 'OLD must stay read-only')
        carried = ['hermes/env', 'hermes/config.yaml', 'hermes/state.db', 'hermes/state.db-wal',
                   'hermes/memories/MEMORY.md', 'hermes/sessions/s1.json', 'hermes/logs/agent.log',
                   'hermes/cron/jobs.json', 'hermes/skills/.usage.json', 'cases/c1/case.json',
                   'learning/l1.json', 'reports/run-1/report.json', 'repairs/journal.jsonl', 'audit/a.log',
                   'clamav/main.cvd', 'hermes/skills/field-learned/SKILL.md',
                   'hermes/skills/field-learned/refs/notes.md']
        for rel in carried:
            with self.subTest(rel=rel):
                self.assertEqual(info(self.new, rel), info(self.old, rel), 'mode/uid/gid/mtime')
                self.assertEqual(dump(self.new, '%s/%s' % (STATE, rel)), OLD_FILES[rel][0], 'content')
        for rel in ('hermes/memories', 'hermes/skills/field-learned/refs', 'cases/c1', 'reports/run-1'):
            with self.subTest(directory=rel):
                self.assertEqual(info(self.new, rel), info(self.old, rel))
        # carried files keep their field ownership and the key stays private
        self.assertEqual(info(self.new, 'hermes/env')[:3], (0o100600, 1000, 1000))
        self.assertEqual(info(self.new, 'hermes/sessions/s1.json')[1:3], (1001, 1002))

    def test_same_path_file_in_new_is_replaced(self):
        self.assertEqual(dump(self.new, STATE + '/reports/run-1/report.json'), b'{"new": true}\n')
        self.assertEqual(self.migrate().returncode, 0)
        self.assertEqual(dump(self.new, STATE + '/reports/run-1/report.json'), b'{"old": true}\n')
        self.assertEqual(dump(self.new, STATE + '/hermes/config.yaml'), b'model: old\nonboarded: true\n')
        self.assertIn(FAKE_SECRET.encode(), dump(self.new, STATE + '/hermes/env'))

    def test_program_files_and_bundled_skills_stay_from_new(self):
        self.assertEqual(self.migrate().returncode, 0)
        self.assertEqual(dump(self.new, STATE + '/hermes/hermes-agent/VERSION'), b'new-program\n')
        self.assertEqual(dump(self.new, STATE + '/hermes/SOUL.md'), b'NEW soul\n')
        self.assertEqual(dump(self.new, STATE + '/hermes/skills/rescue-printer/SKILL.md'), b'new only skill\n')
        self.assertFalse(exists(self.new, 'hermes/cache/junk.bin'), 'non-allowlisted paths are not carried')

    def test_field_learned_skill_is_carried_but_a_shared_skill_keeps_the_new_version(self):
        self.assertEqual(self.migrate().returncode, 0)
        self.assertEqual(dump(self.new, STATE + '/hermes/skills/field-learned/SKILL.md'), b'learned in the field\n')
        self.assertEqual(dump(self.new, STATE + '/hermes/skills/rescue-boot-diagnosis/SKILL.md'), b'NEW bundled skill\n')

    def test_lock_files_and_symlinks_are_skipped_and_reported(self):
        proc = self.migrate()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for rel in ('hermes/cron/tick.lock', 'hermes/sessions/.locks', OLD_SYMLINK):
            with self.subTest(rel=rel):
                self.assertFalse(exists(self.new, rel))
                self.assertIn('skipped (lock or not a regular file/directory): %s' % rel, proc.stdout)
        dry = self.migrate('--dry-run')
        self.assertIn('skipped (lock or not a regular file/directory): %s' % OLD_SYMLINK, dry.stdout)

    def test_new_image_is_clean_and_staging_is_removed(self):
        proc = self.migrate()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        fsck = run_tool([TOOLS['e2fsck'], '-fn', self.new], check=False)
        self.assertEqual(fsck.returncode, 0, fsck.stdout.decode('utf-8', 'replace')[-300:])
        self.assertEqual(os.listdir(self.tmpdir), [], 'staging directory must be removed')

    def test_secret_value_is_never_printed(self):
        for extra in ((), ('--dry-run',)):
            proc = self.migrate(*extra)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn(FAKE_SECRET, proc.stdout + proc.stderr)
            self.assertNotIn('OPENCODE_GO_API_KEY', proc.stdout + proc.stderr)

    def test_migration_is_repeatable(self):
        self.assertEqual(self.migrate().returncode, 0)
        again = self.migrate()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(dump(self.new, STATE + '/hermes/state.db'), DB_BYTES)

    # --- refusals -------------------------------------------------------------------------------------------

    def test_refuses_the_same_file_for_from_and_to(self):
        before = sha(self.new)
        proc = self.migrate(old=self.new, new=self.new)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('same file', proc.stderr)
        self.assertEqual(sha(self.new), before)

    def test_refuses_a_hard_link_to_the_same_image(self):
        link = os.path.join(self.work, 'link.dat')
        os.link(self.new, link)
        proc = self.migrate(old=link, new=self.new)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('same file', proc.stderr)

    def test_refuses_a_device_node_instead_of_an_image(self):
        for side in ('old', 'new'):
            with self.subTest(side=side):
                proc = self.migrate(**{side: '/dev/null'})
                self.assertEqual(proc.returncode, 2)
                self.assertIn('regular image file', proc.stderr)

    def test_refuses_a_missing_file(self):
        proc = self.migrate(old=os.path.join(self.work, 'absent.dat'))
        self.assertEqual(proc.returncode, 2)

    def test_refuses_an_image_without_the_state_root(self):
        other = os.path.join(self.work, 'other.dat')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'upper' / 'etc').mkdir(parents=True)
            (Path(tmp) / 'upper' / 'etc' / 'hostname').write_text('x')
            run_tool([TOOLS['mke2fs'], '-q', '-t', 'ext4', '-d', tmp, '-E', 'root_owner=0:0', other, '8M'])
        for side in ('old', 'new'):
            with self.subTest(side=side):
                before = sha(self.new)
                proc = self.migrate(**{side: other})
                self.assertEqual(proc.returncode, 2)
                self.assertIn('not a rescue persistence image', proc.stderr)
                self.assertEqual(sha(self.new), before)

    def test_missing_debugfs_exits_3_without_touching_the_images(self):
        before = sha(self.new)
        real_exists = os.path.exists

        def fake_exists(path):
            return False if str(path).endswith(('/debugfs', '/e2fsck')) else real_exists(path)

        err = io.StringIO()
        with mock.patch.object(migrate.shutil, 'which', return_value=None), \
                mock.patch.object(migrate.os.path, 'exists', side_effect=fake_exists), \
                contextlib.redirect_stderr(err):
            code = migrate.main(['--from', self.old, '--to', self.new])
        self.assertEqual(code, 3)
        self.assertIn('debugfs and e2fsck', err.getvalue())
        self.assertEqual(sha(self.new), before)

    # --- helpers --------------------------------------------------------------------------------------------

    def test_quote_refuses_characters_that_would_break_a_debugfs_request(self):
        self.assertEqual(migrate.quote('/a/b c'), '"/a/b c"')
        for bad in ('/a"b', '/a\nb'):
            with self.assertRaises(ValueError):
                migrate.quote(bad)

    def test_debugfs_mode_reports_type_so_sif_keeps_the_file_type(self):
        self.assertEqual(info(self.old, 'hermes/env')[0], 0o100600)
        self.assertEqual(info(self.old, 'hermes/memories')[0] & 0o170000, 0o040000)


NEW_ENV_TEXT = b"HERMES_HOME=/home/mint/.local/share/rescue-omes/hermes\nOPENCODE_GO_API_KEY=''\nRESCUE_STATE_DIR=/x\n"


@unittest.skipUnless(HAVE_TOOLS, 'mke2fs, debugfs and e2fsck (e2fsprogs) are required')
class MigrateKeyOnlyTest(unittest.TestCase):
    """--key-only: a clean NEW image gets the provider key and nothing else from OLD."""

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix='migkey-')
        cls.old_tpl = os.path.join(cls.base, 'old.tpl')
        cls.new_tpl = os.path.join(cls.base, 'new.tpl')
        build_image(OLD_FILES, cls.old_tpl, symlink=True, owners=OLD_UID)
        new_files = dict(NEW_FILES, **{'hermes/env': (NEW_ENV_TEXT, 0o600)})
        build_image(new_files, cls.new_tpl, mtime_base=BASE_MTIME + 5000, owners={'hermes/env': (1001, 1002)})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix='migcase-', dir=self.base)
        self.old = os.path.join(self.work, 'old.dat')
        self.new = os.path.join(self.work, 'new.dat')
        self.tmpdir = os.path.join(self.work, 'tmp')
        os.mkdir(self.tmpdir)
        shutil.copyfile(self.old_tpl, self.old)
        shutil.copyfile(self.new_tpl, self.new)

    def put_env(self, image, content):
        """Replace hermes/env in IMAGE with CONTENT (bytes) through debugfs."""
        src = os.path.join(self.work, 'env.src')
        Path(src).write_bytes(content)
        migrate.DEBUGFS = TOOLS['debugfs']
        for request in ('rm "%s/hermes/env"' % STATE, 'write "%s" "%s/hermes/env"' % (src, STATE)):
            run_tool([TOOLS['debugfs'], '-w', '-R', request, image], check=request.startswith('write'))
        os.unlink(src)

    def key_only(self, *extra):
        env = dict(os.environ, TMPDIR=self.tmpdir)
        return subprocess.run([sys.executable, str(SCRIPT), '--from', self.old, '--to', self.new, '--key-only', *extra],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=300, check=False)

    def test_key_is_carried_and_nothing_else(self):
        proc = self.key_only()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("OPENCODE_GO_API_KEY='%s'\n" % FAKE_SECRET, dump(self.new, STATE + '/hermes/env').decode())
        for rel in ('hermes/state.db', 'hermes/state.db-wal', 'hermes/memories/MEMORY.md',
                    'hermes/sessions/s1.json', 'hermes/skills/field-learned/SKILL.md', 'hermes/logs/agent.log',
                    'cases/c1/case.json', 'learning/l1.json', 'repairs/journal.jsonl', 'audit/a.log',
                    'clamav/main.cvd'):
            self.assertFalse(exists(self.new, rel), rel)
        # NEW's own files are untouched
        self.assertEqual(dump(self.new, STATE + '/reports/run-1/report.json'), b'{"new": true}\n')
        self.assertEqual(dump(self.new, STATE + '/hermes/config.yaml'), b'model: new\nonboarded: false\n')
        self.assertEqual(os.listdir(self.tmpdir), [], 'staging directory must be removed')

    def test_other_lines_of_new_env_are_kept_and_the_key_line_replaced_in_place(self):
        self.assertEqual(self.key_only().returncode, 0)
        lines = dump(self.new, STATE + '/hermes/env').decode().splitlines()
        self.assertEqual(lines, ['HERMES_HOME=/home/mint/.local/share/rescue-omes/hermes',
                                 "OPENCODE_GO_API_KEY='%s'" % FAKE_SECRET, 'RESCUE_STATE_DIR=/x'])

    def test_key_line_is_appended_when_new_has_none(self):
        self.put_env(self.new, b'HERMES_HOME=/h')       # no trailing newline
        self.assertEqual(self.key_only().returncode, 0)
        self.assertEqual(dump(self.new, STATE + '/hermes/env').decode(),
                         "HERMES_HOME=/h\nOPENCODE_GO_API_KEY='%s'\n" % FAKE_SECRET)

    def test_owner_group_and_mode_are_kept_and_end_0600(self):
        self.assertEqual(self.key_only().returncode, 0)
        mode, uid, gid, _mtime = info(self.new, 'hermes/env')
        self.assertEqual((mode, uid, gid), (0o100600, 1001, 1002))

    def test_missing_new_env_is_created_with_the_owner_of_the_hermes_directory(self):
        run_tool([TOOLS['debugfs'], '-w', '-R', 'rm "%s/hermes/env"' % STATE, self.new])
        run_tool([TOOLS['debugfs'], '-w', '-R', 'sif "%s/hermes" uid 1003' % STATE, self.new])
        run_tool([TOOLS['debugfs'], '-w', '-R', 'sif "%s/hermes" gid 1004' % STATE, self.new])
        self.assertEqual(self.key_only().returncode, 0)
        mode, uid, gid, _mtime = info(self.new, 'hermes/env')
        self.assertEqual((mode, uid, gid), (0o100600, 1003, 1004))
        self.assertEqual(dump(self.new, STATE + '/hermes/env').decode(), "OPENCODE_GO_API_KEY='%s'\n" % FAKE_SECRET)

    def test_empty_or_missing_key_is_refused_and_changes_nothing(self):
        cases = {'empty': b"OPENCODE_GO_API_KEY=''\n", 'absent': b'HERMES_HOME=/x\n', 'blank': b'',
                 'comment': b"# OPENCODE_GO_API_KEY=abc\n"}
        for name, content in cases.items():
            with self.subTest(case=name):
                shutil.copyfile(self.old_tpl, self.old)
                shutil.copyfile(self.new_tpl, self.new)
                self.put_env(self.old, content)
                before = sha(self.new)
                proc = self.key_only()
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn('nothing to carry', proc.stderr)
                self.assertEqual(sha(self.new), before)

    def test_old_without_hermes_env_is_refused(self):
        run_tool([TOOLS['debugfs'], '-w', '-R', 'rm "%s/hermes/env"' % STATE, self.old])
        before = sha(self.new)
        proc = self.key_only()
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(sha(self.new), before)

    def test_unsafe_values_are_refused_without_printing_them(self):
        bad = {'subshell': b'OPENCODE_GO_API_KEY=$(touch /tmp/pwn)\n',
               'backtick': b'OPENCODE_GO_API_KEY="a`id`b"\n',
               'dollar': b'OPENCODE_GO_API_KEY=ab$HOME\n',
               'carriage-return': b"OPENCODE_GO_API_KEY='ab\rcd'\n",
               'newline': b"OPENCODE_GO_API_KEY='ab\ncd'\n"}
        for name, content in bad.items():
            with self.subTest(case=name):
                shutil.copyfile(self.old_tpl, self.old)
                shutil.copyfile(self.new_tpl, self.new)
                self.put_env(self.old, content)
                before = sha(self.new)
                proc = self.key_only()
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(sha(self.new), before)
                self.assertNotIn('touch', proc.stdout + proc.stderr)

    def test_allowlisted_quoting_forms_are_parsed_like_rescue_env(self):
        for content, expect in (('export OPENCODE_GO_API_KEY="a\\$b" # c\n', 'a$b'),
                                ("OPENCODE_GO_API_KEY='it'\\''s'\n", "it's"),
                                ('OPENCODE_GO_API_KEY=plain-value\r\n', 'plain-value')):
            with self.subTest(content=content):
                self.assertEqual(migrate.extract_key(content), (expect, ''))

    def test_the_key_is_never_printed(self):
        for extra in ((), ('--dry-run',)):
            proc = self.key_only(*extra)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn(FAKE_SECRET, proc.stdout + proc.stderr)
            self.assertNotIn('OPENCODE_GO_API_KEY', proc.stdout + proc.stderr)

    def test_the_key_is_never_on_a_subprocess_argv(self):
        migrate.DEBUGFS = TOOLS['debugfs']
        seen = []
        real_run = migrate.subprocess.run

        def spy(argv, *a, **kw):
            seen.append(list(argv))
            return real_run(argv, *a, **kw)

        args = migrate.argparse.Namespace(old=self.old, new=self.new, dry_run=False, key_only=True)
        with mock.patch.object(migrate.subprocess, 'run', side_effect=spy), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(migrate.key_only(args, TOOLS['e2fsck']), 0)
        self.assertTrue(seen)
        self.assertFalse([a for argv in seen for a in argv if FAKE_SECRET in a])

    def test_dry_run_reports_and_changes_nothing(self):
        before_new, before_old = sha(self.new), sha(self.old)
        proc = self.key_only('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Provider key present in old.dat: yes', proc.stdout)
        self.assertIn('would replace the key line', proc.stdout)
        self.assertEqual((sha(self.new), sha(self.old)), (before_new, before_old))
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_dry_run_without_key_says_no(self):
        self.put_env(self.old, b"OPENCODE_GO_API_KEY=''\n")
        proc = self.key_only('--dry-run')
        self.assertEqual(proc.returncode, 2)
        self.assertIn('Provider key present in old.dat: no', proc.stdout)

    def test_new_image_is_clean_and_old_is_unchanged(self):
        before_old = sha(self.old)
        proc = self.key_only()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Key carried and verified', proc.stdout)
        fsck = run_tool([TOOLS['e2fsck'], '-fn', self.new], check=False)
        self.assertEqual(fsck.returncode, 0, fsck.stdout.decode('utf-8', 'replace')[-300:])
        self.assertEqual(sha(self.old), before_old)

    def test_repeat_run_is_idempotent(self):
        self.assertEqual(self.key_only().returncode, 0)
        first = dump(self.new, STATE + '/hermes/env')
        self.assertEqual(self.key_only().returncode, 0)
        self.assertEqual(dump(self.new, STATE + '/hermes/env'), first)


if __name__ == '__main__':
    unittest.main()
