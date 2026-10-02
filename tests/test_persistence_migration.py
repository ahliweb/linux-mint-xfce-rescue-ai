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


if __name__ == '__main__':
    unittest.main()
