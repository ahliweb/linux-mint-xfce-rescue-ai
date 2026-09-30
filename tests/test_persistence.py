"""Offline tests for the Ventoy persistence tooling (no docker, network, root, or block devices)."""
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
HAVE_GPG = shutil.which("gpg") is not None
DUMMY_KEY = "dummy-persistence-test-value"

_spec = importlib.util.spec_from_file_location("overlay_whiteouts", SCRIPTS / "lib" / "overlay_whiteouts.py")
ow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ow)


def run(args, cwd=None, env=None):
    return subprocess.run(
        [str(a) for a in args], cwd=cwd, env=env, capture_output=True, text=True, timeout=120
    )


def fake_ext_image(path, label=b"casper-rw", magic=0xEF53, size=4096):
    data = bytearray(size)
    struct.pack_into("<H", data, 1024 + 56, magic)
    data[1024 + 120:1024 + 120 + len(label)] = label
    pathlib.Path(path).write_bytes(bytes(data))


class BuildPersistenceArgumentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.iso = self.base / "mint.iso"
        self.iso.write_bytes(b"not a real iso")
        self.out = self.base / "out.dat"

    def build(self, *args, env=None):
        return run([SCRIPTS / "build-persistence.sh", *args], env=env)

    def good(self, *extra):
        return ["--iso", self.iso, "--output", self.out, "--no-provision-secrets", *extra]

    def test_help_exits_zero(self):
        r = self.build("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--no-provision-secrets", r.stderr)

    def test_missing_required_arguments(self):
        self.assertEqual(self.build().returncode, 2)
        self.assertEqual(self.build("--iso", self.iso).returncode, 2)
        self.assertEqual(self.build("--bogus").returncode, 2)

    def test_missing_iso(self):
        r = self.build("--iso", self.base / "nope.iso", "--output", self.out, "--no-provision-secrets")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ISO not found", r.stderr)

    def test_bad_size_values(self):
        for bad in ("abc", "4095", "1024", "-5", "9999999999"):
            with self.subTest(size=bad):
                r = self.build(*self.good("--size-mib", bad))
                self.assertEqual(r.returncode, 2, r.stderr)
        self.assertFalse(self.out.exists())

    def fake_tools(self):
        """PATH with a docker that always fails `info`, plus no-op 7z/e2fsck."""
        bindir = self.base / "bin"
        bindir.mkdir(exist_ok=True)
        self.docker_log = self.base / "docker.log"
        (bindir / "docker").write_text(f'#!/bin/sh\necho "$@" >> {self.docker_log}\nexit 1\n')
        for name in ("7z", "e2fsck"):
            (bindir / name).write_text("#!/bin/sh\nexit 0\n")
        for f in bindir.iterdir():
            f.chmod(0o755)
        return dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")

    def test_minimum_size_passes_validation(self):
        r = self.build(*self.good("--size-mib", "4096"), env=self.fake_tools())
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Docker daemon", r.stderr)  # got past every argument check
        self.assertFalse(self.out.exists())

    def test_existing_output_is_refused_and_untouched(self):
        self.out.write_text("precious")
        r = self.build(*self.good())
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exists", r.stderr)
        self.assertEqual(self.out.read_text(), "precious")

    def test_existing_output_symlink_is_refused(self):
        target = self.base / "target"
        self.out.symlink_to(target)
        r = self.build(*self.good())
        self.assertEqual(r.returncode, 1)
        self.assertFalse(target.exists())

    def test_invalid_installer_sha(self):
        for bad in ("nothex", "abc123", "g" * 64, "a" * 63):
            with self.subTest(sha=bad):
                r = self.build(*self.good("--installer-sha256", bad))
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("Invalid installer SHA-256", r.stderr)

    def test_env_sha_variable_is_validated_too(self):
        r = self.build(*self.good(), env=dict(os.environ, HERMES_INSTALLER_SHA256="zz"))
        self.assertEqual(r.returncode, 2)

    def test_env_file_conflicts_with_no_provision(self):
        r = self.build("--iso", self.iso, "--output", self.out, "--no-provision-secrets",
                       "--env-file", self.base / "x.env")
        self.assertEqual(r.returncode, 2)
        self.assertIn("mutually exclusive", r.stderr)

    def test_explicit_env_file_must_exist_and_hold_key(self):
        r = self.build("--iso", self.iso, "--output", self.out, "--env-file", self.base / "missing.env")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)
        empty = self.base / "empty.env"
        empty.write_text("OTHER=1\n")
        empty.chmod(0o600)
        r = self.build("--iso", self.iso, "--output", self.out, "--env-file", empty)
        self.assertEqual(r.returncode, 1)
        self.assertIn("OPENCODE_GO_API_KEY", r.stderr)

    def test_key_is_read_as_data_and_never_echoed(self):
        # With fake tools on PATH the script stops at `docker info`; the dummy
        # key must not leak to output and must never reach a docker argv.
        env = self.fake_tools()
        marker = self.base / "pwned"
        envf = self.base / "secret.env"
        envf.write_text(f"OPENCODE_GO_API_KEY='{DUMMY_KEY}'\nEVIL=$(touch {marker})\nOTHER=`touch {marker}`\n")
        envf.chmod(0o600)
        r = self.build("--iso", self.iso, "--output", self.out, "--env-file", envf, env=env)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Docker daemon", r.stderr)
        self.assertNotIn(DUMMY_KEY, r.stdout + r.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.out.exists())
        if self.docker_log.exists():
            self.assertNotIn(DUMMY_KEY, self.docker_log.read_text())
        # nothing was left behind next to the output
        self.assertEqual([p.name for p in self.base.glob(".build-persistence.*")], [])


class OverlayWhiteoutTests(unittest.TestCase):
    def make_layer(self, path):
        with tarfile.open(path, "w") as tar:
            def add_dir(name, mode=0o755):
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                ti.mode = mode
                ti.uid = ti.gid = 1000
                tar.addfile(ti)

            def add_file(name, data=b"x", mode=0o644):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = mode
                ti.uid = ti.gid = 1000
                tar.addfile(ti, io.BytesIO(data))

            add_dir("etc")
            add_file("etc/.wh.removed.conf", b"")            # whiteout
            add_file("etc/hostname", b"container")           # excluded
            add_file("etc/passwd", b"root:x:0:0")            # excluded (casper owns accounts)
            add_dir("var")
            add_dir("var/lib")
            add_dir("var/lib/opaquedir")
            add_file("var/lib/opaquedir/.wh..wh..opq", b"")  # opaque marker
            add_file("var/lib/opaquedir/new.txt", b"n")
            add_dir("var/lib/apt")
            add_dir("var/lib/apt/lists")
            add_file("var/lib/apt/lists/junk", b"j")         # excluded
            add_dir("var/log")
            add_dir("var/log/sub")                           # directory skeleton kept
            add_file("var/log/big.log", b"log")              # dropped
            add_file("var/log/sub/x.log", b"log")            # dropped
            add_dir("tmp")                                   # excluded
            add_file("tmp/.wh.cache", b"")                   # excluded whiteout
            add_dir("home")
            add_dir("home/mint")
            add_dir("home/mint/.cache")                      # excluded
            add_file("home/mint/.cache/x", b"c")             # excluded
            add_dir("home/mint/.local")
            add_file("home/mint/.local/keep", b"hermes")
            ti = tarfile.TarInfo("home/mint/.local/link")
            ti.type = tarfile.LNKTYPE
            ti.linkname = "home/mint/.local/keep"
            tar.addfile(ti)
            ti = tarfile.TarInfo("home/mint/sym")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/usr/bin/env"
            tar.addfile(ti)
            add_file("home/mint/.wh.deleted-in-home", b"")   # whiteout in a user dir
            add_file(".wh.top-level", b"")                   # whiteout at the root

    def test_classify(self):
        self.assertEqual(ow.classify("a/b/.wh.c"), ("whiteout", "a/b/c"))
        self.assertEqual(ow.classify("./.wh.c"), ("whiteout", "c"))
        self.assertEqual(ow.classify("a/b/.wh..wh..opq"), ("opaque", "a/b"))
        self.assertEqual(ow.classify("a/b/.whale"), ("plain", "a/b/.whale"))
        self.assertEqual(ow.classify("./x/y/"), ("plain", "x/y"))

    def test_convert_layer_plan_and_filtered_tar(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = pathlib.Path(tmp, "layer.tar"), pathlib.Path(tmp, "out.tar")
            self.make_layer(src)
            plan = ow.convert_layer(str(src), str(dst)).as_dict()
            self.assertEqual(plan["whiteouts"], ["etc/removed.conf", "home/mint/deleted-in-home", "top-level"])
            self.assertEqual(plan["opaque"], ["var/lib/opaquedir"])
            with tarfile.open(dst) as tar:
                names = tar.getnames()
            self.assertFalse([n for n in names if ".wh." in n], names)
            for gone in ("etc/hostname", "etc/passwd", "var/lib/apt/lists/junk", "var/log/big.log",
                         "var/log/sub/x.log", "tmp", "tmp/.wh.cache", "home/mint/.cache", "home/mint/.cache/x"):
                self.assertNotIn(gone, names)
            for kept in ("etc", "var/lib/opaquedir/new.txt", "var/log", "var/log/sub",
                         "home/mint/.local/keep", "home/mint/.local/link", "home/mint/sym"):
                self.assertIn(kept, names)
            self.assertNotIn("tmp/cache", plan["whiteouts"])
            # ownership is preserved through the filter
            with tarfile.open(dst) as tar:
                self.assertEqual(tar.getmember("home/mint/.local/keep").uid, 1000)

    def test_hardlink_to_excluded_member_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = pathlib.Path(tmp, "layer.tar"), pathlib.Path(tmp, "out.tar")
            with tarfile.open(src, "w") as tar:
                ti = tarfile.TarInfo("tmp/a")
                ti.size = 1
                tar.addfile(ti, io.BytesIO(b"x"))
                ti = tarfile.TarInfo("usr/b")
                ti.type = tarfile.LNKTYPE
                ti.linkname = "tmp/a"
                tar.addfile(ti)
            with self.assertRaises(ValueError):
                ow.convert_layer(str(src), str(dst))

    def test_path_traversal_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = pathlib.Path(tmp, "layer.tar"), pathlib.Path(tmp, "out.tar")
            with tarfile.open(src, "w") as tar:
                ti = tarfile.TarInfo("../evil")
                ti.size = 1
                tar.addfile(ti, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                ow.convert_layer(str(src), str(dst))

    def test_debugfs_script_creates_char_device_0_0_whiteouts(self):
        plan = {"whiteouts": ["etc/removed.conf", "top-level", "dir with space/gone file"], "opaque": []}
        script = ow.debugfs_script(plan)
        # debugfs mknod links its argument literally into the cwd: cd into the parent first.
        self.assertEqual(script.splitlines(), [
            'cd "/upper/dir with space"', 'mknod "gone file" c 0 0',
            "cd /upper/etc", "mknod removed.conf c 0 0",
            "cd /upper", "mknod top-level c 0 0",
        ])

    def test_debugfs_script_for_opaque_dirs(self):
        script = ow.debugfs_script({"opaque": ["var/lib/opaquedir", "usr/share/x"]})
        self.assertEqual(script.splitlines(), [
            "ea_set /upper/usr/share/x trusted.overlay.opaque y",
            "ea_set /upper/var/lib/opaquedir trusted.overlay.opaque y",
        ])
        self.assertEqual(ow.debugfs_script({"opaque": [], "whiteouts": []}), "")

    def test_debugfs_script_combines_both_and_rejects_unsafe_paths(self):
        script = ow.debugfs_script({"whiteouts": ["a/b"], "opaque": ["a"]}, prefix="/x")
        self.assertEqual(script.splitlines(), ["cd /x/a", "mknod b c 0 0", "ea_set /x/a trusted.overlay.opaque y"])
        for bad in ("../x", '"quote', "back\\slash", "new\nline", "/abs"):
            with self.subTest(path=bad):
                with self.assertRaises(ValueError):
                    ow.debugfs_script({"opaque": [bad]})
                with self.assertRaises(ValueError):
                    ow.debugfs_script({"whiteouts": [bad]})

    def test_verify_script_inspects_every_planned_object(self):
        plan = {"whiteouts": ["etc/a"], "opaque": ["var/lib/x"]}
        self.assertEqual(ow.verify_script(plan).splitlines(), [
            "stat /upper/etc/a", "ea_get /upper/var/lib/x trusted.overlay.opaque"])

    def test_ensure_parents_creates_missing_directories_and_rejects_unsafe(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "etc"))
            made = ow.ensure_parents({"whiteouts": ["etc/a", "newdir/sub/b"]}, tmp)
            self.assertEqual(made, ["newdir/sub"])
            self.assertTrue(os.path.isdir(os.path.join(tmp, "newdir", "sub")))
            with self.assertRaises(ValueError):
                ow.ensure_parents({"whiteouts": ["../escape"]}, tmp)

    @unittest.skipUnless(shutil.which("mkfs.ext4") and shutil.which("debugfs"), "e2fsprogs is required")
    def test_debugfs_script_applies_to_a_real_ext4_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            for d in ("stage/upper/etc", "stage/upper/var/lib/x", "stage/upper/dir with space", "stage/work"):
                (base / d).mkdir(parents=True)
            plan = {"whiteouts": ["etc/removed.conf", "dir with space/gone file"],
                    "opaque": ["var/lib/x", "dir with space"]}
            image = base / "i.img"
            with open(image, "wb") as fh:
                fh.truncate(20 * 1024 * 1024)
            r = run(["mkfs.ext4", "-F", "-q", "-L", "casper-rw", "-d", base / "stage", image])
            if r.returncode != 0:
                self.skipTest("mkfs.ext4 -d unavailable: " + r.stderr)
            (base / "s.dbg").write_text(ow.debugfs_script(plan))
            (base / "v.dbg").write_text(ow.verify_script(plan))
            self.assertEqual(run(["debugfs", "-w", "-f", base / "s.dbg", image]).returncode, 0)
            out = run(["debugfs", "-f", base / "v.dbg", image]).stdout
            self.assertEqual(out.count("Type: character special"), 2)
            self.assertEqual(out.count("Device major/minor number: 00:00"), 2)
            self.assertEqual(out.count('trusted.overlay.opaque (1) = "y"'), 2)
            fsck = run(["e2fsck", "-fn", image]) if shutil.which("e2fsck") else None
            if fsck is not None:
                self.assertEqual(fsck.returncode, 0, fsck.stdout)

    def test_exclusion_rules(self):
        for path in ("tmp/x", "run", "etc/hostname", "etc/resolv.conf", "home/mint/.cache/uv",
                     "var/lib/apt/lists/a", "etc/group", "etc/subuid-", "var/log/syslog"):
            self.assertTrue(ow.is_excluded(path), path)
        for path in ("home/mint/.local/share/rescue-omes/hermes/env", "usr/local/bin/hermes",
                     "etc/xdg/autostart/x.desktop", "var/lib/dpkg/status", "etc/sudoers.d/casper"):
            self.assertFalse(ow.is_excluded(path), path)
        self.assertFalse(ow.is_excluded("var/log/sub", is_dir=True))

    def test_cli_convert_writes_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp, "layer.tar")
            self.make_layer(src)
            r = run(["python3", SCRIPTS / "lib" / "overlay_whiteouts.py", "convert", src,
                     pathlib.Path(tmp, "f.tar"), pathlib.Path(tmp, "plan.json")])
            self.assertEqual(r.returncode, 0, r.stderr)
            plan = json.loads(pathlib.Path(tmp, "plan.json").read_text())
            self.assertIn("etc/removed.conf", plan["whiteouts"])
            r = run(["python3", SCRIPTS / "lib" / "overlay_whiteouts.py", "debugfs", pathlib.Path(tmp, "plan.json")])
            self.assertIn("mknod removed.conf c 0 0\n", r.stdout)
            self.assertIn("ea_set /upper/var/lib/opaquedir trusted.overlay.opaque y\n", r.stdout)
            upper = pathlib.Path(tmp, "upper")
            upper.mkdir()
            r = run(["python3", SCRIPTS / "lib" / "overlay_whiteouts.py", "prepare",
                     pathlib.Path(tmp, "plan.json"), upper])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((upper / "etc").is_dir())


@unittest.skipUnless(HAVE_GPG, "gpg is required")
class PrepareVentoyPersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(cls.tmp.name)
        cls.gpghome = base / "gnupg"
        cls.gpghome.mkdir(mode=0o700)
        r = run(["gpg", "--homedir", cls.gpghome, "--batch", "--pinentry-mode", "loopback",
                 "--passphrase", "", "--quick-gen-key", "Test <t@example.invalid>",
                 "default", "default", "never"])
        if r.returncode != 0:
            raise unittest.SkipTest("cannot create throwaway GPG key: " + r.stderr)
        r = run(["gpg", "--homedir", cls.gpghome, "--batch", "--with-colons", "--list-secret-keys"])
        cls.fpr = [ln.split(":")[9] for ln in r.stdout.splitlines() if ln.startswith("fpr:")][0]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(dir=self.tmp.name))
        # A private copy of the scripts so a host/ directory can be simulated.
        self.repo = self.work / "repo"
        shutil.copytree(SCRIPTS, self.repo / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        self.iso = self.work / "linuxmint-test-xfce.iso"
        self.iso.write_bytes(b"fake iso content\n" * 100)
        digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.sums = self.work / "sha256sum.txt"
        self.sums.write_text(f"{digest}  linuxmint-test-xfce.iso\n")
        self.sig = self.work / "sha256sum.txt.gpg"
        r = run(["gpg", "--homedir", self.gpghome, "--batch", "--yes", "--output", self.sig,
                 "--detach-sign", self.sums])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.mnt = self.work / "usb"
        (self.mnt / "ventoy").mkdir(parents=True)
        bindir = self.work / "bin"
        bindir.mkdir()
        (bindir / "mountpoint").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "mountpoint").chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        self.image = self.work / "persist.dat"
        fake_ext_image(self.image)

    def prepare(self, *extra):
        return run([self.repo / "scripts" / "prepare-ventoy-usb.sh", "--ventoy-mount", self.mnt,
                    "--mint-iso", self.iso, "--sha256sums", self.sums, "--signature", self.sig,
                    "--gpg-homedir", self.gpghome, "--signer-fingerprint", self.fpr,
                    "--no-provision-secrets", *extra], env=self.env)

    def config(self):
        return json.loads((self.mnt / "ventoy" / "ventoy.json").read_text())

    def test_persistence_is_merged_next_to_control_and_other_keys(self):
        (self.mnt / "ventoy" / "ventoy.json").write_text(json.dumps({
            "theme": {"display_mode": "GUI"},
            "persistence": [{"image": "/ISO/other.iso", "backend": "/persistence/other.dat"}],
            "control": [{"VTOY_SECONDARY_BOOT_MENU": "0"}],
        }))
        r = self.prepare("--persistence", self.image)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("read-back: PASS", r.stdout)
        config = self.config()
        self.assertEqual(config["theme"], {"display_mode": "GUI"})
        self.assertIn({"VTOY_SECONDARY_BOOT_MENU": "0"}, config["control"])
        self.assertIn({"VTOY_DEFAULT_IMAGE": "/ISO/LinuxMintXFCE/linuxmint-test-xfce.iso"}, config["control"])
        entries = config["persistence"]
        self.assertIn({"image": "/ISO/other.iso", "backend": "/persistence/other.dat"}, entries)
        self.assertIn({"image": "/ISO/LinuxMintXFCE/linuxmint-test-xfce.iso",
                       "backend": "/persistence/rescue-omes-casper-rw.dat",
                       "autosel": 1, "timeout": 0}, entries)
        self.assertEqual(len(entries), 2)
        self.assertFalse((self.mnt / "ventoy.json").exists())
        copied = self.mnt / "persistence" / "rescue-omes-casper-rw.dat"
        self.assertEqual(copied.read_bytes(), self.image.read_bytes())

    def test_without_flag_there_is_no_persistence_entry(self):
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("persistence", self.config())
        self.assertFalse((self.mnt / "persistence").exists())

    def test_persistence_entry_replaces_same_image_and_works_without_auto_boot(self):
        self.assertEqual(self.prepare("--persistence", self.image).returncode, 0)
        r = self.prepare("--persistence", self.image, "--replace-persistence", "--no-auto-boot")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.config()["persistence"]), 1)

    def test_existing_persistence_on_usb_is_not_overwritten_by_default(self):
        target = self.mnt / "persistence" / "rescue-omes-casper-rw.dat"
        target.parent.mkdir()
        target.write_bytes(b"hermes memory")
        r = self.prepare("--persistence", self.image)
        self.assertEqual(r.returncode, 1)
        self.assertIn("--replace-persistence", r.stderr)
        self.assertEqual(target.read_bytes(), b"hermes memory")
        self.assertFalse((self.mnt / "ISO").exists())

    def test_invalid_images_are_rejected_before_copying_anything(self):
        bad_magic = self.work / "bad-magic.dat"
        fake_ext_image(bad_magic, magic=0x1234)
        bad_label = self.work / "bad-label.dat"
        fake_ext_image(bad_label, label=b"other")
        tiny = self.work / "tiny.dat"
        tiny.write_bytes(b"x")
        for image in (bad_magic, bad_label, tiny):
            with self.subTest(image=image.name):
                r = self.prepare("--persistence", image)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertFalse((self.mnt / "ISO").exists())
                self.assertFalse((self.mnt / "persistence").exists())
        r = self.prepare("--persistence", self.work / "missing.dat")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_host_launchers_are_copied_to_usb_root_when_host_exists(self):
        host = self.repo / "host"
        host.mkdir()
        for name in ("RESCUE-WINDOWS.cmd", "RESCUE-MACOS.command", "rescue-linux.sh", "notes.txt"):
            (host / name).write_text(f"launcher {name}\n")
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("RESCUE-WINDOWS.cmd", "RESCUE-MACOS.command", "rescue-linux.sh"):
            self.assertEqual((self.mnt / name).read_text(), f"launcher {name}\n")
        self.assertFalse((self.mnt / "notes.txt").exists())
        # host/ is part of the bundle allowlist as well
        self.assertTrue((self.mnt / "rescue-omes" / "host" / "rescue-linux.sh").is_file())

    def test_no_host_directory_is_fine(self):
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.mnt / "rescue-linux.sh").exists())

    def test_bundle_only_includes_host_and_still_excludes_secrets(self):
        host = self.repo / "host"
        host.mkdir()
        (host / "rescue-linux.sh").write_text("#!/bin/sh\n")
        (host / ".env").write_text("OPENCODE_GO_API_KEY=x\n")
        dest = self.work / "bundle"
        r = run([self.repo / "scripts" / "prepare-ventoy-usb.sh", "--bundle-only", dest])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((dest / "host" / "rescue-linux.sh").is_file())
        self.assertFalse((dest / "host" / ".env").exists())


if __name__ == "__main__":
    unittest.main()
