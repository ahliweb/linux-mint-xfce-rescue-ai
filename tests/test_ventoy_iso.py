"""Offline tests for the Ventoy/Mint ISO scripts (no network, root, or block devices)."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
MINT_FPR = "27DEB15644C6B3CF3BD7D291300F846BA25BAE09"
HAVE_GPG = shutil.which("gpg") is not None


def run(args, cwd=None, env=None):
    return subprocess.run(
        [str(a) for a in args], cwd=cwd, env=env, capture_output=True, text=True, timeout=120
    )


@unittest.skipUnless(HAVE_GPG, "gpg is required")
class VerifyMintIsoTests(unittest.TestCase):
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
        fprs = [ln.split(":")[9] for ln in r.stdout.splitlines() if ln.startswith("fpr:")]
        cls.fpr = fprs[0]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(dir=self.tmp.name))
        self.isodir = self.work / "isos"
        self.isodir.mkdir()
        self.cwd = self.work / "cwd"
        self.cwd.mkdir()
        self.iso = self.isodir / "linuxmint-test-xfce.iso"
        self.iso.write_bytes(b"fake iso content\n" * 100)
        self.sums = self.work / "sha256sum.txt"
        self.sig = self.work / "sha256sum.txt.gpg"

    def write_sums(self, text=None):
        digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.sums.write_text(text if text is not None else
                             f"{digest}  linuxmint-test-xfce.iso\n{'0' * 64} *other.iso\n")
        if self.sig.exists():
            self.sig.unlink()
        r = run(["gpg", "--homedir", self.gpghome, "--batch", "--yes", "--output", self.sig,
                 "--detach-sign", self.sums])
        self.assertEqual(r.returncode, 0, r.stderr)

    def verify(self, *extra, fpr=True):
        args = [SCRIPTS / "verify-mint-iso.sh", "--iso", self.iso, "--sha256sums", self.sums,
                "--signature", self.sig, "--gpg-homedir", self.gpghome]
        if fpr:
            args += ["--signer-fingerprint", self.fpr]
        return run(args + list(extra), cwd=self.cwd)

    def test_prepare_writes_ventoy_json_where_ventoy_reads_it(self):
        self.write_sums()
        mnt = self.work / "usb"
        (mnt / "ventoy").mkdir(parents=True)
        bindir = self.work / "bin"
        bindir.mkdir()
        (bindir / "mountpoint").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "mountpoint").chmod(0o755)
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        r = run([SCRIPTS / "prepare-ventoy-usb.sh", "--ventoy-mount", mnt, "--mint-iso", self.iso,
                 "--sha256sums", self.sums, "--signature", self.sig, "--gpg-homedir", self.gpghome,
                 "--signer-fingerprint", self.fpr, "--no-provision-secrets"], env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((mnt / "ventoy.json").exists())
        config = json.loads((mnt / "ventoy" / "ventoy.json").read_text())
        self.assertIn({"VTOY_DEFAULT_IMAGE": "/ISO/LinuxMintXFCE/linuxmint-test-xfce.iso"},
                      config["control"])

    def test_pass_with_iso_in_other_directory(self):
        self.write_sums()
        r = self.verify()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("verification: PASS", r.stdout)

    def test_fingerprint_is_normalized(self):
        self.write_sums()
        spaced = " ".join(self.fpr[i:i + 4] for i in range(0, len(self.fpr), 4)).lower()
        r = self.verify("--signer-fingerprint", spaced)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_star_binary_format(self):
        digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.write_sums(f"{digest} *linuxmint-test-xfce.iso\n")
        self.assertEqual(self.verify().returncode, 0)

    def test_tampered_iso_fails(self):
        self.write_sums()
        self.iso.write_bytes(self.iso.read_bytes() + b"tamper")
        r = self.verify()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISMATCH", r.stderr)

    def test_default_mint_fingerprint_rejects_other_signer(self):
        self.write_sums()
        r = self.verify(fpr=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unexpected key", r.stderr)

    def test_missing_entry_fails(self):
        self.write_sums(f"{'1' * 64}  something-else.iso\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_duplicate_entry_fails(self):
        digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.write_sums(f"{digest}  linuxmint-test-xfce.iso\n{digest}  linuxmint-test-xfce.iso\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_tampered_sums_fails_signature(self):
        self.write_sums()
        self.sums.write_text(self.sums.read_text() + "\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_invalid_fingerprint_rejected(self):
        self.write_sums()
        self.assertEqual(self.verify("--signer-fingerprint", "nothex").returncode, 2)

    def test_default_fingerprint_constant(self):
        self.assertIn(MINT_FPR, (SCRIPTS / "verify-mint-iso.sh").read_text())


class InstallVentoyUsbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Fake sudo on PATH: if the script ever reaches it, the test fails.
        self.bindir = pathlib.Path(self.tmp.name) / "bin"
        self.bindir.mkdir()
        self.marker = pathlib.Path(self.tmp.name) / "sudo-called"
        sudo = self.bindir / "sudo"
        sudo.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nexit 99\n")
        sudo.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bindir}:{os.environ['PATH']}")
        self.vdir = pathlib.Path(self.tmp.name) / "ventoy"
        self.vdir.mkdir()

    def call(self, *args):
        r = run([SCRIPTS / "install-ventoy-usb.sh", *args], env=self.env)
        self.assertFalse(self.marker.exists(), "sudo must not be invoked")
        return r

    def test_refuses_without_yes(self):
        r = self.call("--device", "/dev/null", "--ventoy-dir", self.vdir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--yes", r.stderr)

    def test_refuses_non_block_device(self):
        r = self.call("--device", "/dev/null", "--ventoy-dir", self.vdir, "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Not a block device", r.stderr)

    def test_refuses_regular_file(self):
        f = pathlib.Path(self.tmp.name) / "disk.img"
        f.write_bytes(b"x")
        r = self.call("--device", f, "--ventoy-dir", self.vdir, "--yes")
        self.assertNotEqual(r.returncode, 0)

    def test_requires_arguments(self):
        self.assertEqual(self.call().returncode, 2)


BLOCK_DEV = next((d for d in ("/dev/sda", "/dev/vda", "/dev/nvme0n1", "/dev/loop0")
                  if pathlib.Path(d).is_block_device()), None)


class PrepareVentoyMountDetectionTests(unittest.TestCase):
    """A fresh Ventoy data partition is empty; detection must use partition labels."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name)
        self.bindir = base / "bin"
        self.bindir.mkdir()
        self.mnt = base / "mnt"
        self.mnt.mkdir()
        self.iso = base / "x.iso"
        self.iso.write_bytes(b"iso")

    def stub(self, name, body):
        p = self.bindir / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)

    def prepare(self, source, data_label, efi_label):
        self.stub("mountpoint", "exit 0")
        self.stub("findmnt", f"echo {source}")
        self.stub("lsblk", f"""case "$*" in
  *PKNAME*) echo fake ;;
  *LABEL*/dev/fake*) printf '%s\\n%s\\n' '{data_label}' '{efi_label}' ;;
  *LABEL*) echo '{data_label}' ;;
esac""")
        env = dict(os.environ, PATH=f"{self.bindir}:{os.environ['PATH']}")
        return run([SCRIPTS / "prepare-ventoy-usb.sh", "--ventoy-mount", self.mnt,
                    "--mint-iso", self.iso, "--sha256sums", self.iso, "--signature", self.iso,
                    "--no-provision-secrets"], env=env)

    def test_empty_mount_on_non_block_source_refused(self):
        r = self.prepare("/dev/null", "Ventoy", "VTOYEFI")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not look like a Ventoy", r.stderr)

    @unittest.skipIf(BLOCK_DEV is None, "no block device node for the -b check")
    def test_fresh_ventoy_labels_accepted(self):
        r = self.prepare(BLOCK_DEV, "Ventoy", "VTOYEFI")
        # Detection passes; verification of the bogus ISO then fails, nothing copied.
        self.assertNotIn("does not look like a Ventoy", r.stderr)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(list(self.mnt.iterdir()), [])

    @unittest.skipIf(BLOCK_DEV is None, "no block device node for the -b check")
    def test_missing_vtoyefi_sibling_refused(self):
        r = self.prepare(BLOCK_DEV, "Ventoy", "OTHER")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not look like a Ventoy", r.stderr)

    @unittest.skipIf(BLOCK_DEV is None, "no block device node for the -b check")
    def test_wrong_data_label_refused(self):
        r = self.prepare(BLOCK_DEV, "DATA", "VTOYEFI")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not look like a Ventoy", r.stderr)


class PrepareVentoyUsbBundleTests(unittest.TestCase):
    def test_allowlisted_bundle_copy(self):
        with tempfile.TemporaryDirectory() as td:
            repo = pathlib.Path(td) / "repo"
            (repo / "scripts").mkdir(parents=True)
            shutil.copy(SCRIPTS / "prepare-ventoy-usb.sh", repo / "scripts")
            shutil.copy(SCRIPTS / "verify-mint-iso.sh", repo / "scripts")
            files = {
                "AGENTS.md": "a", "README.md": "r", "Makefile": "m",
                "config/hermes-rescue.config.yaml": "y",
                "config/rescue.env.example": "OPENCODE_GO_API_KEY=\n",
                "docs/design.md": "d", "profiles/p/x.md": "p", "rescue-ai/v1/s.json": "{}",
                "tests/test_x.py": "t",
                # excluded material
                ".env": "SECRET=dummy", "config/rescue.env": "OPENCODE_GO_API_KEY=dummy",
                "foo.iso": "iso", "docs/big.img": "img", "docs/a.tar.gz": "gz",
                ".git/config": "g", "scripts/__pycache__/x.pyc": "pyc", "scripts/y.pyc": "pyc",
                "profiles/p/.env": "S=1", "profiles/p/local.env": "S=1",
                "ventoy-download/Ventoy-linux.tar.gz": "v", "evidence/out.json": "{}",
                "untracked-dir/file.txt": "u",
            }
            for rel, content in files.items():
                p = repo / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            dest = pathlib.Path(td) / "dest" / "rescue-omes"
            r = run([repo / "scripts" / "prepare-ventoy-usb.sh", "--bundle-only", dest])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            got = {str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()}
            for rel in ("AGENTS.md", "README.md", "Makefile", "config/hermes-rescue.config.yaml",
                        "config/rescue.env.example", "docs/design.md", "profiles/p/x.md",
                        "rescue-ai/v1/s.json", "tests/test_x.py", "scripts/prepare-ventoy-usb.sh",
                        "scripts/verify-mint-iso.sh"):
                self.assertIn(rel, got)
            for rel in (".env", "config/rescue.env", "foo.iso", "docs/big.img", "docs/a.tar.gz",
                        ".git/config", "scripts/y.pyc", "profiles/p/.env", "profiles/p/local.env",
                        "ventoy-download/Ventoy-linux.tar.gz", "evidence/out.json",
                        "untracked-dir/file.txt"):
                self.assertNotIn(rel, got)
            self.assertFalse(any("__pycache__" in g for g in got))
            self.assertFalse((dest / ".git").exists())
            self.assertFalse(any(g.endswith(".env") for g in got))

    def test_bundle_only_refuses_non_empty_destination(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "keep.txt").write_text("x")
            r = run([SCRIPTS / "prepare-ventoy-usb.sh", "--bundle-only", td])
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue((pathlib.Path(td) / "keep.txt").exists())

    def test_real_repo_bundle_has_no_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            dest = pathlib.Path(td) / "b"
            r = run([SCRIPTS / "prepare-ventoy-usb.sh", "--bundle-only", dest])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            names = [p.name for p in dest.rglob("*")]
            self.assertNotIn("rescue.env", names)
            self.assertNotIn(".env", names)
            self.assertFalse(any(n.endswith(".iso") for n in names))
            self.assertFalse((dest / ".git").exists())


class DownloadVentoyTests(unittest.TestCase):
    def _reject(self, version):
        with tempfile.TemporaryDirectory() as td:
            # Broken proxy env proves validation happens before any network use.
            env = dict(os.environ, HTTPS_PROXY="http://127.0.0.1:9", https_proxy="http://127.0.0.1:9")
            r = run([SCRIPTS / "download-ventoy.sh", "--output-dir", td + "/out", "--version", version],
                    env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Invalid --version", r.stderr)
            self.assertFalse(pathlib.Path(td, "out").exists())

    def test_rejects_path_traversal_version(self):
        self._reject("../x")

    def test_rejects_other_bad_versions(self):
        for v in ("1.0.99/../../x", "v1.0.9;id", "latest", "1..", "v"):
            with self.subTest(v=v):
                self._reject(v)

    def test_single_api_call_in_source(self):
        src = (SCRIPTS / "download-ventoy.sh").read_text()
        self.assertEqual(len(re.findall(r"urllib\.request\.urlopen", src)), 1)
        self.assertIn("https://github.com/ventoy/Ventoy/releases/download/", src)


if __name__ == "__main__":
    unittest.main()
