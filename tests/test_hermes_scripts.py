#!/usr/bin/env python3
"""Source-level tests for the Hermes rescue shell scripts (stdlib only).

No network, no real hermes, dummy secrets only. When the suite runs as root the
scripts (which refuse root) are executed through ``setpriv`` as uid 65534.
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DUMMY_KEY = "dummy-test-key-123"
UNPRIV_ID = "65534"
COPY_DIRS = ("scripts", "rescue-ai", "profiles", "config", "docs")


def _can_run_unprivileged():
    if os.geteuid() != 0:
        return True
    return shutil.which("setpriv") is not None


@unittest.skipUnless(_can_run_unprivileged(), "need a non-root user or setpriv")
class HermesScriptTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rescue-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._open(self.tmp)
        # Private copy of the source tree so the installer may write config/rescue.env.
        self.src = self.tmp / "src"
        self.src.mkdir()
        for name in COPY_DIRS:
            shutil.copytree(
                REPO / name, self.src / name,
                ignore=shutil.ignore_patterns("__pycache__", "rescue.env", ".env"),
            )
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.state = self.tmp / "state with space"
        self.prefix = self.tmp / "prefix"
        self.bin = self.tmp / "bin"
        self.shims = self.tmp / "shims"
        self.shims.mkdir()
        self._open(self.tmp, recursive=True)

    @staticmethod
    def _open(path, recursive=False):
        """Make files reachable by the unprivileged user when tests run as root."""
        if os.geteuid() != 0:
            return
        paths = [path]
        if recursive:
            paths = [path] + [p for p in path.rglob("*") if not p.is_symlink()]
        for p in paths:
            mode = stat.S_IMODE(p.stat().st_mode)
            new = mode | 0o777 if p.is_dir() else mode | 0o644 | (0o111 if mode & 0o100 else 0)
            os.chmod(p, new)
            os.chown(p, int(UNPRIV_ID), int(UNPRIV_ID))

    def run_cmd(self, argv, env_extra=None, path=None, stdin=None):
        env = {
            "HOME": str(self.home),
            "PATH": path if path is not None else "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C",
        }
        env.update(env_extra or {})
        cmd = [str(a) for a in argv]
        if os.geteuid() == 0:
            cmd = ["setpriv", f"--reuid={UNPRIV_ID}", f"--regid={UNPRIV_ID}", "--clear-groups"] + cmd
        return subprocess.run(
            cmd, env=env, input=stdin, capture_output=True, text=True, timeout=60, cwd=str(self.tmp)
        )

    def install(self, *extra):
        script = self.src / "scripts" / "install-hermes-rescue.sh"
        args = [
            script, "--state-dir", self.state, "--prefix", self.prefix,
            "--bin-dir", self.bin, "--skip-hermes-install",
        ] + list(extra)
        return self.run_cmd(args)

    def write_shim(self, name, body):
        shim = self.shims / name
        shim.write_text("#!/bin/sh\n" + body)
        shim.chmod(0o755)
        self._open(shim)


class TestRescueLoadEnv(HermesScriptTestCase):
    def load(self, content, mode=0o600, preset=None, extra_script=""):
        env_file = self.tmp / "test.env"
        env_file.write_text(content)
        os.chmod(env_file, mode)
        self._open(env_file)
        os.chmod(env_file, mode)
        lib = self.src / "scripts" / "lib" / "rescue-env.sh"
        script = (
            f'source "{lib}"; rescue_load_env "{env_file}"; rc=$?; '
            'for k in OPENCODE_GO_API_KEY RESCUE_STATE_DIR HERMES_HOME OPENCODE_ADAPTER_COMMAND '
            'OPENCODE_TIMEOUT_SECONDS EVIL; do printf "%s=[%s]\\n" "$k" "${!k-}"; done; '
            f'echo "rc=$rc"; {extra_script}'
        )
        result = self.run_cmd(["bash", "-c", script], env_extra=preset)
        values = dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )
        return result, {k: v[1:-1] if v.startswith("[") else v for k, v in values.items()}

    def test_parses_allowlisted_keys_and_quotes(self):
        result, v = self.load(
            "# comment\n\n"
            "OPENCODE_GO_API_KEY='k'\\''ey'\n"
            "export RESCUE_STATE_DIR=\"/tmp/a b\"\n"
            "HERMES_HOME=/tmp/with\\ space\n"
            "OPENCODE_TIMEOUT_SECONDS=30  # trailing comment\n"
            "EVIL='nope'\n"
            "OPENCODE_ADAPTER_COMMAND=cat\n"
        )
        self.assertEqual(v["rc"], "0", result.stderr)
        self.assertEqual(v["OPENCODE_GO_API_KEY"], "k'ey")
        self.assertEqual(v["RESCUE_STATE_DIR"], "/tmp/a b")
        self.assertEqual(v["HERMES_HOME"], "/tmp/with space")
        self.assertEqual(v["OPENCODE_TIMEOUT_SECONDS"], "30")
        self.assertEqual(v["OPENCODE_ADAPTER_COMMAND"], "cat")
        self.assertEqual(v["EVIL"], "")

    def test_handles_printf_q_output(self):
        result, v = self.load("OPENCODE_GO_API_KEY=a\\$b\\ c\;d\n")
        self.assertEqual(v["OPENCODE_GO_API_KEY"], "a$b c;d")

    def test_does_not_execute_payloads(self):
        marker = self.tmp / "pwned"
        result, v = self.load(
            f"OPENCODE_GO_API_KEY=$(touch {marker})\n"
            f"RESCUE_STATE_DIR=\"`touch {marker}`\"\n"
            f"HERMES_HOME='$(touch {marker})'\n"
            f"EVIL=$(touch {marker})\n"
            f"$(touch {marker})\n"
            f"touch {marker}\n"
        )
        self.assertFalse(marker.exists(), "payload was executed")
        self.assertEqual(v["OPENCODE_GO_API_KEY"], "")
        self.assertEqual(v["RESCUE_STATE_DIR"], "")
        self.assertEqual(v["HERMES_HOME"], f"$(touch {marker})")  # single quotes stay literal data

    def test_existing_environment_wins(self):
        result, v = self.load(
            "OPENCODE_GO_API_KEY=from-file\nRESCUE_STATE_DIR=/from/file\n",
            preset={"OPENCODE_GO_API_KEY": "from-env"},
        )
        self.assertEqual(v["OPENCODE_GO_API_KEY"], "from-env")
        self.assertEqual(v["RESCUE_STATE_DIR"], "/from/file")

    def test_rejects_world_writable_file(self):
        result, v = self.load("OPENCODE_GO_API_KEY=abc\n", mode=0o666)
        self.assertEqual(v["rc"], "1")
        self.assertEqual(v["OPENCODE_GO_API_KEY"], "")
        self.assertIn("world-writable", result.stderr)

    def test_missing_file_is_fine(self):
        lib = self.src / "scripts" / "lib" / "rescue-env.sh"
        result = self.run_cmd(["bash", "-c", f'source "{lib}"; rescue_load_env "{self.tmp}/nope"'])
        self.assertEqual(result.returncode, 0)

    def test_desktop_quote(self):
        lib = self.src / "scripts" / "lib" / "rescue-env.sh"
        script = (
            f'source "{lib}"; rescue_desktop_quote "/plain/path"; echo; '
            'rescue_desktop_quote "/a b/c"; echo; rescue_desktop_quote \'/x"y$z\'; echo; '
            'rescue_desktop_quote "/p%q" || echo REFUSED-PCT; '
            'rescue_desktop_quote $\'/n\\nl\' || echo REFUSED-NL'
        )
        result = self.run_cmd(["bash", "-c", script])
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], "/plain/path")
        self.assertEqual(lines[1], '"/a b/c"')
        self.assertEqual(lines[2], '"/x\\\\"y\\\\$z"')
        self.assertIn("REFUSED-PCT", lines)
        self.assertIn("REFUSED-NL", lines)


class TestInstalledBundle(HermesScriptTestCase):
    def test_install_creates_bundle_symlinks_state_and_autostart(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for rel in (
            "scripts/launch-hermes-rescue.sh", "scripts/check-hermes-rescue.sh",
            "scripts/check-hardware-readiness.py", "scripts/lib/rescue-env.sh",
            "rescue-ai/v1/rescue-evidence.schema.json", "profiles/rescue-hermes/SOUL.md",
            "config/hermes-rescue.config.yaml", "config/rescue.env.example",
            "docs/run-report.md", "docs/malware.md",  # the run report cites docs/ paths; they must exist in the runtime bundle
        ):
            self.assertTrue((self.prefix / rel).is_file(), rel)
        names = {p.name for p in self.prefix.rglob("*")}
        self.assertNotIn("rescue.env", names)
        self.assertNotIn(".env", names)
        for tool in ("launch-hermes-rescue.sh", "check-hermes-rescue.sh"):
            link = self.bin / tool
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.path.realpath(link), os.path.realpath(self.prefix / "scripts" / tool))
        env_file = self.state / "hermes" / "env"
        self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
        self.assertNotIn("export", env_file.read_text())
        # Every skill shipped in the profile is installed into the Hermes state.
        shipped = sorted(p.parent.name for p in (self.src / "profiles/rescue-hermes/skills").glob("*/SKILL.md"))
        installed = sorted(p.parent.name for p in (self.state / "hermes/skills").glob("*/SKILL.md"))
        self.assertEqual(installed, shipped)
        self.assertIn("rescue-target-os", installed)
        desktop = self.home / ".config" / "autostart" / "hermes-rescue.desktop"
        exec_line = next(l for l in desktop.read_text().splitlines() if l.startswith("Exec="))
        self.assertIn(f'--state-dir "{self.state}"', exec_line)
        self.assertIn("--hardware-mode auto", exec_line)
        verify = self.run_cmd(
            [self.src / "scripts" / "verify-autostart.sh", "--state-dir", self.state]
        )
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("PASS", verify.stdout)
        verify_bin = self.run_cmd(
            [self.prefix / "scripts" / "verify-autostart.sh", "--state-dir", self.state, "--bin-dir", self.bin]
        )
        self.assertEqual(verify_bin.returncode, 0, verify_bin.stdout + verify_bin.stderr)
        bad = self.run_cmd(
            [self.src / "scripts" / "verify-autostart.sh", "--state-dir", self.tmp / "other"]
        )
        self.assertNotEqual(bad.returncode, 0)

    def test_installer_key_roundtrip_and_no_autostart(self):
        env = {"OPENCODE_GO_API_KEY": "dummy'quote key"}
        script = self.src / "scripts" / "install-hermes-rescue.sh"
        result = self.run_cmd(
            [script, "--state-dir", self.state, "--prefix", self.prefix, "--bin-dir", self.bin,
             "--skip-hermes-install", "--no-autostart"], env_extra=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.home / ".config" / "autostart" / "hermes-rescue.desktop").exists())
        lib = self.src / "scripts" / "lib" / "rescue-env.sh"
        out = self.run_cmd(["bash", "-c", f'source "{lib}"; rescue_load_env "{self.state}/hermes/env"; printf %s "$OPENCODE_GO_API_KEY"'])
        self.assertEqual(out.stdout, "dummy'quote key")

    def test_installer_refuses_bad_state_dir(self):
        script = self.src / "scripts" / "install-hermes-rescue.sh"
        result = self.run_cmd(
            [script, "--state-dir", self.tmp / "100%bad", "--prefix", self.prefix,
             "--bin-dir", self.bin, "--skip-hermes-install"])
        self.assertEqual(result.returncode, 2)

    def test_symlinked_launcher_resolves_bundle_root(self):
        self.assertEqual(self.install().returncode, 0)
        result = self.run_cmd(
            [self.bin / "check-hermes-rescue.sh", "--state-dir", self.state],
            path="/usr/bin:/bin",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Hermes executable not found", result.stdout)

    def test_check_never_puts_key_on_argv(self):
        self.assertEqual(self.install().returncode, 0)
        argv_log = self.tmp / "curl-argv.txt"
        stdin_log = self.tmp / "curl-stdin.txt"
        self.write_shim("hermes", "exit 0\n")
        self.write_shim(
            "curl",
            f'printf "%s\\n" "$@" > "{argv_log}"\ncat > "{stdin_log}"\nprintf 200\n',
        )
        result = self.run_cmd(
            [self.bin / "check-hermes-rescue.sh", "--state-dir", self.state],
            env_extra={"OPENCODE_GO_API_KEY": DUMMY_KEY},
            path=f"{self.shims}:/usr/bin:/bin",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("READY", result.stdout)
        argv = argv_log.read_text()
        self.assertNotIn(DUMMY_KEY, argv)
        self.assertIn("--config", argv)
        self.assertIn(DUMMY_KEY, stdin_log.read_text())
        self.assertNotIn(DUMMY_KEY, result.stdout + result.stderr)

    def test_conversation_dry_run(self):
        self.assertEqual(self.install().returncode, 0)
        result = self.run_cmd(
            [self.prefix / "scripts" / "test-hermes-conversation.sh", "--state-dir", self.state])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DRY RUN", result.stdout)

    def test_launch_uses_bundle_hardware_check_and_blocks_on_failure(self):
        self.assertEqual(self.install().returncode, 0)
        self.write_shim("hermes", "printf 'HERMES-RAN %s\\n' \"$*\"\n")
        result = self.run_cmd(
            [self.bin / "launch-hermes-rescue.sh", "--state-dir", self.state,
             "--min-cpu", "100000"],
            path=f"{self.shims}:/usr/local/bin:/usr/bin:/bin",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("HERMES-RAN", result.stdout)
        self.assertIn("hardware-readiness-", result.stderr)
        self.assertIn("GAGAL", result.stderr)
        self.assertNotIn("No such file", result.stderr)


class TestLauncherValidation(HermesScriptTestCase):
    def test_launch_rejects_non_numeric_thresholds(self):
        launcher = self.src / "scripts" / "launch-hermes-rescue.sh"
        for flag, value in (
            ("--min-cpu", "abc"), ("--min-cpu", "0"), ("--min-ram-gib", "x"),
            ("--min-usb-gib", "0"), ("--min-usb-gib", "-3"),
        ):
            with self.subTest(flag=flag, value=value):
                result = self.run_cmd([launcher, flag, value, "--state-dir", self.state])
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_state_dir_from_rescue_env_is_honored(self):
        # RESCUE_STATE_DIR in config/rescue.env is used when --state-dir is absent.
        target = self.tmp / "configured state"
        (self.src / "config" / "rescue.env").write_text(f"RESCUE_STATE_DIR='{target}'\n")
        os.chmod(self.src / "config" / "rescue.env", 0o600)
        self._open(self.src / "config" / "rescue.env")
        os.chmod(self.src / "config" / "rescue.env", 0o600)
        result = self.run_cmd([self.src / "scripts" / "launch-hermes-rescue.sh"])
        self.assertEqual(result.returncode, 1)
        self.assertIn(str(target), result.stderr)


class TestAnalyzeAdapter(HermesScriptTestCase):
    def test_invalid_evidence_is_not_sent(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{}")
        self._open(bad)
        sink = self.tmp / "sink.txt"
        result = self.run_cmd(
            [self.src / "scripts" / "analyze-opencode-go.sh", bad],
            env_extra={"OPENCODE_ADAPTER_COMMAND": f"cat > {sink}"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sink.exists())

    def test_rejects_bad_timeout(self):
        fixture = self.src / "rescue-ai/v1/fixtures/valid-sanitized-opencode-go.json"
        result = self.run_cmd(
            [self.src / "scripts" / "analyze-opencode-go.sh", fixture],
            env_extra={"OPENCODE_ADAPTER_COMMAND": "cat", "OPENCODE_TIMEOUT_SECONDS": "abc"},
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
