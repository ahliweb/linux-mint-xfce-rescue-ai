#!/usr/bin/env python3
"""Tests for scripts/lib/progress.py, scripts/lib/progress.sh and the progress wiring (stdlib only).

Progress is drawn only on the terminal. Tests redirect it to a file with the RESCUE_PROGRESS_TTY test hook.
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
PY = REPO / "scripts" / "lib" / "progress.py"
SH = REPO / "scripts" / "lib" / "progress.sh"


def load():
    spec = importlib.util.spec_from_file_location("rescue_progress", PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonProgressCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="progress-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tty = self.tmp / "tty"
        self.tty.write_text("")
        self.mod = load()

    def env(self, **extra):
        base = {"TERM": "xterm", "RESCUE_PROGRESS_TTY": str(self.tty), "COLUMNS": "60"}
        base.update(extra)
        return mock.patch.dict(os.environ, base)

    def drawn(self):
        return self.tty.read_bytes().decode("ascii")

    def test_progress_draws_bar_on_the_tty_only(self):
        out, err = io.StringIO(), io.StringIO()
        with self.env(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            bar = self.mod.Progress(4, "scan")
            bar.advance(1, "first")
            bar.set(2, "second")
            bar.close("finished")
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "")
        text = self.drawn()
        self.assertIn("\r[#####---------------]  25%  first", text)
        self.assertIn(" 50%  second", text)
        self.assertIn("[####################] 100%  finished", text)
        self.assertTrue(text.endswith("\n"))
        self.assertTrue(all(ord(c) < 128 for c in text))

    def test_lines_fit_the_terminal_width(self):
        with self.env(COLUMNS="30"):
            bar = self.mod.Progress(2, "x" * 200)
            bar.close()
        for chunk in self.drawn().replace("\n", "\r").split("\r"):
            self.assertLess(len(chunk.rstrip()), 30)

    def test_step_header(self):
        with self.env():
            self.mod.step(3, 7, "Memindai malware / Scanning for malware")
        self.assertEqual(self.drawn(), "[3/7] Memindai malware / Scanning for malware\n")

    def test_disabled_by_env_draws_nothing(self):
        for extra in ({"RESCUE_PROGRESS": "0"}, {"TERM": "dumb"}):
            with self.subTest(extra=extra), self.env(**extra):
                self.mod.step(1, 2, "x")
                bar = self.mod.Progress(3, "x")
                bar.advance()
                bar.close()
                with self.mod.Budget("b", 10):
                    pass
                self.assertEqual(self.drawn(), "")

    def test_no_terminal_is_a_silent_noop(self):
        with self.env(RESCUE_PROGRESS_TTY=str(self.tmp / "missing" / "tty")):
            self.mod.step(1, 2, "x")
            bar = self.mod.Progress(3, "x")
            bar.advance(5, "y")
            bar.set(-4)
            bar.close("z")
            with self.mod.Budget("b", 10) as budget:
                budget.close()
        self.assertEqual(self.drawn(), "")

    def test_budget_caps_at_99_until_closed(self):
        with self.env():
            self.mod.REFRESH_SECONDS = 0.05
            budget = self.mod.Budget("opaque", 1)
            time.sleep(1.3)  # beyond the budget
            budget.close("done")
        text = self.drawn()
        self.assertIn(" 99%  opaque", text)
        self.assertNotIn("100%  opaque", text)
        self.assertIn("100%  done", text)
        self.assertEqual(budget._thread.is_alive(), False)

    def test_budget_context_manager_and_double_close(self):
        with self.env():
            with self.mod.Budget("ctx", 5) as budget:
                pass
            budget.close()
        self.assertIn("100%  ctx", self.drawn())

    def test_never_raises_on_bad_input_or_io_error(self):
        with self.env():
            bar = self.mod.Progress("not a number", None)
            bar.advance("bad")
            bar.set(object())
            bar.close(object())
            budget = self.mod.Budget(None, "nope")
            budget.close()
            self.mod.step(None, object(), None)
        with self.env():
            bar = self.mod.Progress(2, "x")
            bar._d.tty.close()  # every later write fails with ValueError
            bar.advance()
            bar.close()


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class ShellProgressCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="progress-sh-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tty = self.tmp / "tty"
        self.tty.write_text("")

    def run_bash(self, script, **env_extra):
        env = {"PATH": os.environ["PATH"], "TERM": "xterm", "RESCUE_PROGRESS_TTY": str(self.tty)}
        env.update(env_extra)
        return subprocess.run(["bash", "-c", "set -Eeuo pipefail\nsource %s\n%s" % (SH, script)], env=env,
                              capture_output=True, text=True, timeout=60, cwd=self.tmp)

    def test_step_prints_plain_line_to_stdout_and_header_to_tty(self):
        res = self.run_bash('rescue_progress_step 3 7 "Memindai malware"')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout, "[3/7] Memindai malware\n")
        self.assertEqual(res.stderr, "")
        self.assertEqual(self.tty.read_text(), "[3/7] Memindai malware\n")

    def test_run_returns_exit_code_and_keeps_command_output(self):
        res = self.run_bash('rc=0\nrescue_progress_run "Work" 5 -- bash -c \'echo out; echo err >&2; exit 7\' || rc=$?\n'
                            'echo "rc=$rc"')
        self.assertEqual(res.stdout, "out\nrc=7\n")
        self.assertEqual(res.stderr, "err\n")
        drawn = self.tty.read_text()
        self.assertIn("Work", drawn)
        self.assertIn("100%", drawn)

    def test_run_draws_elapsed_against_budget(self):
        res = self.run_bash('rescue_progress_run "Slow" 4 -- sleep 2.3')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertRegex(self.tty.read_text(), r"\[#+-+\]\s+\d+%  Slow  00:0[12]/00:04")

    def test_run_leaves_no_drawer_behind(self):
        res = self.run_bash('rescue_progress_run "x" 30 -- true\nsleep 1.2\nsize=$(wc -c < "$RESCUE_PROGRESS_TTY")\n'
                            'sleep 1.2\ntest "$size" = "$(wc -c < "$RESCUE_PROGRESS_TTY")"')
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_disabled_runs_command_silently(self):
        for extra in ({"RESCUE_PROGRESS": "0"}, {"TERM": "dumb"}, {"RESCUE_PROGRESS_TTY": "/nonexistent-dir/tty"}):
            with self.subTest(extra=extra):
                self.tty.write_text("")
                res = self.run_bash('rc=0\nrescue_progress_run "x" 5 -- bash -c "exit 3" || rc=$?\n'
                                    'rescue_progress_step 1 2 "plain"\necho "rc=$rc"', **extra)
                self.assertEqual(res.stdout, "[1/2] plain\nrc=3\n")
                self.assertEqual(res.stderr, "")
                self.assertEqual(self.tty.read_text(), "")

    def test_run_without_command_fails(self):
        res = self.run_bash('rc=0\nrescue_progress_run "x" 5 -- || rc=$?\necho "rc=$rc"')
        self.assertEqual(res.stdout, "rc=2\n")


class ConcurrencyCase(unittest.TestCase):
    def test_offline_modules_keep_domain_order_and_hooks_work(self):
        import sys
        import types
        sys.path.insert(0, str(REPO / "scripts"))
        import rescue_modules as rm

        def make(name, delay):
            def fn(ctx, root, target):
                time.sleep(delay)
                return [{"check_id": cid, "status": "pass"} for cid in ids[name]]
            return types.SimpleNamespace(collect_offline_target=fn)

        ids = {"operating_system": ["os-detection"], "software": ["encryption-status"], "malware": ["malware-scan"],
               "printer": ["os-detection"]}
        mods = {n: make(n, d) for n, d in (("operating_system", 0.15), ("software", 0.05), ("malware", 0.0),
                                           ("printer", 0.1))}
        notes, ctx = [], rm.Context(mode="live")
        ctx.progress_note = notes.append
        with mock.patch.object(rm, "_modules", lambda c: iter(mods.items())):
            first = rm.collect_offline_target(ctx, "/x", {"family": "windows"})
            second = rm.collect_offline_target(ctx, "/x", {"family": "windows"})
        self.assertEqual(first, second)
        self.assertEqual([c["check_id"] for c in first],
                         ["os-detection", "encryption-status", "malware-scan", "os-detection"])
        self.assertEqual(notes, ["malware scan", "malware scan"])

    def test_a_failing_module_is_dropped_not_fatal(self):
        import sys
        import types
        sys.path.insert(0, str(REPO / "scripts"))
        import rescue_modules as rm

        def boom(ctx, root, target):
            raise RuntimeError("x")

        mods = {"software": types.SimpleNamespace(collect_offline_target=boom),
                "malware": types.SimpleNamespace(collect_offline_target=lambda c, r, t: [
                    {"check_id": "malware-scan", "status": "unknown"}])}
        ctx = rm.Context(mode="live")
        with mock.patch.object(rm, "_modules", lambda c: iter(mods.items())):
            out = rm.collect_offline_target(ctx, "/x", {})
        self.assertEqual(out, [{"check_id": "malware-scan", "status": "unknown"}])
        self.assertTrue(ctx.warnings)


class WiringCase(unittest.TestCase):
    def test_scripts_fall_back_when_the_helper_is_missing(self):
        # old bundles: scan-target-os.py and the analyzer must not import-fail without progress.py
        for name in ("scan-target-os.py", "opencode-go-analyze.py", "check-hardware-readiness.py"):
            text = (REPO / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn("progress", text)
            self.assertIn("except Exception", text)

    def test_scan_progress_never_reaches_stdout_or_stderr(self):
        tty = Path(tempfile.mkdtemp(prefix="progress-scan-")) / "tty"
        self.addCleanup(shutil.rmtree, tty.parent, True)
        tty.write_text("")
        env = dict(os.environ, TERM="xterm", RESCUE_PROGRESS_TTY=str(tty))
        fx = tty.parent / "fx"
        (fx / "win" / "Windows" / "System32" / "config").mkdir(parents=True)
        (fx / "win" / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"")
        (fx / "win.meta.json").write_text('{"fstype": "ntfs", "label": "OS", "free_percent": 50}')
        out = tty.parent / "ev.json"
        res = subprocess.run(["python3", str(REPO / "scripts" / "scan-target-os.py"), "--output", str(out),
                              "--fixture-root", str(fx)], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("[1/5]", res.stdout + res.stderr)
        self.assertNotIn("\r", res.stdout + res.stderr)
        drawn = tty.read_text()
        self.assertIn("[1/5]", drawn)
        self.assertIn("[5/5]", drawn)
        self.assertIn("os-0", drawn)


if __name__ == "__main__":
    unittest.main()
