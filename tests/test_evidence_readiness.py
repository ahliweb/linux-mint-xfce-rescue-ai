#!/usr/bin/env python3
"""Tests for evidence collector/validator and the hardware readiness gate (stdlib unittest)."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FIXTURES = ROOT / "rescue-ai" / "v1" / "fixtures"

try:
    import jsonschema  # noqa: F401
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False


def run_validator(*paths):
    return subprocess.run([sys.executable, str(SCRIPTS / "validate-evidence.py"), *map(str, paths)],
                          text=True, capture_output=True, check=False)


def load_hw():
    spec = importlib.util.spec_from_file_location("check_hardware_readiness", SCRIPTS / "check-hardware-readiness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is not installed")
class ValidatorTests(unittest.TestCase):
    def test_valid_fixture(self):
        result = run_validator(FIXTURES / "valid-sanitized-opencode-go.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence: valid", result.stdout)

    def test_invalid_fixture_reports_reason(self):
        result = run_validator(FIXTURES / "invalid-raw-ai-fields.json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        reason = (FIXTURES / "invalid-raw-ai-fields.reason.txt").read_text().strip().lower()
        self.assertIn("additional properties", reason)
        self.assertIn("additional properties", result.stdout.lower())
        self.assertIn("INVALID", result.stdout)

    def test_mixed_files_exit_one(self):
        result = run_validator(FIXTURES / "valid-sanitized-opencode-go.json",
                               FIXTURES / "invalid-raw-ai-fields.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("evidence: valid (", result.stdout)
        self.assertIn("evidence: INVALID (", result.stdout)

    def test_schema_1_1_fixtures_valid(self):
        result = run_validator(FIXTURES / "valid-live-multi-os-1.1.json",
                               FIXTURES / "valid-windows-host-1.1.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_free_text_value_rejected(self):
        result = run_validator(FIXTURES / "invalid-text-value-1.1.json")
        self.assertEqual(result.returncode, 1)

    def _mutated(self, fixture, mutate):
        data = json.loads((FIXTURES / fixture).read_text())
        mutate(data)
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(os.unlink, tmp.name)
        json.dump(data, tmp)
        tmp.close()
        return run_validator(Path(tmp.name))

    def test_dangling_target_ref_rejected(self):
        r = self._mutated("valid-live-multi-os-1.1.json",
                          lambda d: d["checks"][2].__setitem__("target_ref", "os-7"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not match any target_systems", r.stdout)

    def test_duplicate_target_ref_rejected(self):
        r = self._mutated("valid-live-multi-os-1.1.json",
                          lambda d: d["target_systems"][1].__setitem__("ref", "os-0"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("unique", r.stdout)

    def test_version_1_0_cannot_use_1_1_fields(self):
        r = self._mutated("valid-windows-host-1.1.json", lambda d: d.__setitem__("schema_version", "1.0"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("schema_version 1.0", r.stdout)

    def test_entry_count_must_match_checks(self):
        r = self._mutated("valid-windows-host-1.1.json",
                          lambda d: d["evidence_manifest"].__setitem__("entry_count", 99))
        self.assertEqual(r.returncode, 1)
        self.assertIn("entry_count", r.stdout)

    def test_missing_file_exit_two(self):
        result = run_validator(Path(tempfile.gettempdir()) / "definitely-missing-evidence-file.json")
        self.assertEqual(result.returncode, 2)

    def test_malformed_json_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            result = run_validator(bad)
        self.assertEqual(result.returncode, 2)

    def test_no_arguments_is_usage_error(self):
        result = run_validator()
        self.assertEqual(result.returncode, 2)


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is not installed")
class CollectorTests(unittest.TestCase):
    def test_collector_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "evidence.json"
            result = subprocess.run([str(SCRIPTS / "collect-evidence.sh"), "--output", str(out)],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("wrote", result.stdout)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(run_validator(out).returncode, 0)
            data = json.loads(out.read_text())
            self.assertIs(data["verification"]["hashes_verified"], False)
            self.assertEqual(data["verification"]["status"], "not_applicable")
            expected = hashlib.sha256(json.dumps(data["checks"], sort_keys=True).encode()).hexdigest()
            self.assertEqual(data["evidence_manifest"]["manifest_sha256"], expected)
            self.assertEqual(data["evidence_manifest"]["entry_count"], len(data["checks"]))
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["evidence.json"])

    def test_collector_requires_output_value(self):
        result = subprocess.run([str(SCRIPTS / "collect-evidence.sh"), "--output"],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)


class HardwareReadinessTests(unittest.TestCase):
    def setUp(self):
        self.hw = load_hw()

    def test_cpu_threshold(self):
        with mock.patch.object(self.hw.os, "cpu_count", return_value=2):
            self.assertEqual(self.hw.check_cpu(2)["status"], "pass")
            self.assertEqual(self.hw.check_cpu(4)["status"], "fail")
        with mock.patch.object(self.hw.os, "cpu_count", return_value=None):
            self.assertEqual(self.hw.check_cpu(1)["status"], "fail")

    def test_ram_threshold(self):
        with mock.patch.object(self.hw, "read_mem_mib", return_value=4096.0):
            self.assertEqual(self.hw.check_ram(4.0)["status"], "pass")
            self.assertEqual(self.hw.check_ram(8.0)["status"], "fail")
        with mock.patch.object(self.hw, "read_mem_mib", return_value=None):
            self.assertEqual(self.hw.check_ram(4.0)["status"], "unknown")

    def test_usb_behaviour(self):
        cases = [
            (("sata", 500.0, "/dev/sda1"), "fail"),
            (("usb", 32.0, "/dev/sdb1"), "pass"),
            (("usb", 4.0, "/dev/sdb1"), "fail"),
            (("", None, "live-media mount was not detected"), "fail"),
            (("", None, ""), "fail"),
            (("usb", None, "/dev/sdb1"), "unknown"),
        ]
        for value, expected in cases:
            with self.subTest(value=value), mock.patch.object(self.hw, "storage_for_live_media", return_value=value):
                self.assertEqual(self.hw.check_usb(8.0)["status"], expected)

    def _run_main(self, argv, statuses):
        def fake(check_id, status):
            return lambda *a, **k: self.hw.check_result(check_id, status, "fake", "fake")
        patches = [
            mock.patch.object(self.hw, "check_cpu", fake("cpu", statuses["cpu"])),
            mock.patch.object(self.hw, "check_ram", fake("ram", statuses["ram"])),
            mock.patch.object(self.hw, "check_vga", fake("vga-display", statuses["vga"])),
            mock.patch.object(self.hw, "check_network", fake("internet-connectivity", statuses["net"])),
            mock.patch.object(self.hw, "check_usb", fake("usb-boot-media", statuses["usb"])),
            mock.patch.object(sys, "argv", ["check-hardware-readiness.py", *argv]),
        ]
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = self.hw.main()
        return code, stdout.getvalue()

    def test_overall_aggregation_and_report_mode(self):
        ok = dict(cpu="pass", ram="pass", vga="pass", net="pass", usb="pass")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sub" / "report.json"
            code, _ = self._run_main(["--output", str(out)], ok)
            self.assertEqual(code, 0)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            report = json.loads(out.read_text())
            self.assertEqual(report["report_version"], "1.0")
            self.assertEqual(report["summary"]["overall"], "ready")

            bad = dict(ok, usb="fail")
            code, _ = self._run_main(["--output", str(out)], bad)
            self.assertEqual(code, 1)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(json.loads(out.read_text())["summary"]["overall"], "not_ready")

            code, _ = self._run_main(["--output", str(out)], dict(ok, ram="unknown"))
            self.assertEqual(code, 1)

            code, _ = self._run_main(["--output", str(out)], dict(ok, vga="warn"))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text())["summary"]["overall"], "ready_with_warnings")
            self.assertEqual([p.name for p in out.parent.iterdir()], ["report.json"])

    def test_wizard_prompt_shows_real_minimum(self):
        prompts = []

        def fake_input(prompt=""):
            prompts.append(prompt)
            return "n"

        ok = dict(cpu="pass", ram="pass", vga="pass", net="pass", usb="pass")
        with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.input", fake_input):
            code, _ = self._run_main(["--mode", "wizard", "--min-cpu", "3", "--min-ram-gib", "6",
                                      "--min-usb-gib", "16", "--output", str(Path(tmp) / "r.json")], ok)
            report = json.loads((Path(tmp) / "r.json").read_text())
        self.assertEqual(len(prompts), 5)
        joined = "\n".join(prompts)
        self.assertIn(">= 3 logical CPU(s)", joined)
        self.assertIn(">= 6.0 GiB", joined)
        self.assertIn(">= 16.0 GiB", joined)
        self.assertNotIn("configured threshold", joined)
        self.assertTrue(all(c["status"] == "warn" for c in report["checks"]))
        self.assertEqual(code, 0)

    def test_wizard_eof_skips_with_warning(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.input", side_effect=EOFError):
            code, _ = self._run_main(["--mode", "wizard", "--output", str(Path(tmp) / "r.json")],
                                     dict(cpu="pass", ram="pass", vga="pass", net="pass", usb="pass"))
            report = json.loads((Path(tmp) / "r.json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["warnings"], 5)


if __name__ == "__main__":
    unittest.main()
