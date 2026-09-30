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
        # fail only for a RESOLVED usb disk below the minimum; anything unresolved or non-USB warns
        cases = [
            (("sata", 500.0, "/dev/sda1"), "warn"),
            (("usb", 32.0, "/dev/sdb1"), "pass"),
            (("usb", 4.0, "/dev/sdb1"), "fail"),
            (("", None, "live-media mount was not detected"), "warn"),
            (("", None, ""), "warn"),
            (("unknown", None, "/dev/mapper/ventoy"), "warn"),
            (("usb", None, "/dev/sdb1"), "warn"),
        ]
        for value, expected in cases:
            with self.subTest(value=value), mock.patch.object(self.hw, "storage_for_live_media", return_value=value):
                check = self.hw.check_usb(8.0)
                self.assertEqual(check["status"], expected)
                self.assertTrue(check["required"])

    def test_unresolvable_usb_keeps_observed_format_and_does_not_block(self):
        with mock.patch.object(self.hw, "storage_for_live_media", return_value=("unknown", None, "/dev/mapper/ventoy")):
            check = self.hw.check_usb(8.0)
        self.assertEqual(check["observed"], "transport=unknown, source=/dev/mapper/ventoy")
        self.assertIn("not blocking", check["note"])

    # --- live-media resolution (dm / partition / loop) with mocked lsblk, findmnt and sysfs

    def _mock_system(self, lsblk, findmnt=None, sysfs=None):
        """lsblk: {device: output}; findmnt: {key: output}; sysfs: {loopN: backing_file}."""
        calls = []

        def fake(*args, timeout=8):
            calls.append(args)
            if args[0] == "lsblk":
                return lsblk.get(args[-1], "")
            if args[0] == "findmnt":
                key = args[args.index("-T") + 1] if "-T" in args else args[-1]
                return (findmnt or {}).get(key, "")
            return ""

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for name, backing in (sysfs or {}).items():
            d = Path(tmp.name) / name / "loop"
            d.mkdir(parents=True)
            (d / "backing_file").write_text(backing + "\n")
        return calls, mock.patch.object(self.hw, "command", fake), mock.patch.object(self.hw, "SYSFS_BLOCK", Path(tmp.name))

    def test_ventoy_dm_device_resolves_to_usb_disk_not_iso_size(self):
        gib = 1024 ** 3
        lsblk = {"/dev/mapper/ventoy": f"ventoy dm  {int(2.8 * gib)}\nsda1 part  {30 * gib}\nsda disk usb {32 * gib}\n"}
        calls, cmd, sysfs = self._mock_system(lsblk, findmnt={"/cdrom": "/dev/mapper/ventoy"})
        with cmd, sysfs:
            tran, size, source = self.hw.storage_for_live_media()
            check = self.hw.check_usb(8.0)
        self.assertEqual((tran, round(size)), ("usb", 32))
        self.assertEqual(source, "/dev/mapper/ventoy -> sda")
        self.assertEqual(check["status"], "pass")
        self.assertIn("32.00 GiB", check["observed"])
        # read-only, fixed argv: the device is a single trailing argument, never a shell string
        lsblk_calls = [c for c in calls if c[0] == "lsblk"]
        self.assertTrue(lsblk_calls)
        self.assertTrue(all(c[:6] == ("lsblk", "-b", "-s", "-n", "-r", "-o") for c in lsblk_calls))

    def test_small_resolved_usb_still_fails(self):
        gib = 1024 ** 3
        lsblk = {"/dev/sdb1": f"sdb1 part  {3 * gib}\nsdb disk usb {4 * gib}\n"}
        _, cmd, sysfs = self._mock_system(lsblk, findmnt={"/cdrom": "/dev/sdb1"})
        with cmd, sysfs:
            self.assertEqual(self.hw.check_usb(8.0)["status"], "fail")

    def test_resolved_non_usb_transport_warns(self):
        gib = 1024 ** 3
        lsblk = {"/dev/sda1": f"sda1 part  {100 * gib}\nsda disk sata {500 * gib}\n"}
        _, cmd, sysfs = self._mock_system(lsblk, findmnt={"/cdrom": "/dev/sda1"})
        with cmd, sysfs:
            check = self.hw.check_usb(8.0)
        self.assertEqual(check["status"], "warn")
        self.assertEqual(check["observed"], "transport=sata, source=/dev/sda1 -> sda")

    def test_loop_backing_file_is_followed_to_the_physical_disk(self):
        gib = 1024 ** 3
        lsblk = {"/dev/loop3": f"loop3 loop  {3 * gib}\n",
                 "/dev/sdc2": f"sdc2 part  {60 * gib}\nsdc disk usb {64 * gib}\n"}
        _, cmd, sysfs = self._mock_system(lsblk, findmnt={"/cdrom": "/dev/loop3", "/isos/mint.iso": "/dev/sdc2[/isos]"},
                                          sysfs={"loop3": "/isos/mint.iso"})
        with cmd, sysfs:
            tran, size, _ = self.hw.storage_for_live_media()
        self.assertEqual((tran, round(size)), ("usb", 64))

    def test_loop_chain_is_depth_bounded_and_unresolvable_sources_warn(self):
        lsblk = {"/dev/loop0": "loop0 loop  1000\n", "/dev/loop1": "loop1 loop  1000\n"}
        # loop0 -> file on loop1 -> file on loop0 -> ... must terminate
        _, cmd, sysfs = self._mock_system(lsblk, findmnt={"/cdrom": "/dev/loop0", "/a": "/dev/loop1", "/b": "/dev/loop0"},
                                          sysfs={"loop0": "/a", "loop1": "/b"})
        with cmd, sysfs:
            self.assertIsNone(self.hw.resolve_physical_disk("/dev/loop0"))
            tran, size, source = self.hw.storage_for_live_media()
            self.assertEqual((tran, size, source), ("unknown", None, "/dev/loop0"))
            self.assertEqual(self.hw.check_usb(8.0)["status"], "warn")
        # not a /dev path (for example an overlay/tmpfs name) and empty lsblk output both stay unresolved
        with mock.patch.object(self.hw, "command", lambda *a, **k: ""):
            self.assertIsNone(self.hw.resolve_physical_disk("overlay"))
            self.assertIsNone(self.hw.resolve_physical_disk("/dev/nothing"))

    def test_network_is_advisory_and_warns_when_offline(self):
        with mock.patch.object(self.hw, "command", return_value=""), \
                mock.patch.object(self.hw.socket, "getaddrinfo", side_effect=self.hw.socket.gaierror), \
                mock.patch.object(self.hw.urllib.request, "urlopen", side_effect=OSError("down")):
            check = self.hw.check_network("https://opencode.ai")
        self.assertEqual((check["status"], check["required"]), ("warn", False))
        self.assertEqual(check["observed"], "default-route=no, dns=no, https=OSError")
        self.assertIn("OpenCode Go", check["note"])
        self.assertIn("Hermes", check["note"])

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

            # offline (network warn) and an unresolvable USB warn never block: exit 0, ready_with_warnings
            code, _ = self._run_main(["--output", str(out)], dict(ok, net="warn", usb="warn"))
            self.assertEqual(code, 0)
            summary = json.loads(out.read_text())["summary"]
            self.assertEqual((summary["overall"], summary["failures"], summary["warnings"]), ("ready_with_warnings", 0, 2))

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
