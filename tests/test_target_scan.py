#!/usr/bin/env python3
"""Tests for scan-target-os.py, opencode-go-analyze.py and the launcher wiring (stdlib only).

No root, no real disks, no mounts, no real network (a loopback http.server stands in
for OpenCode Go) and dummy API keys only.
Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan-target-os.py"
ANALYZE = REPO / "scripts" / "opencode-go-analyze.py"
VALIDATE = REPO / "scripts" / "validate-evidence.py"
PROMPT = REPO / "profiles" / "rescue-hermes" / "analysis-prompt.md"
FIXTURE = REPO / "rescue-ai" / "v1" / "fixtures" / "valid-live-multi-os-1.1.json"
DUMMY_KEY = "dummy-analyze-key-987"
ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
APFS = "7c3457ef-0000-11aa-aa11-00306543ecac"

sys.path.insert(0, str(Path(__file__).resolve().parent))


def load_scan_module():
    spec = importlib.util.spec_from_file_location("scan_target_os", SCAN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def touch(path, data=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def meta(root, name, **kw):
    (root / (name + ".meta.json")).write_text(json.dumps(kw))


SECRETS = ("SecretUser", "secret-host", "confidential-report", "leaky-file.txt")


class ScanFixtureCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="scan-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = self.tmp / "fx"
        self.fx.mkdir()

    def build_windows(self, name="win", **meta_kw):
        root = self.fx / name
        touch(root / "Windows/System32/config/SYSTEM")
        touch(root / "hiberfil.sys", b"hibernation-data")
        touch(root / "Windows/Minidump/one.dmp")
        touch(root / "Windows/Minidump/two.dmp")
        touch(root / "Windows/WinSxS/pending.xml")
        touch(root / "Users/SecretUser/confidential-report.docx")
        meta(self.fx, name, fstype="ntfs", label="OSDISK", free_percent=3.5, **meta_kw)

    def build_mint(self, name="mint", os_id="linuxmint", pretty="Linux Mint 22.3"):
        root = self.fx / name
        touch(root / "usr/lib/os-release", f'PRETTY_NAME="{pretty}"\nID={os_id}\n'.encode())
        (root / "etc").mkdir(parents=True, exist_ok=True)
        os.symlink("../usr/lib/os-release", root / "etc/os-release")
        touch(root / "etc/hostname", b"secret-host\n")
        touch(root / "etc/fstab", (
            "# comment\n"
            "UUID=abcd-1234 / ext4 defaults 0 1\n"
            "UUID=deadbeef-dead-beef /data ext4 defaults 0 2\n"
            "UUID=00000000-optional /opt2 ext4 nofail 0 2\n"
            "tmpfs /tmp tmpfs defaults 0 0\n").encode())
        touch(root / "boot/vmlinuz-6.8.0-1-generic")
        touch(root / "boot/initrd.img-6.8.0-1-generic")
        touch(root / "boot/vmlinuz-6.8.0-2-generic")  # no initrd
        touch(root / "var/lib/dpkg/status", (
            "Package: good\nStatus: install ok installed\n\n"
            "Package: bad\nStatus: install ok half-installed\n\n").encode())
        touch(root / "home/SecretUser/leaky-file.txt")
        meta(self.fx, name, fstype="ext4", uuid="ABCD-1234", free_percent=42)

    def scan(self, extra=None):
        out = self.tmp / "out" / "evidence.json"
        result = subprocess.run(
            [sys.executable, str(SCAN), "--output", str(out), "--fixture-root", str(self.fx)] + (extra or []),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return out, result

    def validate(self, path):
        result = subprocess.run([sys.executable, str(VALIDATE), str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @staticmethod
    def index(data):
        refs = {t["ref"]: t for t in data["target_systems"]}
        checks = {}
        for c in data["checks"]:
            checks[(c.get("target_ref"), c["check_id"])] = c
        return refs, checks

    def ref_of(self, data, family):
        return next(t["ref"] for t in data["target_systems"] if t["family"] == family)


class TestScanFixtures(ScanFixtureCase):
    def setUp(self):
        super().setUp()
        self.build_windows()
        self.build_mint()
        meta(self.fx, "bl", fstype="BitLocker", label="SecretVolume")
        meta(self.fx, "mac", fstype="apfs", parttype=APFS, apfs="unsupported")
        touch(self.fx / "esp/EFI/Microsoft/Boot/bootmgfw.efi")
        touch(self.fx / "esp/EFI/ubuntu/shimx64.efi")
        meta(self.fx, "esp", fstype="vfat", parttype=ESP)

    def test_evidence_validates_and_is_private(self):
        out, _ = self.scan()
        self.validate(out)
        self.assertEqual(oct(out.stat().st_mode & 0o777), "0o600")
        data = json.loads(out.read_text())
        self.assertEqual(data["schema_version"], "1.2")
        self.assertEqual(data["source_platform"], "linux-mint-xfce-live")
        self.assertEqual(data["evidence_manifest"]["storage_class"], "usb-rescue-state")
        self.assertEqual(data["evidence_manifest"]["entry_count"], len(data["checks"]))
        self.assertEqual([t["ref"] for t in data["target_systems"]],
                         ["os-%d" % i for i in range(len(data["target_systems"]))])
        self.assertTrue(all(t["detection"] == "live-offline" for t in data["target_systems"]))

    def test_windows_checks(self):
        data = json.loads(self.scan()[0].read_text())
        refs, checks = self.index(data)
        ref = next(r for r, t in refs.items() if t["family"] == "windows" and t["access"] == "read-only-mounted")
        self.assertEqual(refs[ref]["release"], "Windows")
        self.assertEqual(refs[ref]["encryption"], "none")
        self.assertEqual(checks[(ref, "os-detection")]["status"], "pass")
        self.assertEqual(checks[(ref, "windows-fast-startup")]["status"], "warn")
        self.assertEqual(checks[(ref, "windows-pending-updates")]["status"], "warn")
        dumps = checks[(ref, "windows-crash-dumps")]
        self.assertEqual((dumps["status"], dumps["value"]), ("warn", {"kind": "count", "number": 2}))
        free = checks[(ref, "disk-free-space")]
        self.assertEqual((free["status"], free["value"]["kind"], free["value"]["number"]), ("fail", "percent", 3.5))
        self.assertEqual(checks[(ref, "windows-event-log-errors")]["status"], "unknown")
        self.assertEqual(checks[(ref, "windows-ntfs-dirty")]["status"], "unknown")
        self.assertEqual(checks[(ref, "boot-loader-files")]["status"], "pass")
        for c in data["checks"]:
            if c.get("target_ref") == ref:
                self.assertEqual(c["source"], "offline-target-scan")

    def test_linux_mint_checks(self):
        data = json.loads(self.scan()[0].read_text())
        refs, checks = self.index(data)
        ref = self.ref_of(data, "linuxmint")
        self.assertEqual(refs[ref]["release"], "Linux Mint 22.3")
        self.assertEqual(checks[(ref, "os-detection")]["status"], "pass")
        fstab = checks[(ref, "linux-fstab-consistency")]
        self.assertEqual((fstab["status"], fstab["value"]["number"]), ("fail", 1))
        kernel = checks[(ref, "linux-kernel-initrd")]
        self.assertEqual((kernel["status"], kernel["value"]["number"]), ("fail", 1))
        self.assertEqual(checks[(ref, "linux-package-state")]["status"], "fail")
        self.assertEqual(checks[(ref, "linux-journal-errors")]["status"], "unknown")
        self.assertEqual(checks[(ref, "boot-loader-files")]["status"], "pass")
        self.assertEqual(checks[(ref, "disk-free-space")]["status"], "pass")

    def test_bitlocker_is_never_unlocked(self):
        data = json.loads(self.scan()[0].read_text())
        refs, checks = self.index(data)
        ref = next(r for r, t in refs.items() if t["encryption"] == "bitlocker")
        self.assertEqual(refs[ref]["family"], "windows")
        self.assertEqual(refs[ref]["access"], "not-mounted-encrypted")
        self.assertEqual(checks[(ref, "encryption-status")]["status"], "warn")
        self.assertNotIn((ref, "windows-fast-startup"), checks)

    def test_apfs_without_tool_is_unsupported(self):
        data = json.loads(self.scan()[0].read_text())
        refs, checks = self.index(data)
        ref = self.ref_of(data, "macos")
        self.assertEqual(refs[ref]["access"], "not-mounted-unsupported")
        self.assertEqual(checks[(ref, "macos-apfs-container")]["status"], "unknown")
        self.assertEqual(checks[(ref, "os-detection")]["status"], "warn")

    def test_no_names_paths_or_users_in_output(self):
        text = self.scan()[0].read_text()
        for secret in SECRETS + (str(self.tmp), "SecretVolume", "OSDISK", "Users", "hiberfil", "/dev/", "Minidump"):
            self.assertNotIn(secret, text)

    def test_environment_checks_have_no_target_ref(self):
        data = json.loads(self.scan()[0].read_text())
        env = [c for c in data["checks"] if "target_ref" not in c]
        self.assertEqual({c["check_id"] for c in env}, {"block-device-discovery", "network-connectivity"})


class TestScanVariants(ScanFixtureCase):
    def test_filevault_and_luks(self):
        meta(self.fx, "mac", fstype="apfs", parttype=APFS, apfs="filevault")
        meta(self.fx, "crypt", fstype="crypto_LUKS")
        data = json.loads(self.scan()[0].read_text())
        self.validate(self.tmp / "out" / "evidence.json")
        refs, checks = self.index(data)
        mac = self.ref_of(data, "macos")
        self.assertEqual((refs[mac]["encryption"], refs[mac]["access"]), ("filevault", "not-mounted-encrypted"))
        self.assertEqual(checks[(mac, "macos-filevault")]["status"], "warn")
        luks = next(r for r, t in refs.items() if t["encryption"] == "luks")
        self.assertEqual(refs[luks]["access"], "not-mounted-encrypted")

    def test_mounted_apfs_counts_panics_and_reads_version(self):
        root = self.fx / "macvol"
        vol = root / "apfs1"
        touch(vol / "System/Library/CoreServices/SystemVersion.plist",
              b'<?xml version="1.0"?><plist version="1.0"><dict><key>ProductName</key><string>macOS</string>'
              b"<key>ProductVersion</key><string>14.5</string></dict></plist>")
        touch(vol / "Library/Logs/DiagnosticReports/a.panic")
        touch(vol / "Library/Logs/DiagnosticReports/b.panic")
        touch(vol / "Library/Logs/DiagnosticReports/c.ips")
        meta(self.fx, "macvol", fstype="apfs", parttype=APFS, free_percent=50)
        data = json.loads(self.scan()[0].read_text())
        self.validate(self.tmp / "out" / "evidence.json")
        refs, checks = self.index(data)
        ref = self.ref_of(data, "macos")
        self.assertEqual(refs[ref]["release"], "macOS 14.5")
        self.assertEqual(refs[ref]["access"], "read-only-mounted")
        crash = checks[(ref, "macos-crash-reports")]
        self.assertEqual((crash["status"], crash["value"]["number"]), ("warn", 2))

    def test_windows_dirty_flag_and_case_insensitive_paths(self):
        root = self.fx / "win"
        touch(root / "WINDOWS/system32/CONFIG/system")
        touch(root / "HIBERFIL.SYS", b"x")
        meta(self.fx, "win", fstype="ntfs", dirty=True)
        data = json.loads(self.scan()[0].read_text())
        _, checks = self.index(data)
        ref = self.ref_of(data, "windows")
        self.assertEqual(checks[(ref, "windows-ntfs-dirty")]["status"], "warn")
        self.assertEqual(checks[(ref, "windows-fast-startup")]["status"], "warn")
        self.assertEqual(checks[(ref, "windows-pending-updates")]["status"], "pass")

    def test_unmountable_ntfs_is_reported_without_guessing(self):
        meta(self.fx, "win", fstype="ntfs")  # no directory: cannot be mounted
        data = json.loads(self.scan()[0].read_text())
        self.validate(self.tmp / "out" / "evidence.json")
        refs, checks = self.index(data)
        ref = next(iter(refs))
        self.assertEqual((refs[ref]["family"], refs[ref]["access"]), ("unknown", "unknown"))
        self.assertEqual(checks[(ref, "windows-ntfs-dirty")]["status"], "fail")

    def test_data_partitions_and_recovery_are_ignored(self):
        touch(self.fx / "data/notes.txt")
        meta(self.fx, "data", fstype="ext4")
        meta(self.fx, "recovery", fstype="ntfs", parttype="de94bba4-06d1-4d40-a16a-bfd50179d6ac")
        data = json.loads(self.scan()[0].read_text())
        self.assertEqual(data["target_systems"], [])
        self.assertIn(("os-detection", "warn"), {(c["check_id"], c["status"]) for c in data["checks"]})
        self.validate(self.tmp / "out" / "evidence.json")

    def test_other_linux_and_boot_loader_without_esp_files(self):
        self.build_mint("deb", os_id="debian", pretty="Debian GNU/Linux 12 (bookworm)")
        touch(self.fx / "esp/EFI/BOOT/bootx64.efi")
        meta(self.fx, "esp", fstype="vfat", parttype=ESP)
        data = json.loads(self.scan()[0].read_text())
        refs, checks = self.index(data)
        ref = self.ref_of(data, "linux-other")
        self.assertEqual(refs[ref]["release"], "Debian GNU/Linux 12 (bookworm)")
        self.assertEqual(checks[(ref, "boot-loader-files")]["status"], "warn")

    def test_caps_at_eight_targets_and_64_checks(self):
        for i in range(10):
            meta(self.fx, "locked%02d" % i, fstype="BitLocker")
        data = json.loads(self.scan()[0].read_text())
        self.assertEqual(len(data["target_systems"]), 8)
        self.validate(self.tmp / "out" / "evidence.json")

    def test_check_budget_drops_whole_targets_not_checks(self):
        for i in range(10):
            self.build_windows("w%02d" % i)
        data = json.loads(self.scan()[0].read_text())
        self.assertLessEqual(len(data["checks"]), 160)
        self.assertLessEqual(len(data["target_systems"]), 8)
        refs = {t["ref"] for t in data["target_systems"]}
        self.assertEqual({c["target_ref"] for c in data["checks"] if "target_ref" in c}, refs)
        self.validate(self.tmp / "out" / "evidence.json")


class TestScanUnits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scan = load_scan_module()

    def test_resolve_stays_inside_root(self):
        tmp = Path(tempfile.mkdtemp(prefix="resolve-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        root = tmp / "root"
        (root / "etc").mkdir(parents=True)
        touch(root / "usr/lib/os-release", b"ID=x\n")
        os.symlink("../usr/lib/os-release", root / "etc/os-release")
        os.symlink("/etc/hostname", root / "etc/abs-link")  # absolute: must NOT read the live system
        os.symlink("../../../../../../etc/hostname", root / "etc/dotdot")
        touch(tmp / "outside", b"secret")
        os.symlink("../../outside", root / "etc/escape")
        self.assertEqual(self.scan.resolve(root, "etc/os-release"), os.path.realpath(root / "usr/lib/os-release"))
        self.assertIsNone(self.scan.resolve(root, "etc/abs-link"))
        self.assertIsNone(self.scan.resolve(root, "etc/dotdot"))
        self.assertIsNone(self.scan.resolve(root, "etc/escape"))
        self.assertEqual(self.scan.resolve(root, "ETC/OS-RELEASE"), os.path.realpath(root / "usr/lib/os-release"))

    def test_excluded_disks(self):
        tree = {"blockdevices": [
            {"path": "/dev/nvme0n1", "type": "disk", "rm": False, "tran": "nvme", "children": [
                {"path": "/dev/nvme0n1p1", "type": "part", "fstype": "vfat", "parttype": ESP},
                {"path": "/dev/nvme0n1p2", "type": "part", "fstype": "ntfs", "mountpoints": [None]}]},
            {"path": "/dev/sda", "type": "disk", "rm": True, "tran": "usb", "children": [
                {"path": "/dev/sda1", "type": "part", "fstype": "exfat", "label": "Ventoy"}]},
            {"path": "/dev/sdb", "type": "disk", "rm": False, "tran": "sata", "children": [
                {"path": "/dev/sdb1", "type": "part", "fstype": "iso9660", "mountpoints": ["/cdrom"]}]},
            {"path": "/dev/sdc", "type": "disk", "rm": False, "tran": "sata", "children": [
                {"path": "/dev/sdc1", "type": "part", "fstype": "vfat", "label": "VTOYEFI"}]},
            {"path": "/dev/sdd", "type": "disk", "rm": "1", "tran": "sata"},
            {"path": "/dev/sde", "type": "disk", "rm": False, "tran": "sata", "children": [
                {"path": "/dev/sde1", "type": "part", "fstype": "ext4", "mountpoints": ["/run/live/medium"]}]},
            {"path": "/dev/loop0", "type": "loop", "fstype": "squashfs"},
            {"path": "/dev/zram0", "type": "disk", "fstype": "swap"},
            {"path": "/dev/sr0", "type": "rom"},
        ]}
        records = []
        self.scan._flatten(tree["blockdevices"], None, records)
        bad = self.scan.excluded_disks(records)
        self.assertEqual(bad, {"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/sde",
                               "/dev/loop0", "/dev/zram0", "/dev/sr0"})
        self.assertNotIn("/dev/nvme0n1", bad)
        self.assertEqual(self.scan.classify(next(r for r in records if r["path"] == "/dev/nvme0n1p2")), "ntfs")
        self.assertEqual(self.scan.classify(next(r for r in records if r["path"] == "/dev/nvme0n1p1")), "esp")

    def test_classify(self):
        make = self.scan.make_part
        self.assertEqual(self.scan.classify(make(fstype="BitLocker")), "bitlocker")
        self.assertEqual(self.scan.classify(make(fstype="crypto_LUKS")), "luks")
        self.assertEqual(self.scan.classify(make(fstype=None, parttype=APFS)), "apfs")
        self.assertEqual(self.scan.classify(make(fstype="apfs")), "apfs")
        self.assertEqual(self.scan.classify(make(fstype="btrfs")), "linuxfs")
        self.assertIsNone(self.scan.classify(make(fstype="exfat")))
        self.assertIsNone(self.scan.classify(make(fstype="LVM2_member")))

    def test_sanitize_release(self):
        s = self.scan.sanitize_release
        self.assertEqual(s("Linux Mint 22.3"), "Linux Mint 22.3")
        cleaned = s("  \x1b[31mUbuntu 24.04\n$(rm -rf)")
        self.assertTrue(cleaned.endswith("Ubuntu 24.04(rm -rf)"))
        self.assertNotRegex(cleaned, r"[\x00-\x1f$]")
        self.assertIsNone(s("$$$"))
        self.assertIsNone(s(None))
        self.assertLessEqual(len(s("A" * 200)), 64)

    @staticmethod
    def ntfs_image(dirty):
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        struct.pack_into("<H", boot, 0x0B, 512)
        boot[0x0D] = 8
        struct.pack_into("<Q", boot, 0x30, 4)
        struct.pack_into("<b", boot, 0x40, -10)
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<HH", rec, 4, 0x30, 3)
        struct.pack_into("<H", rec, 0x14, 0x38)
        rec[0x30:0x32] = b"\x01\x00"
        rec[510:512] = b"\x01\x00"
        rec[1022:1024] = b"\x01\x00"
        struct.pack_into("<II", rec, 0x38, 0x70, 0x28)
        struct.pack_into("<IH", rec, 0x38 + 0x10, 12, 0x18)
        struct.pack_into("<H", rec, 0x38 + 0x18 + 10, 1 if dirty else 0)
        struct.pack_into("<I", rec, 0x38 + 0x28, 0xFFFFFFFF)
        image = bytearray(4 * 4096 + 4 * 1024)
        image[0:512] = boot
        image[4 * 4096 + 3 * 1024:4 * 4096 + 4 * 1024] = rec
        return bytes(image)

    def test_ntfs_dirty_flag_parser(self):
        self.assertTrue(self.scan.ntfs_volume_dirty(io.BytesIO(self.ntfs_image(True))))
        self.assertFalse(self.scan.ntfs_volume_dirty(io.BytesIO(self.ntfs_image(False))))
        self.assertIsNone(self.scan.ntfs_volume_dirty(io.BytesIO(b"\x00" * 4096)))
        self.assertIsNone(self.scan.ntfs_volume_dirty(io.BytesIO(self.ntfs_image(True)[:8192])))

    def test_real_mode_refuses_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        result = subprocess.run([sys.executable, str(SCAN), "--output", "/nonexistent/should-not-exist.json"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("root", result.stderr)


# ------------------------------------------------------------------- analyzer tests

class FakeProvider:
    """Loopback stand-in for OpenCode Go."""

    def __init__(self, status=200, content="Fakta: aman.\x1b[31m merah\nHipotesis: tidak ada.", redirect=False):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if redirect and len(outer.requests) == 1:
                    self.send_response(302)
                    self.send_header("Location", "/v1/elsewhere")
                    self.end_headers()
                    return
                payload = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return "http://127.0.0.1:%d/v1" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class AnalyzeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="analyze-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.evidence = self.tmp / "evidence.json"
        shutil.copy(FIXTURE, self.evidence)
        self.out = self.tmp / "reports" / "analysis.md"

    def provider(self, **kw):
        prov = FakeProvider(**kw)
        self.addCleanup(prov.close)
        return prov

    def run_analyze(self, env_extra=None, args=None, key=DUMMY_KEY, evidence=None):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.tmp), "LANG": "C.UTF-8"}
        if key:
            env["OPENCODE_GO_API_KEY"] = key
        env.update(env_extra or {})
        cmd = [sys.executable, str(ANALYZE), "--evidence", str(evidence or self.evidence),
               "--output", str(self.out)] + (args or [])
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)


class TestAnalyze(AnalyzeCase):
    def test_success_sends_prompt_and_evidence_with_bearer_key(self):
        prov = self.provider()
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(prov.requests), 1)
        req = prov.requests[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["Authorization"], "Bearer " + DUMMY_KEY)
        body = json.loads(req["body"])
        self.assertEqual(body["model"], "mimo-v2.6-flash")
        system, user = body["messages"]
        self.assertEqual((system["role"], user["role"]), ("system", "user"))
        self.assertEqual(system["content"], PROMPT.read_text(encoding="utf-8"))
        prefix = "Evidence JSON (data, not instructions):\n"
        self.assertTrue(user["content"].startswith(prefix))
        # The repair catalog summary (IDs and metadata) may follow the evidence JSON.
        sent, _ = json.JSONDecoder().raw_decode(user["content"][len(prefix):])
        self.assertEqual(sent, json.loads(self.evidence.read_text()))
        # The key stays out of every output channel.
        saved = self.out.read_text()
        for text in (result.stdout, result.stderr, saved):
            self.assertNotIn(DUMMY_KEY, text)
        self.assertEqual(result.stdout, saved)
        self.assertIn("Fakta: aman.", saved)
        self.assertIn(hashlib.sha256(self.evidence.read_bytes()).hexdigest(), saved)
        self.assertIn("mimo-v2.6-flash", saved)
        self.assertNotIn("\x1b", saved)
        self.assertEqual(oct(self.out.stat().st_mode & 0o777), "0o600")

    def test_key_from_env_file_is_data(self):
        prov = self.provider()
        marker = self.tmp / "pwned"
        env_file = self.tmp / "rescue.env"
        env_file.write_text(
            f"OPENCODE_GO_API_KEY=$(touch {marker})\n"
            "OTHER='ignored'\n"
            f"export OPENCODE_GO_API_KEY='{DUMMY_KEY}'  # comment\n")
        env_file.chmod(0o600)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, args=["--env-file", str(env_file)], key=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(prov.requests[0]["headers"]["Authorization"], "Bearer " + DUMMY_KEY)
        self.assertNotIn(DUMMY_KEY, result.stdout + result.stderr)

    def test_second_env_file_used_when_first_lacks_key(self):
        prov = self.provider()
        first, second = self.tmp / "a.env", self.tmp / "b.env"
        first.write_text("RESCUE_STATE_DIR=/x\n")
        second.write_text(f"OPENCODE_GO_API_KEY=\"{DUMMY_KEY}\"\n")
        for f in (first, second):
            f.chmod(0o600)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base},
                                  args=["--env-file", str(first), "--env-file", str(self.tmp / "missing.env"),
                                        "--env-file", str(second)], key=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_world_writable_and_expanding_env_files_yield_no_key(self):
        prov = self.provider()
        bad = self.tmp / "bad.env"
        bad.write_text(f"OPENCODE_GO_API_KEY={DUMMY_KEY}\n")
        bad.chmod(0o666)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, args=["--env-file", str(bad)], key=None)
        self.assertEqual(result.returncode, 3)
        self.assertIn("world-writable", result.stderr)
        expanding = self.tmp / "exp.env"
        expanding.write_text('OPENCODE_GO_API_KEY="pre$HOME"\n')
        expanding.chmod(0o600)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, args=["--env-file", str(expanding)], key=None)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(prov.requests, [])

    def test_missing_key_exit_3_and_nothing_sent(self):
        prov = self.provider()
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, key=None)
        self.assertEqual(result.returncode, 3)
        self.assertIn("OPENCODE_GO_API_KEY", result.stderr)
        self.assertIn("tidak", result.stderr)
        self.assertEqual(prov.requests, [])
        self.assertFalse(self.out.exists())

    def test_invalid_evidence_exit_2_and_nothing_sent(self):
        prov = self.provider()
        bad = self.tmp / "bad.json"
        bad.write_text("{}")
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, evidence=bad)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(prov.requests, [])
        not_json = self.tmp / "nope.json"
        not_json.write_text("not json")
        self.assertEqual(self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, evidence=not_json).returncode, 2)
        data = json.loads(self.evidence.read_text())
        data["checks"][0]["hostname"] = "leak"  # extra property is rejected by the schema
        leaky = self.tmp / "leaky.json"
        leaky.write_text(json.dumps(data))
        self.assertEqual(self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, evidence=leaky).returncode, 2)
        self.assertEqual(prov.requests, [])

    def test_http_error_and_unreachable_exit_4(self):
        prov = self.provider(status=500)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base})
        self.assertEqual(result.returncode, 4)
        self.assertIn("500", result.stderr)
        self.assertNotIn(DUMMY_KEY, result.stdout + result.stderr)
        self.assertFalse(self.out.exists())
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": "http://127.0.0.1:9/v1", "OPENCODE_TIMEOUT_SECONDS": "5"})
        self.assertEqual(result.returncode, 4)

    def test_redirects_are_refused(self):
        prov = self.provider(redirect=True)
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base})
        self.assertEqual(result.returncode, 4)
        self.assertEqual(len(prov.requests), 1)

    def test_dry_run_makes_no_request_and_needs_no_key(self):
        prov = self.provider()
        result = self.run_analyze({"RESCUE_TEST_BASE_URL": prov.base}, args=["--dry-run"], key=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mimo-v2.6-flash", result.stdout)
        self.assertIn(hashlib.sha256(self.evidence.read_bytes()).hexdigest(), result.stdout)
        self.assertIn(prov.base + "/chat/completions", result.stdout)
        self.assertEqual(prov.requests, [])
        self.assertFalse(self.out.exists())

    def test_dry_run_still_validates(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{}")
        self.assertEqual(self.run_analyze(args=["--dry-run"], evidence=bad).returncode, 2)

    def test_non_loopback_test_base_url_is_ignored(self):
        official = "https://opencode.ai/zen/go/v1/chat/completions"
        for base in ("http://evil.example/v1", "https://127.0.0.1:1/v1", "http://127.0.0.1:1@evil.example/v1",
                     "http://127.0.0.10:80/v1", "http://localhost:8000/v1"):
            with self.subTest(base=base):
                result = self.run_analyze({"RESCUE_TEST_BASE_URL": base}, args=["--dry-run"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("endpoint: " + official, result.stdout)
        result = self.run_analyze(args=["--dry-run"])
        self.assertIn("endpoint: " + official, result.stdout)

    def test_bad_timeout_is_rejected(self):
        result = self.run_analyze({"OPENCODE_TIMEOUT_SECONDS": "abc"}, args=["--dry-run"])
        self.assertEqual(result.returncode, 2)


# --------------------------------------------------------------- launcher wiring

try:
    import test_hermes_scripts as _ths
except ImportError:  # pragma: no cover
    _ths = None

STUB_SCAN = """#!/usr/bin/env python3
import shutil, sys
args = sys.argv[1:]
if {fail}:
    sys.exit(1)
open({marker!r}, "w").write("scan-ran")
shutil.copy({fixture!r}, args[args.index("--output") + 1])
"""


@unittest.skipIf(_ths is None, "test_hermes_scripts helpers unavailable")
@unittest.skipUnless(_ths and _ths._can_run_unprivileged(), "need a non-root user or setpriv")
class TestLauncherWiring(_ths.HermesScriptTestCase if _ths else unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.install().returncode, 0)
        self.marker = self.tmp / "scan-marker"
        self.write_shim("hermes", "printf 'HERMES-RAN %s\\n' \"$*\"\n")
        self.write_shim("sudo", '[ "$1" = -n ] && shift\nexec "$@"\n')
        hw = self.src / "scripts" / "check-hardware-readiness.py"
        hw.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n")
        os.chmod(hw, 0o755)
        self._open(hw)
        self.provider = FakeProvider()
        self.addCleanup(self.provider.close)

    def stub_scan(self, fail=False):
        stub = self.src / "scripts" / "scan-target-os.py"
        fixture = self.src / "rescue-ai" / "v1" / "fixtures" / "valid-live-multi-os-1.1.json"
        stub.write_text(STUB_SCAN.format(fail=fail, marker=str(self.marker), fixture=str(fixture)))
        os.chmod(stub, 0o755)
        self._open(stub)
        os.chmod(stub, 0o755)

    def launch(self, *extra, key=DUMMY_KEY):
        env = {"RESCUE_TEST_BASE_URL": self.provider.base}
        if key:
            env["OPENCODE_GO_API_KEY"] = key
        return self.run_cmd(
            [self.src / "scripts" / "launch-hermes-rescue.sh", "--state-dir", self.state, *extra],
            env_extra=env, path=f"{self.shims}:/usr/bin:/bin")

    def reports(self, pattern):
        return sorted((self.state / "reports").glob(pattern))

    def test_scan_then_analysis_then_hermes(self):
        self.stub_scan()
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertIn("HERMES-RAN", result.stdout)
        self.assertEqual(len(self.reports("target-evidence-*.json")), 1)
        self.assertEqual(len(self.reports("analysis-*.md")), 1)
        latest = self.state / "reports" / "latest-evidence.json"
        self.assertEqual(latest.read_text(), self.reports("target-evidence-*.json")[0].read_text())
        self.assertIn("Fakta: aman.", self.reports("analysis-*.md")[0].read_text())
        self.assertLess(result.stdout.index("Fakta: aman."), result.stdout.index("HERMES-RAN"))
        self.assertNotIn(DUMMY_KEY, result.stdout + result.stderr)
        self.assertEqual(len(self.provider.requests), 1)

    def test_scan_failure_does_not_block_hermes(self):
        self.stub_scan(fail=True)
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HERMES-RAN", result.stdout)
        self.assertIn("PERINGATAN", result.stderr)
        self.assertIn("WARNING", result.stderr)
        self.assertEqual(self.provider.requests, [])
        self.assertEqual(self.reports("analysis-*.md"), [])

    def test_analysis_failure_does_not_block_hermes(self):
        self.stub_scan()
        result = self.launch(key=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HERMES-RAN", result.stdout)
        self.assertIn("PERINGATAN", result.stderr)
        self.assertEqual(len(self.reports("target-evidence-*.json")), 1)
        self.assertEqual(self.reports("analysis-*.md"), [])

    def test_no_target_scan_flag_skips_everything(self):
        self.stub_scan()
        result = self.launch("--no-target-scan")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HERMES-RAN", result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.reports("target-evidence-*.json"), [])
        self.assertEqual(self.provider.requests, [])


if __name__ == "__main__":
    unittest.main()
