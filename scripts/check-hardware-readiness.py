#!/usr/bin/env python3
"""Read-only hardware/network readiness gate for the rescue live session."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request

UTC = dt.timezone.utc
DEFAULT_URL = "https://opencode.ai"


def now() -> str:
    return dt.datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def command(*args: str, timeout: int = 8) -> str:
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def check_result(check_id: str, status: str, observed: str, minimum: str,
                 required: bool = True, note: str = "") -> dict:
    return {
        "check_id": check_id,
        "status": status,
        "required": required,
        "observed": observed,
        "minimum": minimum,
        "note": note,
        "observed_at": now(),
    }


def read_mem_mib() -> float | None:
    try:
        text = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.M)
        return int(match.group(1)) / 1024 if match else None
    except OSError:
        return None


def storage_for_live_media() -> tuple[str, float | None, str]:
    candidates = ["/run/live/medium", "/cdrom", "/media"]
    source = ""
    for path in candidates:
        found = command("findmnt", "-no", "SOURCE", path)
        if found:
            source = found.splitlines()[0].strip()
            break
    if not source:
        return "", None, "live-media mount was not detected"
    device = source
    if device.startswith("/dev/"):
        size_text = command("lsblk", "-bndo", "SIZE", device)
        tran = command("lsblk", "-ndo", "TRAN", device) or "unknown"
        try:
            return tran, int(size_text) / (1024 ** 3), device
        except ValueError:
            return tran, None, device
    return "unknown", None, source


def check_cpu(min_cpus: int) -> dict:
    count = os.cpu_count() or 0
    model = ""
    try:
        for line in pathlib.Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[-1].strip()
                break
    except OSError:
        pass
    status = "pass" if count >= min_cpus else "fail"
    return check_result("cpu", status, f"{count} logical CPU(s){('; ' + model) if model else ''}",
                        f">= {min_cpus} logical CPU(s)")


def check_ram(min_ram: float) -> dict:
    mib = read_mem_mib()
    if mib is None:
        return check_result("ram", "unknown", "MemTotal unavailable", f">= {min_ram:.1f} GiB")
    status = "pass" if mib / 1024 >= min_ram else "fail"
    return check_result("ram", status, f"{mib / 1024:.2f} GiB", f">= {min_ram:.1f} GiB")


def check_vga() -> dict:
    drm = [p.name for p in pathlib.Path("/sys/class/drm").glob("card[0-9]*")]
    pci = command("lspci")
    found = bool(drm or re.search(r"VGA|3D controller|Display controller", pci, re.I))
    detail = ", ".join(drm) if drm else ("PCI display adapter detected" if found else "no display adapter detected")
    return check_result("vga-display", "pass" if found else "fail", detail,
                        "display adapter (DRM or PCI VGA/3D/Display)")


def check_network(url: str) -> dict:
    route = command("ip", "route", "show", "default")
    host = urllib.parse.urlparse(url).hostname
    dns = False
    if host:
        try:
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            dns = True
        except socket.gaierror:
            pass
    https = False
    http_status = "unavailable"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "rescue-readiness/1.0"}, method="HEAD")
        with urllib.request.urlopen(request, timeout=10) as response:
            https = 200 <= response.status < 500
            http_status = str(response.status)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        http_status = type(exc).__name__
    ok = bool(route and dns and https)
    return check_result("internet-connectivity", "pass" if ok else "fail",
                        f"default-route={'yes' if route else 'no'}, dns={'yes' if dns else 'no'}, https={http_status}",
                        f"IP/default route + DNS + HTTPS to {url}", note="network is required for OpenCode Go")


def check_usb(min_usb: float) -> dict:
    tran, size, source = storage_for_live_media()
    if not source:
        return check_result("usb-boot-media", "fail", "USB/live medium cannot be verified",
                            f">= {min_usb:.1f} GiB removable boot media", note="physical firmware boot must still be tested")
    if tran != "usb":
        return check_result("usb-boot-media", "fail", f"transport={tran}, source={source}",
                            f"USB transport and >= {min_usb:.1f} GiB", note="boot source is not identified as USB")
    if size is None:
        return check_result("usb-boot-media", "unknown", f"USB size unavailable ({source})",
                            f">= {min_usb:.1f} GiB removable boot media")
    status = "pass" if size >= min_usb else "fail"
    return check_result("usb-boot-media", status, f"USB {size:.2f} GiB ({source})",
                        f">= {min_usb:.1f} GiB removable boot media",
                        note="USB transport and live mount detected")


def write_private(destination: pathlib.Path, text: str) -> None:
    """Create/replace the report atomically; the file is 0600 from creation (no chmod window)."""
    tmp = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, destination)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ask(step: dict, mode: str) -> bool:
    if mode == "auto":
        return True
    prompt = f"Periksa {step['check_id']} (minimum {step['minimum']})? [Y/n] "
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in ("", "y", "yes", "ya")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("auto", "wizard"), default="auto")
    parser.add_argument("--output", required=True, help="JSON report destination")
    parser.add_argument("--min-cpu", type=int, default=2)
    parser.add_argument("--min-ram-gib", type=float, default=4.0)
    parser.add_argument("--min-usb-gib", type=float, default=8.0)
    parser.add_argument("--internet-url", default=DEFAULT_URL)
    args = parser.parse_args()
    if args.min_cpu < 1 or args.min_ram_gib <= 0 or args.min_usb_gib <= 0:
        parser.error("minimum thresholds must be positive")

    checks = []
    # (check_id, minimum_text, fn): minimum_text is what the wizard shows before asking.
    definitions = [
        ("cpu", f">= {args.min_cpu} logical CPU(s)", lambda: check_cpu(args.min_cpu)),
        ("ram", f">= {args.min_ram_gib:.1f} GiB", lambda: check_ram(args.min_ram_gib)),
        ("vga-display", "display adapter (DRM or PCI VGA/3D/Display)", check_vga),
        ("internet-connectivity", f"IP/default route + DNS + HTTPS to {args.internet_url}",
         lambda: check_network(args.internet_url)),
        ("usb-boot-media", f"USB transport and >= {args.min_usb_gib:.1f} GiB", lambda: check_usb(args.min_usb_gib)),
    ]
    for check_id, minimum_text, fn in definitions:
        preview = {"check_id": check_id, "minimum": minimum_text}
        if not ask(preview, args.mode):
            checks.append(check_result(check_id, "warn", "skipped by operator", "not skipped", note="wizard skip"))
            continue
        checks.append(fn())

    failures = [c for c in checks if c["required"] and c["status"] == "fail"]
    unknown_required = [c for c in checks if c["required"] and c["status"] == "unknown"]
    warnings = [c for c in checks if c["status"] == "warn"]
    overall = "not_ready" if (failures or unknown_required) else ("ready_with_warnings" if warnings else "ready")
    report = {
        "report_version": "1.0",
        "report_type": "hardware-readiness",
        "run_id": "hardware-" + dt.datetime.now(UTC).strftime("%Y%m%d-%H%M%S"),
        "mode": args.mode,
        "collected_at": now(),
        "thresholds": {"min_logical_cpu": args.min_cpu, "min_ram_gib": args.min_ram_gib, "min_usb_gib": args.min_usb_gib},
        "checks": checks,
        "summary": {"overall": overall, "failures": len(failures), "unknown_required": len(unknown_required), "warnings": len(warnings)},
        "operator_message": "Minimal requirements are not met; resolve failures before starting rescue diagnosis." if overall == "not_ready" else "Hardware preflight completed.",
    }
    destination = pathlib.Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_private(destination, json.dumps(report, indent=2) + "\n")
    print(f"Hardware readiness: {overall.upper()}")
    for check in checks:
        print(f"[{check['status'].upper():7}] {check['check_id']}: {check['observed']} (minimum: {check['minimum']})")
        if check.get("note"):
            print(f"          warning: {check['note']}")
    print(f"Report: {destination}")
    return 1 if failures or unknown_required else 0


if __name__ == "__main__":
    raise SystemExit(main())
