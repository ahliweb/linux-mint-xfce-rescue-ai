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


SYSFS_BLOCK = pathlib.Path("/sys/block")
SYSFS_CLASS_BLOCK = pathlib.Path("/sys/class/block")
MAX_RESOLVE_DEPTH = 4
MAX_WALK_DEPTH = 8
_DISK_TYPES = ("disk", "rom")
_USB_PATH = re.compile(r"/usb\d+(/|$)")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}")


def _lsblk_chain(device: str) -> list[tuple[str, str, str, int | None]]:
    """(name, type, tran, size_bytes) for DEVICE and its parents (dm, partition -> disk), read-only."""
    rows = []
    for line in command("lsblk", "-b", "-s", "-n", "-r", "-o", "NAME,TYPE,TRAN,SIZE", device).splitlines():
        cols = line.split(" ")
        if len(cols) != 4 or not cols[0]:
            continue
        try:
            size = int(cols[3])
        except ValueError:
            size = None
        rows.append((cols[0], cols[1], cols[2], size))
    return rows


def _node(name: str) -> pathlib.Path | None:
    """sysfs directory of block device NAME (partitions only exist under /sys/class/block)."""
    if not _SAFE_NAME.fullmatch(name):
        return None
    for root in (SYSFS_CLASS_BLOCK, SYSFS_BLOCK):
        candidate = root / name
        if candidate.is_dir():
            return candidate
    return None


def _read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _loop_backing_source(name: str) -> str:
    """Device that holds the backing file of loop device NAME (partition suffix allowed); '' when unknown."""
    base = re.sub(r"p\d+$", "", name) if re.fullmatch(r"loop\d+p\d+", name) else name
    if not re.fullmatch(r"loop\d+", base):
        return ""
    node = _node(base)
    backing = _read(node / "loop" / "backing_file") if node else ""
    if not backing.startswith("/"):
        return ""
    found = command("findmnt", "-T", backing, "-no", "SOURCE")
    if not found:
        return ""
    return re.sub(r"\[.*\]$", "", found.splitlines()[0].strip())


def _dm_node_for(source: str) -> str:
    """Kernel name (dm-N) for a /dev/mapper/NAME source: realpath first, then the dm/name files."""
    kernel = os.path.basename(os.path.realpath(source))
    if re.fullmatch(r"dm-\d+", kernel):
        return kernel
    wanted = os.path.basename(source)
    try:
        for entry in sorted(SYSFS_CLASS_BLOCK.glob("dm-*")):
            if _read(entry / "dm" / "name") == wanted:
                return entry.name
    except OSError:
        pass
    return ""


def _sysfs_walk(name: str, chain: list[str], depth: int, loop_depth: int) -> tuple[str, str] | None:
    """Walk NAME down to its physical disk through slaves/, partitions and loop backing files.
    Appends visited names to CHAIN. Returns (disk_name, '') or None; a reason is appended to CHAIN
    as '? (reason)' when the walk dead-ends."""
    node = _node(name)
    if node is None:
        chain.append("? (not in sysfs)")
        return None
    if depth > MAX_WALK_DEPTH:
        chain.append("? (too deep)")
        return None
    real = pathlib.Path(os.path.realpath(node))
    if (node / "partition").exists() or (real / "partition").exists():
        parent = real.parent.name
        chain.append(parent)
        return _sysfs_walk(parent, chain, depth + 1, loop_depth) if parent != name else None
    slaves = []
    try:
        slaves = sorted(p.name for p in (node / "slaves").iterdir())
    except OSError:
        pass
    if slaves:
        for slave in slaves:
            trial = list(chain)
            trial.append(slave)
            found = _sysfs_walk(slave, trial, depth + 1, loop_depth)
            if found:
                chain[:] = trial
                return found
        chain.append("? (slaves unresolved)")
        return None
    if re.fullmatch(r"loop\d+", name):
        backing = _loop_backing_source(name)
        if not backing or loop_depth >= MAX_RESOLVE_DEPTH:
            chain.append("? (no backing device)")
            return None
        chain.append(backing)
        inner = _sysfs_walk(os.path.basename(os.path.realpath(backing)), chain, depth + 1, loop_depth + 1)
        return inner
    if (node / "dm").is_dir() or name.startswith(("dm-", "md")):
        chain.append("? (no slaves)")
        return None
    return name, ""


def _sysfs_disk_info(disk: str) -> tuple[str, float | None]:
    """(transport, size_gib) of physical DISK from sysfs; transport '' when sysfs cannot tell."""
    node = _node(disk)
    if node is None:
        return "", None
    paths = [os.path.realpath(node)]
    if (node / "device").exists():
        paths.append(os.path.realpath(node / "device"))
    if any(_USB_PATH.search(p + "/") for p in paths):
        tran = "usb"
    elif disk.startswith("nvme"):
        tran = "nvme"
    else:
        tran = ""
    sectors = _read(node / "size")
    size = int(sectors) * 512 / (1024 ** 3) if sectors.isdigit() else None
    return tran, size


def _resolve_sysfs(source: str, loop_depth: int = 0) -> tuple[tuple[str, float | None, str] | None, list[str]]:
    """sysfs resolution: ((transport, size_gib, disk) | None, chain). Chain starts with SOURCE."""
    chain = [source]
    kernel = _dm_node_for(source) if source.startswith("/dev/mapper/") else os.path.basename(os.path.realpath(source))
    if not kernel:
        chain.append("? (dm node not found)")
        return None, chain
    if kernel != os.path.basename(source):
        chain.append(kernel)
    found = _sysfs_walk(kernel, chain, 0, loop_depth)
    if not found:
        return None, chain
    disk = found[0]
    tran, size = _sysfs_disk_info(disk)
    if chain[-1] != disk:
        chain.append(disk)
    return (tran, size, disk), chain


def resolve_live_source(source: str) -> tuple[tuple[str, float | None, str] | None, str]:
    """Resolve a live-media source (partition, dm device such as /dev/mapper/ventoy, loop device) to its
    physical disk with sysfs first and lsblk as fallback/cross-check. Returns
    ((transport, size_gib, disk) | None, chain_text); chain_text names only kernel devices."""
    if not source.startswith("/dev/"):
        return None, source
    sys_found, chain = _resolve_sysfs(source)
    if sys_found and sys_found[0] and sys_found[0] != "unknown":
        return sys_found, " -> ".join(chain)
    lsblk_found = resolve_physical_disk(source)
    if lsblk_found and lsblk_found[0] != "unknown":
        if sys_found and lsblk_found[2] == sys_found[2]:
            return lsblk_found, " -> ".join(chain)
        return lsblk_found, f"{source} -> {lsblk_found[2]}" if lsblk_found[2] != os.path.basename(source) else source
    if sys_found:  # disk found but no transport source knows it
        tran, size, disk = sys_found
        if size is None and lsblk_found:
            size = lsblk_found[1]
        return ("unknown", size, disk), " -> ".join(chain)
    if lsblk_found:
        return lsblk_found, f"{source} -> {lsblk_found[2]}" if lsblk_found[2] != os.path.basename(source) else source
    return None, " -> ".join(chain)


def resolve_physical_disk(source: str, depth: int = 0) -> tuple[str, float | None, str] | None:
    """lsblk-based resolution (fallback). Returns (transport, size_gib, disk_name) or None."""
    if depth > MAX_RESOLVE_DEPTH or not source.startswith("/dev/"):
        return None
    rows = _lsblk_chain(source)
    for name, kind, tran, size in rows:
        if kind in _DISK_TYPES:
            return (tran or "unknown", None if size is None else size / (1024 ** 3), name)
    for name, kind, _tran, _size in rows:
        if kind == "loop":
            backing = _loop_backing_source(name)
            if backing and backing != source:
                return resolve_physical_disk(backing, depth + 1)
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
    resolved, chain = resolve_live_source(source)
    if resolved is None:
        return "unknown", None, chain
    tran, size, _disk = resolved
    return tran, size, chain


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
    # Not required: the local read-only scan works offline; the network is only needed for the
    # OpenCode Go analysis and Hermes. An offline run degrades to a warning, never a blocker.
    return check_result("internet-connectivity", "pass" if ok else "warn",
                        f"default-route={'yes' if route else 'no'}, dns={'yes' if dns else 'no'}, https={http_status}",
                        f"IP/default route + DNS + HTTPS to {url}", required=False,
                        note="needed for OpenCode Go analysis and Hermes; the local scan works offline")


def check_usb(min_usb: float) -> dict:
    """fail only for a resolved USB disk below the minimum; unresolvable or non-USB transports warn."""
    tran, size, source = storage_for_live_media()
    minimum = f"USB transport and >= {min_usb:.1f} GiB"
    if not source or not tran:
        return check_result("usb-boot-media", "warn", "USB/live medium cannot be verified", minimum,
                            note="live-media source not detected; physical firmware boot must still be tested")
    if tran == "usb":
        if size is None:
            return check_result("usb-boot-media", "warn", f"USB size unavailable ({source})", minimum,
                                note="USB detected but its size could not be read")
        return check_result("usb-boot-media", "pass" if size >= min_usb else "fail", f"USB {size:.2f} GiB ({source})",
                            minimum, note="USB transport and live mount detected")
    detail = f" ({tran}, {size:.1f} GiB)" if size is not None and tran != "unknown" else ""
    return check_result("usb-boot-media", "warn", f"transport={tran or 'unknown'}, source={source}{detail}", minimum,
                        note="boot source could not be resolved to a USB disk (virtual, bridged or mapped device); "
                             "the chain shows where resolution stopped; not blocking")


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
