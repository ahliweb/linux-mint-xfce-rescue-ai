#!/usr/bin/env python3
"""Convert a container image layer (AUFS whiteouts) into an overlayfs upper layer.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Docker/OCI layer tarballs mark deletions with AUFS-style entries:

  * ``dir/.wh.name``   -> ``name`` was deleted (whiteout)
  * ``dir/.wh..wh..opq`` -> ``dir`` is opaque (lower content is hidden)

casper mounts the persistence filesystem's ``upper/`` directory as the
overlayfs upper layer. Overlayfs represents the same two facts as:

  * a character device ``0:0`` named ``name``       (whiteout)
  * the xattr ``trusted.overlay.opaque=y`` on ``dir`` (opaque directory)

This module has three stages, all pure Python and unit-testable without root:

  convert   filter a layer tar: drop whiteout markers and excluded paths and
            write the remaining members to a new tar; emit a JSON plan.
  prepare   make sure the parent directories of every whiteout exist in the
            extracted upper directory.
  debugfs   print a ``debugfs -w`` script that creates the 0:0 character
            devices and sets the opaque xattrs directly in the finished ext4
            image. overlayfs (a container's own filesystem) refuses to create
            0:0 devices, and ``trusted.*`` xattrs need CAP_SYS_ADMIN, but
            debugfs edits the image file and needs no privilege at all.

Nothing here executes content from the layer: names are data.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile

WH_PREFIX = ".wh."
WH_OPAQUE = ".wh..wh..opq"

# Paths (relative, no leading slash) that must never travel from the build
# container into the persistence overlay: casper/systemd regenerate them at
# boot, they are container artefacts, or they are pure caches.
EXCLUDE_TREES = (
    "tmp",
    "var/tmp",
    "run",
    "dev",
    "proc",
    "sys",
    "mnt",
    "media",
    "root",
    ".dockerenv",
    "etc/hostname",
    "etc/hosts",
    "etc/resolv.conf",
    "etc/machine-id",
    "var/lib/dbus/machine-id",
    "var/cache/apt",
    "var/lib/apt/lists",
    "home/mint/.cache",
    # The live user is created by casper on first boot (uid 1000); the account
    # databases stay untouched so casper's own user setup is authoritative.
    "etc/passwd",
    "etc/passwd-",
    "etc/group",
    "etc/group-",
    "etc/shadow",
    "etc/shadow-",
    "etc/gshadow",
    "etc/gshadow-",
    "etc/subuid",
    "etc/subuid-",
    "etc/subgid",
    "etc/subgid-",
)
# Directories whose non-directory content is dropped but whose directory
# skeleton is kept (logs are noise, the directories may be expected).
DIRS_ONLY = ("var/log",)


def norm(name: str) -> str:
    """Return a tar member name as a clean relative path (no ./, no trailing /)."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    return "/".join(parts)


def under(path: str, tree: str) -> bool:
    return path == tree or path.startswith(tree + "/")


def is_excluded(path: str, is_dir: bool = False) -> bool:
    path = norm(path)
    for tree in EXCLUDE_TREES:
        if under(path, tree):
            return True
    for tree in DIRS_ONLY:
        if path != tree and under(path, tree) and not is_dir:
            return True
    return False


def classify(name: str):
    """Classify a member name: ("opaque", dir) | ("whiteout", target) | ("plain", path)."""
    path = norm(name)
    parent, _, base = path.rpartition("/")
    if base == WH_OPAQUE:
        return "opaque", parent
    if base.startswith(WH_PREFIX):
        target = base[len(WH_PREFIX):]
        return "whiteout", f"{parent}/{target}" if parent else target
    return "plain", path


class Plan:
    """What must be done to turn the filtered tar into an overlayfs upper layer."""

    def __init__(self):
        self.whiteouts: list[str] = []
        self.opaque: list[str] = []
        self.kept = 0
        self.excluded = 0

    def as_dict(self):
        return {
            "whiteouts": sorted(set(self.whiteouts)),
            "opaque": sorted(set(self.opaque)),
            "kept": self.kept,
            "excluded": self.excluded,
        }


def _safe(path: str) -> bool:
    return bool(path) and not path.startswith("/") and ".." not in path.split("/")


def convert_layer(src_tar: str, dst_tar: str) -> Plan:
    """Filter *src_tar* into *dst_tar* and return the whiteout/opaque plan."""
    plan = Plan()
    kept_names: set[str] = set()
    with tarfile.open(src_tar, "r:*") as src, tarfile.open(dst_tar, "w", format=tarfile.PAX_FORMAT) as dst:
        for member in src:
            kind, path = classify(member.name)
            if kind == "opaque":
                if _safe(path) and not is_excluded(path, True):
                    plan.opaque.append(path)
                continue
            if kind == "whiteout":
                if _safe(path) and not is_excluded(path):
                    plan.whiteouts.append(path)
                else:
                    plan.excluded += 1
                continue
            if not path:
                # The layer root ("./"): keep nothing, the upper root exists.
                continue
            if not _safe(path):
                raise ValueError(f"unsafe path in layer: {member.name!r}")
            if is_excluded(path, member.isdir()):
                plan.excluded += 1
                continue
            if member.islnk():
                target = norm(member.linkname)
                if is_excluded(target) or target not in kept_names:
                    raise ValueError(f"hard link {path!r} points at dropped member {target!r}")
                member.linkname = target
            member.name = path
            if member.isfile():
                dst.addfile(member, src.extractfile(member))
            else:
                dst.addfile(member)
            kept_names.add(path)
            plan.kept += 1
    return plan


def ensure_parents(plan: dict, upper: str) -> list[str]:
    """Create missing parent directories of whiteouts below *upper*."""
    made = []
    for rel in plan.get("whiteouts", []):
        if not _safe(rel):
            raise ValueError(f"unsafe whiteout path: {rel!r}")
        parent = os.path.dirname(os.path.join(upper, rel))
        if not os.path.isdir(parent):
            # The lower layer holds the directory; overlayfs needs it in the
            # upper layer to place the whiteout.
            os.makedirs(parent, exist_ok=True)
            made.append(os.path.relpath(parent, upper))
    return made


def _quote(text: str) -> str:
    return f'"{text}"' if any(c in text for c in " \t") else text


def _dq(prefix: str, rel: str) -> str:
    """Quote a debugfs path argument; reject characters debugfs cannot carry."""
    if not _safe(rel) or any(c in rel for c in "\n\r\"\\"):
        raise ValueError(f"unsupported path for debugfs: {rel!r}")
    return _quote(f"{prefix}/{rel}")


def debugfs_script(plan: dict, prefix: str = "/upper") -> str:
    """Return a ``debugfs -w`` script: 0:0 whiteout devices, then opaque xattrs.

    debugfs ``mknod`` links its argument literally into the current directory,
    so every whiteout is created after a ``cd`` into its parent.
    """
    lines = []
    for rel in sorted(set(plan.get("whiteouts", []))):
        _dq(prefix, rel)  # validates the whole path (also the parts quoted separately)
        parent, _, base = rel.rpartition("/")
        lines.append(f"cd {_dq(prefix, parent) if parent else _quote(prefix)}")
        lines.append(f"mknod {_quote(base)} c 0 0")
    for rel in sorted(set(plan.get("opaque", []))):
        lines.append(f"ea_set {_dq(prefix, rel)} trusted.overlay.opaque y")
    return "\n".join(lines) + ("\n" if lines else "")


def verify_script(plan: dict, prefix: str = "/upper") -> str:
    """Return a read-only debugfs script that inspects every planned object."""
    lines = []
    for rel in sorted(set(plan.get("whiteouts", []))):
        lines.append(f"stat {_dq(prefix, rel)}")
    for rel in sorted(set(plan.get("opaque", []))):
        lines.append(f"ea_get {_dq(prefix, rel)} trusted.overlay.opaque")
    return "\n".join(lines) + ("\n" if lines else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert")
    c.add_argument("layer_tar")
    c.add_argument("filtered_tar")
    c.add_argument("plan_json")
    a = sub.add_parser("prepare")
    a.add_argument("plan_json")
    a.add_argument("upper_dir")
    for name in ("debugfs", "verify"):
        d = sub.add_parser(name)
        d.add_argument("plan_json")
        d.add_argument("--prefix", default="/upper")
    args = ap.parse_args(argv)

    if args.cmd == "convert":
        plan = convert_layer(args.layer_tar, args.filtered_tar)
        with open(args.plan_json, "w", encoding="utf-8") as fh:
            json.dump(plan.as_dict(), fh, indent=1)
        print(f"layer converted: kept={plan.kept} excluded={plan.excluded} "
              f"whiteouts={len(set(plan.whiteouts))} opaque={len(set(plan.opaque))}")
        return 0
    with open(args.plan_json, encoding="utf-8") as fh:
        plan = json.load(fh)
    if args.cmd == "prepare":
        made = ensure_parents(plan, args.upper_dir)
        print(f"whiteout parent directories created: {len(made)}")
    elif args.cmd == "debugfs":
        sys.stdout.write(debugfs_script(plan, args.prefix))
    else:
        sys.stdout.write(verify_script(plan, args.prefix))
    return 0


if __name__ == "__main__":
    sys.exit(main())
