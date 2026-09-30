"""Additional OS detection (Linux Mint, other Linux, Windows, macOS) beyond scan-target-os.py and the host launchers.

Owned by ahliweb/linux-mint-xfce-rescue-ai#16. Contract: see scripts/rescue_modules/__init__.py
and docs/repair-framework.md. Read-only; return [] (or 'unknown' checks) when a tool or
permission is missing.
"""


def collect_system(ctx):
    return []


def collect_offline_target(ctx, root, target):
    return []
