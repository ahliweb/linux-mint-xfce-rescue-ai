"""Hardware detection (CPU, memory, disk, GPU, display, network, battery, USB).

Owned by ahliweb/linux-mint-xfce-rescue-ai#15. Contract: see scripts/rescue_modules/__init__.py
and docs/repair-framework.md. Read-only; return [] (or 'unknown' checks) when a tool or
permission is missing.
"""


def collect_system(ctx):
    return []


def collect_offline_target(ctx, root, target):
    return []
