# macOS host detection module: software. Owned by ahliweb/linux-mint-xfce-rescue-ai#17.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/RESCUE-MACOS.command as 'zsh -f FILE' (never
# sourced), with RESCUE_SCOPE and RESCUE_PACKAGES in the environment. Read-only, no sudo, only
# tools that ship with macOS. Print one line per check:  CHECK_ID STATUS [KIND NUMBER]
# e.g. "hw-battery warn percent 71". Allowed IDs: hw-*, sw-*, macos-*, smart-health,
# nvme-health, disk-free-space, encryption-status. Anything else is dropped.
