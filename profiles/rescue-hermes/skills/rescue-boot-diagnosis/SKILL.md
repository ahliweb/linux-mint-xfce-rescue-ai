---
name: rescue-boot-diagnosis
description: Use when a PC cannot boot; collect bounded facts and propose only allowlisted read-only checks.
---

# Rescue boot diagnosis

1. Confirm the launcher hardware-readiness report is `ready` or review each blocking failure before continuing.
2. Read the sanitized evidence and its manifest hash.
3. Classify the symptom: firmware entry, bootloader, filesystem, disk I/O, kernel, or unknown.
4. Retrieve only matching approved playbooks.
5. Ask OpenCode Go to rank hypotheses, not to invent commands.
6. Run only typed read-only adapters.
7. Ask the operator to label the result after verification.

Do not run `fsck` repair mode, `grub-install`, `efibootmgr` writes, `dd`, `mkfs`, `parted`, `cryptsetup` mutation, or any arbitrary shell command from AI output.
