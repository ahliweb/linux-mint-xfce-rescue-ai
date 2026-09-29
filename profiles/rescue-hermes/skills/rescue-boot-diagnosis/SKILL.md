---
name: rescue-boot-diagnosis
description: Use when a PC cannot boot; collect bounded facts and propose only allowlisted read-only checks.
---

# Rescue boot diagnosis

1. Read the sanitized evidence and its manifest hash.
2. Classify the symptom: firmware entry, bootloader, filesystem, disk I/O, kernel, or unknown.
3. Retrieve only matching approved playbooks.
4. Ask OpenCode Go to rank hypotheses, not to invent commands.
5. Run only typed read-only adapters.
6. Ask the operator to label the result after verification.

Do not run `fsck` repair mode, `grub-install`, `efibootmgr` writes, `dd`, `mkfs`, `parted`, `cryptsetup` mutation, or any arbitrary shell command from AI output.
