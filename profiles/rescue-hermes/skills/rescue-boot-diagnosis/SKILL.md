---
name: rescue-boot-diagnosis
description: Use when a PC cannot boot; collect bounded facts and propose only allowlisted read-only checks.
---

# Rescue boot diagnosis

Start with the skill `rescue-autorun` (the kickoff turn runs it): it reads the newest run report and the typed follow-up first. Use this skill for the diagnosis steps below after that.

1. Confirm the launcher hardware-readiness report is `ready` (or `ready_with_warnings` after reviewing each warning) or review each blocking failure before continuing.
2. Read the sanitized evidence and its manifest hash.
3. Classify the symptom: firmware entry, bootloader, filesystem, disk I/O, kernel, or unknown.
4. Use only skills that are already installed as playbooks (automatic case retrieval by signature is Planned; see `docs/hermes-learning-loop.md`).
5. Ask OpenCode Go to rank hypotheses, not to invent commands.
6. Run only the launcher's fixed read-only collectors and detection modules; propose repairs only as catalog `action_id`s (typed `tool_id` adapters are Planned).
7. Ask the operator for the verified outcome in the conversation (structured feedback labels are Planned; nothing is stored as learning automatically).

Do not run `fsck` repair mode, `grub-install`, `efibootmgr` writes, `dd`, `mkfs`, `parted`, `cryptsetup` mutation, or any arbitrary shell command from AI output.
