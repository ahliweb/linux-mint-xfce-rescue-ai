# Linux Mint XFCE Rescue AI

Bootable USB rescue toolkit for diagnosing PCs that cannot boot into their operating system. It runs read-only diagnostics locally, sanitizes evidence, and optionally sends only bounded metadata to an OpenCode Go adapter for analysis.

## Design goals

- Linux Mint XFCE live USB, preferably created with Ventoy.
- Uses the rescue PC's CPU, RAM, storage, network, and USB adapters for collection.
- OpenCode Go is the AI provider; no local model and no second model router are required.
- No automatic destructive repair. Mutating actions require explicit operator approval and read-back verification.
- Secrets, raw logs, prompts, model responses, and arbitrary shell commands are excluded from the evidence contract.

## Quick start

```bash
cp config/rescue.env.example config/rescue.env
# Edit OPENCODE_ADAPTER_COMMAND only if AI analysis is enabled.
./scripts/collect-evidence.sh --output evidence.json
./scripts/validate-evidence.py evidence.json
# Optional: send the sanitized evidence through the configured OpenCode Go adapter.
./scripts/analyze-opencode-go.sh evidence.json
```

The adapter command is deliberately explicit because OpenCode CLI authentication and model naming are deployment-specific. It receives the sanitized evidence on stdin; it must not receive credentials through the evidence file.

## USB build

1. Download a current Linux Mint XFCE ISO from the official Linux Mint site.
2. Verify the ISO checksum/signature.
3. Write it to a Ventoy USB or a dedicated USB using a trusted workstation.
4. Boot the affected PC in UEFI mode when possible.
5. Connect Ethernet first when diagnosing unknown Wi-Fi hardware.
6. Mount target disks read-only and collect evidence before any repair.

This repository does not include an ISO image or bootloader writer.

## Security

Treat the rescue USB and evidence files as sensitive. Use a separate writable storage area, encrypt reports when they leave the rescue machine, and delete them only under the device owner's approved policy.

## Learning loop

The Hermes-specific architecture for becoming more effective over time is documented in [docs/hermes-learning-loop.md](docs/hermes-learning-loop.md). It uses sanitized case signatures, operator feedback, verified outcomes, curated memory, regression evaluation, and signed skill-bundle promotion. It does not permit unreviewed self-modifying repair behavior.

## Status

The standalone repository contains the v1 evidence contract, read-only collector, OpenCode Go adapter boundary, validation, fixtures, and implementation documentation. Hardware-specific repair plugins are intentionally out of scope for v1.
