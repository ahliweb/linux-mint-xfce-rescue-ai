# Linux Mint XFCE Rescue AI

Bootable USB rescue toolkit with a dedicated **Hermes Rescue profile** and cloud AI default:

- Provider: OpenCode Go via OpenAI-compatible endpoint
- Model: `mimo-v2.6-flash`
- OpenCode model ID: `opencode-go/mimo-v2.6-flash`
- Hermes route: `custom` + `https://opencode.ai/zen/go/v1`

The system runs read-only diagnostics locally, sanitizes evidence, and asks Hermes/OpenCode Go for bounded hypotheses and next checks. It never performs destructive repair without operator approval.

## What is implemented

- Hermes profile files: `profiles/rescue-hermes/`.
- Hermes configuration template with OpenCode Go/MiMo-V2.6-Flash as the default model.
- Bootstrap installer that installs Hermes through the official installer, creates an isolated `HERMES_HOME`, installs the rescue profile, and creates a desktop autostart entry.
- `launch-hermes-rescue.sh` to start Hermes with the isolated profile.
- `check-hermes-rescue.sh` to validate Hermes, configuration, provider endpoint, and model settings without exposing the API key.
- Read-only evidence collector and schema validator.
- `scripts/prepare-ventoy-usb.sh` — verifies the Linux Mint ISO signature/checksum before copying it.
- `scripts/verify-mint-iso.sh` — performs Linux Mint SHA-256 and GPG verification.
- `scripts/download-ventoy.sh` — downloads the official Ventoy Linux release package.
- `scripts/install-ventoy-usb.sh` — installs Ventoy only to an explicitly confirmed removable USB disk.
- `scripts/test-hermes-conversation.sh` — dry-run by default; `--live` performs one bounded cloud smoke test.
- `scripts/verify-autostart.sh` — validates the XFCE autostart entry.

## Important boot limitation

Plugging in a USB flash drive does not force a PC to boot from it. The PC firmware must support USB boot and the operator must select the USB from the boot menu or change the boot order. Secure Boot may require an approved configuration.

This repository does not silently erase disks, install Ventoy, or manufacture an ISO. Those actions are deliberately explicit and operator-confirmed.

## Quick start on a live Linux Mint XFCE session

```bash
cp config/rescue.env.example config/rescue.env
chmod 600 config/rescue.env
$EDITOR config/rescue.env   # set OPENCODE_GO_API_KEY; never commit it

sudo ./scripts/install-hermes-rescue.sh \
  --state-dir /media/$USER/RESCUE-STATE/hermes-state

./scripts/check-hermes-rescue.sh \
  --state-dir /media/$USER/RESCUE-STATE/hermes-state

./scripts/launch-hermes-rescue.sh \
  --state-dir /media/$USER/RESCUE-STATE/hermes-state
```

The state directory must be on a writable persistent partition if memory and sessions should survive reboot. For a normal live session, use a separate encrypted writable storage device.

## Prepare an existing Ventoy USB

Install Ventoy to the confirmed USB using the official Ventoy workflow first. Then mount its data partition and run:

```bash
./scripts/prepare-ventoy-usb.sh \
  --ventoy-mount /media/$USER/VENTOY \
  --mint-iso /path/to/linuxmint-xfce.iso
```

The helper copies the ISO and the rescue bundle. It does not install Ventoy and does not write a raw disk. On boot, choose the Linux Mint XFCE ISO, connect the network, and run the bootstrap script from the copied rescue bundle.

## End-to-end execution checklist

1. Identify the removable USB with `lsblk -o NAME,PATH,RM,SIZE,MODEL,TRAN,MOUNTPOINTS`. Do not use `/dev/sda` or any disk with mounted children. Download and extract Ventoy, then run `sudo ./scripts/install-ventoy-usb.sh --device /dev/sdX --ventoy-dir ./ventoy-X.Y.Z --yes` only after reviewing the displayed model and size.
2. Download Linux Mint XFCE plus `sha256sum.txt` and `sha256sum.txt.gpg` from the same official mirror. Verify with `scripts/verify-mint-iso.sh`.
3. Mount the first Ventoy partition and run `scripts/prepare-ventoy-usb.sh` with the ISO, checksum file, and signature file. This copies the ISO and rescue source bundle.
4. On the target PC, select the USB in the UEFI/BIOS boot menu. The USB cannot force boot merely by being plugged in.
5. In the Linux Mint XFCE desktop, connect the network and open a terminal in the copied `rescue-omes` directory.
6. Run `sudo ./scripts/install-hermes-rescue.sh --state-dir /media/$USER/RESCUE-STATE/hermes-state`.
7. Set `OPENCODE_GO_API_KEY` in `config/rescue.env`, then run `./scripts/check-hermes-rescue.sh --state-dir ...`.
8. Run `./scripts/test-hermes-conversation.sh --state-dir ... --live` only after approving a real cloud request. Without `--live`, it is a no-cost dry run.
9. Run `./scripts/verify-autostart.sh --state-dir ...`, reboot from the live environment, log in to XFCE, and verify the launcher with `pgrep -af hermes`. A physical reboot is required; it is not simulated by the source repository.


OpenCode Go credentials are secrets. They are not stored in this repository or in evidence. Set `OPENCODE_GO_API_KEY` in the local `config/rescue.env`, or place it in the isolated Hermes secret environment at setup time.

OpenCode Go currently documents the model as `MiMo-V2.6-Flash` with model ID `mimo-v2.6-flash`. Model availability and plan limits can change, so `check-hermes-rescue.sh` verifies the configured ID and endpoint but does not invent a fallback provider.

## Security boundary

Hermes has a separate rescue profile and must not reuse the operator's personal `~/.hermes` directory. Default actions are read-only. Logs are untrusted data and cannot issue commands. Skills are versioned and candidate learning is not promoted without verification and approval.

See:

- [Hermes learning loop](docs/hermes-learning-loop.md)
- [Rescue design](docs/design.md)
- [Hermes profile](profiles/rescue-hermes/)
- [OpenCode Go documentation](https://opencode.ai/docs/go)
- [Hermes provider documentation](https://hermes-agent.nousresearch.com/docs/integrations/providers)
