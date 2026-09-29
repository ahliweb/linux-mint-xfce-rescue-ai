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
- Ventoy preparation helper that copies a verified Linux Mint XFCE ISO and this rescue bundle to an already-installed Ventoy partition.
- Hermes closed-loop learning design: sanitized cases, feedback, verification, candidate skills, regression evaluation, and signed promotion.

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

## OpenCode Go authentication

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
