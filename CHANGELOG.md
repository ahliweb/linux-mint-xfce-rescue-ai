# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) with the version stored in `VERSION`. This repository has no Node/changesets tooling; this file is the changeset record.

> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.

## [Unreleased]

### Added

- Evidence schema 1.1 (backward compatible with 1.0): `target_systems` for the operating systems examined (Linux Mint, other Linux, Windows, macOS), per-check `target_ref` and bounded numeric `value`, host platforms `linux-host`/`windows-host`/`macos-host`, OS-specific check IDs, and storage class `usb-rescue-state`. `validate-evidence.py` also rejects dangling or duplicate target references, 1.1 fields in 1.0 evidence, and a mismatched `entry_count`. ahliweb/linux-mint-xfce-rescue-ai#7
- `profiles/rescue-hermes/analysis-prompt.md`: one system prompt shared by every direct OpenCode Go client. ahliweb/linux-mint-xfce-rescue-ai#7
- `scripts/build-persistence.sh`: builds a Ventoy `casper-rw` persistence image (ext4) from the verified Mint 22.3 ISO with Hermes, both rescue skills, the full rescue bundle, XFCE autostart, and `dislocker`/`libfsapfs-utils`/`smartmontools`/`nvme-cli` pre-installed, so all Hermes state lives on the USB. It runs in docker without touching a block device, converts layer whiteouts to overlayfs form (`scripts/lib/overlay_whiteouts.py`), and places the API key only in a network-less helper container and only when provisioning is requested. See `docs/persistence.md`. ahliweb/linux-mint-xfce-rescue-ai#10
- `prepare-ventoy-usb.sh --persistence FILE.dat [--replace-persistence]`: validates the image (ext, label `casper-rw`), copies it with sha256 read-back, and merges a `persistence` entry into `/ventoy/ventoy.json`. It refuses to overwrite an existing image on the USB. ahliweb/linux-mint-xfce-rescue-ai#10
- Candidate skill submission: `scripts/submit-skill.py` and `scripts/lib/skill_sanitize.py` sanitize a candidate `SKILL.md`, secret-scan it (and refuse instead of fixing), embed a `<!-- skill-sha256: HEX -->` marker, skip content that was already submitted (open or closed issues), show a full preview, and create a `skill-candidate` GitHub issue only after operator confirmation: typing `kirim`/`submit`, or `--confirm-sha256` bound to the previewed hash when there is no terminal. New allowlisted key `RESCUE_GITHUB_ISSUES_TOKEN` (fine-grained, Issues read/write on this repository only; never on argv, in logs, in output, or in the issue). `launch-hermes-rescue.sh` removes it from the Hermes environment. Without a token, a pre-filled issue URL or a `0600` body file is printed. New Hermes skill `rescue-skill-submission` and `docs/skill-submission.md`. Real GitHub calls are Environment-blocked; maintainers must create the `skill-candidate` label. ahliweb/linux-mint-xfce-rescue-ai#18
- `prepare-ventoy-usb.sh` includes `host/` in the bundle allowlist and copies the host launchers to the USB root. ahliweb/linux-mint-xfce-rescue-ai#10

## [0.2.1] - 2026-09-30

### Fixed

- `prepare-ventoy-usb.sh` accepted only a Ventoy data partition that already contained `ventoy/`, `ventoy.json`, or `EFI/`, so it refused a freshly installed (empty) Ventoy USB. It now also recognizes the `Ventoy`-labelled partition whose disk has a sibling `VTOYEFI` partition.
- `prepare-ventoy-usb.sh` wrote the auto-boot configuration to `<mount>/ventoy.json`, which Ventoy ignores; it now writes `<mount>/ventoy/ventoy.json`, so `VTOY_DEFAULT_IMAGE` and `VTOY_MENU_TIMEOUT` take effect. USBs prepared with 0.2.0 should be re-prepared (or the file moved into `ventoy/`).

## [0.2.0] - 2026-09-29

### Security

- `verify-mint-iso.sh` now requires the Linux Mint signing key fingerprint `27DEB15644C6B3CF3BD7D291300F846BA25BAE09` by default (`--signer-fingerprint`, `--gpg-homedir`) and compares the ISO SHA-256 directly against exactly one checksum entry. ahliweb/linux-mint-xfce-rescue-ai#1
- `download-ventoy.sh` makes a single release API call, validates `--version`, checks the download URL, requires a SHA-256 digest, and removes the file on mismatch. ahliweb/linux-mint-xfce-rescue-ai#1
- `install-ventoy-usb.sh` parses `lsblk` JSON and refuses mounted disks, non-whole-disk targets, and the disk backing the root filesystem. ahliweb/linux-mint-xfce-rescue-ai#1
- `prepare-ventoy-usb.sh` copies the rescue bundle from an allowlist so `.env`, `config/rescue.env`, `.git`, ISOs, and archives are never written to the USB by the bundle copy; API-key provisioning stays an explicit, allowlisted step. ahliweb/linux-mint-xfce-rescue-ai#1
- `check-hermes-rescue.sh` sends the API key to `curl` through a stdin config instead of the command line. ahliweb/linux-mint-xfce-rescue-ai#2
- Config files are read by the new allowlisted parser `scripts/lib/rescue-env.sh` and are never executed; world-writable files are refused. ahliweb/linux-mint-xfce-rescue-ai#2
- Evidence and hardware-readiness reports are created `0600` atomically. ahliweb/linux-mint-xfce-rescue-ai#3

### Fixed

- Installed Hermes launcher works: `install-hermes-rescue.sh` installs a runtime bundle and symlinks the launcher and check scripts; scripts resolve their root through `readlink -f`. ahliweb/linux-mint-xfce-rescue-ai#2
- `README.md` no longer tells operators to run `sudo ./scripts/install-hermes-rescue.sh`; the installer refuses root and uses `sudo` internally. ahliweb/linux-mint-xfce-rescue-ai#2
- `collect-evidence.sh` no longer claims verification it did not perform (`hashes_verified: false`, `status: not_applicable`); check status derives from real signals. ahliweb/linux-mint-xfce-rescue-ai#3
- The hardware-readiness wizard shows the real minimum for each check. ahliweb/linux-mint-xfce-rescue-ai#3
- Launcher thresholds (`--min-cpu`, `--min-ram-gib`, `--min-usb-gib`) and `OPENCODE_TIMEOUT_SECONDS` are validated. ahliweb/linux-mint-xfce-rescue-ai#2

### Added

- `scripts/install-hermes-rescue.sh` options `--prefix` (default `/usr/local/lib/rescue-omes`), `--bin-dir` (default `/usr/local/bin`), `--installer-sha256` / `HERMES_INSTALLER_SHA256`, `--no-autostart`, and `--skip-hermes-install`; honors `RESCUE_STATE_DIR`. ahliweb/linux-mint-xfce-rescue-ai#2
- `prepare-ventoy-usb.sh --bundle-only DEST`, `--signer-fingerprint`, `--gpg-homedir`, and read-back hash verification of the copied ISO. ahliweb/linux-mint-xfce-rescue-ai#1
- `validate-evidence.py` accepts several files and uses exit codes `0` valid, `1` invalid, `2` usage or parse error. ahliweb/linux-mint-xfce-rescue-ai#3
- `analyze-opencode-go.sh` validates evidence before sending it to the operator-configured adapter; `config/rescue.env` is optional. ahliweb/linux-mint-xfce-rescue-ai#2
- `make check` (syntax, `shellcheck -x`, fixture validation, unit tests, diff check), GitHub Actions CI (`.github/workflows/ci.yml`), `VERSION`, and 52 unit tests in `tests/`. ahliweb/linux-mint-xfce-rescue-ai#4
- Documentation: `docs/testing.md`, `docs/security-model.md`, and this changelog.

### Changed

- `AGENTS.md` verification commands now lead with `make check` and `shellcheck`, and define the SemVer and changelog rule.
- `README.md` marks each component as implemented, hardware-required, environment-blocked, or planned, documents the config file format, and updates the Ventoy preparation diagram to the allowlisted bundle flow.
- `docs/design.md` describes the implemented collector and the hardened media workflow.

## [0.1.0]

Baseline of the toolkit before versioning was introduced.

### Added

- Initial Linux Mint XFCE Rescue AI toolkit: read-only evidence collector, `rescue-ai/v1` evidence schema with valid and invalid fixtures, and validator.
- Hermes Rescue profile (`profiles/rescue-hermes/`) with OpenCode Go and `mimo-v2.6-flash` as the default model, isolated `HERMES_HOME`, bootstrap installer, health check, launcher, smoke-test script, and XFCE autostart.
- Ventoy workflow: download, install to a confirmed USB, and prepare scripts with Linux Mint ISO verification and automatic ISO selection.
- Hardware readiness preflight (CPU, RAM, VGA/display, internet, USB live media) with `auto` and `wizard` modes and a JSON report.
- Governance and design documentation, Mermaid diagrams, and the MIT license (`docs/`, `LICENSE`).
