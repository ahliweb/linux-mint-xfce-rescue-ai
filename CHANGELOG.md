# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) with the version stored in `VERSION`. This repository has no Node/changesets tooling; this file is the changeset record.

> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.

## [Unreleased]

### Added

- The Windows and macOS host launchers execute the typed repair catalog natively, under the same contract as `rescue-repair.py`: policy gate, typed parameters (no `-` suffix), a backup fingerprint identical to the Python one, and no-shell execution with a hard timeout. Windows uses `Process` with MSVCRT-correct quoting and an allowlisted child environment that never includes keys; macOS uses the argv array under `env -i`. Both run verify, then an automatic rollback or a manual rollback doc, and write a hash-chained journal in `reports/repairs/journal.jsonl` that `rescue-repair.py --verify-journal` accepts. macOS parses the catalog with the built-in JXA (`osascript -l JavaScript`). Both analyzer requests now list the applicable catalog actions. New flags: `-Approve`, `-Param`, `-BackupRef`, `-Select`, `-ListRepairs` / `--approve`, `--param`, `--backup-ref`, `--select`, `--list-repairs`. Actions that need admin rights run only from an already elevated session; the launchers never elevate. See `docs/host-repair.md`. ahliweb/linux-mint-xfce-rescue-ai#25
- OS detection and typed OS repairs: new checks `linux-boot-partition-space`, `linux-grub-config`, `linux-apt-sources`, `linux-dpkg-lock`, `windows-boot-config`, `windows-system-files`, `windows-restore-points`, `macos-disk-verify` (`scripts/rescue_modules/operating_system.py`, `host/modules/windows/os.ps1`, `host/modules/macos/os.zsh`). Catalogs: `os-linux.json` (live USB offline chroot repairs for dpkg, initramfs and GRUB; host dpkg/apt; restart failed units) and `os-windows.json` (`sfc /verifyonly`, `sfc /scannow`, `DISM /RestoreHealth`, `chkdsk /scan`). `os-macos.json` stays empty on purpose: repairs go through macOS Recovery. See `docs/os-repair.md`. ahliweb/linux-mint-xfce-rescue-ai#16
- Target mount provider `scripts/lib/target_mount.py` for offline repairs from the live USB. It re-identifies the target with the scanner's own logic and refuses on a family mismatch, encryption, unknown refs, macOS read-write, a hibernated or dirty (or unverifiable) NTFS volume, a target already mounted, or a missing separate `/boot`. It mounts under a private directory, adds chroot binds only for read-write Linux targets, and unmounts in reverse order also on signals. It never touches disks outside the rescue live session. ahliweb/linux-mint-xfce-rescue-ai#16
- Installed software inventory and health (`--scope software`, or `software.selected --packages a,b`): `scripts/rescue_modules/software.py` (live USB offline dpkg targets read-only, and the Linux host), `host/modules/windows/software.ps1` (Uninstall registry keys, Run keys, winget), and `host/modules/macos/software.zsh` (apps, pkgutil, bounded codesign). It emits numbers-only `sw-*` checks; package names never appear in evidence, and selected packages that are not installed are reported as a count. Six typed destructive catalog actions (package-state or restore-point backup, manual rollback): `sw.dpkg-configure-pending`, `sw.apt-fix-broken`, `sw.apt-reinstall-package`, `sw.dpkg-configure-target` (live USB, needs the target mount provider), `sw.winget-repair-package`, `sw.winget-upgrade-package`. See `docs/software.md`. ahliweb/linux-mint-xfce-rescue-ai#17
- Scoped hardware detection (`hardware.cpu|memory|disk|gpu|display|network|battery|usb`) in `scripts/rescue_modules/hardware.py` (live USB and Linux host), `host/modules/windows/hardware.ps1`, and `host/modules/macos/hardware.zsh`. It emits numeric-only `hw-*`, `smart-health` (live USB), and `nvme-health` checks. Four typed catalog actions: `hw.smart-short-selftest`, `hw.nvme-short-selftest`, `hw.network-service-restart` (safe) and `hw.wifi-rfkill-unblock` (reversible), on the live USB and Linux hosts. See `docs/hardware.md`. ahliweb/linux-mint-xfce-rescue-ai#15
- Evidence schema 1.2 (backward compatible): `scope`, `repair_policy`, `repair_proposals` (catalog action IDs only), hardware `hw-*` and software `sw-*` check IDs, eight more OS check IDs, `mutation_status` `failed`/`rolled_back`, and up to 160 checks. `validate-evidence.py` rejects 1.2 fields in 1.0/1.1 evidence and more than 64 checks before 1.2, and checks scope combinations, proposal targets, and trigger checks. ahliweb/linux-mint-xfce-rescue-ai#15 ahliweb/linux-mint-xfce-rescue-ai#16 ahliweb/linux-mint-xfce-rescue-ai#17
- Typed repair catalog: `rescue-ai/v1/repair-catalog.schema.json`, one catalog file per domain in `rescue-ai/v1/catalog/` (empty until the hardware/OS/software work lands), and `scripts/lib/repair_catalog.py`. The loader enforces fixed argv arrays with whole-element placeholders, forbidden programs (shells, interpreters, privilege wrappers, `dd`, network fetchers), typed parameters, and risk-class rules (`safe` / `reversible` with an automatic rollback / `destructive` with a backup and a manual or restore rollback). `make check` validates the catalogs.
- `scripts/rescue-repair.py`: policy-gated repair engine for the live USB and Linux hosts. Policies are `detect-only`, `approve-each` (default; interactive `ya`/`yes` or `--approve`, the typed `action_id` for destructive actions) and `auto-safe` (opt-in; only safe catalog-trigger actions). It takes `--backup-ref` for destructive actions, runs preconditions, verify, and automatic rollback, and writes a hash-chained journal `repairs/journal.jsonl` on the USB (`rescue-ai/v1/repair-journal.schema.json`, `--verify-journal`). AI proposals are read from a `rescue-proposals` block and accepted only as exact, applicable catalog IDs.
- Detection module hooks: `scripts/rescue_modules/` (called by `scan-target-os.py` for the machine and for each read-only mounted target, and by `host/rescue-linux.sh`), `host/modules/windows/*.ps1` (call operator, child scope), and `host/modules/macos/*.zsh` (child process). Module output is validated data.
- `--scope`, `--packages`, `--repair-policy` on `launch-hermes-rescue.sh`, `scan-target-os.py`, and `host/rescue-linux.sh`; `-Scope`, `-Packages`, `-RepairPolicy` on `host/rescue-windows.ps1`; `--scope`, `--packages`, `--repair-policy` on `host/RESCUE-MACOS.command`. All collectors now write schema 1.2. The live launcher and the Linux host launcher run the repair engine after the analysis (`--list` only in `--evidence-only`/`--dry-run`).
- `opencode-go-analyze.py` appends the applicable catalog actions (IDs and metadata, never argv) to the request, and `analysis-prompt.md` defines the `rescue-proposals` block.
- Evidence schema 1.1 (backward compatible with 1.0): `target_systems` for the operating systems examined (Linux Mint, other Linux, Windows, macOS), per-check `target_ref` and bounded numeric `value`, host platforms `linux-host`/`windows-host`/`macos-host`, OS-specific check IDs, and storage class `usb-rescue-state`. `validate-evidence.py` also rejects dangling or duplicate target references, 1.1 fields in 1.0 evidence, and a mismatched `entry_count`. ahliweb/linux-mint-xfce-rescue-ai#7
- `profiles/rescue-hermes/analysis-prompt.md`: one system prompt shared by every direct OpenCode Go client. ahliweb/linux-mint-xfce-rescue-ai#7
- `scripts/build-persistence.sh`: builds a Ventoy `casper-rw` persistence image (ext4) from the verified Mint 22.3 ISO with Hermes, both rescue skills, the full rescue bundle, XFCE autostart, and `dislocker`/`libfsapfs-utils`/`smartmontools`/`nvme-cli` pre-installed, so all Hermes state lives on the USB. It runs in docker without touching a block device, converts layer whiteouts to overlayfs form (`scripts/lib/overlay_whiteouts.py`), and places the API key only in a network-less helper container and only when provisioning is requested. See `docs/persistence.md`. ahliweb/linux-mint-xfce-rescue-ai#10
- `prepare-ventoy-usb.sh --persistence FILE.dat [--replace-persistence]`: validates the image (ext, label `casper-rw`), copies it with sha256 read-back, and merges a `persistence` entry into `/ventoy/ventoy.json`. It refuses to overwrite an existing image on the USB. ahliweb/linux-mint-xfce-rescue-ai#10
- Candidate skill submission: `scripts/submit-skill.py` and `scripts/lib/skill_sanitize.py` sanitize a candidate `SKILL.md`, secret-scan it (and refuse instead of fixing), embed a `<!-- skill-sha256: HEX -->` marker, skip content that was already submitted (open or closed issues), show a full preview, and create a `skill-candidate` GitHub issue only after operator confirmation: typing `kirim`/`submit`, or `--confirm-sha256` bound to the previewed hash when there is no terminal. New allowlisted key `RESCUE_GITHUB_ISSUES_TOKEN` (fine-grained, Issues read/write on this repository only; never on argv, in logs, in output, or in the issue). `launch-hermes-rescue.sh` removes it from the Hermes environment. Without a token, a pre-filled issue URL or a `0600` body file is printed. New Hermes skill `rescue-skill-submission` and `docs/skill-submission.md`. Real GitHub calls are Environment-blocked; maintainers must create the `skill-candidate` label. ahliweb/linux-mint-xfce-rescue-ai#18
- `prepare-ventoy-usb.sh` includes `host/` in the bundle allowlist and copies the host launchers to the USB root. ahliweb/linux-mint-xfce-rescue-ai#10

### Security

- Repair catalog `package_name` parameters may no longer end with `-`: apt reads that suffix as "remove this package", which would turn `install --reinstall` into a removal. ahliweb/linux-mint-xfce-rescue-ai#17

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
