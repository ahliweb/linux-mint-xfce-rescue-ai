#!/usr/bin/env bash
# Runs as root INSIDE the throwaway Linux Mint build container created by
# scripts/build-persistence.sh. It is never executed on the host.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# Inputs (environment): SKIP_HERMES=0|1, HERMES_INSTALLER_SHA256=<hex or empty>
# Inputs (files):       /opt/rescue-src  allowlisted rescue bundle
# Secrets:              none. The API key is never present in this container.
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
src=/opt/rescue-src
prefix=/usr/local/lib/rescue-omes
bin_dir=/usr/local/bin
live_user=mint
live_uid=1000
live_home=/home/mint
state_dir=$live_home/.local/share/rescue-omes
skip_hermes=${SKIP_HERMES:-0}
installer_sha256=${HERMES_INSTALLER_SHA256:-}

log() { printf '[build] %s\n' "$*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'must run as root inside the build container' >&2; exit 1; }
[[ -d $src && -f $src/scripts/install-hermes-rescue.sh ]] || { echo "missing bundle at $src" >&2; exit 1; }

# 1. Base packages + rescue tooling from the Ubuntu 24.04 (noble) archive.
log 'apt-get update'
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl git python3 python3-jsonschema sudo xz-utils adduser
optional=(dislocker libfsapfs-utils smartmontools nvme-cli)
missing_optional=()
if ! apt-get install -y -q --no-install-recommends "${optional[@]}"; then
  for pkg in "${optional[@]}"; do
    apt-get install -y -q --no-install-recommends "$pkg" || missing_optional+=("$pkg")
  done
fi
if ((${#missing_optional[@]})); then
  log "WARNING: optional packages unavailable and skipped: ${missing_optional[*]}"
else
  log "optional rescue tools installed: ${optional[*]}"
fi

# 2. Build-only live user. The account databases are NOT copied into the
# persistence image (casper creates the real user with uid 1000 on first boot);
# only the numeric ownership of /home/mint matters.
snapshot() { cut -d: -f1 /etc/passwd /etc/group | sort -u; }
if getent passwd "$live_user" >/dev/null; then
  [[ $(id -u "$live_user") -eq $live_uid ]] || { echo "existing $live_user has uid other than $live_uid" >&2; exit 1; }
else
  getent group "$live_uid" >/dev/null && { echo "gid $live_uid is already used" >&2; exit 1; }
  groupadd -g "$live_uid" "$live_user"
  useradd -m -u "$live_uid" -g "$live_uid" -s /bin/bash -c 'Live session user' "$live_user"
fi
snapshot > /tmp/accounts.after-user
# Temporary passwordless sudo for install-hermes-rescue.sh; removed below.
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$live_user" > /etc/sudoers.d/zz-rescue-omes-build
chmod 0440 /etc/sudoers.d/zz-rescue-omes-build

as_mint() {
  runuser -u "$live_user" -- env -i \
    HOME="$live_home" USER="$live_user" LOGNAME="$live_user" SHELL=/bin/bash \
    PATH="$live_home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LANG=C.UTF-8 HERMES_HOME="$state_dir/hermes" \
    UV_CACHE_DIR=/tmp/uv-cache UV_LINK_MODE=copy NPM_CONFIG_CACHE=/tmp/npm-cache \
    "$@"
}
as_mint mkdir -p "$state_dir/hermes" "$live_home/.config"
as_mint chmod 0700 "$state_dir" "$state_dir/hermes"

# 3. Hermes: official installer, run as the live user, HERMES_HOME on the
# persistent state directory so every Hermes read/write lands in the overlay.
if ((skip_hermes)); then
  log 'Hermes install skipped (--skip-hermes-install)'
else
  installer=/tmp/hermes-install.sh
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    https://hermes-agent.nousresearch.com/install.sh --output "$installer"
  actual=$(sha256sum -- "$installer" | cut -d ' ' -f 1)
  log "Hermes installer sha256: $actual"
  if [[ -n $installer_sha256 ]]; then
    if [[ ${actual,,} != "${installer_sha256,,}" ]]; then
      echo "Hermes installer SHA-256 mismatch (expected ${installer_sha256,,}); not executing it." >&2
      exit 1
    fi
    log 'Hermes installer SHA-256 verified against the pin'
  else
    log 'WARNING: Hermes installer is not pinned; pass --installer-sha256 HEX to build-persistence.sh'
  fi
  chmod 0755 "$installer"
  # No tty here, so the interactive setup/gateway stages are skipped. The
  # browser and computer-use add-ons are large and unnecessary for rescue.
  as_mint bash "$installer" --non-interactive --skip-browser --skip-computer-use
  hermes_wrapper=$live_home/.local/bin/hermes
  [[ -x $hermes_wrapper ]] || { echo "Hermes install did not publish $hermes_wrapper" >&2; exit 1; }
  ln -sfn "$hermes_wrapper" "$bin_dir/hermes"
fi

# 4. Rescue runtime bundle, profile, config, env template and XFCE autostart:
# the repository's own installer, run as the live user with sudo available.
# It skips the Hermes download because `hermes` is already on PATH.
cp -a -- "$src" /tmp/rescue-src-ro
chown -R 0:0 /tmp/rescue-src-ro
as_mint bash /tmp/rescue-src-ro/scripts/install-hermes-rescue.sh \
  --state-dir "$state_dir" --prefix "$prefix" --bin-dir "$bin_dir" --skip-hermes-install

# install-hermes-rescue.sh installs every profile skill; re-copy them here too so the
# image stays correct even when built from an older installer, then assert them.
skills_installed=()
for skill_dir in /tmp/rescue-src-ro/profiles/rescue-hermes/skills/*/; do
  [[ -f ${skill_dir}SKILL.md ]] || continue
  skill=$(basename -- "$skill_dir")
  as_mint install -d -m 0700 "$state_dir/hermes/skills/$skill"
  as_mint install -m 0600 "${skill_dir}SKILL.md" "$state_dir/hermes/skills/$skill/SKILL.md"
  skills_installed+=("$skill")
done
log "rescue skills installed: ${skills_installed[*]}"
for required in rescue-boot-diagnosis rescue-target-os rescue-skill-submission; do
  [[ -f $state_dir/hermes/skills/$required/SKILL.md ]] || { echo "required skill missing: $required" >&2; exit 1; }
done

# Replace the installer's runtime subset with the full allowlisted bundle
# (adds host/ launchers, docs, tests) so the running system carries the same
# files as the USB's rescue-omes/ directory.
rm -rf -- "$prefix"
cp -a -- "$src" "$prefix"
printf 'Rescue runtime bundle built into the persistence image by build-persistence.sh (ahlikoding.com / satpamsiber.com under ahliweb.com)\n' > "$prefix/.rescue-omes-bundle"
chown -R 0:0 "$prefix"
find "$prefix" -type d -exec chmod 0755 {} +
find "$prefix" -type f -exec chmod 0644 {} +
find "$prefix" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.command' \) -exec chmod 0755 {} +
find "$prefix" \( -name '__pycache__' \) -type d -prune -exec rm -rf {} +
ln -sfn "$prefix/scripts/launch-hermes-rescue.sh" "$bin_dir/launch-hermes-rescue.sh"
ln -sfn "$prefix/scripts/check-hermes-rescue.sh" "$bin_dir/check-hermes-rescue.sh"

# 5. In-container assertions about what was produced.
autostart=$live_home/.config/autostart/hermes-rescue.desktop
[[ -f $autostart ]] || { echo "autostart entry missing: $autostart" >&2; exit 1; }
grep -qxF "Exec=$bin_dir/launch-hermes-rescue.sh --state-dir $state_dir --hardware-mode auto" "$autostart" \
  || { echo 'autostart Exec line is not the expected launcher command' >&2; cat "$autostart" >&2; exit 1; }
[[ -f $state_dir/hermes/env && $(stat -c %a "$state_dir/hermes/env") == 600 ]] \
  || { echo 'state hermes/env missing or not 0600' >&2; exit 1; }
if grep -Eq "^OPENCODE_GO_API_KEY=[^']|^OPENCODE_GO_API_KEY='[^']" "$state_dir/hermes/env"; then
  echo 'refusing: the build container must not contain an API key' >&2
  exit 1
fi
((skip_hermes)) || [[ -x $bin_dir/hermes && -d $state_dir/hermes/hermes-agent ]] \
  || { echo 'Hermes is not installed under the state directory' >&2; exit 1; }

# 6. No system users or groups may have been added by packages: the account
# databases are excluded from the overlay and casper owns them.
snapshot > /tmp/accounts.final
if ! diff -q /tmp/accounts.after-user /tmp/accounts.final >/dev/null; then
  echo 'packages added system users/groups; the account databases are excluded from the image:' >&2
  diff /tmp/accounts.after-user /tmp/accounts.final >&2 || true
  exit 1
fi

# 7. Remove build-only artefacts so they do not reach the layer.
rm -f /etc/sudoers.d/zz-rescue-omes-build
apt-get clean
rm -rf /tmp/rescue-src-ro /tmp/hermes-install.sh /tmp/uv-cache /tmp/npm-cache /tmp/accounts.* /opt/rescue-src /opt/persistence-container-build.sh
log "done. Hermes state: $state_dir/hermes  Autostart: $autostart"
