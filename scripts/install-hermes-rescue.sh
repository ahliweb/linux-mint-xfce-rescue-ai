#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

usage() {
  printf 'usage: %s [--state-dir DIR] [--prefix DIR] [--bin-dir DIR] [--installer-sha256 HEX] [--no-autostart] [--skip-hermes-install]\n' "$0" >&2
}

state_dir="$HOME/.local/share/rescue-omes"
state_dir_set=0
prefix=/usr/local/lib/rescue-omes
bin_dir=/usr/local/bin
installer_sha256=${HERMES_INSTALLER_SHA256:-}
autostart=1
skip_hermes=0
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; state_dir_set=1; shift 2 ;;
    --prefix) prefix=${2:?missing prefix directory}; shift 2 ;;
    --bin-dir) bin_dir=${2:?missing launcher directory}; shift 2 ;;
    --installer-sha256) installer_sha256=${2:?missing SHA-256 hex digest}; shift 2 ;;
    --no-autostart) autostart=0; shift ;;
    --skip-hermes-install) skip_hermes=1; shift ;;
    *) usage; exit 2 ;;
  esac
done

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  printf 'Run this script as the live-session desktop user, not as root. It uses sudo only where required.\n' >&2
  exit 1
fi

# Optional source-tree config: may provide RESCUE_STATE_DIR and OPENCODE_GO_API_KEY.
rescue_load_env "$root/config/rescue.env" || exit 1
if ((!state_dir_set)) && [[ -n ${RESCUE_STATE_DIR:-} ]]; then
  state_dir=$RESCUE_STATE_DIR
fi

if [[ -n $installer_sha256 && ! $installer_sha256 =~ ^[0-9a-fA-F]{64}$ ]]; then
  printf 'Invalid installer SHA-256 (expected 64 hex characters).\n' >&2
  exit 2
fi
case $state_dir in *$'\n'* | *'%'*)
  printf 'State directory must not contain a newline or %%: refusing.\n' >&2
  exit 2 ;;
esac
abs_path() { realpath -m -- "$1"; }
state_dir=$(abs_path "$state_dir")
prefix=$(abs_path "$prefix")
bin_dir=$(abs_path "$bin_dir")
case $prefix in
  / | "$HOME" | "$root") printf 'Refusing unsafe --prefix: %s\n' "$prefix" >&2; exit 2 ;;
esac
case $root/ in
  "$prefix"/*) printf 'Refusing --prefix that contains the source tree: %s\n' "$prefix" >&2; exit 2 ;;
esac
case $prefix in *$'\n'*) printf 'Prefix must not contain a newline.\n' >&2; exit 2 ;; esac
case $bin_dir in *$'\n'*) printf 'Bin dir must not contain a newline.\n' >&2; exit 2 ;; esac

# A path needs sudo when its nearest existing ancestor (or itself, if present) is not writable.
needs_sudo() {
  local p=$1
  if [[ -e $p ]]; then
    [[ -w $p ]] || return 0
  fi
  while [[ ! -e $p ]]; do p=$(dirname -- "$p"); done
  [[ -d $p && -w $p ]] || return 0
  return 1
}
sudo_cmd=()
if needs_sudo "$bin_dir" || needs_sudo "$prefix" || needs_sudo "$(dirname -- "$prefix")"; then
  command -v sudo >/dev/null 2>&1 || { printf 'sudo is required to install into %s and %s.\n' "$prefix" "$bin_dir" >&2; exit 1; }
  sudo_cmd=(sudo)
fi

install -d -m 0700 "$state_dir" "$state_dir/hermes" "$state_dir/cases" "$state_dir/learning/candidates" "$state_dir/learning/approved"

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import jsonschema" >/dev/null 2>&1 || { ((!skip_hermes)) && ! command -v curl >/dev/null 2>&1; }; then
  "${sudo_cmd[@]}" apt-get update
  "${sudo_cmd[@]}" apt-get install -y ca-certificates curl git python3 python3-jsonschema
fi

if ! command -v hermes >/dev/null 2>&1; then
  if ((skip_hermes)); then
    printf 'WARNING: hermes is not installed and --skip-hermes-install was given; install it before launching.\n' >&2
  else
    installer=$(mktemp)
    trap 'rm -f "$installer"' EXIT
    curl --fail --silent --show-error --location \
      https://hermes-agent.nousresearch.com/install.sh --output "$installer"
    if [[ -n $installer_sha256 ]]; then
      actual_sha256=$(sha256sum -- "$installer" | cut -d ' ' -f 1)
      if [[ ${actual_sha256,,} != "${installer_sha256,,}" ]]; then
        printf 'Hermes installer SHA-256 mismatch (expected %s, got %s); not executing it.\n' "${installer_sha256,,}" "$actual_sha256" >&2
        exit 1
      fi
      printf 'Hermes installer SHA-256 verified.\n'
    else
      printf 'WARNING: the Hermes installer is not pinned. Set HERMES_INSTALLER_SHA256 or pass --installer-sha256 HEX to verify it before execution.\n' >&2
    fi
    chmod 700 "$installer"
    printf 'Downloaded the official Hermes installer to %s. Executing it now.\n' "$installer"
    bash "$installer"
  fi
fi

# Runtime bundle: scripts, schema, profiles, docs (the run report cites them) and config templates. Never rescue.env or .env.
if [[ -e $prefix && ! -f $prefix/.rescue-omes-bundle ]] && [[ -n $(ls -A -- "$prefix" 2>/dev/null) || ! -d $prefix ]]; then
  printf 'Refusing to replace %s: it exists and is not a rescue-omes bundle.\n' "$prefix" >&2
  exit 1
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"; [[ -z ${installer:-} ]] || rm -f "$installer"' EXIT
install -d -m 0755 "$stage/config"
cp -R -- "$root/scripts" "$root/rescue-ai" "$root/profiles" "$root/docs" "$stage/"
install -m 0644 "$root/config/hermes-rescue.config.yaml" "$root/config/rescue.env.example" "$stage/config/"
find "$stage" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
find "$stage/scripts" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} +
printf 'Rescue runtime bundle installed by install-hermes-rescue.sh (ahlikoding.com / satpamsiber.com under ahliweb.com)\n' > "$stage/.rescue-omes-bundle"
chmod 0644 "$stage/.rescue-omes-bundle"
if ((${#sudo_cmd[@]})); then
  "${sudo_cmd[@]}" chown -R 0:0 "$stage"
fi
"${sudo_cmd[@]}" install -d -m 0755 "$(dirname -- "$prefix")" "$bin_dir"
"${sudo_cmd[@]}" rm -rf -- "$prefix"
"${sudo_cmd[@]}" mv -- "$stage" "$prefix"
"${sudo_cmd[@]}" ln -sfn -- "$prefix/scripts/launch-hermes-rescue.sh" "$bin_dir/launch-hermes-rescue.sh"
"${sudo_cmd[@]}" ln -sfn -- "$prefix/scripts/check-hermes-rescue.sh" "$bin_dir/check-hermes-rescue.sh"
"${sudo_cmd[@]}" ln -sfn -- "$prefix/scripts/malware-quarantine.py" "$bin_dir/rescue-malware-quarantine"
trap '[[ -z ${installer:-} ]] || rm -f "$installer"' EXIT

install -m 0600 "$root/profiles/rescue-hermes/SOUL.md" "$state_dir/hermes/SOUL.md"
install -m 0600 "$root/profiles/rescue-hermes/AGENTS.md" "$state_dir/hermes/AGENTS.md"
# Every skill shipped in the profile (rescue-boot-diagnosis, rescue-target-os, rescue-skill-submission, ...).
for skill_dir in "$root"/profiles/rescue-hermes/skills/*/; do
  [[ -f ${skill_dir}SKILL.md ]] || continue
  skill=$(basename -- "$skill_dir")
  install -d -m 0700 "$state_dir/hermes/skills/$skill"
  install -m 0600 "${skill_dir}SKILL.md" "$state_dir/hermes/skills/$skill/SKILL.md"
done
install -m 0600 "$root/config/hermes-rescue.config.yaml" "$state_dir/hermes/config.yaml"

# Convenience template for the operator; only created in a writable source tree.
if [[ ! -f "$root/config/rescue.env" && -w "$root/config" ]]; then
  install -m 0600 "$root/config/rescue.env.example" "$root/config/rescue.env"
  printf 'Created %s; set OPENCODE_GO_API_KEY before starting Hermes.\n' "$root/config/rescue.env" >&2
fi

# Desktop entry: the terminal is opened explicitly (xfce4-terminal --maximize -x LAUNCHER ...) so the
# operator always sees the launcher. The same entry goes to the application menu (re-run after connecting
# Wi-Fi; always installed) and, unless --no-autostart, to the XFCE autostart directory.
template="$root/profiles/rescue-hermes/hermes-rescue.desktop"
launcher_q=$(rescue_desktop_quote "$bin_dir/launch-hermes-rescue.sh") || { printf 'Unsupported launcher path for the desktop entry.\n' >&2; exit 2; }
state_q=$(rescue_desktop_quote "$state_dir") || { printf 'Unsupported state directory for the desktop entry (newline or %%).\n' >&2; exit 2; }
render_desktop() { # render_desktop MODE(menu|autostart): fill the template placeholders
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $1 == menu && $line == X-GNOME-Autostart-enabled=* ]]; then continue; fi
    line=${line//@LAUNCHER@/"$launcher_q"}
    line=${line//@STATE_DIR@/"$state_q"}
    printf '%s\n' "$line"
  done < "$template"
}
install -d -m 0755 "$HOME/.local/share/applications"
render_desktop menu > "$HOME/.local/share/applications/hermes-rescue.desktop"
chmod 0644 "$HOME/.local/share/applications/hermes-rescue.desktop"
if ((autostart)); then
  install -d -m 0755 "$HOME/.config/autostart"
  render_desktop autostart > "$HOME/.config/autostart/hermes-rescue.desktop"
  chmod 0644 "$HOME/.config/autostart/hermes-rescue.desktop"
fi

# Preserve an existing key when re-running the installer without a new one.
rescue_load_env "$state_dir/hermes/env" || exit 1
api_key=${OPENCODE_GO_API_KEY:-}
case $api_key in *$'\n'* | *$'\r'*)
  printf 'OPENCODE_GO_API_KEY must not contain newlines; refusing.\n' >&2
  exit 2 ;;
esac
(
  umask 077
  {
    printf 'HERMES_HOME=%s\n' "$(rescue_sh_squote "$state_dir/hermes")"
    printf 'OPENCODE_GO_API_KEY=%s\n' "$(rescue_sh_squote "$api_key")"
  } > "$state_dir/hermes/env"
)
chmod 0600 "$state_dir/hermes/env"

printf 'Hermes Rescue installed. Bundle: %s  Launchers: %s  State: %s\n' "$prefix" "$bin_dir" "$state_dir"
printf 'Next: set OPENCODE_GO_API_KEY in config/rescue.env, run check-hermes-rescue.sh, then launch Hermes.\n'
