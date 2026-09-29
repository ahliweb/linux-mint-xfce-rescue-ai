#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
state_dir=${RESCUE_STATE_DIR:-"$HOME/.local/share/rescue-omes"}
while (($#)); do
  case "$1" in
    --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
    *) printf 'usage: %s [--state-dir DIR]\n' "$0" >&2; exit 2 ;;
  esac
done

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  printf 'Run this script as the live-session desktop user, not as root. It uses sudo only where required.\n' >&2
  exit 1
fi
sudo_cmd=()
if [[ ! -w /usr/local/bin ]]; then
  command -v sudo >/dev/null 2>&1 || { printf 'sudo is required to install the launcher.\n' >&2; exit 1; }
  sudo_cmd=(sudo)
fi

install -d -m 0700 "$state_dir/hermes" "$state_dir/cases" "$state_dir/learning/candidates" "$state_dir/learning/approved"

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  "${sudo_cmd[@]}" apt-get update
  "${sudo_cmd[@]}" apt-get install -y ca-certificates curl git python3 python3-jsonschema
fi

if ! command -v hermes >/dev/null 2>&1; then
  installer=$(mktemp)
  trap 'rm -f "$installer"' EXIT
  curl --fail --silent --show-error --location \
    https://hermes-agent.nousresearch.com/install.sh --output "$installer"
  chmod 700 "$installer"
  printf 'Downloaded the official Hermes installer to %s. Executing it now.\n' "$installer"
  bash "$installer"
fi

"${sudo_cmd[@]}" install -d -m 0755 /usr/local/bin
"${sudo_cmd[@]}" install -m 0755 "$root/scripts/launch-hermes-rescue.sh" /usr/local/bin/launch-hermes-rescue.sh
"${sudo_cmd[@]}" install -m 0755 "$root/scripts/check-hermes-rescue.sh" /usr/local/bin/check-hermes-rescue.sh

install -d -m 0700 "$state_dir/hermes/skills/rescue-boot-diagnosis"
install -m 0600 "$root/profiles/rescue-hermes/SOUL.md" "$state_dir/hermes/SOUL.md"
install -m 0600 "$root/profiles/rescue-hermes/AGENTS.md" "$state_dir/hermes/AGENTS.md"
install -m 0600 "$root/profiles/rescue-hermes/skills/rescue-boot-diagnosis/SKILL.md" \
  "$state_dir/hermes/skills/rescue-boot-diagnosis/SKILL.md"
install -m 0600 "$root/config/hermes-rescue.config.yaml" "$state_dir/hermes/config.yaml"

if [[ ! -f "$root/config/rescue.env" ]]; then
  install -m 0600 "$root/config/rescue.env.example" "$root/config/rescue.env"
  printf 'Created %s; set OPENCODE_GO_API_KEY before starting Hermes.\n' "$root/config/rescue.env" >&2
fi

install -d -m 0755 "$HOME/.config/autostart"
sed "s|/usr/local/bin/launch-hermes-rescue.sh|/usr/local/bin/launch-hermes-rescue.sh --state-dir $state_dir|" \
  "$root/profiles/rescue-hermes/hermes-rescue.desktop" > "$HOME/.config/autostart/hermes-rescue.desktop"
chmod 0644 "$HOME/.config/autostart/hermes-rescue.desktop"

if [[ -f "$root/config/rescue.env" ]]; then
  # shellcheck disable=SC1091
  source "$root/config/rescue.env"
fi
cat > "$state_dir/hermes/env" <<EOF
export HERMES_HOME=$(printf '%q' "$state_dir/hermes")
export OPENCODE_GO_API_KEY=$(printf '%q' "${OPENCODE_GO_API_KEY:-}")
EOF
chmod 0600 "$state_dir/hermes/env"

printf 'Hermes Rescue installed. State: %s\n' "$state_dir"
printf 'Next: set OPENCODE_GO_API_KEY in config/rescue.env, run check-hermes-rescue.sh, then launch Hermes.\n'
