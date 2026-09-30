# macOS host detection module: os. Owned by ahliweb/linux-mint-xfce-rescue-ai#16.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/RESCUE-MACOS.command as 'zsh -f FILE' (never
# sourced), with RESCUE_SCOPE and RESCUE_PACKAGES in the environment. Read-only, no sudo, only
# tools that ship with macOS. Print one line per check:  CHECK_ID STATUS [KIND NUMBER]
# e.g. "hw-battery warn percent 71". Allowed IDs: hw-*, sw-*, macos-*, smart-health,
# nvme-health, disk-free-space, encryption-status. Anything else is dropped.
#
# macos-disk-verify: NOT `diskutil verifyVolume` (not read-only safe on the running startup
# disk). Only `diskutil info` / `diskutil apfs list` status: the startup volume is mounted and its
# APFS container is listed; a "Failing" SMART status is a fail. Anything unreadable is unknown.

emulate -L zsh
setopt no_unset pipe_fail 2>/dev/null

if (( ! $+commands[diskutil] )); then
  print -r -- "macos-disk-verify unknown"
  exit 0
fi

info=$(diskutil info / 2>/dev/null) || info=''
apfs=$(diskutil apfs list 2>/dev/null) || apfs=''

if [[ -z $info ]]; then
  print -r -- "macos-disk-verify unknown"
elif [[ $info =~ 'SMART Status:[[:space:]]*Failing' ]]; then
  print -r -- "macos-disk-verify fail"
elif [[ $info =~ 'Mounted:[[:space:]]*Yes' && -n $apfs ]]; then
  print -r -- "macos-disk-verify pass"
elif [[ $info =~ 'Mounted:[[:space:]]*Yes' ]]; then
  print -r -- "macos-disk-verify warn"
else
  print -r -- "macos-disk-verify unknown"
fi
