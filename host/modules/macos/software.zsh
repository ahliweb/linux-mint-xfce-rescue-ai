# macOS host detection module: software. Owned by ahliweb/linux-mint-xfce-rescue-ai#17.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/RESCUE-MACOS.command as 'zsh -f FILE' (never
# sourced), with RESCUE_SCOPE and RESCUE_PACKAGES in the environment. Read-only, no sudo, only
# tools that ship with macOS. Print one line per check:  CHECK_ID STATUS [KIND NUMBER]
# e.g. "hw-battery warn percent 71". Allowed IDs: hw-*, sw-*, macos-*, smart-health,
# nvme-health, disk-free-space, encryption-status. Anything else is dropped.
#
# Evidence carries NUMBERS ONLY: never an app name, bundle ID or path.
# Sources: /Applications and ~/Applications (*.app count), `pkgutil --pkgs` (receipt count),
# launch agent/daemon plists (startup items) and, for operator-selected apps only,
# `codesign --verify` (at most 10 apps, each bounded to 20 seconds).
# RESCUE_TEST_ROOT is a test hook that prefixes the /Applications and /Library paths.

setopt null_glob no_unset 2>/dev/null

root=${RESCUE_TEST_ROOT:-}
scope=${RESCUE_SCOPE:-all}
packages=${RESCUE_PACKAGES:-}
max_selected=10
startup_warn=50

run_bounded() {
  # run_bounded SECONDS COMMAND... : exit status of COMMAND, 124 on timeout, 127 when missing
  local secs=$1 pid watcher rc
  shift
  (( $+commands[$1] )) || return 127
  "$@" >/dev/null 2>&1 &
  pid=$!
  ( sleep $secs; kill $pid 2>/dev/null ) >/dev/null 2>&1 &
  watcher=$!
  wait $pid 2>/dev/null
  rc=$?
  kill $watcher 2>/dev/null
  wait $watcher 2>/dev/null
  (( rc > 128 )) && return 124
  return $rc
}

selected=()
if [[ ,$scope, == *,software.selected,* ]]; then
  for p in ${(s:,:)packages}; do
    [[ $p =~ '^[A-Za-z0-9][A-Za-z0-9+._@-]{0,127}$' ]] && selected+=($p)
  done
  selected=(${selected[1,$max_selected]})
fi

app_dirs=($root/Applications $HOME/Applications)

if (( ${#selected} )); then
  present=0 missing=0 bad=0 unknown=0
  for name in $selected; do
    found=''
    for d in $app_dirs; do
      [[ -d $d/$name.app && ! -L $d/$name.app ]] && found=$d/$name.app && break
    done
    if [[ -z $found ]]; then
      (( missing++ ))
      continue
    fi
    (( present++ ))
    run_bounded 20 codesign --verify --deep --strict "$found"
    case $? in
      0) ;;
      127) (( unknown++ )) ;;
      *) (( bad++ )) ;;
    esac
  done
  if (( present == 0 && missing == 0 )); then
    print -r -- 'sw-inventory unknown'
  else
    inv=pass; (( missing )) && inv=warn
    print -r -- "sw-inventory $inv count $present"
  fi
  if (( unknown && ! bad )); then
    print -r -- 'sw-app-health unknown'
  elif (( bad )); then
    print -r -- "sw-app-health fail count $(( bad + missing ))"
  elif (( missing )); then
    print -r -- "sw-app-health warn count $missing"
  else
    print -r -- 'sw-app-health pass count 0'
  fi
else
  napps=0 readable=0
  for d in $app_dirs; do
    [[ -d $d ]] || continue
    readable=1
    apps=($d/*.app(N))
    (( napps += ${#apps} ))
  done
  if (( readable )); then
    inv=pass; (( napps == 0 )) && inv=warn
    print -r -- "sw-inventory $inv count $napps"
  else
    print -r -- 'sw-inventory unknown'
  fi
  print -r -- 'sw-app-health not_applicable'
fi

# Installer receipts known to macOS (pkgutil --pkgs), counted, never listed.
if (( $+commands[pkgutil] )); then
  if pkgs=$(pkgutil --pkgs 2>/dev/null); then
    pkg_list=(${(f)pkgs})
    print -r -- "sw-package-health pass count ${#pkg_list}"
  else
    print -r -- 'sw-package-health unknown'
  fi
else
  print -r -- 'sw-package-health unknown'
fi

# Startup items: launch agent / daemon plists (login items proper need osascript, which is not used).
nstart=0 sreadable=0
for d in $HOME/Library/LaunchAgents $root/Library/LaunchAgents $root/Library/LaunchDaemons; do
  [[ -d $d ]] || continue
  sreadable=1
  items=($d/*.plist(N))
  (( nstart += ${#items} ))
done
if (( sreadable )); then
  st=pass; (( nstart > startup_warn )) && st=warn
  print -r -- "sw-startup-items $st count $nstart"
else
  print -r -- 'sw-startup-items unknown'
fi
