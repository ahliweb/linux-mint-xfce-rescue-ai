# macOS host detection module: hardware. Owned by ahliweb/linux-mint-xfce-rescue-ai#15.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/RESCUE-MACOS.command as 'zsh -f FILE' (never
# sourced), with RESCUE_SCOPE and RESCUE_PACKAGES in the environment. Read-only, no sudo, only
# tools that ship with macOS (sysctl, pmset, ioreg, diskutil, networksetup, system_profiler).
# Prints one line per check:  CHECK_ID STATUS [KIND NUMBER]   e.g. "hw-battery warn percent 18".
# Numbers only: no names, serial numbers, MAC addresses or device paths. A tool that is missing,
# slow (bounded by a timeout) or not permitted gives 'unknown'. Without pmset (not a Mac) the
# module prints nothing. Operator documentation: docs/hardware.md.

emulate -L zsh
setopt no_unset pipe_fail
export PATH=/usr/sbin:/usr/bin:/bin:/sbin
export LC_ALL=C

(( $+commands[pmset] )) || exit 0

scope=${RESCUE_SCOPE:-all}
wants() {
  local s
  for s in ${(s:,:)scope}; do
    [[ $s == all || $s == hardware || $s == hardware.$1 ]] && return 0
  done
  return 1
}

emit() { print -r -- "$*"; }

# bounded SECONDS COMMAND...: run a command, kill it after SECONDS, stdout only, no temp files.
bounded() {
  local secs=$1 pid watcher rc
  shift
  "$@" 2>/dev/null &
  pid=$!
  { sleep $secs; kill $pid } >/dev/null 2>&1 &
  watcher=$!
  wait $pid 2>/dev/null
  rc=$?
  kill $watcher >/dev/null 2>&1
  return $rc
}

# first_int: first run of digits on stdin, or nothing
first_int() { sed -n 's/[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -n 1; }

# ------------------------------------------------------------------------------------- cpu
if wants cpu; then
  cpus=$(sysctl -n hw.logicalcpu 2>/dev/null | first_int)
  if [[ -n $cpus ]] && (( cpus > 0 )); then emit "hw-cpu pass count $cpus"; else emit "hw-cpu unknown"; fi
  # pmset -g therm: CPU_Speed_Limit = 100 means no thermal throttling; percent of full speed.
  limit=$(bounded 10 pmset -g therm | sed -n 's/.*CPU_Speed_Limit[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -n 1)
  if [[ -z $limit ]]; then
    emit "hw-cpu-thermal unknown"
  elif (( limit < 50 )); then emit "hw-cpu-thermal fail percent $limit"
  elif (( limit < 100 )); then emit "hw-cpu-thermal warn percent $limit"
  else emit "hw-cpu-thermal pass percent $limit"; fi
fi

# ---------------------------------------------------------------------------------- memory
if wants memory; then
  mem=$(sysctl -n hw.memsize 2>/dev/null | first_int)
  if [[ -z $mem ]] || (( mem <= 0 )); then emit "hw-memory unknown"
  elif (( mem < 2147483648 )); then emit "hw-memory warn bytes $mem"
  else emit "hw-memory pass bytes $mem"; fi
  emit "hw-memory-errors not_applicable"   # macOS exposes no ECC counters to a normal user
fi

# ------------------------------------------------------------------------------------ disk
if wants disk; then
  list=$(bounded 15 diskutil list internal physical)
  disks=(${(f)"$(print -r -- $list | sed -n 's|^/dev/\(disk[0-9][0-9]*\).*|\1|p')"})
  disks=(${disks:#})
  if [[ -z $list ]]; then
    emit "hw-disk unknown"; emit "smart-health unknown"; emit "nvme-health unknown"
  else
    if (( ${#disks} )); then emit "hw-disk pass count ${#disks}"; else emit "hw-disk fail count 0"; fi
    smart=none; nvme=none
    for d in $disks; do
      info=$(bounded 15 diskutil info $d)
      state=$(print -r -- $info | sed -n 's/^ *SMART Status: *//p' | head -n 1)
      solid=$(print -r -- $info | grep -c -E 'Protocol: *(PCI|Apple Fabric)')
      case $state in
        Verified) new=pass ;;
        Failing) new=fail ;;
        *) new=unknown ;;
      esac
      if (( solid )); then
        [[ $new == fail || $nvme == none || ( $nvme == unknown && $new == pass ) ]] && nvme=$new
      else
        [[ $new == fail || $smart == none || ( $smart == unknown && $new == pass ) ]] && smart=$new
      fi
    done
    [[ $smart == none ]] && smart=not_applicable
    [[ $nvme == none ]] && nvme=not_applicable
    emit "smart-health $smart"
    emit "nvme-health $nvme"
  fi
fi

# ------------------------------------------------------------------------------- gpu / display
if wants gpu || wants display; then
  gfx=$(bounded 20 system_profiler -json SPDisplaysDataType)
  if [[ -z $gfx ]]; then
    wants gpu && { emit "hw-gpu unknown"; emit "hw-gpu-driver unknown"; }
    wants display && emit "hw-display unknown"
  else
    if wants gpu; then
      gpus=$(print -r -- $gfx | grep -c '"sppci_model"')
      if (( gpus > 0 )); then emit "hw-gpu pass count $gpus"; emit "hw-gpu-driver pass count 0"
      else emit "hw-gpu not_applicable"; emit "hw-gpu-driver not_applicable"; fi
    fi
    if wants display; then
      screens=$(print -r -- $gfx | grep -c '"_spdisplays_resolution"')
      if (( screens > 0 )); then emit "hw-display pass count $screens"; else emit "hw-display warn count 0"; fi
    fi
  fi
fi

# ----------------------------------------------------------------------------------- network
if wants network; then
  ports=$(bounded 10 networksetup -listallhardwareports)
  if [[ -z $ports ]]; then
    emit "hw-network-adapter unknown"; emit "hw-wifi unknown"
  else
    n=$(print -r -- $ports | grep -c '^Hardware Port:')
    active=$(bounded 10 ifconfig | grep -c 'status: active')
    if (( n == 0 )); then emit "hw-network-adapter fail count 0"
    elif (( active == 0 )); then emit "hw-network-adapter warn count $n"
    else emit "hw-network-adapter pass count $n"; fi
    wifidev=$(print -r -- $ports | sed -n '/^Hardware Port: Wi-Fi/{n;s/^Device: *\([a-z0-9]*\).*/\1/p;}' | head -n 1)
    if [[ -z $wifidev ]]; then
      emit "hw-wifi not_applicable"
    else
      power=$(bounded 10 networksetup -getairportpower $wifidev)
      case $power in
        *": On") emit "hw-wifi pass count 0" ;;
        *": Off") emit "hw-wifi warn count 1" ;;
        *) emit "hw-wifi unknown" ;;
      esac
    fi
  fi
fi

# ----------------------------------------------------------------------------------- battery
if wants battery; then
  batt=$(bounded 10 pmset -g batt)
  if [[ -z $batt ]]; then
    emit "hw-battery unknown"
  elif [[ $batt != *InternalBattery* ]]; then
    emit "hw-battery not_applicable"
  else
    charge=$(print -r -- $batt | sed -n 's/.*[^0-9]\([0-9][0-9]*\)%.*/\1/p' | head -n 1)
    st=pass
    raw=$(bounded 10 ioreg -rn AppleSmartBattery | sed -n 's/.*"AppleRawMaxCapacity" = \([0-9][0-9]*\).*/\1/p' | head -n 1)
    design=$(bounded 10 ioreg -rn AppleSmartBattery | sed -n 's/.*"DesignCapacity" = \([0-9][0-9]*\).*/\1/p' | head -n 1)
    if [[ -n $raw && -n $design ]] && (( design > 0 )); then
      health=$(( 100 * raw / design ))
      if (( health < 40 )); then st=fail; elif (( health < 60 )); then st=warn; fi
    fi
    if [[ -z $charge ]]; then
      emit "hw-battery unknown"
    else
      if [[ $batt == *discharging* ]]; then
        if (( charge < 10 )); then st=fail; elif (( charge < 20 )) && [[ $st == pass ]]; then st=warn; fi
      fi
      emit "hw-battery $st percent $charge"
    fi
  fi
fi

# -------------------------------------------------------------------------------------- usb
if wants usb; then
  usb=$(bounded 15 ioreg -p IOUSB -w0)
  if [[ -z $usb ]]; then
    emit "hw-usb unknown"
  else
    total=$(print -r -- $usb | grep -c '+-o')
    (( total > 0 )) && total=$(( total - 1 ))    # the first entry is the root hub
    emit "hw-usb pass count $total"
  fi
fi
