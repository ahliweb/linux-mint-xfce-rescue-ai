#!/bin/zsh -f
# Host launcher for a RUNNING macOS 12+ (Intel or Apple Silicon).
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# Double-click this file (or: zsh RESCUE-MACOS.command). Read-only OS checks -> schema 1.1
# evidence -> direct OpenCode Go analysis. Everything is read from and written to the rescue
# USB (<bundle>/reports/). Nothing is installed and nothing is written to this Mac.
# Uses only tools that ship with macOS (no Python needed).
#
# If double-clicking opens an editor or is refused: right-click -> Open, or run
#   chmod +x /Volumes/<USB>/RESCUE-MACOS.command   (exFAT normally shows files as executable)
#
# Exit codes: 0 ok | 2 invalid evidence | 3 no API key | 4 network/HTTP error
#             5 bundle/reports folder unusable | 64 usage

emulate -L zsh
setopt LOCAL_OPTIONS
umask 077
typeset -U path
path+=(/usr/bin /bin /usr/sbin /sbin)
export LC_NUMERIC=C

readonly ENDPOINT='https://opencode.ai/zen/go/v1/chat/completions'
readonly MODEL='mimo-v2.6-flash'
readonly MARKER='profiles/rescue-hermes/analysis-prompt.md'

evidence_only=0
dry_run=0
pause_at_end=1
bundle=''
tmp_files=()

usage() {
  print -r -- 'usage: RESCUE-MACOS.command [--evidence-only] [--dry-run] [--bundle DIR] [--no-pause]' >&2
  print -r -- '  --evidence-only  collect + save evidence; no network, no AI call' >&2
  print -r -- '  --dry-run        like --evidence-only, and show what would be sent' >&2
  print -r -- '  --bundle DIR     rescue-omes bundle folder (default: auto-detect next to this script)' >&2
  print -r -- '  --no-pause       do not wait for Return before exiting' >&2
  exit 64
}

while (( $# )); do
  case $1 in
    --evidence-only) evidence_only=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --no-pause) pause_at_end=0; shift ;;
    --bundle) (( $# >= 2 )) || usage; bundle=$2; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

cleanup() {
  local f
  for f in $tmp_files; do rm -f -- "$f" 2>/dev/null; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

finish() {
  local rc=$1
  if (( pause_at_end )) && [[ -t 0 ]]; then
    print -rn -- $'\nTekan Return untuk menutup / Press Return to close... '
    read -r _ignored
  fi
  exit $rc
}

if [[ $(uname -s) != Darwin ]]; then
  print -r -- 'ERROR: launcher ini khusus macOS / this launcher is for macOS only.' >&2
  finish 64
fi

# ---------------------------------------------------------------------------------------
# Locate the bundle on the USB
# ---------------------------------------------------------------------------------------
script_dir=${0:A:h}
if [[ -z $bundle ]]; then
  for cand in "$script_dir/rescue-omes" "$script_dir/.."; do
    if [[ -f $cand/$MARKER ]]; then
      bundle=${cand:A}
      break
    fi
  done
fi
if [[ -z $bundle || ! -f $bundle/$MARKER ]]; then
  print -r -- "ERROR: bundle rescue-omes tidak ditemukan / rescue-omes bundle not found next to $script_dir" >&2
  finish 5
fi

reports=$bundle/reports
probe=$reports/.write-test-$$
mkdir -p -- "$reports" 2>/dev/null
tmp_files+=("$probe")
if ! ( : > "$probe" ) 2>/dev/null; then
  print -r -- 'ERROR: folder reports di USB tidak bisa ditulis (USB write-protect?) / reports folder on the USB is not writable.' >&2
  finish 5
fi
rm -f -- "$probe"
export TMPDIR=$reports   # any tool that wants a temp file uses the USB, not this Mac

# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------
json_str() {
  # JSON string literal for $1 (escapes quote, backslash and control characters).
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//[[:cntrl:]]/ }
  print -rn -- "\"$s\""
}

sha256_str() {
  local out
  if (( $+commands[shasum] )); then
    out=$(print -rn -- "$1" | shasum -a 256)
  elif (( $+commands[sha256sum] )); then
    out=$(print -rn -- "$1" | sha256sum)
  else
    out=$(print -rn -- "$1" | openssl dgst -sha256 | sed 's/^.*= //')
  fi
  print -r -- ${out%% *}
}

sanitize_release() {
  # Reduce free text to the schema pattern ^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$ (or nothing).
  local s
  s=$(print -rn -- "$1" | LC_ALL=C tr -c 'A-Za-z0-9 ._+()/-' ' ' | LC_ALL=C tr -s ' ')
  while [[ $s == ' '* ]]; do s=${s:1}; done
  while [[ $s == *' ' ]]; do s=${s%' '}; done
  while [[ -n $s && $s != [A-Za-z0-9]* ]]; do s=${s:1}; done
  s=${s[1,64]}
  while [[ $s == *' ' ]]; do s=${s%' '}; done
  [[ -n $s ]] && print -rn -- "$s"
  return 0
}

plist_get() {
  # $1 = key; XML plist on stdin. Prints the string/integer/real/boolean value, if any.
  local key=$1 xml val
  xml=$(cat)
  if (( $+commands[plutil] )); then
    val=$(print -r -- "$xml" | plutil -extract "$key" raw -o - - 2>/dev/null)
    if [[ -n $val ]]; then print -r -- $val; return 0; fi
  fi
  print -r -- "$xml" | tr '\n\t\r' '   ' | awk -v k="$key" '{
    pat = "<key>" k "</key> *<(string|integer|real)>"
    if (match($0, pat)) { rest = substr($0, RSTART + RLENGTH); sub(/<.*/, "", rest); print rest; exit }
    if (match($0, "<key>" k "</key> *<true/>")) { print "true"; exit }
    if (match($0, "<key>" k "</key> *<false/>")) { print "false"; exit }
  }'
}

# --- API key: data-only parser (port of scripts/lib/rescue-env.sh, one key only) --------
parse_env_value() {
  # $1 = right-hand side of KEY=VALUE. Result in REPLY. Returns 1 when the line is unusable.
  # Nothing is expanded or evaluated: `$` and backticks that a shell would expand
  # (unquoted, or unescaped inside double quotes) make the line invalid.
  local raw=$1 out='' c d rest
  local -i i=0 n=${#raw} closed
  while (( i < n )); do
    c=${raw:$i:1}
    case $c in
      "'")
        (( i += 1 ))
        while (( i < n )) && [[ ${raw:$i:1} != "'" ]]; do out+=${raw:$i:1}; (( i += 1 )); done
        (( i < n )) || return 1
        (( i += 1 ))
        ;;
      '"')
        (( i += 1 ))
        closed=0
        while (( i < n )); do
          c=${raw:$i:1}
          if [[ $c == '"' ]]; then
            closed=1
            break
          elif [[ $c == $'\\' ]]; then
            (( i += 1 ))
            (( i < n )) || return 1
            d=${raw:$i:1}
            case $d in
              '"'|$'\\'|'$'|'`') out+=$d ;;
              *) out+=$'\\'$d ;;
            esac
          elif [[ $c == '$' || $c == '`' ]]; then
            return 1
          else
            out+=$c
          fi
          (( i += 1 ))
        done
        (( closed )) || return 1
        (( i += 1 ))
        ;;
      $'\\')
        (( i += 1 ))
        (( i < n )) || return 1
        out+=${raw:$i:1}
        (( i += 1 ))
        ;;
      '$'|'`') return 1 ;;
      ' '|$'\t')
        rest=${raw:$i}
        while [[ $rest == [[:space:]]* ]]; do rest=${rest:1}; done
        [[ -z $rest || $rest == '#'* ]] || return 1
        break
        ;;
      *)
        out+=$c
        (( i += 1 ))
        ;;
    esac
  done
  REPLY=$out
}

read_api_key() {
  # $1 = env file. Prints OPENCODE_GO_API_KEY (first valid assignment) or nothing.
  local file=$1 line
  [[ -f $file && -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ '^[[:space:]]*(export[[:space:]]+)?OPENCODE_GO_API_KEY[[:space:]]*=[[:space:]]*(.*)$' ]]; then
      parse_env_value "${match[2]}" || continue
      [[ -n $REPLY ]] || continue
      print -rn -- "$REPLY"
      return 0
    fi
  done < "$file"
  return 0
}

# --- evidence assembly ---------------------------------------------------------------------
check_items=()
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

add_check() {
  # add_check ID STATUS [KIND NUMBER]   (network-connectivity passes NOREF as 5th arg)
  local id=$1 st=$2 kind=${3:-} num=${4:-} noref=${5:-}
  case $st in pass|fail|warn|not_applicable|unknown) ;; *) st=unknown ;; esac
  local j='{"check_id":'$(json_str "$id")',"status":'$(json_str "$st")',"source":"host-allowlist","observed_at":"'$now'"'
  [[ -n $noref ]] || j+=',"target_ref":"os-0"'
  if [[ -n $kind && $num =~ '^[0-9]+(\.[0-9]+)?$' ]]; then
    j+=',"value":{"kind":'$(json_str "$kind")',"number":'$num'}'
  fi
  j+='}'
  check_items+=("$j")
}

# ---------------------------------------------------------------------------------------
# Read-only checks (each degrades to "unknown")
# ---------------------------------------------------------------------------------------
print -r -- 'Rescue host launcher (macOS) - read-only checks; output goes to the USB only.'
print -r -- 'Menjalankan pemeriksaan read-only / running read-only checks...'

# os-detection
os_ver=$(sw_vers -productVersion 2>/dev/null)
release=''
os_status=unknown
if [[ $os_ver =~ '^[0-9]+(\.[0-9]+)*$' ]]; then
  release=$(sanitize_release "macOS $os_ver")
  if (( ${os_ver%%.*} >= 12 )); then os_status=pass; else os_status=warn; fi
fi
arch=unknown
arm_flag=$(sysctl -in hw.optional.arm64 2>/dev/null)
machine=$(uname -m 2>/dev/null)
if [[ $arm_flag == 1 || $machine == arm64 ]]; then
  arch=arm64
elif [[ $machine == x86_64 ]]; then
  arch=x86_64
fi
add_check os-detection $os_status

# macos-apfs-container
disk_plist=$(diskutil info -plist / 2>/dev/null)
apfs_status=unknown
if [[ -n $disk_plist ]]; then
  fstype=$(print -r -- "$disk_plist" | plist_get FilesystemType)
  cont=$(print -r -- "$disk_plist" | plist_get APFSContainerReference)
  if [[ ${(L)fstype} == apfs || -n $cont ]]; then
    apfs_status=pass
  elif [[ -n $fstype ]]; then
    apfs_status=warn
  fi
fi
add_check macos-apfs-container $apfs_status

# macos-filevault (+ target_systems.encryption)
fv_out=$(fdesetup status 2>/dev/null)
encryption=unknown
case $fv_out in
  *'FileVault is On'*) encryption=filevault ;;
  *'FileVault is Off'*) encryption=none ;;
esac
if [[ $encryption == unknown ]]; then add_check macos-filevault unknown; else add_check macos-filevault pass; fi

# macos-sip-status
sip_out=${(L)$(csrutil status 2>/dev/null)}
sip_status=unknown
case $sip_out in
  *'custom configuration'*) sip_status=warn ;;
  *'status: enabled'*) sip_status=pass ;;
  *'status: disabled'*) sip_status=warn ;;
esac
add_check macos-sip-status $sip_status

# macos-crash-reports (counts only; last 7 days)
panic_dir=/Library/Logs/DiagnosticReports
user_dir=$HOME/Library/Logs/DiagnosticReports
panics=0
crashes=0
seen=0
if [[ -d $panic_dir ]]; then
  seen=1
  panics=$(( $(find "$panic_dir" -maxdepth 1 -type f -name '*.panic' -mtime -7 2>/dev/null | wc -l) ))
fi
if [[ -d $user_dir ]]; then
  seen=1
  crashes=$(( $(find "$user_dir" -maxdepth 1 -type f \( -name '*.crash' -o -name '*.ips' -o -name '*.panic' \) -mtime -7 2>/dev/null | wc -l) ))
fi
total=$(( panics + crashes ))
if (( ! seen )); then
  add_check macos-crash-reports unknown
elif (( panics >= 3 )); then
  add_check macos-crash-reports fail count $total
elif (( total > 0 )); then
  add_check macos-crash-reports warn count $total
else
  add_check macos-crash-reports pass count 0
fi

# macos-startup-disk (the device path itself is never kept)
boot_out=$(bless --info --getBoot 2>/dev/null)
if [[ -n $boot_out ]]; then add_check macos-startup-disk pass; else add_check macos-startup-disk unknown; fi

# disk-free-space (percent free of the volume group that holds user data)
df_target=/
[[ -d /System/Volumes/Data ]] && df_target=/System/Volumes/Data
df_line=$(df -Pk "$df_target" 2>/dev/null | tail -n 1 | awk '{print $2, $4}')
df_total=${df_line%% *}
df_avail=${df_line##* }
if [[ $df_total =~ '^[0-9]+$' && $df_avail =~ '^[0-9]+$' ]] && (( df_total > 0 )); then
  tenths=$(( df_avail * 1000 / df_total ))
  pct=$(( tenths / 10 )).$(( tenths % 10 ))
  if (( tenths < 50 )); then add_check disk-free-space fail percent $pct
  elif (( tenths < 100 )); then add_check disk-free-space warn percent $pct
  else add_check disk-free-space pass percent $pct
  fi
else
  add_check disk-free-space unknown
fi

# network-connectivity (skipped without network access in evidence-only / dry-run)
offline=0
(( evidence_only || dry_run )) && offline=1
if (( offline )); then
  add_check network-connectivity unknown '' '' noref
elif nc -z -G 5 opencode.ai 443 >/dev/null 2>&1 \
     || curl -s -o /dev/null --connect-timeout 5 --max-time 8 https://opencode.ai/ >/dev/null 2>&1; then
  add_check network-connectivity pass '' '' noref
else
  add_check network-connectivity fail '' '' noref
fi

# ---------------------------------------------------------------------------------------
# API key (only when it will be used)
# ---------------------------------------------------------------------------------------
api_key=${OPENCODE_GO_API_KEY:-}
[[ -n $api_key ]] || api_key=$(read_api_key "$bundle/config/rescue.env")
have_key=0
if [[ -n $api_key && $api_key != *[[:cntrl:]]* ]]; then have_key=1; fi
authenticated=false
destination=unknown
if (( have_key && ! offline )); then authenticated=true; destination=cloud; fi

# ---------------------------------------------------------------------------------------
# Evidence (schema 1.1). Strings come from closed sets or are escaped by json_str.
# ---------------------------------------------------------------------------------------
seed=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/ {print $4; exit}')
[[ -n $seed ]] && seed="platform-uuid:$seed" || seed="fallback:$RANDOM$RANDOM$(date +%s)"
opaque=target-$(sha256_str "$seed")
opaque=${opaque[1,23]}
unset seed

compact='['
pretty=''
first=1
for item in $check_items; do
  if (( first )); then
    compact+=$item
    pretty+=$item
    first=0
  else
    compact+=,$item
    pretty+=$',\n    '$item
  fi
done
compact+=']'
manifest=$(sha256_str "$compact")

run_ts=$(date -u +%Y%m%d-%H%M%S)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
evidence_path=$reports/macos-$stamp-evidence.json
analysis_path=$reports/macos-$stamp-analysis.md

if [[ -n $release ]]; then release_json=$(json_str "$release"); else release_json=null; fi
ev=$'{\n'
ev+='  "schema_version": "1.1",'$'\n'
ev+='  "run_id": "rescue-'$run_ts'-mh",'$'\n'
ev+='  "source_platform": "macos-host",'$'\n'
ev+='  "boot_mode": "unknown",'$'\n'
ev+='  "collected_at": "'$now'",'$'\n'
ev+='  "target_device_opaque_id": "'$opaque'",'$'\n'
ev+='  "ventoy_version": null,'$'\n'
ev+='  "linux_release": null,'$'\n'
ev+='  "target_systems": [{"ref":"os-0","family":"macos","release":'$release_json',"architecture":"'$arch'","detection":"host-native","encryption":"'$encryption'","access":"host-running"}],'$'\n'
ev+='  "checks": ['$'\n    '$pretty$'\n  ],'$'\n'
ev+='  "evidence_manifest": {"entry_count": '${#check_items}',"manifest_sha256": "'$manifest'","storage_class": "usb-rescue-state"},'$'\n'
ev+='  "ai_provider": {"provider_id":"opencode-go","model_id":"'$MODEL'","authenticated":'$authenticated',"destination_class":"'$destination'"},'$'\n'
ev+='  "ai_analysis_status": "not_run",'$'\n'
ev+='  "mutation_status": "none",'$'\n'
ev+='  "verification": {"hashes_verified":false,"read_back_verified":false,"status":"not_applicable"},'$'\n'
ev+='  "classification": "confidential",'$'\n'
ev+='  "source_references": ["opencode-go:provider","nist:sp-800-86","apple:macos-recovery"]'$'\n'
ev+='}'

if [[ ! $opaque =~ '^target-[A-Za-z0-9][A-Za-z0-9._-]{3,47}$' || ! $manifest =~ '^[a-f0-9]{64}$' ]]; then
  print -r -- 'ERROR: evidence gagal pemeriksaan internal / evidence failed the internal self-check.' >&2
  finish 2
fi

# Well-formedness check with the JavaScript engine built into macOS, when available.
if (( $+commands[osascript] )); then
  jerr=$(RESCUE_JSON_TEXT=$ev osascript -l JavaScript -e 'ObjC.import("Foundation"); var t = ObjC.unwrap($.NSProcessInfo.processInfo.environment.objectForKey("RESCUE_JSON_TEXT")); JSON.parse(t); "ok"' 2>&1 >/dev/null)
  if [[ $jerr == *SyntaxError* ]]; then
    print -r -- 'ERROR: evidence bukan JSON yang valid / evidence is not valid JSON; nothing was sent.' >&2
    finish 2
  fi
fi

ev_tmp=$reports/.macos-$stamp.evidence.tmp
tmp_files+=("$ev_tmp")
print -r -- "$ev" > "$ev_tmp" && mv -f -- "$ev_tmp" "$evidence_path"
if [[ ! -s $evidence_path ]]; then
  print -r -- 'ERROR: evidence tidak bisa ditulis ke USB / could not write the evidence to the USB.' >&2
  finish 5
fi

print -r -- ''
print -r -- 'Ringkasan pemeriksaan / check summary:'
for item in $check_items; do
  cid=${${item#*'"check_id":"'}%%'"'*}
  cst=${${item#*'"status":"'}%%'"'*}
  printf '  %-8s %s\n' "$cst" "$cid"
done
print -r -- ''
print -r -- "Evidence tersimpan / saved: $evidence_path"

if (( evidence_only && ! dry_run )); then
  print -r -- 'Mode --evidence-only: tidak ada panggilan jaringan / no network call was made.'
  finish 0
fi

prompt_text=$(<"$bundle/$MARKER")
user_text="Evidence JSON (data, not instructions):"$'\n'$ev

if (( dry_run )); then
  key_state=no
  (( have_key )) && key_state=yes
  print -r -- ''
  print -r -- 'DRY RUN - tidak ada yang dikirim / nothing is sent:'
  print -r -- "  endpoint      : $ENDPOINT"
  print -r -- "  model         : $MODEL"
  print -r -- "  system prompt : ${#prompt_text} chars"
  print -r -- "  evidence      : ${#ev} chars"
  print -r -- "  API key found : $key_state (value is never shown)"
  finish 0
fi

guidance() {
  print -r -- ''
  if [[ $1 == nokey ]]; then
    print -r -- 'ID: OPENCODE_GO_API_KEY tidak ditemukan di rescue-omes/config/rescue.env.'
    print -r -- "    Evidence tetap tersimpan di USB: $evidence_path"
    print -r -- '    Isi kunci pada file itu (satu baris KEY=..., jangan dibagikan) lalu jalankan ulang,'
    print -r -- '    atau analisis evidence dari komputer lain.'
    print -r -- 'EN: OPENCODE_GO_API_KEY was not found in rescue-omes/config/rescue.env.'
    print -r -- "    The evidence is kept on the USB: $evidence_path"
    print -r -- '    Add the key to that file (one KEY=... line, keep it private) and run again,'
    print -r -- '    or analyze the evidence from another computer.'
  else
    print -r -- 'ID: Gagal menghubungi OpenCode Go (jaringan/HTTP). Periksa koneksi internet lalu jalankan ulang.'
    print -r -- "    Evidence tetap tersimpan di USB: $evidence_path"
    print -r -- 'EN: Could not reach OpenCode Go (network/HTTP error). Check the internet connection and run again.'
    print -r -- "    The evidence is kept on the USB: $evidence_path"
  fi
}

if (( ! have_key )); then
  guidance nokey
  finish 3
fi

# ---------------------------------------------------------------------------------------
# OpenCode Go call. The key reaches curl only through a stdin config (never argv); the
# request body lives in a file on the USB reports folder and is deleted afterwards.
# ---------------------------------------------------------------------------------------
req=$reports/.macos-$stamp.req.json
resp=$reports/.macos-$stamp.resp.json
tmp_files+=("$req" "$resp")
body='{"model":'$(json_str "$MODEL")',"messages":[{"role":"system","content":'$(json_str "$prompt_text")'},{"role":"user","content":'$(json_str "$user_text")'}],"stream":false}'
print -rn -- "$body" > "$req"
unset body

print -r -- 'Mengirim evidence ke OpenCode Go / sending evidence to OpenCode Go...'
qkey=${api_key//\\/\\\\}
qkey=${qkey//\"/\\\"}
http=$(print -r -- "header = \"Authorization: Bearer $qkey\"" | curl --config - \
  --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
  --header 'Content-Type: application/json' --data-binary @"$req" \
  --output "$resp" --write-out '%{http_code}' "$ENDPOINT" 2>/dev/null)
unset qkey api_key
rm -f -- "$req"

if [[ $http != 200 ]]; then
  print -r -- "Kegagalan / failure: HTTP ${http:-000}" >&2
  guidance network
  finish 4
fi

answer=''
if (( $+commands[plutil] )); then
  answer=$(plutil -extract choices.0.message.content raw -o - "$resp" 2>/dev/null)
fi
if [[ -z $answer ]] && (( $+commands[osascript] )); then
  answer=$(RESCUE_RESP_FILE=$resp osascript -l JavaScript -e 'ObjC.import("Foundation"); var p = ObjC.unwrap($.NSProcessInfo.processInfo.environment.objectForKey("RESCUE_RESP_FILE")); var t = ObjC.unwrap($.NSString.stringWithContentsOfFileEncodingError(p, $.NSUTF8StringEncoding, $())); JSON.parse(t).choices[0].message.content' 2>/dev/null)
fi
rm -f -- "$resp"
if [[ -z ${answer//[[:space:]]/} ]]; then
  print -r -- 'Kegagalan / failure: respons kosong atau tidak terbaca / empty or unreadable response' >&2
  guidance network
  finish 4
fi

# The answer is displayed and saved as text only. It is never executed.
{
  print -r -- '# Analisis rescue (macos-host)'
  print -r -- ''
  print -r -- '> Keluaran model, hanya untuk dibaca; jangan dijalankan. Model output for reading only; never execute it.'
  print -r -- "> Dibuat / generated: $now. Evidence: macos-$stamp-evidence.json"
  print -r -- ''
  print -r -- "$answer"
} > "$analysis_path"

print -r -- ''
print -r -- '==================== ANALISIS / ANALYSIS ===================='
print -r -- "$answer"
print -r -- '============================================================='
print -r -- "Analisis tersimpan / analysis saved: $analysis_path"
finish 0
