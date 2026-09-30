# shellcheck shell=bash
# Shared helpers for the Hermes rescue scripts. Source this file; do not execute it.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# rescue_load_env FILE
#   Safe replacement for `source FILE`. The file is DATA, never code.
#   Accepted format, one assignment per line:
#     [export ]KEY=VALUE
#   * Only these keys are read; every other key is ignored:
#       OPENCODE_GO_API_KEY RESCUE_STATE_DIR HERMES_HOME
#       OPENCODE_ADAPTER_COMMAND OPENCODE_TIMEOUT_SECONDS RESCUE_GITHUB_ISSUES_TOKEN
#     (RESCUE_GITHUB_ISSUES_TOKEN: fine-grained GitHub token, Issues read/write on this
#     repository only, used by scripts/submit-skill.py; never printed or put on argv.)
#   * VALUE may be unquoted, 'single quoted', "double quoted", or a mix, exactly
#     like the output of `printf %q` or KEY='it'\''s'. Backslash escapes are
#     honored outside single quotes. `$` and backticks that the shell would
#     expand (unquoted, or unescaped inside double quotes) make the line invalid:
#     it is skipped with a warning and NOTHING is evaluated or expanded.
#   * Blank lines and lines starting with `#` are ignored.
#   * A variable that is already non-empty in the environment is NOT overridden;
#     the file only fills variables that are unset or empty.
#   * A missing file is fine (return 0). A world-writable file is refused
#     (return 1). A file owned by neither the current user nor root is skipped
#     with a warning (return 0).
#
# rescue_sh_squote VALUE      prints VALUE as one single-quoted word ('\'' escape).
# rescue_desktop_quote ARG    prints ARG quoted for a Desktop Entry Exec= line
#                             (freedesktop spec); returns 1 for newline or `%`.

_RESCUE_ENV_KEYS=" OPENCODE_GO_API_KEY RESCUE_STATE_DIR HERMES_HOME OPENCODE_ADAPTER_COMMAND OPENCODE_TIMEOUT_SECONDS RESCUE_GITHUB_ISSUES_TOKEN "

# Parse the right-hand side of an assignment into REPLY. Returns 1 if invalid.
_rescue_env_parse_value() {
  local raw=$1 out='' i=0 n c rest
  n=${#raw}
  while ((i < n)); do
    c=${raw:i:1}
    case $c in
      "'")
        i=$((i + 1))
        while ((i < n)) && [[ ${raw:i:1} != "'" ]]; do out+=${raw:i:1}; i=$((i + 1)); done
        ((i < n)) || return 1
        i=$((i + 1))
        ;;
      '"')
        i=$((i + 1))
        while ((i < n)); do
          c=${raw:i:1}
          if [[ $c == '"' ]]; then
            break
          elif [[ $c == $'\\' ]]; then
            i=$((i + 1))
            ((i < n)) || return 1
            c=${raw:i:1}
            case $c in
              '"' | $'\\' | '$' | '`') out+=$c ;;
              *) out+="\\$c" ;;
            esac
          elif [[ $c == '$' || $c == '`' ]]; then
            return 1
          else
            out+=$c
          fi
          i=$((i + 1))
        done
        ((i < n)) || return 1
        i=$((i + 1))
        ;;
      $'\\')
        i=$((i + 1))
        ((i < n)) || return 1
        out+=${raw:i:1}
        i=$((i + 1))
        ;;
      '$' | '`') return 1 ;;
      ' ' | $'\t')
        rest=${raw:i}
        rest=${rest#"${rest%%[![:space:]]*}"}
        [[ -z $rest || $rest == \#* ]] || return 1
        break
        ;;
      *)
        out+=$c
        i=$((i + 1))
        ;;
    esac
  done
  REPLY=$out
}

rescue_load_env() {
  local file=${1:?rescue_load_env: missing file} line key val mode owner me
  [[ -e $file ]] || return 0
  if [[ ! -f $file || ! -r $file ]]; then
    printf 'rescue-env: %s is not a readable regular file; refusing.\n' "$file" >&2
    return 1
  fi
  mode=$(stat -Lc '%a' -- "$file") || return 1
  owner=$(stat -Lc '%u' -- "$file") || return 1
  me=$(id -u)
  if ((8#$mode & 8#002)); then
    printf 'rescue-env: %s is world-writable (mode %s); refusing to read it.\n' "$file" "$mode" >&2
    return 1
  fi
  if [[ $owner != "$me" && $owner != 0 ]]; then
    printf 'rescue-env: WARNING: %s is not owned by the current user; skipping it.\n' "$file" >&2
    return 0
  fi

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      key=${BASH_REMATCH[2]}
      [[ $_RESCUE_ENV_KEYS == *" $key "* ]] || continue
      if ! _rescue_env_parse_value "${BASH_REMATCH[3]}"; then
        printf 'rescue-env: WARNING: ignoring unparsable value for %s in %s\n' "$key" "$file" >&2
        continue
      fi
      val=$REPLY
      if [[ -z ${!key:-} ]]; then
        printf -v "$key" '%s' "$val"
        export "${key?}"
      fi
    fi
  done < "$file"
  return 0
}

rescue_sh_squote() {
  local q="'" v=$1
  v=${v//"$q"/"$q\\$q$q"}
  printf "'%s'" "$v"
}

rescue_desktop_quote() {
  local arg=$1 out='' i c need=0
  case $arg in
    *$'\n'* | *'%'*) return 1 ;;
  esac
  if [[ -z $arg ]]; then
    need=1
  else
    for ((i = 0; i < ${#arg}; i++)); do
      c=${arg:i:1}
      case $c in
        ' ' | $'\t' | '"' | "'" | $'\\' | '>' | '<' | '~' | '|' | '&' | ';' | '$' | '*' | '?' | '#' | '(' | ')' | '`') need=1 ;;
      esac
    done
  fi
  out=$arg
  if ((need)); then
    out=${out//\\/\\\\}
    out=${out//\"/\\\"}
    out=${out//\$/\\\$}
    out=${out//\`/\\\`}
    out="\"$out\""
  fi
  # Desktop Entry string values treat backslash as an escape too: double it.
  out=${out//\\/\\\\}
  printf '%s' "$out"
}
