#!/usr/bin/env python3
"""Load, validate and match the typed repair action catalog (rescue-ai/v1/catalog/*.json).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

The catalog is reviewed code: every command is a fixed argv array. Nothing that
comes from evidence, logs, filenames or model output ever becomes a command;
the AI can only name an ``action_id`` and the engine decides, under the repair
policy, whether that action runs. This module is pure Python (plus
python3-jsonschema) so it can be unit-tested without root, disks or network.

Placeholders inside argv elements take exactly one of three forms:

  ``{name}``                 the whole element is the parameter value
  ``--opt={name}``           a literal option prefix, then the value
  ``{target_root}/lit/path`` only for target_root parameters, a literal path suffix

Engine-provided parameter types (never operator input): ``target_root`` (mount point of the target
OS), ``state_dir`` (one fixed subdirectory, ``clamav`` or ``quarantine``, of the USB state) and
``android_device`` (the integer ``adb -t`` transport id of the phone named by the proposal's ``and-N``
target_ref, resolved by the engine at execution time; see docs/android.md), ``fastboot_device`` (the same
phone in fastboot mode, rendered as the ``usb:<port>`` selector of ``fastboot -s``) and ``fastboot_slot``
(the active A/B slot read from the phone right before the action, for rollback). ``firmware_file`` (an
operator-supplied absolute path, hashed by the engine and passed as an inherited file descriptor) and
``sha256`` (the operator's expected SHA-256 of that file) are operator input, validated by the engine.
Placeholders may also take the form ``--{name}`` for an enum parameter (Heimdall partition options).
``detection_ref`` (``d-N``) is an operator-chosen opaque reference to one entry of the local
malware detection list; the engine resolves it to a verified regular-file path.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIR = ROOT / 'rescue-ai/v1/catalog'
CATALOG_SCHEMA = ROOT / 'rescue-ai/v1/repair-catalog.schema.json'
EVIDENCE_SCHEMA = ROOT / 'rescue-ai/v1/rescue-evidence.schema.json'

DOMAIN_PREFIX = {'hardware': 'hw', 'os-linux': 'os-linux', 'os-windows': 'os-windows',
                 'os-macos': 'os-macos', 'software': 'sw', 'malware': 'mw', 'android': 'android'}
DOMAIN_FAMILIES = {'os-linux': {'linuxmint', 'linux-other'}, 'os-windows': {'windows'}, 'os-macos': {'macos'},
                   'android': {'android'}}
DOMAIN_PLATFORMS = {'os-linux': {'live-linux', 'linux-host'}, 'os-windows': {'live-linux', 'windows-host'},
                    'os-macos': {'live-linux', 'macos-host'}, 'android': {'live-linux', 'linux-host'}}
# Parameter types only the Python engine can resolve: such actions never apply to the Windows/macOS host
# launchers (they list the types as unsupported), so they are limited to the Python engine's platforms.
PYTHON_ENGINE_PLATFORMS = {'live-linux', 'linux-host'}
ENGINE_ONLY_PARAMS = frozenset({'android_device', 'fastboot_device', 'fastboot_slot', 'firmware_file', 'sha256'})
GUARDS = ('bootloader-unlocked', 'image-matches-device', 'single-download-mode-device')
# What an Android action may send to the phone (docs/android.md). adb is always addressed with
# ``-t {android_device}``; the sub-command and the on-device program are closed lists, so a catalog change
# cannot add root, install, push/pull, sideload, remount, reboot into bootloader/recovery, or a wipe.
ADB_NO_ARGS = ('reboot', 'get-state')
ADB_SHELL = {'pm': ('trim-caches',), 'settings': ('get', 'put', 'delete'), 'df': None}
# Flashing (docs/android.md). fastboot is always ``fastboot -s {fastboot_device} ...`` (or ``fastboot devices``) with
# a closed list of sub-commands: no erase, format, -w, flashing unlock/lock, oem, slot or verity switches, and the
# partition parameter of ``flash`` is an enum whose values must come from this allowlist (never bootloader, radio,
# modem, persist, efs, frp, devinfo, userdata). Heimdall (Samsung download mode, experimental) likewise.
FASTBOOT_GETVARS = ('product', 'unlocked', 'current-slot', 'slot-count', 'is-userspace')
FASTBOOT_FLASH_PARTITIONS = frozenset({'boot', 'init_boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'recovery'})
HEIMDALL_PARTITIONS = frozenset({'BOOT', 'RECOVERY', 'VBMETA', 'DTBO'})
SLOTS = frozenset({'a', 'b'})
SHA256_RE = re.compile(r'^[A-Fa-f0-9]{64}\Z')       # \Z: a trailing newline must not slip through
FIRMWARE_KINDS = ('image', 'zip')
DETECTION_RE = re.compile(r'^d-[0-9]{1,4}$')
LIVE_PLATFORMS = {'linux-mint-xfce-live': 'live-linux', 'systemrescue-live': 'live-linux',
                  'other-live-linux': 'live-linux', 'linux-host': 'linux-host',
                  'windows-host': 'windows-host', 'macos-host': 'macos-host'}
SCOPE_ITEMS = ('hardware.cpu', 'hardware.memory', 'hardware.disk', 'hardware.gpu', 'hardware.display',
               'hardware.network', 'hardware.battery', 'hardware.usb', 'os', 'software', 'malware', 'android')
SCOPE_VALUES = ('all', 'hardware') + SCOPE_ITEMS[:10] + ('software.selected', 'malware', 'android')

# Programs that would turn a fixed argv back into "run anything": shells,
# interpreters, privilege wrappers (the engine adds `sudo -n` itself), command
# runners, and raw block writers. Backups are made by the operator, not by dd.
FORBIDDEN_PROGRAMS = frozenset("""
sh bash dash zsh ksh mksh csh tcsh fish busybox env sudo su doas pkexec runuser setpriv
python python2 python3 perl ruby node nodejs php lua tclsh osascript expect script
cmd cmd.exe powershell powershell.exe pwsh pwsh.exe wscript wscript.exe cscript cscript.exe
mshta mshta.exe rundll32 rundll32.exe regsvr32 regsvr32.exe
xargs find awk gawk mawk nawk sed eval exec nohup timeout nice ionice setsid watch
dd ssh scp curl wget nc ncat socat docker podman
""".split())

PLACEHOLDER = re.compile(r'\{([a-z][a-z0-9_]{0,31})\}')
WHOLE = re.compile(r'^\{([a-z][a-z0-9_]{0,31})\}$')
PREFIXED = re.compile(r'^(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*=)\{([a-z][a-z0-9_]{0,31})\}$')
OPTION = re.compile(r'^--\{([a-z][a-z0-9_]{0,31})\}$')          # --{name}: the value (an enum) is the option name
ROOTED = re.compile(r'^\{([a-z][a-z0-9_]{0,31})\}((?:/[A-Za-z0-9._+-]+)+)$')

PACKAGE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$')
SERVICE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$')
BLOCK_RE = re.compile(r'^/dev/[A-Za-z0-9][A-Za-z0-9_-]{0,31}(/[A-Za-z0-9][A-Za-z0-9_-]{0,31}){0,2}$')
ENUM_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$')

PROPOSAL_FENCE = re.compile(r'^[ \t]*```rescue-proposals[ \t]*\n(.*?)\n[ \t]*```[ \t]*$', re.S | re.M)
MAX_PROPOSAL_BLOCK = 4096
MAX_AI_PROPOSALS = 16


class CatalogError(Exception):
    """The catalog is unusable; .problems lists every reason."""

    def __init__(self, problems):
        super().__init__(problems[0] if problems else 'invalid catalog')
        self.problems = list(problems)


def _jsonschema():
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CatalogError(['python3-jsonschema is required: sudo apt install python3-jsonschema']) from exc
    return jsonschema


def evidence_check_ids(schema_path=EVIDENCE_SCHEMA):
    schema = json.loads(Path(schema_path).read_text(encoding='utf-8'))
    return set(schema['properties']['checks']['items']['properties']['check_id']['enum'])


# ------------------------------------------------------------------ invariants

def _steps(action):
    steps = [('execute', action['execute']), ('verify', action['verify'])]
    steps += [('preconditions/%d' % i, s) for i, s in enumerate(action.get('preconditions') or [])]
    rollback = action['rollback']
    if rollback.get('step'):
        steps.append(('rollback', rollback['step']))
    return steps


def _placeholder_errors(where, argv, params):
    errors, used = [], set()
    for i, element in enumerate(argv):
        if '{' not in element and '}' not in element:
            continue
        m = WHOLE.match(element) or PREFIXED.match(element) or OPTION.match(element)
        name = None
        if m:
            name = m.group(m.lastindex)
            if OPTION.match(element) and params.get(name, {}).get('type') != 'enum':
                errors.append('%s argv[%d]: --{name} is only allowed for an enum parameter' % (where, i))
        else:
            r = ROOTED.match(element)
            if r and '..' not in r.group(2).split('/'):
                name = r.group(1)
                if params.get(name, {}).get('type') != 'target_root':
                    errors.append('%s argv[%d]: a path suffix is only allowed after a target_root parameter'
                                  % (where, i))
            else:
                errors.append('%s argv[%d]: placeholders must be {name}, --opt={name}, --{enum}, or {target_root}/path'
                              % (where, i))
                continue
        if i == 0:
            errors.append('%s argv[0] must be a literal program name' % where)
        if name not in params:
            errors.append('%s argv[%d]: parameter {%s} is not declared' % (where, i, name))
        used.add(name)
    return errors, used


def android_command_errors(where, argv, android_params):
    """adb is always ``adb -t {android_device} <closed sub-command>``; see ADB_NO_ARGS and ADB_SHELL."""
    if argv[0] != 'adb':
        return []
    if not android_params:
        return ['%s: adb needs an android_device parameter' % where]
    device = '{%s}' % android_params[0]['name']
    if len(argv) < 4 or argv[1:3] != ['-t', device]:
        return ['%s: adb must be addressed as -t %s followed by a sub-command' % (where, device)]
    sub, rest = argv[3], argv[4:]
    if sub in ADB_NO_ARGS:
        return [] if not rest else ['%s: adb %s takes no arguments' % (where, sub)]
    if sub != 'shell' or not rest:
        return ['%s: adb sub-command %r is not allowed (allowed: shell, %s)' % (where, sub, ', '.join(ADB_NO_ARGS))]
    program = rest[0]
    if program not in ADB_SHELL:
        return ['%s: adb shell program %r is not allowed (allowed: %s)' % (where, program, ', '.join(sorted(ADB_SHELL)))]
    allowed = ADB_SHELL[program]
    if allowed is not None and (len(rest) < 2 or rest[1] not in allowed):
        return ['%s: adb shell %s may only use: %s' % (where, program, ', '.join(allowed))]
    if program == 'settings' and (len(rest) < 4 or rest[2] != 'global'):
        return ['%s: adb shell settings is limited to the global namespace and one literal key' % where]
    if any('{' in e or '}' in e for e in rest):
        return ['%s: no placeholder is allowed after adb shell' % where]
    return []


def _param_of(params, element):
    m = WHOLE.match(element)
    return params.get(m.group(1)) if m else None


def fastboot_command_errors(where, argv, params):
    """fastboot is ``fastboot devices`` or ``fastboot -s {fastboot_device} <closed sub-command>``."""
    if argv[0] != 'fastboot':
        return []
    if argv == ['fastboot', 'devices']:
        return []
    device = [p['name'] for p in params.values() if p['type'] == 'fastboot_device']
    if len(device) != 1:
        return ['%s: fastboot needs exactly one fastboot_device parameter' % where]
    if len(argv) < 4 or argv[1:3] != ['-s', '{%s}' % device[0]]:
        return ['%s: fastboot must be addressed as -s {%s} followed by a sub-command' % (where, device[0])]
    sub, rest = argv[3], argv[4:]
    if sub == 'getvar':
        if len(rest) == 1 and rest[0] in FASTBOOT_GETVARS:
            return []
        return ['%s: fastboot getvar may only read: %s' % (where, ', '.join(FASTBOOT_GETVARS))]
    if sub == 'reboot':
        return [] if not rest else ['%s: fastboot reboot takes no arguments (never reboot-bootloader)' % where]
    m = PREFIXED.match(sub)
    if m and m.group(1) == '--set-active=' and not rest:
        slot = params.get(m.group(2)) or {}
        if slot.get('type') == 'fastboot_slot' or (slot.get('type') == 'enum' and set(slot['values']) <= SLOTS):
            return []
        return ['%s: --set-active takes an enum limited to a/b or a fastboot_slot parameter' % where]
    if sub == 'flash' and len(rest) == 2:
        part, fw = _param_of(params, rest[0]), _param_of(params, rest[1])
        if not part or part['type'] != 'enum' or not set(part['values']) <= FASTBOOT_FLASH_PARTITIONS:
            return ['%s: fastboot flash partitions must be an enum within %s' % (where, ', '.join(sorted(FASTBOOT_FLASH_PARTITIONS)))]
        if not fw or fw['type'] != 'firmware_file' or fw.get('values') != ['image']:
            return ['%s: fastboot flash takes a firmware_file parameter of kind image' % where]
        return []
    if sub == 'update' and len(rest) == 1:
        fw = _param_of(params, rest[0])
        if not fw or fw['type'] != 'firmware_file' or fw.get('values') != ['zip']:
            return ['%s: fastboot update takes a firmware_file parameter of kind zip (and never -w)' % where]
        return []
    return ['%s: fastboot sub-command %r is not allowed (allowed: getvar, reboot, --set-active=, flash, update)' % (where, sub)]


def heimdall_command_errors(where, argv, params):
    """heimdall: detect, print-pit --no-reboot (read-only), or flash --{PARTITION} {firmware} --no-reboot."""
    if argv[0] != 'heimdall':
        return []
    if argv in (['heimdall', 'detect'], ['heimdall', 'print-pit', '--no-reboot']):
        return []
    if len(argv) == 5 and argv[1] == 'flash' and argv[4] == '--no-reboot':
        opt = OPTION.match(argv[2])
        part = params.get(opt.group(1)) if opt else None
        fw = _param_of(params, argv[3])
        if not part or part['type'] != 'enum' or not set(part['values']) <= HEIMDALL_PARTITIONS:
            return ['%s: heimdall flash partitions must be an enum within %s' % (where, ', '.join(sorted(HEIMDALL_PARTITIONS)))]
        if not fw or fw['type'] != 'firmware_file' or fw.get('values') != ['image']:
            return ['%s: heimdall flash takes a firmware_file parameter of kind image' % where]
        return []
    return ['%s: heimdall may only run detect, print-pit --no-reboot, or flash --{PARTITION} {file} --no-reboot' % where]


def _expect_line_errors(where, step, params):
    line = step.get('expect_line')
    if line is None:
        return []
    m = re.match(r'^[^{}]*(?:\{([a-z][a-z0-9_]{0,31})\})?$', line)
    if not m:
        return ['%s: expect_line allows one trailing {enum_param} placeholder only' % where]
    if m.group(1) and params.get(m.group(1), {}).get('type') != 'enum':
        return ['%s: expect_line placeholder {%s} must be a declared enum parameter' % (where, m.group(1))]
    return []


def action_errors(action, domain, check_ids):
    """Cross-field rules the JSON Schema cannot express for one action."""
    aid = action['action_id']
    errors = []
    say = errors.append
    if aid.split('.', 1)[0] != DOMAIN_PREFIX[domain]:
        say('%s: action_id prefix must be %r in domain %s' % (aid, DOMAIN_PREFIX[domain], domain))

    params = {}
    for p in action.get('params') or []:
        if p['name'] in params:
            say('%s: duplicate parameter %s' % (aid, p['name']))
        params[p['name']] = p
        kind = p['type']
        if kind == 'enum':
            if not p.get('values'):
                say('%s: enum parameter %s needs values' % (aid, p['name']))
            elif 'default' in p and p['default'] not in p['values']:
                say('%s: default of %s is not one of its values' % (aid, p['name']))
        elif kind == 'state_dir':
            if p.get('values') not in (['clamav'], ['quarantine']):
                say('%s: state_dir parameter %s needs exactly one value: clamav or quarantine' % (aid, p['name']))
        elif kind == 'firmware_file':
            if p.get('values') not in (['image'], ['zip']):
                say('%s: firmware_file parameter %s needs exactly one value: image or zip' % (aid, p['name']))
        elif 'values' in p:
            say('%s: only enum, state_dir and firmware_file parameters take values (%s)' % (aid, p['name']))
        if kind == 'integer':
            lo, hi = p.get('minimum'), p.get('maximum')
            if lo is None or hi is None or lo > hi:
                say('%s: integer parameter %s needs minimum <= maximum' % (aid, p['name']))
            elif 'default' in p and not (isinstance(p['default'], int) and lo <= p['default'] <= hi):
                say('%s: default of %s is outside minimum..maximum' % (aid, p['name']))
        elif 'minimum' in p or 'maximum' in p:
            say('%s: only integer parameters take minimum/maximum (%s)' % (aid, p['name']))
        if kind in ('block_device', 'target_root', 'detection_ref', 'state_dir', 'android_device', 'fastboot_device',
                    'fastboot_slot', 'firmware_file', 'sha256') and 'default' in p:
            say('%s: %s parameters cannot have a default (%s)' % (aid, kind, p['name']))
        if kind in ENGINE_ONLY_PARAMS and not set(action['platforms']) <= PYTHON_ENGINE_PLATFORMS:
            say('%s: %s parameters exist only on %s (the host launchers cannot resolve them)'
                % (aid, kind, ' and '.join(sorted(PYTHON_ENGINE_PLATFORMS))))
        if kind in ('android_device', 'fastboot_device', 'fastboot_slot') and action.get('target_families') != ['android']:
            say('%s: %s parameters need target_families ["android"]' % (aid, kind))
        if kind == 'firmware_file' and not any(q['name'] == p['name'] + '_sha256' and q['type'] == 'sha256'
                                               for q in action.get('params') or []):
            say('%s: firmware_file %s needs a sha256 parameter named %s_sha256' % (aid, p['name'], p['name']))
        if kind == 'sha256' and not any(q['name'] + '_sha256' == p['name'] and q['type'] == 'firmware_file'
                                        for q in action.get('params') or []):
            say('%s: sha256 parameter %s must be named <firmware_file name>_sha256' % (aid, p['name']))
        if kind == 'target_root' and set(action['platforms']) != {'live-linux'}:
            say('%s: target_root parameters exist only on the live-linux platform' % aid)

    android_params = [p for p in params.values() if p['type'] == 'android_device']
    fastboot_params = [p for p in params.values() if p['type'] == 'fastboot_device']
    guards = action.get('guards') or []
    if len(android_params) > 1:
        say('%s: at most one android_device parameter' % aid)
    if len(fastboot_params) > 1:
        say('%s: at most one fastboot_device parameter' % aid)
    if sum(1 for p in params.values() if p['type'] == 'fastboot_slot') > 1:
        say('%s: at most one fastboot_slot parameter' % aid)
    if domain == 'android' and len(android_params) + len(fastboot_params) != 1 and 'single-download-mode-device' not in guards:
        say('%s: android actions are addressed to one phone and need exactly one android_device (adb) or fastboot_device '
            '(fastboot) parameter, or the single-download-mode-device guard (heimdall)' % aid)
    if guards and not set(action['platforms']) <= PYTHON_ENGINE_PLATFORMS:
        say('%s: guards exist only on %s (the host launchers cannot run them)' % (aid, ' and '.join(sorted(PYTHON_ENGINE_PLATFORMS))))
    firmware = [p for p in params.values() if p['type'] == 'firmware_file']
    if 'bootloader-unlocked' in guards and not fastboot_params:
        say('%s: the bootloader-unlocked guard needs a fastboot_device parameter' % aid)
    if 'image-matches-device' in guards and not (fastboot_params and any(p.get('values') == ['zip'] for p in firmware)):
        say('%s: the image-matches-device guard needs a fastboot_device and a firmware_file of kind zip' % aid)
    if 'single-download-mode-device' in guards and (android_params or fastboot_params):
        say('%s: the single-download-mode-device guard replaces a device parameter' % aid)

    used = set()
    for where, step in _steps(action):
        argv = step['argv']
        errors.extend(android_command_errors('%s %s' % (aid, where), argv, android_params))
        errors.extend(fastboot_command_errors('%s %s' % (aid, where), argv, params))
        errors.extend(heimdall_command_errors('%s %s' % (aid, where), argv, params))
        errors.extend(_expect_line_errors('%s %s' % (aid, where), step, params))
        if step.get('expect_line') is not None and not set(action['platforms']) <= PYTHON_ENGINE_PLATFORMS:
            say('%s %s: expect_line exists only on %s (the host launchers do not check output)'
                % (aid, where, ' and '.join(sorted(PYTHON_ENGINE_PLATFORMS))))
        if argv[0].lower() in FORBIDDEN_PROGRAMS:
            say('%s %s: program %r is not allowed in the catalog' % (aid, where, argv[0]))
        if argv[0] == 'chroot' and (action['risk'] == 'safe' or not action.get('requires_root')):
            say('%s %s: chroot needs requires_root and a non-safe risk class' % (aid, where))
        errs, names = _placeholder_errors('%s %s' % (aid, where), argv, params)
        errors.extend(errs)
        used |= names
    for name in params:
        if name not in used and params[name]['type'] != 'sha256':   # a sha256 is consumed by the engine with its firmware_file
            say('%s: parameter %s is declared but never used' % (aid, name))
    for p in params.values():
        if p['type'] == 'fastboot_slot' and not any(
                (m := PREFIXED.match(e)) and m.group(1) == '--set-active=' and m.group(2) == p['name']
                for _, st in _steps(action) for e in st['argv']):
            say('%s: a fastboot_slot parameter is only for --set-active=' % aid)
    flashing = any(st['argv'][:2] == ['fastboot', '-s'] and len(st['argv']) > 3 and st['argv'][3] in ('flash', 'update')
                   or st['argv'][:2] == ['heimdall', 'flash'] for _, st in _steps(action))
    if flashing:
        if action['risk'] != 'destructive':
            say('%s: flashing actions are destructive' % aid)
        if action['triggers']:
            say('%s: flashing actions are never proposed by a trigger (operator --select only)' % aid)
        wanted = {'fastboot': ['bootloader-unlocked'], 'heimdall': ['single-download-mode-device']}
        program = action['execute']['argv'][0]
        for guard in wanted.get(program, []):
            if guard not in guards:
                say('%s: %s flashing needs the %s guard' % (aid, program, guard))
        if action['execute']['argv'][3:4] == ['update'] and 'image-matches-device' not in guards:
            say('%s: fastboot update needs the image-matches-device guard' % aid)

    risk, rollback, backup = action['risk'], action['rollback'], action['backup']
    kind = rollback['kind']
    if kind == 'step' and not rollback.get('step'):
        say('%s: rollback kind step needs a step' % aid)
    if kind != 'step' and rollback.get('step'):
        say('%s: rollback step given but kind is %s' % (aid, kind))
    if kind in ('manual', 'restore-backup') and not rollback.get('doc'):
        say('%s: rollback kind %s needs a doc reference' % (aid, kind))
    if backup['required'] and not backup.get('what'):
        say('%s: a required backup must say what is backed up' % aid)
    if risk == 'safe':
        if kind not in ('none', 'step'):
            say('%s: safe actions roll back automatically or not at all' % aid)
        if backup['required'] or action.get('requires_target_rw'):
            say('%s: safe actions cannot require a backup or a read-write target' % aid)
    elif risk == 'reversible':
        if kind != 'step':
            say('%s: reversible actions need an automatic rollback step' % aid)
    elif risk == 'destructive':
        if not backup['required']:
            say('%s: destructive actions require a backup' % aid)
        if kind not in ('restore-backup', 'manual'):
            say('%s: destructive actions roll back by restore-backup or a manual procedure' % aid)
    if action.get('requires_target_rw'):
        if set(action['platforms']) != {'live-linux'}:
            say('%s: requires_target_rw exists only on the live-linux platform' % aid)
        if not any(p['type'] == 'target_root' for p in params.values()):
            say('%s: requires_target_rw needs a target_root parameter' % aid)

    families = action.get('target_families')
    if domain == 'hardware':
        if families:
            say('%s: hardware actions are about the machine and take no target_families' % aid)
        if not action['scope'].startswith('hardware.'):
            say('%s: hardware actions need a hardware.* scope' % aid)
    else:
        if not families and domain != 'malware':  # malware actions may be about the scanner, not one OS
            say('%s: %s actions need target_families' % (aid, domain))
        expected_scope = {'software': 'software', 'malware': 'malware', 'android': 'android'}.get(domain, 'os')
        if action['scope'] != expected_scope:
            say('%s: %s actions use scope %r' % (aid, domain, expected_scope))
    if domain in DOMAIN_FAMILIES and families and not set(families) <= DOMAIN_FAMILIES[domain]:
        say('%s: target_families must be within %s' % (aid, sorted(DOMAIN_FAMILIES[domain])))
    if domain in DOMAIN_PLATFORMS and not set(action['platforms']) <= DOMAIN_PLATFORMS[domain]:
        say('%s: platforms must be within %s' % (aid, sorted(DOMAIN_PLATFORMS[domain])))
    for t in action['triggers']:
        if t['check_id'] not in check_ids:
            say('%s: trigger check_id %r is not in the evidence schema' % (aid, t['check_id']))
    return errors


# ---------------------------------------------------------------------- loading

class Catalog:
    def __init__(self, actions, sha256, files):
        self.actions = actions      # action_id -> action dict (with '_domain')
        self.sha256 = sha256        # SHA-256 over every file name + content, sorted
        self.files = files

    def get(self, action_id):
        return self.actions.get(action_id)


def directory_sha256(catalog_dir=CATALOG_DIR):
    """The catalog SHA-256 (every file name + content, sorted) WITHOUT validating it (no python3-jsonschema needed).

    None when the directory has no catalog files. Equals load(...).sha256 for a catalog that loads.
    """
    paths = sorted(Path(catalog_dir).glob('*.json'))
    if not paths:
        return None
    digest = hashlib.sha256()
    try:
        for path in paths:
            digest.update(path.name.encode('utf-8') + b'\0' + path.read_bytes() + b'\0')
    except OSError:
        return None
    return digest.hexdigest()


def load(catalog_dir=CATALOG_DIR, schema_path=CATALOG_SCHEMA, evidence_schema=EVIDENCE_SCHEMA):
    """Load and validate every *.json catalog; raise CatalogError with all problems."""
    jsonschema = _jsonschema()
    schema = json.loads(Path(schema_path).read_text(encoding='utf-8'))
    validator = jsonschema.Draft202012Validator(schema)
    check_ids = evidence_check_ids(evidence_schema)
    problems, actions, files = [], {}, []
    digest = hashlib.sha256()
    paths = sorted(Path(catalog_dir).glob('*.json'))
    if not paths:
        raise CatalogError(['no catalog files in %s' % catalog_dir])
    domains = {}
    for path in paths:
        raw = path.read_bytes()
        digest.update(path.name.encode('utf-8') + b'\0' + raw + b'\0')
        files.append(path.name)
        try:
            doc = json.loads(raw.decode('utf-8'))
        except ValueError as exc:
            problems.append('%s: invalid JSON: %s' % (path.name, exc))
            continue
        errs = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
        if errs:
            best = jsonschema.exceptions.best_match(errs)
            where = '/'.join(str(p) for p in best.absolute_path) or '<root>'
            problems.append('%s: %s at %s' % (path.name, best.message, where))
            continue
        domain = doc['domain']
        if domain in domains:
            problems.append('%s: domain %s is already defined by %s' % (path.name, domain, domains[domain]))
        domains[domain] = path.name
        for action in doc['actions']:
            problems.extend('%s: %s' % (path.name, e) for e in action_errors(action, domain, check_ids))
            if action['action_id'] in actions:
                problems.append('%s: duplicate action_id %s' % (path.name, action['action_id']))
            actions[action['action_id']] = dict(action, _domain=domain)
    if problems:
        raise CatalogError(problems)
    return Catalog(actions, digest.hexdigest(), files)


# ---------------------------------------------------------------------- matching

def normalize_scope(scope):
    """Validate a scope list (or comma string); returns a tuple. Default: ('all',)."""
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.split(',') if s.strip()]
    scope = tuple(dict.fromkeys(scope or ['all']))
    bad = [s for s in scope if s not in SCOPE_VALUES]
    if bad:
        raise ValueError('unknown scope item(s): %s (allowed: %s)' % (', '.join(bad), ', '.join(SCOPE_VALUES)))
    if 'all' in scope and len(scope) > 1:
        raise ValueError('scope "all" must be used alone')
    for group in ('hardware', 'software'):
        if group in scope and any(s.startswith(group + '.') for s in scope):
            raise ValueError('scope "%s" already covers its %s.* items' % (group, group))
    return scope


def in_scope(scope, item):
    """Is catalog scope *item* selected by the normalized operator *scope*?"""
    if 'all' in scope or item in scope:
        return True
    if item.startswith('hardware.'):
        return 'hardware' in scope
    if item == 'software':
        return 'software.selected' in scope
    return False


def platform_of(evidence):
    return LIVE_PLATFORMS.get(evidence.get('source_platform'))


def _families(evidence):
    return {t['ref']: t['family'] for t in evidence.get('target_systems') or []}


def applicable(action, platform, scope, target_ref, families):
    """(ok, reason) for running *action* against *target_ref* on *platform*."""
    if platform not in action['platforms']:
        return False, 'platform'
    if not in_scope(scope, action['scope']):
        return False, 'scope'
    wanted = action.get('target_families')
    if wanted:
        if target_ref is None or families.get(target_ref) not in wanted:
            return False, 'target-family'
    return True, None


def triggered(catalog, evidence, scope):
    """Catalog-trigger proposals for *evidence*: list of dicts, evidence order, de-duplicated."""
    platform, families = platform_of(evidence), _families(evidence)
    out, seen = [], set()
    for check in evidence.get('checks') or []:
        for aid, action in catalog.actions.items():
            for trig in action['triggers']:
                if trig['check_id'] != check['check_id'] or check['status'] not in trig['status']:
                    continue
                ref = check.get('target_ref') if action.get('target_families') else None
                ok, _ = applicable(action, platform, scope, ref, families)
                key = (aid, ref)
                if ok and key not in seen:
                    seen.add(key)
                    item = {'action_id': aid, 'origin': 'catalog-trigger', 'trigger_check_id': check['check_id']}
                    if ref:
                        item['target_ref'] = ref
                    out.append(item)
    return out


def parse_ai_proposals(text, catalog, evidence, scope):
    """Extract the last ```rescue-proposals block from model *text*.

    Returns (accepted, rejected_count). The block is untrusted data: only exact
    catalog IDs that are applicable to this evidence survive, as proposals with
    origin ai-proposal. Anything malformed is rejected, never repaired.
    """
    blocks = PROPOSAL_FENCE.findall(text or '')
    if not blocks:
        return [], 0
    block = blocks[-1]
    if len(block.encode('utf-8')) > MAX_PROPOSAL_BLOCK:
        return [], 1
    try:
        doc = json.loads(block)
    except ValueError:
        return [], 1
    items = doc.get('proposed_actions') if isinstance(doc, dict) and set(doc) == {'proposed_actions'} else None
    if not isinstance(items, list):
        return [], 1
    platform, families = platform_of(evidence), _families(evidence)
    accepted, rejected, seen = [], 0, set()
    for item in items[:MAX_AI_PROPOSALS]:
        if not isinstance(item, dict) or not set(item) <= {'action_id', 'target_ref'}:
            rejected += 1
            continue
        aid, ref = item.get('action_id'), item.get('target_ref')
        action = catalog.get(aid) if isinstance(aid, str) else None
        if action is None or (ref is not None and (not isinstance(ref, str) or ref not in families)):
            rejected += 1
            continue
        if not action.get('target_families'):
            ref = None
        ok, _ = applicable(action, platform, scope, ref, families)
        if not ok or (aid, ref) in seen:
            rejected += 1
            continue
        seen.add((aid, ref))
        out = {'action_id': aid, 'origin': 'ai-proposal'}
        if ref:
            out['target_ref'] = ref
        accepted.append(out)
    rejected += max(0, len(items) - MAX_AI_PROPOSALS)
    return accepted, rejected


def prompt_summary(catalog, evidence, scope):
    """Compact list of applicable actions for the analysis prompt (IDs and metadata only, no argv)."""
    platform = platform_of(evidence)
    rows = []
    for aid in sorted(catalog.actions):
        a = catalog.actions[aid]
        if platform not in a['platforms'] or not in_scope(scope, a['scope']):
            continue
        rows.append({'action_id': aid, 'title': a['title'], 'scope': a['scope'], 'risk': a['risk'],
                     'target_families': a.get('target_families', []),
                     'triggers': sorted({t['check_id'] for t in a['triggers']})})
    return rows


# ---------------------------------------------------------------------- params

def validate_param(param, value, packages=None):
    """Return the typed value or raise ValueError. block_device/target_root get extra runtime checks."""
    kind = param['type']
    if kind == 'enum':
        if value not in param['values']:
            raise ValueError('must be one of: %s' % ', '.join(param['values']))
        return value
    if kind == 'integer':
        try:
            number = int(str(value), 10)
        except ValueError:
            raise ValueError('must be an integer') from None
        if not param['minimum'] <= number <= param['maximum']:
            raise ValueError('must be between %d and %d' % (param['minimum'], param['maximum']))
        return number
    text = str(value)
    if kind == 'package_name':
        if not PACKAGE_RE.match(text):
            raise ValueError('is not a valid package name')
        if text.endswith('-'):
            # apt reads a trailing '-' as "remove this package": `install --reinstall vim-` removes vim.
            raise ValueError('must not end with "-" (apt would treat it as a removal)')
        if packages is not None and text not in packages:
            raise ValueError('is not in the operator-selected package list')
        return text
    if kind == 'service_name':
        if not SERVICE_RE.match(text):
            raise ValueError('is not a valid service name')
        return text
    if kind == 'detection_ref':
        if not DETECTION_RE.match(text):
            raise ValueError('is not a detection reference (d-N)')
        return text
    if kind == 'block_device':
        if not BLOCK_RE.match(text) or '..' in text.split('/'):
            raise ValueError('is not a /dev/ block device path')
        return text
    if kind == 'target_root':
        raise ValueError('is provided by the target mount provider, never by the operator')
    if kind == 'state_dir':
        raise ValueError('is provided by the engine (the USB state directory), never by the operator')
    if kind == 'android_device':
        raise ValueError('is resolved by the engine from the USB inventory and adb, never by the operator')
    if kind in ('fastboot_device', 'fastboot_slot'):
        raise ValueError('is resolved by the engine from the phone in fastboot mode, never by the operator')
    if kind == 'sha256':
        if not SHA256_RE.match(text):
            raise ValueError('must be the 64 hexadecimal characters of the official SHA-256')
        return text.lower()
    if kind == 'firmware_file':
        if (not text.startswith('/') or len(text) > 1024 or os.path.normpath(text) != text
                or re.search(r'[\x00-\x1f\x7f]', text)):
            raise ValueError('must be an absolute, normalized path without control characters')
        return text
    raise ValueError('unknown parameter type %s' % kind)


def render(argv, values):
    """Substitute validated *values* into a catalog argv; every element stays one argument."""
    out = []
    for element in argv:
        m = WHOLE.match(element) or PREFIXED.match(element) or ROOTED.match(element) or OPTION.match(element)
        if m is None:
            out.append(element)
            continue
        out.append(PLACEHOLDER.sub(lambda mm: str(values[mm.group(1)]), element, count=1))
    return out


def render_expect_line(line, values):
    """The exact output line a step must print: *line* with its one trailing {enum_param} replaced by the value."""
    return re.sub(r'\{([a-z][a-z0-9_]{0,31})\}$', lambda m: str(values[m.group(1)]), line)


def _main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(description='Validate the repair catalog.')
    ap.add_argument('--catalog-dir', default=str(CATALOG_DIR))
    args = ap.parse_args(argv)
    try:
        catalog = load(args.catalog_dir)
    except CatalogError as exc:
        for problem in exc.problems:
            print('catalog: INVALID: %s' % problem, file=sys.stderr)
        return 1
    print('catalog: valid (%d actions in %d files, sha256 %s)' % (len(catalog.actions), len(catalog.files),
                                                                     catalog.sha256))
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
