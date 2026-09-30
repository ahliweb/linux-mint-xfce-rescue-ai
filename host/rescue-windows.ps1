<#
.SYNOPSIS
  Host launcher for a RUNNING Windows 10/11: read-only checks, schema 1.2 evidence,
  direct OpenCode Go analysis. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

.DESCRIPTION
  Works in Windows PowerShell 5.1 and PowerShell 7. No administrator rights are required or
  requested (checks that need them report 'unknown'). Nothing is installed and nothing is
  written to the host disk: the evidence and the analysis are written to <bundle>\reports\ on
  the rescue USB. The evidence contains only closed-set status codes and bounded numbers;
  never a user name, computer name, path, serial number, or raw text.

  The model answer is displayed and saved as text. It is never executed.

  Repairs: typed catalog actions only (rescue-ai\v1\catalog), run under -RepairPolicy, journaled
  to <bundle>\reports\repairs\journal.jsonl (docs/host-repair.md). Never elevates.

  Exit codes: 0 ok | 1 a repair action failed or was rolled back | 2 invalid evidence, catalog
              or -Select | 3 no API key | 4 network/HTTP error | 5 bundle/reports/journal
              unusable | 64 usage

.PARAMETER EvidenceOnly
  Collect, validate and save the evidence. No network access at all (the connectivity
  check is reported as 'unknown').

.PARAMETER DryRun
  Like -EvidenceOnly, and also print what would be sent (endpoint, model, sizes, whether a
  key is present). Nothing is sent.

.PARAMETER BundleDir
  The rescue-omes bundle folder. Default: <script folder>\rescue-omes, then <script folder>\..

.PARAMETER Scope
  Detection scope, comma separated: all (default), hardware, hardware.cpu, ..., os, software,
  software.selected, malware. Selects the optional detection modules in host\modules\windows\.

.PARAMETER Packages
  Comma separated package IDs for -Scope software.selected.

.PARAMETER RepairPolicy
  detect-only | approve-each (default) | auto-safe. Recorded in the evidence and enforced by the
  repair engine (see docs/repair-framework.md).

.PARAMETER Approve
  Comma separated action IDs pre-approved for this run (approve-each without a terminal).

.PARAMETER Param
  Comma separated ACTION_ID.NAME=VALUE parameter values (typed and validated).

.PARAMETER BackupRef
  A backup/image file for destructive actions; only its size and a fingerprint are journaled.

.PARAMETER Select
  Comma separated ACTION_ID[:os-N] chosen by the operator (must apply to this host and scope).

.PARAMETER ListRepairs
  Show the repair plan only: nothing is executed and nothing is journaled.
#>
[CmdletBinding()]
param(
    [switch]$EvidenceOnly,
    [switch]$DryRun,
    [string]$BundleDir,
    [string]$Scope = 'all',
    [string]$Packages = '',
    [ValidateSet('detect-only', 'approve-each', 'auto-safe')]
    [string]$RepairPolicy = 'approve-each',
    [string[]]$Approve = @(),
    [string[]]$Param = @(),
    [string]$BackupRef = '',
    [string[]]$Select = @(),
    [switch]$ListRepairs
)

$script:Endpoint = 'https://opencode.ai/zen/go/v1/chat/completions'
$script:ModelId = 'mimo-v2.6-flash'
$script:BundleMarker = 'profiles/rescue-hermes/analysis-prompt.md'
$script:ExitCode = 0

# ----------------------------------------------------------------------------------------
# Pure helpers (unit-tested through RESCUE_PS_LIBRARY_ONLY=1 dot-sourcing)
# ----------------------------------------------------------------------------------------

function Get-UtcIso {
    param([DateTime]$When = [DateTime]::UtcNow)
    return $When.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    } finally {
        $sha.Dispose()
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function Get-OpaqueTargetId {
    param([string]$Seed)
    if ([string]::IsNullOrWhiteSpace($Seed)) { $Seed = 'fallback:' + [guid]::NewGuid().ToString() }
    return 'target-' + (Get-Sha256Hex -Text $Seed).Substring(0, 16)
}

function ConvertTo-SafeRelease {
    # Reduce free text to the schema pattern ^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$ or $null.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $t = [regex]::Replace($Text, '[^A-Za-z0-9 ._+()/-]', ' ')
    $t = [regex]::Replace($t, ' +', ' ').Trim()
    $t = [regex]::Replace($t, '^[^A-Za-z0-9]+', '')
    if ($t.Length -gt 64) { $t = $t.Substring(0, 64).Trim() }
    if ($t.Length -eq 0) { return $null }
    return $t
}

function ConvertTo-JsonString {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($ch -ceq [char]34) { [void]$sb.Append('\"') }
        elseif ($ch -ceq [char]92) { [void]$sb.Append('\\') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32 -or $code -eq 127) { [void]$sb.Append('\u' + $code.ToString('x4')) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-RescueJson {
    # Small deterministic serializer (own code so numbers are culture-independent and the
    # output is identical on Windows PowerShell 5.1 and PowerShell 7).
    # -Indent -1 = compact.
    param($Value, [int]$Indent = -1, [int]$Level = 0)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ConvertTo-JsonString -Text $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) {
        return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return ([System.Convert]::ToDouble($Value).ToString('0.###', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    $pretty = $Indent -ge 0
    $nl = ''
    $pad = ''
    $padIn = ''
    if ($pretty) {
        $nl = "`n"
        $pad = ' ' * ($Indent * $Level)
        $padIn = ' ' * ($Indent * ($Level + 1))
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Value.Keys) {
            $sep = ':'
            if ($pretty) { $sep = ': ' }
            $parts.Add($padIn + (ConvertTo-JsonString -Text ([string]$key)) + $sep + (ConvertTo-RescueJson -Value $Value[$key] -Indent $Indent -Level ($Level + 1)))
        }
        if ($parts.Count -eq 0) { return '{}' }
        return '{' + $nl + ($parts -join (',' + $nl)) + $nl + $pad + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $parts.Add($padIn + (ConvertTo-RescueJson -Value $item -Indent $Indent -Level ($Level + 1)))
        }
        if ($parts.Count -eq 0) { return '[]' }
        return '[' + $nl + ($parts -join (',' + $nl)) + $nl + $pad + ']'
    }
    return ConvertTo-JsonString -Text ([string]$Value)
}

function ConvertFrom-EnvValue {
    # Port of _rescue_env_parse_value from scripts/lib/rescue-env.sh. The value is DATA:
    # nothing is expanded or evaluated. Returns @{ Ok = $bool; Value = $string }.
    param([string]$Raw)
    $bad = @{ Ok = $false; Value = '' }
    $SQ = [char]39; $DQ = [char]34; $BS = [char]92; $DL = [char]36; $BT = [char]96
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    $n = $Raw.Length
    while ($i -lt $n) {
        $c = $Raw[$i]
        if ($c -ceq $SQ) {
            $i++
            while ($i -lt $n -and $Raw[$i] -cne $SQ) { [void]$sb.Append($Raw[$i]); $i++ }
            if ($i -ge $n) { return $bad }
            $i++
        }
        elseif ($c -ceq $DQ) {
            $i++
            $closed = $false
            while ($i -lt $n) {
                $c = $Raw[$i]
                if ($c -ceq $DQ) { $closed = $true; break }
                elseif ($c -ceq $BS) {
                    $i++
                    if ($i -ge $n) { return $bad }
                    $d = $Raw[$i]
                    if ($d -ceq $DQ -or $d -ceq $BS -or $d -ceq $DL -or $d -ceq $BT) { [void]$sb.Append($d) }
                    else { [void]$sb.Append($BS); [void]$sb.Append($d) }
                }
                elseif ($c -ceq $DL -or $c -ceq $BT) { return $bad }
                else { [void]$sb.Append($c) }
                $i++
            }
            if (-not $closed) { return $bad }
            $i++
        }
        elseif ($c -ceq $BS) {
            $i++
            if ($i -ge $n) { return $bad }
            [void]$sb.Append($Raw[$i])
            $i++
        }
        elseif ($c -ceq $DL -or $c -ceq $BT) { return $bad }
        elseif ($c -ceq ' ' -or $c -ceq [char]9) {
            $rest = $Raw.Substring($i).Trim()
            if ($rest.Length -eq 0 -or $rest.StartsWith('#')) { break }
            return $bad
        }
        else {
            [void]$sb.Append($c)
            $i++
        }
    }
    return @{ Ok = $true; Value = $sb.ToString() }
}

function Get-ApiKeyFromEnvFile {
    # Reads ONLY OPENCODE_GO_API_KEY from a KEY=VALUE file, as data. First valid assignment
    # wins. Returns $null when the file/key is missing or unusable. Never prints the value.
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $lines = [System.IO.File]::ReadAllLines($Path)
    } catch {
        return $null
    }
    foreach ($line in $lines) {
        $line = $line.TrimEnd([char]13)
        if ($line -cmatch '^\s*(?:export\s+)?OPENCODE_GO_API_KEY\s*=\s*(.*)$') {
            $parsed = ConvertFrom-EnvValue -Raw $Matches[1]
            if (-not $parsed.Ok) { continue }
            if ($parsed.Value.Length -eq 0) { continue }
            return $parsed.Value
        }
    }
    return $null
}

function Test-KeyUsable {
    param([string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return $false }
    return ($Key -notmatch '[\x00-\x1f\x7f]')
}

# Closed sets from rescue-ai/v1/rescue-evidence.schema.json (the fields these launchers use).
$script:CheckIds = @(
    'block-device-discovery', 'filesystem-discovery', 'firmware-boot-entry', 'kernel-log', 'system-journal',
    'smart-health', 'nvme-health', 'lvm-or-raid-discovery', 'filesystem-read-only', 'network-connectivity',
    'iso-integrity', 'os-detection', 'disk-free-space', 'encryption-status', 'boot-loader-files',
    'windows-fast-startup', 'windows-ntfs-dirty', 'windows-pending-updates', 'windows-crash-dumps',
    'windows-event-log-errors', 'windows-defender-status', 'windows-update-service',
    'linux-fstab-consistency', 'linux-kernel-initrd', 'linux-package-state', 'linux-failed-units',
    'linux-journal-errors', 'macos-apfs-container', 'macos-filevault', 'macos-sip-status',
    'macos-crash-reports', 'macos-software-update', 'macos-startup-disk',
    'linux-boot-partition-space', 'linux-grub-config', 'linux-apt-sources', 'linux-dpkg-lock',
    'windows-boot-config', 'windows-system-files', 'windows-restore-points', 'macos-disk-verify',
    'hw-cpu', 'hw-cpu-thermal', 'hw-memory', 'hw-memory-errors', 'hw-disk', 'hw-gpu',
    'hw-gpu-driver', 'hw-display', 'hw-network-adapter', 'hw-wifi', 'hw-battery', 'hw-usb',
    'sw-inventory', 'sw-package-health', 'sw-broken-dependencies', 'sw-pending-config',
    'sw-held-packages', 'sw-package-integrity', 'sw-app-health', 'sw-startup-items',
    'malware-scan', 'malware-signatures', 'malware-realtime-protection', 'malware-quarantine')
$script:ScopeValues = @('all', 'hardware', 'hardware.cpu', 'hardware.memory', 'hardware.disk', 'hardware.gpu',
    'hardware.display', 'hardware.network', 'hardware.battery', 'hardware.usb', 'os', 'software', 'software.selected', 'malware')
$script:ModuleDomains = @('hardware', 'os', 'software', 'malware')
$script:MaxChecks = 160
# Environment variables a repair child process may inherit (system/profile locations only).
$script:ChildEnvAllowlist = @('SystemDrive', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
    'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432', 'ALLUSERSPROFILE', 'PUBLIC',
    'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP',
    'OS', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'PATHEXT', 'ComSpec')
$script:Statuses = @('pass', 'fail', 'warn', 'not_applicable', 'unknown')
$script:Platforms = @('linux-mint-xfce-live', 'systemrescue-live', 'other-live-linux', 'linux-host', 'windows-host', 'macos-host')
$script:BootModes = @('uefi', 'legacy-bios', 'unknown')

function New-Check {
    param(
        [string]$Id,
        [string]$Status,
        [string]$TargetRef = 'os-0',
        [string]$Kind,
        $Number
    )
    $c = [ordered]@{
        check_id    = $Id
        status      = $Status
        source      = 'host-allowlist'
        observed_at = (Get-UtcIso)
    }
    if ($TargetRef) { $c['target_ref'] = $TargetRef }
    if ($Kind) { $c['value'] = [ordered]@{ kind = $Kind; number = $Number } }
    return $c
}

function Get-CountStatus {
    param([int]$Count, [int]$FailAt = 0)
    if ($FailAt -gt 0 -and $Count -ge $FailAt) { return 'fail' }
    if ($Count -gt 0) { return 'warn' }
    return 'pass'
}

function New-RescueEvidence {
    param(
        [object[]]$Checks,
        [string]$Family = 'windows',
        $Release,
        [string]$Architecture = 'unknown',
        [string]$Encryption = 'unknown',
        [string]$BootMode = 'unknown',
        [string]$OpaqueSeed,
        [bool]$Authenticated = $false,
        [string]$Destination = 'unknown',
        [DateTime]$When = [DateTime]::UtcNow,
        [string[]]$Scope = @('all'),
        [string]$RepairPolicy = 'approve-each'
    )
    $compact = ConvertTo-RescueJson -Value @($Checks)
    return [ordered]@{
        schema_version           = '1.2'
        run_id                   = 'rescue-' + $When.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture) + '-wh'
        source_platform          = 'windows-host'
        boot_mode                = $BootMode
        collected_at             = (Get-UtcIso -When $When)
        target_device_opaque_id  = (Get-OpaqueTargetId -Seed $OpaqueSeed)
        ventoy_version           = $null
        linux_release            = $null
        target_systems           = @([ordered]@{
                ref          = 'os-0'
                family       = $Family
                release      = $Release
                architecture = $Architecture
                detection    = 'host-native'
                encryption   = $Encryption
                access       = 'host-running'
            })
        checks                   = @($Checks)
        evidence_manifest        = [ordered]@{
            entry_count     = @($Checks).Count
            manifest_sha256 = (Get-Sha256Hex -Text $compact)
            storage_class   = 'usb-rescue-state'
        }
        ai_provider              = [ordered]@{
            provider_id       = 'opencode-go'
            model_id          = $script:ModelId
            authenticated     = $Authenticated
            destination_class = $Destination
        }
        ai_analysis_status       = 'not_run'
        mutation_status          = 'none'
        verification             = [ordered]@{ hashes_verified = $false; read_back_verified = $false; status = 'not_applicable' }
        classification           = 'confidential'
        source_references         = @('opencode-go:provider', 'nist:sp-800-86', 'microsoft:windows-recovery')
        scope                    = @($Scope)
        repair_policy            = $RepairPolicy
    }
}

function ConvertTo-RescueScope {
    # Validates a comma separated scope. Returns @{ Ok; Scope; Error } (same rules as
    # scripts/lib/repair_catalog.py normalize_scope).
    param([string]$Text)
    $items = @()
    foreach ($s in ($Text -split ',')) {
        $s = $s.Trim()
        if ($s -and $items -notcontains $s) { $items += $s }
    }
    if ($items.Count -eq 0) { $items = @('all') }
    foreach ($s in $items) {
        if ($script:ScopeValues -notcontains $s) { return @{ Ok = $false; Scope = @(); Error = "unknown scope item: $s" } }
    }
    if ($items -contains 'all' -and $items.Count -gt 1) { return @{ Ok = $false; Scope = @(); Error = 'scope all must be used alone' } }
    foreach ($g in @('hardware', 'software')) {
        if ($items -contains $g -and @($items | Where-Object { $_.StartsWith($g + '.') }).Count -gt 0) {
            return @{ Ok = $false; Scope = @(); Error = "scope $g already covers its $g.* items" }
        }
    }
    return @{ Ok = $true; Scope = $items; Error = '' }
}

function Test-ScopeWants {
    param([string[]]$Scope, [string]$Domain)
    if ($Scope -contains 'all' -or $Scope -contains $Domain) { return $true }
    if ($Domain -eq 'hardware') { return @($Scope | Where-Object { $_.StartsWith('hardware.') }).Count -gt 0 }
    if ($Domain -eq 'software') { return $Scope -contains 'software.selected' }
    return $false
}

function ConvertFrom-ModuleCheck {
    # One item emitted by a host\modules\windows\<domain>.ps1 module -> a check, or $null when it
    # is outside the evidence contract (module output is data and is validated here).
    param($Item, [string]$Domain)
    if ($null -eq $Item -or -not ($Item -is [System.Collections.IDictionary])) { return $null }
    $id = [string]$Item['check_id']
    $status = [string]$Item['status']
    if ($script:CheckIds -notcontains $id -or $script:Statuses -notcontains $status) { return $null }
    $ref = 'os-0'
    if ($Domain -eq 'hardware') { $ref = '' }
    $kind = [string]$Item['kind']
    if ($kind) {
        $n = $Item['number']
        if (@('percent', 'count', 'bytes', 'days', 'seconds', 'celsius') -notcontains $kind) { return $null }
        if (-not ($n -is [int] -or $n -is [long] -or $n -is [double]) -or $n -lt 0 -or $n -gt 1e15) { return $null }
        return New-Check -Id $id -Status $status -TargetRef $ref -Kind $kind -Number $n
    }
    return New-Check -Id $id -Status $status -TargetRef $ref
}

function Invoke-RescueModules {
    # Runs the optional detection modules host\modules\windows\{hardware,os,software}.ps1 in a
    # child scope with the call operator (no string evaluation, no dot-sourcing). A failing
    # module is reported and skipped; it never stops the collection.
    param([string]$Bundle, [string[]]$Scope, [string[]]$PackageList)
    $out = @()
    if (-not $Bundle) { return , $out }
    foreach ($domain in $script:ModuleDomains) {
        if (-not (Test-ScopeWants -Scope $Scope -Domain $domain)) { continue }
        $path = Join-Path (Join-Path (Join-Path (Join-Path $Bundle 'host') 'modules') 'windows') ($domain + '.ps1')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try {
            foreach ($item in @(& $path -Scope $Scope -Packages $PackageList)) {
                $c = ConvertFrom-ModuleCheck -Item $item -Domain $domain
                if ($null -ne $c) { $out += $c } else { Write-Host "  catatan / note: module $domain emitted an invalid check (dropped)" }
            }
        } catch {
            Write-Host "  catatan / note: module $domain failed and was skipped"
        }
    }
    return , $out
}

function Test-RescueEvidence {
    # Structural self-check against the schema fields this launcher uses. Returns a list of
    # problems (empty list = OK). The full JSON Schema check is done offline by
    # scripts/validate-evidence.py on a machine that has python3-jsonschema.
    param($Evidence)
    $problems = New-Object System.Collections.Generic.List[string]
    foreach ($k in @('schema_version', 'run_id', 'source_platform', 'boot_mode', 'collected_at',
            'target_device_opaque_id', 'checks', 'evidence_manifest', 'ai_provider', 'ai_analysis_status',
            'mutation_status', 'verification', 'classification')) {
        if (-not $Evidence.Contains($k)) { $problems.Add("missing $k") }
    }
    if ($problems.Count -gt 0) { return , $problems }
    if (@('1.0', '1.1', '1.2') -notcontains $Evidence['schema_version']) { $problems.Add('schema_version') }
    if ($Evidence['run_id'] -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$') { $problems.Add('run_id') }
    if ($script:Platforms -notcontains $Evidence['source_platform']) { $problems.Add('source_platform') }
    if ($script:BootModes -notcontains $Evidence['boot_mode']) { $problems.Add('boot_mode') }
    if ($Evidence['collected_at'] -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { $problems.Add('collected_at') }
    if ($Evidence['target_device_opaque_id'] -notmatch '^target-[A-Za-z0-9][A-Za-z0-9._-]{3,47}$') { $problems.Add('target_device_opaque_id') }
    $refs = @()
    foreach ($t in @($Evidence['target_systems'])) {
        $refs += $t['ref']
        if ($t['ref'] -notmatch '^os-[0-7]$') { $problems.Add('target ref') }
        if (@('linuxmint', 'linux-other', 'windows', 'macos', 'unknown') -notcontains $t['family']) { $problems.Add('target family') }
        if ($null -ne $t['release'] -and $t['release'] -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$') { $problems.Add('target release') }
        if (@('x86_64', 'arm64', 'unknown') -notcontains $t['architecture']) { $problems.Add('target architecture') }
        if (@('live-offline', 'host-native') -notcontains $t['detection']) { $problems.Add('target detection') }
        if (@('none', 'bitlocker', 'filevault', 'luks', 'unknown') -notcontains $t['encryption']) { $problems.Add('target encryption') }
        if (@('read-only-mounted', 'not-mounted-encrypted', 'not-mounted-unsupported', 'host-running', 'unknown') -notcontains $t['access']) { $problems.Add('target access') }
    }
    $checks = @($Evidence['checks'])
    if ($checks.Count -lt 1 -or $checks.Count -gt $script:MaxChecks) { $problems.Add('checks count') }
    foreach ($c in $checks) {
        $id = [string]$c['check_id']
        if ($script:CheckIds -notcontains $id) { $problems.Add("check_id $id") }
        if ($script:Statuses -notcontains $c['status']) { $problems.Add("status of $id") }
        if ($c['source'] -ne 'host-allowlist') { $problems.Add("source of $id") }
        if ($c['observed_at'] -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { $problems.Add("observed_at of $id") }
        if ($c.Contains('target_ref')) {
            if ($c['target_ref'] -notmatch '^os-[0-7]$' -or $refs -notcontains $c['target_ref']) { $problems.Add("target_ref of $id") }
        }
        if ($c.Contains('value')) {
            $v = $c['value']
            if (@('percent', 'count', 'bytes', 'days', 'seconds', 'celsius') -notcontains $v['kind']) { $problems.Add("value kind of $id") }
            if (-not ($v['number'] -is [int] -or $v['number'] -is [long] -or $v['number'] -is [double]) -or $v['number'] -lt 0) { $problems.Add("value number of $id") }
        }
    }
    $m = $Evidence['evidence_manifest']
    if ($m['entry_count'] -ne $checks.Count) { $problems.Add('entry_count') }
    if ($m['manifest_sha256'] -notmatch '^[a-f0-9]{64}$') { $problems.Add('manifest_sha256') }
    if ($m['storage_class'] -ne 'usb-rescue-state') { $problems.Add('storage_class') }
    $ai = $Evidence['ai_provider']
    if ($ai['provider_id'] -ne 'opencode-go') { $problems.Add('provider_id') }
    if (@('cloud', 'unknown') -notcontains $ai['destination_class']) { $problems.Add('destination_class') }
    if (@('not_run', 'completed', 'manual_intervention', 'blocked') -notcontains $Evidence['ai_analysis_status']) { $problems.Add('ai_analysis_status') }
    if (@('none', 'approval_required', 'completed_verified', 'failed', 'rolled_back') -notcontains $Evidence['mutation_status']) { $problems.Add('mutation_status') }
    if ($Evidence.Contains('scope')) {
        $sc = ConvertTo-RescueScope -Text (@($Evidence['scope']) -join ',')
        if (-not $sc.Ok) { $problems.Add('scope') }
    }
    if ($Evidence.Contains('repair_policy') -and @('detect-only', 'approve-each', 'auto-safe') -notcontains $Evidence['repair_policy']) { $problems.Add('repair_policy') }
    return , $problems
}

function Find-RescueBundle {
    param([string]$ScriptDir, [string]$Explicit)
    $candidates = @()
    if ($Explicit) { $candidates += $Explicit }
    else {
        $candidates += (Join-Path $ScriptDir 'rescue-omes')
        $candidates += (Join-Path $ScriptDir '..')
    }
    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $cand $script:BundleMarker) -PathType Leaf) {
            return (Resolve-Path -LiteralPath $cand).ProviderPath
        }
    }
    return $null
}

# ----------------------------------------------------------------------------------------
# Read-only host checks (each one degrades to 'unknown' on any error)
# ----------------------------------------------------------------------------------------

function Test-IsAdmin {
    try {
        $p = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-SystemDrive {
    $d = $env:SystemDrive
    if ([string]::IsNullOrEmpty($d)) { $d = 'C:' }
    return $d
}

function Get-OsInfo {
    $info = @{ Family = 'windows'; Release = $null; Architecture = 'unknown'; Ok = $false }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = ([string]$os.Caption) -replace '^\s*Microsoft\s+', ''
        $display = ''
        try {
            $display = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction Stop).DisplayVersion
        } catch { $display = '' }
        $info.Release = ConvertTo-SafeRelease -Text ($caption + ' ' + $display)
        $info.Ok = -not [string]::IsNullOrEmpty($caption)
    } catch { }
    try {
        $arch = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1).Architecture
        if ($arch -eq 9) { $info.Architecture = 'x86_64' }
        elseif ($arch -eq 12) { $info.Architecture = 'arm64' }
    } catch { }
    return $info
}

function Get-EncryptionState {
    # Returns 'bitlocker', 'none' or 'unknown'. Needs administrator; never elevates.
    if (-not (Test-IsAdmin)) { return 'unknown' }
    $drive = Get-SystemDrive
    try {
        if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
            if ([string]$vol.ProtectionStatus -eq 'On') { return 'bitlocker' }
            $vs = [string]$vol.VolumeStatus
            if ($vs -eq 'FullyEncrypted' -or $vs -eq 'EncryptionInProgress') { return 'bitlocker' }
            if ([string]$vol.ProtectionStatus -eq 'Off') { return 'none' }
        }
    } catch { }
    try {
        # Only the protection on/off markers are read; the raw output is never kept or emitted.
        $text = (& manage-bde.exe -status $drive 2>&1 | Out-String)
        if ($text -match 'Protection Status:\s*Protection On') { return 'bitlocker' }
        if ($text -match 'Protection Status:\s*Protection Off') {
            if ($text -match 'Conversion Status:\s*Fully Encrypted') { return 'bitlocker' }
            return 'none'
        }
    } catch { }
    return 'unknown'
}

function Get-DiskFreeCheck {
    try {
        $drive = Get-SystemDrive
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $drive + "'") -ErrorAction Stop
        if ($disk -and $disk.Size -gt 0) {
            $pct = [math]::Round(([double]$disk.FreeSpace * 100.0) / [double]$disk.Size, 1)
            $status = 'pass'
            if ($pct -lt 5) { $status = 'fail' } elseif ($pct -lt 10) { $status = 'warn' }
            return New-Check -Id 'disk-free-space' -Status $status -Kind 'percent' -Number $pct
        }
    } catch { }
    return New-Check -Id 'disk-free-space' -Status 'unknown'
}

function Get-FastStartupCheck {
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
        if ($v -eq 1) { return New-Check -Id 'windows-fast-startup' -Status 'warn' }
        return New-Check -Id 'windows-fast-startup' -Status 'pass'
    } catch { return New-Check -Id 'windows-fast-startup' -Status 'unknown' }
}

function Get-PendingUpdatesCheck {
    try {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        foreach ($k in $keys) {
            if (Test-Path -LiteralPath $k) { return New-Check -Id 'windows-pending-updates' -Status 'warn' }
        }
        return New-Check -Id 'windows-pending-updates' -Status 'pass'
    } catch { return New-Check -Id 'windows-pending-updates' -Status 'unknown' }
}

function Get-CrashDumpsCheck {
    try {
        $dir = Join-Path $env:SystemRoot 'Minidump'
        $n = 0
        if (Test-Path -LiteralPath $dir) {
            $n = @(Get-ChildItem -LiteralPath $dir -Filter '*.dmp' -File -ErrorAction Stop).Count
        }
        return New-Check -Id 'windows-crash-dumps' -Status (Get-CountStatus -Count $n) -Kind 'count' -Number $n
    } catch { return New-Check -Id 'windows-crash-dumps' -Status 'unknown' }
}

function Get-EventLogErrorsCheck {
    try {
        $start = (Get-Date).AddDays(-7)
        $n = 0
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $start } -MaxEvents 1000 -ErrorAction Stop
            $n = @($events).Count
        } catch {
            if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*') { $n = 0 }
            else { throw }
        }
        return New-Check -Id 'windows-event-log-errors' -Status (Get-CountStatus -Count $n -FailAt 50) -Kind 'count' -Number $n
    } catch { return New-Check -Id 'windows-event-log-errors' -Status 'unknown' }
}

function Get-DefenderCheck {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled -and $mp.AntivirusEnabled) { return New-Check -Id 'windows-defender-status' -Status 'pass' }
        return New-Check -Id 'windows-defender-status' -Status 'warn'
    } catch { return New-Check -Id 'windows-defender-status' -Status 'unknown' }
}

function Get-UpdateServiceCheck {
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop
        if ($null -eq $svc) { return New-Check -Id 'windows-update-service' -Status 'unknown' }
        if ([string]$svc.StartMode -eq 'Disabled') { return New-Check -Id 'windows-update-service' -Status 'warn' }
        return New-Check -Id 'windows-update-service' -Status 'pass'
    } catch { return New-Check -Id 'windows-update-service' -Status 'unknown' }
}

function Get-SmartCheck {
    try {
        $health = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { [string]$_.HealthStatus })
        if ($health.Count -eq 0) { return New-Check -Id 'smart-health' -Status 'unknown' }
        if ($health -contains 'Unhealthy') { return New-Check -Id 'smart-health' -Status 'fail' }
        if ($health -contains 'Warning') { return New-Check -Id 'smart-health' -Status 'warn' }
        if (@($health | Where-Object { $_ -ne 'Healthy' }).Count -eq 0) { return New-Check -Id 'smart-health' -Status 'pass' }
    } catch { }
    return New-Check -Id 'smart-health' -Status 'unknown'
}

function Get-NetworkCheck {
    param([bool]$Skip)
    if ($Skip) { return New-Check -Id 'network-connectivity' -Status 'unknown' -TargetRef '' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('opencode.ai', 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(5000, $false) -and $client.Connected) {
            $client.EndConnect($iar)
            return New-Check -Id 'network-connectivity' -Status 'pass' -TargetRef ''
        }
        return New-Check -Id 'network-connectivity' -Status 'fail' -TargetRef ''
    } catch {
        return New-Check -Id 'network-connectivity' -Status 'fail' -TargetRef ''
    } finally {
        $client.Close()
    }
}

function Get-BootMode {
    if ($env:firmware_type -eq 'UEFI') { return 'uefi' }
    if ($env:firmware_type -eq 'Legacy') { return 'legacy-bios' }
    try {
        $null = Confirm-SecureBootUEFI -ErrorAction Stop
        return 'uefi'
    } catch { return 'unknown' }
}

function Get-MachineSeed {
    try {
        $g = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($g) { return 'machine-guid:' + [string]$g }
    } catch { }
    return $null
}

function Invoke-HostCollection {
    param([bool]$SkipNetwork, [bool]$Authenticated, [string]$Destination, [string]$Bundle,
        [string[]]$Scope = @('all'), [string[]]$PackageList = @(), [string]$RepairPolicy = 'approve-each')
    $os = Get-OsInfo
    $encryption = Get-EncryptionState
    $encStatus = 'pass'
    if ($encryption -eq 'unknown') { $encStatus = 'unknown' }
    $osStatus = 'unknown'
    if ($os.Ok) { $osStatus = 'pass' }
    $checks = @(
        (New-Check -Id 'os-detection' -Status $osStatus),
        (New-Check -Id 'encryption-status' -Status $encStatus),
        (Get-DiskFreeCheck),
        (Get-FastStartupCheck),
        (Get-PendingUpdatesCheck),
        (Get-CrashDumpsCheck),
        (Get-EventLogErrorsCheck),
        (Get-DefenderCheck),
        (Get-UpdateServiceCheck)
    )
    # smart-health is a disk check: only within the operator's hardware.disk scope.
    if ($Scope -contains 'all' -or $Scope -contains 'hardware' -or $Scope -contains 'hardware.disk') { $checks += (Get-SmartCheck) }
    $checks += (Get-NetworkCheck -Skip $SkipNetwork)
    $checks += Invoke-RescueModules -Bundle $Bundle -Scope $Scope -PackageList $PackageList
    if ($checks.Count -gt $script:MaxChecks) { $checks = $checks[0..($script:MaxChecks - 1)] }
    return New-RescueEvidence -Checks $checks -Family $os.Family -Release $os.Release `
        -Architecture $os.Architecture -Encryption $encryption -BootMode (Get-BootMode) `
        -OpaqueSeed (Get-MachineSeed) -Authenticated $Authenticated -Destination $Destination `
        -Scope $Scope -RepairPolicy $RepairPolicy
}

# ----------------------------------------------------------------------------------------
# Repair engine (docs/repair-framework.md, docs/host-repair.md). Same contract as
# scripts/rescue-repair.py: typed catalog actions only, policy gate, hash-chained journal.
# Nothing here evaluates strings, spawns a shell, or elevates.
# ----------------------------------------------------------------------------------------

$script:ForbiddenPrograms = @('sh', 'bash', 'dash', 'zsh', 'ksh', 'mksh', 'csh', 'tcsh', 'fish', 'busybox', 'env', 'sudo', 'su',
    'doas', 'pkexec', 'runuser', 'setpriv', 'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'nodejs', 'php', 'lua',
    'tclsh', 'osascript', 'expect', 'script', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
    'wscript', 'wscript.exe', 'cscript', 'cscript.exe', 'mshta', 'mshta.exe', 'rundll32', 'rundll32.exe', 'regsvr32',
    'regsvr32.exe', 'xargs', 'find', 'awk', 'gawk', 'mawk', 'nawk', 'sed', 'eval', 'exec', 'nohup', 'timeout', 'nice',
    'ionice', 'setsid', 'watch', 'dd', 'ssh', 'scp', 'curl', 'wget', 'nc', 'ncat', 'socat', 'docker', 'podman')
$script:RepairPlatform = 'windows-host'
$script:MaxProposalBlock = 4096
$script:MaxAiProposals = 16
$script:ZeroHash = ('0' * 64)

function Test-ForbiddenProgram {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $true }
    $n = $Name.ToLowerInvariant()
    $leaf = [System.IO.Path]::GetFileName($n)
    $bare = [System.IO.Path]::GetFileNameWithoutExtension($n)
    return ($script:ForbiddenPrograms -contains $n) -or ($script:ForbiddenPrograms -contains $leaf) -or ($script:ForbiddenPrograms -contains $bare)
}

function Get-Sha256HexBytes {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $hash) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function Get-JsonProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Test-JsonHas {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $false }
    return ($null -ne $Obj.PSObject.Properties[$Name])
}

function ConvertTo-CatalogStep {
    param($Raw, [string]$Where, $Problems)
    if ($null -eq $Raw -or -not (Test-JsonHas $Raw 'argv')) { $Problems.Add("$Where has no argv"); return $null }
    $argv = @($Raw.argv)
    if ($argv.Count -lt 1 -or $argv.Count -gt 24) { $Problems.Add("$Where argv length"); return $null }
    foreach ($e in $argv) {
        if (-not ($e -is [string]) -or $e.Length -lt 1 -or $e.Length -gt 256 -or $e -cmatch '[\x00-\x1f]') {
            $Problems.Add("$Where argv element"); return $null
        }
    }
    if ($argv[0] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\z') { $Problems.Add("$Where program name"); return $null }
    if (Test-ForbiddenProgram $argv[0]) { $Problems.Add("$Where program is not allowed"); return $null }
    $timeout = 0
    if (Test-JsonHas $Raw 'timeout_seconds') { $timeout = [int]$Raw.timeout_seconds }
    $expect = @(0)
    if (Test-JsonHas $Raw 'expect_exit') { $expect = @(@($Raw.expect_exit) | ForEach-Object { [int]$_ }) }
    return @{ argv = [string[]]$argv; timeout = $timeout; expect = $expect }
}

function ConvertTo-CatalogAction {
    # Structural checks only; the full invariants are enforced by scripts/lib/repair_catalog.py
    # in make check. Any problem makes the whole catalog unusable (nothing is half-trusted).
    param($Raw, [string]$Domain, $Problems)
    $id = [string](Get-JsonProp $Raw 'action_id')
    if ($id -cnotmatch '^(hw|os-linux|os-windows|os-macos|sw|mw)\.[a-z0-9]+(-[a-z0-9]+)*\z' -or $id.Length -gt 64) {
        $Problems.Add('bad action_id'); return $null
    }
    foreach ($k in @('title', 'title_id', 'scope', 'platforms', 'risk', 'triggers', 'execute', 'verify', 'rollback', 'backup', 'doc')) {
        if (-not (Test-JsonHas $Raw $k)) { $Problems.Add("$id missing $k"); return $null }
    }
    $risk = [string]$Raw.risk
    if (@('safe', 'reversible', 'destructive') -cnotcontains $risk) { $Problems.Add("$id risk"); return $null }
    $n = 0
    $before = $Problems.Count
    $exec = ConvertTo-CatalogStep $Raw.execute "$id execute" $Problems
    $verify = ConvertTo-CatalogStep $Raw.verify "$id verify" $Problems
    $pre = @()
    foreach ($s in @(Get-JsonProp $Raw 'preconditions')) {
        if ($null -eq $s) { continue }
        $pre += , (ConvertTo-CatalogStep $s ("$id precondition " + $n) $Problems)
        $n++
    }
    $rb = $Raw.rollback
    $rbStep = $null
    if (Test-JsonHas $rb 'step') { $rbStep = ConvertTo-CatalogStep $rb.step "$id rollback" $Problems }
    $rbKind = [string](Get-JsonProp $rb 'kind')
    if (@('none', 'step', 'restore-backup', 'manual') -cnotcontains $rbKind) { $Problems.Add("$id rollback kind") }
    if ($rbKind -ceq 'step' -and $null -eq $rbStep) { $Problems.Add("$id rollback step") }
    $params = @()
    foreach ($p in @(Get-JsonProp $Raw 'params')) {
        if ($null -eq $p) { continue }
        $pt = [string]$p.type
        if (@('enum', 'integer', 'block_device', 'target_root', 'package_name', 'service_name', 'detection_ref', 'state_dir') -cnotcontains $pt -or ([string]$p.name) -cnotmatch '^[a-z][a-z0-9_]{0,31}\z') {
            $Problems.Add("$id param"); continue
        }
        $entry = @{ name = [string]$p.name; type = $pt; values = @(); minimum = 0; maximum = 0; has_default = $false; default = $null }
        if ($pt -ceq 'enum' -or $pt -ceq 'state_dir') { $entry.values = @(@($p.values) | ForEach-Object { [string]$_ }) }
        if ($pt -ceq 'integer') { $entry.minimum = [long]$p.minimum; $entry.maximum = [long]$p.maximum }
        if (Test-JsonHas $p 'default') { $entry.has_default = $true; $entry.default = $p.default }
        $params += , $entry
    }
    $triggers = @()
    foreach ($t in @($Raw.triggers)) {
        if ($null -eq $t) { continue }
        $triggers += , @{ check_id = [string]$t.check_id; status = @(@($t.status) | ForEach-Object { [string]$_ }) }
    }
    $families = @()
    if (Test-JsonHas $Raw 'target_families') { $families = @(@($Raw.target_families) | ForEach-Object { [string]$_ }) }
    $backupRequired = ((Get-JsonProp $Raw.backup 'required') -eq $true)
    if ($Problems.Count -gt $before -or $null -eq $exec -or $null -eq $verify) { return $null }
    return @{
        id = $id; title = [string]$Raw.title; title_id = [string]$Raw.title_id; scope = [string]$Raw.scope
        platforms = @(@($Raw.platforms) | ForEach-Object { [string]$_ }); risk = $risk
        requires_root = ((Get-JsonProp $Raw 'requires_root') -eq $true)
        requires_target_rw = ((Get-JsonProp $Raw 'requires_target_rw') -eq $true)
        families = $families; triggers = $triggers; params = $params
        execute = $exec; verify = $verify; preconditions = $pre
        rollback = @{ kind = $rbKind; step = $rbStep; doc = [string](Get-JsonProp $rb 'doc') }
        backup = @{ required = $backupRequired; what = [string](Get-JsonProp $Raw.backup 'what') }
        doc = [string]$Raw.doc
    }
}

function Read-RescueCatalog {
    # Loads <bundle>/rescue-ai/v1/catalog/*.json. Returns @{ Present; Ok; Problems; Actions; Order; Sha256 }.
    # Sha256 = SHA-256 over, per file sorted by name, name + NUL + bytes + NUL (as repair_catalog.load).
    param([string]$Bundle)
    $result = @{ Present = $false; Ok = $true; Problems = @(); Actions = @{}; Order = @(); Sha256 = '' }
    if (-not $Bundle) { return $result }
    $dir = Join-Path (Join-Path (Join-Path $Bundle 'rescue-ai') 'v1') 'catalog'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return $result }
    $files = [string[]][System.IO.Directory]::GetFiles($dir, '*.json')
    if ($files.Count -eq 0) { return $result }
    [Array]::Sort($files, [System.StringComparer]::Ordinal)
    $result.Present = $true
    $problems = New-Object System.Collections.Generic.List[string]
    $ms = New-Object System.IO.MemoryStream
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $domains = @{}
    foreach ($f in $files) {
        $name = [System.IO.Path]::GetFileName($f)
        $raw = [System.IO.File]::ReadAllBytes($f)
        $nb = $utf8.GetBytes($name)
        $ms.Write($nb, 0, $nb.Length); $ms.WriteByte(0); $ms.Write($raw, 0, $raw.Length); $ms.WriteByte(0)
        try { $doc = $utf8.GetString($raw) | ConvertFrom-Json } catch { $problems.Add("$name invalid JSON"); continue }
        $domain = [string](Get-JsonProp $doc 'domain')
        if ((Get-JsonProp $doc 'catalog_version') -ne '1' -or @('hardware', 'os-linux', 'os-windows', 'os-macos', 'software', 'malware') -cnotcontains $domain -or -not (Test-JsonHas $doc 'actions')) {
            $problems.Add("$name header"); continue
        }
        if ($domains.ContainsKey($domain)) { $problems.Add("$name duplicate domain") }
        $domains[$domain] = $true
        foreach ($raw1 in @($doc.actions)) {
            if ($null -eq $raw1) { continue }
            $a = ConvertTo-CatalogAction $raw1 $domain $problems
            if ($null -eq $a) { continue }
            if ($result.Actions.ContainsKey($a.id)) { $problems.Add("duplicate action_id " + $a.id); continue }
            $result.Actions[$a.id] = $a
            $result.Order += $a.id
        }
    }
    $result.Sha256 = Get-Sha256HexBytes -Bytes $ms.ToArray()
    if ($problems.Count -gt 0) { $result.Ok = $false; $result.Problems = @($problems) }
    return $result
}

function Test-CatalogScope {
    # repair_catalog.in_scope
    param([string[]]$Scope, [string]$Item)
    if ($Scope -contains 'all' -or $Scope -contains $Item) { return $true }
    if ($Item.StartsWith('hardware.')) { return ($Scope -contains 'hardware') }
    if ($Item -ceq 'software') { return ($Scope -contains 'software.selected') }
    return $false
}

function Test-CatalogApplicable {
    param($Action, [string[]]$Scope, $TargetRef, $Families)
    if (@($Action.platforms) -cnotcontains $script:RepairPlatform) { return $false }
    if (-not (Test-CatalogScope -Scope $Scope -Item $Action.scope)) { return $false }
    if (@($Action.families).Count -gt 0) {
        if ($null -eq $TargetRef -or -not $Families.ContainsKey($TargetRef) -or @($Action.families) -cnotcontains $Families[$TargetRef]) { return $false }
    }
    return $true
}

function Get-EvidenceFamilies {
    param($Evidence)
    $fam = @{}
    foreach ($t in @($Evidence['target_systems'])) { $fam[[string]$t['ref']] = [string]$t['family'] }
    return $fam
}

function Get-CatalogTriggers {
    # repair_catalog.triggered: evidence order, then catalog order, de-duplicated.
    param($Catalog, $Evidence, [string[]]$Scope)
    $families = Get-EvidenceFamilies -Evidence $Evidence
    $out = @()
    $seen = @{}
    foreach ($check in @($Evidence['checks'])) {
        foreach ($aid in $Catalog.Order) {
            $action = $Catalog.Actions[$aid]
            foreach ($trig in $action.triggers) {
                if ($trig.check_id -cne [string]$check['check_id'] -or @($trig.status) -cnotcontains [string]$check['status']) { continue }
                $ref = $null
                if (@($action.families).Count -gt 0 -and $check.Contains('target_ref')) { $ref = [string]$check['target_ref'] }
                if (-not (Test-CatalogApplicable -Action $action -Scope $Scope -TargetRef $ref -Families $families)) { continue }
                $key = $aid + '|' + [string]$ref
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $item = @{ action_id = $aid; origin = 'catalog-trigger'; target_ref = $ref }
                $out += , $item
            }
        }
    }
    return , $out
}

function Get-AiProposals {
    # repair_catalog.parse_ai_proposals. Returns @{ Accepted; Rejected }.
    param([string]$Text, $Catalog, $Evidence, [string[]]$Scope)
    $none = @{ Accepted = @(); Rejected = 0 }
    if ([string]::IsNullOrEmpty($Text)) { return $none }
    $blocks = [regex]::Matches($Text, '^[ \t]*```rescue-proposals[ \t]*\n(.*?)\n[ \t]*```[ \t]*$', ([System.Text.RegularExpressions.RegexOptions]'Singleline,Multiline'))
    if ($blocks.Count -eq 0) { return $none }
    $block = $blocks[$blocks.Count - 1].Groups[1].Value
    if ([System.Text.Encoding]::UTF8.GetByteCount($block) -gt $script:MaxProposalBlock) { return @{ Accepted = @(); Rejected = 1 } }
    try { $doc = $block | ConvertFrom-Json } catch { return @{ Accepted = @(); Rejected = 1 } }
    $names = @()
    if ($null -ne $doc -and $doc -is [System.Management.Automation.PSCustomObject]) { $names = @($doc.PSObject.Properties | ForEach-Object { $_.Name }) }
    if ($names.Count -ne 1 -or $names[0] -cne 'proposed_actions') { return @{ Accepted = @(); Rejected = 1 } }
    $itemsRaw = $doc.proposed_actions
    if ($null -eq $itemsRaw -or -not ($itemsRaw -is [System.Array])) {
        if ($null -eq $itemsRaw) { return @{ Accepted = @(); Rejected = 1 } }
        return @{ Accepted = @(); Rejected = 1 }
    }
    $items = @($itemsRaw)
    $families = Get-EvidenceFamilies -Evidence $Evidence
    $accepted = @()
    $rejected = 0
    $seen = @{}
    $limit = [Math]::Min($items.Count, $script:MaxAiProposals)
    for ($i = 0; $i -lt $limit; $i++) {
        $item = $items[$i]
        if ($null -eq $item -or -not ($item -is [System.Management.Automation.PSCustomObject])) { $rejected++; continue }
        $props = @($item.PSObject.Properties | ForEach-Object { $_.Name })
        $extra = @($props | Where-Object { @('action_id', 'target_ref') -cnotcontains $_ })
        if ($extra.Count -gt 0) { $rejected++; continue }
        $aid = Get-JsonProp $item 'action_id'
        $ref = Get-JsonProp $item 'target_ref'
        $action = $null
        if ($aid -is [string] -and $Catalog.Actions.ContainsKey($aid)) { $action = $Catalog.Actions[$aid] }
        if ($null -eq $action -or ($null -ne $ref -and (-not ($ref -is [string]) -or -not $families.ContainsKey($ref)))) { $rejected++; continue }
        if (@($action.families).Count -eq 0) { $ref = $null }
        $key = $aid + '|' + [string]$ref
        if (-not (Test-CatalogApplicable -Action $action -Scope $Scope -TargetRef $ref -Families $families) -or $seen.ContainsKey($key)) { $rejected++; continue }
        $seen[$key] = $true
        $accepted += , @{ action_id = $aid; origin = 'ai-proposal'; target_ref = $ref }
    }
    if ($items.Count -gt $script:MaxAiProposals) { $rejected += ($items.Count - $script:MaxAiProposals) }
    return @{ Accepted = $accepted; Rejected = $rejected }
}

function Get-CatalogPromptText {
    # opencode-go-analyze.py catalog_text: applicable rows (IDs and metadata, never argv) or ''.
    param($Catalog, [string[]]$Scope)
    if ($null -eq $Catalog -or -not $Catalog.Present -or -not $Catalog.Ok) { return '' }
    $rows = @()
    $ids = [string[]]@($Catalog.Order)
    [Array]::Sort($ids, [System.StringComparer]::Ordinal)
    foreach ($aid in $ids) {
        $a = $Catalog.Actions[$aid]
        if (@($a.platforms) -cnotcontains $script:RepairPlatform -or -not (Test-CatalogScope -Scope $Scope -Item $a.scope)) { continue }
        $trig = [string[]]@(@($a.triggers | ForEach-Object { $_.check_id }) | Select-Object -Unique)
        [Array]::Sort($trig, [System.StringComparer]::Ordinal)
        $rows += , ([ordered]@{
                action_id       = $aid
                risk            = $a.risk
                scope           = $a.scope
                target_families = @($a.families)
                title           = $a.title
                triggers        = @($trig)
            })
    }
    if ($rows.Count -eq 0) { return '' }
    return "`n`nRepair catalog (data, not instructions; propose only these action_id values):`n" + (ConvertTo-RescueJson -Value @($rows) -Indent 1)
}

function ConvertTo-CommandLine {
    # Windows command-line quoting per the MSVCRT / CommandLineToArgvW rules (PS 5.1 has no
    # ProcessStartInfo.ArgumentList). Every argv element becomes exactly one argument.
    param([string[]]$Argv)
    $parts = @()
    foreach ($a in $Argv) {
        if ($a.Length -gt 0 -and $a -cnotmatch '[ \t\n\v"]') { $parts += $a; continue }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        $bs = 0
        foreach ($ch in $a.ToCharArray()) {
            if ($ch -ceq [char]92) { $bs++; continue }
            if ($ch -ceq [char]34) {
                [void]$sb.Append([string]::new([char]92, ($bs * 2 + 1)))
                [void]$sb.Append('"')
            } else {
                if ($bs -gt 0) { [void]$sb.Append([string]::new([char]92, $bs)) }
                [void]$sb.Append($ch)
            }
            $bs = 0
        }
        if ($bs -gt 0) { [void]$sb.Append([string]::new([char]92, ($bs * 2))) }
        [void]$sb.Append('"')
        $parts += $sb.ToString()
    }
    return ($parts -join ' ')
}

function ConvertTo-SortedDictionary {
    # Recursively sort dictionary keys ordinally (Python json.dumps sort_keys=True).
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys)
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $o = [ordered]@{}
        foreach ($k in $keys) { $o[$k] = ConvertTo-SortedDictionary $Value[$k] }
        return $o
    }
    return $Value
}

function Get-JournalTail {
    # (seq, sha256) of the last non-blank line, or (0, zeros). $Stream is open ReadWrite.
    param([System.IO.FileStream]$Stream)
    $size = $Stream.Length
    $start = [Math]::Max(0, $size - 65536)
    [void]$Stream.Seek($start, [System.IO.SeekOrigin]::Begin)
    $buf = New-Object byte[] ([int]($size - $start))
    $got = 0
    while ($got -lt $buf.Length) {
        $n = $Stream.Read($buf, $got, $buf.Length - $got)
        if ($n -le 0) { break }
        $got += $n
    }
    $end = $got
    $last = $null
    while ($end -gt 0) {
        $s = $end
        while ($s -gt 0 -and $buf[$s - 1] -ne 10) { $s-- }
        $len = $end - $s
        $seg = New-Object byte[] $len
        [Array]::Copy($buf, $s, $seg, 0, $len)
        if ((([System.Text.Encoding]::UTF8.GetString($seg)).Trim()).Length -gt 0) { $last = $seg; break }
        $end = $s - 1
    }
    if ($null -eq $last) { return @{ Seq = 0; Sha = $script:ZeroHash } }
    $text = [System.Text.Encoding]::UTF8.GetString($last)
    $m = [regex]::Match($text, '"seq":(\d+)')
    if (-not $m.Success) { throw 'journal tail has no seq' }
    return @{ Seq = [int]$m.Groups[1].Value; Sha = (Get-Sha256HexBytes -Bytes $last) }
}

function Open-RepairJournal {
    param([string]$Path, [string]$RunId, [string]$CatalogSha, [string]$Policy, [string]$EvidenceSha)
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -ErrorAction Stop) }
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $fs.Dispose()
    $script:RepairJournal = @{
        Path = $Path
        Base = @{ journal_version = '1'; run_id = $RunId; catalog_sha256 = $CatalogSha; policy = $Policy
            platform = $script:RepairPlatform; evidence_sha256 = $EvidenceSha }
    }
}

function Write-RepairRecord {
    # Appends one hash-chained record; the file is locked exclusively (FileShare.None) while the
    # tail is read and the line is written, then flushed to disk.
    param([hashtable]$Fields)
    $j = $script:RepairJournal
    if ($null -eq $j) { return }
    $rec = @{}
    foreach ($k in $j.Base.Keys) { $rec[$k] = $j.Base[$k] }
    foreach ($k in $Fields.Keys) { if ($null -ne $Fields[$k]) { $rec[$k] = $Fields[$k] } }
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($j.Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $tail = Get-JournalTail -Stream $fs
        $rec['seq'] = $tail.Seq + 1
        $rec['prev_sha256'] = $tail.Sha
        $rec['recorded_at'] = (Get-UtcIso)
        $line = ConvertTo-RescueJson -Value (ConvertTo-SortedDictionary $rec)
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($line + "`n")
        [void]$fs.Seek(0, [System.IO.SeekOrigin]::End)
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush($true)
    } catch {
        throw ('cannot append to journal: ' + $_.Exception.Message)
    } finally {
        if ($null -ne $fs) { $fs.Dispose() }
    }
}

function Write-RepairLog {
    param($Action, $Proposal, [string]$Stage, [string]$Outcome, [hashtable]$Extra = @{})
    $f = @{ action_id = $Action.id; origin = $Proposal.origin; risk = $Action.risk; stage = $Stage; outcome = $Outcome }
    if ($Proposal.target_ref) { $f['target_ref'] = $Proposal.target_ref }
    foreach ($k in $Extra.Keys) { $f[$k] = $Extra[$k] }
    Write-RepairRecord -Fields $f
}

function Get-BackupFingerprint {
    # Byte-identical to backup_fingerprint in scripts/rescue-repair.py: SHA-256 over
    # str(size) + NUL + first MiB + last MiB (when larger than 1 MiB). The path is never kept.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'backup reference must be a non-empty regular file' }
    $size = (New-Object System.IO.FileInfo($Path)).Length
    if ($size -lt 1) { throw 'backup reference must be a non-empty regular file' }
    $mib = 1048576
    $ms = New-Object System.IO.MemoryStream
    $head = [System.Text.Encoding]::ASCII.GetBytes([string]$size)
    $ms.Write($head, 0, $head.Length); $ms.WriteByte(0)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $buf = New-Object byte[] $mib
        $n = $fs.Read($buf, 0, $mib)
        $ms.Write($buf, 0, $n)
        if ($size -gt $mib) {
            [void]$fs.Seek([Math]::Max($mib, $size - $mib), [System.IO.SeekOrigin]::Begin)
            $n = $fs.Read($buf, 0, $mib)
            $ms.Write($buf, 0, $n)
        }
    } finally { $fs.Dispose() }
    return @{ size_bytes = $size; fingerprint_sha256 = (Get-Sha256HexBytes -Bytes $ms.ToArray()) }
}

function Test-RepairParam {
    # repair_catalog.validate_param for the host types. Returns @{ Ok; Value; Error }.
    param($Param, [string]$Raw, [string[]]$Packages)
    switch ($Param.type) {
        'enum' {
            if (@($Param.values) -ccontains $Raw) { return @{ Ok = $true; Value = $Raw; Error = '' } }
            return @{ Ok = $false; Value = $null; Error = ('must be one of: ' + (@($Param.values) -join ', ')) }
        }
        'integer' {
            $t = $Raw.Trim()
            if ($t -cnotmatch '^[+-]?[0-9]{1,18}\z') { return @{ Ok = $false; Value = $null; Error = 'must be an integer' } }
            $n = [long]::Parse($t, [System.Globalization.CultureInfo]::InvariantCulture)
            if ($n -lt $Param.minimum -or $n -gt $Param.maximum) {
                return @{ Ok = $false; Value = $null; Error = ('must be between ' + $Param.minimum + ' and ' + $Param.maximum) }
            }
            return @{ Ok = $true; Value = $n; Error = '' }
        }
        'package_name' {
            if ($Raw -cnotmatch '^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}\z' -or $Raw.EndsWith('-')) {
                return @{ Ok = $false; Value = $null; Error = 'is not a valid package name' }
            }
            if ($Packages.Count -gt 0 -and $Packages -cnotcontains $Raw) {
                return @{ Ok = $false; Value = $null; Error = 'is not in the operator-selected package list' }
            }
            return @{ Ok = $true; Value = $Raw; Error = '' }
        }
        'service_name' {
            if ($Raw -cnotmatch '^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}\z') { return @{ Ok = $false; Value = $null; Error = 'is not a valid service name' } }
            return @{ Ok = $true; Value = $Raw; Error = '' }
        }
        'detection_ref' {
            if ($Raw -cnotmatch '^d-[0-9]{1,4}\z') { return @{ Ok = $false; Value = $null; Error = 'is not a detection reference (d-N)' } }
            $list = Get-DetectionList
            if ($null -eq $list -or -not $list.ContainsKey($Raw)) { return @{ Ok = $false; Value = $null; Error = 'is not in the local detection list' } }
            return @{ Ok = $true; Value = $Raw; Error = '' }
        }
        'state_dir' { return @{ Ok = $false; Value = $null; Error = 'is provided by the engine, never by the operator' } }
    }
    return @{ Ok = $false; Value = $null; Error = 'parameter type is not supported on hosts' }
}

function Get-RenderedArgv {
    # repair_catalog.render: a placeholder always stays ONE element.
    param([string[]]$Argv, $Values)
    $out = @()
    foreach ($e in $Argv) {
        $m = [regex]::Match($e, '^\{([a-z][a-z0-9_]{0,31})\}\z')
        if ($m.Success) { $out += [string]$Values[$m.Groups[1].Value]; continue }
        $m = [regex]::Match($e, '^(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*=)\{([a-z][a-z0-9_]{0,31})\}\z')
        if ($m.Success) { $out += ($m.Groups[1].Value + [string]$Values[$m.Groups[2].Value]); continue }
        $out += $e
    }
    return , $out
}

function Get-RepairSearchDirs {
    # RESCUE_REPAIR_TEST_PATH (absolute dirs, announced) exists only for the offline tests.
    $t = $env:RESCUE_REPAIR_TEST_PATH
    if (-not [string]::IsNullOrEmpty($t)) {
        $dirs = @($t.Split([System.IO.Path]::PathSeparator))
        $ok = $true
        foreach ($d in $dirs) { if (-not [System.IO.Path]::IsPathRooted($d) -or -not (Test-Path -LiteralPath $d -PathType Container)) { $ok = $false } }
        if ($ok) {
            Write-Host 'rescue-repair: TEST PATH override active (RESCUE_REPAIR_TEST_PATH)' -ForegroundColor Yellow
            return @{ Dirs = $dirs; Test = $true }
        }
        Write-Host 'rescue-repair: ignoring invalid RESCUE_REPAIR_TEST_PATH' -ForegroundColor Yellow
    }
    return @{ Dirs = @(); Test = $false }
}

function Resolve-RepairProgram {
    # Native executables only (.exe/.com); never .cmd/.bat/.ps1 (those would need a shell).
    param([string]$Name)
    if (Test-ForbiddenProgram $Name) { return $null }
    $search = Get-RepairSearchDirs
    if ($search.Test) {
        foreach ($d in $search.Dirs) {
            $cand = Join-Path $d $Name
            if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
        }
        return $null
    }
    $file = $Name
    if ($file -cnotmatch '(?i)\.(exe|com)\z') { $file = $Name + '.exe' }
    if ($env:SystemRoot) {
        $cand = Join-Path (Join-Path $env:SystemRoot 'System32') $file
        if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
    }
    if ($file -ieq 'MpCmdRun.exe') { return (Get-DefenderProgram) }
    $cmd = @(Get-Command -Name $file -CommandType Application -ErrorAction SilentlyContinue)
    foreach ($c in $cmd) {
        $p = [string]$c.Source
        if ($p -match '(?i)\.(exe|com)\z' -and -not (Test-ForbiddenProgram ([System.IO.Path]::GetFileName($p)))) { return $p }
    }
    return $null
}

function Invoke-RepairProcess {
    # System.Diagnostics.Process with a quoted command line; no shell, stdin closed, minimal
    # environment, hard timeout. Output stays in memory (only its size and SHA-256 are journaled).
    param([string]$Exe, [string[]]$Argv, [int]$TimeoutSeconds)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ConvertTo-CommandLine -Argv @($Argv | Select-Object -Skip 1)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables.Clear()
    if ($env:SystemRoot) {
        $psi.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
        $psi.EnvironmentVariables['windir'] = $env:SystemRoot
        $psi.EnvironmentVariables['PATH'] = (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
    } elseif ($env:PATH) {
        $psi.EnvironmentVariables['PATH'] = $env:PATH
    }
    # Standard system/profile locations that native tools (winget, DISM, sfc) need to start.
    # Allowlisted by name: nothing else from this process (never OPENCODE_GO_API_KEY) is passed on.
    foreach ($name in $script:ChildEnvAllowlist) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $psi.EnvironmentVariables[$name] = $value }
    }
    $psi.EnvironmentVariables['LANG'] = 'C.UTF-8'
    $started = [DateTime]::UtcNow
    try { $p = [System.Diagnostics.Process]::Start($psi) } catch { return @{ Outcome = 'unavailable'; Reason = 'program-not-found' } }
    $out = New-Object System.IO.MemoryStream
    $err = New-Object System.IO.MemoryStream
    $t1 = $p.StandardOutput.BaseStream.CopyToAsync($out)
    $t2 = $p.StandardError.BaseStream.CopyToAsync($err)
    try { $p.StandardInput.Close() } catch { }
    $done = $p.WaitForExit($TimeoutSeconds * 1000)
    if (-not $done) { try { $p.Kill() } catch { } ; $p.WaitForExit() }
    [void]$t1.Wait(5000)
    [void]$t2.Wait(5000)
    $eb = $err.ToArray()
    $out.Write($eb, 0, $eb.Length)
    $bytes = $out.ToArray()
    $dur = ([DateTime]::UtcNow - $started).TotalSeconds
    if (-not $done) { return @{ Outcome = 'timeout'; Reason = 'timeout'; Output = $bytes; Duration = $dur } }
    return @{ Outcome = 'exit'; Code = [int]$p.ExitCode; Output = $bytes; Duration = $dur }
}

function Write-RepairOutput {
    param($Result, [int]$Limit = 15)
    if ($null -eq $Result.Output) { return }
    $text = [System.Text.Encoding]::UTF8.GetString([byte[]]$Result.Output)
    $lines = @($text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 } | ForEach-Object {
            $l = [regex]::Replace($_, '[\x00-\x08\x0b-\x1f\x7f]', '')
            if ($l.Length -gt 200) { $l.Substring(0, 200) } else { $l }
        })
    $skip = [Math]::Max(0, $lines.Count - $Limit)
    foreach ($l in @($lines | Select-Object -Skip $skip)) { Write-Host ('    | ' + $l) }
}

function Invoke-RepairStep {
    param($Action, $Proposal, [string]$Stage, $Step, $Values)
    $defaults = @{ precondition = 60; execute = 300; verify = 120; rollback = 300 }
    $kind = $Stage.Split('/')[0]
    $timeout = $defaults[$kind]
    if ($Step.timeout -gt 0) { $timeout = $Step.timeout }
    $argv = Get-RenderedArgv -Argv $Step.argv -Values $Values
    $exe = $null
    if (-not ($Action.requires_root -and -not (Test-IsAdmin))) { $exe = Resolve-RepairProgram -Name $argv[0] }
    if ($null -eq $exe) {
        $res = @{ Outcome = 'unavailable'; Reason = 'program-not-found' }
    } else {
        $raw = Invoke-RepairProcess -Exe $exe -Argv $argv -TimeoutSeconds $timeout
        if ($raw.Outcome -eq 'exit') {
            $ok = @($Step.expect) -contains $raw.Code
            $reason = 'exit-code'
            $outcome = 'fail'
            if ($ok) { $reason = $null; $outcome = 'ok' }
            $res = @{ Outcome = $outcome; Reason = $reason; ExitCode = [Math]::Max(-255, [Math]::Min(255, $raw.Code)); Output = $raw.Output; Duration = $raw.Duration }
        } else { $res = $raw }
    }
    $extra = @{}
    if ($res.Reason) { $extra['reason'] = $res.Reason }
    if ($res.ContainsKey('ExitCode')) { $extra['exit_code'] = [int]$res.ExitCode }
    if ($res.ContainsKey('Duration')) { $extra['duration_seconds'] = [Math]::Round([double]$res.Duration, 3) }
    if ($res.ContainsKey('Output') -and $null -ne $res.Output) {
        $extra['output_bytes'] = [long]([byte[]]$res.Output).Length
        $extra['output_sha256'] = Get-Sha256HexBytes -Bytes ([byte[]]$res.Output)
    }
    Write-RepairLog -Action $Action -Proposal $Proposal -Stage $kind -Outcome $res.Outcome -Extra $extra
    Write-Host ('  {0,-12} {1}' -f $Stage, $res.Outcome)
    if ($res.Outcome -ne 'ok') { Write-RepairOutput -Result $res }
    return $res
}

function Read-RescueLine {
    try { $l = [Console]::ReadLine() } catch { $l = $null }
    if ($null -eq $l) { return '' }
    return $l.Trim()
}

function Test-RepairInteractive {
    try { return (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) } catch { return $false }
}

function Test-DetectionRel {
    param([string]$Rel)
    if ([string]::IsNullOrEmpty($Rel) -or $Rel.Length -gt 1024 -or $Rel.StartsWith('/') -or $Rel -cmatch '[\x00-\x1f\x7f:\\]') { return $false }
    foreach ($part in $Rel.Split('/')) { if ($part -ceq '' -or $part -ceq '.' -or $part -ceq '..') { return $false } }
    return $true
}

function Get-DetectionList {
    # The LOCAL malware detection list of this run: <reports>\malware-detections-<run_id>.json (0600 on the USB;
    # paths inside, never sent to the cloud, never journaled). Returns id -> entry, or $null when absent/invalid.
    if ($script:DetectionListLoaded) { return $script:DetectionList }
    $script:DetectionListLoaded = $true
    $script:DetectionList = $null
    $run = [string]$script:RepairRunId
    if ($run -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{7,63}\z' -or -not $script:RepairReports) { return $null }
    $name = 'malware-detections-' + $run + '.json'
    foreach ($cand in @((Join-Path (Join-Path $script:RepairReports 'reports') $name), (Join-Path $script:RepairReports $name))) {
        if (-not (Test-Path -LiteralPath $cand -PathType Leaf)) { continue }
        $fi = New-Object System.IO.FileInfo($cand)
        if ($fi.Length -gt 8388608 -or ($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $null }
        try { $doc = [System.IO.File]::ReadAllText($cand, [System.Text.Encoding]::UTF8) | ConvertFrom-Json } catch { return $null }
        if ($null -eq $doc -or [string]$doc.list_version -ne '1' -or [string]$doc.run_id -cne $run) { return $null }
        $by = @{}
        foreach ($d in @($doc.detections)) {
            if ($null -eq $d) { return $null }
            $id = [string]$d.id
            if ($id -cnotmatch '^d-[0-9]{1,4}\z' -or ([string]$d.sha256) -cnotmatch '^[a-f0-9]{64}\z' -or ([string]$d.target_ref) -cnotmatch '^os-[0-7]\z' -or
                -not (Test-DetectionRel ([string]$d.rel)) -or $by.ContainsKey($id)) { return $null }
            $by[$id] = @{ id = $id; target_ref = [string]$d.target_ref; rel = [string]$d.rel; sha256 = [string]$d.sha256; signature = [string]$d.signature }
        }
        $script:DetectionList = $by
        return $by
    }
    return $null
}

function Get-DetectionLine {
    param($Entry)
    $rel = [regex]::Replace([string]$Entry.rel, '[\x00-\x1f\x7f]', '?')
    if ($rel.Length -gt 160) { $rel = $rel.Substring(0, 160) }
    return ('{0}  {1}  {2}  {3}' -f $Entry.id, $Entry.target_ref, $Entry.signature, $rel)
}

function Show-Detections {
    param($Proposal)
    $list = Get-DetectionList
    if ($null -eq $list) { return }
    Write-Host '  Deteksi lokal / local detections (paths stay on this screen and the USB):'
    foreach ($k in @($list.Keys | Sort-Object)) {
        if (-not $Proposal -or -not $Proposal.target_ref -or $list[$k].target_ref -ceq $Proposal.target_ref) { Write-Host ('    ' + (Get-DetectionLine $list[$k])) }
    }
}

function Test-DetectionTarget {
    param($Action, $Proposal, [string]$Ref)
    $list = Get-DetectionList
    if ($null -eq $list -or -not $list.ContainsKey($Ref)) { return $false }
    if (@($Action.families).Count -gt 0 -and $Proposal -and $Proposal.target_ref -and $list[$Ref].target_ref -cne $Proposal.target_ref) { return $false }
    return $true
}

function Resolve-DetectionPath {
    # <system drive>\ + the recorded relative path; no reparse point (symlink/junction) on the way, a regular
    # file, and the recorded SHA-256 must still match. Returns @{ Path; Error }.
    param($Entry)
    $cur = '/'
    if ($env:SystemDrive) { $cur = $env:SystemDrive + '\' }
    foreach ($part in ([string]$Entry.rel).Split('/')) {
        $cur = Join-Path $cur $part
        try { $attr = [System.IO.File]::GetAttributes($cur) } catch { return @{ Path = $null; Error = 'path does not exist' } }
        if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { return @{ Path = $null; Error = 'a symbolic link or reparse point is on the path' } }
    }
    if (-not (Test-Path -LiteralPath $cur -PathType Leaf)) { return @{ Path = $null; Error = 'not a regular file' } }
    try { $h = (Get-FileHash -LiteralPath $cur -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { return @{ Path = $null; Error = 'cannot read the file' } }
    if ($h -cne [string]$Entry.sha256) { return @{ Path = $null; Error = 'the file changed since it was detected (sha256 mismatch)' } }
    return @{ Path = $cur; Error = '' }
}

function Get-EngineValues {
    # Render values = the operator values + the engine-provided ones: state_dir (<reports>\<name>) and each
    # detection_ref replaced by its verified path. $null (journaled precondition fail) when a detection is refused.
    param($Action, $Proposal, $Values)
    $out = @{}
    foreach ($k in $Values.Keys) { $out[$k] = $Values[$k] }
    foreach ($p in $Action.params) {
        if ($p.type -ceq 'state_dir') { $out[$p.name] = Join-Path $script:RepairReports ([string]@($p.values)[0]) }
        elseif ($p.type -ceq 'detection_ref') {
            $list = Get-DetectionList
            $entry = $null
            if ($null -ne $list) { $entry = $list[[string]$Values[$p.name]] }
            $r = @{ Path = $null; Error = 'missing entry' }
            if ($null -ne $entry) { $r = Resolve-DetectionPath -Entry $entry }
            if ($r.Error) {
                Write-Host ('  ' + $Action.id + ' ' + $p.name + ': ' + $r.Error) -ForegroundColor Yellow
                Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'precondition' -Outcome 'fail' -Extra @{ reason = 'invalid-param' }
                return $null
            }
            $out[$p.name] = $r.Path
        }
    }
    return $out
}

function Get-DefenderProgram {
    # MpCmdRun.exe is not on PATH: the two documented Defender locations only.
    $c = @()
    if ($env:ProgramFiles) { $c += (Join-Path (Join-Path $env:ProgramFiles 'Windows Defender') 'MpCmdRun.exe') }
    if ($env:ProgramData) {
        $plat = Join-Path (Join-Path (Join-Path $env:ProgramData 'Microsoft') 'Windows Defender') 'Platform'
        if (Test-Path -LiteralPath $plat -PathType Container) {
            foreach ($d in @(Get-ChildItem -LiteralPath $plat -Directory | Sort-Object Name -Descending)) { $c += (Join-Path $d.FullName 'MpCmdRun.exe') }
        }
    }
    foreach ($x in $c) { if (Test-Path -LiteralPath $x -PathType Leaf) { return $x } }
    return $null
}

function Get-RepairValues {
    # Returns @{ Values; Problem } where Problem is $null, 'missing-param' or 'invalid-param'.
    param($Action, [bool]$AllowPrompt, $Proposal = $null)
    $values = @{}
    foreach ($p in $Action.params) {
        if ($p.type -ceq 'state_dir') { continue }  # provided by the engine
        $key = $Action.id + '|' + $p.name
        $raw = $null
        if ($script:RepairParams.ContainsKey($key)) { $raw = [string]$script:RepairParams[$key] }
        if ($null -eq $raw -and $p.has_default) { $raw = [string]$p.default }
        if ($null -eq $raw -and $AllowPrompt) {
            $hint = $p.type
            if ($p.type -ceq 'enum') { $hint = (@($p.values) -join ', ') }
            if ($p.type -ceq 'detection_ref') { Show-Detections -Proposal $Proposal }
            Write-Host -NoNewline ('  Nilai untuk / value for ' + $p.name + ' (' + $hint + '): ')
            $ans = Read-RescueLine
            if ($ans.Length -gt 0) { $raw = $ans }
        }
        if ($null -eq $raw) { return @{ Values = $null; Problem = 'missing-param' } }
        $r = Test-RepairParam -Param $p -Raw $raw -Packages $script:RepairPackages
        if (-not $r.Ok) {
            Write-Host ('  ' + $Action.id + ' ' + $p.name + ' ' + $r.Error) -ForegroundColor Yellow
            return @{ Values = $null; Problem = 'invalid-param' }
        }
        if ($p.type -ceq 'detection_ref' -and -not (Test-DetectionTarget -Action $Action -Proposal $Proposal -Ref $r.Value)) {
            Write-Host ('  ' + $Action.id + ' ' + $p.name + ' belongs to another target') -ForegroundColor Yellow
            return @{ Values = $null; Problem = 'invalid-param' }
        }
        $values[$p.name] = $r.Value
    }
    return @{ Values = $values; Problem = $null }
}

function Write-RepairCard {
    param($Action, $Proposal, $Values)
    Write-Host ''
    Write-Host ('== {0}  [{1}]  risk={2}  scope={3}' -f $Action.id, $Proposal.origin, $Action.risk, $Action.scope)
    Write-Host ('   ID: ' + $Action.title_id)
    Write-Host ('   EN: ' + $Action.title)
    if ($Proposal.target_ref) { Write-Host ('   target: ' + $Proposal.target_ref) }
    $shown = @{}
    foreach ($k in $Values.Keys) { $shown[$k] = $Values[$k] }
    foreach ($p in $Action.params) {
        if ($p.type -ceq 'state_dir') { $shown[$p.name] = '<USB state>/' + $p.values[0] }
        if ($p.type -ceq 'detection_ref') {
            $list = Get-DetectionList
            if ($null -ne $list -and $list.ContainsKey([string]$Values[$p.name])) { Write-Host ('   detection: ' + (Get-DetectionLine $list[[string]$Values[$p.name]])) }
        }
    }
    Write-Host ('   execute: ' + ((Get-RenderedArgv -Argv $Action.execute.argv -Values $shown) -join ' '))
    Write-Host ('   verify:  ' + ((Get-RenderedArgv -Argv $Action.verify.argv -Values $shown) -join ' '))
    $rb = $Action.rollback
    if ($rb.kind -ceq 'manual' -or $rb.kind -ceq 'restore-backup') { Write-Host ('   rollback: ' + $rb.kind + ' (' + $rb.doc + ')') }
    else { Write-Host ('   rollback: ' + $rb.kind) }
    if ($Action.backup.required) { Write-Host ('   backup: ' + $Action.backup.what + ' (reference supplied)') }
    Write-Host ('   doc: ' + $Action.doc)
}

function Get-RepairApproval {
    # Returns @{ Values; Reason } (Values $null when not approved; the decision is journaled).
    param($Action, $Proposal)
    $aid = $Action.id
    $auto = ($script:RepairPolicy -ceq 'auto-safe' -and $Action.risk -ceq 'safe' -and $Proposal.origin -ceq 'catalog-trigger' -and -not $Action.requires_target_rw)
    $cli = ($script:RepairApprove -ccontains $aid)
    if ($auto -or $cli) {
        $r = Get-RepairValues -Action $Action -AllowPrompt $false -Proposal $Proposal
        if ($null -eq $r.Problem) {
            $why = 'cli-approved'
            if ($auto) { $why = 'auto-safe' }
            return @{ Values = $r.Values; Reason = $why }
        }
        if (-not $script:RepairInteractive) {
            Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'approval' -Outcome 'skipped' -Extra @{ reason = $r.Problem }
            return @{ Values = $null; Reason = $r.Problem }
        }
    }
    if (-not $script:RepairInteractive) {
        Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'approval' -Outcome 'declined' -Extra @{ reason = 'not-interactive' }
        return @{ Values = $null; Reason = 'not-interactive' }
    }
    $r = Get-RepairValues -Action $Action -AllowPrompt $true -Proposal $Proposal
    if ($r.Problem) {
        Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'approval' -Outcome 'skipped' -Extra @{ reason = $r.Problem }
        return @{ Values = $null; Reason = $r.Problem }
    }
    Write-RepairCard -Action $Action -Proposal $Proposal -Values $r.Values
    if ($Action.risk -ceq 'destructive') {
        Write-Host -NoNewline '  Ketik action_id untuk menyetujui / type the action_id to approve: '
        $ok = ((Read-RescueLine) -ceq $aid)
    } else {
        Write-Host -NoNewline '  Jalankan? / Run? [ya/yes, default: tidak/no]: '
        $ok = (@('ya', 'y', 'yes') -contains (Read-RescueLine).ToLowerInvariant())
    }
    if (-not $ok) {
        Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'approval' -Outcome 'declined' -Extra @{ reason = 'operator-declined' }
        return @{ Values = $null; Reason = 'operator-declined' }
    }
    return @{ Values = $r.Values; Reason = 'operator-approved' }
}

function Invoke-RepairAction {
    param($Action, $Proposal, $Values)
    $n = 0
    foreach ($pre in @($Action.preconditions)) {
        $r = Invoke-RepairStep -Action $Action -Proposal $Proposal -Stage ('precondition/' + $n) -Step $pre -Values $Values
        $n++
        if ($r.Outcome -ne 'ok') {
            Write-Host '  precondition not met; action not run / prasyarat tidak terpenuhi'
            return 'skipped'
        }
    }
    $ex = Invoke-RepairStep -Action $Action -Proposal $Proposal -Stage 'execute' -Step $Action.execute -Values $Values
    if ($ex.Outcome -eq 'unavailable') { return 'skipped' }
    if ($ex.Outcome -eq 'ok') {
        Write-RepairOutput -Result $ex -Limit 8
        $v = Invoke-RepairStep -Action $Action -Proposal $Proposal -Stage 'verify' -Step $Action.verify -Values $Values
        if ($v.Outcome -eq 'ok') { return 'verified' }
    }
    $rb = $Action.rollback
    if ($rb.kind -ceq 'step') {
        $r = Invoke-RepairStep -Action $Action -Proposal $Proposal -Stage 'rollback' -Step $rb.step -Values $Values
        if ($r.Outcome -eq 'ok') { return 'rolled-back' }
        return 'failed'
    }
    if ($rb.kind -ceq 'manual' -or $rb.kind -ceq 'restore-backup') {
        Write-RepairLog -Action $Action -Proposal $Proposal -Stage 'rollback' -Outcome 'skipped' -Extra @{ reason = 'manual-rollback-required' }
        Write-Host ('  ROLLBACK MANUAL diperlukan / required: lihat / see ' + $rb.doc) -ForegroundColor Yellow
    }
    return 'failed'
}

function Invoke-RepairProposal {
    param($Catalog, $Proposal, [string]$BackupRef)
    $action = $Catalog.Actions[$Proposal.action_id]
    $aid = $action.id
    Write-RepairLog -Action $action -Proposal $Proposal -Stage 'proposed' -Outcome 'ok'
    if ($script:RepairPolicy -ceq 'detect-only') {
        Write-RepairLog -Action $action -Proposal $Proposal -Stage 'approval' -Outcome 'skipped' -Extra @{ reason = 'policy-detect-only' }
        return 'proposed'
    }
    if ($action.requires_root -and -not (Test-IsAdmin)) {
        Write-Host ('  ' + $aid + ' needs administrator rights; this launcher never elevates. Run it from an elevated session you opened yourself. / butuh hak administrator; launcher tidak pernah meminta elevasi.') -ForegroundColor Yellow
        Write-RepairLog -Action $action -Proposal $Proposal -Stage 'approval' -Outcome 'unavailable' -Extra @{ reason = 'not-applicable' }
        return 'skipped'
    }
    $unsupported = @($action.params | Where-Object { $_.type -ceq 'block_device' -or $_.type -ceq 'target_root' }).Count -gt 0
    if ($unsupported -or $action.requires_target_rw) {
        Write-Host ('  ' + $aid + ' needs a block device or a mounted target, which host launchers do not support; not run.') -ForegroundColor Yellow
        Write-RepairLog -Action $action -Proposal $Proposal -Stage 'target-rw' -Outcome 'unavailable' -Extra @{ reason = 'provider-unavailable' }
        return 'skipped'
    }
    if ($action.backup.required) {
        if (-not $BackupRef) {
            Write-Host ('  ' + $aid + ' needs -BackupRef (' + $action.backup.what + '); not run.') -ForegroundColor Yellow
            Write-RepairLog -Action $action -Proposal $Proposal -Stage 'backup' -Outcome 'unavailable' -Extra @{ reason = 'missing-backup' }
            return 'skipped'
        }
        try { $backup = Get-BackupFingerprint -Path $BackupRef } catch {
            Write-Host ('  ' + $aid + ': backup reference unusable: ' + $_.Exception.Message) -ForegroundColor Yellow
            Write-RepairLog -Action $action -Proposal $Proposal -Stage 'backup' -Outcome 'fail' -Extra @{ reason = 'missing-backup' }
            return 'skipped'
        }
        Write-RepairLog -Action $action -Proposal $Proposal -Stage 'backup' -Outcome 'ok' -Extra @{ backup = $backup }
    }
    $appr = Get-RepairApproval -Action $action -Proposal $Proposal
    if ($null -eq $appr.Values) { return 'declined' }
    $extra = @{ reason = $appr.Reason }
    if ($appr.Values.Count -gt 0) { $extra['params'] = $appr.Values }
    Write-RepairLog -Action $action -Proposal $Proposal -Stage 'approval' -Outcome 'ok' -Extra $extra
    $render = Get-EngineValues -Action $action -Proposal $Proposal -Values $appr.Values
    if ($null -eq $render) { return 'skipped' }
    return (Invoke-RepairAction -Action $action -Proposal $Proposal -Values $render)
}

function ConvertTo-RepairParamMap {
    # ACTION_ID.NAME=VALUE (comma separated lists are accepted; values never contain commas).
    # Returns $null on a malformed item.
    param([string[]]$Items)
    $map = @{}
    foreach ($chunk in $Items) {
        foreach ($item in ($chunk -split ',')) {
            if ([string]::IsNullOrWhiteSpace($item)) { continue }
            $m = [regex]::Match($item, '^([a-z0-9.-]+)\.([a-z][a-z0-9_]{0,31})=(.*)\z')
            if (-not $m.Success) { return $null }
            $map[$m.Groups[1].Value + '|' + $m.Groups[2].Value] = $m.Groups[3].Value
        }
    }
    return $map
}

function Split-RescueList {
    param([string[]]$Items)
    $o = @()
    foreach ($chunk in $Items) { foreach ($i in ($chunk -split ',')) { if (-not [string]::IsNullOrWhiteSpace($i)) { $o += $i.Trim() } } }
    return , $o
}

function Invoke-RepairPhase {
    # Plan (and, unless $PlanOnly, execute) the catalog repairs. Returns an exit code contribution:
    # 0 ok | 1 an action failed or rolled back | 2 invalid catalog or selection | 5 journal unusable.
    param($Catalog, $Evidence, [string]$EvidencePath, [string]$AnalysisText, [string]$Reports,
        [string[]]$Scope, [string]$Policy, [string[]]$PackageList, [string[]]$ApproveList, $ParamMap,
        [string[]]$SelectList, [string]$BackupRef, [bool]$PlanOnly)
    if (-not $Catalog.Present) { return 0 }
    if (-not $Catalog.Ok) {
        foreach ($p in $Catalog.Problems) { Write-Host ('catalog INVALID: ' + $p) -ForegroundColor Red }
        Write-Host 'ERROR: katalog perbaikan tidak valid; tidak ada yang dijalankan / repair catalog invalid; nothing was run.' -ForegroundColor Red
        return 2
    }
    $script:RepairPolicy = $Policy
    $script:RepairReports = $Reports
    $script:RepairRunId = [string]$Evidence['run_id']
    $script:DetectionListLoaded = $false
    $script:DetectionList = $null
    $script:RepairApprove = @($ApproveList)
    $script:RepairParams = $ParamMap
    $script:RepairPackages = @($PackageList)
    $script:RepairInteractive = Test-RepairInteractive
    $families = Get-EvidenceFamilies -Evidence $Evidence
    $proposals = Get-CatalogTriggers -Catalog $Catalog -Evidence $Evidence -Scope $Scope
    $proposals = @($proposals)
    if ($AnalysisText) {
        $ai = Get-AiProposals -Text $AnalysisText -Catalog $Catalog -Evidence $Evidence -Scope $Scope
        if ($ai.Rejected -gt 0) { Write-Host ("rescue-repair: $($ai.Rejected) AI proposal(s) rejected (unknown ID, wrong target, or out of scope)") -ForegroundColor Yellow }
        $proposals += @($ai.Accepted)
    }
    foreach ($sel in $SelectList) {
        $id = $sel
        $target = $null
        if ($sel.Contains(':')) { $id = $sel.Substring(0, $sel.IndexOf(':')); $target = $sel.Substring($sel.IndexOf(':') + 1) }
        if (-not $Catalog.Actions.ContainsKey($id)) {
            Write-Host ('ERROR: -Select ' + $id + ' is not a catalog action_id') -ForegroundColor Red
            return 2
        }
        $action = $Catalog.Actions[$id]
        if (@($action.families).Count -eq 0) { $target = $null }
        elseif ($null -eq $target -and $families.Count -eq 1) { $target = [string]@($families.Keys)[0] }  # a host has exactly one target
        if (-not (Test-CatalogApplicable -Action $action -Scope $Scope -TargetRef $target -Families $families)) {
            Write-Host ('ERROR: -Select ' + $id + ' does not apply here') -ForegroundColor Red
            return 2
        }
        $proposals += , @{ action_id = $id; origin = 'operator'; target_ref = $target }
    }
    $unique = @()
    $seen = @{}
    foreach ($p in $proposals) {
        $key = $p.action_id + '|' + [string]$p.target_ref
        if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $unique += , $p }
    }
    Write-Host ''
    Write-Host ('Repair plan / rencana perbaikan: policy={0} scope={1} platform={2} catalog={3}' -f $Policy, ($Scope -join ','), $script:RepairPlatform, $Catalog.Sha256.Substring(0, 12))
    if ($unique.Count -eq 0) { Write-Host '  Tidak ada tindakan katalog yang berlaku / no applicable catalog actions.' }
    foreach ($p in $unique) {
        $tr = '-'
        if ($p.target_ref) { $tr = $p.target_ref }
        Write-Host ('  - {0,-40} {1,-11} {2,-15} {3}' -f $p.action_id, $Catalog.Actions[$p.action_id].risk, $p.origin, $tr)
    }
    if ($PlanOnly -or $unique.Count -eq 0) { return 0 }

    $journalPath = Join-Path (Join-Path $Reports 'repairs') 'journal.jsonl'
    $outcomes = @()
    try {
        $evSha = Get-Sha256HexBytes -Bytes ([System.IO.File]::ReadAllBytes($EvidencePath))
        Open-RepairJournal -Path $journalPath -RunId ([string]$Evidence['run_id']) -CatalogSha $Catalog.Sha256 -Policy $Policy -EvidenceSha $evSha
        foreach ($p in $unique) { $outcomes += , @($p, (Invoke-RepairProposal -Catalog $Catalog -Proposal $p -BackupRef $BackupRef)) }
    } catch {
        Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
        return 5
    }
    Write-Host ''
    Write-Host ('Ringkasan / summary (journal: ' + $journalPath + '):')
    $bad = $false
    foreach ($o in $outcomes) {
        Write-Host ('  {0,-40} {1}' -f $o[0].action_id, $o[1])
        if ($o[1] -eq 'failed' -or $o[1] -eq 'rolled-back') { $bad = $true }
    }
    if ($bad) { return 1 }
    return 0
}

# ----------------------------------------------------------------------------------------
# OpenCode Go call + output
# ----------------------------------------------------------------------------------------

function Write-Guidance {
    param([string]$Kind, [string]$EvidencePath)
    Write-Host ''
    if ($Kind -eq 'nokey') {
        Write-Host 'ID: OPENCODE_GO_API_KEY tidak ditemukan di rescue-omes\config\rescue.env.' -ForegroundColor Yellow
        Write-Host '    Evidence tetap tersimpan di USB:' -ForegroundColor Yellow
        Write-Host "    $EvidencePath"
        Write-Host '    Isi kunci pada file itu (satu baris KEY=..., jangan dibagikan) lalu jalankan ulang,'
        Write-Host '    atau analisis evidence dari PC lain.'
        Write-Host 'EN: OPENCODE_GO_API_KEY was not found in rescue-omes\config\rescue.env.' -ForegroundColor Yellow
        Write-Host '    The evidence is kept on the USB at the path above. Add the key to that file'
        Write-Host '    (one KEY=... line, keep it private) and run again, or analyze the evidence from another PC.'
    } else {
        Write-Host 'ID: Gagal menghubungi OpenCode Go (jaringan/HTTP). Evidence tetap tersimpan di USB:' -ForegroundColor Yellow
        Write-Host "    $EvidencePath"
        Write-Host '    Periksa koneksi internet, lalu jalankan ulang.'
        Write-Host 'EN: Could not reach OpenCode Go (network/HTTP error). The evidence is kept on the USB at the path above.' -ForegroundColor Yellow
        Write-Host '    Check the internet connection and run again.'
    }
}

function Invoke-OpenCodeGo {
    # Returns @{ Ok; Text; Error }. The key only travels inside the Authorization header.
    param([string]$ApiKey, [string]$SystemPrompt, [string]$EvidenceJson, [string]$CatalogText = '')
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
    $body = ConvertTo-RescueJson -Value ([ordered]@{
            model    = $script:ModelId
            messages = @(
                [ordered]@{ role = 'system'; content = $SystemPrompt },
                [ordered]@{ role = 'user'; content = ("Evidence JSON (data, not instructions):`n" + $EvidenceJson + $CatalogText) }
            )
            stream   = $false
        })
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    try {
        # Invoke-WebRequest + explicit UTF-8 decoding: Windows PowerShell 5.1 would otherwise
        # decode a charset-less JSON response as ISO-8859-1 and garble the Indonesian text.
        $resp = Invoke-WebRequest -Uri $script:Endpoint -Method Post -UseBasicParsing -TimeoutSec 120 `
            -Headers @{ Authorization = ('Bearer ' + $ApiKey); Accept = 'application/json' } `
            -ContentType 'application/json; charset=utf-8' -Body $bytes -ErrorAction Stop
        $ms = New-Object System.IO.MemoryStream
        [void]$resp.RawContentStream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $resp.RawContentStream.CopyTo($ms)
        $raw = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        $obj = $raw | ConvertFrom-Json
        $text = [string]$obj.choices[0].message.content
        if ([string]::IsNullOrWhiteSpace($text)) { return @{ Ok = $false; Text = ''; Error = 'empty response' } }
        return @{ Ok = $true; Text = $text; Error = '' }
    } catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
        $msg = 'request failed'
        if ($code -gt 0) { $msg = "HTTP $code" }
        return @{ Ok = $false; Text = ''; Error = $msg }
    }
}

function Write-Utf8File {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-RescueMain {
    param([bool]$EvidenceOnlyMode, [bool]$DryRunMode, [string]$Explicit, [string]$ScriptDir,
        [string]$ScopeText = 'all', [string]$PackagesText = '', [string]$Policy = 'approve-each',
        [string[]]$ApproveItems = @(), [string[]]$ParamItems = @(), [string]$BackupPath = '', [string[]]$SelectItems = @(),
        [bool]$ListOnly = $false)
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
    Write-Host 'Rescue host launcher (Windows) - read-only checks; output goes to the USB only.'
    $scopeResult = ConvertTo-RescueScope -Text $ScopeText
    if (-not $scopeResult.Ok) {
        Write-Host ('ERROR: -Scope tidak valid / invalid -Scope: ' + $scopeResult.Error) -ForegroundColor Red
        $script:ExitCode = 64
        return
    }
    $packageList = @($PackagesText -split ',' | Where-Object { $_ })
    foreach ($pkg in $packageList) {
        if ($pkg -notmatch '^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$') {
            Write-Host 'ERROR: -Packages tidak valid / invalid -Packages' -ForegroundColor Red
            $script:ExitCode = 64
            return
        }
    }

    $paramMap = ConvertTo-RepairParamMap -Items $ParamItems
    if ($null -eq $paramMap) {
        Write-Host 'ERROR: -Param harus ACTION_ID.NAME=VALUE / -Param must be ACTION_ID.NAME=VALUE' -ForegroundColor Red
        $script:ExitCode = 64
        return
    }
    $approveList = Split-RescueList -Items $ApproveItems
    $selectList = Split-RescueList -Items $SelectItems

    $bundle = Find-RescueBundle -ScriptDir $ScriptDir -Explicit $Explicit
    if (-not $bundle) {
        Write-Host 'ERROR: bundle rescue-omes tidak ditemukan / rescue-omes bundle not found next to this script.' -ForegroundColor Red
        $script:ExitCode = 5
        return
    }
    $reports = Join-Path $bundle 'reports'
    try {
        if (-not (Test-Path -LiteralPath $reports)) { [void](New-Item -ItemType Directory -Path $reports -ErrorAction Stop) }
        $probe = Join-Path $reports ('.write-test-' + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, '')
        Remove-Item -LiteralPath $probe -Force
    } catch {
        Write-Host 'ERROR: folder reports di USB tidak bisa ditulis (USB write-protect?) / reports folder on the USB is not writable.' -ForegroundColor Red
        $script:ExitCode = 5
        return
    }

    $offline = $EvidenceOnlyMode -or $DryRunMode
    $envFile = Join-Path (Join-Path $bundle 'config') 'rescue.env'
    $apiKey = $env:OPENCODE_GO_API_KEY
    if ([string]::IsNullOrEmpty($apiKey)) { $apiKey = Get-ApiKeyFromEnvFile -Path $envFile }
    $haveKey = Test-KeyUsable -Key $apiKey
    $destination = 'unknown'
    if ($haveKey -and -not $offline) { $destination = 'cloud' }

    Write-Host 'Menjalankan pemeriksaan read-only / running read-only checks...'
    $evidence = Invoke-HostCollection -SkipNetwork $offline -Authenticated ($haveKey -and -not $offline) -Destination $destination `
        -Bundle $bundle -Scope $scopeResult.Scope -PackageList $packageList -RepairPolicy $Policy

    $problems = Test-RescueEvidence -Evidence $evidence
    if ($problems.Count -gt 0) {
        Write-Host ('ERROR: evidence tidak valid / evidence failed self-check: ' + ($problems -join ', ')) -ForegroundColor Red
        $script:ExitCode = 2
        return
    }

    $stamp = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $evidencePath = Join-Path $reports ("windows-$stamp-evidence.json")
    $analysisPath = Join-Path $reports ("windows-$stamp-analysis.md")
    $evidenceJson = ConvertTo-RescueJson -Value $evidence -Indent 2
    Write-Utf8File -Path $evidencePath -Text ($evidenceJson + "`n")

    Write-Host ''
    Write-Host 'Ringkasan pemeriksaan / check summary:'
    foreach ($c in $evidence['checks']) {
        $line = '  {0,-8} {1}' -f $c['status'], $c['check_id']
        if ($c.Contains('value')) { $line += ('  (' + $c['value']['kind'] + '=' + $c['value']['number'] + ')') }
        Write-Host $line
    }
    Write-Host ''
    Write-Host "Evidence tersimpan / saved: $evidencePath"

    $catalog = Read-RescueCatalog -Bundle $bundle
    $planOnly = ($offline -or $ListOnly)
    $repairArgs = @{
        Catalog = $catalog; Evidence = $evidence; EvidencePath = $evidencePath; Reports = $reports
        Scope = $scopeResult.Scope; Policy = $Policy; PackageList = $packageList; ApproveList = $approveList
        ParamMap = $paramMap; SelectList = $selectList; BackupRef = $BackupPath; PlanOnly = $planOnly
    }

    if ($EvidenceOnlyMode -and -not $DryRunMode) {
        Write-Host 'Mode -EvidenceOnly: tidak ada panggilan jaringan / no network call was made.'
        $rc = Invoke-RepairPhase @repairArgs -AnalysisText ''
        if ($rc -ne 0) { $script:ExitCode = $rc }
        return
    }

    $promptPath = Join-Path $bundle $script:BundleMarker
    $systemPrompt = [System.IO.File]::ReadAllText($promptPath, [System.Text.Encoding]::UTF8)
    $compactEvidence = ConvertTo-RescueJson -Value $evidence
    $catalogText = Get-CatalogPromptText -Catalog $catalog -Scope $scopeResult.Scope

    if ($DryRunMode) {
        $keyState = 'no'
        if ($haveKey) { $keyState = 'yes' }
        Write-Host ''
        Write-Host 'DRY RUN - tidak ada yang dikirim / nothing is sent:'
        Write-Host "  endpoint      : $($script:Endpoint)"
        Write-Host "  model         : $($script:ModelId)"
        Write-Host "  system prompt : $($systemPrompt.Length) chars"
        Write-Host "  evidence      : $($compactEvidence.Length) chars"
        Write-Host "  API key found : $keyState (value is never shown)"
        Write-Host ("  repair catalog: " + $catalogText.Length + ' chars appended')
        $rc = Invoke-RepairPhase @repairArgs -AnalysisText ''
        if ($rc -ne 0) { $script:ExitCode = $rc }
        return
    }

    if (-not $haveKey) {
        Write-Guidance -Kind 'nokey' -EvidencePath $evidencePath
        $script:ExitCode = 3
        $rc = Invoke-RepairPhase @repairArgs -AnalysisText ''
        if ($rc -eq 5) { $script:ExitCode = 5 }
        return
    }

    Write-Host 'Mengirim evidence ke OpenCode Go / sending evidence to OpenCode Go...'
    $result = Invoke-OpenCodeGo -ApiKey $apiKey -SystemPrompt $systemPrompt -EvidenceJson $compactEvidence -CatalogText $catalogText
    $apiKey = $null
    if (-not $result.Ok) {
        Write-Host ('Kegagalan / failure: ' + $result.Error) -ForegroundColor Yellow
        Write-Guidance -Kind 'network' -EvidencePath $evidencePath
        $script:ExitCode = 4
        $rc = Invoke-RepairPhase @repairArgs -AnalysisText ''
        if ($rc -eq 5) { $script:ExitCode = 5 }
        return
    }

    $header = "# Analisis rescue (windows-host)`n`n> Keluaran model, hanya untuk dibaca; jangan dijalankan. Model output for reading only; never execute it.`n> Dibuat / generated: $(Get-UtcIso). Evidence: windows-$stamp-evidence.json`n`n"
    Write-Utf8File -Path $analysisPath -Text ($header + $result.Text + "`n")
    Write-Host ''
    Write-Host '==================== ANALISIS / ANALYSIS ===================='
    Write-Host $result.Text
    Write-Host '============================================================='
    Write-Host "Analisis tersimpan / analysis saved: $analysisPath"
    $rc = Invoke-RepairPhase @repairArgs -AnalysisText $result.Text
    if ($rc -ne 0) { $script:ExitCode = $rc }
}

if ($env:RESCUE_PS_LIBRARY_ONLY -eq '1') { return }

Invoke-RescueMain -EvidenceOnlyMode ([bool]$EvidenceOnly) -DryRunMode ([bool]$DryRun) -Explicit $BundleDir -ScriptDir $PSScriptRoot `
    -ScopeText $Scope -PackagesText $Packages -Policy $RepairPolicy `
    -ApproveItems $Approve -ParamItems $Param -BackupPath $BackupRef -SelectItems $Select -ListOnly ([bool]$ListRepairs)
exit $script:ExitCode
