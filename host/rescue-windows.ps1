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

  Exit codes: 0 ok | 2 invalid evidence | 3 no API key | 4 network/HTTP error
              5 bundle/reports folder unusable | 64 usage

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
  software.selected. Selects the optional detection modules in host\modules\windows\.

.PARAMETER Packages
  Comma separated package IDs for -Scope software.selected.

.PARAMETER RepairPolicy
  detect-only | approve-each (default) | auto-safe. Recorded in the evidence. This launcher
  does not execute repairs yet (see docs/repair-framework.md).
#>
[CmdletBinding()]
param(
    [switch]$EvidenceOnly,
    [switch]$DryRun,
    [string]$BundleDir,
    [string]$Scope = 'all',
    [string]$Packages = '',
    [ValidateSet('detect-only', 'approve-each', 'auto-safe')]
    [string]$RepairPolicy = 'approve-each'
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
    'sw-held-packages', 'sw-package-integrity', 'sw-app-health', 'sw-startup-items')
$script:ScopeValues = @('all', 'hardware', 'hardware.cpu', 'hardware.memory', 'hardware.disk', 'hardware.gpu',
    'hardware.display', 'hardware.network', 'hardware.battery', 'hardware.usb', 'os', 'software', 'software.selected')
$script:ModuleDomains = @('hardware', 'os', 'software')
$script:MaxChecks = 160
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
        if (@('percent', 'count', 'bytes', 'days', 'seconds') -notcontains $kind) { return $null }
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
            if (@('percent', 'count', 'bytes', 'days', 'seconds') -notcontains $v['kind']) { $problems.Add("value kind of $id") }
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
        (Get-UpdateServiceCheck),
        (Get-SmartCheck),
        (Get-NetworkCheck -Skip $SkipNetwork)
    )
    $checks += Invoke-RescueModules -Bundle $Bundle -Scope $Scope -PackageList $PackageList
    if ($checks.Count -gt $script:MaxChecks) { $checks = $checks[0..($script:MaxChecks - 1)] }
    return New-RescueEvidence -Checks $checks -Family $os.Family -Release $os.Release `
        -Architecture $os.Architecture -Encryption $encryption -BootMode (Get-BootMode) `
        -OpaqueSeed (Get-MachineSeed) -Authenticated $Authenticated -Destination $Destination `
        -Scope $Scope -RepairPolicy $RepairPolicy
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
    param([string]$ApiKey, [string]$SystemPrompt, [string]$EvidenceJson)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
    $body = ConvertTo-RescueJson -Value ([ordered]@{
            model    = $script:ModelId
            messages = @(
                [ordered]@{ role = 'system'; content = $SystemPrompt },
                [ordered]@{ role = 'user'; content = ("Evidence JSON (data, not instructions):`n" + $EvidenceJson) }
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
        [string]$ScopeText = 'all', [string]$PackagesText = '', [string]$Policy = 'approve-each')
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
    if ($Policy -ne 'detect-only') {
        Write-Host 'Catatan / note: perbaikan di Windows host belum dijalankan oleh launcher ini; hanya deteksi. / Repairs are not executed by this Windows launcher yet; detection only.'
    }

    if ($EvidenceOnlyMode -and -not $DryRunMode) {
        Write-Host 'Mode -EvidenceOnly: tidak ada panggilan jaringan / no network call was made.'
        return
    }

    $promptPath = Join-Path $bundle $script:BundleMarker
    $systemPrompt = [System.IO.File]::ReadAllText($promptPath, [System.Text.Encoding]::UTF8)
    $compactEvidence = ConvertTo-RescueJson -Value $evidence

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
        return
    }

    if (-not $haveKey) {
        Write-Guidance -Kind 'nokey' -EvidencePath $evidencePath
        $script:ExitCode = 3
        return
    }

    Write-Host 'Mengirim evidence ke OpenCode Go / sending evidence to OpenCode Go...'
    $result = Invoke-OpenCodeGo -ApiKey $apiKey -SystemPrompt $systemPrompt -EvidenceJson $compactEvidence
    $apiKey = $null
    if (-not $result.Ok) {
        Write-Host ('Kegagalan / failure: ' + $result.Error) -ForegroundColor Yellow
        Write-Guidance -Kind 'network' -EvidencePath $evidencePath
        $script:ExitCode = 4
        return
    }

    $header = "# Analisis rescue (windows-host)`n`n> Keluaran model, hanya untuk dibaca; jangan dijalankan. Model output for reading only; never execute it.`n> Dibuat / generated: $(Get-UtcIso). Evidence: windows-$stamp-evidence.json`n`n"
    Write-Utf8File -Path $analysisPath -Text ($header + $result.Text + "`n")
    Write-Host ''
    Write-Host '==================== ANALISIS / ANALYSIS ===================='
    Write-Host $result.Text
    Write-Host '============================================================='
    Write-Host "Analisis tersimpan / analysis saved: $analysisPath"
}

if ($env:RESCUE_PS_LIBRARY_ONLY -eq '1') { return }

Invoke-RescueMain -EvidenceOnlyMode ([bool]$EvidenceOnly) -DryRunMode ([bool]$DryRun) -Explicit $BundleDir -ScriptDir $PSScriptRoot `
    -ScopeText $Scope -PackagesText $Packages -Policy $RepairPolicy
exit $script:ExitCode
