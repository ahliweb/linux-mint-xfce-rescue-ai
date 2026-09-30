# Windows host detection module: software. Owned by ahliweb/linux-mint-xfce-rescue-ai#17.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/rescue-windows.ps1 with the call operator in a
# child scope. Read-only, no elevation. Emit one hashtable per check:
#   @{ check_id = 'hw-cpu'; status = 'pass' }   or   @{ check_id = '...'; status = 'warn'; kind = 'count'; number = 3 }
# check_id must be in rescue-ai/v1/rescue-evidence.schema.json; anything else is dropped.
#
# Evidence carries NUMBERS ONLY: never a program name, package ID, path or publisher.
# Sources (all read-only): the HKLM/HKCU Uninstall registry keys, the Run keys and Startup
# folders, and (selected packages only) `winget list --id X --exact`, bounded by a timeout.
# -FixtureFile is a test hook (JSON); the launcher never passes it. Under pwsh on Linux there is no
# registry, so every check degrades to unknown instead of failing.
param([string[]]$Scope = @('all'), [string[]]$Packages = @(), [string]$FixtureFile = '')

$ErrorActionPreference = 'SilentlyContinue'
$script:StartupWarn = 50
$script:MaxSelected = 20
$script:WingetTimeoutMs = 20000

function New-SwCheck {
    param([string]$Id, [string]$Status, [string]$Kind = '', $Number = $null)
    $c = @{ check_id = $Id; status = $Status }
    if ($Kind) { $c['kind'] = $Kind; $c['number'] = $Number }
    return $c
}

function Get-FixtureData {
    if (-not $FixtureFile) { return $null }
    try { return (Get-Content -LiteralPath $FixtureFile -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-UninstallEntries {
    # Returns @{ Ok; Entries } where each entry has Location (string) and LocationExists (bool).
    # System components, updates and entries without a display name are not user-visible programs.
    $fx = Get-FixtureData
    if ($null -ne $fx) {
        $list = @()
        foreach ($e in @($fx.uninstall)) {
            $list += [pscustomobject]@{ Location = [string]$e.location; LocationExists = [bool]$e.location_exists }
        }
        return @{ Ok = $true; Entries = $list }
    }
    if (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE')) { return @{ Ok = $false; Entries = @() } }
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $list = @()
    foreach ($root in $roots) {
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $p -or -not $p.DisplayName) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType -in @('Update', 'Hotfix', 'Security Update')) { continue }
            $loc = [string]$p.InstallLocation
            $exists = $true
            if ($loc) { $exists = [bool](Test-Path -LiteralPath $loc -ErrorAction SilentlyContinue) }
            $list += [pscustomobject]@{ Location = $loc; LocationExists = $exists }
            if ($list.Count -ge 20000) { break }
        }
    }
    return @{ Ok = $true; Entries = $list }
}

function Get-StartupCount {
    $fx = Get-FixtureData
    if ($null -ne $fx) { if ($null -ne $fx.startup_items) { return [int]$fx.startup_items } else { return -1 } }
    if (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE')) { return -1 }
    $n = 0
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
        $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if ($null -ne $p) {
            $n += @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count
        }
    }
    foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if ($d -and (Test-Path -LiteralPath $d)) {
            $n += @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }).Count
        }
    }
    return $n
}

function Test-WingetPackage {
    # $true installed, $false not installed, $null cannot tell (no winget, timeout, fixture-less).
    param([string]$Id)
    $fx = Get-FixtureData
    if ($null -ne $fx) {
        if ($null -eq $fx.winget_installed) { return $null }
        return (@($fx.winget_installed) -contains $Id)
    }
    if ($Id -notmatch '^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,127}$') { return $null }
    $winget = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $winget) { return $null }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $winget.Source
        $psi.Arguments = 'list --id ' + $Id + ' --exact --disable-interactivity --accept-source-agreements'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        if (-not $proc.WaitForExit($script:WingetTimeoutMs)) { try { $proc.Kill() } catch { }; return $null }
        # winget exits 0 when the package is listed; a non-zero code means "no installed package found".
        return ($proc.ExitCode -eq 0)
    } catch { return $null }
}

$selected = @($Packages | Where-Object { $_ })
$isSelected = ($Scope -contains 'software.selected') -and $selected.Count -gt 0
$inv = Get-UninstallEntries

if (-not $inv.Ok) {
    New-SwCheck 'sw-inventory' 'unknown'
} elseif ($isSelected) {
    $missing = 0; $present = 0; $unknown = 0
    foreach ($id in @($selected | Select-Object -First $script:MaxSelected)) {
        $r = Test-WingetPackage -Id $id
        if ($null -eq $r) { $unknown++ } elseif ($r) { $present++ } else { $missing++ }
    }
    if ($unknown -gt 0) {
        New-SwCheck 'sw-inventory' 'unknown'
        New-SwCheck 'sw-app-health' 'unknown'
    } else {
        $st = 'pass'; if ($missing -gt 0) { $st = 'warn' }
        New-SwCheck 'sw-inventory' $st 'count' $present
        New-SwCheck 'sw-app-health' $st 'count' $missing
    }
} else {
    $n = @($inv.Entries).Count
    $st = 'pass'; if ($n -eq 0) { $st = 'warn' }
    New-SwCheck 'sw-inventory' $st 'count' $n
    New-SwCheck 'sw-app-health' 'not_applicable'
}

if ($inv.Ok) {
    # Orphaned installs: an entry names an install folder that no longer exists.
    $orphans = @(@($inv.Entries) | Where-Object { $_.Location -and -not $_.LocationExists }).Count
    $st = 'pass'; if ($orphans -gt 0) { $st = 'warn' }
    New-SwCheck 'sw-package-health' $st 'count' $orphans
} else {
    New-SwCheck 'sw-package-health' 'unknown'
}

$startup = Get-StartupCount
if ($startup -lt 0) {
    New-SwCheck 'sw-startup-items' 'unknown'
} else {
    $st = 'pass'; if ($startup -gt $script:StartupWarn) { $st = 'warn' }
    New-SwCheck 'sw-startup-items' $st 'count' $startup
}
