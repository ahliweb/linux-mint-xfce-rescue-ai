# Windows host detection module: os. Owned by ahliweb/linux-mint-xfce-rescue-ai#16.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/rescue-windows.ps1 with the call operator in a
# child scope. Read-only, no elevation. Emit one hashtable per check:
#   @{ check_id = 'hw-cpu'; status = 'pass' }   or   @{ check_id = '...'; status = 'warn'; kind = 'count'; number = 3 }
# check_id must be in rescue-ai/v1/rescue-evidence.schema.json; anything else is dropped.
#
# Checks: windows-boot-config (bcdedit /enum, only when readable without elevation),
# windows-system-files (CBS.log corruption markers + pending servicing keys),
# windows-restore-points (Get-ComputerRestorePoint; needs admin, otherwise unknown).
# Every check degrades to 'unknown' when a tool or permission is missing. Only counts leave here.
param([string[]]$Scope = @('all'), [string[]]$Packages = @())

$ErrorActionPreference = 'Stop'

function Get-BootConfigResult {
    try {
        if (-not (Get-Command -Name bcdedit -ErrorAction SilentlyContinue)) {
            return @{ check_id = 'windows-boot-config'; status = 'unknown' }
        }
        $global:LASTEXITCODE = 0
        $text = (& bcdedit /enum 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { return @{ check_id = 'windows-boot-config'; status = 'unknown' } }
        # Keys such as "path" are not localized; headings are, so count winload entries.
        $n = ([regex]::Matches($text, '(?im)^\s*path\s+\S*winload\.(exe|efi)')).Count
        if ($n -gt 0) { return @{ check_id = 'windows-boot-config'; status = 'pass'; kind = 'count'; number = $n } }
        return @{ check_id = 'windows-boot-config'; status = 'fail'; kind = 'count'; number = 0 }
    } catch {
        return @{ check_id = 'windows-boot-config'; status = 'unknown' }
    }
}

function Get-SystemFilesResult {
    $known = $false
    $count = 0
    try {
        $log = Join-Path (Join-Path (Join-Path $env:SystemRoot 'Logs') 'CBS') 'CBS.log'
        if (Test-Path -LiteralPath $log -PathType Leaf) {
            $fs = [System.IO.File]::Open($log, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $take = [int][Math]::Min($fs.Length, 4MB)
                [void]$fs.Seek($fs.Length - $take, [System.IO.SeekOrigin]::Begin)
                $buf = New-Object byte[] $take
                $got = $fs.Read($buf, 0, $take)
                $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $got)
            } finally { $fs.Dispose() }
            $count += ([regex]::Matches($text, '(?i)cannot repair member file|csi payload corrupt|store corruption|component store is repairable')).Count
            $known = $true
        }
    } catch { }
    $onWindows = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')) {
        if (-not $onWindows) { continue }
        try {
            if (Test-Path -LiteralPath $key) { $count += 1 }
            $known = $true
        } catch { }
    }
    if (-not $known) { return @{ check_id = 'windows-system-files'; status = 'unknown' } }
    $status = 'pass'
    if ($count -gt 0) { $status = 'warn' }
    return @{ check_id = 'windows-system-files'; status = $status; kind = 'count'; number = $count }
}

function Get-RestorePointsResult {
    try {
        if (-not (Get-Command -Name Get-ComputerRestorePoint -ErrorAction SilentlyContinue)) {
            return @{ check_id = 'windows-restore-points'; status = 'unknown' }
        }
        $points = @(Get-ComputerRestorePoint -ErrorAction Stop)   # needs an elevated session
        $n = $points.Count
        $status = 'warn'
        if ($n -gt 0) { $status = 'pass' }
        return @{ check_id = 'windows-restore-points'; status = $status; kind = 'count'; number = $n }
    } catch {
        return @{ check_id = 'windows-restore-points'; status = 'unknown' }
    }
}

Get-BootConfigResult
Get-SystemFilesResult
Get-RestorePointsResult
