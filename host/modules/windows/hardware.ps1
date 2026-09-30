# Windows host detection module: hardware. Owned by ahliweb/linux-mint-xfce-rescue-ai#15.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/rescue-windows.ps1 with the call operator in a
# child scope. Read-only (CIM/WMI queries and Get-* cmdlets only), no elevation, no repairs.
# Emits one hashtable per check: @{ check_id; status; kind; number } (numbers only, no names,
# serial numbers, MAC addresses or device paths). Anything the current user may not read is
# reported as 'unknown'. Off Windows (for example pwsh on Linux in the tests) the module emits
# nothing. The launcher already emits smart-health (Get-PhysicalDisk), so it is not repeated here.
# Operator documentation: docs/hardware.md. ASCII only (Windows PowerShell 5.1 reads this file).
# Test hook: RESCUE_PS_LIBRARY_ONLY=1 defines the functions and returns (tests feed fake facts).
param([string[]]$Scope = @('all'), [string[]]$Packages = @())

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# Thresholds (documented in docs/hardware.md)
$script:CpuWarnC = 80; $script:CpuFailC = 95
$script:MemWarnBytes = 2GB
$script:BatteryLow = 20; $script:BatteryCritical = 10; $script:BatteryHealthWarn = 60; $script:BatteryHealthFail = 40
$script:NvmeWearWarn = 90; $script:NvmeWearFail = 100; $script:NvmeTempWarn = 70; $script:NvmeTempFail = 80

function Test-HwWants {
    param([string[]]$Scope, [string]$Item)
    foreach ($s in @($Scope)) {
        if ($s -eq 'all' -or $s -eq 'hardware' -or $s -eq ('hardware.' + $Item)) { return $true }
    }
    return $false
}

function New-HwCheck {
    param([string]$Id, [string]$Status, [string]$Kind = '', $Number = $null)
    $c = @{ check_id = $Id; status = $Status }
    if ($Kind -and $null -ne $Number) { $c['kind'] = $Kind; $c['number'] = [long][math]::Floor([double]$Number) }
    return $c
}

function Get-HwCim {
    # CIM query that returns @() (never throws) when the class or the permission is missing;
    # $null means "could not query" so that callers can tell it from "no instances".
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter = '')
    try {
        if ($Filter) {
            return , @(Get-CimInstance -Namespace $Namespace -ClassName $Class -Filter $Filter -ErrorAction Stop)
        }
        return , @(Get-CimInstance -Namespace $Namespace -ClassName $Class -ErrorAction Stop)
    } catch { return $null }
}

function Get-HwFacts {
    # Raw, read-only facts. A value of $null always means "unknown".
    param([string[]]$Scope)
    $f = @{}
    if (Test-HwWants $Scope 'cpu') {
        $cpu = Get-HwCim 'Win32_Processor'
        if ($null -ne $cpu -and $cpu.Count -gt 0) {
            $n = 0; $bad = 0
            foreach ($p in $cpu) {
                $n += [int]$p.NumberOfLogicalProcessors
                if ($p.Status -and $p.Status -ne 'OK') { $bad++ }
            }
            $f['CpuLogical'] = $n; $f['CpuBad'] = $bad
        }
        $temp = $null
        $tz = Get-HwCim 'Win32_PerfFormattedData_Counters_ThermalZoneInformation'
        if ($null -ne $tz -and $tz.Count -gt 0) {
            $k = ($tz | ForEach-Object { [double]$_.Temperature } | Measure-Object -Maximum).Maximum
            if ($k -gt 200) { $temp = [int]($k - 273) }
        }
        if ($null -eq $temp) {
            $acpi = Get-HwCim 'MSAcpi_ThermalZoneTemperature' 'root\wmi'
            if ($null -ne $acpi -and $acpi.Count -gt 0) {
                $k = ($acpi | ForEach-Object { [double]$_.CurrentTemperature } | Measure-Object -Maximum).Maximum
                if ($k -gt 2000) { $temp = [int]($k / 10 - 273.15) }
            }
        }
        $f['TempC'] = $temp
    }
    if (Test-HwWants $Scope 'memory') {
        $mem = Get-HwCim 'Win32_PhysicalMemory'
        if ($null -ne $mem -and $mem.Count -gt 0) {
            $f['MemBytes'] = [long]($mem | ForEach-Object { [long]$_.Capacity } | Measure-Object -Sum).Sum
        } else {
            $os = Get-HwCim 'Win32_OperatingSystem'
            if ($null -ne $os -and $os.Count -gt 0) { $f['MemBytes'] = [long]$os[0].TotalVisibleMemorySize * 1024 }
        }
        # Corrected/uncorrected memory errors are reported by the WHEA logger in the System log.
        try {
            $null = Get-WinEvent -ListProvider 'Microsoft-Windows-WHEA-Logger' -ErrorAction Stop
            $since = (Get-Date).AddDays(-30)
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -ErrorAction SilentlyContinue)
            $f['WheaTotal'] = $ev.Count
            $f['WheaErrors'] = @($ev | Where-Object { $_.Level -le 2 }).Count
        } catch { }
    }
    if (Test-HwWants $Scope 'disk') {
        try {
            $disks = @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.BusType -ne 'USB' })
            $f['DiskCount'] = $disks.Count
            $f['DiskBad'] = @($disks | Where-Object { $_.OperationalStatus -notcontains 'OK' }).Count
            $nv = @($disks | Where-Object { $_.BusType -eq 'NVMe' })
            $f['NvmeCount'] = $nv.Count
            $list = @()
            foreach ($d in $nv) {
                try {
                    $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
                    if ($null -ne $r -and $null -ne $r.Wear) {
                        $list += , @{ Wear = [int]$r.Wear; Temp = [int]$r.Temperature; Uncorrected = [int]$r.ReadErrorsUncorrected }
                    }
                } catch { }
            }
            $f['Nvme'] = $list
        } catch { }
    }
    if (Test-HwWants $Scope 'gpu') {
        $gpu = Get-HwCim 'Win32_VideoController'
        if ($null -ne $gpu) {
            $f['GpuCount'] = $gpu.Count
            $f['GpuBad'] = @($gpu | Where-Object { $_.ConfigManagerErrorCode -ne 0 -or $_.Name -like 'Microsoft Basic Display*' }).Count
        }
    }
    if (Test-HwWants $Scope 'display') {
        $mon = Get-HwCim 'WmiMonitorBasicDisplayParams' 'root\wmi'
        if ($null -ne $mon) { $f['Monitors'] = @($mon | Where-Object { $_.Active }).Count }
    }
    if (Test-HwWants $Scope 'network') {
        try {
            $na = @(Get-NetAdapter -Physical -ErrorAction Stop)
            $f['AdapterCount'] = $na.Count
            $f['AdapterUp'] = @($na | Where-Object { $_.Status -eq 'Up' }).Count
            $wifi = @($na | Where-Object { $_.PhysicalMediaType -like '*802.11*' })
            $f['WifiCount'] = $wifi.Count
            $f['WifiDisabled'] = @($wifi | Where-Object { $_.Status -eq 'Disabled' }).Count
        } catch { }
    }
    if ((Test-HwWants $Scope 'network') -or (Test-HwWants $Scope 'gpu') -or (Test-HwWants $Scope 'usb')) {
        # Driver problems: Win32_PnPEntity.ConfigManagerErrorCode <> 0, counted per device class.
        $pnp = Get-HwCim 'Win32_PnPEntity' 'root\cimv2' 'ConfigManagerErrorCode <> 0'
        if ($null -ne $pnp) {
            $f['PnpNetBad'] = @($pnp | Where-Object { $_.PNPClass -eq 'Net' }).Count
            $f['PnpUsbBad'] = @($pnp | Where-Object { $_.PNPClass -eq 'USB' }).Count
            $f['PnpDisplayBad'] = @($pnp | Where-Object { $_.PNPClass -eq 'Display' }).Count
        }
    }
    if (Test-HwWants $Scope 'battery') {
        $bat = Get-HwCim 'Win32_Battery'
        if ($null -ne $bat) {
            if ($bat.Count -eq 0) { $f['BatteryPresent'] = $false } else {
                $f['BatteryPresent'] = $true
                $f['BatteryCharge'] = [int]($bat | ForEach-Object { [int]$_.EstimatedChargeRemaining } | Measure-Object -Minimum).Minimum
                $f['BatteryDischarging'] = (@($bat | Where-Object { $_.BatteryStatus -eq 1 }).Count -gt 0)
                $full = Get-HwCim 'BatteryFullChargedCapacity' 'root\wmi'
                $design = Get-HwCim 'BatteryStaticData' 'root\wmi'
                if ($null -ne $full -and $null -ne $design -and $full.Count -gt 0 -and $design.Count -gt 0 -and [long]$design[0].DesignedCapacity -gt 0) {
                    $f['BatteryHealth'] = [int](100 * [long]$full[0].FullChargedCapacity / [long]$design[0].DesignedCapacity)
                }
            }
        }
    }
    if (Test-HwWants $Scope 'usb') {
        $usb = Get-HwCim 'Win32_USBControllerDevice'
        if ($null -ne $usb) { $f['UsbCount'] = $usb.Count }
    }
    return $f
}

function ConvertTo-HwChecks {
    # Pure function: facts -> checks (unit-tested with fake facts).
    param([hashtable]$Facts, [string[]]$Scope)
    $out = @()
    $f = $Facts
    if (Test-HwWants $Scope 'cpu') {
        if ($f.ContainsKey('CpuLogical') -and $f['CpuLogical'] -gt 0) {
            $st = 'pass'; if ($f['CpuBad'] -gt 0) { $st = 'warn' }
            $out += New-HwCheck 'hw-cpu' $st 'count' $f['CpuLogical']
        } else { $out += New-HwCheck 'hw-cpu' 'unknown' }
        if ($null -ne $f['TempC']) {
            $st = 'pass'
            if ($f['TempC'] -ge $script:CpuFailC) { $st = 'fail' } elseif ($f['TempC'] -ge $script:CpuWarnC) { $st = 'warn' }
            $out += New-HwCheck 'hw-cpu-thermal' $st 'count' $f['TempC']   # count = degrees Celsius
        } else { $out += New-HwCheck 'hw-cpu-thermal' 'unknown' }
    }
    if (Test-HwWants $Scope 'memory') {
        if ($null -ne $f['MemBytes'] -and $f['MemBytes'] -gt 0) {
            $st = 'pass'; if ($f['MemBytes'] -lt $script:MemWarnBytes) { $st = 'warn' }
            $out += New-HwCheck 'hw-memory' $st 'bytes' $f['MemBytes']
        } else { $out += New-HwCheck 'hw-memory' 'unknown' }
        if ($null -ne $f['WheaTotal']) {
            $st = 'pass'
            if ($f['WheaErrors'] -gt 0) { $st = 'fail' } elseif ($f['WheaTotal'] -gt 0) { $st = 'warn' }
            $out += New-HwCheck 'hw-memory-errors' $st 'count' $f['WheaTotal']   # WHEA events in 30 days
        } else { $out += New-HwCheck 'hw-memory-errors' 'unknown' }
    }
    if (Test-HwWants $Scope 'disk') {
        if ($null -ne $f['DiskCount']) {
            $st = 'pass'
            if ($f['DiskCount'] -eq 0) { $st = 'fail' } elseif ($f['DiskBad'] -gt 0) { $st = 'warn' }
            $out += New-HwCheck 'hw-disk' $st 'count' $f['DiskCount']
            if ($f['NvmeCount'] -eq 0) { $out += New-HwCheck 'nvme-health' 'not_applicable' }
            elseif ($f['Nvme'].Count -eq 0) { $out += New-HwCheck 'nvme-health' 'unknown' }
            else {
                $st = 'pass'; $wear = 0
                foreach ($n in $f['Nvme']) {
                    if ($n.Wear -gt $wear) { $wear = $n.Wear }
                    if ($n.Wear -ge $script:NvmeWearFail -or $n.Temp -ge $script:NvmeTempFail) { $st = 'fail' }
                    elseif ($st -ne 'fail' -and ($n.Wear -ge $script:NvmeWearWarn -or $n.Temp -ge $script:NvmeTempWarn -or $n.Uncorrected -gt 0)) { $st = 'warn' }
                }
                $out += New-HwCheck 'nvme-health' $st 'percent' ([math]::Min($wear, 100))
            }
        } else {
            $out += New-HwCheck 'hw-disk' 'unknown'
            $out += New-HwCheck 'nvme-health' 'unknown'
        }
    }
    if (Test-HwWants $Scope 'gpu') {
        if ($null -ne $f['GpuCount'] -and $f['GpuCount'] -gt 0) {
            $bad = [int]$f['GpuBad']
            if ([int]$f['PnpDisplayBad'] -gt $bad) { $bad = [int]$f['PnpDisplayBad'] }
            $st = 'pass'; if ($bad -gt 0) { $st = 'fail' }
            $out += New-HwCheck 'hw-gpu' 'pass' 'count' $f['GpuCount']
            $out += New-HwCheck 'hw-gpu-driver' $st 'count' $bad
        } elseif ($null -ne $f['GpuCount']) {
            $out += New-HwCheck 'hw-gpu' 'not_applicable'
            $out += New-HwCheck 'hw-gpu-driver' 'not_applicable'
        } else {
            $out += New-HwCheck 'hw-gpu' 'unknown'
            $out += New-HwCheck 'hw-gpu-driver' 'unknown'
        }
    }
    if (Test-HwWants $Scope 'display') {
        if ($null -ne $f['Monitors']) {
            $st = 'pass'; if ($f['Monitors'] -eq 0) { $st = 'warn' }
            $out += New-HwCheck 'hw-display' $st 'count' $f['Monitors']
        } else { $out += New-HwCheck 'hw-display' 'unknown' }
    }
    if (Test-HwWants $Scope 'network') {
        if ($null -ne $f['AdapterCount']) {
            $badDrivers = [int]$f['PnpNetBad']
            if ($badDrivers -gt 0) { $out += New-HwCheck 'hw-network-adapter' 'fail' 'count' $badDrivers }
            elseif ($f['AdapterCount'] -eq 0) { $out += New-HwCheck 'hw-network-adapter' 'fail' 'count' 0 }
            else {
                $st = 'pass'; if ($f['AdapterUp'] -eq 0) { $st = 'warn' }
                $out += New-HwCheck 'hw-network-adapter' $st 'count' $f['AdapterCount']
            }
            if ($f['WifiCount'] -eq 0) { $out += New-HwCheck 'hw-wifi' 'not_applicable' }
            else {
                $st = 'pass'; if ($f['WifiDisabled'] -gt 0) { $st = 'warn' }
                $out += New-HwCheck 'hw-wifi' $st 'count' $f['WifiDisabled']   # count = disabled Wi-Fi adapters
            }
        } else {
            $out += New-HwCheck 'hw-network-adapter' 'unknown'
            $out += New-HwCheck 'hw-wifi' 'unknown'
        }
    }
    if (Test-HwWants $Scope 'battery') {
        if ($f['BatteryPresent'] -eq $false) { $out += New-HwCheck 'hw-battery' 'not_applicable' }
        elseif ($f['BatteryPresent'] -eq $true) {
            $st = 'pass'
            $h = $f['BatteryHealth']
            if ($null -ne $h -and $h -lt $script:BatteryHealthFail) { $st = 'fail' }
            elseif ($null -ne $h -and $h -lt $script:BatteryHealthWarn) { $st = 'warn' }
            $c = [int]$f['BatteryCharge']
            if ($f['BatteryDischarging'] -and $c -lt $script:BatteryCritical) { $st = 'fail' }
            elseif ($f['BatteryDischarging'] -and $c -lt $script:BatteryLow -and $st -eq 'pass') { $st = 'warn' }
            $out += New-HwCheck 'hw-battery' $st 'percent' $c
        } else { $out += New-HwCheck 'hw-battery' 'unknown' }
    }
    if (Test-HwWants $Scope 'usb') {
        if ($null -ne $f['UsbCount']) {
            $st = 'pass'; if ($f['PnpUsbBad'] -gt 0) { $st = 'warn' }
            $out += New-HwCheck 'hw-usb' $st 'count' $f['UsbCount']
        } else { $out += New-HwCheck 'hw-usb' 'unknown' }
    }
    return , $out
}

if ($env:RESCUE_PS_LIBRARY_ONLY -eq '1') { return }
if ($env:OS -ne 'Windows_NT') { return }   # not Windows: no hardware checks from this module

try {
    $facts = Get-HwFacts -Scope $Scope
    foreach ($c in @(ConvertTo-HwChecks -Facts $facts -Scope $Scope)) { $c }
} catch { }
