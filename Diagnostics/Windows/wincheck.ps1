#requires -Version 5.1
<#
.SYNOPSIS
Collects Windows restart, sign-in, update and ongoing-slowness evidence (v2.0).
.DESCRIPTION
Run on the affected Windows computer, elevated, preferably WHILE it is slow.
Does not repair Windows, reboot, change policy, enable logs, disable security,
clear caches, install modules or contact a management console. It writes reports.
Optional health checks and ETL conversion add load; capture live symptoms first.
Raw event XML, CSV, collection coverage, a timeline, HTML, and a verified ZIP are
produced. Missing/disabled/denied/capped/timed-out sources are explicitly recorded.
No finite collector guarantees a root cause or reconstructs unrecorded history.

Direct execution runs collection. Dot-sourcing only defines the function.
Windows PowerShell 5.1 and PowerShell 7 on Windows are supported targets.
Collectors use local background jobs with deadlines. Their failure is isolated.
.PARAMETER IncidentStart
Local computer time unless an explicit UTC offset is supplied. With IncidentEnd,
selects a focused window, collected IN ADDITION to the historical window so a busy
log's history cap does not hide the incident. Boot incident times and logged times
are both preserved. Default focused window: the last four hours.
.PARAMETER IncidentEnd
Defaults to collection start. The historical window includes an older specified
incident even if it predates DaysBack. Report timezone information is preserved.
.PARAMETER MaxEventsPerLog
Historical cap per channel (newest records). An extra event detects truncation.
.PARAMETER MaxIncidentEventsPerLog
Independent cap for the focused incident; raw XML and CSV contain the union.
.PARAMETER SampleSeconds
Current CPU, RAM, paging, disk and process sampling duration. Zero skips sampling.
.PARAMETER IncludeDefenderTrace
Collect a timed Defender performance trace while the symptom is occurring.
Requires the installed cmdlet to support -Seconds. No interactive prompt or
cancellation of another existing trace is attempted.
.PARAMETER IncludeHealthScans
Runs DISM CheckHealth, DISM ScanHealth and SFC VerifyOnly AFTER live capture.
.PARAMETER IncludeWindowsUpdateLog
Decode retained Windows Update ETLs; can take minutes and may require networking.
.PARAMETER IncludeEvtx
Export native EVTX of the focused incident, as well as the default raw XML.
Channels whose whole current file exceeds MaxEvtxSourceMB are skipped with notice.
.PARAMETER IncludeSecurityLog
Collect focused logon/logoff/lock/unlock audit events; does not enable auditing.
.PARAMETER AgentLogPath
Explicit local .log/.txt files or directories to collect, including vendor log
exports. Directories are inspected to depth 3 without following reparse points.
Files are copied only if recent and under the stated size budget; otherwise a
text tail is retained. No guessed vendor database locations or credential stores.
ThreatLocker cloud Unified Audit must be exported separately by an administrator.
.PARAMETER ExternalEvidencePath
Explicit local CSV/JSON/TXT/LOG/EVTX/ETL exports to attach (e.g. ThreatLocker audit).
These are preserved, not interpreted as a vendor-specific schema.
.PARAMETER ZipOnly
Delete this run's expanded folder ONLY after all files in its manifest have been
verified against decompressed ZIP entries by length and SHA-256. Default keeps both.
.EXAMPLE
.\Invoke-WindowsUpdateDelayDiagnostics.ps1 -DaysBack 28 -OutputPath C:\Temp
.EXAMPLE
.\Invoke-WindowsUpdateDelayDiagnostics.ps1 -IncidentStart '2026-09-14T07:00:00' -IncidentEnd '2026-09-14T09:00:00' -IncludeDefenderTrace -OutputPath C:\Temp
.EXAMPLE
. .\Invoke-WindowsUpdateDelayDiagnostics.ps1
Invoke-WindowsUpdateDelayDiagnostics -DaysBack 28 -IncludeHealthScans -IncludeWindowsUpdateLog -IncludeEvtx -ZipOnly -OutputPath C:\Temp
.NOTES
Reports contain machine/user names, installed software, process command lines,
network configuration and log contents. Review before sharing outside your team.
Collector-generated activity is timestamped; avoid mistaking it for the symptom.
Boot/app measurements overlap and must not be summed. Event 100 report time can
lag the boot. WER reports with the same ReportId are not separate proven crashes.
Sources: https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
#>
[CmdletBinding()]
param(
    [ValidateRange(1,90)][int]$DaysBack = 28,
    [datetime]$IncidentStart,
    [datetime]$IncidentEnd,
    [string]$OutputPath = (Join-Path $env:TEMP 'WindowsDiagnostics'),
    [ValidateRange(100,200000)][int]$MaxEventsPerLog = 10000,
    [ValidateRange(100,200000)][int]$MaxIncidentEventsPerLog = 20000,
    [ValidateRange(0,600)][int]$SampleSeconds = 60,
    [ValidateRange(1,30)][int]$SampleIntervalSeconds = 5,
    [ValidateRange(15,1800)][int]$CollectorTimeoutSeconds = 180,
    [switch]$IncludeDefenderTrace,
    [ValidateRange(15,600)][int]$DefenderTraceSeconds = 120,
    [switch]$IncludeHealthScans,
    [switch]$IncludeWindowsUpdateLog,
    [switch]$IncludeEvtx,
    [ValidateRange(1,2048)][int]$MaxEvtxSourceMB = 128,
    [switch]$IncludeSecurityLog,
    [string[]]$AgentLogPath = @(),
    [string[]]$ExternalEvidencePath = @(),
    [ValidateRange(1,256)][int]$MaxLogFileMB = 20,
    [ValidateRange(10,4096)][int]$MaxAttachedLogsMB = 200,
    [switch]$ZipOnly
)

function Invoke-WindowsUpdateDelayDiagnostics {
    [CmdletBinding()]
    param(
        [ValidateRange(1,90)][int]$DaysBack = 28,
        [datetime]$IncidentStart,
        [datetime]$IncidentEnd,
        [string]$OutputPath = (Join-Path $env:TEMP 'WindowsDiagnostics'),
        [ValidateRange(100,200000)][int]$MaxEventsPerLog = 10000,
        [ValidateRange(100,200000)][int]$MaxIncidentEventsPerLog = 20000,
        [ValidateRange(0,600)][int]$SampleSeconds = 60,
        [ValidateRange(1,30)][int]$SampleIntervalSeconds = 5,
        [ValidateRange(15,1800)][int]$CollectorTimeoutSeconds = 180,
        [switch]$IncludeDefenderTrace,
        [ValidateRange(15,600)][int]$DefenderTraceSeconds = 120,
        [switch]$IncludeHealthScans,
        [switch]$IncludeWindowsUpdateLog,
        [switch]$IncludeEvtx,
        [ValidateRange(1,2048)][int]$MaxEvtxSourceMB = 128,
        [switch]$IncludeSecurityLog,
        [string[]]$AgentLogPath = @(),
        [string[]]$ExternalEvidencePath = @(),
        [ValidateRange(1,256)][int]$MaxLogFileMB = 20,
        [ValidateRange(10,4096)][int]$MaxAttachedLogsMB = 200,
        [switch]$ZipOnly
    )
    Set-StrictMode -Version 2
    $ErrorActionPreference = 'Stop'
    if ($env:OS -ne 'Windows_NT') { throw 'Run this collector on the affected Windows computer.' }
    $started = Get-Date
    if (-not $PSBoundParameters.ContainsKey('IncidentEnd')) { $IncidentEnd = $started }
    if (-not $PSBoundParameters.ContainsKey('IncidentStart')) { $IncidentStart = $IncidentEnd.AddHours(-4) }
    if ($IncidentEnd -le $IncidentStart) { throw 'IncidentEnd must be later than IncidentStart.' }
    $historyStart = $started.AddDays(-$DaysBack)
    if ($IncidentStart -lt $historyStart) { $historyStart = $IncidentStart }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $runName = 'WindowsUpdateDelay-{0}-{1}-{2}' -f $env:COMPUTERNAME,$started.ToString('yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8))
    $root = Join-Path ([IO.Path]::GetFullPath($OutputPath)) $runName
    New-Item -ItemType Directory -Path $root | Out-Null
    foreach ($dir in 'Events','Inventory','Live','Logs','Evidence','Status') {
        New-Item -ItemType Directory -Path (Join-Path $root $dir) | Out-Null
    }
    $status = New-Object 'System.Collections.Generic.List[object]'
    $context = @{
        Root=$root; Start=$historyStart; End=$started; IncidentStart=$IncidentStart; IncidentEnd=$IncidentEnd
        MaxEvents=$MaxEventsPerLog; MaxIncident=$MaxIncidentEventsPerLog
        SampleSeconds=$SampleSeconds; Interval=$SampleIntervalSeconds
        IncludeEvtx=[bool]$IncludeEvtx; MaxEvtxMB=$MaxEvtxSourceMB
        TraceSeconds=$DefenderTraceSeconds; AgentPaths=$AgentLogPath; EvidencePaths=$ExternalEvidencePath
        MaxLogMB=$MaxLogFileMB; MaxLogsMB=$MaxAttachedLogsMB
    }
    $metadata = [ordered]@{
        CollectorVersion='2.0'; Computer=$env:COMPUTERNAME; User=$identity.Name; Elevated=$isAdmin
        CollectionStartedLocal=$started.ToString('o'); CollectionStartedUTC=$started.ToUniversalTime().ToString('o')
        TimeZone=[TimeZoneInfo]::Local.Id; HistoryStart=$historyStart.ToString('o')
        IncidentStart=$IncidentStart.ToString('o'); IncidentEnd=$IncidentEnd.ToString('o')
        PowerShell=$PSVersionTable.PSVersion.ToString(); Parameters=$PSBoundParameters
    }
    $metadata | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $root 'Run.json') -Encoding UTF8
    Write-Host "Report folder: $root"
    if (-not $isAdmin) { Write-Warning 'Not elevated: some collectors will report access denied.' }

    # Every worker runs in a local child PowerShell process, with its own scope.
    $common = @'
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
function Save-Json($Relative, $Data) {
    ConvertTo-Json -InputObject $Data -Depth 12 | Set-Content -LiteralPath (Join-Path $C.Root $Relative) -Encoding UTF8
}
function Save-Csv($Relative, $Data) {
    @($Data) | Export-Csv -LiteralPath (Join-Path $C.Root $Relative) -NoTypeInformation -Encoding UTF8
}
function Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}
function Native-Text([string]$File, [string[]]$Arguments, [string]$Relative) {
    $result = & $File @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $result | Out-String -Width 260 | Set-Content -LiteralPath (Join-Path $C.Root $Relative) -Encoding UTF8
    if ($exitCode -ne 0) { throw "$File exited with code $exitCode; see $Relative." }
}
function Attempt([string]$Name, [scriptblock]$Code) {
    try { & $Code }
    catch {
        [pscustomobject]@{Section=$Name; Error=$_.Exception.Message} |
            ConvertTo-Json -Compress | Add-Content (Join-Path $C.Root 'Status/SectionErrors.jsonl') -Encoding UTF8
    }
}
'@
    function Run-Collector([string]$Name, [scriptblock]$Code, [hashtable]$Extra = @{}, [int]$Timeout = $CollectorTimeoutSeconds) {
        $taskContext = $context.Clone()
        foreach ($key in $Extra.Keys) { $taskContext[$key] = $Extra[$key] }
        $begin = Get-Date
        Write-Host ("[{0:HH:mm:ss}] {1}" -f $begin,$Name)
        $job = $null; $outcome='Completed'; $detail=''
        try {
            $job = Start-Job -ScriptBlock {
                param($Source,$C,$Helpers)
                . ([scriptblock]::Create($Helpers))
                & ([scriptblock]::Create($Source))
            } -ArgumentList @($Code.ToString(), $taskContext, $common)
            while ($job.State -in @('Running','NotStarted','Blocked')) {
                if (((Get-Date)-$begin).TotalSeconds -ge $Timeout) {
                    $outcome='TimedOut'; $detail="Exceeded $Timeout seconds; partial files may exist."
                    Stop-Job -Job $job
                    break
                }
                Wait-Job -Job $job -Timeout 5 | Out-Null
                Write-Progress -Activity $Name -Status ("Elapsed {0:N0}s (limit {1}s)" -f ((Get-Date)-$begin).TotalSeconds,$Timeout)
            }
            if ($outcome -ne 'TimedOut') {
                $jobErrors = @()
                $output = @(Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErrors)
                if ($output.Count) { $output | Out-String -Width 240 | Add-Content (Join-Path $root 'Status/WorkerOutput.txt') }
                if ($job.State -ne 'Completed' -or $jobErrors.Count) {
                    $outcome='Failed'; $detail=($jobErrors | Out-String).Trim()
                    if (-not $detail) { $detail=[string]$job.ChildJobs[0].JobStateInfo.Reason }
                }
            }
        } catch { $outcome='Failed'; $detail=$_.Exception.Message }
        finally {
            if ($null -ne $job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
            Write-Progress -Activity $Name -Completed
        }
        $record=[pscustomobject]@{Collector=$Name; Status=$outcome; StartedUTC=$begin.ToUniversalTime().ToString('o'); Seconds=[math]::Round(((Get-Date)-$begin).TotalSeconds,1); Detail=$detail}
        $status.Add($record)
        $record | ConvertTo-Json -Compress | Add-Content (Join-Path $root 'Status/Collectors.jsonl') -Encoding UTF8
        if ($outcome -ne 'Completed') { Write-Warning "$Name : $outcome - $detail" }
    }

    # Sample BEFORE large log queries, inventory scans or optional health checks.
    if ($SampleSeconds -gt 0) {
        Run-Collector 'Live resource sampling' {
            $logical = [int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
            if ($logical -lt 1) { $logical=1 }
            Attempt 'Process identity at sample start' {
                Save-Csv 'Live/ProcessAtStart.csv' @(Get-CimInstance Win32_Process | Select-Object @('Name','ProcessId','ParentProcessId','CreationDate','ExecutablePath','CommandLine'))
            }
            $until=(Get-Date).AddSeconds($C.SampleSeconds)
            do {
                $stamp=(Get-Date).ToUniversalTime().ToString('o')
                Attempt 'Live system counters' {
                    $cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
                    $mem=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
                    [pscustomobject]@{TimeUTC=$stamp; CPUPercent=$cpu.PercentProcessorTime; AvailableMB=$mem.AvailableMBytes; CommittedPercent=$mem.PercentCommittedBytesInUse; PagesPerSec=$mem.PagesPersec; PageReadsPerSec=$mem.PageReadsPersec} |
                        Export-Csv (Join-Path $C.Root 'Live/SystemSamples.csv') -Append -NoTypeInformation -Encoding UTF8
                }
                Attempt 'Live disk counters' {
                    Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk |
                        Select-Object -Property @(@{n='TimeUTC';e={$stamp}},'Name','PercentDiskTime','PercentIdleTime','CurrentDiskQueueLength','DiskReadBytesPersec','DiskWriteBytesPersec','DiskReadsPersec','DiskWritesPersec') |
                        Export-Csv (Join-Path $C.Root 'Live/DiskSamples.csv') -Append -NoTypeInformation -Encoding UTF8
                }
                Attempt 'Raw disk latency counters' {
                    Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk |
                        Select-Object -Property @(@{n='TimeUTC';e={$stamp}},'Name','Timestamp_PerfTime','Frequency_PerfTime','AvgDisksecPerRead','AvgDisksecPerRead_Base','AvgDisksecPerWrite','AvgDisksecPerWrite_Base') |
                        Export-Csv (Join-Path $C.Root 'Live/DiskRawLatencySamples.csv') -Append -NoTypeInformation -Encoding UTF8
                }
                Attempt 'Live process counters' {
                    # IODataBytesPersec includes non-disk I/O. CPU is normalized to machine capacity.
                    Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
                        Where-Object { $_.Name -notin @('_Total','Idle') } |
                        Select-Object -Property @(@{n='TimeUTC';e={$stamp}},'Name','IDProcess',
                            @{n='CPUPercentOfMachine';e={[math]::Round($_.PercentProcessorTime/$logical,2)}},
                            'WorkingSetPrivate','IODataBytesPersec','IOReadBytesPersec','IOWriteBytesPersec','ThreadCount','HandleCount') |
                        Export-Csv (Join-Path $C.Root 'Live/ProcessSamples.csv') -Append -NoTypeInformation -Encoding UTF8
                }
                if ((Get-Date) -lt $until) { Start-Sleep -Seconds $C.Interval }
            } while ((Get-Date) -lt $until)
        } @{} ($SampleSeconds + 90)
    }
    if ($IncludeDefenderTrace) {
        # Timed native recording stays in the foreground: killing its worker at a
        # deadline could abandon an ETW session. Do not cancel an existing trace.
        Write-Host "Recording Defender for $DefenderTraceSeconds seconds, then generating scan reports..."
        $begin=Get-Date; $outcome='Completed'; $detail=''
        try {
            $cmd=Get-Command New-MpPerformanceRecording -ErrorAction Stop
            if (-not $cmd.Parameters.ContainsKey('Seconds')) { throw 'Installed Defender cmdlet has no timed -Seconds option. Capture interactively with New-MpPerformanceRecording and press Enter to stop.' }
            $trace=Join-Path $root 'Live/DefenderPerformance.etl'
            New-MpPerformanceRecording -RecordTo $trace -Seconds $DefenderTraceSeconds -ErrorAction Stop | Out-Null
            Get-MpPerformanceReport -Path $trace -TopProcesses 20 | Out-String -Width 300 | Set-Content (Join-Path $root 'Live/Defender-TopProcesses.txt')
            Get-MpPerformanceReport -Path $trace -TopFiles 20 | Out-String -Width 300 | Set-Content (Join-Path $root 'Live/Defender-TopFiles.txt')
        } catch { $outcome='Failed'; $detail=$_.Exception.Message; Write-Warning $detail }
        $record=[pscustomobject]@{Collector='Defender performance recording';Status=$outcome;StartedUTC=$begin.ToUniversalTime().ToString('o');Seconds=[math]::Round(((Get-Date)-$begin).TotalSeconds,1);Detail=$detail}
        $status.Add($record)
        $record | ConvertTo-Json -Compress | Add-Content (Join-Path $root 'Status/Collectors.jsonl') -Encoding UTF8
    }

    Run-Collector 'System and storage inventory' {
        foreach ($class in 'Win32_OperatingSystem','Win32_ComputerSystem','Win32_BIOS','Win32_Processor','Win32_DiskDrive','Win32_LogicalDisk','Win32_PageFileUsage') {
            Attempt $class { Save-Json "Inventory/$class.json" @(Get-CimInstance -ClassName $class | Select-Object * -ExcludeProperty @('CimClass','CimInstanceProperties','CimSystemProperties')) }
        }
        Attempt 'Physical disks' { Save-Csv 'Inventory/PhysicalDisks.csv' @(Get-PhysicalDisk | Select-Object @('FriendlyName','SerialNumber','UniqueId','MediaType','BusType','HealthStatus','OperationalStatus','Size')) }
        Attempt 'Disk reliability' { Save-Csv 'Inventory/StorageReliability.csv' @(Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object @('DeviceId','Temperature','TemperatureMax','Wear','PowerOnHours','ReadErrorsTotal','ReadErrorsUncorrected','WriteErrorsTotal','WriteErrorsUncorrected')) }
        Attempt 'Volumes' { Save-Csv 'Inventory/Volumes.csv' @(Get-Volume | Select-Object @('DriveLetter','FileSystemLabel','FileSystem','HealthStatus','OperationalStatus','Size','SizeRemaining')) }
        Attempt 'Legacy SMART' { Save-Csv 'Inventory/LegacySMART.csv' @(Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object @('InstanceName','PredictFailure','Reason')) }
        Attempt 'PnP device problems' { Save-Csv 'Inventory/PnPProblems.csv' @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | Select-Object @('Name','PNPDeviceID','Service','ConfigManagerErrorCode','Status')) }
        Attempt 'Signed driver versions' { Save-Csv 'Inventory/SignedDrivers.csv' @(Get-CimInstance Win32_PnPSignedDriver | Select-Object @('DeviceName','DeviceID','DriverProviderName','DriverVersion','DriverDate','InfName','IsSigned')) }
    }
    Run-Collector 'Services, agents, startup and tasks' {
        Save-Csv 'Inventory/Services.csv' @(Get-CimInstance Win32_Service | Select-Object @('Name','DisplayName','State','StartMode','StartName','ProcessId','ExitCode','ServiceSpecificExitCode','PathName'))
        Save-Csv 'Inventory/SystemDrivers.csv' @(Get-CimInstance Win32_SystemDriver | Select-Object @('Name','DisplayName','State','StartMode','PathName'))
        Save-Csv 'Inventory/Processes.csv' @(Get-CimInstance Win32_Process | Select-Object @('Name','ProcessId','ParentProcessId','CreationDate','ExecutablePath','CommandLine'))
        Attempt 'Startup commands' { Save-Csv 'Inventory/StartupItems.csv' @(Get-CimInstance Win32_StartupCommand | Select-Object @('Name','Command','Location','User')) }
        Attempt 'Installed products (registry; no Win32_Product)' {
            $products=foreach($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
                Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object { Field $_ 'DisplayName' } |
                    Select-Object @('DisplayName','DisplayVersion','Publisher','InstallDate','InstallLocation','PSChildName')
            }
            Save-Csv 'Inventory/InstalledProducts.csv' @($products)
        }
        Attempt 'Task inventory' {
            $rows=foreach($task in Get-ScheduledTask) {
                $info=$null
                try { $info=$task | Get-ScheduledTaskInfo } catch { }
                [pscustomobject]@{TaskPath=$task.TaskPath; TaskName=$task.TaskName; State=[string]$task.State; LastRunTime=(Field $info 'LastRunTime'); LastTaskResult=(Field $info 'LastTaskResult'); NextRunTime=(Field $info 'NextRunTime'); Principal=($task.Principal | ConvertTo-Json -Compress -Depth 4); Actions=($task.Actions | ConvertTo-Json -Compress -Depth 4); Triggers=($task.Triggers | ConvertTo-Json -Compress -Depth 4)}
            }
            Save-Csv 'Inventory/ScheduledTasks.csv' @($rows)
        }
        Attempt 'Agent binary versions' {
            $agents=Get-CimInstance Win32_Service | Where-Object { $_.Name+' '+$_.DisplayName+' '+$_.PathName -match 'ThreatLocker|Huntress|ConnectWise|ConnectSecure|CentraStage|AEMAgent|ITSPlatform|CagService|Dell|Sense|WinDefend|TPM' }
            $rows=foreach($svc in $agents) {
                $path=[Environment]::ExpandEnvironmentVariables([string]$svc.PathName)
                $exe=$null
                if($path -match '^\s*"([^"]+\.exe)"') { $exe=$Matches[1] }
                elseif($path -match '^\s*(.+?\.exe)(?:\s|$)') { $exe=$Matches[1] }
                $v=$null; $sig=$null
                if($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
                    $v=(Get-Item -LiteralPath $exe).VersionInfo
                    $sig=Get-AuthenticodeSignature -LiteralPath $exe
                }
                [pscustomobject]@{Service=$svc.Name; DisplayName=$svc.DisplayName; State=$svc.State; Executable=$exe; FileVersion=(Field $v 'FileVersion'); Company=(Field $v 'CompanyName'); SignatureStatus=[string](Field $sig 'Status')}
            }
            Save-Csv 'Inventory/AgentVersions.csv' @($rows)
        }
    }
    Run-Collector 'Updates, reboot indicators and configuration' {
        Attempt 'Update history' {
            $session=New-Object -ComObject Microsoft.Update.Session
            $search=$session.CreateUpdateSearcher(); $total=$search.GetTotalHistoryCount()
            $take=[math]::Min($total,10000)
            Save-Json 'Inventory/UpdateHistoryCoverage.json' @{Available=$total; Read=$take; Capped=($total -gt $take)}
            $rows=@()
            if($take -gt 0) {
                $names=@{0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWithErrors';4='Failed';5='Aborted'}
                $rows=@(foreach($u in $search.QueryHistory(0,$take)) {
                    if($u.Date -lt $C.Start) { continue }
                    $kb=([regex]::Matches([string]$u.Title,'KB\d{6,8}') | ForEach-Object {$_.Value}) -join ';'
                    [pscustomobject]@{DateAsReturned=$u.Date.ToString('o'); Title=$u.Title; KB=$kb; Result=$names[[int]$u.ResultCode]; Operation=[int]$u.Operation; HResult=('0x'+[Convert]::ToString([int32]$u.HResult,16).PadLeft(8,'0')); UpdateId=$u.UpdateIdentity.UpdateID; ClientApplicationID=$u.ClientApplicationID}
                })
            }
            Save-Csv 'Inventory/UpdateHistory.csv' $rows
        }
        Attempt 'Hotfix inventory' { Save-Csv 'Inventory/Hotfixes.csv' @(Get-HotFix | Select-Object @('HotFixID','Description','InstalledOn','InstalledBy')) }
        Attempt 'Defender status' { Save-Json 'Inventory/DefenderStatus.json' (Get-MpComputerStatus | Select-Object * -ExcludeProperty @('CimClass','CimInstanceProperties','CimSystemProperties')) }
        Attempt 'Defender scheduling' { Save-Json 'Inventory/DefenderSettings.json' (Get-MpPreference | Select-Object @('ScanScheduleDay','ScanScheduleTime','ScanParameters','ScanAvgCPULoadFactor','DisableCpuThrottleOnIdleScans','RandomizeScheduleTaskTimes','DisableCatchupQuickScan','DisableCatchupFullScan','DisableRealtimeMonitoring','DisableBehaviorMonitoring')) }
        $keys=@{
            CBS='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            WindowsUpdate='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        }
        $pending=@{}; foreach($k in $keys.Keys) { $pending[$k]=Test-Path $keys[$k] }
        $rename=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
        $pending.PendingFileRenameOperations=Field $rename 'PendingFileRenameOperations'
        Save-Json 'Inventory/PendingReboot.json' $pending
        foreach($spec in @(
            @('ServiceTimeouts','HKLM:\SYSTEM\CurrentControlSet\Control'),
            @('FastStartup','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'),
            @('WindowsUpdatePolicy','HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'),
            @('WindowsUpdateAUPolicy','HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'),
            @('OSVersion','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        )) {
            Attempt $spec[0] { Save-Json "Inventory/$($spec[0]).json" (Get-ItemProperty -LiteralPath $spec[1] | Select-Object * -ExcludeProperty @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) }
        }
        Attempt 'TPM status' { Save-Json 'Inventory/TPM.json' (Get-Tpm | Select-Object @('TpmPresent','TpmReady','TpmEnabled','TpmActivated','ManufacturerIdTxt','ManufacturerVersion','AutoProvisioning','LockedOut','LockoutCount','RestartPending')) }
        Attempt 'Power scheme' { Native-Text 'powercfg.exe' @('/GETACTIVESCHEME') 'Inventory/PowerScheme.txt' }
        Attempt 'Filter drivers' { Native-Text 'fltmc.exe' @('filters') 'Inventory/FilterDrivers.txt' }
    }
    Run-Collector 'Network and identity state' {
        Attempt 'Network adapters' { Save-Csv 'Inventory/NetworkAdapters.csv' @(Get-NetAdapter | Select-Object @('Name','InterfaceDescription','Status','LinkSpeed','DriverInformation','DriverFileName','DriverVersion','DriverDate')) }
        Attempt 'IP configuration' { Get-NetIPConfiguration -Detailed | Format-List * | Out-String -Width 240 | Set-Content (Join-Path $C.Root 'Inventory/IPConfiguration.txt') }
        Attempt 'DNS servers' { Save-Csv 'Inventory/DNSServers.csv' @(Get-DnsClientServerAddress | Select-Object @('InterfaceAlias','AddressFamily','ServerAddresses')) }
        Attempt 'Device join' { Native-Text 'dsregcmd.exe' @('/status') 'Inventory/DeviceJoin.txt' }
        Attempt 'Computer policy' { Native-Text 'gpresult.exe' @('/scope','computer','/r') 'Inventory/ComputerPolicy.txt' }
        Attempt 'Machine certificate expiry' { Save-Csv 'Inventory/CertificateExpiry.csv' @(Get-ChildItem Cert:\LocalMachine\My | Select-Object @('Subject','Issuer','Thumbprint','NotBefore','NotAfter','HasPrivateKey')) }
    }

    $channels=@(
        'System','Application','Setup',
        'Microsoft-Windows-Diagnostics-Performance/Operational',
        'Microsoft-Windows-WindowsUpdateClient/Operational',
        'Microsoft-Windows-Servicing/Operational',
        'Microsoft-Windows-User Profiles Service/Operational',
        'Microsoft-Windows-GroupPolicy/Operational',
        'Microsoft-Windows-Winlogon/Operational',
        'Microsoft-Windows-Shell-Core/Operational',
        'Microsoft-Windows-AppReadiness/Admin','Microsoft-Windows-AppReadiness/Operational',
        'Microsoft-Windows-AppXDeploymentServer/Operational',
        'Microsoft-Windows-AppModel-Runtime/Admin',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-CodeIntegrity/Operational',
        'Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/Packaged app-Execution',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin',
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational',
        'Microsoft-Windows-AAD/Operational','Microsoft-Windows-User Device Registration/Admin',
        'Microsoft-Windows-NetworkProfile/Operational','Microsoft-Windows-WLAN-AutoConfig/Operational',
        'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
        'Microsoft-Windows-Kernel-Boot/Operational'
    )
    Run-Collector 'Discover vendor event channels' {
        $found=foreach($pattern in '*ThreatLocker*','*Huntress*','*ConnectWise*','*ConnectSecure*','*Dell*') {
            Get-WinEvent -ListLog $pattern -ErrorAction SilentlyContinue | Select-Object @('LogName','IsEnabled','RecordCount','LogType')
        }
        Save-Csv 'Inventory/VendorChannels.csv' @($found | Sort-Object LogName -Unique)
    }
    if(Test-Path (Join-Path $root 'Inventory/VendorChannels.csv')) {
        $channels+=@(Import-Csv (Join-Path $root 'Inventory/VendorChannels.csv') | Where-Object { $_.LogType -notmatch 'Analytic|Debug' } | Select-Object -ExpandProperty LogName)
    }
    if($IncludeSecurityLog) { $channels+='Security' }
    $eventCollector={
        $logName=$C.Channel
        $stem=$logName -replace '[^a-zA-Z0-9._-]','_'
        $coverage=[ordered]@{Log=$logName; Status='NotRead'; IsEnabled=$null; AvailableRecords=$null; LogFileBytes=$null; OldestRetainedUTC=$null; NewestRetainedUTC=$null; HistoryCapped=$false; IncidentCapped=$false; Collected=0; XMLFailures=0; MessageFailures=0; EVTX='NotRequested'; Detail=''}
        try {
            $log=Get-WinEvent -ListLog $logName -ErrorAction Stop
            $coverage.IsEnabled=$log.IsEnabled; $coverage.AvailableRecords=$log.RecordCount; $coverage.LogFileBytes=$log.FileSize
            foreach($oldest in @($true,$false)) {
                try {
                    $edge=Get-WinEvent -LogName $logName -MaxEvents 1 -Oldest:$oldest -ErrorAction Stop
                    if($oldest) { $coverage.OldestRetainedUTC=$edge.TimeCreated.ToUniversalTime().ToString('o') }
                    else { $coverage.NewestRetainedUTC=$edge.TimeCreated.ToUniversalTime().ToString('o') }
                } catch { }
            }
            $all=New-Object 'System.Collections.Generic.List[object]'
            $windows=@(@{Name='History';From=$C.Start;To=$C.End;Limit=$C.MaxEvents},@{Name='Incident';From=$C.IncidentStart;To=$C.IncidentEnd;Limit=$C.MaxIncident})
            if($logName -eq 'Security') { $windows=@($windows[1]) }
            foreach($window in $windows) {
                $filter=@{LogName=$logName;StartTime=$window.From;EndTime=$window.To}
                if($logName -eq 'Security') { $filter.Id=4624,4625,4634,4647,4800,4801 }
                try { $batch=@(Get-WinEvent -FilterHashtable $filter -MaxEvents ($window.Limit+1) -ErrorAction Stop) }
                catch {
                    if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $batch=@() }
                    else { throw }
                }
                if($batch.Count -gt $window.Limit) { $coverage[($window.Name+'Capped')]=$true }
                foreach($event in ($batch | Select-Object -First $window.Limit)) { $all.Add($event) }
            }
            $events=@($all.ToArray() | Sort-Object RecordId -Unique)
            $settings=New-Object System.Xml.XmlWriterSettings
            $settings.Encoding=New-Object System.Text.UTF8Encoding($false)
            $writer=[Xml.XmlWriter]::Create((Join-Path $C.Root "Events/$stem.xml"),$settings)
            $flat=New-Object 'System.Collections.Generic.List[object]'
            try {
                $writer.WriteStartDocument(); $writer.WriteStartElement('Events')
                foreach($event in $events) {
                    $data=[ordered]@{}; $raw=''
                    try {
                        $raw=$event.ToXml(); $writer.WriteRaw($raw)
                        $xml=[xml]$raw; $index=0
                        foreach($node in $xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*')) {
                            $name=$node.GetAttribute('Name'); if(-not $name) { $name="Data$index" }
                            if($data.Contains($name)) { $name="$name-$index" }
                            $data[$name]=$node.InnerText; $index++
                        }
                    } catch { $coverage.XMLFailures++ }
                    $message=''
                    try { $message=[string]$event.Message } catch { $coverage.MessageFailures++ }
                    $loggedUTC=$event.TimeCreated.ToUniversalTime().ToString('o')
                    $incidentUTC=$null; $timeBasis='Logged time'; $incidentField=$null
                    if($logName -eq 'Microsoft-Windows-Diagnostics-Performance/Operational') {
                        foreach($candidate in 'BootStartTime','ShutdownStartTime','StartTime') {
                            if($data.Contains($candidate)) {
                                $parsed=[datetimeoffset]::MinValue
                                if([datetimeoffset]::TryParse([string]$data[$candidate],[globalization.cultureinfo]::InvariantCulture,[globalization.datetimestyles]::AssumeUniversal,[ref]$parsed)) {
                                    $incidentUTC=$parsed.UtcDateTime.ToString('o'); $timeBasis='Event incident time'; $incidentField=$candidate; break
                                }
                            }
                        }
                    }
                    $flat.Add([pscustomobject]@{
                        Computer=$event.MachineName; Log=$logName; Provider=$event.ProviderName; Id=$event.Id
                        RecordId=$event.RecordId; LevelNumber=$event.Level; LevelName=$event.LevelDisplayName
                        LoggedLocal=$event.TimeCreated.ToString('o'); LoggedUTC=$loggedUTC
                        IncidentUTC=$incidentUTC; IncidentField=$incidentField
                        TimelineUTC=$(if($incidentUTC){$incidentUTC}else{$loggedUTC}); TimeBasis=$timeBasis
                        BootTimeMs=$data['BootTime']; MainPathBootTimeMs=$data['MainPathBootTime']; PostBootTimeMs=$data['BootPostBootTime']
                        ShutdownTimeMs=$data['ShutdownTime']; TotalTimeMs=$data['TotalTime']; DegradationTimeMs=$data['DegradationTime']
                        Name=$data['Name']; FriendlyName=$data['FriendlyName']; Path=$data['Path']
                        ReportId=$data['ReportId']; EventDataJson=(ConvertTo-Json -InputObject $data -Compress -Depth 6)
                        Message=$message
                    })
                }
                $writer.WriteEndElement(); $writer.WriteEndDocument()
            } finally { $writer.Dispose() }
            Save-Csv "Events/$stem.csv" $flat.ToArray()
            $coverage.Collected=$events.Count
            $coverage.Status=if($events.Count){'Collected'}else{'NoMatches'}
            if(-not $log.IsEnabled) { $coverage.Detail='Channel disabled; retained records may exist, but new incidents may not be recorded.' }
            if($C.IncludeEvtx -and $logName -ne 'Security') {
                if($null -eq $log.FileSize -or $log.FileSize -gt ($C.MaxEvtxMB*1048576)) { $coverage.EVTX='Skipped: source size unknown or exceeds MaxEvtxSourceMB' }
                else {
                    $from=$C.IncidentStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    $to=$C.IncidentEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    $query="*[System[TimeCreated[@SystemTime >= '$from' and @SystemTime <= '$to']]]"
                    $export=Join-Path $C.Root "Events/$stem.evtx"
                    $result=& wevtutil.exe epl $logName $export "/q:$query" '/ow:false' 2>&1
                    if($LASTEXITCODE -ne 0) { $coverage.EVTX='Failed: '+($result -join ' ') } else { $coverage.EVTX='Incident window exported' }
                }
            }
        } catch { $coverage.Status='UnavailableOrFailed'; $coverage.Detail=$_.Exception.Message }
        finally { Save-Json "Status/$stem.coverage.json" $coverage }
    }
    foreach($channel in ($channels | Select-Object -Unique)) {
        Run-Collector "Events: $channel" $eventCollector @{Channel=$channel}
    }

    Run-Collector 'Servicing logs, crash metadata and selected evidence' {
        $ledger=New-Object 'System.Collections.Generic.List[object]'
        $script:copiedBytes=0L; $script:fileIndex=0
        function Copy-Evidence([IO.FileInfo]$File,[string]$Category,[bool]$AllowTail) {
            $script:fileIndex++
            $name='{0:D4}-{1}' -f $script:fileIndex,($File.Name -replace '[^a-zA-Z0-9._-]','_')
            $target=Join-Path $C.Root "$Category/$name"
            $action='Skipped'; $reason=''; $bytes=0L
            try {
                if($File.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point skipped.' }
                if($File.Length -le ($C.MaxLogMB*1048576) -and ($script:copiedBytes+$File.Length) -le ($C.MaxLogsMB*1048576)) {
                    Copy-Item -LiteralPath $File.FullName -Destination $target
                    $action='Copied'
                } elseif($AllowTail -and $script:copiedBytes -lt ($C.MaxLogsMB*1048576)) {
                    # Read a bounded byte tail, not an unbounded line or entire file.
                    $budget=[int][math]::Min(1048576,($C.MaxLogsMB*1048576)-$script:copiedBytes)
                    $stream=[IO.File]::Open($File.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                    try {
                        $amount=[int][math]::Min($stream.Length,$budget); [void]$stream.Seek(-$amount,[IO.SeekOrigin]::End)
                        $buffer=New-Object byte[] $amount; $got=0
                        while($got -lt $amount) { $n=$stream.Read($buffer,$got,$amount-$got); if($n -eq 0){break}; $got+=$n }
                        $target+='.tail.bin'; $out=[IO.File]::Create($target)
                        try { $out.Write($buffer,0,$got) } finally { $out.Dispose() }
                    } finally { $stream.Dispose() }
                    $action='TailOnly'; $reason='Size/budget limit: final bytes preserved; may begin mid-line or mid-character. Open with original log encoding.'
                } else { $reason='File or total attachment size budget exceeded.' }
                if(Test-Path -LiteralPath $target) { $bytes=(Get-Item -LiteralPath $target).Length; $script:copiedBytes+=$bytes }
            } catch { $reason=$_.Exception.Message }
            $ledger.Add([pscustomobject]@{Source=$File.FullName; SourceLength=$File.Length; LastWriteUTC=$File.LastWriteTimeUtc.ToString('o'); Action=$action; SavedAs=$(if($bytes){$target.Substring($C.Root.Length+1)}else{''}); SavedBytes=$bytes; Detail=$reason})
        }
        function Local-Files([string]$Path,[int]$Depth=0) {
            if($Path.StartsWith('\\')) { throw 'Only local evidence paths are supported.' }
            $item=Get-Item -LiteralPath $Path -ErrorAction Stop
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
            if(-not $item.PSIsContainer) { $item; return }
            foreach($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) {
                if($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if($child.PSIsContainer) { if($Depth -lt 3) { Local-Files $child.FullName ($Depth+1) } }
                else { $child }
            }
        }
        foreach($path in @((Join-Path $env:windir 'Logs\CBS'),(Join-Path $env:windir 'Logs\DISM'),(Join-Path $env:windir 'Panther'))) {
            Attempt "Text logs: $path" {
                foreach($f in Get-ChildItem -LiteralPath $path -File | Where-Object { $_.Extension -in '.log','.txt' -and $_.LastWriteTime -ge $C.Start }) { Copy-Evidence $f 'Logs' $true }
            }
        }
        foreach($path in $C.AgentPaths) {
            Attempt "Agent logs: $path" {
                foreach($f in Local-Files $path | Where-Object { $_.Extension -in '.log','.txt' -and $_.LastWriteTime -ge $C.Start }) { Copy-Evidence $f 'Logs' $true }
            }
        }
        foreach($path in $C.EvidencePaths) {
            Attempt "External evidence: $path" {
                foreach($f in Local-Files $path) {
                    if($f.Extension -in '.csv','.json','.txt','.log','.evtx','.etl') { Copy-Evidence $f 'Evidence' ($f.Extension -in '.log','.txt') }
                }
            }
        }
        Attempt 'WER reports' {
            $reports=foreach($path in @((Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),(Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'))) {
                if(Test-Path -LiteralPath $path) { Local-Files $path | Where-Object { $_.Name -eq 'Report.wer' -and $_.LastWriteTime -ge $C.Start } }
            }
            foreach($f in ($reports | Sort-Object LastWriteTime -Descending | Select-Object -First 100)) { Copy-Evidence $f 'Logs' $true }
            Save-Json 'Inventory/WERCoverage.json' @{AvailableRecent=@($reports).Count; Cap=100; Capped=(@($reports).Count -gt 100)}
        }
        Attempt 'Dump file metadata only' {
            $dumps=@(foreach($path in @((Join-Path $env:windir 'Minidump'),(Join-Path $env:windir 'LiveKernelReports'))) {
                if(Test-Path $path) { Local-Files $path | Where-Object {$_.Extension -eq '.dmp'} }
            })
            if(Test-Path (Join-Path $env:windir 'MEMORY.DMP')) { $dumps+=Get-Item (Join-Path $env:windir 'MEMORY.DMP') }
            Save-Csv 'Inventory/DumpMetadata.csv' @($dumps | Select-Object @('FullName','Length','CreationTimeUtc','LastWriteTimeUtc'))
        }
        Save-Csv 'EvidenceFiles.csv' $ledger.ToArray()
    }
    if($IncludeWindowsUpdateLog) {
        Run-Collector 'Decode Windows Update ETL' {
            Get-WindowsUpdateLog -LogPath (Join-Path $C.Root 'Logs/WindowsUpdate.log') -ErrorAction Stop | Out-Null
        } @{} ([math]::Max(600,$CollectorTimeoutSeconds))
    }
    if($IncludeHealthScans) {
        foreach($scan in @(
            @{Name='DISM-CheckHealth';Exe='dism.exe';Args=@('/Online','/Cleanup-Image','/CheckHealth')},
            @{Name='DISM-ScanHealth';Exe='dism.exe';Args=@('/Online','/Cleanup-Image','/ScanHealth')},
            @{Name='SFC-VerifyOnly';Exe='sfc.exe';Args=@('/verifyonly')}
        )) {
            # Native scan runs in foreground; do not abandon/kill the Windows servicing
            # process at a generic collector deadline. Native output shows progress.
            Write-Host "Running $($scan.Name); this optional check can take several minutes."
            $begin=Get-Date; $outcome='Completed'; $detail=''
            try {
                $exe=Join-Path $env:windir ('System32\'+$scan.Exe); $arguments=$scan.Args
                & $exe @arguments 2>&1 | Tee-Object -FilePath (Join-Path $root "Logs/$($scan.Name).txt") | Out-Host
                $detail="Native exit code: $LASTEXITCODE. Read the scan text for its interpretation."
                if($LASTEXITCODE -ne 0) { $outcome='ReviewNativeResult' }
            } catch { $outcome='Failed'; $detail=$_.Exception.Message }
            $record=[pscustomobject]@{Collector=$scan.Name;Status=$outcome;StartedUTC=$begin.ToUniversalTime().ToString('o');Seconds=[math]::Round(((Get-Date)-$begin).TotalSeconds,1);Detail=$detail}
            $status.Add($record)
            $record | ConvertTo-Json -Compress | Add-Content (Join-Path $root 'Status/Collectors.jsonl') -Encoding UTF8
        }
    }

    Write-Host 'Building evidence timeline and report...'
    $coverage=@(Get-ChildItem (Join-Path $root 'Status') -Filter '*.coverage.json' | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json })
    $coverage | Export-Csv (Join-Path $root 'CollectionCoverage.csv') -NoTypeInformation -Encoding UTF8
    $status.ToArray() | Export-Csv (Join-Path $root 'CollectorStatus.csv') -NoTypeInformation -Encoding UTF8
    $events=@(Get-ChildItem (Join-Path $root 'Events') -Filter '*.csv' | ForEach-Object { Import-Csv $_.FullName })
    # Sort UTC instants, not displayed local times. Keep logged time beside incident time.
    $events | Sort-Object -Property @('TimelineUTC','Log','RecordId') | Export-Csv (Join-Path $root 'CorrelatedTimeline.csv') -NoTypeInformation -Encoding UTF8
    $incidentFrom=$IncidentStart.ToUniversalTime().ToString('o'); $incidentTo=$IncidentEnd.ToUniversalTime().ToString('o')
    $incidentEvents=@($events | Where-Object {$_.TimelineUTC -ge $incidentFrom -and $_.TimelineUTC -le $incidentTo})
    $incidentEvents | Sort-Object -Property @('TimelineUTC','Log','RecordId') | Export-Csv (Join-Path $root 'IncidentTimeline.csv') -NoTypeInformation -Encoding UTF8
    $perf=@($events | Where-Object {$_.Provider -eq 'Microsoft-Windows-Diagnostics-Performance'})
    $boots=@($perf | Where-Object {$_.Id -eq '100'} | Sort-Object TimelineUTC -Descending)
    $shutdowns=@($perf | Where-Object {$_.Id -eq '200'} | Sort-Object TimelineUTC -Descending)
    $offenders=@($perf | Where-Object {[int]$_.Id -ge 101 -and [int]$_.Id -le 299 -and $_.Id -ne '200'} | Sort-Object {[double]($_.DegradationTimeMs)} -Descending)
    $boots | Export-Csv (Join-Path $root 'BootMeasurements.csv') -NoTypeInformation -Encoding UTF8
    $shutdowns | Export-Csv (Join-Path $root 'ShutdownMeasurements.csv') -NoTypeInformation -Encoding UTF8
    $offenders | Export-Csv (Join-Path $root 'StartupShutdownContributors.csv') -NoTypeInformation -Encoding UTF8
    $restart=@($events | Where-Object {
        ($_.Provider -eq 'User32' -and $_.Id -eq '1074') -or
        ($_.Provider -eq 'Microsoft-Windows-Kernel-General' -and $_.Id -in '12','13') -or
        ($_.Provider -eq 'EventLog' -and $_.Id -in '6005','6006','6008') -or
        ($_.Provider -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq '41')
    })
    $restart | Sort-Object TimelineUTC | Export-Csv (Join-Path $root 'RestartTimeline.csv') -NoTypeInformation -Encoding UTF8
    $crashes=@($events | Where-Object { $_.Log -eq 'Application' -and $_.Provider -in 'Application Error','Application Hang','.NET Runtime','Windows Error Reporting' })
    $crashes | Export-Csv (Join-Path $root 'CrashesAndWER.csv') -NoTypeInformation -Encoding UTF8
    $serviceErrors=@($events | Where-Object {$_.Provider -eq 'Service Control Manager' -and $_.Id -in '7000','7001','7009','7011','7022','7023','7024','7031','7034','7043'})
    $serviceErrors | Export-Csv (Join-Path $root 'ServiceFailures.csv') -NoTypeInformation -Encoding UTF8
    $policy=@($events | Where-Object {$_.Log -match 'AppLocker|CodeIntegrity|ThreatLocker'})
    $policy | Export-Csv (Join-Path $root 'PolicyEvents.csv') -NoTypeInformation -Encoding UTF8
    $findings=New-Object 'System.Collections.Generic.List[object]'
    function Finding($Category,$Evidence,$Meaning,$Next) { $findings.Add([pscustomobject]@{Category=$Category;Evidence=$Evidence;Interpretation=$Meaning;NextStep=$Next}) }
    if(-not $isAdmin) { Finding 'Coverage' 'Collector not elevated.' 'Some sources may be inaccessible.' 'Review collection errors and rerun elevated if needed.' }
    $gaps=@($coverage | Where-Object {$_.Status -ne 'Collected' -or $_.HistoryCapped -or $_.IncidentCapped -or $_.IsEnabled -eq $false -or $_.XMLFailures -gt 0 -or $_.MessageFailures -gt 0})
    if($gaps.Count) { Finding 'Coverage' "$($gaps.Count) channels have missing/empty/disabled/capped data or conversion gaps." 'NoMatches is not proof that the endpoint was healthy. Retention and collection limits constrain conclusions.' 'Review CollectionCoverage.csv; narrow the incident or raise caps only for a concrete missing interval.' }
    $failures=@($status.ToArray() | Where-Object {$_.Status -ne 'Completed'})
    if($failures.Count) { Finding 'Coverage' "$($failures.Count) collectors failed or timed out." 'The report is partial.' 'Read CollectorStatus.csv and Status/SectionErrors.jsonl.' }
    if(Test-Path (Join-Path $root 'Status/SectionErrors.jsonl')) { Finding 'Coverage' 'One or more inventory subsections failed.' 'Other subsections may still have completed.' 'Read Status/SectionErrors.jsonl for exact sources and errors.' }
    if($boots.Count) {
        $b=$boots[0]
        Finding 'Measured timing' ("Latest retained boot: {0} UTC; reported duration {1} seconds; logged {2}." -f $b.TimelineUTC,([math]::Round(([double]$b.BootTimeMs/1000),2)),$b.LoggedUTC) 'Boot timing does not cover every firmware/offline-servicing/user-perceived delay. Main/post-boot and application times overlap.' 'Compare RestartTimeline.csv, incident timing, BootMeasurements.csv and current resource samples.'
    } else { Finding 'Coverage' 'No boot event 100 was retained in the collected windows.' 'A measured boot phase split is unavailable.' 'Use restart markers and capture a boot trace for a reproducible unresolved delay.' }
    if($offenders.Count) {
        $labels=($offenders | Select-Object -First 5 | ForEach-Object { '{0} ({1}ms, incident {2})' -f $_.Name,$_.TotalTimeMs,$_.TimelineUTC }) -join '; '
        Finding 'Measured contributors' $labels 'Windows reported delayed startup/shutdown components. This is not proof that they caused all slowness; never sum these durations.' 'Compare contributors for the SAME incident and against the other affected machine.'
    }
    if($serviceErrors.Count) { Finding 'Service failures' "$($serviceErrors.Count) service-failure/timeout records collected." 'Multiple records or configured timeout values do not directly measure total elapsed delay.' 'Review ServiceFailures.csv, executable versions and current service state; correlate with restart phase.' }
    $blocks=@($policy | Where-Object {($_.Log -match 'CodeIntegrity' -and $_.Id -eq '3077') -or ($_.Log -match 'AppLocker' -and $_.Id -in '8004','8007','8022','8025','8029','8036','8040')})
    if($blocks.Count) { Finding 'Policy enforcement' "$($blocks.Count) enforcement-related events collected." 'Check exact target, caller and policy; script enforcement can restrict execution rather than block it entirely. Audit-only events are not denials.' 'Match the patch-agent error timestamp and user/caller before changing an application rule.' }
    $patchErrors=@($events | Where-Object {$_.Message -match 'no shell executor|cmd\.exe and powershell\.exe are blocked|Assessment failed'})
    if($patchErrors.Count) { Finding 'Patch assessment' "$($patchErrors.Count) patch assessment/shell-access failure messages collected." 'An agent reports failure; this alone does not identify the enforcing product or prove the delay mechanism.' 'Correlate caller/user/target with ThreatLocker Unified Audit and the patch job logs.' }
    $storageErrors=@($events | Where-Object {$_.Log -eq 'System' -and $_.LevelNumber -in '1','2','3' -and $_.Provider -match '(^disk$|Ntfs|storahci|stornvme|storport|iaStor|WHEA)'})
    if($storageErrors.Count) { Finding 'Storage/hardware evidence' "$($storageErrors.Count) storage/controller/hardware warning/error records collected." 'Provider and event details matter; a normal SMART report does not exclude intermittent faults.' 'Correlate actual I/O resets/retries with disk samples, driver versions and the incident.' }
    $volumePath=Join-Path $root 'Inventory/Volumes.csv'
    if(Test-Path $volumePath) {
        $low=@(Import-Csv $volumePath | Where-Object { $_.Size -and [double]$_.Size -gt 0 -and ([double]$_.SizeRemaining/[double]$_.Size) -lt 0.15 })
        if($low.Count) { Finding 'Capacity' ("Volumes below 15% free: {0}" -f (($low | ForEach-Object { $_.DriveLetter+': '+[math]::Round([double]$_.SizeRemaining/1073741824,1)+' GB' }) -join '; ')) 'Low space can constrain updates and paging, but this threshold alone is not a cause.' 'Check the Windows volume and servicing errors before choosing a cleanup action.' }
    }
    $updateCoveragePath=Join-Path $root 'Inventory/UpdateHistoryCoverage.json'
    if(Test-Path $updateCoveragePath) {
        $updateCoverage=Get-Content $updateCoveragePath -Raw | ConvertFrom-Json
        if($updateCoverage.Capped) { Finding 'Coverage' 'Windows Update COM history exceeded 10,000 records.' 'Older history was not read.' 'Use raw update/Setup events and focused vendor job history for the missing interval.' }
    }
    $wuPath=Join-Path $root 'Inventory/UpdateHistory.csv'
    if(Test-Path $wuPath) {
        $bad=@(Import-Csv $wuPath | Where-Object {$_.Result -in 'Failed','Aborted','SucceededWithErrors'})
        if($bad.Count) { Finding 'Update history' "$($bad.Count) non-success update history entries." 'Aborted scans/updates during a restart are not automatically a failed cumulative update or rollback.' 'Match KB/UpdateId/HRESULT and time with Setup/CBS/update events.' }
    }
    Finding 'ThreatLocker visibility' 'Windows AppLocker/CodeIntegrity logs do not substitute for ThreatLocker cloud audit.' 'A portal denial, Ringfencing event or vendor-side performance issue can exist without a Windows policy event.' 'Export Unified Audit for the incident (note timezone), including computer, user, caller, target, action and matched policy; attach with ExternalEvidencePath.'
    Finding 'Crash interpretation' 'Crash and WER records are retained with RecordId, ReportId, raw XML and dump metadata.' 'A queued/archived WER report can be logged long after the incident. Repeated ReportIds and old dump names are not independent new crashes.' 'Correlate Application Error/.NET events with Report.wer and dump timestamps.'
    if(-not $IncludeDefenderTrace) { Finding 'Optional capture' 'No Defender performance trace requested.' 'Slow MsMpEng startup is not proof of expensive scanning. Current scan work needs a recording during the symptom.' 'Run with IncludeDefenderTrace while slow, or attach a separately recorded ETL.' }
    $findings.ToArray() | Export-Csv (Join-Path $root 'Findings.csv') -NoTypeInformation -Encoding UTF8

    function Html($value) { [Net.WebUtility]::HtmlEncode([string]$value) }
    function Table($rows,$properties) {
        if(@($rows).Count -eq 0) { return '<p>No records collected.</p>' }
        $head=($properties | ForEach-Object {'<th>'+(Html $_)+'</th>'}) -join ''
        $body=foreach($row in $rows) { '<tr>'+ (($properties | ForEach-Object {'<td>'+(Html $row.$_)+'</td>'}) -join '')+'</tr>' }
        '<table><thead><tr>'+$head+'</tr></thead><tbody>'+($body -join '')+'</tbody></table>'
    }
    $html=@"
<!doctype html><html><head><meta charset="utf-8"><title>Windows delay diagnostics</title>
<style>body{font:15px Segoe UI,Arial,sans-serif;margin:32px;color:#182334;max-width:1500px}h1{color:#174e75}table{border-collapse:collapse;width:100%;margin:15px 0;font-size:13px}td,th{border:1px solid #cad3dc;padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef3f7}p{line-height:1.5}.note{background:#fff4d8;padding:14px}</style></head><body>
<h1>Windows restart and slowness diagnostics</h1>
<p>Computer: <b>$(Html $env:COMPUTERNAME)</b> | Version 2.0 | Collected: $(Html $started.ToString('o')) | Timezone: $(Html ([TimeZoneInfo]::Local.Id)) | Elevated: $isAdmin</p>
<p>Focused incident: $(Html $IncidentStart.ToString('o')) through $(Html $IncidentEnd.ToString('o')). Historical start: $(Html $historyStart.ToString('o')).</p>
<p class="note">This is evidence and investigation guidance, not an automatic root-cause verdict. Disabled logs, retention, caps, delayed reporting and unrecorded firmware/offline activity limit conclusions. No security or repair configuration was changed. Optional collection itself creates workload.</p>
<h2>Findings and next checks</h2>$(Table $findings.ToArray() @('Category','Evidence','Interpretation','NextStep'))
<h2>Latest boot measurements (milliseconds)</h2>$(Table @($boots | Select-Object -First 10) @('IncidentUTC','LoggedUTC','BootTimeMs','MainPathBootTimeMs','PostBootTimeMs'))
<h2>Latest shutdown measurements (milliseconds)</h2>$(Table @($shutdowns | Select-Object -First 10) @('IncidentUTC','LoggedUTC','ShutdownTimeMs'))
<p>Use incident time when present, not report creation time. Application measurements overlap with total boot; do not add them together.</p>
<h2>Collection coverage</h2>$(Table $coverage @('Log','Status','IsEnabled','Collected','HistoryCapped','IncidentCapped','OldestRetainedUTC','NewestRetainedUTC','EVTX','Detail'))
<h2>Collector completion</h2>$(Table $status.ToArray() @('Collector','Status','Seconds','Detail'))
<h2>How to use the evidence</h2><p>Start with IncidentTimeline.csv and RestartTimeline.csv. Read the matching raw Events XML/CSV before assigning a cause. Compare AgentVersions.csv, service failures, policies and live samples between affected computers. Section-level failures are in Status/SectionErrors.jsonl. External vendor audit must be exported separately.</p>
<p>Live process I/O includes non-disk I/O. Disk percent counters may exceed 100%; use idle time, queue and throughput together. Historical errors do not establish current resource contention. No crash dumps are copied automatically; metadata and bounded WER text are included.</p>
</body></html>
"@
    $htmlPath=Join-Path $root 'WindowsUpdateDelayReport.html'
    $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    @'
READ FIRST
- HTML is a navigation summary. Use IncidentTimeline.csv and Events/* XML/CSV for evidence.
- CollectionCoverage.csv lists retention boundaries, disabled logs and separate history/incident caps.
- CollectorStatus.csv and Status/SectionErrors.jsonl identify failures. Partial files may remain on timeout.
- History and focused windows are combined by channel RecordId. A cap retains newest matching events.
- Event report time may differ from incident time. Boot and shutdown event data preserve both.
- Security log collection is optional and limited to incident logon/logoff/lock events.
- Agent files are opt-in; do not assume Windows logs contain ThreatLocker Unified Audit.
- File size budgets apply to copied text/vendor exports, not event XML or the live trace.
- TailOnly files are bounded byte tails with original encoding, not complete log copies.
- WER report cap is 100. Compressed historical CBS logs and memory dumps are not copied.
- Registry product inventory is machine-wide. Win32_StartupCommand and scheduled tasks are not a complete autoruns inventory.
- Current snapshots do not reproduce a historical slowdown. Live capture should run during symptoms.
- No root cause is inferred solely from event severity, timeout settings, agent coexistence or missing events.
- For unresolved pre-desktop delays, use an approved Windows Performance Recorder boot trace and OEM diagnostics.
- Do not disable protection or broadly allow shells based solely on this report; validate the actual caller/rule and workload.
- Run the same parameters on the second affected machine and compare before/after evidence for any targeted fix.
- This run only wrote report files and optionally collected traces/scanned integrity; it did not perform repairs.
- Native health checks and the timed Defender recording are foreground operations without forced termination; other collectors are bounded.
- Reports include identifiers and command lines: review before sharing externally.
'@ | Set-Content (Join-Path $root 'READ-ME.txt') -Encoding UTF8

    # Manifest every payload file, verify full decompressed contents, then optionally
    # remove ONLY this GUID-named report directory. No weak 'ZIP has an entry' check.
    Write-Host 'Creating and verifying archive...'
    $manifest=@(Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object {
        [pscustomobject]@{RelativePath=$_.FullName.Substring($root.Length+1).Replace('\','/');Length=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    $manifest | Export-Csv (Join-Path $root 'Manifest.csv') -NoTypeInformation -Encoding UTF8
    $zipPath="$root.zip"; $verified=$false; $archiveError=$null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($root,$zipPath,[IO.Compression.CompressionLevel]::Optimal,$false)
        $archive=[IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            if(@($archive.Entries | Where-Object { $_.Name -ne '' }).Count -ne ($manifest.Count+1)) { throw 'Archive entry count does not match payload plus manifest.' }
            $checkFiles=@($manifest)+@([pscustomobject]@{RelativePath='Manifest.csv';Length=(Get-Item (Join-Path $root 'Manifest.csv')).Length;SHA256=(Get-FileHash (Join-Path $root 'Manifest.csv') -Algorithm SHA256).Hash})
            foreach($entryInfo in $checkFiles) {
                $entry=$archive.GetEntry($entryInfo.RelativePath)
                if($null -eq $entry) { $entry=$archive.GetEntry($entryInfo.RelativePath.Replace('/','\')) }
                if($null -eq $entry -or $entry.Length -ne $entryInfo.Length) { throw "Missing or truncated archive entry: $($entryInfo.RelativePath)" }
                $stream=$entry.Open(); $sha=[Security.Cryptography.SHA256]::Create()
                try { $hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
                finally { $stream.Dispose(); $sha.Dispose() }
                if($hash -ne $entryInfo.SHA256) { throw "Archive hash mismatch: $($entryInfo.RelativePath)" }
            }
            $verified=$true
        } finally { $archive.Dispose() }
    } catch { $archiveError=$_.Exception.Message; Write-Warning "Archive not verified; expanded report retained: $archiveError" }
    $folderResult=$root; $htmlResult=$htmlPath
    if($ZipOnly -and $verified) {
        try { Remove-Item -LiteralPath $root -Recurse -Force; $folderResult=$null; $htmlResult=$null }
        catch { Write-Warning "Verified ZIP retained, but report-folder cleanup failed: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ReportFolder=$folderResult;HtmlReport=$htmlResult;ZipFile=$(if(Test-Path $zipPath){$zipPath}else{$null});ZipVerified=$verified;ArchiveError=$archiveError;FindingCount=$findings.Count;CollectorFailures=$failures.Count;Elevated=$isAdmin;Duration=((Get-Date)-$started)}
}

# Dot-sourcing makes the function available; executing the file runs it once.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WindowsUpdateDelayDiagnostics @PSBoundParameters
}


# Extra one-liners, run by hand only (not part of the diagnostics run):
# .\Invoke-WindowsUpdateDelayDiagnostics.ps1 `
#     -DaysBack 5 `
#     -OutputPath C:\Temp `
#     -IncludeDefenderTrace `
#     -IncludeEvtx



#Region: quick extra:
# $since = (Get-Date).AddDays(-5)

# Get-CimInstance Win32_ReliabilityRecords |
#   Where-Object { $_.TimeGenerated -ge $since }


# $start = (Get-Date).AddDays(-5)

# Get-WinEvent -FilterHashtable @{
#     LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
#     StartTime = $start
# } |
# Select-Object TimeCreated, Id, LevelDisplayName, Message |
# Sort-Object TimeCreated |
# Format-List


#region: pass 2
# $since = (Get-Date).AddDays(-3)

# Reliability history: crashes, failures and other recorded changes
# Get-CimInstance Win32_ReliabilityRecords |
#     Where-Object { $_.TimeGenerated -ge $since } |
#     Sort-Object TimeGenerated |
#     Format-List TimeGenerated, SourceName, EventIdentifier, ProductName, Message

# Windows Update activity
# Get-WinEvent -FilterHashtable @{
#     LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
#     StartTime = $since
# } |
#     Sort-Object TimeCreated |
#     Format-List TimeCreated, Id, LevelDisplayName, Message