<#
.SYNOPSIS
    Datto RMM Component - RDS Active Session Monitor
.DESCRIPTION
    Checks active RDS sessions during a defined business window.
    Alerts if active sessions drop to or below the threshold. Skips outside the window.
.NOTES
    Component Type : Script (PowerShell)
    Category       : Monitor
    Optional Env Vars (Datto Variables):
        usrStartHour   - Window start hour, 0-23   (default 8)
        usrEndHour     - Window end hour, 0-23     (default 17)
        usrAllowedDays - Comma-separated day names (default Monday..Friday)
        usrThreshold   - Alert at or below this session count (default 0)
#>

#region Functions

function Get-RdsComponentParameter {
    [CmdletBinding()]
    param()

    $params = @{}

    if ($env:usrStartHour -match '^\d+$') { $params.StartHour = [int]$env:usrStartHour }
    if ($env:usrEndHour   -match '^\d+$') { $params.EndHour   = [int]$env:usrEndHour }
    if ($env:usrThreshold -match '^\d+$') { $params.Threshold = [int]$env:usrThreshold }

    if (-not [string]::IsNullOrWhiteSpace($env:usrAllowedDays)) {
        $days = ($env:usrAllowedDays -split ',').Trim() | Where-Object { $_ }
        if ($days) { $params.AllowedDays = $days }
    }

    $params
}

function Test-RdsMonitoringWindow {
    [CmdletBinding()]
    param(
        [datetime]$Now = (Get-Date),
        [string[]]$AllowedDays = @('Monday','Tuesday','Wednesday','Thursday','Friday'),
        [int]$StartHour = 8,
        [int]$EndHour = 17
    )

    $startTime = $Now.Date.AddHours($StartHour)
    $endTime   = $Now.Date.AddHours($EndHour)

    ($Now.DayOfWeek.ToString() -in $AllowedDays) -and ($Now -ge $startTime) -and ($Now -le $endTime)
}

function Get-RdsActiveSessionCount {
    [CmdletBinding()]
    param(
        [string]$QuserOutput
    )

    if (-not $PSBoundParameters.ContainsKey('QuserOutput')) {
        $QuserOutput = (quser.exe 2>&1 | Out-String)
    }

    if ([string]::IsNullOrWhiteSpace($QuserOutput) -or $QuserOutput -match 'No User exists') {
        return 0
    }

    @($QuserOutput -split "`r?`n" |
        Select-Object -Skip 1 |
        Where-Object { $_.Trim() -ne '' -and $_ -match '\bActive\b' }).Count
}

function Test-RdsSessionHealth {
    [CmdletBinding()]
    param(
        [datetime]$Now = (Get-Date),
        [string[]]$AllowedDays = @('Monday','Tuesday','Wednesday','Thursday','Friday'),
        [int]$StartHour = 8,
        [int]$EndHour = 17,
        [int]$Threshold = 0,
        [string]$QuserOutput
    )

    $inWindow = Test-RdsMonitoringWindow -Now $Now -AllowedDays $AllowedDays -StartHour $StartHour -EndHour $EndHour

    if (-not $inWindow) {
        return [pscustomobject]@{
            Sessions = $null
            Alert    = 'Outside monitoring window. Check skipped.'
            ExitCode = 0
        }
    }

    $countParams = @{}
    if ($PSBoundParameters.ContainsKey('QuserOutput')) { $countParams.QuserOutput = $QuserOutput }
    $activeSessions = Get-RdsActiveSessionCount @countParams

    if ($activeSessions -le $Threshold) {
        return [pscustomobject]@{
            Sessions = $activeSessions
            Alert    = "CRITICAL: Active RDS sessions have dropped to $activeSessions. Potential connection issue."
            ExitCode = 1
        }
    }

    [pscustomobject]@{
        Sessions = $activeSessions
        Alert    = "Success: $activeSessions active RDS session(s)."
        ExitCode = 0
    }
}

function Write-RdsDattoResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Result
    )

    Write-Output '<-Start Diagnostic->'
    Write-Output "Device    : $env:COMPUTERNAME"
    Write-Output "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($null -ne $Result.Sessions) {
        Write-Output "Active RDS Sessions: $($Result.Sessions)"
    }
    else {
        Write-Output 'Active RDS Sessions: n/a (outside monitoring window)'
    }
    Write-Output '<-End Diagnostic->'

    Write-Output '<-Start Result->'
    Write-Output "Alert=$($Result.Alert)"
    Write-Output '<-End Result->'
}

function Invoke-RdsSessionMonitor {
    [CmdletBinding()]
    param()

    try {
        $params = Get-RdsComponentParameter
        $result = Test-RdsSessionHealth @params
    }
    catch {
        $result = [pscustomobject]@{
            Sessions = $null
            Alert    = "ERROR: Session check failed. $($_.Exception.Message)"
            ExitCode = 1
        }
    }

    Write-RdsDattoResult -Result $result
    $result.ExitCode
}

#endregion

#region Entry point
exit (Invoke-RdsSessionMonitor)
#endregion