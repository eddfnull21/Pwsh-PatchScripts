# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    ScreenConnect / ConnectWise Control - Check / Recon (both read-only). RMM-ready.

.DESCRIPTION
    -Mode Check   DEFAULT. Fast. Lists ScreenConnect / ConnectWise Control uninstall entries
                  (machine 32/64-bit and the current user) with version, install date, product
                  code, location and uninstall command.
    -Mode Recon   Deep trace search (Get-ScreenConnectRecon): uninstall entries, Windows
                  Installer records, services (with exe version), processes, their TCP
                  connections, scheduled tasks, firewall rules and registry traces. Prints a
                  summary table; for the full objects with Details, run
                  Get-ScreenConnectRecon @Options yourself after the paste.
                  -Options @{ IncludeFiles = $true }       also walks Program Files, ProgramData,
                                                           Windows\Temp, Public Desktop and the
                                                           current user's AppData/Desktop/Downloads,
                                                           with SHA-256 and signatures (slow)
                  -Options @{ IncludeEventLogs = $true; EventDays = 30 }
                                                           Application/System events (slow)

    Nothing here changes the system. 'Current user' is SYSTEM when run from RMM, so per-user
    traces of other users are only found by Recon's service/process/file checks.
    Not elevated: some services, tasks, firewall rules and folders are unreadable; the output says so.

.EXAMPLE
    Paste the WHOLE script into a PowerShell session (e.g. the RMM's remote shell) or an RMM
    component. The ENTRY POINT at the bottom picks the mode - edit that one line. For an RMM
    component also set $RMM = $true there, so the script exits with the code.

    Invoke-ScreenConnect                                         # Check
    Invoke-ScreenConnect -Mode Recon                             # Deep trace search
    Invoke-ScreenConnect -Mode Recon -Options @{ IncludeFiles = $true; IncludeEventLogs = $true }

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-ScreenConnect returns one; the entry point exits with it only when $RMM = $true):
        0     Nothing found
        1     Error
        2     Check: ScreenConnect installed / Recon: at least one trace found
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region -------------------- Get-ScreenConnectVersion (from ScreenConnect-recon-diagnostic.ps1 + screenconnect.ps1) --------------------

function Get-ScreenConnectVersion {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $Results = Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -match 'ScreenConnect|ConnectWise Control'
        } |
        Select-Object @{
            Name = 'ComputerName'
            Expression = { $env:COMPUTERNAME }
        }, @{
            Name = 'Product'
            Expression = { $_.DisplayName }
        }, @{
            Name = 'Version'
            Expression = { $_.DisplayVersion }
        }, @{
            Name = 'InstalledDate'
            Expression = { $_.InstallDate }
        }, @{
            Name = 'ProductCode'
            Expression = { $_.PSChildName }
        }, @{
            Name = 'InstallLocation'
            Expression = { $_.InstallLocation }
        }, @{
            # from screenconnect.ps1
            Name = 'UninstallString'
            Expression = { $_.UninstallString }
        } |
        Sort-Object Product, Version -Unique

    # Nothing found = no output; the dispatcher prints the message (a string here would be
    # indistinguishable from a result).
    $Results
}

#endregion

#region -------------------- Get-ScreenConnectRecon (from ScreenConnect-recon.ps1) --------------------

function Get-ScreenConnectRecon {
    [CmdletBinding()]
    param(
        [switch]$IncludeFiles,
        [switch]$IncludeEventLogs,
        [ValidateRange(1, 365)][int]$EventDays = 30
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $Pattern = '(?i)ScreenConnect|ConnectWise[\s_-]*Control|ConnectWise[\s_-]*ScreenConnect'

    function Add-ReconResult {
        param(
            [string]$Category,
            [string]$Name,
            [string]$Version,
            [string]$Path,
            [string]$Status,
            [string]$Identifier,
            [object]$Details
        )

        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Category     = $Category
            Name         = $Name
            Version      = $Version
            Path         = $Path
            Status       = $Status
            Identifier   = $Identifier
            Details      = $Details
        }
    }

    # Installed applications: machine and current user, 32-bit and 64-bit
    $UninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($Application in Get-ItemProperty $UninstallPaths) {
        $SearchText = @(
            $Application.DisplayName
            $Application.Publisher
            $Application.InstallLocation
            $Application.InstallSource
            $Application.UninstallString
            $Application.QuietUninstallString
        ) -join ' '

        if ($SearchText -match $Pattern) {
            Add-ReconResult `
                -Category 'InstalledApplication' `
                -Name $Application.DisplayName `
                -Version $Application.DisplayVersion `
                -Path $Application.InstallLocation `
                -Status 'Installed' `
                -Identifier $Application.PSChildName `
                -Details ([pscustomobject]@{
                    Publisher            = $Application.Publisher
                    InstallDate          = $Application.InstallDate
                    InstallSource        = $Application.InstallSource
                    UninstallString      = $Application.UninstallString
                    QuietUninstallString = $Application.QuietUninstallString
                    RegistryPath         = $Application.PSPath
                })
        }
    }

    # Windows Installer records without invoking Win32_Product
    $InstallerPaths = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\*'
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties'
    )

    foreach ($Product in Get-ItemProperty $InstallerPaths) {
        $SearchText = @(
            $Product.ProductName
            $Product.DisplayName
            $Product.Publisher
            $Product.InstallLocation
            $Product.LocalPackage
        ) -join ' '

        if ($SearchText -match $Pattern) {
            Add-ReconResult `
                -Category 'MSIProduct' `
                -Name $(if ($Product.DisplayName) {
                    $Product.DisplayName
                } else {
                    $Product.ProductName
                }) `
                -Version $Product.DisplayVersion `
                -Path $Product.InstallLocation `
                -Status 'Registered' `
                -Identifier $Product.PSChildName `
                -Details ([pscustomobject]@{
                    Publisher       = $Product.Publisher
                    InstallDate     = $Product.InstallDate
                    LocalPackage    = $Product.LocalPackage
                    UninstallString = $Product.UninstallString
                    RegistryPath    = $Product.PSPath
                })
        }
    }

    # Services and service executable versions
    foreach ($Service in Get-CimInstance Win32_Service) {
        $SearchText = @(
            $Service.Name
            $Service.DisplayName
            $Service.PathName
            $Service.Description
        ) -join ' '

        if ($SearchText -match $Pattern) {
            $Executable = $null

            if ($Service.PathName -match '^\s*"([^"]+)"') {
                $Executable = $Matches[1]
            }
            elseif ($Service.PathName -match '^\s*(.+?\.exe)(?:\s|$)') {
                $Executable = $Matches[1].Trim('"')
            }

            $FileVersion = $null
            $ProductVersion = $null

            if ($Executable -and (Test-Path -LiteralPath $Executable)) {
                $VersionInfo = (Get-Item -LiteralPath $Executable).VersionInfo
                $FileVersion = $VersionInfo.FileVersion
                $ProductVersion = $VersionInfo.ProductVersion
            }

            Add-ReconResult `
                -Category 'Service' `
                -Name $Service.DisplayName `
                -Version $(if ($ProductVersion) {
                    $ProductVersion
                } else {
                    $FileVersion
                }) `
                -Path $Executable `
                -Status $Service.State `
                -Identifier $Service.Name `
                -Details ([pscustomobject]@{
                    StartMode   = $Service.StartMode
                    StartName   = $Service.StartName
                    ProcessId   = $Service.ProcessId
                    CommandLine = $Service.PathName
                    Description = $Service.Description
                })
        }
    }

    # Running processes
    $MatchingProcessIds = @()

    foreach ($Process in Get-CimInstance Win32_Process) {
        # Our own command line can contain 'ScreenConnect' (script name, -Command text).
        if ($Process.ProcessId -eq $PID) { continue }

        $SearchText = @(
            $Process.Name
            $Process.ExecutablePath
            $Process.CommandLine
        ) -join ' '

        if ($SearchText -match $Pattern) {
            $MatchingProcessIds += $Process.ProcessId
            $Version = $null

            if ($Process.ExecutablePath -and
                (Test-Path -LiteralPath $Process.ExecutablePath)) {
                $VersionInfo = (
                    Get-Item -LiteralPath $Process.ExecutablePath
                ).VersionInfo

                $Version = if ($VersionInfo.ProductVersion) {
                    $VersionInfo.ProductVersion
                } else {
                    $VersionInfo.FileVersion
                }
            }

            Add-ReconResult `
                -Category 'Process' `
                -Name $Process.Name `
                -Version $Version `
                -Path $Process.ExecutablePath `
                -Status 'Running' `
                -Identifier ([string]$Process.ProcessId) `
                -Details ([pscustomobject]@{
                    ProcessId       = $Process.ProcessId
                    ParentProcessId = $Process.ParentProcessId
                    CommandLine     = $Process.CommandLine
                })
        }
    }

    # TCP connections belonging to matching processes
    foreach ($Connection in Get-NetTCPConnection) {
        if ($Connection.OwningProcess -in $MatchingProcessIds) {
            Add-ReconResult `
                -Category 'NetworkConnection' `
                -Name 'ScreenConnect TCP connection' `
                -Version $null `
                -Path $null `
                -Status ([string]$Connection.State) `
                -Identifier ([string]$Connection.OwningProcess) `
                -Details ([pscustomobject]@{
                    LocalAddress  = $Connection.LocalAddress
                    LocalPort     = $Connection.LocalPort
                    RemoteAddress = $Connection.RemoteAddress
                    RemotePort    = $Connection.RemotePort
                    ProcessId     = $Connection.OwningProcess
                    CreationTime  = $Connection.CreationTime
                })
        }
    }

    # Scheduled tasks
    foreach ($Task in Get-ScheduledTask) {
        $SearchText = @(
            $Task.TaskName
            $Task.TaskPath
            $Task.Description
            ($Task.Actions | Out-String)
        ) -join ' '

        if ($SearchText -match $Pattern) {
            Add-ReconResult `
                -Category 'ScheduledTask' `
                -Name $Task.TaskName `
                -Version $null `
                -Path $Task.TaskPath `
                -Status ([string]$Task.State) `
                -Identifier "$($Task.TaskPath)$($Task.TaskName)" `
                -Details ([pscustomobject]@{
                    Author      = $Task.Author
                    Description = $Task.Description
                    Actions     = $Task.Actions
                    Triggers    = $Task.Triggers
                })
        }
    }

    # Firewall rules
    foreach ($Rule in Get-NetFirewallRule) {
        $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter

        $SearchText = @(
            $Rule.Name
            $Rule.DisplayName
            $Rule.Description
            $Rule.Group
            $ApplicationFilter.Program
        ) -join ' '

        if ($SearchText -match $Pattern) {
            $PortFilter = $Rule | Get-NetFirewallPortFilter

            Add-ReconResult `
                -Category 'FirewallRule' `
                -Name $Rule.DisplayName `
                -Version $null `
                -Path $ApplicationFilter.Program `
                -Status $(if ($Rule.Enabled -eq 'True') {
                    'Enabled'
                } else {
                    'Disabled'
                }) `
                -Identifier $Rule.Name `
                -Details ([pscustomobject]@{
                    Direction  = $Rule.Direction
                    Action     = $Rule.Action
                    Profile    = $Rule.Profile
                    Protocol   = $PortFilter.Protocol
                    LocalPort  = $PortFilter.LocalPort
                    RemotePort = $PortFilter.RemotePort
                })
        }
    }

    # Focused registry trace search
    $RegistryRoots = @(
        'HKLM:\SOFTWARE\ScreenConnect'
        'HKLM:\SOFTWARE\WOW6432Node\ScreenConnect'
        'HKLM:\SOFTWARE\ConnectWise'
        'HKLM:\SOFTWARE\WOW6432Node\ConnectWise'
        'HKCU:\SOFTWARE\ScreenConnect'
        'HKCU:\SOFTWARE\ConnectWise'
        'HKLM:\SYSTEM\CurrentControlSet\Services'
    )

    foreach ($RegistryRoot in $RegistryRoots) {
        if (-not (Test-Path -LiteralPath $RegistryRoot)) {
            continue
        }

        $RegistryKeys = @(
            Get-Item -LiteralPath $RegistryRoot
            Get-ChildItem -LiteralPath $RegistryRoot -Recurse
        )

        foreach ($RegistryKey in $RegistryKeys) {
            $Properties = Get-ItemProperty -LiteralPath $RegistryKey.PSPath

            $MatchingValues = foreach (
                $Property in $Properties.PSObject.Properties
            ) {
                if ($Property.Name -notmatch '^PS' -and
                    (
                        $Property.Name -match $Pattern -or
                        [string]$Property.Value -match $Pattern
                    )) {
                    '{0}={1}' -f $Property.Name, $Property.Value
                }
            }

            if ($RegistryKey.Name -match $Pattern -or $MatchingValues) {
                Add-ReconResult `
                    -Category 'Registry' `
                    -Name $RegistryKey.PSChildName `
                    -Version $null `
                    -Path $RegistryKey.Name `
                    -Status 'Present' `
                    -Identifier $RegistryKey.Name `
                    -Details ($MatchingValues -join '; ')
            }
        }
    }

    # Common file-system traces
    if ($IncludeFiles) {
        $SearchRoots = @(
            $env:ProgramFiles
            ${env:ProgramFiles(x86)}
            $env:ProgramData
            "$env:windir\Temp"
            "$env:PUBLIC\Desktop"
            "$env:APPDATA"
            "$env:LOCALAPPDATA"
            "$env:USERPROFILE\Desktop"
            "$env:USERPROFILE\Downloads"
        ) | Where-Object {
            $_ -and (Test-Path -LiteralPath $_)
        } | Select-Object -Unique

        foreach ($SearchRoot in $SearchRoots) {
            foreach (
                $Item in Get-ChildItem `
                    -LiteralPath $SearchRoot `
                    -Force `
                    -Recurse
            ) {
                if ($Item.Name -notmatch $Pattern -and
                    $Item.FullName -notmatch $Pattern) {
                    continue
                }

                $FileVersion = $null
                $ProductVersion = $null
                $Hash = $null
                $Signature = $null

                if (-not $Item.PSIsContainer) {
                    $FileVersion = $Item.VersionInfo.FileVersion
                    $ProductVersion = $Item.VersionInfo.ProductVersion

                    if ($Item.Length -lt 1GB) {
                        $Hash = (
                            Get-FileHash `
                                -LiteralPath $Item.FullName `
                                -Algorithm SHA256
                        ).Hash
                    }

                    if ($Item.Extension -match '^\.(exe|dll|sys|msi)$') {
                        $Signature = Get-AuthenticodeSignature `
                            -FilePath $Item.FullName
                    }
                }

                Add-ReconResult `
                    -Category $(if ($Item.PSIsContainer) {
                        'Directory'
                    } else {
                        'File'
                    }) `
                    -Name $Item.Name `
                    -Version $(if ($ProductVersion) {
                        $ProductVersion
                    } else {
                        $FileVersion
                    }) `
                    -Path $Item.FullName `
                    -Status $(if ($Item.PSIsContainer) {
                        'Present'
                    } else {
                        [string]$Signature.Status
                    }) `
                    -Identifier $Hash `
                    -Details ([pscustomobject]@{
                        Length           = $Item.Length
                        CreationTime     = $Item.CreationTime
                        LastWriteTime    = $Item.LastWriteTime
                        FileVersion      = $FileVersion
                        ProductVersion   = $ProductVersion
                        SignatureSubject = $Signature.SignerCertificate.Subject
                        SignatureIssuer  = $Signature.SignerCertificate.Issuer
                    })
            }
        }
    }

    # ScreenConnect-related Application and System events
    if ($IncludeEventLogs) {
        $StartTime = (Get-Date).AddDays(-$EventDays)

        foreach ($LogName in 'Application', 'System') {
            foreach (
                $winEvent in Get-WinEvent -FilterHashtable @{
                    LogName   = $LogName
                    StartTime = $StartTime
                }
            ) {
                $SearchText = @(
                    $winEvent.ProviderName
                    $winEvent.Message
                ) -join ' '

                if ($SearchText -match $Pattern) {
                    Add-ReconResult `
                        -Category 'EventLog' `
                        -Name $winEvent.ProviderName `
                        -Version $null `
                        -Path $LogName `
                        -Status $winEvent.LevelDisplayName `
                        -Identifier ([string]$winEvent.Id) `
                        -Details ([pscustomobject]@{
                            TimeCreated = $winEvent.TimeCreated
                            RecordId    = $winEvent.RecordId
                            Message     = $winEvent.Message
                        })
                }
            }
        }
    }
}

#endregion

#region -------------------- Invoke-ScreenConnect (dispatcher, returns the exit code) --------------------

function Invoke-ScreenConnect {
    [CmdletBinding()]
    param(
        [ValidateSet('Check', 'Recon')]
        [string]$Mode = 'Check',
        [hashtable]$Options = @{}
    )

    try {
        if (-not (Test-IsAdmin)) {
            Write-Host 'NOT ELEVATED: results may be incomplete (other users, some services/tasks/folders); rerun elevated for a full picture.' -ForegroundColor Yellow
        }

        if ($Mode -eq 'Check') {
            $found = @(Get-ScreenConnectVersion)
            if (-not $found) { Write-Host 'ScreenConnect / ConnectWise Control was not found.'; return 0 }
            $found | Format-List | Out-Host
            Write-Host "ScreenConnect: PRESENT ($($found.Count) uninstall entr$(if ($found.Count -eq 1) { 'y' } else { 'ies' }))" -ForegroundColor Yellow
            return 2
        }

        # Recon
        $results = @(Get-ScreenConnectRecon @Options)
        if (-not $results) { Write-Host 'No ScreenConnect / ConnectWise Control traces found.'; return 0 }
        $results | Sort-Object Category, Name |
            Format-Table Category, Name, Version, Status, Path, Identifier -AutoSize -Wrap | Out-String -Width 250 | Out-Host
        $results | Group-Object Category | Sort-Object Name |
            Format-Table @{ n = 'Category'; e = { $_.Name } }, Count -AutoSize | Out-Host
        Write-Host "ScreenConnect traces: $($results.Count) (full objects with Details: Get-ScreenConnectRecon)" -ForegroundColor Yellow
        return 2
    }
    catch {
        # Write-Host, not Write-Error: a caller's ErrorAction Stop must not lose the exit code.
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
}

#endregion

#region ==================== ENTRY POINT - set $RMM, then pick ONE mode ====================

# $true ONLY in an RMM component: the script then ends with 'exit <code>' so the RMM
# sees the result. Leave $false when pasting into a console or RMM remote shell -
# exit would end that session mid-way through the engineer's other patching work.
$RMM = $false

$exitCode = Invoke-ScreenConnect                                   # Check (read-only, fast)
# $exitCode = Invoke-ScreenConnect -Mode Recon                     # Deep trace search (read-only)
# $exitCode = Invoke-ScreenConnect -Mode Recon -Options @{ IncludeFiles = $true; IncludeEventLogs = $true; EventDays = 30 }  # + files and events (slow)

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
