# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Adobe Acrobat DC - Check / Recon / Update / Uninstall / RepairTransforms (RMM-ready)

.DESCRIPTION
    One script for Adobe Acrobat DC (Pro or Reader):

      -Check             DEFAULT. Installed version vs latest in WinGet, and whether
                         anyone has Acrobat open. Changes nothing.
      -Recon             Deep read-only scan of every place Acrobat leaves traces:
                         HKLM/HKU uninstall entries, Adobe Installer keys (DC, 2020,
                         2017), App Paths, services, tasks, processes, files and
                         per-user AppData executables. Use when a scanner reports a
                         version that does not match what is installed.
      -Update            Upgrade through WinGet. Aborts if Acrobat is in use (-Force).
      -Uninstall         Remove all detected Acrobat WinGet packages (-Force).
      -RepairTransforms  Fixes MSI installs that cannot update/repair/uninstall
                         because the recorded Transforms (.mst) file no longer
                         exists - typical on RDS where setup ran from a user's
                         %TEMP%. Backs up the key to LogDir, then removes the value.
      -Interactive       Menu for a technician at an elevated console. Asks before
                         closing Acrobat for a user, wants YES typed before an
                         uninstall, and previews transform repairs first. Not for RMM.

    Every mode except -Recon writes a transcript to C:\Logs\AdobePatch by default.
    -WhatIf previews -Update, -Uninstall and -RepairTransforms without changes.

.PARAMETER Force
    Skip the active-user gate (closes Acrobat). Only with -Update or -Uninstall.

.PARAMETER LoadUserHives
    -Recon: also mount NTUSER.DAT of signed-out profiles. Needs admin.

.PARAMETER DeepFileSearch
    -Recon: recurse into the Adobe folders instead of listing the top level.

.PARAMETER AsJson
    -Recon: emit JSON instead of the text report.

.PARAMETER LogDir
    Transcript and backup folder. Default: C:\Logs\AdobePatch

.EXAMPLE
    Paste the WHOLE script into an elevated console or an RMM component. The
    ENTRY POINT at the bottom picks the mode - edit that one line. For an RMM
    component also set $RMM = $true there, so the script exits with the code.

    Start-AdobePatch                             # Check
    Start-AdobePatch -Recon -LoadUserHives       # Deep scan incl. signed-out users
    Start-AdobePatch -Update                     # Update (aborts if Acrobat is open)
    Start-AdobePatch -Update -Force              # Update, closing Acrobat
    Start-AdobePatch -Uninstall -WhatIf          # Preview uninstall
    Start-AdobePatch -RepairTransforms           # Fix missing-.mst MSI registrations
    Start-AdobePatch -Interactive                # Menu (elevated console only)

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Start-AdobePatch returns one; the entry point exits with it only when $RMM = $true):
        0    Success (up to date / updated / uninstalled / check or recon complete), or
             Adobe Acrobat not installed - nothing to do
        1    Not used (was "not installed" before 2026-10-11, now 0 like the other morphs)
        2    WinGet not found or unusable
        3    No matching WinGet package found (e.g. SCCM/GPO-managed)
        4    Upgrade failed for all detected packages
        5    Uninstall failed for one or more packages
        6    Acrobat is currently in use - action aborted (use -Force to override)
        7    Update check failed - could not determine latest version from WinGet
        8    RepairTransforms could not back up or fix one or more keys
        10   Update / Uninstall / RepairTransforms not running as Administrator (Check runs without)
#>

#region -------------------- Recon (read-only) --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-Finding {
    param(
        [string]$Source,
        [string]$Name,
        [string]$Version,
        [string]$Path,
        [string]$Publisher,
        [string]$User,
        [hashtable]$Extra
    )

    [pscustomobject]@{
        Source    = $Source
        Name      = $Name
        Version   = $Version
        Path      = $Path
        Publisher = $Publisher
        User      = $User
        Extra     = $Extra
    }
}

function Test-AdobeAcrobatName {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match '(?i)\bAdobe\b.*\b(Acrobat|Reader|PDF|ARM|AAM)\b|\b(Acrobat|AcroRd32|Acrobat Reader|AdobeARM|Adobe Acrobat Update)\b'
}

function Get-ProductCodeFromText {
    param([string]$Text)

    if ($Text -match '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') {
        return $matches[0]
    }

    return $null
}

function Get-PathFromRegistryCommand {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    if ($Text -match '^\s*"([^"]+)"') {
        return $matches[1]
    }

    $withoutArgs = ($Text -split '\s+[/-]', 2)[0]
    $withoutIconIndex = ($withoutArgs -split ',', 2)[0]
    return $withoutIconIndex.Trim('" ')
}

function Get-FileVersionEvidence {
    param(
        [string]$Source,
        [string]$Name,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        return
    }

    $item = Get-Item -Path $Path
    if ($item.PSIsContainer) {
        return
    }

    $versionInfo = $item.VersionInfo
    [pscustomobject]@{
        Source         = $Source
        Name           = $Name
        Path           = $item.FullName
        FileVersion    = $versionInfo.FileVersion
        ProductVersion = $versionInfo.ProductVersion
        Modified       = $item.LastWriteTime
    }
}

function Get-VersionEvidence {
    param([object[]]$Findings)

    $candidatePaths = New-Object System.Collections.Generic.List[object]

    foreach ($item in @($Findings | Where-Object { $_.Source -like '*Uninstall*' })) {
        if ($item.Path) {
            $candidatePaths.Add([pscustomobject]@{
                Source = "$($item.Source) install path"
                Name   = $item.Name
                Path   = Join-Path $item.Path 'Acrobat\Acrobat.exe'
            })
            $candidatePaths.Add([pscustomobject]@{
                Source = "$($item.Source) install path"
                Name   = $item.Name
                Path   = Join-Path $item.Path 'Reader\AcroRd32.exe'
            })
            $candidatePaths.Add([pscustomobject]@{
                Source = "$($item.Source) install path"
                Name   = $item.Name
                Path   = Join-Path $item.Path 'AcroRd32.exe'
            })
        }

        $displayIconPath = Get-PathFromRegistryCommand $item.Extra.DisplayIcon
        if ($displayIconPath) {
            $candidatePaths.Add([pscustomobject]@{
                Source = "$($item.Source) display icon"
                Name   = $item.Name
                Path   = $displayIconPath
            })
        }
    }

    foreach ($item in @($Findings | Where-Object { $_.Source -eq 'AppPaths' })) {
        $candidatePaths.Add([pscustomobject]@{
            Source = 'AppPaths'
            Name   = $item.Name
            Path   = $item.Path
        })
    }

    # Default install locations, in case ARP entries are missing or stale.
    foreach ($exe in @(
        "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "$env:ProgramFiles\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    )) {
        $candidatePaths.Add([pscustomobject]@{ Source = 'Default path'; Name = Split-Path $exe -Leaf; Path = $exe })
    }

    # Per-user installs live under each profile's AppData.
    $profilePaths = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath } |
        ForEach-Object { $_.LocalPath }
    foreach ($profilePath in $profilePaths) {
        foreach ($relative in @(
            'AppData\Local\Adobe\Acrobat\DC\Acrobat.exe',
            'AppData\Local\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe'
        )) {
            $candidatePaths.Add([pscustomobject]@{
                Source = 'User AppData'
                Name   = Split-Path $profilePath -Leaf
                Path   = Join-Path $profilePath $relative
            })
        }
    }

    $candidatePaths |
        Where-Object { $_.Path } |
        Sort-Object Path -Unique |
        ForEach-Object {
            Get-FileVersionEvidence -Source $_.Source -Name $_.Name -Path $_.Path
        }
}

function Write-ReconSection {
    param([string]$Title)

    Write-Output ""
    Write-Output "=== $Title ==="
}

function Write-NameValue {
    param(
        [string]$Name,
        [object]$Value
    )

    if ($null -ne $Value -and "$Value".Trim()) {
        Write-Output ("{0,-16}: {1}" -f $Name, $Value)
    }
}

function Get-UninstallEntries {
    param(
        [string[]]$Roots,
        [string]$Source,
        [string]$User
    )

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) {
            continue
        }

        Get-ChildItem -Path $root | ForEach-Object {
            $item = Get-ItemProperty -Path $_.PSPath
            $text = @(
                $item.DisplayName
                $item.Publisher
                $item.InstallLocation
                $item.DisplayIcon
                $item.UninstallString
            ) -join ' '

            if (Test-AdobeAcrobatName $text) {
                New-Finding -Source $Source `
                    -Name $item.DisplayName `
                    -Version $item.DisplayVersion `
                    -Path $item.InstallLocation `
                    -Publisher $item.Publisher `
                    -User $User `
                    -Extra @{
                        RegistryPath    = $_.Name
                        DisplayIcon     = $item.DisplayIcon
                        UninstallString = $item.UninstallString
                        InstallDate     = $item.InstallDate
                        ProductCode     = Get-ProductCodeFromText $item.UninstallString
                    }
            }
        }
    }
}

function Get-InstallerKeyEntries {
    # Acrobat's own Installer keys carry the real version even when ARP entries
    # (and the scanners that read them) are stale.
    param(
        [string]$Root,
        [string]$Source,
        [string]$User
    )

    foreach ($sub in @(
        'SOFTWARE\Adobe\Adobe Acrobat\DC\Installer',
        'SOFTWARE\Adobe\Acrobat Reader\DC\Installer',
        'SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Installer',
        'SOFTWARE\WOW6432Node\Adobe\Acrobat Reader\DC\Installer',
        'SOFTWARE\Adobe\Adobe Acrobat\2020\Installer',
        'SOFTWARE\Adobe\Adobe Acrobat\2017\Installer'
    )) {
        $path = Join-Path $Root $sub
        $item = Get-ItemProperty -Path $path
        if ($item.Version) {
            New-Finding -Source $Source `
                -Name ($sub -replace '^SOFTWARE\\(WOW6432Node\\)?Adobe\\|\\Installer$', '') `
                -Version $item.Version `
                -User $User `
                -Extra @{ RegistryPath = $path }
        }
    }
}

function Get-AppPathEntries {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) {
            continue
        }

        Get-ChildItem -Path $root | Where-Object {
            Test-AdobeAcrobatName $_.PSChildName
        } | ForEach-Object {
            $item = Get-ItemProperty -Path $_.PSPath
            New-Finding -Source 'AppPaths' `
                -Name $_.PSChildName `
                -Path $item.'(default)' `
                -Extra @{
                    RegistryPath = $_.Name
                    PathValue    = $item.Path
                }
        }
    }
}

function Get-LoadedUserUninstallEntries {
    $userRoots = Get-ChildItem -Path Registry::HKEY_USERS | Where-Object {
        $_.PSChildName -match '^S-\d-\d+-(\d+-){1,14}\d+$'
    }

    foreach ($userRoot in $userRoots) {
        $sid = $userRoot.PSChildName
        $roots = @(
            "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "Registry::HKEY_USERS\$sid\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        Get-UninstallEntries -Roots $roots -Source 'HKU-Uninstall-Loaded' -User $sid
        Get-InstallerKeyEntries -Root "Registry::HKEY_USERS\$sid" -Source 'InstallerKey-HKU-Loaded' -User $sid
    }
}

function Get-UnloadedUserUninstallEntries {
    if (-not $LoadUserHives) {
        return
    }

    if (-not (Test-IsAdmin)) {
        Write-Warning 'LoadUserHives was requested, but this session is not elevated. Skipping unloaded user hives.'
        return
    }

    $profiles = Get-CimInstance Win32_UserProfile | Where-Object {
        -not $_.Special -and
        $_.LocalPath -and
        (Test-Path (Join-Path $_.LocalPath 'NTUSER.DAT')) -and
        -not (Test-Path "Registry::HKEY_USERS\$($_.SID)")
    }

    foreach ($userProfile in $profiles) {
        $mountName = "AdobeRecon_$($userProfile.SID -replace '[^A-Za-z0-9]', '_')"
        $mountPath = "HKU\$mountName"
        $ntUserPath = Join-Path $userProfile.LocalPath 'NTUSER.DAT'
        $loaded = $false

        try {
            & reg.exe load $mountPath $ntUserPath | Out-Null
            $loaded = $LASTEXITCODE -eq 0

            if ($loaded) {
                $roots = @(
                    "Registry::HKEY_USERS\$mountName\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    "Registry::HKEY_USERS\$mountName\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )

                Get-UninstallEntries -Roots $roots -Source 'HKU-Uninstall-Unloaded' -User $userProfile.SID
                Get-InstallerKeyEntries -Root "Registry::HKEY_USERS\$mountName" -Source 'InstallerKey-HKU-Unloaded' -User $userProfile.SID
            }
        }
        finally {
            if ($loaded) {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()
                Start-Sleep -Milliseconds 250
                & reg.exe unload $mountPath | Out-Null
            }
        }
    }
}

function Get-ServiceEntries {
    Get-CimInstance Win32_Service | Where-Object {
        Test-AdobeAcrobatName "$($_.Name) $($_.DisplayName) $($_.PathName)"
    } | ForEach-Object {
        New-Finding -Source 'Service' `
            -Name $_.DisplayName `
            -Path $_.PathName `
            -Extra @{
                ServiceName = $_.Name
                State       = $_.State
                StartMode   = $_.StartMode
            }
    }
}

function Get-TaskEntries {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $actionText = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
        Test-AdobeAcrobatName "$($_.TaskName) $($_.TaskPath) $actionText"
    } | ForEach-Object {
        New-Finding -Source 'ScheduledTask' `
            -Name "$($_.TaskPath)$($_.TaskName)" `
            -Path (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ') `
            -Extra @{
                State = $_.State
            }
    }
}

function Get-ProcessEntries {
    Get-CimInstance Win32_Process | Where-Object {
        Test-AdobeAcrobatName "$($_.Name) $($_.ExecutablePath) $($_.CommandLine)"
    } | ForEach-Object {
        New-Finding -Source 'Process' `
            -Name $_.Name `
            -Path $_.ExecutablePath `
            -Extra @{
                ProcessId   = $_.ProcessId
                CommandLine = $_.CommandLine
            }
    }
}

function Get-FileEntries {
    $paths = @(
        "$env:ProgramFiles\Adobe",
        "${env:ProgramFiles(x86)}\Adobe",
        "$env:ProgramData\Adobe",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:Public\Desktop"
    )

    $userRoots = Get-CimInstance Win32_UserProfile | Where-Object {
        -not $_.Special -and $_.LocalPath -and (Test-Path $_.LocalPath)
    } | ForEach-Object {
        @(
            "$($_.LocalPath)\AppData\Local\Adobe",
            "$($_.LocalPath)\AppData\Roaming\Adobe",
            "$($_.LocalPath)\Desktop",
            "$($_.LocalPath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
        )
    }

    $paths += $userRoots
    $paths = $paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    foreach ($path in $paths) {
        $items = if ($DeepFileSearch) {
            Get-ChildItem -Path $path -Recurse -Force
        }
        else {
            Get-ChildItem -Path $path -Force
        }

        $items | Where-Object {
            Test-AdobeAcrobatName "$($_.Name) $($_.FullName)"
        } | ForEach-Object {
            New-Finding -Source 'FileSystem' `
                -Name $_.Name `
                -Path $_.FullName `
                -Extra @{
                    ItemType      = if ($_.PSIsContainer) { 'Directory' } else { 'File' }
                    LastWriteTime = $_.LastWriteTime
                    Length        = if ($_.PSIsContainer) { $null } else { $_.Length }
                }
        }
    }
}

function Invoke-AdobeRecon {
    param(
        [switch]$LoadUserHives,
        [switch]$DeepFileSearch,
        [switch]$AsJson
    )

    # Recon probes many keys/paths that legitimately do not exist; scoped to this call.
    $ErrorActionPreference = 'SilentlyContinue'

    $findings = @()

    $findings += Get-UninstallEntries -Roots @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    ) -Source 'HKLM-Uninstall' -User 'AllUsers'

    $findings += Get-InstallerKeyEntries -Root 'HKLM:\' -Source 'InstallerKey-HKLM' -User 'AllUsers'
    $findings += Get-LoadedUserUninstallEntries
    $findings += Get-UnloadedUserUninstallEntries
    $findings += Get-AppPathEntries
    $findings += Get-ServiceEntries
    $findings += Get-TaskEntries
    $findings += Get-ProcessEntries
    $findings += Get-FileEntries

    $findings = $findings | Where-Object { $_ } | Sort-Object Source, Name, Path -Unique

    $summary = [pscustomobject]@{
        ComputerName        = $env:COMPUTERNAME
        ScanTime            = (Get-Date).ToString('s')
        IsAdmin             = Test-IsAdmin
        LoadedUserHives     = [bool]$LoadUserHives
        DeepFileSearch      = [bool]$DeepFileSearch
        FindingCount        = @($findings).Count
        Findings            = $findings
    }

    if ($AsJson) {
        $summary | ConvertTo-Json -Depth 8
        return
    }

    $installed = @($findings | Where-Object { $_.Source -like '*Uninstall*' })
    $installerKeys = @($findings | Where-Object { $_.Source -like 'InstallerKey*' })
    $background = @($findings | Where-Object { $_.Source -in @('Service', 'ScheduledTask', 'Process') })
    $appPaths = @($findings | Where-Object { $_.Source -eq 'AppPaths' })
    $fileSystem = @($findings | Where-Object { $_.Source -eq 'FileSystem' })
    $versionEvidence = @(Get-VersionEvidence -Findings $findings)

    Write-Output "Adobe Acrobat / Reader Recon"
    Write-Output "============================="
    Write-NameValue 'Computer' $summary.ComputerName
    Write-NameValue 'Scan time' $summary.ScanTime
    Write-NameValue 'Admin' $summary.IsAdmin
    Write-NameValue 'User hives' $(if ($summary.LoadedUserHives) { 'Loaded + unloaded local profiles' } else { 'Loaded profiles only' })
    Write-NameValue 'Deep files' $summary.DeepFileSearch
    Write-NameValue 'Findings' $summary.FindingCount
    Write-NameValue 'Installed apps' $installed.Count
    Write-NameValue 'Installer keys' $installerKeys.Count
    Write-NameValue 'Background' $background.Count
    Write-NameValue 'File traces' $fileSystem.Count
    Write-NameValue 'File versions' $versionEvidence.Count

    if ($summary.FindingCount -eq 0 -and $versionEvidence.Count -eq 0) {
        Write-Output ""
        Write-Output "No Adobe Acrobat / Reader findings detected."
        return
    }

    if ($installed.Count -gt 0) {
        Write-ReconSection 'Installed Products'
        foreach ($item in $installed) {
            Write-Output "- $($item.Name)"
            Write-NameValue 'Version' $item.Version
            Write-NameValue 'Publisher' $item.Publisher
            Write-NameValue 'Scope/User' $item.User
            Write-NameValue 'Install path' $item.Path
            Write-NameValue 'Product code' $item.Extra.ProductCode
            Write-NameValue 'Uninstall' $item.Extra.UninstallString
            Write-NameValue 'Registry' $item.Extra.RegistryPath
            Write-Output ""
        }
    }

    if ($installerKeys.Count -gt 0) {
        Write-ReconSection 'Adobe Installer Keys'
        foreach ($item in $installerKeys) {
            Write-Output "- $($item.Name)"
            Write-NameValue 'Version' $item.Version
            Write-NameValue 'Scope/User' $item.User
            Write-NameValue 'Registry' $item.Extra.RegistryPath
            Write-Output ""
        }
    }

    if ($versionEvidence.Count -gt 0) {
        Write-ReconSection 'Executable Version Evidence'
        foreach ($item in $versionEvidence) {
            Write-Output "- $($item.Name)"
            Write-NameValue 'Evidence' $item.Source
            Write-NameValue 'File version' $item.FileVersion
            Write-NameValue 'Product version' $item.ProductVersion
            Write-NameValue 'Modified' $item.Modified
            Write-NameValue 'Path' $item.Path
            Write-Output ""
        }
    }

    if ($background.Count -gt 0) {
        Write-ReconSection 'Background Components'
        foreach ($item in $background) {
            Write-Output "- [$($item.Source)] $($item.Name)"
            Write-NameValue 'Path' $item.Path
            Write-NameValue 'State' $item.Extra.State
            Write-NameValue 'Start mode' $item.Extra.StartMode
            Write-NameValue 'PID' $item.Extra.ProcessId
            Write-NameValue 'Command line' $item.Extra.CommandLine
            Write-Output ""
        }
    }

    if ($appPaths.Count -gt 0) {
        Write-ReconSection 'Registered App Paths'
        foreach ($item in $appPaths) {
            Write-Output "- $($item.Name)"
            Write-NameValue 'Target' $item.Path
            Write-NameValue 'Path value' $item.Extra.PathValue
            Write-NameValue 'Registry' $item.Extra.RegistryPath
            Write-Output ""
        }
    }

    if ($fileSystem.Count -gt 0) {
        Write-ReconSection 'Filesystem Traces'
        foreach ($item in $fileSystem) {
            Write-Output "- [$($item.Extra.ItemType)] $($item.Name)"
            Write-NameValue 'Path' $item.Path
            Write-NameValue 'Modified' $item.Extra.LastWriteTime
            Write-NameValue 'Size' $item.Extra.Length
            Write-Output ""
        }
    }
}

#endregion

#region -------------------- Interactive menu --------------------

function Show-AdobeMenu {
    param([string]$LogDir)

    # Read-Host would hang an RMM/SYSTEM job forever.
    if (-not [Environment]::UserInteractive) {
        throw 'Interactive mode needs a console. Under RMM use -Check, -Update, -Uninstall or -RepairTransforms.'
    }

    function Wait-Enter { Read-Host '    Press Enter to return to the menu' | Out-Null }

    # Exit 6 = Acrobat is open. Ask before closing it, then retry with -Force.
    function Invoke-WithForcePrompt {
        param([string]$Mode)
        $params = @{ $Mode = $true; LogDir = $LogDir }
        $code = Start-AdobePatch @params
        if ($code -ne 6) { return }
        Write-Host ''
        Write-Host '  +========================================================+' -ForegroundColor Yellow
        Write-Host '  |  WARNING: This will close Acrobat for the active user  |' -ForegroundColor Yellow
        Write-Host '  |  Any unsaved work in Acrobat will be LOST.             |' -ForegroundColor Yellow
        Write-Host '  +========================================================+' -ForegroundColor Yellow
        if ((Read-Host '    Proceed anyway? (Y/N)') -eq 'Y') {
            $params.Force = $true
            Start-AdobePatch @params | Out-Null
        }
    }

    while ($true) {
        Clear-Host
        Write-Host ''
        Write-Host '  +========================================================+' -ForegroundColor Cyan
        Write-Host '  |           ADOBE ACROBAT  -  PATCH TOOL                 |' -ForegroundColor Cyan
        Write-Host '  +========================================================+' -ForegroundColor Cyan
        Write-Host ''
        Write-Host '    [C] Check version and whether Acrobat is in use'
        Write-Host '    [R] Recon - deep scan of every Acrobat trace'
        Write-Host '    [U] Update Acrobat'
        Write-Host '    [X] Uninstall Acrobat'
        Write-Host '    [T] Repair missing MSI transforms'
        Write-Host '    [Q] Quit'
        Write-Host ''

        switch ((Read-Host '    >').Trim().ToUpper()) {
            'C' { Start-AdobePatch -Check -LogDir $LogDir | Out-Null; Wait-Enter }
            'R' { Start-AdobePatch -Recon | Out-Null; Wait-Enter }
            'U' { Invoke-WithForcePrompt -Mode 'Update'; Wait-Enter }
            'X' {
                Write-Host ''
                Write-Host '  +========================================================+' -ForegroundColor Red
                Write-Host '  |  WARNING: This will completely remove Adobe Acrobat     |' -ForegroundColor Red
                Write-Host '  |  from this machine. This action cannot be undone.       |' -ForegroundColor Red
                Write-Host '  +========================================================+' -ForegroundColor Red
                if ((Read-Host '    Type YES to uninstall') -ceq 'YES') {
                    Invoke-WithForcePrompt -Mode 'Uninstall'
                }
                else { Write-Host '    Cancelled.' -ForegroundColor DarkGray }
                Wait-Enter
            }
            'T' {
                Start-AdobePatch -RepairTransforms -WhatIf -LogDir $LogDir | Out-Null
                if ((Read-Host '    Apply these repairs? (Y/N)') -eq 'Y') {
                    Start-AdobePatch -RepairTransforms -LogDir $LogDir | Out-Null
                }
                Wait-Enter
            }
            'Q' { Clear-Host; return }
        }
    }
}

#endregion

#region -------------------- Check / Update / Uninstall / RepairTransforms --------------------

function Start-AdobePatch {
    [CmdletBinding(DefaultParameterSetName = 'Check', SupportsShouldProcess = $true)]
    param(
        [Parameter(ParameterSetName = 'Check')]
        [switch]$Check,

        [Parameter(ParameterSetName = 'Recon')]
        [switch]$Recon,

        [Parameter(ParameterSetName = 'Update')]
        [switch]$Update,

        [Parameter(ParameterSetName = 'Uninstall')]
        [switch]$Uninstall,

        [Parameter(ParameterSetName = 'RepairTransforms')]
        [switch]$RepairTransforms,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(ParameterSetName = 'Update')]
        [Parameter(ParameterSetName = 'Uninstall')]
        [switch]$Force,

        [Parameter(ParameterSetName = 'Recon')]
        [switch]$LoadUserHives,

        [Parameter(ParameterSetName = 'Recon')]
        [switch]$DeepFileSearch,

        [Parameter(ParameterSetName = 'Recon')]
        [switch]$AsJson,

        [string]$LogDir = "C:\Logs\AdobePatch"
    )

    # Recon is read-only and writes nothing, so it skips the transcript and admin gate.
    # Its report goes to the host so this function only ever returns the exit code.
    if ($PSCmdlet.ParameterSetName -eq 'Recon') {
        Invoke-AdobeRecon -LoadUserHives:$LoadUserHives -DeepFileSearch:$DeepFileSearch -AsJson:$AsJson | Out-Host
        return 0
    }
    if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
        Show-AdobeMenu -LogDir $LogDir
        return 0
    }

    # -------------------------------------------------------------------------
    # Logging bootstrap
    # -------------------------------------------------------------------------

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $mode      = switch ($PSCmdlet.ParameterSetName) {
        'Update'           { 'Update' }
        'Uninstall'        { 'Uninstall' }
        'RepairTransforms' { 'RepairTransforms' }
        default            { 'Check' }
    }
    $logFile = Join-Path $LogDir "AdobePatch_${mode}_${timestamp}.log"

    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force -WhatIf:$false | Out-Null
        }
        Start-Transcript -Path $logFile -Append -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    catch {
        Write-Warning "Could not start transcript at '$logFile': $_"
    }

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    function Write-Status {
        param([string]$Message, [string]$Color = "White")
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
    }

    function Write-Section {
        param([string]$Title)
        Write-Host ""
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] --- $Title ---" -ForegroundColor DarkCyan
    }

    function Invoke-FinalExit {
        param([int]$Code)
        Write-Host ""
        Write-Status "----------------------------------------" Cyan
        Write-Status "Finished. Exit code: $Code" $(if ($Code -eq 0) { "Green" } else { "Red" })
        Write-Status "Log written to: $logFile" DarkGray
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        return $Code
    }

    function ConvertTo-NormalisedVersion {
        <#
            Converts Adobe's inconsistent version strings to a comparable
            [System.Version] object.

            Adobe uses two formats depending on source:
              Registry  : 26.1.21346.0    (standard .NET version style)
              WinGet    : 26.001.21346    (leading zeros, missing 4th segment)

            Both represent the same build. This function strips leading zeros
            from each segment and pads to 4 parts so they compare equal.

            Returns $null if the string cannot be parsed - caller must handle.
        #>
        param([string]$Raw)
        try {
            # Remove leading zeros per segment, then parse as [System.Version]
            $segments = ($Raw -split '\.') | ForEach-Object { [int]$_ }
            # Pad to exactly 4 segments (Major.Minor.Build.Revision)
            while ($segments.Count -lt 4) { $segments += 0 }
            return [System.Version]($segments[0..3] -join '.')
        }
        catch {
            return $null
        }
    }

    function Get-AdobeAcrobatInstall {
        $regPaths = @(
            "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer",
            "HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer",
            "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Installer",
            "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader\DC\Installer"
        )
        foreach ($path in $regPaths) {
            $reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($reg -and $reg.Version) {
                return @{ Version = $reg.Version; Path = $path }
            }
        }
        $exePaths = @(
            "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
            "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
            "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
            "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
        )
        foreach ($exe in $exePaths) {
            if (Test-Path $exe) {
                $ver = (Get-Item $exe).VersionInfo.ProductVersion
                return @{ Version = $ver; Path = $exe }
            }
        }
        return $null
    }

    function Get-WingetPath {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($cmd -and (Test-Path $cmd.Source)) { return $cmd.Source }

        $appx = Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller `
                    -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($appx -and $appx.InstallLocation) {
            $p = Join-Path $appx.InstallLocation "winget.exe"
            if (Test-Path $p) { return $p }
        }

        # SYSTEM context fallback - scan WindowsApps for newest machine-wide install
        $globs = @(
            "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe",
            "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x86__8wekyb3d8bbwe\winget.exe"
        )
        foreach ($glob in $globs) {
            $found = Get-Item $glob -ErrorAction SilentlyContinue |
                     Sort-Object Name -Descending | Select-Object -First 1
            if ($found) { return $found.FullName }
        }
        return $null
    }

    function Get-WingetAdobeIds {
        param([string]$WingetExe)
        $knownIds = @(
            "Adobe.Acrobat.Pro",
            "Adobe.Acrobat.Reader.64-bit",
            "Adobe.Acrobat.Reader.32-bit"
        )
        $out = & $WingetExe list --scope machine --accept-source-agreements 2>&1 | Out-String
        $matched = foreach ($id in $knownIds) {
            if ($out -match [regex]::Escape($id)) { $id }
        }
        return @($matched)
    }

    function Get-AdobeLatestVersion {
        <#
            Queries WinGet for the latest available version of the given package ID.
            Parses the "Version: X.X.X" line from `winget show` output.
            Returns a raw version string or $null if it cannot be determined.
        #>
        param([string]$WingetExe, [string]$PackageId)
        $raw = & $WingetExe show --id $PackageId --accept-source-agreements 2>&1 | Out-String
        if ($raw -match '(?m)^Version\s*:\s*(.+)$') {
            return $Matches[1].Trim()
        }
        return $null
    }

    function Get-AcrobatActiveUsers {
        <#
            Returns PSCustomObjects for every user who currently has an Acrobat
            process running. Correlates Win32_Process with GetOwner() to identify
            the owning interactive user and their session state.
        #>
        $adobeProcessNames = @("Acrobat", "AcroRd32")
        $results = @()

        foreach ($procName in $adobeProcessNames) {
            $procs = Get-CimInstance Win32_Process `
                         -Filter "Name = '$procName.exe'" `
                         -ErrorAction SilentlyContinue
            foreach ($proc in $procs) {
                $ownerResult = Invoke-CimMethod -InputObject $proc `
                                   -MethodName GetOwner -ErrorAction SilentlyContinue
                $username = if ($ownerResult -and $ownerResult.User) {
                    "$($ownerResult.Domain)\$($ownerResult.User)"
                } else { "Unknown" }

                $sessionState = "Active"
                try {
                    $queryOutput = query session $proc.SessionId 2>&1 | Out-String
                    if ($queryOutput -match 'Disc') { $sessionState = "Disconnected" }
                }
                catch { <# non-fatal - default remains Active #> }

                $results += [PSCustomObject]@{
                    ProcessName  = $procName
                    PID          = $proc.ProcessId
                    User         = $username
                    SessionId    = $proc.SessionId
                    SessionState = $sessionState
                    StartTime    = $proc.CreationDate
                }
            }
        }
        return $results
    }

    function Stop-AdobeProcesses {
        $adobeProcs = @("Acrobat", "AcroRd32", "AdobeARM", "AdobeCollabSync", "armsvc")
        $killed = $false
        foreach ($proc in $adobeProcs) {
            $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
            if ($running) {
                Write-Status "  Stopping: $proc (PID $($running.Id -join ','))" Yellow
                Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
                $killed = $true
            }
        }
        if ($killed) { Start-Sleep -Seconds 2 }
    }

    # -------------------------------------------------------------------------
    # Header
    # -------------------------------------------------------------------------

    Write-Host ""
    Write-Status "========================================" Cyan
    Write-Status " Adobe Acrobat Patch Script - $mode" Cyan
    Write-Status " Host    : $env:COMPUTERNAME" Cyan
    Write-Status " User    : $env:USERNAME" Cyan
    Write-Status " Log     : $logFile" Cyan
    if ($Force) {
        Write-Status " -Force  : Active-user gate BYPASSED" Yellow
    }
    if ($WhatIfPreference) {
        Write-Status " -WhatIf : preview only, nothing will be changed" Yellow
    }
    Write-Status "========================================" Cyan

    # -------------------------------------------------------------------------
    # Pre-flight: Admin check
    # -------------------------------------------------------------------------

    # Check only reads (registry + winget queries), so it runs without elevation; confirmed
    # elevated and non-elevated on 2026-10-11 with identical results.
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($mode -ne 'Check' -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Status "ERROR: -$mode must run as Administrator." Red
        return (Invoke-FinalExit -Code 10)
    }

    # -------------------------------------------------------------------------
    # REPAIR TRANSFORMS - independent of WinGet, so it runs before those checks
    # -------------------------------------------------------------------------

    if ($mode -eq 'RepairTransforms') {
        Write-Section "MSI Transforms"

        # Removing the value means future repairs/patches run without that
        # customisation (e.g. a language .mst) - acceptable, since the file is gone.
        $broken = 0
        $failed = $false
        $products = Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue
        foreach ($key in $products) {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($props.ProductName -notlike '*Adobe Acrobat*' -or -not $props.Transforms) { continue }

            # ';'-separated list. ':' = embedded in the package; '@'/'|' = secure-transform
            # prefixes. Only rooted paths can be checked; relative ones live in the source.
            $missing = @($props.Transforms -split ';' |
                Where-Object { $_ -and $_ -notlike ':*' } |
                ForEach-Object { $_.TrimStart('@', '|') } |
                Where-Object { [IO.Path]::IsPathRooted($_) -and -not (Test-Path -LiteralPath $_) })

            if ($missing.Count -eq 0) {
                Write-Status "OK      : $($props.ProductName) - transform file(s) present" Green
                continue
            }

            $broken++
            Write-Status "BROKEN  : $($props.ProductName)" Yellow
            Write-Status "  Key   : $($key.Name)" DarkGray
            foreach ($m in $missing) { Write-Status "  Missing: $m" Yellow }

            if (-not $PSCmdlet.ShouldProcess($key.Name, 'Back up key and remove Transforms value')) { continue }

            $backup = Join-Path $LogDir ("Transforms_{0}_{1}.reg" -f $key.PSChildName, $timestamp)
            & reg.exe export $key.Name $backup /y 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Status "  Backup failed (reg export exit $LASTEXITCODE) - value left in place." Red
                $failed = $true
                continue
            }
            try {
                Remove-ItemProperty -LiteralPath $key.PSPath -Name Transforms -ErrorAction Stop -WhatIf:$false
                Write-Status "  Fixed : Transforms removed. Backup: $backup" Green
            }
            catch {
                Write-Status "  Remove failed: $_" Red
                $failed = $true
            }
        }

        if ($broken -eq 0) {
            Write-Status "No Adobe Acrobat MSI registrations with missing transforms found." Green
        }
        return (Invoke-FinalExit -Code $(if ($failed) { 8 } else { 0 }))
    }

    # -------------------------------------------------------------------------
    # Pre-flight: Is Acrobat installed?
    # -------------------------------------------------------------------------

    Write-Section "Installed Version"

    $current = Get-AdobeAcrobatInstall
    if (-not $current) {
        Write-Status "Adobe Acrobat is not installed - nothing to do." Green
        return (Invoke-FinalExit -Code 0)
    }
    $productType = if ($current.Path -match 'Reader') { 'Acrobat Reader DC' } else { 'Acrobat DC (Pro)' }
    Write-Status "Product  : $productType" Cyan
    Write-Status "Version  : $($current.Version)" Cyan
    Write-Status "Source   : $($current.Path)" DarkGray

    # -------------------------------------------------------------------------
    # Pre-flight: WinGet
    # -------------------------------------------------------------------------

    Write-Section "WinGet"

    $wingetExe = Get-WingetPath
    if (-not $wingetExe) {
        Write-Status "ERROR: WinGet not found. Install Microsoft.DesktopAppInstaller or deploy WinGet machine-wide." Red
        return (Invoke-FinalExit -Code 2)
    }
    Write-Status "Path     : $wingetExe" DarkGray

    $wingetVersion = & $wingetExe --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Status "ERROR: WinGet found but failed to execute (exit $LASTEXITCODE)." Red
        return (Invoke-FinalExit -Code 2)
    }
    Write-Status "Version  : $wingetVersion" DarkGray

    $wingetIds = @(Get-WingetAdobeIds -WingetExe $wingetExe)
    if ($wingetIds.Count -eq 0) {
        Write-Status "ERROR: No Adobe package found in WinGet. May be SCCM/GPO-managed." Red
        return (Invoke-FinalExit -Code 3)
    }
    Write-Status "Packages : $($wingetIds -join ', ')" DarkGray

    # -------------------------------------------------------------------------
    # Update check - always runs regardless of mode
    # -------------------------------------------------------------------------

    Write-Section "Update Check"

    $updateNeeded  = $false
    $latestVersion = Get-AdobeLatestVersion -WingetExe $wingetExe -PackageId $wingetIds[0]

    if (-not $latestVersion) {
        Write-Status "WARNING: Could not determine latest available version from WinGet." Yellow
        if ($mode -eq 'Check') {
            return (Invoke-FinalExit -Code 7)
        }
        Write-Status "         Proceeding with upgrade anyway - WinGet will decide." DarkGray
    }
    else {
        # Normalise both versions before comparing to handle Adobe's inconsistent
        # formatting: registry uses "26.1.21346.0", WinGet uses "26.001.21346"
        $installedNorm = ConvertTo-NormalisedVersion -Raw $current.Version
        $latestNorm    = ConvertTo-NormalisedVersion -Raw $latestVersion

        Write-Status "Installed : $($current.Version)  (normalised: $installedNorm)" White
        Write-Status "Available : $latestVersion  (normalised: $latestNorm)" White

        if ($null -eq $installedNorm -or $null -eq $latestNorm) {
            # Fallback to raw string compare if normalisation failed
            Write-Status "WARNING: Version normalisation failed - falling back to string compare." Yellow
            $updateNeeded = ($current.Version -ne $latestVersion)
        }
        else {
            $updateNeeded = ($installedNorm -ne $latestNorm)
        }

        if ($updateNeeded) {
            Write-Status "Status    : UPDATE AVAILABLE  ($installedNorm  ->  $latestNorm)" Yellow
        }
        else {
            Write-Status "Status    : ALREADY UP TO DATE  ($installedNorm)" Green
        }
    }

    # -------------------------------------------------------------------------
    # Active user check - always runs regardless of mode
    # -------------------------------------------------------------------------

    Write-Section "Active User Check"

    $activeUsers = Get-AcrobatActiveUsers

    if ($activeUsers.Count -gt 0) {
        Write-Status "Acrobat is currently IN USE by $($activeUsers.Count) process(es):" Yellow
        foreach ($u in $activeUsers) {
            $started = if ($u.StartTime) { $u.StartTime.ToString('HH:mm:ss') } else { 'unknown' }
            Write-Status ("  [{0}] PID {1} | User: {2} | Session {3} ({4}) | Started {5}" -f `
                $u.ProcessName, $u.PID, $u.User, $u.SessionId, $u.SessionState, $started) Yellow
        }
    }
    else {
        Write-Status "Acrobat is NOT currently in use by any user." Green
    }

    # -------------------------------------------------------------------------
    # CHECK mode - print summary and exit without touching anything
    # -------------------------------------------------------------------------

    if ($mode -eq 'Check') {
        $safeToPath = if (-not $updateNeeded) {
            'N/A (already current)'
        } elseif ($activeUsers.Count -eq 0) {
            'YES'
        } else {
            'NO - user(s) active (use -Force to override)'
        }

        Write-Host ""
        Write-Status "=== SUMMARY ===" Cyan
        Write-Status ("Update needed : {0}" -f $(if ($updateNeeded) { "YES  ($installedNorm -> $latestNorm)" } else { 'NO' })) `
            $(if ($updateNeeded) { 'Yellow' } else { 'Green' })
        Write-Status ("In use        : {0}" -f $(if ($activeUsers.Count -gt 0) { "YES ($($activeUsers.Count) process(es))" } else { 'NO' })) `
            $(if ($activeUsers.Count -gt 0) { 'Yellow' } else { 'Green' })
        Write-Status ("Safe to patch : {0}" -f $safeToPath) `
            $(if ($activeUsers.Count -gt 0 -and $updateNeeded) { 'Red' } else { 'Green' })

        return (Invoke-FinalExit -Code 0)
    }

    # -------------------------------------------------------------------------
    # UPDATE mode - skip if already current (unless WinGet couldn't confirm)
    # -------------------------------------------------------------------------

    if ($mode -eq 'Update' -and $latestVersion -and -not $updateNeeded) {
        Write-Status "Already up to date ($installedNorm). No action required." Green
        return (Invoke-FinalExit -Code 0)
    }

    # -------------------------------------------------------------------------
    # Active-user gate - blocks Update and Uninstall unless -Force is set
    # -------------------------------------------------------------------------

    if ($activeUsers.Count -gt 0) {
        if ($Force) {
            Write-Status "WARNING: Acrobat is in use but -Force specified - proceeding." Yellow
        }
        else {
            Write-Status "ERROR: Acrobat is currently open. Aborting to avoid data loss." Red
            Write-Status "       Use -Force to skip this check." Red
            return (Invoke-FinalExit -Code 6)
        }
    }

    # -WhatIf stops here: everything above was read-only.
    if (-not $PSCmdlet.ShouldProcess("Adobe Acrobat ($($wingetIds -join ', '))", $mode)) {
        return (Invoke-FinalExit -Code 0)
    }

    # -------------------------------------------------------------------------
    # Stop processes before making changes
    # -------------------------------------------------------------------------

    Write-Section "Stopping Adobe Processes"
    Stop-AdobeProcesses

    # -------------------------------------------------------------------------
    # UNINSTALL
    # -------------------------------------------------------------------------

    if ($mode -eq 'Uninstall') {
        Write-Section "Uninstalling"

        $anyFailed = $false
        foreach ($wingetId in $wingetIds) {
            Write-Status "Uninstalling $wingetId ..." Cyan
            # Out-Host keeps winget's text out of the return value (the exit code).
            & $wingetExe uninstall `
                --id $wingetId `
                --silent `
                --scope machine `
                --accept-source-agreements 2>&1 | Out-Host

            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
                Write-Status "Uninstalled $wingetId (exit $LASTEXITCODE)." Green
            }
            else {
                Write-Status "Uninstall failed for $wingetId (exit $LASTEXITCODE)." Red
                $anyFailed = $true
            }
        }

        Start-Sleep -Seconds 3

        if (Get-AdobeAcrobatInstall) {
            Write-Status "WARNING: Acrobat still detected after uninstall. Manual cleanup may be needed." Yellow
        }
        else {
            Write-Status "Acrobat fully removed." Green
        }

        return (Invoke-FinalExit -Code $(if ($anyFailed) { 5 } else { 0 }))
    }

    # -------------------------------------------------------------------------
    # UPDATE
    # -------------------------------------------------------------------------

    Write-Section "Upgrading"

    $WINGET_NO_UPDATE = -1978335189   # 0x8A150021
    $upgraded = $false

    foreach ($wingetId in $wingetIds) {
        Write-Status "Upgrading $wingetId ..." Cyan

        & $wingetExe upgrade `
            --id $wingetId `
            --silent `
            --scope machine `
            --accept-package-agreements `
            --accept-source-agreements `
            --override "/norestart REBOOT=ReallySuppress" 2>&1 | Out-Host

        $ec = $LASTEXITCODE

        switch ($ec) {
            { $_ -eq 0 -or $_ -eq 3010 } {
                Start-Sleep -Seconds 3
                $after = Get-AdobeAcrobatInstall
                $afterNorm = if ($after) { ConvertTo-NormalisedVersion -Raw $after.Version } else { $null }
                if ($afterNorm -and $afterNorm -ne $installedNorm) {
                    Write-Status "SUCCESS: Updated  $installedNorm  ->  $afterNorm" Green
                }
                else {
                    Write-Status "SUCCESS: WinGet exited cleanly; registry version unchanged ($installedNorm). Reboot may be needed to finalise." Green
                }
                $upgraded = $true
            }
            $WINGET_NO_UPDATE {
                Write-Status "WinGet reports no applicable update. Already current: $installedNorm" Green
                $upgraded = $true
            }
            default {
                Write-Status "Upgrade failed for $wingetId (exit $ec)." Red
            }
        }

        if ($upgraded) { break }
    }

    if (-not $upgraded) {
        Write-Status "All upgrade attempts failed. Review log: $logFile" Red
        return (Invoke-FinalExit -Code 4)
    }

    return (Invoke-FinalExit -Code 0)
}

#endregion

#region ==================== ENTRY POINT - set $RMM, then pick ONE mode ====================

# $true ONLY in an RMM component: the script then ends with 'exit <code>' so the RMM
# sees the result. Leave $false when pasting into a console or RMM remote shell -
# exit would end that session mid-way through the engineer's other patching work.
$RMM = $false

$exitCode = Start-AdobePatch
# $exitCode = Start-AdobePatch -Recon
# $exitCode = Start-AdobePatch -Update
# $exitCode = Start-AdobePatch -Update -Force
# $exitCode = Start-AdobePatch -Uninstall
# $exitCode = Start-AdobePatch -RepairTransforms
# $exitCode = Start-AdobePatch -Interactive

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
