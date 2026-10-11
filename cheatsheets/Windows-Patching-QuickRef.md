# Windows patching quick reference

Copy-paste snippets for an elevated PowerShell or an RMM remote shell (often running as SYSTEM). Run them **one block at a time**: several of them change the machine. Replace anything in `<angle brackets>`.

## Contents

- [Session tips](#session-tips)
- [Winget as SYSTEM](#winget-as-system)
- [Find installed software (all users)](#find-installed-software-all-users)
- [User profiles on the machine](#user-profiles-on-the-machine)
- [Windows Update with PSWindowsUpdate](#windows-update-with-pswindowsupdate)
- [Background jobs](#background-jobs)
- [Scheduled reboot](#scheduled-reboot)
- [Update repair: SFC, DISM, CBS log](#update-repair-sfc-dism-cbs-log)
- [Teams Rooms updates (MTRP)](#teams-rooms-updates-mtrp)
- [Remove stale Teams AppX packages](#remove-stale-teams-appx-packages)
- [Watch MSI installs live](#watch-msi-installs-live)
- [Office (Click-to-Run) update](#office-click-to-run-update)

## Session tips

Remote shells redraw faster without PSReadLine:

```powershell
Remove-Module PSReadLine -ErrorAction SilentlyContinue
```

## Winget as SYSTEM

`winget` isn't on PATH for SYSTEM. Resolve it from the App Installer package once per session, then reuse `$winget`:

```powershell
$winget = "$((Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller | Select-Object -Last 1).InstallLocation)\winget.exe"
& $winget --version
```

List and check:

```powershell
& $winget upgrade                              # everything with an update available
& $winget list --id Microsoft.PowerToys        # one package by ID
& $winget list --name nmap                     # search installed by name
(Get-AppxPackage -Name Microsoft.PowerToys*).Version
```

Update, install, remove:

```powershell
$quiet = '--silent', '--accept-package-agreements', '--accept-source-agreements'

& $winget upgrade --id Google.Chrome --exact @quiet
& $winget upgrade --id Microsoft.PowerToys --source winget
& $winget upgrade --id Microsoft.DotNet.SDK.9 @quiet
& $winget upgrade --id <Package.Id> @quiet 2>$null      # hide winget's progress noise
& $winget install --id <Package.Id> -e @quiet
& $winget uninstall --id Insecure.Nmap --purge --force @quiet

& $winget upgrade --all @quiet 2>&1                     # upgrade everything
```

> Some apps aren't managed by winget at all. Adobe Reader, for example, updates itself through `C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe`. See `Patching/Adobe/Adobe-Acrobat-morph.ps1`.

## Find installed software (all users)

Searches the machine-wide uninstall keys plus every **loaded** user hive. Users who are signed out aren't covered.

```powershell
function Get-Software {
    param([string]$Filter = '*')

    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    (Get-ChildItem 'REGISTRY::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '_Classes$' }).PSChildName | ForEach-Object {
        $paths += "REGISTRY::HKEY_USERS\$_\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $paths += "REGISTRY::HKEY_USERS\$_\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    $paths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -like $Filter } |
        Select-Object DisplayName, DisplayVersion, Publisher, UninstallString |
        Sort-Object DisplayName | Format-Table -AutoSize
}

Get-Software '*<AppName>*'

#removal with exit code:
$p = Start-Process msiexec.exe -ArgumentList '/x "{<GUID>}" /qn /norestart' -Wait -PassThru
$p.ExitCode

#removal from registry:
Get-ItemProperty `
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{<GUID>}' `
-Name LocalPackage,InstallSource -ErrorAction SilentlyContinue
```

One-liner for the machine-wide keys plus the current user only:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like '*<AppName>*' } |
    Select-Object DisplayName, DisplayVersion, UninstallString
```

Act on what you found (the GUID comes from `UninstallString`):

```powershell
msiexec /x {<ProductCode-GUID>} /qn /norestart       # uninstall an MSI silently
msiexec /i {<ProductCode-GUID>} /qn /norestart       # reinstall/repair from the cached MSI
```

To clean the uninstall entry left behind, remove several GUIDs, or uninstall a setup `.exe` bundle from Package Cache, see [MSI uninstall by GUID](MSI-Uninstall-by-GUID.md).

## User profiles on the machine

```powershell
Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
    $user = try {
        ([Security.Principal.SecurityIdentifier]$_.SID).Translate([Security.Principal.NTAccount])
    } catch { 'Unknown' }
    [pscustomobject]@{ Username = $user; Path = $_.LocalPath; LastUsed = $_.LastUseTime }
}
```

## Windows Update with PSWindowsUpdate

### Setup

Prefer a **process-scoped** execution policy, which leaves the machine policy untouched and ends with the session:

```powershell
Get-ExecutionPolicy -List
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

If something needs it machine-wide, set it, then put it back afterwards:

```powershell
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force
# ... work ...
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Undefined -Force
```

Install the module:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module PSWindowsUpdate -Force -Confirm:$false
Import-Module PSWindowsUpdate
```

### Check and install

```powershell
Get-WindowsUpdate                                         # what's pending
Install-WindowsUpdate -AcceptAll -IgnoreReboot            # install all, no reboot
Get-WURebootStatus                                        # is a reboot pending?

# With a reboot:
# Install-WindowsUpdate -AcceptAll -AutoReboot
# Install-WindowsUpdate -AcceptAll -ScheduleReboot (Get-Date).AddMinutes(30)
```

### Specific KBs

```powershell
Install-WindowsUpdate -KBArticleID KB<number> -AcceptAll -IgnoreReboot -Verbose
Install-WindowsUpdate -KBArticleID KB<number>, KB<number> -AcceptAll          # several at once
Get-WindowsUpdate     -KBArticleID KB<number> -AcceptAll -Download            # download only
# Install-WindowsUpdate -KBArticleID KB<number> -AcceptAll -AutoReboot        # install and reboot
```

### Run it in the background (local or remote)

```powershell
# Local, without blocking the shell:
Start-Job -ScriptBlock { Install-WindowsUpdate -AcceptAll -IgnoreReboot }

# Remote machine (needs WinRM):
Invoke-Command -ComputerName <COMPUTERNAME> -ScriptBlock {
    Get-WindowsUpdate -KBArticleID KB<number> -AcceptAll -Download
} -AsJob
```

Track the jobs with [Background jobs](#background-jobs).

## Background jobs

```powershell
Get-Job | Format-Table Id, State

# Refresh every 5 s until nothing is running:
do {
    Get-Job | Format-Table Id, State -AutoSize
    Start-Sleep -Seconds 5
} while (Get-Job | Where-Object State -eq 'Running')

# Collect output from finished jobs:
Get-Job | Where-Object State -eq 'Completed' | Receive-Job
```

## Scheduled reboot

One-off forced reboot as SYSTEM at a set time today (24-hour clock):

```powershell
schtasks /create /tn "Reboot" /tr "shutdown /r /t 0 /f" /sc once /st 18:05 /ru SYSTEM /f
schtasks /query  /tn "Reboot"       # check
schtasks /delete /tn "Reboot" /f    # cancel
```

## Update repair: SFC, DISM, CBS log

The usual first steps when updates fail because system files are corrupt. They didn't fix the KB5077181 failure, but they're cheap to try:

```powershell
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
```

Recent errors in the CBS log:

```powershell
$cbsLog = "$env:windir\Logs\CBS\CBS.log"
$today  = (Get-Date).ToString('yyyy-MM-dd')     # or a specific date, e.g. '2026-10-09'

Select-String -Path $cbsLog -Pattern 'error|fail|corrupt|0x8' |
    Where-Object { $_.Line -match $today } | Select-Object -Last 50

# Any date:
# Select-String -Path $cbsLog -Pattern 'error|fail|corrupt|0x8' | Select-Object -Last 50
```

## Teams Rooms updates (MTRP)

On Microsoft Teams Rooms devices, the `MTRP.Powershell.Utils` module lists the updates:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
Import-Module MTRP.Powershell.Utils

Get-MTRPWindowsUpdate | ForEach-Object {
    [pscustomobject]@{
        Title = $_.Title; KB = $_.KB; Size = $_.Size
        IsInstalled = $_.IsInstalled; IsDownloaded = $_.IsDownloaded; RebootRequired = $_.RebootRequired
    }
} | Format-Table Title, KB, Size, IsDownloaded, RebootRequired -Wrap
```

## Remove stale Teams AppX packages

Stale New Teams packages, such as the `1.0.0.0` placeholder, can block updates or get flagged by scanners. List them first, then remove by version or full name:

```powershell
Get-AppxPackage -AllUsers 'MSTeams*' | Select-Object PackageFullName, Version

Get-AppxPackage -AllUsers 'MSTeams*' | Where-Object Version -eq '1.0.0.0' | Remove-AppxPackage -AllUsers
Get-AppxPackage -AllUsers | Where-Object PackageFullName -eq '<PackageFullName>' | Remove-AppxPackage -AllUsers
```

For a full Teams clean-up, use `Patching/Teams/teams-omega.ps1`.

## Watch MSI installs live

Useful when an update hangs or reports 1618 ("another installation is in progress"). Press Ctrl+C to stop.

```powershell
function Watch-Msi {
    while ($true) {
        Clear-Host
        Write-Host "$(Get-Date -Format T) | MSI processes | Ctrl+C to stop"
        $procs = Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'"
        if ($procs) { $procs | Format-List ProcessId, ParentProcessId, CreationDate, CommandLine | Out-Host }
        else { Write-Host 'No msiexec.exe processes found.' }
        Start-Sleep -Seconds 2
    }
}
Watch-Msi
```

## Office (Click-to-Run) update

Starts an update that the user can see. `forceappshutdown=false` lets them save their work first:

```powershell
& 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe' /update user displaylevel=true forceappshutdown=false
```
