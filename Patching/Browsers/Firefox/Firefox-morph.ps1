# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Mozilla Firefox - Check / Update / Uninstall. RMM-ready.

.DESCRIPTION
    -Mode Check      DEFAULT. Read-only. Lists every desktop Firefox found: machine-wide
                     installs (Program Files, both architectures) and per-user installs in
                     every Windows profile (AppData\Local and AppData\Local\Programs), with
                     the firefox.exe version. Also lists Firefox uninstall registrations
                     (HKLM, both registry views, and the hives of logged-on users), Store/MSIX
                     Firefox packages (all users when elevated), and which profiles hold
                     Firefox profile data. No version comparison: the latest version needs a
                     network call, which only Update makes. Offline user hives are not loaded.
    -Mode Update     Updates the machine-wide (HKLM) Firefox to the latest release. Reads the
                     latest version from product-details.mozilla.org; if newer, downloads the
                     full installer for the installed architecture and language, checks its
                     Mozilla Corporation Authenticode signature, runs it silently (/S) and
                     re-reads the installed version. Per-user, ESR and Store installs are not
                     updated. -WhatIf shows the version comparison and downloads nothing.
    -Mode Uninstall  Manual cleanup of desktop Firefox for all users (Remove-Firefox): no
                     uninstaller, MSI or package API is used. Closes running Firefox (unsaved
                     work in it is lost), deletes install folders, scheduled tasks, shortcuts,
                     firewall rules, update caches and registrations, including in the hives of
                     logged-off users (loaded temporarily, unloaded afterwards). Store/MSIX
                     packages are reported, not removed. Then re-checks.
                     Firefox PROFILES (bookmarks, saved passwords, history, sessions) are KEPT
                     unless -Options @{ RemoveProfiles = $true } is passed. That option deletes
                     every user's Firefox profile data permanently; there is no undo.
                     Other options: AdditionalInstallPath / AdditionalProfilePath (exact,
                     dedicated folders to delete; profile paths need RemoveProfiles too) and
                     RemoveSharedMaintenanceService (MozillaMaintenance is shared with Thunderbird).

    Requirements: Windows PowerShell 5.1, 64-bit for Uninstall. Update and Uninstall need an
    elevated or SYSTEM session, also for -WhatIf.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the mode - edit that one
    line. For an RMM component also set $RMM = $true there, so the script exits with the code.

    Invoke-Firefox                                                  # Check (read-only)
    Invoke-Firefox -Mode Update -WhatIf                             # Show installed vs latest
    Invoke-Firefox -Mode Update                                     # Update machine-wide Firefox
    Invoke-Firefox -Mode Uninstall -WhatIf                          # Preview removal
    Invoke-Firefox -Mode Uninstall                                  # Remove Firefox, keep profiles
    Invoke-Firefox -Mode Uninstall -Options @{ RemoveProfiles = $true }                  # ALSO deletes profiles
    Invoke-Firefox -Mode Uninstall -Options @{ RemoveSharedMaintenanceService = $true } -WhatIf

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-Firefox returns one; the entry point exits with it only when $RMM = $true):
        0    Check: no Firefox found / Update: up to date, updated, no machine-wide Firefox,
             or -WhatIf / Uninstall: removed and verified (or -WhatIf)
        1    Error, update failed or unverified, unrecognised (ESR/beta) version, or removal
             incomplete (see output)
        2    Check: Firefox present (install folder, uninstall registration or Store package)
        10   Update / Uninstall: session is not elevated - nothing changed
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region -------------------- Get-FirefoxState (read-only detection) --------------------

function Get-FirefoxState {
    # Same locations and name filters Remove-Firefox uses, read-only (no offline hives).
    $profiles = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.ProfileImagePath } | ForEach-Object {
            [pscustomobject]@{
                SID = $_.PSChildName
                Path = [Environment]::ExpandEnvironmentVariables($_.ProfileImagePath)
            }
        })
    $names = @('Mozilla Firefox', 'Firefox Developer Edition', 'Firefox Nightly')
    $folders = @(
        foreach ($root in (@($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Sort-Object -Unique)) {
            foreach ($name in ($names + 'Nightly')) { , @('Machine', '', "$root\$name") }
        }
        foreach ($p in $profiles) {
            foreach ($name in $names) {
                foreach ($sub in @('AppData\Local', 'AppData\Local\Programs')) {
                    , @('PerUser', (Split-Path $p.Path -Leaf), "$($p.Path)\$sub\$name")
                }
            }
        }
    )
    $installs = @(foreach ($f in $folders) {
        $exe = "$($f[2])\firefox.exe"
        if (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue) {
            [pscustomobject]@{
                Type    = $f[0]
                User    = $f[1]
                Version = (Get-Item -LiteralPath $exe -Force).VersionInfo.ProductVersion
                Path    = $f[2]
            }
        }
    })

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    ) + @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -notlike '*_Classes' } |
        ForEach-Object { "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Uninstall" })
    $registrations = @(foreach ($root in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
        $hive = if ($root -like 'HKLM:*') { 'HKLM' } else { ($root -split '\\')[1] }
        Get-ItemProperty "$root\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '^(?:Mozilla Firefox|Firefox Developer Edition)(?:\s|$)' } |
            Select-Object @{ n = 'Hive'; e = { $hive } }, DisplayName, DisplayVersion, InstallLocation
    })

    $store = @()
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $packages = if (Test-IsAdmin) { Get-AppxPackage -AllUsers } else { Get-AppxPackage }
            $store = @($packages | Where-Object Name -Match 'Firefox' | Select-Object Name, Version, PackageFullName)
        } catch { Write-Host "Could not inspect Store packages: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    $profileData = @(foreach ($p in $profiles) {
        $roaming = "$($p.Path)\AppData\Roaming\Mozilla\Firefox"
        if (Test-Path -LiteralPath "$roaming\profiles.ini" -ErrorAction SilentlyContinue) { $roaming }
    })

    [pscustomobject]@{
        Installs      = $installs
        Registrations = $registrations
        Store         = $store
        ProfileData   = $profileData
        Present       = [bool]($installs.Count + $registrations.Count + $store.Count)
    }
}

function Show-FirefoxState {
    param($State)
    Write-Host '=== Desktop installs (firefox.exe found) ===' -ForegroundColor Cyan
    if ($State.Installs) { $State.Installs | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Uninstall registrations (HKLM + logged-on users) ===' -ForegroundColor Cyan
    if ($State.Registrations) { $State.Registrations | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Store / MSIX packages ===' -ForegroundColor Cyan
    if ($State.Store) { $State.Store | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Firefox profile data (bookmarks, passwords; deleted only with RemoveProfiles) ===' -ForegroundColor Cyan
    if ($State.ProfileData) { $State.ProfileData | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  none' }
}

#endregion

#region -------------------- Update-Firefox (from firefoxupdate.ps1) --------------------

function Update-Firefox {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    $registryPaths = @(
        'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
        'HKLM:\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox'
    )

    $prev = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        # CurrentVersion reads like '128.0 (x64 en-US)'.
        $installedFull = $registryPaths |
            ForEach-Object { (Get-ItemProperty $_ -ErrorAction SilentlyContinue).CurrentVersion } |
            Where-Object { $_ } |
            Select-Object -First 1

        if (-not $installedFull) {
            Write-Warning 'Firefox not installed machine-wide (HKLM). Per-user installs are not updated by this mode.'
            return 0
        }

        $installed = ($installedFull -split ' ')[0]
        if ($installed -notmatch '^\d+(?:\.\d+)+$') {
            Write-Warning "Unrecognised Firefox version '$installedFull' (ESR or beta?). Not updating."
            return 1
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $latest = (Invoke-RestMethod 'https://product-details.mozilla.org/1.0/firefox_versions.json' -UseBasicParsing).LATEST_FIREFOX_VERSION
        if (-not $latest) { throw 'Could not read LATEST_FIREFOX_VERSION from product-details.mozilla.org.' }
        Write-Host "Installed: $installedFull | Latest: $latest"

        if ([version]$installed -ge [version]$latest) {
            Write-Host "Firefox is up to date ($installed)."
            return 0
        }

        if (-not $PSCmdlet.ShouldProcess("Mozilla Firefox $installed", "Update to $latest")) {
            return 0
        }

        # Match the installed build, so a 32-bit or non-English install is replaced in place.
        $arch = if ([Environment]::Is64BitOperatingSystem) { 'win64' } else { 'win' }
        $lang = 'en-US'
        if ($installedFull -match '\((x86|x64|AArch64) ([A-Za-z]{2,3}(?:-[A-Za-z]+)?)\)') {
            $arch = @{ x86 = 'win'; x64 = 'win64'; AArch64 = 'win64-aarch64' }[$Matches[1]]
            $lang = $Matches[2]
        }
        $url = "https://download.mozilla.org/?product=firefox-latest-ssl&os=$arch&lang=$lang"
        # Unique name: a fixed name in a shared TEMP could be pre-planted by another user.
        $file = Join-Path $env:TEMP ('FirefoxSetup_' + [Guid]::NewGuid().ToString('N') + '.exe')

        Write-Host "Updating $installed -> $latest ($arch $lang) ..."
        try {
            Invoke-WebRequest $url -OutFile $file -UseBasicParsing
            $signature = Get-AuthenticodeSignature -LiteralPath $file
            if ($signature.Status -ne 'Valid' -or
                $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O="?Mozilla Corporation"?(?:,|$)') {
                throw 'The downloaded installer does not have a valid Mozilla Corporation signature. Not run.'
            }
            $process = Start-Process $file -ArgumentList '/S' -Wait -NoNewWindow -PassThru
            if ($process.ExitCode -ne 0) { throw "Firefox installer exited with code $($process.ExitCode)." }

            $now = $registryPaths |
                ForEach-Object { (Get-ItemProperty $_ -ErrorAction SilentlyContinue).CurrentVersion } |
                Where-Object { $_ } |
                Select-Object -First 1
            if (-not $now -or [version](($now -split ' ')[0]) -lt [version]$latest) {
                Write-Warning "Installer finished, but the installed version reads '$now'. Check that Firefox was not running; rerun or reboot."
                return 1
            }
            Write-Host "Firefox updated to $latest."
            return 0
        }
        finally {
            Remove-Item $file -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        $ProgressPreference = $prev
    }
}

#endregion

#region -------------------- Remove-Firefox (from Firefox_Uninstall.ps1) --------------------

function Remove-Firefox {
    <#
    .SYNOPSIS
        Manually removes Firefox desktop installations without invoking uninstallers.
    .DESCRIPTION
        Run in elevated, 64-bit Windows PowerShell 5.1 or PowerShell 7.
        Keeps Firefox profile data unless -RemoveProfiles is given. With it, deletes
        every user's profiles, including passwords, bookmarks and sessions.
        All mutations honor ShouldProcess (-WhatIf and -Confirm). Offline hives
        are temporarily mounted only during a real run and unloaded in finally.
        WhatIf reports those hives as deferred; it cannot enumerate their contents.

        Covers standard locations for registered Windows profiles, registered
        desktop installations, Firefox tasks, shortcuts, browser registrations,
        and update caches whose installation IDs can be identified.

        Does not guarantee forensic erasure. Store/MSIX packages, policy-managed
        reinstallations, backups, arbitrary portable copies, redirected folders,
        custom profile folders and protected/default-app association records may
        require separate attention. Warnings and the returned Issues list matter.
        No uninstall executable, MSI, Win32_Product or package-removal API is used.
    .PARAMETER AdditionalInstallPath
        Exact dedicated Firefox installation folders, including portable copies.
        Their entire contents will be deleted. Do not supply a shared directory.
    .PARAMETER AdditionalProfilePath
        Exact dedicated Firefox data folders outside the standard profile tree.
        Their entire contents will be deleted. Do not supply a shared directory.
        Ignored (with a warning) unless -RemoveProfiles is also given.
    .PARAMETER RemoveProfiles
        Also deletes every user's Firefox profile data (Roaming, Local and LocalLow
        Mozilla\Firefox, and Desktop\Old Firefox Data): bookmarks, saved passwords,
        history and sessions. Off by default; there is no undo.
    .PARAMETER RemoveSharedMaintenanceService
        Also deletes MozillaMaintenance and its standard program folders and
        registration. This service is shared with Thunderbird; opt in deliberately.
    .EXAMPLE
        Remove-Firefox -WhatIf
    .EXAMPLE
        Remove-Firefox
    .EXAMPLE
        Remove-Firefox -RemoveSharedMaintenanceService -WhatIf
    .EXAMPLE
        Remove-Firefox -RemoveProfiles -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string[]] $AdditionalInstallPath = @(),
        [string[]] $AdditionalProfilePath = @(),
        [switch] $RemoveSharedMaintenanceService,
        [switch] $RemoveProfiles
    )

    $ErrorActionPreference = 'Stop'
    if ($env:OS -ne 'Windows_NT') { throw 'This function requires Windows.' }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run this in 64-bit PowerShell so both registry views can be inspected.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell with Run as administrator, including for -WhatIf.'
    }

    $issues = [Collections.Generic.List[string]]::new()
    $installs = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $keys = [Collections.Generic.List[string]]::new()
    $softwareRoots = [Collections.Generic.List[string]]::new()
    $classRoots = [Collections.Generic.List[string]]::new()
    $mounts = [Collections.Generic.List[string]]::new()
    $hashes = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $counts = @{ Removed = 0; DeferredHives = 0 }
    $report = {
        param([string] $Message)
        $issues.Add($Message)
        Write-Warning $Message
    }
    $children = {
        param([string] $Path)
        if (Test-Path -LiteralPath $Path) { Get-ChildItem -LiteralPath $Path -Force }
    }
    $profiles = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
        Where-Object { $_.ProfileImagePath } | ForEach-Object {
            [pscustomobject]@{
                SID = $_.PSChildName
                Path = [Environment]::ExpandEnvironmentVariables($_.ProfileImagePath)
            }
        })
    $programRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ } | Sort-Object -Unique
    $protected = @($env:SystemRoot, $env:ProgramData, $env:PUBLIC) +
        @($programRoots) + @($profiles.Path)
    foreach ($userProfile in $profiles) {
        $protected += "$($userProfile.Path)\AppData", "$($userProfile.Path)\AppData\Local",
            "$($userProfile.Path)\AppData\Roaming", "$($userProfile.Path)\Desktop",
            "$($userProfile.Path)\Documents", "$($userProfile.Path)\Downloads"
    }

    # Reject broad deletion targets and junctions/symlinks, including in parents.
    $validateDirectory = {
        param([string] $Path)
        if ($Path -notmatch '^[A-Za-z]:\\') { throw "Not a local absolute path: $Path" }
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        if ($full -eq [IO.Path]::GetPathRoot($full).TrimEnd('\')) {
            throw "Refusing a drive root: $full"
        }
        foreach ($boundary in $protected) {
            if (-not $boundary) { continue }
            $boundary = [IO.Path]::GetFullPath($boundary).TrimEnd('\')
            if ($boundary -eq $full -or $boundary.StartsWith($full + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing a protected folder or its ancestor: $full"
            }
        }
        if ($full.StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing a folder inside Windows: $full"
        }
        $cursor = $full
        while ($cursor) {
            if (Test-Path -LiteralPath $cursor) {
                $item = Get-Item -LiteralPath $cursor -Force
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Reparse point requires manual review: $cursor"
                }
            }
            $cursor = Split-Path -Path $cursor -Parent
        }
        $full
    }
    # Enumerate without following reparse points; fail closed if one is found.
    $walk = {
        param([string] $Path)
        $stack = [Collections.Generic.Stack[string]]::new()
        $stack.Push($Path)
        while ($stack.Count) {
            foreach ($item in (& $children ($stack.Pop()))) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Reparse point requires manual review: $($item.FullName)"
                }
                $item
                if ($item.PSIsContainer) { $stack.Push($item.FullName) }
            }
        }
    }
    $remove = {
        param([string] $Path)
        try {
            if (-not (Test-Path -LiteralPath $Path)) { return }
            $item = Get-Item -LiteralPath $Path -Force
            if ($item.PSProvider.Name -eq 'FileSystem') {
                if ($item.PSIsContainer) {
                    $null = & $validateDirectory $Path
                    $null = & $walk $Path
                } else {
                    $null = & $validateDirectory (Split-Path -Path $Path -Parent)
                    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                        throw "Reparse point requires manual review: $Path"
                    }
                }
            }
            if ($PSCmdlet.ShouldProcess($Path, 'Permanently delete')) {
                Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false
                $counts.Removed++
            }
        } catch { & $report "Could not remove $Path : $($_.Exception.Message)" }
    }
    $owned = {
        param([string] $Executable)
        if (-not $Executable) { return $false }
        $Executable = $Executable.Trim('"')
        foreach ($directory in $installs) {
            if ($Executable.StartsWith($directory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    try {
        # Observe packaged installs; never tamper with WindowsApps or package state.
        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            try {
                foreach ($package in @(Get-AppxPackage -AllUsers | Where-Object Name -Match 'Firefox')) {
                    & $report "Store/MSIX package is outside this manual desktop cleanup: $($package.PackageFullName)"
                }
            } catch { & $report "Could not inspect Store packages: $($_.Exception.Message)" }
        }

        $softwareRoots.Add('Registry::HKEY_LOCAL_MACHINE\Software')
        $softwareRoots.Add('Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node')
        $classRoots.Add('Registry::HKEY_LOCAL_MACHINE\Software\Classes')
        $classRoots.Add('Registry::HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node')

        # All loaded users, including users not in the normal profile list.
        foreach ($hive in Get-ChildItem Registry::HKEY_USERS) {
            if ($hive.PSChildName -like '*_Classes') {
                $classRoots.Add("Registry::$($hive.Name)")
            } else {
                $softwareRoots.Add("Registry::$($hive.Name)\Software")
                $softwareRoots.Add("Registry::$($hive.Name)\Software\WOW6432Node")
                $classRoots.Add("Registry::$($hive.Name)\Software\Classes")
            }
            $hive.Close()
        }
        foreach ($userProfile in $profiles) {
            foreach ($kind in @('User', 'Classes')) {
                $sid = $userProfile.SID
                $hiveFile = "$($userProfile.Path)\NTUSER.DAT"
                if ($kind -eq 'Classes') {
                    $sid += '_Classes'
                    $hiveFile = "$($userProfile.Path)\AppData\Local\Microsoft\Windows\UsrClass.dat"
                }
                if (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid") { continue }
                if (-not (Test-Path -LiteralPath $hiveFile)) { continue }
                if (-not $PSCmdlet.ShouldProcess($hiveFile, 'Temporarily load offline hive to discover and clean Firefox registrations')) {
                    $counts.DeferredHives++
                    continue
                }
                $mountName = 'FirefoxCleanup_' + [Guid]::NewGuid().ToString('N')
                try {
                    $message = & "$env:SystemRoot\System32\reg.exe" load "HKU\$mountName" $hiveFile 2>&1
                    if ($LASTEXITCODE -ne 0) { throw ($message -join ' ') }
                    $mounts.Add($mountName)
                    $base = "Registry::HKEY_USERS\$mountName"
                    if ($kind -eq 'Classes') { $classRoots.Add($base) }
                    else {
                        $softwareRoots.Add("$base\Software")
                        $softwareRoots.Add("$base\Software\WOW6432Node")
                        $classRoots.Add("$base\Software\Classes")
                    }
                } catch { & $report "Could not inspect offline hive $hiveFile : $($_.Exception.Message)" }
            }
        }

        foreach ($root in $programRoots) {
            foreach ($name in @('Mozilla Firefox', 'Firefox Developer Edition', 'Firefox Nightly', 'Nightly')) {
                $candidate = "$root\$name"
                # A generic 'Nightly' folder must contain Firefox to be included.
                if ($name -ne 'Nightly' -or (Test-Path -LiteralPath "$candidate\firefox.exe")) {
                    $installs.Add($candidate)
                }
            }
        }
        foreach ($userProfile in $profiles) {
            $userPath = $userProfile.Path
            foreach ($name in @('Mozilla Firefox', 'Firefox Developer Edition', 'Firefox Nightly')) {
                $installs.Add("$userPath\AppData\Local\$name")
                $installs.Add("$userPath\AppData\Local\Programs\$name")
            }
            $roaming = "$userPath\AppData\Roaming\Mozilla\Firefox"
            # Profile data is opt-in: the source deleted it by default.
            if ($RemoveProfiles) {
                $files.Add($roaming)
                $files.Add("$userPath\AppData\Local\Mozilla\Firefox")
                $files.Add("$userPath\AppData\LocalLow\Mozilla\Firefox")
                $files.Add("$userPath\Desktop\Old Firefox Data")
            }
            # Preserve external profiles unless the caller explicitly supplies them.
            foreach ($ini in @("$roaming\profiles.ini", "$roaming\installs.ini")) {
                if (-not (Test-Path -LiteralPath $ini)) { continue }
                foreach ($line in Get-Content -LiteralPath $ini) {
                    if ($line -match '^\[(?:Install)?([0-9A-Fa-f]{8,32})\]$') {
                        $null = $hashes.Add($Matches[1])
                    }
                    if ($line -match '^(?:Path|Default)=(.+)$') {
                        $value = $Matches[1].Trim().Replace('/', '\')
                        if (-not [IO.Path]::IsPathRooted($value)) { $value = "$roaming\$value" }
                        $value = [IO.Path]::GetFullPath($value)
                        if ($RemoveProfiles -and
                            -not $value.StartsWith($roaming + '\', [StringComparison]::OrdinalIgnoreCase) -and
                            $AdditionalProfilePath -notcontains $value) {
                            & $report "External profile reference: $value . Review and supply -AdditionalProfilePath to delete it."
                        }
                    }
                }
            }
        }
        foreach ($path in $AdditionalInstallPath) { $installs.Add((& $validateDirectory $path)) }
        if ($RemoveProfiles) {
            foreach ($path in $AdditionalProfilePath) { $files.Add((& $validateDirectory $path)) }
        } else {
            if ($AdditionalProfilePath) { & $report 'AdditionalProfilePath ignored: deleting profile data needs -RemoveProfiles.' }
            Write-Host 'Firefox profiles (bookmarks, saved passwords, history) are kept. Use -RemoveProfiles to delete them.'
        }

        # Discover program paths before deleting their registration.
        foreach ($root in ($softwareRoots | Sort-Object -Unique)) {
            foreach ($entry in (& $children "$root\Microsoft\Windows\CurrentVersion\Uninstall")) {
                $path = "Registry::$($entry.Name)"
                $entry.Close()
                $record = Get-ItemProperty -LiteralPath $path
                if ($record.DisplayName -notmatch '^(?:Mozilla Firefox|Firefox Developer Edition)(?:\s|$)') { continue }
                $keys.Add($path)
                $candidates = @($record.InstallLocation)
                if ($record.UninstallString -match '^\s*"?(.+?)\\uninstall\\helper\.exe"?(?:\s|$)') {
                    $candidates += $Matches[1]
                }
                foreach ($candidate in $candidates) {
                    if (-not $candidate) { continue }
                    try {
                        $candidate = & $validateDirectory $candidate
                        if (Test-Path -LiteralPath "$candidate\firefox.exe") { $installs.Add($candidate) }
                        elseif (Test-Path -LiteralPath $candidate) {
                            & $report "Unverified install folder: $candidate . Supply -AdditionalInstallPath after reviewing it."
                        }
                    } catch { & $report $_.Exception.Message }
                }
            }
            foreach ($entry in (& $children "$root\Mozilla")) {
                $path = "Registry::$($entry.Name)"
                $name = $entry.PSChildName
                $entry.Close()
                if ($name -notmatch '^(?:Mozilla )?Firefox(?:\s|$)') { continue }
                $keys.Add($path)
                if (Test-Path -LiteralPath "$path\TaskBarIDs") {
                    $idKey = Get-Item -LiteralPath "$path\TaskBarIDs"
                    try {
                        foreach ($valueName in $idKey.GetValueNames()) {
                            $hash = [string] $idKey.GetValue($valueName)
                            if ($hash -match '^[0-9A-Fa-f]{8,32}$') { $null = $hashes.Add($hash) }
                            if ($valueName -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath "$valueName\firefox.exe")) {
                                $installs.Add((& $validateDirectory $valueName))
                            }
                        }
                    } finally { $idKey.Close() }
                }
            }
            $keys.Add("$root\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe")
            foreach ($entry in (& $children "$root\Clients\StartMenuInternet")) {
                if ($entry.PSChildName -match '^Firefox(?:-|$)') { $keys.Add("Registry::$($entry.Name)") }
                $entry.Close()
            }
            $registered = "$root\RegisteredApplications"
            if (Test-Path -LiteralPath $registered) {
                $regKey = Get-Item -LiteralPath $registered
                try { $names = @($regKey.GetValueNames()) } finally { $regKey.Close() }
                foreach ($name in $names) {
                    if ($name -match '^Firefox(?:-|$)' -and $PSCmdlet.ShouldProcess("$registered : $name", 'Delete Firefox registration value')) {
                        Remove-ItemProperty -LiteralPath $registered -Name $name -Confirm:$false
                        $counts.Removed++
                    }
                }
            }
        }
        foreach ($root in ($classRoots | Sort-Object -Unique)) {
            $keys.Add("$root\Applications\firefox.exe")
            foreach ($entry in (& $children $root)) {
                if ($entry.PSChildName -match '^Firefox(?:HTML|URL|PDF)(?:-|$)') { $keys.Add("Registry::$($entry.Name)") }
                $entry.Close()
            }
        }
        foreach ($root in ($softwareRoots | Sort-Object -Unique)) {
            foreach ($runName in @('Run', 'RunOnce')) {
                $runPath = "$root\Microsoft\Windows\CurrentVersion\$runName"
                if (-not (Test-Path -LiteralPath $runPath)) { continue }
                $runKey = Get-Item -LiteralPath $runPath
                try {
                    foreach ($name in $runKey.GetValueNames()) {
                        $command = [string] $runKey.GetValue($name)
                        if ($command -notmatch '^\s*(?:"([^"]+)"|(\S+))') { continue }
                        $executable = $Matches[1]
                        if (-not $executable) { $executable = $Matches[2] }
                        if ((& $owned $executable) -and $PSCmdlet.ShouldProcess("$runPath : $name", 'Delete Firefox startup value')) {
                            Remove-ItemProperty -LiteralPath $runPath -Name $name -Confirm:$false
                            $counts.Removed++
                        }
                    }
                } finally { $runKey.Close() }
            }
        }
        foreach ($hash in $hashes) {
            foreach ($base in @("$env:ProgramData\Mozilla", "$env:ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38")) {
                $files.Add("$base\updates\$hash")
                $files.Add("$base\profile_count_$hash.json")
            }
            foreach ($userProfile in $profiles) { $files.Add("$($userProfile.Path)\AppData\Local\Mozilla\updates\$hash") }
        }

        # Disable/delete background launch points, then stop Firefox processes.
        foreach ($task in Get-ScheduledTask) {
            $isFirefox = $task.TaskPath -eq '\Mozilla\' -and
                $task.TaskName -match '^Firefox (?:Default Browser Agent|Background Update)(?:\s|$)'
            foreach ($action in $task.Actions) { if (& $owned $action.Execute) { $isFirefox = $true } }
            if ($isFirefox -and $PSCmdlet.ShouldProcess($task.TaskPath + $task.TaskName, 'Stop and delete scheduled task')) {
                try {
                    if ($task.State -eq 'Running') { Stop-ScheduledTask -InputObject $task }
                    Unregister-ScheduledTask -InputObject $task -Confirm:$false
                    $counts.Removed++
                } catch { & $report "Could not delete task $($task.TaskName): $($_.Exception.Message)" }
            }
        }
        foreach ($process in Get-CimInstance Win32_Process) {
            if ($process.Name -eq 'firefox.exe' -or (& $owned $process.ExecutablePath)) {
                if ($PSCmdlet.ShouldProcess("$($process.Name) PID $($process.ProcessId)", 'Stop process')) {
                    try { Stop-Process -Id $process.ProcessId -Force -Confirm:$false }
                    catch { & $report "Could not stop PID $($process.ProcessId): $($_.Exception.Message)" }
                }
            }
        }
        if (Get-Command Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) {
            try {
                foreach ($filter in Get-NetFirewallApplicationFilter -PolicyStore PersistentStore) {
                    if (-not (& $owned $filter.Program)) { continue }
                    foreach ($rule in @(Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $filter)) {
                        if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Delete local Firefox firewall rule')) {
                            Remove-NetFirewallRule -InputObject $rule -Confirm:$false
                            $counts.Removed++
                        }
                    }
                }
            } catch { & $report "Could not fully clean local firewall rules: $($_.Exception.Message)" }
        }

        if ($RemoveSharedMaintenanceService) {
            $serviceOK = $true
            $service = Get-Service MozillaMaintenance -ErrorAction SilentlyContinue
            if ($service -and $PSCmdlet.ShouldProcess('MozillaMaintenance (shared with Thunderbird)', 'Stop and delete service')) {
                try {
                    if ($service.Status -ne 'Stopped') { Stop-Service MozillaMaintenance -Force -Confirm:$false }
                    $message = & "$env:SystemRoot\System32\sc.exe" delete MozillaMaintenance 2>&1
                    if ($LASTEXITCODE -ne 0) { throw ($message -join ' ') }
                    $counts.Removed++
                } catch {
                    $serviceOK = $false
                    & $report "Could not delete maintenance service: $($_.Exception.Message)"
                }
            } elseif ($service -and -not $WhatIfPreference) { $serviceOK = $false }
            if ($serviceOK) {
                foreach ($root in $programRoots) { $files.Add("$root\Mozilla Maintenance Service") }
                foreach ($root in @('Registry::HKEY_LOCAL_MACHINE\Software', 'Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node')) {
                    $keys.Add("$root\Mozilla\MaintenanceService")
                    $keys.Add("$root\Microsoft\Windows\CurrentVersion\Uninstall\MozillaMaintenanceService")
                }
            }
        } elseif (Get-Service MozillaMaintenance -ErrorAction SilentlyContinue) {
            & $report 'Shared MozillaMaintenance service retained. Use -RemoveSharedMaintenanceService to include it.'
        }

        $shortcutRoots = @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu")
        foreach ($userProfile in $profiles) {
            $shortcutRoots += "$($userProfile.Path)\Desktop",
                "$($userProfile.Path)\AppData\Roaming\Microsoft\Windows\Start Menu",
                "$($userProfile.Path)\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
        }
        $shell = New-Object -ComObject WScript.Shell
        try {
            foreach ($root in ($shortcutRoots | Sort-Object -Unique)) {
                if (-not (Test-Path -LiteralPath $root)) { continue }
                try {
                    # Desktop is protected from deletion, but can be inspected.
                    if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                        throw "Redirected shortcut folder requires manual review: $root"
                    }
                    foreach ($link in (& $walk $root | Where-Object { -not $_.PSIsContainer -and $_.Extension -eq '.lnk' })) {
                        $shortcut = $shell.CreateShortcut($link.FullName)
                        try { $target = $shortcut.TargetPath }
                        finally { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
                        if ([IO.Path]::GetFileName($target) -ieq 'firefox.exe' -or (& $owned $target)) {
                            # Delete the single link directly; its parent is not a removal target.
                            if ($PSCmdlet.ShouldProcess($link.FullName, 'Delete Firefox shortcut')) {
                                Remove-Item -LiteralPath $link.FullName -Force -Confirm:$false
                                $counts.Removed++
                            }
                        }
                    }
                } catch { & $report "Could not fully inspect shortcuts in $root : $($_.Exception.Message)" }
            }
        } finally { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }

        foreach ($path in (($files.ToArray() + $installs.ToArray()) | Sort-Object -Unique)) { & $remove $path }
        # Registrations are last so install paths remain discoverable during cleanup.
        foreach ($path in ($keys | Sort-Object -Unique)) { & $remove $path }
    } catch {
        & $report "Cleanup stopped before completing: $($_.Exception.Message)"
    } finally {
        # Release provider handles before unloading ONLY the hives we mounted.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        for ($i = $mounts.Count - 1; $i -ge 0; $i--) {
            $mountName = $mounts[$i]
            try {
                $message = & "$env:SystemRoot\System32\reg.exe" unload "HKU\$mountName" 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($message -join ' ') }
            } catch { & $report "Could not unload HKU\$mountName; unload it manually or restart Windows. $($_.Exception.Message)" }
        }
        $identity.Dispose()
    }
    if ($counts.DeferredHives) {
        & $report "$($counts.DeferredHives) offline hive(s) were not inspected. WhatIf does not mount or change registry hives."
    }
    [pscustomobject]@{
        WhatIf = [bool] $WhatIfPreference
        ProfilesRemoved = [bool] $RemoveProfiles
        RemovedItems = $counts.Removed
        DeferredHives = $counts.DeferredHives
        Issues = $issues.ToArray()
        Note = 'Review Issues; this is desktop Firefox cleanup, not a guarantee of zero historical traces. Choose another default browser in Windows Settings.'
    }
}

#endregion

#region -------------------- Invoke-Firefox (dispatcher, returns the exit code) --------------------

function Invoke-Firefox {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Update', 'Uninstall')]
        [string]$Mode = 'Check',
        # Parameters of the mode's function, e.g. @{ RemoveProfiles = $true } for Uninstall
        [hashtable]$Options = @{}
    )

    try {
        if ($Mode -ne 'Check' -and -not (Test-IsAdmin)) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session (also for WhatIf). Nothing changed." -ForegroundColor Red
            return 10
        }
        # -WhatIf on Invoke-Firefox, or WhatIf in -Options; either works.
        $o = @{} + $Options
        if (-not $o.ContainsKey('WhatIf')) { $o['WhatIf'] = [bool]$WhatIfPreference }

        switch ($Mode) {
            'Check' {
                $state = Get-FirefoxState
                Show-FirefoxState $state
                if (-not (Test-IsAdmin)) {
                    Write-Host "NOT ELEVATED: other users' folders, hives and Store packages may be missing - rerun elevated." -ForegroundColor Yellow
                }
                if ($state.Present) { Write-Host 'Firefox: PRESENT' -ForegroundColor Yellow; return 2 }
                Write-Host 'Firefox: not present'
                return 0
            }
            'Update' {
                $rc = @(Update-Firefox @o)
                return [int]$rc[-1]   # the function's last output is its exit code
            }
            'Uninstall' {
                $result = @(Remove-Firefox @o)[-1]
                $result | Select-Object WhatIf, ProfilesRemoved, RemovedItems, DeferredHives, Note | Format-List | Out-Host
                Write-Host "Issues: $(@($result.Issues).Count) (see the WARNING lines above)"
                if ($o['WhatIf']) { return 0 }

                Write-Host '--- Verification ---'
                $after = Get-FirefoxState
                Show-FirefoxState $after
                $failed = @(@($result.Issues) -match '^(?:Could not|Cleanup stopped)')
                if (($after.Installs.Count + $after.Registrations.Count) -or $failed.Count) {
                    Write-Host 'Removal INCOMPLETE (see the issues above; files in use may need a reboot and a rerun).' -ForegroundColor Yellow
                    return 1
                }
                if ($after.Store) { Write-Host 'Store/MSIX Firefox remains: outside this cleanup, remove it separately.' -ForegroundColor Yellow }
                Write-Host 'Desktop Firefox removed.' -ForegroundColor Green
                return 0
            }
        }
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

# Uninstall KEEPS Firefox profiles by default. RemoveProfiles = $true deletes every user's
# bookmarks, saved passwords, history and sessions for good - only use it deliberately.
$exitCode = Invoke-Firefox                                                   # Check (read-only)
# $exitCode = Invoke-Firefox -Mode Update -WhatIf                            # Show installed vs latest, downloads nothing
# $exitCode = Invoke-Firefox -Mode Update                                    # LIVE: machine-wide Firefox to latest (signed installer)
# $exitCode = Invoke-Firefox -Mode Uninstall -WhatIf                         # Preview removal, changes nothing
# $exitCode = Invoke-Firefox -Mode Uninstall                                 # DESTRUCTIVE: removes desktop Firefox, closes it; keeps profiles
# $exitCode = Invoke-Firefox -Mode Uninstall -Options @{ RemoveProfiles = $true } -WhatIf   # Preview, including profiles
# $exitCode = Invoke-Firefox -Mode Uninstall -Options @{ RemoveProfiles = $true }           # DATA LOSS: also deletes all Firefox profiles

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
