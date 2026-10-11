Remove-Module PSReadLine -ErrorAction SilentlyContinue

function Invoke-TeamsRemediation {
    <#
    .SYNOPSIS
        Audits every Teams install on the machine, removes everything except the newest New Teams
        (MSTeams) build, and optionally installs/updates New Teams via teamsbootstrapper.exe.

    .DESCRIPTION
        [1/4] Audit      Classic Teams per user, every MSTeams build, legacy MicrosoftTeams AppX,
                         Teams-related uninstall registry entries (incl. the Machine-Wide Installer).
        [2/4] Remove     Classic Teams (Update.exe first, folder delete fallback), stale side-by-side
                         MSTeams builds, legacy AppX (per-user AND provisioned copies),
                         Teams Machine-Wide Installer MSI + orphaned registry keys.
        [3/4] Update     ONLY with -InstallLatest: download the latest bootstrapper, swap in if newer.
        [4/4] Provision  ONLY with -InstallLatest: teamsbootstrapper.exe -p (stage, no restart).

        -WhatIf  : full audit report, every action shown as "What if:", nothing changed.
        -Verbose : exit codes, paths, versions and other diagnostic detail.
        -Confirm : prompt before each individual action.

    .PARAMETER InstallLatest
        Download the latest teamsbootstrapper.exe and provision New Teams. Off by default.

    .PARAMETER ForceFolderDelete
        Skip Update.exe and delete Classic Teams folders directly.

    .EXAMPLE
        Invoke-TeamsRemediation -WhatIf                 # report only, no changes
    .EXAMPLE
        Invoke-TeamsRemediation -Verbose                # remove old Teams, no install
    .EXAMPLE
        Invoke-TeamsRemediation -InstallLatest -Verbose # remove old Teams + install/update New Teams
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [switch]$InstallLatest,
        [switch]$ForceFolderDelete,

        [string]$BootstrapperPath = "$env:ProgramData\TeamsBootstrapper\teamsbootstrapper.exe",
        [string]$FwLink           = 'https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409',

        # Minimum acceptable New Teams build; the newest installed MSTeams below this is flagged
        # BELOW BASELINE. Policy: latest fully-released Windows build (N-1 while a new one rolls out).
        # Update when Microsoft ships a security fix:
        #   https://learn.microsoft.com/en-us/officeupdates/teams-app-versioning
        # 26246.1604.5133.838 = Windows public cloud, released 28 Sep 2026.
        [version]$MinSafeNewTeamsVersion = '26246.1604.5133.838'
    )

    # Console paste can't use #Requires -RunAsAdministrator, so check here.
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell session (Run as Administrator).'
    }

    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # ====================================================================== #
    # Helpers
    # ====================================================================== #

    function Show-Phase {
        param([int]$Phase, [string]$Activity)
        Write-Progress -Id 1 -Activity 'Teams Remediation' -Status "[$Phase/4] $Activity" -PercentComplete (($Phase - 1) * 25)
        Write-Host ''
        Write-Host "[$Phase/4] $Activity" -ForegroundColor Cyan
    }

    function ConvertTo-VersionOrNull {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $parsed = $null
        if ([version]::TryParse(($Value.Trim() -split '\s+')[0], [ref]$parsed)) { return $parsed }
        return $null
    }

    function Get-FileVersionOrNull {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        ConvertTo-VersionOrNull (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
    }

    function Get-ProcessPathSafe {
        param($Process)
        try { $Process.Path } catch { $null }
    }

    function Get-ProfilesRoot {
        try {
            $dir = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory).ProfilesDirectory
            $expanded = [Environment]::ExpandEnvironmentVariables($dir)
            if ($expanded -and (Test-Path -LiteralPath $expanded)) { return $expanded.TrimEnd('\') }
        } catch { }
        Join-Path $env:SystemDrive 'Users'
    }

    # ...\<profile>\AppData\Local\Microsoft\Teams\current\Teams.exe -> ...\<profile>
    function Get-ProfileRootFromTeamsPath {
        param([string]$Path)
        for ($i = 0; $i -lt 6; $i++) { $Path = Split-Path -Path $Path -Parent }
        $Path
    }

    function Remove-TeamsUserFolders {
        param([string]$ProfileRoot)
        foreach ($folder in 'AppData\Local\Microsoft\Teams', 'AppData\Roaming\Microsoft\Teams') {
            $full = Join-Path $ProfileRoot $folder
            if (Test-Path -LiteralPath $full) {
                Write-Verbose "Deleting $full"
                Remove-Item -LiteralPath $full -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        -not (Test-Path -LiteralPath (Join-Path $ProfileRoot 'AppData\Local\Microsoft\Teams\current\Teams.exe'))
    }

    function Add-Finding {
        param([string]$Type, [string]$User, [string]$Version, [string]$Path,
              [string]$Detail, [string]$Status, [string]$Action, [bool]$Running)
        $inventory.Add([PSCustomObject]@{
            Type = $Type; User = $User; Version = $Version; Path = $Path
            Detail = $Detail; Status = $Status; Action = $Action; Running = $Running
        })
    }

    function Write-Finding {
        param($Finding)
        $color = switch ($Finding.Status) {
            'END OF LIFE'    { 'Red' }
            'OUTDATED'       { 'Red' }
            'BELOW BASELINE' { 'Red' }
            'LEGACY'         { 'Yellow' }
            'INSTALLED'      { 'Yellow' }
            'OK'             { 'Green' }
            default          { 'Gray' }
        }
        $tag = if ($Finding.Running) { ' [RUNNING]' } else { '' }
        Write-Host ''
        Write-Host "  > $($Finding.Type)$tag" -ForegroundColor Yellow
        foreach ($field in 'User', 'Version', 'Path', 'Detail') {
            if ($Finding.$field) {
                Write-Host ("    +- {0,-8} " -f $field) -NoNewline -ForegroundColor DarkGray
                Write-Host $Finding.$field
            }
        }
        Write-Host '    \- Status   ' -NoNewline -ForegroundColor DarkGray
        Write-Host "$($Finding.Status) -> $($Finding.Action)" -ForegroundColor $color
    }

    # Removes an AppX package for all users AND its provisioned (staged) copy, then verifies.
    # Without the deprovision step the package silently comes back for new profiles.
    function Remove-TeamsAppx {
        param($Package)

        $installedFor = @($Package.PackageUserInformation | Where-Object { "$($_.InstallState)" -eq 'Installed' })
        if ($installedFor) {
            Write-Verbose "Remove-AppxPackage $($Package.PackageFullName) -AllUsers ($($installedFor.Count) user(s))"
            try {
                Remove-AppxPackage -Package $Package.PackageFullName -AllUsers -Confirm:$false
            } catch {
                Write-Host "  -> Remove-AppxPackage error: $($_.Exception.Message.Split("`n")[0])" -ForegroundColor Red
            }
        }

        $staged = @($provisionedPackages |
            Where-Object { $_.DisplayName -eq $Package.Name -and $_.Version -eq [string]$Package.Version })
        foreach ($prov in $staged) {
            $deprovision = @{ Online = $true }
            if ($provisionedSupportsAllUsers) { $deprovision.AllUsers = $true }
            else { Write-Verbose 'Remove-AppxProvisionedPackage has no -AllUsers on this build; removing staged copy only.' }
            try {
                $prov | Remove-AppxProvisionedPackage @deprovision | Out-Null
                Write-Verbose "Deprovisioned $($prov.PackageName)"
            } catch {
                Write-Host "  -> Remove-AppxProvisionedPackage error: $($_.Exception.Message.Split("`n")[0])" -ForegroundColor Red
            }
        }

        # Trust the machine, not the cmdlet return codes.
        $still = Get-AppxPackage -AllUsers -Name $Package.Name -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageFullName -eq $Package.PackageFullName }
        if (-not $still) { return $true }

        $holders = ($still.PackageUserInformation |
            Where-Object { "$($_.InstallState)" -eq 'Installed' } |
            ForEach-Object { $_.UserSecurityId.Username }) -join ', '
        $msg = "  -> FAILED to remove $($Package.Name) v$($Package.Version)"
        if ($holders) { $msg += " - still installed for: $holders (sign those users out and re-run)" }
        Write-Host $msg -ForegroundColor Red
        $false
    }

    # ====================================================================== #
    # State
    # ====================================================================== #

    $inventory   = [System.Collections.Generic.List[object]]::new()
    $failedUsers = [System.Collections.Generic.List[string]]::new()
    $summary = [ordered]@{
        ClassicFound        = 0
        ClassicRemoved      = 0
        ClassicFailed       = 0
        AppxRemoved         = 0
        AppxFailed          = 0
        MsiRemoved          = 0
        RegistryCleaned     = 0
        NewTeamsBefore      = $null
        NewTeamsAfter       = $null
        BootstrapperVersion = $null
    }

    $machineWideProductCodes = @('{731F6BAA-A986-45A4-8936-7C3AAAAA760B}')

    $provisionedPackages = @()
    $provisionedSupportsAllUsers = $false
    try {
        $provisionedSupportsAllUsers =
            (Get-Command Remove-AppxProvisionedPackage).Parameters.ContainsKey('AllUsers')
    } catch { }

    try {

    # ====================================================================== #
    # [1/4] AUDIT
    # ====================================================================== #
    Show-Phase 1 'Auditing Teams installs'

    $profilesRoot = Get-ProfilesRoot
    Write-Verbose "Profile root: $profilesRoot"

    $runningV1      = @(Get-Process -Name 'Teams'    -ErrorAction SilentlyContinue)
    $runningV2      = @(Get-Process -Name 'ms-teams' -ErrorAction SilentlyContinue)
    $runningV1Paths = @($runningV1 | ForEach-Object { Get-ProcessPathSafe $_ } | Where-Object { $_ })
    $runningV2Paths = @($runningV2 | ForEach-Object { Get-ProcessPathSafe $_ } | Where-Object { $_ })
    Write-Verbose "Running: $($runningV1.Count) Classic Teams.exe, $($runningV2.Count) ms-teams.exe"

    # --- Classic Teams (v1), per user ---
    $classicInstalls = @(Get-ChildItem -Path (Join-Path $profilesRoot '*\AppData\Local\Microsoft\Teams\current\Teams.exe') -File -ErrorAction SilentlyContinue)
    $summary.ClassicFound = $classicInstalls.Count
    # Classic Teams is out of support (last build 1.8.00.21151, Aug 2025): every version is END OF LIFE.
    foreach ($exe in $classicInstalls) {
        $updateExe = Join-Path $exe.Directory.Parent.FullName 'Update.exe'
        Add-Finding -Type 'Teams Classic (v1)' `
            -User    (Split-Path (Get-ProfileRootFromTeamsPath $exe.FullName) -Leaf) `
            -Version $exe.VersionInfo.ProductVersion -Path $exe.FullName `
            -Detail  $(if (Test-Path -LiteralPath $updateExe) { "`"$updateExe`" --uninstall -s" }) `
            -Status  'END OF LIFE' `
            -Action  'REMOVE' `
            -Running ($runningV1Paths -contains $exe.FullName)
    }

    # --- New Teams (MSTeams): keep the highest build, older side-by-side builds are stale ---
    $allMSTeams = @(Get-AppxPackage -AllUsers -Name 'MSTeams' -ErrorAction SilentlyContinue |
        Sort-Object PackageFullName -Unique |
        Sort-Object { ConvertTo-VersionOrNull $_.Version } -Descending)
    $newTeams     = $allMSTeams | Select-Object -First 1
    $staleMSTeams = @($allMSTeams | Select-Object -Skip 1)
    $summary.NewTeamsBefore = if ($newTeams) { [string]$newTeams.Version }

    foreach ($pkg in $allMSTeams) {
        $isLatest = $pkg -eq $newTeams
        $pkgVer   = ConvertTo-VersionOrNull $pkg.Version
        $status = if (-not $isLatest) { 'OUTDATED' }
                  elseif ($pkgVer -and $pkgVer -lt $MinSafeNewTeamsVersion) { 'BELOW BASELINE' }
                  else { 'OK' }
        $action = if (-not $isLatest) { 'REMOVE' } elseif ($InstallLatest) { 'KEEP + UPDATE' } else { 'KEEP' }
        Add-Finding -Type 'Teams New (v2, MSTeams)' -User 'All Users' -Version $pkg.Version `
            -Path $pkg.InstallLocation -Detail $pkg.PackageFullName -Status $status -Action $action `
            -Running ([bool]($pkg.InstallLocation -and ($runningV2Paths | Where-Object { $_ -like "$($pkg.InstallLocation)*" })))
    }

    # --- Legacy built-in chat AppX (MicrosoftTeams) ---
    $legacyAppx = @(Get-AppxPackage -AllUsers -Name 'MicrosoftTeams' -ErrorAction SilentlyContinue |
        Sort-Object PackageFullName -Unique)
    foreach ($pkg in $legacyAppx) {
        Add-Finding -Type 'Teams Legacy AppX (MicrosoftTeams)' -User 'All Users' -Version $pkg.Version `
            -Path $pkg.InstallLocation -Detail $pkg.PackageFullName -Status 'LEGACY' -Action 'REMOVE'
    }

    # --- Uninstall registry: report anything Teams, remove only the Machine-Wide Installer ---
    $uninstallEntries = @(Get-ItemProperty -Path @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        ) -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*Teams*' -or $_.PSChildName -in $machineWideProductCodes } |
        Sort-Object PSPath -Unique)

    $machineWideEntries = @($uninstallEntries | Where-Object {
        $_.PSPath -notlike '*HKEY_CURRENT_USER*' -and
        ($_.DisplayName -eq 'Teams Machine-Wide Installer' -or $_.PSChildName -in $machineWideProductCodes)
    })

    foreach ($entry in $uninstallEntries) {
        $isMachineWide = $machineWideEntries -contains $entry
        Add-Finding -Type "Registry: $($entry.DisplayName)" `
            -User    $(if ($entry.PSPath -like '*HKEY_CURRENT_USER*') { $env:USERNAME } else { 'System' }) `
            -Version $entry.DisplayVersion -Path $entry.InstallLocation -Detail $entry.UninstallString `
            -Status  $(if ($isMachineWide) { 'INSTALLED' } else { 'INFO' }) `
            -Action  $(if ($isMachineWide) { 'REMOVE' } else { 'LEAVE' })
    }

    # --- Report ---
    $line = '-' * 80
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  Teams Version Report - $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') - $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    if ($inventory.Count -eq 0) { Write-Host '  No Teams installs found.' -ForegroundColor DarkGray }
    foreach ($f in $inventory) { Write-Finding $f }
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ('  Total: {0}  To remove: {1}  Running: {2}' -f $inventory.Count,
        @($inventory | Where-Object Action -eq 'REMOVE').Count,
        @($inventory | Where-Object Running).Count) -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor Cyan

    if (-not $newTeams -and -not $InstallLatest) {
        Write-Warning 'New Teams (MSTeams) is not installed and -InstallLatest was not specified. After removal this machine will have no Teams client.'
    }

    # ====================================================================== #
    # [2/4] REMOVE everything except the newest New Teams
    # ====================================================================== #
    Show-Phase 2 'Removing old Teams versions'

    # --- Classic Teams per user ---
    if (-not $classicInstalls) {
        Write-Verbose 'No Classic Teams binaries, skipping'
    } else {
        $i = 0
        foreach ($exe in $classicInstalls) {
            $i++
            $profileRoot = Get-ProfileRootFromTeamsPath $exe.FullName
            $user        = Split-Path $profileRoot -Leaf
            $currentDir  = $exe.Directory.FullName
            $updateExe   = Join-Path $exe.Directory.Parent.FullName 'Update.exe'

            Write-Progress -Id 2 -ParentId 1 -Activity 'Classic Teams removal' `
                -Status "$user ($i of $($classicInstalls.Count))" -PercentComplete (($i / $classicInstalls.Count) * 100)

            if (-not $PSCmdlet.ShouldProcess("$user :: $($exe.FullName)", 'Uninstall Classic Teams')) { continue }

            $lockers = @($runningV1 | Where-Object { (Get-ProcessPathSafe $_) -eq $exe.FullName })
            if ($lockers) {
                Write-Host "  -> [$user] Stopping $($lockers.Count) running Teams.exe" -ForegroundColor Yellow
                $lockers | Stop-Process -Force -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            $removed = $false
            if (-not $ForceFolderDelete -and (Test-Path -LiteralPath $updateExe)) {
                Write-Host "  -> [$user] Running Update.exe --uninstall -s" -ForegroundColor Yellow
                $proc = Start-Process -FilePath $updateExe -ArgumentList '--uninstall', '-s' -Wait -PassThru -WindowStyle Hidden
                Start-Sleep -Milliseconds 500   # Squirrel deletes asynchronously.
                # Exit code is unreliable (-1 even on success); trust the filesystem.
                $removed = -not (Test-Path -LiteralPath $exe.FullName)
                Write-Verbose "[$user] Update.exe exit code $($proc.ExitCode), binary gone: $removed"
            }

            if (-not $removed) {
                Write-Host "  -> [$user] Deleting folders directly" -ForegroundColor Yellow
                if (Test-Path -LiteralPath $currentDir) {
                    Remove-Item -LiteralPath $currentDir -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
                $removed = Remove-TeamsUserFolders -ProfileRoot $profileRoot
            }

            if ($removed) {
                Write-Host "     Removed for $user" -ForegroundColor Green
                $summary.ClassicRemoved++
            } else {
                Write-Host "     FAILED for $user - binary still present" -ForegroundColor Red
                $summary.ClassicFailed++
                $failedUsers.Add($user)
            }
        }
        Write-Progress -Id 2 -Activity 'Classic Teams removal' -Completed
    }

    # --- Stale MSTeams builds + legacy MicrosoftTeams AppX ---
    $appxToRemove = @($staleMSTeams) + @($legacyAppx)
    if (-not $appxToRemove) {
        Write-Verbose 'No outdated MSTeams builds or legacy AppX, skipping'
    } else {
        try { $provisionedPackages = @(Get-AppxProvisionedPackage -Online) }
        catch { Write-Verbose "Get-AppxProvisionedPackage failed: $($_.Exception.Message)" }

        foreach ($package in $appxToRemove) {
            if (-not $PSCmdlet.ShouldProcess("$($package.PackageFullName) (v$($package.Version))", 'Remove AppX package (all users + provisioned)')) { continue }

            # Don't pull the package out from under a session still running it.
            if ($package.InstallLocation) {
                $inUse = @($runningV2 | Where-Object { (Get-ProcessPathSafe $_) -like "$($package.InstallLocation)*" })
                if ($inUse) {
                    Write-Host "  -> Stopping ms-teams running from $($package.Name) v$($package.Version)" -ForegroundColor Yellow
                    $inUse | Stop-Process -Force -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                }
            }

            if (Remove-TeamsAppx -Package $package) {
                Write-Host "  -> Removed $($package.Name) v$($package.Version)" -ForegroundColor Green
                $summary.AppxRemoved++
            } else {
                $summary.AppxFailed++
            }
        }
    }

    # --- Teams Machine-Wide Installer (MSI) ---
    if (-not $machineWideEntries) {
        Write-Verbose 'No Machine-Wide Installer, skipping'
    } else {
        foreach ($entry in $machineWideEntries) {
            $productCode = $entry.PSChildName
            $displayName = if ($entry.DisplayName) { $entry.DisplayName } else { $productCode }

            if ($PSCmdlet.ShouldProcess($displayName, "msiexec.exe /x $productCode /qn /norestart")) {
                $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn', '/norestart' -Wait -PassThru
                Write-Verbose "msiexec exit code for ${displayName}: $($proc.ExitCode)"
                if ($proc.ExitCode -in 0, 3010) {
                    Write-Host "  -> Removed $displayName" -ForegroundColor Green
                    $summary.MsiRemoved++
                } else {
                    Write-Host "  -> $displayName msiexec exit code $($proc.ExitCode)" -ForegroundColor Red
                }
            }

            foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
                $registryPath = Join-Path $root $productCode
                if ((Test-Path -LiteralPath $registryPath) -and
                    $PSCmdlet.ShouldProcess($registryPath, 'Remove orphaned uninstall key')) {
                    Remove-Item -LiteralPath $registryPath -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Verbose "Removed registry key $registryPath"
                    $summary.RegistryCleaned++
                }
            }
        }
    }

    # ====================================================================== #
    # [3/4] UPDATE bootstrapper + [4/4] PROVISION  (opt-in: -InstallLatest)
    # ====================================================================== #
    if (-not $InstallLatest) {
        Write-Host ''
        Write-Host '[3/4] + [4/4] Install/update skipped. Pass -InstallLatest to download and provision the latest New Teams.' -ForegroundColor DarkGray
    } else {
        Show-Phase 3 'Updating Teams bootstrapper'

        $tmp        = Join-Path $env:TEMP 'teamsbootstrapper.new.exe'
        $downloaded = $false

        if ($PSCmdlet.ShouldProcess($FwLink, 'Download latest teamsbootstrapper.exe')) {
            $folder = Split-Path $BootstrapperPath -Parent
            if (-not (Test-Path -LiteralPath $folder)) {
                New-Item -ItemType Directory -Path $folder -Force -Confirm:$false | Out-Null
            }
            Write-Verbose "Downloading $FwLink -> $tmp"
            $oldProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'   # IWR's progress bar makes downloads crawl.
            try {
                Invoke-WebRequest -Uri $FwLink -OutFile $tmp -UseBasicParsing
                $downloaded = $true
            } catch {
                Write-Warning "Download failed: $($_.Exception.Message). Falling back to existing bootstrapper if present."
            } finally {
                $ProgressPreference = $oldProgress
            }
        }

        $localVer = Get-FileVersionOrNull $BootstrapperPath
        Write-Verbose "Local bootstrapper: $(if ($localVer) { "v$localVer" } else { 'none' })"

        if ($downloaded) {
            $newVer = Get-FileVersionOrNull $tmp
            Write-Verbose "Downloaded bootstrapper: $(if ($newVer) { "v$newVer" } else { 'no version info' })"
            if (-not $newVer) {
                Write-Warning 'Downloaded file has no version info (bad download or link changed); discarding it.'
            } elseif (-not $localVer -or $newVer -gt $localVer) {
                if ($PSCmdlet.ShouldProcess($BootstrapperPath, "Replace bootstrapper with v$newVer")) {
                    Move-Item -LiteralPath $tmp -Destination $BootstrapperPath -Force -Confirm:$false
                    Write-Host "  Bootstrapper updated to v$newVer" -ForegroundColor Green
                }
            } else {
                Write-Host "  Local bootstrapper already current (v$localVer)." -ForegroundColor Green
            }
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        }
        $summary.BootstrapperVersion = [string](Get-FileVersionOrNull $BootstrapperPath)

        Show-Phase 4 'Provisioning New Teams'

        if ($PSCmdlet.ShouldProcess('all users on this machine', "Provision New Teams via '$BootstrapperPath -p'")) {
            if (-not (Test-Path -LiteralPath $BootstrapperPath)) {
                Write-Warning "Bootstrapper not found at $BootstrapperPath; cannot provision."
            } else {
                $proc = Start-Process -FilePath $BootstrapperPath -ArgumentList '-p' -NoNewWindow -PassThru -Wait
                Write-Verbose "teamsbootstrapper.exe -p exit code: $($proc.ExitCode)"
                if ($proc.ExitCode -ne 0) {
                    Write-Warning "Bootstrapper exited $($proc.ExitCode). See C:\Windows\Temp\teamsprovision.log.<date>"
                }
            }
        }
    }

    }
    finally {
        Write-Progress -Id 2 -Activity 'Classic Teams removal' -Completed
        Write-Progress -Id 1 -Activity 'Teams Remediation' -Completed
    }

    # ====================================================================== #
    # Summary
    # ====================================================================== #
    $summary.NewTeamsAfter = [string](Get-AppxPackage -AllUsers -Name 'MSTeams' -ErrorAction SilentlyContinue |
        Sort-Object { ConvertTo-VersionOrNull $_.Version } -Descending |
        Select-Object -First 1).Version

    Write-Host ''
    if ($WhatIfPreference) {
        Write-Host 'Dry run complete (-WhatIf). No changes were made.' -ForegroundColor Cyan
    } elseif ($failedUsers.Count -gt 0 -or $summary.AppxFailed -gt 0) {
        if ($failedUsers.Count) {
            Write-Host "Done, but Classic Teams could not be removed for: $($failedUsers -join ', ')" -ForegroundColor Yellow
            Write-Host 'Re-run with -ForceFolderDelete, or check for a locked Teams.exe in those profiles.' -ForegroundColor Yellow
        }
        if ($summary.AppxFailed) {
            Write-Host "Done, but $($summary.AppxFailed) AppX package(s) could not be removed (see above)." -ForegroundColor Yellow
        }
    } elseif ($summary.NewTeamsAfter) {
        Write-Host "Done. Only New Teams (MSTeams v$($summary.NewTeamsAfter)) remains." -ForegroundColor Green
    } else {
        Write-Host 'Done. Old Teams removed; New Teams is NOT installed (run with -InstallLatest).' -ForegroundColor Yellow
    }

    $summary.FailedUsers = $failedUsers.ToArray()
    $summary.Inventory   = $inventory.ToArray()
    [PSCustomObject]$summary
}

# ---- Edit this line, then paste the whole block. ----
# Invoke-TeamsRemediation -WhatIf                     # report only
# Invoke-TeamsRemediation -Verbose                    # remove old Teams, no install
# Invoke-TeamsRemediation -InstallLatest -Verbose     # remove + install/update New Teams
Invoke-TeamsRemediation -WhatIf