# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Google Chrome - Check / Recon (both read-only) / Update (machine-wide, never closes Chrome). RMM-ready.

.DESCRIPTION
    -Mode Check   DEFAULT. Fast, read-only. Lists machine-wide and per-user chrome.exe versions,
                  the deployment type (GoogleUpdater / legacy Omaha / MSI), the update engine,
                  MSI product code, whether Chrome is running and whether an update is already
                  staged (new_chrome.exe, waiting for a relaunch). It runs Invoke-ChromeUpdate
                  with -WhatIf, so it also prints the "What if:" line of what Update would do.
                  Action needed (exit 2) when any of these holds:
                    - an install is older than the newest one found (scanners flag the old one)
                    - an update is staged but Chrome has not been relaunched yet
                    - the machine install is below -Options @{ TargetVersion = '<version>' }
                    - MSI-only install with no self-updater, or Google Update policy blocks updates
                  Without TargetVersion the script cannot tell if the newest install is the latest
                  release (it never goes online); it says so.
    -Mode Recon   Deep read-only scan (Invoke-ChromeRecon): every profile's Chrome folder (also
                  leftovers without a readable chrome.exe), the uninstall registry entries with
                  their uninstall commands, and an assessment for scanners that report an old
                  Chrome version. No options.
    -Mode Update  Invoke-ChromeUpdate: triggers a machine-wide update through the engine that is
                  really present - GoogleUpdater (updater.exe --update-apps --system, or the
                  GoogleUpdaterTaskSystem* task) or legacy Omaha (GoogleUpdateTaskMachineUA task,
                  or GoogleUpdate.exe /ua). Never downloads an installer and never closes
                  chrome.exe; a running Chrome applies the update on its next relaunch.
                  MSI-only installs are reported, not patched. -WhatIf previews.
                  -Options (parameters of Invoke-ChromeUpdate):
                    TargetVersion = '<version>'        only act when the machine install is lower
                    RelaunchNotification = 'Recommended' | 'Required'
                                                       also set the Chrome relaunch policy
                    RelaunchNotificationPeriodHours = 1..596
                    TimeoutSeconds = 300               wait for the updater
                    VerboseUpdaterLog = $true          updater.log under GoogleUpdater
                    Verbose = $true                    show the steps

    Per-user installs (AppData) cannot be updated from SYSTEM; Check and Recon list them.
    Not elevated: other users' profiles may be unreadable, so per-user results can be incomplete.

.EXAMPLE
    Paste the WHOLE script into a PowerShell session (e.g. the RMM's remote shell) or an RMM
    component. The ENTRY POINT at the bottom picks the mode - edit that one line. For an RMM
    component also set $RMM = $true there, so the script exits with the code.

    Invoke-Chrome                                                    # Check
    Invoke-Chrome -Options @{ TargetVersion = '<version>' }          # Check against a minimum version
    Invoke-Chrome -Mode Recon                                        # Deep read-only scan
    Invoke-Chrome -Mode Update -WhatIf                               # Preview the update
    Invoke-Chrome -Mode Update -Options @{ RelaunchNotification = 'Recommended' }

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-Chrome returns one; the entry point exits with it only when $RMM = $true):
        0     Check / Recon: nothing to do (or Chrome not installed)
              Update: updated, already current, nothing to update, or -WhatIf
        1     Error. Update: Chrome could not be updated - policy blocked, MSI-only, per-user
              only, no trigger could start, or the updater returned an error (see Message)
        2     Check / Recon: action needed (see the listed reasons / assessment)
        10    Update: session is not elevated - nothing changed (also for -WhatIf)
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Moved out of Invoke-ChromeUpdate so Check can use it too.
function ConvertTo-ChromeVersion {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }
    $m = [regex]::Match($Version, '\d+(?:\.\d+){1,3}')
    if (-not $m.Success) { return $null }
    try { return [version]$m.Value } catch { return $null }
}

#endregion

#region -------------------- Invoke-ChromeUpdate (from 00_Chrome_Updater(Omaha vs MSI).ps1) --------------------

function Invoke-ChromeUpdate {
<#
.SYNOPSIS
    Detects Google Chrome installs + which update ENGINE is present (modern
    Chromium updater "GoogleUpdater" vs legacy Omaha "GoogleUpdate", vs MSI-only),
    reports run state, triggers a non-disruptive machine-wide update using the
    correct engine, and can set the RelaunchNotification policy to nudge users to
    restart after a staged update.

.DESCRIPTION
    Built to run as SYSTEM from an RMM. It never downloads an installer and never
    force-closes chrome.exe.

    Engine handling (this is the important fix):
      * NewUpdater  - Chrome 116+/current builds. Omaha was replaced by the
                      Chromium updater. The binary at
                      C:\Program Files (x86)\Google\Update\GoogleUpdate.exe is now
                      just a COPY of updater.exe kept for legacy hand-off, and it
                      does NOT understand the old '/ua' switch (returns 75009,
                      kErrorUnknownCommandLine). We trigger updates with the modern
                      switches (--update-apps --system) against the real
                      GoogleUpdater\<ver>\updater.exe, or by starting the
                      GoogleUpdaterTaskSystem* scheduled task.
      * Omaha       - genuine legacy Google Update (GoogleUpdate.exe v1.3.x, the
                      GoogleUpdateTaskMachineUA task). Triggered with '/ua'.
      * None        - no self-updating engine (MSI-only). Reports ProductCode and
                      tells you to patch via your MSI channel.

    Supports -WhatIf / -Confirm via ShouldProcess for BOTH the update trigger and
    the RelaunchNotification policy write.

.PARAMETER TargetVersion
    Optional. Only treat the machine install as stale / trigger an update when the
    on-disk version is lower than this. Omit to let the updater decide "latest".

.PARAMETER RelaunchNotification
    None (default)  - do not touch the policy.
    Recommended     - value 1: recurring reminder to relaunch (least disruptive).
    Required        - value 2: force relaunch after the notification period.

.PARAMETER RelaunchNotificationPeriodHours
    Optional. Sets RelaunchNotificationPeriod (hours -> ms). 0 = leave as-is.
    Chrome's default when unset is 7 days. Capped at 596 hours (~24.8 days): the
    value is a DWORD in milliseconds and must fit a signed 32-bit integer.

.PARAMETER TimeoutSeconds
    How long to wait for the triggered updater to finish. Default 300.

.PARAMETER VerboseUpdaterLog
    When triggering the modern updater, also pass --enable-logging so activity is
    written to C:\Program Files (x86)\Google\GoogleUpdater\updater.log for
    troubleshooting.

.EXAMPLE
    Invoke-ChromeUpdate -WhatIf
.EXAMPLE
    Invoke-ChromeUpdate -RelaunchNotification Recommended
.EXAMPLE
    Invoke-ChromeUpdate -RelaunchNotification Required -RelaunchNotificationPeriodHours 48
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [version]$TargetVersion,
        [ValidateSet('None','Recommended','Required')]
        [string]$RelaunchNotification = 'None',
        # fix: was unbounded; above 596 h the ms value overflowed [int] and threw after
        # RelaunchNotification had already been written.
        [ValidateRange(0, 596)]
        [int]$RelaunchNotificationPeriodHours = 0,
        [int]$TimeoutSeconds = 300,
        [switch]$VerboseUpdaterLog
    )

    $ErrorActionPreference = 'Stop'

    # ---------- helpers -------------------------------------------------------

    function Get-FileVersionSafe {
        param([string]$Path)
        if (Test-Path $Path) {
            try { return (Get-Item $Path).VersionInfo.FileVersion } catch { return $null }
        }
        return $null
    }

    function Get-MachineChromeInstalls {
        $paths = @(
            'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
        )
        foreach ($p in $paths) {
            if (Test-Path $p) {
                # Staged = version of new_chrome.exe: an update installed while Chrome was
                # running, applied (renamed over chrome.exe) on the next relaunch.
                [pscustomobject]@{ Scope='Machine'; Path=$p; Version=Get-FileVersionSafe -Path $p
                                   Staged=Get-FileVersionSafe -Path (Join-Path (Split-Path $p) 'new_chrome.exe') }
            }
        }
    }

    function Get-PerUserChromeInstalls {
        $out = @()
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } |
            ForEach-Object {
                $exe = Join-Path $_.FullName 'AppData\Local\Google\Chrome\Application\chrome.exe'
                if (Test-Path $exe) {
                    $out += [pscustomobject]@{
                        Scope='PerUser'; Path=$exe; Version=Get-FileVersionSafe -Path $exe; User=$_.Name
                    }
                }
            }
        return $out
    }

    function Get-ChromeMsiInfo {
        # Detect an MSI/Chrome Enterprise registration in the uninstall hives.
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($root in $roots) {
            Get-ItemProperty $root -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -match 'Google Chrome' -and
                    ($_.WindowsInstaller -eq 1 -or $_.UninstallString -match 'msiexec' -or $_.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$')
                } |
                ForEach-Object {
                    [pscustomobject]@{
                        ProductCode    = $_.PSChildName
                        DisplayName    = $_.DisplayName
                        DisplayVersion = $_.DisplayVersion
                    }
                }
        }
    }

    function Get-ChromeUpdaterInfo {
        # Works out which update engine is really present.
        $info = [ordered]@{
            Engine            = 'None'   # 'NewUpdater' | 'Omaha' | 'None'
            NewUpdaterExe     = $null    # ...\GoogleUpdater\<ver>\updater.exe
            NewUpdaterVersion = $null
            NewUpdaterTask    = $null    # GoogleUpdaterTaskSystem<ver>
            LegacyExe         = $null    # ...\Google\Update\GoogleUpdate.exe (real Omaha OR shim)
            LegacyExeVersion  = $null
            LegacyExeIsShim   = $false   # $true when GoogleUpdate.exe is a copy of updater.exe
            LegacyUaTask      = $null    # GoogleUpdateTaskMachineUA (real Omaha)
        }

        # --- Modern Chromium updater (GoogleUpdater) ---
        foreach ($root in @(
            'C:\Program Files (x86)\Google\GoogleUpdater',
            'C:\Program Files\Google\GoogleUpdater'
        )) {
            if (Test-Path $root) {
                $cand = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
                        Where-Object { Test-Path (Join-Path $_.FullName 'updater.exe') } |
                        Sort-Object { ConvertTo-ChromeVersion $_.Name } -Descending |
                        Select-Object -First 1
                if ($cand) {
                    $info.NewUpdaterExe     = Join-Path $cand.FullName 'updater.exe'
                    $info.NewUpdaterVersion = $cand.Name
                    break
                }
            }
        }

        # --- Legacy path GoogleUpdate.exe (could be real Omaha, or the new shim) ---
        foreach ($p in @(
            'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe',
            'C:\Program Files\Google\Update\GoogleUpdate.exe'
        )) {
            if (Test-Path $p) {
                $info.LegacyExe        = $p
                $info.LegacyExeVersion = Get-FileVersionSafe -Path $p
                $lv = ConvertTo-ChromeVersion $info.LegacyExeVersion
                # Real Omaha is v1.3.x.x; the new-updater shim carries a Chrome-class
                # version (e.g. 138.x / 149.x). Major >= 100 => it's the shim.
                if ($lv -and $lv.Major -ge 100) { $info.LegacyExeIsShim = $true }
                break
            }
        }

        # --- Scheduled tasks ---
        $newTask = Get-ScheduledTask -TaskName 'GoogleUpdaterTaskSystem*' -ErrorAction SilentlyContinue |
                   Select-Object -First 1
        if ($newTask) { $info.NewUpdaterTask = $newTask.TaskName }

        if (Get-ScheduledTask -TaskName 'GoogleUpdateTaskMachineUA' -ErrorAction SilentlyContinue) {
            $info.LegacyUaTask = 'GoogleUpdateTaskMachineUA'
        }

        # --- Decide engine ---
        if ($info.NewUpdaterExe -or $info.NewUpdaterTask -or $info.LegacyExeIsShim) {
            $info.Engine = 'NewUpdater'
        } elseif ($info.LegacyExe -or $info.LegacyUaTask) {
            $info.Engine = 'Omaha'
        }

        return [pscustomobject]$info
    }

    function Test-ChromeUpdatesDisabled {
        # $true if Google Update policy blocks Chrome updates. Chrome GUID below.
        # The modern updater still honours these HKLM\...\Policies\Google\Update keys.
        $chromeGuid = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
        $polKey     = 'HKLM:\SOFTWARE\Policies\Google\Update'
        if (-not (Test-Path $polKey)) { return $false }
        $pol     = Get-ItemProperty $polKey -ErrorAction SilentlyContinue
        $default = $pol.UpdateDefault
        $perApp  = $pol.("Update$chromeGuid")
        if ($null -ne $perApp)  { return ($perApp  -eq 0) }
        if ($null -ne $default) { return ($default -eq 0) }
        return $false
    }

    function Set-RelaunchNotificationPolicy {
        param([string]$Mode, [int]$PeriodHours)
        $key = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        $value = if ($Mode -eq 'Recommended') { 1 } else { 2 }
        New-ItemProperty -Path $key -Name 'RelaunchNotification' -Value $value -PropertyType DWord -Force | Out-Null
        if ($PeriodHours -gt 0) {
            $ms = [int]($PeriodHours * 3600000)
            New-ItemProperty -Path $key -Name 'RelaunchNotificationPeriod' -Value $ms -PropertyType DWord -Force | Out-Null
        }
        return $value
    }

    function Get-UpdaterExitMeaning {
        # Translates the more common modern-updater exit codes. Base is 75000 on
        # Windows (kUpdaterErrorBase); Omaha legacy uses HRESULTs / small ints.
        param($Code)
        if ($null -eq $Code) { return $null }
        switch ([int]$Code) {
            0     { 'kErrorOk - success (check completed / update applied)'; break }
            75002 { 'kErrorFailedToSwap'; break }
            75004 { 'kErrorPermissionDenied'; break }
            75009 { 'kErrorUnknownCommandLine - wrong switch for this engine (e.g. /ua sent to the new updater)'; break }
            75045 { 'kErrorIdle - ran but nothing to do (already current / no applicable update)'; break }
            75046 { 'kErrorEulaRequired'; break }
            75047 { 'kErrorUnsupportedOperatingSystem'; break }
            75079 { 'kErrorPolicyFetchFailed'; break }
            75083 { 'kErrorNoApps - no registered apps to update'; break }
            default {
                if ([int]$Code -ge 75000 -and [int]$Code -lt 76000) {
                    "Chromium updater error (kUpdaterErrorBase + $([int]$Code - 75000))"
                } else {
                    "Exit code $Code"
                }
                break
            }
        }
    }

    # ---------- detect --------------------------------------------------------

    $machine  = @(Get-MachineChromeInstalls)
    $peruser  = @(Get-PerUserChromeInstalls)
    $msiInfo  = @(Get-ChromeMsiInfo)
    $updater  = Get-ChromeUpdaterInfo

    $msiPresent = $msiInfo.Count -gt 0

    $deploymentType =
        if     ($updater.Engine -eq 'NewUpdater' -and $msiPresent) { 'MSI (self-updating via GoogleUpdater)' }
        elseif ($updater.Engine -eq 'NewUpdater')                  { 'GoogleUpdater (Chromium updater)' }
        elseif ($updater.Engine -eq 'Omaha' -and $msiPresent)      { 'MSI (with legacy Omaha)' }
        elseif ($updater.Engine -eq 'Omaha')                       { 'Omaha (legacy, standalone)' }
        elseif ($msiPresent)                                       { 'MSI (no self-updater)' }
        else                                                       { 'Unknown' }

    $running   = @(Get-Process -Name chrome -ErrorAction SilentlyContinue)
    $isRunning = $running.Count -gt 0

    $result = [ordered]@{
        Computer                = $env:COMPUTERNAME
        Timestamp               = (Get-Date).ToString('s')
        DeploymentType          = $deploymentType
        UpdaterEngine           = $updater.Engine
        UpdaterExe              = $(if ($updater.NewUpdaterExe) { $updater.NewUpdaterExe } else { $updater.LegacyExe })
        UpdaterVersion          = $(if ($updater.NewUpdaterVersion) { $updater.NewUpdaterVersion } else { $updater.LegacyExeVersion })
        LegacyExeIsShim         = $updater.LegacyExeIsShim
        MsiPresent              = $msiPresent
        MsiProductCode          = ($msiInfo | Select-Object -First 1 -ExpandProperty ProductCode)
        ChromeRunning           = $isRunning
        RunningProcessIds       = @($running | Select-Object -ExpandProperty Id)
        MachineInstalls         = $machine
        PerUserInstalls         = $peruser
        UpdatesPolicyBlocked    = $false
        RelaunchNotificationSet = $null
        Action                  = 'None'
        UpdaterExitCode         = $null
        UpdaterExitMeaning      = $null
        VersionBefore           = $null
        VersionAfter            = $null
        StagedVersion           = $null
        Message                 = ''
    }

    Write-Verbose "Engine: $($updater.Engine) | Deployment: $deploymentType | Chrome running: $isRunning ($($running.Count))"

    # ---------- RelaunchNotification policy (independent of update path) -------

    if ($RelaunchNotification -ne 'None') {
        $descPol = "set RelaunchNotification=$RelaunchNotification" +
                   $(if ($RelaunchNotificationPeriodHours -gt 0) { " (period ${RelaunchNotificationPeriodHours}h)" } else { '' })
        if ($PSCmdlet.ShouldProcess("$($env:COMPUTERNAME) Chrome policy", $descPol)) {
            $val = Set-RelaunchNotificationPolicy -Mode $RelaunchNotification -PeriodHours $RelaunchNotificationPeriodHours
            $result.RelaunchNotificationSet = $val
            Write-Verbose "RelaunchNotification policy written (value $val)."
        } else {
            $result.RelaunchNotificationSet = "WhatIf: would $descPol"
        }
    }

    # ---------- guard: nothing to update --------------------------------------

    if (-not $machine) {
        $result.Action  = 'Skipped'
        $result.Message = 'No machine-wide Chrome install found. Per-user installs cannot be patched from SYSTEM; handle those in the user context.'
        Write-Warning $result.Message
        return [pscustomobject]$result
    }

    $machinePrimary = $machine |
        Sort-Object { ConvertTo-ChromeVersion $_.Version } -Descending |
        Select-Object -First 1
    $result.VersionBefore = $machinePrimary.Version
    $currentVer = ConvertTo-ChromeVersion $machinePrimary.Version

    if ($TargetVersion -and $currentVer -and $currentVer -ge $TargetVersion) {
        $result.Action  = 'None'
        $result.Message = "Machine Chrome $($machinePrimary.Version) already >= target $TargetVersion."
        return [pscustomobject]$result
    }

    # No self-updating engine at all: defer to the MSI channel.
    if ($updater.Engine -eq 'None') {
        $result.Action  = 'DeferToMsi'
        $result.Message = "No self-updating engine present (MSI-only, ProductCode $($result.MsiProductCode)). Patch via your MSI channel: msiexec /i <new>.msi /qn REINSTALL=ALL REINSTALLMODE=vomus."
        Write-Warning $result.Message
        return [pscustomobject]$result
    }

    if (Test-ChromeUpdatesDisabled) {
        $result.UpdatesPolicyBlocked = $true
        $result.Action  = 'Blocked'
        $result.Message = 'Google Update policy disables Chrome updates (UpdateDefault/per-app = 0). Fix the policy before this can patch.'
        Write-Warning $result.Message
        return [pscustomobject]$result
    }

    # ---------- act: trigger the correct engine (guarded by ShouldProcess) ----

    $target   = "$($env:COMPUTERNAME) Chrome $($machinePrimary.Version)"
    $descAct  = if ($TargetVersion) { "update to >= $TargetVersion via $($updater.Engine)" }
                else                { "update to latest via $($updater.Engine) (non-disruptive, no relaunch forced)" }

    if ($PSCmdlet.ShouldProcess($target, $descAct)) {

        if ($isRunning) {
            Write-Verbose 'Chrome running; update stages and applies on next relaunch. Not closing it.'
        }

        $triggered = $false

        if ($updater.Engine -eq 'NewUpdater') {

            # Prefer the real versioned updater.exe; the shim copy also accepts
            # modern switches, so fall back to it if needed.
            $exe = if ($updater.NewUpdaterExe)   { $updater.NewUpdaterExe }
                   elseif ($updater.LegacyExeIsShim) { $updater.LegacyExe }
                   else { $null }

            if ($exe) {
                # '--update-apps' is the modern equivalent of Omaha '/ua': check and
                # update every registered app. '--system' = machine scope.
                $argList = @('--update-apps','--system','--installsource','scheduler')
                if ($VerboseUpdaterLog) {
                    $argList += @('--enable-logging','--vmodule=*/chrome/updater/*=2')
                }
                Write-Verbose "Running: `"$exe`" $($argList -join ' ')"
                $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -WindowStyle Hidden
                $null = $p.Handle   # fix: without a cached handle, ExitCode is empty once the process has exited (PS 5.1)
                if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
                    try { $p.Kill(); [void]$p.WaitForExit(5000) } catch {}   # fix: ExitCode throws until the kill completes
                    $result.Message = "Updater did not exit within $TimeoutSeconds s; update may still be running in the background."
                }
                $result.Action          = 'TriggeredViaChromiumUpdater'
                $result.UpdaterExitCode  = $p.ExitCode
                $triggered = $true
            }

            # Fallback: kick the modern scheduled task if we couldn't run the exe.
            if (-not $triggered -and $updater.NewUpdaterTask) {
                try {
                    Start-ScheduledTask -TaskName $updater.NewUpdaterTask
                    $result.Action = 'TriggeredViaChromiumUpdaterTask'
                    $triggered = $true
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Seconds 5
                        $info  = Get-ScheduledTask -TaskName $updater.NewUpdaterTask | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                        $state = (Get-ScheduledTask -TaskName $updater.NewUpdaterTask).State
                    } while ($state -eq 'Running' -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds)
                    $result.UpdaterExitCode = $info.LastTaskResult
                } catch {
                    Write-Verbose "Modern task trigger failed: $($_.Exception.Message)"
                }
            }

        }
        elseif ($updater.Engine -eq 'Omaha') {

            # Genuine legacy Omaha: the '/ua' path is still correct here.
            if ($updater.LegacyUaTask) {
                try {
                    Start-ScheduledTask -TaskName $updater.LegacyUaTask
                    $triggered = $true
                    $result.Action = 'TriggeredViaOmahaScheduledTask'
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Seconds 5
                        $info  = Get-ScheduledTask -TaskName $updater.LegacyUaTask | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                        $state = (Get-ScheduledTask -TaskName $updater.LegacyUaTask).State
                    } while ($state -eq 'Running' -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds)
                    $result.UpdaterExitCode = $info.LastTaskResult
                } catch {
                    Write-Verbose "Omaha task trigger failed: $($_.Exception.Message)"
                }
            }

            if (-not $triggered -and $updater.LegacyExe -and -not $updater.LegacyExeIsShim) {
                $p = Start-Process -FilePath $updater.LegacyExe -ArgumentList '/ua','/installsource','scheduler' -PassThru -WindowStyle Hidden
                $null = $p.Handle   # fix: see above
                if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
                    try { $p.Kill(); [void]$p.WaitForExit(5000) } catch {}
                    $result.Message = "Updater did not exit within $TimeoutSeconds s; update may still be staging."
                }
                $result.Action         = 'TriggeredViaGoogleUpdateExe'
                $result.UpdaterExitCode = $p.ExitCode
                $triggered = $true
            }
        }

        # fix: when nothing could be started, the result used to say Action=None and "Update triggered".
        if (-not $triggered) {
            $result.Action  = 'TriggerFailed'
            $result.Message = "No $($updater.Engine) trigger could be started (updater exe or task missing, or the task failed to start; rerun with -Verbose)."
        }

        $result.UpdaterExitMeaning = Get-UpdaterExitMeaning $result.UpdaterExitCode

        Start-Sleep -Seconds 3
        $after = @(Get-MachineChromeInstalls) |
                 Sort-Object { ConvertTo-ChromeVersion $_.Version } -Descending |
                 Select-Object -First 1
        $result.VersionAfter  = $after.Version
        $result.StagedVersion = $after.Staged

        if (-not $result.Message) {
            $result.Message = if ($result.VersionAfter -ne $result.VersionBefore) {
                "Chrome updated on disk: $($result.VersionBefore) -> $($result.VersionAfter). Applies live on next relaunch."
            } elseif ($result.StagedVersion) {
                # fix: a running Chrome keeps chrome.exe at the old version, which used to read as "already current".
                "Update staged: new_chrome.exe $($result.StagedVersion) is waiting; chrome.exe stays $($result.VersionAfter) until Chrome relaunches. Updater exit: $($result.UpdaterExitCode) ($($result.UpdaterExitMeaning))."
            } elseif ($result.UpdaterExitCode -in @(0, 75045)) {
                "No newer version applied ($($result.VersionAfter)) - already current or nothing applicable. ($($result.UpdaterExitMeaning))"
            } else {
                "Update triggered. On-disk version still $($result.VersionAfter). Updater exit: $($result.UpdaterExitCode) ($($result.UpdaterExitMeaning)). May be staged for next relaunch, or check the exit meaning."
            }
        }
    }
    else {
        $result.Action  = 'WhatIf'
        $result.Message = "WHATIF: would $descAct. Chrome running=$isRunning; would NOT be force-closed."
    }

    return [pscustomobject]$result
}

#endregion

#region -------------------- Invoke-ChromeRecon (from Chrome_Recon.ps1) --------------------

function Invoke-ChromeRecon {

    $ErrorActionPreference = 'SilentlyContinue'

    function Get-FileVersionSafe {
        param([string]$Path)
        if (Test-Path $Path) {
            try { return (Get-Item $Path).VersionInfo.FileVersion } catch { return $null }
        }
        return $null
    }

    function ConvertTo-ChromeVersion {
        param([string]$Version)

        if ([string]::IsNullOrWhiteSpace($Version)) {
            return $null
        }

        $match = [regex]::Match($Version, '\d+(?:\.\d+){1,3}')
        if (-not $match.Success) {
            return $null
        }

        try { return [version]$match.Value } catch { return $null }
    }

    function Format-InstallName {
        param($Install)

        if ($Install.Scope -eq 'PerUser' -and $Install.UserProfile) {
            return "Per-user ($($Install.UserProfile))"
        }

        return $Install.Scope
    }

    function Get-UninstallEntries {
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        foreach ($root in $roots) {
            Get-ItemProperty $root | Where-Object {
                $_.DisplayName -match 'Google Chrome'
            } | Select-Object `
                @{Name='Scope';Expression={
                    if ($_.PSPath -like '*HKLM*') { 'Machine' } else { 'CurrentUser' }
                }},
                DisplayName,
                DisplayVersion,
                InstallLocation,
                UninstallString
        }
    }

    function Get-ProfileChromeInstalls {
        $results = @()

        $userDirs = Get-ChildItem 'C:\Users' -Directory | Where-Object {
            $_.Name -notin @('Public','Default','Default User','All Users')
        }

        foreach ($userDir in $userDirs) {
            $chromeRoot = Join-Path $userDir.FullName 'AppData\Local\Google\Chrome\Application'
            $chromeExe  = Join-Path $chromeRoot 'chrome.exe'

            if (Test-Path $chromeRoot) {
                $results += [pscustomobject]@{
                    Scope        = 'PerUser'
                    UserProfile  = $userDir.Name
                    Path         = $chromeRoot
                    Version      = Get-FileVersionSafe -Path $chromeExe
                }
            }
        }

        return $results
    }

    function Get-MachineChromeInstalls {
        $paths = @(
            'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
        )

        foreach ($path in $paths) {
            if (Test-Path $path) {
                [pscustomobject]@{
                    Scope        = 'Machine'
                    UserProfile  = $null
                    Path         = Split-Path $path -Parent
                    Version      = Get-FileVersionSafe -Path $path
                }
            }
        }
    }

    Write-Host ""
    Write-Host "Chrome Multi-User Recon" -ForegroundColor Cyan
    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "Run time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    $machineInstalls = @(Get-MachineChromeInstalls)
    $userInstalls    = @(Get-ProfileChromeInstalls)
    $allInstalls     = @($machineInstalls + $userInstalls)

    if (-not $allInstalls) {
        Write-Host "No Chrome installs found." -ForegroundColor Yellow
        return 0
    }

    $parsed = @(foreach ($item in $allInstalls) {
        [pscustomobject]@{
            Scope       = $item.Scope
            UserProfile = $item.UserProfile
            Version     = $item.Version
            VersionObj  = ConvertTo-ChromeVersion -Version $item.Version
            Path        = $item.Path
        }
    })

    $highest = $parsed |
        Where-Object { $_.VersionObj } |
        Sort-Object VersionObj -Descending |
        Select-Object -First 1

    $stale = @()
    if ($highest) {
        $stale = @($parsed | Where-Object {
            $_.VersionObj -and $_.VersionObj -lt $highest.VersionObj
        })
    }

    $unparsed = @($parsed | Where-Object { -not $_.VersionObj })
    $perUserInstalls = @($parsed | Where-Object { $_.Scope -eq 'PerUser' })
    $machineInstalls = @($parsed | Where-Object { $_.Scope -eq 'Machine' })

    Write-Host "Summary" -ForegroundColor Cyan
    Write-Host "  Chrome installs found : $($parsed.Count)"
    Write-Host "  Machine installs      : $($machineInstalls.Count)"
    Write-Host "  Per-user installs     : $($perUserInstalls.Count)"

    if ($highest) {
        Write-Host "  Highest version       : $($highest.Version) ($($highest.Path))" -ForegroundColor Green
    } else {
        Write-Host "  Highest version       : Unable to determine" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Detected Installations" -ForegroundColor Cyan
    $parsed |
        Sort-Object Scope, UserProfile, VersionObj |
        Select-Object `
            @{Name='Install';Expression={ Format-InstallName -Install $_ }},
            @{Name='Version';Expression={ if ($_.Version) { $_.Version } else { 'Unknown' } }},
            @{Name='Status';Expression={
                if (-not $_.VersionObj) { 'Version not parsed' }
                elseif ($highest -and $_.VersionObj -lt $highest.VersionObj) { 'Older than highest' }
                elseif ($highest -and $_.Path -eq $highest.Path) { 'Highest detected' }
                else { 'Current/duplicate' }
            }},
            Path |
        Format-Table -Wrap -AutoSize | Out-Host

    Write-Host ""
    Write-Host "Uninstall Registry Entries" -ForegroundColor Cyan
    $uninstalls = @(Get-UninstallEntries)

    if ($uninstalls.Count -gt 0) {
        $uninstalls |
            Select-Object Scope, DisplayName, DisplayVersion, InstallLocation |
            Format-Table -Wrap -AutoSize | Out-Host

        Write-Host "Uninstall commands:" -ForegroundColor DarkCyan
        $uninstalls | ForEach-Object {
            if ($_.UninstallString) {
                Write-Host "  [$($_.Scope)] $($_.UninstallString)"
            }
        }
    } else {
        Write-Host "  No Chrome uninstall entries found." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Assessment" -ForegroundColor Cyan
    if ($stale.Count -gt 0) {
        Write-Host "  Finding : Older Chrome install(s) detected." -ForegroundColor Red
        Write-Host "  Impact  : Vulnerability scanners may report the older version even when machine Chrome is patched."
        Write-Host "  Targets :"
        $stale | ForEach-Object {
            Write-Host "    - $(Format-InstallName -Install $_): $($_.Version) at $($_.Path)" -ForegroundColor Yellow
        }
    } elseif ($perUserInstalls.Count -gt 0 -and $machineInstalls.Count -gt 0) {
        Write-Host "  Finding : Machine and per-user Chrome installs both exist." -ForegroundColor Yellow
        Write-Host "  Impact  : This can still confuse inventory tools if profile-level paths are scanned separately."
    } elseif ($unparsed.Count -gt 0) {
        Write-Host "  Finding : Some Chrome versions could not be parsed." -ForegroundColor Yellow
        Write-Host "  Impact  : Compare those paths manually before closing the alert."
    } else {
        Write-Host "  Finding : No older or duplicate Chrome installs detected." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Recommended Next Step" -ForegroundColor Cyan
    if ($stale.Count -gt 0) {
        Write-Host "  Remove the older per-user Chrome install(s), then rerun the ConnectSecure/CyberCNS scan." -ForegroundColor Yellow
    } elseif ($perUserInstalls.Count -gt 0 -and $machineInstalls.Count -gt 0) {
        Write-Host "  Standardize on machine-wide Chrome where possible and remove redundant per-user installs." -ForegroundColor Yellow
    } elseif ($unparsed.Count -gt 0) {
        Write-Host "  Check the unparsed install path(s) manually, then rerun this recon." -ForegroundColor Yellow
    } else {
        Write-Host "  No local Chrome cleanup needed. Investigate scanner cache, stale agent data, or detection logic." -ForegroundColor Green
        return 0
    }
    return 2   # any finding above
}

#endregion

#region -------------------- Invoke-Chrome (dispatcher, returns the exit code) --------------------

function Invoke-Chrome {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Recon', 'Update')]
        [string]$Mode = 'Check',
        # Parameters of Invoke-ChromeUpdate, e.g. @{ TargetVersion = '<version>' } (Check uses only that one)
        [hashtable]$Options = @{}
    )

    try {
        if ($Mode -eq 'Update' -and -not (Test-IsAdmin)) {
            Write-Host 'ERROR: -Mode Update needs an elevated or SYSTEM session (also for -WhatIf). Nothing changed.' -ForegroundColor Red
            return 10
        }
        if (-not (Test-IsAdmin)) {
            Write-Host "NOT ELEVATED: other users' profiles may be unreadable, so per-user results can be incomplete." -ForegroundColor Yellow
        }

        switch ($Mode) {
            'Check' {
                # -WhatIf: detection only. Other options (RelaunchNotification...) are ignored on purpose.
                $o = @{ WhatIf = $true }
                if ($Options.TargetVersion) { $o.TargetVersion = $Options.TargetVersion }
                $r = Invoke-ChromeUpdate @o

                $installs = @(@($r.MachineInstalls) + @($r.PerUserInstalls))
                if (-not $installs) { Write-Host 'Google Chrome is not installed (no machine-wide or per-user chrome.exe).'; return 0 }

                $r | Format-List DeploymentType, UpdaterEngine, UpdaterExe, UpdaterVersion, LegacyExeIsShim,
                                 MsiPresent, MsiProductCode, ChromeRunning | Out-Host
                $installs | Format-Table Scope, User, Version, Staged, Path -AutoSize | Out-String -Width 250 | Out-Host

                $reasons = @()
                $highest = $installs | Sort-Object { ConvertTo-ChromeVersion $_.Version } -Descending | Select-Object -First 1
                $hv      = ConvertTo-ChromeVersion $highest.Version
                $stale   = @($installs | Where-Object { $v = ConvertTo-ChromeVersion $_.Version; $v -and $hv -and $v -lt $hv })
                if ($stale) {
                    $reasons += "older than $($highest.Version): " + (($stale | ForEach-Object {
                        "$($_.Scope)$(if ($_.User) { " ($($_.User))" }) $($_.Version)" }) -join ', ')
                }
                foreach ($s in @($r.MachineInstalls | Where-Object Staged)) {
                    $reasons += "update $($s.Staged) staged over $($s.Version), applies when Chrome relaunches (Update -Options @{ RelaunchNotification = 'Recommended' } nudges users)"
                }
                switch ($r.Action) {
                    'WhatIf' {
                        if ($o.TargetVersion) { $reasons += "machine Chrome $($r.VersionBefore) is below target $($o.TargetVersion)" }
                        else { Write-Host "No TargetVersion given, so whether $($r.VersionBefore) is the latest release is unknown. Pass -Options @{ TargetVersion = '<version>' }." -ForegroundColor DarkYellow }
                    }
                    'None'       { Write-Host $r.Message -ForegroundColor Green }
                    'DeferToMsi' { $reasons += 'MSI-only install with no self-updater: patch through the MSI channel' }
                    'Blocked'    { $reasons += 'Google Update policy blocks Chrome updates' }
                }

                if ($reasons) {
                    $reasons | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                    Write-Host "Chrome: ACTION NEEDED ($($reasons.Count) reason$(if ($reasons.Count -ne 1) { 's' }))" -ForegroundColor Yellow
                    return 2
                }
                Write-Host 'Chrome: OK' -ForegroundColor Green
                return 0
            }
            'Recon' {
                $rc = @(Invoke-ChromeRecon)
                return [int]$rc[-1]   # the function's last output is its exit code
            }
            'Update' {
                $o = @{} + $Options
                if ($WhatIfPreference) { $o.WhatIf = $true }
                $r = Invoke-ChromeUpdate @o
                $r | Select-Object * -ExcludeProperty MachineInstalls, PerUserInstalls | Format-List | Out-Host
                @(@($r.MachineInstalls) + @($r.PerUserInstalls)) |
                    Format-Table Scope, User, Version, Staged, Path -AutoSize | Out-String -Width 250 | Out-Host

                switch -Wildcard ($r.Action) {
                    'TriggeredVia*' {
                        if ($r.UpdaterExitCode -in @(0, 75045) -or $r.VersionAfter -ne $r.VersionBefore) { return 0 }
                        return 1
                    }
                    'None'    { return 0 }
                    'WhatIf'  { return 0 }
                    'Skipped' { if (@($r.PerUserInstalls).Count) { return 1 }; return 0 }
                    default   { return 1 }   # DeferToMsi, Blocked, TriggerFailed
                }
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

$exitCode = Invoke-Chrome                                                # Check (read-only, fast)
# $exitCode = Invoke-Chrome -Options @{ TargetVersion = '<version>' }    # Check against a minimum version (read-only)
# $exitCode = Invoke-Chrome -Mode Recon                                  # Deep scan of every profile + uninstall entries (read-only)
# $exitCode = Invoke-Chrome -Mode Update -WhatIf                         # Preview, changes nothing (needs admin)
# $exitCode = Invoke-Chrome -Mode Update                                 # LIVE: machine-wide update via GoogleUpdater/Omaha, never closes Chrome
# $exitCode = Invoke-Chrome -Mode Update -Options @{ RelaunchNotification = 'Recommended' }   # LIVE: + relaunch reminder policy
# $exitCode = Invoke-Chrome -Mode Update -Options @{ TargetVersion = '<version>'; VerboseUpdaterLog = $true; Verbose = $true }

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
