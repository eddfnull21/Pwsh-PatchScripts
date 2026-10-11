# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    WinGet bulk upgrade (everything except Microsoft Office / Microsoft 365) - Check / Upgrade. RMM-ready.

.DESCRIPTION
    -Mode Check     DEFAULT. Read-only. Runs 'winget list --upgrade-available' and applies the same
                    exclusions as Upgrade (Office / M365 always, plus BlockingPinIds,
                    ExcludedPackageIds and AdditionalExcludePattern), then lists the packages Upgrade
                    would touch. No pins, no installers, no log folders. Works without elevation
                    (it then sees the current user's view of installed packages).
    -Mode Upgrade   Upgrades each eligible package one at a time by exact ID (--silent), waiting for
                    any other installer / Windows Installer activity first and following each
                    upgrade's process tree and logs (%TEMP%\WinGet-Upgrade-<guid>). Ensures a
                    persistent blocking WinGet pin for every BlockingPinIds entry before discovery.
                    A failed package does not stop the queue. -Options @{ WhatIf = $true } previews.

    Options (both modes) are parameters of Invoke-WingetUpgradeExceptOffice, passed as a hashtable:
        ExcludedPackageIds        exact IDs skipped by this script only, e.g. @('<Vendor.Package>')
        BlockingPinIds            exact IDs also pinned (blocking) in WinGet by Upgrade - persists
                                  after the script; removing an ID here does not remove the pin
        AdditionalExcludePattern  regexes matched against ID and name
        IncludeUnknown ($true), IncludePinned, Force, SkipPackagesInUse, Live, Source ('winget'),
        WingetPath, plus Verbose / WhatIf

    WinGet is resolved from PATH, then App Installer (Get-AppxPackage, -AllUsers when needed), then
    C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*. winget.exe is usually not on PATH
    for SYSTEM; Microsoft does not support the WinGet CLI under SYSTEM, though it generally works for
    machine-wide packages. Per-user packages of other users are not seen or upgraded under SYSTEM.

    Requirements: Windows PowerShell 5.1, App Installer (WinGet), English WinGet output (the table is
    parsed). Upgrade needs an elevated or SYSTEM session, also for -WhatIf.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the mode - edit that one
    line. For an RMM component also set $RMM = $true there, so the script exits with the code.

    Invoke-Winget                                                          # Check (read-only)
    Invoke-Winget -Options @{ ExcludedPackageIds = @('<Vendor.Package>') } # Check with exclusions
    Invoke-Winget -Mode Upgrade -Options @{ WhatIf = $true; Live = $true } # Preview upgrades
    Invoke-Winget -Mode Upgrade -Options @{ Live = $true }                 # Upgrade, streaming output
    Invoke-Winget -Mode Upgrade -Options @{ Live = $true; SkipPackagesInUse = $true }

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-Winget returns one; the entry point exits with it only when $RMM = $true):
        0     Check: nothing to upgrade / Upgrade: done, nothing to do, or -WhatIf
        1     Error (WinGet missing, discovery or pinning failed), or one or more upgrades failed
        2     Check: upgrades available (something for Upgrade to act on)
        3010  Upgrade: done, restart required to finish
        10    Upgrade: session is not elevated - nothing changed
#>

#region -------------------- Invoke-WingetUpgradeExceptOffice (from the v1.1 upgrade script) --------------------

function Invoke-WingetUpgradeExceptOffice {
    <#
    .SYNOPSIS
    Sequentially upgrades WinGet packages except Office and configured IDs.

    .DESCRIPTION
    Intended for Windows PowerShell 5.1 / PowerShell 7 on Windows.

    Returns one integer:
      0    Success, preview, or no work.
      1    Upgrade or monitoring failure; preflight, pinning, or discovery failure.
      2    -CheckOnly: eligible upgrades found.
      3010 Restart required.

    -CheckOnly stops after discovery: lists the eligible packages and never
    pins, waits or upgrades. Invoke-Winget -Mode Check passes it with -WhatIf.

    Skipped packages do not count as failures.

    -WhatIf performs discovery, which may refresh WinGet's cache or accept
    source terms. It never changes pins or starts installers.

    -Live streams output and installer logs. Otherwise, installer output uses
    -Verbose. Both modes retain logs and wait for the launched process tree.

    Existing-installer detection is best-effort. Detached services and
    installations starting between checks can escape detection.
    Ctrl+C interrupts monitoring; installers may remain running.

    -SkipPackagesInUse requires an exact registry display-name match plus a
    running executable beneath the application's InstallLocation.

    Office protection applies to direct targets, not installer dependencies
    or unrelated automatic updaters. WinGet CLI is not supported under SYSTEM.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([int])]
    param(
        [bool]$IncludeUnknown = $true,
        [switch]$IncludePinned,
        [switch]$Force,
        [switch]$SkipPackagesInUse,
        [switch]$Live,

        [ValidateNotNull()]
        [string[]]$AdditionalExcludePattern = @(),

        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Source = 'winget',

        [ValidateNotNullOrEmpty()]
        [string]$WingetPath,

        # CUSTOM RULES: exact IDs, never wildcards, e.g. @('<Vendor.Package>').
        # Upgrade creates a persistent blocking WinGet pin for each; they are also excluded.
        # Removing an ID from this list does not remove an existing WinGet pin.
        [ValidateNotNull()]
        [string[]]$BlockingPinIds = @(),

        # These exclusions affect only this function; no pins are created.
        # e.g. @('<Vendor.Package>')
        [ValidateNotNull()]
        [string[]]$ExcludedPackageIds = @(),

        [switch]$CheckOnly
    )

    Set-StrictMode -Version 2.0

    $officeIdPattern = '(?i)^(?:Microsoft\.(?:Office(?:$|\.)|365|M365|Microsoft(?:Office|365))|9WZDNCRD29V9$)'
    $officeNamePattern = '(?i)^(?:Microsoft\s+(?:365|M365)|Microsoft\s+Office(?!\s+Deployment\s+Tool)|Office\s+(?:365|LTSC|Professional|Standard|Home|Personal))(?:\s|\(|$)'

    # Private scriptblocks keep this as one callable function.
    $quoteArguments = {
        param([string[]]$Values)

        (@(foreach ($value in $Values) {
            '"' + ($value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
        })) -join ' '
    }

    # Capture both streams asynchronously to avoid pipe-buffer deadlocks.
    $runCommand = {
        param([string]$Executable, [string[]]$Arguments)

        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $Executable
        $info.Arguments = & $quoteArguments $Arguments
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
        $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info

        try {
            if (-not $process.Start()) {
                throw "Could not start $Executable."
            }

            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            $process.WaitForExit()

            [pscustomobject]@{
                Code      = [int]$process.ExitCode
                Text      = $stdout.GetAwaiter().GetResult()
                ErrorText = $stderr.GetAwaiter().GetResult()
            }
        }
        finally {
            $process.Dispose()
        }
    }

    $readLogs = {
        param(
            [string[]]$Paths,
            [hashtable]$Readers,
            [string]$Label,
            [switch]$Final,
            [switch]$TailExisting,
            [switch]$ShowLive
        )

        $changed = $false

        foreach ($path in $Paths) {
            try {
                if (-not [IO.File]::Exists($path)) { continue }

                $length = ([IO.FileInfo]$path).Length
                if ($Readers.ContainsKey($path) -and
                    $length -lt $Readers[$path].Reader.BaseStream.Position) {
                    $Readers[$path].Reader.Dispose()
                    $Readers.Remove($path)
                }

                $firstRead = -not $Readers.ContainsKey($path)
                if ($firstRead) {
                    if ($length -lt 3 -and -not $Final) { continue }

                    $stream = [IO.File]::Open(
                        $path,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Read,
                        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    )
                    $Readers[$path] = @{
                        Reader  = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
                        Pending = ''
                    }
                }

                $state = $Readers[$path]
                $chunk = $state.Reader.ReadToEnd()

                if ($chunk.Length -gt 0 -or ($Final -and $state.Pending.Length -gt 0)) {
                    $changed = $chunk.Length -gt 0 -or $changed
                    $text = $state.Pending + $chunk

                    if ($Final -and $text -notmatch '[\r\n]$') { $text += "`n" }

                    $lines = [regex]::Split($text, "`r`n|`n|`r")
                    $state.Pending = $lines[$lines.Length - 1]
                    $firstLine = 0

                    if ($TailExisting -and $firstRead) {
                        $firstLine = [Math]::Max(0, $lines.Length - 21)
                    }

                    for ($i = $firstLine; $i -lt $lines.Length - 1; $i++) {
                        $clean = $lines[$i] -replace '\x1B\[[0-?]*[ -/]*[@-~]', ''
                        if ([string]::IsNullOrWhiteSpace($clean)) { continue }

                        $message = '[{0}][{1}] {2}' -f $Label, [IO.Path]::GetFileName($path), $clean
                        if ($ShowLive) { Write-Host $message }
                        else { Write-Verbose $message }
                    }
                }
            }
            catch [IO.IOException] {
                Write-Verbose "Log temporarily unavailable: $path"
            }
            catch [UnauthorizedAccessException] {
                Write-Verbose "Log not readable: $path"
            }
        }

        return $changed
    }

    $testMsiBusy = {
        foreach ($name in @('Global\_MSIExecute', '_MSIExecute')) {
            $mutex = $null
            $owned = $false

            try {
                $mutex = [Threading.Mutex]::OpenExisting($name)
                try { $owned = $mutex.WaitOne(0) }
                catch [Threading.AbandonedMutexException] { $owned = $true }

                if (-not $owned) { return $true }
            }
            catch [Threading.WaitHandleCannotBeOpenedException] {
                # No execution mutex exists.
            }
            catch [UnauthorizedAccessException] {
                throw 'Cannot inspect the Windows Installer mutex. Run with sufficient rights.'
            }
            finally {
                if ($owned) { $mutex.ReleaseMutex() }
                if ($null -ne $mutex) { $mutex.Dispose() }
            }
        }

        return $false
    }

    # Heuristic detection: cannot coordinate arbitrary external updaters.
    $getActivity = {
        param([hashtable]$Tracked)

        $snapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $byId = @{}
        foreach ($item in $snapshot) {
            $byId[[int]$item.ProcessId] = $item
        }

        $active = @{}
        foreach ($item in $snapshot) {
            $id = [int]$item.ProcessId
            if ($id -eq $PID) { continue }

            $command = [string]$item.CommandLine
            $isWinget = $item.Name -ieq 'winget.exe' -and
                $command -match '(?i)(?:^|\s)"?(?:install|upgrade|update)"?(?:\s|$)'
            $isMsiClient = $item.Name -ieq 'msiexec.exe' -and
                $command -match '(?i)(?:^|\s)"?/(?:i|x|package|uninstall|update|a|j[um]?|f[a-z]*)(?=\s|"|[A-Za-z]:|\{|$)'
            $isSetup = $item.Name -match '(?i)(?:setup|installer).*\.exe$' -and
                $command -match '(?i)(?:^|\s)"?(?:--?|/)(?:s|silent|verysilent|quiet|qn|passive|install|uninstall|log)(?:\s|=|"|$)'
            $wasTracked = $Tracked.ContainsKey($id) -and
                $Tracked[$id] -eq $item.CreationDate

            if ($isWinget -or $isMsiClient -or $isSetup -or $wasTracked) {
                $active[$id] = $item
            }
        }

        # Follow descendants and recognizable setup ancestors.
        # Creation times protect against recycled process IDs.
        $changed = $true
        while ($changed) {
            $changed = $false

            foreach ($item in $snapshot) {
                $id = [int]$item.ProcessId
                $parent = [int]$item.ParentProcessId

                if ($id -eq $PID -or $active.ContainsKey($id)) { continue }

                if ($active.ContainsKey($parent) -and
                    $item.CreationDate -ge $active[$parent].CreationDate) {
                    $active[$id] = $item
                    $changed = $true
                }
            }

            foreach ($item in @($active.Values)) {
                $parent = [int]$item.ParentProcessId

                if ($byId.ContainsKey($parent) -and
                    -not $active.ContainsKey($parent) -and
                    $byId[$parent].Name -match '(?i)(?:setup|installer).*\.exe$' -and
                    $byId[$parent].CreationDate -le $item.CreationDate) {
                    $active[$parent] = $byId[$parent]
                    $changed = $true
                }
            }
        }

        $Tracked.Clear()
        $logs = @{}

        foreach ($item in $active.Values) {
            $Tracked[[int]$item.ProcessId] = $item.CreationDate
            $command = ([string]$item.CommandLine).Replace('\"', '"')
            $logMatches = [regex]::Matches(
                $command,
                '(?i)(?:--log|-o|/log|/l[iewarucmopvx+!*]*)(?:"?\s+|=|(?="))(?:"(?<path>[^"]+)"|(?<path>\S+))'
            )

            foreach ($match in $logMatches) {
                $path = [Environment]::ExpandEnvironmentVariables($match.Groups['path'].Value)
                if ([IO.Path]::IsPathRooted($path)) { $logs[$path] = $true }
            }
        }

        [pscustomobject]@{
            Processes = @($active.Values)
            Logs      = @($logs.Keys)
            MsiBusy   = (& $testMsiBusy)
        }
    }

    $waitIdle = {
        param([switch]$ShowLive, [switch]$Preview)

        $tracked = @{}
        Write-Verbose 'Checking for existing installers and Windows Installer activity.'
        $activity = & $getActivity -Tracked $tracked

        if ($activity.Processes.Count -eq 0 -and -not $activity.MsiBusy) {
            Write-Verbose 'No existing installer activity detected.'
            return
        }

        if ($Preview) {
            foreach ($item in $activity.Processes) {
                Write-Host (
                    '[WhatIf] Would wait for {0}, PID {1}, session {2}.' -f
                    $item.Name, $item.ProcessId, $item.SessionId
                )
            }

            if ($activity.MsiBusy) {
                Write-Host '[WhatIf] Would wait for the Windows Installer execution mutex.'
            }

            if ($ShowLive) {
                foreach ($path in $activity.Logs) {
                    Write-Host "[WhatIf] Would watch $path"
                }
            }
            return
        }

        Write-Host '[existing install] Another installer is active. Waiting.'
        $readers = @{}
        $paths = @{}
        $seen = @{}
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $lastHeartbeatAt = -15.0
        $idleSamples = 0

        try {
            while ($true) {
                foreach ($item in $activity.Processes) {
                    $key = '{0}/{1}' -f $item.ProcessId, $item.CreationDate
                    if (-not $seen.ContainsKey($key)) {
                        Write-Host (
                            '[existing install] {0}, PID {1}, session {2}' -f
                            $item.Name, $item.ProcessId, $item.SessionId
                        )
                        $seen[$key] = $true
                    }
                }

                foreach ($path in $activity.Logs) {
                    if (-not $paths.ContainsKey($path)) {
                        Write-Verbose "[existing install] Log: $path"
                        $paths[$path] = $true
                    }
                }

                $idle = $activity.Processes.Count -eq 0 -and -not $activity.MsiBusy
                if ($idle) { $idleSamples++ }
                else { $idleSamples = 0 }

                $finished = $idleSamples -ge 2

                if ($ShowLive) {
                    [void](& $readLogs -Paths @($paths.Keys) -Readers $readers `
                        -Label 'existing install' -Final:$finished -TailExisting -ShowLive)
                }

                if ($finished) { break }

                if ($timer.Elapsed.TotalSeconds - $lastHeartbeatAt -ge 15) {
                    $lastHeartbeatAt = $timer.Elapsed.TotalSeconds
                    Write-Host (
                        '[existing install] Waiting; elapsed {0}; processes {1}; MSI busy {2}.' -f
                        $timer.Elapsed.ToString('hh\:mm\:ss'),
                        $activity.Processes.Count,
                        $activity.MsiBusy
                    )
                }

                Start-Sleep -Seconds 2
                $activity = & $getActivity -Tracked $tracked
            }

            Write-Host '[existing install] Tracked installers have exited and MSI is idle. Continuing.'
        }
        finally {
            foreach ($state in $readers.Values) { $state.Reader.Dispose() }
            $timer.Stop()
        }
    }

    $runUpgrade = {
        param(
            [string]$Executable,
            [string[]]$Arguments,
            [string]$PackageId,
            [string]$LogDirectory,
            [switch]$ShowLive
        )

        [void][IO.Directory]::CreateDirectory($LogDirectory)
        $installerLog = Join-Path $LogDirectory 'installer.log'
        $stdoutLog = Join-Path $LogDirectory 'winget.stdout.log'
        $stderrLog = Join-Path $LogDirectory 'winget.stderr.log'
        $Arguments += @('--log', $installerLog)
        $commandLine = & $quoteArguments $Arguments

        $readers = @{}
        $job = $null
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $lastOutputAt = 0.0
        $lastHeartbeatAt = 0.0

        if ($ShowLive) { Write-Host "[$PackageId] Logs: $LogDirectory" }
        else { Write-Verbose "[$PackageId] Logs: $LogDirectory" }

        try {
            # Start-Process -Wait waits for descendants on Windows.
            # Running it in a job lets the parent follow logs while waiting.
            $job = Start-Job -ArgumentList $Executable, $commandLine, $stdoutLog, $stderrLog -ScriptBlock {
                param($Executable, $CommandLine, $StdoutLog, $StderrLog)

                $ErrorActionPreference = 'Stop'
                try {
                    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
                }
                catch {
                    Write-Warning "Could not select UTF-8 in the worker: $($_.Exception.Message)"
                }

                $process = Start-Process -FilePath $Executable -ArgumentList $CommandLine `
                    -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog `
                    -NoNewWindow -Wait -PassThru

                try {
                    if ($null -eq $process.ExitCode) {
                        throw 'WinGet did not provide an exit code.'
                    }
                    [int]$process.ExitCode
                }
                finally {
                    $process.Dispose()
                }
            } -ErrorAction Stop

            while ($true) {
                $finished = $job.State -in @('Completed', 'Failed', 'Stopped')
                $logPaths = @(Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' `
                    -File -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty FullName)

                if (& $readLogs -Paths $logPaths -Readers $readers -Label $PackageId `
                    -Final:$finished -ShowLive:$ShowLive) {
                    $lastOutputAt = $timer.Elapsed.TotalSeconds
                }

                if ($finished) { break }

                if ($ShowLive -and $timer.Elapsed.TotalSeconds - $lastHeartbeatAt -ge 15) {
                    $lastHeartbeatAt = $timer.Elapsed.TotalSeconds
                    Write-Host (
                        '[{0}] Waiting for WinGet/installer process tree; elapsed {1}; no new output for {2}s.' -f
                        $PackageId,
                        $timer.Elapsed.ToString('hh\:mm\:ss'),
                        [int]($timer.Elapsed.TotalSeconds - $lastOutputAt)
                    )
                }

                Start-Sleep -Milliseconds 500
            }

            $result = @(Receive-Job -Job $job -ErrorAction Stop)
            if ($job.State -ne 'Completed' -or
                $result.Count -ne 1 -or $result[0] -isnot [int]) {
                throw "Installer completion could not be established. Inspect $LogDirectory and running processes."
            }

            Write-Verbose "[$PackageId] Process tree finished; WinGet exit code $($result[0])."
            return [int]$result[0]
        }
        finally {
            foreach ($state in $readers.Values) { $state.Reader.Dispose() }

            if ($null -ne $job) {
                if ($job.State -notin @('Completed', 'Failed', 'Stopped')) {
                    Write-Warning 'Monitoring interrupted. Installers may still be running; check before retrying.'
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                }
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }

            $timer.Stop()
        }
    }

    $parsePackages = {
        param([string]$Text)

        $lines = @((
            $Text -replace '\x1B\[[0-?]*[ -/]*[@-~]', '' -replace '[\x08\x0C]', ''
        ) -split '\r\n|\n|\r')

        $separator = -1
        $idStart = -1
        $versionStart = -1
        $sourceStart = -1

        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^\s*-{5,}\s*$') { continue }

            $tokens = [regex]::Matches($lines[$i - 1], '\S+')
            for ($j = 1; $j -lt $tokens.Count - 1; $j++) {
                if ($tokens[$j].Value -ine 'Id') { continue }

                $separator = $i
                $idStart = $tokens[$j].Index
                $versionStart = $tokens[$j + 1].Index

                foreach ($token in $tokens) {
                    if ($token.Value -ieq 'Source') { $sourceStart = $token.Index }
                }
                break
            }
            if ($separator -ge 0) { break }
        }

        if ($separator -lt 0) {
            $nonempty = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($nonempty.Count -eq 1 -and
                $nonempty[0].Trim() -ceq 'No installed package found matching input criteria.') {
                return
            }
            throw 'Unrecognized WinGet table. Update WinGet or use an English display language, then retry.'
        }

        $seen = @{}
        $foundRow = $false

        for ($i = $separator + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]

            if ([string]::IsNullOrWhiteSpace($line)) {
                if ($foundRow) { break }
                continue
            }

            if ($foundRow -and $line.Trim() -match '^\d+ upgrades? available\.$') { break }
            if ($line.Length -le $versionStart) { throw "Incomplete package row: $line" }

            $id = $line.Substring($idStart, $versionStart - $idStart).Trim()
            $name = $line.Substring(0, $idStart).Trim()

            # Validate boundaries so a shifted column cannot yield a partial ID.
            if (-not $name -or
                $id -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]*$' -or
                $id.EndsWith('...') -or
                -not [char]::IsWhiteSpace($line[$idStart - 1]) -or
                -not [char]::IsWhiteSpace($line[$versionStart - 1]) -or
                [char]::IsWhiteSpace($line[$versionStart])) {
                throw "Ambiguous or truncated package row; increase terminal width: $line"
            }

            if ($sourceStart -ge 0 -and
                ($line.Length -le $sourceStart -or
                    $line.Substring($sourceStart).Trim() -ine $Source)) {
                throw "Unexpected source or shifted package row: $line"
            }

            $foundRow = $true
            if (-not $seen.ContainsKey($id)) {
                $seen[$id] = $true
                [pscustomobject]@{ Id = $id; Name = $name }
            }
        }

        if (-not $foundRow) {
            throw 'WinGet returned an empty or unrecognized package table.'
        }
    }

    $isInUse = {
        param([string]$PackageName)

        $locations = @(
            foreach ($entry in $uninstallEntries) {
                if ([string]$entry.DisplayName -ine $PackageName) { continue }

                try {
                    $raw = [Environment]::ExpandEnvironmentVariables(
                        [string]$entry.InstallLocation
                    ).Trim().Trim('"')

                    if (-not [IO.Path]::IsPathRooted($raw)) { continue }

                    $path = [IO.Path]::GetFullPath($raw).TrimEnd([char[]]'\/')
                    if ($path -ieq [IO.Path]::GetPathRoot($path).TrimEnd([char[]]'\/')) {
                        continue
                    }

                    if (Test-Path -LiteralPath $path -PathType Container) { $path + '\' }
                }
                catch {
                    Write-Verbose "Ignored invalid InstallLocation for $PackageName."
                }
            }
        )

        if ($locations.Count -eq 0) { return $false }

        # Refresh processes for each check instead of using a stale snapshot.
        foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
            try {
                $path = $process.Path
                if (-not $path) { continue }

                foreach ($location in $locations) {
                    if ($path.StartsWith($location, [StringComparison]::OrdinalIgnoreCase)) {
                        return $true
                    }
                }
            }
            catch {
                Write-Verbose "Cannot inspect process $($process.Id)."
            }
        }

        return $false
    }

    # Was 2 in the source; 2 now means "upgrades available" (morph convention).
    $failureCode = 1

    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'This function requires Windows.'
        }

        $patterns = @(
            foreach ($pattern in $AdditionalExcludePattern) {
                if ([string]::IsNullOrWhiteSpace($pattern)) {
                    throw 'Exclusion patterns cannot be blank.'
                }

                [regex]::new(
                    $pattern,
                    [Text.RegularExpressions.RegexOptions]::IgnoreCase,
                    [timespan]::FromSeconds(2)
                )
            }
        )

        $candidates = @()
        if ($PSBoundParameters.ContainsKey('WingetPath')) {
            $candidates = @((Resolve-Path -LiteralPath $WingetPath -ErrorAction Stop).ProviderPath)
        }
        else {
            $candidates = @(Get-Command winget.exe -CommandType Application `
                -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)

            if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
                $appx = @(Get-AppxPackage -Name Microsoft.DesktopAppInstaller `
                    -ErrorAction SilentlyContinue)

                if ($appx.Count -eq 0) {
                    $appx = @(Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller `
                        -ErrorAction SilentlyContinue)
                }

                # Staged/partial registrations can have no InstallLocation; Join-Path would throw.
                $candidates += @($appx | Where-Object { $_.InstallLocation } |
                    Sort-Object { [version]$_.Version } -Descending |
                    ForEach-Object { Join-Path $_.InstallLocation 'winget.exe' })
            }

            # Fallback when the Appx module is unusable (e.g. some SYSTEM / 32-bit hosts).
            $candidates += @(Resolve-Path -Path "$env:SystemDrive\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe" `
                -ErrorAction SilentlyContinue |
                Sort-Object { [version](($_.ProviderPath -split '_')[1]) } -Descending |
                ForEach-Object { $_.ProviderPath })
        }

        $executable = $null
        foreach ($candidate in @($candidates | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }

            try {
                $probe = & $runCommand $candidate @('--version')
                if ($probe.Code -eq 0) {
                    $executable = $candidate
                    break
                }
                Write-Verbose "WinGet probe failed: $candidate ($($probe.Code))."
            }
            catch {
                Write-Verbose $_.Exception.Message
            }
        }

        if (-not $executable) {
            throw 'WinGet is unavailable. Repair App Installer or supply -WingetPath.'
        }
        Write-Verbose "Using $executable"

        $commonArguments = @(
            '--source', $Source,
            '--accept-source-agreements',
            '--disable-interactivity'
        )
        if ($VerbosePreference -notin @('SilentlyContinue', 'Ignore')) {
            $commonArguments += '--verbose-logs'
        }

        if (-not $CheckOnly) { & $waitIdle -ShowLive:$Live -Preview:$WhatIfPreference }

        foreach ($id in $BlockingPinIds) {
            if (-not $PSCmdlet.ShouldProcess($id, 'Ensure a persistent blocking WinGet pin') -or $CheckOnly) {
                continue
            }

            $arguments = @(
                'pin', 'add', '--id', $id, '--exact', '--blocking', '--force'
            ) + $commonArguments

            $result = & $runCommand $executable $arguments
            Write-Verbose ($result.Text + $result.ErrorText)

            if ($result.Code -ne 0) {
                throw "Cannot pin $id; exit $($result.Code). $($result.ErrorText) $($result.Text)"
            }
        }

        $listArguments = @('list', '--upgrade-available') + $commonArguments
        if ($IncludeUnknown) { $listArguments += '--include-unknown' }
        if ($IncludePinned) { $listArguments += '--include-pinned' }

        $result = & $runCommand $executable $listArguments
        Write-Verbose ($result.Text + $result.ErrorText)

        if ($result.Code -in @(-1978335212, -1978335189)) { return 0 }
        if ($result.Code -ne 0) {
            throw "Discovery failed; exit $($result.Code). $($result.ErrorText) $($result.Text)"
        }

        # Fully parse and validate discovery before starting any upgrades.
        $packages = @(& $parsePackages $result.Text)
        $targets = @(
            foreach ($package in $packages) {
                $reason = $null

                if ($package.Id -in $BlockingPinIds -or $package.Id -in $ExcludedPackageIds) {
                    $reason = 'configured ID'
                }
                elseif ($package.Id -match $officeIdPattern -or
                    $package.Name -match $officeNamePattern) {
                    $reason = 'Microsoft Office / Microsoft 365'
                }
                else {
                    foreach ($pattern in $patterns) {
                        if ($pattern.IsMatch($package.Id) -or $pattern.IsMatch($package.Name)) {
                            $reason = 'additional exclusion'
                            break
                        }
                    }
                }

                if ($reason) { Write-Verbose "Excluded $($package.Id): $reason" }
                else { $package }
            }
        )

        Write-Verbose "Discovered $($packages.Count); eligible $($targets.Count)."
        if ($CheckOnly) {
            foreach ($package in $targets) {
                Write-Host "[Check] Would upgrade $($package.Name) [$($package.Id)]"
            }
            Write-Host ('WINGET_CHECK status={0} eligible={1} excluded={2} (Verbose shows why)' -f
                $(if ($targets.Count) { 'UPGRADES_AVAILABLE' } else { 'CLEAR' }),
                $targets.Count, ($packages.Count - $targets.Count))
            if ($targets.Count) { return 2 }
            return 0
        }
        if ($targets.Count -eq 0) { return 0 }

        $uninstallEntries = @()
        if ($SkipPackagesInUse) {
            $registryPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )

            $uninstallEntries = @(Get-ItemProperty -Path $registryPaths `
                -ErrorAction SilentlyContinue | Where-Object {
                    $_.PSObject.Properties['DisplayName'] -and
                    $_.PSObject.Properties['InstallLocation'] -and
                    $_.DisplayName -and $_.InstallLocation
                })
        }

        $runRoot = Join-Path ([IO.Path]::GetTempPath()) (
            'WinGet-Upgrade-' + [guid]::NewGuid().ToString('N')
        )

        $attempted = 0
        $upgraded = 0
        $unchanged = 0
        $reboots = 0
        $skipped = 0
        $failed = 0
        $failureCode = 1

        foreach ($package in $targets) {
            if ($SkipPackagesInUse -and (& $isInUse $package.Name)) {
                $skipped++
                Write-Verbose "In use; skipping $($package.Id)."
                continue
            }

            if (-not $PSCmdlet.ShouldProcess(
                "$($package.Name) [$($package.Id)]",
                "Upgrade using source '$Source'"
            )) {
                $skipped++
                continue
            }

            & $waitIdle -ShowLive:$Live

            # An application may have started while the queue was waiting.
            if ($SkipPackagesInUse -and (& $isInUse $package.Name)) {
                $skipped++
                Write-Verbose "In use after waiting; skipping $($package.Id)."
                continue
            }

            $arguments = @(
                'upgrade', '--id', $package.Id,
                '--exact', '--silent', '--accept-package-agreements'
            ) + $commonArguments

            if ($IncludeUnknown) { $arguments += '--include-unknown' }
            if ($IncludePinned) { $arguments += '--include-pinned' }
            if ($Force) { $arguments += '--force' }

            $attempted++
            $directory = Join-Path $runRoot (
                '{0:D3}-{1}' -f $attempted, ($package.Id -replace '[^A-Za-z0-9._-]', '_')
            )

            Write-Verbose "Upgrading $($package.Id); logs: $directory"

            # Runner errors stop the queue because completion is uncertain.
            # A normal nonzero WinGet exit is classified below and the queue continues.
            $code = & $runUpgrade -Executable $executable -Arguments $arguments `
                -PackageId $package.Id -LogDirectory $directory -ShowLive:$Live

            $hex = '0x{0:X8}' -f ([int64]$code -band 4294967295L)
            Write-Verbose "$($package.Id): $code ($hex)"

            switch ($code) {
                0           { $upgraded++ }
                -1978335189 { $unchanged++ } # No applicable update remains.
                -1978334967 { $reboots++ }   # Restart required to finish.
                -1978334965 { $reboots++ }   # Restart initiated.
                3010        { $reboots++ }
                1641        { $reboots++ }
                default {
                    $failed++
                    Write-Warning "Upgrade failed for $($package.Id): $code ($hex). Logs: $directory"
                }
            }
        }

        $summary = "Finished: attempted=$attempted, upgraded=$upgraded, unchanged=$unchanged, rebootRequired=$reboots, skipped=$skipped, failed=$failed."
        if ($Live) { Write-Host $summary }
        else { Write-Verbose $summary }

        if ($failed) { return 1 }
        if ($reboots) {
            Write-Warning 'A restart is required.'
            return 3010
        }

        return 0
    }
    catch {
        Write-Error -Message $_.Exception.Message -ErrorAction Continue
        return $failureCode
    }
}

#endregion

#region -------------------- Invoke-Winget (dispatcher, returns the exit code) --------------------

function Invoke-Winget {
    param(
        [ValidateSet('Check', 'Upgrade')]
        [string]$Mode = 'Check',
        # Parameters of Invoke-WingetUpgradeExceptOffice, e.g. @{ WhatIf = $true; Live = $true }
        [hashtable]$Options = @{}
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    try {
        $o = @{} + $Options
        if ($Mode -eq 'Check') {
            $o['CheckOnly'] = $true
            $o['WhatIf'] = $true
            if (-not $isAdmin) { Write-Host 'NOT ELEVATED: listing the current user''s view only; run elevated or as SYSTEM for the machine view.' -ForegroundColor Yellow }
        }
        elseif (-not $isAdmin) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session (also for WhatIf). Nothing changed." -ForegroundColor Red
            return 10
        }

        $rc = @(Invoke-WingetUpgradeExceptOffice @o)
        return [int]$rc[-1]   # the function's last output is its exit code
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

$exitCode = Invoke-Winget                                                           # Check (read-only)
# $exitCode = Invoke-Winget -Options @{ ExcludedPackageIds = @('<Vendor.Package>') } # Check, with your exclusions
# $exitCode = Invoke-Winget -Mode Upgrade -Options @{ WhatIf = $true; Live = $true } # Preview, changes nothing
# $exitCode = Invoke-Winget -Mode Upgrade -Options @{ Live = $true }                 # LIVE: upgrade all except Office
# $exitCode = Invoke-Winget -Mode Upgrade -Options @{ Live = $true; SkipPackagesInUse = $true }   # LIVE, skip running apps
# $exitCode = Invoke-Winget -Mode Upgrade -Options @{ Live = $true; BlockingPinIds = @('<Vendor.Package>') }  # LIVE + persistent pin

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
