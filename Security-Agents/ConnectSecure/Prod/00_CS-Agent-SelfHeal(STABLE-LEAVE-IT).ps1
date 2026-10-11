<#
.SYNOPSIS
  ConnectSecure (CyberCNS) Agent - Self-Healing tool v2 (single self-contained file).

.DESCRIPTION
  Detects the health and version of the locally installed ConnectSecure agent and
  takes the minimum corrective action to bring it back to online + current.

  All executable work lives inside functions; the ONLY top-level code is the guarded
  auto-run block at the very bottom. Pasting this file into a console (including an
  RMM remote PowerShell session) defines everything, runs NOTHING, and prints a
  one-line hint. Running the file via -File (e.g. a Datto RMM component) auto-runs
  the heal and exits with the result code. The function itself always RETURNS its
  exit code - it never calls 'exit' - so invoking it from a pasted session can never
  kill the RMM remote shell.

  HEALTH MODEL (two axes + monitor state):
    Health  : NotInstalled | Dead | Unhealthy | Healthy
      GROUND TRUTH for Healthy is a RECENT SUCCESSFUL portal check-in (a 200
      status-update / getwork logged within CheckinStaleMinutes) - the same signal
      behind the portal's online flag / "Last Ping". If present, the agent is
      Healthy and transient comms errors it already recovered from do NOT override
      it. Log *freshness* is NOT a signal: the agent writes local heartbeat ticks
      (observed ~2 min apart on 4.3.89) even while offline in the portal.
      Verdict precedence (first match wins; evaluated by Resolve-CSHealthVerdict):
        R1 recent successful check-in                      -> Healthy
        R2 (inside evidence) future-dated check-in beyond clock tolerance is
           DISCARDED, so it can never satisfy R1
        R3 -x self-test explicit failure text              -> Unhealthy
        R4 -x self-test explicit success text              -> Healthy
           (a stale-checkin verdict with a PASSING -x is treated as a parser gap
            in the version-sensitive success-phrase list, not an outage - a
            healthy agent is never reinstalled over it)
        R5 check-in stale AND enough log history visible   -> Unhealthy
        R6 repeated comms-error minutes that POSTDATE the last success -> Unhealthy
        R7 fully inconclusive: Healthy if the log was readable, else Unhealthy
      Timestamps are clock-calibrated: the agent is running whenever the log is
      scanned, so the newest parsed line must be near "now"; any large discrepancy
      is snapped to 15-minute increments (UTC-logging builds, skewed clocks, DST)
      and applied to all evidence. ClockOffsetMinutes is surfaced in the result.
    Version : Current | Outdated | Unknown
      Installed version ladder: HKLM uninstall DisplayVersion (64-bit registry view;
      the live agent registers ONLY there despite the x86 path, and Go binaries have
      empty FileVersion) -> 'cybercnsagent.exe --version' (timeboxed 15s) ->
      dependency.json. Server version parsed from the agent-link download URL.
    Monitor : the watchdog service (CyberCNSAgentMonitor / ConnectSecureAgentMonitor,
      DisplayName CyberCNSMonitoringAgent - all three matched). Down while the main
      agent is Healthy -> light RepairMonitor action, never a Reinstall.

  DECISION MATRIX:
      Health         Version    Action
      -----------    --------   -----------------------------------------------
      NotInstalled   any        Install (latest)
      Dead           any        Start-Service recovery + settle; if it recovers,
                                re-evaluate; otherwise Reinstall
      Unhealthy      any        Reinstall (latest) - includes Unhealthy+Outdated
      Healthy(+mon.down) any    RepairMonitor (then Update if also Outdated)
      Healthy        Outdated   Update (in-place binary swap)
      Healthy        Current    None
      Healthy        Unknown    None (cannot confirm outdated) - logged

  NEVER-WORSE-OFF ORDERING: no destructive step runs until everything needed to
  restore the agent is staged and validated locally. Reinstall downloads and
  validates the installer BEFORE uninstalling; a failed install after uninstall is
  retried once from the staged file, and if it still fails the next run's
  NotInstalled->Install path is a defined recovery. A failed in-place Update rolls
  back to the .bak binary and re-enables/starts the services before reporting.

  GUARD RAILS:
    - Global mutex: overlapping runs exit 5 (Blocked-ConcurrentRun) without probing.
    - Reinstall flap-breaker: run history is kept in C:\Program Files (x86)\CyberCNSAgent\CS-SelfHeal\
      state.json (survives reinstall; the agent dir is deleted by uninstall). More
      than MaxReinstallsPer24h (2) / MaxReinstallsPer7d (3) reinstalls without an
      intervening confirmed-Healthy run -> exit 6 (Deferred-ReinstallCooldown) with
      evidence: fix the environment, not the agent.
    - Agent-mid-upgrade detection (fresh updates_consecure writes / fresh .bak /
      second agent process / fresh dependency check) -> exit 6 (Deferred).
    - Reboot-pending blocks only when PendingFileRenameOperations touches the agent
      dir -> exit 6 (Deferred). The _MSIExecute mutex is probed as a courtesy and
      only WARNS (the agent is a standalone EXE; no MSI in its lifecycle).
    - Watchdog ordering: the monitor is stopped FIRST and started LAST everywhere,
      so it cannot resurrect the main service mid-uninstall/update.
    - Every child process (-x, --version, installer, uninstaller) runs with a
      kill-on-timeout, so no single wedged binary can hang the run.

  VERIFICATION (after a real action): polls up to VerifyTimeoutSeconds for a portal
  check-in STRICTLY NEWER than the action start (pre-action evidence can never fake
  success). Polls are cheap (service/process/log tail); -x runs at most once, near
  the end, only if no check-in appeared. A service found Present-but-Stopped during
  verification gets up to 2 Start-Service retries before the run may report
  verification failure (fixes the field-confirmed exit-4-with-no-recovery case).
  Running-but-not-yet-confirmed = SuccessPending (exit 0), not a failure.

  HARDCODED tenant values: see Get-CSHealTenantConfig near the top of the file.
  Any value still starting with 'changeme' is treated as "not provided" and blocks
  the action that needs it.

.PARAMETER CommsTimeoutSeconds        Max seconds for the agent '-x' comms self-test
                                      (one 60s retry on timeout; timeout is
                                      INCONCLUSIVE, never a failure verdict).
.PARAMETER CommsErrorLookbackMinutes  Window scanned for portal-comms failures. Default 240.
.PARAMETER CommsErrorThreshold        Distinct one-minute failure buckets, newer than the
                                      last success, that mark the agent Unhealthy. Default 3.
.PARAMETER CheckinStaleMinutes        Max age of the most recent successful check-in before
                                      a live agent is treated as stale/offline. Default 60.
.PARAMETER VerifyTimeoutSeconds       Post-action poll window for the agent to settle to
                                      Healthy. Default 300 (first check-in takes 1-3 min;
                                      getwork cadence is ~5 min).
.PARAMETER LogFreshnessMinutes        Informational only (surfaced as LogAgeMinutes).
.PARAMETER MaxReinstallsPer24h        Flap-breaker: reinstalls allowed in 24h without an
                                      intervening confirmed-Healthy run. Default 2.
.PARAMETER MaxReinstallsPer7d        Flap-breaker: same over 7 days. Default 3.
.PARAMETER Silent                     Suppress console output (the machine-parseable
                                      CSSH-RESULT line is always emitted).
.PARAMETER WhatIf                     Dry run: report the decision and the steps that
                                      WOULD run; change nothing.
.PARAMETER Debug                      Persist diagnostics to disk (.log + timestamped
                                      result JSON + raw -x output) under
                                      C:\Program Files (x86)\CyberCNSAgent\CS-Toolbox-TEMP\Collected-Info\SelfHeal.
                                      state.json + SelfHeal-Last.json (ProgramData) are
                                      always maintained regardless of -Debug.

.EXAMPLE
  # RMM remote terminal / console: paste the whole file (defines only, prints a hint),
  # then run a dry-run. The call RETURNS the exit code; your session survives.
  $rc = Invoke-CSAgentSelfHeal -WhatIf

.EXAMPLE
  # Datto RMM component / scheduled deployment: run the file directly (auto-runs, exits).
  powershell -NoProfile -ExecutionPolicy Bypass -File .\CS-Agent-SelfHeal.ps1

.NOTES
  Exit codes:
    0  OK: NoActionNeeded / RecoveredByServiceStart / Repaired-Monitor /
       NoAction-VersionUnknown / Success:<Action> / SuccessPending:<Action> /
       WhatIf-WouldRun / WhatIf-WouldDefer
    2  Preconditions failed (AbortedPreconditions, WhatIf-WouldAbort)
    3  Action error (ActionFailed) or unhandled error
    4  Verification failed (agent not confirmed after the action + start retries)
    5  Blocked (concurrent run holds the mutex)
    6  Deferred (reinstall cooldown / agent mid-upgrade / reboot pending)
  Env overrides for the auto-run guard: CS_SELFHEAL_AUTORUN=1 forces auto-run for
  exotic delivery; CS_SELFHEAL_NOAUTORUN=1 suppresses it (used by tests).
  Windows PowerShell 5.1 safe (no PS7-only syntax).
#>

#requires -version 5.1

# =====================================================================
#  >>> EDIT THESE <<<  Hardcoded ConnectSecure values for this tenant.
#  A function (not loose assignments) so pasting the file executes nothing.
#    CompanyID / TenantID / Secret : required for Install / Reinstall.
#    UninstallSecret               : required for Reinstall (uninstall step;
#                                    mandatory as of 2026-04-01).
#  Any value still starting with 'changeme' is treated as "not provided".
# =====================================================================
function Get-CSHealTenantConfig {
    [pscustomobject]@{
        CompanyID       = 'CompanyID-redacted'
        TenantID        = 'TenantID-redacted'
        Secret          = 'Secret-redacted'
        UninstallSecret = 'UninstallSecret-redacted'
    
    }
}

# =====================================================================
#region Pure decision core (no probes, no side effects - unit-testable)
# =====================================================================

function Test-CSProvidedValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value.Trim().ToLowerInvariant() -like 'changeme*') { return $false }
    return $true
}

function ConvertTo-CSVersion3 {
    # Normalizes any version-ish string to its FIRST clean 'a.b.c'; $null if none.
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }
    $m = [regex]::Match($Version.Trim(), '(\d+)\.(\d+)\.(\d+)')
    if ($m.Success) { return ('{0}.{1}.{2}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value) }
    return $null
}

function Get-CSLogEvidence {
    <#
      PURE log-evidence extractor: takes raw log lines + "now" + thresholds, returns
      every signal the health verdict needs. No file I/O, no Get-Date - callers pass
      both, so tests can feed synthetic logs and synthetic clocks.

      CLOCK CALIBRATION: log timestamps carry no zone marker ('yyyy/MM/dd HH:mm:ss').
      This is only ever called while the agent process is RUNNING and appending, so
      the newest parsed line must be near $Now. If it is off by more than
      ClockToleranceMinutes, the discrepancy is snapped to the nearest 15-minute
      increment (covers UTC+/-N incl. :30/:45 zones, and DST) and applied to every
      timestamp. This makes UTC-logging agent builds and skewed clocks self-correct.

      SIGNATURE RULES:
        - A line matching an error signature NEVER counts as a check-in, even if it
          also contains an ok phrase (an error mentioning the agent/status/update
          endpoint must not spoof the ground-truth signal).
        - The bare endpoint mention 'agent/status/update' only counts as a check-in
          when the same line also carries a success token (200 / success).
        - Error lines WITHOUT a parseable timestamp (stack-trace continuations)
          collapse into at most ONE synthetic bucket, so a single multi-line trace
          cannot cross the error threshold by itself.
        - A future-dated check-in beyond the clock tolerance is DISCARDED (R2):
          it can never satisfy the "recent check-in" rule.
    #>
    param(
        [AllowEmptyCollection()][AllowNull()][string[]]$Lines,
        [Parameter(Mandatory)][datetime]$Now,
        [int]$CheckinStaleMinutes = 60,
        [int]$CommsErrorLookbackMinutes = 240,
        [int]$ClockToleranceMinutes = 16,
        [int]$ClockSnapMinutes = 15,
        [double]$LogWriteAgeMinutes = 0   # log file mtime age; gates calibration (see below)
    )

    $ev = [pscustomobject]@{
        ParsedAnyTimestamp = $false
        NewestParsed       = $null      # raw (uncalibrated) newest timestamp seen
        OldestParsed       = $null
        ClockOffsetMinutes = 0
        LastOkAdj          = $null      # calibrated time of most recent successful check-in
        LastErrAdj         = $null      # calibrated time of most recent comms error
        ErrBucketCount     = 0          # distinct error minutes within the lookback window
        LastCheckinAgeMin  = $null      # minutes since LastOkAdj (post-calibration)
        CheckinStale       = $false
        HistorySufficient  = $false     # visible history reaches past the stale cutoff
        DiscardedFutureOk  = $false
    }
    if ($null -eq $Lines -or $Lines.Count -eq 0) { return $ev }

    # Error signatures are regex FRAGMENTS (most literal, some patterned).
    $errFragments = @(
        'no such host', 'dial tcp', 'connection refused', 'no route to host',
        'timeout awaiting response', 'i/o timeout', 'context deadline exceeded',
        'failed with status code 5\d\d', 'error publishing message', 'publishing data to c',
        'x509', 'certificate signed by unknown authority', 'proxyconnect', 'tls handshake error'
    )
    # Successful-check-in signatures: the lines the agent writes when a status/ping/
    # getwork call returns 200. Version-sensitive by design; a miss here is NEVER
    # proof of ill health (the -x self-test is the tiebreaker).
    $okFragments = @(
        'last scan time updated successfully', 'got work api status\s*:\s*200',
        'status queued for processing', 'agent status verified successfully',
        'no-change heartbeat', 'status update successful'
    )
    $errRx = [regex]('(?i)(' + ($errFragments -join '|') + ')')
    $okRx  = [regex]('(?i)(' + ($okFragments  -join '|') + ')')
    $tsRx  = [regex]'^(\d{4}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2})'

    # Pass 1: parse timestamps, classify lines, remember matched events with their
    # RAW timestamps (calibration is applied afterwards, once the offset is known).
    $events = New-Object System.Collections.Generic.List[object]   # @{ T=[datetime]|$null; Kind='ok'|'err' }
    $unparsedErrSeen = $false
    $topTimes = New-Object System.Collections.Generic.List[datetime]   # newest ~12 parsed timestamps (calibration anchor pool)
    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $dt = $null
        $m = $tsRx.Match($line)
        if ($m.Success) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParseExact(($m.Groups[1].Value + ' ' + $m.Groups[2].Value),
                    'yyyy/MM/dd HH:mm:ss',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
                $dt = $parsed
                $ev.ParsedAnyTimestamp = $true
                if ($null -eq $ev.NewestParsed -or $dt -gt $ev.NewestParsed) { $ev.NewestParsed = $dt }
                if ($null -eq $ev.OldestParsed -or $dt -lt $ev.OldestParsed) { $ev.OldestParsed = $dt }
                # Maintain the pool of the ~12 newest timestamps for the anchor pick.
                if ($topTimes.Count -lt 12) {
                    $topTimes.Add($dt)
                    if ($topTimes.Count -eq 12) { $topTimes.Sort() }
                } elseif ($dt -gt $topTimes[0]) {
                    $topTimes[0] = $dt
                    $topTimes.Sort()
                }
            }
        }

        $isErr = $errRx.IsMatch($line)
        if ($isErr) {
            if ($null -ne $dt) { $events.Add(@{ T = $dt; Kind = 'err' }) }
            else               { $unparsedErrSeen = $true }
            continue   # an error line never counts as a check-in
        }

        $isOk = $okRx.IsMatch($line)
        if (-not $isOk -and $line -match '(?i)agent/status/update') {
            # Endpoint mention alone is ambiguous - require a success token too.
            if ($line -match '(?i)(\b200\b|success)') { $isOk = $true }
        }
        if ($isOk -and $null -ne $dt) { $events.Add(@{ T = $dt; Kind = 'ok' }) }
    }

    # Clock calibration. The premise is "the agent is running AND APPENDING, so
    # the newest genuine lines are near now" (heartbeat cadence ~2 min). That
    # premise fails for a running-but-WEDGED agent that stopped writing: its old
    # timestamps must NOT be shifted forward (that would convert hours-stale
    # evidence into a fresh check-in and mask the very fault this tool exists to
    # catch). The log file's mtime independently proves "appending": calibration
    # only applies when the file was written within the last 10 minutes. (mtime
    # still never decides HEALTH - it only gates this correction.)
    # Genuine lines also arrive in CLUSTERS - the anchor is the newest timestamp
    # CORROBORATED by another line within 5 minutes, so a single corrupt/forged
    # future-dated line cannot hijack the calibration. If nothing is corroborated
    # (sparse log), no calibration is applied (offset 0 = assume local, the v1
    # behaviour, with the -x tiebreak as the safety net).
    if ($ev.ParsedAnyTimestamp -and $topTimes.Count -ge 2 -and ([math]::Abs($LogWriteAgeMinutes) -le 10)) {
        $sorted = @($topTimes | Sort-Object -Descending)
        $anchor = $null
        for ($ai = 0; $ai -lt $sorted.Count; $ai++) {
            for ($bi = 0; $bi -lt $sorted.Count; $bi++) {
                if ($ai -eq $bi) { continue }
                if ([math]::Abs(($sorted[$ai] - $sorted[$bi]).TotalMinutes) -le 5) { $anchor = $sorted[$ai]; break }
            }
            if ($null -ne $anchor) { break }
        }
        if ($null -ne $anchor) {
            $rawSkewMin = ($Now - $anchor).TotalMinutes
            if ([math]::Abs($rawSkewMin) -gt 10) {
                $ev.ClockOffsetMinutes = [int]([math]::Round($rawSkewMin / $ClockSnapMinutes) * $ClockSnapMinutes)
            }
        }
    }
    $offset = $ev.ClockOffsetMinutes

    $errCutoff   = $Now.AddMinutes(-1 * [math]::Abs($CommsErrorLookbackMinutes))
    $staleCutoff = $Now.AddMinutes(-1 * [math]::Abs($CheckinStaleMinutes))

    $errBuckets = New-Object System.Collections.Generic.HashSet[string]
    foreach ($e in $events) {
        $adj = ([datetime]$e.T).AddMinutes($offset)
        if ($e.Kind -eq 'err') {
            if ($adj -ge $errCutoff) { [void]$errBuckets.Add($adj.ToString('yyyy/MM/dd HH:mm')) }
            if ($null -eq $ev.LastErrAdj -or $adj -gt $ev.LastErrAdj) { $ev.LastErrAdj = $adj }
        } else {
            if ($null -eq $ev.LastOkAdj -or $adj -gt $ev.LastOkAdj) { $ev.LastOkAdj = $adj }
        }
    }
    # All unparsed (continuation) error lines collapse into a single synthetic bucket.
    if ($unparsedErrSeen) { [void]$errBuckets.Add('unparsed') }
    $ev.ErrBucketCount = $errBuckets.Count

    if ($null -ne $ev.LastOkAdj) {
        $age = [math]::Round(($Now - $ev.LastOkAdj).TotalMinutes, 1)
        if ($age -lt (-1 * [math]::Abs($ClockToleranceMinutes))) {
            # R2: still future-dated after calibration (clock jumped backwards) -
            # discard; it must not satisfy the recent-check-in rule.
            $ev.LastOkAdj = $null
            $ev.DiscardedFutureOk = $true
        } else {
            $ev.LastCheckinAgeMin = $age
        }
    }

    # Staleness is only judged once visible (calibrated) history reaches past the
    # stale cutoff - a just-(re)started agent is never flagged for not having
    # checked in yet, and a truncated/rotated log falls to the -x tiebreak instead.
    if ($null -ne $ev.OldestParsed) {
        $ev.HistorySufficient = ($ev.OldestParsed.AddMinutes($offset) -le $staleCutoff)
    }
    if ($ev.HistorySufficient) {
        if ($null -eq $ev.LastOkAdj)                { $ev.CheckinStale = $true }
        elseif ($ev.LastOkAdj -lt $staleCutoff)     { $ev.CheckinStale = $true }
    }

    return $ev
}

function Resolve-CSHealthVerdict {
    <#
      PURE health verdict: evidence in, verdict out (no probing, no clock reads).
      Returns @{ Health; Rule; Reason }. Precedence R1..R7 (R2 lives inside
      Get-CSLogEvidence as the future-dated discard).
    #>
    param(
        [Parameter(Mandatory)][bool]$Installed,
        [Parameter(Mandatory)][bool]$Running,
        [Parameter(Mandatory)][bool]$LogRead,
        [AllowNull()]$Evidence,          # Get-CSLogEvidence output, or $null when log unread
        [AllowNull()]$CommsOk,           # $true/$false/$null from -x ($null = inconclusive/skipped)
        [int]$CheckinStaleMinutes = 60,
        [int]$CommsErrorThreshold = 3
    )

    if (-not $Installed) { return @{ Health = 'NotInstalled'; Rule = 'R0'; Reason = 'No agent service and no agent executable.' } }
    if (-not $Running)   { return @{ Health = 'Dead';         Rule = 'R0'; Reason = 'Installed but the agent is not running.' } }

    $age = $null
    if ($LogRead -and $null -ne $Evidence) { $age = $Evidence.LastCheckinAgeMin }

    # R1 - ground truth: a recent successful check-in (== the portal online signal).
    # Transient comms errors the agent already recovered from do NOT override it.
    if ($null -ne $age -and $age -le $CheckinStaleMinutes) {
        return @{ Health = 'Healthy'; Rule = 'R1'; Reason = ('Successful portal check-in {0} min ago (window {1} min).' -f $age, $CheckinStaleMinutes) }
    }
    # R3 - the agent's own -x self-test explicitly failed (e.g. broken/lost config).
    if ($CommsOk -eq $false) {
        return @{ Health = 'Unhealthy'; Rule = 'R3'; Reason = 'The -x comms self-test reported an explicit failure.' }
    }
    # R4 - -x explicitly passed: trusted over the stale heuristic (a stale verdict
    # with a passing -x most likely means this agent version's success-log wording
    # is not in the signature list - a parser gap, not an outage).
    if ($CommsOk -eq $true) {
        return @{ Health = 'Healthy'; Rule = 'R4'; Reason = 'The -x comms self-test passed (overrides stale-check-in heuristic).' }
    }
    # R5 - alive for longer than the window with no successful check-in -> the
    # portal Last Ping is stale. Only asserted when enough history is visible.
    if ($LogRead -and $null -ne $Evidence -and $Evidence.CheckinStale) {
        return @{ Health = 'Unhealthy'; Rule = 'R5'; Reason = ('No successful check-in within {0} min despite sufficient log history; -x inconclusive.' -f $CheckinStaleMinutes) }
    }
    # R6 - repeated recent comms failures, and they POSTDATE the last success (an
    # old burst of errors followed by any success signature cannot condemn).
    if ($LogRead -and $null -ne $Evidence -and $Evidence.ErrBucketCount -ge $CommsErrorThreshold) {
        $postdates = ($null -eq $Evidence.LastOkAdj) -or
                     ($null -ne $Evidence.LastErrAdj -and $Evidence.LastErrAdj -gt $Evidence.LastOkAdj)
        if ($postdates) {
            return @{ Health = 'Unhealthy'; Rule = 'R6'; Reason = ('{0} distinct comms-failure minutes newer than the last confirmed success.' -f $Evidence.ErrBucketCount) }
        }
    }
    # R7 - fully inconclusive: trust a readable log with no failure evidence.
    if ($LogRead) {
        return @{ Health = 'Healthy'; Rule = 'R7'; Reason = 'Inconclusive but the log is readable with no condemning evidence.' }
    }
    return @{ Health = 'Unhealthy'; Rule = 'R7'; Reason = 'Agent log missing/unreadable and -x inconclusive - nothing confirms health.' }
}

function Resolve-CSHealAction {
    # PURE decision matrix: returns an ORDERED list of actions (RepairMonitor is a
    # light pre-step that never replaces the version action). Empty list = no action.
    param(
        [Parameter(Mandatory)][string]$Health,
        [Parameter(Mandatory)][string]$VersionState,
        [bool]$MonitorDown = $false
    )
    switch ($Health) {
        'NotInstalled' { return @('Install') }
        'Dead'         { return @('Reinstall') }
        'Unhealthy'    { return @('Reinstall') }   # policy: any Unhealthy -> Reinstall (incl. Outdated)
        'Healthy'      {
            $actions = @()
            if ($MonitorDown) { $actions += 'RepairMonitor' }
            if ($VersionState -eq 'Outdated') { $actions += 'Update' }
            return $actions
        }
        default        { return @() }
    }
}

function Get-CSExitCodeForOutcome {
    # PURE outcome -> exit-code map (the stable RMM contract).
    param([Parameter(Mandatory)][string]$Outcome)
    switch -Wildcard ($Outcome) {
        'NoActionNeeded'            { return 0 }
        'RecoveredByServiceStart'   { return 0 }
        'Repaired-Monitor'          { return 0 }
        'NoAction-VersionUnknown'   { return 0 }
        'Success:*'                 { return 0 }
        'SuccessPending:*'          { return 0 }
        'WhatIf-WouldRun'           { return 0 }
        'WhatIf-WouldDefer'         { return 0 }
        'WhatIf-WouldAbort'         { return 2 }
        'AbortedPreconditions'      { return 2 }
        'ActionFailed*'             { return 3 }   # incl. ActionFailed-Staging
        'Error'                     { return 3 }
        'ActionVerificationFailed'  { return 4 }
        'Blocked-ConcurrentRun'     { return 5 }
        'Deferred-*'                { return 6 }
        default                     { return 3 }
    }
}

#endregion

function Invoke-CSAgentSelfHeal {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [int]$LogFreshnessMinutes = 60,          # informational only (LogAgeMinutes); never drives health
        [int]$CommsTimeoutSeconds = 120,
        [int]$CommsErrorLookbackMinutes = 240,
        [int]$CommsErrorThreshold = 3,
        [int]$CheckinStaleMinutes = 60,
        [int]$VerifyTimeoutSeconds = 300,
        [int]$MaxReinstallsPer24h = 2,
        [int]$MaxReinstallsPer7d = 3,
        [switch]$Silent
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    # Invoke-WebRequest's progress bar makes PS 5.1 downloads dramatically slower.
    $ProgressPreference = 'SilentlyContinue'

    # -Debug gates VERBOSE disk output (run log, timestamped result JSON, raw -x
    # capture). The tiny state.json + SelfHeal-Last.json in ProgramData are always
    # maintained: they power the reinstall flap-breaker and post-mortems. Detect
    # -Debug explicitly, then neutralize $DebugPreference so a nested Write-Debug
    # can never prompt in a non-interactive (SYSTEM / RMM) session.
    $script:CSHDebugMode = $PSBoundParameters.ContainsKey('Debug')
    $DebugPreference = 'SilentlyContinue'

    #region Context / environment
    function Initialize-CSHealContext {
        $cfg = Get-CSHealTenantConfig

        # Set once anything DESTRUCTIVE (uninstall / service stop for swap) has
        # begun: distinguishes 'ActionFailed' from 'ActionFailed-Staging' (agent
        # untouched), which the flap-breaker must not count as a real reinstall.
        $script:CSHDestructiveStarted = $false
        $script:CSHUpdateBakOk        = $false

        $script:CSH = @{
            ToolVersion       = '2.0.0'
            RunId             = [guid]::NewGuid().ToString('N').Substring(0, 12)
            RunStamp          = (Get-Date).ToString('yyyyMMdd_HHmmss')
            Cfg               = $cfg

            AgentDir          = 'C:\Program Files (x86)\CyberCNSAgent'
            AgentExePath      = 'C:\Program Files (x86)\CyberCNSAgent\cybercnsagent.exe'
            AgentLogDir       = 'C:\Program Files (x86)\CyberCNSAgent\logs'
            AgentLogPath      = 'C:\Program Files (x86)\CyberCNSAgent\logs\cybercns.log'
            UninstallBatPath  = 'C:\Program Files (x86)\CyberCNSAgent\uninstall.bat'
            AgentConfigPath   = 'C:\Program Files (x86)\CyberCNSAgent\agent_config.json'
            DependencyJson    = 'C:\Program Files (x86)\CyberCNSAgent\dependency.json'
            UpdatesDir        = 'C:\Program Files (x86)\CyberCNSAgent\updates_consecure'

            AgentServiceName  = 'CyberCNSAgent'
            # The monitor/watchdog is registered under different names across agent
            # generations; its DisplayName differs from both. Match all three.
            MonitorNames      = @('CyberCNSAgentMonitor', 'ConnectSecureAgentMonitor')
            MonitorDisplay    = 'CyberCNSMonitoringAgent'
            ProcessNames      = @('cybercnsagent', 'cybercnsagentmonitor')

            PlatformHost      = 'configuration.myconnectsecure.com'
            AgentApiUrl       = 'https://configuration.myconnectsecure.com/api/v4/configuration/agentlink?ostype=windows'

            StateDir          = 'C:\Program Files (x86)\CyberCNSAgent\CS-SelfHeal'
            StatePath         = 'C:\Program Files (x86)\CyberCNSAgent\CS-SelfHeal\state.json'
            LastResultPath    = 'C:\Program Files (x86)\CyberCNSAgent\CS-SelfHeal\SelfHeal-Last.json'
            StageDir          = 'C:\Program Files (x86)\CyberCNSAgent\CS-SelfHeal\stage'

            DebugRoot         = 'C:\Program Files (x86)\CyberCNSAgent\CS-Toolbox-TEMP\Collected-Info\SelfHeal'
            TempDir           = $null   # set below
            WorkDir           = $null   # -x / child-process capture files
            LogPath           = $null   # -Debug run log
            ResultPath        = $null   # -Debug timestamped result JSON

            TailBytes         = 4MB
            VerifyTailBytes   = 512KB
            VerifyPollSeconds = 15
            SettleGraceSeconds = 180    # post-Start-Service settle window before judging
            MinInstallerBytes = 1MB
            MinFreeDiskMB     = 500
            InstallerTimeoutSeconds  = 900
            UninstallTimeoutSeconds  = 300
            VersionProbeTimeoutSeconds = 15

            LatestDownload    = $null   # cached agentlink result: @{Url;Version} or $false after a failed attempt
            Mutex             = $null
            MutexAcquired     = $false
        }

        $script:CSH.TempDir    = Join-Path $env:TEMP ('CS-SelfHeal-' + $script:CSH.RunStamp)
        $script:CSH.LogPath    = Join-Path $script:CSH.DebugRoot ('SelfHeal_{0}.log'  -f $script:CSH.RunStamp)
        $script:CSH.ResultPath = Join-Path $script:CSH.DebugRoot ('SelfHeal_{0}.json' -f $script:CSH.RunStamp)

        # Result document: v1 keys preserved verbatim (RMM parsers depend on the
        # shape), v2 additions appended. Built FIRST so finally/reporting always has it.
        $script:CSHRes = [ordered]@{
            ToolVersion          = $script:CSH.ToolVersion
            Timestamp            = (Get-Date).ToString('o')
            Host                 = $env:COMPUTERNAME
            User                 = $env:USERNAME
            WhatIf               = [bool]$WhatIfPreference
            Installed            = $null
            ExePresent           = $null
            ServicePresent       = $null
            ServiceStatus        = $null
            ProcessAlive         = $null
            LogAgeMinutes        = $null
            CommsOk              = $null
            RecentCommsErrMin    = $null
            LastCheckinAgeMin    = $null
            CheckinStale         = $null
            Health               = $null
            InstalledVersion     = $null
            ServerVersion        = $null
            VersionState         = $null
            RecoveryAttempted    = $null
            RecoveredByStart     = $null
            PlannedAction        = $null
            Decision             = $null
            PreconditionsOk      = $null
            PreconditionReasons  = @()
            Outcome              = 'Unknown'
            PostHealth           = $null
            PostInstalledVersion = $null
            PostServiceStatus    = $null
            ExitCode             = $null
            # ---- v2 additions ----
            SchemaVersion        = '2.0'
            RunId                = $script:CSH.RunId
            HealthRule           = $null
            ClockOffsetMinutes   = $null
            HistorySufficient    = $null
            RotatedLogsRead      = 0
            MonitorServiceName   = $null
            MonitorState         = $null
            MonitorRepaired      = $false
            MutexAcquired        = $null
            CooldownActive       = $false
            DeferReason          = $null
            ActionStartTime      = $null
            PostCheckinAgeMin    = $null
            StartServiceRetries  = 0
            StagedInstallerValid = $null
            RebootPending        = $null
            AgentUpgradeInProgress = $null
            MsiMutexBusy         = $null
            XExitCode            = $null
            XSkipped             = $null
            VersionSource        = $null
            TenantMismatch       = $null
            StateFile            = $script:CSH.StatePath
        }

        # Working dirs. Failures are non-fatal: every file write is best-effort.
        try {
            if (-not (Test-Path -LiteralPath $script:CSH.TempDir)) {
                New-Item -ItemType Directory -Path $script:CSH.TempDir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
            }
        } catch { }
        try {
            if (-not (Test-Path -LiteralPath $script:CSH.StateDir)) {
                New-Item -ItemType Directory -Path $script:CSH.StateDir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
            }
        } catch { }

        $script:CSHCanLog = $false
        if ($script:CSHDebugMode) {
            try {
                if (-not (Test-Path -LiteralPath $script:CSH.DebugRoot)) {
                    New-Item -ItemType Directory -Path $script:CSH.DebugRoot -Force -WhatIf:$false -ErrorAction Stop | Out-Null
                }
                $script:CSHCanLog = (Test-Path -LiteralPath $script:CSH.DebugRoot)
            } catch { $script:CSHCanLog = $false }
        }
        $script:CSH.WorkDir = if ($script:CSHCanLog) { $script:CSH.DebugRoot } else { $script:CSH.TempDir }
    }

    function Set-CSRes {
        param([Parameter(Mandatory)][string]$Key, $Value)
        $script:CSHRes[$Key] = $Value
    }
    #endregion

    #region Logging / console
    function Write-CSHeal {
        param(
            [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP', 'ACT', 'WHATIF', 'STATE')]
            [string]$Level = 'INFO',
            [Parameter(Mandatory)][string]$Message
        )
        $line = '[{0}] [{1,-6}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
        if ($script:CSHCanLog) {
            try { Add-Content -LiteralPath $script:CSH.LogPath -Value $line -Encoding UTF8 -WhatIf:$false } catch { }
        }
        if ($Silent) { return }
        switch ($Level) {
            'OK'     { Write-Host $line -ForegroundColor Green }
            'WARN'   { Write-Host $line -ForegroundColor Yellow }
            'ERROR'  { Write-Host $line -ForegroundColor Red }
            'STEP'   { Write-Host $line -ForegroundColor Cyan }
            'ACT'    { Write-Host $line -ForegroundColor Magenta }
            'WHATIF' { Write-Host $line -ForegroundColor DarkCyan }
            'STATE'  { Write-Host $line -ForegroundColor White }
            default  { Write-Host $line -ForegroundColor Gray }
        }
    }

    function Write-CSHealDebugLines {
        # Captured native output is surfaced ONLY under -Debug (the vendor uninstall
        # path emits benign noise that must not be mistaken for real failures).
        param([string]$Label = 'native', $Lines)
        if (-not $script:CSHDebugMode) { return }
        foreach ($l in @($Lines)) {
            if ($null -ne $l) {
                $s = ("$l").Trim()
                if ($s.Length -gt 0) { Write-CSHeal -Level INFO -Message ('{0}: {1}' -f $Label, $s) }
            }
        }
    }

    function Show-CSHealBanner {
        if ($Silent) { return }
        $mode = if ($WhatIfPreference) { 'DRY RUN (-WhatIf): nothing will be changed' } else { 'LIVE RUN' }
        Write-Host ''
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host ' ConnectSecure Agent - Self-Healing v2' -ForegroundColor Cyan
        Write-Host (' Host: {0}    Mode: {1}' -f $env:COMPUTERNAME, $mode) -ForegroundColor Gray
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host ''
    }
    #endregion

    #region Small utilities
    function Enable-CSTls12 {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    }

    function Test-CSIsAdmin {
        try {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { return $false }
    }

    function Invoke-CSOrWhatIf {
        param(
            [Parameter(Mandatory)][string]$Description,
            [Parameter(Mandatory)][scriptblock]$Action
        )
        if ($WhatIfPreference) {
            Write-CSHeal -Level WHATIF -Message ('Would: {0}' -f $Description)
            return $null
        }
        Write-CSHeal -Level ACT -Message $Description
        return (& $Action)
    }

    function Invoke-CSProcessCapture {
        <#
          Runs a child process with redirected stdout/stderr and a HARD timeout
          (kill on expiry) - no child can hang the run. Returns
          @{ Ran; TimedOut; ExitCode; Output }. Exit codes come from the Process
          object, so $LASTEXITCODE (a strict-mode trap when unset) is never touched.
          WaitForExit(ms) can return before the OS flushes the redirect files, so
          after a full WaitForExit() the capture is read with a short retry loop.
        #>
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [string[]]$ArgumentList = @(),
            [int]$TimeoutSeconds = 120,
            [string]$WorkingDirectory = $null,
            [string]$RawArgumentString = $null,   # bypasses per-arg quoting (cmd.exe /s /c patterns)
            [string]$CaptureTag = 'proc'
        )
        $res = [pscustomobject]@{ Ran = $false; TimedOut = $false; ExitCode = $null; Output = '' }
        if (-not (Test-Path -LiteralPath $FilePath)) { return $res }

        $tag = '{0}_{1}' -f $CaptureTag, ([guid]::NewGuid().ToString('N').Substring(0, 6))
        $so = Join-Path $script:CSH.WorkDir ($tag + '_out.txt')
        $se = Join-Path $script:CSH.WorkDir ($tag + '_err.txt')

        # Start-Process joins an ArgumentList array with spaces WITHOUT quoting in
        # PS 5.1, so quote anything containing whitespace or quotes ourselves.
        $argStr = $null
        if (-not [string]::IsNullOrEmpty($RawArgumentString)) {
            $argStr = $RawArgumentString
        } elseif ($ArgumentList.Count -gt 0) {
            $argStr = (@($ArgumentList | ForEach-Object {
                if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { "$_" }
            })) -join ' '
        }

        $p = $null
        try {
            $sp = @{
                FilePath               = $FilePath
                NoNewWindow            = $true
                PassThru               = $true
                RedirectStandardOutput = $so
                RedirectStandardError  = $se
            }
            if ($argStr)           { $sp['ArgumentList']     = $argStr }
            if ($WorkingDirectory) { $sp['WorkingDirectory'] = $WorkingDirectory }
            $p = Start-Process @sp
            $res.Ran = $true

            if (-not $p.WaitForExit([math]::Max(1, $TimeoutSeconds) * 1000)) {
                $res.TimedOut = $true
                # Kill the whole process TREE - a bare Process.Kill() orphans any
                # children (the agent installer spawns dependency downloads and
                # service registrations that would keep writing to the agent dir).
                $treeKilled = $false
                try {
                    Start-Process -FilePath "$env:SystemRoot\System32\taskkill.exe" `
                        -ArgumentList ('/PID {0} /T /F' -f $p.Id) -NoNewWindow -Wait -ErrorAction Stop | Out-Null
                    $treeKilled = $true
                } catch { }
                if (-not $treeKilled) { try { $p.Kill() } catch { } }
            }
            try { $p.WaitForExit() } catch { }
            try { $res.ExitCode = $p.ExitCode } catch { }

            $text = ''
            for ($readTry = 0; $readTry -lt 10; $readTry++) {
                $text = ''
                foreach ($f in @($so, $se)) {
                    if (Test-Path -LiteralPath $f) {
                        $c = Get-Content -LiteralPath $f -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($c) { $text += "`n" + $c }
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($text) -or $res.TimedOut) { break }
                Start-Sleep -Milliseconds 300
            }
            $res.Output = $text
        } catch {
            Write-CSHeal -Level WARN -Message ('Child process "{0}" could not run: {1}' -f (Split-Path -Leaf $FilePath), $_.Exception.Message)
        }
        return $res
    }
    #endregion

    #region Probes (read-only)
    function Get-CSMonitorServices {
        # All watchdog service objects, matched by BOTH known names and the DisplayName.
        $found = @{}
        foreach ($n in $script:CSH.MonitorNames) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($s) { $found[$s.Name] = $s }
        }
        $byDisp = Get-Service -DisplayName $script:CSH.MonitorDisplay -ErrorAction SilentlyContinue
        foreach ($s in @($byDisp)) { if ($s) { $found[$s.Name] = $s } }
        return @($found.Values)
    }

    function Get-CSAgentInventory {
        $svc      = Get-Service -Name $script:CSH.AgentServiceName -ErrorAction SilentlyContinue
        # @() wrap: a function returning a 1-element array unrolls to a scalar in
        # PS 5.1, and .Count on a scalar throws under StrictMode.
        $monitors = @(Get-CSMonitorServices)
        $exe      = Test-Path -LiteralPath $script:CSH.AgentExePath

        # Liveness counts ONLY the main agent (service or cybercnsagent process).
        # The monitor/watchdog process must NOT mask a stopped agent service - a
        # Disabled agent with a live watchdog would otherwise never read Dead and
        # the cheap Start-Service recovery would be withheld forever. The monitor
        # has its own MonitorState axis.
        $procAlive = [bool](Get-Process -Name 'cybercnsagent' -ErrorAction SilentlyContinue)

        $monState = 'Missing'; $monName = $null
        if ($monitors.Count -gt 0) {
            $monName = ($monitors | ForEach-Object { $_.Name }) -join '+'
            $anyRunning = $false
            foreach ($m in $monitors) { if ($m.Status -eq 'Running') { $anyRunning = $true } }
            $monState = if ($anyRunning) { 'Up' } else { 'Down' }
        }

        $logAge = $null
        try {
            if (Test-Path -LiteralPath $script:CSH.AgentLogPath) {
                $logAge = [math]::Round(((Get-Date) - (Get-Item -LiteralPath $script:CSH.AgentLogPath).LastWriteTime).TotalMinutes, 1)
            }
        } catch { }

        return [pscustomobject]@{
            ServicePresent = [bool]$svc
            ServiceStatus  = if ($svc) { $svc.Status.ToString() } else { 'NotInstalled' }
            ServiceRunning = ($svc -and $svc.Status -eq 'Running')
            ExePresent     = [bool]$exe
            Installed      = ([bool]$svc -or [bool]$exe)
            ProcessAlive   = $procAlive
            Running        = (($svc -and $svc.Status -eq 'Running') -or $procAlive)
            MonitorState   = $monState
            MonitorName    = $monName
            LogAgeMinutes  = $logAge   # informational only - never a health signal
        }
    }

    function Read-CSLogTailLines {
        <#
          Byte-based tail of a (possibly locked) log via a shared-read FileStream
          (same pattern as cs-agent-log-search.ps1). Line-count tails starve on
          chatty logs; a fixed byte window cannot. The first (partial) line after a
          mid-file seek is discarded. Returns a string[] ($null on read failure).
        #>
        param(
            [Parameter(Mandatory)][string]$Path,
            [long]$TailBytes = 4MB
        )
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $fs = $null
        try {
            $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            $len    = $fs.Length
            $seeked = $false
            if ($len -gt $TailBytes) {
                [void]$fs.Seek($len - $TailBytes, [System.IO.SeekOrigin]::Begin)
                $seeked = $true
            }
            $buf  = New-Object byte[] ([int][math]::Min($len, $TailBytes))
            $read = $fs.Read($buf, 0, $buf.Length)
            # ,@(...): the comma keeps an empty/1-element array from unrolling on
            # return - a readable-but-EMPTY log must reach the caller as an empty
            # array, not as the $null that means "read FAILURE" (which would flip
            # R7 to Unhealthy and reinstall a healthy agent over a 0-byte log).
            if ($read -le 0) { return ,@() }
            $text  = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
            $lines = $text -split "`r`n|`n"
            if ($seeked -and $lines.Count -gt 1) { $lines = $lines[1..($lines.Count - 1)] }
            return ,@($lines)
        } catch {
            return $null
        } finally {
            if ($fs) { try { $fs.Dispose() } catch { } }
        }
    }

    function Get-CSPortalActivity {
        <#
          Reads the agent log tail and extracts the health evidence via the pure
          Get-CSLogEvidence. If visible history does not reach the stale cutoff,
          rotated siblings (none exist on current agents - pure future-proofing)
          are merged in and the evidence recomputed. Returns
          @{ LogRead; Evidence; RotatedRead }.
        #>
        param(
            [long]$TailBytes = 0,
            [datetime]$Now = (Get-Date)
        )
        if ($TailBytes -le 0) { $TailBytes = $script:CSH.TailBytes }
        $out = [pscustomobject]@{ LogRead = $false; Evidence = $null; RotatedRead = 0 }

        $lines = Read-CSLogTailLines -Path $script:CSH.AgentLogPath -TailBytes $TailBytes
        if ($null -eq $lines) { return $out }
        $out.LogRead = $true

        # File mtime gates the clock calibration inside the evidence extractor
        # (proof the agent is actually APPENDING - see Get-CSLogEvidence). It is
        # never a health signal itself.
        $mtimeAge = 0
        try {
            $mtimeAge = ((Get-Date) - (Get-Item -LiteralPath $script:CSH.AgentLogPath -ErrorAction Stop).LastWriteTime).TotalMinutes
        } catch { $mtimeAge = 0 }

        $ev = Get-CSLogEvidence -Lines $lines -Now $Now -LogWriteAgeMinutes $mtimeAge `
                -CheckinStaleMinutes $CheckinStaleMinutes -CommsErrorLookbackMinutes $CommsErrorLookbackMinutes

        if (-not $ev.HistorySufficient) {
            # Defensive: merge up to 2 newest rotated/archived siblings, if any.
            $rot = @()
            try {
                if (Test-Path -LiteralPath $script:CSH.AgentLogDir) {
                    $rot = @(Get-ChildItem -LiteralPath $script:CSH.AgentLogDir -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '^(?i)cybercns\.log\.' -or $_.Name -match '^(?i)cybercns[-_]\d.*\.log$' -or $_.Name -match '^(?i)cybercns.*\.old$' } |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 2)
                }
            } catch { }
            if ($rot.Count -gt 0) {
                $merged = New-Object System.Collections.Generic.List[string]
                foreach ($f in ($rot | Sort-Object LastWriteTime)) {
                    $rl = Read-CSLogTailLines -Path $f.FullName -TailBytes $TailBytes
                    if ($null -ne $rl) { foreach ($l in $rl) { $merged.Add($l) }; $out.RotatedRead++ }
                }
                foreach ($l in $lines) { $merged.Add($l) }
                $ev = Get-CSLogEvidence -Lines $merged.ToArray() -Now $Now -LogWriteAgeMinutes $mtimeAge `
                        -CheckinStaleMinutes $CheckinStaleMinutes -CommsErrorLookbackMinutes $CommsErrorLookbackMinutes
            }
        }
        $out.Evidence = $ev
        return $out
    }

    function Test-CSAgentComms {
        <#
          Runs the agent's own comms self-test ('cybercnsagent.exe -x') and judges
          its OUTPUT TEXT. The exit code is NOT reliable (the agent prints
          'Status: SUCCESS' yet can exit non-zero) - it is recorded as evidence only.
          Returns @{ Verdict = $true|$false|$null; ExitCode; TimedOut }.
          A TIMEOUT is INCONCLUSIVE ($null - one 60s retry first), never a failure:
          a slow -x on a loaded box must not, on its own, cause a Reinstall.
        #>
        param([int]$TimeoutSeconds = 120)
        $out = [pscustomobject]@{ Verdict = $null; ExitCode = $null; TimedOut = $false }
        if (-not (Test-Path -LiteralPath $script:CSH.AgentExePath)) { return $out }

        $cap = Invoke-CSProcessCapture -FilePath $script:CSH.AgentExePath -ArgumentList @('-x') `
                -TimeoutSeconds $TimeoutSeconds -CaptureTag 'commscheck'
        if ($cap.TimedOut) {
            Write-CSHeal -Level WARN -Message ('Comms self-test (-x) timed out after {0}s; retrying once (60s)...' -f $TimeoutSeconds)
            $cap = Invoke-CSProcessCapture -FilePath $script:CSH.AgentExePath -ArgumentList @('-x') `
                    -TimeoutSeconds 60 -CaptureTag 'commscheck_retry'
        }
        $out.ExitCode = $cap.ExitCode
        $out.TimedOut = $cap.TimedOut
        if (-not $cap.Ran -or $cap.TimedOut) { return $out }   # Verdict stays $null (inconclusive)

        $text = $cap.Output
        if ([string]::IsNullOrWhiteSpace($text)) { return $out }

        # Authoritative overall status line printed by the agent.
        if ($text -match '(?im)^\s*Status\s*:\s*SUCCESS\b')                   { $out.Verdict = $true;  return $out }
        if ($text -match '(?im)^\s*Status\s*:\s*(FAIL|FAILED|FAILURE|ERROR)') { $out.Verdict = $false; return $out }

        foreach ($m in @('agent working correctly',
                         'Communication to ConnectSecure Portal functioning',
                         'API communication verified')) {
            if ($text.IndexOf($m, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $out.Verdict = $true; return $out }
        }
        # Negative signals, incl. the broken/lost-config output (observed on 4.3.84:
        # -x cannot load the config, re-registers, platform rejects with HTTP 400
        # tenant_or_company_id_missing). A genuine agent fault -> must read Unhealthy.
        foreach ($m in @('not reachable', 'unreachable', 'connection refused',
                         'could not connect', 'unable to verify',
                         'error encountered while loading agent configuration',
                         'error encountered when contacting the central server',
                         'failed to fetch and store config',
                         'error in connecting to central server',
                         'tenant_or_company_id_missing',
                         'company_id_missing', 'tenant_id_missing',
                         [string][char]0x2717, [string][char]0x2718)) {
            if ($text.IndexOf([string]$m, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $out.Verdict = $false; return $out }
        }
        return $out   # unrecognized output -> inconclusive
    }

    function Get-CSInstalledVersion {
        <#
          Version-source ladder (the live agent's Go binaries have EMPTY FileVersion,
          and its uninstall key lives ONLY in the 64-bit hive despite the x86 path):
            1. 'cybercnsagent.exe --version' (timeboxed 15s, kill on hang) - FIRST,
               because an in-place binary swap does NOT update the uninstall
               registry key: after any Update the registry is stale (old version),
               which would both fail post-Update verification and re-trigger the
               Update on every subsequent run. The vendor's own update tool also
               trusts --version. First clean STANDALONE 3-part match (lookarounds
               reject fragments of 4-part numbers like '2024.4.3.88'; first-match
               avoids trailing runtime versions like 'go1.21.5').
            2. HKLM64 uninstall DisplayVersion (RegistryView.Registry64 - correct
               even from a 32-bit PowerShell host, no sysnative relaunch needed)
            3. dependency.json's cybercnsagent entry
          Returns @{ Version; Source }.
        #>
        $out = [pscustomobject]@{ Version = $null; Source = $null }

        if (Test-Path -LiteralPath $script:CSH.AgentExePath) {
            $cap = Invoke-CSProcessCapture -FilePath $script:CSH.AgentExePath -ArgumentList @('--version') `
                    -TimeoutSeconds $script:CSH.VersionProbeTimeoutSeconds -CaptureTag 'version'
            if ($cap.Ran -and -not $cap.TimedOut -and -not [string]::IsNullOrWhiteSpace($cap.Output)) {
                $ms = [regex]::Matches($cap.Output, '(?<!\d)(?<!\d\.)(\d+\.\d+\.\d+)(?!\.?\d)')
                if ($ms.Count -gt 0) {
                    $out.Version = $ms[0].Groups[1].Value
                    $out.Source  = 'ExeVersionFlag'
                    return $out
                }
            }
        }

        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $unin = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($unin) {
                foreach ($skName in $unin.GetSubKeyNames()) {
                    $sk = $null
                    try {
                        $sk = $unin.OpenSubKey($skName)
                        if (-not $sk) { continue }
                        $dn = [string]$sk.GetValue('DisplayName')
                        if ($dn -and ($dn -like '*ConnectSecure*' -or $dn -like '*CyberCNS*')) {
                            $dv = ConvertTo-CSVersion3 ([string]$sk.GetValue('DisplayVersion'))
                            if ($dv) { $out.Version = $dv; $out.Source = 'Registry64'; break }
                        }
                    } catch { } finally { if ($sk) { try { $sk.Dispose() } catch { } } }
                }
                try { $unin.Dispose() } catch { }
            }
            try { $base.Dispose() } catch { }
        } catch { }
        if ($out.Version) { return $out }

        try {
            if (Test-Path -LiteralPath $script:CSH.DependencyJson) {
                $dep = Get-Content -LiteralPath $script:CSH.DependencyJson -Raw -ErrorAction Stop | ConvertFrom-Json
                foreach ($prop in $dep.PSObject.Properties) {
                    if ($prop.Name -match '(?i)cybercnsagent') {
                        $v = $null
                        try { $v = ConvertTo-CSVersion3 ([string]$prop.Value.Version) } catch { }
                        if ($v) { $out.Version = $v; $out.Source = 'DependencyJson'; break }
                    }
                }
            }
        } catch { }
        return $out
    }

    function Get-CSDownloadUrlFromResponse {
        param([Parameter(Mandatory)][object]$Resp)
        if ($Resp -is [string] -and $Resp -match '^https?://') { return $Resp.Trim() }
        foreach ($prop in 'url', 'URL', 'link', 'agentlink', 'AgentLink', 'downloadUrl') {
            try {
                $v = $Resp.$prop
                if ($v -and ([string]$v) -match '^https?://') { return [string]$v }
            } catch { }
        }
        try {
            if ($Resp.data) {
                foreach ($prop in 'url', 'link') {
                    $v = $Resp.data.$prop
                    if ($v -and ([string]$v) -match '^https?://') { return [string]$v }
                }
            }
        } catch { }
        try {
            $json = $Resp | ConvertTo-Json -Depth 10 -Compress
            $m = [regex]::Match($json, 'https?://[^"\\]+?\.exe')
            if ($m.Success) { return $m.Value }
        } catch { }
        return $null
    }

    function Resolve-CSAgentDownload {
        # Cached agentlink resolution: @{Url;Version} or $null. Read-only. Doubles as
        # the platform-reachability precondition: a successful HTTPS GET proves
        # DNS + TLS + HTTP end to end (a bare TCP-443 connect can pass through
        # captive portals and TLS-inspecting proxies that would break the download).
        if ($null -ne $script:CSH.LatestDownload) {
            if ($script:CSH.LatestDownload -is [bool]) { return $null }   # earlier attempt failed
            return $script:CSH.LatestDownload
        }
        Enable-CSTls12
        $resp = $null
        for ($i = 1; $i -le 3; $i++) {
            try {
                # -TimeoutSec: without it PS 5.1 waits FOREVER on a stalled proxy,
                # wedging the run while it holds the global mutex (every later run
                # would exit 5 until someone kills the process).
                $resp = Invoke-RestMethod -Method Get -Uri $script:CSH.AgentApiUrl -TimeoutSec 60 -ErrorAction Stop
                break
            } catch {
                if ($i -eq 3) { Write-CSHeal -Level WARN -Message ('Agent-link API failed: {0}' -f $_.Exception.Message) }
                else { Start-Sleep -Seconds 2 }
            }
        }
        if (-not $resp) { $script:CSH.LatestDownload = $false; return $null }

        $url = Get-CSDownloadUrlFromResponse -Resp $resp
        if (-not $url) {
            Write-CSHeal -Level WARN -Message 'Agent-link API returned no usable download URL.'
            $script:CSH.LatestDownload = $false
            return $null
        }
        $ver = $null
        if ($url -match '/agents/(\d+\.\d+\.\d+)') { $ver = $Matches[1] }
        $script:CSH.LatestDownload = [pscustomobject]@{ Url = $url; Version = $ver }
        return $script:CSH.LatestDownload
    }

    function Get-CSTenantIdentity {
        # Reads the agent's registered tenant/company (plaintext in agent_config.json)
        # so a reinstall that would MIGRATE the agent to a different tenant is at
        # least recorded. Returns @{ TenantId; CompanyId } (values may be $null).
        $out = [pscustomobject]@{ TenantId = $null; CompanyId = $null }
        try {
            if (Test-Path -LiteralPath $script:CSH.AgentConfigPath) {
                $j = Get-Content -LiteralPath $script:CSH.AgentConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json
                foreach ($p in $j.PSObject.Properties) {
                    if ($p.Name -eq 'tenant_id')  { $out.TenantId  = [string]$p.Value }
                    if ($p.Name -eq 'company_id') { $out.CompanyId = [string]$p.Value }
                }
            }
        } catch { }
        return $out
    }

    function Test-CSRebootPendingForAgent {
        # Blocks ONLY when a pending file rename touches the agent directory (a
        # generic CBS/WU reboot flag alone must not stop a heal).
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $k = $base.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager')
            if ($k) {
                $v = $k.GetValue('PendingFileRenameOperations')
                try { $k.Dispose() } catch { }
                try { $base.Dispose() } catch { }
                if ($v) {
                    foreach ($entry in @($v)) {
                        if ($entry -and ([string]$entry) -match '(?i)CyberCNSAgent') { return $true }
                    }
                }
            } else { try { $base.Dispose() } catch { } }
        } catch { }
        return $false
    }

    function Test-CSAgentMidUpgrade {
        # The agent self-updates its DEPENDENCIES (updates_consecure\) and keeps a
        # .bak of the main binary during swaps. Acting mid-upgrade risks a corrupted
        # install - defer when any signal is fresh.
        $reasons = @()
        $cut = (Get-Date).AddMinutes(-10)
        try {
            if (Test-Path -LiteralPath $script:CSH.UpdatesDir) {
                $fresh = @(Get-ChildItem -LiteralPath $script:CSH.UpdatesDir -File -Recurse -ErrorAction SilentlyContinue |
                           Where-Object { $_.LastWriteTime -gt $cut } | Select-Object -First 1)
                if ($fresh.Count -gt 0) { $reasons += 'fresh files in updates_consecure' }
            }
        } catch { }
        try {
            $bak = Get-Item -LiteralPath ($script:CSH.AgentExePath + '.bak') -ErrorAction SilentlyContinue
            if ($bak -and $bak.LastWriteTime -gt $cut) { $reasons += 'cybercnsagent.exe.bak written <10 min ago' }
        } catch { }
        try {
            $procs = @(Get-Process -Name 'cybercnsagent' -ErrorAction SilentlyContinue)
            if ($procs.Count -gt 1) { $reasons += ('{0} concurrent cybercnsagent processes (installer instance?)' -f $procs.Count) }
        } catch { }
        try {
            $t = Get-Item -LiteralPath (Join-Path $script:CSH.AgentDir 'last_dependency_check_time.txt') -ErrorAction SilentlyContinue
            if ($t -and $t.LastWriteTime -gt (Get-Date).AddMinutes(-5)) { $reasons += 'dependency check ran <5 min ago' }
        } catch { }
        return [pscustomobject]@{ InProgress = ($reasons.Count -gt 0); Reasons = $reasons }
    }

    function Test-CSMsiMutexBusy {
        # Courtesy probe only: the agent has NO MSI in its lifecycle, so a busy
        # Windows Installer merely WARNS (recorded in the result), never defers.
        $m = $null
        try {
            $m = [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')
            $got = $false
            try { $got = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
            if ($got) { try { $m.ReleaseMutex() } catch { } }
            return (-not $got)
        } catch {
            return $false   # mutex doesn't exist -> no MSI running
        } finally {
            if ($m) { try { $m.Dispose() } catch { } }
        }
    }

    function Get-CSFreeDiskMB {
        param([Parameter(Mandatory)][string]$Path)
        try {
            $root = [System.IO.Path]::GetPathRoot($Path)
            if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\' }
            $di = New-Object System.IO.DriveInfo($root)
            return [math]::Round($di.AvailableFreeSpace / 1MB)
        } catch { return $null }
    }
    #endregion

    #region Persistent state (flap breaker; survives reinstall - lives in ProgramData)
    function Read-CSHealState {
        $empty = [pscustomobject]@{ SchemaVersion = 1; Runs = @() }
        try {
            if (-not (Test-Path -LiteralPath $script:CSH.StatePath)) { return $empty }
            $j = Get-Content -LiteralPath $script:CSH.StatePath -Raw -ErrorAction Stop | ConvertFrom-Json
            $runs = @()
            try { $runs = @($j.Runs) } catch { $runs = @() }
            return [pscustomobject]@{ SchemaVersion = 1; Runs = $runs }
        } catch {
            # Corrupt/unreadable state must NEVER block a heal - treat as empty.
            return $empty
        }
    }

    function Write-CSHealState {
        param([Parameter(Mandatory)]$State)
        try {
            $json = $State | ConvertTo-Json -Depth 6
            Set-Content -LiteralPath $script:CSH.StatePath -Value $json -Encoding UTF8 -Force -WhatIf:$false
        } catch {
            Write-CSHeal -Level WARN -Message ('Could not write state file: {0}' -f $_.Exception.Message)
        }
    }

    function Add-CSHealRunRecord {
        <#
          Compacted run history (dry runs are never recorded; the caller also never
          records Deferred-* runs - they change nothing and, in a count-capped ring,
          their own cooldown deferrals would flush out the very reinstall records
          the cooldown counts, re-arming it every ~10 runs):
            - A CONFIRMED-HEALTHY run resets the flap-breaker, which makes all
              earlier history irrelevant -> the state collapses to that one record.
            - Any other run appends; records older than 7 days (the widest cooldown
              window) are pruned, capped at 20 as a size backstop.
        #>
        param(
            [Parameter(Mandatory)]$State,
            [Parameter(Mandatory)][string]$Action,
            [Parameter(Mandatory)][string]$Outcome,
            [Parameter(Mandatory)][int]$ExitCode,
            [object]$ConfirmedOverride = $null   # caller knows better (e.g. recovered-pending)
        )
        $confirmed = $false
        if ($Outcome -in @('NoActionNeeded', 'RecoveredByServiceStart', 'Repaired-Monitor', 'NoAction-VersionUnknown') -or
            $Outcome -like 'Success:*') { $confirmed = $true }
        if ($null -ne $ConfirmedOverride) { $confirmed = [bool]$ConfirmedOverride }
        $rec = [pscustomobject]@{
            TimeUtc          = [datetime]::UtcNow.ToString('o')
            Action           = $Action
            Outcome          = $Outcome
            ExitCode         = $ExitCode
            ConfirmedHealthy = $confirmed
            RunId            = $script:CSH.RunId
        }
        if ($confirmed) {
            return [pscustomobject]@{ SchemaVersion = 1; Runs = @($rec) }
        }
        $cutoff = [datetime]::UtcNow.AddDays(-7)
        $kept = @()
        foreach ($r in @($State.Runs)) {
            $t = $null
            try { $t = [datetime]::Parse([string]$r.TimeUtc, [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { }
            if ($null -ne $t -and $t -gt $cutoff) { $kept += $r }
        }
        $runs = @($kept) + @($rec)
        if ($runs.Count -gt 20) { $runs = $runs[($runs.Count - 20)..($runs.Count - 1)] }
        return [pscustomobject]@{ SchemaVersion = 1; Runs = $runs }
    }

    function Test-CSReinstallCooldown {
        <#
          Refuses to repeat the identical failed remedy unboundedly: counts
          Reinstall runs SINCE the most recent confirmed-Healthy run; if that count
          already reached MaxReinstallsPer24h within 24h (or MaxReinstallsPer7d
          within 7 days), a further Reinstall is deferred. Any run that confirms
          Healthy resets the counter naturally. Policy is unchanged: Unhealthy still
          always MAPS to Reinstall - this only bounds repetition.
        #>
        param([Parameter(Mandatory)]$State)
        $out = [pscustomobject]@{ Active = $false; Reason = $null; RecentReinstalls24h = 0; RecentReinstalls7d = 0 }
        $runs = @($State.Runs)
        if ($runs.Count -eq 0) { return $out }

        $lastHealthyIdx = -1
        for ($i = 0; $i -lt $runs.Count; $i++) {
            $c = $false
            try { $c = [bool]$runs[$i].ConfirmedHealthy } catch { }
            if ($c) { $lastHealthyIdx = $i }
        }
        $nowUtc = [datetime]::UtcNow
        for ($i = $lastHealthyIdx + 1; $i -lt $runs.Count; $i++) {
            $r = $runs[$i]
            $act = ''; $oc = ''; $t = $null
            try { $act = [string]$r.Action } catch { }
            try { $oc  = [string]$r.Outcome } catch { }
            try { $t = [datetime]::Parse([string]$r.TimeUtc, [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { }
            if ($act -ne 'Reinstall' -or $null -eq $t) { continue }
            # Only reinstalls that actually RAN count - a run that was itself
            # deferred, aborted at preconditions, or failed during staging (agent
            # untouched) must not inflate the cooldown.
            if ($oc -like 'Deferred-*' -or $oc -eq 'AbortedPreconditions' -or $oc -eq 'ActionFailed-Staging') { continue }
            if ($t -gt $nowUtc.AddHours(-24)) { $out.RecentReinstalls24h++ }
            if ($t -gt $nowUtc.AddDays(-7))   { $out.RecentReinstalls7d++ }
        }
        if ($out.RecentReinstalls24h -ge $MaxReinstallsPer24h) {
            $out.Active = $true
            $out.Reason = ('{0} reinstalls in the last 24h without a confirmed-Healthy run (max {1}). The remedy is not fixing the cause - investigate the environment (DNS/proxy/firewall to *.myconnectsecure.com).' -f $out.RecentReinstalls24h, $MaxReinstallsPer24h)
        } elseif ($out.RecentReinstalls7d -ge $MaxReinstallsPer7d) {
            $out.Active = $true
            $out.Reason = ('{0} reinstalls in the last 7 days without a confirmed-Healthy run (max {1}). Investigate the environment instead of reinstalling again.' -f $out.RecentReinstalls7d, $MaxReinstallsPer7d)
        }
        return $out
    }
    #endregion

    #region Service control (watchdog-safe ordering)
    function Stop-CSAgentServices {
        # MONITOR FIRST: the watchdog restarts the main agent, so it must be down
        # and disabled before the main service is touched.
        foreach ($n in ($script:CSH.MonitorNames + @($script:CSH.AgentServiceName))) {
            try { Set-Service -Name $n -StartupType Disabled -ErrorAction SilentlyContinue } catch { }
            try { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue } catch { }
        }
        foreach ($m in (Get-CSMonitorServices)) {
            try { Set-Service -Name $m.Name -StartupType Disabled -ErrorAction SilentlyContinue } catch { }
            try { Stop-Service -Name $m.Name -Force -ErrorAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 2
        foreach ($p in $script:CSH.ProcessNames) {
            try { Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
        }
    }

    function Start-CSAgentServices {
        # Main first, watchdog last.
        foreach ($n in (@($script:CSH.AgentServiceName) + $script:CSH.MonitorNames)) {
            try { Set-Service -Name $n -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
            try { Start-Service -Name $n -ErrorAction SilentlyContinue } catch { }
        }
        foreach ($m in (Get-CSMonitorServices)) {
            try { Set-Service -Name $m.Name -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
            try { Start-Service -Name $m.Name -ErrorAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 2
    }
    #endregion

    #region Corrective actions
    function Invoke-CSDownloadFile {
        param(
            [Parameter(Mandatory)][string]$Uri,
            [Parameter(Mandatory)][string]$OutFile,
            [int]$MaxAttempts = 3
        )
        Enable-CSTls12
        $dir = Split-Path -Parent $OutFile
        if (-not (Test-Path -LiteralPath $dir)) {
            try { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null }
            catch { throw "Could not create download folder '$dir': $($_.Exception.Message)" }
        }
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
        for ($i = 1; $i -le $MaxAttempts; $i++) {
            try {
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
                if ((Test-Path -LiteralPath $OutFile) -and ((Get-Item -LiteralPath $OutFile).Length -gt 0)) {
                    try { Unblock-File -LiteralPath $OutFile -ErrorAction SilentlyContinue } catch { }
                    return $true
                }
                throw 'Downloaded file missing or empty.'
            } catch {
                if ($i -eq $MaxAttempts) { throw }
                Start-Sleep -Seconds 2
            }
        }
        return $false
    }

    function Get-CSStagedInstaller {
        <#
          Stages and VALIDATES the installer BEFORE anything destructive may run -
          the load-bearing ordering that makes "uninstalled but can't reinstall"
          impossible by construction. Returns @{ Path; Version } or throws.
        #>
        $dl = Resolve-CSAgentDownload
        if (-not $dl) { throw 'Could not resolve the agent download URL from the platform.' }
        $verText = if ($dl.Version) { $dl.Version } else { 'unknown' }

        $exe = Join-Path $script:CSH.StageDir 'cybercnsagent.exe'
        $ok = Invoke-CSOrWhatIf -Description ('Download + validate agent installer ({0}) to {1}' -f $verText, $exe) -Action {
            Invoke-CSDownloadFile -Uri $dl.Url -OutFile $exe | Out-Null
            $len = (Get-Item -LiteralPath $exe).Length
            if ($len -lt $script:CSH.MinInstallerBytes) {
                throw ('Staged installer is implausibly small ({0} bytes) - refusing to proceed.' -f $len)
            }
            $true
        }
        if ($WhatIfPreference) { return [pscustomobject]@{ Path = $exe; Version = $dl.Version } }
        if (-not $ok) { throw 'Agent installer download failed.' }
        Set-CSRes 'StagedInstallerValid' $true
        return [pscustomobject]@{ Path = $exe; Version = $dl.Version }
    }

    function Install-CSAgentFromStage {
        # Runs the staged installer with the registration values. The exit code is
        # ENFORCED (v1 logged it and carried on, converting install failures into
        # confusing verification failures).
        param([Parameter(Mandatory)]$Staged)
        Invoke-CSOrWhatIf -Description ('Run installer: cybercnsagent.exe -c {0} -e {1} -j **** -i' -f $script:CSH.Cfg.CompanyID, $script:CSH.Cfg.TenantID) -Action {
            # The installer mutates the system the moment it launches (services,
            # files) - from here on a failure is 'ActionFailed', never '-Staging'.
            $script:CSHDestructiveStarted = $true
            $cap = Invoke-CSProcessCapture -FilePath $Staged.Path `
                    -ArgumentList @('-c', $script:CSH.Cfg.CompanyID, '-e', $script:CSH.Cfg.TenantID, '-j', $script:CSH.Cfg.Secret, '-i') `
                    -TimeoutSeconds $script:CSH.InstallerTimeoutSeconds -CaptureTag 'installer'
            Write-CSHealDebugLines -Label 'installer' -Lines ($cap.Output -split "`n")
            if ($cap.TimedOut) { throw ('Installer did not finish within {0}s and was terminated.' -f $script:CSH.InstallerTimeoutSeconds) }
            if (-not $cap.Ran) { throw 'Installer could not be started.' }
            if ($null -ne $cap.ExitCode -and $cap.ExitCode -ne 0) {
                throw ('Installer exited with code {0}.' -f $cap.ExitCode)
            }
        } | Out-Null
        Invoke-CSOrWhatIf -Description 'Start ConnectSecure agent services' -Action { Start-CSAgentServices } | Out-Null
    }

    function Uninstall-CSAgentBestEffort {
        # Vendor order: exe -r -y <secret> first, then uninstall.bat. The monitor is
        # stopped/disabled FIRST so the watchdog cannot resurrect the agent mid-way.
        # All native output is captured and surfaced only under -Debug (the vendor
        # uninstaller emits benign taskkill/locked-file noise).
        if (-not $WhatIfPreference) { $script:CSHDestructiveStarted = $true }
        Invoke-CSOrWhatIf -Description 'Stop agent + monitor services (monitor first)' -Action { Stop-CSAgentServices } | Out-Null

        if (Test-Path -LiteralPath $script:CSH.AgentExePath) {
            Invoke-CSOrWhatIf -Description 'Uninstall agent (cybercnsagent.exe -r -y ****)' -Action {
                $uArgs = @('-r')
                if (-not [string]::IsNullOrWhiteSpace($script:CSH.Cfg.UninstallSecret)) {
                    $uArgs += @('-y', $script:CSH.Cfg.UninstallSecret)
                }
                $cap = Invoke-CSProcessCapture -FilePath $script:CSH.AgentExePath -ArgumentList $uArgs `
                        -TimeoutSeconds $script:CSH.UninstallTimeoutSeconds -CaptureTag 'uninstall_r'
                Write-CSHealDebugLines -Label 'uninstall(-r)' -Lines ($cap.Output -split "`n")
            } | Out-Null
        }
        if (Test-Path -LiteralPath $script:CSH.UninstallBatPath) {
            Invoke-CSOrWhatIf -Description 'Run vendor uninstall.bat (best-effort)' -Action {
                # cmd.exe /c only PRESERVES path quotes when there are no special
                # characters between them - and '(x86)' contains parentheses, so a
                # plain  /c "C:\Program Files (x86)\...\uninstall.bat"  gets its
                # quotes stripped and cmd tries to run 'C:\Program'. The canonical
                # fix is /S with an OUTER quote pair around the whole command.
                $secretPart = ''
                if (-not [string]::IsNullOrWhiteSpace($script:CSH.Cfg.UninstallSecret)) { $secretPart = ' ' + $script:CSH.Cfg.UninstallSecret }
                $raw = '/s /c ""' + $script:CSH.UninstallBatPath + '"' + $secretPart + '"'
                $cap = Invoke-CSProcessCapture -FilePath "$env:SystemRoot\System32\cmd.exe" -RawArgumentString $raw `
                        -TimeoutSeconds $script:CSH.UninstallTimeoutSeconds -WorkingDirectory $script:CSH.AgentDir -CaptureTag 'uninstall_bat'
                if ($null -ne $cap.ExitCode -and $cap.ExitCode -ne 0) {
                    Write-CSHeal -Level WARN -Message ('uninstall.bat exited {0} (best-effort step; continuing).' -f $cap.ExitCode)
                }
                Write-CSHealDebugLines -Label 'uninstall.bat' -Lines ($cap.Output -split "`n")
            } | Out-Null
        }
    }

    function Invoke-CSAgentInstallAction {
        $staged = Get-CSStagedInstaller
        Install-CSAgentFromStage -Staged $staged
    }

    function Invoke-CSAgentReinstallAction {
        Write-CSHeal -Level STEP -Message 'Reinstall: stage+validate installer FIRST, then uninstall, then fresh install.'
        $staged = Get-CSStagedInstaller           # throws BEFORE anything destructive if it can't stage
        Uninstall-CSAgentBestEffort
        if (-not $WhatIfPreference) { Start-Sleep -Seconds 3 }
        try {
            Install-CSAgentFromStage -Staged $staged
        } catch {
            # The agent is already uninstalled - one in-run retry from the staged
            # file before giving up. (If this also fails, the next run's
            # NotInstalled -> Install path is the defined recovery.) Quiesce first:
            # a timed-out attempt 1 may have left half-registered services or
            # straggler processes that would race attempt 2 for the same files.
            Write-CSHeal -Level WARN -Message ('Install failed after uninstall ({0}) - quiescing and retrying once from the staged installer.' -f $_.Exception.Message)
            try { Stop-CSAgentServices } catch { }
            Start-Sleep -Seconds 5
            Install-CSAgentFromStage -Staged $staged
        }
    }

    function Update-CSAgentInPlace {
        # In-place binary swap (the vendor-blessed update: Agent-Update-Tool.ps1).
        # On ANY failure after the services were stopped, the .bak is restored and
        # the services are re-enabled + restarted - a failed Update must never leave
        # the agent Disabled+Stopped (the v1 defect).
        Write-CSHeal -Level STEP -Message 'Update: in-place binary replacement to the latest agent version.'
        $staged = Get-CSStagedInstaller
        if ($WhatIfPreference) {
            Invoke-CSOrWhatIf -Description 'Stop services, back up cybercnsagent.exe to .bak, swap in the new binary, restart services' -Action { } | Out-Null
            return
        }

        $bakPath = $script:CSH.AgentExePath + '.bak'
        Invoke-CSOrWhatIf -Description 'Stop ConnectSecure agent services (monitor first)' -Action { Stop-CSAgentServices } | Out-Null
        $script:CSHDestructiveStarted = $true
        $script:CSHUpdateBakOk = $false
        try {
            Invoke-CSOrWhatIf -Description ('Back up current binary and replace with {0}' -f $staged.Version) -Action {
                # A stale .bak left by the agent's own updater must never be
                # mistaken for THIS run's backup (rolling it back would silently
                # DOWNGRADE an intact binary) - clear it first, and only flag the
                # backup as usable after our own copy succeeded.
                if (Test-Path -LiteralPath $bakPath) { Remove-Item -LiteralPath $bakPath -Force -ErrorAction SilentlyContinue }
                if (Test-Path -LiteralPath $script:CSH.AgentExePath) {
                    Copy-Item -LiteralPath $script:CSH.AgentExePath -Destination $bakPath -Force -ErrorAction Stop
                    $script:CSHUpdateBakOk = $true
                }
                Copy-Item -LiteralPath $staged.Path -Destination $script:CSH.AgentExePath -Force -ErrorAction Stop
            } | Out-Null
        } catch {
            $rb = if ($script:CSHUpdateBakOk) { ' - rolling back the binary and restoring services' } else { ' - binary untouched; restoring services' }
            Write-CSHeal -Level ERROR -Message ('Binary swap failed: {0}{1}.' -f $_.Exception.Message, $rb)
            if ($script:CSHUpdateBakOk) {
                try { Copy-Item -LiteralPath $bakPath -Destination $script:CSH.AgentExePath -Force -ErrorAction SilentlyContinue } catch { }
            }
            try { Start-CSAgentServices } catch { }
            throw
        }
        Invoke-CSOrWhatIf -Description 'Start ConnectSecure agent services' -Action { Start-CSAgentServices } | Out-Null
    }

    function Repair-CSAgentMonitor {
        # Light heal: the main agent is demonstrably Healthy; only the watchdog is
        # down. Enable + start it - never a Reinstall.
        Invoke-CSOrWhatIf -Description 'Enable + start the agent monitor (watchdog) service' -Action {
            foreach ($m in (Get-CSMonitorServices)) {
                try { Set-Service -Name $m.Name -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
                try { Start-Service -Name $m.Name -ErrorAction SilentlyContinue } catch { }
            }
        } | Out-Null
        if ($WhatIfPreference) { return $true }
        Start-Sleep -Seconds 3
        $inv = Get-CSAgentInventory
        Set-CSRes 'MonitorState' $inv.MonitorState
        return ($inv.MonitorState -eq 'Up')
    }
    #endregion

    #region Verification
    function Wait-CSPostActionHealth {
        <#
          Polls for the agent to settle after an action (or after a Start-Service
          recovery). Evidence is ANCHORED: only a successful check-in STRICTLY newer
          than ($AnchorTime - 60s) counts, so pre-action log history can never fake
          success. Polls are cheap (service/process + small log tail); -x runs at
          most ONCE, in the final stretch, and only if nothing was seen.
          A Present-but-Stopped service gets up to $MaxStartRetries Start-Service
          attempts (the field-confirmed v1 exit-4 fix).
          Returns @{ Grade='Confirmed'|'Pending'|'XFailed'|'ServiceDown';
                     PostCheckinAgeMin; StartRetries; XExitCode }
        #>
        param(
            [Parameter(Mandatory)][datetime]$AnchorTime,
            [int]$TimeoutSeconds = 300,
            [int]$MaxStartRetries = 2
        )
        $deadline    = (Get-Date).AddSeconds([math]::Max(15, $TimeoutSeconds))
        $anchor      = $AnchorTime.AddSeconds(-60)
        $startRetries = 0
        $xTried      = $false
        $xExit       = $null
        $lastAge     = $null

        while ($true) {
            $inv = Get-CSAgentInventory

            if ($inv.ServicePresent -and -not $inv.ServiceRunning -and $startRetries -lt $MaxStartRetries) {
                $startRetries++
                Write-CSHeal -Level WARN -Message ('Service present but stopped during verification - Start-Service attempt {0}/{1}.' -f $startRetries, $MaxStartRetries)
                try { Set-Service -Name $script:CSH.AgentServiceName -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
                try { Start-Service -Name $script:CSH.AgentServiceName -ErrorAction SilentlyContinue } catch { }
                Start-Sleep -Seconds 10
                continue
            }

            if ($inv.Running) {
                $act = Get-CSPortalActivity -TailBytes $script:CSH.VerifyTailBytes
                if ($act.LogRead -and $null -ne $act.Evidence -and $null -ne $act.Evidence.LastOkAdj) {
                    $lastAge = $act.Evidence.LastCheckinAgeMin
                    # Belt-and-braces on the anchor: only accept log-based
                    # confirmation when the log file has actually been APPENDED
                    # since the action started - calibrated pre-action evidence
                    # can then never be shifted past the anchor.
                    $logTouched = $false
                    try { $logTouched = ((Get-Item -LiteralPath $script:CSH.AgentLogPath -ErrorAction Stop).LastWriteTime -ge $anchor) } catch { }
                    if ($logTouched -and $act.Evidence.LastOkAdj -ge $anchor) {
                        return [pscustomobject]@{ Grade = 'Confirmed'; PostCheckinAgeMin = $lastAge; StartRetries = $startRetries; XExitCode = $xExit }
                    }
                }
                # Final stretch and still nothing: one -x tiebreak.
                $remaining = ($deadline - (Get-Date)).TotalSeconds
                if (-not $xTried -and $remaining -le 75 -and $remaining -gt 5) {
                    $xTried = $true
                    Write-CSHeal -Level STEP -Message 'No post-action check-in seen yet - running the -x self-test once as tiebreaker.'
                    $x = Test-CSAgentComms -TimeoutSeconds ([math]::Min($CommsTimeoutSeconds, [int][math]::Max(30, $remaining - 10)))
                    $xExit = $x.ExitCode
                    if ($x.Verdict -eq $true)  { return [pscustomobject]@{ Grade = 'Confirmed'; PostCheckinAgeMin = $lastAge; StartRetries = $startRetries; XExitCode = $xExit } }
                    if ($x.Verdict -eq $false) { return [pscustomobject]@{ Grade = 'XFailed';   PostCheckinAgeMin = $lastAge; StartRetries = $startRetries; XExitCode = $xExit } }
                }
            }

            if ((Get-Date) -ge $deadline) { break }
            Start-Sleep -Seconds $script:CSH.VerifyPollSeconds
        }

        $inv = Get-CSAgentInventory
        if ($inv.Running) {
            return [pscustomobject]@{ Grade = 'Pending'; PostCheckinAgeMin = $lastAge; StartRetries = $startRetries; XExitCode = $xExit }
        }
        return [pscustomobject]@{ Grade = 'ServiceDown'; PostCheckinAgeMin = $lastAge; StartRetries = $startRetries; XExitCode = $xExit }
    }
    #endregion

    #region State assessment (read-only; -x is lazy)
    function Get-CSAgentState {
        $inv = Get-CSAgentInventory

        $commsOk  = $null
        $xSkipped = $null
        $xExit    = $null
        $activity = [pscustomobject]@{ LogRead = $false; Evidence = $null; RotatedRead = 0 }
        $health   = $null
        $rule     = $null
        $reason   = $null

        if (-not $inv.Installed) {
            $v = Resolve-CSHealthVerdict -Installed $false -Running $false -LogRead $false -Evidence $null -CommsOk $null
            $health = $v.Health; $rule = $v.Rule; $reason = $v.Reason
        } elseif (-not $inv.Running) {
            $v = Resolve-CSHealthVerdict -Installed $true -Running $false -LogRead $false -Evidence $null -CommsOk $null
            $health = $v.Health; $rule = $v.Rule; $reason = $v.Reason
        } else {
            $activity = Get-CSPortalActivity

            # LAZY -x: when the log already proves a fresh check-in (R1), the
            # self-test is skipped entirely - no contention with the running agent
            # and no 0-120s wait on the happy path.
            $freshCheckin = ($activity.LogRead -and $null -ne $activity.Evidence -and
                             $null -ne $activity.Evidence.LastCheckinAgeMin -and
                             $activity.Evidence.LastCheckinAgeMin -le $CheckinStaleMinutes)
            if ($freshCheckin) {
                $xSkipped = $true
            } else {
                $xSkipped = $false
                $x = Test-CSAgentComms -TimeoutSeconds $CommsTimeoutSeconds
                $commsOk = $x.Verdict
                $xExit   = $x.ExitCode
            }

            $v = Resolve-CSHealthVerdict -Installed $true -Running $true `
                    -LogRead $activity.LogRead -Evidence $activity.Evidence -CommsOk $commsOk `
                    -CheckinStaleMinutes $CheckinStaleMinutes -CommsErrorThreshold $CommsErrorThreshold
            $health = $v.Health; $rule = $v.Rule; $reason = $v.Reason
        }

        # Version axis (server side hits the agentlink API once per run, cached).
        $instVer = [pscustomobject]@{ Version = $null; Source = $null }
        if ($inv.Installed) { $instVer = Get-CSInstalledVersion }
        $dl = Resolve-CSAgentDownload
        $serverVersion = if ($dl) { $dl.Version } else { $null }

        $iNorm = ConvertTo-CSVersion3 $instVer.Version
        $sNorm = ConvertTo-CSVersion3 $serverVersion
        $versionState = 'Unknown'
        if ($iNorm -and $sNorm) {
            try {
                if ([version]$iNorm -ge [version]$sNorm) { $versionState = 'Current' } else { $versionState = 'Outdated' }
            } catch { $versionState = 'Unknown' }
        }

        $ev = $activity.Evidence
        return [pscustomobject]@{
            Installed          = $inv.Installed
            ExePresent         = $inv.ExePresent
            ServicePresent     = $inv.ServicePresent
            ServiceStatus      = $inv.ServiceStatus
            ProcessAlive       = $inv.ProcessAlive
            Running            = $inv.Running
            MonitorState       = $inv.MonitorState
            MonitorName        = $inv.MonitorName
            LogAgeMinutes      = $inv.LogAgeMinutes
            LogRead            = $activity.LogRead
            RotatedLogsRead    = $activity.RotatedRead
            CommsOk            = $commsOk
            XSkipped           = $xSkipped
            XExitCode          = $xExit
            RecentCommsErrMin  = if ($null -ne $ev) { $ev.ErrBucketCount } else { $null }
            LastCheckinAgeMin  = if ($null -ne $ev) { $ev.LastCheckinAgeMin } else { $null }
            CheckinStale       = if ($null -ne $ev) { [bool]$ev.CheckinStale } else { $false }
            ClockOffsetMinutes = if ($null -ne $ev) { $ev.ClockOffsetMinutes } else { $null }
            HistorySufficient  = if ($null -ne $ev) { [bool]$ev.HistorySufficient } else { $false }
            Health             = $health
            HealthRule         = $rule
            HealthReason       = $reason
            InstalledVersion   = $instVer.Version
            VersionSource      = $instVer.Source
            ServerVersion      = $serverVersion
            VersionState       = $versionState
        }
    }

    function Test-CSActionPreconditions {
        param([Parameter(Mandatory)][string[]]$Actions)
        $reasons = New-Object System.Collections.Generic.List[object]
        $ok = $true
        $needsCreds     = ($Actions -contains 'Install' -or $Actions -contains 'Reinstall')
        $needsUninstall = ($Actions -contains 'Reinstall')
        $needsPlatform  = ($Actions -contains 'Install' -or $Actions -contains 'Reinstall' -or $Actions -contains 'Update')

        if ($needsCreds) {
            $credsOk = (Test-CSProvidedValue $script:CSH.Cfg.CompanyID) -and
                       (Test-CSProvidedValue $script:CSH.Cfg.TenantID) -and
                       (Test-CSProvidedValue $script:CSH.Cfg.Secret)
            if ($credsOk) { $reasons.Add([pscustomobject]@{ Ok = $true;  Text = 'Company ID, Tenant ID and Secret are present.' }) }
            else          { $ok = $false; $reasons.Add([pscustomobject]@{ Ok = $false; Text = 'Company ID, Tenant ID and/or Secret missing or still placeholder.' }) }
        }
        if ($needsUninstall) {
            if (Test-CSProvidedValue $script:CSH.Cfg.UninstallSecret) {
                $reasons.Add([pscustomobject]@{ Ok = $true;  Text = 'Uninstall secret is present.' })
            } else {
                $ok = $false
                $reasons.Add([pscustomobject]@{ Ok = $false; Text = 'Uninstall secret missing or still placeholder (required to uninstall during reinstall; mandatory as of 2026-04-01).' })
            }
        }

        $admin = Test-CSIsAdmin
        if ($admin) { $reasons.Add([pscustomobject]@{ Ok = $true; Text = 'Running with administrative privileges.' }) }
        elseif ($WhatIfPreference) { $reasons.Add([pscustomobject]@{ Ok = $false; Text = 'Not elevated (acceptable for -WhatIf; required for a real run).' }) }
        else { $ok = $false; $reasons.Add([pscustomobject]@{ Ok = $false; Text = 'Not running as Administrator.' }) }

        if ($needsPlatform) {
            # A full HTTPS GET of the agentlink API (cached) - proves DNS+TLS+HTTP
            # end to end, unlike a bare TCP connect. Its response is also required
            # to stage the installer, so nothing destructive can start without it.
            $dl = Resolve-CSAgentDownload
            if ($dl) { $reasons.Add([pscustomobject]@{ Ok = $true;  Text = ('Platform reachable: agentlink API answered with a download URL (latest {0}).' -f $dl.Version) }) }
            else     { $ok = $false; $reasons.Add([pscustomobject]@{ Ok = $false; Text = 'Platform NOT reachable: the agentlink API did not yield a download URL.' }) }

            $freeMB = Get-CSFreeDiskMB -Path $script:CSH.StageDir
            if ($null -eq $freeMB -or $freeMB -ge $script:CSH.MinFreeDiskMB) {
                $reasons.Add([pscustomobject]@{ Ok = $true; Text = ('Sufficient free disk for staging ({0} MB).' -f $freeMB) })
            } else {
                $ok = $false
                $reasons.Add([pscustomobject]@{ Ok = $false; Text = ('Insufficient free disk: {0} MB free, {1} MB required.' -f $freeMB, $script:CSH.MinFreeDiskMB) })
            }
        }
        # PS 5.1: .ToArray(), not @($list) - casting a hashtable holding a generic
        # List via [pscustomobject] throws "Argument types do not match".
        return [pscustomobject]@{ Ok = $ok; Reasons = $reasons.ToArray() }
    }
    #endregion

    #region Result persistence + machine-parseable output
    function Write-CSHealResult {
        $json = $null
        try { $json = $script:CSHRes | ConvertTo-Json -Depth 6 } catch { }
        if ($json) {
            # Always-on: SelfHeal-Last.json in ProgramData (post-mortem trail).
            try { Set-Content -LiteralPath $script:CSH.LastResultPath -Value $json -Encoding UTF8 -Force -WhatIf:$false } catch { }
            # -Debug only: timestamped copy alongside the run log.
            if ($script:CSHCanLog) {
                try {
                    Set-Content -LiteralPath $script:CSH.ResultPath -Value $json -Encoding UTF8 -Force -WhatIf:$false
                    Write-CSHeal -Level INFO -Message ('Result JSON: {0}' -f $script:CSH.ResultPath)
                } catch { }
            }
        }
        # The machine-parseable contract: one final stdout line, ALWAYS (even -Silent).
        try {
            $compact = $script:CSHRes | ConvertTo-Json -Depth 6 -Compress
            Write-Host ('CSSH-RESULT|{0}' -f $compact)
        } catch { }
    }
    #endregion

    #region Core orchestration (returns the exit code; never calls 'exit')
    function Invoke-CSHealCore {
        Show-CSHealBanner

        # ---- Concurrency guard: second instance exits 5 without probing ----
        try {
            $script:CSH.Mutex = New-Object System.Threading.Mutex($false, 'Global\CS-AgentSelfHeal')
            try { $script:CSH.MutexAcquired = $script:CSH.Mutex.WaitOne(0) }
            catch [System.Threading.AbandonedMutexException] { $script:CSH.MutexAcquired = $true }
        } catch {
            $script:CSH.MutexAcquired = $true   # mutex machinery unavailable - do not block healing
        }
        Set-CSRes 'MutexAcquired' $script:CSH.MutexAcquired
        if (-not $script:CSH.MutexAcquired) {
            Write-CSHeal -Level WARN -Message 'Another self-heal instance is already running on this host - exiting without action.'
            Set-CSRes 'Outcome' 'Blocked-ConcurrentRun'
            return (Get-CSExitCodeForOutcome 'Blocked-ConcurrentRun')
        }

        $healState = Read-CSHealState

        # ---- Probe current state ----
        Write-CSHeal -Level STEP -Message 'Assessing agent state...'
        $state = Get-CSAgentState

        foreach ($pair in @(
            @('Installed', $state.Installed), @('ExePresent', $state.ExePresent),
            @('ServicePresent', $state.ServicePresent), @('ServiceStatus', $state.ServiceStatus),
            @('ProcessAlive', $state.ProcessAlive), @('LogAgeMinutes', $state.LogAgeMinutes),
            @('CommsOk', $state.CommsOk), @('RecentCommsErrMin', $state.RecentCommsErrMin),
            @('LastCheckinAgeMin', $state.LastCheckinAgeMin), @('CheckinStale', $state.CheckinStale),
            @('Health', $state.Health), @('HealthRule', $state.HealthRule),
            @('InstalledVersion', $state.InstalledVersion), @('ServerVersion', $state.ServerVersion),
            @('VersionState', $state.VersionState), @('VersionSource', $state.VersionSource),
            @('ClockOffsetMinutes', $state.ClockOffsetMinutes), @('HistorySufficient', $state.HistorySufficient),
            @('RotatedLogsRead', $state.RotatedLogsRead), @('MonitorServiceName', $state.MonitorName),
            @('MonitorState', $state.MonitorState), @('XExitCode', $state.XExitCode), @('XSkipped', $state.XSkipped)
        )) { Set-CSRes $pair[0] $pair[1] }

        Write-CSHeal -Level STATE -Message ('Installed={0} Service={1} Process={2} Monitor={3} LogAge(min)={4} Comms={5} RecentCommsErrMin={6} LastCheckinAge(min)={7} CheckinStale={8} ClockOffset(min)={9}' -f `
            $state.Installed, $state.ServiceStatus, $state.ProcessAlive, $state.MonitorState, $state.LogAgeMinutes, $state.CommsOk, $state.RecentCommsErrMin, $state.LastCheckinAgeMin, $state.CheckinStale, $state.ClockOffsetMinutes)
        Write-CSHeal -Level STATE -Message ('Health={0} ({1}: {2})' -f $state.Health, $state.HealthRule, $state.HealthReason)
        Write-CSHeal -Level STATE -Message ('InstalledVersion={0} (source={1}) ServerVersion={2} VersionState={3}' -f `
            $state.InstalledVersion, $state.VersionSource, $state.ServerVersion, $state.VersionState)

        # Tenant-migration visibility: reinstalling with these creds would re-register.
        $ident = Get-CSTenantIdentity
        $mismatch = $false
        if ($ident.TenantId -and (Test-CSProvidedValue $script:CSH.Cfg.TenantID) -and $ident.TenantId -ne $script:CSH.Cfg.TenantID) { $mismatch = $true }
        if ($ident.CompanyId -and (Test-CSProvidedValue $script:CSH.Cfg.CompanyID) -and $ident.CompanyId -ne $script:CSH.Cfg.CompanyID) { $mismatch = $true }
        Set-CSRes 'TenantMismatch' $mismatch
        if ($mismatch) {
            Write-CSHeal -Level WARN -Message 'Agent is registered to a DIFFERENT company/tenant than the configured credentials - a Reinstall would MIGRATE it.'
        }

        # ---- Liveness recovery: Start-Service (+ settle) before any Reinstall ----
        $recoveredByStart = $false
        $recoveredConfirmed = $false
        if ($state.Health -eq 'Dead' -and $state.ServicePresent) {
            if ($WhatIfPreference) {
                Write-CSHeal -Level WHATIF -Message ('Agent not running but service "{0}" exists.' -f $script:CSH.AgentServiceName)
                Write-CSHeal -Level WHATIF -Message 'Would attempt Start-Service, allow a settle window, then re-evaluate; if it stays down -> Reinstall.'
                Set-CSRes 'RecoveryAttempted' 'WouldAttemptStartService'
            } else {
                Write-CSHeal -Level STEP -Message ('Agent not running but service "{0}" exists -> attempting service-start recovery.' -f $script:CSH.AgentServiceName)
                Set-CSRes 'RecoveryAttempted' 'StartService'
                $startAt = Get-Date
                try { Set-Service -Name $script:CSH.AgentServiceName -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
                try { Start-Service -Name $script:CSH.AgentServiceName -ErrorAction SilentlyContinue } catch { }
                $running = $false
                for ($i = 0; $i -lt 6; $i++) {
                    Start-Sleep -Seconds 2
                    $inv = Get-CSAgentInventory
                    if ($inv.Running) { $running = $true; break }
                }
                Set-CSRes 'RecoveredByStart' $running
                if ($running) {
                    # A freshly started agent has had NO chance to check in - judging
                    # staleness now would reinstall right after a successful lighter
                    # heal. Give it a bounded settle window anchored to the start.
                    Write-CSHeal -Level OK -Message 'Service started - allowing the agent a settle window before judging health.'
                    $settle = Wait-CSPostActionHealth -AnchorTime $startAt `
                                -TimeoutSeconds ([math]::Min($script:CSH.SettleGraceSeconds, $VerifyTimeoutSeconds)) -MaxStartRetries 1
                    Set-CSRes 'StartServiceRetries' $settle.StartRetries
                    if ($settle.Grade -eq 'Confirmed') {
                        $recoveredByStart = $true
                        $recoveredConfirmed = $true
                        $state = Get-CSAgentState
                        Set-CSRes 'Health' $state.Health; Set-CSRes 'HealthRule' $state.HealthRule
                        Set-CSRes 'ServiceStatus' $state.ServiceStatus
                        Write-CSHeal -Level OK -Message 'Agent recovered by service start and confirmed a fresh check-in.'
                    } elseif ($settle.Grade -eq 'XFailed') {
                        Write-CSHeal -Level WARN -Message 'Service started but the -x self-test explicitly failed -> treating as Unhealthy (Reinstall).'
                        $state = $state | Select-Object *   # shallow copy, then override the verdict
                        $state.Health = 'Unhealthy'; $state.HealthRule = 'R3'
                        Set-CSRes 'Health' 'Unhealthy'; Set-CSRes 'HealthRule' 'R3'
                    } elseif ($settle.Grade -eq 'Pending') {
                        # Running but not yet confirmed: recovered-pending. Do NOT
                        # escalate to Reinstall on a start that just succeeded - the
                        # next scheduled run confirms or escalates with history.
                        $recoveredByStart = $true
                        Write-CSHeal -Level WARN -Message 'Service started; a fresh check-in was not confirmed within the settle window - reporting recovery, next run will confirm.'
                        $state = $state | Select-Object *
                        $state.Health = 'Healthy'; $state.HealthRule = 'Rsettle'
                        Set-CSRes 'Health' 'Healthy'; Set-CSRes 'HealthRule' 'Rsettle'
                    } else {
                        # ServiceDown: the agent DIED AGAIN during the settle window
                        # (crash loop). Not recovered - the state stays Dead so the
                        # decision matrix proceeds to Reinstall.
                        Write-CSHeal -Level WARN -Message 'Service died again during the settle window (crash loop?) -> will Reinstall.'
                        Set-CSRes 'RecoveredByStart' $false
                    }
                } else {
                    Write-CSHeal -Level WARN -Message 'Service did not recover after the start attempt -> will Reinstall.'
                }
            }
        } elseif ($state.Health -eq 'Dead') {
            Write-CSHeal -Level WARN -Message 'Agent files present but no service installed -> cannot start; will Reinstall.'
            Set-CSRes 'RecoveryAttempted' 'None-NoService'
        }

        # ---- Decide ----
        # RepairMonitor only when the watchdog service EXISTS but is stopped; a
        # MISSING (unregistered) monitor cannot be fixed by Start-Service and the
        # main agent is healthy, so it is recorded (MonitorState) rather than acted on.
        $actions = @(Resolve-CSHealAction -Health $state.Health -VersionState $state.VersionState `
                        -MonitorDown ($state.MonitorState -eq 'Down'))
        $decision = ('Health={0}; Version={1}; Monitor={2} -> Action={3}' -f $state.Health, $state.VersionState, $state.MonitorState,
                        $(if ($actions.Count -gt 0) { $actions -join '+' } else { 'None' }))
        Set-CSRes 'PlannedAction' $(if ($actions.Count -gt 0) { $actions -join '+' } else { 'None' })
        Set-CSRes 'Decision' $decision
        Write-CSHeal -Level OK -Message ('Decision: {0}' -f $decision)

        if ($actions.Count -eq 0) {
            $noActionOutcome = 'NoActionNeeded'
            if ($recoveredByStart) {
                Write-CSHeal -Level OK -Message 'Agent recovered by service start. No further action.'
                $noActionOutcome = 'RecoveredByServiceStart'
            } elseif ($state.Health -eq 'Healthy' -and $state.VersionState -eq 'Unknown') {
                Write-CSHeal -Level WARN -Message 'Agent is Healthy but the latest version is UNKNOWN (platform did not resolve). Skipping update by design.'
                $noActionOutcome = 'NoAction-VersionUnknown'
            } else {
                Write-CSHeal -Level OK -Message 'Agent is healthy and current. No action required.'
            }
            Set-CSRes 'Outcome' $noActionOutcome
            # Healthy runs are recorded too - a confirmed-Healthy record is what
            # resets the flap-breaker window. A recovered-PENDING start (settle
            # inconclusive) explicitly does NOT count as confirmed.
            if (-not $WhatIfPreference) {
                $confOverride = $null
                if ($noActionOutcome -eq 'RecoveredByServiceStart' -and -not $recoveredConfirmed) { $confOverride = $false }
                $newState = Add-CSHealRunRecord -State $healState -Action 'None' -Outcome $noActionOutcome -ExitCode 0 -ConfirmedOverride $confOverride
                Write-CSHealState -State $newState
            }
            return (Get-CSExitCodeForOutcome $noActionOutcome)
        }

        # ---- Defer gates (transient conditions: retry later, exit 6) ----
        $deferReason = $null; $deferOutcome = $null
        if ($actions -contains 'Reinstall') {
            $cool = Test-CSReinstallCooldown -State $healState
            Set-CSRes 'CooldownActive' $cool.Active
            if ($cool.Active) { $deferReason = $cool.Reason; $deferOutcome = 'Deferred-ReinstallCooldown' }
        }
        if (-not $deferOutcome -and ($actions -contains 'Reinstall' -or $actions -contains 'Update')) {
            $up = Test-CSAgentMidUpgrade
            Set-CSRes 'AgentUpgradeInProgress' $up.InProgress
            if ($up.InProgress) {
                $deferReason = ('Agent appears to be mid-upgrade: {0}.' -f ($up.Reasons -join '; '))
                $deferOutcome = 'Deferred-AgentUpgradeInProgress'
            }
        }
        if (-not $deferOutcome -and ($actions -contains 'Install' -or $actions -contains 'Reinstall' -or $actions -contains 'Update')) {
            $rb = Test-CSRebootPendingForAgent
            Set-CSRes 'RebootPending' $rb
            if ($rb) {
                $deferReason = 'A pending file-rename operation touches the agent directory - reboot required before acting.'
                $deferOutcome = 'Deferred-RebootPending'
            }
            $msiBusy = Test-CSMsiMutexBusy
            Set-CSRes 'MsiMutexBusy' $msiBusy
            if ($msiBusy) { Write-CSHeal -Level WARN -Message 'Windows Installer is busy (courtesy note only - the agent has no MSI).' }
        }
        if ($deferOutcome) {
            Set-CSRes 'DeferReason' $deferReason
            if ($WhatIfPreference) {
                Write-CSHeal -Level WHATIF -Message ('A real run would DEFER: {0}' -f $deferReason)
                Set-CSRes 'Outcome' 'WhatIf-WouldDefer'
                return (Get-CSExitCodeForOutcome 'WhatIf-WouldDefer')
            }
            Write-CSHeal -Level WARN -Message ('Deferred: {0}' -f $deferReason)
            Set-CSRes 'Outcome' $deferOutcome
            # Deliberately NOT recorded in state.json: a deferred run changes
            # nothing, and recording it would let cooldown deferrals crowd the
            # very reinstall history the cooldown is counting.
            return (Get-CSExitCodeForOutcome $deferOutcome)
        }

        # ---- Preconditions ----
        Write-CSHeal -Level STEP -Message ('Checking preconditions for "{0}"...' -f ($actions -join '+'))
        $pre = Test-CSActionPreconditions -Actions $actions
        Set-CSRes 'PreconditionsOk' $pre.Ok
        Set-CSRes 'PreconditionReasons' $pre.Reasons
        foreach ($r in $pre.Reasons) {
            if ($r.Ok) { Write-CSHeal -Level OK   -Message ('  precondition OK : {0}' -f $r.Text) }
            else       { Write-CSHeal -Level WARN -Message ('  precondition X  : {0}' -f $r.Text) }
        }
        if (-not $pre.Ok) {
            if ($WhatIfPreference) {
                Write-CSHeal -Level WHATIF -Message ('Preconditions not satisfied; a real run would ABORT "{0}".' -f ($actions -join '+'))
                Set-CSRes 'Outcome' 'WhatIf-WouldAbort'
                return (Get-CSExitCodeForOutcome 'WhatIf-WouldAbort')   # exit 2: dry runs must reveal misconfig
            }
            Write-CSHeal -Level ERROR -Message ('Preconditions not satisfied; aborting "{0}".' -f ($actions -join '+'))
            Set-CSRes 'Outcome' 'AbortedPreconditions'
            $newState = Add-CSHealRunRecord -State $healState -Action ($actions -join '+') -Outcome 'AbortedPreconditions' -ExitCode 2
            Write-CSHealState -State $newState
            return (Get-CSExitCodeForOutcome 'AbortedPreconditions')
        }

        # ---- Execute ----
        if ($WhatIfPreference) { Write-CSHeal -Level WHATIF -Message ('Preconditions satisfied. Steps that WOULD run for "{0}":' -f ($actions -join '+')) }
        else                   { Write-CSHeal -Level STEP   -Message ('Performing "{0}"...' -f ($actions -join '+')) }

        $majorAction = $null
        foreach ($a in $actions) { if ($a -in @('Install', 'Reinstall', 'Update')) { $majorAction = $a } }
        $actionStart = Get-Date
        Set-CSRes 'ActionStartTime' $actionStart.ToString('o')

        try {
            foreach ($a in $actions) {
                switch ($a) {
                    'RepairMonitor' {
                        $repaired = Repair-CSAgentMonitor
                        Set-CSRes 'MonitorRepaired' ([bool]$repaired)
                        if (-not $WhatIfPreference) {
                            if ($repaired) { Write-CSHeal -Level OK   -Message 'Monitor (watchdog) service repaired and running.' }
                            else           { Write-CSHeal -Level WARN -Message 'Monitor service did not reach Running - recorded; the main agent is healthy so no escalation.' }
                        }
                    }
                    'Install'   { Invoke-CSAgentInstallAction   | Out-Null }
                    'Reinstall' { Invoke-CSAgentReinstallAction | Out-Null }
                    'Update'    { Update-CSAgentInPlace         | Out-Null }
                }
            }
        } catch {
            # Staging failures (download/validate) happen BEFORE anything
            # destructive: the agent is untouched, and the flap-breaker must not
            # count such a run as a real reinstall.
            $failOutcome = if ($script:CSHDestructiveStarted) { 'ActionFailed' } else { 'ActionFailed-Staging' }
            $touch = if ($script:CSHDestructiveStarted) { '' } else { ' during staging (agent untouched)' }
            Write-CSHeal -Level ERROR -Message ('Action "{0}" failed{1}: {2}' -f ($actions -join '+'), $touch, $_.Exception.Message)
            Set-CSRes 'Outcome' $failOutcome
            $newState = Add-CSHealRunRecord -State $healState -Action ($actions -join '+') -Outcome $failOutcome -ExitCode 3
            Write-CSHealState -State $newState
            return (Get-CSExitCodeForOutcome $failOutcome)
        }

        if ($WhatIfPreference) {
            Write-CSHeal -Level WHATIF -Message 'Dry run complete - no changes were made.'
            Set-CSRes 'Outcome' 'WhatIf-WouldRun'
            return (Get-CSExitCodeForOutcome 'WhatIf-WouldRun')
        }

        # ---- Monitor-repair-only run: verified inline, nothing else to verify ----
        if (-not $majorAction) {
            # Honest outcome: only claim Repaired-Monitor when the watchdog actually
            # reached Running; otherwise the (healthy) agent run is NoActionNeeded
            # with MonitorState/MonitorRepaired recording the residual problem.
            $monOutcome = if ($script:CSHRes['MonitorRepaired']) { 'Repaired-Monitor' } else { 'NoActionNeeded' }
            Set-CSRes 'Outcome' $monOutcome
            $newState = Add-CSHealRunRecord -State $healState -Action 'RepairMonitor' -Outcome $monOutcome -ExitCode 0
            Write-CSHealState -State $newState
            return (Get-CSExitCodeForOutcome $monOutcome)
        }

        # ---- Verify (anchored to the action start; cheap polls; -x once) ----
        Write-CSHeal -Level STEP -Message ('Verifying result (up to {0}s for the agent to settle; only POST-action check-ins count)...' -f $VerifyTimeoutSeconds)
        $verify = Wait-CSPostActionHealth -AnchorTime $actionStart -TimeoutSeconds $VerifyTimeoutSeconds -MaxStartRetries 2
        Set-CSRes 'StartServiceRetries' $verify.StartRetries
        Set-CSRes 'PostCheckinAgeMin' $verify.PostCheckinAgeMin
        if ($null -ne $verify.XExitCode) { Set-CSRes 'XExitCode' $verify.XExitCode }

        $postInv = Get-CSAgentInventory
        Set-CSRes 'PostServiceStatus' $postInv.ServiceStatus
        $postVer = Get-CSInstalledVersion
        Set-CSRes 'PostInstalledVersion' $postVer.Version

        # Update has an extra success requirement: the binary must actually be the
        # staged version (a swap that silently failed must not read as success).
        # Only the swapped binary's OWN answer (--version) may fail this gate: the
        # registry/dependency.json fallbacks are provably stale right after an
        # in-place swap, and failing on them would false-alarm a successful update.
        $updateVersionOk = $true
        if ($majorAction -eq 'Update') {
            $dl = Resolve-CSAgentDownload
            $want = ConvertTo-CSVersion3 $(if ($dl) { $dl.Version } else { $null })
            $have = ConvertTo-CSVersion3 $postVer.Version
            if ($want -and $have -and $postVer.Source -eq 'ExeVersionFlag' -and $have -ne $want) { $updateVersionOk = $false }
        }

        $grade = $verify.Grade
        Set-CSRes 'PostHealth' $(switch ($grade) {
            'Confirmed'   { 'Healthy' }
            'Pending'     { 'Unconfirmed' }
            'XFailed'     { 'Unhealthy' }
            'ServiceDown' { 'Dead' }
        })
        Write-CSHeal -Level STATE -Message ('Post-action: Grade={0} Service={1} Version={2} PostCheckinAge(min)={3} StartRetries={4}' -f `
            $grade, $postInv.ServiceStatus, $postVer.Version, $verify.PostCheckinAgeMin, $verify.StartRetries)

        $outcome = $null
        if ($grade -eq 'Confirmed' -and $updateVersionOk) {
            Write-CSHeal -Level OK -Message ('"{0}" completed successfully - agent is Healthy and reporting to the platform.' -f $majorAction)
            $outcome = ('Success:{0}' -f $majorAction)
        } elseif ($grade -eq 'Confirmed' -and -not $updateVersionOk) {
            Write-CSHeal -Level ERROR -Message ('Update ran and the agent reports in, but the binary version is NOT the staged one - the swap did not take effect.')
            $outcome = 'ActionVerificationFailed'
        } elseif ($grade -eq 'Pending') {
            Write-CSHeal -Level WARN -Message ('"{0}" applied and the agent is running, but a post-action check-in was not confirmed within {1}s - likely still completing its first check-in. Re-run to confirm.' -f $majorAction, $VerifyTimeoutSeconds)
            $outcome = ('SuccessPending:{0}' -f $majorAction)
        } elseif ($grade -eq 'XFailed') {
            Write-CSHeal -Level ERROR -Message ('"{0}" ran but the post-action -x self-test explicitly failed - the action did not fix portal comms.' -f $majorAction)
            $outcome = 'ActionVerificationFailed'
        } else {
            Write-CSHeal -Level ERROR -Message ('"{0}" ran but the agent is not running afterwards (after {1} Start-Service retries); verification failed.' -f $majorAction, $verify.StartRetries)
            $outcome = 'ActionVerificationFailed'
        }
        Set-CSRes 'Outcome' $outcome
        $code = Get-CSExitCodeForOutcome $outcome
        $newState = Add-CSHealRunRecord -State $healState -Action $majorAction -Outcome $outcome -ExitCode $code
        Write-CSHealState -State $newState
        return $code
    }
    #endregion

    #region Run (returns the code - console/RMM-session safe; 'exit' lives only in the -File guard)
    Initialize-CSHealContext

    $code = 3
    try {
        $code = Invoke-CSHealCore
    } catch {
        try { Write-CSHeal -Level ERROR -Message ('Unhandled error: {0}' -f $_.Exception.Message) } catch { }
        Set-CSRes 'Outcome' 'Error'
        $code = 3
    } finally {
        Set-CSRes 'ExitCode' $code
        Write-CSHealResult

        # Staged installer is large (~35 MB) - never leave it behind.
        try {
            if (Test-Path -LiteralPath $script:CSH.StageDir) {
                Remove-Item -LiteralPath $script:CSH.StageDir -Recurse -Force -WhatIf:$false -ErrorAction Stop
            }
        } catch { }
        # Transient working dir: removed unless -Debug captured into DebugRoot.
        if (-not $script:CSHDebugMode -and $script:CSH.TempDir) {
            try {
                if (Test-Path -LiteralPath $script:CSH.TempDir) {
                    Remove-Item -LiteralPath $script:CSH.TempDir -Recurse -Force -WhatIf:$false -ErrorAction Stop
                }
            } catch { }
        }
        if ($script:CSH.Mutex) {
            if ($script:CSH.MutexAcquired) { try { $script:CSH.Mutex.ReleaseMutex() } catch { } }
            try { $script:CSH.Mutex.Dispose() } catch { }
        }
        if (-not $Silent) {
            Write-Host ''
            Write-Host ('Self-heal finished. Outcome={0} ExitCode={1}' -f $script:CSHRes['Outcome'], $code) -ForegroundColor Cyan
        }
    }
    return $code
    #endregion
}

# ---------------------------------------------------------------------
# Auto-run guard - the ONLY top-level executable code in this file.
#   - Direct -File execution (e.g. a Datto RMM component): auto-runs the
#     heal and exits with the result code.
#   - Pasted into a console / RMM remote PowerShell session, or delivered
#     via IEX: defines everything, runs NOTHING, prints a hint. Call
#     Invoke-CSAgentSelfHeal yourself; it RETURNS the exit code and never
#     kills your session.
#   - CS_SELFHEAL_AUTORUN=1  forces auto-run for exotic delivery methods.
#   - CS_SELFHEAL_NOAUTORUN=1 suppresses auto-run (used by tests).
# ---------------------------------------------------------------------
#region Auto-run guard
if ($env:CS_SELFHEAL_NOAUTORUN -ne '1') {
    $csshIsDotSourced = ($MyInvocation.InvocationName -eq '.')
    $csshViaFile      = [bool]$PSCommandPath
    if (-not $csshIsDotSourced) {
        if ($csshViaFile -or $env:CS_SELFHEAL_AUTORUN -eq '1') {
            # The guard runs OUTSIDE the function's strict-mode/EAP scope: without
            # this try/catch an invocation failure (e.g. a mistyped parameter name
            # binding against @args) would leave $csshRc unset and 'exit $csshRc'
            # would report exit 0 - a silent false success to the RMM.
            $csshRc = 3
            try {
                $csshRc = Invoke-CSAgentSelfHeal @args
            } catch {
                Write-Host ('CS-Agent-SelfHeal failed to start: {0}' -f $_.Exception.Message) -ForegroundColor Red
                Write-Host ('CSSH-RESULT|{"ToolVersion":"2.0.0","Outcome":"Error","ExitCode":3,"Note":"invocation failure before the run started (bad parameters?)"}')
                $csshRc = 3
            }
            if ($null -eq $csshRc -or $csshRc -isnot [int]) { $csshRc = 3 }
            exit $csshRc
        }
        Write-Host 'CS-Agent-SelfHeal v2 loaded (nothing was run).' -ForegroundColor Cyan
        Write-Host 'Run:  $rc = Invoke-CSAgentSelfHeal -WhatIf     # dry run, returns the exit code' -ForegroundColor Cyan
        Write-Host '      $rc = Invoke-CSAgentSelfHeal             # real heal (your session survives)' -ForegroundColor Cyan
    }
}
#endregion
$rc = Invoke-CSAgentSelfHeal