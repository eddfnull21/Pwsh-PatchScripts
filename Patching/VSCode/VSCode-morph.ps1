# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    VS Code (machine-wide) - Check / Update / Migrate. Paste-and-run.

.DESCRIPTION
    One script, three modes, chosen in the ENTRY POINT at the bottom:

      Check    DEFAULT. Read-only. Asks the official VS Code update API for the latest
               release and compares it with the machine-wide System Setup; lists every
               profile's per-user User Setup. Downloads nothing, prompts nobody.
      Update   Updates machine-wide VS Code in place (InstallIfMissing to install it).
               Downloads with BITS, verifies SHA-256 and the Microsoft signature. If VS
               Code is running, CloseApps asks each affected user (WTS Yes/No prompt)
               before closing it; no answer = no.
      Migrate  Installs/updates System Setup, then asks each user with a per-user
               User Setup for consent and removes it through a limited task running as
               that user. Settings and extensions are kept.

    Options go in -Options as a hashtable; they are Update-VSCode's parameters:
    Channel (stable|insider), Force, InstallIfMissing, CloseApps, KeepInstaller, Live,
    LiveIntervalSeconds, MergeTasks, ConsentTimeoutSeconds, UninstallTimeoutSeconds,
    UserSid, BitsPriority, WhatIf. WhatIf performs no downloads, prompts or changes.

.EXAMPLE
    Paste the WHOLE script into an elevated console or an RMM component after editing
    the ENTRY POINT at the bottom:

    Invoke-VSCode                                                   # Check
    Invoke-VSCode -Mode Update  -Options @{ CloseApps = $true; Live = $true }
    Invoke-VSCode -Mode Migrate -Options @{ CloseApps = $true; Live = $true; WhatIf = $true }

    After a paste Update-VSCode stays loaded and can be called directly for objects.

.NOTES
    Exit codes (Invoke-VSCode returns one; the entry point exits with it only when $RMM = $true):
        0     OK: up to date / updated / installed / migrated / WhatIf preview
        1     Unexpected error (download, hash, signature, installer failure, ...)
        2     Check: action needed (update available or per-user User Setups found)
        3     Migrate: System Setup not ready, or a user's removal failed
        4     Deferred: VS Code in use, a user declined/no answer, session changed,
              or a user migration is still pending - rerun later
        3010  Reboot required to finish
        10    Update/Migrate need an elevated or SYSTEM session

    Built from 000_AO_nsvscode.ps1 (Update-VSCode, verbatim). The earlier Omega
    patcher/converter generations it superseded are in OLD\ with -old-stable.
#>

#region -------------------- Update-VSCode (update + User Setup -> System Setup migration) --------------------

function Update-VSCode {
    <#
    .SYNOPSIS
        Updates machine-wide VS Code; optionally migrates standard User Setups.

    .DESCRIPTION
        Run in standalone elevated Windows PowerShell 5.1 or PowerShell 7.
        Requires BitsTransfer; migration also requires ScheduledTasks.

        -Live prints timestamped status and elapsed time, including during
        blocking consent prompts and installer waits. Downloads show actual
        transferred bytes and percentage when the total size is available.

        The heartbeat indicates the current operation is still being awaited;
        it does not imply that an installer is making measurable progress.
        Live output goes directly to the console, leaving result objects clean.

        -CloseApps requests consent before closing machine-wide VS Code.
        -Migrate verifies System Setup before requesting each user's consent
        to remove their User Setup using a limited owner-context task.

        Settings/extensions are retained. Custom installation paths are excluded.
        No response or timeout declines consent. Timed-out tasks are retained.
        -Force can downgrade System Setup but never bypasses consent.
        -WhatIf performs no downloads, consent prompts, closing, or installation.

        Windows execution has not been tested in this environment.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Update')]
    param(
        [ValidateSet('stable', 'insider')]
        [string]$Channel = 'stable',

        [Parameter(Mandatory, ParameterSetName = 'Migrate')]
        [switch]$Migrate,

        [Parameter(ParameterSetName = 'Migrate')]
        [ValidatePattern('^S-1-\d+(?:-\d+)+$')]
        [string[]]$UserSid,

        [Parameter(ParameterSetName = 'Update')]
        [switch]$Force,

        [Parameter(ParameterSetName = 'Update')]
        [switch]$InstallIfMissing,

        [switch]$CloseApps,
        [switch]$KeepInstaller,
        [switch]$Live,

        [ValidateRange(1, 60)]
        [int]$LiveIntervalSeconds = 2,

        [ValidatePattern('^!?[a-z]+(?:,!?[a-z]+)*$')]
        [string]$MergeTasks = '!runcode',

        [ValidateRange(1, 600)]
        [int]$ConsentTimeoutSeconds = 60,

        [Parameter(ParameterSetName = 'Migrate')]
        [ValidateRange(30, 1800)]
        [int]$UninstallTimeoutSeconds = 300,

        [ValidateSet('Foreground', 'High', 'Normal', 'Low')]
        [string]$BitsPriority = 'Foreground'
    )

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Update-VSCode requires Windows.'
    }

    # A native timer keeps the heartbeat alive even when PowerShell is blocked.
    # No background PowerShell job or additional public function is required.
    if (-not ('VSCodeMaintenance.LiveSupportV2' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VSCodeMaintenance {
    public static class LiveSupportV2 {
        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSSendMessageW(
            IntPtr server, uint session,
            string title, uint titleBytes,
            string message, uint messageBytes,
            uint style, uint timeout, out uint response,
            [MarshalAs(UnmanagedType.Bool)] bool wait);

        [DllImport("wtsapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformationW(
            IntPtr server, uint session, int infoClass,
            out IntPtr buffer, out uint bytes);

        [DllImport("wtsapi32.dll", ExactSpelling = true)]
        private static extern void WTSFreeMemory(IntPtr buffer);

        public static bool Ask(
            int sessionId, string title, string message, int timeout) {
            uint session = sessionId < 0
                ? WTSGetActiveConsoleSessionId()
                : (uint)sessionId;

            if (session == UInt32.MaxValue || session == 0) return false;

            IntPtr buffer;
            uint bytes;
            if (!WTSQuerySessionInformationW(
                IntPtr.Zero, session, 8, out buffer, out bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try {
                // WTSConnectState = 8; WTSActive = 0.
                if (bytes < 4 || Marshal.ReadInt32(buffer) != 0) return false;
            }
            finally {
                WTSFreeMemory(buffer);
            }

            // YESNO | ICONQUESTION | DEFBUTTON2 (No) | SETFOREGROUND.
            const uint style = 0x4 | 0x20 | 0x100 | 0x10000;
            uint response;

            if (!WTSSendMessageW(
                IntPtr.Zero, session,
                title, (uint)Encoding.Unicode.GetByteCount(title),
                message, (uint)Encoding.Unicode.GetByteCount(message),
                style, (uint)timeout, out response, true))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return response == 6;
        }

        public sealed class Watcher : IDisposable {
            private readonly object gate = new object();
            private readonly Stopwatch total = Stopwatch.StartNew();
            private readonly Stopwatch step = Stopwatch.StartNew();
            private readonly Timer timer;
            private string state = "Starting";
            private bool disposed;

            public Watcher(int intervalMilliseconds) {
                timer = new Timer(
                    Tick, null, intervalMilliseconds, intervalMilliseconds);
            }

            // Update measured progress without restarting the step clock.
            public string State {
                get { lock (gate) { return state; } }
                set { lock (gate) { state = value; } }
            }

            public void Step(string message) {
                lock (gate) {
                    if (disposed) return;
                    state = message;
                    step.Restart();
                    Emit();
                }
            }

            private void Tick(object unused) {
                lock (gate) {
                    if (!disposed) Emit();
                }
            }

            private void Emit() {
                try {
                    Console.WriteLine(
                        "[{0:HH:mm:ss}] total {1:0}s | step {2:0}s | {3}",
                        DateTime.Now,
                        total.Elapsed.TotalSeconds,
                        step.Elapsed.TotalSeconds,
                        state);
                }
                catch {
                    // Console output must never crash maintenance.
                }
            }

            public void Dispose() {
                lock (gate) {
                    if (disposed) return;
                    disposed = true;
                    timer.Dispose();
                    // Already queued callbacks see disposed before writing.
                }
            }
        }
    }
}
'@
    }

    $watcher = $null
    if ($Live) {
        $watcher = [VSCodeMaintenance.LiveSupportV2+Watcher]::new(
            $LiveIntervalSeconds * 1000)
    }

    # Private scriptblocks keep this as a single PowerShell function.
    $report = {
        param([string]$Message)
        if ($null -ne $watcher) {
            $watcher.Step($Message)
        }
        Write-Verbose $Message
    }

    $askConsent = {
        param(
            [string]$Title,
            [string]$Message,
            [int]$SessionId,
            [int]$TimeoutSeconds
        )

        & $report "Waiting for consent: session $SessionId; timeout ${TimeoutSeconds}s."
        try {
            $approved = [VSCodeMaintenance.LiveSupportV2]::Ask(
                $SessionId, $Title, $Message, $TimeoutSeconds)
            & $report "Consent for session ${SessionId}: $approved."
            return $approved
        }
        catch {
            Write-Warning "Unable to obtain consent for session ${SessionId}: $($_.Exception.Message)"
            return $false
        }
    }

    $readInsidersProduct = {
        param([string]$Directory)

        $launcher = Join-Path $Directory 'bin\code-insiders.cmd'
        $launcherText = Get-Content -LiteralPath $launcher -Raw
        $match = [regex]::Match(
            $launcherText,
            '(?i)%~dp0\.\.\\(?<folder>[^"\r\n]*?)resources\\app\\out\\cli\.js')

        if (-not $match.Success) {
            throw "Cannot resolve the installed Insiders resources from $launcher."
        }

        $relative = $match.Groups['folder'].Value + 'resources\app\product.json'
        $path = [IO.Path]::GetFullPath((Join-Path $Directory $relative))

        if (-not $path.StartsWith(
            $Directory.TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Insiders metadata is outside its installation directory.'
        }

        $product = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]$product.commit -notmatch '^[a-f0-9]{40}$' -or -not $product.date) {
            throw "Insiders build metadata is incomplete: $path"
        }

        return $product
    }

    $updateSystem = {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$Channel,
            [switch]$Force,
            [switch]$CloseApps,
            [switch]$InstallIfMissing,
            [switch]$KeepInstaller,
            [string]$MergeTasks,
            [int]$ConsentTimeoutSeconds,
            [string]$BitsPriority
        )

        & $report "Inspecting machine-wide VS Code ($Channel)."

        $exe = if ($Channel -eq 'insider') { 'Code - Insiders.exe' } else { 'Code.exe' }
        $dir = if ($Channel -eq 'insider') { 'Microsoft VS Code Insiders' } else { 'Microsoft VS Code' }
        $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
        $root = Join-Path $programFiles $dir
        $exePath = Join-Path $root $exe
        $rootPrefix = $root.TrimEnd('\') + '\'

        $result = [pscustomobject][ordered]@{
            Channel          = $Channel
            Path             = $exePath
            Status           = 'NotInstalled'
            PreviousVersion  = $null
            TargetVersion    = $null
            InstalledVersion = $null
            RebootRequired   = $false
            ExitCode         = $null
            InstallerPath    = $null
        }

        $exists = Test-Path -LiteralPath $exePath -PathType Leaf
        if (-not $exists -and -not $InstallIfMissing) {
            & $report "System: NotInstalled ($exePath). Use -InstallIfMissing to install."
            return $result
        }

        $readInstalledBuild = {
            $versionText = [Diagnostics.FileVersionInfo]::GetVersionInfo($exePath).ProductVersion
            if ($versionText -notmatch '^(\d+\.\d+\.\d+)') {
                throw "Cannot read the installed version from $exePath."
            }

            $numericVersion = [version]$Matches[1]
            $product = if ($Channel -eq 'insider') {
                & $readInsidersProduct $root
            }
            else {
                $null
            }

            [pscustomobject]@{
                Text    = $versionText.Trim()
                Version = $numericVersion
                Product = $product
            }
        }

        $findInstallProcesses = {
            foreach ($candidate in (Get-CimInstance Win32_Process -Filter "Name = '$exe'")) {
                if (-not $candidate.ExecutablePath) {
                    throw "Cannot determine the path of VS Code process $($candidate.ProcessId)."
                }
                if ($candidate.ExecutablePath.StartsWith(
                    $rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $candidate
                }
            }
        }

        $installed = if ($exists) {
            & $readInstalledBuild
        }
        else {
            [pscustomobject]@{
                Text = 'Not installed'
                Version = [version]'0.0.0'
                Product = $null
            }
        }

        if ($exists) {
            $result.PreviousVersion = $result.InstalledVersion = $installed.Text
        }

        # Match the installed executable's architecture, not the PowerShell host.
        if ($exists) {
            $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($exePath))
            try {
                if ($reader.ReadUInt16() -ne 0x5A4D) {
                    throw 'Invalid executable header.'
                }
                $reader.BaseStream.Position = 0x3C
                $peOffset = $reader.ReadInt32()
                $reader.BaseStream.Position = $peOffset
                if ($reader.ReadUInt32() -ne 0x4550) {
                    throw 'Invalid PE signature.'
                }
                $architecture = switch ($reader.ReadUInt16()) {
                    0x8664 { 'x64' }
                    0xAA64 { 'arm64' }
                    default {
                        throw 'Only existing x64 and ARM64 installations are supported.'
                    }
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        else {
            $architecture = switch (
                (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
            ) {
                9  { 'x64' }
                12 { 'arm64' }
                default { throw 'Only x64 and ARM64 Windows are supported.' }
            }
        }

        & $report "Checking the latest $Channel release for $architecture."

        $oldTls = [Net.ServicePointManager]::SecurityProtocol
        try {
            if ($PSVersionTable.PSVersion.Major -lt 6 -and [int]$oldTls -ne 0) {
                [Net.ServicePointManager]::SecurityProtocol =
                    $oldTls -bor [Net.SecurityProtocolType]::Tls12
            }

            $release = Invoke-RestMethod -TimeoutSec 30 -Uri (
                "https://update.code.visualstudio.com/api/update/win32-$architecture/$Channel/latest"
            )
        }
        finally {
            [Net.ServicePointManager]::SecurityProtocol = $oldTls
        }

        if ([string]$release.productVersion -notmatch '^(\d+\.\d+\.\d+)(?:-insider)?$') {
            throw 'The update API returned an invalid product version.'
        }

        $latestVersion = [version]$Matches[1]
        $result.TargetVersion = [string]$release.productVersion
        $downloadUri = [uri]$release.url

        if (-not $downloadUri.IsAbsoluteUri -or
            $downloadUri.Scheme -ne 'https' -or
            [string]$release.sha256hash -notmatch '^[a-f0-9]{64}$' -or
            [string]$release.version -notmatch '^[a-f0-9]{40}$') {
            throw 'The update API returned invalid installer metadata.'
        }

        & $report "Installed: $($installed.Text) | Latest: $($release.productVersion) | $architecture."

        $current = $installed.Version -ge $latestVersion
        if ($Channel -eq 'insider' -and $installed.Version -eq $latestVersion -and -not $Force) {
            $current = $installed.Product.commit -eq $release.version
            if (-not $current) {
                $buildDate = [DateTimeOffset]::Parse($installed.Product.date)
                $releaseDate = [DateTimeOffset]::FromUnixTimeMilliseconds(
                    [long]$release.timestamp)
                $current = $buildDate -gt $releaseDate
            }
        }

        if ($current -and -not $Force) {
            $result.Status = 'CurrentOrNewer'
            & $report "System: $($result.Status)."
            return $result
        }

        $action = "Update VS Code $($installed.Text) -> $($release.productVersion)"
        if ($CloseApps) {
            $action += '; close running VS Code only with affected users'' consent'
        }

        & $report 'Checking approval to update System Setup.'
        if (-not $PSCmdlet.ShouldProcess($exePath, $action)) {
            $result.Status = 'NotExecuted'
            & $report "System: $($result.Status)."
            return $result
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            if (-not $principal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)) {
                throw 'Run this function in elevated PowerShell or as SYSTEM.'
            }
        }
        finally {
            $identity.Dispose()
        }

        & $report 'Checking running machine-wide VS Code processes.'
        if (@(& $findInstallProcesses).Count -gt 0 -and -not $CloseApps) {
            Write-Warning 'VS Code is running. Close it or use -CloseApps to request user consent.'
            $result.Status = 'InUse'
            & $report "System: $($result.Status)."
            return $result
        }

        $stage = Join-Path $programFiles ('VSCodeUpdate-' + [guid]::NewGuid().ToString('N'))
        $created = $false
        $verified = $false
        $bitsJob = $null

        try {
            & $report 'Creating a protected installer staging directory.'
            $null = New-Item -ItemType Directory -Path $stage -Confirm:$false
            $created = $true

            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
                $acl.AddAccessRule(
                    [Security.AccessControl.FileSystemAccessRule]::new(
                        [Security.Principal.SecurityIdentifier]::new($sid),
                        'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            }
            Set-Acl -LiteralPath $stage -AclObject $acl -Confirm:$false

            $setup = Join-Path $stage 'setup.exe'
            Import-Module BitsTransfer
            & $report "Downloading VS Code $($release.productVersion)."

            # Asynchronous BITS allows actual progress to be observed.
            $bitsJob = Start-BitsTransfer -Source $downloadUri.AbsoluteUri `
                -Destination $setup -Priority $BitsPriority -Asynchronous `
                -RetryInterval 60 -RetryTimeout 300 `
                -Description "VS Code $Channel $($release.productVersion)" `
                -Confirm:$false

            while ($true) {
                $bitsJob = Get-BitsTransfer -JobId $bitsJob.JobId
                $state = [string]$bitsJob.JobState

                if ($null -ne $watcher) {
                    $downloaded = [double]$bitsJob.BytesTransferred
                    $total = [double]$bitsJob.BytesTotal
                    $detail = '{0:N1} MiB received' -f ($downloaded / 1MB)

                    # BITS uses UInt64.MaxValue when the total is unknown.
                    if ($total -gt 0 -and $total -lt [double][uint64]::MaxValue) {
                        $detail = '{0:N1}/{1:N1} MiB ({2:N1}%)' -f (
                            $downloaded / 1MB), ($total / 1MB),
                            ([Math]::Min(100, 100 * $downloaded / $total))
                    }

                    $watcher.State = "Download: $state | $detail"
                }

                if ($state -eq 'Transferred') {
                    Complete-BitsTransfer -BitsJob $bitsJob -Confirm:$false
                    $bitsJob = $null
                    break
                }

                if ($state -in 'Error', 'Cancelled', 'Suspended', 'Acknowledged') {
                    throw "BITS download stopped: $state. $($bitsJob.ErrorDescription)"
                }

                # TransientError is retried by BITS according to RetryTimeout.
                Start-Sleep -Milliseconds 500
            }

            & $report 'Verifying installer SHA-256.'
            if ((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -ne $release.sha256hash) {
                throw 'Installer SHA-256 does not match the selected release.'
            }

            & $report 'Verifying the Microsoft installer signature.'
            $signature = Get-AuthenticodeSignature -LiteralPath $setup
            if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
                $signature.SignerCertificate.Subject -notmatch
                    '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
                throw "Installer failed Microsoft signature validation: $($signature.Status)."
            }

            $verified = $true
            if ($KeepInstaller) {
                $result.InstallerPath = $setup
            }

            & $report 'Rechecking running VS Code processes.'
            $running = @(& $findInstallProcesses)
            if ($running.Count -gt 0) {
                if (-not $CloseApps) {
                    $result.Status = 'InUse'
                    & $report "System: $($result.Status)."
                    return $result
                }

                $approvedSessions = @($running.SessionId | Sort-Object -Unique)
                $approvedOwners = @{}
                foreach ($candidate in $running) {
                    $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
                    if ($owner.ReturnValue -ne 0) {
                        throw 'Cannot identify the user who must consent.'
                    }
                    $approvedOwners[[int]$candidate.SessionId] = $owner.Sid
                }

                $message = "A VS Code update is ready.`r`n`r`n" +
                    'Save your files and finish any terminal tasks before clicking Yes. ' +
                    'Yes will force-close all VS Code windows from this installation in your session. ' +
                    "Unsaved work and running tasks may be lost.`r`n`r`n" +
                    'Close VS Code and install the update now? No or no response skips this update.'

                # Collect every approval before closing any editor.
                foreach ($session in $approvedSessions) {
                    if (-not (& $askConsent -Title 'VS Code update' -Message $message `
                        -TimeoutSeconds $ConsentTimeoutSeconds -SessionId $session)) {
                        $result.Status = 'ConsentDeclined'
                        & $report "System: $($result.Status)."
                        return $result
                    }
                }

                & $report 'Revalidating sessions and process owners after consent.'
                $running = @(& $findInstallProcesses)
                if (@($running | Where-Object {
                    $_.SessionId -notin $approvedSessions
                }).Count -gt 0) {
                    $result.Status = 'SessionChanged'
                    & $report "System: $($result.Status)."
                    return $result
                }

                foreach ($candidate in $running) {
                    $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
                    if ($owner.ReturnValue -ne 0 -or
                        $owner.Sid -ne $approvedOwners[[int]$candidate.SessionId]) {
                        $result.Status = 'SessionChanged'
                        & $report "System: $($result.Status)."
                        return $result
                    }
                }

                & $report "Closing $($running.Count) approved VS Code process(es)."
                foreach ($candidate in $running) {
                    $process = Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue
                    if (-not $process) { continue }

                    try {
                        if ($process.HasExited) { continue }

                        if ($process.Path -ne $candidate.ExecutablePath -or
                            $process.SessionId -ne $candidate.SessionId -or
                            [Math]::Abs(
                                ($process.StartTime.ToUniversalTime() -
                                 $candidate.CreationDate.ToUniversalTime()).TotalMilliseconds
                            ) -gt 1) {
                            throw 'The running process changed while consent was being obtained.'
                        }

                        try { $process.Kill() }
                        catch { if (-not $process.HasExited) { throw } }

                        if (-not $process.WaitForExit(10000)) {
                            throw "VS Code process $($candidate.ProcessId) did not exit."
                        }
                    }
                    finally {
                        $process.Dispose()
                    }
                }
            }

            if (@(& $findInstallProcesses).Count -gt 0) {
                throw 'VS Code is still running or restarted; installation was cancelled.'
            }

            $arguments = @(
                '/VERYSILENT', '/SUPPRESSMSGBOXES', '/SP-', '/NORESTART',
                '/RESTARTEXITCODE=3010', '/NOCLOSEAPPLICATIONS', '/NORESTARTAPPLICATIONS',
                ('/MERGETASKS={0},!runcode' -f $MergeTasks),
                '/LOG',
                ('/DIR="{0}"' -f $root)
            )

            # Keep Start-Process -Wait semantics, including its process-tree wait.
            # The native watcher continues printing while this call blocks.
            & $report "Installing VS Code $($release.productVersion); waiting for Setup to finish."
            $installer = Start-Process -FilePath $setup `
                -ArgumentList $arguments -Wait -PassThru
            try {
                $exitCode = $installer.ExitCode
            }
            finally {
                $installer.Dispose()
            }

            $result.ExitCode = $exitCode
            & $report "Installer finished with exit code $exitCode."

            if ($exitCode -notin 0, 3010) {
                throw "VS Code installer exited with $exitCode. See its Setup log in the run account's TEMP directory."
            }

            if ($exitCode -eq 3010) {
                $result.Status = 'RebootRequired'
                $result.RebootRequired = $true
                $result.InstalledVersion = $null
                Write-Warning 'Installation requires a reboot. No reboot was initiated.'
            }
            else {
                & $report 'Verifying the installed version and build.'
                $after = & $readInstalledBuild
                $result.InstalledVersion = $after.Text

                if ($after.Version -ne $latestVersion -or
                    ($Channel -eq 'insider' -and $after.Product.commit -ne $release.version)) {
                    throw 'Installer returned success, but the expected version/build is not installed.'
                }

                $result.Status = if ($exists) { 'Updated' } else { 'Installed' }
            }

            & $report "System: $($result.Status)."
            return $result
        }
        finally {
            # Remove only the BITS job created by this invocation.
            if ($null -ne $bitsJob) {
                Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }

            if ($created -and -not ($KeepInstaller -and $verified)) {
                & $report 'Cleaning up the staged installer.'
                Remove-Item -LiteralPath $stage -Recurse -Force `
                    -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }

    try {
        $Channel = $Channel.ToLowerInvariant()
        & $report "Starting VS Code maintenance ($Channel)."

        if (-not $Migrate) {
            $system = & $updateSystem -Channel $Channel -Force:$Force `
                -CloseApps:$CloseApps -InstallIfMissing:$InstallIfMissing `
                -KeepInstaller:$KeepInstaller -MergeTasks $MergeTasks `
                -ConsentTimeoutSeconds $ConsentTimeoutSeconds `
                -BitsPriority $BitsPriority

            & $report "Finished: $($system.Status)."
            return $system
        }

        if (-not $PSBoundParameters.ContainsKey('MergeTasks')) {
            $MergeTasks = '!runcode,addcontextmenufiles,addcontextmenufolders,associatewithfiles,addtopath'
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)) {
                throw 'Run this function in elevated PowerShell or as SYSTEM.'
            }
        }
        finally {
            $identity.Dispose()
        }

        $exe = if ($Channel -eq 'insider') { 'Code - Insiders.exe' } else { 'Code.exe' }
        $dir = if ($Channel -eq 'insider') { 'Microsoft VS Code Insiders' } else { 'Microsoft VS Code' }

        & $report 'Scanning profiles for standard User Setup installations.'
        $profiles = @(
            Get-CimInstance Win32_UserProfile -Filter 'Special = FALSE' |
                Where-Object {
                    $_.LocalPath -and (-not $UserSid -or $_.SID -in $UserSid)
                }
        )

        $users = @(
            foreach ($userProfile in $profiles) {
                $installDir = Join-Path $userProfile.LocalPath "AppData\Local\Programs\$dir"
                if (Test-Path -LiteralPath (Join-Path $installDir $exe) -PathType Leaf) {
                    [pscustomobject][ordered]@{
                        UserSid     = $userProfile.SID
                        InstallPath = $installDir
                        Status      = 'Pending'
                        ExitCode    = $null
                        TaskName    = $null
                        Detail      = $null
                    }
                }
            }
        )

        & $report "Found $($users.Count) User Setup installation(s); checking migration approval."
        if (-not $PSCmdlet.ShouldProcess(
            "System Setup and $($users.Count) detected User Setup(s)",
            'Install/verify System Setup, then request consent and remove each User Setup in its owner context')) {
            foreach ($user in $users) { $user.Status = 'NotExecuted' }
            & $report 'Finished: NotExecuted.'
            return [pscustomobject]@{
                System = $null
                Users = $users
                Status = 'NotExecuted'
            }
        }

        Import-Module ScheduledTasks

        $system = & $updateSystem -Channel $Channel -InstallIfMissing `
            -CloseApps:$CloseApps -KeepInstaller:$KeepInstaller `
            -MergeTasks $MergeTasks -ConsentTimeoutSeconds $ConsentTimeoutSeconds `
            -BitsPriority $BitsPriority -Confirm:$false

        if ($system.Status -notin 'Updated', 'Installed', 'CurrentOrNewer') {
            & $report "Finished: SystemNotReady ($($system.Status)); User Setups retained."
            return [pscustomobject]@{
                System = $system
                Users = $users
                Status = 'SystemNotReady'
            }
        }

        & $report 'Verifying System Setup before migrating users.'
        $systemVersionText = [Diagnostics.FileVersionInfo]::GetVersionInfo(
            $system.Path).ProductVersion

        if ($systemVersionText -notmatch '^(\d+\.\d+\.\d+)') {
            throw 'Cannot verify System Setup version.'
        }

        $systemVersion = [version]$Matches[1]
        $systemProduct = if ($Channel -eq 'insider') {
            & $readInsidersProduct (Split-Path $system.Path -Parent)
        }

        $userIndex = 0
        foreach ($user in $users) {
            $userIndex++
            try {
                & $report "User $userIndex/$($users.Count): inspecting $($user.UserSid)."

                $userExe = Join-Path $user.InstallPath $exe
                $sourceVersionText = [Diagnostics.FileVersionInfo]::GetVersionInfo(
                    $userExe).ProductVersion

                if ($sourceVersionText -notmatch '^(\d+\.\d+\.\d+)') {
                    throw 'Cannot read User Setup version.'
                }

                if ([version]$Matches[1] -gt $systemVersion) {
                    $user.Status = 'UserVersionNewer'
                    $user.Detail = 'User Setup retained because its version is newer than System Setup.'
                    continue
                }

                if ($Channel -eq 'insider') {
                    $sourceProduct = & $readInsidersProduct $user.InstallPath
                    if ($sourceProduct.commit -ne $systemProduct.commit -and
                        [DateTimeOffset]::Parse($sourceProduct.date) -gt
                        [DateTimeOffset]::Parse($systemProduct.date)) {
                        $user.Status = 'UserVersionNewer'
                        $user.Detail = 'User Setup retained because its Insiders build is newer.'
                        continue
                    }
                }

                $uninstallRoot = "Registry::HKEY_USERS\$($user.UserSid)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                if (-not (Test-Path -LiteralPath $uninstallRoot)) {
                    $user.Status = 'UserNotAvailable'
                    continue
                }

                $registrations = @(
                    Get-ChildItem -LiteralPath $uninstallRoot |
                        ForEach-Object {
                            Get-ItemProperty -LiteralPath $_.PSPath
                        } |
                        Where-Object {
                            $_.InstallLocation -and
                            $_.InstallLocation.TrimEnd('\') -eq $user.InstallPath.TrimEnd('\') -and
                            $_.Publisher -eq 'Microsoft Corporation'
                        }
                )

                if ($registrations.Count -ne 1) {
                    throw 'Expected exactly one registered Microsoft User Setup at this path.'
                }

                $uninstallCommand = [string]$registrations[0].UninstallString
                if ($uninstallCommand -notmatch '^\s*"(?<exe>[^"]+\.exe)"(?:\s|$)') {
                    throw 'The registered uninstaller is not a supported quoted executable path.'
                }

                $uninstaller = [IO.Path]::GetFullPath($Matches['exe'])
                if ([IO.Path]::GetDirectoryName($uninstaller) -ne $user.InstallPath -or
                    [IO.Path]::GetFileName($uninstaller) -notmatch '^unins\d+\.exe$' -or
                    -not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
                    throw 'Registered uninstaller is missing or outside the User Setup directory.'
                }

                $taskName = "VSCode-UserSetup-Removal-$Channel-$($user.UserSid)"
                $existingTask = Get-ScheduledTask -TaskName $taskName `
                    -ErrorAction SilentlyContinue

                if ($existingTask) {
                    $user.Status = 'ExistingTask'
                    $user.TaskName = $taskName
                    $user.Detail = 'Inspect the existing task before retrying; no duplicate was launched.'
                    continue
                }

                & $report "Finding active sessions for $($user.UserSid)."
                $sessions = @(
                    foreach ($process in (
                        Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe' OR Name = '$exe'"
                    )) {
                        if ($process.SessionId -eq 0) { continue }
                        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
                        if ($owner.ReturnValue -eq 0 -and $owner.Sid -eq $user.UserSid) {
                            [int]$process.SessionId
                        }
                    }
                ) | Sort-Object -Unique
                $sessions = @($sessions)

                if ($sessions.Count -eq 0) {
                    $user.Status = 'UserNotAvailable'
                    continue
                }

                $message = "The shared VS Code installation is ready.`r`n`r`n" +
                    'May we remove your personal VS Code installation so future updates can be managed centrally? ' +
                    "Your settings and extensions will be kept.`r`n`r`n" +
                    'Save your files and finish terminal tasks before clicking Yes. ' +
                    'Any VS Code windows from your personal installation will be force-closed. ' +
                    'Unsaved work and running tasks may be lost. No or no response postpones migration.'

                $consented = $true
                foreach ($session in $sessions) {
                    if (-not (& $askConsent `
                        -Title 'Move VS Code to shared installation' -Message $message `
                        -TimeoutSeconds $ConsentTimeoutSeconds -SessionId $session)) {
                        $consented = $false
                        break
                    }
                }

                if (-not $consented) {
                    $user.Status = 'ConsentDeclined'
                    continue
                }

                # Only data is interpolated, via a base64 JSON payload.
                # The worker runs with the owner's limited interactive token.
                $payload = @{
                    Sid         = $user.UserSid
                    InstallDir  = $user.InstallPath
                    ExeName     = $exe
                    Uninstaller = $uninstaller
                    Sessions    = @($sessions)
                } | ConvertTo-Json -Compress

                $payload64 = [Convert]::ToBase64String(
                    [Text.Encoding]::UTF8.GetBytes($payload))

                $worker = @'
$ErrorActionPreference = 'Stop'
try {
    $data = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($identity.User.Value -ne $data.Sid) { exit 10 }

        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
            exit 10
        }
    }
    finally {
        $identity.Dispose()
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $data.Uninstaller
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch
            '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
        exit 12
    }

    $prefix = $data.InstallDir.TrimEnd('\') + '\'
    $findUserCode = {
        Get-CimInstance Win32_Process -Filter "Name = '$($data.ExeName)'" |
            Where-Object {
                $_.ExecutablePath -and
                $_.ExecutablePath.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase)
            }
    }

    $running = @(& $findUserCode)
    if (@($running | Where-Object {
        $_.SessionId -notin $data.Sessions
    }).Count -gt 0) {
        exit 11
    }

    foreach ($candidate in $running) {
        $process = Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue
        if (-not $process) { continue }

        try {
            if ($process.HasExited) { continue }

            if ($process.Path -ne $candidate.ExecutablePath -or
                $process.SessionId -ne $candidate.SessionId -or
                [Math]::Abs(
                    ($process.StartTime.ToUniversalTime() -
                     $candidate.CreationDate.ToUniversalTime()).TotalMilliseconds
                ) -gt 1) {
                exit 11
            }

            try { $process.Kill() }
            catch { if (-not $process.HasExited) { throw } }

            if (-not $process.WaitForExit(10000)) { exit 13 }
        }
        finally {
            $process.Dispose()
        }
    }

    if (@(& $findUserCode).Count -gt 0) { exit 13 }

    $installer = Start-Process -FilePath $data.Uninstaller -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG'
    ) -Wait -PassThru

    try { $exitCode = $installer.ExitCode }
    finally { $installer.Dispose() }

    exit $exitCode
}
catch {
    exit 20
}
'@

                $worker = $worker.Replace('__PAYLOAD__', $payload64)
                $encoded = [Convert]::ToBase64String(
                    [Text.Encoding]::Unicode.GetBytes($worker))
                $powershell = Join-Path $env:SystemRoot `
                    'System32\WindowsPowerShell\v1.0\powershell.exe'

                $action = New-ScheduledTaskAction -Execute $powershell -Argument (
                    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + $encoded
                )
                $principal = New-ScheduledTaskPrincipal `
                    -UserId $user.UserSid -LogonType Interactive -RunLevel Limited
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)

                & $report "Starting User Setup removal for $($user.UserSid)."

                # No trigger and no -Force: never overwrite an existing task.
                $null = Register-ScheduledTask -TaskName $taskName `
                    -Action $action -Principal $principal -Settings $settings
                $user.TaskName = $taskName
                Start-ScheduledTask -TaskName $taskName

                $timer = [Diagnostics.Stopwatch]::StartNew()
                $completed = $false

                do {
                    $task = Get-ScheduledTask -TaskName $taskName
                    $info = Get-ScheduledTaskInfo -TaskName $taskName

                    if ($null -ne $watcher) {
                        $watcher.State = (
                            'User {0}/{1}: {2} | task {3} | result {4} | {5:N0}/{6}s' -f
                            $userIndex, $users.Count, $user.UserSid,
                            $task.State, $info.LastTaskResult,
                            $timer.Elapsed.TotalSeconds, $UninstallTimeoutSeconds
                        )
                    }

                    if ($info.LastRunTime.Year -gt 2000 -and
                        $task.State -notin 'Running', 'Queued' -and
                        $info.LastTaskResult -ne 267009) {
                        $completed = $true
                        break
                    }

                    Start-Sleep -Milliseconds 500
                } while ($timer.Elapsed.TotalSeconds -lt $UninstallTimeoutSeconds)

                if (-not $completed) {
                    $user.Status = 'TaskPending'
                    $user.Detail = 'Task retained; inspect its state/result before retrying. No recurring trigger exists.'
                    continue
                }

                $user.ExitCode = $info.LastTaskResult
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                $user.TaskName = $null

                & $report "Verifying User Setup removal for $($user.UserSid)."
                if ($info.LastTaskResult -eq 0 -and
                    -not (Test-Path -LiteralPath $userExe) -and
                    -not (Test-Path -LiteralPath $registrations[0].PSPath)) {
                    $user.Status = 'Converted'
                }
                else {
                    $user.Status = 'UninstallIncomplete'
                    $user.Detail = 'Removal was not verified. Worker codes: 10=token, 11=session changed, 12=signature, 13=still running, 20=error; other codes may be uninstaller/task errors.'
                }
            }
            catch {
                $user.Status = 'Failed'
                $user.Detail = $_.Exception.Message
                Write-Warning "Migration for $($user.UserSid) was not completed: $($user.Detail)"
            }
            finally {
                & $report "User $userIndex/$($users.Count): $($user.UserSid) -> $($user.Status)."
            }
        }

        $status = if (@($users | Where-Object Status -ne 'Converted').Count -gt 0) {
            'MigrationPending'
        }
        else {
            'Complete'
        }

        & $report "Finished: $status."
        [pscustomobject]@{
            System = $system
            Users = $users
            Status = $status
        }
    }
    catch {
        & $report "Failed: $($_.Exception.Message)"
        throw
    }
    finally {
        if ($null -ne $watcher) {
            $watcher.Dispose()
        }
    }
}

#endregion

#region -------------------- Invoke-VSCode (dispatcher, returns the exit code) --------------------

function Invoke-VSCode {
    param(
        [ValidateSet('Check', 'Update', 'Migrate')]
        [string]$Mode = 'Check',
        # Update-VSCode parameters, e.g. @{ CloseApps = $true; Live = $true; Channel = 'insider' }
        [hashtable]$Options = @{}
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $preview = [bool]$Options['WhatIf']

    try {
        switch ($Mode) {
            'Check' {
                $channel = if ($Options['Channel']) { [string]$Options['Channel'] } else { 'stable' }
                # Load now: auto-loading it under -WhatIf prints a "What if: Set Alias" line per alias.
                Import-Module CimCmdlets
                # -WhatIf stops Update-VSCode right after the version comparison: no download,
                # no prompt, no admin needed. -InstallIfMissing makes it look up the latest
                # release even when there is no machine-wide install.
                $system = Update-VSCode -Channel $channel -InstallIfMissing -WhatIf
                $exe = if ($channel -eq 'insider') { 'Code - Insiders.exe' } else { 'Code.exe' }
                $dir = if ($channel -eq 'insider') { 'Microsoft VS Code Insiders' } else { 'Microsoft VS Code' }
                $users = @(Get-CimInstance Win32_UserProfile -Filter 'Special = FALSE' | Where-Object LocalPath |
                    ForEach-Object {
                        $exePath = Join-Path $_.LocalPath "AppData\Local\Programs\$dir\$exe"
                        if (Test-Path -LiteralPath $exePath -PathType Leaf -ErrorAction SilentlyContinue) {
                            [pscustomobject]@{
                                UserSid = $_.SID
                                Version = [Diagnostics.FileVersionInfo]::GetVersionInfo($exePath).ProductVersion
                                Path    = $exePath
                            }
                        }
                    })

                $installed = [bool]$system.InstalledVersion
                $updateNeeded = $installed -and $system.Status -ne 'CurrentOrNewer'
                $machine = if (-not $installed) { 'not installed' }
                           elseif ($updateNeeded) { "$($system.InstalledVersion)  -> UPDATE AVAILABLE" }
                           else { "$($system.InstalledVersion)  (current)" }
                Write-Host ''
                Write-Host "VS Code ($channel) on $env:COMPUTERNAME"
                Write-Host "  Latest release   : $($system.TargetVersion)"
                Write-Host "  Machine-wide     : $machine" -ForegroundColor $(if ($updateNeeded) { 'Yellow' } else { 'Green' })
                Write-Host ("  Per-user installs: {0}{1}" -f $users.Count, $(if ($users.Count) { '  -> candidates for Migrate' } else { '' })) `
                    -ForegroundColor $(if ($users.Count) { 'Yellow' } else { 'Green' })
                if ($users.Count) { $users | Format-Table UserSid, Version, Path -AutoSize | Out-Host }
                if (-not $isAdmin) {
                    Write-Host "  Not elevated: other users' profiles may be unreadable, so per-user installs can be undercounted." -ForegroundColor DarkGray
                }
                if ($updateNeeded -or $users.Count) { return 2 }
                return 0
            }
            { $_ -in 'Update', 'Migrate' } {
                # Update-VSCode checks elevation before the Migrate preview too (it must read other profiles).
                if (-not $isAdmin -and ($Mode -eq 'Migrate' -or -not $preview)) {
                    Write-Host "ERROR: $Mode needs an elevated or SYSTEM session$(if ($Mode -eq 'Update') { ' (or pass WhatIf)' })." -ForegroundColor Red
                    return 10
                }
                $params = $Options.Clone()
                if ($Mode -eq 'Migrate') { $params['Migrate'] = $true }
                $result = Update-VSCode @params

                if ($Mode -eq 'Update') {
                    $result | Format-List Channel, Status, PreviousVersion, TargetVersion, InstalledVersion, ExitCode | Out-Host
                    if ($result.Status -eq 'RebootRequired') { return 3010 }
                    if ($result.Status -in 'InUse', 'ConsentDeclined', 'SessionChanged') { return 4 }
                    return 0   # Updated / Installed / CurrentOrNewer / NotInstalled / NotExecuted
                }

                if ($result.System) { $result.System | Format-List Channel, Status, PreviousVersion, TargetVersion, InstalledVersion | Out-Host }
                if ($result.Users) { $result.Users | Format-Table UserSid, Status, ExitCode, TaskName, Detail -AutoSize | Out-Host }
                Write-Host "Migration: $($result.Status)"
                if ($result.Status -eq 'SystemNotReady' -or
                    @($result.Users | Where-Object { $_.Status -in 'Failed', 'UninstallIncomplete' }).Count) { return 3 }
                if ($result.System.RebootRequired) { return 3010 }
                if ($result.Status -eq 'MigrationPending') { return 4 }
                return 0   # Complete / NotExecuted
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

$exitCode = Invoke-VSCode                                                            # Check (read-only)
# $exitCode = Invoke-VSCode -Mode Update  -Options @{ CloseApps = $true; Live = $true }                     # LIVE update, asks users before closing
# $exitCode = Invoke-VSCode -Mode Update  -Options @{ InstallIfMissing = $true; CloseApps = $true; Live = $true }
# $exitCode = Invoke-VSCode -Mode Migrate -Options @{ CloseApps = $true; Live = $true; WhatIf = $true }     # preview migration
# $exitCode = Invoke-VSCode -Mode Migrate -Options @{ CloseApps = $true; Live = $true }                     # LIVE migration, per-user consent

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
