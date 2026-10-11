Remove-Module PSReadLine -ErrorAction SilentlyContinue

function Start-InteractiveSystemPowerShell {
    [CmdletBinding()]
    param(
        [string]$Application,

        [string]$ApplicationArguments = '',

        [ValidateRange(0, 2147483647)]
        [int]$LaunchDelaySeconds = 0,

        [string]$Command = '',

        [switch]$AsLoggedInUser,

        [switch]$Listen = $true,

        [switch]$MirrorCommands = $true,

        [switch]$NoAttach,

        [switch]$HideWindow,

        [Alias('MinimiseWindow')]
        [switch]$MinimizeWindow
    )

    $ErrorActionPreference = 'Stop'

    if ($HideWindow -and $MinimizeWindow) {
        throw 'Use either -HideWindow or -MinimizeWindow, not both.'
    }
    $windowState = if ($HideWindow) { 'Hidden' } elseif ($MinimizeWindow) { 'Minimized' } else { 'Normal' }
    # -1 preserves the default startup behavior; 0 = SW_HIDE, 2 = SW_SHOWMINIMIZED.
    [System.Int16]$showWindow = if ($HideWindow) { 0 } elseif ($MinimizeWindow) { 2 } else { -1 }

    if ($MirrorCommands -and -not $Listen) {
        throw '-MirrorCommands requires -Listen (which is enabled by default).'
    }

    if (-not $NoAttach -and -not $Listen) {
        throw 'Automatic attachment requires -Listen (enabled by default).'
    }
    $interactiveHost = $Host -as [Management.Automation.Host.IHostSupportsInteractiveSession]
    if (-not $NoAttach -and $null -eq $interactiveHost) {
        throw 'This host cannot attach interactively. Run from an interactive PowerShell terminal.'
    }

    $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

// New type name allows reloading this script when the older launcher is loaded.
public static class SystemSessionLauncherV2
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr newToken
    );

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(
        out IntPtr environment,
        IntPtr token,
        bool inherit
    );

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(
        IntPtr environment
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr token,
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation
    );

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(
        IntPtr handle
    );

    public static int Launch(
        int tokenProcessId,
        string application,
        string arguments,
        short showWindow
    )
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        const uint TOKEN_ADJUST_SESSIONID = 0x0100;

        const uint TOKEN_ACCESS =
            TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE |
            TOKEN_QUERY |
            TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID;

        const uint CREATE_NEW_CONSOLE = 0x00000010;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const int STARTF_USESHOWWINDOW = 0x00000001;

        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

        try
        {
            processHandle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                tokenProcessId
            );

            if (processHandle == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!OpenProcessToken(
                processHandle,
                TOKEN_ACCESS,
                out tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!DuplicateTokenEx(
                tokenHandle,
                TOKEN_ACCESS,
                IntPtr.Zero,
                2,
                1,
                out primaryToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!CreateEnvironmentBlock(
                out environment,
                primaryToken,
                false))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            STARTUPINFO startupInfo = new STARTUPINFO();

            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startupInfo.lpDesktop = @"winsta0\default";
            startupInfo.lpTitle = "Interactive PowerShell";
            // Apply visibility when the new console is created, not afterward.
            if (showWindow >= 0)
            {
                startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
                startupInfo.wShowWindow = showWindow;
            }

            string fullCommandLine = "\"" + application + "\"";

            if (!String.IsNullOrWhiteSpace(arguments))
                fullCommandLine += " " + arguments;

            if (fullCommandLine.Length >= 32767)
                throw new ArgumentException("Command is too long. Invoke a .ps1 file using -Command instead.");

            StringBuilder commandLine =
                new StringBuilder(fullCommandLine);

            if (!CreateProcessAsUser(
                primaryToken,
                application,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                environment,
                Environment.SystemDirectory,
                ref startupInfo,
                out processInfo))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return processInfo.dwProcessId;
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero)
                CloseHandle(processInfo.hThread);

            if (processInfo.hProcess != IntPtr.Zero)
                CloseHandle(processInfo.hProcess);

            if (environment != IntPtr.Zero)
                DestroyEnvironmentBlock(environment);

            if (primaryToken != IntPtr.Zero)
                CloseHandle(primaryToken);

            if (tokenHandle != IntPtr.Zero)
                CloseHandle(tokenHandle);

            if (processHandle != IntPtr.Zero)
                CloseHandle(processHandle);
        }
    }
}
'@

    if (-not ('SystemSessionLauncherV2' -as [type])) {
        Add-Type -TypeDefinition $source
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    if ($identity.User.Value -ne 'S-1-5-18') {
        throw "This function must run as SYSTEM. Current identity: $($identity.Name)"
    }

    $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -gt 0 } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1

    if (-not $explorer) {
        throw 'No interactive user session was found.'
    }

    if ($AsLoggedInUser) {
        $tokenProcess = $explorer
        $sessionTitle = 'Interactive User PowerShell'
    }
    else {
        $tokenProcess = Get-Process -Name winlogon -ErrorAction Stop |
            Where-Object { $_.SessionId -eq $explorer.SessionId } |
            Select-Object -First 1

        if (-not $tokenProcess) {
            throw "No winlogon process was found in session $($explorer.SessionId)."
        }

        $sessionTitle = 'Interactive SYSTEM PowerShell'
    }

    $powershell =
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    $applicationValue = ''

    if ($Application) {
        $expandedApplication =
            [Environment]::ExpandEnvironmentVariables($Application)

        if (-not (Test-Path -LiteralPath $expandedApplication -PathType Leaf)) {
            throw "Application not found: $expandedApplication"
        }

        $applicationValue =
            $expandedApplication.Replace("'", "''")
    }

    $applicationArgumentsValue =
        $ApplicationArguments.Replace("'", "''")

    $initialCommand = @"
`$Host.UI.RawUI.WindowTitle = '$sessionTitle'

Clear-Host

Write-Host '$sessionTitle'
Write-Host "Identity: `$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "Session ID: `$((Get-Process -Id `$PID).SessionId)"
Write-Host "Process ID: `$PID"
Write-Host ''

`$application = '$applicationValue'
`$applicationArguments = '$applicationArgumentsValue'
`$launchDelaySeconds = $LaunchDelaySeconds

if (-not [string]::IsNullOrWhiteSpace(`$application)) {
    if (`$launchDelaySeconds -gt 0) {
        Write-Host "Launching application in `$launchDelaySeconds second(s)..."
        Start-Sleep -Seconds `$launchDelaySeconds
    }

    try {
        if ([string]::IsNullOrWhiteSpace(`$applicationArguments)) {
            `$process = Start-Process -FilePath `$application -PassThru
        }
        else {
            `$process = Start-Process -FilePath `$application -ArgumentList `$applicationArguments -PassThru
        }

        Write-Host "Application launched: `$application"
        Write-Host "Application process ID: `$(`$process.Id)"
    }
    catch {
        Write-Host "Failed to launch application:"
        Write-Host `$_.Exception.Message
    }
}

Write-Host ''
Write-Host '$sessionTitle is ready.'
"@

    if ($MirrorCommands) {
        $mirrorSetup = @'
# These environment variables are shared with the attached runspace in this process.
$__imDirectory = Join-Path ([IO.Path]::GetTempPath()) ('InteractivePowerShell-' + [guid]::NewGuid().ToString('N'))
$__imAcl = [Security.AccessControl.DirectorySecurity]::new()
$__imAcl.SetAccessRuleProtection($true, $false)
foreach ($__imSid in @('S-1-5-18', 'S-1-5-32-544',
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) | Select-Object -Unique) {
    $__imAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($__imSid),
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
}
[IO.Directory]::CreateDirectory($__imDirectory, $__imAcl) | Out-Null
$__imPath = Join-Path $__imDirectory 'session.txt'
# Start an independent cleanup process before creating any transcript data.
# Hold the original process handle and check its start time to avoid PID reuse.
$__imCleanupSource = @(
    '$ErrorActionPreference = ''Stop'''
    ('$targetId = {0}' -f $PID)
    ('$started = {0}L' -f (Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks)
    ('$directory = ''{0}''' -f $__imDirectory.Replace("'", "''"))
    '$transcript = Join-Path $directory ''session.txt'''
    '$target = $null'
    'try {'
    '    try {'
    '        $target = [Diagnostics.Process]::GetProcessById($targetId)'
    '        $null = $target.Handle'
    '        if ($target.StartTime.ToUniversalTime().Ticks -eq $started) {'
    '            while ([IO.Directory]::Exists($directory) -and -not $target.WaitForExit(1000)) {}'
    '        }'
    '    } catch [ArgumentException] {} catch [InvalidOperationException] {}'
    '} finally { if ($target) { $target.Dispose() } }'
    'for ($attempt = 0; $attempt -lt 30; $attempt++) {'
    '    try {'
    '        if (-not [IO.Directory]::Exists($directory)) { exit 0 }'
    '        [IO.File]::Delete($transcript)'
    '        if ([IO.Directory]::Exists($directory)) { [IO.Directory]::Delete($directory) }'
    '        exit 0'
    '    } catch { Start-Sleep -Seconds 1 }'
    '}'
    'exit 1'
) -join "`r`n"
$__imCleanupEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($__imCleanupSource))
try {
    $__imCleanupProcess = Start-Process -FilePath "$PSHOME\powershell.exe" -WindowStyle Hidden -PassThru -ErrorAction Stop -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $__imCleanupEncoded)
    Start-Sleep -Milliseconds 200
    if ($__imCleanupProcess.HasExited) { throw 'The transcript cleanup process failed to start.' }
}
catch {
    [IO.Directory]::Delete($__imDirectory)
    throw
}
# A BOM makes Windows PowerShell 5.1 preserve UTF-8 when appending transcripts.
[IO.File]::WriteAllText($__imPath, '', [Text.UTF8Encoding]::new($true))
$env:INTERACTIVE_PS_TRANSCRIPT = $__imPath
$env:INTERACTIVE_PS_MIRROR_STOP = '0'
'@
        $initialCommand = $mirrorSetup + "`r`n" + $initialCommand
    }

    # Append code before encoding: quotes, newlines and child variables stay intact.
    $initialCommand += "`r`n$Command`r`n"

    if ($MirrorCommands) {
        $initialCommand += @'

Write-Host 'Desktop transcript viewer is ready.' -ForegroundColor Green
Write-Host 'Waiting for the attached prompt to start transcription...'
Write-Host "Temporary transcript: $__imPath"
Write-Host 'This window closes and its transcript is removed when the attachment ends.'
$__imStream = $null
$__imReader = $null
$__imSawAttachment = $false
try {
    $__imStream = [IO.File]::Open($__imPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $__imReader = [IO.StreamReader]::new($__imStream, [Text.Encoding]::UTF8, $true)
    while ($env:INTERACTIVE_PS_MIRROR_STOP -ne '1') {
        # Direct console output avoids feeding mirrored text back into transcription.
        [Console]::Write($__imReader.ReadToEnd())
        # Native process attachment creates a RemoteHost runspace. Wait until
        # all attached runspaces have closed before exiting the viewer.
        $__imAttached = @(Get-Runspace | Where-Object {
            $_.Name -eq 'RemoteHost' -and
            $_.RunspaceStateInfo.State -in @('BeforeOpen', 'Opening', 'Opened', 'Closing')
        })
        if ($__imAttached.Count -gt 0) { $__imSawAttachment = $true }
        elseif ($__imSawAttachment -or $__imStream.Length -gt 3) {
            # A transcript larger than its UTF-8 BOM also covers an attachment
            # that started and ended between polling intervals.
            break
        }
        Start-Sleep -Milliseconds 200
    }
    [Console]::Write($__imReader.ReadToEnd())
}
finally {
    try {
        if ($__imReader) { $__imReader.Dispose() }
        elseif ($__imStream) { $__imStream.Dispose() }
    }
    finally {
        # Exit first to release transcript handles held by this process.
        # The existing hidden cleanup process waits for exit, then deletes
        # only this session's transcript and empty directory, retrying locks.
        # Never keep the desktop window open during those retries.
        [Environment]::Exit(0)
    }
}
'@
    }

    elseif ($Listen) {
        $initialCommand += @'

Write-Host 'Waiting for the remote attachment. This window closes when it ends.'
$__imSawAttachment = $false
try {
    while ($true) {
        $__imAttached = @(Get-Runspace | Where-Object {
            $_.Name -eq 'RemoteHost' -and
            $_.RunspaceStateInfo.State -in @('BeforeOpen', 'Opening', 'Opened', 'Closing')
        })
        if ($__imAttached.Count -gt 0) { $__imSawAttachment = $true }
        elseif ($__imSawAttachment) { break }
        Start-Sleep -Milliseconds 200
    }
}
finally { [Environment]::Exit(0) }
'@
    }

    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($initialCommand)
    )

    $powershellArguments = @(
        '-NoLogo'
        '-NoProfile'
        '-NoExit'
        '-EncodedCommand'
        $encodedCommand
    ) -join ' '

    $processId = [SystemSessionLauncherV2]::Launch(
        $tokenProcess.Id,
        $powershell,
        $powershellArguments,
        $showWindow
    )

    try {
        Start-Sleep -Seconds 1
    
        if (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
            throw "The PowerShell process exited immediately. PID: $processId"
        }
    
        if ($Listen) {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Get-PSHostProcessInfo -Id $processId -ErrorAction SilentlyContinue)) {
                if (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
                    throw "The spawned PowerShell exited before attachment was ready. PID: $processId"
                }
                if ([DateTime]::UtcNow -ge $deadline) {
                    throw "PowerShell PID $processId is running, but its attachment endpoint was not detected. Retry with the default visible window to inspect startup output."
                }
                Start-Sleep -Milliseconds 100
            }
        }
    }
    catch {
        if (-not $NoAttach) { Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue }
        throw
    }

    Write-Host "$sessionTitle launched. Session $($explorer.SessionId), process $processId. Window: $windowState."
    if ($NoAttach) {
        Write-Host "Attach with: Enter-PSHostProcess -Id $processId"
        if ($MirrorCommands) {
            Write-Host 'Then run: Start-Transcript -LiteralPath $env:INTERACTIVE_PS_TRANSCRIPT -Append'
        }
        return [pscustomobject]@{
            ProcessId = $processId
            SessionId = $explorer.SessionId
            AsLoggedInUser = [bool]$AsLoggedInUser
            Listen = [bool]$Listen
            MirrorCommands = [bool]$MirrorCommands
            WindowState = $windowState
        }
    }

    $entered = $false
    $initializer = $null
    try {
        # Let the native cmdlet manage prompt switching and close-on-detach.
        Enter-PSHostProcess -Id $processId -ErrorAction Stop
        $entered = $true
        if ($MirrorCommands) {
            $attachedRunspace = $interactiveHost.Runspace
            if ($null -eq $attachedRunspace -or
                $attachedRunspace.ConnectionInfo.ProcessId -ne $processId) {
                throw 'This host does not expose the attached runspace for automatic transcription. Use -NoAttach for the manual flow.'
            }
            $initializer = [Management.Automation.PowerShell]::Create()
            $initializer.Runspace = $attachedRunspace
            [void]$initializer.AddScript(@'
$__initDeadline = [DateTime]::UtcNow.AddSeconds(15)
while ([string]::IsNullOrEmpty($env:INTERACTIVE_PS_TRANSCRIPT)) {
    if ([DateTime]::UtcNow -ge $__initDeadline) {
        throw 'The desktop transcript viewer did not initialize.'
    }
    Start-Sleep -Milliseconds 100
}
Start-Transcript -LiteralPath $env:INTERACTIVE_PS_TRANSCRIPT -Append -ErrorAction Stop | Out-Null
Remove-Variable __initDeadline
'@)
            $null = $initializer.Invoke()
            if ($initializer.HadErrors) { throw $initializer.Streams.Error[0] }
        }
        # Keyboard handling belongs to the calling host, not the child runspace.
        # Only intercept Ctrl+D while that host is attached to one of our sessions.
        # Restore a previous built-in binding when Ctrl+D is used outside them.
        $ctrlDEnabled = $false
        try {
            if (-not (Get-Module PSReadLine) -or
                -not (Get-Command PSConsoleHostReadLine -ErrorAction SilentlyContinue)) {
                throw 'PSReadLine is not active in this calling shell.'
            }
            if ((Get-PSReadLineOption).EditMode -eq 'Vi') {
                throw 'The automatic shortcut supports Windows and Emacs editing modes.'
            }
            $currentAttachment = $interactiveHost.Runspace
            if ($null -eq $currentAttachment -or $currentAttachment.ConnectionInfo.ProcessId -ne $processId) {
                throw 'The calling host does not expose this attachment for keyboard handling.'
            }
            $bindings = @(Get-PSReadLineKeyHandler -Bound)
            $previous = $bindings | Where-Object Key -eq 'Ctrl+d' | Select-Object -First 1
            if ($bindings | Where-Object Key -like 'Ctrl+d,*') {
                throw 'Ctrl+D is already the prefix of a custom key sequence.'
            }
            $stateVariable = Get-Variable InteractivePSCtrlDState -Scope Script -ErrorAction SilentlyContinue
            $keyState = if ($stateVariable) { $stateVariable.Value } else { $null }
            if ($null -eq $keyState -or $null -eq $previous -or $previous.Function -ne 'InteractivePSEndSession') {
                $oldMethod = $null
                if ($previous) {
                    $oldMethod = [Microsoft.PowerShell.PSConsoleReadLine].GetMethods() |
                        Where-Object { $_.IsStatic -and $_.Name -eq $previous.Function -and $_.GetParameters().Count -eq 2 } |
                        Select-Object -First 1
                    # Public PSReadLine APIs cannot retrieve a custom handler's
                    # script block, so do not overwrite one we cannot restore.
                    if ($null -eq $oldMethod) { throw 'An existing custom Ctrl+D binding was preserved.' }
                }
                $keyState = @{
                    Host = $interactiveHost
                    Runspaces = [System.Collections.Generic.HashSet[guid]]::new()
                    PreviousFunction = if ($previous) { $previous.Function } else { $null }
                    PreviousMethod = $oldMethod
                }
                $keyHandler = {
                    param($key, $arg)
                    $current = $keyState.Host.Runspace
                    if ($null -ne $current -and $keyState.Runspaces.Contains($current.InstanceId)) {
                        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
                        [Microsoft.PowerShell.PSConsoleReadLine]::Insert('Exit-PSHostProcess')
                        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
                        return
                    }
                    if ($keyState.PreviousFunction) {
                        Set-PSReadLineKeyHandler -Chord Ctrl+d -Function $keyState.PreviousFunction
                        $null = $keyState.PreviousMethod.Invoke($null, [object[]]@($key, $arg))
                    }
                    else {
                        Remove-PSReadLineKeyHandler -Chord Ctrl+d
                        [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
                    }
                }.GetNewClosure()
                Set-PSReadLineKeyHandler -Chord Ctrl+d -BriefDescription InteractivePSEndSession -ScriptBlock $keyHandler
                $script:InteractivePSCtrlDState = $keyState
            }
            [void]$keyState.Runspaces.Add($currentAttachment.InstanceId)
            $ctrlDEnabled = $true
        }
        catch {
            Write-Warning "Ctrl+D could not be enabled: $($_.Exception.Message) Use Exit-PSHostProcess to end the session."
        }
        if ($ctrlDEnabled) {
            Write-Host 'Attached. Ctrl+D at the prompt or Exit-PSHostProcess closes the desktop terminal and cleans up the transcript.'
        }
        else {
            Write-Host 'Attached. Type commands normally; Exit-PSHostProcess ends the session.'
        }
    }
    catch {
        if ($entered) { Exit-PSHostProcess -ErrorAction SilentlyContinue }
        # Failed setup must not leave an unattended interactive window behind.
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        if ($initializer) { $initializer.Dispose() }
    }
}


#Start-InteractiveSystemPowerShell -AsLoggedInUser
#Start-InteractiveSystemPowerShell -AsLoggedInUser -HideWindow
#Start-InteractiveSystemPowerShell -AsLoggedInUser -MinimizeWindow

#region Notes
# LOAD ONCE (from a PowerShell process already running as SYSTEM):
# . .\Start-InteractiveSystemPowerShell.ps1
#
# ONE COMMAND -- logged-on user, automatic attachment and desktop mirroring:
# Start-InteractiveSystemPowerShell -AsLoggedInUser
#
# SYSTEM variation:
# Start-InteractiveSystemPowerShell
#
# HIDDEN terminal -- remote prompt still attaches normally:
# Start-InteractiveSystemPowerShell -AsLoggedInUser -HideWindow
# Start-InteractiveSystemPowerShell -HideWindow
#
# MINIMIZED terminal -- end user can restore it from the taskbar:
# Start-InteractiveSystemPowerShell -AsLoggedInUser -MinimizeWindow
# Start-InteractiveSystemPowerShell -MinimizeWindow
# Use either flag; do not combine them. Neither flag means a normal window.
# These flags affect only the PowerShell terminal, not other apps you launch.
#
# Then type commands normally:
# whoami
# Get-Date
# Get-ChildItem
#
# END -- closes the desktop terminal and removes its temporary transcript:
# Press Ctrl+D at the attached prompt (discards any unfinished input), or run:
# Exit-PSHostProcess
# If a command is running, press Ctrl+C first, then Ctrl+D at the prompt.
# Ctrl+D needs PSReadLine in the calling shell; if unavailable, use the command.
#
# Disable mirroring/transcription but keep automatic attachment:
# Start-InteractiveSystemPowerShell -AsLoggedInUser -MirrorCommands:$false
#
# Optional application launch:
# Start-InteractiveSystemPowerShell -AsLoggedInUser -Application "$env:SystemRoot\System32\notepad.exe"
#
# ADVANCED: keep the old manual sequence when needed:
# $session = Start-InteractiveSystemPowerShell -AsLoggedInUser -NoAttach
# Enter-PSHostProcess -Id $session.ProcessId
# Start-Transcript -LiteralPath $env:INTERACTIVE_PS_TRANSCRIPT -Append
#
# WINDOWS CHECK: launch with one command, verify whoami and visible output in
# both windows, then press Ctrl+D. The desktop should close promptly after
# detachment, without waiting for transcript deletion. Its printed temporary
# transcript path should then disappear (the hidden cleanup process retries
# locks for up to 30 seconds). Repeat by disconnecting your remote-shell client.
# Abrupt network loss closes the window when the remoting host detects the loss;
# a host retaining disconnected sessions can delay it. Cleanup cannot be
# guaranteed if both the desktop and cleanup processes are killed or power is lost.
# Repeat with SYSTEM and -MirrorCommands:$false. Also test Exit-PSHostProcess,
# relaunching, Ctrl+D with unfinished input, and Ctrl+D back in the original
# shell: its prior built-in binding should be restored there. Custom bindings
# and clients that intercept Ctrl+D require the explicit exit command.
# Also repeat with -HideWindow and -MinimizeWindow: verify the initial window
# state, attachment, Ctrl+D shutdown, and transcript cleanup. Restore the
# minimized window to verify mirroring. Combining both flags must fail before
# launching a process. Reload this file before testing the new flags.
    <#
    .SYNOPSIS
        Launches, attaches to, and mirrors an interactive Windows PowerShell session.
    .DESCRIPTION
        Dot-source this file, then run this ONE command at an interactive prompt:
          Start-InteractiveSystemPowerShell -AsLoggedInUser
        Omit AsLoggedInUser for SYSTEM. The launcher must itself run as SYSTEM.
        It selects the session with the most recently started Explorer process.
        Launch, native process attachment, and transcription start automatically.
        Type commands normally. Ctrl+D at the prompt (or Exit-PSHostProcess)
        ends the attachment, closes
        the desktop PowerShell, and removes the temporary transcript.
        Connection loss closes the desktop once PowerShell detects that the
        attachment ended. A remoting host that retains a disconnected session
        can delay that detection; this is not a network-heartbeat mechanism.
        Commands run in a separate runspace in the spawned process. Startup
        Command variables are not shared with the attached prompt. Mirroring
        displays commands and transcribed text as it is flushed, not a full TTY.
    .PARAMETER AsLoggedInUser
        Runs the spawned process as the logged-on user instead of SYSTEM.
    .PARAMETER HideWindow
        Starts the spawned PowerShell console hidden. Remote attachment and
        transcript cleanup still work. Applies only to the terminal window,
        not to programs launched with Application or Command.
    .PARAMETER MinimizeWindow
        Starts the spawned PowerShell console minimized so the user can restore
        it from the taskbar. Cannot be combined with HideWindow. Without either
        flag, the terminal starts normally. MinimiseWindow is an alias.
    .PARAMETER MirrorCommands
        Enabled by default. Use -MirrorCommands:$false to disable the desktop
        text mirror and transcription. Closing the attachment still closes
        the desktop PowerShell.
    .PARAMETER NoAttach
        Advanced/manual mode: return a session object instead of attaching.
        With mirroring enabled, start transcription after entering the process:
          Start-Transcript -LiteralPath $env:INTERACTIVE_PS_TRANSCRIPT -Append
    .PARAMETER Listen
        Enabled by default. Waits for the native attachment endpoint and closes
        the desktop process when its attachment ends. A standalone desktop
        window requires -NoAttach -Listen:$false -MirrorCommands:$false.
    .PARAMETER Command
        Startup code for the desktop runspace. Use single quotes so variables
        expand in the child process. Avoid blocking startup code when attaching.
    .PARAMETER LaunchDelaySeconds
        Delay before launching Application, if one is supplied.
    .NOTES
        Transcripts are kept in a private temporary directory. At session end,
        the desktop closes without waiting for deletion. A hidden cleanup
        process removes the transcript after exit and retries temporary locks
        for up to 30 seconds, including if the desktop is killed. Killing both
        processes or shutting down the machine can still prevent cleanup.
        Windows PowerShell 5.1 and a host supporting interactive sessions are
        required. Run directly at the prompt, not inside a background script job.
        Ctrl+D requires PSReadLine in the shell receiving your keystrokes, in
        Windows or Emacs mode. It discards any pending input and submits
        Exit-PSHostProcess. While a command runs, use Ctrl+C first. Hosts that
        intercept shortcuts need Exit-PSHostProcess instead. Custom Ctrl+D
        bindings are preserved; a warning explains when the shortcut is unavailable.
    .EXAMPLE
        Start-InteractiveSystemPowerShell -AsLoggedInUser
    .EXAMPLE
        Start-InteractiveSystemPowerShell
    .EXAMPLE
        Start-InteractiveSystemPowerShell -AsLoggedInUser -MirrorCommands:$false
    #>
