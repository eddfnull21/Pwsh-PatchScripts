function Show-UserConsent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$Title   = "Action Required",
        [string]$Message = "Do you agree to proceed?",
        [int]$TimeoutSeconds = 0   # 0 = wait forever
    )

    # Load the Win32 helper once; skip if already present this session
    if (-not ([System.Management.Automation.PSTypeName]'WTSHelper').Type) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WTSHelper {
    [DllImport("wtsapi32.dll", SetLastError=true)]
    public static extern bool WTSSendMessage(
        IntPtr hServer, int sessionId,
        string pTitle, int titleLength,
        string pMessage, int messageLength,
        int style, int timeout,
        out int pResponse, bool bWait);

    [DllImport("kernel32.dll")]
    public static extern int WTSGetActiveConsoleSessionId();
}
"@
    }

    $MB_YESNO = 0x4
    $IDYES = 6

    $sessionId = [WTSHelper]::WTSGetActiveConsoleSessionId()

    $response = 0
    # bWait = $true blocks until the user responds (or timeout, if set)
    [WTSHelper]::WTSSendMessage([IntPtr]::Zero, $sessionId,
        $Title, $Title.Length,
        $Message, $Message.Length,
        $MB_YESNO, $TimeoutSeconds, [ref]$response, $true) | Out-Null

    return ($response -eq $IDYES)
}


if (Show-UserConsent -Message "message") {
    Write-Output "User agreed"
    # proceed...
} else {
    Write-Output "User declined"
    # abort...
}

