# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Microsoft 3D Viewer (end of life) - Check / Remove / RemoveWithConsent. RMM-ready.

.DESCRIPTION
    -Action Check              DEFAULT. Read-only. Reports the 3D Viewer Appx package
                               per user (all users when elevated), the provisioned
                               package, the reinstall-block policy key, and residual
                               WindowsApps folders / Start Menu shortcuts (informational).
                               Not elevated: only the current user can be scanned; the
                               output says so.
    -Action Remove             No prompt. Removes the Appx for every user (per SID, then
                               -AllUsers), removes the provisioned package, and creates
                               the Deprovisioned policy key that blocks reinstallation
                               (also when nothing was installed). Then verifies.
    -Action RemoveWithConsent  Same as Remove, but first shows a Yes/No message box in
                               the active console session (WTSSendMessage, 30 s
                               timeout). No / timeout / no user logged on = nothing
                               changed, exit 4. If 3D Viewer is not installed for any
                               user and not provisioned, no prompt is shown; only the
                               reinstall-block key is written.

    Requirements: Windows PowerShell 5.1. Remove modes need an elevated or SYSTEM session.
    -WhatIf previews Remove and RemoveWithConsent (no prompt, no changes).

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's
    remote shell) or an RMM component. The ENTRY POINT at the bottom picks the mode -
    edit that one line. For an RMM component also set $RMM = $true there, so the
    script exits with the code.

    Invoke-3DViewer                                    # Check (read-only)
    Invoke-3DViewer -Action Remove -WhatIf             # Preview removal
    Invoke-3DViewer -Action Remove                     # Remove, no prompt
    Invoke-3DViewer -Action RemoveWithConsent          # Ask the user first, then remove

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-3DViewer returns one; the entry point exits with it only when $RMM = $true):
        0    Check: not present / Remove: removed and verified (or -WhatIf)
        1    Error, or removal incomplete (see verification output)
        2    Check: 3D Viewer present (installed for a user or provisioned)
        4    RemoveWithConsent: user declined, prompt timed out, or no user to ask - nothing changed
        10   Remove/RemoveWithConsent: session is not elevated - nothing changed
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region -------------------- Test-3DViewerInstalled (read-only detection) --------------------

function Test-3DViewerInstalled {
    $results = [PSCustomObject]@{
        AppX           = $null
        AppX_AllUsers  = $null
        Users          = $null
        Provisioned    = $null
        BlockKey       = $false
        WindowsApps    = $null
        WindowsAppsResidual = $false
        StartMenu      = $null
        Installed      = $false
    }

    try {
        $appx = Get-AppxPackage -Name "Microsoft.Microsoft3DViewer" -EA SilentlyContinue
        if ($appx) { $results.AppX = $appx.Version.ToString(); $results.Installed = $true }
    } catch {}

    try {
        $appxAll = Get-AppxPackage -AllUsers -Name "Microsoft.Microsoft3DViewer" -EA SilentlyContinue
        if ($appxAll) {
            $results.AppX_AllUsers = ($appxAll | Select-Object -ExpandProperty PackageFullName) -join "; "
            $results.Users = ($appxAll.PackageUserInformation | ForEach-Object { "$_" }) -join "; "
            $results.Installed = $true
        }
    } catch {}

    try {
        $prov = Get-AppxProvisionedPackage -Online -EA SilentlyContinue |
            Where-Object { $_.DisplayName -eq "Microsoft.Microsoft3DViewer" }
        if ($prov) { $results.Provisioned = $prov.PackageName; $results.Installed = $true }
    } catch {}

    $results.BlockKey = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe"

    try {
        $wf = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.Microsoft3DViewer*" -EA SilentlyContinue
        if ($wf) {
            $results.WindowsApps = ($wf.Name -join ", ")
            $results.WindowsAppsResidual = $true
            # NOTE: do NOT set Installed=$true based on folder presence
        }
    } catch {}

    try {
        @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs") | ForEach-Object {
            $s = Get-ChildItem $_ -Recurse -Filter "*3D Viewer*" -EA SilentlyContinue
            # Informational only: a Store app has no .lnk, so a match is not proof of an install
            if ($s) { $results.StartMenu = ($s.FullName -join "; ") }
        }
    } catch {}

    return $results
}

#endregion

#region -------------------- Show-UserConsent (WTS Yes/No prompt) --------------------

function Show-UserConsent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$Title   = "Action Required",
        [string]$Message = "Do you agree to proceed?",
        [int]$TimeoutSeconds = 0
    )

    # Unique type name: other repo scripts define a different 'WTSHelper' (Unicode, byte lengths).
    if (-not ('Viewer3DWTSHelper' -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Viewer3DWTSHelper {
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

    $sessionId = [Viewer3DWTSHelper]::WTSGetActiveConsoleSessionId()

    $response = 0
    [Viewer3DWTSHelper]::WTSSendMessage([IntPtr]::Zero, $sessionId,
        $Title, $Title.Length,
        $Message, $Message.Length,
        $MB_YESNO, $TimeoutSeconds, [ref]$response, $true) | Out-Null

    return ($response -eq $IDYES)
}

#endregion

#region -------------------- Remove-Microsoft3DViewer (all users + provisioned + block) --------------------

function Remove-Microsoft3DViewer {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $pkg = 'Microsoft.Microsoft3DViewer'

    # Remove for every user (handles both Installed and Staged states)
    Get-AppxPackage -AllUsers -Name $pkg | ForEach-Object {
        $full = $_.PackageFullName
        foreach ($u in $_.PackageUserInformation) {
            $sid = $u.UserSecurityId.Sid
            if ($PSCmdlet.ShouldProcess("$full for $sid", 'Remove-AppxPackage')) {
                Remove-AppxPackage -Package $full -User $sid -ErrorAction SilentlyContinue
            }
        }
        # Deployment-level removal to clear any remaining staged registration
        if ($PSCmdlet.ShouldProcess($full, 'Remove-AppxPackage -AllUsers')) {
            Remove-AppxPackage -Package $full -AllUsers -ErrorAction SilentlyContinue
        }
    }

    # Remove provisioned package so new users don't get it
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $pkg | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.PackageName, 'Remove-AppxProvisionedPackage')) {
            Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # Block reinstall via deprovisioning policy
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\AppxAllUserStore\Deprovisioned\$pkg`_8wekyb3d8bbwe"
    if (-not (Test-Path $regPath)) {
        if ($PSCmdlet.ShouldProcess($regPath, 'New-Item (deprovision block)')) {
            New-Item -Path $regPath -Force | Out-Null
        }
    }

    # Verification (skipped in -WhatIf preview)
    if (-not $WhatIfPreference) {
        # Allow background cleanup / pending removals to finalize
        Start-Sleep -Seconds 5

        Write-Output ''
        Write-Output '--- Verification ---'

        $appx  = Get-AppxPackage -AllUsers -Name $pkg
        $prov  = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $pkg
        $block = Test-Path $regPath

        if (-not $appx) { Write-Output 'Appx: removed for all users' }
        else {
            Write-Output 'Appx: still present ->'
            $appx.PackageUserInformation | ForEach-Object { Write-Output "  $_" }
        }
        if (-not $prov)  { Write-Output 'Provisioned: removed' }     else { Write-Output 'Provisioned: STILL PRESENT' }
        if ($block)      { Write-Output 'Reinstall block: in place' } else { Write-Output 'Reinstall block: MISSING' }
    }
}

#endregion

#region -------------------- Invoke-3DViewer (dispatcher, returns the exit code) --------------------

function Invoke-3DViewer {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Remove', 'RemoveWithConsent')]
        [string]$Action = 'Check'
    )

    try {
        $admin = Test-IsAdmin
        if ($Action -ne 'Check' -and -not $admin) {
            Write-Host "ERROR: -Action $Action needs an elevated or SYSTEM session. Nothing changed." -ForegroundColor Red
            return 10
        }

        $state = Test-3DViewerInstalled
        if ($Action -eq 'Check') {
            $state | Format-List | Out-Host
            if (-not $admin) {
                Write-Host 'NOT ELEVATED: only the current user was scanned. AppX_AllUsers, Users, Provisioned and WindowsApps are incomplete - rerun elevated.' -ForegroundColor Yellow
            }
            if ($state.Installed) { Write-Host '3D Viewer: PRESENT' -ForegroundColor Yellow; return 2 }
            Write-Host '3D Viewer: not present'
            return 0
        }

        if ($Action -eq 'RemoveWithConsent') {
            if (-not $state.AppX_AllUsers -and -not $state.Provisioned) {
                Write-Host 'Not installed for any user and not provisioned - no prompt needed; ensuring the reinstall block only.'
            }
            elseif ($WhatIfPreference) {
                Write-Host 'What if: would ask the logged-on user (Yes/No, 30 s) before removing.'
            }
            elseif (Show-UserConsent -Title "Action Required" -Message "Patching this as it is now end of life. This should not affect your work. Allow/Deny?" -TimeoutSeconds 30) {
                Write-Host "User agreed"
            }
            else {
                Write-Host "User declined (or timed out / no user logged on). Nothing changed."
                return 4
            }
        }

        Remove-Microsoft3DViewer -WhatIf:$WhatIfPreference | Out-Host
        if ($WhatIfPreference) { return 0 }

        $after = Test-3DViewerInstalled
        if ($after.AppX_AllUsers -or $after.Provisioned -or -not $after.BlockKey) {
            Write-Host 'Removal INCOMPLETE (see verification above; a reboot may be needed if the app was in use).' -ForegroundColor Yellow
            return 1
        }
        Write-Host '3D Viewer removed for all users, deprovisioned, reinstall blocked.' -ForegroundColor Green
        return 0
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

$exitCode = Invoke-3DViewer                                    # Check (read-only)
# $exitCode = Invoke-3DViewer -Action Remove -WhatIf           # Preview removal, changes nothing
# $exitCode = Invoke-3DViewer -Action Remove                   # DESTRUCTIVE: removes for all users, no prompt
# $exitCode = Invoke-3DViewer -Action RemoveWithConsent        # DESTRUCTIVE after Yes: prompts the logged-on user (30 s)

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
