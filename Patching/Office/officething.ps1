<#
.SYNOPSIS
    Microsoft 365 / Office Click-to-Run - Check / Update / UpdateAsUser. RMM-ready.

.DESCRIPTION
    -Mode Check         DEFAULT. Read-only. Shows the C2R client, Office version, update channel
                        and the interactively logged-on user.
    -Mode Update        Asks OfficeC2RClient.exe for an update in the current account (no prompt,
                        apps are NOT force-closed).
    -Mode UpdateAsUser  Same, but runs it as the logged-on user through a one-off scheduled task
                        (removed again after 5 s) - for when SYSTEM-context updates don't apply.

    Requirements: Windows PowerShell 5.1. Update and UpdateAsUser need an elevated or SYSTEM session.

.EXAMPLE
    Paste the WHOLE script; pick the mode in the ENTRY POINT at the bottom.

    Invoke-OfficeUpdate                        # Check (read-only)
    Invoke-OfficeUpdate -Mode Update
    Invoke-OfficeUpdate -Mode UpdateAsUser

.NOTES
    Exit codes (Invoke-OfficeUpdate returns one; the entry point exits with it only when $RMM = $true):
        0     Check done / update request submitted
        1     Error (C2R client missing, no logged-on user, task failed)
        10    Update / UpdateAsUser: session is not elevated - nothing changed
    Check cannot tell whether an update is pending, so it never returns 2.
#>

#region -------------------- Update-Office / Update-OfficeAsLoggedOnUser --------------------

function Update-Office {
    [CmdletBinding()]
    param()

    $OfficeC2R = @(
        "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
        "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -First 1

    if (-not $OfficeC2R) {
        throw "Microsoft Office Click-to-Run client was not found."
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    Start-Process -FilePath $OfficeC2R -ArgumentList @(
        "/update"
        "user"
        "updatepromptuser=false"
        "forceappshutdown=false"
        "displaylevel=false"
    )

    Write-Output "Office update request submitted under account: $identity"
}

function Update-OfficeAsLoggedOnUser {
    [CmdletBinding()]
    param()

    $OfficeC2R = @(
        "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
        "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    ) | Where-Object {
        $_ -and (Test-Path -LiteralPath $_)
    } | Select-Object -First 1

    if (-not $OfficeC2R) {
        throw "Microsoft Office Click-to-Run client was not found."
    }

    $LoggedOnUser = (Get-CimInstance Win32_ComputerSystem).UserName

    if (-not $LoggedOnUser) {
        throw "No interactively logged-on user was found."
    }

    $TaskName = "OfficeUpdate-$([guid]::NewGuid().ToString('N'))"

    $Arguments = '/update user updatepromptuser=false forceappshutdown=false displaylevel=false'

    $Action = New-ScheduledTaskAction `
        -Execute $OfficeC2R `
        -Argument $Arguments

    $Principal = New-ScheduledTaskPrincipal `
        -UserId $LoggedOnUser `
        -LogonType Interactive `
        -RunLevel Limited

    try {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $Action `
            -Principal $Principal `
            -Force `
            -ErrorAction Stop | Out-Null

        Start-ScheduledTask -TaskName $TaskName

        Write-Output "Office update submitted as logged-on user: $LoggedOnUser"
    }
    finally {
        Start-Sleep -Seconds 5

        Unregister-ScheduledTask `
            -TaskName $TaskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
}

#endregion

#region -------------------- Invoke-OfficeUpdate (dispatcher, returns the exit code) --------------------

function Invoke-OfficeUpdate {
    [CmdletBinding()]
    param(
        [ValidateSet('Check', 'Update', 'UpdateAsUser')]
        [string]$Mode = 'Check'
    )

    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($Mode -ne 'Check' -and -not $isAdmin) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session. Nothing changed." -ForegroundColor Red
            return 10
        }
        switch ($Mode) {
            'Check' {
                $client = @(
                    "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
                    "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
                ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
                $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
                Write-Host "C2R client     : $(if ($client) { $client } else { 'not found' })"
                Write-Host "Office version : $($cfg.VersionToReport)"
                Write-Host "Update channel : $(if ($cfg.UpdateChannel) { $cfg.UpdateChannel } else { $cfg.CDNBaseUrl })"
                Write-Host "Logged-on user : $((Get-CimInstance Win32_ComputerSystem).UserName)"
                return 0
            }
            'Update'       { Update-Office | Out-Host; return 0 }
            'UpdateAsUser' { Update-OfficeAsLoggedOnUser | Out-Host; return 0 }
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
# sees the result. Leave $false when pasting into a console or RMM remote shell.
$RMM = $false

$exitCode = Invoke-OfficeUpdate                          # Check (read-only)
# $exitCode = Invoke-OfficeUpdate -Mode Update           # LIVE: request an Office update (apps not force-closed)
# $exitCode = Invoke-OfficeUpdate -Mode UpdateAsUser     # LIVE: same, as the logged-on user (one-off task)

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
