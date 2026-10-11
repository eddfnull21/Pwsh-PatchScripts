<#
.SYNOPSIS
    Microsoft 365 / Office Click-to-Run - Check / Remove (ALL C2R products). RMM-ready.

.DESCRIPTION
    -Mode Check   DEFAULT. Read-only. Reports whether Click-to-Run Office is installed, its
                  version and product IDs.
    -Mode Remove  Removes ALL Click-to-Run Office products with the Office Deployment Tool
                  (<Remove All="TRUE"/>, silent). Downloads the ODT from download.microsoft.com
                  to %TEMP%\OfficeScrub, checks it is signed by Microsoft, extracts setup.exe
                  (also signature-checked), runs the removal and verifies the C2R client is
                  gone. -WhatIf previews without downloading or removing anything.

    Requirements: Windows PowerShell 5.1. Remove needs an elevated or SYSTEM session.
    The ODT download URL is versioned; if Microsoft retires it, place setup.exe in
    %TEMP%\OfficeScrub and re-run.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session or an RMM component.
    The ENTRY POINT at the bottom picks the mode - edit that one line. For an RMM component
    also set $RMM = $true there, so the script exits with the code.

    Invoke-OfficeRemover                     # Check (read-only)
    Invoke-OfficeRemover -Mode Remove -WhatIf
    Invoke-OfficeRemover -Mode Remove        # removes ALL Click-to-Run Office

.NOTES
    Exit codes (Invoke-OfficeRemover returns one; the entry point exits with it only when $RMM = $true):
        0     Check: not installed / Remove: removed and verified, nothing to remove, or -WhatIf
        1     Error: download, signature, extraction or uninstall failed, or Office still present
        2     Check: Click-to-Run Office is installed
        10    Remove: session is not elevated - nothing changed
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$OfficeC2RClient = "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe"

function Test-MicrosoftSigned {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match '(?:^|,\s*)O="?Microsoft Corporation"?(?:,|$)')
}

#endregion

#region -------------------- Remove-OfficeC2R --------------------

function Remove-OfficeC2R {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    $odtUninstallConfig = @"
<Configuration>
  <Remove All="TRUE"/>
  <Display Level="None" AcceptEULA="TRUE"/>
  <Property Name="AUTOACTIVATE" Value="0"/>
</Configuration>
"@

    $c2rInstaller = $OfficeC2RClient
    $setupPath    = "$env:TEMP\OfficeScrub"
    $configPath   = "$setupPath\uninstall.xml"
    $odtPath      = "$setupPath\setup.exe"

    # Verify C2R is actually installed
    if (-not (Test-Path $c2rInstaller)) {
        Write-Host "No Click-to-Run Office installation found. Nothing to remove."
        return 0
    }

    # Get current version for logging
    $currentVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" `
        -ErrorAction SilentlyContinue).VersionToReport
    Write-Host "Detected Office C2R version: $currentVersion"

    if (-not $PSCmdlet.ShouldProcess("Office Click-to-Run $currentVersion (ALL products)", 'Download ODT and remove')) {
        return 0
    }

    # Download ODT setup.exe (skipped when setup.exe was placed there by hand)
    Write-Host "Preparing Office Deployment Tool..."
    New-Item -Path $setupPath -ItemType Directory -Force | Out-Null
    Set-Content -Path $configPath -Value $odtUninstallConfig -Encoding UTF8

    if (-not (Test-Path $odtPath)) {
        try {
            $odtUrl = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_19929-20062.exe"
            Write-Host "Downloading ODT..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $odtUrl -OutFile "$setupPath\odt.exe" -UseBasicParsing
            if (-not (Test-MicrosoftSigned "$setupPath\odt.exe")) {
                Write-Host "ODT download is not validly signed by Microsoft. Not run." -ForegroundColor Red
                return 1
            }
            Start-Process -FilePath "$setupPath\odt.exe" -ArgumentList "/quiet /extract:$setupPath" -Wait
        }
        catch {
            Write-Host "ODT download failed: $_" -ForegroundColor Red
            Write-Host "Place setup.exe manually in $setupPath and re-run."
            return 1
        }
    }

    if (-not (Test-Path $odtPath)) {
        Write-Host "setup.exe not found at $odtPath after extraction." -ForegroundColor Red
        return 1
    }
    if (-not (Test-MicrosoftSigned $odtPath)) {
        Write-Host "setup.exe at $odtPath is not validly signed by Microsoft. Not run." -ForegroundColor Red
        return 1
    }

    # Run uninstall
    Write-Host "Running Office uninstall - this may take several minutes..."
    $proc = Start-Process -FilePath $odtPath `
        -ArgumentList "/configure `"$configPath`"" `
        -Wait -PassThru

    if ($proc.ExitCode -ne 0) {
        Write-Host "ODT exited with code $($proc.ExitCode). Uninstall may have failed." -ForegroundColor Red
        return 1
    }

    # Verify removal
    if (Test-Path $c2rInstaller) {
        Write-Host "Uninstall completed but C2R files still detected. Manual review may be needed." -ForegroundColor Yellow
        return 1
    }
    Write-Host "Office C2R successfully removed." -ForegroundColor Green

    # Cleanup
    Remove-Item -Path $setupPath -Recurse -Force -ErrorAction SilentlyContinue
    return 0
}

#endregion

#region -------------------- Invoke-OfficeRemover (dispatcher, returns the exit code) --------------------

function Invoke-OfficeRemover {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Remove')]
        [string]$Mode = 'Check'
    )

    $ProgressPreference = 'SilentlyContinue'
    try {
        if ($Mode -eq 'Remove' -and -not (Test-IsAdmin)) {
            Write-Host 'ERROR: -Mode Remove needs an elevated or SYSTEM session. Nothing changed.' -ForegroundColor Red
            return 10
        }
        if ($Mode -eq 'Check') {
            if (-not (Test-Path $OfficeC2RClient)) { Write-Host 'Click-to-Run Office: not installed'; return 0 }
            $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
            Write-Host "Click-to-Run Office: PRESENT  version $($cfg.VersionToReport)  products $($cfg.ProductReleaseIds)" -ForegroundColor Yellow
            return 2
        }
        return [int](Remove-OfficeC2R -Confirm:$false -WhatIf:$WhatIfPreference)
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

$exitCode = Invoke-OfficeRemover                          # Check (read-only)
# $exitCode = Invoke-OfficeRemover -Mode Remove -WhatIf   # Preview, downloads and removes nothing
# $exitCode = Invoke-OfficeRemover -Mode Remove           # DESTRUCTIVE: removes ALL Click-to-Run Office

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
