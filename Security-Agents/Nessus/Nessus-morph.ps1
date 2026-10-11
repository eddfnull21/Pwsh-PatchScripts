# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Tenable Nessus Agent / Scanner - Check / Remove / ForceClean / Link. RMM-ready.

.DESCRIPTION
    -Mode Check       DEFAULT. Read-only. Lists Nessus uninstall registrations, services,
                      processes, standard folders, Tenable registry keys and Windows Installer
                      product entries, then shows 'nessuscli agent status --show-uuid'.
                      The token, 'fix --list' and 'fix --secure --list' are NOT shown: they can
                      print the agent token / linking key into RMM output.
    -Mode Remove      Clean uninstall (Remove-Nessus): stops services and processes, runs
                      msiexec /x for every Tenable Nessus MSI product (logs in %TEMP%), then
                      deletes leftover services, folders and registry keys. Refuses before any
                      change if a registered uninstaller is not MSI. -WhatIf lists each target.
    -Mode ForceClean  Fallback for a broken install that msiexec cannot remove or reinstall
                      over: stops the agent, kills processes, deletes the agent folder and
                      registry key, the known agent uninstall keys, and the Nessus entries in
                      HKLM\SOFTWARE\Classes\Installer\Products (Windows then treats it as not
                      installed). No msiexec. The agent service registration is left in place.
    -Mode Link        Links an installed agent to Tenable cloud with nessuscli. Needs
                      -Options @{ Key = '<linking key>'; Groups = '<group>'; Network = '<network>' }.
                      Name defaults to the computer name. Never hardcode a live key in this file.

    Requirements: Windows PowerShell 5.1, 64-bit for Remove. Remove, ForceClean and Link need an
    elevated or SYSTEM session. -WhatIf previews Remove, ForceClean and Link.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the mode - edit that one
    line. For an RMM component also set $RMM = $true there, so the script exits with the code.

    Invoke-Nessus                                   # Check (read-only)
    Invoke-Nessus -Mode Remove -WhatIf              # Preview clean uninstall
    Invoke-Nessus -Mode Remove                      # Clean uninstall
    Invoke-Nessus -Mode ForceClean -WhatIf          # Preview forced cleanup
    Invoke-Nessus -Mode ForceClean                  # Forced cleanup of a broken install
    Invoke-Nessus -Mode Link -Options @{ Key = $env:NessusKey; Groups = 'MyGroup'; Network = 'MyNetwork' }

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-Nessus returns one; the entry point exits with it only when $RMM = $true):
        0     Check: no Nessus footprint / Remove, ForceClean, Link: done (or -WhatIf)
        1     Error, or removal incomplete / link failed (see output)
        2     Check: Nessus footprint present (something for Remove / ForceClean to act on)
        3010  Remove: done, restart required to finish
        10    Remove / ForceClean / Link: session is not elevated - nothing changed
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$NessusCli = "C:\Program Files\Tenable\Nessus Agent\nessuscli.exe"

#endregion

#region -------------------- Get-NessusState (read-only detection) --------------------

function Get-NessusState {
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $folders = @(
        foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
            if ($base) { Join-Path $base 'Tenable\Nessus Agent'; Join-Path $base 'Tenable\Nessus' }
        }
    ) | Sort-Object -Unique
    $registryPaths = @(
        'HKLM:\SOFTWARE\Tenable\Nessus Agent'
        'HKLM:\SOFTWARE\Tenable\Nessus'
        'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus Agent'
        'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus'
    )

    $state = [pscustomobject]@{
        Products          = @(foreach ($root in $uninstallRoots) {
                                if (Test-Path -LiteralPath $root) {
                                    Get-ItemProperty "$root\*" -EA SilentlyContinue |
                                        Where-Object { $_.DisplayName -match '(?i)\bNessus\b' } |
                                        Select-Object DisplayName, DisplayVersion, Publisher, PSChildName, UninstallString
                                }
                            })
        Services          = @(Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)nessus' -or $_.DisplayName -match '(?i)\bNessus\b' } |
                                Select-Object Name, DisplayName, Status, StartType)
        Processes         = @(Get-Process -Name 'nessus*' -EA SilentlyContinue | Select-Object ProcessName, Id)
        Folders           = @($folders | Where-Object { Test-Path -LiteralPath $_ })
        RegistryKeys      = @($registryPaths | Where-Object { Test-Path -LiteralPath $_ })
        InstallerProducts = @(Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -EA SilentlyContinue |
                                Where-Object { (Get-ItemProperty $_.PSPath -EA SilentlyContinue).ProductName -like '*Nessus*' } |
                                ForEach-Object { $_.PSChildName })
        Present           = $false
    }
    $state.Present = [bool]($state.Products.Count + $state.Services.Count + $state.Processes.Count +
                            $state.Folders.Count + $state.RegistryKeys.Count + $state.InstallerProducts.Count)
    return $state
}

function Show-NessusState {
    param($State)
    Write-Host '=== Uninstall registrations ===' -ForegroundColor Cyan
    if ($State.Products) { $State.Products | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Services ===' -ForegroundColor Cyan
    if ($State.Services) { $State.Services | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Processes ===' -ForegroundColor Cyan
    if ($State.Processes) { $State.Processes | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }
    Write-Host '=== Folders ===' -ForegroundColor Cyan
    if ($State.Folders) { $State.Folders | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  none' }
    Write-Host '=== Registry keys ===' -ForegroundColor Cyan
    if ($State.RegistryKeys) { $State.RegistryKeys | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  none' }
    Write-Host '=== Windows Installer product entries (Classes\Installer\Products) ===' -ForegroundColor Cyan
    if ($State.InstallerProducts) { $State.InstallerProducts | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  none' }
}

#endregion

#region -------------------- Remove-Nessus (clean MSI uninstall + leftovers) --------------------

function Remove-Nessus {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $ErrorActionPreference = 'Stop'
    $rebootRequired = $false

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw 'Run this function in PowerShell as Administrator.'
    }

    if ([Environment]::Is64BitOperatingSystem -and
        -not [Environment]::Is64BitProcess) {
        throw 'Run this function in 64-bit PowerShell.'
    }

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $serviceFilter = {
        $_.Name -match '(?i)nessus' -or
        $_.DisplayName -match '(?i)\bNessus\b'
    }

    $products = @(
        foreach ($root in $uninstallRoots) {
            if (Test-Path -LiteralPath $root) {
                Get-ItemProperty "$root\*" |
                    Where-Object {
                        $_.DisplayName -match '(?i)\bNessus\b' -and
                        $_.Publisher -match '(?i)Tenable'
                    }
            }
        }
    )

    $folders = @(
        foreach ($base in @(
            $env:ProgramFiles
            ${env:ProgramFiles(x86)}
            $env:ProgramData
        )) {
            if ($base) {
                Join-Path $base 'Tenable\Nessus Agent'
                Join-Path $base 'Tenable\Nessus'
            }
        }
    ) | Sort-Object -Unique

    $registryPaths = @(
        'HKLM:\SOFTWARE\Tenable\Nessus Agent'
        'HKLM:\SOFTWARE\Tenable\Nessus'
        'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus Agent'
        'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus'
    )

    # Identify products that cannot be uninstalled automatically.
    $unsupportedProducts = @(
        foreach ($product in $products) {
            if (
                $product.PSChildName -notmatch
                    '^\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$' -or
                (
                    $product.WindowsInstaller -ne 1 -and
                    $product.UninstallString -notmatch '(?i)msiexec'
                )
            ) {
                $product
            }
        }
    )

    # Detailed, read-only preview.
    if ($WhatIfPreference) {
        $preview = @(
            Get-Service | Where-Object $serviceFilter |
                ForEach-Object {
                    [pscustomobject]@{
                        Action = 'Stop service'
                        Target = "$($_.Name) [$($_.DisplayName)] - $($_.Status)"
                    }
                }

            Get-Process -Name 'nessus*' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        Action = 'Stop process'
                        Target = "$($_.ProcessName) [PID $($_.Id)]"
                    }
                }

            foreach ($product in (
                $products | Sort-Object PSChildName -Unique
            )) {
                if ($unsupportedProducts.PSPath -contains $product.PSPath) {
                    Write-Warning "Unsupported uninstaller: $($product.DisplayName). Actual removal will stop before making changes."
                    continue
                }

                [pscustomobject]@{
                    Action = 'Uninstall MSI product'
                    Target = "$($product.DisplayName) [$($product.PSChildName)]"
                }

                $log = Join-Path $env:TEMP (
                    "Nessus-Uninstall-$($product.PSChildName).log"
                )

                Write-Verbose (
                    'Uninstall command: msiexec.exe /x {0} /qn /norestart /L*v "{1}"' -f
                    $product.PSChildName, $log
                )
            }

            Get-Service | Where-Object $serviceFilter |
                ForEach-Object {
                    [pscustomobject]@{
                        Action = 'Delete service if remaining after uninstall'
                        Target = $_.Name
                    }
                }

            foreach ($folder in $folders) {
                if (Test-Path -LiteralPath $folder) {
                    [pscustomobject]@{
                        Action = 'Delete folder and all contents if remaining'
                        Target = $folder
                    }
                } else {
                    Write-Verbose "Folder absent: $folder"
                }
            }

            foreach ($path in $registryPaths) {
                if (Test-Path -LiteralPath $path) {
                    [pscustomobject]@{
                        Action = 'Delete registry key and subkeys if remaining'
                        Target = $path
                    }
                } else {
                    Write-Verbose "Registry key absent: $path"
                }
            }
        )

        if ($preview.Count -eq 0) {
            Write-Host 'No automatically removable Nessus targets found in the checked locations.'
        } else {
            foreach ($item in $preview) {
                [void]$PSCmdlet.ShouldProcess(
                    $item.Target,
                    $item.Action
                )
            }
        }

        Write-Verbose 'Cleanup targets reflect current state; MSI uninstall may remove them first.'
        Write-Host 'Preview complete. No changes made.'
        return
    }

    # Validate before performing any changes.
    if ($unsupportedProducts.Count -gt 0) {
        throw (
            'Cannot automatically uninstall these products: {0}. Use their registered uninstallers first.' -f
            ($unsupportedProducts.DisplayName -join ', ')
        )
    }

    # Approve the complete operation together so declining an uninstall
    # cannot be followed by destructive cleanup.
    $target = 'Local Nessus Agent and Nessus Scanner installations'
    $action = 'Uninstall and delete Nessus services, standard folders, scan data, configuration, and registry settings'

    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        return
    }

    Get-Service | Where-Object $serviceFilter |
        ForEach-Object {
            if ($_.Status -ne 'Stopped') {
                Write-Verbose "Stopping service: $($_.Name)"
                Stop-Service -InputObject $_ -Force -Confirm:$false
            }
        }

    Get-Process -Name 'nessus*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Verbose "Stopping process: $($_.ProcessName) [PID $($_.Id)]"
            Stop-Process -InputObject $_ -Force -Confirm:$false
        }

    # Windows Installer maintains its own registration database.
    foreach ($product in (
        $products | Sort-Object PSChildName -Unique
    )) {
        $code = $product.PSChildName
        $log = Join-Path $env:TEMP "Nessus-Uninstall-$code.log"

        Write-Verbose "Uninstalling: $($product.DisplayName) [$code]"
        Write-Verbose "MSI log: $log"

        $process = Start-Process -FilePath 'msiexec.exe' `
            -ArgumentList "/x $code /qn /norestart /L*v `"$log`"" `
            -Wait -PassThru

        switch ($process.ExitCode) {
            0 {
                Write-Verbose 'Uninstall completed successfully.'
            }
            1605 {
                Write-Verbose 'Product is already uninstalled.'
            }
            3010 {
                Write-Verbose 'Uninstall completed; restart required.'
                $rebootRequired = $true
            }
            default {
                throw "Uninstall failed with code $($process.ExitCode). Cleanup stopped. Log: $log"
            }
        }
    }

    # Remove services that remain after uninstall.
    foreach ($service in @(
        Get-Service | Where-Object $serviceFilter
    )) {
        if ($service.Status -ne 'Stopped') {
            Write-Verbose "Stopping remaining service: $($service.Name)"
            Stop-Service -InputObject $service -Force -Confirm:$false
        }

        Write-Verbose "Deleting remaining service: $($service.Name)"
        $output = & sc.exe delete $service.Name 2>&1

        if ($LASTEXITCODE -notin @(0, 1060, 1072)) {
            throw "Could not delete service '$($service.Name)': $output"
        }

        $rebootRequired = $true
    }

    Get-Process -Name 'nessus*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Verbose "Stopping remaining process: $($_.ProcessName) [PID $($_.Id)]"
            Stop-Process -InputObject $_ -Force -Confirm:$false
        }

    foreach ($folder in $folders) {
        if (Test-Path -LiteralPath $folder) {
            Write-Verbose "Deleting folder and contents: $folder"
            Remove-Item -LiteralPath $folder `
                -Recurse -Force -Confirm:$false
        } else {
            Write-Verbose "Folder absent: $folder"
        }
    }

    foreach ($path in $registryPaths) {
        if (Test-Path -LiteralPath $path) {
            Write-Verbose "Deleting registry key: $path"
            Remove-Item -LiteralPath $path `
                -Recurse -Force -Confirm:$false
        } else {
            Write-Verbose "Registry key absent: $path"
        }
    }

    $remaining = @(
        foreach ($root in $uninstallRoots) {
            if (Test-Path -LiteralPath $root) {
                Get-ItemProperty "$root\*" |
                    Where-Object {
                        $_.DisplayName -match '(?i)\bNessus\b' -and
                        $_.Publisher -match '(?i)Tenable'
                    }
            }
        }
    )

    if ($remaining.Count -gt 0) {
        Write-Warning "Installation registrations remain: $($remaining.DisplayName -join ', ')"
    }

    if ($rebootRequired) {
        Write-Warning 'Restart Windows to finish removal.'
    }

    [pscustomobject]@{
        CleanupCompleted       = $true
        RemainingRegistrations = $remaining.Count
        RebootRequired         = $rebootRequired
    }
}

#endregion

#region -------------------- Clear-NessusAgentForced (from Nessus_install_fix.ps1) --------------------

function Clear-NessusAgentForced {
    # No ShouldProcess calls needed: Stop-Service / Stop-Process / Remove-Item honour the inherited -WhatIf.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    # Stop & kill any nessus processes
    Stop-Service "Tenable Nessus Agent" -Force -ErrorAction SilentlyContinue
    Get-Process -Name "nessus*","nessusd*" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove install directory
    Remove-Item "C:\Program Files\Tenable\Nessus Agent" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove registry entries
    Remove-Item "HKLM:\SOFTWARE\Tenable\Nessus Agent" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D24D0B45-4A7F-4745-92B5-52ADCC481816}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D2D0FC19-AAF5-4F2F-B4B6-DA713C90859B}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D0822BC1-BFBE-44E9-BC56-7378EFE30433}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AE6C4895-0C2F-48D7-BB54-80DC613374CD}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9F32B408-032A-4198-8E68-B7C23B970F89}" -Recurse -Force -ErrorAction SilentlyContinue

    # Clean up MSI database entry (tricks Windows into thinking it's uninstalled)
    $key = "HKLM:\SOFTWARE\Classes\Installer\Products"
    Get-ChildItem $key | Where-Object { (Get-ItemProperty $_.PSPath).ProductName -like "*Nessus*" } | Remove-Item -Recurse -Force
}

#endregion

#region -------------------- Connect-NessusAgent (from Nessus_install_fix.ps1) --------------------

function Connect-NessusAgent {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Key,
        [string]$Name = $env:COMPUTERNAME,   # uses machine hostname automatically
        [string]$Groups,
        [string]$Network
    )

    if (-not $Key -or $Key -match '^(YOUR_LINKING_KEY|changeme)') { throw 'Link needs a real linking key: -Options @{ Key = ... }' }
    if (-not (Test-Path -LiteralPath $NessusCli)) { throw "nessuscli not found: $NessusCli. Install the agent first." }

    # Target text leaves the key out so it never lands in RMM output.
    if (-not $PSCmdlet.ShouldProcess("agent '$Name' (groups '$Groups', network '$Network')", 'nessuscli agent link --cloud')) { return 0 }
    & $NessusCli agent link --key=$Key --cloud --name=$Name --groups=$Groups --network=$Network | Out-Host
    return $LASTEXITCODE
}

#endregion

#region -------------------- Invoke-Nessus (dispatcher, returns the exit code) --------------------

function Invoke-Nessus {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Remove', 'ForceClean', 'Link')]
        [string]$Mode = 'Check',
        [hashtable]$Options = @{}
    )

    try {
        if ($Mode -ne 'Check' -and -not (Test-IsAdmin)) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session. Nothing changed." -ForegroundColor Red
            return 10
        }

        switch ($Mode) {
            'Check' {
                $state = Get-NessusState
                Show-NessusState $state
                if (Test-Path -LiteralPath $NessusCli) {
                    Write-Host '=== Agent status (token hidden) ===' -ForegroundColor Cyan
                    & $NessusCli agent status --show-uuid 2>&1 | Out-Host
                }
                if (-not (Test-IsAdmin)) { Write-Host 'NOT ELEVATED: agent status may be refused; rerun elevated.' -ForegroundColor Yellow }
                if ($state.Present) { Write-Host 'Nessus: PRESENT' -ForegroundColor Yellow; return 2 }
                Write-Host 'Nessus: not present'
                return 0
            }
            'Remove' {
                $result = Remove-Nessus -Verbose -WhatIf:$WhatIfPreference
                if ($WhatIfPreference) { return 0 }
                $result | Format-List | Out-Host
                if (-not $result -or $result.RemainingRegistrations -gt 0) { return 1 }
                if ($result.RebootRequired) { return 3010 }
                return 0
            }
            'ForceClean' {
                Clear-NessusAgentForced -WhatIf:$WhatIfPreference
                if ($WhatIfPreference) { return 0 }
                Write-Host '--- Verification ---'
                $after = Get-NessusState
                Show-NessusState $after
                if ($after.Products.Count + $after.Folders.Count + $after.RegistryKeys.Count + $after.InstallerProducts.Count) {
                    Write-Host 'Forced cleanup INCOMPLETE (leftovers outside the agent paths, or files in use - try Remove, or reboot and rerun).' -ForegroundColor Yellow
                    return 1
                }
                Write-Host 'Forced cleanup done. Reinstall the agent, then Link.' -ForegroundColor Green
                return 0
            }
            'Link' {
                $rc = Connect-NessusAgent @Options -WhatIf:$WhatIfPreference
                if ($rc -ne 0) { Write-Host "nessuscli agent link failed (exit $rc)." -ForegroundColor Red; return 1 }
                return 0
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

$exitCode = Invoke-Nessus                                      # Check (read-only)
# $exitCode = Invoke-Nessus -Mode Remove -WhatIf               # Preview clean uninstall, changes nothing
# $exitCode = Invoke-Nessus -Mode Remove                       # DESTRUCTIVE: msiexec uninstall + delete folders, scan data, registry
# $exitCode = Invoke-Nessus -Mode ForceClean -WhatIf           # Preview forced cleanup, changes nothing
# $exitCode = Invoke-Nessus -Mode ForceClean                   # DESTRUCTIVE: broken-install purge, no msiexec
# $exitCode = Invoke-Nessus -Mode Link -Options @{ Key = $env:NessusKey; Groups = '<group>'; Network = '<network>' }

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
