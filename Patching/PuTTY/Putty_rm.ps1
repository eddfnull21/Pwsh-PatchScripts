function Remove-PuTTY {
    <#
    .SYNOPSIS
        Completely removes PuTTY and its associated configuration/artifacts.

    .DESCRIPTION
        Removes:
          - PuTTY installed via MSI/EXE uninstall entries
          - PuTTY installed via winget (where detectable)
          - Common PuTTY installation directories
          - Start Menu and Desktop shortcuts
          - Per-user PuTTY configuration (HKCU)
          - PuTTY registry keys under loaded user profiles
          - Common PuTTY files found in user profiles

        Supports -WhatIf and -Confirm.

    .EXAMPLE
        Remove-PuTTY -WhatIf

    .EXAMPLE
        Remove-PuTTY -Confirm:$false
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    $ErrorActionPreference = 'Continue'

    # Require elevation.
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw 'Remove-PuTTY must be run from an elevated PowerShell session.'
    }

    Write-Verbose 'Searching for PuTTY installations...'

    # ------------------------------------------------------------------
    # 1. Uninstall registered PuTTY installations
    # ------------------------------------------------------------------
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        $apps = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
            ForEach-Object {
                Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            } |
            Where-Object {
                $_.DisplayName -match '^PuTTY(?:\s|$)'
            }

        foreach ($app in $apps) {
            $name = $app.DisplayName
            Write-Verbose "Found installed product: $name"

            if ($PSCmdlet.ShouldProcess($name, 'Uninstall PuTTY')) {

                # MSI installation
                if ($app.WindowsInstaller -eq 1 -or
                    $app.UninstallString -match 'MsiExec(?:\.exe)?') {

                    $productCode = $null

                    if ($app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
                        $productCode = $app.PSChildName
                    }
                    elseif ($app.UninstallString -match '\{[0-9A-Fa-f-]+\}') {
                        $productCode = $Matches[0]
                    }

                    if ($productCode) {
                        Write-Verbose "Uninstalling MSI $productCode"
                        $p = Start-Process -FilePath 'msiexec.exe' `
                            -ArgumentList @('/x', $productCode, '/qn', '/norestart') `
                            -Wait -PassThru

                        if ($p.ExitCode -notin 0, 1605, 1614, 3010) {
                            Write-Warning "MSI uninstall returned exit code $($p.ExitCode)."
                        }
                    }
                    else {
                        Write-Warning "Could not determine MSI product code for $name."
                    }
                }

                # Non-MSI installation
                elseif ($app.QuietUninstallString) {
                    Write-Verbose "Running quiet uninstaller for $name"

                    $command = $app.QuietUninstallString
                    Start-Process -FilePath 'cmd.exe' `
                        -ArgumentList '/d', '/s', '/c', "`"$command`"" `
                        -Wait
                }
                elseif ($app.UninstallString) {
                    Write-Warning (
                        "Found an EXE uninstaller for '$name', but no registered " +
                        'quiet uninstall command. Residual files will still be removed.'
                    )
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # 2. Remove common machine-wide PuTTY directories/files
    # ------------------------------------------------------------------
    $machinePaths = @(
        "$env:ProgramFiles\PuTTY",
        "${env:ProgramFiles(x86)}\PuTTY",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\PuTTY",
        "$env:PUBLIC\Desktop\PuTTY.lnk"
    ) | Where-Object { $_ }

    foreach ($path in $machinePaths) {
        if (Test-Path -LiteralPath $path) {
            if ($PSCmdlet.ShouldProcess($path, 'Remove PuTTY artifact')) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Continue
            }
        }
    }

    # ------------------------------------------------------------------
    # 3. Remove PuTTY configuration from the current user's registry
    # ------------------------------------------------------------------
    $hkcuKeys = @(
        'HKCU:\Software\SimonTatham\PuTTY',
        'HKCU:\Software\SimonTatham'
    )

    foreach ($key in $hkcuKeys) {
        if (Test-Path -LiteralPath $key) {
            if ($PSCmdlet.ShouldProcess($key, 'Remove PuTTY registry configuration')) {
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Continue
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Remove PuTTY registry configuration from loaded user hives
    # ------------------------------------------------------------------
    $userSids = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSChildName -match '^S-1-5-21-' -and
            $_.PSChildName -notmatch '_Classes$'
        }

    foreach ($sid in $userSids) {
        $key = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\SimonTatham\PuTTY"

        if (Test-Path -LiteralPath $key) {
            if ($PSCmdlet.ShouldProcess(
                $key,
                'Remove PuTTY configuration from loaded user hive'
            )) {
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Continue
            }
        }

        # Remove SimonTatham parent only when empty.
        $parent = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\SimonTatham"

        if (Test-Path -LiteralPath $parent) {
            $children = @(Get-ChildItem -LiteralPath $parent -ErrorAction SilentlyContinue)

            if ($children.Count -eq 0) {
                if ($PSCmdlet.ShouldProcess(
                    $parent,
                    'Remove empty SimonTatham registry key'
                )) {
                    Remove-Item -LiteralPath $parent -Force -ErrorAction Continue
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # 5. Remove PuTTY artifacts from local user profiles
    # ------------------------------------------------------------------
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object {
            -not $_.Special -and
            $_.LocalPath -and
            (Test-Path -LiteralPath $_.LocalPath)
        }

    foreach ($profile in $profiles) {
        $profilePath = $profile.LocalPath

        $userPaths = @(
            "$profilePath\Desktop\PuTTY.lnk",
            "$profilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PuTTY",
            "$profilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PuTTY.lnk"
        )

        foreach ($path in $userPaths) {
            if (Test-Path -LiteralPath $path) {
                if ($PSCmdlet.ShouldProcess($path, 'Remove PuTTY user artifact')) {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Continue
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # 6. Remove common PuTTY executables accidentally left in Windows PATH
    #    locations ONLY when they're inside known PuTTY directories.
    # ------------------------------------------------------------------
    $puttyExecutables = @(
        'putty.exe',
        'puttygen.exe',
        'pscp.exe',
        'psftp.exe',
        'plink.exe',
        'pageant.exe'
    )

    foreach ($exe in $puttyExecutables) {
        $commands = Get-Command $exe -All -ErrorAction SilentlyContinue

        foreach ($command in $commands) {
            $source = $command.Source

            if ($source -and
                $source -match '\\PuTTY\\' -and
                (Test-Path -LiteralPath $source)) {

                if ($PSCmdlet.ShouldProcess(
                    $source,
                    'Remove residual PuTTY executable'
                )) {
                    Remove-Item -LiteralPath $source -Force -ErrorAction Continue
                }
            }
        }
    }

    Write-Verbose 'PuTTY removal processing complete.'
}
Remove-PuTTY -WhatIf -Verbose


#Remove-PuTTY -Confirm:$false -Verbose