# Update 7-Zip with winget - run by hand only (the file's default is the Uninstall-7Zip -WhatIf preview below):
# $winget = "$((Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller | Select-Object -Last 1).InstallLocation)\winget.exe"

# if (-not (Test-Path -LiteralPath $winget -PathType Leaf)) {
#     throw "winget.exe was not found. Ensure Microsoft App Installer is installed."
# }

# & $winget upgrade --id 7zip.7zip --exact --source winget `
#     --scope machine `
#     --silent `
#     --disable-interactivity `
#     --accept-package-agreements `
#     --accept-source-agreements

# write-host $LASTEXITCODE

#winget series

Remove-Module PSReadLine -ErrorAction SilentlyContinue

function Uninstall-7Zip {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    # All persistent changes are guarded by this function's ShouldProcess.
    # No Win32_Product queries, downloads, forced process termination,
    # registry ownership changes, or explicit output/log files.

    $ErrorActionPreference = 'Stop'
    $preview = [bool]$WhatIfPreference
    $blocked = $false
    $cleanupAllowed = $true
    $failures = 0
    $rebootRequired = $false

    if ($env:OS -ne 'Windows_NT') {
        throw 'This function requires Windows.'
    }
    if ($PSVersionTable.PSVersion -lt [version]'5.1') {
        throw 'Use Windows PowerShell 5.1 or PowerShell 7.'
    }
    if ([Environment]::Is64BitOperatingSystem -and
        -not [Environment]::Is64BitProcess) {
        throw 'Open a 64-bit PowerShell session so both registry views are checked.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $admin = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    Write-Host "Mode: $(if ($preview) { 'WHATIF / read-only' } else { 'APPLY' })"
    Write-Host "Account: $($identity.Name); Administrator: $admin"
    Write-Host 'Scope: machine installations and the current Windows account.'
    Write-Host 'Cleanup is conditional on successful removal of all detected installations.'

    if (-not $admin) {
        Write-Warning 'Missing prerequisite: elevation. Preview continues; actual changes require Run as administrator.'
        $blocked = $true
    }

    $running = @(Get-Process -ErrorAction Stop |
        Where-Object { $_.ProcessName -in @('7z', '7zFM', '7zG') })

    foreach ($process in $running) {
        Write-Warning "Running process: $($process.ProcessName), PID $($process.Id). Close it before removal."
    }
    if ($running.Count) {
        $blocked = $true
    }

    Write-Host 'Explorer may hold the 7-Zip shell DLL open; a sign-out or restart may be needed.'

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $settingsKeys = @(
        'HKLM:\SOFTWARE\7-Zip'
        'HKLM:\SOFTWARE\WOW6432Node\7-Zip'
        'HKCU:\SOFTWARE\7-Zip'
        'HKCU:\SOFTWARE\WOW6432Node\7-Zip'
    )

    $folders = @()
    foreach ($base in @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432
    )) {
        if ($base) {
            $folders += Join-Path $base '7-Zip'
        }
    }
    if ($env:LOCALAPPDATA) {
        $folders += Join-Path $env:LOCALAPPDATA 'Programs\7-Zip'
    }

    $plans = @()
    $registrations = @()
    $seenCommands = @{}

    # Read-only discovery. Any inventory failure prevents actual cleanup.
    foreach ($root in $uninstallRoots) {
        try {
            if (-not (Test-Path -LiteralPath $root)) { continue }

            foreach ($key in Get-ChildItem -LiteralPath $root) {
                $entry = Get-ItemProperty -LiteralPath $key.PSPath

                # Match official-style names, excluding forks such as 7-Zip ZS.
                if ($entry.DisplayName -notmatch
                    '^7-Zip(?: \d[\w.-]*(?: \([^)]+\))?)?$') {
                    continue
                }

                $registrations += $key.PSPath
                Write-Host "FOUND: $($entry.DisplayName) [$($entry.DisplayVersion)]"
                Write-Host "  Registry: $($key.Name)"
                Write-Host "  Publisher: $($entry.Publisher)"
                Write-Host "  UninstallString: $($entry.UninstallString)"

                if ($entry.InstallLocation) {
                    $folders += [Environment]::ExpandEnvironmentVariables(
                        ([string]$entry.InstallLocation).Trim().Trim('"')
                    )
                }

                $exe = $null
                $arguments = $null
                $kind = 'EXE'
                $problem = $null

                if ($entry.WindowsInstaller -eq 1) {
                    $kind = 'MSI'
                    $productCode = $key.PSChildName
                    if ($productCode -notmatch
                        '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') {
                        $problem = 'MSI registration has no valid product-code GUID.'
                    } else {
                        $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
                        $arguments = "/x $productCode /qn /norestart"
                    }
                } else {
                    $raw = [Environment]::ExpandEnvironmentVariables(
                        [string]$entry.UninstallString
                    )
                    # Never execute arbitrary registry text through a shell.
                    if ($raw -match '^\s*"([^"]+\\Uninstall\.exe)"(?:\s.*)?$') {
                        $exe = $Matches[1]
                    } elseif ($raw -match '^\s*([A-Za-z]:\\.+?\\Uninstall\.exe)(?:\s.*)?$') {
                        $exe = $Matches[1]
                    } else {
                        $problem = 'Unrecognized EXE uninstall command; automatic execution is blocked.'
                    }
                    if ($exe) {
                        $arguments = '/S'
                        $folders += Split-Path -Path $exe -Parent
                    }
                }

                if ($problem) {
                    Write-Warning "$($entry.DisplayName): $problem"
                    $blocked = $true
                    continue
                }

                $commandKey = "$exe|$arguments"
                if (-not $seenCommands.ContainsKey($commandKey)) {
                    $seenCommands[$commandKey] = $true
                    $plans += [pscustomobject]@{
                        Name = $entry.DisplayName
                        Kind = $kind
                        Exe  = $exe
                        Args = $arguments
                    }
                }
            }
        } catch {
            Write-Warning "Inventory failed at ${root}: $($_.Exception.Message)"
            $blocked = $true
        }
    }

    foreach ($key in $settingsKeys) {
        try {
            if (Test-Path -LiteralPath $key) {
                $settings = Get-ItemProperty -LiteralPath $key
                foreach ($name in @('Path', 'Path32', 'Path64')) {
                    $value = $settings.$name
                    if ($value) {
                        $folders += [Environment]::ExpandEnvironmentVariables(
                            ([string]$value).Trim().Trim('"')
                        )
                    }
                }
            }
        } catch {
            Write-Warning "Cannot inspect ${key}: $($_.Exception.Message)"
            $blocked = $true
        }
    }

    # Restrict manual cleanup to dedicated folders named exactly 7-Zip.
    # Reject junctions/symlinks anywhere along the path.
    $safeFolders = @()
    foreach ($folder in ($folders | Sort-Object -Unique)) {
        try {
            if ($folder -notmatch '^[A-Za-z]:\\') {
                throw 'Only absolute local drive paths are supported.'
            }
            $full = [IO.Path]::GetFullPath($folder).TrimEnd('\')
            if ([IO.Path]::GetFileName($full) -ine '7-Zip') {
                Write-Warning "Manual cleanup excluded for custom/shared directory: $full"
                continue
            }

            $cursor = $full
            while ($cursor) {
                if (Test-Path -LiteralPath $cursor) {
                    $item = Get-Item -LiteralPath $cursor -Force
                    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                        throw "Reparse point detected: $cursor"
                    }
                }
                $parent = [IO.Directory]::GetParent($cursor)
                $cursor = if ($parent) { $parent.FullName } else { $null }
            }
            $safeFolders += $full
        } catch {
            Write-Warning "Excluded folder '$folder': $($_.Exception.Message)"
        }
    }
    $safeFolders = @($safeFolders | Sort-Object -Unique)

    # Recover normal EXE uninstallers whose Add/Remove Programs entry is missing.
    foreach ($folder in $safeFolders) {
        $exe = Join-Path $folder 'Uninstall.exe'
        if (Test-Path -LiteralPath $exe -PathType Leaf) {
            $alreadyPlanned = @($plans | Where-Object {
                $_.Kind -eq 'EXE' -and $_.Exe -ieq $exe
            }).Count
            $msiPresent = @($plans | Where-Object { $_.Kind -eq 'MSI' }).Count

            if (-not $alreadyPlanned -and -not $msiPresent) {
                $plans += [pscustomobject]@{
                    Name = '7-Zip (unregistered EXE installation)'
                    Kind = 'EXE'
                    Exe  = $exe
                    Args = '/S'
                }
            }
        }
    }

    # Validate every command before any command is executed.
    foreach ($plan in $plans) {
        Write-Host "PLAN: $($plan.Name)"
        Write-Host "  Command: `"$($plan.Exe)`" $($plan.Args)"
        try {
            if (-not (Test-Path -LiteralPath $plan.Exe -PathType Leaf)) {
                throw "Missing uninstaller: $($plan.Exe)"
            }
            if ($plan.Kind -eq 'EXE') {
                $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($plan.Exe)
                if ("$($info.ProductName) $($info.FileDescription)" -notmatch '7-Zip') {
                    throw 'Executable metadata does not identify a 7-Zip uninstaller.'
                }
                Write-Host "  Executable version: $($info.FileVersion)"
            } else {
                $service = Get-Service -Name msiserver
                Write-Host "  Windows Installer: $($service.Status); startup $($service.StartType)"
                if ($service.StartType -eq 'Disabled') {
                    throw 'Windows Installer service is disabled.'
                }
            }
        } catch {
            Write-Warning $_.Exception.Message
            $blocked = $true
        }
    }

    if (-not $plans.Count) {
        Write-Host 'No supported uninstaller was found; checking known leftovers.'
    }

    if ($blocked) {
        Write-Warning 'Prerequisites failed. An actual run will make no changes; preview actions below are conditional.'
        if (-not $preview) { return }
    }

    foreach ($plan in $plans) {
        $action = "Uninstall using `"$($plan.Exe)`" $($plan.Args)"
        if ($PSCmdlet.ShouldProcess($plan.Name, $action)) {
            try {
                $process = Start-Process -FilePath $plan.Exe `
                    -ArgumentList $plan.Args -PassThru -Wait
                $code = $process.ExitCode
                Write-Host "RESULT: $($plan.Name), exit code $code"

                if ($plan.Kind -eq 'MSI' -and $code -in @(3010, 1641)) {
                    $rebootRequired = $true
                    $cleanupAllowed = $false
                    Write-Warning 'Windows Installer reports a restart. Restart and rerun before manual cleanup.'
                } elseif ($code -ne 0) {
                    $cleanupAllowed = $false
                    $failures++
                    Write-Warning "Uninstall failed. MSI examples: 1603=failure; 1612=missing source; 1618=another install running. Code: $code"
                }
            } catch {
                $cleanupAllowed = $false
                $failures++
                Write-Warning "Uninstall failed: $($_.Exception.Message)"
            }
        } elseif (-not $preview) {
            $cleanupAllowed = $false
        }
    }

    # Never hide failed uninstallations by manually deleting their registration.
    if (-not $preview) {
        foreach ($registration in $registrations) {
            try {
                if (Test-Path -LiteralPath $registration) {
                    Write-Warning "Uninstall registration remains: $registration"
                    $cleanupAllowed = $false
                }
            } catch {
                Write-Warning $_.Exception.Message
                $cleanupAllowed = $false
            }
        }
        if (-not $cleanupAllowed) {
            Write-Warning 'Manual cleanup skipped because removal was declined, failed, incomplete, or needs a restart.'
            return
        }
    }

    # Remove only known program files, preserving archives and unknown content.
    $knownFiles = @(
        '7z.exe', '7z.dll', '7zFM.exe', '7zG.exe',
        '7-zip.dll', '7-zip32.dll', '7-zip.chm',
        '7z.sfx', '7zCon.sfx', 'Uninstall.exe',
        'descript.ion', 'History.txt', 'License.txt',
        'readme.txt', 'Uninstall.xml'
    )

    foreach ($folder in $safeFolders) {
        try {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                Write-Host "ABSENT: $folder"
                continue
            }

            $rootItem = Get-Item -LiteralPath $folder -Force
            if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Folder became a reparse point; cleanup skipped.'
            }

            foreach ($item in Get-ChildItem -LiteralPath $folder -Force) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    Write-Warning "Preserved reparse point: $($item.FullName)"
                    continue
                }

                if (-not $item.PSIsContainer -and $item.Name -in $knownFiles) {
                    if ($PSCmdlet.ShouldProcess(
                        $item.FullName, 'Delete known 7-Zip program leftover after successful uninstall'
                    )) {
                        Remove-Item -LiteralPath $item.FullName -Force -Confirm:$false
                    }
                } elseif ($item.PSIsContainer -and $item.Name -ieq 'Lang') {
                    foreach ($language in Get-ChildItem -LiteralPath $item.FullName -Force) {
                        if (-not $language.PSIsContainer -and
                            -not ($language.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                            $language.Name -match '^[a-z]{2,3}(?:-[a-z0-9]+)?\.txt$') {
                            if ($PSCmdlet.ShouldProcess(
                                $language.FullName, 'Delete 7-Zip language leftover after successful uninstall'
                            )) {
                                Remove-Item -LiteralPath $language.FullName -Force -Confirm:$false
                            }
                        } else {
                            Write-Warning "Preserved unrecognized language-folder content: $($language.FullName)"
                        }
                    }
                } else {
                    Write-Warning "Preserved unrecognized content: $($item.FullName)"
                }
            }
        } catch {
            $failures++
            Write-Warning "Cleanup problem at ${folder}: $($_.Exception.Message)"
        }
    }

    # Exact vendor settings keys only. No broad registry searches/deletions.
    foreach ($key in $settingsKeys) {
        try {
            if (Test-Path -LiteralPath $key) {
                $null = Get-Item -LiteralPath $key
                if ($PSCmdlet.ShouldProcess(
                    $key, 'Delete 7-Zip settings/history after successful uninstall'
                )) {
                    Remove-Item -LiteralPath $key -Recurse -Force -Confirm:$false
                }
            }
        } catch {
            $failures++
            Write-Warning "Settings cleanup failed at ${key}: $($_.Exception.Message)"
        }
    }

    # Inspect existing shortcuts without saving or modifying them.
    $shortcutFolders = @()
    foreach ($special in @('Programs', 'CommonPrograms')) {
        $base = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::$special
        )
        if ($base) { $shortcutFolders += Join-Path $base '7-Zip' }
    }

    $shell = $null
    try {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($folder in $shortcutFolders) {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
            $item = Get-Item -LiteralPath $folder -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Write-Warning "Preserved shortcut-folder reparse point: $folder"
                continue
            }

            foreach ($link in Get-ChildItem -LiteralPath $folder -Force) {
                if ($link.PSIsContainer -or $link.Extension -ine '.lnk' -or
                    ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    Write-Warning "Preserved unrecognized shortcut-folder content: $($link.FullName)"
                    continue
                }
                $shortcut = $shell.CreateShortcut($link.FullName)
                $target = $shortcut.TargetPath
                $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)

                if ($target -and
                    (Split-Path -Path $target -Parent) -in $safeFolders -and
                    (Split-Path -Path $target -Leaf) -in $knownFiles) {
                    if ($PSCmdlet.ShouldProcess(
                        $link.FullName, "Delete 7-Zip shortcut targeting $target after successful uninstall"
                    )) {
                        Remove-Item -LiteralPath $link.FullName -Force -Confirm:$false
                    }
                } else {
                    Write-Warning "Preserved shortcut with unrelated/unverified target: $($link.FullName) -> $target"
                }
            }
        }
    } catch {
        $failures++
        Write-Warning "Shortcut inspection/cleanup failed: $($_.Exception.Message)"
    } finally {
        if ($shell) {
            $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        }
    }

    # Delete directories only when empty. Never recursively delete program folders.
    $emptyCandidates = @()
    foreach ($folder in $safeFolders) {
        $emptyCandidates += Join-Path $folder 'Lang'
        $emptyCandidates += $folder
    }
    $emptyCandidates += $shortcutFolders

    foreach ($folder in $emptyCandidates) {
        try {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
            $item = Get-Item -LiteralPath $folder -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }

            $children = @(Get-ChildItem -LiteralPath $folder -Force)
            if ($preview) {
                $null = $PSCmdlet.ShouldProcess(
                    $folder,
                    "Delete directory ONLY if empty after preceding cleanup; currently $($children.Count) immediate item(s)"
                )
            } elseif (-not $children.Count) {
                if ($PSCmdlet.ShouldProcess($folder, 'Delete empty 7-Zip directory')) {
                    # Nonrecursive .NET deletion also refuses a directory that
                    # becomes nonempty between the check and the deletion.
                    [IO.Directory]::Delete($folder, $false)
                }
            } else {
                Write-Warning "Directory retained with remaining content: $folder"
            }
        } catch {
            $failures++
            Write-Warning "Directory cleanup failed at ${folder}: $($_.Exception.Message)"
        }
    }

    Write-Host ''
    if ($preview) {
        Write-Host "Preview complete. Uninstall commands: $($plans.Count); prerequisite blockers: $blocked; inspection errors: $failures."
        Write-Host 'All cleanup actions are conditional; the uninstaller may remove those targets itself.'
        Write-Host 'Preview does not test write permissions, MSI source availability, or every possible file lock.'
    } else {
        Write-Host "Finished. Cleanup errors: $failures; installer requested restart: $rebootRequired."
        Write-Host 'Review warnings for retained files. Sign out or restart if Explorer still displays 7-Zip.'
    }
    Write-Host 'Package-manager records, other users, arbitrary portable copies, and custom PATH/default-app entries are not modified.'
}

Uninstall-7Zip -WhatIf
# Uninstall-7Zip



#check
# $paths = @(
#     "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
#     "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
#     "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
# )

# Get-ItemProperty $paths -ErrorAction SilentlyContinue |
#     Where-Object { $_.DisplayName -like "7-Zip*" } |
#     Select-Object DisplayName, DisplayVersion, InstallLocation |
#     Sort-Object DisplayVersion -Unique