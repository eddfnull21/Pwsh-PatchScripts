# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    PowerToys - Status / Update (migrate to machine-wide) / Uninstall. RMM-ready.

.DESCRIPTION
    -Action Status     DEFAULT. Lists MSI payloads (machine and per-user) and the
                       state of each profile's migration cleanup task. Changes nothing.
    -Action Update     Migrates to the latest machine-wide PowerToys from winget:
                       downloads and signature-checks the installer, installs and
                       verifies it, removes older machine MSIs, then schedules a
                       limited-privilege logon task per profile that removes that
                       user's own per-user install. Signed-out users finish at next logon.
    -Action Uninstall  Removes PowerToys completely: startup tasks, processes, the
                       machine install, and each profile's per-user install and
                       settings (via a temporary S4U task running as that user).

    Requirements: Windows PowerShell 5.1, 64-bit, running as LOCAL SYSTEM.
    -WhatIf previews Update and Uninstall without downloading or removing anything.

.EXAMPLE
    Paste the WHOLE script into a SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the action -
    edit that one line. For an RMM component also set $RMM = $true there, so the
    script exits with the code.

    Invoke-PowerToys                             # Status
    Invoke-PowerToys -Action Update -WhatIf      # Preview the migration plan
    Invoke-PowerToys -Action Update
    Invoke-PowerToys -Action Uninstall

    After a paste the functions stay loaded, so further actions can be typed directly.

.NOTES
    Exit codes (Invoke-PowerToys returns one; the entry point exits with it only when $RMM = $true):
        0     Success / status reported / -WhatIf
        1     Failed or incomplete (see output and per-user logs)
        3010  Restart required; rerun after reboot to continue
#>

#region -------------------- Update-PowerToys (migrate to machine-wide) --------------------

# Migration sequence: acquire the current machine-scope installer from winget;
# install and verify it; retire older machine MSIs; run cleanup in SYSTEM's own
# context; arrange limited-privilege cleanup for every existing regular profile.
# Signed-out profiles finish at next logon. Tasks remain to retry on later logons.
# Inspect task results and per-user cleanup.log before declaring migration complete.
# Necessary bundle metadata and Appx shell registrations are not separate payloads.
# This script does not delete orphaned files/registry records to simulate uninstall,
# does not enforce an application-control policy, and does not access unloaded
# profiles' raw registry hives. MSI scope inventory uses ProductsEx across all users.
# Windows execution has not been tested in the authoring environment.
function Update-PowerToys {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$StatusOnly)

    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $false
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        throw 'Run this function as LOCAL SYSTEM.'
    }

    # Windows Installer records the actual payload scope. A Burn bundle's HKU
    # registration or cache directory does not establish the MSI's scope.
    # ProductsEx also finds registered MSI installations in signed-out profiles.
    # Do not replace this with Win32_Product (which can trigger consistency checks).
    $getMsi = {
        param($QuerySid)
        $wi = New-Object -ComObject WindowsInstaller.Installer
        try {
            $products = $wi.GetType().InvokeMember(
                'ProductsEx', [Reflection.BindingFlags]::GetProperty,
                $null, $wi, @('', $QuerySid, 7)
            )
            foreach ($product in $products) {
                if ([int]$product.State -ne 5) { continue }
                $name = $product.InstallProperty('ProductName')
                if ($name -notmatch '^PowerToys(?: \(Preview\))?$') { continue }
                if ($product.InstallProperty('Publisher') -ne 'Microsoft Corporation') { continue }
                $v = [version]$product.InstallProperty('VersionString')
                $v = [version]::new($v.Major, $v.Minor, [Math]::Max(0, $v.Build), [Math]::Max(0, $v.Revision))
                [pscustomobject]@{
                    Name = $name
                    Version = $v
                    ProductCode = [string]$product.ProductCode
                    Context = [int]$product.Context
                    Sid = [string]$product.UserSid
                    InstallLocation = [string]$product.InstallProperty('InstallLocation')
                }
            }
        }
        finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wi) }
    }

    $before = @(& $getMsi 'S-1-1-0')
    $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object {
        -not $_.Special -and $_.SID -match '^S-1-' -and $_.LocalPath
    })
    $currentMachine = $before | Where-Object Context -eq 4 |
        Sort-Object Version -Descending | Select-Object -First 1

    Write-Host "`nCurrent MSI payloads (installer bundles are not additional payloads):"
    $before | Select-Object Version, ProductCode,
        @{n='Scope';e={if ($_.Context -eq 4) {'Machine'} else {$_.Sid}}},
        InstallLocation | Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'PowerToys Appx registrations (these alone do not prove a separate user install):'
    Get-AppxPackage -AllUsers -Name 'Microsoft.PowerToys*' |
        Select-Object Name, Version | Format-Table -AutoSize | Out-Host

    if ($StatusOnly) {
        [pscustomobject]@{
            Scope='Machine'; Status=if (@($before | Where-Object Context -eq 4).Count -eq 1) {
                'OneRegisteredMachineMSI'
            } else { 'RequiresReview' }
            Detail=if ($currentMachine) { [string]$currentMachine.Version } else { 'No machine MSI' }
        }
        foreach ($userProfile in $profiles) {
            $taskName = 'PowerToys-MachineMigration-' + $userProfile.SID
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            $status = 'NotScheduled'
            $detail = $taskName
            if ($task) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName
                if ($task.State -eq 'Running') { $status = 'Running' }
                elseif ($info.LastRunTime.Year -lt 2000) { $status = 'PendingUserLogon' }
                elseif ($info.LastTaskResult -eq 0) { $status = 'WorkerCompleted' }
                else { $status = 'FailedOrPending'; $detail += "; last result $($info.LastTaskResult)" }
            }
            if (@($before | Where-Object { $_.Context -ne 4 -and $_.Sid -eq $userProfile.SID }).Count) {
                $status += ';UserMSIRemains'
            }
            [pscustomobject]@{Scope=$userProfile.SID;Status=$status;Detail=$detail}
        }
        foreach ($p in $before | Where-Object { $_.Context -ne 4 -and $_.Sid -notin @($profiles.SID) }) {
            [pscustomobject]@{Scope=$p.Sid;Status='UserMSIRequiresReview';Detail=$p.ProductCode}
        }
        return
    }

    Write-Host 'PLAN: install/update the latest machine installer from the winget source.'
    Write-Host 'PLAN: verify its machine MSI and executable before removing other products.'
    foreach ($p in $before) {
        if ($p.Context -ne 4) {
            Write-Host "REMOVE USER INSTALL: $($p.Version), SID $($p.Sid), $($p.ProductCode)"
        }
        elseif ($currentMachine -and $p.Version -lt $currentMachine.Version) {
            Write-Host "REMOVE OLD MACHINE MSI: $($p.Version), $($p.ProductCode)"
        }
        else {
            Write-Host "KEEP/UPDATE MACHINE MSI: $($p.Version), $($p.ProductCode)"
        }
    }
    Write-Host "PLAN: arrange user-context cleanup for $($profiles.Count) existing profiles."
    Write-Host 'Signed-out profiles remain PENDING until their cleanup task runs successfully.'

    $appInstaller = Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller |
        Where-Object InstallLocation | Sort-Object {[version]$_.Version} -Descending |
        Select-Object -First 1
    if (-not $appInstaller) { throw 'Microsoft.DesktopAppInstaller was not found.' }
    $winget = Join-Path $appInstaller.InstallLocation 'winget.exe'
    if (-not (Test-Path -LiteralPath $winget -PathType Leaf)) { throw "Missing $winget" }

    # WhatIf deliberately stops before downloads, installs, uninstalls or task creation.
    # It cannot predict an upgrade's resulting product code or version.
    if (-not $PSCmdlet.ShouldProcess(
        'PowerToys on this computer and its existing user profiles',
        'Migrate to latest machine-wide installation; remove alternate installations and schedule user cleanup'
    )) {
        return
    }

    & $winget list --id Microsoft.PowerToys --exact --source winget `
        --accept-source-agreements --disable-interactivity | Out-Host
    # A missing installation is valid on a machine being migrated.
    if ($LASTEXITCODE -notin @(0, -1978335212)) {
        throw "WinGet list failed: $LASTEXITCODE"
    }

    # Download the machine installer explicitly. Unlike 'upgrade' alone, this
    # also establishes a machine installation when only user installations exist.
    $stage = Join-Path $env:ProgramData ('PowerToys-Migration-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $stage)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $stage -AclObject $acl
    Write-Host "Installer and logs: $stage"

    & $winget download --id Microsoft.PowerToys --exact --source winget `
        --scope machine --architecture x64 --download-directory $stage `
        --accept-source-agreements --accept-package-agreements `
        --disable-interactivity | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "WinGet download failed: $LASTEXITCODE" }

    $setup = @(Get-ChildItem -LiteralPath $stage -File -Filter '*.exe' | Where-Object {
        $_.VersionInfo.ProductName -match 'PowerToys'
    })
    if ($setup.Count -ne 1) { throw "Expected one PowerToys installer in $stage; found $($setup.Count)." }
    $setup = $setup[0]
    $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
        throw 'The downloaded installer does not have a valid Microsoft Corporation signature.'
    }
    if ($setup.VersionInfo.ProductVersion -notmatch '^(\d+\.\d+\.\d+(?:\.\d+)?)') {
        throw 'Cannot determine the downloaded installer version.'
    }
    $target = [version]$Matches[1]
    $target = [version]::new($target.Major, $target.Minor, [Math]::Max(0,$target.Build), [Math]::Max(0,$target.Revision))
    if (@($before | Where-Object { $_.Version -gt $target }).Count) {
        throw "An installed version is newer than source version $target. No installation was removed."
    }

    $desiredLocation = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerToys'
    $runSetup = Start-Process -FilePath $setup.FullName -Wait -PassThru `
        -ArgumentList ('/install /quiet /norestart InstallFolder="{0}" /log "{1}"' -f $desiredLocation, (Join-Path $stage 'install.log'))
    if ($runSetup.ExitCode -notin @(0, 1641, 3010)) {
        throw "Machine installation failed: $($runSetup.ExitCode). No cleanup performed."
    }
    if ($runSetup.ExitCode -in @(1641, 3010)) {
        Write-Warning 'RESTART REQUIRED: restart Windows and rerun Update-PowerToys to continue migration.'
        return [pscustomobject]@{Status='RestartRequired'; Logs=$stage}
    }

    $afterInstall = @(& $getMsi 'S-1-1-0')
    $keep = $afterInstall | Where-Object Context -eq 4 |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $keep -or $keep.Version -lt $target -or -not $keep.InstallLocation) {
        throw 'Could not verify the requested machine-wide MSI. No cleanup performed.'
    }
    if ($keep.InstallLocation.TrimEnd('\') -ne $desiredLocation.TrimEnd('\')) {
        throw "Machine install location is unexpected: $($keep.InstallLocation). No cleanup performed."
    }
    $machineExe = Join-Path $keep.InstallLocation 'PowerToys.exe'
    if (-not (Test-Path -LiteralPath $machineExe -PathType Leaf)) {
        throw "Machine executable is missing: $machineExe. No cleanup performed."
    }
    $machineFile = (Get-Item -LiteralPath $machineExe).VersionInfo
    $fileVersion = [version]::new($machineFile.FileMajorPart, $machineFile.FileMinorPart,
        $machineFile.FileBuildPart, $machineFile.FilePrivatePart)
    if ($fileVersion -lt $target) { throw 'Machine executable is older than the target. Cleanup stopped.' }
    Write-Host "KEEP VERIFIED: machine PowerToys $($keep.Version), $($keep.ProductCode), $machineExe"

    # Retire only exact, lower-version machine product codes, never the keeper.
    $oldMachine = @($afterInstall | Where-Object { $_.Context -eq 4 -and $_.Version -lt $keep.Version })
    foreach ($p in $oldMachine) {
        Write-Host "REMOVE MACHINE MSI: $($p.Version), $($p.ProductCode)"
        $log = Join-Path $stage ('remove-' + $p.ProductCode.Trim('{}') + '.log')
        $proc = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -Wait -PassThru `
            -ArgumentList ('/x {0} /qn /norestart /L*v "{1}"' -f $p.ProductCode, $log)
        if ($proc.ExitCode -notin @(0, 1641, 3010)) { throw "MSI removal failed: $($proc.ExitCode). See $log" }
        if ($proc.ExitCode -in @(1641, 3010)) {
            Write-Warning 'RESTART REQUIRED: restart and rerun to finish migration.'
            return [pscustomobject]@{Status='RestartRequired'; Logs=$stage}
        }
        if (@(& $getMsi 'S-1-1-0' | Where-Object {
            $_.Context -eq 4 -and $_.ProductCode -eq $p.ProductCode
        }).Count) { throw "The removed MSI is still registered: $($p.ProductCode)" }
        Write-Host "REMOVED MACHINE MSI: $($p.Version)"
    }

    # Old installers can touch shared resources. Repair the retained product
    # after explicit removal of old machine MSIs, then recheck it.
    if ($oldMachine.Count) {
        $repair = Start-Process -FilePath $setup.FullName -Wait -PassThru `
            -ArgumentList ('/repair /quiet /norestart /log "{0}"' -f (Join-Path $stage 'repair.log'))
        if ($repair.ExitCode -notin @(0, 1641, 3010)) { throw "Machine repair failed: $($repair.ExitCode)" }
        if ($repair.ExitCode -in @(1641, 3010)) {
            Write-Warning 'RESTART REQUIRED: restart and rerun to arrange user cleanup.'
            return [pscustomobject]@{Status='RestartRequired'; Logs=$stage}
        }
    }

    # This worker runs as the owning user, at limited privilege. It never runs
    # an HKCU uninstall command as SYSTEM and never deletes uninstall keys.
    $userWorker = {
        param([version]$MinimumVersion, [string]$ExpectedSid)
        $ErrorActionPreference = 'Stop'
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedSid) { exit 20 }
        $logDir = Join-Path $env:LOCALAPPDATA 'PowerToys-MachineMigration'
        [void](New-Item -ItemType Directory -Path $logDir -Force)
        Start-Transcript -Path (Join-Path $logDir 'cleanup.log') -Append | Out-Null
        try {
            $inventory = @(& $getMsi $null)
            $keeper = $inventory | Where-Object Context -eq 4 |
                Sort-Object Version -Descending | Select-Object -First 1
            if (-not $keeper -or $keeper.Version -lt $MinimumVersion -or -not $keeper.InstallLocation) {
                throw 'The replacement machine installation is not ready.'
            }
            $exe = Join-Path $keeper.InstallLocation 'PowerToys.exe'
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Machine executable is missing.' }
            $file = (Get-Item -LiteralPath $exe).VersionInfo
            $v = [version]::new($file.FileMajorPart,$file.FileMinorPart,$file.FileBuildPart,$file.FilePrivatePart)
            if ($v -lt $MinimumVersion) { throw 'Machine executable is older than the required version.' }

            $userProducts = @($inventory | Where-Object Context -ne 4)
            if (@($userProducts | Where-Object {$_.Version -gt $keeper.Version}).Count) {
                throw 'A user installation is newer than the machine copy. Update the machine first.'
            }
            $userPaths = @(
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            $bundles = @(Get-ItemProperty -Path $userPaths -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -match '^PowerToys \(Preview\) (x64|ARM64)$' -and
                $_.Publisher -eq 'Microsoft Corporation' -and $_.UninstallString -match '^"[^\"]+\.exe"'
            } | Sort-Object UninstallString -Unique)
            $changed = $false
            foreach ($b in $bundles) {
                $v = [version]$b.DisplayVersion
                $v = [version]::new($v.Major,$v.Minor,[Math]::Max(0,$v.Build),[Math]::Max(0,$v.Revision))
                $loc = ([string]$b.InstallLocation).TrimEnd('\')
                $userMatch = @($userProducts | Where-Object {
                    $_.Version -eq $v -and $loc -and $_.InstallLocation.TrimEnd('\') -eq $loc
                })
                $machineMatch = @($inventory | Where-Object {
                    $_.Context -eq 4 -and $_.Version -eq $v -and
                    (-not $loc -or $_.InstallLocation.TrimEnd('\') -eq $loc)
                })
                if ($v -gt $keeper.Version) { throw "Bundle $v is newer than the machine copy." }
                if ($machineMatch.Count -and -not $userMatch.Count) {
                    Write-Host "KEEP BUNDLE METADATA: $v; no separate user MSI matched."
                    continue
                }
                if ($machineMatch.Count -and $userMatch.Count) {
                    throw "Ambiguous bundle ${v}: both machine and user MSIs match. Manual installer review required."
                }
                if (-not $userMatch.Count -and $v -ge $keeper.Version) {
                    throw "Cannot prove bundle $v is safe to remove."
                }
                if ($b.UninstallString -notmatch '^"([^\"]+\.exe)"') { throw 'Invalid bundle uninstall command.' }
                $uninstaller = $Matches[1]
                if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
                    throw "Missing cached uninstaller: $uninstaller"
                }
                Write-Host "REMOVE USER/RETIRED BUNDLE: $v"
                $p = Start-Process -FilePath $uninstaller -ArgumentList '/uninstall /quiet /norestart' -Wait -PassThru
                if ($p.ExitCode -in @(1641,3010)) { throw 'Uninstaller requires a restart; cleanup remains pending.' }
                if ($p.ExitCode -ne 0) { throw "Bundle uninstall failed: $($p.ExitCode)" }
                if (Test-Path -LiteralPath $b.PSPath) { throw 'Bundle uninstall registration still exists.' }
                $changed = $true
            }

            # Direct MSI fallback is restricted to proven per-user products with
            # no matching bundle. Never uninstall a code registered machine-wide.
            $current = @(& $getMsi $null)
            foreach ($p in @($current | Where-Object Context -ne 4)) {
                if (@($current | Where-Object { $_.Context -eq 4 -and $_.ProductCode -eq $p.ProductCode }).Count) {
                    throw 'The same product code is also installed machine-wide; refusing ambiguous MSI removal.'
                }
                if (@($bundles | Where-Object {
                    (Test-Path -LiteralPath $_.PSPath) -and
                    ([version]$_.DisplayVersion).Major -eq $p.Version.Major -and
                    ([version]$_.DisplayVersion).Minor -eq $p.Version.Minor -and
                    ([version]$_.DisplayVersion).Build -eq $p.Version.Build
                }).Count) { throw 'A matching bundle remains; its uninstall must be resolved first.' }
                Write-Host "REMOVE USER MSI: $($p.Version), $($p.ProductCode)"
                $proc = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -Wait -PassThru `
                    -ArgumentList ('/x {0} /qn /norestart' -f $p.ProductCode)
                if ($proc.ExitCode -ne 0) { throw "User MSI removal did not complete: $($proc.ExitCode)" }
                $changed = $true
            }
            $final = @(& $getMsi $null)
            if (@($final | Where-Object Context -ne 4).Count) { throw 'A separate user MSI still exists.' }
            foreach ($oldUser in $userProducts) {
                if ($oldUser.InstallLocation -and
                    $oldUser.InstallLocation.TrimEnd('\') -ne $keeper.InstallLocation.TrimEnd('\') -and
                    (Test-Path -LiteralPath (Join-Path $oldUser.InstallLocation 'PowerToys.exe') -PathType Leaf)) {
                    throw "A user executable remains at $($oldUser.InstallLocation); do not declare migration complete."
                }
            }
            if (-not @($final | Where-Object {
                $_.Context -eq 4 -and $_.ProductCode -eq $keeper.ProductCode
            }).Count -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                throw 'The retained machine installation failed verification.'
            }
            # Let the supported application initialize its per-user integrations.
            # Do not blanket-remove SparseApp/context-menu Appx registrations.
            if ($changed -and $ExpectedSid -ne 'S-1-5-18') { Start-Process -FilePath $exe | Out-Null }
            Write-Host 'COMPLETE: no separate registered user MSI remains; machine copy retained.'
            Stop-Transcript | Out-Null
            exit 0
        }
        catch {
            Write-Host ('FAILED/PENDING: ' + $_.Exception.Message)
            Stop-Transcript | Out-Null
            exit 1
        }
    }

    # Encode a self-contained worker; no credentials or execution-policy bypass.
    # No SYSTEM worker consumes executable paths from user-writable logs/files.
    $results = @()
    $remaining = @(& $getMsi 'S-1-1-0')
    if (@($remaining | Where-Object {
        $_.Context -eq 4 -and ($_.Version -lt $keep.Version -or $_.ProductCode -ne $keep.ProductCode)
    }).Count) { throw 'More than one machine MSI remains. User cleanup was not scheduled.' }
    if (-not @($remaining | Where-Object {
        $_.Context -eq 4 -and $_.ProductCode -eq $keep.ProductCode
    }).Count -or -not (Test-Path -LiteralPath $machineExe -PathType Leaf)) {
        throw 'Retained machine copy failed verification. User cleanup was not scheduled.'
    }

    # SYSTEM is also a bundle-registration owner. Clean its own obsolete bundle
    # metadata through its installer, in a child process (the worker uses exit).
    $systemPayload = '$getMsi = {' + $getMsi.ToString() + "}`r`n& {" + $userWorker.ToString() +
        "} -MinimumVersion '$($keep.Version)' -ExpectedSid 'S-1-5-18'"
    $systemEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($systemPayload))
    if ($systemEncoded.Length -gt 29000) { throw 'SYSTEM worker exceeds the Windows command-line size limit.' }
    $systemCleanup = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $systemEncoded" -Wait -PassThru
    if ($systemCleanup.ExitCode -ne 0) {
        throw 'SYSTEM-owned cleanup failed. Inspect SYSTEM LocalAppData\PowerToys-MachineMigration\cleanup.log.'
    }

    foreach ($userProfile in $profiles) {
        $sid = [string]$userProfile.SID
        if ($sid -notmatch '^S-1-(?:\d+-)+\d+$') { throw "Invalid profile SID: $sid" }
        $taskName = 'PowerToys-MachineMigration-' + $sid
        $payload = '$getMsi = {' + $getMsi.ToString() + "}`r`n& {" + $userWorker.ToString() +
            "} -MinimumVersion '$($keep.Version)' -ExpectedSid '$sid'"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        if ($encoded.Length -gt 29000) { throw 'Worker exceeds the Windows command-line size limit.' }
        try {
            $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
                -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded"
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
            $trigger.Delay = 'PT30S'
            $principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings `
                -Description 'Remove separate PowerToys user installations only after verifying the replacement machine MSI.' `
                -Force | Out-Null
            # Interactive tasks require the user's existing logon token. If no
            # token exists, the logon trigger runs the task on their next sign-in.
            try { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop }
            catch { Write-Host "PENDING USER LOGON: $sid" }
            $results += [pscustomobject]@{
                Scope=$sid; Version=$null; Status='PendingUserCleanup'
                Detail=$taskName
            }
        }
        catch {
            $results += [pscustomobject]@{
                Scope=$sid; Version=$null; Status='FailedToSchedule'; Detail=$_.Exception.Message
            }
        }
    }
    foreach ($p in $remaining | Where-Object Context -ne 4) {
        if ($p.Sid -notin @($profiles.SID)) {
            $results += [pscustomobject]@{
                Scope=$p.Sid; Version=$p.Version; Status='RequiresReview'
                Detail="User MSI $($p.ProductCode) has no schedulable regular profile."
            }
        }
    }
    Write-Host "`nKEEP: machine-wide PowerToys $($keep.Version)"
    Write-Host 'User cleanup is asynchronous. Pending is not a completed migration.'
    Write-Host 'Task result 0 after an actual run means its worker completed; nonzero means inspect the user log.'
    Write-Host 'Worker log: <user LocalAppData>\PowerToys-MachineMigration\cleanup.log'
    Write-Host 'Appx shell integration registrations can legitimately remain with the machine installation.'
    [pscustomobject]@{Scope='Machine';Version=$keep.Version;Status='Verified';Detail=$machineExe}
    $results
}

#endregion

#region -------------------- Uninstall-PowerToys (full removal, all profiles) --------------------

function Uninstall-PowerToys {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Windows PowerShell 5.1, 64-bit, running as NT AUTHORITY\SYSTEM.
    # Deletes settings as well as standard EXE/MSI installations.
    # Per-user work runs as that user through a temporary S4U task.
    # Accounts that cannot run a task are reported as incomplete.
    # S4U needs batch-logon permission and cannot access network/EFS sources.
    # Portable/Scoop copies and damaged installers need separate remediation.
    if (-not [Environment]::Is64BitProcess) {
        throw 'Run this function in 64-bit Windows PowerShell.'
    }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        throw 'Run this function as NT AUTHORITY\SYSTEM.'
    }

    # A script block keeps the whole implementation inside this one function.
    $remove = {
        param([bool]$Machine, [string]$ExpectedSid, [string]$ExpectedProfile)

        $ErrorActionPreference = 'Stop'
        $ConfirmPreference = 'None'
        $failed = $false
        $reboot = $false
        $installer = $null
        $namePattern = '^(?:Microsoft )?PowerToys(?: \(Preview\))?(?: (?:x64|x86|arm64))?$'
        $guidPattern = '\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}'
        $msiPattern = '^\s*"?(?:[^"]*\\)?msiexec(?:\.exe)?"?\s+/[ix]\s*(' + $guidPattern + ')(?:\s|$)'
        $hive = if ($Machine) { 'HKLM:' } else { 'HKCU:' }
        $context = if ($Machine) { 4 } else { 3 }
        $roots = @(
            "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            "$hive\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        $getEntries = {
            foreach ($root in $roots) {
                if (Test-Path -LiteralPath $root) {
                    Get-ChildItem -LiteralPath $root | Get-ItemProperty |
                        Where-Object {
                            $_.DisplayName -match $namePattern -and
                            $_.Publisher -eq 'Microsoft Corporation'
                        }
                }
            }
        }

        # Unlike Win32_Product, enumeration does not trigger MSI repairs.
        # Query only this context; an all-users query cannot establish ownership.
        $getProducts = {
            $products = $installer.GetType().InvokeMember(
                'ProductsEx', [Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($null, $null, $context)
            )
            foreach ($product in $products) {
                $name = $product.GetType().InvokeMember(
                    'InstallProperty', [Reflection.BindingFlags]::GetProperty,
                    $null, $product, @('ProductName')
                )
                if ($name -notmatch $namePattern) { continue }
                $publisher = $product.GetType().InvokeMember(
                    'InstallProperty', [Reflection.BindingFlags]::GetProperty,
                    $null, $product, @('Publisher')
                )
                if ($publisher -eq 'Microsoft Corporation') { $product.ProductCode }
            }
        }

        try {
            if (-not $Machine -and (
                [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedSid -or
                $env:USERPROFILE.TrimEnd('\') -ne $ExpectedProfile.TrimEnd('\')
            )) { throw 'Unexpected account or profile; nothing removed.' }
            $installer = New-Object -ComObject WindowsInstaller.Installer

            # Run Burn EXE bundles before any remaining MSI packages.
            $entries = @(& $getEntries)
            $bundles = $entries | Where-Object { $_.WindowsInstaller -ne 1 } |
                Group-Object UninstallString

            foreach ($bundle in $bundles) {
                try {
                    $command = $bundle.Name
                    # Legacy MSI entries are handled by ProductsEx below.
                    if ($command -match $msiPattern) {
                        continue
                    }
                    if ($command -notmatch '^\s*(?:"(?<exe>[^"]+\.exe)"|(?<exe>.+?\.exe))\s+/uninstall(?:\s|$)') {
                        throw "Unsupported uninstall command: $command"
                    }
                    $exe = [Environment]::ExpandEnvironmentVariables($Matches.exe)
                    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                        throw "Cached uninstaller missing: $exe"
                    }
                    $signature = Get-AuthenticodeSignature -LiteralPath $exe
                    if ($signature.Status -ne 'Valid' -or
                        $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
                        throw "Uninstaller does not have a valid Microsoft signature: $exe"
                    }
                    $process = Start-Process -FilePath $exe -ArgumentList '/uninstall /quiet /norestart' -Wait -PassThru
                    Write-Host "$exe : exit $($process.ExitCode)"
                    if ($process.ExitCode -notin 0, 1641, 3010) {
                        throw "Bundle uninstall failed: $($process.ExitCode)"
                    }
                    if ($process.ExitCode -in 1641, 3010) { $reboot = $true }
                }
                catch {
                    $failed = $true
                    Write-Warning $_
                }
            }

            # Re-enumerate after the bundles, including MSI products without ARP keys.
            foreach ($code in @(& $getProducts)) {
                $process = Start-Process "$env:SystemRoot\System32\msiexec.exe" `
                    -ArgumentList "/x $code /qn /norestart" -Wait -PassThru
                Write-Host "$code : exit $($process.ExitCode)"
                if ($process.ExitCode -in 1641, 3010) { $reboot = $true }
                if ($process.ExitCode -notin 0, 1641, 3010, 1605, 1614) {
                    $failed = $true
                    Write-Warning "MSI uninstall failed: $($process.ExitCode)"
                }
            }
            if (@(& $getProducts).Count) {
                throw 'PowerToys MSI registrations remain in this account/context.'
            }

            # Remove only MSI ARP keys proven stale in this exact context.
            # A missing EXE or exit 1605 is NOT proof that another user's app is gone.
            foreach ($entry in @(& $getEntries)) {
                $code = $null
                if ($entry.WindowsInstaller -eq 1 -and $entry.PSChildName -match "^$guidPattern$") {
                    $code = $entry.PSChildName
                }
                elseif ($entry.UninstallString -match $msiPattern) {
                    $code = $Matches[1]
                }
                if ($code) {
                    $products = $installer.GetType().InvokeMember(
                        'ProductsEx', [Reflection.BindingFlags]::GetProperty,
                        $null, $installer, @($code, $null, $context)
                    )
                    if ($products.Count -eq 0) {
                        Remove-Item -LiteralPath $entry.PSPath -Recurse -Force
                    }
                }
            }
            if (@(& $getEntries).Count -or $failed) {
                throw 'Removal incomplete; remaining uninstall entries and application files retained.'
            }

            $paths = if ($Machine) {
                "$env:ProgramFiles\PowerToys"
                "${env:ProgramFiles(x86)}\PowerToys"
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\PowerToys.lnk"
            }
            else {
                "$env:LOCALAPPDATA\PowerToys"
                "$env:LOCALAPPDATA\Microsoft\PowerToys"
                "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PowerToys.lnk"
            }
            foreach ($path in $paths) {
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Recurse -Force
                }
            }
            foreach ($key in @(
                "$hive\SOFTWARE\Microsoft\PowerToys"
                "$hive\SOFTWARE\WOW6432Node\Microsoft\PowerToys"
            )) {
                if (Test-Path -LiteralPath $key) {
                    Remove-Item -LiteralPath $key -Recurse -Force
                }
            }
            foreach ($run in @(
                "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                "$hive\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            )) {
                if (Test-Path -LiteralPath $run) {
                    $values = Get-ItemProperty -LiteralPath $run
                    if ($values.PSObject.Properties['PowerToys']) {
                        Remove-ItemProperty -LiteralPath $run -Name PowerToys
                    }
                }
            }
            if ($reboot) { return 3010 }
            return 0
        }
        catch {
            Write-Warning $_
            return 1
        }
        finally {
            if ($null -ne $installer) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
            }
        }
    }

    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop |
        Where-Object { -not $_.Special -and $_.LocalPath })
    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    if ($PSCmdlet.ShouldProcess('All sessions', 'Stop PowerToys and remove its startup tasks')) {
        Get-ScheduledTask -ErrorAction Stop | Where-Object {
            @($_.Actions | Where-Object { $_.Execute -match '(?i)(?:^|\\)PowerToys\.exe"?$' }).Count
        } | Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop

        Get-Process -Name 'PowerToys', 'PowerToys.*' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction Stop
    }

    if ($PSCmdlet.ShouldProcess('Machine', 'Uninstall PowerToys and delete its standard folders/settings')) {
        $code = & $remove $true
        [pscustomobject]@{
            Scope = 'Machine'
            ExitCode = $code
            Status = $(if ($code -eq 0) { 'Removed / absent' }
                elseif ($code -eq 3010) { 'Restart required' } else { 'Incomplete' })
        }
    }

    foreach ($userProfile in $profiles) {
        if (-not $PSCmdlet.ShouldProcess($userProfile.LocalPath,
            'Uninstall PowerToys and erase its settings using a temporary task as the owning user')) { continue }

        $taskName = 'Uninstall-PowerToys-' + [guid]::NewGuid().ToString('N')
        $registered = $false
        $running = $false
        try {
            $sidLiteral = "'" + $userProfile.SID.Replace("'", "''") + "'"
            $profileLiteral = "'" + $userProfile.LocalPath.Replace("'", "''") + "'"
            $payload = '$ErrorActionPreference = "Stop"; try { $log = Join-Path $env:TEMP "Uninstall-PowerToys.log"; $code = & {' +
                $remove.ToString() + '} $false ' + $sidLiteral + ' ' + $profileLiteral +
                ' 3>> $log 6>> $log; if ($null -eq $code) { exit 1 }; exit ([int]$code) } catch { exit 1 }'
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
            if ($encoded.Length -gt 30000) { throw 'Scheduled-task command is too long.' }
            $principal = New-ScheduledTaskPrincipal -UserId $userProfile.SID -LogonType S4U -RunLevel Limited
            $action = New-ScheduledTaskAction -Execute $powerShell `
                -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
                -Settings $settings -ErrorAction Stop | Out-Null
            $registered = $true
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $running = $true
            $deadline = (Get-Date).AddMinutes(20)
            do {
                Start-Sleep -Seconds 1
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
                $running = $task.State -in 'Running', 'Queued' -or
                    $info.LastTaskResult -in 267009, 267011
            } while ($running -and (Get-Date) -lt $deadline)

            if ($running) {
                throw "Task still pending/running: $taskName. Retained; completion is not confirmed."
            }
            $code = $info.LastTaskResult
            if ($code -notin 0, 3010) {
                Write-Warning "$($userProfile.SID): incomplete (task result $code). Check task logon policy and the user's %TEMP%\Uninstall-PowerToys.log."
            }
            [pscustomobject]@{
                Scope = $userProfile.LocalPath
                ExitCode = $code
                Status = $(if ($code -eq 0) { 'Removed / absent' }
                    elseif ($code -eq 3010) { 'Restart required' } else { 'Incomplete' })
            }
        }
        catch {
            Write-Warning "$($userProfile.SID): $_"
            [pscustomobject]@{ Scope = $userProfile.LocalPath; ExitCode = $null; Status = 'Incomplete' }
        }
        finally {
            if ($registered -and -not $running) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Continue
            }
        }
    }
}

#endregion

#region -------------------- Invoke-PowerToys (dispatcher, returns the exit code) --------------------

function Invoke-PowerToys {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Status', 'Update', 'Uninstall')]
        [string]$Action = 'Status'
    )

    try {
        switch ($Action) {
            'Status'    { Update-PowerToys -StatusOnly | Format-Table -AutoSize | Out-Host; return 0 }
            'Update'    { $results = @(Update-PowerToys -WhatIf:$WhatIfPreference) }
            'Uninstall' { $results = @(Uninstall-PowerToys -WhatIf:$WhatIfPreference) }
        }
        $results | Format-Table -AutoSize | Out-Host
        if ($results.Status -contains 'RestartRequired' -or $results.Status -contains 'Restart required') { return 3010 }
        if ($results.Status -contains 'Incomplete' -or $results.Status -contains 'FailedToSchedule') { return 1 }
        return 0
    }
    catch {
        # Write-Host, not Write-Error: a caller's ErrorAction Stop must not lose the exit code.
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
}

#endregion

#region ==================== ENTRY POINT - set $RMM, then pick ONE action ====================

# $true ONLY in an RMM component: the script then ends with 'exit <code>' so the RMM
# sees the result. Leave $false when pasting into a console or RMM remote shell -
# exit would end that session mid-way through the engineer's other patching work.
$RMM = $false

$exitCode = Invoke-PowerToys
# $exitCode = Invoke-PowerToys -Action Update -WhatIf
# $exitCode = Invoke-PowerToys -Action Update
# $exitCode = Invoke-PowerToys -Action Uninstall

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
