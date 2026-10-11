# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Python (python.org CPython) - Check / Remove, end-of-life aware. RMM-ready.

.DESCRIPTION
    -Mode Check   DEFAULT. Read-only. Lists every uninstall entry containing 'Python' (machine,
                  and every logged-on user's hive) plus Python install folders on disk (Program
                  Files, C:\PythonXY, and every profile's AppData\Local\Programs\Python and
                  AppData\Local\Python\pythoncore-* (Python install manager) - this
                  also finds per-user installs of users who are not logged on, without loading
                  their hives). Flags end-of-life versions. Returns 2 when the target (see
                  Version below) is present.
    -Mode Remove  Runs Uninstall-PythonVersion for each targeted version: the python.org bundle,
                  its MSIs, orphaned uninstall keys, PythonCore registry keys, install folders,
                  %APPDATA%\Python user-site folders, Package Cache and PATH entries - machine-wide
                  and in every user profile (offline profiles' NTUSER.DAT is loaded temporarily).
                  Another user's per-user install cannot be uninstalled from this session, so its
                  registry entries and files are scrubbed instead ('Scrubbed (not uninstalled)').
                  Registry keys are exported to %ProgramData%\PythonUninstall\<timestamp> first.

    -Options (both modes):
        Version   'EOL' (default) every version below EOLBelow | 'All' every CPython version |
                  '3.11' or '3.11.4' one version ('3.1' does not match '3.11')
        EOLBelow  Versions below this are end of life. Default '3.10'.
    -Options (Remove only, passed to Uninstall-PythonVersion):
        AllProfiles / RemoveFiles / CleanPath   default $true (set $false to skip)
        Architecture    'x86' | 'x64' | 'arm64' | 'Any' (default)
        IncludeLauncher remove the shared py.exe launcher too - only when no Python remains
        BackupPath      folder for the .reg exports

    Not handled: Microsoft Store Python (Appx), Anaconda/Miniconda and other products that
    bundle Python (Check lists their uninstall entries as Kind 'Other'), and venvs/embedded copies.

    Requirements: Windows PowerShell 5.1, 64-bit on 64-bit Windows. Remove (including its
    -WhatIf preview, which loads offline hives) needs an elevated or SYSTEM session.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the mode - edit that one
    line. For an RMM component also set $RMM = $true there, so the script exits with the code.

    Invoke-Python                                              # Check for EOL Python (read-only)
    Invoke-Python -Options @{ Version = 'All' }                # Check, any Python counts
    Invoke-Python -Mode Remove -WhatIf                         # Preview removal of EOL Python
    Invoke-Python -Mode Remove                                 # Remove EOL Python, all profiles
    Invoke-Python -Mode Remove -Options @{ Version = '3.11.4' }

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-Python returns one; the entry point exits with it only when $RMM = $true):
        0     Check: target not present / Remove: done or nothing to do (or -WhatIf)
        1     Error, an uninstall FAILED, or the target is still present afterwards
        2     Check: target present (EOL Python by default)
        3010  Remove: done, reboot required to finish
        10    Remove: session is not elevated - nothing changed

    The EOL line is policy, not data: 3.9 ended October 2025; 3.10 ends October 2026 (PEP 619),
    3.11 October 2027 (PEP 664). Raise EOLBelow as those dates pass.
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Local AD (S-1-5-21) and Entra ID / Azure AD (S-1-12-1) user accounts.
$PyUserSidPattern = '^S-1-5-21-|^S-1-12-1-'

function Get-PyUserProfile {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -EA SilentlyContinue | ForEach-Object {
        $dir = (Get-ItemProperty $_.PSPath -Name ProfileImagePath -EA SilentlyContinue).ProfileImagePath
        if ($_.PSChildName -match $PyUserSidPattern -and $dir -and (Test-Path $dir)) {
            [pscustomobject]@{ Sid = $_.PSChildName; Dir = $dir }
        }
    }
}

#endregion

#region -------------------- Get-PythonInventory (read-only detection) --------------------

function Get-PythonInventory {
    param([version]$EOLBelow = '3.10')

    $profiles = @(Get-PyUserProfile)

    # Uninstall entries: machine (both views) + every loaded user hive. Offline hives are not
    # loaded here (read-only); the folder scan below covers those users.
    $roots = @(
        @{ Scope = 'Machine'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Scope = 'Machine'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    foreach ($hive in Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue | Where-Object { $_.PSChildName -match $PyUserSidPattern -and $_.PSChildName -notmatch '_Classes$' }) {
        $p = $profiles | Where-Object Sid -eq $hive.PSChildName | Select-Object -First 1
        $name = if ($p) { Split-Path $p.Dir -Leaf } else { $hive.PSChildName }
        foreach ($sub in 'Software\Microsoft\Windows\CurrentVersion\Uninstall', 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
            $roots += @{ Scope = $name; Path = "Registry::HKEY_USERS\$($hive.PSChildName)\$sub" }
        }
    }

    $rows = @(
        foreach ($root in $roots) {
            Get-ItemProperty "$($root.Path)\*" -EA SilentlyContinue | Where-Object { $_.DisplayName -like '*Python*' } | ForEach-Object {
                $kind = if ($_.DisplayName -match '^Python\s+\d+\.\d+') { 'CPython' }
                        elseif ($_.DisplayName -match '^Python Launcher') { 'Launcher' }
                        else { 'Other' }
                # Python's component MSIs are SystemComponent=1 (hidden in Apps & Features): Hidden rows are counted, not listed.
                $ver = if ($kind -eq 'CPython' -and $_.DisplayName -match '^Python\s+(\d+\.\d+(?:\.\d+)?)') { $Matches[1] } else { $_.DisplayVersion }
                [pscustomobject]@{
                    Scope    = $root.Scope
                    Kind     = $kind
                    Version  = $ver
                    Minor    = if ($kind -eq 'CPython') { ($ver -split '\.')[0..1] -join '.' } else { $null }
                    Hidden   = ($_.SystemComponent -eq 1)
                    Name     = $_.DisplayName
                    Location = $_.PSChildName
                }
            }
        }

        # Install folders. Python 2.x defaulted to C:\PythonXY.
        $folderRoots = @(
            foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:SystemDrive\")) { if ($base) { @{ Scope = 'Machine'; Path = $base } } }
            foreach ($p in $profiles) { @{ Scope = (Split-Path $p.Dir -Leaf); Path = "$($p.Dir)\AppData\Local\Programs\Python" } }
        )
        foreach ($fr in $folderRoots) {
            Get-ChildItem -LiteralPath $fr.Path -Directory -Filter 'Python*' -EA SilentlyContinue |
                Where-Object { $_.Name -match '^Python(\d)(\d+)(-32|-arm64)?$' -and (Test-Path (Join-Path $_.FullName 'python.exe')) } |
                ForEach-Object {
                    $minor = $_.Name -replace '^Python(\d)(\d+).*$', '$1.$2'
                    $pv = (Get-Item (Join-Path $_.FullName 'python.exe') -EA SilentlyContinue).VersionInfo.ProductVersion
                    [pscustomobject]@{
                        Scope = $fr.Scope; Kind = 'Folder'; Version = $(if ($pv) { $pv } else { $minor })
                        Minor = $minor; Hidden = $false; Name = $_.Name; Location = $_.FullName
                    }
                }
        }

        # Python install manager (pymanager, default from 3.14; can install older versions too).
        foreach ($p in $profiles) {
            Get-ChildItem -LiteralPath "$($p.Dir)\AppData\Local\Python" -Directory -Filter 'pythoncore-*' -EA SilentlyContinue |
                Where-Object { $_.Name -match '^pythoncore-\d+\.\d+-(64|32|arm64)$' -and (Test-Path (Join-Path $_.FullName 'python.exe')) } |
                ForEach-Object {
                    $minor = $_.Name -replace '^pythoncore-(\d+\.\d+)-.*$', '$1'
                    $pv = (Get-Item (Join-Path $_.FullName 'python.exe') -EA SilentlyContinue).VersionInfo.ProductVersion
                    [pscustomobject]@{
                        Scope = (Split-Path $p.Dir -Leaf); Kind = 'Folder'; Version = $(if ($pv) { $pv } else { $minor })
                        Minor = $minor; Hidden = $false; Name = $_.Name; Location = $_.FullName
                    }
                }
        }

        # pip --user site folders survive any uninstall. Listed, not counted as an install.
        foreach ($p in $profiles) {
            Get-ChildItem -LiteralPath "$($p.Dir)\AppData\Roaming\Python" -Directory -Filter 'Python*' -EA SilentlyContinue |
                Where-Object { $_.Name -match '^Python(\d)(\d+)(-32|-arm64)?$' } |
                ForEach-Object {
                    $minor = $_.Name -replace '^Python(\d)(\d+).*$', '$1.$2'
                    [pscustomobject]@{
                        Scope = (Split-Path $p.Dir -Leaf); Kind = 'UserSite'; Version = $minor
                        Minor = $minor; Hidden = $false; Name = $_.Name; Location = $_.FullName
                    }
                }
        }
    )

    foreach ($r in $rows) {
        $eol = $false
        if ($r.Kind -in 'CPython', 'Folder', 'UserSite' -and $r.Minor) { $eol = [version]$r.Minor -lt $EOLBelow }
        $r | Add-Member -NotePropertyName EOL -NotePropertyValue $eol
    }
    return $rows
}

# Versions to act on. Only CPython uninstall entries and install folders count; Launcher,
# Other and UserSite rows are reported but never make a version a target on their own.
function Resolve-PythonTarget {
    param($Rows, [string]$Version = 'EOL')
    $cand = @($Rows | Where-Object { $_.Kind -in 'CPython', 'Folder' })
    switch ($Version) {
        'EOL'   { return @($cand | Where-Object EOL | ForEach-Object Minor | Sort-Object { [version]$_ } -Unique) }
        'All'   { return @($cand | ForEach-Object Minor | Sort-Object { [version]$_ } -Unique) }
        default {
            if ($Version -notmatch '^\d+\.\d+(\.\d+)?$') { throw "Version must be 'EOL', 'All', or like '3.11' / '3.11.4' (got '$Version')." }
            if ($cand | Where-Object { $_.Version -eq $Version -or $_.Version -like "$Version.*" }) { return @($Version) }
            return @()
        }
    }
}

function Show-PythonInventory {
    param($Rows)
    $visible = @($Rows | Where-Object { -not $_.Hidden })
    if ($visible) { $visible | Sort-Object Scope, Kind, Name | Format-Table Scope, Kind, Version, EOL, Name, Location -AutoSize | Out-Host }
    else { Write-Host 'No Python uninstall entries or install folders found.' }
    $h = @($Rows | Where-Object Hidden).Count
    if ($h) { Write-Host "(+$h hidden Python component MSI entries, removed together with their version)" }
}

#endregion

#region -------------------- Uninstall-PythonVersion (from python-check(broken).ps1, fixed) --------------------

function Uninstall-PythonVersion {
<#
.SYNOPSIS
    Removes a specific Python version machine-wide AND from every user profile:
    bundle, all associated MSIs, residual registry keys, leftover directories,
    and (optionally) stale PATH entries.

.DESCRIPTION
    Python can be installed three ways, and a "leftover" is usually one of the
    ones you didn't check:

      1. Machine-wide  -> HKLM Uninstall + C:\Program Files\PythonXY (C:\PythonXY for 2.x)
      2. Per-user      -> HKCU Uninstall + %LOCALAPPDATA%\Programs\Python\PythonXY
                          (Python install manager: %LOCALAPPDATA%\Python\pythoncore-X.Y-64)
      3. pip --user    -> %APPDATA%\Python\PythonXY (survives ANY uninstall)

    Case 2 and 3 exist once per profile. Profiles that aren't logged on have no
    HKCU, so this loads each profile's NTUSER.DAT under HKU:\ temporarily
    (via reg.exe load) and unloads it in a finally block.

    IMPORTANT: a per-user MSI install belonging to another user cannot be
    cleanly uninstalled from your session - msiexec will not see it (1605).
    For those profiles this removes the registry entries and files directly and
    flags the result as 'Scrubbed (not uninstalled)'. The current user's own
    per-user installs are uninstalled normally.

.PARAMETER Version
    Two- or three-part version, e.g. '3.11' or '3.11.4'. Boundary-aware, so
    '3.1' will not match '3.11'.

.PARAMETER AllProfiles
    Scan and clean every profile in ProfileList, not just the current user.

.PARAMETER RemoveFiles
    Delete leftover directories (install dirs, %APPDATA%\Python, Start Menu
    shortcuts, Package Cache).

.PARAMETER CleanPath
    Strip matching entries from machine PATH and each cleaned profile's PATH.

.PARAMETER IncludeLauncher
    Also remove the shared Python Launcher (py.exe). Only if no other Python remains.

.PARAMETER BackupPath
    Directory for .reg exports taken before any key is deleted.

.EXAMPLE
    Uninstall-PythonVersion -Version 3.11.4 -AllProfiles -RemoveFiles -CleanPath -WhatIf

.EXAMPLE
    Uninstall-PythonVersion -Version 3.9 -AllProfiles -RemoveFiles -Force
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern('^\d+\.\d+(\.\d+)?$')]
        [string]$Version,

        [ValidateSet('x86', 'x64', 'arm64', 'Any')]
        [string]$Architecture = 'Any',

        [switch]$AllProfiles,
        [switch]$RemoveFiles,
        [switch]$CleanPath,
        [switch]$IncludeLauncher,
        [switch]$Force,

        [string]$BackupPath = (Join-Path $env:ProgramData "PythonUninstall\$(Get-Date -Format yyyyMMdd-HHmmss)")
    )

    $ErrorActionPreference = 'Stop'
    if ($Force) { $ConfirmPreference = 'None' }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Elevation required (hive loading and HKLM writes need admin).' }

    $minor    = ($Version -split '\.')[0..1] -join '.'          # 3.11
    $tag      = 'Python' + ($minor -replace '\.', '')           # Python311
    $tagRx    = [regex]::Escape($tag) + '(?!\d)'                # Python31 must not match Python311
    $report   = [System.Collections.Generic.List[object]]::new()
    $loaded   = [System.Collections.Generic.List[string]]::new()
    $rebootNeeded = $false
    $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

    $add = { param($Scope, $Item, $Action, $Status)
        $report.Add([pscustomobject]@{ Scope = $Scope; Item = $Item; Action = $Action; Status = $Status })
    }

    # reg.exe wants HKLM\Foo, the provider gives HKLM:\Foo or a long PSPath
    $toRegPath = {
        param($p)
        ($p -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' `
            -replace '^HKEY_LOCAL_MACHINE', 'HKLM' `
            -replace '^HKEY_CURRENT_USER',  'HKCU' `
            -replace '^HKEY_USERS',         'HKU'  `
            -replace '^(HK[A-Z]{1,2}):',    '$1')       # {1,2}: HKU has one letter after HK
    }

    $backupKey = {
        param($psPath, $label)
        if ($WhatIfPreference) { return }
        if (-not (Test-Path $BackupPath)) { New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null }
        $file = Join-Path $BackupPath ("{0}.reg" -f ($label -replace '[^\w.-]', '_'))
        & reg.exe export (& $toRegPath $psPath) $file /y 2>$null | Out-Null
    }

    try {
        # ================= build the list of scopes to examine =================
        # Native   = machine scope (HKLM, Program Files, machine PATH)
        # CanUninstall = msiexec/bundle can see these installs from this session
        $scopes = [System.Collections.Generic.List[object]]::new()
        $scopes.Add([pscustomobject]@{
            Name = 'Machine'; Root = 'HKLM:\SOFTWARE'; Root32 = 'HKLM:\SOFTWARE\WOW6432Node'
            ProfileDir = $null; Native = $true; CanUninstall = $true
        })

        $profiles = @()
        if ($AllProfiles) {
            $plKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            $profiles = Get-ChildItem $plKey | ForEach-Object {
                $sid = $_.PSChildName
                $dir = (Get-ItemProperty $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
                if ($sid -match $PyUserSidPattern -and $dir -and (Test-Path $dir)) {
                    [pscustomobject]@{ Sid = $sid; Dir = $dir }
                }
            }
        }
        else {
            $profiles = @([pscustomobject]@{
                Sid = $currentSid
                Dir = $env:USERPROFILE
            })
        }

        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
        }

        foreach ($pf in $profiles) {
            $hive = "HKU:\$($pf.Sid)"
            if (-not (Test-Path $hive)) {
                # profile not logged on - mount NTUSER.DAT read/write, unload later
                $dat = Join-Path $pf.Dir 'NTUSER.DAT'
                if (-not (Test-Path $dat)) {
                    & $add 'Profile' $pf.Dir 'Load hive' 'Skipped (no NTUSER.DAT)'
                    continue
                }
                $mount = "PyScan_$($pf.Sid -replace '\W','')"
                & reg.exe load "HKU\$mount" $dat 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    & $add 'Profile' $pf.Dir 'Load hive' "Failed ($LASTEXITCODE - in use?)"
                    continue
                }
                $loaded.Add($mount)
                $hive = "HKU:\$mount"
            }
            $scopes.Add([pscustomobject]@{
                Name = Split-Path $pf.Dir -Leaf; Root = "$hive\SOFTWARE"
                Root32 = "$hive\SOFTWARE\WOW6432Node"; ProfileDir = $pf.Dir; Native = $false
                CanUninstall = ($pf.Sid -eq $currentSid)
            })
        }

        # ================= scan + uninstall each scope =================
        $namePattern = '^Python\s+' + [regex]::Escape($Version) + '(\D|$)'

        foreach ($scope in $scopes) {
            $uninstRoots = @(
                "$($scope.Root)\Microsoft\Windows\CurrentVersion\Uninstall"
                "$($scope.Root32)\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            $targets = foreach ($root in $uninstRoots) {
                if (-not (Test-Path $root)) { continue }
                foreach ($key in Get-ChildItem $root -ErrorAction SilentlyContinue) {
                    $p = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                    if (-not $p.DisplayName) { continue }

                    $byName = $p.DisplayName -match $namePattern
                    $byVer  = $p.DisplayName -match '^Python\b' -and $p.DisplayVersion -and
                              ($p.DisplayVersion -eq $Version -or $p.DisplayVersion -like "$Version.*")
                    if (-not ($byName -or $byVer)) { continue }
                    if (-not $IncludeLauncher -and $p.DisplayName -match 'Launcher') { continue }

                    $arch = if     ($p.DisplayName -match '\(32-bit\)')  { 'x86' }
                            elseif ($p.DisplayName -match '\(ARM64\)')   { 'arm64' }
                            elseif ($p.DisplayName -match '\(64-bit\)')  { 'x64' }
                            elseif ($key.Name -match 'WOW6432Node')      { 'x86' } else { 'x64' }
                    if ($Architecture -ne 'Any' -and $arch -ne $Architecture) { continue }

                    [pscustomobject]@{
                        Name        = $p.DisplayName
                        Arch        = $arch
                        # Burn bundle keys are GUIDs too, but not MSI products: msiexec /x would
                        # return 1605 and the bundle's key would then be deleted as "orphaned".
                        ProductCode = if (-not $p.BundleCachePath -and $key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $key.PSChildName } else { $null }
                        IsBundle    = [bool]$p.BundleCachePath
                        Cache       = $p.BundleCachePath
                        Command     = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
                        KeyPath     = $key.PSPath
                    }
                }
            }

            # bundle first - it takes most of its own MSIs with it
            $targets = @($targets | Sort-Object @{ Expression = { -not $_.IsBundle } }, Name)

            foreach ($t in $targets) {
                $label = '{0} [{1}]' -f $t.Name, $t.Arch

                # Another user's per-user install: msiexec cannot see it from here.
                if (-not $scope.CanUninstall) {
                    if ($PSCmdlet.ShouldProcess("$($scope.Name): $label", 'Scrub registry entry')) {
                        & $backupKey $t.KeyPath "$($scope.Name)_$($t.Name)"
                        Remove-Item $t.KeyPath -Recurse -Force -ErrorAction Continue
                        & $add $scope.Name $label 'Scrub' 'Scrubbed (not uninstalled)'
                    }
                    else { & $add $scope.Name $label 'Scrub' 'WhatIf' }
                    continue
                }

                if ($t.ProductCode) {
                    $file = "$env:SystemRoot\System32\msiexec.exe"
                    $argv = @('/x', $t.ProductCode, '/qn', '/norestart')
                }
                elseif ($t.Command) {
                    $cmd = $t.Command.Trim()
                    if     ($cmd -match '^"([^"]+)"\s*(.*)$') { $file = $Matches[1]; $rest = $Matches[2] }
                    elseif ($cmd -match '^(\S+)\s*(.*)$')     { $file = $Matches[1]; $rest = $Matches[2] }
                    else                                       { $file = $cmd; $rest = '' }
                    if ($t.IsBundle) {
                        if ($rest -notmatch '/uninstall|/x')  { $rest += ' /uninstall' }
                        if ($rest -notmatch '/quiet|/silent') { $rest += ' /quiet' }
                        if ($rest -notmatch '/norestart')     { $rest += ' /norestart' }
                    }
                    $argv = @($rest.Trim() -split '\s+' | Where-Object { $_ })
                }
                else {
                    & $add $scope.Name $label 'Uninstall' 'Skipped (no command)'
                    continue
                }

                Write-Verbose ("{0}: {1} {2}" -f $scope.Name, $file, ($argv -join ' '))
                if (-not $PSCmdlet.ShouldProcess("$($scope.Name): $label", 'Uninstall')) {
                    & $add $scope.Name $label 'Uninstall' 'WhatIf'
                    continue
                }

                $exit = (Start-Process $file -ArgumentList $argv -Wait -PassThru -WindowStyle Hidden).ExitCode
                $status = switch ($exit) {
                    0       { 'Removed' }
                    1641    { $rebootNeeded = $true; 'Removed (reboot pending)' }
                    3010    { $rebootNeeded = $true; 'Removed (reboot pending)' }
                    1605    { 'Already gone' }
                    1614    { 'Already gone' }
                    default { "FAILED ($exit)" }
                }
                if ($status -like 'FAILED*') { Write-Warning "$($scope.Name): $label -> $status" }
                & $add $scope.Name $label 'Uninstall' $status

                # ARP key that outlived its own uninstaller. Not after a failure: deleting the
                # key would hide a product that is still installed.
                if ($status -notlike 'FAILED*' -and (Test-Path $t.KeyPath)) {
                    if ($PSCmdlet.ShouldProcess($t.KeyPath, 'Remove orphaned ARP key')) {
                        & $backupKey $t.KeyPath "ARP_$($t.Name)"
                        Remove-Item $t.KeyPath -Recurse -Force -ErrorAction Continue
                        & $add $scope.Name 'orphaned ARP key' 'Registry' 'Removed'
                    }
                }
            }

            # ---------- residual registry, per scope ----------
            $suffixes = switch ($Architecture) {
                'x86'   { @('-32') }
                'arm64' { @('-arm64') }
                'x64'   { @('') }
                default { @('', '-32', '-arm64') }
            }
            $residual = foreach ($base in $scope.Root, $scope.Root32) {
                foreach ($s in $suffixes) { "$base\Python\PythonCore\$minor$s" }
            }
            foreach ($path in ($residual | Select-Object -Unique)) {
                if (-not (Test-Path $path)) { continue }
                if ($PSCmdlet.ShouldProcess($path, 'Remove registry key')) {
                    & $backupKey $path "$($scope.Name)_PythonCore_$minor"
                    Remove-Item $path -Recurse -Force -ErrorAction Continue
                    & $add $scope.Name $path 'Registry' 'Removed'
                }
                else { & $add $scope.Name $path 'Registry' 'WhatIf' }
            }

            # ---------- PATH, per scope ----------
            if ($CleanPath) {
                $envKey = if ($scope.Native) {
                    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
                } else {
                    ($scope.Root -replace '\\SOFTWARE$', '\Environment')
                }
                if (Test-Path $envKey) {
                    $rk  = Get-Item $envKey
                    $raw = $rk.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
                    if ($raw) {
                        $kind  = $rk.GetValueKind('Path')
                        $parts = @($raw -split ';' | Where-Object { $_ })
                        $keep  = @($parts | Where-Object { $_ -notmatch $tagRx })
                        if ($keep.Count -ne $parts.Count) {
                            $new = ($keep -join ';')
                            if ($PSCmdlet.ShouldProcess("$($scope.Name) PATH", 'Remove Python entries')) {
                                & $backupKey $envKey "$($scope.Name)_Environment"
                                # Built first: inside the method call, the commas of -replace split the arguments.
                                $fullKey = (& $toRegPath $envKey) -replace '^HKLM', 'HKEY_LOCAL_MACHINE' -replace '^HKU', 'HKEY_USERS'
                                [Microsoft.Win32.Registry]::SetValue($fullKey, 'Path', $new, $kind)
                                & $add $scope.Name 'PATH' 'Edit' "Removed $($parts.Count - $keep.Count) entr(y/ies)"
                            }
                            else { & $add $scope.Name 'PATH' 'Edit' 'WhatIf' }
                        }
                    }
                }
            }

            # ---------- filesystem leftovers, per scope ----------
            if ($RemoveFiles) {
                $paths = if ($scope.Native) {
                    @(
                        "$env:ProgramFiles\$tag"
                        "${env:ProgramFiles(x86)}\$tag"
                        "$env:SystemDrive\$tag"
                        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Python $minor"
                    )
                } else {
                    $d = $scope.ProfileDir
                    @(
                        "$d\AppData\Local\Programs\Python\$tag"
                        "$d\AppData\Local\Programs\Python\$tag-32"
                        "$d\AppData\Local\Programs\Python\$tag-arm64"
                        "$d\AppData\Local\Python\pythoncore-$minor-64"      # Python install manager
                        "$d\AppData\Local\Python\pythoncore-$minor-32"
                        "$d\AppData\Local\Python\pythoncore-$minor-arm64"
                        "$d\AppData\Roaming\Python\$tag"
                        "$d\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Python $minor"
                    )
                }
                foreach ($path in $paths) {
                    if (-not (Test-Path -LiteralPath $path)) { continue }
                    if ($PSCmdlet.ShouldProcess($path, 'Delete directory')) {
                        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Continue
                        & $add $scope.Name $path 'Delete' 'Removed'
                    }
                    else { & $add $scope.Name $path 'Delete' 'WhatIf' }
                }

                # Burn package cache for this version (machine scope only)
                if ($scope.Native) {
                    $cache = Join-Path $env:ProgramData 'Package Cache'
                    $cacheRx = '^python-' + [regex]::Escape($Version) + '(\D|$)'   # 3.1 must not match python-3.11
                    if (Test-Path $cache) {
                        Get-ChildItem $cache -Directory -ErrorAction SilentlyContinue |
                            Where-Object {
                                Get-ChildItem $_.FullName -Filter "python-$Version*" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Name -match $cacheRx }
                            } | ForEach-Object {
                                if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete package cache')) {
                                    Remove-Item $_.FullName -Recurse -Force -ErrorAction Continue
                                    & $add 'Machine' $_.FullName 'Delete' 'Removed'
                                }
                                else { & $add 'Machine' $_.FullName 'Delete' 'WhatIf' }
                            }
                    }
                }
            }
        }
    }
    finally {
        # release handles before unloading, or reg unload fails silently
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        foreach ($m in $loaded) {
            & reg.exe unload "HKU\$m" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "Failed to unload HKU\$m - unload manually." }
        }
    }

    if ($rebootNeeded) { Write-Warning 'A reboot is required to finish removal.' }
    if ((Test-Path $BackupPath) -and -not $WhatIfPreference) { Write-Verbose "Registry backups: $BackupPath" }
    $report
}

#endregion

#region -------------------- Invoke-Python (dispatcher, returns the exit code) --------------------

function Invoke-Python {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Remove')]
        [string]$Mode = 'Check',
        [hashtable]$Options = @{}
    )

    try {
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            # 32-bit PowerShell sees HKLM\SOFTWARE redirected to WOW6432Node and misses 64-bit installs.
            Write-Host 'ERROR: run this in 64-bit PowerShell. Nothing changed.' -ForegroundColor Red
            return 1
        }
        $admin = Test-IsAdmin
        if ($Mode -ne 'Check' -and -not $admin) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session. Nothing changed." -ForegroundColor Red
            return 10
        }

        $o = @{ Version = 'EOL'; EOLBelow = '3.10'; AllProfiles = $true; RemoveFiles = $true; CleanPath = $true }
        foreach ($k in $Options.Keys) { $o[$k] = $Options[$k] }
        $version = $o.Version; $eolBelow = [version]$o.EOLBelow
        $o.Remove('Version'); $o.Remove('EOLBelow')

        $rows = Get-PythonInventory -EOLBelow $eolBelow
        $targets = @(Resolve-PythonTarget -Rows $rows -Version $version)

        if ($Mode -eq 'Check') {
            Show-PythonInventory $rows
            if (-not $admin) { Write-Host 'NOT ELEVATED: other profiles may be unreadable; rerun elevated for a full scan.' -ForegroundColor Yellow }
            Write-Host 'Offline users: only their install folders are scanned (their hives are loaded by Remove only).'
            if ($targets) { Write-Host "Target '$version' (EOL below $eolBelow): PRESENT -> $($targets -join ', ')" -ForegroundColor Yellow; return 2 }
            Write-Host "Target '$version' (EOL below $eolBelow): not present"
            return 0
        }

        # Remove
        if (-not $targets) { Write-Host "Nothing to remove for target '$version' (EOL below $eolBelow)."; return 0 }
        Write-Host "Removing Python $($targets -join ', ') ..."
        $report = @(foreach ($v in $targets) { Uninstall-PythonVersion -Version $v @o -Confirm:$false -WhatIf:$WhatIfPreference })
        if ($report) { $report | Format-Table -AutoSize | Out-Host }
        if ($WhatIfPreference) { return 0 }

        if ($report | Where-Object { $_.Status -like 'FAILED*' }) { Write-Host 'One or more uninstalls FAILED (see above).' -ForegroundColor Red; return 1 }
        $left = @(Resolve-PythonTarget -Rows (Get-PythonInventory -EOLBelow $eolBelow) -Version $version)
        if ($left -and $o.Architecture -in $null, 'Any') {
            Write-Host "Still present afterwards: $($left -join ', ') (files in use, RemoveFiles off, or a reboot pending)." -ForegroundColor Yellow
            return 1
        }
        if ($report | Where-Object { $_.Status -like '*reboot pending*' }) { Write-Host 'Removed; reboot required.' -ForegroundColor Yellow; return 3010 }
        Write-Host 'Removed.' -ForegroundColor Green
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

$exitCode = Invoke-Python                                                  # Check for EOL Python (read-only)
# $exitCode = Invoke-Python -Options @{ Version = 'All' }                  # Check, any Python counts (read-only)
# $exitCode = Invoke-Python -Mode Remove -WhatIf                           # Preview EOL removal (loads offline hives, changes nothing)
# $exitCode = Invoke-Python -Mode Remove                                   # DESTRUCTIVE: removes EOL Python, all profiles, files, PATH
# $exitCode = Invoke-Python -Mode Remove -Options @{ Version = '3.11.4' }  # DESTRUCTIVE: one version
# $exitCode = Invoke-Python -Mode Remove -Options @{ Version = 'All'; IncludeLauncher = $true }  # DESTRUCTIVE: every CPython + py.exe

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
