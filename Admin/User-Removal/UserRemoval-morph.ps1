# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
# 2026-10-19: LastUsedFrom / Created / HiveWrite added; fallback date is now the folder write time, not NTUSER.DAT - re-run the tests before updating the line above.
<#
.SYNOPSIS
    User profile / local account removal - Check / Remove / Cleanup / Interactive. RMM-ready.

.DESCRIPTION
    Everything is matched by SID, never by folder or user name, so a domain user 'CORP\bob' and a
    local account 'bob' are never confused.

    -Mode Check        DEFAULT. Read-only. Lists every user profile (local, domain, Entra ID),
                       local accounts without a profile, and broken state:
                         NoFolder  profile registered but its folder is gone (user gets a TEMP
                                   profile at next logon)
                         .bak      ProfileList\<SID>.bak key (the classic TEMP-profile cause)
                         Orphan    folder under the profiles directory with no registration
                       Last used = ProfileList load/unload time (Windows 10 1903+), falling back to
                       the profile folder's write time (then WMI). NTUSER.DAT is shown (HiveWrite)
                       but not used: Windows servicing rewrites every registered hive. The From
                       column in Check shows which source was used.
                       Returns 2 when broken state is found, or when the -Options
                       Users / InactiveDays targets below are present.
    -Mode Remove       Non-interactive. Targets come from -Options (one of them is required):
                         Users        = @('CORP\bob', 'bob', 'S-1-5-21-...', 'C:\Users\bob')
                                        A bare name must match exactly one SID, else it refuses
                                        and lists the matches.
                         InactiveDays = 90   profiles not used for N days
                         IncludeNeverUsed = $true   with InactiveDays: also profiles with no
                                        last-use data
                       Per target: the profile is deleted through Windows (Win32_UserProfile,
                       which removes the ProfileList key, ProfileGuid and folder together). Only
                       if that succeeds is a locked leftover folder removed (rd, which does not
                       follow junctions), and only inside the profiles directory. If it fails,
                       nothing else is touched for that user. Then the local account, by SID:
                         RemoveAccount  default $true with Users, $false with InactiveDays
    -Mode Cleanup      Fixes broken state: removes registrations whose folder is gone (including
                       .bak keys; .reg backup first) and unregistered TEMP* folders. Orphan
                       non-TEMP folders can hold a user's old data, so they are only removed with
                       -Options @{ RemoveOrphanFolders = $true }. A .bak key whose folder exists is
                       reported, never changed (fix by hand: see NOTES).
    -Mode Interactive  Console menu (arrow keys, SPACE select, ENTER, Y + DELETE to confirm) over
                       the same inventory; removals go through the same code as Remove, including
                       the local account. Needs a real console - not an RMM non-interactive shell.

    Never touched: system/service accounts, built-in accounts by RID (500 Administrator, 501
    Guest, 503 DefaultAccount, 504 WDAGUtilityAccount - whatever they are renamed to), the
    current user, loaded profiles (logged on or in use), names in -Options Exclude (default
    'defaultuser0'), and the throwaway folders of Windows' virtual accounts (UMFD-*, DWM-*,
    '*.Font Driver Host*', '*.Window Manager*'). Domain and Entra accounts are never deleted -
    only their profiles.

    Remove and Cleanup write a results CSV (and Cleanup's .reg backups) to
    %ProgramData%\UserRemoval\<timestamp>. Requirements: Windows PowerShell 5.1, 64-bit (the
    LocalAccounts module is missing in 32-bit PowerShell). Remove, Cleanup and Interactive need
    an elevated or SYSTEM session. -WhatIf previews Remove and Cleanup.

.EXAMPLE
    Paste the WHOLE script into an elevated/SYSTEM PowerShell session (e.g. the RMM's remote
    shell) or an RMM component. The ENTRY POINT at the bottom picks the mode - edit that one
    line. For an RMM component also set $RMM = $true there, so the script exits with the code.

    Invoke-UserRemoval                                                   # Check
    Invoke-UserRemoval -Options @{ InactiveDays = 90 }                   # Check: who is stale?
    Invoke-UserRemoval -Mode Remove -Options @{ Users = 'CORP\bob' } -WhatIf
    Invoke-UserRemoval -Mode Remove -Options @{ Users = 'bob', 'alice' }
    Invoke-UserRemoval -Mode Remove -Options @{ InactiveDays = 90 } -WhatIf
    Invoke-UserRemoval -Mode Cleanup -WhatIf
    Invoke-UserRemoval -Mode Interactive

    After a paste the functions stay loaded, so further modes can be typed directly.

.NOTES
    Exit codes (Invoke-UserRemoval returns one; the entry point exits with it only when $RMM = $true):
        0     Check: nothing to report / Remove, Cleanup: done or nothing to do (or -WhatIf)
        1     Error, or one or more removals failed / left something behind (see results)
        2     Check: broken state found, or the Users / InactiveDays targets are present
        10    Remove / Cleanup / Interactive: session is not elevated - nothing changed

    Manual fix for a .bak key whose folder exists (user logs on to a TEMP profile): with the user
    logged off, delete ProfileList\<SID> (the one without .bak, if its folder is TEMP/missing),
    rename <SID>.bak to <SID>, and set its RefCount and State values to 0.
#>

#region -------------------- Helpers --------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$UPProfileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
# Folders under the profiles directory that are never user profiles.
$UPReservedFolders = @('Default', 'Default User', 'Public', 'All Users', 'defaultuser0')
# Windows' own virtual accounts (font driver host, desktop window manager) make throwaway profile
# folders like 'UMFD-0', 'TEMP.Font Driver Host.003', 'DWM-1.Window Manager'. One may be in use.
$UPSystemFolderPattern = '^(UMFD|DWM)-\d+|\.(Font Driver Host|Window Manager)(\.\d+)?$'

function Get-UPProfilesRoot {
    $dir = (Get-ItemProperty $UPProfileListKey -Name ProfilesDirectory -EA SilentlyContinue).ProfilesDirectory
    if (-not $dir) { $dir = '%SystemDrive%\Users' }
    return [Environment]::ExpandEnvironmentVariables($dir).TrimEnd('\')
}

# A leftover folder may only be deleted if it sits directly in the profiles directory.
function Test-UPSafeFolder {
    param([string]$Path, [string]$Root)
    if (-not $Path) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $false }
    $parent = Split-Path $full -Parent
    $leaf = Split-Path $full -Leaf
    return ($parent -eq $Root -and $leaf -and $leaf -notin $UPReservedFolders -and $leaf -notmatch $UPSystemFolderPattern)
}

# Junction-safe recursive delete: rd /s removes junctions without following them, unlike
# Remove-Item -Recurse in Windows PowerShell 5.1.
function Remove-UPFolder {
    param([string]$Path)
    & cmd.exe /d /c "rd /s /q `"$Path`"" 2>&1 | Out-Null
    return -not (Test-Path -LiteralPath $Path)
}

function ConvertFrom-UPFileTime {
    param($High, $Low)
    if ($null -eq $High -or $null -eq $Low) { return $null }
    # REG_DWORD arrives as Int32 (negative above 0x7FFFFFFF); might error since [uint32] of a negative throws.
    $ft = (([int64]$High -band 4294967295) -shl 32) -bor ([int64]$Low -band 4294967295)
    if ($ft -le 0) { return $null }
    return [datetime]::FromFileTime($ft)
}

# Folder and hive timestamps: shown in Check, and used as last-use fallbacks.
function Get-UPFolderTimes {
    param([string]$Path)
    $dir  = if ($Path) { Get-Item -LiteralPath $Path -Force -EA SilentlyContinue }
    $hive = if ($dir)  { Get-Item -LiteralPath (Join-Path $Path 'NTUSER.DAT') -Force -EA SilentlyContinue }
    [pscustomobject]@{
        Created     = if ($dir)  { $dir.CreationTime }   else { $null }
        FolderWrite = if ($dir)  { $dir.LastWriteTime }  else { $null }
        HiveWrite   = if ($hive) { $hive.LastWriteTime } else { $null }
    }
}

#endregion

#region -------------------- Get-UserProfileInventory (read-only) --------------------

function Get-UserProfileInventory {
    param([string[]]$Exclude = @('defaultuser0'))

    $root = Get-UPProfilesRoot
    $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $localUsers = @(try { Get-LocalUser -ErrorAction Stop } catch { @() })
    $localBySid = @{}
    foreach ($u in $localUsers) { $localBySid[$u.SID.Value] = $u }
    $cimBySid = @{}
    foreach ($c in @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue)) { $cimBySid[$c.SID] = $c }

    $protect = {
        param($sid, $account, $path)
        if ($sid -notmatch '^S-1-5-21-|^S-1-12-1-') { return 'System/service account' }
        if ($sid -match '-(500|501|503|504)$') { return 'Built-in account' }
        if ($sid -eq $currentSid) { return 'Current user' }
        $name = if ($account) { ($account -split '\\')[-1] } else { $null }
        $leaf = if ($path) { Split-Path $path -Leaf } else { $null }
        if (($name -and $name -in $Exclude) -or ($leaf -and $leaf -in $Exclude)) { return 'Excluded' }
        return $null
    }
    $typeOf = {
        param($sid)
        if ($localBySid.ContainsKey($sid)) { 'Local' }
        elseif ($sid -match '^S-1-12-1-') { 'Entra' }
        elseif ($sid -match '^S-1-5-21-') { 'Domain' }
        else { 'System' }
    }
    $nameOf = {
        param($sid)
        if ($localBySid.ContainsKey($sid)) { return "$env:COMPUTERNAME\$($localBySid[$sid].Name)" }
        try { return ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { return $null }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $registeredPaths = @{}

    foreach ($key in Get-ChildItem $UPProfileListKey -ErrorAction SilentlyContinue) {
        $p = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        $isBak = $key.PSChildName -like '*.bak'
        $sid = $key.PSChildName -replace '\.bak$', ''
        $path = $p.ProfileImagePath
        if ($path) { $registeredPaths[$path.TrimEnd('\').ToLowerInvariant()] = $true }
        $cim = if (-not $isBak) { $cimBySid[$sid] } else { $null }
        $account = & $nameOf $sid

        # ProfileList times change only when Windows loads/unloads the profile for a session. On 1903+
        # every logon sets them, so if they are missing the user has not logged on since; fall back to
        # the folder's write time. NTUSER.DAT and Win32_UserProfile are NOT used for dating: servicing
        # loads every registered hive and bumps both (seen: all hives rewritten at the same minute).
        $lastLoad   = ConvertFrom-UPFileTime $p.LocalProfileLoadTimeHigh   $p.LocalProfileLoadTimeLow
        $lastUnload = ConvertFrom-UPFileTime $p.LocalProfileUnloadTimeHigh $p.LocalProfileUnloadTimeLow
        $times = Get-UPFolderTimes $path
        $lastUsed = @($lastLoad, $lastUnload) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        $lastUsedFrom = 'ProfileList'
        if (-not $lastUsed) { $lastUsed = $times.FolderWrite; $lastUsedFrom = 'Folder' }
        if (-not $lastUsed -and $cim) { $lastUsed = $cim.LastUseTime; $lastUsedFrom = 'WMI' }
        if (-not $lastUsed) { $lastUsedFrom = $null }

        $rows.Add([pscustomobject]@{
            Kind         = 'Profile'
            SID          = $sid
            Account      = $account
            Type         = & $typeOf $sid
            Path         = $path
            PathExists   = [bool]($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue))
            Loaded       = [bool]($cim -and $cim.Loaded)
            LastUsed     = $lastUsed
            LastUsedFrom = $lastUsedFrom
            Created      = $times.Created
            HiveWrite    = $times.HiveWrite
            LastLoad     = $lastLoad
            LastUnload   = $lastUnload
            IsTemp       = [bool]($path -and (Split-Path $path -Leaf) -match '^TEMP(\.|$)')
            IsBak        = $isBak
            HasAccount   = $localBySid.ContainsKey($sid)
            Protected    = & $protect $sid $account $path
            RegKey       = $key.PSPath
        })
    }

    # Local accounts that never logged on (no profile).
    foreach ($u in $localUsers) {
        $sid = $u.SID.Value
        if ($rows | Where-Object { $_.Kind -eq 'Profile' -and $_.SID -eq $sid }) { continue }
        $account = "$env:COMPUTERNAME\$($u.Name)"
        $rows.Add([pscustomobject]@{
            Kind = 'AccountOnly'; SID = $sid; Account = $account; Type = 'Local'; Path = $null
            PathExists = $false; Loaded = $false; LastUsed = $u.LastLogon
            LastUsedFrom = $(if ($u.LastLogon) { 'LastLogon' }); Created = $null; HiveWrite = $null
            IsTemp = $false; IsBak = $false
            HasAccount = $true; Protected = & $protect $sid $account $null; RegKey = $null
        })
    }

    # Folders nobody is registered for: dated by the folder's write time, as registered profiles
    # without ProfileList times are (NTUSER.DAT can be rewritten by imaging/migration tools).
    foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
        if ($dir.Name -in $UPReservedFolders -or $dir.Name -match $UPSystemFolderPattern) { continue }
        if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }   # e.g. 'All Users', 'Default User' junctions
        if ($registeredPaths.ContainsKey($dir.FullName.TrimEnd('\').ToLowerInvariant())) { continue }
        $times = Get-UPFolderTimes $dir.FullName
        $rows.Add([pscustomobject]@{
            Kind = 'OrphanFolder'; SID = $null; Account = $null; Type = '-'; Path = $dir.FullName
            PathExists = $true; Loaded = $false
            LastUsed = $dir.LastWriteTime; LastUsedFrom = 'Folder'
            Created = $times.Created; HiveWrite = $times.HiveWrite
            IsTemp = $dir.Name -match '^TEMP(\.|$)'; IsBak = $false; HasAccount = $false
            Protected = $(if ($dir.Name -in $Exclude) { 'Excluded' } else { $null }); RegKey = $null
        })
    }

    return $rows
}

function Get-UPFlags {
    param($Row)
    $f = [System.Collections.Generic.List[string]]::new()
    if ($Row.HasAccount) { $f.Add('ACC') }
    if ($Row.Loaded) { $f.Add('LOADED') }
    if ($Row.IsTemp) { $f.Add('TEMP') }
    if ($Row.IsBak) { $f.Add('.bak') }
    if ($Row.Kind -eq 'Profile' -and -not $Row.PathExists) { $f.Add('NoFolder') }
    if ($Row.Kind -eq 'OrphanFolder') { $f.Add('Orphan') }
    if ($Row.Kind -eq 'AccountOnly') { $f.Add('NoProfile') }
    if ($Row.Protected) { $f.Add("PROTECTED: $($Row.Protected)") }
    return ($f -join ' ')
}

function Show-UserProfileInventory {
    param($Rows)
    $Rows | Where-Object { $_.Type -ne 'System' } | Sort-Object Kind, Account |
        Format-Table @{ n = 'Account'; e = { if ($_.Account) { $_.Account } elseif ($_.SID) { "(unresolved) $($_.SID)" } else { '-' } } },
            Type,
            @{ n = 'LastUsed'; e = { if ($_.Loaded) { 'in use' } elseif ($_.LastUsed) { $_.LastUsed.ToString('yyyy-MM-dd') } else { '-' } } },
            @{ n = 'From'; e = { $_.LastUsedFrom } },
            @{ n = 'LastLoad'; e = { if ($_.LastLoad) { $_.LastLoad.ToString('yyyy-MM-dd HH:mm') } } },
            @{ n = 'LastUnload'; e = { if ($_.LastUnload) { $_.LastUnload.ToString('yyyy-MM-dd HH:mm') } } },
            @{ n = 'HiveWrite'; e = { if ($_.HiveWrite) { $_.HiveWrite.ToString('yyyy-MM-dd HH:mm') } } },
            @{ n = 'Created'; e = { if ($_.Created) { $_.Created.ToString('yyyy-MM-dd') } } },
            @{ n = 'Flags'; e = { Get-UPFlags $_ } },
            Path -AutoSize -Wrap | Out-String -Width 300 | Out-Host
}

# Broken state Cleanup acts on (or reports).
function Get-UPBrokenRows {
    param($Rows)
    @($Rows | Where-Object {
        -not $_.Protected -and -not $_.Loaded -and (
            ($_.Kind -eq 'Profile' -and (-not $_.PathExists -or $_.IsBak)) -or
            ($_.Kind -eq 'OrphanFolder' -and $_.IsTemp)
        )
    })
}

#endregion

#region -------------------- Resolve-UserTarget --------------------

function Resolve-UserTarget {
    param($Rows, [string[]]$Users, [int]$InactiveDays = 0, [switch]$IncludeNeverUsed)

    $candidates = @($Rows | Where-Object { $_.Kind -in 'Profile', 'AccountOnly' -and -not $_.IsBak -and $_.Type -ne 'System' })
    $targets = [System.Collections.Generic.List[object]]::new()

    foreach ($u in $Users) {
        if (-not $u) { continue }
        $hit = if ($u -match '^S-1-\d+(-\d+)+$') { @($candidates | Where-Object SID -eq $u) }
               elseif ($u -match '^[A-Za-z]:\\') { @($candidates | Where-Object { $_.Path -and $_.Path.TrimEnd('\') -eq $u.TrimEnd('\') }) }
               elseif ($u -match '\\') { @($candidates | Where-Object { $_.Account -eq $u }) }
               else { @($candidates | Where-Object { $_.Account -and ($_.Account -split '\\')[-1] -eq $u }) }
        $sids = @($hit | ForEach-Object SID | Sort-Object -Unique)
        if ($sids.Count -gt 1) {
            throw "'$u' matches more than one user: $(($hit | ForEach-Object { "$($_.Account) [$($_.SID)]" }) -join '; '). Use DOMAIN\name or the SID."
        }
        if (-not $hit) { Write-Host "Not found: '$u' (no profile or local account)." -ForegroundColor Yellow; continue }
        foreach ($h in $hit) { if ($targets -notcontains $h) { $targets.Add($h) } }
    }

    if ($InactiveDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$InactiveDays)
        foreach ($r in $candidates | Where-Object { $_.Kind -eq 'Profile' -and -not $_.Loaded -and -not $_.Protected }) {
            if (($r.LastUsed -and $r.LastUsed -lt $cutoff) -or (-not $r.LastUsed -and $IncludeNeverUsed)) {
                if ($targets -notcontains $r) { $targets.Add($r) }
            }
        }
    }
    return $targets
}

#endregion

#region -------------------- Remove-UserProfileTarget (one user) --------------------

function Remove-UserProfileTarget {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Row, [switch]$RemoveAccount, [string]$Root, [string]$Progress)

    $res = [pscustomobject]@{
        Account = $Row.Account; SID = $Row.SID; Path = $Row.Path
        Profile = '-'; Folder = '-'; LocalAccount = '-'; Status = ''
    }
    # Progress lines go to the host (console or RMM log); results are still returned as objects.
    $label = if ($Row.Account) { $Row.Account } elseif ($Row.Path) { "? $(Split-Path $Row.Path -Leaf)" } else { $Row.SID }
    $say = { param($Text, $Color = 'Gray') Write-Host "      $Text" -ForegroundColor $Color }
    Write-Host ''
    Write-Host "$Progress$label" -ForegroundColor Cyan
    & $say "SID:  $($Row.SID)" DarkGray
    if ($Row.Path) { & $say "Path: $($Row.Path)" DarkGray }

    if ($Row.Protected) { $res.Status = "Skipped ($($Row.Protected))"; & $say $res.Status Yellow; return $res }
    $failed = $false; $partial = $false

    if ($Row.Kind -eq 'Profile') {
        # Fresh state: the user may have logged on since the inventory was taken.
        $cim = Get-CimInstance Win32_UserProfile -Filter "SID='$($Row.SID)'" -ErrorAction SilentlyContinue
        if (-not $cim) {
            $res.Profile = 'No profile record'
            & $say 'Profile: no profile record in Windows - nothing to delete' Yellow
        }
        elseif ($cim.Loaded) {
            $res.Status = 'Skipped (profile loaded - user logged on or in use)'; & $say $res.Status Yellow; return $res
        }
        elseif ($PSCmdlet.ShouldProcess("$($Row.Account) $($Row.Path)", 'Delete profile (registration + folder)')) {
            & $say 'Profile: deleting registry entry and folder (large profiles can take minutes)...'
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try {
                $cim | Remove-CimInstance -ErrorAction Stop
                $res.Profile = 'Removed'
                & $say ('Profile: removed ({0:N1}s)' -f $sw.Elapsed.TotalSeconds) Green
            }
            catch {
                # Nothing else is touched: a folder deleted without its registration gives the user a TEMP profile.
                $res.Profile = "FAILED: $($_.Exception.Message)"
                $res.Status = 'Failed'
                & $say "Profile: FAILED - $($_.Exception.Message)" Red
                & $say 'Nothing else changed for this user.' Red
                return $res
            }
            if ($Row.Path -and (Test-Path -LiteralPath $Row.Path)) {
                & $say 'Folder: still present (locked files?), removing leftover...'
                if (-not (Test-UPSafeFolder $Row.Path $Root)) { $res.Folder = 'Leftover kept (outside the profiles folder)'; $partial = $true }
                elseif (Remove-UPFolder $Row.Path) { $res.Folder = 'Leftover removed' }
                else { $res.Folder = 'Leftover remains (files in use? reboot and run Cleanup)'; $partial = $true }
                & $say "Folder: $($res.Folder)" $(if ($partial) { 'Yellow' } else { 'Green' })
            }
        }
        else { $res.Profile = 'WhatIf' }
    }

    if (($RemoveAccount -or $Row.Kind -eq 'AccountOnly') -and $Row.HasAccount) {
        if ($PSCmdlet.ShouldProcess($Row.Account, 'Remove local account')) {
            try { Remove-LocalUser -SID $Row.SID -ErrorAction Stop; $res.LocalAccount = 'Removed'; & $say 'Local account: removed' Green }
            catch { $res.LocalAccount = "FAILED: $($_.Exception.Message)"; $failed = $true; & $say "Local account: FAILED - $($_.Exception.Message)" Red }
        }
        else { $res.LocalAccount = 'WhatIf' }
    }
    elseif ($Row.HasAccount) { & $say 'Local account: kept (RemoveAccount not set)' DarkGray }

    $res.Status = if ($failed) { 'Failed' } elseif ($partial) { 'Partial' } elseif ($WhatIfPreference) { 'WhatIf' } else { 'Removed' }
    & $say "Result: $($res.Status)" $(switch ($res.Status) { 'Removed' { 'Green' } 'WhatIf' { 'Gray' } default { 'Yellow' } })
    return $res
}

#endregion

#region -------------------- Invoke-UserProfileCleanup (broken state) --------------------

function Invoke-UserProfileCleanup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Rows, [switch]$RemoveOrphanFolders, [string]$Root, [string]$BackupDir)

    foreach ($r in $Rows) {
        if ($r.Protected -or $r.Loaded) { continue }
        $res = [pscustomobject]@{ Account = $r.Account; SID = $r.SID; Path = $r.Path; Issue = ''; Action = ''; Status = '' }

        if ($r.Kind -eq 'Profile' -and -not $r.PathExists) {
            # Registration without a folder: nothing to lose, and it causes TEMP logons.
            $res.Issue = if ($r.IsBak) { '.bak key, folder gone' } else { 'Registered, folder gone' }
            if ($PSCmdlet.ShouldProcess($r.RegKey, 'Remove profile registration (folder is gone)')) {
                if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
                $regPath = $r.RegKey -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
                & reg.exe export $regPath (Join-Path $BackupDir "ProfileList_$((Split-Path $r.RegKey -Leaf) -replace '[^\w.-]', '_').reg") /y 2>&1 | Out-Null
                try {
                    $cim = if (-not $r.IsBak) { Get-CimInstance Win32_UserProfile -Filter "SID='$($r.SID)'" -EA SilentlyContinue }
                    if ($cim) { $cim | Remove-CimInstance -ErrorAction Stop } else { Remove-Item -LiteralPath $r.RegKey -Recurse -Force -ErrorAction Stop }
                    $res.Action = 'Registration removed (.reg backup)'; $res.Status = 'Fixed'
                }
                catch { $res.Action = "FAILED: $($_.Exception.Message)"; $res.Status = 'Failed' }
            }
            else { $res.Action = 'WhatIf'; $res.Status = 'WhatIf' }
        }
        elseif ($r.Kind -eq 'Profile' -and $r.IsBak) {
            $res.Issue = '.bak key, folder exists'; $res.Action = 'Not changed - fix by hand (see NOTES)'; $res.Status = 'Manual'
        }
        elseif ($r.Kind -eq 'OrphanFolder' -and ($r.IsTemp -or $RemoveOrphanFolders)) {
            $res.Issue = if ($r.IsTemp) { 'Unregistered TEMP folder' } else { 'Unregistered folder' }
            if (-not (Test-UPSafeFolder $r.Path $Root)) { $res.Action = 'Kept (outside the profiles folder)'; $res.Status = 'Skipped' }
            elseif ($PSCmdlet.ShouldProcess($r.Path, 'Delete unregistered folder')) {
                if (Remove-UPFolder $r.Path) { $res.Action = 'Folder removed'; $res.Status = 'Fixed' }
                else { $res.Action = 'Folder remains (files in use?)'; $res.Status = 'Failed' }
            }
            else { $res.Action = 'WhatIf'; $res.Status = 'WhatIf' }
        }
        else { continue }
        $res
    }
}

#endregion

#region -------------------- Interactive menu (from Removeuser-sonetv3.ps1) --------------------

function Get-TruncatedString {
    param([string]$Text, [int]$MaxLength)
    if ($Text.Length -le $MaxLength) { return $Text }
    if ($MaxLength -le 1) { return $Text.Substring(0, $MaxLength) }
    return $Text.Substring(0, $MaxLength - 1) + '~'
}

function Show-UPSelectionList {
    param($Users, [int]$CurrentIndex, [System.Collections.Generic.HashSet[string]]$SelectedKeys)

    Clear-Host
    Write-Host '==============================================================' -ForegroundColor Cyan
    Write-Host '         USER PROFILE REMOVAL  -  INTERACTIVE MODE' -ForegroundColor Cyan
    Write-Host '==============================================================' -ForegroundColor Cyan
    Write-Host '  Up/Down Navigate  |  SPACE Select  |  ENTER Confirm  |  Q Quit' -ForegroundColor Cyan
    Write-Host '==============================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('  {0} {1} {2} {3} {4}' -f ' ', 'SEL', 'USER'.PadRight(44), 'STATUS'.PadRight(20), 'LAST USE') -ForegroundColor DarkGray

    for ($i = 0; $i -lt $Users.Count; $i++) {
        $item = $Users[$i]
        $isSelected = $SelectedKeys.Contains($item.SID)
        $isCurrent = $i -eq $CurrentIndex
        $checkbox = if ($isSelected) { '[X]' } else { '[ ]' }
        $prefix = if ($isCurrent) { '>' } else { ' ' }
        # Unresolved SIDs all share the machine/domain prefix, so show the folder name instead.
        $name = if ($item.Account) { $item.Account } elseif ($item.Path) { "? $(Split-Path $item.Path -Leaf)" } else { $item.SID }
        $label = Get-TruncatedString -Text $name -MaxLength 44
        $status = Get-TruncatedString -Text $(Get-UPFlags $item) -MaxLength 20
        $lastUse = if ($item.Loaded) { 'in use' } elseif ($item.LastUsed) { $item.LastUsed.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
        $line = '{0} {1} {2} {3} {4}' -f $prefix, $checkbox, $label.PadRight(44), $status.PadRight(20), $lastUse

        if ($item.Loaded) { if ($isCurrent) { Write-Host $line -ForegroundColor Black -BackgroundColor DarkGray } else { Write-Host $line -ForegroundColor DarkGray } }
        elseif ($isCurrent -and $isSelected) { Write-Host $line -ForegroundColor Black -BackgroundColor Green }
        elseif ($isCurrent) { Write-Host $line -ForegroundColor Black -BackgroundColor White }
        elseif ($isSelected) { Write-Host $line -ForegroundColor Green }
        elseif ($item.IsTemp) { Write-Host $line -ForegroundColor DarkYellow }
        else { Write-Host $line }
    }

    Write-Host ''
    Write-Host "Selected: $($SelectedKeys.Count) user(s)" -ForegroundColor Magenta
    Write-Host 'ACC = local account (also removed)  |  LOADED = in use, cannot be removed  |  NoProfile = account only' -ForegroundColor DarkGray
    Write-Host '? = account name not resolvable (deleted, or domain unreachable) - shown by profile folder' -ForegroundColor DarkGray
}

function Confirm-UPDeletion {
    param($SelectedItems)
    Clear-Host
    Write-Host '==============================================================' -ForegroundColor Yellow
    Write-Host '                      REVIEW SELECTION' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor Yellow
    Write-Host ''
    foreach ($item in $SelectedItems) {
        Write-Host "  * $(if ($item.Account) { $item.Account } else { '(unresolved account)' })" -ForegroundColor Cyan
        if ($item.Path) { Write-Host "    Path: $($item.Path)" -ForegroundColor DarkGray }
        Write-Host "    SID:  $($item.SID)" -ForegroundColor DarkGray
        if ($item.LastUsed) { Write-Host "    Last: $($item.LastUsed)" -ForegroundColor DarkGray }
        Write-Host "    Profile: $($item.Kind -eq 'Profile') | Local account: $($item.HasAccount)" -ForegroundColor DarkGray
    }
    Write-Host ''
    if ((Read-Host 'Proceed with deletion? (Y/N)') -ne 'Y') { return $false }
    Write-Host ''
    return ((Read-Host "Type 'DELETE' to confirm") -ceq 'DELETE')
}

function Invoke-UPInteractive {
    param($Rows, [string]$Root)

    $allUsers = @($Rows | Where-Object { $_.Kind -in 'Profile', 'AccountOnly' -and -not $_.IsBak -and -not $_.Protected -and $_.Type -ne 'System' } |
        Sort-Object Loaded, @{ e = { $_.IsTemp }; Descending = $true }, @{ e = { $_.LastUsed }; Descending = $false }, Account)
    if (-not $allUsers) { Write-Host 'No users available to remove.' -ForegroundColor Yellow; return @() }

    $selectedIndex = 0
    $selectedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($true) {
        Show-UPSelectionList -Users $allUsers -CurrentIndex $selectedIndex -SelectedKeys $selectedKeys
        $keyInfo = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        switch ($keyInfo.VirtualKeyCode) {
            38 { if ($selectedIndex -gt 0) { $selectedIndex-- } }
            40 { if ($selectedIndex -lt ($allUsers.Count - 1)) { $selectedIndex++ } }
            32 {
                $item = $allUsers[$selectedIndex]
                if ($item.Loaded) {
                    try { [Console]::Beep(800, 120) } catch { }
                    Write-Host "`nThis profile is loaded (in use) and cannot be selected." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 700
                }
                elseif (-not $selectedKeys.Remove($item.SID)) { [void]$selectedKeys.Add($item.SID) }
            }
            13 {
                if ($selectedKeys.Count -eq 0) { break }
                $selected = @($allUsers | Where-Object { $selectedKeys.Contains($_.SID) })
                if (-not (Confirm-UPDeletion -SelectedItems $selected)) { Write-Host 'Cancelled.' -ForegroundColor Yellow; Start-Sleep -Seconds 1; break }
                Clear-Host
                Write-Host "Removing $($selected.Count) user(s)..." -ForegroundColor Red
                $i = 0
                return @(foreach ($t in $selected) { $i++; Remove-UserProfileTarget -Row $t -RemoveAccount -Root $Root -Progress "[$i/$($selected.Count)] " -Confirm:$false })
            }
            81 { Clear-Host; return @() }
        }
    }
}

#endregion

#region -------------------- Invoke-UserRemoval (dispatcher, returns the exit code) --------------------

function Invoke-UserRemoval {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Check', 'Remove', 'Cleanup', 'Interactive')]
        [string]$Mode = 'Check',
        [hashtable]$Options = @{}
    )

    try {
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            Write-Host 'ERROR: run this in 64-bit PowerShell (Get-LocalUser is missing in 32-bit). Nothing changed.' -ForegroundColor Red
            return 1
        }
        $admin = Test-IsAdmin
        if ($Mode -ne 'Check' -and -not $admin) {
            Write-Host "ERROR: -Mode $Mode needs an elevated or SYSTEM session. Nothing changed." -ForegroundColor Red
            return 10
        }

        $known = 'Users', 'InactiveDays', 'IncludeNeverUsed', 'RemoveAccount', 'Exclude', 'RemoveOrphanFolders'
        $bad = @($Options.Keys | Where-Object { $_ -notin $known })
        if ($bad) { throw "Unknown option(s): $($bad -join ', '). Valid: $($known -join ', ')." }

        $exclude = if ($Options.ContainsKey('Exclude')) { @($Options.Exclude) } else { @('defaultuser0') }
        $users = @($Options.Users | Where-Object { $_ })
        $days = [int]$Options.InactiveDays
        $root = Get-UPProfilesRoot
        $runDir = Join-Path $env:ProgramData "UserRemoval\$(Get-Date -Format yyyyMMdd-HHmmss)"
        $rows = @(Get-UserProfileInventory -Exclude $exclude)

        switch ($Mode) {
            'Check' {
                Show-UserProfileInventory $rows
                if (-not $admin) { Write-Host 'NOT ELEVATED: loaded state and some folders may be incomplete; rerun elevated.' -ForegroundColor Yellow }
                $broken = @(Get-UPBrokenRows $rows)
                $orphans = @($rows | Where-Object { $_.Kind -eq 'OrphanFolder' -and -not $_.IsTemp })
                if ($broken) { Write-Host "Broken state: $($broken.Count) (Cleanup fixes registrations without a folder and TEMP folders)" -ForegroundColor Yellow }
                if ($orphans) { Write-Host "Unregistered folders: $($orphans.Count) (may hold old user data; Cleanup removes them only with RemoveOrphanFolders)" }
                $targets = @()
                if ($users -or $days) {
                    $targets = @(Resolve-UserTarget -Rows $rows -Users $users -InactiveDays $days -IncludeNeverUsed:([bool]$Options.IncludeNeverUsed))
                    Write-Host "Targets: $($targets.Count)$(if ($targets) { ' -> ' + (($targets | ForEach-Object { if ($_.Account) { $_.Account } elseif ($_.Path) { "? $(Split-Path $_.Path -Leaf)" } else { $_.SID } }) -join ', ') })" -ForegroundColor $(if ($targets) { 'Yellow' } else { 'Gray' })
                }
                if ($broken -or $targets) { return 2 }
                Write-Host 'Nothing to report.'
                return 0
            }
            'Remove' {
                if (-not $users -and -not $days) { throw "Remove needs -Options @{ Users = ... } or @{ InactiveDays = N }." }
                $targets = @(Resolve-UserTarget -Rows $rows -Users $users -InactiveDays $days -IncludeNeverUsed:([bool]$Options.IncludeNeverUsed))
                if (-not $targets) { Write-Host 'Nothing to remove.'; return 0 }
                # Leavers named explicitly lose their local account too; age-based cleanup keeps accounts unless asked.
                $removeAccount = if ($Options.ContainsKey('RemoveAccount')) { [bool]$Options.RemoveAccount } else { [bool]$users }
                Write-Host "Removing $($targets.Count) user(s)$(if ($WhatIfPreference) { ' (WhatIf - nothing changes)' })..." -ForegroundColor $(if ($WhatIfPreference) { 'Gray' } else { 'Red' })
                $i = 0
                $results = @(foreach ($t in $targets) { $i++; Remove-UserProfileTarget -Row $t -RemoveAccount:$removeAccount -Root $root -Progress "[$i/$($targets.Count)] " -Confirm:$false -WhatIf:$WhatIfPreference })
            }
            'Cleanup' {
                $results = @(Invoke-UserProfileCleanup -Rows $rows -RemoveOrphanFolders:([bool]$Options.RemoveOrphanFolders) -Root $root -BackupDir $runDir -Confirm:$false -WhatIf:$WhatIfPreference)
                if (-not $results) { Write-Host 'Nothing to clean up.'; return 0 }
            }
            'Interactive' {
                try { [void]$Host.UI.RawUI.KeyAvailable } catch { Write-Host 'ERROR: Interactive needs a real console (not an RMM shell). Use -Mode Remove. Nothing changed.' -ForegroundColor Red; return 1 }
                $results = @(Invoke-UPInteractive -Rows $rows -Root $root)
                if (-not $results) { return 0 }
            }
        }

        Write-Host ''
        Write-Host "Summary: $(($results | Group-Object Status | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')" -ForegroundColor Cyan
        $results | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Out-Host
        if ($WhatIfPreference) { return 0 }
        if (-not (Test-Path $runDir)) { New-Item -ItemType Directory -Path $runDir -Force | Out-Null }
        $results | Export-Csv (Join-Path $runDir "$Mode-results.csv") -NoTypeInformation
        Write-Host "Results: $runDir"
        if ($results | Where-Object { $_.Status -in 'Failed', 'Partial', 'Manual' }) { return 1 }
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

$exitCode = Invoke-UserRemoval                                                           # Check (read-only)
# $exitCode = Invoke-UserRemoval -Options @{ InactiveDays = 90 }                         # Check: who hasn't logged on for 90 days (read-only)
# $exitCode = Invoke-UserRemoval -Mode Remove -Options @{ Users = '<DOMAIN\user>' } -WhatIf   # Preview a leaver removal
# $exitCode = Invoke-UserRemoval -Mode Remove -Options @{ Users = '<DOMAIN\user>' }      # DESTRUCTIVE: profile + local account (if any)
# $exitCode = Invoke-UserRemoval -Mode Remove -Options @{ InactiveDays = 90 } -WhatIf    # Preview stale-profile cleanup
# $exitCode = Invoke-UserRemoval -Mode Remove -Options @{ InactiveDays = 90 }            # DESTRUCTIVE: profiles unused 90+ days (accounts kept)
# $exitCode = Invoke-UserRemoval -Mode Cleanup -WhatIf                                   # Preview broken-profile fixes
# $exitCode = Invoke-UserRemoval -Mode Cleanup                                           # Fix registrations without a folder, TEMP folders
# $exitCode = Invoke-UserRemoval -Mode Interactive                                       # Console menu (not for RMM components)

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion