# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    Microsoft Visual C++ Redistributable end-of-life toolkit - Check / Recon / Install / Remove.
    Paste-and-run.

.DESCRIPTION
    One script, four modes, chosen in the ENTRY POINT at the bottom:

      Check    DEFAULT. Lists every VC++ runtime registered in Add/Remove Programs (HKLM both
               registry views + loaded user hives) and flags what Remove would target:
                 EOL       2005 / 2008 / 2010 / 2012 / 2013 runtime (always removed by Remove)
                 Older14x  2015-2022+ (14.x) copy older than the newest one for its arch
                 Keep      newest 14.x per arch (x86 / x64 / arm64)
                 Review    VC++ entry with an unparseable version (never auto-removed)
               Registry reads only, no admin needed, no logs written.
      Recon    Which installed applications depend on which VC++ runtime: DLLs loaded by running
               processes, private runtime DLLs beside the app, runtime DLL names inside the app's
               EXE/DLL files. High / Medium / Low confidence per app; LegacyDependentApps lists
               the apps that still need a 2005-2013 runtime. Read-only, can be slow (use MaxApps).
      Install  Downloads the latest 14.x redistributable from Microsoft (aka.ms/vc14, signature
               checked, winget fallback) and installs / upgrades it silently per arch
               (default x64 + x86 on 64-bit Windows, arm64 + x86 on ARM64, x86 on 32-bit).
               Removes nothing. LIVE unless WhatIf.
      Remove   Keeps only the newest 14.x per arch and uninstalls everything else: all 2005-2013
               runtimes plus older / duplicate 14.x (Burn bundles and hidden Minimum/Additional
               Runtime MSIs). Installs the latest 14.x first for any arch that has none, skips
               removals for an arch that still has no current runtime (Force overrides), retries
               msiexec 1618, then deletes orphaned VC++ folders under ProgramData\Package Cache
               only. Logs + summary.csv: C:\ProgramData\VCppCleanup. LIVE unless WhatIf.

    Run Check and Recon first: 14.x does NOT replace msvcr120.dll & co., so removing 2005-2013
    breaks apps that still need them.

.EXAMPLE
    Paste the WHOLE script into an elevated console or an RMM component, after editing the
    ENTRY POINT at the bottom. Mode-specific options go in -Options as a hashtable (they are the
    parameters of the underlying function):

    Invoke-VCRedistEOL                                                  # Check
    Invoke-VCRedistEOL -Mode Recon -Options @{ MaxApps = 50; ShowAllApps = $true }
    Invoke-VCRedistEOL -Mode Install -Options @{ WhatIf = $true }       # preview
    Invoke-VCRedistEOL -Mode Install -Options @{ InstallArch = 'x64', 'x86' }
    Invoke-VCRedistEOL -Mode Remove -Options @{ WhatIf = $true }        # preview
    Invoke-VCRedistEOL -Mode Remove                                     # LIVE
    Invoke-VCRedistEOL -Mode Remove -Options @{ NoInstall = $true; Force = $true }

    After a paste the functions stay loaded: Test-VCRedistEOL, Invoke-ScanVCRedistUsageV2
    (AsJson for JSON), Remove-EOLOldVC (InstallOnly for the Install mode).

.NOTES
    Exit codes (Invoke-VCRedistEOL returns one; the entry point exits with it only when $RMM = $true):
        0     OK / nothing to do / preview or recon complete
        1     Unexpected error, or Install/Remove: one or more operations failed
        2     Check: EOL (2005-2013) or older/duplicate 14.x runtime found
        3010  Install/Remove: success, reboot required
        10    Install/Remove (also their WhatIf preview) need an elevated or SYSTEM session
    Remove-EOLOldVC called directly returns 5 instead of 10 when not elevated.
#>

#region -------------------- Shared: VC++ registry inventory (read-only) --------------------

# Used by Check and by Remove-EOLOldVC. Registry-only on purpose: Win32_Product triggers an MSI
# reconfigure of every product. Explicit RegistryView so a 32-bit host still sees 64-bit entries.

function ConvertTo-VcVersion {
    # Parse DisplayVersion (or fall back to the "- NN.N..." suffix in DisplayName) into a
    # [version] normalised to 4 components (missing parts -> 0) so -eq / Sort are reliable.
    param([string]$DisplayVersion, [string]$DisplayName)
    $token = $null
    if (-not [string]::IsNullOrWhiteSpace($DisplayVersion)) {
        $m = [regex]::Match($DisplayVersion, '^\s*(\d+(?:\.\d+){0,3})')
        if ($m.Success) { $token = $m.Groups[1].Value }
    }
    if (-not $token -and $DisplayName) {
        $m2 = [regex]::Match($DisplayName, '-\s*(\d+(?:\.\d+){1,3})')
        if ($m2.Success) { $token = $m2.Groups[1].Value }
    }
    if (-not $token) { return $null }
    if ($token -notmatch '\.') { $token = "$token.0" }   # [version] needs >= 2 parts
    $v = $null
    if (-not [version]::TryParse($token, [ref]$v)) { return $null }
    $mnr = if ($v.Minor    -lt 0) { 0 } else { $v.Minor }
    $bld = if ($v.Build    -lt 0) { 0 } else { $v.Build }
    $rev = if ($v.Revision -lt 0) { 0 } else { $v.Revision }
    return (New-Object System.Version($v.Major, $mnr, $bld, $rev))
}

function Get-VcClass {
    # 8/9/10/11/12 = 2005/2008/2010/2012/2013 (legacy); >=14 = 2015-2022+ unified (keep line).
    # If the version can't be parsed, fall back to the legacy YEAR in the name so an EOL
    # 2005-2013 redist with a blank/garbage DisplayVersion is still purged. A missing version
    # is never classified 'Unified' from the name alone - without a version we cannot prove it
    # is the newest, so it is left as 'Unknown' (surfaced for review, never auto-removed).
    param([version]$Version, [string]$Name)
    if ($null -ne $Version) {
        if ($Version.Major -ge 14) { return 'Unified' }
        if ($Version.Major -ge 8 -and $Version.Major -le 12) { return 'Legacy' }
    }
    if ($Name -match '(?i)\b(2005|2008|2010|2012|2013)\b') { return 'Legacy' }
    return 'Unknown'
}

function Get-VcArch {
    # Architecture from the DisplayName token (authoritative); token-less names are the
    # old 2005/2008 x86 bundles -> default x86.
    param([string]$Name)
    if ($Name -match '(?i)\barm64\b')                    { return 'arm64' }
    if ($Name -match '(?i)(\(x64\)|\bx64\b|\bamd64\b)')  { return 'x64'  }
    if ($Name -match '(?i)(\(x86\)|\bx86\b)')            { return 'x86'  }
    return 'x86'
}

function Read-UninstallEntries {
    # Enumerate one already-open Uninstall RegistryKey and yield VC++ redist entries.
    param([Microsoft.Win32.RegistryKey]$UninstallKey, [string]$Scope)
    if ($null -eq $UninstallKey) { return }
    $reMatch  = '^Microsoft Visual C\+\+ .*(Redistributable|Runtime)'
    $reIgnore = 'Debug Runtime'
    foreach ($sub in $UninstallKey.GetSubKeyNames()) {
        $k = $null
        try { $k = $UninstallKey.OpenSubKey($sub) } catch { continue }
        if ($null -eq $k) { continue }
        try {
            $dn = [string]$k.GetValue('DisplayName')
            if ([string]::IsNullOrWhiteSpace($dn)) { continue }
            if ($dn -notmatch $reMatch) { continue }
            if ($dn -match  $reIgnore)  { continue }

            $ver = [string]$k.GetValue('DisplayVersion')
            $bcp = [string]$k.GetValue('BundleCachePath')
            $wi  = 0; try { $wi = [int]$k.GetValue('WindowsInstaller', 0) } catch {}
            $sc  = 0; try { $sc = [int]$k.GetValue('SystemComponent', 0) } catch {}
            if     ($bcp)     { $kind = 'Bundle' }
            elseif ($wi -eq 1){ $kind = 'MSI' }
            else              { $kind = 'Other' }

            $vObj = ConvertTo-VcVersion -DisplayVersion $ver -DisplayName $dn

            [pscustomobject]@{
                Scope                = $Scope
                KeyName              = $sub
                DisplayName          = $dn
                DisplayVersion       = $ver
                Version              = $vObj
                Class                = (Get-VcClass $vObj $dn)
                Arch                 = (Get-VcArch $dn)
                Kind                 = $kind
                SystemComponent      = $sc
                BundleCachePath      = $bcp
                QuietUninstallString = [string]$k.GetValue('QuietUninstallString')
                UninstallString      = [string]$k.GetValue('UninstallString')
            }
        }
        finally { $k.Close() }
    }
}

function Get-VcInventory {
    # HKLM (both views, bitness-proof) + loaded HKU hives. All actionable.
    $subPath    = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $subPathWow = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $uk = $base.OpenSubKey($subPath)   # view handles Wow6432 redirection
            try { Read-UninstallEntries -UninstallKey $uk -Scope "HKLM/$view" } finally { if ($uk) { $uk.Close() } }
        } finally { $base.Close() }
    }

    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
    try {
        $sids = $users.GetSubKeyNames() | Where-Object { $_ -notlike '*_Classes' -and $_ -ne '.DEFAULT' }
        foreach ($sid in $sids) {
            foreach ($p in @($subPath, $subPathWow)) {
                $uk = $users.OpenSubKey("$sid\$p")
                try { Read-UninstallEntries -UninstallKey $uk -Scope "HKU/$sid" } finally { if ($uk) { $uk.Close() } }
            }
        }
    } finally { $users.Close() }
}

function Get-VCRuntimeVersion {
    # Authoritative "is a 14.x runtime installed" check via the VC Runtimes registry key.
    param([ValidateSet('x64', 'x86', 'arm64')][string]$Arch)
    $view = if ($Arch -eq 'x86') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    $sub  = "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch"
    $base = $null; $k = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $k = $base.OpenSubKey($sub)
        if (-not $k) { return $null }
        $installed = 0; try { $installed = [int]$k.GetValue('Installed', 0) } catch {}
        if ($installed -ne 1) { return $null }
        return [string]$k.GetValue('Version')
    } catch { return $null }
    finally { if ($k) { $k.Close() }; if ($base) { $base.Close() } }
}

function Get-KeepMap {
    # A single 14.x install is 3 registry entries: the Burn BUNDLE plus two hidden child
    # MSIs (Minimum/Additional Runtime). Anchor the keeper on the newest BUNDLE per arch
    # (the bundle owns/ref-counts its children). Fall back to the newest of all Unified
    # entries only when no bundle is registered (orphaned child MSIs) so a runtime is still
    # kept. Returns arch -> [version] of the anchor.
    param($Inventory)
    $map = @{}
    $Inventory | Where-Object { $_.Class -eq 'Unified' -and $_.Version } |
        Group-Object Arch | ForEach-Object {
            $bundles = @($_.Group | Where-Object { $_.Kind -eq 'Bundle' })
            $anchor  = if ($bundles.Count -gt 0) { $bundles } else { $_.Group }
            $map[$_.Name] = ($anchor | Sort-Object Version -Descending | Select-Object -First 1).Version
        }
    return $map
}
function Test-IsKept {
    param($Entry, $KeepMap)
    if ($Entry.Class -ne 'Unified' -or -not $Entry.Version) { return $false }
    if (-not $KeepMap.ContainsKey($Entry.Arch)) { return $false }
    $keep = $KeepMap[$Entry.Arch]
    # Keep the WHOLE current release together. Microsoft has shipped releases where the
    # bundle's DisplayVersion and its child MSIs' ProductVersion differ by build (e.g.
    # 14.40.33810 bundle vs 14.40.33816 runtime MSIs), so match on Major.Minor rather than
    # byte-exact version - this protects both directions of skew. Also keep anything newer.
    if ($Entry.Version.Major -eq $keep.Major -and $Entry.Version.Minor -eq $keep.Minor) { return $true }
    return ($Entry.Version -ge $keep)
}

#endregion

#region -------------------- Check: Test-VCRedistEOL (fast, read-only) --------------------

function Test-VCRedistEOL {
    # One row per VC++ ARP entry, classified with the same rules Remove-EOLOldVC uses to pick
    # its removal candidates (Legacy, or Unified that Test-IsKept rejects).
    [CmdletBinding()]
    param()

    $inv     = @(Get-VcInventory)
    $keepMap = Get-KeepMap $inv

    $runtimes = foreach ($a in 'x86', 'x64', 'arm64') {
        $rt = Get-VCRuntimeVersion -Arch $a
        '{0}={1}' -f $a, $(if ($rt) { $rt } else { 'none' })
    }
    Write-Host ("VC Runtimes key (current 14.x per arch): {0}" -f ($runtimes -join '  '))

    foreach ($e in $inv) {
        $status = if     ($e.Class -eq 'Legacy')     { 'EOL' }
                  elseif ($e.Class -eq 'Unknown')    { 'Review' }
                  elseif (Test-IsKept $e $keepMap)   { 'Keep' }
                  else                               { 'Older14x' }
        [pscustomobject]@{
            Status      = $status
            Arch        = $e.Arch
            Version     = $e.DisplayVersion
            Kind        = $e.Kind
            Scope       = $e.Scope
            DisplayName = $e.DisplayName
        }
    }
}

#endregion

#region -------------------- Recon: Invoke-ScanVCRedistUsageV2 (who uses which runtime, read-only) --------------------

function Invoke-ScanVCRedistUsageV2 {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxApps = 0,

        [Parameter()]
        [int] $MaxFilesPerApp = 250,

        [Parameter()]
        [int] $MaxBinaryScanMB = 16,

        [Parameter()]
        [switch] $IncludeSystemComponents,

        [Parameter()]
        [switch] $IncludeWindowsApps,

        [Parameter()]
        [switch] $ShowAllApps,

        [Parameter()]
        [switch] $AsJson
    )

    # Scoped here (the standalone script set these at script level) so they do not leak into the console.
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

function Get-VcRuntimeRuleTable {
    [CmdletBinding()]
    param()

    @(
        [PSCustomObject]@{ Pattern = "msvcr80.dll";      Release = "2005";   RuntimeFamily = "VC++ 2005";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcp80.dll";      Release = "2005";   RuntimeFamily = "VC++ 2005";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "mfc80.dll";        Release = "2005";   RuntimeFamily = "VC++ 2005";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcr90.dll";      Release = "2008";   RuntimeFamily = "VC++ 2008";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcp90.dll";      Release = "2008";   RuntimeFamily = "VC++ 2008";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "mfc90.dll";        Release = "2008";   RuntimeFamily = "VC++ 2008";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcr100.dll";     Release = "2010";   RuntimeFamily = "VC++ 2010";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcp100.dll";     Release = "2010";   RuntimeFamily = "VC++ 2010";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "mfc100.dll";       Release = "2010";   RuntimeFamily = "VC++ 2010";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcr110.dll";     Release = "2012";   RuntimeFamily = "VC++ 2012";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcp110.dll";     Release = "2012";   RuntimeFamily = "VC++ 2012";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "mfc110.dll";       Release = "2012";   RuntimeFamily = "VC++ 2012";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcr120.dll";     Release = "2013";   RuntimeFamily = "VC++ 2013";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "msvcp120.dll";     Release = "2013";   RuntimeFamily = "VC++ 2013";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "mfc120.dll";       Release = "2013";   RuntimeFamily = "VC++ 2013";  SupportState = "EndOfLife" }
        [PSCustomObject]@{ Pattern = "vcruntime140.dll"; Release = "14.x";   RuntimeFamily = "VC++ 14.x";  SupportState = "Supported" }
        [PSCustomObject]@{ Pattern = "vcruntime140_1.dll"; Release = "14.x"; RuntimeFamily = "VC++ 14.x";  SupportState = "Supported" }
        [PSCustomObject]@{ Pattern = "msvcp140.dll";     Release = "14.x";   RuntimeFamily = "VC++ 14.x";  SupportState = "Supported" }
        [PSCustomObject]@{ Pattern = "concrt140.dll";    Release = "14.x";   RuntimeFamily = "VC++ 14.x";  SupportState = "Supported" }
        [PSCustomObject]@{ Pattern = "mfc140.dll";       Release = "14.x";   RuntimeFamily = "VC++ 14.x";  SupportState = "Supported" }
    )
}

function New-OrdinalIgnoreCaseStringSet {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Items = @()
    )

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Items) {
        if (-not [string]::IsNullOrWhiteSpace($item)) {
            $null = $set.Add($item)
        }
    }

    return ,$set
}

function Get-InstalledSoftware {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $NameLike
    )

    $uninstallRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $hkuMounted = $false
    try {
        Write-Verbose "Enumerating installed software from uninstall registry keys."
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name HKU -PSProvider Registry -Root "Registry::HKEY_USERS" -ErrorAction Stop
            $hkuMounted = $true
        }

        $userRoots = Get-ChildItem -Path "HKU:" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "S-\d-\d+-(\d+-){1,14}\d+$" } |
            ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }

        $allRoots = $uninstallRoots + $userRoots

        foreach ($root in $allRoots) {
            foreach ($entry in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
                $displayName = $entry.GetValue("DisplayName")
                if ([string]::IsNullOrWhiteSpace($displayName)) {
                    continue
                }

                if ($PSBoundParameters.ContainsKey("NameLike") -and $displayName -notlike $NameLike) {
                    continue
                }

                [PSCustomObject]@{
                    Name                    = $displayName
                    Version                 = $entry.GetValue("DisplayVersion")
                    Publisher               = $entry.GetValue("Publisher")
                    InstallLocation         = $entry.GetValue("InstallLocation")
                    DisplayIcon             = $entry.GetValue("DisplayIcon")
                    UninstallString         = $entry.GetValue("UninstallString")
                    QuietUninstallString    = $entry.GetValue("QuietUninstallString")
                    InstallSource           = $entry.GetValue("InstallSource")
                    BundleCachePath         = $entry.GetValue("BundleCachePath")
                    WindowsInstaller        = $entry.GetValue("WindowsInstaller")
                    SystemComponent         = $entry.GetValue("SystemComponent")
                    ReleaseType             = $entry.GetValue("ReleaseType")
                    ParentKeyName           = $entry.GetValue("ParentKeyName")
                    NoRemove                = $entry.GetValue("NoRemove")
                    EstimatedSizeKB         = $entry.GetValue("EstimatedSize")
                    RegistryKey             = $entry.PSPath
                    ProductCode             = $entry.PSChildName
                }
            }
        }
    }
    finally {
        if ($hkuMounted) {
            Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue
        }
    }
}

function Get-InstalledVcRedist {
    [CmdletBinding()]
    param()

    Write-Verbose "Filtering installed software for Visual C++ Redistributable packages."
    Get-InstalledSoftware | Where-Object {
        $_.Name -match "Microsoft Visual C\+\+" -and $_.Name -match "Redistributable"
    } | ForEach-Object {
        $release = $null
        if ($_.Name -match "2015|2017|2019|2022|2026|(?i)\bv14\b|(?i)\b14\.\d+") {
            $release = "14.x"
        }
        elseif ($_.Name -match "\b(2005|2008|2010|2012|2013)\b") {
            $release = $Matches[1]
        }

        $architecture = "Unknown"
        if ($_.Name -match "(?i)\bx64\b") {
            $architecture = "x64"
        }
        elseif ($_.Name -match "(?i)\bx86\b") {
            $architecture = "x86"
        }
        elseif ($_.Name -match "(?i)\barm64\b") {
            $architecture = "ARM64"
        }

        [PSCustomObject]@{
            Name          = $_.Name
            Version       = $_.Version
            Release       = $release
            Architecture  = $architecture
            SupportState  = if ($release -eq "14.x") { "Supported" } elseif ($release) { "EndOfLife" } else { "Unknown" }
            RegistryKey   = $_.RegistryKey
        }
    }
}

function Test-IsExcludedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [switch] $IncludeWindowsApps
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $true
    }

    $normalized = ([string] $Path).Trim().ToLowerInvariant()
    $windowsDir = Convert-ToCandidateText -Value $env:WINDIR
    if (-not [string]::IsNullOrWhiteSpace($windowsDir) -and $normalized.StartsWith($windowsDir.Trim().ToLowerInvariant())) {
        return $true
    }

    if (-not $IncludeWindowsApps -and $normalized -like "*\windowsapps\*") {
        return $true
    }

    return $false
}

function Expand-CandidateValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [string] $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Value)
        if ([string]::IsNullOrWhiteSpace($expanded)) {
            return $null
        }

        return ($expanded -replace '[\r\n\t]+', ' ').Trim()
    }
    catch {
        return ($Value -replace '[\r\n\t]+', ' ').Trim()
    }
}

function Convert-ToCandidateText {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = foreach ($item in $Value) {
            if ($null -ne $item) {
                [string] $item
            }
        }

        return @($parts) -join "; "
    }

    return [string] $Value
}

function Get-CandidateValueVariants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Value
    )

    $rawText = Convert-ToCandidateText -Value $Value
    if ([string]::IsNullOrWhiteSpace($rawText)) {
        return @()
    }

    $expanded = Expand-CandidateValue -Value $rawText
    if ([string]::IsNullOrWhiteSpace($expanded)) {
        return @()
    }

    $variants = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null = $variants.Add($expanded)

    foreach ($match in ([regex]::Matches($expanded, '"([^"]+)"'))) {
        if ($match.Groups.Count -gt 1) {
            $null = $variants.Add($match.Groups[1].Value)
        }
    }

    foreach ($pattern in @(
        '(?i)([A-Z]:\\[^"<>|?*]+?\.(?:exe|dll|msi|bat|cmd|ico))',
        '(?i)([A-Z]:\\[^"<>|?*]+)',
        '(?i)(\\\\[^\\\/\s]+\\[^"<>|?*]+)'
    )) {
        foreach ($match in ([regex]::Matches($expanded, $pattern))) {
            if ($match.Groups.Count -gt 1) {
                $null = $variants.Add($match.Groups[1].Value)
            }
        }
    }

    foreach ($item in @($variants)) {
        if ($item -match '^([^,]+),-?\d+$') {
            $null = $variants.Add($Matches[1])
        }
    }

    @($variants | ForEach-Object {
        if ($null -ne $_) {
            $candidate = ([string] $_).Trim('"').Trim()
            $candidate = $candidate -replace '[\r\n\t]+', ' '
            $candidate = $candidate -replace '\s{2,}', ' '
            $candidate = $candidate.Trim()

            if ($candidate -match '^(.*?\.(?:exe|dll|msi|bat|cmd|ico))(?=\s|$)') {
                $candidate = $Matches[1]
            }
            elseif ($candidate -match '^([^,]+),-?\d+$') {
                $candidate = $Matches[1]
            }

            $candidate.Trim()
        }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Resolve-ExistingCandidatePath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string] $Candidate
    )

    $normalized = Convert-ToCandidateText -Value $Candidate
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $normalized = Expand-CandidateValue -Value $normalized
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $normalized = $normalized.Trim('"').Trim()
    $normalized = $normalized -replace '[\r\n\t]+', ' '
    $normalized = $normalized -replace '\s{2,}', ' '
    $normalized = $normalized.Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    foreach ($probe in @(
        $normalized,
        $normalized.TrimEnd('\', '/'),
        $normalized -replace '/', '\'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) {
        try {
            if (Test-Path -LiteralPath $probe) {
                return (Get-Item -LiteralPath $probe -ErrorAction Stop)
            }
        }
        catch {
        }
    }

    try {
        $parentPath = Split-Path -Path $normalized -Parent -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($parentPath) -and (Test-Path -LiteralPath $parentPath)) {
            return (Get-Item -LiteralPath $parentPath -ErrorAction Stop)
        }
    }
    catch {
    }

    return $null
}

function Get-SearchTokens {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $stopWords = New-OrdinalIgnoreCaseStringSet -Items @(
        "and", "for", "the", "with", "from", "client", "software", "service",
        "services", "app", "apps", "application", "enterprise", "classic",
        "update", "tool", "tools", "component", "components", "agent", "suite",
        "secure", "security", "bit", "x64", "x86", "64", "32", "microsoft"
    )

    $tokens = foreach ($token in ($Text -split '[^A-Za-z0-9]+')) {
        if ($token.Length -lt 3) {
            continue
        }

        if ($stopWords.Contains($token)) {
            continue
        }

        $token.ToLowerInvariant()
    }

    @($tokens | Select-Object -Unique)
}

function Get-FallbackInstallRootCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $App,

        [Parameter()]
        [switch] $IncludeWindowsApps
    )

    $fallbackCandidates = @()
    $fallbackDiagnostics = @()

    try {
        $appNameText = Convert-ToCandidateText -Value $App.Name
        $publisherText = Convert-ToCandidateText -Value $App.Publisher
        $searchTokens = @(
            @((Get-SearchTokens -Text $appNameText) + (Get-SearchTokens -Text $publisherText)) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
        )

        $commonRoots = @()
        foreach ($root in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
            if (-not [string]::IsNullOrWhiteSpace($root)) {
                $commonRoots += $root
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            try {
                $localProgramsRoot = Join-Path $env:LOCALAPPDATA "Programs"
                if (-not [string]::IsNullOrWhiteSpace($localProgramsRoot)) {
                    $commonRoots += $localProgramsRoot
                }
            }
            catch {
            }
        }

        $commonRoots = @($commonRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        if (-not $searchTokens) {
            $fallbackDiagnostics += "Fallback search skipped because no useful app-name or publisher tokens were available."
            return [PSCustomObject]@{
                CandidatePaths = @()
                Diagnostics    = @($fallbackDiagnostics)
            }
        }

        foreach ($root in $commonRoots) {
            try {
                if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) {
                    continue
                }

                $childDirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)
                foreach ($dir in $childDirs) {
                    $dirFullName = Convert-ToCandidateText -Value $dir.FullName
                    if ([string]::IsNullOrWhiteSpace($dirFullName)) {
                        continue
                    }
                    $dirName = Split-Path -Path $dirFullName -Leaf
                    if ([string]::IsNullOrWhiteSpace($dirName)) {
                        continue
                    }

                    $dirNameLower = $dirName.ToLowerInvariant()
                    $matchedTokens = @($searchTokens | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $dirNameLower -like "*$_*" })
                    if (-not $matchedTokens) {
                        continue
                    }

                    if (-not [string]::IsNullOrWhiteSpace($dirFullName) -and -not (Test-IsExcludedPath -Path $dirFullName -IncludeWindowsApps:$IncludeWindowsApps)) {
                        if ($dirFullName -notin $fallbackCandidates) {
                            $fallbackCandidates += $dirFullName
                            $fallbackDiagnostics += ("Fallback root match: '{0}' via token(s): {1}" -f $dirFullName, ($matchedTokens -join ", "))
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($dirFullName)) {
                        continue
                    }

                    foreach ($nestedDir in @(Get-ChildItem -LiteralPath $dirFullName -Directory -ErrorAction SilentlyContinue)) {
                        $nestedFullName = Convert-ToCandidateText -Value $nestedDir.FullName
                        if ([string]::IsNullOrWhiteSpace($nestedFullName)) {
                            continue
                        }
                        $nestedName = Split-Path -Path $nestedFullName -Leaf
                        if ([string]::IsNullOrWhiteSpace($nestedName)) {
                            continue
                        }

                        $nestedNameLower = $nestedName.ToLowerInvariant()
                        $nestedMatchedTokens = @($searchTokens | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $nestedNameLower -like "*$_*" })
                        if (-not $nestedMatchedTokens) {
                            continue
                        }

                        if (-not [string]::IsNullOrWhiteSpace($nestedFullName) -and -not (Test-IsExcludedPath -Path $nestedFullName -IncludeWindowsApps:$IncludeWindowsApps)) {
                            if ($nestedFullName -notin $fallbackCandidates) {
                                $fallbackCandidates += $nestedFullName
                                $fallbackDiagnostics += ("Fallback nested match: '{0}' via token(s): {1}" -f $nestedFullName, ($nestedMatchedTokens -join ", "))
                            }
                        }
                    }
                }
            }
            catch {
                $fallbackDiagnostics += ("Fallback root scan warning for '{0}': {1}" -f $root, $_.Exception.Message)
            }
        }

        if (@($fallbackCandidates).Count -eq 0) {
            $fallbackDiagnostics += ("Fallback search checked common roots but found no matching install folders for tokens: {0}" -f ($searchTokens -join ", "))
        }
    }
    catch {
        $fallbackDiagnostics += ("Fallback search failed safely: {0}" -f $_.Exception.Message)
    }

    [PSCustomObject]@{
        CandidatePaths = @($fallbackCandidates | Sort-Object -Unique)
        Diagnostics    = @($fallbackDiagnostics)
    }
}

function Resolve-AppPathCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $App,

        [Parameter()]
        [switch] $IncludeWindowsApps
    )

    $candidates = New-OrdinalIgnoreCaseStringSet
    $diagnostics = New-Object System.Collections.Generic.List[string]
    $fieldMap = [ordered]@{
        InstallLocation      = $App.InstallLocation
        DisplayIcon          = $App.DisplayIcon
        UninstallString      = $App.UninstallString
        QuietUninstallString = $App.QuietUninstallString
        InstallSource        = $App.InstallSource
        BundleCachePath      = $App.BundleCachePath
    }

    foreach ($field in $fieldMap.Keys) {
        $rawValue = $fieldMap[$field]
        $rawValueText = Convert-ToCandidateText -Value $rawValue
        if ([string]::IsNullOrWhiteSpace($rawValueText)) {
            $diagnostics.Add(("{0}: empty" -f $field))
            continue
        }

        $valueVariants = @(Get-CandidateValueVariants -Value $rawValue)
        if (-not $valueVariants) {
            $diagnostics.Add(("{0}: no path-like content in '{1}'" -f $field, $rawValueText))
            continue
        }

        $resolvedForField = 0
        foreach ($variant in $valueVariants) {
            try {
                $normalizedVariant = Convert-ToCandidateText -Value $variant
                if ([string]::IsNullOrWhiteSpace($normalizedVariant)) {
                    continue
                }

                $normalizedVariant = Expand-CandidateValue -Value $normalizedVariant
                if ([string]::IsNullOrWhiteSpace($normalizedVariant)) {
                    continue
                }

                $normalizedVariant = $normalizedVariant.Trim('"').Trim()
                if ([string]::IsNullOrWhiteSpace($normalizedVariant)) {
                    continue
                }

                Write-Verbose ("  Path check [{0}]: {1}" -f $field, $normalizedVariant)

                $item = Resolve-ExistingCandidatePath -Candidate $normalizedVariant
                if ($null -eq $item) {
                    continue
                }

                if ($item.PSIsContainer) {
                    $candidatePath = $item.FullName
                }
                else {
                    $candidatePath = $item.DirectoryName
                }

                if ([string]::IsNullOrWhiteSpace($candidatePath)) {
                    continue
                }

                if (Test-IsExcludedPath -Path $candidatePath -IncludeWindowsApps:$IncludeWindowsApps) {
                    $diagnostics.Add(("{0}: excluded path '{1}'" -f $field, $candidatePath))
                    continue
                }

                if ($candidates.Add($candidatePath)) {
                    $diagnostics.Add(("{0}: resolved '{1}'" -f $field, $candidatePath))
                }
                $resolvedForField++
            }
            catch {
            }
        }

        if ($resolvedForField -eq 0) {
            $diagnostics.Add(("{0}: no existing path resolved from '{1}'" -f $field, $rawValueText))
        }
    }

    if (@($candidates | ForEach-Object { $_ }).Count -eq 0) {
        $fallbackResolution = Get-FallbackInstallRootCandidates -App $App -IncludeWindowsApps:$IncludeWindowsApps
        foreach ($fallbackPath in @($fallbackResolution.CandidatePaths)) {
            $null = $candidates.Add($fallbackPath)
        }
        foreach ($note in @($fallbackResolution.Diagnostics)) {
            $diagnostics.Add($note)
        }
    }

    [PSCustomObject]@{
        CandidatePaths = @($candidates | Sort-Object)
        Diagnostics    = @($diagnostics)
    }
}

function Resolve-ExecutableCandidatePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Value
    )

    $cleanValue = $Value.Trim()

    if ($cleanValue -match '^"([^"]+)"') {
        $cleanValue = $Matches[1]
    }
    elseif ($cleanValue -match '^(.*?\.exe)\b') {
        $cleanValue = $Matches[1]
    }
    elseif ($cleanValue -match '^(.*?\.dll)\b') {
        $cleanValue = $Matches[1]
    }
    elseif ($cleanValue -match '^([^,]+),\d+$') {
        $cleanValue = $Matches[1]
    }

    return $cleanValue.Trim('"').Trim()
}

function Get-InterestingBinaryFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $RootPaths,

        [Parameter(Mandatory)]
        [int] $MaxFilesPerApp
    )

    $selectedFiles = New-Object System.Collections.Generic.List[object]
    $selectedPaths = New-OrdinalIgnoreCaseStringSet
    $interestingExtensions = New-OrdinalIgnoreCaseStringSet -Items @(".exe", ".dll")

    if ($MaxFilesPerApp -le 0) {
        return @()
    }

    foreach ($root in $RootPaths) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }

        Write-Verbose ("Scanning binaries under: {0}" -f $root)
        foreach ($file in (Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue)) {
            if (-not $interestingExtensions.Contains($file.Extension)) {
                continue
            }

            if ($selectedPaths.Contains($file.FullName)) {
                continue
            }

            if ($selectedFiles.Count -lt $MaxFilesPerApp) {
                $selectedFiles.Add($file)
                $null = $selectedPaths.Add($file.FullName)
                continue
            }

            $smallestIndex = 0
            $smallestLength = $selectedFiles[0].Length
            for ($i = 1; $i -lt $selectedFiles.Count; $i++) {
                if ($selectedFiles[$i].Length -lt $smallestLength) {
                    $smallestLength = $selectedFiles[$i].Length
                    $smallestIndex = $i
                }
            }

            if ($file.Length -le $smallestLength) {
                continue
            }

            $null = $selectedPaths.Remove($selectedFiles[$smallestIndex].FullName)
            $selectedFiles[$smallestIndex] = $file
            $null = $selectedPaths.Add($file.FullName)
        }
    }

    $selectedFiles | Sort-Object @{ Expression = "Length"; Descending = $true }, @{ Expression = "FullName"; Descending = $false }
}

function Find-PatternInBinary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string[]] $Patterns,

        [Parameter(Mandatory)]
        [int] $MaxBinaryScanMB
    )

    $maxBytes = $MaxBinaryScanMB * 1MB
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -gt $maxBytes) {
        return @()
    }

    $remainingPatterns = New-OrdinalIgnoreCaseStringSet -Items $Patterns
    if ($remainingPatterns.Count -eq 0) {
        return @()
    }

    $binaryMatches = New-Object System.Collections.Generic.List[string]
    $maxPatternLength = ($Patterns | Measure-Object -Maximum Length).Maximum
    if (-not $maxPatternLength) {
        return @()
    }

    $chunkSize = 1MB
    $buffer = New-Object byte[] ($chunkSize + $maxPatternLength)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $carryCount = 0

    try {
        while (($readCount = $stream.Read($buffer, $carryCount, $chunkSize)) -gt 0) {
            $totalBytes = $carryCount + $readCount
            $asciiText = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $totalBytes).ToLowerInvariant()

            foreach ($pattern in @($remainingPatterns)) {
                if ($asciiText.Contains($pattern.ToLowerInvariant())) {
                    $binaryMatches.Add($pattern)
                    $null = $remainingPatterns.Remove($pattern)
                }
            }

            if ($remainingPatterns.Count -eq 0) {
                break
            }

            $carryCount = [Math]::Min($maxPatternLength - 1, $totalBytes)
            if ($carryCount -gt 0) {
                [Array]::Copy($buffer, $totalBytes - $carryCount, $buffer, 0, $carryCount)
            }
        }
    }
    finally {
        $stream.Dispose()
    }

    $binaryMatches | Select-Object -Unique
}

function Get-RunningProcessVcMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $RuleTable
    )

    $patternNames = New-OrdinalIgnoreCaseStringSet -Items ($RuleTable.Pattern | ForEach-Object { $_.ToLowerInvariant() })

    Write-Verbose "Inspecting running processes for loaded VC++ runtime modules."
    foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) {
        $mainPath = $null
        try {
            $mainPath = $process.Path
        }
        catch {
        }

        if ([string]::IsNullOrWhiteSpace($mainPath)) {
            try {
                $mainPath = $process.MainModule.FileName
            }
            catch {
            }
        }

        if ([string]::IsNullOrWhiteSpace($mainPath) -or -not (Test-Path -LiteralPath $mainPath)) {
            continue
        }

        $moduleHits = New-Object System.Collections.Generic.List[string]
        try {
            foreach ($module in $process.Modules) {
                if ($null -eq $module -or [string]::IsNullOrWhiteSpace($module.ModuleName)) {
                    continue
                }

                $moduleName = $module.ModuleName.ToLowerInvariant()
                if ($patternNames.Contains($moduleName)) {
                    $moduleHits.Add($moduleName)
                }
            }
        }
        catch {
        }

        if ($moduleHits.Count -eq 0) {
            continue
        }

        $mainDirectory = Split-Path -Path $mainPath -Parent
        if ([string]::IsNullOrWhiteSpace($mainDirectory)) {
            continue
        }

        [PSCustomObject]@{
            ProcessName  = $process.ProcessName
            ProcessId    = $process.Id
            Path         = $mainPath
            Directory    = $mainDirectory
            ModuleHits   = $moduleHits | Select-Object -Unique
        }
    }
}

function Get-AppVcEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $App,

        [Parameter(Mandatory)]
        [object[]] $RuleTable,

        [Parameter(Mandatory)]
        [int] $MaxFilesPerApp,

        [Parameter(Mandatory)]
        [int] $MaxBinaryScanMB,

        [Parameter()]
        [object[]] $RunningProcessVcMap = @(),

        [Parameter()]
        [switch] $IncludeWindowsApps,

        [Parameter()]
        [hashtable] $RuleLookup = @{},

        [Parameter()]
        [System.Collections.IDictionary] $BinaryFileCache = @{},

        [Parameter()]
        [System.Collections.IDictionary] $BinaryHitCache = @{}
    )

    $pathResolution = Resolve-AppPathCandidates -App $App -IncludeWindowsApps:$IncludeWindowsApps
    $rootPaths = @()
    if ($null -ne $pathResolution) {
        $rootPaths = @($pathResolution.CandidatePaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if (-not $rootPaths) {
        Write-Verbose ("Skipping '{0}' because no candidate install paths were resolved." -f $App.Name)
        if ($null -ne $pathResolution) {
            foreach ($note in @($pathResolution.Diagnostics)) {
                Write-Verbose ("  Path resolution: {0}" -f $note)
            }
        }
        return $null
    }

    Write-Verbose ("Resolved {0} candidate path(s) for '{1}'." -f @($rootPaths).Count, $App.Name)
    foreach ($rootPath in $rootPaths) {
        Write-Verbose ("  Candidate path: {0}" -f $rootPath)
    }
    $rootPathKey = (@($rootPaths) | Sort-Object) -join "|"
    if ($BinaryFileCache.Contains($rootPathKey)) {
        $binaryFiles = @($BinaryFileCache[$rootPathKey])
        Write-Verbose ("Reusing cached binary list for '{0}'." -f $App.Name)
    }
    else {
        $binaryFiles = @(Get-InterestingBinaryFiles -RootPaths $rootPaths -MaxFilesPerApp $MaxFilesPerApp)
        $BinaryFileCache[$rootPathKey] = $binaryFiles
        Write-Verbose ("Selected {0} binary file(s) for '{1}'." -f @($binaryFiles).Count, $App.Name)
    }

    if (-not $binaryFiles) {
        Write-Verbose ("Skipping '{0}' because no EXE/DLL files were found in candidate paths." -f $App.Name)
        return $null
    }

    $patternNames = @($RuleTable.Pattern | ForEach-Object { $_.ToLowerInvariant() })
    $patternNameSet = New-OrdinalIgnoreCaseStringSet -Items $patternNames
    $privateRuntimeHits = New-Object System.Collections.Generic.List[string]
    $importHits = New-Object System.Collections.Generic.List[string]
    $processHits = New-Object System.Collections.Generic.List[string]
    $matchingProcesses = New-Object System.Collections.Generic.List[string]
    $inspectedFiles = 0

    foreach ($file in $binaryFiles) {
        $inspectedFiles++
        $fileName = $file.Name.ToLowerInvariant()

        if ($patternNameSet.Contains($fileName)) {
            $privateRuntimeHits.Add($fileName)
            continue
        }

        try {
            if ($BinaryHitCache.Contains($file.FullName)) {
                $hits = @($BinaryHitCache[$file.FullName])
            }
            else {
                $hits = @(Find-PatternInBinary -Path $file.FullName -Patterns $patternNames -MaxBinaryScanMB $MaxBinaryScanMB)
                $BinaryHitCache[$file.FullName] = $hits
            }

            foreach ($hit in $hits) {
                $importHits.Add($hit)
            }
        }
        catch {
        }
    }

    $allHits = @($privateRuntimeHits + $importHits) | Select-Object -Unique
    foreach ($process in $RunningProcessVcMap) {
        if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.Directory)) {
            continue
        }

        $isMatch = $false
        foreach ($rootPath in $rootPaths) {
            if ([string]::IsNullOrWhiteSpace($rootPath)) {
                continue
            }

            if ($process.Directory.StartsWith($rootPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                $rootPath.StartsWith($process.Directory, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isMatch = $true
                break
            }
        }

        if ($isMatch) {
            foreach ($moduleHit in $process.ModuleHits) {
                $processHits.Add($moduleHit)
            }
            $matchingProcesses.Add("$($process.ProcessName)[$($process.ProcessId)]")
        }
    }

    $allHits = @($allHits + $processHits) | Select-Object -Unique
    if (-not $allHits) {
        Write-Verbose ("No VC++ runtime evidence found for '{0}' after inspecting {1} file(s)." -f $App.Name, $inspectedFiles)
        return $null
    }

    $matchedRules = @(foreach ($hit in $allHits) {
        if ($RuleLookup.ContainsKey($hit)) {
            $RuleLookup[$hit]
        }
    })

    $legacyRules = @($matchedRules | Where-Object { $_.SupportState -eq "EndOfLife" })
    $confidence = if (@($processHits).Count -gt 0 -or @($privateRuntimeHits).Count -gt 0) { "High" } elseif (@($importHits).Count -gt 0) { "Medium" } else { "Low" }

    [PSCustomObject]@{
        AppName                = $App.Name
        AppVersion             = $App.Version
        Publisher              = $App.Publisher
        CandidatePaths         = $rootPaths
        FilesInspected         = $inspectedFiles
        PrivateRuntimeDlls     = $privateRuntimeHits | Select-Object -Unique
        ImportRuntimeDlls      = $importHits | Select-Object -Unique
        RunningProcessModules  = $processHits | Select-Object -Unique
        MatchingProcesses      = $matchingProcesses | Select-Object -Unique
        RuntimeFamilies        = $matchedRules.RuntimeFamily | Select-Object -Unique
        ReleaseGenerations     = $matchedRules.Release | Select-Object -Unique
        SupportStates          = $matchedRules.SupportState | Select-Object -Unique
        UsesLegacyRuntime      = (@($legacyRules).Count -gt 0)
        Confidence             = $confidence
        RegistryKey            = $App.RegistryKey
    }
}

function Get-AppInventory {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch] $IncludeSystemComponents
    )

    Write-Verbose "Building application inventory for VC++ usage scan."
    $apps = Get-InstalledSoftware | Where-Object {
        $_.Name -and
        $_.Name -notmatch "^Microsoft Visual C\+\+" -and
        $_.Name -notmatch "^Update for " -and
        $null -eq $_.ParentKeyName
    }

    if (-not $IncludeSystemComponents) {
        $apps = $apps | Where-Object { $_.SystemComponent -ne 1 }
    }

    $apps |
        Sort-Object Name -Unique |
        Where-Object { $_.Name -notmatch "driver|hotfix|security update|service pack" }
}

function New-VcUsageReport {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object[]] $AppEvidence = @(),

        [Parameter()]
        [object[]] $InstalledRuntimePackages = @()
    )

    Write-Verbose "Building VC++ usage report."
    $installedByRelease = @{}
    foreach ($group in ($InstalledRuntimePackages | Group-Object Release)) {
        $installedByRelease[$group.Name] = [PSCustomObject]@{
            Release = $group.Name
            Installed = $true
            Versions = ($group.Group.Version | Sort-Object -Unique)
            Packages = ($group.Group.Name | Sort-Object -Unique)
        }
    }

    $report = foreach ($item in $AppEvidence) {
        $legacyReleases = @($item.ReleaseGenerations | Where-Object { $_ -and $_ -ne "14.x" })
        $releasePresence = foreach ($release in $item.ReleaseGenerations) {
            $found = if ($installedByRelease.ContainsKey($release)) { $installedByRelease[$release] } else { $null }
            [PSCustomObject]@{
                Release = $release
                InstalledRedistributableDetected = [bool] $found
                InstalledVersions = if ($found) { $found.Versions } else { @() }
            }
        }

        [PSCustomObject]@{
            AppName                 = $item.AppName
            AppVersion              = $item.AppVersion
            Publisher               = $item.Publisher
            Confidence              = $item.Confidence
            UsesLegacyRuntime       = $item.UsesLegacyRuntime
            LegacyReleaseGenerations = $legacyReleases
            RuntimeFamilies         = $item.RuntimeFamilies
            CandidatePaths          = $item.CandidatePaths
            PrivateRuntimeDlls      = $item.PrivateRuntimeDlls
            ImportRuntimeDlls       = $item.ImportRuntimeDlls
            RunningProcessModules   = $item.RunningProcessModules
            MatchingProcesses       = $item.MatchingProcesses
            ReleasePresence         = $releasePresence
            FilesInspected          = $item.FilesInspected
            RegistryKey             = $item.RegistryKey
        }
    }

    [PSCustomObject]@{
        ComputerName             = $env:COMPUTERNAME
        ScanTimeUtc              = [DateTime]::UtcNow.ToString("s") + "Z"
        InstalledVcRedists       = $InstalledRuntimePackages | Sort-Object Release, Architecture, Version
        ApplicationsUsingVc      = $report | Sort-Object @{ Expression = "UsesLegacyRuntime"; Descending = $true }, Confidence, AppName
        LegacyDependentApps      = $report | Where-Object { $_.UsesLegacyRuntime } | Sort-Object AppName
        Summary                  = [PSCustomObject]@{
            InstalledVcPackages   = @($InstalledRuntimePackages).Count
            AppsScannedWithEvidence = @($report).Count
            AppsUsingLegacyRuntime = @($report | Where-Object { $_.UsesLegacyRuntime }).Count
        }
        Notes                    = @(
            "Inference-based result: an app may ship private runtime DLLs or reference runtime DLL names without strictly needing a machine-wide redistributable package."
            "VC++ 14.x covers the unified runtime family used by Visual Studio 2015 and later under Microsoft's binary compatibility model."
            "Redistributables for 2013 and earlier remain side-by-side and should be reviewed individually when found."
        )
    }
}

    Write-Verbose "Starting VC++ redistributable usage scan."
    $ruleTable = Get-VcRuntimeRuleTable
    $ruleLookup = @{}
    foreach ($rule in $ruleTable) {
        $ruleLookup[$rule.Pattern.ToLowerInvariant()] = $rule
    }

    $installedVcRedists = Get-InstalledVcRedist
    Write-Verbose ("Detected {0} installed VC++ redistributable package(s)." -f @($installedVcRedists).Count)
    $runningProcessVcMap = @(Get-RunningProcessVcMap -RuleTable $ruleTable)
    Write-Verbose ("Collected runtime module data from {0} running process(es)." -f @($runningProcessVcMap).Count)
    $allApps = @(Get-AppInventory -IncludeSystemComponents:$IncludeSystemComponents)
    $apps = if ($MaxApps -gt 0) {
        @($allApps | Select-Object -First $MaxApps)
    }
    else {
        $allApps
    }

    if ($MaxApps -gt 0) {
        Write-Verbose ("Scanning up to {0} application(s) out of {1} discovered." -f @($apps).Count, @($allApps).Count)
    }
    else {
        Write-Verbose ("Scanning all {0} discovered application(s)." -f @($apps).Count)
    }
    $binaryFileCache = @{}
    $binaryHitCache = @{}

    $appIndex = 0
    $appEvidence = foreach ($app in $apps) {
        $appIndex++
        Write-Verbose ("[{0}/{1}] Inspecting '{2}'." -f $appIndex, @($apps).Count, $app.Name)
        Get-AppVcEvidence -App $app -RuleTable $ruleTable -MaxFilesPerApp $MaxFilesPerApp -MaxBinaryScanMB $MaxBinaryScanMB -RunningProcessVcMap $runningProcessVcMap -IncludeWindowsApps:$IncludeWindowsApps -RuleLookup $ruleLookup -BinaryFileCache $binaryFileCache -BinaryHitCache $binaryHitCache
    }

    $appEvidence = @($appEvidence | Where-Object { $_ })
    Write-Verbose ("Found VC++ runtime evidence for {0} application(s)." -f @($appEvidence).Count)
    $report = New-VcUsageReport -AppEvidence $appEvidence -InstalledRuntimePackages $installedVcRedists

    if ($AsJson) {
        $report | ConvertTo-Json -Depth 8
        return
    }

    Write-Host ""
    Write-Host ("VCREDIST_SCAN status={0} installed_redists={1} apps_flagged={2} apps_with_evidence={3}" -f `
        $(if ($report.Summary.AppsUsingLegacyRuntime -gt 0) { "RISK_FOUND" } else { "CLEAR" }), `
        $report.Summary.InstalledVcPackages, `
        $report.Summary.AppsUsingLegacyRuntime, `
        $report.Summary.AppsScannedWithEvidence)
    Write-Host "Computer: $($report.ComputerName)"
    Write-Host "Scan Time (UTC): $($report.ScanTimeUtc)"
    Write-Host "Installed VC++ Redistributables Found: $($report.Summary.InstalledVcPackages)"
    Write-Host "Applications With VC++ Evidence: $($report.Summary.AppsScannedWithEvidence)"
    Write-Host "Applications Using Legacy / EOL VC++ Generations: $($report.Summary.AppsUsingLegacyRuntime)"
    Write-Host ""

    if ($report.InstalledVcRedists) {
        Write-Host "Installed VC++ Redistributables"
        $report.InstalledVcRedists |
            Select-Object Release, Architecture, Version, SupportState, Name |
            Format-Table -AutoSize
        Write-Host ""
    }

    $tableData = if ($ShowAllApps) {
        $report.ApplicationsUsingVc
    }
    else {
        $report.LegacyDependentApps
    }

    if (-not $tableData) {
        Write-Host "No applications with legacy / EOL VC++ runtime evidence were detected in the scanned app set."
    }
    else {
        Write-Host "Application Findings"
        $tableData |
            Select-Object AppName, AppVersion, Publisher, Confidence, UsesLegacyRuntime,
                @{n = "Releases"; e = { ($_.LegacyReleaseGenerations -join ", ") } },
                @{n = "RuntimeFamilies"; e = { ($_.RuntimeFamilies -join ", ") } } |
            Format-Table -Wrap -AutoSize
    }
}

#endregion

#region -------------------- Install / Remove: Remove-EOLOldVC (LIVE unless -WhatIf) --------------------

function Remove-EOLOldVC {
    <#
    .SYNOPSIS
        Removes every Microsoft Visual C++ Redistributable EXCEPT the newest 2015-2022
        (14.x) runtime per architecture, across all users, including leftover folders.

    .DESCRIPTION
        Built for EOL / vulnerability remediation (e.g. items flagged by a connectSecure /
        RMM agent). Designed to run non-interactively as NT AUTHORITY\SYSTEM on Windows
        PowerShell 5.1 (the in-box shell) as well as PowerShell 7.

        Behaviour (per the agreed policy):
          * KEEP   : only the newest 14.x (2015-2022/2026 unified) runtime for each of
                     x86 / x64 / arm64.
          * REMOVE : ALL legacy 2005 / 2008 / 2010 / 2012 / 2013 runtimes unconditionally,
                     PLUS any older or duplicate 14.x copies, PLUS leftover Package Cache
                     folders. Both the visible Burn "bundle" ARP entries and the hidden
                     "Minimum/Additional Runtime" MSI products are handled.
          * SAFETY : before removing anything for a given architecture, if no current 14.x
                     runtime exists for that architecture it is installed first (download
                     from Microsoft, winget fallback). If a current runtime still cannot be
                     established the removals for that architecture are SKIPPED (use -Force
                     to override, -NoInstall to skip the install step).

        Discovery is registry-only (fast, side-effect free). Win32_Product is deliberately
        NOT used because merely enumerating it triggers an MSI reconfigure/repair of every
        installed product. Registry reads use explicit RegistryView so a 32-bit RMM host is
        not silently redirected and does not miss native 64-bit entries.

        Folder cleanup is limited to C:\ProgramData\Package Cache\{GUID} folders belonging
        to removed / orphaned redistributables. The actual runtime DLLs in System32,
        SysWOW64 and WinSxS are NEVER hand-deleted - the MSI uninstaller owns and
        reference-counts those; deleting them would break the kept runtime and every app.

        IMPORTANT CAVEAT: Visual C++ runtimes are NOT backward compatible across major
        versions. An application built against 2013 needs msvcr120.dll, which the 14.x
        runtime does NOT provide. Force-removing 2005-2013 will break apps that specifically
        depend on those older runtimes. This is the requested behaviour for EOL cleanup -
        validate on representative machines before fleet-wide deployment.

    .PARAMETER NoInstall
        Skip the "install the current 14.x runtime if missing" safety step.

    .PARAMETER Force
        Remove legacy / old runtimes even when no current 14.x runtime is present for that
        architecture (bypasses the safety gate). Combine with -NoInstall for a pure,
        unconditional purge.

    .PARAMETER SkipUserHiveScan
        Skip scanning offline user profile hives (C:\Users\*\NTUSER.DAT). Per-user VC++
        installs are extremely rare; this scan is detection/reporting only.

    .PARAMETER SkipLeftoverCleanup
        Skip the Package Cache leftover-folder sweep.

    .PARAMETER InstallOnly
        Install mode: download + install (or upgrade to) the latest 14.x runtime for each
        -InstallArch and stop. Nothing is inventoried or removed.

    .PARAMETER InstallArch
        Architectures for -InstallOnly. Default: x64 + x86 on 64-bit Windows, arm64 + x86 on
        ARM64, x86 on 32-bit Windows.

    .PARAMETER LogDirectory
        Where the transcript, per-operation MSI logs and summary.csv are written.
        Default: C:\ProgramData\VCppCleanup

    .PARAMETER MsiTimeoutSeconds
        How long to wait for the Windows Installer mutex before each operation. Default 180.

    .PARAMETER MsiMaxRetries
        How many times to retry an operation that returns 1618 (installer busy). Default 5.

    .EXAMPLE
        Remove-EOLOldVC -WhatIf
        Dry run - reports every install / uninstall / folder deletion it WOULD perform.

    .EXAMPLE
        Remove-EOLOldVC
        Live run. Ensures the current runtime, then removes all older / legacy redistributables.

    .EXAMPLE
        Remove-EOLOldVC -NoInstall -Force
        Unconditional purge of all non-newest redistributables with no pre-install and no
        safety gate.

    .NOTES
        Exit codes (for RMM mapping):
            0     = success, nothing pending
            3010  = success, reboot required
            1     = one or more operations failed
            5     = precondition failed (not elevated)
        Treat 0 / 3010 as success (3010 => schedule a reboot).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch] $NoInstall,
        [switch] $Force,
        [switch] $SkipUserHiveScan,
        [switch] $SkipLeftoverCleanup,
        [switch] $InstallOnly,
        [ValidateSet('x64', 'x86', 'arm64')] [string[]] $InstallArch,
        [string] $LogDirectory = (Join-Path $env:ProgramData 'VCppCleanup'),
        [ValidateRange(1, 3600)] [int] $MsiTimeoutSeconds = 180,
        [ValidateRange(1, 20)]   [int] $MsiMaxRetries = 5
    )

    # ---------------------------------------------------------------------------
    # Bootstrap - make the run silent and non-interactive under an RMM/SYSTEM agent
    # ---------------------------------------------------------------------------
    $ConfirmPreference     = 'None'               # never auto-prompt on a real run
    $ProgressPreference    = 'SilentlyContinue'   # no progress UI in session 0
    $ErrorActionPreference = 'Continue'           # keep going; we handle errors per-item

    $script:LogDir         = $LogDirectory
    $script:MsiMaxRetries  = $MsiMaxRetries
    $script:MsiTimeoutSecs = $MsiTimeoutSeconds
    $script:RebootRequired = $false
    $script:Results        = New-Object System.Collections.Generic.List[object]

    try { if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null } } catch {}

    function Write-Log {
        param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
        $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message)
        switch ($Level) {
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'OK'    { Write-Host $line -ForegroundColor Green }
            default { Write-Host $line }
        }
    }

    # ===========================================================================
    #  Helpers  (registry inventory helpers - ConvertTo-VcVersion, Get-VcClass, Get-VcArch,
    #  Read-UninstallEntries, Get-VcInventory, Get-VCRuntimeVersion, Get-KeepMap, Test-IsKept -
    #  live in the Shared region at the top so Check can use them too)
    # ===========================================================================

    function Test-IsElevated {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsSystem {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ($id.User.Value -eq 'S-1-5-18')
    }

    function Split-UninstallExe {
        # Extract just the executable path from an UninstallString (handles quoted paths).
        param([string]$Cmd)
        if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
        $Cmd = $Cmd.Trim()
        if ($Cmd.StartsWith('"')) {
            $end = $Cmd.IndexOf('"', 1)
            if ($end -gt 1) { return $Cmd.Substring(1, $end - 1) }
        }
        $m = [regex]::Match($Cmd, '^(?<exe>.*?\.exe)(?:\s|$)', 'IgnoreCase')
        if ($m.Success) { return $m.Groups['exe'].Value.Trim() }
        return ($Cmd -split '\s+', 2)[0]
    }

    function Get-VcInventoryOffline {
        # Detection only: load offline NTUSER.DAT for users not currently logged on and report
        # any per-user VC++ entries. These are NOT auto-removed (a temporarily-mounted hive is
        # the wrong context to run an uninstall); they are surfaced for manual review.
        $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $loaded = @()
        $usersBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
        try { $loaded = $usersBase.GetSubKeyNames() } finally { $usersBase.Close() }

        Get-ChildItem $profileList -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.PSChildName
            if ($sid -notlike 'S-1-5-21-*')  { return }
            if ($loaded -contains $sid)      { return }
            $img = (Get-ItemProperty $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $img) { return }
            $dat = Join-Path $img 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $dat)) { return }

            $mount = "VCTmp_$([guid]::NewGuid().ToString('N'))"
            $out = & reg.exe load "HKU\$mount" "$dat" 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Log "Could not load hive for $sid (in use/locked): $out" 'WARN'; return }
            try {
                $ub = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
                try {
                    foreach ($p in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                     'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                        $uk = $ub.OpenSubKey("$mount\$p")
                        try { Read-UninstallEntries -UninstallKey $uk -Scope "HKU-offline/$sid" } finally { if ($uk) { $uk.Close() } }
                    }
                } finally { $ub.Close() }
            }
            finally {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                $u = & reg.exe unload "HKU\$mount" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                    $u = & reg.exe unload "HKU\$mount" 2>&1
                    if ($LASTEXITCODE -ne 0) { Write-Log "Failed to unload temp hive $mount : $u" 'WARN' }
                }
            }
        }
    }

    function Wait-ForMsi {
        # Poll the machine-wide Windows Installer mutex so we don't collide (1618).
        param([int]$TimeoutSeconds = 180, [int]$PollSeconds = 5)
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $mutex = $null
            try {
                $opened = [System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$mutex)
                if (-not $opened) { return $true }                          # not present -> installer idle
                try { if ($mutex.WaitOne(0)) { $mutex.ReleaseMutex(); return $true } }
                catch [System.Threading.AbandonedMutexException] { $mutex.ReleaseMutex(); return $true }
            }
            catch [System.UnauthorizedAccessException] {
                if (-not (Get-Process -Name msiexec -ErrorAction SilentlyContinue)) { return $true }
            }
            catch { return $true }
            finally { if ($mutex) { $mutex.Dispose() } }
            Start-Sleep -Seconds $PollSeconds
        }
        return $false
    }

    function Get-ActionState {
        param([int]$ExitCode)
        switch ($ExitCode) {
            0     { 'Success' }
            1707  { 'Success' }
            1605  { 'Skipped' }          # product not installed (already gone / cascaded)
            1614  { 'Skipped' }          # already uninstalled
            1638  { 'Skipped' }          # newer version already present (install no-op)
            3010  { 'RebootRequired' }
            1641  { 'RebootRequired' }
            default { 'Failed' }
        }
    }

    function New-VcResult {
        param($Name, $Version, $Arch, $Action, $State, $ExitCode, $ErrorMsg)
        [pscustomobject]@{
            TimeStamp = (Get-Date).ToString('o')
            Name      = $Name
            Version   = $Version
            Arch      = $Arch
            Action    = $Action
            State     = $State
            ExitCode  = $ExitCode
            Error     = $ErrorMsg
        }
    }

    function Invoke-Operation {
        # Serialised, mutex-aware, 1618-retrying process runner. Returns { ExitCode; Log; Error }.
        param([string]$FilePath, [string[]]$Arguments, [bool]$IsMsi)
        $logPath = Join-Path $script:LogDir ('op_{0}.log' -f ([guid]::NewGuid().ToString('N')))
        $argList = @() + $Arguments
        # Pre-quote the log path: Start-Process -ArgumentList does NOT quote array elements that
        # contain spaces (on PS 5.1 and 7), so a spaced -LogDirectory would split the log arg and
        # make msiexec reject the whole command line (1639) -> every uninstall fails.
        if     ($IsMsi)                                                            { $argList += @('/L*v', ('"{0}"' -f $logPath)) }
        elseif ([System.IO.Path]::GetFileName($FilePath) -match '(?i)vc_?redist')  { $argList += @('/log', ('"{0}"' -f $logPath)) }

        for ($attempt = 1; $attempt -le $script:MsiMaxRetries; $attempt++) {
            [void](Wait-ForMsi -TimeoutSeconds $script:MsiTimeoutSecs)
            try {
                $p = Start-Process -FilePath $FilePath -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
                $code = if ($null -ne $p -and $null -ne $p.ExitCode) { [int]$p.ExitCode } else { -1 }
            }
            catch {
                return [pscustomobject]@{ ExitCode = -1; Log = $logPath; Error = $_.Exception.Message }
            }
            if ($code -ne 1618) { return [pscustomobject]@{ ExitCode = $code; Log = $logPath; Error = $null } }
            Write-Log ("Installer busy (1618) on attempt {0}/{1}; backing off." -f $attempt, $script:MsiMaxRetries) 'WARN'
            Start-Sleep -Seconds ([Math]::Min(60, 15 * $attempt))
        }
        return [pscustomobject]@{ ExitCode = 1618; Log = $logPath; Error = 'Installer remained busy (1618) after retries.' }
    }

    function Resolve-Uninstall {
        # Decide how to silently remove one inventory entry. Returns { FilePath; Args; IsMsi } or $null.
        param($Entry)
        $guidRe = '^\{[0-9A-Fa-f\-]+\}$'
        if ($Entry.Kind -eq 'MSI' -and $Entry.KeyName -match $guidRe) {
            return @{ FilePath = "$env:SystemRoot\System32\msiexec.exe"; Args = @("/x$($Entry.KeyName)", '/qn', 'REBOOT=ReallySuppress'); IsMsi = $true }
        }
        if ($Entry.Kind -eq 'Bundle') {
            $exe = $null
            if ($Entry.BundleCachePath -and (Test-Path -LiteralPath $Entry.BundleCachePath)) { $exe = $Entry.BundleCachePath }
            else {
                $cmd = if ($Entry.QuietUninstallString) { $Entry.QuietUninstallString } else { $Entry.UninstallString }
                $cand = Split-UninstallExe $cmd
                if ($cand -and (Test-Path -LiteralPath $cand)) { $exe = $cand }
            }
            if ($exe) { return @{ FilePath = $exe; Args = @('/uninstall', '/quiet', '/norestart'); IsMsi = $false } }
            return $null   # cached installer gone; child MSIs (if any) are removed via their own entries
        }
        # Other / unknown wrapper: best effort
        $cmd = if ($Entry.QuietUninstallString) { $Entry.QuietUninstallString } else { $Entry.UninstallString }
        if ($cmd) {
            if ($cmd -match '(?i)msiexec' -and $Entry.KeyName -match $guidRe) {
                return @{ FilePath = "$env:SystemRoot\System32\msiexec.exe"; Args = @("/x$($Entry.KeyName)", '/qn', 'REBOOT=ReallySuppress'); IsMsi = $true }
            }
            $cand = Split-UninstallExe $cmd
            if ($cand -and (Test-Path -LiteralPath $cand)) {
                return @{ FilePath = $cand; Args = @('/uninstall', '/quiet', '/norestart'); IsMsi = $false }
            }
        }
        return $null
    }

    function Install-LatestVCRedist {
        # Download the current runtime from Microsoft (winget fallback) and install it silently.
        [CmdletBinding(SupportsShouldProcess = $true)]
        param([ValidateSet('x64', 'x86', 'arm64')][string]$Arch)

        $primary  = @{ x64 = 'https://aka.ms/vc14/vc_redist.x64.exe'; x86 = 'https://aka.ms/vc14/vc_redist.x86.exe'; arm64 = 'https://aka.ms/vc14/vc_redist.arm64.exe' }
        $fallback = @{ x64 = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'; x86 = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'; arm64 = 'https://aka.ms/vs/17/release/vc_redist.arm64.exe' }

        if (-not $PSCmdlet.ShouldProcess("Microsoft Visual C++ $Arch (latest 14.x)", 'Download and install')) {
            $script:Results.Add((New-VcResult -Name "VC++ 14.x $Arch" -Version 'latest' -Arch $Arch -Action 'Install' -State 'WhatIf' -ExitCode $null -ErrorMsg $null))
            return $true
        }

        $work = Join-Path $env:TEMP 'VCppCleanup'
        if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }
        $exe = Join-Path $work "vc_redist.$Arch.exe"

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
            }
        } catch {}

        $downloaded = $false
        foreach ($url in @($primary[$Arch], $fallback[$Arch])) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
                if ((Test-Path $exe) -and (Get-Item $exe).Length -gt 0) { $downloaded = $true; break }
            } catch { Write-Log "Download failed ($url): $($_.Exception.Message)" 'WARN' }
            try {
                Import-Module BitsTransfer -ErrorAction Stop
                Start-BitsTransfer -Source $url -Destination $exe -ErrorAction Stop
                if ((Test-Path $exe) -and (Get-Item $exe).Length -gt 0) { $downloaded = $true; break }
            } catch { Write-Log "BITS download failed ($url): $($_.Exception.Message)" 'WARN' }
        }

        if ($downloaded) {
            $sig = Get-AuthenticodeSignature -LiteralPath $exe
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Microsoft*') {
                Write-Log "Refusing to run '$exe': signature $($sig.Status)." 'ERROR'
                $downloaded = $false
            }
            else {
                $r = Invoke-Operation -FilePath $exe -Arguments @('/install', '/quiet', '/norestart') -IsMsi $false
                $state = Get-ActionState $r.ExitCode
                if ($state -eq 'RebootRequired') { $script:RebootRequired = $true }
                $ok = @('Success', 'RebootRequired', 'Skipped') -contains $state
                Write-Log ("Install VC++ 14.x $Arch -> $state (exit $($r.ExitCode))") ($(if ($ok) { 'OK' } else { 'ERROR' }))
                $script:Results.Add((New-VcResult -Name "VC++ 14.x $Arch" -Version 'latest' -Arch $Arch -Action 'Install' -State $state -ExitCode $r.ExitCode -ErrorMsg $r.Error))
                if ($ok) { return $true }
            }
        }

        # Fallback: winget (unreliable under SYSTEM, hence last resort)
        Write-Log "Attempting winget fallback for VC++ 14.x $Arch." 'WARN'
        try {
            $id = @{ x64 = 'Microsoft.VCRedist.2015+.x64'; x86 = 'Microsoft.VCRedist.2015+.x86'; arm64 = 'Microsoft.VCRedist.2015+.arm64' }[$Arch]
            $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
            if (-not $winget) {
                $pkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
                if ($pkg) { $cand = Join-Path $pkg.InstallLocation 'winget.exe'; if (Test-Path $cand) { $winget = $cand } }
            }
            if ($winget) {
                & $winget install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --scope machine 2>&1 | Out-Null
                $ok = ($LASTEXITCODE -eq 0)
                $st = if ($ok) { 'Success' } else { 'Failed' }
                Write-Log ("winget install $id -> $st (exit $LASTEXITCODE)") ($(if ($ok) { 'OK' } else { 'ERROR' }))
                $script:Results.Add((New-VcResult -Name "VC++ 14.x $Arch (winget)" -Version 'latest' -Arch $Arch -Action 'Install' -State $st -ExitCode $LASTEXITCODE -ErrorMsg $null))
                return $ok
            }
            Write-Log "winget not available in this context." 'WARN'
        } catch { Write-Log "winget fallback failed: $($_.Exception.Message)" 'WARN' }

        $script:Results.Add((New-VcResult -Name "VC++ 14.x $Arch" -Version 'latest' -Arch $Arch -Action 'Install' -State 'Failed' -ExitCode $null -ErrorMsg 'All install methods failed.'))
        return $false
    }

    function Remove-PackageCacheFolder {
        # Delete a leftover Package Cache folder - only under ProgramData\Package Cache, never a
        # protected (kept) folder, never a reparse point, never the cache root itself.
        [CmdletBinding(SupportsShouldProcess = $true)]
        param([Parameter(Mandatory)][string]$Path, [string[]]$ProtectedPaths = @())

        $cacheRoot = Join-Path $env:ProgramData 'Package Cache'
        try { $full = [System.IO.Path]::GetFullPath($Path) } catch { Write-Log "Bad path '$Path'." 'WARN'; return }
        $rootFull = [System.IO.Path]::GetFullPath($cacheRoot)
        $rootSep  = $rootFull.TrimEnd('\') + '\'

        if (-not $full.StartsWith($rootSep, [StringComparison]::OrdinalIgnoreCase)) { Write-Log "REFUSING (outside Package Cache): $full" 'WARN'; return }
        if ($full.TrimEnd('\').Equals($rootFull.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { Write-Log "REFUSING (cache root): $full" 'WARN'; return }
        foreach ($p in $ProtectedPaths) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            $pf = ([System.IO.Path]::GetFullPath($p)).TrimEnd('\')
            if ($full.TrimEnd('\').Equals($pf, [StringComparison]::OrdinalIgnoreCase)) { Write-Log "REFUSING (kept runtime cache): $full" 'WARN'; return }
        }
        if (-not (Test-Path -LiteralPath $full)) { return }
        $di = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
        if ($di -and ($di.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Write-Log "REFUSING (reparse point): $full" 'WARN'; return }

        if ($PSCmdlet.ShouldProcess($full, 'Remove leftover VC++ Package Cache folder')) {
            try {
                Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
                Remove-Item -LiteralPath $full -Recurse -Force -Confirm:$false -ErrorAction Stop
                Write-Log "Removed leftover folder: $full" 'OK'
                $script:Results.Add((New-VcResult -Name (Split-Path $full -Leaf) -Version $null -Arch $null -Action 'RemoveFolder' -State 'Success' -ExitCode $null -ErrorMsg $null))
            }
            catch {
                Write-Log "Could not remove '$full' (in use?): $($_.Exception.Message)" 'WARN'
                $script:Results.Add((New-VcResult -Name (Split-Path $full -Leaf) -Version $null -Arch $null -Action 'RemoveFolder' -State 'Failed' -ExitCode $null -ErrorMsg $_.Exception.Message))
            }
        }
        else {
            $script:Results.Add((New-VcResult -Name (Split-Path $full -Leaf) -Version $null -Arch $null -Action 'RemoveFolder' -State 'WhatIf' -ExitCode $null -ErrorMsg $null))
        }
    }

    function Invoke-PackageCacheCleanup {
        param([string[]]$ProtectedFolders)
        $root = Join-Path $env:ProgramData 'Package Cache'
        if (-not (Test-Path -LiteralPath $root)) { return }

        # "Owned" = still registered by a bundle in the CURRENT registry. Never delete an owned
        # folder (protects the kept runtime AND anything whose uninstall failed / was skipped).
        $owned = @{}
        foreach ($f in (Get-VcInventory)) {
            if ($f.BundleCachePath) { $owned[$f.BundleCachePath.ToLowerInvariant()] = $true }
        }

        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dir = $_.FullName
            $exe = Get-ChildItem -LiteralPath $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '(?i)^vc_?redist' } | Select-Object -First 1
            if (-not $exe) { return }
            $pn = ''
            try { $pn = [string]$exe.VersionInfo.ProductName } catch {}
            if (($exe.Name -notmatch '(?i)vc_?redist') -and ($pn -notlike '*Visual C++*')) { return }
            if ($owned.ContainsKey($exe.FullName.ToLowerInvariant())) { return }   # still registered -> keep
            Remove-PackageCacheFolder -Path $dir -ProtectedPaths $ProtectedFolders
        }
    }

    # ===========================================================================
    #  Main
    # ===========================================================================
    $exitCode  = 0
    $transcript = Join-Path $script:LogDir ('Remove-OldVCpp_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
    try { Start-Transcript -Path $transcript -Force | Out-Null } catch {}

    try {
        Write-Log ("Remove-EOLOldVC starting. WhatIf={0} NoInstall={1} Force={2} InstallOnly={3} User={4} SYSTEM={5}" -f `
            $WhatIfPreference, [bool]$NoInstall, [bool]$Force, [bool]$InstallOnly, ([Security.Principal.WindowsIdentity]::GetCurrent().Name), (Test-IsSystem))

        if (-not (Test-IsElevated)) {
            Write-Log 'Must run elevated (Administrator or NT AUTHORITY\SYSTEM). Aborting.' 'ERROR'
            $exitCode = 5
            throw 'NotElevated'
        }

        if ($InstallOnly) {
            # Install mode: latest 14.x per arch, in place (exit 1638 = same/newer present -> Skipped).
            if (-not $InstallArch) {
                $InstallArch = if (@($env:PROCESSOR_ARCHITECTURE, $env:PROCESSOR_ARCHITEW6432) -contains 'ARM64') { 'arm64', 'x86' }
                               elseif ([Environment]::Is64BitOperatingSystem) { 'x64', 'x86' } else { 'x86' }
            }
            foreach ($arch in $InstallArch) {
                Write-Log ("Installing / upgrading to the latest VC++ 14.x $arch runtime.")
                [void](Install-LatestVCRedist -Arch $arch)
            }
        }
        else {
            # --- 1. Inventory -------------------------------------------------------
            $inv = @(Get-VcInventory)
            Write-Log ("Found {0} Visual C++ redistributable registry entries (bundles + MSI products)." -f $inv.Count)
            foreach ($e in ($inv | Sort-Object Arch, Class, DisplayName)) {
                Write-Log ("  [{0,-7}] [{1,-5}] {2}" -f $e.Class, $e.Arch, $e.DisplayName)
            }

            if (-not $SkipUserHiveScan) {
                $offline = @(Get-VcInventoryOffline)
                foreach ($o in $offline) {
                    Write-Log ("Per-user VC++ entry found in offline profile ({0}): {1} - review manually." -f $o.Scope, $o.DisplayName) 'WARN'
                    $script:Results.Add((New-VcResult -Name $o.DisplayName -Version $o.DisplayVersion -Arch $o.Arch -Action 'ReviewManually' -State 'Skipped' -ExitCode $null -ErrorMsg $o.Scope))
                }
            }

            # --- 2. Compute keep set (newest 14.x per arch) -------------------------

            $keepMap = Get-KeepMap $inv

            # Surface name-matched VC++ entries whose version could not be classified (blank/garbage
            # DisplayVersion and no legacy year in the name). They are never auto-removed - reported so
            # a flagged EOL item is not silently left behind with no operator signal.
            foreach ($u in @($inv | Where-Object { $_.Class -eq 'Unknown' })) {
                Write-Log ("UNCLASSIFIED VC++ entry '{0}' (version '{1}' unparseable) - not auto-removed; review manually." -f $u.DisplayName, $u.DisplayVersion) 'WARN'
                $script:Results.Add((New-VcResult -Name $u.DisplayName -Version $u.DisplayVersion -Arch $u.Arch -Action 'ReviewManually' -State 'Skipped' -ExitCode $null -ErrorMsg 'Version unparseable (Class=Unknown); not auto-removed.'))
            }

            # Removal candidates = legacy (any) + unified that is not the newest for its arch.
            # Unified requires a parsed Version before it can be a candidate (defensive: never remove a
            # version-less Unified entry, which could be a current runtime we failed to version).
            $candidates = @($inv | Where-Object {
                ($_.Class -eq 'Legacy') -or ($_.Class -eq 'Unified' -and $_.Version -and -not (Test-IsKept $_ $keepMap))
            })

            if ($candidates.Count -eq 0) {
                Write-Log 'Nothing to remove - only the newest 14.x runtime per architecture is present.' 'OK'
            }

            # --- 3. Ensure a current 14.x runtime exists for each affected arch ------
            $ensureArches = @($candidates | Where-Object { $_.Arch -in @('x64', 'x86', 'arm64') } | Select-Object -ExpandProperty Arch | Sort-Object -Unique)
            if (-not $NoInstall -and $ensureArches.Count -gt 0) {
                foreach ($arch in $ensureArches) {
                    if ($keepMap.ContainsKey($arch)) {
                        Write-Log ("Current 14.x $arch runtime already present ($($keepMap[$arch])); keeping it.")
                        continue
                    }
                    $rt = Get-VCRuntimeVersion -Arch $arch
                    if ($rt) { Write-Log ("Current 14.x $arch runtime detected ($rt); keeping it."); continue }
                    Write-Log ("No current 14.x $arch runtime present - installing latest before removals.") 'WARN'
                    [void](Install-LatestVCRedist -Arch $arch)
                }
                # Re-inventory so freshly installed runtimes become the keep target.
                $inv = @(Get-VcInventory)
                $keepMap = Get-KeepMap $inv
                $candidates = @($inv | Where-Object {
                    ($_.Class -eq 'Legacy') -or ($_.Class -eq 'Unified' -and $_.Version -and -not (Test-IsKept $_ $keepMap))
                })
            }

            # --- 4. Safety gate: don't strip the last runtime of an arch ------------
            function Test-ArchSafe {
                param([string]$Arch)
                if ($Force) { return $true }
                if ($keepMap.ContainsKey($Arch)) { return $true }
                if (Get-VCRuntimeVersion -Arch $Arch) { return $true }
                if ($WhatIfPreference -and -not $NoInstall) { return $true }   # a real run would have installed it
                return $false
            }

            $toRemove = New-Object System.Collections.Generic.List[object]
            foreach ($c in $candidates) {
                if (Test-ArchSafe -Arch $c.Arch) { $toRemove.Add($c) }
                else {
                    Write-Log ("SKIPPING '{0}' - no current 14.x $($c.Arch) runtime present (install failed/disabled). Use -Force to override." -f $c.DisplayName) 'WARN'
                    $script:Results.Add((New-VcResult -Name $c.DisplayName -Version $c.DisplayVersion -Arch $c.Arch -Action 'Uninstall' -State 'Skipped' -ExitCode $null -ErrorMsg 'No current runtime; removal gated for safety.'))
                }
            }

            # --- 5. Remove: unified bundles -> unified MSIs -> legacy ---------------
            # (bundles before their child MSIs so the Burn cascade + dependency ref-counts release first)
            $ordered = $toRemove | Sort-Object -Property `
                @{ Expression = {
                    $c = switch ($_.Class) { 'Unified' { 0 } 'Legacy' { 2 } default { 3 } }
                    $k = if ($_.Kind -eq 'Bundle') { 0 } else { 1 }
                    '{0}{1}' -f $c, $k
                } }, DisplayName

            foreach ($e in $ordered) {
                $resolve = Resolve-Uninstall $e
                if ($null -eq $resolve) {
                    # Orphaned ARP entry (cached installer + UninstallString exe both gone). It cannot be
                    # removed via its own metadata; its child MSIs (if any) are removed via their own
                    # entries. Record as Skipped/ReviewManually (not Failed) so a rerun can still report a
                    # clean no-op instead of forcing exit 1 forever.
                    Write-Log ("No usable uninstaller for '{0}' (cached installer missing) - orphaned entry, review manually." -f $e.DisplayName) 'WARN'
                    $script:Results.Add((New-VcResult -Name $e.DisplayName -Version $e.DisplayVersion -Arch $e.Arch -Action 'ReviewManually' -State 'Skipped' -ExitCode $null -ErrorMsg 'No usable uninstall command (orphaned ARP entry).'))
                    continue
                }
                if ($PSCmdlet.ShouldProcess($e.DisplayName, 'Uninstall Visual C++ Redistributable')) {
                    $r = Invoke-Operation -FilePath $resolve.FilePath -Arguments $resolve.Args -IsMsi $resolve.IsMsi
                    $state = Get-ActionState $r.ExitCode
                    if ($state -eq 'RebootRequired') { $script:RebootRequired = $true }
                    $lvl = if ($state -eq 'Failed') { 'ERROR' } elseif ($state -eq 'Success' -or $state -eq 'RebootRequired') { 'OK' } else { 'INFO' }
                    Write-Log ("{0} -> {1} (exit {2})" -f $e.DisplayName, $state, $r.ExitCode) $lvl
                    $script:Results.Add((New-VcResult -Name $e.DisplayName -Version $e.DisplayVersion -Arch $e.Arch -Action 'Uninstall' -State $state -ExitCode $r.ExitCode -ErrorMsg $r.Error))
                }
                else {
                    $script:Results.Add((New-VcResult -Name $e.DisplayName -Version $e.DisplayVersion -Arch $e.Arch -Action 'Uninstall' -State 'WhatIf' -ExitCode $null -ErrorMsg $null))
                }
            }

            # --- 6. Leftover Package Cache folders ----------------------------------
            if (-not $SkipLeftoverCleanup) {
                $freshKeep = Get-KeepMap (Get-VcInventory)
                $protected = @()
                foreach ($k in (Get-VcInventory)) {
                    if ($k.Class -eq 'Unified' -and (Test-IsKept $k $freshKeep) -and $k.BundleCachePath) {
                        $protected += (Split-Path $k.BundleCachePath -Parent)
                    }
                }
                if ($WhatIfPreference) {
                    Write-Log 'Package Cache leftover sweep runs after the real uninstalls; not previewed under -WhatIf.'
                } else {
                    Write-Log 'Sweeping leftover VC++ Package Cache folders.'
                    Invoke-PackageCacheCleanup -ProtectedFolders $protected
                }
            }
        }

        # --- 7. Summary ---------------------------------------------------------
        $failed = @($script:Results | Where-Object { $_.State -eq 'Failed' })
        $reboot = @($script:Results | Where-Object { $_.State -eq 'RebootRequired' })
        $done   = @($script:Results | Where-Object { $_.State -in @('Success', 'RebootRequired') })
        Write-Log ("SUMMARY: {0} actions logged, {1} succeeded, {2} failed, reboot-required={3}" -f `
            $script:Results.Count, $done.Count, $failed.Count, ($reboot.Count -gt 0)) 'OK'

        if     ($failed.Count -gt 0)          { $exitCode = 1 }
        elseif ($script:RebootRequired)       { $exitCode = 3010 }
        else                                  { $exitCode = 0 }
    }
    catch {
        if ($_.Exception.Message -ne 'NotElevated') {
            Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
            $script:Results.Add((New-VcResult -Name 'Script' -Version $null -Arch $null -Action 'Run' -State 'Failed' -ExitCode $null -ErrorMsg $_.Exception.Message))
            if ($exitCode -eq 0) { $exitCode = 1 }
        }
    }
    finally {
        # BOM-less UTF-8 so RMM CSV parsers don't choke on a leading BOM in the first header
        # (Windows PowerShell 5.1's Export-Csv -Encoding UTF8 emits a BOM; PS7 does not).
        try {
            $csvPath  = Join-Path $script:LogDir 'summary.csv'
            $csvLines = $script:Results | ConvertTo-Csv -NoTypeInformation
            [System.IO.File]::WriteAllLines($csvPath, [string[]]$csvLines, (New-Object System.Text.UTF8Encoding($false)))
        } catch {}
        try { Stop-Transcript | Out-Null } catch {}
    }

    return $exitCode
}

#endregion

#region -------------------- Invoke-VCRedistEOL (dispatcher, returns the exit code) --------------------

function Invoke-VCRedistEOL {
    param(
        [ValidateSet('Check', 'Recon', 'Install', 'Remove')]
        [string]$Mode = 'Check',
        # Parameters of the mode's function, e.g. @{ WhatIf = $true } or @{ MaxApps = 50 }
        [hashtable]$Options = @{}
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    try {
        switch ($Mode) {
            'Check' {
                $rows = @(Test-VCRedistEOL @Options)
                if ($rows.Count -eq 0) { Write-Host 'No Visual C++ redistributables registered.'; return 0 }
                $rows | Sort-Object Arch, Status, DisplayName |
                    Format-Table Status, Arch, Version, Kind, Scope, DisplayName -AutoSize | Out-Host
                $eol   = @($rows | Where-Object Status -eq 'EOL').Count
                $older = @($rows | Where-Object Status -eq 'Older14x').Count
                $rev   = @($rows | Where-Object Status -eq 'Review').Count
                Write-Host ("VCREDIST_CHECK status={0} eol={1} older14x={2} review={3} keep={4}" -f `
                    $(if ($eol + $older) { 'EOL_FOUND' } else { 'CLEAR' }), $eol, $older, $rev,
                    @($rows | Where-Object Status -eq 'Keep').Count)
                if ($eol + $older) { return 2 }
                return 0
            }
            'Recon' {
                Invoke-ScanVCRedistUsageV2 @Options | Out-Host
                return 0
            }
            default {
                # Install / Remove. Remove-EOLOldVC refuses to run unelevated even under WhatIf
                # (returns 5), so gate here before it creates its log folder / transcript.
                if (-not $isAdmin) {
                    Write-Host "ERROR: $Mode needs an elevated or SYSTEM session (also for WhatIf)." -ForegroundColor Red
                    return 10
                }
                $o = @{} + $Options
                if ($Mode -eq 'Install') { $o['InstallOnly'] = $true }
                $rc = @(Remove-EOLOldVC @o)
                return [int]$rc[-1]   # the function's last output is its exit code
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

$exitCode = Invoke-VCRedistEOL                                                  # Check (read-only)
# $exitCode = Invoke-VCRedistEOL -Mode Recon -Options @{ MaxApps = 50 }         # who needs which runtime (read-only, slow)
# $exitCode = Invoke-VCRedistEOL -Mode Recon -Options @{ ShowAllApps = $true }  # all apps, not only legacy-dependent
# $exitCode = Invoke-VCRedistEOL -Mode Install -Options @{ WhatIf = $true }     # preview
# $exitCode = Invoke-VCRedistEOL -Mode Install                                  # LIVE: latest 14.x per arch
# $exitCode = Invoke-VCRedistEOL -Mode Remove -Options @{ WhatIf = $true }      # preview
# $exitCode = Invoke-VCRedistEOL -Mode Remove                                   # LIVE: keep newest 14.x, remove the rest

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
