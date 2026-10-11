# Tested with PSScriptAnalyzer 1.25.0 and Pester 6.2.0 on Windows PowerShell 5.1 (tests\Morphs.Tests.ps1, 2026-10-11): static, paste-model and elevation-gate checks; live changes not run.
<#
.SYNOPSIS
    .NET (Core / 5+) end-of-life toolkit - Check / Recon / Remove / Update. Paste-and-run.

.DESCRIPTION
    One script, four modes, chosen in the ENTRY POINT at the bottom:

      Check   DEFAULT. Fast EOL scan of the shared runtime folders and SDKs. Read-only.
              EOL = major.minor in -EoLVersions (1.0-3.1, 5.0, 6.0, 7.0).
      Recon   Evidence-based "who uses which runtime" inventory: dotnet CLI, Framework
              registry, ARP, loaded modules of running processes, runtimeconfig.json,
              services, scheduled tasks, IIS and a binary scan. Each runtime gets a verdict:
              Observed use - keep / Superseded by <newer patch> - removal candidate /
              Potential dependency - review / No evidence found - verify. Read-only.
      Remove  Uninstalls every modern .NET component BELOW -RemoveBelow (default 8.0.28):
              runtimes, ASP.NET Core, Desktop, hosting bundles, SDKs, packs, hosts - in
              dependency order, MSI and Burn bundles, both registry views. .NET Framework,
              .NET Standard, Visual Studio, Mono, SDK/targeting packs for Framework are
              deny-listed. Detects and cleans "ghost" ARP keys. DRY RUN unless Armed.
      Update  Within supported majors (default 8 and 10): installs the latest patch via
              winget, then removes older patch bundles, orphaned child MSIs and leftover
              runtime folders no installer owns. Newest is always kept. LIVE unless WhatIf.

    Run Check or Recon first. Remove does not check whether an app still needs a runtime.

.EXAMPLE
    Paste the WHOLE script into an elevated console or an RMM component, after editing
    the ENTRY POINT at the bottom. Mode-specific options go in -Options as a hashtable
    (they are the parameters of the underlying function):

    Invoke-DotNetEOL                                         # Check
    Invoke-DotNetEOL -Mode Recon -Options @{ TargetVersion = '6.0'; SkipAssemblyScan = $true }
    Invoke-DotNetEOL -Mode Remove                            # dry run
    Invoke-DotNetEOL -Mode Remove -Options @{ CleanLeftoverFolders = $true; CleanLeftoverRegistry = $true; Armed = $true }
    Invoke-DotNetEOL -Mode Update -Options @{ WhatIf = $true }

    After a paste the functions stay loaded: Test-DotNetSEoL, Get-DotNetInventory
    (-PassThru for objects), Remove-OldDotNet, Update-DotNetRuntime.

.NOTES
    Exit codes (Invoke-DotNetEOL returns one; the entry point exits with it only when $RMM = $true):
        0     OK / nothing to do / dry run complete
        1     Unexpected error
        2     Check: end-of-life .NET found
        3     Remove/Update: one or more actions failed
        3010  Remove/Update: reboot required to finish
        10    Remove -Armed / live Update needs an elevated or SYSTEM session

    The EOL list is policy, not data: .NET 8 and 9 reach end of support on 2026-11-10.
    Add '8.0','9.0' to EoLVersions and raise RemoveBelow when that date passes.
#>

#region -------------------- Check: Test-DotNetSEoL (fast, read-only) --------------------

function Test-DotNetSEoL {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string[]]$EoLVersions = @('1.0', '1.1', '2.0', '2.1', '2.2', '3.0', '3.1', '5.0', '6.0', '7.0')
    )

    $searchPaths = @(
        'C:\Program Files\dotnet\shared',
        'C:\Program Files (x86)\dotnet\shared'
    )

    $runtimes = @('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App', 'Microsoft.WindowsDesktop.App')
    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($base in $searchPaths) {
        if (-not (Test-Path $base)) { continue }

        foreach ($runtime in $runtimes) {
            $runtimePath = Join-Path $base $runtime
            if (-not (Test-Path $runtimePath)) { continue }

            Get-ChildItem -Path $runtimePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $versionFolder = $_.Name
                $majorMinor = ($versionFolder -split '\.')[0..1] -join '.'
                $isEoL = $EoLVersions -contains $majorMinor

                $findings.Add([pscustomobject]@{
                    ComputerName    = $ComputerName
                    Runtime         = $runtime
                    Version         = $versionFolder
                    MajorMinor      = $majorMinor
                    Path            = $_.FullName
                    EndOfLife       = $isEoL
                    Status          = if ($isEoL) { 'EoL - VULNERABLE' } else { 'Supported' }
                })
            }
        }
    }

    # Also check dotnet CLI output if available
    $dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnetCmd) {
        try {
            $sdks = & dotnet --list-sdks 2>$null
            foreach ($sdk in $sdks) {
                if ($sdk -match '^(\d+\.\d+)\.\d+') {
                    $majorMinor = $Matches[1]
                    $isEoL = $EoLVersions -contains $majorMinor
                    $findings.Add([pscustomobject]@{
                        ComputerName = $ComputerName
                        Runtime      = 'SDK'
                        Version      = ($sdk -split ' ')[0]
                        MajorMinor   = $majorMinor
                        Path         = ($sdk -replace '^[^\[]+\[|\]$','')
                        EndOfLife    = $isEoL
                        Status       = if ($isEoL) { 'EoL - VULNERABLE' } else { 'Supported' }
                    })
                }
            }
        } catch { }
    }

    if ($findings.Count -eq 0) {
        Write-Host "No .NET Core / ASP.NET Core installations found on $ComputerName" -ForegroundColor Yellow
        return
    }

    $findings | Sort-Object EndOfLife -Descending | Format-Table -AutoSize | Out-Host

    $eolCount = ($findings | Where-Object EndOfLife).Count
    if ($eolCount -gt 0) {
        Write-Host ""
        Write-Host "[!] Found $eolCount End-of-Life .NET installation(s) on $ComputerName" -ForegroundColor Red
        Write-Host "[!] Remediation: Uninstall EoL versions via 'Apps & Features' or dotnet-core-uninstall tool" -ForegroundColor Red
    } else {
        Write-Host "[OK] No End-of-Life .NET versions detected on $ComputerName" -ForegroundColor Green
    }

    return $findings
}

#endregion

#region -------------------- Recon: Get-DotNetInventory (evidence-based, read-only) --------------------

<#
    Observed use means a process loaded a module from that exact runtime directory.
    PotentialConsumers means a runtime falls in a declared dependency's version
    range; it is NOT an assertion that the host selects that particular patch.
    SharedCandidate is a framework-dependent configuration whose actual host/root
    is unknown. Nearby runtime files alone never prove private runtime use.

    This is a bounded snapshot, not proof that a runtime can be uninstalled.
    Single-file apps, custom hosts, containers, other users, inaccessible files,
    environment/command-line overrides, SDK use and framework reference unification
    can require additional investigation. No application binaries are launched.
    Only discovered dotnet hosts are invoked, with --list-runtimes / --list-sdks;
    use -SkipDotNetCli to inventory their folders without executing those hosts.

    -TargetVersion  Numeric prefix (8, 8.0, 8.0.12). Filters only the runtime summary.
    -DotNetRoots    Additional shared dotnet installation roots to inventory.
    -AppRoots       Application directories to scan (reparse points are skipped).
    -MaxDepth       Maximum directory depth below each AppRoot (default 64).
    -PassThru       Emit objects instead of the report (ConvertTo-Json -Depth 8 to export).

    Runtime binding references:
    https://learn.microsoft.com/en-us/dotnet/core/versions/selection
    https://github.com/dotnet/runtime/blob/main/docs/design/features/framework-version-resolution.md
#>
function Get-DotNetInventory {
    [CmdletBinding()]
    param(
        [switch]$SkipDotNetCli,
        [switch]$SkipFrameworkRegistry,
        [switch]$SkipUninstallEntries,
        [switch]$SkipRunningProcesses,
        [switch]$SkipRuntimeConfigs,
        [switch]$SkipServices,
        [switch]$SkipScheduledTasks,
        [switch]$SkipIIS,
        [switch]$SkipAssemblyScan,
        [string[]]$AppRoots = @(
            $env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)},
            $env:ProgramData, "$env:SystemDrive\inetpub\wwwroot"
        ),
        [string[]]$DotNetRoots = @(),
        [ValidatePattern('^\d+(\.\d+){0,2}$')][string]$TargetVersion,
        [ValidateRange(1,256)][int]$MaxDepth = 64,
        [ValidateRange(1,300)][int]$CliTimeoutSeconds = 15,
        [switch]$PassThru
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Get-DotNetInventory requires Windows; no scan was performed.'
    }
    # Registry, JSON and XML records have optional properties. Keep the caller's
    # StrictMode setting unchanged outside this function's local scope.
    Set-StrictMode -Off
    $started = [DateTime]::UtcNow
    $results = [System.Collections.Generic.List[object]]::new()
    $diagnostics = [System.Collections.Generic.List[object]]::new()
    $roots = @{}
    $runtimeCache = @{}
    $archCache = @{}
    $seenEvidence = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $stats = @{ Directories = 0; Files = 0; Configs = 0; Binaries = 0 }

    function New-Result {
        param([string]$Source, [string]$Category, [hashtable]$Data)
        $record = [ordered]@{ Source = $Source; Category = $Category }
        foreach ($key in ($Data.Keys | Sort-Object)) { $record[$key] = $Data[$key] }
        [pscustomobject]$record
    }
    function Add-Diagnostic {
        param([string]$Source, [string]$Path, [string]$Message, [string]$Status = 'Failed')
        $diagnostics.Add((New-Result $Source 'ScanDiagnostic' @{
            Path = $Path; Message = $Message; Status = $Status
        }))
        Write-Verbose ("{0}: {1}: {2}" -f $Source, $Path, $Message)
    }
    function Get-FullPath {
        param([string]$Path, [string]$BaseDirectory)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
        if ($expanded.StartsWith('\??\')) { $expanded = $expanded.Substring(4) }
        if ($expanded -match '^\\SystemRoot\\') { $expanded = $env:SystemRoot + $expanded.Substring(11) }
        if ($expanded -match '%[^%]+%') { return $null }
        if (-not [IO.Path]::IsPathRooted($expanded)) {
            if (-not $BaseDirectory) { return $null }
            $expanded = Join-Path $BaseDirectory $expanded
        }
        try { [IO.Path]::GetFullPath($expanded) } catch { return $null }
    }
    function Test-UnderPath {
        param([string]$Path, [string]$Root)
        if (-not $Path -or -not $Root) { return $false }
        $prefix = $Root.TrimEnd('\') + '\'
        $Path.Equals($Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
            $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    }
    function Get-SharedRoot {
        param([string]$Path)
        foreach ($root in ($roots.Values | Sort-Object { $_.Path.Length } -Descending)) {
            if (Test-UnderPath $Path (Join-Path $root.Path 'shared')) { return $root }
        }
    }
    function Get-PEArchitecture {
        param([string]$Path)
        if (-not $Path) { return 'Unknown' }
        if ($archCache.ContainsKey($Path)) { return $archCache[$Path] }
        $stream = $null; $reader = $null; $arch = 'Unknown'
        try {
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = [IO.BinaryReader]::new($stream)
            if ($stream.Length -ge 64 -and $reader.ReadUInt16() -eq 0x5A4D) {
                $stream.Position = 0x3C
                $offset = $reader.ReadInt32()
                if ($offset -ge 64 -and $offset -le ($stream.Length - 26)) {
                    $stream.Position = $offset
                    if ($reader.ReadUInt32() -eq 0x00004550) {
                        $machine = $reader.ReadUInt16()
                        $arch = switch ($machine) { 0x8664 { 'x64' }; 0xAA64 { 'arm64' }; 0x14C { 'x86' }; default { 'Unknown' } }
                        # Managed I386 PE files can be AnyCPU. Do not force them to x86.
                        if ($arch -eq 'x86') {
                            try {
                                $assembly = [Reflection.AssemblyName]::GetAssemblyName($Path)
                                if ($assembly.ProcessorArchitecture -eq 'MSIL') { $arch = 'AnyCPU' }
                            } catch { }
                        }
                    }
                }
            }
        } catch { Write-Verbose "Architecture unavailable for ${Path}: $($_.Exception.Message)" }
        finally {
            if ($reader) { $reader.Dispose() }
            elseif ($stream) { $stream.Dispose() }
        }
        $archCache[$Path] = $arch
        $arch
    }
    function Add-Root {
        param([string]$Path, [string]$Scope)
        $full = Get-FullPath $Path
        if (-not $full) { return }
        $full = $full.TrimEnd('\')
        if ($roots.ContainsKey($full)) { return }
        try {
            $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) { return }
            $roots[$full] = [pscustomobject]@{
                Path = $full; Scope = $Scope
                Architecture = Get-PEArchitecture (Join-Path $full 'dotnet.exe')
            }
        } catch {
            if ($Scope -eq 'Explicit' -or $_.CategoryInfo.Category -ne 'ObjectNotFound') {
                Add-Diagnostic 'DotNetRoots' $full $_.Exception.Message
            }
        }
    }
    function Read-XmlFile {
        param([string]$Path)
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create($Path, $settings)
        try {
            $doc = [Xml.XmlDocument]::new()
            $doc.XmlResolver = $null
            $doc.Load($reader)
            return ,$doc
        } finally { $reader.Dispose() }
    }
    function Get-AppRuntime {
        param([string]$Path)
        if (-not $Path) { return }
        if ($runtimeCache.ContainsKey($Path)) { return $runtimeCache[$Path] }
        $found = @()
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            $isConfig = $item.Name.EndsWith('.runtimeconfig.json', [StringComparison]::OrdinalIgnoreCase)
            $base = if ($isConfig) { $Path.Substring(0, $Path.Length - '.runtimeconfig.json'.Length) }
                    else { Join-Path $item.DirectoryName $item.BaseName }
            $config = $base + '.runtimeconfig.json'
            $binary = if ($isConfig) {
                if (Test-Path -LiteralPath ($base + '.exe') -PathType Leaf) { $base + '.exe' }
                elseif (Test-Path -LiteralPath ($base + '.dll') -PathType Leaf) { $base + '.dll' }
                else { $null }
            } else { $Path }
            $arch = Get-PEArchitecture $binary
            if ($isConfig -or (Test-Path -LiteralPath $config -PathType Leaf)) {
                $json = Get-Content -LiteralPath $config -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $options = $json.runtimeOptions
                if (-not $options) { throw 'No runtimeOptions object in runtimeconfig.json.' }
                $frameworks = @(@($options.framework) + @($options.frameworks) | Where-Object { $_ })
                $included = @($options.includedFrameworks | Where-Object { $_ })
                if ($frameworks.Count -and $included.Count) { throw 'Conflicting framework and includedFrameworks declarations.' }
                $deployment = if ($frameworks.Count) { 'SharedCandidate' } elseif ($included.Count) { 'SelfContained' } else { 'Unknown' }
                $entries = if ($frameworks.Count) { $frameworks } elseif ($included.Count) { $included } else { @($null) }
                $found = @(foreach ($fw in $entries) {
                    if ($fw -and (-not $fw.name -or -not $fw.version)) { throw 'Framework entry lacks a name or version.' }
                    $policy = if ($fw.rollForward) { $fw.rollForward } elseif ($options.rollForward) { $options.rollForward } else { 'Minor' }
                    $legacy = if ($null -ne $fw.rollForwardOnNoCandidateFx) { $fw.rollForwardOnNoCandidateFx } else { $options.rollForwardOnNoCandidateFx }
                    $patches = if ($null -ne $fw.applyPatches) { $fw.applyPatches } elseif ($null -ne $options.applyPatches) { $options.applyPatches } else { $true }
                    if ($null -ne $legacy) {
                        $policy = switch ([string]$legacy) { '0' { 'LatestPatch' }; '1' { 'Minor' }; '2' { 'Major' }; default { 'Unknown' } }
                    }
                    [pscustomobject]@{
                        Deployment = $deployment; UsesGlobal = $(if ($deployment -eq 'SelfContained') { $false } else { $null })
                        Framework = [string]$fw.name; Version = [string]$fw.version
                        Architecture = $arch; RuntimeConfigPath = $config; BinaryPath = $binary
                        Identity = $base; RollForward = [string]$policy; ApplyPatches = $patches
                        Evidence = $(if ($deployment -eq 'SelfContained') { 'Declared includedFrameworks' } else { 'Declared dependency; host/root not resolved' })
                    }
                })
                if (-not $binary -and -not (Get-SharedRoot $config)) { Add-Diagnostic 'RuntimeConfig' $config 'No matching EXE or DLL; may be a component configuration or stale file.' 'Unresolved' }
                if ($deployment -eq 'Unknown') { Add-Diagnostic 'RuntimeConfig' $config 'No shared or included frameworks declared.' 'Unresolved' }
            } else {
                try {
                    $null = [Reflection.AssemblyName]::GetAssemblyName($Path)
                    # Metadata alone cannot distinguish modern managed DLLs from
                    # classic Framework assemblies. Do not load the assembly.
                    $deployment = 'ManagedUnknown'; $framework = $null
                    $classic = $Path + '.config'
                    if (Test-Path -LiteralPath $classic -PathType Leaf) {
                        $doc = Read-XmlFile $classic
                        $supported = $doc.SelectSingleNode('/configuration/startup/supportedRuntime')
                        if ($supported -and ($supported.sku -like '.NETFramework*' -or $supported.version -eq 'v2.0.50727')) {
                            $deployment = 'Framework'; $framework = '.NET Framework'
                        }
                    }
                    $found = @([pscustomobject]@{
                        Deployment = $deployment; Framework = $framework; Version = $null
                        UsesGlobal = $null; Architecture = $arch; BinaryPath = $Path
                        Identity = $Path; Evidence = 'Managed assembly metadata; modern runtime requirement unavailable'
                    })
                } catch [BadImageFormatException] { }
            }
        } catch {
            Add-Diagnostic 'AppRuntime' $Path $_.Exception.Message
        }
        $runtimeCache[$Path] = $found
        $found
    }
    function Add-AppEvidence {
        param([string]$Source, [string]$Category, [string]$Path, [hashtable]$Context, [switch]$PolicyUnknown)
        foreach ($rt in @(Get-AppRuntime $Path)) {
            $identity = "$Category|$Source|$($rt.Identity)|$($rt.Framework)|$($rt.Version)|$PolicyUnknown|$($Context.Name)|$($Context.TaskPath)|$($Context.Site)|$($Context.AppPath)|$($Context.PhysicalPath)"
            if (-not $seenEvidence.Add($identity)) { continue }
            $data = @{}
            foreach ($p in $rt.PSObject.Properties) { $data[$p.Name] = $p.Value }
            foreach ($key in $Context.Keys) { $data[$key] = $Context[$key] }
            if ($PolicyUnknown) { $data.RollForward = 'Unknown'; $data.Evidence += '; launch overrides may apply' }
            $data.Path = $Path
            $data.AppName = [IO.Path]::GetFileName($rt.Identity)
            $results.Add((New-Result $Source $Category $data))
        }
    }
    function Resolve-LaunchTarget {
        param([string]$Command, [string]$Arguments, [string]$WorkingDirectory)
        if (-not $Command) { return }
        $commandText = [Environment]::ExpandEnvironmentVariables($Command.Trim())
        $exeText = $null; $tail = ''
        if ($commandText -match '^"(?<exe>[^"]+)"\s*(?<tail>.*)$') { $exeText = $Matches.exe; $tail = $Matches.tail }
        elseif ($commandText -match '^(?<exe>.*?\.exe)(?:\s+(?<tail>.*))?$') { $exeText = $Matches.exe; $tail = $Matches.tail }
        elseif ($commandText -match '^(?<exe>\S+)(?:\s+(?<tail>.*))?$') { $exeText = $Matches.exe; $tail = $Matches.tail }
        $argsText = ("$tail $Arguments").Trim()
        $baseName = [IO.Path]::GetFileName($exeText)
        if ($baseName -in @('dotnet','dotnet.exe')) {
            # Inspect app arguments, not dotnet.exe itself. Never execute the command.
            # An explicit runtimeconfig is authoritative even with dotnet exec.
            if ($argsText -match '(?:^|\s)--runtimeconfig(?:\s+|=)(?:"(?<q>[^"]+)"|(?<u>\S+))') {
                $target = if ($Matches.q) { $Matches.q } else { $Matches.u }
            } else {
                # Accept common host switches. Unknown syntax stays unresolved.
                $tokens = @([regex]::Matches($argsText, '"[^"]*"|\S+') | ForEach-Object { $_.Value.Trim('"') })
                $target = $null
                for ($i = 0; $i -lt $tokens.Count; $i++) {
                    if ($tokens[$i] -eq 'exec') { continue }
                    if ($tokens[$i] -in @('--roll-forward','--fx-version','--depsfile','--additionalprobingpath','--roll-forward-on-no-candidate-fx')) { $i++; continue }
                    if ($tokens[$i].StartsWith('-')) { break }
                    if ($tokens[$i] -match '\.(dll|exe)$') { $target = $tokens[$i] }
                    break
                }
            }
            return [pscustomobject]@{ Path = Get-FullPath $target $WorkingDirectory; PolicyUnknown = [bool]($argsText -match '(?:^|\s)--(?:roll-forward|fx-version)') }
        }
        [pscustomobject]@{ Path = Get-FullPath $exeText $WorkingDirectory; PolicyUnknown = $false }
    }

    # Discover machine, architecture-specific, registered and explicit installs.
    foreach ($parent in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique) {
        Add-Root (Join-Path $parent 'dotnet') 'Machine'
        Add-Root (Join-Path $parent 'dotnet\x64') 'Machine'
    }
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $hive = $null; $installedKey = $null
        try {
            $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $installedKey = $hive.OpenSubKey('SOFTWARE\dotnet\Setup\InstalledVersions')
            if ($installedKey) {
                foreach ($archName in $installedKey.GetSubKeyNames()) {
                    $archKey = $installedKey.OpenSubKey($archName)
                    try { if ($archKey) { Add-Root ([string]$archKey.GetValue('InstallLocation')) 'Registered' } }
                    finally { if ($archKey) { $archKey.Dispose() } }
                }
            }
        } catch { Add-Diagnostic 'RuntimeRegistry' ([string]$view) $_.Exception.Message }
        finally { if ($installedKey) { $installedKey.Dispose() }; if ($hive) { $hive.Dispose() } }
    }
    foreach ($path in $DotNetRoots) { Add-Root $path 'Explicit' }
    foreach ($name in @('DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT_X86','DOTNET_ROOT_ARM64','DOTNET_ROOT(x86)')) {
        Add-Root ([Environment]::GetEnvironmentVariable($name)) 'Environment'
    }
    foreach ($cmd in @(Get-Command dotnet.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
        Add-Root (Split-Path -Parent $cmd.Source) 'PATH'
    }

    # Inventory directories even when CLI execution is disabled. Canonical path
    # identity avoids duplicate rows from CLI and filesystem observations.
    $installedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    function Add-Installed {
        param([string]$Source, [string]$Type, [string]$Name, [string]$Version, [string]$Path, $Root)
        $full = Get-FullPath $Path
        if (-not $full -or -not $installedPaths.Add($full)) { return }
        $arch = $Root.Architecture
        if ($Type -eq 'Runtime' -and $Name -eq 'Microsoft.NETCore.App') { $arch = Get-PEArchitecture (Join-Path $full 'coreclr.dll') }
        $results.Add((New-Result $Source 'InstalledRuntime' @{
            Type = $Type; Name = $Name; Version = $Version; Path = $full
            Architecture = $arch; Root = $Root.Path; Scope = $Root.Scope
        }))
    }
    function Invoke-DotNetList {
        param([string]$Cli, [string]$Argument)
        $process = [Diagnostics.Process]::new()
        try {
            $process.StartInfo = [Diagnostics.ProcessStartInfo]::new()
            $process.StartInfo.FileName = $Cli
            $process.StartInfo.Arguments = $Argument
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            $null = $process.Start()
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit($CliTimeoutSeconds * 1000)) {
                $process.Kill()
                Add-Diagnostic 'dotnet CLI' $Cli "Timed out after $CliTimeoutSeconds seconds ($Argument)."
                return
            }
            if ($process.ExitCode -ne 0) { Add-Diagnostic 'dotnet CLI' $Cli "Exit code $($process.ExitCode) ($Argument)."; return }
            # Bound redirected stream waits too (a child could retain a handle).
            if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { Add-Diagnostic 'dotnet CLI' $Cli 'Output stream did not close.'; return }
            $stdout.Result -split '\r?\n'
        } catch { Add-Diagnostic 'dotnet CLI' $Cli $_.Exception.Message }
        finally { $process.Dispose() }
    }
    foreach ($root in @($roots.Values | Sort-Object Path)) {
        Write-Verbose "Inventorying $($root.Path)"
        foreach ($subfolder in @('shared','sdk')) {
            $base = Join-Path $root.Path $subfolder
            if (-not (Test-Path -LiteralPath $base)) { continue }
            try {
                foreach ($item in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop)) {
                    if ($subfolder -eq 'sdk') { Add-Installed 'Filesystem' 'SDK' 'SDK' $item.Name $item.FullName $root; continue }
                    foreach ($version in @(Get-ChildItem -LiteralPath $item.FullName -Directory -ErrorAction Stop)) {
                        if ($version.Name -match '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$') {
                            Add-Installed 'Filesystem' 'Runtime' $item.Name $version.Name $version.FullName $root
                        }
                    }
                }
            } catch { Add-Diagnostic 'RuntimeFolders' $base $_.Exception.Message }
        }
        $cli = Join-Path $root.Path 'dotnet.exe'
        if (-not $SkipDotNetCli -and (Test-Path -LiteralPath $cli -PathType Leaf)) {
            foreach ($line in @(Invoke-DotNetList $cli '--list-runtimes')) {
                if ($line -match '^(?<name>\S+)\s+(?<version>\S+)\s+\[(?<path>.+)\]$') {
                    $name = $Matches.name; $version = $Matches.version; $path = Join-Path $Matches.path $version
                    if (Test-UnderPath $path (Join-Path $root.Path 'shared')) { Add-Installed 'dotnet CLI' 'Runtime' $name $version $path $root }
                }
            }
            foreach ($line in @(Invoke-DotNetList $cli '--list-sdks')) {
                if ($line -match '^(?<version>\S+)\s+\[(?<path>.+)\]$') {
                    $version = $Matches.version; $path = Join-Path $Matches.path $version
                    if (Test-UnderPath $path (Join-Path $root.Path 'sdk')) { Add-Installed 'dotnet CLI' 'SDK' 'SDK' $version $path $root }
                }
            }
        }
    }

    # Preserve the current user's global tool inventory without asserting AnyCPU.
    if ($env:USERPROFILE) {
        $toolRoot = Join-Path $env:USERPROFILE '.dotnet\tools'
        try {
            if (Test-Path -LiteralPath $toolRoot -ErrorAction Stop) {
                foreach ($tool in @(Get-ChildItem -LiteralPath $toolRoot -File -Filter '*.exe' -ErrorAction Stop)) {
                    $results.Add((New-Result 'Global .NET tools' 'InstalledRuntime' @{
                        Type = 'Tool'; Name = $tool.BaseName; Version = $tool.VersionInfo.ProductVersion
                        Architecture = Get-PEArchitecture $tool.FullName
                        Path = $tool.FullName; Root = $toolRoot; Scope = 'CurrentUser'
                    }))
                }
            }
        } catch { Add-Diagnostic 'GlobalTools' $toolRoot $_.Exception.Message }
    }

    function Resolve-FrameworkRelease {
        param([int]$Release)
        switch ($Release) {
            { $_ -ge 533320 } { '4.8.1'; break }
            { $_ -ge 528040 } { '4.8'; break }
            { $_ -ge 461808 } { '4.7.2'; break }
            { $_ -ge 461308 } { '4.7.1'; break }
            { $_ -ge 460798 } { '4.7'; break }
            { $_ -ge 394802 } { '4.6.2'; break }
            { $_ -ge 394254 } { '4.6.1'; break }
            { $_ -ge 393295 } { '4.6'; break }
            { $_ -ge 379893 } { '4.5.2'; break }
            { $_ -ge 378675 } { '4.5.1'; break }
            { $_ -ge 378389 } { '4.5'; break }
            default { 'Unknown' }
        }
    }
    if (-not $SkipFrameworkRegistry) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            if (-not [Environment]::Is64BitOperatingSystem -and $view -eq [Microsoft.Win32.RegistryView]::Registry64) { continue }
            $hive = $null
            try {
                $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
                foreach ($subkey in @('v4\Full','v4\Client','v3.5','v3.0\Setup','v2.0.50727','v1.1.4322')) {
                    $key = $hive.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\$subkey")
                    try {
                        if (-not $key) { continue }
                        $release = $key.GetValue('Release')
                        $version = $key.GetValue('Version')
                        $install = $key.GetValue('Install', $key.GetValue('InstallSuccess', 0))
                        if (-not $release -and [int]$install -ne 1) { continue }
                        $results.Add((New-Result 'Registry' 'FrameworkRegistry' @{
                            Name = $subkey; Version = $(if ($release) { Resolve-FrameworkRelease $release } else { $version })
                            Release = $release; RegistryView = [string]$view
                        }))
                    } finally { if ($key) { $key.Dispose() } }
                }
            } catch { Add-Diagnostic 'FrameworkRegistry' ([string]$view) $_.Exception.Message }
            finally { if ($hive) { $hive.Dispose() } }
        }
    }
    if (-not $SkipUninstallEntries) {
        foreach ($keyPath in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )) {
            if (-not (Test-Path -LiteralPath $keyPath)) { continue }
            $entryErrors = @()
            foreach ($item in @(Get-ItemProperty -Path ($keyPath + '\*') -ErrorAction SilentlyContinue -ErrorVariable entryErrors)) {
                if ($item.DisplayName -notmatch '\.NET|ASP\.NET|Desktop Runtime|Hosting Bundle') { continue }
                if ($item.DisplayName -match 'Windows SDK|Extension SDK|Targeting Pack|Templates|Toolset|Manifest|Native SDK|AppHost Pack') { continue }
                $results.Add((New-Result 'Uninstall' 'InstalledProduct' @{
                    Name = $item.DisplayName; Version = $item.DisplayVersion
                    Publisher = $item.Publisher; RegistryPath = $item.PSPath
                }))
            }
            foreach ($errorRecord in $entryErrors) { Add-Diagnostic 'Uninstall' $keyPath $errorRecord.Exception.Message }
        }
    }

    if (-not $SkipRunningProcesses) {
        Write-Verbose 'Inspecting loaded modules; access failures will be reported.'
        $processErrors = @()
        foreach ($processItem in @(Get-Process -ErrorAction SilentlyContinue -ErrorVariable processErrors)) {
            try {
                $modules = @($processItem.Modules)
                $observed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($module in $modules) {
                    $modulePath = $module.FileName
                    $framework = $null; $version = $null; $runtimePath = $null; $deployment = $null
                    $knownRoot = Get-SharedRoot $modulePath
                    if ($modulePath -match '^(?<directory>.*\\shared\\(?<framework>[^\\]+)\\(?<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?))\\') {
                        $framework = $Matches.framework; $version = $Matches.version; $runtimePath = $Matches.directory
                        $deployment = if ($knownRoot) { 'Shared' } else { 'PrivateShared' }
                    } elseif ($module.ModuleName -ieq 'coreclr.dll') {
                        $framework = 'Microsoft.NETCore.App'; $version = $module.FileVersionInfo.ProductVersion
                        $runtimePath = Split-Path -Parent $modulePath; $deployment = 'LocalRuntime'
                    } elseif ($module.ModuleName -in @('clr.dll','mscorwks.dll')) {
                        $framework = '.NET Framework'; $version = $module.FileVersionInfo.ProductVersion
                        $runtimePath = Split-Path -Parent $modulePath; $deployment = 'Framework'
                    } else { continue }
                    if (-not $observed.Add("$framework|$runtimePath")) { continue }
                    $results.Add((New-Result 'Process' 'RunningProcess' @{
                        ProcessName = $processItem.ProcessName; PID = $processItem.Id
                        Framework = $framework; Version = $version; Deployment = $deployment
                        UsesGlobal = [bool]$knownRoot; RuntimePath = $runtimePath; LoadedFrom = $modulePath
                        Architecture = Get-PEArchitecture $modulePath; Path = $processItem.Path
                        Evidence = 'Observed loaded module; applies to this PID only'
                    }))
                }
            } catch { Add-Diagnostic 'RunningProcesses' ("PID {0} ({1})" -f $processItem.Id, $processItem.ProcessName) $_.Exception.Message }
        }
        foreach ($errorRecord in $processErrors) { Add-Diagnostic 'RunningProcesses' '' $errorRecord.Exception.Message }
    }

    # One traversal for config and assembly scans. Queue all explicit AppRoots
    # before their descendants so overlapping roots preserve their depth budgets.
    if (-not $SkipRuntimeConfigs -or -not $SkipAssemblyScan) {
        $queue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($rootPath in @($AppRoots | Where-Object { $_ } | Select-Object -Unique)) {
            $full = Get-FullPath $rootPath
            if ($full) { $queue.Enqueue([pscustomobject]@{ Path = $full; Depth = 0 }) }
            else { Add-Diagnostic 'AppRoots' $rootPath 'An absolute, resolvable path is required.' }
        }
        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()
            if (-not $seenDirectories.Add($current.Path)) { continue }
            try {
                $directory = Get-Item -LiteralPath $current.Path -Force -ErrorAction Stop
                if (-not $directory.PSIsContainer) { throw 'AppRoot is not a directory.' }
                if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    Add-Diagnostic 'AppScan' $current.Path 'Directory reparse point was not followed.' 'Excluded'
                    continue
                }
                $stats.Directories++
                $children = @(Get-ChildItem -LiteralPath $current.Path -Force -ErrorAction Stop)
                foreach ($child in $children) {
                    if ($child.PSIsContainer) {
                        $runtimeInternal = $false
                        foreach ($installRoot in $roots.Values) {
                            foreach ($subfolder in @('shared','sdk','host','packs')) {
                                if (Test-UnderPath $child.FullName (Join-Path $installRoot.Path $subfolder)) { $runtimeInternal = $true; break }
                            }
                            if ($runtimeInternal) { break }
                        }
                        if ($runtimeInternal) { continue }
                        if ($current.Depth -ge $MaxDepth) { Add-Diagnostic 'AppScan' $child.FullName "Maximum depth $MaxDepth reached." 'Excluded'; continue }
                        $queue.Enqueue([pscustomobject]@{ Path = $child.FullName; Depth = $current.Depth + 1 })
                    } else {
                        $stats.Files++
                        if ($child.Name -like '*.runtimeconfig.json' -and -not $SkipRuntimeConfigs) {
                            $stats.Configs++
                            Add-AppEvidence 'runtimeconfig.json' 'AppRuntimeConfig' $child.FullName @{ AppPath = $child.DirectoryName }
                        } elseif ($child.Extension -in @('.exe','.dll') -and -not $SkipAssemblyScan) {
                            $stats.Binaries++
                            Add-AppEvidence 'AssemblyScan' 'AppBinary' $child.FullName @{}
                        }
                    }
                }
            } catch { Add-Diagnostic 'AppScan' $current.Path $_.Exception.Message }
            if (($stats.Directories % 250) -eq 0) { Write-Verbose ("Scanned {0} directories, {1} files." -f $stats.Directories, $stats.Files) }
        }
    }

    if (-not $SkipServices) {
        $serviceErrors = @()
        foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue -ErrorVariable serviceErrors)) {
            # SCM does not provide a service-specific working directory here.
            $launch = Resolve-LaunchTarget $service.PathName '' ''
            if (-not $launch.Path) {
                Add-Diagnostic 'Services' $service.Name 'Launch target could not be resolved statically.' 'Unresolved'; continue
            }
            Add-AppEvidence 'Service' 'Service' $launch.Path @{
                Name = $service.Name; DisplayName = $service.DisplayName; State = $service.State; StartMode = $service.StartMode
            } -PolicyUnknown:$launch.PolicyUnknown
        }
        foreach ($errorRecord in $serviceErrors) { Add-Diagnostic 'Services' '' $errorRecord.Exception.Message }
    }
    if (-not $SkipScheduledTasks) {
        try {
            foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
                foreach ($action in $task.Actions) {
                    if (-not $action.Execute) { Add-Diagnostic 'ScheduledTasks' ($task.TaskPath + $task.TaskName) 'Non-executable task action; target was not inspected.' 'Unresolved'; continue }
                    $launch = Resolve-LaunchTarget $action.Execute $action.Arguments $action.WorkingDirectory
                    if (-not $launch.Path) { Add-Diagnostic 'ScheduledTasks' ($task.TaskPath + $task.TaskName) 'Launch target or working directory could not be resolved.' 'Unresolved'; continue }
                    Add-AppEvidence 'ScheduledTask' 'ScheduledTask' $launch.Path @{
                        TaskPath = $task.TaskPath; Name = $task.TaskName; State = [string]$task.State; Executable = $launch.Path
                    } -PolicyUnknown:$launch.PolicyUnknown
                }
            }
        } catch { Add-Diagnostic 'ScheduledTasks' '' $_.Exception.Message }
    }
    if (-not $SkipIIS) {
        $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
        if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
            $appHost = Join-Path $env:SystemRoot 'Sysnative\inetsrv\config\applicationHost.config'
        }
        try {
            if (Test-Path -LiteralPath $appHost -ErrorAction Stop) {
                $doc = Read-XmlFile $appHost
                foreach ($pool in $doc.SelectNodes('/configuration/system.applicationHost/applicationPools/add')) {
                    $results.Add((New-Result 'IIS' 'AppPool' @{
                        Name = $pool.name
                        ManagedRuntimeVersion = $(if ($pool.HasAttribute('managedRuntimeVersion')) { $pool.GetAttribute('managedRuntimeVersion') } else { '(inherited/default)' })
                        PipelineMode = $pool.managedPipelineMode
                    }))
                }
                foreach ($site in $doc.SelectNodes('/configuration/system.applicationHost/sites/site')) {
                    foreach ($app in $site.SelectNodes('application')) {
                        foreach ($vdir in $app.SelectNodes('virtualDirectory')) {
                            $physical = Get-FullPath $vdir.physicalPath
                            if (-not $physical) { Add-Diagnostic 'IIS' $site.name 'Physical path could not be resolved.' 'Unresolved'; continue }
                            $webConfig = Join-Path $physical 'web.config'
                            try {
                                if (-not (Test-Path -LiteralPath $webConfig -ErrorAction Stop)) { continue }
                                $webDoc = Read-XmlFile $webConfig
                                foreach ($anc in $webDoc.SelectNodes('/configuration/system.webServer/aspNetCore | /configuration/location/system.webServer/aspNetCore')) {
                                    $launch = Resolve-LaunchTarget $anc.processPath $anc.arguments $physical
                                    if (-not $launch.Path) { Add-Diagnostic 'IIS' $webConfig 'ASP.NET Core launch target could not be resolved.' 'Unresolved'; continue }
                                    $hasOverrides = $launch.PolicyUnknown -or [bool]$anc.SelectSingleNode('environmentVariables/environmentVariable[starts-with(@name,"DOTNET_")]')
                                    Add-AppEvidence 'IIS' 'AspNetCoreApp' $launch.Path @{
                                        Site = $site.name; AppPath = $app.path; PhysicalPath = $physical; HostingModel = $anc.hostingModel
                                    } -PolicyUnknown:$hasOverrides
                                }
                            } catch { Add-Diagnostic 'IIS' $webConfig $_.Exception.Message }
                        }
                    }
                }
            }
        } catch { Add-Diagnostic 'IIS' $appHost $_.Exception.Message }
    }

    # Installed shared frameworks and SDK hosts can themselves require runtimes.
    # Read their direct declarations instead of inventing an ASP.NET -> Core patch.
    foreach ($installed in @($results | Where-Object { $_.Category -eq 'InstalledRuntime' -and $_.Type -in @('Runtime','SDK') })) {
        $configName = if ($installed.Type -eq 'SDK') { 'dotnet.runtimeconfig.json' } else { $installed.Name + '.runtimeconfig.json' }
        $configPath = Join-Path $installed.Path $configName
        if (Test-Path -LiteralPath $configPath -PathType Leaf) {
            Add-AppEvidence 'Installed component' 'RuntimeDependency' $configPath @{
                Name = $installed.Name; ParentVersion = $installed.Version
                ParentRoot = $installed.Root; Architecture = $installed.Architecture
            }
        }
    }

    # This is a conservative compatibility-range check, not the host's full
    # binding algorithm. Never label the lowest requested version an exact pin
    # just because it is installed. Do not infer removal safety from no matches.
    function Test-PotentialDependency {
        param($Consumer, $Installed)
        if ($Consumer.Framework -ne $Installed.Name) { return $false }
        if ($Consumer.Architecture -in @('x86','x64','arm64') -and $Installed.Architecture -in @('x86','x64','arm64') -and $Consumer.Architecture -ne $Installed.Architecture) { return $false }
        if ($Consumer.ParentRoot -and $Consumer.ParentRoot -ne $Installed.Root) { return $false }
        if ($Consumer.RollForward -eq 'Unknown') { return $true }
        $requested = $null; $available = $null
        if ($Consumer.Version -notmatch '^\d+\.\d+\.\d+$' -or $Installed.Version -notmatch '^\d+\.\d+\.\d+$') { return $true }
        if (-not [version]::TryParse($Consumer.Version, [ref]$requested) -or -not [version]::TryParse($Installed.Version, [ref]$available)) { return $true }
        if ($available -lt $requested) { return $false }
        switch ($Consumer.RollForward) {
            'Disable' { return $available -eq $requested }
            'LatestPatch' {
                if ($Consumer.ApplyPatches -eq $false) { return $available -eq $requested }
                return $available.Major -eq $requested.Major -and $available.Minor -eq $requested.Minor
            }
            { $_ -in @('Minor','LatestMinor') } { return $available.Major -eq $requested.Major }
            { $_ -in @('Major','LatestMajor') } { return $true }
            default { return $true }
        }
    }
    $consumers = @($results | Where-Object { $_.Deployment -eq 'SharedCandidate' })
    $processes = @($results | Where-Object Category -eq 'RunningProcess')
    $unknownCount = @($results | Where-Object { $_.Deployment -in @('Unknown','ManagedUnknown') }).Count
    $skipped = @(
        if ($SkipDotNetCli) { 'DotNetCli' }
        if ($SkipFrameworkRegistry) { 'FrameworkRegistry' }
        if ($SkipUninstallEntries) { 'UninstallEntries' }
        if ($SkipRunningProcesses) { 'RunningProcesses' }
        if ($SkipRuntimeConfigs) { 'RuntimeConfigs' }
        if ($SkipServices) { 'Services' }
        if ($SkipScheduledTasks) { 'ScheduledTasks' }
        if ($SkipIIS) { 'IIS' }
        if ($SkipAssemblyScan) { 'AssemblyScan' }
    )
    foreach ($row in @($results | Where-Object { $_.Category -eq 'InstalledRuntime' -and $_.Type -eq 'Runtime' } | Sort-Object -Property @('Name','Architecture','Root','Version'))) {
        if ($TargetVersion -and $row.Version -notmatch ('^' + [regex]::Escape($TargetVersion) + '(?:\.|-|\+|$)')) { continue }
        $live = @($processes | Where-Object { $_.RuntimePath -eq $row.Path } | Select-Object -ExpandProperty PID -Unique).Count
        $possible = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($consumer in $consumers) {
            if (Test-PotentialDependency $consumer $row) { $null = $possible.Add([string]$consumer.Identity) }
        }
        # The host binds the HIGHEST installed patch of a major.minor band, so an older patch
        # is superseded unless a consumer pins an exact patch (RollForward Disable / Unknown
        # launch policy / applyPatches false). Patch-aware verdict carried over from checker V4.2.
        $rowVersion = $null; $supersededBy = $null; $pinned = 0
        if ([version]::TryParse(($row.Version -replace '[-+].*$', ''), [ref]$rowVersion)) {
            $supersededBy = $results | Where-Object {
                    $_.Category -eq 'InstalledRuntime' -and $_.Type -eq 'Runtime' -and $_.Name -eq $row.Name -and
                    $_.Architecture -eq $row.Architecture -and $_.Root -eq $row.Root
                } | ForEach-Object {
                    $other = $null
                    if ([version]::TryParse(($_.Version -replace '[-+].*$', ''), [ref]$other) -and
                        $other.Major -eq $rowVersion.Major -and $other.Minor -eq $rowVersion.Minor -and $other -gt $rowVersion) {
                        [pscustomobject]@{ Text = $_.Version; Sort = $other }
                    }
                } | Sort-Object Sort | Select-Object -Last 1 -ExpandProperty Text
            foreach ($consumer in $consumers) {
                if (($consumer.RollForward -in @('Disable', 'Unknown') -or $consumer.ApplyPatches -eq $false) -and
                    (Test-PotentialDependency $consumer $row)) { $pinned++ }
            }
        }
        $verdict = if ($live) { 'Observed use - keep' }
                   elseif ($supersededBy -and -not $pinned) { "Superseded by $supersededBy - removal candidate" }
                   elseif ($possible.Count) { 'Potential dependency - review' }
                   else { 'No evidence found - verify before removal' }
        $results.Add((New-Result 'Summary' 'RuntimeSummary' @{
            Runtime = $row.Name; Version = $row.Version; Architecture = $row.Architecture
            Root = $row.Root; Scope = $row.Scope; Path = $row.Path
            SupersededBy = $supersededBy; PinnedConsumers = $pinned
            ObservedProcesses = $live; PotentialConsumers = $possible.Count
            Verdict = $verdict; DiagnosticCount = $diagnostics.Count; UnknownEvidenceCount = $unknownCount
        }))
    }
    $results.Add((New-Result 'Inventory' 'ScanCoverage' @{
        StartedUtc = $started.ToString('o'); CompletedUtc = [DateTime]::UtcNow.ToString('o')
        DurationSeconds = [math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 2)
        ComputerName = $env:COMPUTERNAME; PowerShellVersion = [string]$PSVersionTable.PSVersion
        Is64BitProcess = [Environment]::Is64BitProcess; AppRoots = @($AppRoots | Where-Object { $_ })
        SkippedSources = $skipped; DiagnosticCount = $diagnostics.Count; UnknownEvidenceCount = $unknownCount
        DirectoriesVisited = $stats.Directories; FilesVisited = $stats.Files
        ConfigFilesInspected = $stats.Configs; BinariesInspected = $stats.Binaries; MaxDepth = $MaxDepth
        RemovalSafetyEstablished = $false
        Limitations = @(
            'A bounded snapshot cannot prove that a runtime is unused.'
            'PotentialConsumers are compatible version ranges, not resolved bindings or live apps.'
            'Launch environments, custom hosts, wrappers, single-file apps and containers are not fully resolved.'
            'Managed assemblies without a runtimeconfig do not identify an exact runtime requirement.'
            'IIS inherited/external configuration and other users may require additional inspection.'
            'Shared runtime/SDK/host/packs trees are excluded from app traversal; direct component runtimeconfigs are inspected separately.'
            'UsesGlobal is true only for loaded modules under a discovered shared root; consult Scope for machine vs custom roots.'
        )
    }))
    foreach ($diagnostic in $diagnostics) { $results.Add($diagnostic) }
    if ($PassThru) { return $results.ToArray() }

    function Show-Section {
        param([string]$Title, [object[]]$Rows, [string[]]$Columns)
        Write-Host "`n$Title"
        if (-not $Rows.Count) { Write-Host '  (none found)'; return }
        $Rows | Format-Table -Property $Columns -AutoSize | Out-String -Width 240 | Write-Host
    }
    Show-Section 'Installed .NET runtimes and SDKs' @($results | Where-Object Category -eq 'InstalledRuntime') @('Type','Name','Version','Architecture','Scope','Path')
    Show-Section '.NET Framework registry' @($results | Where-Object Category -eq 'FrameworkRegistry') @('Name','Version','RegistryView','Release')
    Show-Section '.NET installed products' @($results | Where-Object Category -eq 'InstalledProduct') @('Name','Version','Publisher')
    Show-Section 'Observed running processes' $processes @('ProcessName','PID','Framework','Version','Deployment','LoadedFrom')
    Show-Section 'Application and component dependencies' @($results | Where-Object { $_.Category -in @('AppRuntimeConfig','Service','ScheduledTask','AspNetCoreApp','RuntimeDependency') }) @('Category','AppName','Framework','Version','Architecture','Deployment','Path')
    if (-not $SkipAssemblyScan) {
        Show-Section 'Binary scan: declared modern runtime dependencies' @($results | Where-Object { $_.Category -eq 'AppBinary' -and $_.Framework -and $_.Framework -ne '.NET Framework' }) @('AppName','Framework','Version','Deployment','Path')
    }
    Show-Section 'IIS application pools' @($results | Where-Object Category -eq 'AppPool') @('Name','ManagedRuntimeVersion','PipelineMode')
    Show-Section 'Runtime usage assessment' @($results | Where-Object Category -eq 'RuntimeSummary') @('Runtime','Version','Architecture','ObservedProcesses','PotentialConsumers','Verdict','Root')
    if ($diagnostics.Count) {
        Write-Warning ("{0} scan gaps or unresolved items. First 20 shown; -PassThru includes all diagnostics." -f $diagnostics.Count)
        Show-Section 'Scan diagnostics (first 20)' @($diagnostics | Select-Object -First 20) @('Source','Status','Path','Message')
    }
    Write-Host ("Visited {0} directories / {1} files. Unclassified managed or config evidence: {2}." -f $stats.Directories, $stats.Files, $unknownCount)
    if ($skipped.Count) { Write-Host ('Skipped: ' + ($skipped -join ', ')) }
    Write-Host 'ObservedProcesses counts PIDs loading that exact runtime directory.'
    Write-Host 'PotentialConsumers counts distinct declared dependencies in its allowed version range, including installed components.'
    Write-Host 'Superseded means a newer patch of the same major.minor is installed and no observed process or exact-patch pin uses this one.'
    Write-Host 'No evidence found is not proof of removal safety. Review gaps and test affected workloads before uninstalling.'
    Write-Host 'Use -PassThru for full paths, evidence, summaries and coverage; -SkipAssemblyScan for a faster scan.'
}

#endregion

#region -------------------- Remove: Remove-OldDotNet (EOL removal, dry run unless -Armed) --------------------

<#
.SYNOPSIS
    Thoroughly uninstalls ALL kinds of modern .NET (.NET Core 1.x-3.x and .NET 5/6/7/8/9...)
    BELOW a given version, keeping that version and everything newer.

.DESCRIPTION
    The official "dotnet-core-uninstall" tool misses installs because:
      * Its filter only accepts WiX "Burn" .exe bundle entries and ignores every raw-MSI component
        (Host, Host FX Resolver, Templates, Toolset, AppHost/Targeting packs, ANCM, MSI runtimes/SDKs).
      * One 'remove' call only sweeps one target x architecture at a time.
      * Without --force it silently keeps versions it thinks Visual Studio needs.
      * Each tool build has a hard-coded version ceiling; VS-managed installs are never touched.
      * winget (used to auto-install it) is often not usable in the SYSTEM context.

    This function instead enumerates the Windows uninstall (ARP) registry DIRECTLY across BOTH the
    64-bit and WOW6432Node (x86) views and silently uninstalls each modern-.NET component below the
    threshold, in a dependency-safe order. It optionally sweeps orphaned version folders and can also
    run dotnet-core-uninstall as a redundant second pass.

    ORPHANED ARP ENTRIES
    --------------------
    ARP is NOT authoritative on its own. Windows Installer can complete a removal successfully
    (files deleted, product state absent, MSI log says "Removal completed successfully") and still
    leave the Uninstall registry key behind. Such a ghost:
      * is re-detected as a removal candidate on EVERY subsequent run, forever;
      * makes the re-issued "msiexec /x" return 1605 ("not installed"), which this script counts as
        success -- so the run always reports success while changing nothing;
      * counts as "still installed" in the $stillInstalled guard, permanently blocking the leftover
        folder and registry sweeps for that version.

    Every MSI-style candidate is therefore validated against the Windows Installer product database
    before being treated as real. Ghosts are reported and their stale keys deleted.

    The product-state probe uses MsiQueryProductStateW (msi.dll) via P/Invoke, with a Windows
    Installer registry lookup as an independent second opinion. Both paths are logged. If BOTH
    probes fail to give a usable answer the entry is treated as INSTALLED (fail closed) and a WARN
    is written -- a live product is never skipped, and the failure is never silent.

    .NET Framework (4.x / 3.5) is a Windows OS component and is ALWAYS excluded, even though 4.8
    numerically compares as "below 8.0.28".

    SAFETY MODEL:
      * By DEFAULT the function is a safe DRY RUN and changes nothing.
      * Pass -Armed to actually perform removals. Armed runs require an elevated session
        (Administrator or SYSTEM); a check enforces this.
      * -WhatIf always forces preview, even if -Armed is also supplied.

.PARAMETER RemoveBelow
    Version threshold. Anything strictly below is removed; this version and everything newer
    (including all 9.x / 10.x) is kept. Default: 8.0.28.

.PARAMETER Armed
    Actually perform removals. WITHOUT -Armed the function runs as a safe preview / dry run
    (equivalent to -WhatIf) and changes nothing. -Armed is required for any destructive action,
    including unattended SYSTEM runs. If -WhatIf is also supplied it wins and the run stays a preview.

.PARAMETER CleanLeftoverFolders
    Also delete orphaned <version> folders left under Program Files\dotnet after uninstall.

.PARAMETER CleanLeftoverRegistry
    Also prune stale "installed versions" markers left in the registry under
    HKLM\SOFTWARE\dotnet\Setup\InstalledVersions (both the native and WOW6432Node views). These are
    the entries that make `dotnet --list-runtimes` / `--list-sdks` and MSBuild SDK resolution report
    runtimes/SDKs whose files are already gone. Only version-named markers strictly below the
    threshold that no longer correspond to a still-registered product are removed; the single
    sharedhost/hostfxr markers and anything under the Windows Installer database are left untouched.

.PARAMETER KeepOrphanedArpEntries
    Do NOT delete stale Add/Remove Programs keys whose MSI product is no longer installed. By default
    such ghosts are removed (when armed) because they otherwise reappear as phantom candidates on
    every run and suppress the leftover sweeps. Orphans are always EXCLUDED from the uninstall list
    regardless of this switch -- it only controls whether the dead key itself is deleted.

.PARAMETER ShowProductStateProbe
    Log the result of every product-state probe (which method answered, and the raw INSTALLSTATE).
    Use this when orphan detection is not behaving as expected.

.PARAMETER AlsoRunUninstallTool
    Run dotnet-core-uninstall as a supplementary pass. Locates it on PATH or in Program Files.
    Mostly redundant after the ARP sweep. Combine with -InstallUninstallTool to auto-install it.

.PARAMETER InstallUninstallTool
    If -AlsoRunUninstallTool is set, -Armed is set, and dotnet-core-uninstall is not already present,
    attempt to install it via winget (best-effort; winget is typically unavailable under SYSTEM).
    Off by default -- the ARP sweep does not need this tool. Never runs during a dry run.

.PARAMETER IncludeUserProfiles
    Also clean per-user "private" installs (from the dotnet-install script, which have NO uninstaller
    and NO registry entry). Scans every user profile's %LocalAppData%\Microsoft\dotnet and .dotnet
    folders and removes version folders below the threshold. Implies folder cleanup for those roots.

.PARAMETER Scope
    'All' (default) removes every family incl. SDKs. 'RuntimesOnly' keeps SDKs/Templates/Toolset/packs.

.PARAMETER LogPath
    Transcript log path. Defaults to %WINDIR%\Temp\Remove-OldDotNet_<timestamp>.log.

.EXAMPLE
    # Safe preview (this is the default -- no -Armed means nothing is changed):
    Remove-OldDotNet -RemoveBelow 8.0.28 -CleanLeftoverFolders

.EXAMPLE
    # Diagnose orphan detection without changing anything:
    Remove-OldDotNet -RemoveBelow 8.0.28 -ShowProductStateProbe

.EXAMPLE
    # Actual cleanup (must be elevated or SYSTEM):
    Remove-OldDotNet -RemoveBelow 8.0.28 -CleanLeftoverFolders -CleanLeftoverRegistry -Armed

.NOTES
    Default is a non-destructive dry run. Destructive runs need -Armed AND an elevated/SYSTEM session
    (SYSTEM satisfies the Administrator role check). Dot-source or paste this file, then call it.
#>
function Remove-OldDotNet {
    [CmdletBinding(SupportsShouldProcess)]   # gives -WhatIf; ConfirmImpact left at default so a
    param(                                   # non-interactive run never prompts.
        [version]$RemoveBelow = '8.0.28',
        [switch] $Armed,
        [switch] $CleanLeftoverFolders,
        [switch] $CleanLeftoverRegistry,
        [switch] $KeepOrphanedArpEntries,
        [switch] $ShowProductStateProbe,
        [switch] $AlsoRunUninstallTool,
        [switch] $InstallUninstallTool,
        [switch] $IncludeUserProfiles,
        [ValidateSet('All', 'RuntimesOnly')]
        [string] $Scope = 'All',
        [string] $LogPath
    )

    # ==============================================================================================
    #  Setup
    # ==============================================================================================
    if (-not $LogPath) {
        $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
        $LogPath = Join-Path $env:WINDIR "Temp\Remove-OldDotNet_$stamp.log"
    }

    # Deny-list: names that must NEVER be uninstalled by this tool (safety wins over the include list).
    # 'Uninstall Tool' guards the dotnet-core-uninstall tool itself (name contains ".NET Core SDK").
    # '.NET Standard' is a frozen build-time spec (max 2.1); its version is on a different scale and
    # only *looks* below the threshold -- removing it breaks netstandard builds for no cleanup gain.
    $DenyPattern = '\.NET Framework\b|\.NET Standard|Visual Studio|\bMono\b|Developer Pack|Reference Assemblies|Windows SDK|Uninstall Tool'

    # Matches a bare ProductCode-style Uninstall subkey name.
    $GuidKeyPattern = '^\{[0-9A-Fa-f-]{36}\}$'

    $ArpHiveNative = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $ArpHiveWow    = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    function Write-Log {
        param([string]$Message, [string]$Level = 'INFO')
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'OK'    { Write-Host $line -ForegroundColor Green }
            'STEP'  { Write-Host $line -ForegroundColor Cyan }
            'KEEP'  { Write-Host $line -ForegroundColor DarkGray }
            'GHOST' { Write-Host $line -ForegroundColor Magenta }
            'PROBE' { Write-Host $line -ForegroundColor DarkCyan }
            default { Write-Host $line -ForegroundColor Gray }
        }
        # -WhatIf:$false so the transcript is still written (and not echoed as noise) during preview runs.
        try { Add-Content -LiteralPath $LogPath -Value $line -WhatIf:$false -ErrorAction Stop } catch { }
    }

    # ==============================================================================================
    #  Product-state probing
    # ==============================================================================================

    # ----------------------------------------------------------------------------------------------
    #  Compile the msi.dll P/Invoke shim once per session.
    #
    #  WHY NOT COM: the previous implementation used
    #      $inst.GetType().InvokeMember('ProductState','GetProperty',$null,$inst,@($code))
    #  ProductState is a PARAMETERISED property on the RCW, and late-bound InvokeMember against
    #  GetType() often fails to bind it, throwing instead of returning a value. The catch then
    #  fell through to "installed" and orphan detection silently never fired. P/Invoke has no
    #  such binding ambiguity.
    #
    #  MsiQueryProductState returns INSTALLSTATE:
    #     -1 INSTALLSTATE_NOTUSED / invalid product code
    #     -2 INSTALLSTATE_BADCONFIG
    #     -3 INSTALLSTATE_INVALIDARG
    #      1 INSTALLSTATE_ADVERTISED
    #      2 INSTALLSTATE_ABSENT
    #      5 INSTALLSTATE_DEFAULT  <- installed for the current user/machine
    # ----------------------------------------------------------------------------------------------
    $script:MsiShimReady = $false
    function Initialize-MsiShim {
        if ($script:MsiShimReady) { return $true }
        if ('DotNetCleanup.Msi' -as [type]) { $script:MsiShimReady = $true; return $true }
        try {
            Add-Type -ErrorAction Stop -Namespace 'DotNetCleanup' -Name 'Msi' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("msi.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
public static extern int MsiQueryProductStateW(string szProduct);
'@
            $script:MsiShimReady = $true
            return $true
        }
        catch {
            Write-Log "Could not compile the msi.dll probe: $($_.Exception.Message)" 'WARN'
            return $false
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Convert a ProductCode GUID to its Windows Installer "packed"/"squished" form, which is how
    #  the installer database keys its Products subkeys under
    #  HKLM\...\Installer\UserData\<SID>\Products\<packed>.
    #
    #  Packing = reverse the first three GUID fields, then swap each byte-pair of the last two.
    #  This is a READ-ONLY lookup used purely as a second opinion; nothing under Installer\ is
    #  ever written to.
    # ----------------------------------------------------------------------------------------------
    function ConvertTo-PackedProductCode {
        param([string]$ProductCode)
        $g = $ProductCode.Trim('{', '}') -replace '-', ''
        if ($g.Length -ne 32) { return $null }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append($g.Substring(0, 8).ToCharArray()[7..0] -join '')    # field 1 reversed
        [void]$sb.Append($g.Substring(8, 4).ToCharArray()[3..0] -join '')    # field 2 reversed
        [void]$sb.Append($g.Substring(12, 4).ToCharArray()[3..0] -join '')   # field 3 reversed
        foreach ($start in 16, 20, 24, 28) {                                 # remaining byte-pairs swapped
            $chunk = $g.Substring($start, 4)
            [void]$sb.Append($chunk[1]); [void]$sb.Append($chunk[0])
            [void]$sb.Append($chunk[3]); [void]$sb.Append($chunk[2])
        }
        return $sb.ToString()
    }

    # ----------------------------------------------------------------------------------------------
    #  Second-opinion probe: is the ProductCode present in the Windows Installer product database?
    #  Returns $true / $false / $null (could not determine).
    # ----------------------------------------------------------------------------------------------
    function Test-MsiProductInRegistry {
        param([string]$ProductCode)
        $packed = ConvertTo-PackedProductCode $ProductCode
        if (-not $packed) { return $null }
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
            'HKLM:\SOFTWARE\Classes\Installer\Products'
        )
        $sawRoot = $false
        foreach ($r in $roots) {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            $sawRoot = $true
            if ($r -like '*UserData') {
                foreach ($sid in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
                    $p = Join-Path $sid.PSPath "Products\$packed\InstallProperties"
                    if (Test-Path -LiteralPath $p) { return $true }
                }
            }
            else {
                if (Test-Path -LiteralPath (Join-Path $r $packed)) { return $true }
            }
        }
        if (-not $sawRoot) { return $null }
        return $false
    }

    # ----------------------------------------------------------------------------------------------
    #  Authoritative "is this MSI product actually installed?" check.
    #
    #  Non-GUID keys (Burn bundles register under their own bundle GUID and are NOT MSI products)
    #  always return $true -- they are outside this check's remit.
    #
    #  FAILS CLOSED: if neither probe yields a usable answer, returns $true (installed) AND logs a
    #  WARN. A live product is never skipped, and the fallback is never silent.
    # ----------------------------------------------------------------------------------------------
    function Test-MsiProductInstalled {
        param([string]$ProductCode, [string]$ContextName = '')

        if ($ProductCode -notmatch $GuidKeyPattern) { return $true }

        $apiState  = $null
        $apiAnswer = $null
        if (Initialize-MsiShim) {
            try {
                $apiState = [DotNetCleanup.Msi]::MsiQueryProductStateW($ProductCode)
                # Only 5 (INSTALLSTATE_DEFAULT) counts as installed. 1 (advertised) has no payload.
                # -3 INSTALLSTATE_INVALIDARG means we asked a malformed question -> no answer.
                if ($apiState -ne -3) { $apiAnswer = ($apiState -eq 5) }
            }
            catch {
                Write-Log "msi.dll probe threw for $ProductCode ($ContextName): $($_.Exception.Message)" 'WARN'
            }
        }

        $regAnswer = Test-MsiProductInRegistry $ProductCode

        if ($ShowProductStateProbe) {
            Write-Log ("PROBE {0} {1} -> MsiQueryProductState={2} ({3})  RegistryDb={4}" -f `
                       $ProductCode, $ContextName,
                       $(if ($null -eq $apiState) { 'n/a' } else { $apiState }),
                       $(if ($null -eq $apiAnswer) { 'undetermined' } elseif ($apiAnswer) { 'installed' } else { 'absent' }),
                       $(if ($null -eq $regAnswer) { 'undetermined' } elseif ($regAnswer) { 'present' } else { 'absent' })) 'PROBE'
        }

        # The API is authoritative when it answered.
        if ($null -ne $apiAnswer) { return $apiAnswer }
        # Otherwise fall back to the installer database.
        if ($null -ne $regAnswer) {
            Write-Log ("msi.dll probe unavailable for {0} ({1}); using installer database -> {2}" -f `
                       $ProductCode, $ContextName, $(if ($regAnswer) { 'installed' } else { 'absent' })) 'WARN'
            return $regAnswer
        }

        Write-Log ("Could not determine product state for {0} ({1}); assuming INSTALLED (fail closed)." -f `
                   $ProductCode, $ContextName) 'WARN'
        return $true
    }

    # ----------------------------------------------------------------------------------------------
    #  Is this ARP entry a ghost (key present, MSI product gone)?
    #
    #  Applies to BOTH registry views. The earlier Native-only restriction was over-cautious: the
    #  bitness concern belongs to the COM object, not to MsiQueryProductState, which resolves
    #  per-machine products regardless of the calling process's bitness. The registry second opinion
    #  is likewise bitness-independent (it reads the 64-bit UserData hive directly).
    # ----------------------------------------------------------------------------------------------
    function Test-OrphanedArpEntry {
        param($Entry)
        if ($Entry.BundleCachePath)               { return $false }   # Burn bundle, not an MSI product
        if ($Entry.Key -notmatch $GuidKeyPattern) { return $false }   # not a ProductCode-keyed entry
        return (-not (Test-MsiProductInstalled -ProductCode $Entry.Key -ContextName $Entry.DisplayName))
    }

    # ----------------------------------------------------------------------------------------------
    #  Delete a stale ARP key whose product is gone. Gated by -WhatIf.
    #  Verifies the key is actually gone afterwards rather than trusting Remove-Item's silence.
    # ----------------------------------------------------------------------------------------------
    function Remove-OrphanedArpEntry {
        param($Entry)
        $hivePath = if ($Entry.Hive -eq 'WOW6432Node') { $ArpHiveWow } else { $ArpHiveNative }
        $keyPath  = Join-Path $hivePath $Entry.Key

        if (-not (Test-Path -LiteralPath $keyPath)) {
            Write-Log "Orphaned ARP key already gone: $($Entry.Key)" 'INFO'
            return 'AlreadyGone'
        }
        if (-not $PSCmdlet.ShouldProcess("$($Entry.DisplayName)  [stale ARP key $($Entry.Key) in $($Entry.Hive)]",
                                         'Remove orphaned uninstall registration')) {
            return 'WhatIf'
        }
        try {
            Remove-Item -LiteralPath $keyPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Log "Failed to remove orphaned ARP key '$($Entry.Key)': $($_.Exception.Message)" 'ERROR'
            return 'Failed'
        }
        if (Test-Path -LiteralPath $keyPath) {
            Write-Log "Orphaned ARP key still present after removal: $keyPath" 'ERROR'
            return 'Failed'
        }
        Write-Log "Removed orphaned ARP key: $($Entry.Key)  ($($Entry.DisplayName)) [$($Entry.Hive)]" 'OK'
        return 'Success'
    }

    # ==============================================================================================
    #  ARP enumeration and classification
    # ==============================================================================================

    function Get-DotNetArpEntries {
        $out = New-Object System.Collections.Generic.List[object]
        $hives = @(
            @{ Path = $ArpHiveNative; Hive = 'Native' },
            @{ Path = $ArpHiveWow;    Hive = 'WOW6432Node' }
        )
        foreach ($h in $hives) {
            if (-not (Test-Path $h.Path)) { continue }
            foreach ($k in (Get-ChildItem -Path $h.Path -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                if (-not $p) { continue }
                $out.Add([pscustomobject]@{
                    Key                  = $k.PSChildName
                    Hive                 = $h.Hive
                    DisplayName          = $p.DisplayName
                    DisplayVersion       = $p.DisplayVersion
                    UninstallString      = $p.UninstallString
                    QuietUninstallString = $p.QuietUninstallString
                    BundleCachePath      = $p.BundleCachePath
                })
            }
        }
        return $out
    }

    # ----------------------------------------------------------------------------------------------
    #  Classify a DisplayName into a .NET component family + uninstall order.
    #  Order = dependents first, shared host last, so nothing is left blocked / orphaned.
    #  NOTE: case order matters (e.g. "Host FX Resolver" before "Host", "Windows Desktop"/"Hosting"
    #  before bare "Runtime"/"Host").
    # ----------------------------------------------------------------------------------------------
    function Get-DotNetComponent {
        param([string]$Name)
        switch -Regex ($Name) {
            'Windows Server Hosting|Hosting Bundle' { return [pscustomobject]@{ Family = 'HostingBundle';  Order = 5 } }
            '\.NET( Core)? SDK'                     { return [pscustomobject]@{ Family = 'SDK';            Order = 1 } }
            'Templates'                             { return [pscustomobject]@{ Family = 'Templates';      Order = 2 } }
            'Toolset'                               { return [pscustomobject]@{ Family = 'Toolset';        Order = 2 } }
            '(AppHost|Targeting) Pack'              { return [pscustomobject]@{ Family = 'Pack';           Order = 2 } }
            'ASP\.NET Core'                         { return [pscustomobject]@{ Family = 'AspNetCore';     Order = 3 } }
            'Windows Desktop Runtime'               { return [pscustomobject]@{ Family = 'WindowsDesktop'; Order = 4 } }
            'Host FX Resolver'                      { return [pscustomobject]@{ Family = 'HostFxr';        Order = 7 } }
            '\.NET( Core)? Runtime'                 { return [pscustomobject]@{ Family = 'Runtime';        Order = 6 } }
            '\.NET( Core)? Host'                    { return [pscustomobject]@{ Family = 'Host';           Order = 8 } }
            default                                 { return $null }
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Extract the marketing .NET version. Prefer the version embedded in the DisplayName
    #  (e.g. "Microsoft .NET Runtime - 8.0.13 (x64)"), fall back to DisplayVersion. Returns [version]
    #  or $null. A 3-part match is required so a bare "8.0" can't be mistaken for "8.0.0".
    # ----------------------------------------------------------------------------------------------
    function Get-DotNetVersion {
        param([string]$DisplayName, [string]$DisplayVersion)
        $ver = $null
        if ($DisplayName -match '(\d+\.\d+\.\d+(?:\.\d+)?)') {
            if ([version]::TryParse($Matches[1], [ref]$ver)) { return $ver }
        }
        if ($DisplayVersion) {
            if ($DisplayVersion -match '(\d+\.\d+\.\d+(?:\.\d+)?)') {
                if ([version]::TryParse($Matches[1], [ref]$ver)) { return $ver }
            }
        }
        return $null
    }

    # ----------------------------------------------------------------------------------------------
    #  Normalize a [version] to major.minor.build for cross-source key comparison.
    #  ARP entries usually carry a 3-part version, but a 4-part DisplayVersion fallback
    #  (e.g. 8.0.13.33208) must still match a 3-part folder name (8.0.13) in the "still installed"
    #  guard -- otherwise a live install's folder/marker could be swept.
    # ----------------------------------------------------------------------------------------------
    function Get-VersionKey {
        param([version]$V)
        if ($null -eq $V) { return $null }
        $build = if ($V.Build -lt 0) { 0 } else { $V.Build }
        return ('{0}.{1}.{2}' -f $V.Major, $V.Minor, $build)
    }

    # ----------------------------------------------------------------------------------------------
    #  Build the silent uninstall command for an entry.
    #  MSI  -> msiexec /x {ProductCode} /qn /norestart /L*v <log>
    #  Burn -> "<bundle.exe>" /uninstall /quiet /norestart
    # ----------------------------------------------------------------------------------------------
    function Get-SilentUninstallCommand {
        param($Item)

        $us  = $Item.UninstallString
        $qus = $Item.QuietUninstallString

        # Classify MSI vs Burn bundle.
        # CAUTION: "the Uninstall subkey is a GUID" is NOT sufficient to call something an MSI --
        # Burn bundles (e.g. the Windows Desktop Runtime / Hosting Bundle) ALSO register under a
        # GUID subkey. Running "msiexec /x {bundleGUID}" on a bundle returns 1605 ("not installed"),
        # which looks like success but leaves the bundle in place. The decisive signals instead:
        #   * BundleCachePath present  -> definitely a Burn bundle; use its cached .exe /uninstall.
        #   * UninstallString invokes msiexec (and NO bundle cache) -> a real MSI.
        #   * otherwise (an .exe uninstaller, no msiexec) -> treat as a bundle .exe.
        $mentionsMsiexec = ($us -match '(?i)msiexec') -or ($qus -match '(?i)msiexec')
        $isMsi           = $mentionsMsiexec -and -not $Item.BundleCachePath

        if ($isMsi) {
            # Prefer the ProductCode from the msiexec command line; fall back to a GUID subkey name.
            $guid = $null
            if     ($us  -match '(\{[0-9A-Fa-f-]{36}\})') { $guid = $Matches[1] }
            elseif ($qus -match '(\{[0-9A-Fa-f-]{36}\})') { $guid = $Matches[1] }
            elseif ($Item.Key -match $GuidKeyPattern)     { $guid = $Item.Key }
            if (-not $guid) { return $null }

            $safe   = ($Item.DisplayName -replace '[^\w\.\-]', '_')
            $msiLog = Join-Path $env:WINDIR "Temp\Remove-OldDotNet_msi_$safe.log"
            return [pscustomobject]@{
                Type      = 'MSI'
                FilePath  = Join-Path $env:WINDIR 'System32\msiexec.exe'
                Arguments = "/x $guid /qn /norestart /L*v `"$msiLog`""
            }
        }

        # Burn bundle .exe -- prefer QuietUninstallString (points at the cached installer with args).
        $src = if ($qus) { $qus } else { $us }
        if (-not $src) { return $null }

        $exe = $null; $argStr = ''
        if     ($src -match '^\s*"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $argStr = $Matches[2] }
        elseif ($src -match '^\s*(\S+)\s*(.*)$')     { $exe = $Matches[1]; $argStr = $Matches[2] }
        if (-not $exe) { return $null }

        if ($argStr -notmatch '(?i)/uninstall') { $argStr = "$argStr /uninstall" }
        if ($argStr -notmatch '(?i)/quiet')     { $argStr = "$argStr /quiet" }
        if ($argStr -notmatch '(?i)/norestart') { $argStr = "$argStr /norestart" }

        return [pscustomobject]@{
            Type      = 'Bundle'
            FilePath  = $exe
            Arguments = $argStr.Trim()
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Run the uninstall, interpret exit codes, retry on 1618 (install-in-progress).
    #  After a successful MSI removal, verify the ARP key actually went away -- Windows Installer
    #  sometimes leaves it behind, and an unnoticed ghost resurfaces as a phantom candidate next run.
    # ----------------------------------------------------------------------------------------------
    function Invoke-SilentUninstall {
        param($Item)

        $cmd = Get-SilentUninstallCommand $Item
        if (-not $cmd) {
            Write-Log "No usable uninstall command for: $($Item.DisplayName)" 'ERROR'
            return [pscustomobject]@{ ExitCode = $null; Result = 'NoCommand' }
        }
        if ($cmd.Type -eq 'Bundle' -and -not (Test-Path -LiteralPath $cmd.FilePath)) {
            Write-Log "Bundle installer missing (Package Cache cleared?): $($cmd.FilePath)" 'WARN'
            return [pscustomobject]@{ ExitCode = $null; Result = 'BundleExeMissing' }
        }

        $successCodes = @(0, 1605, 3010, 1641)   # ok / not-installed / reboot-required / reboot-initiated
        $attempt = 0; $max = 3; $exit = $null
        do {
            $attempt++
            try {
                # Splat so an empty argument string never trips Start-Process's non-empty binding.
                $spArgs = @{
                    FilePath    = $cmd.FilePath
                    Wait        = $true
                    PassThru    = $true
                    WindowStyle = 'Hidden'
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($cmd.Arguments)) {
                    $spArgs.ArgumentList = $cmd.Arguments
                }
                $p = Start-Process @spArgs
                $exit = $p.ExitCode
            }
            catch {
                Write-Log "Launch failed for '$($Item.DisplayName)': $($_.Exception.Message)" 'ERROR'
                return [pscustomobject]@{ ExitCode = $null; Result = 'LaunchError' }
            }
            if ($exit -eq 1618 -and $attempt -lt $max) {
                Write-Log "Another install in progress (1618); retry $attempt/$max in 30s..." 'WARN'
                Start-Sleep -Seconds 30
            }
        } while ($exit -eq 1618 -and $attempt -lt $max)

        $result = if ($successCodes -contains $exit) { 'Success' } else { 'Failed' }
        Write-Log ("Uninstalled '{0}' [{1}] -> exit {2} ({3})" -f $Item.DisplayName, $cmd.Type, $exit, $result) `
                  ($(if ($result -eq 'Success') { 'OK' } else { 'ERROR' }))

        # Post-removal ghost check: product gone but key still there.
        $ghostCleaned = $null
        if ($result -eq 'Success' -and (Test-OrphanedArpEntry $Item)) {
            Write-Log "ARP key survived a successful removal: $($Item.DisplayName)" 'GHOST'
            if ($KeepOrphanedArpEntries) {
                Write-Log '  leaving it in place (-KeepOrphanedArpEntries)' 'WARN'
                $ghostCleaned = 'Kept'
            }
            else {
                $ghostCleaned = Remove-OrphanedArpEntry $Item
            }
        }

        return [pscustomobject]@{ ExitCode = $exit; Result = $result; GhostCleanup = $ghostCleaned }
    }

    # ----------------------------------------------------------------------------------------------
    #  Build the set of classified .NET candidate entries (any version).
    #  Ghost entries (ARP key present, MSI product absent) are separated out; they are never
    #  uninstall candidates.
    # ----------------------------------------------------------------------------------------------
    function Get-DotNetCandidates {
        $result  = New-Object System.Collections.Generic.List[object]
        $orphans = New-Object System.Collections.Generic.List[object]
        # Dedup by uninstall Key: an MSI product (Key == ProductCode GUID) is often visible in BOTH
        # the Native and WOW6432Node views. It's one product -- one msiexec /x removes it globally --
        # so processing it once avoids double-counting and a redundant 1605 "not installed" pass.
        # NOTE: dedup happens AFTER the ghost split, so a ghost registered in both views still gets
        # both dead keys deleted.
        $seenKeys = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

        foreach ($e in (Get-DotNetArpEntries)) {
            $name = $e.DisplayName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($name -notmatch '^Microsoft (\.NET|ASP\.NET Core|Windows Desktop Runtime)\b') { continue }
            if ($name -match $DenyPattern) { continue }               # never touch Framework / VS / etc.

            $comp = Get-DotNetComponent $name
            if (-not $comp) { continue }
            if ($Scope -eq 'RuntimesOnly' -and $comp.Family -in @('SDK', 'Templates', 'Toolset', 'Pack')) { continue }

            $ver = Get-DotNetVersion -DisplayName $name -DisplayVersion $e.DisplayVersion
            if (-not $ver) { Write-Log "Skipping (no parseable version): $name" 'WARN'; continue }

            # Ghost check BEFORE dedup and before the entry is ever treated as a real product.
            if (Test-OrphanedArpEntry $e) {
                Write-Log ("ORPHAN  {0}  v{1}  -- product not installed (stale ARP key {2} in {3})" -f `
                           $name, $ver, $e.Key, $e.Hive) 'GHOST'
                $orphans.Add([pscustomobject]@{
                    DisplayName = $name; Family = $comp.Family; Version = $ver
                    Key = $e.Key; Hive = $e.Hive; BundleCachePath = $e.BundleCachePath
                })
                continue
            }

            if ($e.Key -and -not $seenKeys.Add($e.Key)) {
                Write-Log "Skipping duplicate registration (already seen key): $name [$($e.Hive)]" 'INFO'
                continue
            }

            $arch = if     ($name -match '\((x64|x86|arm64)\)') { $Matches[1] }
                    elseif ($e.Hive -eq 'WOW6432Node')          { 'x86' }
                    else                                        { 'x64' }

            $result.Add([pscustomobject]@{
                DisplayName          = $name
                Family               = $comp.Family
                Order                = $comp.Order
                Version              = $ver
                Arch                 = $arch
                Key                  = $e.Key
                Hive                 = $e.Hive
                UninstallString      = $e.UninstallString
                QuietUninstallString = $e.QuietUninstallString
                BundleCachePath      = $e.BundleCachePath
            })
        }
        return [pscustomobject]@{ Candidates = $result; Orphans = $orphans }
    }

    # ==============================================================================================
    #  Leftover folder / registry sweeps
    # ==============================================================================================

    function Remove-FolderSafely {
        param([string]$Path, [string]$Desc)
        if ($PSCmdlet.ShouldProcess($Desc, 'Remove folder')) {
            try {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
                Write-Log "Removed leftover folder: $Path" 'OK'
            }
            catch { Write-Log "Failed to remove folder '$Path': $($_.Exception.Message)" 'ERROR' }
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Sweep <version> folders below the threshold under the given dotnet roots.
    #  $StillInstalled = hashtable of version-strings that are STILL registered (machine-wide pass);
    #  a folder is only removed if its owning product is gone -- never orphan a live registration.
    #  For per-user roots (no registry) pass an empty hashtable so pure version comparison applies.
    # ----------------------------------------------------------------------------------------------
    function Remove-LeftoverDotNetFolders {
        param([version]$Threshold, [string[]]$Roots, [hashtable]$StillInstalled)

        # Folders on a different version scale that must never be swept (mirror the ARP deny-list).
        # NETStandard.Library.Ref is frozen at 2.1.0 and backs the kept .NET Standard targeting pack.
        $FolderDenyPattern = 'NETStandard'

        $verFolders = @(
            'shared\Microsoft.NETCore.App'
            'shared\Microsoft.AspNetCore.App'
            'shared\Microsoft.WindowsDesktop.App'
            'sdk'
            'templates'
        )

        foreach ($root in $Roots) {
            if (-not $root -or -not (Test-Path $root)) { continue }

            # Regular version-stamped folders (incl. every packs\<packname>\<version>).
            $targets = New-Object System.Collections.Generic.List[string]
            foreach ($vf in $verFolders) { $targets.Add((Join-Path $root $vf)) }
            $packsRoot = Join-Path $root 'packs'
            if (Test-Path $packsRoot) {
                foreach ($pk in (Get-ChildItem $packsRoot -Directory -ErrorAction SilentlyContinue)) {
                    $targets.Add($pk.FullName)
                }
            }

            foreach ($t in $targets) {
                if (-not (Test-Path $t)) { continue }
                if ($t -match $FolderDenyPattern) { continue }   # protect .NET Standard ref pack, etc.
                foreach ($d in (Get-ChildItem $t -Directory -ErrorAction SilentlyContinue)) {
                    $v = $null
                    if (-not [version]::TryParse(($d.Name -replace '-.*$', ''), [ref]$v)) { continue }
                    if ($v -lt $Threshold -and -not $StillInstalled.ContainsKey((Get-VersionKey $v))) {
                        Remove-FolderSafely $d.FullName "$($d.FullName)  (v$v < $Threshold)"
                    }
                }
            }

            # host\fxr: the shared host launches every kept runtime -- NEVER remove the highest fxr.
            $fxr = Join-Path $root 'host\fxr'
            if (Test-Path $fxr) {
                $parsed = New-Object System.Collections.Generic.List[object]
                foreach ($d in (Get-ChildItem $fxr -Directory -ErrorAction SilentlyContinue)) {
                    $vv = $null
                    if ([version]::TryParse(($d.Name -replace '-.*$', ''), [ref]$vv)) {
                        $parsed.Add([pscustomobject]@{ Dir = $d; V = $vv })
                    }
                }
                if ($parsed.Count) {
                    $maxV = ($parsed | Sort-Object V | Select-Object -Last 1).V
                    # Only protect the highest fxr if a KEPT runtime (>= threshold) actually needs it.
                    # If every fxr is below the threshold, nothing is kept, so all may be removed.
                    $protectMax = ($maxV -ge $Threshold)
                    foreach ($pp in $parsed) {
                        if ($pp.V -lt $Threshold -and -not ($protectMax -and $pp.V -eq $maxV) -and
                            -not $StillInstalled.ContainsKey((Get-VersionKey $pp.V))) {
                            Remove-FolderSafely $pp.Dir.FullName "$($pp.Dir.FullName)  (host\fxr v$($pp.V) < $Threshold)"
                        }
                    }
                }
            }
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Prune version-named MARKERS (values and/or subkeys) under one registry key.
    #  A marker is removed only when its name parses as a version, is strictly below the threshold,
    #  and that version is NOT still registered as an installed product. Gated by -WhatIf.
    # ----------------------------------------------------------------------------------------------
    function Remove-DotNetRegVersionMarkers {
        param([string]$KeyPath, [version]$Threshold, [hashtable]$StillInstalled, [string]$Label)

        if (-not (Test-Path -LiteralPath $KeyPath)) { return }

        # (a) version-named VALUES (e.g. ...\sharedfx\Microsoft.NETCore.App has "6.0.16"=dword:1).
        $props = Get-ItemProperty -LiteralPath $KeyPath -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($vn in $props.PSObject.Properties.Name) {
                if ($vn -like 'PS*') { continue }                                   # skip provider noise
                $v = $null
                if (-not [version]::TryParse(($vn -replace '-.*$', ''), [ref]$v)) { continue }
                if ($v -lt $Threshold -and -not $StillInstalled.ContainsKey((Get-VersionKey $v))) {
                    if ($PSCmdlet.ShouldProcess("$Label value '$vn'", 'Remove .NET registry marker')) {
                        try {
                            Remove-ItemProperty -LiteralPath $KeyPath -Name $vn -Force -ErrorAction Stop
                            Write-Log "Removed registry marker: $Label\$vn  (v$v < $Threshold)" 'OK'
                        }
                        catch { Write-Log "Failed registry marker '$Label\$vn': $($_.Exception.Message)" 'ERROR' }
                    }
                }
            }
        }

        # (b) version-named SUBKEYS (some layouts store each version as its own subkey).
        foreach ($sub in (Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue)) {
            $v = $null
            if (-not [version]::TryParse(($sub.PSChildName -replace '-.*$', ''), [ref]$v)) { continue }
            if ($v -lt $Threshold -and -not $StillInstalled.ContainsKey((Get-VersionKey $v))) {
                if ($PSCmdlet.ShouldProcess("$Label subkey '$($sub.PSChildName)'", 'Remove .NET registry marker')) {
                    try {
                        Remove-Item -LiteralPath $sub.PSPath -Recurse -Force -ErrorAction Stop
                        Write-Log "Removed registry subkey: $Label\$($sub.PSChildName)  (v$v < $Threshold)" 'OK'
                    }
                    catch { Write-Log "Failed registry subkey '$Label\$($sub.PSChildName)': $($_.Exception.Message)" 'ERROR' }
                }
            }
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Delete a registry key only if it has no remaining subkeys AND no non-provider values.
    #  Used to clear ghost sharedfx\<app> containers left empty after their versions were pruned.
    # ----------------------------------------------------------------------------------------------
    function Remove-EmptyRegistryKey {
        param([string]$KeyPath, [string]$Label)
        if (-not (Test-Path -LiteralPath $KeyPath)) { return }
        $subCount = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue).Count
        $valCount = 0
        $p = Get-ItemProperty -LiteralPath $KeyPath -ErrorAction SilentlyContinue
        if ($p) { $valCount = @($p.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' }).Count }
        if ($subCount -eq 0 -and $valCount -eq 0) {
            if ($PSCmdlet.ShouldProcess("$Label (empty)", 'Remove empty .NET registry key')) {
                try {
                    Remove-Item -LiteralPath $KeyPath -Force -ErrorAction Stop
                    Write-Log "Removed empty registry key: $Label" 'OK'
                }
                catch { Write-Log "Failed empty registry key '$Label': $($_.Exception.Message)" 'ERROR' }
            }
        }
    }

    # ----------------------------------------------------------------------------------------------
    #  Sweep stale .NET "installed versions" markers below the threshold.
    #  Authoritative location modern .NET writes OUTSIDE Add/Remove Programs:
    #    HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\<arch>\{sharedfx\<app>, sdk}
    #  Both the native and WOW6432Node (x86) views are scanned. $StillInstalled protects any version
    #  that is still a registered product (so a version kept on purpose is never orphaned).
    #
    #  Deliberately NOT touched:
    #    * sharedhost / hostfxr single 'Version' markers -- they track the one kept host.
    #    * anything under Classes\Installer or Installer\UserData -- the Windows Installer database is
    #      owned by msiexec; hand-editing it corrupts MSI state. (This script READS those keys as a
    #      product-state second opinion, but never writes to them.)
    #    * .NET Framework NDP keys -- an OS component (already excluded everywhere else).
    # ----------------------------------------------------------------------------------------------
    function Remove-LeftoverDotNetRegistry {
        param([version]$Threshold, [hashtable]$StillInstalled)

        $roots = @(
            'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions',
            'HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions'
        )
        $sharedFxNames = @('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App', 'Microsoft.WindowsDesktop.App')

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($arch in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {   # x64 / x86 / arm64
                $archName = $arch.PSChildName
                $archPath = Join-Path $root $archName

                foreach ($fx in $sharedFxNames) {
                    $fxPath = Join-Path $archPath "sharedfx\$fx"
                    Remove-DotNetRegVersionMarkers -KeyPath $fxPath -Threshold $Threshold `
                        -StillInstalled $StillInstalled -Label "$archName\sharedfx\$fx"
                    Remove-EmptyRegistryKey -KeyPath $fxPath -Label "$archName\sharedfx\$fx"
                }

                $sdkPath = Join-Path $archPath 'sdk'
                Remove-DotNetRegVersionMarkers -KeyPath $sdkPath -Threshold $Threshold `
                    -StillInstalled $StillInstalled -Label "$archName\sdk"
            }
        }
    }

    # ==============================================================================================
    #  Supplementary tool / profile helpers
    # ==============================================================================================

    function Get-DotNetUninstallTool {
        $cmd = Get-Command 'dotnet-core-uninstall' -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        $roots = @($env:ProgramFiles)
        if (${env:ProgramFiles(x86)}) { $roots += ${env:ProgramFiles(x86)} }
        foreach ($root in $roots) {
            $p = Join-Path $root 'dotnet-core-uninstall\dotnet-core-uninstall.exe'
            if (Test-Path $p) { return $p }
        }
        return $null
    }

    # Resolves via the DesktopAppInstaller Appx package, which works when winget isn't on PATH.
    function Get-WingetExe {
        $cmd = Get-Command 'winget' -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        try {
            $appPath = (Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
                        Select-Object -Last 1).InstallLocation
        } catch { $appPath = $null }
        if (-not $appPath) { return $null }
        return (Get-ChildItem -Path $appPath -Filter 'winget.exe' -Recurse -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName -First 1)
    }

    # Authoritative source for real user profile paths: ProfileList in the registry.
    function Get-UserProfilePaths {
        $out = New-Object System.Collections.Generic.List[string]
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($k in (Get-ChildItem $pl -ErrorAction SilentlyContinue)) {
            $path = (Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $path) { continue }
            $ok = $false
            try { $ok = Test-Path -LiteralPath $path -ErrorAction Stop } catch { $ok = $false }
            if ($ok) { $out.Add($path) }
        }
        return $out
    }

    # ==============================================================================================
    #  MAIN
    # ==============================================================================================

    # --- Arming / elevation -----------------------------------------------------------------------
    # Everything destructive below is gated by ShouldProcess / $WhatIfPreference. We set that
    # variable explicitly here so the run's behaviour depends ONLY on -Armed / an explicit -WhatIf
    # on THIS call -- never on an ambient session preference. (A session with $WhatIfPreference
    # already $true would otherwise silently neuter -Armed: the run reports Armed=True/WhatIf=True
    # and removes nothing.)
    #
    # We must tell an explicit per-call -WhatIf apart from an inherited global $WhatIfPreference.
    # Only a bound -WhatIf shows up in $PSBoundParameters; -WhatIf:$false is treated as "not preview".
    $explicitWhatIf = $PSBoundParameters.ContainsKey('WhatIf') -and [bool]$PSBoundParameters['WhatIf']

    if ($explicitWhatIf) {
        # Explicit -WhatIf always wins: force preview even if -Armed was also supplied.
        $WhatIfPreference = $true
        Write-Log 'MODE: DRY RUN (-WhatIf). Nothing will be changed.' 'STEP'
    }
    elseif ($Armed) {
        # Armed and no explicit -WhatIf: actually perform, overriding any ambient session
        # $WhatIfPreference = $true so the removals aren't silently skipped.
        $WhatIfPreference = $false
    }
    else {
        # Default = safe dry run.
        $WhatIfPreference = $true
        Write-Log 'MODE: DRY RUN (no -Armed). Nothing will be changed. Add -Armed to perform removals.' 'STEP'
    }

    # Only an ACTUAL removal needs elevation. SYSTEM satisfies the Administrator role check.
    if ($Armed -and -not $WhatIfPreference) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] `
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log 'Armed mode requires an elevated session (Administrator or SYSTEM). Aborting.' 'ERROR'
            Write-Error 'Armed mode requires an elevated PowerShell session.'
            return
        }
        Write-Log 'MODE: ARMED. Removals will be performed.' 'WARN'
    }

    Write-Log ("=== Remove-OldDotNet start === RemoveBelow={0}  Scope={1}  Armed={2}  WhatIf={3}  KeepOrphans={4}" -f `
               $RemoveBelow, $Scope, $Armed, $WhatIfPreference, $KeepOrphanedArpEntries) 'STEP'
    Write-Log "Log file: $LogPath"
    Write-Log ("Process: PID {0}, {1}-bit PowerShell {2}" -f `
               $PID, $(if ([Environment]::Is64BitProcess) { 64 } else { 32 }), $PSVersionTable.PSVersion) 'INFO'
    if (-not (Initialize-MsiShim)) {
        Write-Log 'msi.dll product-state probe unavailable; falling back to the installer database for orphan detection.' 'WARN'
    }

    $scan       = Get-DotNetCandidates
    $candidates = $scan.Candidates
    $orphans    = $scan.Orphans

    $results = New-Object System.Collections.Generic.List[object]

    # --- Stale ARP keys whose product is already gone ---------------------------------------------
    if ($orphans.Count) {
        Write-Log ("Found {0} orphaned ARP entr(y/ies) -- product uninstalled, registration left behind." -f `
                   $orphans.Count) 'GHOST'
        if ($KeepOrphanedArpEntries) {
            Write-Log 'Leaving orphaned ARP keys in place (-KeepOrphanedArpEntries). They are still excluded from removal.' 'WARN'
            foreach ($o in ($orphans | Sort-Object Family, Version)) {
                $results.Add([pscustomobject]@{
                    DisplayName = $o.DisplayName; Family = $o.Family; Arch = 'n/a'
                    Version = $o.Version; Action = 'RemoveOrphanArp'; ExitCode = $null; Result = 'Kept'
                })
            }
        }
        else {
            foreach ($o in ($orphans | Sort-Object Family, Version)) {
                $res = Remove-OrphanedArpEntry $o
                $results.Add([pscustomobject]@{
                    DisplayName = $o.DisplayName; Family = $o.Family; Arch = 'n/a'
                    Version = $o.Version; Action = 'RemoveOrphanArp'; ExitCode = $null; Result = $res
                })
            }
        }
    }

    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Log 'No installed modern .NET components found in the registry. Nothing to uninstall.' 'WARN'
    }
    else {
        $toRemove = @($candidates | Where-Object { $_.Version -lt $RemoveBelow })
        $kept     = @($candidates | Where-Object { $_.Version -ge $RemoveBelow })

        Write-Log ("Found {0} installed .NET component(s): {1} below {2} (remove), {3} kept." -f `
                   $candidates.Count, $toRemove.Count, $RemoveBelow, $kept.Count) 'STEP'
        foreach ($k in ($kept | Sort-Object Family, Version)) {
            Write-Log ("KEEP  {0,-14} {1,-7} v{2}  ({3})" -f $k.Family, $k.Arch, $k.Version, $k.DisplayName) 'KEEP'
        }

        # Uninstall dependents first, host last; newest first within a family.
        $ordered = $toRemove | Sort-Object Order, @{ Expression = 'Version'; Descending = $true }
        foreach ($item in $ordered) {
            $target = "$($item.DisplayName) [$($item.Arch)] v$($item.Version)"
            if ($PSCmdlet.ShouldProcess($target, 'Uninstall .NET component')) {
                $r = Invoke-SilentUninstall $item
                $results.Add([pscustomobject]@{
                    DisplayName = $item.DisplayName; Family = $item.Family; Arch = $item.Arch
                    Version = $item.Version; Action = 'Uninstall'; ExitCode = $r.ExitCode; Result = $r.Result
                })
                if ($r.GhostCleanup) {
                    $results.Add([pscustomobject]@{
                        DisplayName = $item.DisplayName; Family = $item.Family; Arch = $item.Arch
                        Version = $item.Version; Action = 'RemoveOrphanArp'; ExitCode = $null; Result = $r.GhostCleanup
                    })
                }
            }
            else {
                $results.Add([pscustomobject]@{
                    DisplayName = $item.DisplayName; Family = $item.Family; Arch = $item.Arch
                    Version = $item.Version; Action = 'Uninstall'; ExitCode = $null; Result = 'WhatIf'
                })
            }
        }
    }

    # --- Optional supplementary tool pass ---------------------------------------------------------
    if ($AlsoRunUninstallTool) {
        $tool = Get-DotNetUninstallTool

        if (-not $tool -and $InstallUninstallTool) {
            if ($WhatIfPreference) {
                Write-Log 'dotnet-core-uninstall not found; skipping winget install during dry run.' 'WARN'
            }
            else {
                $winget = Get-WingetExe
                if (-not $winget) {
                    Write-Log 'winget not available (typical under SYSTEM); cannot auto-install the tool.' 'WARN'
                }
                else {
                    Write-Log "Installing dotnet-core-uninstall via winget: $winget" 'STEP'
                    try {
                        & $winget install Microsoft.DotNet.UninstallTool `
                            --silent --accept-source-agreements --accept-package-agreements 2>&1 |
                            ForEach-Object { Write-Log "  $_" }
                    } catch { Write-Log "  winget error: $($_.Exception.Message)" 'WARN' }
                    $tool = Get-DotNetUninstallTool
                }
            }
        }

        if (-not $tool) {
            $hint = if ($InstallUninstallTool) { '' } else { ' (pass -InstallUninstallTool to auto-install via winget)' }
            Write-Log "dotnet-core-uninstall not installed; skipping supplementary tool pass$hint." 'WARN'
        }
        else {
            Write-Log "Supplementary pass via: $tool" 'STEP'
            Write-Log 'Current .NET installations (dotnet-core-uninstall list):'
            try { & $tool list 2>&1 | ForEach-Object { Write-Log "  $_" } }
            catch { Write-Log "  list error: $($_.Exception.Message)" 'WARN' }

            # dotnet-core-uninstall commands are: list | dry-run | remove (NOT 'whatif').
            $verb    = if ($WhatIfPreference) { 'dry-run' } else { 'remove' }
            $targets = @('--sdk', '--runtime', '--aspnet-runtime', '--windows-desktop-runtime', '--hosting-bundle')
            $archs   = @('--x64', '--x86', '--arm64')
            foreach ($t in $targets) {
                # --hosting-bundle is its own filter category and takes NO architecture option;
                # everything else is swept per-arch.
                $archSet = if ($t -eq '--hosting-bundle') { @($null) } else { $archs }
                foreach ($a in $archSet) {
                    $argList = @($verb, '--all-below', "$RemoveBelow", $t)
                    if ($a) { $argList += $a }
                    if ($verb -eq 'remove') { $argList += @('--yes', '--force') }
                    Write-Log ("tool: {0} {1}" -f (Split-Path $tool -Leaf), ($argList -join ' '))
                    try { & $tool @argList 2>&1 | ForEach-Object { Write-Log "  $_" } }
                    catch { Write-Log "  tool error: $($_.Exception.Message)" 'WARN' }
                }
            }
        }
    }

    # --- "Still installed" set shared by both leftover sweeps -------------------------------------
    # Scope-INDEPENDENT on purpose: even under -Scope RuntimesOnly (where SDKs are deliberately kept
    # and never uninstalled), their versions must count as "still installed" so a leftover sweep
    # never orphans a live folder or marker.
    #
    # Ghost entries are excluded here too. A stale ARP key must not protect a folder or marker whose
    # product is already gone -- that is exactly what kept the leftovers un-sweepable.
    if ($CleanLeftoverFolders -or $CleanLeftoverRegistry) {
        $stillInstalled = @{}
        foreach ($e in (Get-DotNetArpEntries)) {
            $nm = $e.DisplayName
            if ([string]::IsNullOrWhiteSpace($nm)) { continue }
            if ($nm -notmatch '^Microsoft (\.NET|ASP\.NET Core|Windows Desktop Runtime)\b') { continue }
            if ($nm -match $DenyPattern) { continue }
            if (Test-OrphanedArpEntry $e) { continue }
            $vv = Get-DotNetVersion -DisplayName $nm -DisplayVersion $e.DisplayVersion
            if ($vv) { $stillInstalled[(Get-VersionKey $vv)] = $true }
        }
        Write-Log ("Versions still registered machine-wide: {0}" -f `
                   $(if ($stillInstalled.Count) { ($stillInstalled.Keys | Sort-Object) -join ', ' } else { '(none)' })) 'INFO'
    }

    if ($CleanLeftoverFolders) {
        Write-Log 'Sweeping leftover version folders under Program Files\dotnet...' 'STEP'
        $machineRoots = @("$env:ProgramFiles\dotnet")
        if (Test-Path "$env:ProgramFiles\dotnet\x64") { $machineRoots += "$env:ProgramFiles\dotnet\x64" }  # ARM64 x64 SDK
        if (${env:ProgramFiles(x86)}) { $machineRoots += "${env:ProgramFiles(x86)}\dotnet" }
        Remove-LeftoverDotNetFolders -Threshold $RemoveBelow -Roots $machineRoots -StillInstalled $stillInstalled
    }

    if ($CleanLeftoverRegistry) {
        Write-Log 'Sweeping leftover .NET markers under HKLM\SOFTWARE\dotnet\Setup\InstalledVersions...' 'STEP'
        Remove-LeftoverDotNetRegistry -Threshold $RemoveBelow -StillInstalled $stillInstalled
    }

    # Per-user "private" installs (dotnet-install script: no uninstaller, no registry entry).
    # Removal == deleting the version folders, so this runs independently of -CleanLeftoverFolders.
    if ($IncludeUserProfiles) {
        Write-Log 'Scanning user profiles for per-user (private) .NET installs...' 'STEP'
        $noRegistry = @{}   # per-user installs have no ARP entry -> pure version comparison
        foreach ($userProfile in (Get-UserProfilePaths)) {
            $userRoots = @()
            foreach ($rel in @('AppData\Local\Microsoft\dotnet', '.dotnet')) {
                $rp = Join-Path $userProfile $rel
                if ((Test-Path $rp) -and (Test-Path (Join-Path $rp 'dotnet.exe'))) { $userRoots += $rp }
            }
            if ($userRoots.Count) {
                Write-Log "  profile '$userProfile' -> $($userRoots -join '; ')"
                Remove-LeftoverDotNetFolders -Threshold $RemoveBelow -Roots $userRoots -StillInstalled $noRegistry
            }
        }
    }

    # --- Summary ----------------------------------------------------------------------------------
    $failed = @($results | Where-Object { $_.Result -eq 'Failed' })
    $ghosts = @($results | Where-Object { $_.Action -eq 'RemoveOrphanArp' })
    Write-Log ("=== Done. {0} action(s) recorded ({1} orphaned ARP key(s)), {2} failed. ===" -f `
               $results.Count, $ghosts.Count, $failed.Count) `
              ($(if ($failed.Count) { 'WARN' } else { 'OK' }))
    if ($failed.Count) {
        Write-Log 'Failed actions (see log / MSI logs in %WINDIR%\Temp):' 'WARN'
        foreach ($f in $failed) {
            Write-Log ("  FAIL [{0}] {1} v{2} exit={3}" -f $f.Action, $f.DisplayName, $f.Version, $f.ExitCode) 'WARN'
        }
    }

    return $results
}

#endregion

#region -------------------- Update: Update-DotNetRuntime (patch + trim within supported majors) --------------------

function Update-DotNetRuntime {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidatePattern('^\d+$')]
        [string[]]$Major = @('8', '10')
    )

    $okCodes = 0, 3010, 1641   # 3010/1641 = success, reboot needed
    $mode    = if ($WhatIfPreference) { 'PREVIEW (WhatIf) - no changes will be made' } else { 'LIVE - changes will be made' }
    $paths   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'

    $getEntries   = { Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } }
    $isRegistered = { param($key) [bool](& $getEntries | Where-Object PSChildName -eq $key) }

    # Locate winget once (not on PATH when running as SYSTEM)
    # -AllUsers needs admin; fall back to PATH so a non-admin -WhatIf preview still works.
    $wingetDir = try { (Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
                  Sort-Object Version | Select-Object -Last 1).InstallLocation } catch { $null }
    $winget = if ($wingetDir) { Join-Path $wingetDir 'winget.exe' } else { (Get-Command winget.exe -ErrorAction SilentlyContinue).Source }
    if (-not ($winget -and (Test-Path $winget))) { $winget = $null }

    # Uninstalls one item, then checks the registry to confirm it is really gone
    $removeItem = {
        param($Item)
        if (-not $PSCmdlet.ShouldProcess("$($Item.Name) $($Item.Key)", 'Uninstall')) {
            Write-Host "        (preview) would remove $($Item.Version)  $($Item.Key)"
            return
        }
        if ($Item.IsMsi) {
            $code = (Start-Process msiexec.exe -ArgumentList "/x $($Item.Key) /qn /norestart" -Wait -PassThru).ExitCode
        } else {
            cmd /c $Item.Command | Out-Null
            $code = $LASTEXITCODE
        }
        if ($code -in $okCodes -and -not (& $isRegistered $Item.Key)) {
            Write-Host "        REMOVED $($Item.Version)  $($Item.Key)"
            $summary.Removed++
            if ($code -ne 0) { $summary.RebootNeeded = $true }
        } elseif ($code -in $okCodes) {
            Write-Host "        NOT REMOVED $($Item.Version)  $($Item.Key) - reported success but still registered (something depends on it)"
            $summary.Failed++
        } else {
            Write-Host "        FAILED $($Item.Version)  $($Item.Key) (exit code $code)"
            $summary.Failed++
        }
    }

    # For each group (product + architecture), keep the newest and remove the rest
    $pruneGroups = {
        param($Items)
        foreach ($group in $Items | Group-Object Label) {
            $sorted = @($group.Group | Sort-Object Version)
            $keep   = $sorted[-1]
            $old    = @($sorted | Select-Object -SkipLast 1)
            if (-not $old) {
                Write-Host "      $($group.Name): keeping $($keep.Version) - nothing older"
                continue
            }
            Write-Host "      $($group.Name): keeping $($keep.Version)"
            foreach ($o in $old) { & $removeItem $o }
        }
    }

    $total = [ordered]@{ Updated = 0; Removed = 0; Failed = 0; RebootNeeded = $false }

    foreach ($ver in $Major) {
        $summary = [ordered]@{ Updated = 0; Removed = 0; Failed = 0; RebootNeeded = $false }

        Write-Host ""
        Write-Host "=================================================="
        Write-Host " .NET $ver runtime maintenance on $env:COMPUTERNAME"
        Write-Host " Mode: $mode"
        Write-Host "=================================================="

        $wingetIds = @{
            'Windows Desktop Runtime' = "Microsoft.DotNet.DesktopRuntime.$ver"
            '.NET Runtime'            = "Microsoft.DotNet.Runtime.$ver"
            'ASP.NET Core Runtime'    = "Microsoft.DotNet.AspNetCore.$ver"
        }

        # Visible bundles - names vary ("Runtime - 10.0.11" and "Runtime 10.0.11")
        $bundleDefs = @(
            @{ Rx = "^Microsoft (?<p>Windows Desktop Runtime|\.NET Runtime|ASP\.NET Core Runtime) (?:- )?(?<v>$ver\.0\.\d+) \((?<a>x64|x86|arm64)\)$" },
            @{ Rx = "^Microsoft ASP\.NET Core (?<v>$ver\.0\.\d+) - Shared Framework \((?<a>x64|x86|arm64)\)$"; P = 'ASP.NET Core Runtime' }
        )
        $getBundles = {
            foreach ($e in & $getEntries) {
                if ($e.SystemComponent -eq 1) { continue }
                foreach ($d in $bundleDefs) {
                    if ($e.DisplayName -match $d.Rx) {
                        $product = if ($d.P) { $d.P } else { $Matches.p }
                        $isMsi   = $e.UninstallString -match '^\s*"?MsiExec'
                        $cmd     = $e.QuietUninstallString
                        if (-not $isMsi -and -not $cmd -and $e.UninstallString) { $cmd = "$($e.UninstallString) /quiet" }
                        if ($isMsi -or $cmd) {
                            [pscustomobject]@{
                                Product = $product
                                Version = [version]$Matches.v
                                Label   = "$product ($($Matches.a))"
                                Name    = $e.DisplayName
                                Key     = $e.PSChildName
                                IsMsi   = $isMsi
                                Command = $cmd
                            }
                        }
                        break
                    }
                }
            }
        }

        # Hidden child MSIs (installed by bundles; can be left orphaned)
        $childPatterns = @(
            "^Microsoft (?<c>\.NET Host FX Resolver|\.NET Host|\.NET Runtime|Windows Desktop Runtime) (?:- )?(?<v>$ver\.0\.\d+) \((?<a>x64|x86|arm64)\)$",
            "^Microsoft (?<c>ASP\.NET Core) (?<v>$ver\.0\.\d+) (?:- )?Shared Framework \((?<a>x64|x86|arm64)\)$"
        )
        $getChildren = {
            foreach ($e in & $getEntries) {
                if ($e.SystemComponent -ne 1 -or $e.UninstallString -notmatch '^\s*"?MsiExec') { continue }
                foreach ($p in $childPatterns) {
                    if ($e.DisplayName -match $p) {
                        [pscustomobject]@{
                            Version = [version]$Matches.v
                            Label   = "$($Matches.c) ($($Matches.a))"
                            Name    = $e.DisplayName
                            Key     = $e.PSChildName
                            IsMsi   = $true
                        }
                        break
                    }
                }
            }
        }

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[1/6] Locating winget"
        if ($winget) { Write-Host "      Found winget $(& $winget --version) at $winget" }
        else         { Write-Host "      WARNING: winget.exe not found. Updates skipped; cleanup still runs." }

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[2/6] Scanning for installed .NET $ver runtime bundles"
        $before = @(& $getBundles)
        if ($before) {
            $before | Sort-Object Label, Version | ForEach-Object {
                Write-Host ("      {0,-38} {1}" -f $_.Label, $_.Version)
            }
        } else {
            Write-Host "      No bundles found."
        }

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[3/6] Updating to the latest .NET $ver patch"
        if (-not $before)     { Write-Host "      Skipped - no bundles to update." }
        elseif (-not $winget) { Write-Host "      Skipped - winget not available." }
        else {
            foreach ($product in $before.Product | Sort-Object -Unique) {
                $id      = $wingetIds[$product]
                $current = ($before | Where-Object Product -eq $product | Sort-Object Version | Select-Object -Last 1).Version
                Write-Host "      $product (currently $current) -> winget id $id"

                if ($PSCmdlet.ShouldProcess($id, 'winget install/upgrade')) {
                    & $winget install --id $id --source winget --silent `
                        --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
                    $code = $LASTEXITCODE
                    $new  = (& $getBundles | Where-Object Product -eq $product | Sort-Object Version | Select-Object -Last 1).Version
                    if ($new -gt $current)     { Write-Host "      UPDATED: $current -> $new"; $summary.Updated++ }
                    elseif ($new -eq $current) { Write-Host "      Already up to date ($current)" }
                    else                       { Write-Host "      WARNING: winget returned code $code; version unchanged"; $summary.Failed++ }
                } else {
                    Write-Host "      (preview) would check for and install any newer $ver.0.x version"
                }
            }
        }

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[4/6] Removing older .NET $ver bundles (newest is always kept)"
        $after = if ($WhatIfPreference) { $before } else { @(& $getBundles) }
        if (-not $after) { Write-Host "      Nothing to do." }
        & $pruneGroups $after

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[5/6] Removing orphaned .NET $ver components (newest is always kept)"
        if ($WhatIfPreference) {
            Write-Host "      Note: preview may list components that step 4 would remove with their bundle."
        }
        $children = @(& $getChildren)
        if (-not $children) { Write-Host "      No .NET $ver components found." }
        & $pruneGroups $children

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "[6/6] Removing leftover runtime folders no installer owns (newest is always kept)"
        if ($WhatIfPreference) {
            Write-Host "      Note: preview shows folders still owned by items above as SKIPPED;"
            Write-Host "      a live run deletes them once their owner has been removed."
        }
        $entries = @(& $getEntries)
        $roots   = @("$env:ProgramFiles\dotnet\shared", "${env:ProgramFiles(x86)}\dotnet\shared") | Where-Object { Test-Path $_ }
        $anyDirs = $false

        foreach ($root in $roots) {
            $suffix = if ($root -like '*(x86)*') { ' (x86)' } else { '' }
            foreach ($fw in Get-ChildItem $root -Directory) {
                $dirs = @(Get-ChildItem $fw.FullName -Directory |
                          Where-Object Name -match "^$ver\.0\.\d+$" |
                          Sort-Object { [version]$_.Name })
                if (-not $dirs) { continue }
                $anyDirs = $true
                $keep = $dirs[-1]
                $old  = @($dirs | Select-Object -SkipLast 1)

                if (-not $old) {
                    Write-Host "      $($fw.Name)$suffix`: keeping $($keep.Name) - no leftovers"
                    continue
                }
                Write-Host "      $($fw.Name)$suffix`: keeping $($keep.Name)"

                foreach ($dir in $old) {
                    $rx    = "(?<![\d.])$([regex]::Escape($dir.Name))(?![\d.])"
                    $owner = $entries | Where-Object { $_.DisplayName -match $rx } | Select-Object -First 1
                    if ($owner) {
                        Write-Host "        SKIPPED $($dir.Name) - still owned by '$($owner.DisplayName)'"
                        continue
                    }
                    if ($PSCmdlet.ShouldProcess($dir.FullName, 'Delete folder')) {
                        try {
                            Remove-Item $dir.FullName -Recurse -Force -ErrorAction Stop
                            Write-Host "        DELETED folder $($dir.Name)"
                            $summary.Removed++
                        } catch {
                            Write-Host "        FAILED to delete $($dir.Name) - files in use? Reboot and re-run."
                            $summary.Failed++
                        }
                    } else {
                        Write-Host "        (preview) would delete folder $($dir.Name)"
                    }
                }
            }
        }
        if (-not $anyDirs) { Write-Host "      No .NET $ver folders found." }

        # -----------------------------------------------------------
        Write-Host ""
        Write-Host "---------- .NET $ver summary ----------"
        Write-Host " Updated : $($summary.Updated)"
        Write-Host " Removed : $($summary.Removed)"
        Write-Host " Failed  : $($summary.Failed)"
        Write-Host " Reboot  : $(if ($summary.RebootNeeded) { 'REQUIRED' } else { 'not needed' })"

        $total.Updated += $summary.Updated; $total.Removed += $summary.Removed; $total.Failed += $summary.Failed
        if ($summary.RebootNeeded) { $total.RebootNeeded = $true }
    }

    $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (Test-Path $dotnet) {
        Write-Host ""
        Write-Host "=================================================="
        Write-Host " Runtimes now installed (from $dotnet)"
        Write-Host "=================================================="
        & $dotnet --list-runtimes | ForEach-Object { Write-Host "   $_" }
    }
    Write-Host ""
    [pscustomobject]$total
}

#endregion

#region -------------------- Invoke-DotNetEOL (dispatcher, returns the exit code) --------------------

function Invoke-DotNetEOL {
    param(
        [ValidateSet('Check', 'Recon', 'Remove', 'Update')]
        [string]$Mode = 'Check',
        # Parameters of the mode's function, e.g. @{ RemoveBelow = '8.0.28'; Armed = $true }
        [hashtable]$Options = @{}
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $preview = [bool]$Options['WhatIf']

    try {
        switch ($Mode) {
            'Check' {
                $findings = @(Test-DotNetSEoL @Options)
                if (@($findings | Where-Object EndOfLife).Count) { return 2 }
                return 0
            }
            'Recon' {
                Get-DotNetInventory @Options | Out-Host
                return 0
            }
            'Remove' {
                if ($Options['Armed'] -and -not $preview -and -not $isAdmin) {
                    Write-Host 'ERROR: Armed removal needs an elevated or SYSTEM session.' -ForegroundColor Red
                    return 10
                }
                $results = @(Remove-OldDotNet @Options)
                $results | Format-Table Action, Result, ExitCode, Version, Arch, DisplayName -AutoSize | Out-Host
                if (@($results | Where-Object Result -eq 'Failed').Count) { return 3 }
                if (@($results | Where-Object { $_.ExitCode -in 3010, 1641 }).Count) { return 3010 }
                return 0
            }
            'Update' {
                if (-not $preview -and -not $isAdmin) {
                    Write-Host 'ERROR: a live Update needs an elevated or SYSTEM session (or pass WhatIf).' -ForegroundColor Red
                    return 10
                }
                $summary = Update-DotNetRuntime @Options
                if ($summary.Failed) { return 3 }
                if ($summary.RebootNeeded) { return 3010 }
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

$exitCode = Invoke-DotNetEOL                                                    # Check (read-only)
# $exitCode = Invoke-DotNetEOL -Mode Recon                                      # who uses what (read-only, slow)
# $exitCode = Invoke-DotNetEOL -Mode Recon -Options @{ TargetVersion = '6.0'; SkipAssemblyScan = $true }
# $exitCode = Invoke-DotNetEOL -Mode Remove                                     # DRY RUN below 8.0.28
# $exitCode = Invoke-DotNetEOL -Mode Remove -Options @{ RemoveBelow = '8.0.28'; CleanLeftoverFolders = $true; CleanLeftoverRegistry = $true; Armed = $true }
# $exitCode = Invoke-DotNetEOL -Mode Update -Options @{ WhatIf = $true }        # preview 8 + 10
# $exitCode = Invoke-DotNetEOL -Mode Update -Options @{ Major = '8', '10' }     # LIVE

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
