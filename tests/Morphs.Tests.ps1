#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }, PSScriptAnalyzer
<#
    Contract, safety and helper tests for every *-morph.ps1 (pester.dev, Pester 5+).

    Run in Windows PowerShell 5.1 (what RMM agents use), from the repo root, NOT elevated:
        powershell -NoProfile -Command "Invoke-Pester .\tests -Output Detailed"
    Skip the slow child-process runs:  Invoke-Pester .\tests -ExcludeTagFilter Paste

    Nothing here changes the machine: the paste runs use each morph's default read-only mode,
    and the elevation-gate runs (skipped when elevated) only check that a destructive mode
    refuses with 10 before acting.
#>

BeforeDiscovery {
    $repo = Split-Path $PSScriptRoot -Parent
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # A destructive call per morph whose elevation gate was checked to run before any action.
    # PowerToys has no 10 (it requires SYSTEM); ScreenConnect is read-only.
    $gates = @{
        'Adobe-Acrobat-morph.ps1'     = 'Start-AdobePatch -Uninstall -WhatIf'
        'Chrome-morph.ps1'            = 'Invoke-Chrome -Mode Update -WhatIf'
        'DotNet-EOL-morph.ps1'        = 'Invoke-DotNetEOL -Mode Update'
        'Firefox-morph.ps1'           = 'Invoke-Firefox -Mode Uninstall -WhatIf'
        'Microsoft3DViewer-morph.ps1' = 'Invoke-3DViewer -Action Remove -WhatIf'
        'Nessus-morph.ps1'            = 'Invoke-Nessus -Mode Remove -WhatIf'
        'Python-morph.ps1'            = 'Invoke-Python -Mode Remove -WhatIf'
        'UserRemoval-morph.ps1'       = 'Invoke-UserRemoval -Mode Cleanup -WhatIf'
        'VCRedist-EOL-morph.ps1'      = 'Invoke-VCRedistEOL -Mode Install -Options @{ WhatIf = $true }'
        'VSCode-morph.ps1'            = 'Invoke-VSCode -Mode Migrate -Options @{ CloseApps = $true; Live = $true; WhatIf = $true }'
        'Winget-morph.ps1'            = 'Invoke-Winget -Mode Upgrade -Options @{ WhatIf = $true; Live = $true }'
    }

    # Default (read-only) modes return 0/1/2, never 10. Adobe keeps its own RMM code table:
    # its Check returns 0 (current or not installed), 2, 3 (no WinGet package) or 7 (latest version unknown).
    $defaultCodes = @{ 'Adobe-Acrobat-morph.ps1' = @(0, 2, 3, 7) }

    $morphs = @(Get-ChildItem $repo -Recurse -Filter '*-morph.ps1' |
        Where-Object { $_.FullName -notmatch '\\OLD\\' } |
        Sort-Object Name |
        ForEach-Object {
            $codes = if ($defaultCodes.ContainsKey($_.Name)) { $defaultCodes[$_.Name] } else { @(0, 1, 2) }
            @{ Name = $_.Name; Path = $_.FullName; Gate = $gates[$_.Name]; IsAdmin = $isAdmin; DefaultCodes = $codes }
        })
}

BeforeAll {
    $script:Settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $script:Ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

    # Pastes a morph into a fresh Windows PowerShell 5.1 process the way an engineer would
    # (Invoke-Expression of the whole text), optionally with another entry line or $RMM = $true.
    function Invoke-MorphPaste {
        param([string]$Path, [string]$EntryLine, [switch]$Rmm)
        $src = [IO.File]::ReadAllText($Path)
        if ($EntryLine) { $src = $src -replace '(?m)^\$exitCode = .*$', ('$exitCode = ' + $EntryLine.Replace('$', '$$')) }
        if ($Rmm) { $src = $src -replace '(?m)^\$RMM = \$false', '$RMM = $true' }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("morphtest_{0}.ps1" -f [guid]::NewGuid())
        [IO.File]::WriteAllText($tmp, $src, [Text.UTF8Encoding]::new($true))
        try {
            $cmd = "Invoke-Expression ([IO.File]::ReadAllText('$tmp')); 'PASTE-RESULT|' + `$exitCode.GetType().FullName + '|' + (@(`$exitCode).Count) + '|' + `$exitCode"
            $out = & $script:Ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd 2>&1 | ForEach-Object { "$_" }
            [pscustomobject]@{ Output = $out; ProcessExit = $LASTEXITCODE; Result = ($out | Where-Object { $_ -like 'PASTE-RESULT|*' } | Select-Object -Last 1) }
        }
        finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
}

Describe '<Name>' -ForEach $morphs {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        $text = [IO.File]::ReadAllText($Path)
    }

    Context 'Static checks' {

        It 'parses without errors' {
            $parseErrors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" } | Should -BeNullOrEmpty
        }

        It 'is ASCII or has a UTF-8 BOM (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
            $bytes = [IO.File]::ReadAllBytes($Path)
            $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
            ($hasBom -or -not ($bytes | Where-Object { $_ -gt 0x7F } | Select-Object -First 1)) | Should -BeTrue
        }

        It 'has no script-level param() block (paste model)' {
            $ast.ParamBlock | Should -BeNullOrEmpty
        }

        It 'has the ENTRY POINT contract: $RMM = $false, one active $exitCode line, exit only behind $RMM' {
            ([regex]::Matches($text, '(?m)^\$RMM = \$false\b')).Count | Should -Be 1
            ([regex]::Matches($text, '(?m)^\$exitCode = ')).Count | Should -Be 1
            ([regex]::Matches($text, '(?m)^if \(\$RMM\) \{ exit \$exitCode \}')).Count | Should -Be 1
            # exit appears nowhere else at top level
            $topExit = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.PipelineAst] -and $_.Extent.Text -match '^\s*exit\b' }
            $topExit | Should -BeNullOrEmpty
        }

        It 'puts the ENTRY POINT after every function definition' {
            $lastFunctionEnd = ($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] } |
                ForEach-Object { $_.Extent.EndLineNumber } | Measure-Object -Maximum).Maximum
            $rmmLineNumber = ($text.Substring(0, [regex]::Match($text, '(?m)^\$RMM = \$false').Index) -split "`n").Count
            $rmmLineNumber | Should -BeGreaterThan $lastFunctionEnd
        }

        It 'runs nothing at top level except definitions, assignments and the entry point' {
            $loose = foreach ($s in $ast.EndBlock.Statements) {
                if ($s -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }
                if ($s -is [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
                if ($s -is [System.Management.Automation.Language.IfStatementAst] -and $s.Clauses[0].Item1.Extent.Text -match '^\$RMM$|-as\s*\[type\]') { continue }
                if ($s -is [System.Management.Automation.Language.PipelineAst] -and $s.Extent.Text -match '^Write-Host\b') { continue }
                "$($s.Extent.StartLineNumber): $($s.Extent.Text.Split("`n")[0])"
            }
            $loose | Should -BeNullOrEmpty
        }

        It 'guards every Add-Type with a -as [type] check' {
            $addTypes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Add-Type' }, $true)
            $unguarded = foreach ($at in $addTypes) {
                $p = $at.Parent; $guarded = $false
                while ($p) {
                    if ($p -is [System.Management.Automation.Language.IfStatementAst] -and ($p.Clauses | Where-Object { $_.Item1.Extent.Text -match '-as\s*\[type\]' })) { $guarded = $true; break }
                    # Early-return form: if ('X' -as [type]) { ...; return ... } earlier in the same function.
                    if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                        $before = $p.Extent.Text.Substring(0, $at.Extent.StartOffset - $p.Extent.StartOffset)
                        if ($before -match '-as\s*\[type\]\)\s*\{[^}]*\breturn\b') { $guarded = $true }
                        break
                    }
                    $p = $p.Parent
                }
                if (-not $guarded) { "line $($at.Extent.StartLineNumber)" }
            }
            $unguarded | Should -BeNullOrEmpty
        }

        It 'has no PSScriptAnalyzer findings (tests\PSScriptAnalyzerSettings.psd1)' {
            Invoke-ScriptAnalyzer -Path $Path -Settings $script:Settings |
                ForEach-Object { "$($_.Line) $($_.RuleName): $($_.Message)" } | Should -BeNullOrEmpty
        }
    }

    Context 'Paste model (child Windows PowerShell 5.1)' -Tag 'Paste' {

        It 'default mode leaves the session open with a single [int] exit code' {
            $run = Invoke-MorphPaste -Path $Path
            $run.Result | Should -Not -BeNullOrEmpty -Because ($run.Output | Select-Object -Last 15 | Out-String)
            $type, $count, $value = $run.Result.Split('|')[1..3]
            $type | Should -Be 'System.Int32'
            $count | Should -Be '1'
            [int]$value | Should -BeIn $DefaultCodes
        }

        It 'with $RMM = $true the process exits with the same code' {
            $plain = Invoke-MorphPaste -Path $Path
            $rmm = Invoke-MorphPaste -Path $Path -Rmm
            $rmm.Result | Should -BeNullOrEmpty -Because 'exit must end the process before the next statement'
            $rmm.ProcessExit | Should -Be ([int]$plain.Result.Split('|')[3])
        }

        It 'refuses a destructive mode with 10 when not elevated' -Skip:($IsAdmin -or -not $Gate) {
            $run = Invoke-MorphPaste -Path $Path -EntryLine $Gate
            $run.Result | Should -Match '\|System\.Int32\|1\|10$' -Because ($run.Output | Select-Object -Last 10 | Out-String)
        }
    }
}

Describe 'Helper logic' {

    BeforeAll {
        function Import-MorphFunctions([string]$RelativePath) {
            $p = Join-Path (Split-Path $PSScriptRoot -Parent) $RelativePath
            $src = [IO.File]::ReadAllText($p) -replace '(?ms)^#region =+ ENTRY POINT.*$', ''
            . ([scriptblock]::Create($src))
        }
    }

    Context 'Python-morph: Resolve-PythonTarget' {
        BeforeAll {
            . Import-MorphFunctions 'Patching\Python\Python-morph.ps1'
            function New-PyRow($kind, $ver, $eol) { [pscustomobject]@{ Kind = $kind; Version = $ver; Minor = (($ver -split '\.')[0..1] -join '.'); EOL = $eol } }
            $rows = @((New-PyRow CPython '3.9.13' $true), (New-PyRow Folder '3.11.4' $false), (New-PyRow UserSite '2.7' $true), (New-PyRow Launcher '3.11.4150.0' $false))
            $rows[3].Minor = $null
        }
        It 'EOL picks only end-of-life installs (not UserSite or Launcher rows)' { (Resolve-PythonTarget $rows 'EOL') -join ',' | Should -Be '3.9' }
        It 'All returns every installed minor, sorted as versions' { (Resolve-PythonTarget $rows 'All') -join ',' | Should -Be '3.9,3.11' }
        It 'a two-part version matches its micro versions' { Resolve-PythonTarget $rows '3.11' | Should -Be '3.11' }
        It '3.1 does not match 3.11' { @(Resolve-PythonTarget $rows '3.1').Count | Should -Be 0 }
        It 'rejects a malformed version' { { Resolve-PythonTarget $rows 'latest' } | Should -Throw }
    }

    Context 'UserRemoval-morph: SID-safe targeting and folder guard' {
        BeforeAll {
            . Import-MorphFunctions 'Admin\User-Removal\UserRemoval-morph.ps1'
            function New-UpRow($kind, $sid, $acct, $path, $last, $extra = @{}) {
                $r = [pscustomobject]@{ Kind = $kind; SID = $sid; Account = $acct; Type = 'Local'; Path = $path; PathExists = $true; Loaded = $false
                    LastUsed = $last; IsTemp = $false; IsBak = $false; HasAccount = $false; Protected = $null; RegKey = $null }
                foreach ($k in $extra.Keys) { $r.$k = $extra[$k] }
                $r
            }
            $old = (Get-Date).AddDays(-200); $new = (Get-Date).AddDays(-5)
            $rows = @(
                (New-UpRow Profile 'S-1-5-21-1-2-3-1001' 'PC\bob' 'C:\Users\bob' $old @{ HasAccount = $true })
                (New-UpRow Profile 'S-1-5-21-9-9-9-2001' 'CORP\bob' 'C:\Users\bob.CORP' $old @{ Type = 'Domain' })
                (New-UpRow Profile 'S-1-12-1-5-6-7-8' 'AzureAD\Ann' 'C:\Users\Ann' $new @{ Type = 'Entra' })
                (New-UpRow Profile 'S-1-5-21-9-9-9-2002' 'CORP\carl' 'C:\Users\carl' $null @{ Type = 'Domain' })
                (New-UpRow Profile 'S-1-5-21-9-9-9-2003' 'CORP\dan' 'C:\Users\dan' $old @{ Type = 'Domain'; Loaded = $true })
                (New-UpRow Profile 'S-1-5-21-1-2-3-500' 'PC\Admin2' 'C:\Users\Admin2' $old @{ Protected = 'Built-in account' })
                (New-UpRow Profile 'S-1-5-21-9-9-9-2004' 'CORP\gone' 'C:\Users\gone' $old @{ Type = 'Domain'; PathExists = $false })
                (New-UpRow Profile 'S-1-5-21-9-9-9-2005' 'CORP\bk' 'C:\Users\bk' $old @{ Type = 'Domain'; IsBak = $true })
                (New-UpRow OrphanFolder $null $null 'C:\Users\TEMP' $old @{ IsTemp = $true })
                (New-UpRow OrphanFolder $null $null 'C:\Users\olddata' $old)
            )
        }
        It 'refuses a bare name shared by a local and a domain user' { { Resolve-UserTarget $rows -Users 'bob' } | Should -Throw '*more than one user*' }
        It 'DOMAIN\name picks only that SID' { (Resolve-UserTarget $rows -Users 'CORP\bob').SID | Should -Be 'S-1-5-21-9-9-9-2001' }
        It 'a SID picks that user' { (Resolve-UserTarget $rows -Users 'S-1-5-21-1-2-3-1001').Account | Should -Be 'PC\bob' }
        It 'a path (trailing \ allowed) picks that profile' { (Resolve-UserTarget $rows -Users 'C:\Users\Ann\').Account | Should -Be 'AzureAD\Ann' }
        It 'InactiveDays skips loaded, protected, .bak and never-used profiles' {
            (Resolve-UserTarget $rows -InactiveDays 90).Account -join ',' | Should -Be 'PC\bob,CORP\bob,CORP\gone'
        }
        It 'IncludeNeverUsed adds profiles with no last-use data' { (Resolve-UserTarget $rows -InactiveDays 90 -IncludeNeverUsed).Account | Should -Contain 'CORP\carl' }
        It 'broken state = folder gone, .bak key, TEMP folder (not other orphan folders)' {
            (Get-UPBrokenRows $rows | ForEach-Object { if ($_.Account) { $_.Account } else { $_.Path } }) -join ',' | Should -Be 'CORP\gone,CORP\bk,C:\Users\TEMP'
        }
        It 'skips a protected row before doing anything' {
            (Remove-UserProfileTarget -Row $rows[5] -RemoveAccount -Root 'C:\Users' -Confirm:$false).Status | Should -Be 'Skipped (Built-in account)'
        }
        It 'Test-UPSafeFolder allows <Path> = <Expected>' -ForEach @(
            @{ Path = 'C:\Users\bob'; Expected = $true }
            @{ Path = 'C:\Users\TEMP'; Expected = $true }
            @{ Path = 'C:\Users'; Expected = $false }
            @{ Path = 'C:\Users\bob\Documents'; Expected = $false }
            @{ Path = 'D:\Users\bob'; Expected = $false }
            @{ Path = 'C:\Users\Public'; Expected = $false }
            @{ Path = 'C:\Users\TEMP.Font Driver Host.004'; Expected = $false }
            @{ Path = 'C:\Users\UMFD-0'; Expected = $false }
        ) {
            Test-UPSafeFolder $Path 'C:\Users' | Should -Be $Expected
        }
    }
}
