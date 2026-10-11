<#
.SYNOPSIS
    Removes extra Office (Microsoft 365 Apps) language packs with the Office Deployment Tool.

.DESCRIPTION
    Needs setup.exe (or the ODT self-extractor ODT.exe) in %TEMP%. Builds a <Remove All="FALSE">
    config for O365ProPlusRetail with the languages below and runs setup.exe /configure.
    Office's own install language (ClientCulture under the Click-to-Run configuration key) is
    always left out of the list, so the base language is never removed - whether that is
    en-us, en-gb or another one.

    -WhatIf (the ENTRY POINT default) shows which languages would be removed and changes nothing.
    Needs an elevated or SYSTEM session for a real run.

.NOTES
    Exit codes (Remove-OfficeLanguagePacks returns one; the entry point exits with it only when $RMM = $true):
        0     Done, or -WhatIf
        1     Error (setup.exe missing, extraction or removal failed)
        3010  Done; restart Windows to finish
        10    Not elevated (real run) - nothing changed
#>

function Remove-OfficeLanguagePacks {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$Languages = @('ar-sa', 'da-dk', 'de-de', 'en-us', 'es-es', 'fi-fi', 'fr-fr', 'it-it',
                                 'nb-no', 'nl-nl', 'pl-pl', 'pt-pt', 'sv-se')
    )

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    try {
        $base = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue).ClientCulture
        $remove = @($Languages | Where-Object { $_ -and $_ -ne $base })
        Write-Host "Office install language (kept): $(if ($base) { $base } else { 'unknown' })"
        if (-not $base) { Write-Host 'WARNING: could not read ClientCulture; make sure the list does not contain the install language.' -ForegroundColor Yellow }
        Write-Host "Languages to remove: $($remove -join ', ')"
        if (-not $remove) { Write-Host 'Nothing to remove.'; return 0 }

        if (-not $PSCmdlet.ShouldProcess("Office language packs: $($remove -join ', ')", 'Remove with the Office Deployment Tool')) { return 0 }

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { Write-Host 'ERROR: needs an elevated or SYSTEM session. Nothing changed.' -ForegroundColor Red; return 10 }

        $setup = Join-Path $env:TEMP 'setup.exe'
        $odt = Join-Path $env:TEMP 'ODT.exe'
        $config = Join-Path $env:TEMP 'remove-languages.xml'

        if (!(Test-Path -LiteralPath $setup)) {
            if (!(Test-Path -LiteralPath $odt)) {
                throw "Cannot find $setup or $odt"
            }

            $extract = Start-Process -FilePath $odt `
                -ArgumentList "/quiet /extract:`"$env:TEMP`"" `
                -Wait -PassThru

            if ($extract.ExitCode -ne 0 -or !(Test-Path -LiteralPath $setup)) {
                throw "ODT extraction failed. Exit code: $($extract.ExitCode)"
            }
        }

        $langXml = ($remove | ForEach-Object { "      <Language ID=`"$_`" />" }) -join "`r`n"
        @"
<Configuration>
  <Remove All="FALSE">
    <Product ID="O365ProPlusRetail">
$langXml
    </Product>
  </Remove>
</Configuration>
"@ | Set-Content -LiteralPath $config -Encoding UTF8

        $result = Start-Process -FilePath $setup `
            -ArgumentList "/configure `"$config`"" `
            -Wait -PassThru

        if ($result.ExitCode -notin 0, 3010) {
            throw "Office language removal failed. Exit code: $($result.ExitCode)"
        }

        if ($result.ExitCode -eq 3010) {
            Write-Host 'Completed. Restart Windows to finish.'
            return 3010
        }
        Write-Host 'Office Deployment Tool completed successfully.'
        return 0
    }
    catch {
        # Write-Host, not Write-Error: a caller's ErrorAction Stop must not lose the exit code.
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
}

#region ==================== ENTRY POINT - set $RMM, then pick ONE mode ====================

# $true ONLY in an RMM component: the script then ends with 'exit <code>' so the RMM
# sees the result. Leave $false when pasting into a console or RMM remote shell.
$RMM = $false

$exitCode = Remove-OfficeLanguagePacks -WhatIf          # Preview (changes nothing)
# $exitCode = Remove-OfficeLanguagePacks                # LIVE: remove the listed languages (install language kept)

if ($RMM) { exit $exitCode }
Write-Host "Exit code: $exitCode (session left open; set `$RMM = `$true for RMM components)"

#endregion
