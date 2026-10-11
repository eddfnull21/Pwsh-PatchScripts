<#
.SYNOPSIS
    Microsoft Office CVE-2026-21509 Security Patch Script

.DESCRIPTION
    Mitigates CVE-2026-21509 - Microsoft Office Zero-Day Security Feature Bypass Vulnerability

    VULNERABILITY DETAILS:
    - CVE ID: CVE-2026-21509
    - CVSS Score: 7.8 (High)
    - Type: Security Feature Bypass
    - Status: ACTIVELY EXPLOITED IN THE WILD
    - CISA KEV: Added - Federal agencies must patch by February 16, 2026

    This zero-day allows attackers to bypass OLE security mitigations in Microsoft Office,
    enabling execution of malicious code via specially crafted documents without macro warnings.

    AFFECTED PRODUCTS:
    - Microsoft Office 2016
    - Microsoft Office 2019
    - Microsoft Office LTSC 2021
    - Microsoft Office LTSC 2024
    - Microsoft 365 Apps for Enterprise

    MITIGATION:
    This script applies a registry-based workaround by blocking the vulnerable COM/OLE control
    CLSID {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} with compatibility flags.

    NOTE: Office 2021+ users receive automatic service-side protection after app restart.
          Office 2016/2019 require this registry fix OR official KB5002713 update.

.NOTES
    Author: Generated for RMM Deployment
    Date: 2026-02-13
    Version: 1.0

    REFERENCES:
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21509
    - https://support.microsoft.com/kb/5002713

    REQUIREMENTS:
    - Administrator privileges
    - Windows PowerShell 5.1 or later

.EXAMPLE
    .\office-patch.ps1

.EXAMPLE
    .\office-patch.ps1 -Verbose
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

# Configuration
$VulnerableCLSID = "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}"
$CompatibilityFlagsValue = 0x400  # Kill bit to disable the control
$LogFile = Join-Path $PSScriptRoot "CVE-2026-21509-patch-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupFile = Join-Path $PSScriptRoot "CVE-2026-21509-registry-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }

    # File output
    Add-Content -Path $LogFile -Value $logMessage
}

# Banner
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CVE-2026-21509 Mitigation Script" -ForegroundColor Cyan
Write-Host "Microsoft Office Zero-Day Patch" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Log "Starting CVE-2026-21509 mitigation process" -Level Info

# Check if Office is installed
function Get-OfficeVersion {
    Write-Log "Detecting Microsoft Office installation..." -Level Info

    $officeVersions = @()

    # Check for Office 2016/2019/2021/2024 (Version 16.0)
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot",
        "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            try {
                $installPath = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Path
                if ($installPath) {
                    $officeVersions += $path
                    Write-Log "Found Office installation at: $path" -Level Info
                }
            }
            catch {
                # Continue checking other paths
            }
        }
    }

    return $officeVersions
}

# Backup registry
function Backup-Registry {
    Write-Log "Creating registry backup..." -Level Info

    try {
        $registryKeys = @(
            "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\16.0\Common\COM Compatibility",
            "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility",
            "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility"
        )

        foreach ($key in $registryKeys) {
            $regPath = "Registry::$key"
            if (Test-Path $regPath) {
                $exportCmd = "reg export `"$key`" `"$BackupFile`" /y 2>&1"
                Invoke-Expression $exportCmd | Out-Null
            }
        }

        Write-Log "Registry backup created: $BackupFile" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to create registry backup: $_" -Level Warning
        return $false
    }
}

# Apply mitigation to a specific registry path
function Set-COMCompatibilityFlag {
    param(
        [string]$BasePath
    )

    try {
        $fullPath = "$BasePath\$VulnerableCLSID"

        # Create the COM Compatibility key if it doesn't exist
        if (-not (Test-Path $BasePath)) {
            New-Item -Path $BasePath -Force | Out-Null
            Write-Log "Created registry path: $BasePath" -Level Info
        }

        # Create the CLSID key if it doesn't exist
        if (-not (Test-Path $fullPath)) {
            New-Item -Path $fullPath -Force | Out-Null
            Write-Log "Created CLSID key: $fullPath" -Level Info
        }

        # Set the Compatibility Flags value
        Set-ItemProperty -Path $fullPath -Name "Compatibility Flags" -Value $CompatibilityFlagsValue -Type DWord -Force

        # Verify the setting
        $verifyValue = (Get-ItemProperty -Path $fullPath)."Compatibility Flags"
        if ($verifyValue -eq $CompatibilityFlagsValue) {
            Write-Log "Successfully applied mitigation to: $fullPath" -Level Success
            return $true
        }
        else {
            Write-Log "Failed to verify mitigation at: $fullPath" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error applying mitigation to $BasePath : $_" -Level Error
        return $false
    }
}

# Main execution
try {
    # Check Office installation
    $officeInstalled = Get-OfficeVersion

    if ($officeInstalled.Count -eq 0) {
        Write-Log "No compatible Microsoft Office installation detected." -Level Warning
        Write-Log "This script targets Office 2016, 2019, 2021, 2024, and Microsoft 365 Apps." -Level Warning
        exit 0
    }

    Write-Log "Office installation detected. Proceeding with mitigation..." -Level Info

    # Backup registry
    Backup-Registry

    # Define registry paths to patch
    $registryPaths = @(
        # Standard 64-bit Office installation
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\COM Compatibility",
        # 32-bit Office on 64-bit Windows
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility",
        # Click-to-Run installations
        "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility"
    )

    # Apply mitigation to all relevant paths
    $successCount = 0
    $totalPaths = 0

    foreach ($regPath in $registryPaths) {
        # Check if the base path exists or if we can create it
        $parentPath = Split-Path $regPath -Parent
        if ((Test-Path $parentPath) -or (Test-Path (Split-Path $parentPath -Parent))) {
            $totalPaths++
            Write-Log "Applying mitigation to: $regPath" -Level Info

            if (Set-COMCompatibilityFlag -BasePath $regPath) {
                $successCount++
            }
        }
        else {
            Write-Verbose "Skipping non-applicable path: $regPath"
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "MITIGATION SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($successCount -gt 0) {
        Write-Log "Successfully applied mitigation to $successCount location(s)" -Level Success
        Write-Log "Vulnerable COM object $VulnerableCLSID has been blocked" -Level Success

        Write-Host "`n[IMPORTANT NEXT STEPS]" -ForegroundColor Yellow
        Write-Host "1. Restart all Office applications for changes to take effect" -ForegroundColor Yellow
        Write-Host "2. For Office 2016/2019: Install official update KB5002713" -ForegroundColor Yellow
        Write-Host "3. For Office 2021+: Apps are protected via service-side fix after restart" -ForegroundColor Yellow
        Write-Host "4. Verify protection by testing with safe sample documents" -ForegroundColor Yellow
        Write-Host "`n5. Apply official Microsoft security updates as soon as available" -ForegroundColor Yellow

        Write-Log "Registry backup saved to: $BackupFile" -Level Info
        Write-Log "Log file saved to: $LogFile" -Level Info

        exit 0
    }
    else {
        Write-Log "Failed to apply mitigation. Manual intervention required." -Level Error
        Write-Log "Please apply official Microsoft update KB5002713" -Level Error
        exit 1
    }
}
catch {
    Write-Log "Critical error during execution: $_" -Level Error
    Write-Log $_.ScriptStackTrace -Level Error
    exit 1
}
finally {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Script execution completed" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Additional information
Write-Host "`nREFERENCES:" -ForegroundColor Cyan
Write-Host "- Microsoft Advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21509"
Write-Host "- KB Article: https://support.microsoft.com/kb/5002713"
Write-Host "- CISA KEV: Federal deadline February 16, 2026"
Write-Host "`nTHREAT INTELLIGENCE:" -ForegroundColor Cyan
Write-Host "- Actively exploited by APT28 (Fancy Bear)"
Write-Host "- Exploitation confirmed by Ukraine CERT and Zscaler"
Write-Host "- Used in targeted attacks with malicious Office documents"
Write-Host "`n"
