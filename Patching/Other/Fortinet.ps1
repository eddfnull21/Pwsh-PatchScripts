# FortiClient VPN Update Script
# Description: Downloads and installs/updates FortiClient VPN silently

# =============================================================================
# CONFIGURATION
# =============================================================================

# FortiClient VPN download URL (Online Installer)
# For enterprise deployments, you may want to use the MSI from Fortinet Support
$DownloadUrl = "https://links.fortinet.com/forticlient/win/vpnagent"

# Alternative: Direct MSI URL (requires valid Fortinet support account for latest versions)
# $DownloadUrl = "https://fortinet.com/d/forticlient_vpn.msi"

# Download path
$DownloadPath = "$env:TEMP\FortiClientVPN"
$InstallerFile = "$DownloadPath\FortiClientVPNInstaller.exe"

# Log file
$LogFile = "$env:TEMP\FortiClientVPN_Install.log"

# =============================================================================
# FUNCTIONS
# =============================================================================

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value "[$Timestamp] $Message"
}

function Get-FortiClientVersion {
    try {
        # Check registry for installed version
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $regPaths) {
            $app = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                   Where-Object { $_.DisplayName -like "*FortiClient*" }
            if ($app) {
                return $app.DisplayVersion
            }
        }
        
        # Alternative: Check executable version
        $exePath = "${env:ProgramFiles}\Fortinet\FortiClient\FortiClient.exe"
        if (Test-Path $exePath) {
            return (Get-Item $exePath).VersionInfo.FileVersion
        }
        
        $exePathX86 = "${env:ProgramFiles(x86)}\Fortinet\FortiClient\FortiClient.exe"
        if (Test-Path $exePathX86) {
            return (Get-Item $exePathX86).VersionInfo.FileVersion
        }
        
        return $null
    }
    catch {
        return $null
    }
}

function Test-FortiClientInstalled {
    $paths = @(
        "${env:ProgramFiles}\Fortinet\FortiClient\FortiClient.exe",
        "${env:ProgramFiles(x86)}\Fortinet\FortiClient\FortiClient.exe"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $true
        }
    }
    return $false
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

Write-Log "Starting FortiClient VPN Update Process"

# Check current installation
$currentVersion = Get-FortiClientVersion
if ($currentVersion) {
    Write-Log "Current FortiClient version: $currentVersion"
} else {
    Write-Log "FortiClient is not currently installed"
}

# Create download directory
if (-not (Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
    Write-Log "Created download directory: $DownloadPath"
}

# Download installer
Write-Log "Downloading FortiClient VPN installer from: $DownloadUrl"
try {
    # Use WebClient for faster download with progress
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($DownloadUrl, $InstallerFile)
    Write-Log "Download completed successfully"
}
catch {
    Write-Log "ERROR: Download failed - $_"
    exit 1
}

# Verify download
if (-not (Test-Path $InstallerFile)) {
    Write-Log "ERROR: Installer file not found after download"
    exit 1
}

# Only run an installer Fortinet signed (the download URL is a redirect we do not control).
$signature = Get-AuthenticodeSignature -FilePath $InstallerFile
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O="?Fortinet') {
    Write-Log "ERROR: Installer signature is $($signature.Status), signer '$($signature.SignerCertificate.Subject)' - not a valid Fortinet signature. Not run."
    Remove-Item -Path $DownloadPath -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Log "Signature OK: $($signature.SignerCertificate.Subject)"

$fileSize = (Get-Item $InstallerFile).Length / 1MB
Write-Log "Installer size: $([math]::Round($fileSize, 2)) MB"

# Install/Update FortiClient VPN
Write-Log "Starting installation..."

$installArgs = @(
    "/S",           # Silent install
    "/v/qn",        # MSI quiet mode
    "/vREINSTALL=ALL",
    "/vREINSTALLMODE=vomus"
)

try {
    $process = Start-Process -FilePath $InstallerFile -ArgumentList $installArgs -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Log "Installation completed successfully (Exit code: 0)"
    }
    else {
        Write-Log "WARNING: Installation completed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Log "ERROR: Installation failed - $_"
    exit 1
}

# Verify installation
Start-Sleep -Seconds 5  # Wait for installation to finalize

$newVersion = Get-FortiClientVersion
if ($newVersion) {
    Write-Log "FortiClient VPN updated successfully to version: $newVersion"
}
else {
    Write-Log "WARNING: Could not verify installation"
}

# Cleanup
Write-Log "Cleaning up temporary files..."
Remove-Item -Path $DownloadPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Log "FortiClient VPN update process completed"

# =============================================================================
# ALTERNATIVE METHODS
# =============================================================================

<#
.SYNOPSIS
Alternative methods for updating FortiClient VPN

METHOD 1: Using Winget (Windows Package Manager)
-------------------------------------------------
winget install Fortinet.FortiClientVPN --accept-package-agreements --accept-source-agreements

To update:
winget upgrade Fortinet.FortiClientVPN --accept-package-agreements --accept-source-agreements


METHOD 2: Using MSI with Direct Download
----------------------------------------
If you have the MSI installer:

$msiPath = "path\to\FortiClientVPN.msi"
$msiArgs = "/i `"$msiPath`" /qn REINSTALL=ALL REINSTALLMODE=vomus /l*v `"$env:TEMP\forticlient_install.log`""
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait


METHOD 3: Using Chocolatey
--------------------------
choco install forticlientvpn -y
# To update:
choco upgrade forticlientvpn -y


METHOD 4: PowerShell Script for RMM Deployment
-----------------------------------------------
# Silently install with specific features
$arguments = @(
    "/i",
    "`"$msiPath`"",
    "/qn",
    "INSTALLLEVEL=3",           # Install VPN module only
    "REBOOT=ReallySuppress",    # Suppress reboot
    "/l*v",
    "`"$env:TEMP\forticlient.log`""
)
Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow


COMMON EXIT CODES:
------------------
0   - Success
1603 - Fatal error (often previous version installed)
1618 - Another installation in progress
1638 - Newer version already installed
1641 - Restart required
3010 - Restart required

#>