function Get-BitLockerSuspensionCause {
    [CmdletBinding()]
    param(
        [string]$MountPoint = 'C:',
        [int]$DaysBack = 14
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $Since = (Get-Date).AddDays(-$DaysBack)

    Write-Host "`n=== BitLocker Suspension Investigation ===" -ForegroundColor Cyan
    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "Volume   : $MountPoint"
    Write-Host "Since    : $Since`n"

    # -------------------------------------------------------------------------
    # Current BitLocker state
    # -------------------------------------------------------------------------
    Write-Host "=== CURRENT BITLOCKER STATE ===" -ForegroundColor Yellow

    $bl = Get-BitLockerVolume -MountPoint $MountPoint

    if ($bl) {
        [pscustomobject]@{
            MountPoint           = $bl.MountPoint
            VolumeStatus         = $bl.VolumeStatus
            ProtectionStatus     = $bl.ProtectionStatus
            EncryptionPercentage = $bl.EncryptionPercentage
            EncryptionMethod     = $bl.EncryptionMethod
            LockStatus           = $bl.LockStatus
            AutoUnlockEnabled    = $bl.AutoUnlockEnabled
            KeyProtector         = ($bl.KeyProtector.KeyProtectorType -join ', ')
        } | Format-List
    }

    Write-Host "`n=== MANAGE-BDE DETAIL ===" -ForegroundColor Yellow
    $manageBde = (& manage-bde.exe -status $MountPoint 2>&1)
    $manageBde | ForEach-Object { Write-Host $_ }

    # -------------------------------------------------------------------------
    # WMI/CIM view - useful for suspension/reboot information
    # -------------------------------------------------------------------------
    Write-Host "`n=== BITLOCKER WMI STATE ===" -ForegroundColor Yellow

    $driveLetter = $MountPoint.TrimEnd('\')

    $vol = Get-CimInstance `
        -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
        -ClassName Win32_EncryptableVolume |
        Where-Object DriveLetter -eq $driveLetter

    if ($vol) {
        $protection = Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus

        [pscustomobject]@{
            DriveLetter      = $vol.DriveLetter
            ProtectionStatus = switch ($protection.ProtectionStatus) {
                0 { 'OFF / SUSPENDED' }
                1 { 'ON' }
                2 { 'UNKNOWN' }
                default { $protection.ProtectionStatus }
            }
            PersistentVolumeID = $vol.PersistentVolumeID
        } | Format-List
    }

    # -------------------------------------------------------------------------
    # Policies which can influence BitLocker
    # -------------------------------------------------------------------------
    Write-Host "`n=== BITLOCKER POLICY ===" -ForegroundColor Yellow

    $policyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\FVE',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker'
    )

    foreach ($path in $policyPaths) {
        if (Test-Path $path) {
            Write-Host "`n[$path]" -ForegroundColor DarkCyan
            Get-ItemProperty $path |
                Select-Object * -ExcludeProperty `
                    PSPath, PSParentPath, PSChildName, PSDrive, PSProvider |
                Format-List
        }
    }

    # -------------------------------------------------------------------------
    # Discover all BitLocker-related event logs instead of relying on one name
    # -------------------------------------------------------------------------
    Write-Host "`n=== BITLOCKER EVENTS ===" -ForegroundColor Yellow

    $logs = Get-WinEvent -ListLog * 2>$null |
        Where-Object {
            $_.LogName -match 'BitLocker|BitLocker-API|BitLocker-DrivePreparation'
        } |
        Where-Object { $_.IsEnabled } |
        Select-Object -ExpandProperty LogName -Unique

    $events = foreach ($log in $logs) {
        Get-WinEvent -FilterHashtable @{
            LogName   = $log
            StartTime = $Since
        } -ErrorAction SilentlyContinue
    }

    # Also look in System/Application for BitLocker providers
    $events += Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        StartTime = $Since
    } -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProviderName -match 'BitLocker|FVE|TPM'
    }

    $events += Get-WinEvent -FilterHashtable @{
        LogName   = 'Application'
        StartTime = $Since
    } -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProviderName -match 'BitLocker|FVE'
    }

    $events = $events |
        Sort-Object TimeCreated -Descending |
        Select-Object -Unique RecordId, TimeCreated, Id, LevelDisplayName,
            ProviderName, LogName, Message

    # Events most likely to explain suspension
    $interesting = $events | Where-Object {
        $_.Message -match '(?i)suspend|suspended|protection.*off|disable.*protector|' +
                          'protector.*disabled|reboot|firmware|BIOS|UEFI|TPM|' +
                          'update|maintenance|PCR|Secure Boot'
    }

    if ($interesting) {
        $interesting |
            Select-Object TimeCreated, Id, ProviderName, LogName,
                @{N='Message';E={
                    ($_.Message -replace "`r|`n",' ') -replace '\s+',' '
                }} |
            Format-Table -Wrap -AutoSize
    }
    else {
        Write-Host "No obvious suspension event found in the last $DaysBack days." `
            -ForegroundColor DarkYellow
    }

    # -------------------------------------------------------------------------
    # Try to determine the likely reason
    # -------------------------------------------------------------------------
    Write-Host "`n=== LIKELY CAUSE ===" -ForegroundColor Yellow

    $text = ($interesting.Message -join "`n")

    $cause = if ($text -match '(?i)firmware|BIOS|UEFI') {
        'Firmware/BIOS/UEFI maintenance appears to have triggered the suspension.'
    }
    elseif ($text -match '(?i)Windows Update|update|servicing|maintenance') {
        'Windows Update or servicing appears to have triggered the suspension.'
    }
    elseif ($text -match '(?i)TPM|PCR|Secure Boot') {
        'A TPM / PCR / Secure Boot change appears related to the suspension.'
    }
    elseif ($text -match '(?i)suspend|protector.*disabled|disable.*protector') {
        'BitLocker protectors were explicitly suspended/disabled. Check the events above for the process or management action responsible.'
    }
    elseif ($bl.ProtectionStatus -eq 'Off' -and
            $bl.VolumeStatus -match 'FullyEncrypted') {
        'The disk is encrypted but BitLocker protection is currently suspended. The original suspension event was not found in the available logs.'
    }
    else {
        'No definite cause could be established from the retained Windows event logs.'
    }

    Write-Host $cause -ForegroundColor Green

    Write-Host "`nNOTE: Do not run Resume-BitLocker yet if you are investigating the cause." `
        -ForegroundColor Cyan
}

Get-BitLockerSuspensionCause -DaysBack 60



#next
function Get-BitLockerRawHistory {
    param([int]$DaysBack = 30)

    $Since = (Get-Date).AddDays(-$DaysBack)

    $Logs = @(
        'Microsoft-Windows-BitLocker/BitLocker Management',
        'Microsoft-Windows-BitLocker-API/Management',
        'Microsoft-Windows-BitLocker-API/Operational'
    )

    foreach ($Log in $Logs) {
        if (Get-WinEvent -ListLog $Log -ErrorAction SilentlyContinue) {
            Write-Host "`n========== $Log ==========" -ForegroundColor Cyan

            Get-WinEvent -FilterHashtable @{
                LogName   = $Log
                StartTime = $Since
            } -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated |
            Select-Object TimeCreated, Id, ProviderName,
                @{N='Message';E={$_.Message -replace "`r?`n",' '}} |
            Format-List
        }
    }

    Write-Host "`n========== BitLocker Driver ==========" -ForegroundColor Cyan

    Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        StartTime = $Since
    } -ErrorAction SilentlyContinue |
    Where-Object ProviderName -eq 'Microsoft-Windows-BitLocker-Driver' |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id,
        @{N='Message';E={$_.Message -replace "`r?`n",' '}} |
    Format-List
}

Get-BitLockerRawHistory -DaysBack 30