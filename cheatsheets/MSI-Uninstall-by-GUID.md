# MSI uninstall by GUID

Remove an app by its product code, then clean the uninstall entry it leaves behind. A leftover entry keeps vulnerability scanners flagging the app after it's gone. Copy-paste into an elevated PowerShell or an RMM remote shell (often running as SYSTEM). Run **one block at a time** and replace anything in `<angle brackets>`.

To find software across every logged-on user first, use `Get-Software` in the [Windows patching quick reference](Windows-Patching-QuickRef.md#find-installed-software-all-users).

## Contents

- [Find the product code](#find-the-product-code)
- [Uninstall one GUID and clean up](#uninstall-one-guid-and-clean-up)
- [Several GUIDs](#several-guids)
- [Bundles in Package Cache](#bundles-in-package-cache)
- [Find the app's service](#find-the-apps-service)
- [Exit codes](#exit-codes)

## Find the product code

The key name (`PSChildName`) is the GUID for MSI installs. `HKCU` here is the current user only, which is SYSTEM's own hive in an RMM shell.

```powershell
$AppName = '<AppName>'
$UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*$AppName*" } |
    Select-Object DisplayName, DisplayVersion, PSChildName, UninstallString
```

Avoid `wmic product` and `Win32_Product`. They're slow, they make Windows Installer run a consistency check (a self-repair) on every MSI product, and `wmic` is removed from current Windows 11 builds.

## Uninstall one GUID and clean up

Uses `$AppName` and `$UninstallPaths` from the block above.

```powershell
$Guid = '{<ProductCode-GUID>}'
$p = Start-Process msiexec.exe -ArgumentList "/x $Guid /qn /norestart /L*v `"$env:TEMP\$AppName-uninstall.log`"" -Wait -PassThru
"Exit code: $($p.ExitCode)"
```

Remove the leftover uninstall key **only after a success code** (0, 1605, 1614, 1641, 3010). After a failure, that key may be the only sign that the app is still installed.

```powershell
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Guid",
"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$Guid" |
    Where-Object { Test-Path $_ } |
    Remove-Item -Recurse -Force
```

Confirm it's gone:

```powershell
Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*$AppName*" } |
    Select-Object DisplayName, DisplayVersion, PSChildName
```

## Several GUIDs

Uninstalls each GUID and cleans its key only when the uninstall succeeded.

```powershell
$ProductGuids = @(
    '{<ProductCode-GUID-1>}'
    '{<ProductCode-GUID-2>}'
)
foreach ($guid in $ProductGuids) {
    $p = Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru
    Write-Host "$guid exit: $($p.ExitCode)"
    if ($p.ExitCode -in 0, 1605, 1614, 1641, 3010) {
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$guid" |
            Where-Object { Test-Path $_ } |
            Remove-Item -Recurse -Force
    }
}
```

Then rerun the check from [Find the product code](#find-the-product-code).

## Bundles in Package Cache

Some setup `.exe` installers (WiX "Burn" bundles, which wrap several MSIs) also register under a GUID key, but they aren't MSI products: `msiexec /x` returns 1605 and removes nothing. Run the cached setup instead. Find it from the entry's `BundleCachePath` or `QuietUninstallString`:

```powershell
Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*$AppName*" -and $_.BundleCachePath } |
    Select-Object DisplayName, BundleCachePath, QuietUninstallString
```

```powershell
$p = Start-Process '<BundleCachePath, e.g. C:\ProgramData\Package Cache\{<GUID>}\<Setup>.exe>' `
    -ArgumentList '/uninstall /quiet /norestart' -Wait -PassThru
"Exit code: $($p.ExitCode)"
```

## Find the app's service

Agents often leave a service behind:

```powershell
Get-Service | Where-Object { $_.Name -like "*$AppName*" -or $_.DisplayName -like "*$AppName*" }
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Uninstalled |
| 1605 | Not installed in this context. Also what you get for another user's per-user install, which `msiexec` can't see from SYSTEM |
| 1614 | Already uninstalled |
| 1618 | Another install is running. See [Watch MSI installs live](Windows-Patching-QuickRef.md#watch-msi-installs-live) |
| 1641 | Uninstalled; a restart was started |
| 3010 | Uninstalled; restart required |
| 1603 | Fatal error. Read the `/L*v` log, searching for `Return value 3` |
