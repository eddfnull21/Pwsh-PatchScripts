function Get-OfficeVersion {
    $result = [PSCustomObject]@{
        Product = $null
        Version = $null
        Architecture = $null
        InstallType = $null
    }

    # Click-to-Run (Microsoft 365 / Office 2019 / 2021)
    $c2rKey = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    if (Test-Path $c2rKey) {
        $cfg = Get-ItemProperty -Path $c2rKey

        $result.Product      = $cfg.ProductReleaseIds
        $result.Version      = $cfg.VersionToReport
        $result.Architecture = $cfg.Platform
        $result.InstallType  = "Click-to-Run"

        return $result
    }

    # MSI installations (Office 2016 and earlier)
    $officeVersions = "16.0","15.0","14.0","12.0"
    foreach ($ver in $officeVersions) {
        $key = "HKLM:\SOFTWARE\Microsoft\Office\$ver\Common\InstallRoot"

        if (Test-Path $key) {
            $path = (Get-ItemProperty -Path $key).Path
            $exe = Join-Path $path "WINWORD.EXE"

            if (Test-Path $exe) {
                $fileVersion = (Get-Item $exe).VersionInfo.ProductVersion

                $result.Product = switch ($ver) {
                    "16.0" { "Office 2016/2019/2021" }
                    "15.0" { "Office 2013" }
                    "14.0" { "Office 2010" }
                    "12.0" { "Office 2007" }
                }

                $result.Version = $fileVersion
                $result.Architecture = if ($path -match "Program Files \(x86\)") { "x86" } else { "x64" }
                $result.InstallType = "MSI"

                return $result
            }
        }
    }

    Write-Warning "Microsoft Office not found."
}

get-OfficeVersion