function Get-LocalPortScan {
    [CmdletBinding()]
    param(
        [switch]$IncludeUDP,
        [switch]$NetworkOnly
    )

    Write-Verbose "Loading service information..."

    $ServiceMap = @{}

    Get-CimInstance Win32_Service | ForEach-Object {
        if ($_.ProcessId -gt 0) {
            if (-not $ServiceMap.ContainsKey($_.ProcessId)) {
                $ServiceMap[$_.ProcessId] = @()
            }

            $ServiceMap[$_.ProcessId] += $_
        }
    }


    function Get-ProcessInfo {
        param(
            [string]$Protocol,
            [string]$Address,
            [int]$Port,
            [int]$ProcessId
        )

        # --------------------------------------------------
        # Determine bind type
        # --------------------------------------------------

        $BindType = switch ($Address) {
            "127.0.0.1" { "LOCALHOST" }
            "::1"       { "LOCALHOST" }
            "0.0.0.0"   { "NETWORK" }
            "::"        { "NETWORK" }
            default     { "NETWORK" }
        }

        # Skip localhost-only bindings when requested
        if ($NetworkOnly -and $BindType -eq "LOCALHOST") {
            return
        }


        # --------------------------------------------------
        # Process information
        # --------------------------------------------------

        $Proc = Get-Process `
            -Id $ProcessId `
            -ErrorAction SilentlyContinue

        if ($Proc) {
            $ProcessName = $Proc.ProcessName
        }
        elseif ($ProcessId -eq 4) {
            $ProcessName = "System"
        }
        else {
            $ProcessName = "Unknown"
        }


        # --------------------------------------------------
        # Version information
        # --------------------------------------------------

        $Product = $null
        $Version = $null

        try {
            if ($Proc.Path) {

                $VI = [Diagnostics.FileVersionInfo]::GetVersionInfo(
                    $Proc.Path
                )

                $Product = $VI.ProductName

                if ($VI.ProductVersion) {
                    $Version = $VI.ProductVersion
                }
                else {
                    $Version = $VI.FileVersion
                }
            }
        }
        catch {
            Write-Verbose "Unable to read version for PID $ProcessId"
        }


        # --------------------------------------------------
        # Windows service information
        # --------------------------------------------------

        $ServiceName = ""

        if ($ServiceMap.ContainsKey($ProcessId)) {

            $ServiceName = (
                $ServiceMap[$ProcessId].Name |
                Sort-Object -Unique
            ) -join ","
        }


        # --------------------------------------------------
        # Build description
        # --------------------------------------------------

        $Details = @(
            $ServiceName
            $Product
            $Version
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }


        [PSCustomObject]@{
            Number  = $Port
            Port    = "$Port/$($Protocol.ToLower())"
            State   = if ($Protocol -eq "TCP") {
                "LISTENING"
            }
            else {
                "BOUND"
            }

            Bind    = $BindType
            Address = $Address
            Process = $ProcessName
            PID     = $ProcessId
            Details = $Details -join " "
        }
    }


    # ======================================================
    # TCP LISTENERS
    # ======================================================

    Write-Verbose "Enumerating TCP listening ports..."

    $Results = foreach (
        $Connection in Get-NetTCPConnection -State Listen
    ) {

        Get-ProcessInfo `
            -Protocol "TCP" `
            -Address $Connection.LocalAddress `
            -Port $Connection.LocalPort `
            -ProcessId $Connection.OwningProcess
    }


    # ======================================================
    # UDP ENDPOINTS
    # ======================================================

    if ($IncludeUDP) {

        Write-Verbose "Enumerating UDP bound endpoints..."

        $Results += foreach (
            $Endpoint in Get-NetUDPEndpoint
        ) {

            Get-ProcessInfo `
                -Protocol "UDP" `
                -Address $Endpoint.LocalAddress `
                -Port $Endpoint.LocalPort `
                -ProcessId $Endpoint.OwningProcess
        }
    }


    # ======================================================
    # REMOVE DUPLICATES
    #
    # Same process/port can appear as:
    #
    # 0.0.0.0:135
    # :::135
    #
    # We only need one entry in the summary.
    # ======================================================

    $Results = $Results |
        Where-Object { $_ } |
        Group-Object Port, PID, Bind |
        ForEach-Object {

            $Group = $_.Group

            # Prefer IPv4 address for display where available
            $Selected = $Group |
                Sort-Object {
                    if ($_.Address -eq "0.0.0.0") { 0 }
                    elseif ($_.Address -notmatch ":") { 1 }
                    elseif ($_.Address -eq "::") { 2 }
                    else { 3 }
                } |
                Select-Object -First 1

            $Selected
        } |
        Sort-Object Number, Port


    Write-Verbose "Found $($Results.Count) unique endpoints."


    # ======================================================
    # OUTPUT
    # ======================================================

    ""
    "PORT        STATE      BIND       ADDRESS              PROCESS                       PID     SERVICE / VERSION"
    "----        -----      ----       -------              -------                       ---     -----------------"

    foreach ($R in $Results) {

        "{0,-11} {1,-10} {2,-10} {3,-20} {4,-29} {5,-7} {6}" -f `
            $R.Port,
            $R.State,
            $R.Bind,
            $R.Address,
            $R.Process,
            $R.PID,
            $R.Details
    }
}

Get-LocalPortScan -NetworkOnly -IncludeUDP -Verbose