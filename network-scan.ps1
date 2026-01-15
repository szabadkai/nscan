# Simple Network Scanner for Windows
# Usage: .\network-scan.ps1

param(
    [string]$Network = "auto",
    [int[]]$Ports = @(22, 80, 443, 445, 3389, 8080),
    [int]$Timeout = 100
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              SIMPLE NETWORK SCANNER                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get local IP and calculate network range
if ($Network -eq "auto") {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
    $Network = $localIP -replace '\.\d+$', '.0/24'
    Write-Host "  Detected local network: " -NoNewline -ForegroundColor Gray
    Write-Host "$Network" -ForegroundColor Yellow
}

# Parse network range
$baseIP = $Network -replace '/\d+$', ''
$baseIP = $baseIP -replace '\.\d+$', ''

Write-Host "  Scanning $baseIP.1-254 for active hosts..." -ForegroundColor Gray
Write-Host ""

$activeHosts = @()

# Ping sweep
1..254 | ForEach-Object -Parallel {
    $ip = "$using:baseIP.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -Timeout 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        # Try to resolve hostname
        $hostname = $null
        try {
            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
        } catch {
            # Try NetBIOS name via nbtstat
            try {
                $nbtResult = nbtstat -A $ip 2>$null | Select-String '<00>' | Select-Object -First 1
                if ($nbtResult) {
                    $hostname = ($nbtResult -split '\s+')[1]
                }
            } catch { }
        }
        
        [PSCustomObject]@{
            IP = $ip
            Hostname = $hostname
            Status = "Up"
        }
    }
} -ThrottleLimit 50 | ForEach-Object {
    $activeHosts += $_
    if ($_.Hostname) {
        Write-Host "  [+] " -NoNewline -ForegroundColor Green
        Write-Host "$($_.Hostname)" -NoNewline -ForegroundColor White
        Write-Host " ($($_.IP))" -ForegroundColor DarkGray
    } else {
        Write-Host "  [+] $($_.IP)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "  Found $($activeHosts.Count) active host(s)" -ForegroundColor Cyan
Write-Host ""

# Display summary table with hostnames prominent
if ($activeHosts.Count -gt 0) {
    Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  DISCOVERED DEVICES                                            │" -ForegroundColor Cyan
    Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    
    foreach ($h in ($activeHosts | Sort-Object { [version]($_.IP -replace '(\d+)\.(\d+)\.(\d+)\.(\d+)', '$1.$2.$3.$4') })) {
        $displayName = if ($h.Hostname) { $h.Hostname } else { "(unknown)" }
        $ipPadded = $h.IP.PadRight(15)
        $namePadded = $displayName.PadRight(30)
        
        if ($h.Hostname) {
            Write-Host "│  " -NoNewline -ForegroundColor DarkGray
            Write-Host "$namePadded" -NoNewline -ForegroundColor White
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host "$ipPadded" -NoNewline -ForegroundColor Yellow
            Write-Host "  │" -ForegroundColor DarkGray
        } else {
            Write-Host "│  " -NoNewline -ForegroundColor DarkGray
            Write-Host "$namePadded" -NoNewline -ForegroundColor DarkGray
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host "$ipPadded" -NoNewline -ForegroundColor Yellow
            Write-Host "  │" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "└────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    # Port scan active hosts
    Write-Host "  Scanning common ports on active hosts..." -ForegroundColor Gray
    Write-Host ""

    foreach ($h in $activeHosts) {
        $openPorts = @()

        foreach ($port in $Ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($h.IP, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait -and $tcpClient.Connected) {
                $openPorts += $port
                $tcpClient.Close()
            } else {
                $tcpClient.Close()
            }
        }

        # Display with hostname prominent
        $displayName = if ($h.Hostname) { $h.Hostname } else { $h.IP }
        
        if ($openPorts.Count -gt 0) {
            Write-Host "  " -NoNewline
            if ($h.Hostname) {
                Write-Host "$displayName" -NoNewline -ForegroundColor White
                Write-Host " ($($h.IP))" -NoNewline -ForegroundColor DarkGray
            } else {
                Write-Host "$displayName" -NoNewline -ForegroundColor Yellow
            }
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($openPorts -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "  " -NoNewline
            if ($h.Hostname) {
                Write-Host "$displayName" -NoNewline -ForegroundColor Gray
                Write-Host " ($($h.IP))" -NoNewline -ForegroundColor DarkGray
            } else {
                Write-Host "$displayName" -NoNewline -ForegroundColor DarkGray
            }
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "no open ports" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Scan complete!                                              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
