# Simple Network Scanner for Windows
# Usage: .\network-scan.ps1

param(
    [string]$Network = "auto",
    [int[]]$Ports = @(22, 80, 443, 445, 3389, 8080),
    [int]$Timeout = 100
)

# Clear screen for clean output
Clear-Host

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

Write-Host "  Scanning $baseIP.1-254 for active hosts..." -NoNewline -ForegroundColor Gray

# Ping sweep - collect all results silently first
$activeHosts = 1..254 | ForEach-Object -Parallel {
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
            SortKey = [int]($ip -split '\.')[-1]
        }
    }
} -ThrottleLimit 50

# Sort results by IP
$activeHosts = $activeHosts | Sort-Object SortKey

Write-Host " Done!" -ForegroundColor Green
Write-Host ""
Write-Host "  Found $($activeHosts.Count) active host(s)" -ForegroundColor Cyan
Write-Host ""

# Display summary table with hostnames prominent
if ($activeHosts.Count -gt 0) {
    Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  DISCOVERED DEVICES                                            │" -ForegroundColor Cyan
    Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    
    foreach ($h in $activeHosts) {
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

    # Port scan active hosts - collect results first
    Write-Host "  Scanning common ports..." -NoNewline -ForegroundColor Gray
    
    $portResults = @()
    foreach ($h in $activeHosts) {
        $openPorts = @()

        foreach ($port in $Ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($h.IP, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait -and $tcpClient.Connected) {
                $openPorts += $port
            }
            $tcpClient.Close()
        }

        $portResults += [PSCustomObject]@{
            Host = $h
            OpenPorts = $openPorts
        }
    }
    
    Write-Host " Done!" -ForegroundColor Green
    Write-Host ""
    
    # Display port results
    Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  OPEN PORTS                                                    │" -ForegroundColor Cyan
    Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray

    foreach ($result in $portResults) {
        $h = $result.Host
        $openPorts = $result.OpenPorts
        $displayName = if ($h.Hostname) { $h.Hostname } else { $h.IP }
        
        if ($openPorts.Count -gt 0) {
            $portsStr = $openPorts -join ', '
            $namePart = $displayName.PadRight(25)
            Write-Host "│  " -NoNewline -ForegroundColor DarkGray
            if ($h.Hostname) {
                Write-Host "$namePart" -NoNewline -ForegroundColor White
            } else {
                Write-Host "$namePart" -NoNewline -ForegroundColor Yellow
            }
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($portsStr.PadRight(28))" -NoNewline -ForegroundColor Green
            Write-Host "│" -ForegroundColor DarkGray
        } else {
            $namePart = $displayName.PadRight(25)
            Write-Host "│  " -NoNewline -ForegroundColor DarkGray
            Write-Host "$namePart" -NoNewline -ForegroundColor DarkGray
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "no open ports                   " -NoNewline -ForegroundColor DarkGray
            Write-Host "│" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "└────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Scan complete!                                              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
