# Simple Network Scanner for Windows
# Usage: .\network-scan.ps1

param(
    [string]$Network = "auto",
    [int[]]$Ports = @(22, 80, 443, 445, 3389, 8080),
    [int]$Timeout = 100
)

Write-Host "=== Simple Network Scanner ===" -ForegroundColor Cyan
Write-Host ""

# Get local IP and calculate network range
if ($Network -eq "auto") {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
    $Network = $localIP -replace '\.\d+$', '.0/24'
    Write-Host "Detected local network: $Network" -ForegroundColor Yellow
}

# Parse network range
$baseIP = $Network -replace '/\d+$', ''
$baseIP = $baseIP -replace '\.\d+$', ''

Write-Host "Scanning $baseIP.1-254 for active hosts..." -ForegroundColor Green
Write-Host ""

$activeHosts = @()

# Ping sweep
1..254 | ForEach-Object -Parallel {
    $ip = "$using:baseIP.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -Timeout 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        [PSCustomObject]@{
            IP = $ip
            Status = "Up"
        }
    }
} -ThrottleLimit 50 | ForEach-Object {
    $activeHosts += $_
    Write-Host "[+] Found: $($_.IP)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Found $($activeHosts.Count) active host(s)" -ForegroundColor Cyan
Write-Host ""

# Port scan active hosts
if ($activeHosts.Count -gt 0) {
    Write-Host "Scanning common ports on active hosts..." -ForegroundColor Green
    Write-Host ""

    foreach ($host in $activeHosts) {
        $openPorts = @()

        foreach ($port in $Ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($host.IP, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait -and $tcpClient.Connected) {
                $openPorts += $port
                $tcpClient.Close()
            } else {
                $tcpClient.Close()
            }
        }

        if ($openPorts.Count -gt 0) {
            Write-Host "$($host.IP) - Open ports: $($openPorts -join ', ')" -ForegroundColor Yellow
        } else {
            Write-Host "$($host.IP) - No common ports open" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "Scan complete!" -ForegroundColor Cyan
