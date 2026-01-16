# Set Strict Mode to catch undefined variables
Set-StrictMode -Version Latest

# --- 1. Administrator Elevation Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating privileges to Administrator..." -ForegroundColor Cyan
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
        exit
    } catch {
        Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
        return
    }
}

# --- 2. Environment Configuration ---
$reportDir = Join-Path $env:TEMP "SystemHealthReports"
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

$fileDate = Get-Date -Format "yyyyMMdd_HHmmss"
$htmlPath = Join-Path $reportDir "Exhaustive_HealthReport_$fileDate.html"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# --- 3. Exhaustive Data Collection ---
$D = @{
    sysInfo = $null; osInfo = $null; cpuInfo = $null; ramModuleInfo = @();
    gpuInfo = @(); biosInfo = $null; boardInfo = $null; monitorInfo = @();
    diskInfo = @(); smartInfo = @(); bitLocker = @(); tpmStatus = $null;
    defender = $null; firewall = @(); updateStatus = $null;
    netAdapters = @(); activeConnections = @(); dnsSettings = @();
    battery = $null; criticalEvents = @(); userAccounts = @();
    bootMode = "Unknown";
}

Write-Host "Collecting all PC parameters (Hardware, Software, Security, Network)..." -ForegroundColor Yellow

try {
    # Hardware & Motherboard
    $D.sysInfo = Get-CimInstance Win32_ComputerSystem
    $D.biosInfo = Get-CimInstance Win32_BIOS
    $D.boardInfo = Get-CimInstance Win32_BaseBoard
    $D.cpuInfo = Get-CimInstance Win32_Processor
    $D.gpuInfo = Get-CimInstance Win32_VideoController
    $D.ramModuleInfo = Get-CimInstance Win32_PhysicalMemory 
    $D.monitorInfo = Get-CimInstance Win32_DesktopMonitor

    # OS & Performance
    $D.osInfo = Get-CimInstance Win32_OperatingSystem
    $D.userAccounts = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"

    # Security & Updates
    $D.tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
    $D.bitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    $D.defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $D.firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $D.updateStatus = Get-CimInstance -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperationsState" -ErrorAction SilentlyContinue

    # Storage
    $D.diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $D.smartInfo = Get-StorageReliabilityCounter -ErrorAction SilentlyContinue

    # Network
    $D.netAdapters = Get-NetAdapter | Where-Object Status -eq "Up"
    $D.dnsSettings = Get-DnsClientServerAddress -AddressFamily IPv4

    # Battery & Boot
    $D.battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { $D.bootMode = "UEFI" } else { $D.bootMode = "Legacy/BIOS" }

    # Critical Events
    $D.criticalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 20 -ErrorAction SilentlyContinue

} catch {
    Write-Host "Warning: Partial collection occurred: $($_.Exception.Message)" -ForegroundColor Gray
}

# --- 4. HTML Generation ---
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Exhaustive System Audit</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f9; color: #333; margin: 0; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border-top: 4px solid #3498db; }
        .card h2 { margin-top: 0; color: #2c3e50; font-size: 1.1rem; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { text-align: left; color: #7f8c8d; font-weight: 600; padding: 8px 4px; }
        td { padding: 8px 4px; border-bottom: 1px solid #f9f9f9; }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .badge { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .green { background: #e8f5e9; color: #2e7d32; }
        .red { background: #ffebee; color: #c62828; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Exhaustive System Audit</h1>
        <p>Device: $($D.sysInfo.Name) | Generated: $timestamp</p>
    </div>

    <div class="grid">
        <!-- Motherboard & BIOS -->
        <div class="card">
            <h2>Motherboard & BIOS</h2>
            <table>
                <tr><th>Manufacturer</th><td>$($D.boardInfo.Manufacturer)</td></tr>
                <tr><th>Model</th><td>$($D.boardInfo.Product)</td></tr>
                <tr><th>BIOS Version</th><td>$($D.biosInfo.SMBIOSBIOSVersion)</td></tr>
                <tr><th>Boot Mode</th><td>$($D.bootMode)</td></tr>
            </table>
        </div>

        <!-- Processor & GPU -->
        <div class="card">
            <h2>CPU & Graphics</h2>
            <table>
                <tr><th>CPU</th><td>$($D.cpuInfo.Name)</td></tr>
                <tr><th>Cores/Threads</th><td>$($D.cpuInfo.NumberOfCores) / $($D.cpuInfo.NumberOfLogicalProcessors)</td></tr>
                $($D.gpuInfo | ForEach-Object { "<tr><th>GPU</th><td>$($_.Name)</td></tr>" })
            </table>
        </div>

        <!-- Memory Modules -->
        <div class="card">
            <h2>Memory (RAM) Details</h2>
            <table>
                <tr><th>Slot</th><th>Capacity</th><th>Speed</th></tr>
                $($D.ramModuleInfo | ForEach-Object { 
                    "<tr><td>$($_.DeviceLocator)</td><td>$([math]::Round($_.Capacity/1GB, 0)) GB</td><td>$($_.Speed) MT/s</td></tr>" 
                })
            </table>
        </div>

        <!-- Security Status -->
        <div class="card">
            <h2>Security Configuration</h2>
            <table>
                <tr><th>TPM Status</th><td>$($D.tpmStatus.TpmPresent)</td></tr>
                <tr><th>Defender AV</th><td>$($D.defender.AntivirusEnabled)</td></tr>
                <tr><td>BitLocker</td><td>$($D.bitLocker.ProtectionStatus | Select-Object -First 1)</td></tr>
            </table>
        </div>

        <!-- Storage & SMART -->
        <div class="card">
            <h2>Local Storage</h2>
            <table>
                <tr><th>Drive</th><th>Size</th><th>Free %</th><th>Filesystem</th></tr>
                $($D.diskInfo | ForEach-Object {
                    $pct = [math]::Round(($_.FreeSpace / $_.Size)*100, 1)
                    "<tr><td>$($_.DeviceID)</td><td>$([math]::Round($_.Size/1GB, 1)) GB</td><td>$pct%</td><td>$($_.FileSystem)</td></tr>"
                })
            </table>
        </div>

        <!-- Network Interfaces -->
        <div class="card">
            <h2>Network Adapters</h2>
            <table>
                <tr><th>Interface</th><th>MAC Address</th><th>Link Speed</th></tr>
                $($D.netAdapters | ForEach-Object {
                    "<tr><td>$($_.Name)</td><td>$($_.MacAddress)</td><td>$($_.LinkSpeed)</td></tr>"
                })
            </table>
        </div>
    </div>

    <!-- Critical Event Log -->
    <div class="card" style="margin-top:20px;">
        <h2>System Error Log (Last 20 Events)</h2>
        <table style="font-size:0.8rem;">
            <tr><th width="20%">Time</th><th width="20%">Source</th><th>Message</th></tr>
            $($D.criticalEvents | ForEach-Object {
                "<tr><td>$($_.TimeCreated)</td><td>$($_.ProviderName)</td><td>$($_.Message)</td></tr>"
            })
        </table>
    </div>
</body>
</html>
"@

# --- 5. Output File Handling ---
try {
    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "`nSUCCESS: Exhaustive report generated." -ForegroundColor Green
    Write-Host $htmlPath -ForegroundColor White
    Start-Process $htmlPath
} catch {
    Write-Host "ERROR: Could not write file: $($_.Exception.Message)" -ForegroundColor Red
}
