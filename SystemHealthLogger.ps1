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
$htmlPath = Join-Path $reportDir "HealthReport_$fileDate.html"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# --- 3. Data Collection ---
$D = @{
    sysInfo = "N/A"; osInfo = "N/A"; cpuInfo = "N/A"; memInfo = "N/A";
    diskInfo = @(); bitLocker = @(); tpmStatus = "N/A"; bootMode = "Unknown";
    defender = "N/A"; netAdapters = @(); criticalEvents = @();
    battery = "N/A"; firewall = "N/A";
}

Write-Host "Collecting comprehensive system health data..." -ForegroundColor Yellow

try {
    # Hardware & OS
    $D.sysInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $D.osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $D.cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    
    # Memory Calculation
    $totalRam = [math]::Round($D.osInfo.TotalVisibleMemorySize / 1MB, 2)
    $freeRam = [math]::Round($D.osInfo.FreePhysicalMemory / 1MB, 2)
    $D.memInfo = @{ Total = $totalRam; Free = $freeRam; UsedPercent = [math]::Round((($totalRam - $freeRam) / $totalRam) * 100, 1) }

    # Storage & Security
    $D.diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    $D.bitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    $D.tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
    
    # Security Status (Defender & Firewall)
    $D.defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $D.firewall = Get-NetFirewallProfile -Name Domain, Public, Private -ErrorAction SilentlyContinue

    # Battery (if laptop)
    $D.battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue

    # Network
    $D.netAdapters = Get-NetAdapter | Where-Object Status -eq "Up" -ErrorAction SilentlyContinue
    
    # Events
    $D.criticalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 10 -ErrorAction SilentlyContinue

    # Boot Mode
    if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { $D.bootMode = "UEFI" } else { $D.bootMode = "Legacy/BIOS" }

} catch {
    Write-Host "Warning: Some data points were skipped: $($_.Exception.Message)" -ForegroundColor Gray
}

# --- 4. HTML Generation ---
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive System Health</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; padding: 30px; line-height: 1.6; }
        .container { max-width: 1000px; margin: auto; }
        .card { background: white; border-radius: 12px; padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border-left: 5px solid #3498db; }
        .card-security { border-left-color: #e74c3c; }
        .card-hardware { border-left-color: #2ecc71; }
        h1 { color: #1a2a6c; margin-bottom: 5px; }
        h2 { color: #2c3e50; margin-top: 0; font-size: 1.2rem; text-transform: uppercase; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px 8px; border-bottom: 1px solid #edf2f7; }
        th { color: #718096; font-weight: 600; font-size: 0.9rem; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .bg-green { background: #d4edda; color: #155724; }
        .bg-red { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Health Dashboard</h1>
        <p>Report generated on: <strong>$timestamp</strong></p>

        <div class="card card-hardware">
            <h2>Core Hardware</h2>
            <table>
                <tr><th>Component</th><th>Detail</th></tr>
                <tr><td>Hostname</td><td>$($D.sysInfo.Name)</td></tr>
                <tr><td>Processor</td><td>$($D.cpuInfo.Name)</td></tr>
                <tr><td>Memory</td><td>$($D.memInfo.Total) GB ($($D.memInfo.UsedPercent)% Used)</td></tr>
                <tr><td>Boot Mode</td><td>$($D.bootMode)</td></tr>
                $(if($D.battery){ "<tr><td>Battery</td><td>$($D.battery.EstimatedChargeRemaining)% Remaining</td></tr>" })
            </table>
        </div>

        <div class="card card-security">
            <h2>Security & Compliance</h2>
            <table>
                <tr><th>Check</th><th>Status</th></tr>
                <tr><td>Real-Time Protection</td><td>$($D.defender.RealTimeProtectionEnabled)</td></tr>
                <tr><td>TPM Enabled</td><td>$($D.tpmStatus.TpmPresent)</td></tr>
                <tr><td>Antivirus Signatures</td><td>$($D.defender.AntivirusSignatureLastUpdated)</td></tr>
                <tr><td>BitLocker</td><td>$($D.bitLocker.ProtectionStatus | Select-Object -First 1)</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Storage Utilization</h2>
            <table>
                <tr><th>Drive</th><th>Format</th><th>Size (GB)</th><th>Free (%)</th></tr>
                $($D.diskInfo | ForEach-Object {
                    $freePct = [math]::Round(($_.FreeSpace/$_.Size)*100, 1)
                    $class = if($freePct -lt 10){ "bg-red" } else { "bg-green" }
                    "<tr><td>$($_.DeviceID)</td><td>$($_.FileSystem)</td><td>$([math]::Round($_.Size/1GB, 1))</td><td><span class='badge $class'>$freePct%</span></td></tr>"
                })
            </table>
        </div>

        <div class="card">
            <h2>Active Network Interfaces</h2>
            <table>
                <tr><th>Adapter</th><th>Speed</th><th>MAC Address</th></tr>
                $($D.netAdapters | ForEach-Object {
                    "<tr><td>$($_.Name)</td><td>$($_.LinkSpeed)</td><td>$($_.MacAddress)</td></tr>"
                })
            </table>
        </div>

        <div class="card">
            <h2>Recent Critical Events</h2>
            <table style="font-size: 0.85rem;">
                <tr><th>Time</th><th>Message</th></tr>
                $($D.criticalEvents | ForEach-Object {
                    "<tr><td>$($_.TimeCreated)</td><td>$($_.Message)</td></tr>"
                })
            </table>
        </div>
    </div>
</body>
</html>
"@

# --- 5. Output File Handling ---
try {
    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Host "`nSUCCESS: Report generated at:" -ForegroundColor Green
    Write-Host $htmlPath -ForegroundColor White
    Start-Process $htmlPath
} catch {
    Write-Host "CRITICAL ERROR: Could not write file. Error: $($_.Exception.Message)" -ForegroundColor Red
}
