# Set Strict Mode to catch undefined variables
Set-StrictMode -Version Latest

# --- 1. Administrator Elevation Check ---
# Required for TPM, BitLocker, and Defender queries.
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
# Use the local Temp folder to avoid OneDrive/Cloud sync issues with the Documents folder.
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
}

Write-Host "Collecting system health data..." -ForegroundColor Yellow

try {
    # System & OS Info
    $D.sysInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $D.osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $D.cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    
    # Storage & Security
    $D.diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    $D.bitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    $D.tpmStatus = Get-Tpm -ErrorAction SilentlyContinue
    
    # Network & Events
    $D.netAdapters = Get-NetAdapter | Where-Object Status -eq "Up" -ErrorAction SilentlyContinue
    $D.criticalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 10 -ErrorAction SilentlyContinue

    # Boot Mode (Legacy vs UEFI)
    if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { $D.bootMode = "UEFI" } else { $D.bootMode = "Legacy/BIOS" }

} catch {
    Write-Host "Warning: Some data points could not be collected: $($_.Exception.Message)" -ForegroundColor Gray
}

# --- 4. HTML Generation ---
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Health Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; padding: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .status-ok { color: #27ae60; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <h1>System Health Report</h1>
    <p>Generated: $timestamp</p>

    <div class="card">
        <h2>System Information</h2>
        <table>
            <tr><th>Hostname</th><td>$($D.sysInfo.Name)</td></tr>
            <tr><th>OS</th><td>$($D.osInfo.Caption) ($($D.osInfo.OSArchitecture))</td></tr>
            <tr><th>CPU</th><td>$($D.cpuInfo.Name)</td></tr>
            <tr><th>Boot Mode</th><td>$($D.bootMode)</td></tr>
            <tr><th>TPM Present</th><td>$($D.tpmStatus.TpmPresent)</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Storage Status</h2>
        <table>
            <tr><th>Drive</th><th>Size (GB)</th><th>Free Space (%)</th></tr>
            $($D.diskInfo | ForEach-Object {
                "<tr><td>$($_.DeviceID)</td><td>$([math]::Round($_.Size/1GB, 2))</td><td>$([math]::Round(($_.FreeSpace/$_.Size)*100, 1))%</td></tr>"
            })
        </table>
    </div>

    <div class="card">
        <h2>Critical System Events (Last 10)</h2>
        <table>
            <tr><th>Time</th><th>Source</th><th>Message</th></tr>
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
    Write-Host "`nSUCCESS: Report generated at:" -ForegroundColor Green
    Write-Host $htmlPath -ForegroundColor White
    
    # Automatically open the report
    Start-Process $htmlPath
} catch {
    Write-Host "CRITICAL ERROR: Could not write file. Ensure $htmlPath is not open." -ForegroundColor Red
}
