# Save as: EnterpriseSystemHealthDashboard.ps1
# Forces PowerShell to catch non-terminating errors, though we have error handling in place.
Set-StrictMode -Version Latest

# Define the timestamp and the path where the final HTML report will be saved.
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$htmlPath = "$env:USERPROFILE\Documents\EnterpriseSystemHealthDashboard.html"

# --- 1. Initialize Diagnostics Data Structure ---
# Using a hashtable ($D) to reliably store all results from every command, 
# ensuring all variables exist before use, even if commands fail.
$D = @{
    sysInfo = $null; biosInfo = $null; osInfo = $null; cpuInfo = $null; memInfo = $null;
    diskInfo = @(); bitLocker = @(); defender = $null; netAdapters = @();
    installedApps = @(); tpmStatus = $null; driveHealth = @();
    bootMode = "Error/Unknown"; pingAzure = "N/A"; pingDNS = "N/A";
    lowSpaceDrives = @(); wearPercent = "N/A"; criticalEvents = @();
    virtualMemoryStatus = "N/A";
}

# --- 2. Robust Data Collection using Try/Catch ---
# This function queries the Windows system (WMI/CIM, Registry) for all necessary hardware and health information.
function Get-SystemData {
    param(
        [Parameter(Mandatory=$true)]$DataHash
    )
    
    # Store volatile commands inside a safe block
    try {
        # Core Hardware/OS Information Collection (CIM)
        $DataHash.sysInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $DataHash.biosInfo = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $DataHash.osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $DataHash.cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop
        $DataHash.memInfo = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | Measure-Object -Property Capacity -Sum
        
        # Storage and Health Checks
        $DataHash.diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop # Local fixed drives
        $DataHash.bitLocker = Get-BitLockerVolume -ErrorAction Stop # BitLocker status
        $DataHash.driveHealth = Get-CimInstance -ClassName MSStorageDriver_FailurePredictStatus -Namespace root\wmi -ErrorAction Stop |
            Where-Object {$_.PredictFailure -ne $false} # Checks for drives predicting failure (SMART)
        
        # Security and Network Information
        $DataHash.defender = Get-MpComputerStatus -ErrorAction Stop # Windows Defender status
        $DataHash.tpmStatus = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop # TPM (Trusted Platform Module) status
        $DataHash.netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq "Up"} # Active network adapters
        
        # Installed Applications List (Can be slow or fail on permissions)
        $DataHash.installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher | Where-Object {$_.DisplayName} -ErrorAction SilentlyContinue

        # Paging File Check (Virtual Memory)
        $pagingFile = Get-CimInstance Win32_PageFileSetting -ErrorAction Stop
        if ($pagingFile) {
            $DataHash.virtualMemoryStatus = "Configured: $($pagingFile.Name) | Minimum: $($pagingFile.MinimumSize)MB | Maximum: $($pagingFile.MaximumSize)MB"
        } else {
             $DataHash.virtualMemoryStatus = "Not Configured"
        }

    } catch {
        # Log any errors caught during the core data collection phase (e.g., CIM/WMI failed)
        Write-Warning "A critical error occurred during data collection: $($_.Exception.Message)"
    }
    
    # Secure Boot Check (requires elevated privileges, check command existence first)
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try {
            # Use standard if/else for compatibility across all PowerShell versions
            if ((Confirm-SecureBootUEFI) -eq $true) { 
                $DataHash.bootMode = "UEFI"
            } else {
                $DataHash.bootMode = "Legacy BIOS"
            }
        } catch {
            $DataHash.bootMode = "Access Denied (Run as Admin)"
        }
    }

    # Connectivity Tests (Ping external services)
    $DataHash.pingAzure = if (Test-Connection -ComputerName "azure.microsoft.com" -Count 2 -Quiet -ErrorAction SilentlyContinue) { "OK" } else { "FAIL" }
    $DataHash.pingDNS = if (Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue) { "OK" } else { "FAIL" }

    # Critical Events (Last 24h: System Log, Level 1=Critical, 2=Error)
    $startTime = (Get-Date).AddDays(-1)
    try {
        $DataHash.criticalEvents = Get-WinEvent -FilterHashTable @{LogName='System'; Level=1,2; StartTime=$startTime} -ErrorAction Stop | Select-Object TimeCreated, Id, Message -First 5
    } catch {
        $DataHash.criticalEvents = "Error accessing System Log"
    }

    # Sample Battery Data (used for demonstration chart and wear calculation)
    # NOTE: Live battery capacity requires more complex WMI queries which are not standardized, so sample data is used here.
    $DataHash.batteryLabels = "'Sep 5','Sep 12','Sep 19','Sep 26','Oct 3','Oct 4','Oct 5'"
    $DataHash.fullChargeData = "43846,44140,44033,43899,43984,43950,43410"
    $DataHash.designCapacity = 50510
    $DataHash.latestCapacity = 43410
}

# Execute the data collection function
Get-SystemData -DataHash $D


# --- 3. Anomaly Detection and Recommendation Generation ---
# This section analyzes the collected raw data ($D) and translates it into specific health statuses, findings, and actionable recommendations.

$lowDiskSpaceThreshold = 10 # Percent threshold to flag a drive as critical
$diskSpaceStatus = "OK"
foreach ($disk in $D.diskInfo) {
    if ($disk.Size -gt 0) {
        $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
        if ($freeSpacePercent -lt $lowDiskSpaceThreshold) {
            $D.lowSpaceDrives += "$($disk.DeviceID) ($freeSpacePercent% Free)"
        }
    }
}
if ($D.lowSpaceDrives.Count -gt 0) {
    $diskSpaceStatus = "CRITICAL"
}

$smartStatus = "OK"
if ($D.driveHealth.Count -gt 0) {
    $smartStatus = "CRITICAL"
}

$eventLogStatus = "OK"
if ($D.criticalEvents -is [System.Collections.ICollection] -and $D.criticalEvents.Count -gt 0) {
    $eventLogStatus = "WARNING"
} elseif ($D.criticalEvents -eq "Error accessing System Log") {
    $eventLogStatus = "WARNING"
}

# Calculate Battery Wear Percentage (based on sample data)
$wearPercent = "N/A"
if ($D.designCapacity -ne 0) {
    $wearPercent = [math]::Round((1 - ($D.latestCapacity / $D.designCapacity)) * 100, 2)
    $D.wearPercent = $wearPercent
}


# --- Generate Findings and Recommendations ---
$findings = @()        # Array to store detected issues (the "what is wrong")
$recommendations = @() # Array to store required actions (the "how to fix it")

# Helper function to safely retrieve properties from objects which might be null
function Get-SafeProperty {
    param($Object, $Property, $DefaultValue = 'N/A')
    if ($Object -and $Object.$Property -ne $null) {
        return $Object.$Property
    }
    return $DefaultValue
}

# Rule Checks: Add findings/recommendations based on the determined statuses

# Disk Health (SMART & Low Space)
if ($smartStatus -eq "CRITICAL") {
    $findings += "Storage Integrity Warning: Predictive failure warnings detected on one or more drives."
    $recommendations += "Immediate Action Required: **Back up all critical data immediately.** Plan to replace the failing drive (SSD/HDD) soon to prevent potential data loss."
}

if ($diskSpaceStatus -eq "CRITICAL") {
    $diskSpaceText = $D.lowSpaceDrives -join '; '
    $findings += "Critical Disk Space: Low space detected on: $diskSpaceText. Disk performance may degrade rapidly."
    $recommendations += "Free up space on the affected drive(s) by deleting large files, clearing temporary files, or offloading data to external storage."
}

# Memory/Paging File Check
$ramTotalGB = [math]::Round(Get-SafeProperty -Object $D.memInfo -Property Sum / 1GB, 2, 0)
if ($D.virtualMemoryStatus -eq "Not Configured") {
    $findings += "Virtual Memory Alert: Paging file (Virtual Memory) is not configured, which can cause instability or crashes under high memory load."
    $recommendations += "It is highly recommended to configure a system-managed Paging File to prevent system instability, even if you have sufficient physical RAM ($($ramTotalGB)GB)."
}

# Battery Health
if ($D.wearPercent -is [double] -and $D.wearPercent -gt 25) {
    $findings += "Significant Battery Degradation: The battery wear rate is $($D.wearPercent)%, indicating considerable capacity loss."
    $recommendations += "For optimal mobility and run time, consider replacing the laptop battery, as its current capacity is significantly reduced."
}

# Security Findings (Defender)
$defenderRT = Get-SafeProperty -Object $D.defender -Property RealTimeProtectionEnabled
if ($defenderRT -ne "True") {
    $findings += "Security Alert: Real-Time Protection is currently disabled."
    $recommendations += "Immediate Action Required: Enable Windows Defender Real-Time Protection to ensure the system is protected against active threats."
}

# TPM/Secure Boot Finding
$tpmReady = Get-SafeProperty -Object $D.tpmStatus -Property IsReady -DefaultValue $false
if ($tpmReady -ne $true) {
     $findings += "Security Hardware Status: TPM is reported as not ready or absent."
     $recommendations += "If TPM is expected, check BIOS settings to ensure it is enabled and active. This is often required for modern security features (e.g., BitLocker)."
}

# --- Overall Health Calculation ---
# Determines the single, highest-severity status (CRITICAL > WARNING/FAIL > HEALTHY) for the final report header.
$overallStatus = "HEALTHY"
$healthChecks = @($diskSpaceStatus, $smartStatus, $eventLogStatus, $D.bootMode, $D.pingAzure, $D.pingDNS, $D.virtualMemoryStatus)

if ($healthChecks -contains "CRITICAL") {
    $overallStatus = "CRITICAL"
} elseif ($healthChecks -match "WARNING|FAIL|Access Denied|Not Configured|Error") {
    $overallStatus = "WARNING"
}

# Set the CSS class based on the calculated status
$overallStatusClass = "status-ok"
if ($overallStatus -eq "CRITICAL") {
    $overallStatusClass = "status-critical"
} elseif ($overallStatus -eq "WARNING") {
    $overallStatusClass = "status-warning"
}


# --- HTML Generation ---
# This section constructs the final HTML report using a HEREDOC string (@"...") 
# and dynamic PowerShell code injection to insert data into the HTML tables.

# Convert Findings and Recommendations arrays into HTML list elements
$findingsHtml = if ($findings.Count -gt 0) {
    "<ul class='findings-list'>" + ($findings | ForEach-Object { "<li>$_</li>" }) -join "" + "</ul>"
} else {
    "<p class='status-ok status-block'>**No major anomalies or critical issues were automatically detected.** System health appears good.</p>"
}

$recommendationsHtml = if ($recommendations.Count -gt 0) {
    "<ul class='recommendation-list'>" + ($recommendations | ForEach-Object { "<li>$_</li>" }) -join "" + "</ul>"
} else {
    "<p>The system is generally stable. Continue regular maintenance (updates, backups) as a best practice.</p>"
}


$html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>Endpoint Device Summary</title>
  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
  <style>
    :root {
      --primary-color: #005a9c;
      --bg-color: #f8f8f8;
      --card-bg: #ffffff;
      --border-color: #ddd;
      --font-color: #333;
    }
    body { 
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        background: var(--bg-color); 
        color: var(--font-color);
        margin: 0; 
        display: flex;
    }
    h1, h2, h3 { color: var(--primary-color); }
    h1 { font-size: 1.8em; margin: 0 0 10px 0; }
    h2 { font-size: 1.4em; border-bottom: 2px solid #eee; padding-bottom: 5px; margin-bottom: 15px; }
    
    /* Layout */
    .sidebar {
        width: 250px;
        background: var(--card-bg);
        box-shadow: 2px 0 5px rgba(0,0,0,0.05);
        padding: 20px;
        height: 100vh;
        position: fixed;
        top: 0;
        left: 0;
        overflow-y: auto;
    }
    .main-content {
        margin-left: 250px; /* Offset for fixed sidebar */
        padding: 20px 30px;
        width: 100%;
        max-width: 1200px;
    }
    .header {
        border-bottom: 3px solid var(--primary-color);
        margin-bottom: 20px;
        padding-bottom: 10px;
    }

    /* Section Styling */
    .section { 
        background: var(--card-bg); 
        padding: 20px; 
        margin-bottom: 25px; 
        border-radius: 8px; 
        box-shadow: 0 4px 6px rgba(0,0,0,0.05); 
        border-left: 4px solid var(--primary-color);
    }
    
    /* Navigation Links */
    .nav-links { list-style: none; padding: 0; }
    .nav-links li { margin-bottom: 8px; }
    .nav-links a {
        display: block;
        padding: 8px 10px;
        text-decoration: none;
        color: var(--font-color);
        border-radius: 4px;
        transition: background-color 0.2s;
    }
    .nav-links a:hover { background-color: #f0f0f0; }
    .nav-links .active { 
        background-color: var(--primary-color); 
        color: white !important; 
        font-weight: bold;
    }

    /* Table Styling */
    table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 15px; border-radius: 8px; overflow: hidden; }
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
    th { background-color: #eef; color: #444; font-weight: 600; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    tr:last-child td { border-bottom: none; }

    /* Status Blocks */
    .status-block {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 0.9em;
        text-transform: uppercase;
        margin: 2px 0;
    }
    .status-ok { background-color: #d4edda; color: #155724; }
    .status-warning { background-color: #fff3cd; color: #856404; }
    .status-critical { background-color: #f8d7da; color: #721c24; }
    .status-na { background-color: #eee; color: #666; }

    /* Summary & Recommendation Styling */
    .recommendation-list { list-style: disc; padding-left: 20px; }
    .recommendation-list li { margin-bottom: 10px; font-size: 0.95em; }
    .findings-list { list-style: circle; padding-left: 20px; font-style: italic; color: #777; margin-bottom: 20px;}
    .recommendation-list li:first-child { color: #cc0000; font-weight: bold; } /* Highlight first critical item */
    
    /* Footer */
    .footer {
        margin-top: 30px;
        padding-top: 15px;
        border-top: 1px solid #ddd;
        text-align: center;
        font-size: 0.8em;
        color: #777;
    }

    /* Timer */
    .timer { font-size: 0.9em; color: #666; }

    /* Media Queries for responsiveness */
    @media (max-width: 900px) {
        .sidebar {
            width: 100%;
            height: auto;
            position: relative;
            box-shadow: none;
            border-bottom: 1px solid var(--border-color);
        }
        .main-content {
            margin-left: 0;
            padding: 15px;
        }
        .sidebar .nav-links { display: flex; flex-wrap: wrap; justify-content: space-around; }
        .sidebar .nav-links li { width: 45%; margin: 5px 0; }
        .sidebar h3, .sidebar p { display: none; }
    }
  </style>
</head>
<body>
    
  <!-- Navigation Sidebar -->
  <div class='sidebar'>
    <h3>Endpoint Device Summary</h3>
    <p class='timer'>Last updated: <span id='last-updated-timer'>...</span></p>
    <ul class='nav-links'>
      <li><a href='#summary-section'>Summary & Recommendations</a></li>
      <li><a href='#device-section'>Device Info</a></li>
      <li><a href='#cpu-mem-section'>CPU & Memory</a></li>
      <li><a href='#storage-section'>Storage</a></li>
      <li><a href='#battery-section'>Battery Health</a></li>
      <li><a href='#bitlocker-section'>BitLocker Status</a></li>
      <li><a href='#defender-section'>Windows Defender</a></li>
      <li><a href='#network-section'>Network</a></li>
      <li><a href='#connectivity-section'>Connectivity</a></li>
      <li><a href='#events-section'>Critical Events</a></li>
      <li><a href='#apps-section'>Installed Applications</a></li>
    </ul>
  </div>

  <!-- Main Content Area -->
  <div class='main-content'>
    <div class='header'>
        <h1>Endpoint Device Summary</h1>
        <p><strong>Report Timestamp:</strong> $timestamp</p>
    </div>

    <!-- Summary & Recommendations Section -->
    <div class='section' id='summary-section'>
        <h2>Summary & Recommendations</h2>
        <table>
            <tr>
                <th style='width: 30%;'>Overall Health</th>
                <td><span class='status-block $($overallStatusClass)'>$overallStatus</span></td>
            </tr>
            <tr>
                <th>Disk Integrity (SMART)</th>
                <td><span class='status-block $($smartStatus -replace 'CRITICAL', 'status-critical' -replace 'OK', 'status-ok')'>$smartStatus</span></td>
            </tr>
            <tr>
                <th>Disk Space</th>
                <td><span class='status-block $($diskSpaceStatus -replace 'CRITICAL', 'status-critical' -replace 'OK', 'status-ok')'>$diskSpaceStatus</span></td>
            </tr>
            <tr>
                <th>System Events (24h)</th>
                <td><span class='status-block $($eventLogStatus -replace 'WARNING', 'status-warning' -replace 'OK', 'status-ok')'>$eventLogStatus</span></td>
            </tr>
            <tr>
                <th>Paging File (V-Mem)</th>
                <td><span class='status-block $($D.virtualMemoryStatus -replace 'Not Configured', 'status-warning' -replace 'Configured.*', 'status-ok')'>$($D.virtualMemoryStatus.Split("|")[0])</span></td>
            </tr>
        </table>

        <h3>Detailed Findings</h3>
        $findingsHtml
        
        <h3>Actionable Recommendations</h3>
        $recommendationsHtml
    </div>

    <!-- Device Info Section -->
    <div class='section' id='device-section'>
      <h2>Device Info</h2>
      <table>
        <tr><th>Name</th><td>$(Get-SafeProperty -Object $D.sysInfo -Property Name)</td></tr>
        <tr><th>Manufacturer</th><td>$(Get-SafeProperty -Object $D.sysInfo -Property Manufacturer)</td></tr>
        <tr><th>Model</th><td>$(Get-SafeProperty -Object $D.sysInfo -Property Model)</td></tr>
        <tr><th>BIOS Version</th><td>$(Get-SafeProperty -Object $D.biosInfo -Property SMBIOSBIOSVersion)</td></tr>
        <tr><th>Boot Mode</th><td><span class='status-block $($D.bootMode -replace 'UEFI', 'status-ok' -replace 'Legacy BIOS|Access Denied.*', 'status-warning')'>$D.bootMode</span></td></tr>
        <tr><th>TPM Status</th><td><span class='status-block $($D.tpmStatus.IsReady -replace 'True', 'status-ok' -replace 'False', 'status-warning' -replace 'N/A', 'status-na')'>$(Get-SafeProperty -Object $D.tpmStatus -Property IsReady -DefaultValue 'N/A')</span></td></tr>
        <tr><th>OS</th><td>$(Get-SafeProperty -Object $D.osInfo -Property Caption) Build $(Get-SafeProperty -Object $D.osInfo -Property BuildNumber)</td></tr>
        <tr><th>Uptime (Hours)</th><td>$([math]::Round((New-TimeSpan -Start $(Get-SafeProperty -Object $D.osInfo -Property LastBootUpTime -DefaultValue (Get-Date))).TotalHours, 2))</td></tr>
      </table>
    </div>

    <!-- CPU & Memory Section -->
    <div class='section' id='cpu-mem-section'>
      <h2>CPU & Memory</h2>
      <table>
        <tr><th>CPU</th><td>$(Get-SafeProperty -Object $D.cpuInfo -Property Name)</td></tr>
        <tr><th>Cores / Threads</th><td>$(Get-SafeProperty -Object $D.cpuInfo -Property NumberOfCores -DefaultValue 'N/A') / $(Get-SafeProperty -Object $D.cpuInfo -Property NumberOfLogicalProcessors -DefaultValue 'N/A')</td></tr>
        <tr><th>Total RAM</th><td>$([math]::Round($(Get-SafeProperty -Object $D.memInfo -Property Sum / 1GB -DefaultValue 0), 2)) GB</td></tr>
        <tr><th>Virtual Memory</th><td>$D.virtualMemoryStatus</td></tr>
      </table>
    </div>

    <!-- Storage Section -->
    <div class='section' id='storage-section'>
      <h2>Storage</h2>
      <table>
        <tr><th>Drive</th><th>Total (GB)</th><th>Free (GB)</th><th>Free (%)</th></tr>
"@

# Disk Info Loop 
# Dynamically inserts disk drive rows into the Storage table based on disk health percentage.
foreach ($disk in $D.diskInfo) {
    $sizeGB = [math]::Round($disk.Size / 1GB, 2)
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
    
    $percentClass = if ($freePercent -lt 10) { "status-critical" } elseif ($freePercent -lt 20) { "status-warning" } else { "status-ok" }
    
    $html += "<tr><td>$($disk.DeviceID)</td><td>$sizeGB</td><td>$freeGB</td><td><span class='status-block $percentClass'>$freePercent%</span></td></tr>"
}

$html += @"
      </table>
    </div>

    <!-- Battery Health Section (Bar Chart) -->
    <div class='section' id='battery-section'>
      <h2>Battery Health</h2>
      <p><strong>Wear Rate:</strong> <span class='status-block $(if ($D.wearPercent -is [double] -and $D.wearPercent -gt 25) { 'status-critical' } else { 'status-ok' })'>$($D.wearPercent)%</span> (Based on latest sample vs. design capacity)</p>
      <div style="width: 100%; max-width: 600px; margin: 0 auto;">
          <canvas id='batteryChart' height='300'></canvas>
      </div>
      <script>
        const ctx = document.getElementById('batteryChart').getContext('2d');
        const batteryChart = new Chart(ctx, {
          type: 'bar', /* Changed to Bar Chart */
          data: {
            labels: [$($D.batteryLabels)],
            datasets: [{
              label: 'Full Charge Capacity (mWh)',
              data: [$($D.fullChargeData)],
              backgroundColor: 'rgba(0, 90, 156, 0.7)', /* Primary Color */
              borderColor: 'rgba(0, 90, 156, 1)',
              borderWidth: 1,
            }]
          },
          options: {
            responsive: true,
            scales: {
                y: { beginAtZero: false }
            },
            plugins: {
              title: {
                display: true,
                text: 'Battery Capacity Trend Over Time'
              },
              legend: {
                display: false
              }
            }
          }
        });
      </script>
    </div>

    <!-- BitLocker Status Section -->
    <div class='section' id='bitlocker-section'>
      <h2>BitLocker Status</h2>
      <table>
        <tr><th>Volume</th><th>Status</th><th>Protection</th><th>Method</th></tr>
"@

# BitLocker Info Loop (Safe if $D.bitLocker is empty or null)
# Dynamically inserts BitLocker status rows.
foreach ($vol in $D.bitLocker) {
    $html += "<tr><td>$($vol.MountPoint)</td><td>$($vol.VolumeStatus)</td><td>$($vol.ProtectionStatus)</td><td>$($vol.EncryptionMethod)</td></tr>"
}

$html += @"
      </table>
    </div>

    <!-- Windows Defender Section -->
    <div class='section' id='defender-section'>
      <h2>Windows Defender</h2>
      <table>
        <tr><th>Real-Time Protection</th><td><span class='status-block $(Get-SafeProperty -Object $D.defender -Property RealTimeProtectionEnabled -DefaultValue 'False' -replace 'True', 'status-ok' -replace 'False', 'status-critical')'>$(Get-SafeProperty -Object $D.defender -Property RealTimeProtectionEnabled)</span></td></tr>
        <tr><th>Antivirus Enabled</th><td><span class='status-block $(Get-SafeProperty -Object $D.defender -Property AntivirusEnabled -DefaultValue 'False' -replace 'True', 'status-ok' -replace 'False', 'status-critical')'>$(Get-SafeProperty -Object $D.defender -Property AntivirusEnabled)</span></td></tr>
        <tr><th>Last Scan Time</th><td>$(Get-SafeProperty -Object $D.defender -Property LastFullScanEndTime)</td></tr>
        <tr><th>Engine Version</th><td>$(Get-SafeProperty -Object $D.defender -Property AntivirusEngineVersion)</td></tr>
      </table>
    </div>

    <!-- Network Adapters Section -->
    <div class='section' id='network-section'>
      <h2>Network Adapters</h2>
      <table>
        <tr><th>Name</th><th>MAC</th><th>Speed</th><th>Status</th></tr>
"@

# Network Adapter Loop
# Dynamically inserts active network adapter details.
foreach ($adapter in $D.netAdapters) {
    $html += "<tr><td>$($adapter.Name)</td><td>$($adapter.MacAddress)</td><td>$($adapter.LinkSpeed)</td><td>$($adapter.Status)</td></tr>"
}

$html += @"
      </table>
    </div>

    <!-- Connectivity Test Section -->
    <div class='section' id='connectivity-section'>
      <h2>Connectivity Test</h2>
      <table>
        <tr><th>Azure Ping (External Service)</th><td><span class='status-block $($D.pingAzure -replace 'OK', 'status-ok' -replace 'FAIL', 'status-critical')'>$D.pingAzure</span></td></tr>
        <tr><th>DNS Ping (8.8.8.8)</th><td><span class='status-block $($D.pingDNS -replace 'OK', 'status-ok' -replace 'FAIL', 'status-critical')'>$D.pingDNS</span></td></tr>
      </table>
    </div>

    <!-- Critical Event Log Section -->
    <div class='section' id='events-section'>
      <h2>Critical Event Log (Last 24h)</h2>
"@

# Event Log Details Loop
# Dynamically inserts details for the most recent critical/error events.
if ($D.criticalEvents -is [System.Collections.ICollection] -and $D.criticalEvents.Count -gt 0) {
    $html += "<table>"
    $html += "<tr><th>Time</th><th>ID</th><th>Message (Snippet)</th></tr>"
    foreach ($event in $D.criticalEvents) {
        # Truncate message for display
        $messageSnippet = if ($event.Message.Length -gt 120) { "$($event.Message.Substring(0, 120))..." } else { $event.Message }
        $html += "<tr><td>$($event.TimeCreated)</td><td>$($event.Id)</td><td style='font-size:0.85em;'>$messageSnippet</td></tr>"
    }
    $html += "</table>"
} elseif ($eventLogStatus -eq "OK") {
    $html += "<p>No Critical or Error-level events found in the System log within the last 24 hours.</p>"
} else {
    $html += "<p class='status-warning status-block'>Error or warning when attempting to read the System Event Log. Run script as Administrator for full access.</p>"
}

$html += @"
    </div>

    <!-- Installed Applications Section -->
    <div class='section' id='apps-section'>
      <h2>Installed Applications</h2>
      <table>
        <tr><th>Name</th><th>Version</th><th>Publisher</th></tr>
"@

# Installed Apps Loop
# Dynamically inserts a list of installed applications from the registry.
foreach ($app in $D.installedApps) {
    # Check if DisplayName exists before adding the row
    if ($app.DisplayName) {
        $html += "<tr><td>$($app.DisplayName)</td><td>$($app.DisplayVersion)</td><td>$($app.Publisher)</td></tr>"
    }
}

$html += @"
      </table>
    </div>
  
    <footer class='footer'>
      Report generated by Digital Design Experience | <a href='https://www.designx.co.ke' target='_blank'>www.designx.co.ke</a>
    </footer>
  
  </div> <!-- End main-content -->

  <script>
    // Dynamic Element 1: Last Updated Timer
    const reportTimestamp = new Date('$timestamp');
    const timerElement = document.getElementById('last-updated-timer');

    function updateTimer() {
        const now = new Date();
        const diffSeconds = Math.floor((now - reportTimestamp) / 1000);

        if (diffSeconds < 60) {
            timerElement.textContent = `just now (${diffSeconds}s ago)`;
        } else if (diffSeconds < 3600) {
            const minutes = Math.floor(diffSeconds / 60);
            timerElement.textContent = `${minutes}m ago`;
        } else {
            const hours = Math.floor(diffSeconds / 3600);
            timerElement.textContent = `${hours}h ago`;
        }
    }

    // Dynamic Element 2: Sidebar Highlighting
    const sections = document.querySelectorAll('.section');
    const navLinks = document.querySelectorAll('.nav-links a');

    function highlightNav() {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 30; 
            if (scrollY >= sectionTop) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(a => {
            a.classList.remove('active');
            if (a.getAttribute('href').substring(1) === current) {
                a.classList.add('active');
            }
        });
    }

    // Initialize timer and highlighting
    window.onload = function() {
        updateTimer();
        setInterval(updateTimer, 1000);
        
        highlightNav();
        window.addEventListener('scroll', highlightNav);

        navLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                // Smooth scroll functionality for links
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                window.scrollTo({
                    top: targetElement.offsetTop - 20,
                    behavior: 'smooth'
                });
            });
        });
    };
  </script>
</body>
</html>
"@

# --- 4. Robust Final Output ---
# Attempts to write the generated HTML content to the file path, handling potential file access errors.
try {
    # Ensure the HTML content was generated before attempting to write
    if ($html -and $html.Length -gt 1000) { # Basic length check
        $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
        Write-Host "SUCCESS: HTML Report successfully written to $htmlPath" -ForegroundColor Green
    } else {
        Write-Host "ERROR: HTML content variable (\$html) was empty or invalid. File not written." -ForegroundColor Red
    }
} catch {
    # Catching a file access error (e.g., file open in browser/editor)
    Write-Host "CRITICAL FILE WRITE ERROR: Failed to write file to $htmlPath." -ForegroundColor Red
    Write-Host "Reason: Ensure the file is not currently open and the user has permissions to the path." -ForegroundColor Yellow
    Write-Host "Exception Details: $($_.Exception.Message)" -ForegroundColor Red
}
