📊 Endpoint Device Summary

A professional, high-performance PowerShell diagnostic tool that performs a deep-dive audit of a Windows computer's hardware, security, and networking. It transforms complex system data into a beautiful, color-coded HTML dashboard for instant analysis.

🚀 Key Features

Exhaustive Hardware Audit: Captures Motherboard/BIOS details, CPU specifications, GPU identification, and individual RAM module speeds.

Security Sentinel: Real-time monitoring of TPM status, Windows Defender, BitLocker encryption, and Firewall profiles.

Health Tracking: Analyzes storage SMART reliability, drive capacity (with color-coded warnings), and laptop battery health.

Network Diagnostics: Maps active network interfaces, MAC addresses, link speeds, and IPv4 DNS configurations.

Critical Log Capture: Automatically parses the last 20 System Error events to identify recent crashes or service failures.

Self-Elevating: Automatically requests Administrator privileges required for deep-system queries.

🛠️ Installation & Usage

Prerequisites

Windows 10/11 or Windows Server 2016+

PowerShell 5.1 (Integrated) or PowerShell 7+

Running the Script

Download the SystemHealthLogger.ps1 file.

Right-click the file and select Run with PowerShell.

Alternatively, run via CLI (recommended for viewing live progress):

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\SystemHealthLogger.ps1


📂 Output

The script generates a standalone HTML report in your temporary directory:
$env:TEMP\SystemHealthReports\Exhaustive_HealthReport_YYYYMMDD_HHMMSS.html

The report will automatically open in your default web browser once the collection is complete.

⚠️ Security Note

This script requires Administrator Privileges to access secure system components like the TPM chip, BitLocker status, and System Event Logs. The script includes an auto-elevation block for convenience.

📝 License

This project is open-source and free to use for personal or enterprise auditing.
