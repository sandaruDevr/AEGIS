# CyberSec Agent - WSL2 Native Messaging Host Installer
# Run this script as Administrator to install the native messaging host

$ErrorActionPreference = "Stop"

Write-Host "=== CyberSec Agent - WSL2 Native Messaging Host Installer ===" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n[1/5] Checking Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "ERROR: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Install Python 3 from: https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}
Write-Host "OK: Python found at $($python.Source)" -ForegroundColor Green

# 2. Check WSL2
Write-Host "`n[2/5] Checking WSL2..." -ForegroundColor Yellow
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    Write-Host "ERROR: WSL2 is not installed." -ForegroundColor Red
    Write-Host "Run 'wsl --install' in an admin PowerShell, then reboot." -ForegroundColor Red
    exit 1
}
Write-Host "OK: WSL2 found" -ForegroundColor Green

# 3. Copy host files to permanent location
Write-Host "`n[3/5] Installing host files..." -ForegroundColor Yellow
$installDir = "$env:LOCALAPPDATA\CyberSecAgent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Copy-Item "$PSScriptRoot\wsl_bridge.py" "$installDir\wsl_bridge.py" -Force
Copy-Item "$PSScriptRoot\wsl_bridge.bat" "$installDir\wsl_bridge.bat" -Force
Write-Host "OK: Files copied to $installDir" -ForegroundColor Green

# 4. Get extension ID from user
Write-Host "`n[4/5] Extension ID required." -ForegroundColor Yellow
Write-Host "To find your extension ID:" -ForegroundColor White
Write-Host "  1. Open Chrome and go to chrome://extensions" -ForegroundColor White
Write-Host "  2. Enable 'Developer mode' (top right toggle)" -ForegroundColor White
Write-Host "  3. Load the CyberSec Agent extension (if not already loaded)" -ForegroundColor White
Write-Host "  4. Copy the extension ID (e.g., abcdefghijklmnopqrstuvwxyz...)" -ForegroundColor White
Write-Host ""
$extId = Read-Host "Paste your extension ID here"

if (-not $extId -or $extId.Length -lt 20) {
    Write-Host "ERROR: Invalid extension ID." -ForegroundColor Red
    exit 1
}

# 5. Create and register the native messaging host JSON
Write-Host "`n[5/5] Registering native messaging host..." -ForegroundColor Yellow

$hostJson = @{
    name = "wsl_bridge"
    description = "WSL2 Bridge for CyberSec Agent - executes security commands in WSL2"
    path = "$installDir\wsl_bridge.bat"
    type = "stdio"
    allowed_origins = @("chrome-extension://$extId/")
} | ConvertTo-Json -Depth 3

# Save JSON to install dir
$jsonPath = "$installDir\wsl_bridge.json"
$hostJson | Out-File -FilePath $jsonPath -Encoding utf8 -NoNewline

# Register in Chrome's NativeMessagingHosts directory
$nmhDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts"
New-Item -ItemType Directory -Force -Path $nmhDir | Out-Null
Copy-Item $jsonPath "$nmhDir\wsl_bridge.json" -Force

# Also register via Windows Registry (fallback method)
$regKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\wsl_bridge"
New-Item -Path $regKey -Force | Out-Null
Set-ItemProperty -Path $regKey -Name "(Default)" -Value $jsonPath

Write-Host "OK: Native messaging host registered." -ForegroundColor Green
Write-Host "  JSON path: $jsonPath" -ForegroundColor Gray
Write-Host "  Registry: $regKey" -ForegroundColor Gray
Write-Host "  Chrome NMH dir: $nmhDir\wsl_bridge.json" -ForegroundColor Gray

# Verify
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
Write-Host "Testing WSL2 connectivity..." -ForegroundColor Yellow
$testResult = & wsl.exe -- echo "WSL2 is working" 2>&1
if ($testResult -match "WSL2 is working") {
    Write-Host "OK: WSL2 is operational" -ForegroundColor Green
} else {
    Write-Host "WARNING: WSL2 test failed. Make sure WSL2 is set up correctly." -ForegroundColor Red
    Write-Host "Output: $testResult" -ForegroundColor Gray
}

Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Write-Host "Reload the CyberSec Agent extension in Chrome, then try a WSL command." -ForegroundColor White
Write-Host "Example: Ask the agent to 'run nmap -sV on example.com'" -ForegroundColor White
