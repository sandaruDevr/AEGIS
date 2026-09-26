$dir = "$env:LOCALAPPDATA\CyberSecAgent"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item "$PSScriptRoot\wsl_bridge.bat" "$dir\wsl_bridge.bat" -Force
Copy-Item "$PSScriptRoot\wsl_bridge.py" "$dir\wsl_bridge.py" -Force
Write-Output "Files copied to $dir"

# Register in Edge's NativeMessagingHosts directory
$nmhDirEdge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\NativeMessagingHosts"
New-Item -ItemType Directory -Force -Path $nmhDirEdge | Out-Null
Copy-Item "$PSScriptRoot\wsl_bridge.json" "$nmhDirEdge\wsl_bridge.json" -Force

# Register via Windows Registry for Edge
$regKeyEdge = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\wsl_bridge"
New-Item -Path $regKeyEdge -Force | Out-Null
Set-ItemProperty -Path $regKeyEdge -Name "(Default)" -Value "$PSScriptRoot\wsl_bridge.json"

# Also keep Chrome registration
$nmhDirChrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts"
New-Item -ItemType Directory -Force -Path $nmhDirChrome | Out-Null
Copy-Item "$PSScriptRoot\wsl_bridge.json" "$nmhDirChrome\wsl_bridge.json" -Force
$regKeyChrome = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\wsl_bridge"
New-Item -Path $regKeyChrome -Force | Out-Null
Set-ItemProperty -Path $regKeyChrome -Name "(Default)" -Value "$PSScriptRoot\wsl_bridge.json"

Write-Output "Native messaging host registered for Edge and Chrome."
Write-Output "  Install dir: $dir"
Write-Output "  Edge NMH: $nmhDirEdge\wsl_bridge.json"
Write-Output "  Edge Registry: $regKeyEdge"
Write-Output ""
Write-Output "Done! Reload the extension in Edge."
