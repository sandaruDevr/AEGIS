# WSL2 Native Messaging Host Setup

This directory contains the native messaging host for the CyberSec Agent extension, enabling WSL2 command execution for security tools.

## Installation

1. **Install Python 3** (if not already installed): https://www.python.org/downloads/

2. **Copy the native host files** to a permanent location:
   ```
   mkdir "C:\Program Files\CyberSecAgent"
   copy wsl_bridge.bat "C:\Program Files\CyberSecAgent\"
   copy wsl_bridge.py "C:\Program Files\CyberSecAgent\"
   ```

3. **Update the extension ID** in `wsl_bridge.json`:
   - Load the extension in Chrome
   - Go to `chrome://extensions`
   - Copy the extension ID (e.g., `abcdefghijklmnopqrstuvwxyz`)
   - Edit `wsl_bridge.json` and replace `PLACEHOLDER_REPLACE_WITH_EXTENSION_ID` with your extension ID

4. **Register the native messaging host**:
   - For all users: Copy `wsl_bridge.json` to `C:\Program Files\Google\Chrome\Application\NativeMessagingHosts\wsl_bridge.json`
   - For current user: Copy `wsl_bridge.json` to `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\NativeMessagingHosts\wsl_bridge.json`

5. **Verify WSL2 is installed**:
   ```
   wsl --install
   wsl --list --verbose
   ```

6. **Install security tools in WSL2** (optional but recommended):
   ```bash
   sudo apt update && sudo apt install -y nmap nikto sqlmap gobuster dirb sslscan whois dnsutils netcat-openbsd traceroute hydra wfuzz ffuf
   # Install additional tools
   pip3 install httpx nuclei
   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

## Verification

After installation, reload the extension and try:
```
Run a port scan on example.com using nmap
```

The agent will use `run_wsl_command` to execute `nmap` via WSL2.

## Troubleshooting

- **"WSL bridge not available"**: Ensure the native messaging host JSON is in the correct registry location and the path in the JSON points to the correct `.bat` file.
- **"WSL2 is not installed"**: Run `wsl --install` in an admin PowerShell.
- **Command not found**: Install the security tools inside WSL2 using apt/pip/go.
