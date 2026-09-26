# Generate a stable key for the Chrome extension using Python
$pyScript = @'
import base64, hashlib, os, tempfile

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

import sys

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
der_bytes = key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

b64 = base64.b64encode(der_bytes).decode()
print("KEY:" + b64)

h = hashlib.sha256(der_bytes).digest()
ext_id = "".join(chr(b % 26 + ord("a")) for b in h[:16])
print("EXTID:" + ext_id)
'@

$pyFile = "$env:TEMP\genkey.py"
$pyScript | Out-File $pyFile -Encoding ascii

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Output "ERROR: Python not found. Install Python 3 first."
    exit 1
}

$output = & $python.Source $pyFile

$keyLine = ($output | Where-Object { $_ -like 'KEY:*' })
$extIdLine = ($output | Where-Object { $_ -like 'EXTID:*' })

if (-not $keyLine -or -not $extIdLine) {
    Write-Output "ERROR: Key generation failed. Output:"
    Write-Output $output
    exit 1
}

$pubKeyB64 = $keyLine.Substring(4)
$extId = $extIdLine.Substring(6)

Write-Output "=== Base64 Public Key ==="
Write-Output $pubKeyB64
Write-Output ""
Write-Output "=== Extension ID ==="
Write-Output $extId

$pubKeyB64 | Out-File "$PSScriptRoot\extension_key_b64.txt" -Encoding ascii -NoNewline
$extId | Out-File "$PSScriptRoot\extension_id.txt" -Encoding ascii -NoNewline
Write-Output ""
Write-Output "Saved to extension_key_b64.txt and extension_id.txt"
