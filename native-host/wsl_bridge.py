#!/usr/bin/env python3
"""
WSL Bridge - Native Messaging Host for CyberSec Agent extension.
Receives commands from the Chrome extension and executes them in WSL2.
"""

import json
import struct
import subprocess
import sys
import threading
import os

def read_message():
    """Read a message from stdin (Chrome native messaging protocol)."""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None
    length = struct.unpack('=I', raw_length)[0]
    if length == 0:
        return None
    data = sys.stdin.buffer.read(length)
    return json.loads(data.decode('utf-8'))

def send_message(msg):
    """Send a message to stdout (Chrome native messaging protocol)."""
    data = json.dumps(msg).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('=I', len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()

def execute_wsl_command(command, timeout_ms=30000):
    """Execute a command in WSL2 and return stdout, stderr, exit code."""
    timeout_s = min(timeout_ms / 1000, 120)
    try:
        # Use wsl.exe to run the command
        result = subprocess.run(
            ['wsl.exe', '--', 'bash', '-c', command],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exitCode': result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            'error': f'Command timed out after {timeout_s}s.',
        }
    except FileNotFoundError:
        return {
            'error': 'WSL2 is not installed or wsl.exe not found in PATH.',
        }
    except Exception as e:
        return {
            'error': str(e),
        }

def main():
    while True:
        msg = read_message()
        if msg is None:
            break

        command = msg.get('command', '')
        timeout = msg.get('timeout', 30000)

        if not command:
            send_message({'error': 'No command provided.'})
            continue

        result = execute_wsl_command(command, timeout)
        send_message(result)

if __name__ == '__main__':
    main()
