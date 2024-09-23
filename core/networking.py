"""
This module provides functions for enabling/disabling IP forwarding
and retrieving the IP address of the current machine.
"""

import subprocess
import socket
from core import platform


def enable_ip_forwarding():
    """
    Enables IP forwarding on the current machine.

    IP forwarding is enabled based on the operating system type
    (macOS, Linux, or Windows).
    """
    os_platform = platform.get_os()
    cmd = None
    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled']
    else:
        raise ValueError(f"Unsupported OS platform: {os_platform}")
    assert subprocess.call(cmd) == 0


def disable_ip_forwarding():
    """
    Disables IP forwarding on the current machine.

    IP forwarding is disabled based on the operating system type
    (macOS, Linux, or Windows).
    """
    os_platform = platform.get_os()
    cmd = None
    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled']
    else:
        raise ValueError(f"Unsupported OS platform: {os_platform}")

    assert subprocess.call(cmd) == 0

def get_ip_address():
    """Get the IP address of the current machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        return ip_address
    except OSError as e:
        print(f"Error while getting IP address: {e}")
        return None
