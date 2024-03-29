import core.platform as platform
import subprocess
import socket

def enable_ip_forwarding():

    os_platform = platform.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled']

    assert subprocess.call(cmd) == 0


def disable_ip_forwarding():

    os_platform = platform.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled']

    assert subprocess.call(cmd) == 0

def get_ip_address():
    """Get the IP address of the current machine."""
    try:
        # Create a socket object
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a remote server (doesn't have to be reachable)
            s.connect(("8.8.8.8", 80))
            # Get the IP address of the current machine
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        print(f"Error while getting IP address: {e}")
        return None
    