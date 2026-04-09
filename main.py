"""
This script launches a GUI application for ARP sniffing.

It uses PySide6 for the graphical user interface (GUI) and argparse to handle
command-line arguments. The application initializes a device discovery window
that displays ARP scanning results for a given network interface.
"""

import argparse
import sys

from PySide6.QtWidgets import QApplication  # pylint: disable=E0611

from core.arp_scanner import DeviceDiscoveryDialog

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Sniffer")
    parser.add_argument("--interface", required=True, help="Network interface name")
    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Timeout in milliseconds for ARP scan (default: 1000)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Custom target CIDR range, e.g. 10.0.0.0/24 (default: interface network)",
    )
    args = parser.parse_args()

    app = QApplication(sys.argv)

    window = DeviceDiscoveryDialog(
        args.interface,
        oui_url="http://standards-oui.ieee.org/oui/oui.csv",
        timeout=args.timeout,
        target_cidr=args.target,
    )
    window.show()

    sys.exit(app.exec())
