"""
This script launches a GUI application for ARP sniffing.

It uses PySide6 for the graphical user interface (GUI) and argparse to handle
command-line arguments. The application initializes a device discovery window
that displays ARP scanning results for a given network interface.
"""

import argparse
import sys
from PySide6.QtWidgets import QApplication # pylint: disable=E0611
from core.arp_scanner import DeviceDiscoveryDialog

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARP Sniffer')
    parser.add_argument('--interface', required=True, help='Network interface name')
    args = parser.parse_args()

    app = QApplication(sys.argv)

    window = DeviceDiscoveryDialog(
        args.interface,
        oui_url="http://standards-oui.ieee.org/oui/oui.csv"
    )
    window.show()

    sys.exit(app.exec())
