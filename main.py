from PySide6.QtWidgets import QApplication
import argparse
import sys
from core.arp_scanner import DeviceDiscoveryDialog

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARP Sniffer')
    parser.add_argument('--interface', required=True, help='Network interface name')
    args = parser.parse_args()

    app = QApplication(sys.argv)

    window = DeviceDiscoveryDialog(args.interface, oui_url="http://standards-oui.ieee.org/oui/oui.csv")
    window.show()

    sys.exit(app.exec())


