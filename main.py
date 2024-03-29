from PySide6.QtWidgets import QApplication
import argparse
import sys
from core.arp_scanner import DeviceDiscoveryDialog, MacVendorLookup
from core.networking import enable_ip_forwarding


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARP Sniffer')
    parser.add_argument('--interface', required=True, help='Network interface name')
    args = parser.parse_args()
    oui_url = "http://standards-oui.ieee.org/oui/oui.csv"
    MacVendorLookup.load_data(oui_url)
    print(enable_ip_forwarding())

    app = QApplication(sys.argv)

    window = DeviceDiscoveryDialog(args.interface, oui_url=oui_url)
    window.show()

    sys.exit(app.exec())


