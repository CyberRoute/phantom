import socket
import sys
from PySide6.QtWidgets import QApplication, QDialog, QListWidgetItem
from ui_arpscan import Ui_DeviceDiscovery
from PySide6.QtCore import Slot, Qt
import scapy.all as scapy


class DeviceDiscoveryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._ui = Ui_DeviceDiscovery()
        self._ui.setupUi(self)
        self._ui.scan.clicked.connect(self.start_arpscan)

    def get_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception as e:
            return "N/A"  # Return "N/A" if hostname retrieval fails

    @Slot()
    def start_arpscan(self):
        # ip_address = scapy.get_if_addr(self.interface)
        # netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
        # network = self.calculate_network_cidr(ip_address=ip_address, subnet_mask=netmask)
        # Use scapy to perform ARP scan
        self._ui.scan.setEnabled(False)
        arp_results = []
        arp_packets = scapy.arping("192.168.1.0/24", verbose=0)[0]
        for packet in arp_packets:
            if packet[1].haslayer(scapy.ARP):
                ip_address = packet[1][scapy.ARP].psrc
                mac_address = packet[1][scapy.ARP].hwsrc

                # Look up vendor information using MacVendorLookup class
                #vendor = self.mac_vendor_lookup.lookup_vendor(mac_address)

                # Retrieve hostname
                hostname = self.get_hostname(ip_address)
                label = f"{ip_address, mac_address, hostname}"
                items = self._ui.list.findItems(label, Qt.MatchExactly)
                if not items:
                    item = QListWidgetItem(label)
                    self._ui.list.addItem(item)

                arp_results.append([ip_address, mac_address, hostname, packet[1][scapy.ARP]])
        print(arp_results)
       
        return arp_results
    
if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = DeviceDiscoveryDialog()
    window.show()

    sys.exit(app.exec())