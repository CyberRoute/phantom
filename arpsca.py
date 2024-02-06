import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextBrowser
from PyQt5.QtCore import QTimer
import scapy.all as scapy
import csv
import requests
from io import StringIO


class MacVendorLookup:
    mac_vendor_data = None

    @classmethod
    def load_data(cls, url):
        if cls.mac_vendor_data is None:
            response = requests.get(url)
            csv_data = StringIO(response.text)

            cls.mac_vendor_data = {}
            csvreader = csv.reader(csv_data)
            next(csvreader)
            for row in csvreader:
                oui = row[1].replace("-", "").upper()[:6]
                vendor = row[2]
                cls.mac_vendor_data[oui] = vendor

    def __init__(self, url):
        self.load_data(url)

    def lookup_vendor(self, mac_address):
        cleaned_mac = mac_address.upper().replace(":", "").replace("-", "")
        oui = cleaned_mac[:6]
        return self.mac_vendor_data.get(oui, "Vendor not found")


class ARPSniffer(QWidget):
    def __init__(self, oui_url):
        super().__init__()

        self.mac_vendor_lookup = MacVendorLookup(oui_url)
        self.init_ui()

    def init_ui(self):
        self.result_text = QTextBrowser(self)
        layout = QVBoxLayout(self)
        layout.addWidget(self.result_text)

        self.setWindowTitle('ARP Sniffer')
        self.setGeometry(100, 100, 600, 400)  # Decreased window size

        # Set stylesheet for QTextBrowser
        self.result_text.setStyleSheet("background-color: black; color: green; font-size: 14pt;")  # Increased font size

        # Timer to update ARP results every second
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_results)
        self.timer.start(1000)

        self.show()

    def update_results(self):
        # Perform ARP scan using scapy
        arp_results = self.scan_arp()

        # Display results in the text browser
        self.result_text.clear()
        for result in arp_results:
            self.result_text.append(result)

    def scan_arp(self):
        # Use scapy to perform ARP scan
        arp_results = []
        arp_packets = scapy.arping("192.168.1.0/24", verbose=0)[0]
        for packet in arp_packets:
            if packet[1].haslayer(scapy.ARP):
                ip_address = packet[1][scapy.ARP].psrc
                mac_address = packet[1][scapy.ARP].hwsrc

                # Look up vendor information using MacVendorLookup class
                vendor = self.mac_vendor_lookup.lookup_vendor(mac_address)

                arp_result = f"IP {ip_address} is at {mac_address} (Vendor: {vendor})"
                arp_results.append(arp_result)

        return arp_results


if __name__ == '__main__':
    oui_url = "http://standards-oui.ieee.org/oui/oui.csv"
    MacVendorLookup.load_data(oui_url)

    app = QApplication(sys.argv)
    ex = ARPSniffer(oui_url)
    sys.exit(app.exec_())

