import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextBrowser, QLabel, QHBoxLayout
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
        self.setWindowTitle('ARP Sniffer')

        # Create description labels
        ip_label = QLabel("IP Address")
        mac_label = QLabel("MAC Address")
        vendor_label = QLabel("Vendor")
        hostname_label = QLabel("Hostname")  # Added hostname label

        # Create a QHBoxLayout to display labels horizontally
        description_layout = QHBoxLayout()
        description_layout.addWidget(ip_label)
        description_layout.addWidget(mac_label)
        description_layout.addWidget(vendor_label)
        description_layout.addWidget(hostname_label)  # Added hostname label

        # Create QTextBrowser for displaying ARP results
        self.result_text_arp = QTextBrowser(self)
        self.result_text_arp.setStyleSheet("background-color: black; color: green; font-size: 14pt;")

        # Create QVBoxLayout for the main layout
        layout = QVBoxLayout(self)
        layout.addLayout(description_layout)  # Add description labels
        layout.addWidget(self.result_text_arp)  # Add QTextBrowser

        # Timer to update ARP results every second
        self.timer_arp = QTimer(self)
        self.timer_arp.timeout.connect(self.update_results_arp)
        self.timer_arp.start(1000)

        # Show the window
        self.show()

    def update_results_arp(self):
        # Perform ARP scan using scapy
        arp_results = self.scan_arp()

        # Display results in the ARP tab
        self.result_text_arp.clear()
        for result in arp_results:
            self.result_text_arp.append(result)

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

                # Retrieve hostname
                hostname = self.get_hostname(ip_address)

                arp_result = f"{ip_address:<15} {mac_address:<20} {vendor:<20} {hostname}"  # Updated to include hostname
                arp_results.append(arp_result)

        return arp_results

    def get_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception as e:
            print("Error retrieving hostname:", e)
            return "N/A"  # Return "N/A" if hostname retrieval fails


if __name__ == '__main__':
    oui_url = "http://standards-oui.ieee.org/oui/oui.csv"
    MacVendorLookup.load_data(oui_url)

    app = QApplication(sys.argv)
    ex = ARPSniffer(oui_url)
    sys.exit(app.exec_())
