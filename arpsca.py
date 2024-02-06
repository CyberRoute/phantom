import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import QTimer, Qt
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
        headers = ["IP Address", "MAC Address", "Vendor", "Hostname"]
        self.table_widget = QTableWidget()
        self.table_widget.setStyleSheet("background-color: black; color: green; font-size: 14pt;")
        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

        # Set table to stretch horizontally
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.verticalHeader().setVisible(False)

        # Set headers alignment to left-aligned
        for i in range(len(headers)):
            self.table_widget.horizontalHeaderItem(i).setTextAlignment(Qt.AlignLeft)

        # Set columns to be resizable
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # Create QVBoxLayout for the main layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.table_widget)  # Add QTableWidget

        # Timer to update ARP results every second
        self.timer_arp = QTimer(self)
        self.timer_arp.timeout.connect(self.update_results_arp)
        self.timer_arp.start(1000)

        # Show the window
        self.show()

    def update_results_arp(self):
        # Perform ARP scan using scapy
        arp_results = self.scan_arp()

        # Display results in the table
        self.table_widget.setRowCount(len(arp_results))
        for i, result in enumerate(arp_results):
            for j, value in enumerate(result):
                item = QTableWidgetItem(value)
                self.table_widget.setItem(i, j, item)

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

                arp_results.append([ip_address, mac_address, vendor, hostname])

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
    sys.exit(app.exec())

    sys.exit(app.exec())
