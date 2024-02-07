import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QHBoxLayout, QLabel, QLineEdit, QMessageBox
from PyQt5.QtCore import QTimer, Qt, QSize
from PyQt5.QtGui import QIcon
import scapy.all as scapy
import csv
import requests
from io import StringIO
import argparse
import netifaces

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
    def __init__(self, oui_url, interface):
        super().__init__()

        self.interface = interface
        self.mac_vendor_lookup = MacVendorLookup(oui_url)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('ARP Sniffer')
        self.setMinimumSize(800, 600)

        # Create description labels
        headers = ["IP Address", "MAC Address", "Vendor", "Hostname"]
        self.table_widget = QTableWidget()
        self.table_widget.setStyleSheet("background-color: black; color: green; font-size: 14pt;")
        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

        # Set table to stretch horizontally
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.setSortingEnabled(True)


        # Set headers alignment to left-aligned
        for i in range(len(headers)):
            self.table_widget.horizontalHeaderItem(i).setTextAlignment(Qt.AlignLeft)

        # Create refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon("refresh.png"))
        self.refresh_button.clicked.connect(self.update_results_arp)

        # Create filter line edit
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by IP or MAC address...")
        self.filter_edit.textChanged.connect(self.filter_results)

        # Create status label
        self.status_label = QLabel("Ready")

        # Create QHBoxLayout for toolbar
        toolbar_layout = QHBoxLayout()
        toolbar_layout.addWidget(self.refresh_button)
        toolbar_layout.addWidget(self.filter_edit)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.status_label)

        # Create QVBoxLayout for the main layout
        layout = QVBoxLayout(self)
        layout.addLayout(toolbar_layout)
        layout.addWidget(self.table_widget)

        # Timer to update ARP results every second
        self.timer_arp = QTimer(self)
        self.timer_arp.timeout.connect(self.update_results_arp)
        self.timer_arp.start(1000)

        # Show the window
        self.show()

    def update_results_arp(self):
        try:
            # Perform ARP scan using scapy
            arp_results = self.scan_arp()

            # Display results in the table
            self.table_widget.setRowCount(len(arp_results))
            for i, result in enumerate(arp_results):
                for j, value in enumerate(result):
                    item = QTableWidgetItem(value)
                    self.table_widget.setItem(i, j, item)

            self.status_label.setText("ARP scan completed.")
        except Exception as e:
            self.status_label.setText(f"Error: {e}")

    def scan_arp(self):
        ip_address = scapy.get_if_addr(self.interface)
        netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
        network = self.calculate_network_cidr(ip_address=ip_address, subnet_mask=netmask)
        # Use scapy to perform ARP scan
        arp_results = []
        arp_packets = scapy.arping(network, verbose=0)[0]
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
            return "N/A"  # Return "N/A" if hostname retrieval fails
        
    def calculate_network_cidr(self, ip_address, subnet_mask):
        # Split the IP address and subnet mask into octets
        ip_octets = [int(octet) for octet in ip_address.split('.')]
        subnet_octets = [int(octet) for octet in subnet_mask.split('.')]

        # Perform bitwise AND operation on corresponding octets
        network_octets = [ip_octets[i] & subnet_octets[i] for i in range(4)]

        # Calculate the number of set bits in the subnet mask
        prefix_length = sum(bin(octet).count('1') for octet in subnet_octets)

        # Format the network address in CIDR notation
        network_address = '.'.join(map(str, network_octets)) + '/' + str(prefix_length)

        return network_address

    def filter_results(self):
        filter_text = self.filter_edit.text().strip().lower()
        for i in range(self.table_widget.rowCount()):
            for j in range(self.table_widget.columnCount()):
                item = self.table_widget.item(i, j)
                if item is not None:
                    text = item.text().lower()
                    if filter_text in text:
                        self.table_widget.setRowHidden(i, False)
                        break
                    else:
                        self.table_widget.setRowHidden(i, True)

def parse_args():
    parser = argparse.ArgumentParser(description='ARP Sniffer')
    parser.add_argument('--interface', required=True, help='Network interface name')
    return parser.parse_args()

if __name__ == '__main__':
    oui_url = "http://standards-oui.ieee.org/oui/oui.csv"
    MacVendorLookup.load_data(oui_url)

    args = parse_args()
    interface = args.interface

    app = QApplication(sys.argv)
    ex = ARPSniffer(oui_url, interface)
    sys.exit(app.exec())
