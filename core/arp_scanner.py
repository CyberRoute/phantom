import csv
from io import StringIO
from PySide6.QtWidgets import QDialog, QListWidgetItem, QLabel, QMainWindow, QVBoxLayout, QWidget
import requests
from ui.ui_arpscan import Ui_DeviceDiscovery
from PySide6.QtGui import QColor, QFont
from PySide6.QtCore import Slot, Qt, QTimer
import scapy.all as scapy
import socket
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
    
class DeviceDetailsWindow(QMainWindow):
    def __init__(self, ip_address, mac_address, hostname, vendor):
        super().__init__()
        self.setWindowTitle("Device Details")
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"IP Address: {ip_address}"))
        layout.addWidget(QLabel(f"MAC Address: {mac_address}"))
        layout.addWidget(QLabel(f"Hostname: {hostname}"))
        layout.addWidget(QLabel(f"Vendor: {vendor}"))
        
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

class DeviceDiscoveryDialog(QDialog):
    def __init__(self, interface, oui_url, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.mac_vendor_lookup = MacVendorLookup(oui_url)

        self._ui = Ui_DeviceDiscovery()
        self._ui.setupUi(self)
        self._ui.scan.clicked.connect(self.toggle_scan)
        self.interface_label = QLabel(f"Interface: {self.interface}")
        self.interface_label.setStyleSheet("color: green") 
        self._ui.verticalLayout.addWidget(self.interface_label)
        self._ui.list.itemClicked.connect(self.open_device_details)
        self.ip_address = None
        self.mac = None
        self.hostname = None
        self.vendor = None

        self._ui.scan.setEnabled(True)  # Disable scan initially
        
        # Increase the size of the UI window
        self.resize(800, 600)
        
        # Increase the font size of QListWidget items
        font = QFont()
        font.setPointSize(12)  # Set the font size to 12
        self._ui.list.setFont(font)  # Apply the font to the QListWidget

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
    
    @Slot(QListWidgetItem)
    def open_device_details(self, item):
        # Get the text of the clicked item
        selected_text = item.text()

        # Split the selected text
        parts = selected_text.split()

        # Check if there are at least four parts
        if len(parts) >= 4:
            # Extract device information from the parts
            self.ip_address = parts[0]
            self.mac = parts[1]
            self.hostname = parts[2]  # Join the hostname parts
            self.vendor = " ".join(parts[3:])

            # Open the detailed information window
            self.device_details_window = DeviceDetailsWindow(self.ip_address, self.mac, self.hostname, self.vendor)
            self.device_details_window.show()
        else:
            print("Invalid format: Not enough information")

    
    @Slot()
    def toggle_scan(self):
        self.timer_arp = QTimer(self)
        self.timer_arp.timeout.connect(self.start_scan)
        self.timer_arp.start(100)

    Slot()
    def start_arpscan(self):
        ip_address = scapy.get_if_addr(self.interface)
        netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
        network = self.calculate_network_cidr(ip_address=ip_address, subnet_mask=netmask)
        # Use scapy to perform ARP scan
        self._ui.scan.setEnabled(False)
        arp_results = []
        arp_packets = scapy.arping(network, verbose=0)[0]
        for packet in arp_packets:
            if packet[1].haslayer(scapy.ARP):
                self.ip_address = packet[1][scapy.ARP].psrc
                self.mac = packet[1][scapy.ARP].hwsrc

                # Look up vendor information using MacVendorLookup class
                self.vendor = self.mac_vendor_lookup.lookup_vendor(self.mac)

                # Retrieve hostname inside the loop
                self.hostname = self.get_hostname(self.ip_address)
                label = f"{self.ip_address} {self.mac} {self.hostname} {self.vendor}"
                items = self._ui.list.findItems(label, Qt.MatchExactly)
                if not items:
                    item = QListWidgetItem(label)
                    item.setBackground(QColor(Qt.black))
                    item.setForeground(QColor(Qt.white))
                    self._ui.list.addItem(item)

                arp_results.append([self.ip_address, self.mac, self.hostname, self.vendor, packet[1][scapy.ARP]])
        print(arp_results)

        return arp_results
    
    @Slot()
    def start_scan(self):
        self.start_arpscan()
        self._ui.scan.setEnabled(False)

    @Slot()
    def scan_finished(self):
        self._ui.scan.setEnabled(True)