from PySide6.QtWidgets import *
from ui.ui_arpscan import Ui_DeviceDiscovery
from PySide6.QtGui import *
from PySide6.QtCore import *
import scapy.all as scapy
import socket
import netifaces
import core.networking as net
import core.sniffer as sniffer
import core.vendor as vendor
from core.platform import get_os


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

class Worker(QRunnable):
    """
    Worker thread
    """

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    @Slot()
    def run(self):
        """
        Your code goes in this function
        """
        print("Sniffer Thread start")
        myip = net.get_ip_address()
        print(self.interface)
        snif = sniffer.PacketCollector(self.interface, myip)
        snif.start_capture()
        print("Sniffer Thread complete")

class DeviceDiscoveryDialog(QDialog):
    def __init__(self, interface, oui_url, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.mac_vendor_lookup = vendor.MacVendorLookup(oui_url)

        self._ui = Ui_DeviceDiscovery()
        self._ui.setupUi(self)
        self._ui.scan.clicked.connect(self.toggle_scan)
        net.enable_ip_forwarding()
        self._ui.quit.clicked.connect(self.quit_application)
        self.interface_label = QLabel(f"Interface: {self.interface}")
        self.interface_label.setStyleSheet("color: black")
        self.os_label = QLabel(f"OS: {get_os()}")
        self.os_label.setStyleSheet("color: black")

        self._ui.verticalLayout.addWidget(self.os_label)

        self._ui.verticalLayout.addWidget(self.interface_label)
        self._ui.list.itemClicked.connect(self.open_device_details)
        self.ip_address = None
        self.mac = None
        self.hostname = None
        self.vendor = None

        self.threadpool = QThreadPool()
        print("Multithreading with maximum %d threads" % self.threadpool.maxThreadCount())

        self._ui.scan.setEnabled(True)  # Disable scan initially

        # Increase the size of the UI window
        self.resize(800, 600)

        # Increase the font size of QListWidget items
        font = QFont()
        font.setPointSize(12)  # Set the font size to 12
        self._ui.list.setFont(font)  # Apply the font to the QListWidget
        self._ui.listpkt.setFont(font)

        # Add descriptions for the two QListWidgetItems
        description_item_1 = QListWidgetItem("Devices detected")
        description_item_1.setBackground(QColor(Qt.darkGray))
        description_item_1.setForeground(QColor(Qt.white))
        description_item_2 = QListWidgetItem("ARP packets")
        description_item_2.setBackground(QColor(Qt.darkGray))
        description_item_2.setForeground(QColor(Qt.white))
        self._ui.list.addItem(description_item_1)
        self._ui.listpkt.addItem(description_item_2)

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
        self._ui.scan.setEnabled(False)
        self.timer_arp = QTimer(self)
        self.timer_arp.setInterval(1000)  # Set interval to 20 seconds
        self.timer_arp.timeout.connect(self.start_scan)
        self.timer_arp.start()

        # Start the sniffer in a separate thread using QThreadPool
        worker = Worker(self.interface)  # Pass self.interface to the Worker constructor
        self.threadpool.start(worker)

    @Slot()
    def start_scan(self):
        ARPScanner.run_arp_scan(self.interface, self._ui, self.mac_vendor_lookup)

    def quit_application(self):
        """
        Slot function to be called when the Quit button is clicked.
        Disable IP forwarding and close the application.
        """
        net.disable_ip_forwarding()
        self.close()

class ARPScanner:
    @staticmethod
    def calculate_network_cidr(ip_address, subnet_mask):
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

    @staticmethod
    def get_hostname(ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception as e:
            return "N/A"  # Return "N/A" if hostname retrieval fails

    @staticmethod
    def run_arp_scan(interface, ui, mac_vendor_lookup):
        # Function to perform ARP scan
        ip_address = scapy.get_if_addr(interface)
        try:
            netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']

            network = ARPScanner.calculate_network_cidr(ip_address=ip_address, subnet_mask=netmask)
        except KeyError:
            return "network recalculation"
        arp_results = []
        arp_packets = scapy.arping(network, verbose=0)[0]
        for packet in arp_packets:
            if packet[1].haslayer(scapy.ARP):
                ip_address = packet[1][scapy.ARP].psrc
                mac = packet[1][scapy.ARP].hwsrc
                vendor = mac_vendor_lookup.lookup_vendor(mac)
                hostname = ARPScanner.get_hostname(ip_address)
                label = f"{ip_address} {mac} {hostname} {vendor}"
                items = ui.list.findItems(label, Qt.MatchExactly)
                if not items:
                    item = QListWidgetItem(label)
                    item.setBackground(QColor(Qt.black))
                    item.setForeground(QColor(Qt.white))
                    ui.list.addItem(item)
                label = str(packet[1][scapy.ARP])
                items = ui.listpkt.findItems(label, Qt.MatchExactly)
                if not items:
                    item = QListWidgetItem(label)
                    item.setBackground(QColor(Qt.black))
                    item.setForeground(QColor(Qt.white))
                    ui.listpkt.addItem(item)
                arp_results.append((ip_address, mac, hostname, vendor, packet[1][scapy.ARP]))
        return arp_results