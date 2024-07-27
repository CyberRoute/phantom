from PySide6.QtWidgets import *
from ui.ui_arpscan import Ui_DeviceDiscovery
from PySide6.QtGui import *
from PySide6.QtCore import *
from PyQt6.QtCore import QThread, pyqtSignal
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

    def __init__(self, packet_collector):
        super().__init__()
        self.packet_collector = packet_collector

    @Slot()
    def run(self):
        """
        Your code goes in this function
        """
        print("Sniffer Thread start")
        self.packet_collector.start_capture()
        print("Sniffer Thread complete")


class StopWorker(QRunnable):
    """
    Worker thread to stop the packet collector
    """

    def __init__(self, packet_collector):
        super().__init__()
        self.packet_collector = packet_collector

    @Slot()
    def run(self):
        """
        Code to stop the packet collector
        """
        print("Stopping Sniffer Thread")
        self.packet_collector.stop_capture()
        print("Stopped Sniffer Thread")


class DeviceDiscoveryDialog(QDialog):
    def __init__(self, interface, oui_url, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.mac_vendor_lookup = vendor.MacVendorLookup(oui_url)

        self._ui = Ui_DeviceDiscovery()  # Assuming Ui_DeviceDiscovery is defined elsewhere
        self._ui.setupUi(self)
        self.setWindowIcon(QIcon("images/phantom_logo.png"))

        self._ui.scan.clicked.connect(self.toggle_scan)
        net.enable_ip_forwarding()
        self._ui.quit.clicked.connect(self.quit_application)
        self.interface_label = QLabel(f"Interface: {self.interface}")
        self.interface_label.setStyleSheet("color: black")
        self.os_label = QLabel(f"OS: {get_os()}")  # Assuming get_os is defined elsewhere
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

        # Add QListWidget to tab_7
        self.add_list_widget_to_tab_7()

        # Initialize PacketCollector
        self.packet_collector = sniffer.PacketCollector(self.interface, net.get_ip_address())
        self.packet_collector.packetCaptured.connect(self.add_packet_to_list)

        # Progress Label for ARP Scan
        self.progress_label = QLabel("Progress: 0%")
        self._ui.verticalLayout.addWidget(self.progress_label)

    def add_list_widget_to_tab_7(self):
        self.list_widget_tab7 = QListWidget()
        tab7_layout = QVBoxLayout(self._ui.tab_7)
        tab7_layout.addWidget(self.list_widget_tab7)

        # Adding data to list_widget_tab7
        description_item_1 = QListWidgetItem("Devices detected in tab 7")
        description_item_1.setBackground(QColor(Qt.darkGray))
        description_item_1.setForeground(QColor(Qt.white))

        description_item_2 = QListWidgetItem("ARP packets in tab 7")
        description_item_2.setBackground(QColor(Qt.darkGray))
        description_item_2.setForeground(QColor(Qt.white))

        self.list_widget_tab7.addItem(description_item_1)
        self.list_widget_tab7.addItem(description_item_2)

    def add_packet_to_list(self, packet_summary):
        packet_item = QListWidgetItem(packet_summary)
        packet_item.setBackground(QColor(Qt.darkGray))
        packet_item.setForeground(QColor(Qt.white))
        print(packet_summary)
        self.list_widget_tab7.addItem(packet_item)

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
        # self.timer_arp = QTimer(self)
        # self.timer_arp.setInterval(1000)  # Set interval to 1 second
        # self.timer_arp.timeout.connect(self.start_scan)
        # self.timer_arp.start()

        # Start the sniffer in a separate thread using QThreadPool
        #worker = Worker(self.packet_collector)  # Pass packet_collector to the Worker constructor
        #self.threadpool.start(worker)
        self.start_scan()


    @Slot()
    def start_scan(self):
        self.arp_scanner_thread = ARPScannerThread(self.interface, self.mac_vendor_lookup)
        self.arp_scanner_thread.finished.connect(self.handle_scan_results)
        self.arp_scanner_thread.progress_updated.connect(self.update_progress)
        self.arp_scanner_thread.start()

    @Slot(list)
    def handle_scan_results(self, results):
        for ip_address, mac, hostname, vendor, packet in results:
            label = f"{ip_address} {mac} {hostname} {vendor}"
            items = self._ui.list.findItems(label, Qt.MatchExactly)
            if not items:
                item = QListWidgetItem(label)
                item.setBackground(QColor(Qt.black))
                item.setForeground(QColor(Qt.white))
                self._ui.list.addItem(item)
            label = str(packet)
            items = self._ui.listpkt.findItems(label, Qt.MatchExactly)
            if not items:
                item = QListWidgetItem(label)
                item.setBackground(QColor(Qt.black))
                item.setForeground(QColor(Qt.white))
                self._ui.listpkt.addItem(item)
        self._ui.scan.setEnabled(True)

    @Slot(int)
    def update_progress(self, value):
        self.progress_label.setText(f"Progress: {value}%")

    def quit_application(self):
        """
        Slot function to be called when the Quit button is clicked.
        Disable IP forwarding and close the application.
        """
        self._ui.quit.setEnabled(False)
        net.disable_ip_forwarding()

        # Stop the ARP scanner thread if it is running
        if hasattr(self, 'arp_scanner_thread') and self.arp_scanner_thread.isRunning():
            self.arp_scanner_thread.terminate()
            self.arp_scanner_thread.wait()

        # Stop the packet collector in a separate thread to avoid blocking the UI
        stop_worker = StopWorker(self.packet_collector)
        self.threadpool.start(stop_worker)
        if hasattr(self, 'arp_scanner_thread') and self.arp_scanner_thread.isRunning():
            self.arp_scanner_thread.terminate()
            self.arp_scanner_thread.wait()

        # Close the dialog after a short delay to allow stop_worker to complete
        QTimer.singleShot(2000, self.close)  # 2-second delay

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

class ARPScannerThread(QThread):
    finished = pyqtSignal(list)
    progress_updated = pyqtSignal(int)

    def __init__(self, interface, mac_vendor_lookup):
        super().__init__()
        self.interface = interface
        self.mac_vendor_lookup = mac_vendor_lookup

    def run(self):
        ip_address = scapy.get_if_addr(self.interface)
        try:
            netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
            network = ARPScanner.calculate_network_cidr(ip_address, netmask)
        except KeyError:
            self.finished.emit([])
            return

        arp_results = []
        arp_packets = scapy.arping(network, verbose=0)[0]
        total_packets = len(arp_packets)
        for i, packet in enumerate(arp_packets):
            if packet[1].haslayer(scapy.ARP):
                ip_address = packet[1][scapy.ARP].psrc
                mac = packet[1][scapy.ARP].hwsrc
                vendor = self.mac_vendor_lookup.lookup_vendor(mac)
                hostname = ARPScanner.get_hostname(ip_address)
                arp_results.append((ip_address, mac, hostname, vendor, packet[1][scapy.ARP]))

            progress = int((i + 1) / total_packets * 100)
            self.progress_updated.emit(progress)

        self.finished.emit(arp_results)


