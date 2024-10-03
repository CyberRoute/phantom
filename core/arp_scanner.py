"""
Module Arp Scanner
"""
import netifaces
from scapy.all import arping, ARP, get_if_addr # pylint: disable=E0611
from PySide6.QtWidgets import ( # pylint: disable=E0611
    QMainWindow,
    QVBoxLayout,
    QLabel,
    QWidget,
    QDialog,
    QListWidget,
    QListWidgetItem
)
from PySide6.QtGui import QIcon, QFont, QColor # pylint: disable=E0611
from PySide6.QtCore import Slot, Qt, QTimer # pylint: disable=E0611
from PyQt6.QtCore import QThread, pyqtSignal # pylint: disable=E0611
from ui.ui_arpscan import Ui_DeviceDiscovery
from core import vendor
from core.platform import get_os
import core.networking as net


class DeviceDetailsWindow(QMainWindow): # pylint: disable=too-few-public-methods
    """
    A window that displays detailed information about a network device.

    Attributes:
        ip_address (str): The IP address of the device.
        mac_address (str): The MAC address of the device.
        hostname (str): The hostname of the device.
        vendor (str): The vendor of the device.
    """
    def __init__(self, ip_address, mac_address, hostname, device_vendor):
        super().__init__()
        self.setWindowTitle("Device Details")

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"IP Address: {ip_address}"))
        layout.addWidget(QLabel(f"MAC Address: {mac_address}"))
        layout.addWidget(QLabel(f"Hostname: {hostname}"))
        layout.addWidget(QLabel(f"Vendor: {device_vendor}"))

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)


class DeviceDiscoveryDialog(QDialog): # pylint: disable=too-many-instance-attributes
    """Device Discovery"""
    def __init__(self, interface, oui_url, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.mac_vendor_lookup = vendor.MacVendorLookup(oui_url)

        self._ui = Ui_DeviceDiscovery()
        self._ui.setupUi(self)

        # Initialize the UI and connection setup
        self.setup_ui_elements()

        # Initialize scanner and device info storage
        self.scanner_timer = None
        self.device_info = {}  # Store dynamic device info here
        self.arp_scanner_thread = None

    def setup_ui_elements(self):
        """Sets up the UI elements and connections."""
        self.setWindowIcon(QIcon("images/phantom_logo.png"))

        self._ui.scan.clicked.connect(self.toggle_scan)
        net.enable_ip_forwarding()
        self._ui.quit.clicked.connect(self.quit_application)

        # Add static labels and list widgets
        self.add_static_ui_labels()

         # Connect item click signal to open_device_details
        self._ui.list.itemClicked.connect(self.open_device_details)

        # Set the default font for the list items
        self.setup_font_for_list_widgets()

        self.resize(800, 600)

    def add_static_ui_labels(self):
        """Adds static labels like interface and OS information."""
        interface_label = QLabel(f"Interface: {self.interface}")
        interface_label.setStyleSheet("color: black")

        os_label = QLabel(f"OS: {get_os()}")
        os_label.setStyleSheet("color: black")

        self._ui.verticalLayout.addWidget(os_label)
        self._ui.verticalLayout.addWidget(interface_label)

    def setup_font_for_list_widgets(self):
        """Sets up a uniform font for list widgets."""
        font = QFont()
        font.setPointSize(12)
        self._ui.list.setFont(font)
        self._ui.listpkt.setFont(font)
        self._ui.tab_1.setFont(font)

    @Slot(QListWidgetItem)
    def open_device_details(self, item):
        """Click on a device opens another window with details."""
        self.device_info = self.parse_device_details(item.text())
        if self.device_info:
            self.show_device_details_window()
        else:
            print("Invalid format: Not enough information")

    def parse_device_details(self, text):
        """Parses device details from the selected list item text."""
        parts = text.split()
        if len(parts) >= 4:
            return {
                "ip_address": parts[0],
                "mac": parts[1],
                "hostname": parts[2],
                "vendor": " ".join(parts[3:])
            }
        return None

    def show_device_details_window(self):
        """Opens a window showing detailed device information."""
        self.device_details_window = DeviceDetailsWindow( # pylint: disable=attribute-defined-outside-init
            self.device_info['ip_address'],
            self.device_info['mac'],
            self.device_info['hostname'],
            self.device_info['vendor']
        )
        self.device_details_window.show()

    @Slot()
    def toggle_scan(self):
        """Toggle scanning all local networks every 1s."""
        self._ui.scan.setEnabled(False)
        self.scanner_timer = self.setup_scanner_timer()
        self.scanner_timer.start()

    def setup_scanner_timer(self):
        """Sets up the scanner timer to periodically trigger ARP scanning."""
        timer_arp = QTimer(self)
        timer_arp.setInterval(1000)
        timer_arp.timeout.connect(self.start_scan)
        return timer_arp

    @Slot()
    def start_scan(self):
        """Starts scanning the network."""
        # Check if there's already a running scan, and don't start another one
        if self.arp_scanner_thread is not None and self.arp_scanner_thread.isRunning():
            print("Scan is already in progress.")
            return

        # Create and start a new ARP scan thread
        self.arp_scanner_thread = ARPScannerThread(self.interface, self.mac_vendor_lookup)
        # Connect signals to handle thread completion and verbose output
        self.arp_scanner_thread.finished.connect(self.handle_scan_results)
        # Start the thread
        self.arp_scanner_thread.start()
        print("Started ARP scan.")

    @Slot(list)
    def handle_scan_results(self, results):
        """Updates the scan results."""
        for ip_address, mac, hostname, device_vendor, packet in results:
            # Add device to the list if not already present
            self.add_device_to_list(ip_address, mac, hostname, device_vendor)

            # Add packet to the packet list if not already present
            packet_label = str(packet)
            self.add_packet_if_new(packet_label)


    def add_device_to_list(self, ip_address, mac, hostname, device_vendor):
        """Adds a device to the list widget in the UI."""
        label = f"{ip_address} {mac} {hostname}, {device_vendor}"
        if not self._ui.list.findItems(label, Qt.MatchExactly):
            item = QListWidgetItem(label)
            item.setBackground(QColor(Qt.black))
            item.setForeground(QColor(Qt.white))
            self._ui.list.addItem(item)

    def add_packet_if_new(self, packet_label):
        """Adds a packet to the listpkt widget if it doesn't already exist."""
        existing_items = self._ui.listpkt.findItems(packet_label, Qt.MatchExactly)
        if not existing_items:  # Add only if the packet is not already listed
            packet_item = QListWidgetItem(packet_label)
            packet_item.setBackground(QColor(Qt.black))
            packet_item.setForeground(QColor(Qt.white))
            self._ui.listpkt.addItem(packet_item)

    def quit_application(self):
        """Quit the application."""
        self._ui.quit.setEnabled(False)
        net.disable_ip_forwarding()
        # Stop any running threads safely
        if self.arp_scanner_thread is not None:
            self.arp_scanner_thread.terminate()
            self.arp_scanner_thread.wait()
        QTimer.singleShot(2000, self.close)


class ARPScannerThread(QThread): # pylint: disable=too-few-public-methods
    """Executing arp scan in separate thread"""
    finished = pyqtSignal(list)

    def __init__(self, interface, mac_vendor_lookup, timeout=1):
        super().__init__()
        self.interface = interface
        self.mac_vendor_lookup = mac_vendor_lookup
        self.timeout = timeout

    def run(self):
        "run the scan"
        ip_address = get_if_addr(self.interface)
        try:
            netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
            network = net.calculate_network_cidr(ip_address, netmask)
        except KeyError:
            self.finished.emit([])
            return

        arp_results = []
        try:
            arp_packets = arping(network, timeout=self.timeout, verbose=1)[0]
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error during ARP scan: {e}")
            self.finished.emit([])
            return
        for _, packet in enumerate(arp_packets):
            if packet[1].haslayer(ARP):
                ip_address = packet[1][ARP].psrc
                mac = packet[1][ARP].hwsrc
                device_vendor = self.mac_vendor_lookup.lookup_vendor(mac)
                hostname = net.get_hostname(ip_address)
                arp_results.append((ip_address, mac, hostname, device_vendor, packet[1][ARP]))
        self.finished.emit(arp_results)
