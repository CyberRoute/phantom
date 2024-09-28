"""
Module Arp Scanner
"""
import io
import sys
import socket
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
from PySide6.QtCore import Slot, Qt, QThreadPool, QTimer # pylint: disable=E0611
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
        self.setWindowIcon(QIcon("images/phantom_logo.png"))

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
        print(f"Multithreading with maximum {self.threadpool.maxThreadCount()} threads")

        self._ui.scan.setEnabled(True)

        self.resize(800, 600)

        font = QFont()
        font.setPointSize(12)
        self._ui.list.setFont(font)
        self._ui.listpkt.setFont(font)

        self.add_list_widget_to_tab_1()


    def add_list_widget_to_tab_1(self):
        """Adds a QListWidget to the first tab of the UI."""
        self.list_widget_tab7 = QListWidget()
        tab7_layout = QVBoxLayout(self._ui.tab_1)
        tab7_layout.addWidget(self.list_widget_tab7)

        # description_item_1 = QListWidgetItem("Devices detected in tab 7")
        # description_item_1.setBackground(QColor(Qt.darkGray))
        # description_item_1.setForeground(QColor(Qt.white))

        # description_item_2 = QListWidgetItem("ARP packets in tab 7")
        # description_item_2.setBackground(QColor(Qt.darkGray))
        # description_item_2.setForeground(QColor(Qt.white))

        # self.list_widget_tab7.addItem(description_item_1)
        # self.list_widget_tab7.addItem(description_item_2)

    def add_packet_to_list(self, packet_summary):
        """Adds a packet summary to the list widget in the first tab."""
        packet_item = QListWidgetItem(packet_summary)
        packet_item.setBackground(QColor(Qt.black))
        packet_item.setForeground(QColor(Qt.white))
        self.list_widget_tab7.addItem(packet_item)

    @Slot(QListWidgetItem)
    def open_device_details(self, item):
        """click on device open another window with details"""
        selected_text = item.text()
        parts = selected_text.split()

        if len(parts) >= 4:
            self.ip_address = parts[0]
            self.mac = parts[1]
            self.hostname = parts[2]
            self.vendor = " ".join(parts[3:])

            self.device_details_window = DeviceDetailsWindow( # pylint: disable=attribute-defined-outside-init
                self.ip_address,
                self.mac,
                self.hostname,
                self.vendor
            )
            self.device_details_window.show()
        else:
            print("Invalid format: Not enough information")

    @Slot()
    def toggle_scan(self):
        """keep scannning all local network every 1s"""
        self._ui.scan.setEnabled(False)
        self.timer_arp = QTimer(self) # pylint: disable=attribute-defined-outside-init
        self.timer_arp.setInterval(1000)
        self.timer_arp.timeout.connect(self.start_scan)
        self.timer_arp.start()

    @Slot()
    def start_scan(self):
        """start scanning"""
        self.arp_scanner_thread = ARPScannerThread(self.interface, self.mac_vendor_lookup) # pylint: disable=attribute-defined-outside-init
        self.arp_scanner_thread.finished.connect(self.handle_scan_results)
        self.arp_scanner_thread.verbose_output.connect(self.update_tab7_verbose_output)
        self.arp_scanner_thread.start()

    @Slot(list)
    def handle_scan_results(self, results):
        """update scan results"""
        for ip_address, mac, hostname, device_vendor, packet in results:
            label = f"{ip_address} {mac} {hostname}, {device_vendor}"
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

    @Slot(str)
    def update_tab7_verbose_output(self, verbose_output):
        """update tab7"""
        # Update the list_widget_tab7 with verbose output
        font = QFont()
        font.setPointSize(12)
        self._ui.tab_1.setFont(font)

        for line in verbose_output.splitlines():
            if line.strip():  # Skip empty lines
                item = QListWidgetItem(line)
                item.setBackground(QColor(Qt.black))
                item.setForeground(QColor(Qt.white))
                self.list_widget_tab7.addItem(item)

    def quit_application(self):
        """quit the app"""
        self._ui.quit.setEnabled(False)
        net.disable_ip_forwarding()

        if hasattr(self, 'arp_scanner_thread') and self.arp_scanner_thread.isRunning():
            self.arp_scanner_thread.terminate()
            self.arp_scanner_thread.wait()
        QTimer.singleShot(2000, self.close)


class ARPScannerThread(QThread): # pylint: disable=too-few-public-methods
    """Executing arp scan in separate thread"""
    finished = pyqtSignal(list)
    progress_updated = pyqtSignal(int)
    verbose_output = pyqtSignal(str)  # Signal to emit verbose output

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
        original_stdout = sys.stdout  # Save a reference to the original standard output
        try:
            # Redirect stdout to capture Scapy output
            sys.stdout = io.StringIO()

            arp_packets = arping(network, timeout=self.timeout, verbose=1)[0]

            # Get the verbose output
            verbose_output = sys.stdout.getvalue()
            self.verbose_output.emit(verbose_output)  # Emit the verbose output

        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error during ARP scan: {e}")
            self.finished.emit([])
            return
        finally:
            sys.stdout = original_stdout  # Reset the standard output to its original state

        for _, packet in enumerate(arp_packets):
            if packet[1].haslayer(ARP):
                ip_address = packet[1][ARP].psrc
                mac = packet[1][ARP].hwsrc
                device_vendor = self.mac_vendor_lookup.lookup_vendor(mac)
                hostname = net.get_hostname(ip_address)
                arp_results.append((ip_address, mac, hostname, device_vendor, packet[1][ARP]))
        self.finished.emit(arp_results)
