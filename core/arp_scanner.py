"""
Module Arp Scanner
"""

import concurrent.futures
import csv
import ipaddress
import json
from datetime import datetime

import netifaces
from PySide6.QtCore import Qt, QThread, Signal, Slot  # pylint: disable=E0611
from PySide6.QtGui import QColor, QFont, QIcon  # pylint: disable=E0611
from PySide6.QtWidgets import (QDialog, QFileDialog,  # pylint: disable=E0611
                               QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMainWindow, QMessageBox, QProgressBar,
                               QPushButton, QSplitter, QTextEdit, QVBoxLayout,
                               QWidget)
from scapy.all import ARP, Ether, get_if_addr, srp  # pylint: disable=E0611

from core import db
import core.networking as net
from core import vendor
from core.mitm import MitmThread
from core.ollama_analyst import OllamaThread
from core.platform import get_os
from ui.ui_arpscan import Ui_DeviceDiscovery

try:
    import arpscanner

    NATIVE_ARP_AVAILABLE = True
except ImportError:
    NATIVE_ARP_AVAILABLE = False

# Parallelism: number of workers for concurrent host resolution
_RESOLVE_WORKERS = 20


class DeviceDetailsWindow(QMainWindow):  # pylint: disable=too-many-instance-attributes
    """Window showing detailed information about a device, with MITM controls."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        ip_address,
        mac_address,
        hostname,
        device_vendor,
        interface,
        gateway_ip,
        status="seen",
        first_seen=None,
        last_seen=None,
        mac_history=None,
    ):
        super().__init__()
        self.setWindowTitle(f"Device — {ip_address}")
        self.ip_address = ip_address
        self.interface = interface
        self.gateway_ip = gateway_ip
        self._device_vendor = device_vendor
        self._hostname = hostname
        self._mitm: MitmThread | None = None

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"IP Address: {ip_address}"))
        layout.addWidget(QLabel(f"MAC Address: {mac_address}"))
        layout.addWidget(QLabel(f"Hostname: {hostname}"))
        layout.addWidget(QLabel(f"Vendor: {device_vendor}"))

        if status == "new":
            lbl = QLabel("  NEW DEVICE — first time seen")
            lbl.setStyleSheet("color: #00ff00; font-weight: bold")
            layout.addWidget(lbl)
        elif status == "mac_changed":
            lbl = QLabel("  MAC ADDRESS CHANGED — possible ARP spoofing!")
            lbl.setStyleSheet("color: #ff4444; font-weight: bold")
            layout.addWidget(lbl)

        if first_seen:
            layout.addWidget(QLabel(f"First seen: {first_seen}"))
        if last_seen:
            layout.addWidget(QLabel(f"Last seen:  {last_seen}"))

        if mac_history and len(mac_history) > 1:
            layout.addWidget(QLabel("MAC History:"))
            for entry in mac_history:
                layout.addWidget(
                    QLabel(f"  {entry['seen_at']}  {entry['mac_address']}")
                )

        # MITM controls
        self._status_label = QLabel("MITM: idle")
        self._status_label.setStyleSheet("color: grey")
        layout.addWidget(self._status_label)

        self._mitm_button = QPushButton("Start MITM")
        self._mitm_button.setCheckable(True)
        self._mitm_button.clicked.connect(self._toggle_mitm)
        layout.addWidget(self._mitm_button)

        self._save_pcap_button = QPushButton("Save PCAP")
        self._save_pcap_button.clicked.connect(self._save_pcap)
        self._save_pcap_button.setEnabled(False)
        layout.addWidget(self._save_pcap_button)

        mono = QFont("Monospace")
        mono.setPointSize(9)

        self._packet_list = QListWidget()
        self._packet_list.setFont(mono)
        self._packet_list.currentRowChanged.connect(self._on_packet_selected)

        self._packet_detail = QTextEdit()
        self._packet_detail.setReadOnly(True)
        self._packet_detail.setFont(mono)
        self._packet_detail.setStyleSheet("background:black; color:white;")
        self._packet_detail.setPlaceholderText("Select a packet to inspect it...")

        # Analyse button + LLM output
        self._analyse_button = QPushButton("Analyse with LLM")
        self._analyse_button.setEnabled(False)
        self._analyse_button.clicked.connect(self._analyse_packet)

        self._llm_output = QTextEdit()
        self._llm_output.setReadOnly(True)
        self._llm_output.setFont(mono)
        self._llm_output.setStyleSheet("background:black; color:white;")
        self._llm_output.setPlaceholderText("LLM analysis will appear here...")
        self._llm_output.setMaximumHeight(180)

        # Stack: packet list | packet detail | [analyse btn + llm output]
        pkt_splitter = QSplitter(Qt.Vertical)
        pkt_splitter.addWidget(self._packet_list)
        pkt_splitter.addWidget(self._packet_detail)
        pkt_splitter.setSizes([180, 180])

        self._user_context = QLineEdit()
        self._user_context.setPlaceholderText(
            "Optional context for the LLM (e.g. 'this is a smart TV', 'focus on credentials')..."
        )
        self._user_context.returnPressed.connect(self._analyse_packet)

        layout.addWidget(QLabel("Captured packets:"))
        layout.addWidget(pkt_splitter)
        layout.addWidget(QLabel("Context:"))
        layout.addWidget(self._user_context)
        layout.addWidget(self._analyse_button)
        layout.addWidget(QLabel("LLM analysis:"))
        layout.addWidget(self._llm_output)

        self._captured_packets = []  # newest first, mirrors list order
        self._ollama_thread: OllamaThread | None = None

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.resize(680, 850)

    @Slot(bool)
    def _toggle_mitm(self, checked):
        if checked:
            self._mitm = MitmThread(self.interface, self.ip_address, self.gateway_ip)
            self._mitm.statusChanged.connect(self._on_status)
            self._mitm.packetCaptured.connect(self._on_packet)
            self._mitm.stopped.connect(self._on_mitm_stopped)
            self._mitm.start()
            self._mitm_button.setText("Stop MITM")
            self._status_label.setStyleSheet("color: #ff8800; font-weight: bold")
        else:
            self._mitm_button.setEnabled(False)
            if self._mitm:
                self._mitm.stop()  # async — _on_mitm_stopped will reset UI

    @Slot()
    def _on_mitm_stopped(self):
        self._mitm = None
        self._mitm_button.setText("Start MITM")
        self._mitm_button.setChecked(False)
        self._mitm_button.setEnabled(True)
        self._status_label.setStyleSheet("color: grey")

    @Slot(str)
    def _on_status(self, msg):
        self._status_label.setText(f"MITM: {msg}")
        print(f"[MITM] {msg}")

    @Slot(object)
    def _on_packet(self, pkt):
        self._captured_packets.insert(0, pkt)  # newest first — mirrors list row index
        self._save_pcap_button.setEnabled(True)
        item = QListWidgetItem(pkt.summary())
        item.setForeground(QColor(Qt.white))
        item.setBackground(QColor(Qt.black))
        self._packet_list.insertItem(0, item)
        if self._packet_list.count() > 500:
            self._packet_list.takeItem(self._packet_list.count() - 1)
            self._captured_packets = self._captured_packets[:500]

    @Slot(int)
    def _on_packet_selected(self, row):
        if row < 0 or row >= len(self._captured_packets):
            return
        pkt = self._captured_packets[row]
        self._packet_detail.setPlainText(_format_packet(pkt))
        self._analyse_button.setEnabled(True)
        self._llm_output.clear()

    @Slot()
    def _analyse_packet(self):
        row = self._packet_list.currentRow()
        if row < 0 or row >= len(self._captured_packets):
            return

        # Cancel any running analysis
        if self._ollama_thread and self._ollama_thread.isRunning():
            self._ollama_thread.terminate()

        pkt_text = _format_packet(self._captured_packets[row])
        user_context = self._user_context.text().strip()
        self._ollama_thread = OllamaThread(
            pkt_text,
            user_context=user_context,
            device_vendor=self._device_vendor,
            hostname=self._hostname,
        )
        self._ollama_thread.token.connect(self._on_llm_token)
        self._ollama_thread.error.connect(self._on_llm_error)
        self._ollama_thread.finished.connect(self._on_llm_finished)
        self._ollama_thread.start()

        self._analyse_button.setEnabled(False)
        self._llm_output.setPlainText("Analysing...")

    @Slot(str)
    def _on_llm_token(self, token):
        cursor = self._llm_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        # Clear placeholder on first real token
        if self._llm_output.toPlainText() == "Analysing...":
            self._llm_output.clear()
        cursor.insertText(token)
        self._llm_output.setTextCursor(cursor)
        self._llm_output.ensureCursorVisible()

    @Slot(str)
    def _on_llm_error(self, msg):
        self._llm_output.setPlainText(f"Error: {msg}")

    @Slot()
    def _on_llm_finished(self):
        self._analyse_button.setEnabled(True)

    @Slot()
    def _save_pcap(self):
        if not self._captured_packets:
            return
        from scapy.all import wrpcap  # pylint: disable=E0611

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PCAP",
            f"mitm_{self.ip_address}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
            "PCAP Files (*.pcap)",
        )
        if path:
            wrpcap(path, self._captured_packets)
            print(f"[MITM] Saved {len(self._captured_packets)} packets to {path}")

    def closeEvent(self, event):  # pylint: disable=invalid-name
        """Stop MITM thread when window closes."""
        if self._mitm and self._mitm.isRunning():
            self._mitm.stop()
            # Don't wait — let the thread finish in the background and clean up
        super().closeEvent(event)


class DeviceDiscoveryDialog(QDialog):  # pylint: disable=too-many-instance-attributes
    """Device Discovery"""

    def __init__(self, interface, oui_url, timeout=1000, target_cidr=None, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.mac_vendor_lookup = vendor.MacVendorLookup(oui_url)
        self.timeout = timeout
        self.target_cidr = target_cidr  # None means use interface network

        self._ui = Ui_DeviceDiscovery()
        self._ui.setupUi(self)

        db.init_db()

        # In-memory results for export and spoof seeding
        self._last_results: list = []
        # status tag per IP: 'new' | 'mac_changed' | 'seen'
        self._device_status: dict[str, str] = {}

        self.setup_ui_elements()

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self._ui.verticalLayout.addWidget(self.progress_bar)

        # Export button
        self.export_button = QPushButton("Export Results", self)
        self.export_button.clicked.connect(self.export_results)
        self._ui.verticalLayout.addWidget(self.export_button)

        self.scanner_timer = None
        self.device_info = {}
        self.arp_scanner_thread = None
        self.device_details_window = None

        self._load_known_devices()

    # ------------------------------------------------------------------
    # Known devices from DB
    # ------------------------------------------------------------------

    def _load_known_devices(self):
        """Populate the list with previously seen devices from the DB (shown as stale)."""
        for d in db.get_all_devices():
            self._add_stale_device(
                d["ip_address"], d["mac_address"], d["hostname"], d["vendor"]
            )

    def _add_stale_device(self, ip, mac, hostname, vendor_name):
        label = f"{ip} {mac} {hostname}, {vendor_name}"
        if self._ui.devices.findItems(label, Qt.MatchExactly):
            return
        item = QListWidgetItem(label)
        item.setBackground(QColor("#1a1a1a"))
        item.setForeground(QColor("#666666"))  # grey = cached, not yet confirmed live
        self._ui.devices.addItem(item)

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def setup_ui_elements(self):
        """Sets up the UI elements and connections."""
        self.setWindowIcon(QIcon("images/phantom_logo.png"))
        self._ui.scan.clicked.connect(self.start_scan)
        self._ui.quit.clicked.connect(self.quit_application)
        self.add_static_ui_labels()
        self._ui.devices.itemClicked.connect(self.open_device_details)
        self.setup_font_for_list_widgets()
        self.resize(900, 650)

    def add_static_ui_labels(self):
        """Adds static labels like interface and OS information."""
        local_ip_address = get_if_addr(self.interface)
        default_gateway = netifaces.gateways()[2][0][0]
        local_mac_address = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0][
            "addr"
        ]

        for text in [
            f"OS: {get_os()}",
            f"Interface: {self.interface}",
            f"Local IP Address: {local_ip_address}",
            f"Default Gateway: {default_gateway}",
            f"Local MAC Address: {local_mac_address}",
            f"Scan Timeout: {self.timeout}ms",
        ]:
            lbl = QLabel(text)
            lbl.setStyleSheet("color: black")
            self._ui.verticalLayout.addWidget(lbl)

        if self.target_cidr:
            lbl = QLabel(f"Target CIDR: {self.target_cidr}")
            lbl.setStyleSheet("color: #0044cc; font-weight: bold")
            self._ui.verticalLayout.addWidget(lbl)

    def setup_font_for_list_widgets(self):
        """Sets up a uniform font for list widgets."""
        font = QFont()
        font.setPointSize(12)
        self._ui.devices.setFont(font)
        self._ui.responses.setFont(font)

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    @Slot()
    def start_scan(self):
        """Starts scanning the network."""
        if self.arp_scanner_thread is not None and self.arp_scanner_thread.isRunning():
            print("Scan already in progress.")
            return

        # Grey out existing entries — they'll be re-lit if confirmed live
        for i in range(self._ui.devices.count()):
            item = self._ui.devices.item(i)
            item.setBackground(QColor("#1a1a1a"))
            item.setForeground(QColor("#666666"))
        self._ui.responses.clear()
        self._last_results = []
        self._device_status = {}
        self.progress_bar.setValue(0)

        self.arp_scanner_thread = ARPScannerThread(
            self.interface,
            self.mac_vendor_lookup,
            self.timeout / 1000,
            target_cidr=self.target_cidr,
        )
        self.arp_scanner_thread.partialResults.connect(self.handle_partial_results)
        self.arp_scanner_thread.finished.connect(self.handle_scan_results)
        self.arp_scanner_thread.progressChanged.connect(self.update_progress)
        self.arp_scanner_thread.start()
        target = self.target_cidr or 'local network'
        print(f"Started ARP scan — timeout: {self.timeout}ms, target: {target}")

    @Slot(int)
    def update_progress(self, progress):
        """Update the progress bar value."""
        self.progress_bar.setValue(progress)

    @Slot(list)
    def handle_partial_results(self, partial_results):
        """Handle partial scan results as they arrive."""
        for ip_address, mac, hostname, device_vendor, _ in partial_results:
            status = self._upsert_and_tag(ip_address, mac, hostname, device_vendor)
            self.add_device_to_list(ip_address, mac, hostname, device_vendor, status)

    @Slot(list)
    def handle_scan_results(self, results):
        """Handle the final list of scan results."""
        self._last_results = results
        for ip_address, mac, hostname, device_vendor, packet in results:
            status = self._upsert_and_tag(ip_address, mac, hostname, device_vendor)
            self.add_device_to_list(ip_address, mac, hostname, device_vendor, status)
            self.add_packet_if_new(str(packet))

    def _upsert_and_tag(self, ip, mac, hostname, device_vendor) -> str:
        """Persist to DB, cache and return the status tag."""
        if ip not in self._device_status:
            status = db.upsert_device(ip, mac, hostname, device_vendor)
            self._device_status[ip] = status
        return self._device_status[ip]

    def add_device_to_list(
        self, ip_address, mac, hostname, device_vendor, status="seen"
    ):
        """Add or update a device entry with live colour coding."""
        label = f"{ip_address} {mac} {hostname}, {device_vendor}"

        # Find any existing row for this IP (label may differ if mac/hostname changed)
        existing = None
        for i in range(self._ui.devices.count()):
            if self._ui.devices.item(i).text().startswith(ip_address + " "):
                existing = self._ui.devices.item(i)
                break

        if existing:
            existing.setText(label)
            item = existing
        else:
            item = QListWidgetItem(label)
            self._ui.devices.addItem(item)

        if status == "new":
            item.setBackground(QColor("#003300"))
            item.setForeground(QColor("#00ff00"))
        elif status == "mac_changed":
            item.setBackground(QColor("#330000"))
            item.setForeground(QColor("#ff4444"))
        else:
            item.setBackground(QColor(Qt.black))
            item.setForeground(QColor(Qt.white))

    def add_packet_if_new(self, packet_label):
        """Add a packet summary to the responses list if not already present."""
        if not self._ui.responses.findItems(packet_label, Qt.MatchExactly):
            item = QListWidgetItem(packet_label)
            item.setBackground(QColor(Qt.black))
            item.setForeground(QColor(Qt.white))
            self._ui.responses.addItem(item)

    # ------------------------------------------------------------------
    # Device detail click
    # ------------------------------------------------------------------

    @Slot(QListWidgetItem)
    def open_device_details(self, item):
        """Open the DeviceDetailsWindow for the clicked list item."""
        self.device_info = self._parse_device_details(item.text())
        if self.device_info:
            ip = self.device_info["ip_address"]
            status = self._device_status.get(ip, "seen")
            history = db.get_mac_history(ip)
            known = next((d for d in db.get_all_devices() if d["ip_address"] == ip), {})
            gateway_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]
            self.device_details_window = (
                DeviceDetailsWindow(
                    ip,
                    self.device_info["mac"],
                    self.device_info["hostname"],
                    self.device_info["vendor"],
                    interface=self.interface,
                    gateway_ip=gateway_ip,
                    status=status,
                    first_seen=known.get("first_seen"),
                    last_seen=known.get("last_seen"),
                    mac_history=history,
                )
            )
            self.device_details_window.show()

    @staticmethod
    def _parse_device_details(text):
        parts = text.split()
        if len(parts) >= 4:
            return {
                "ip_address": parts[0],
                "mac": parts[1],
                "hostname": parts[2],
                "vendor": " ".join(parts[3:]),
            }
        return None

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @Slot()
    def export_results(self):
        """Export last scan results to JSON or CSV."""
        if not self._last_results:
            QMessageBox.information(self, "Export", "No scan results to export.")
            return

        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"phantom_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "JSON Files (*.json);;CSV Files (*.csv)",
        )
        if not path:
            return

        records = [
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": dv,
                "status": self._device_status.get(ip, "seen"),
            }
            for ip, mac, hostname, dv, _ in self._last_results
        ]

        if "csv" in selected_filter.lower() or path.endswith(".csv"):
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["ip", "mac", "hostname", "vendor", "status"]
                )
                writer.writeheader()
                writer.writerows(records)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)

        QMessageBox.information(
            self, "Export", f"Saved {len(records)} devices to {path}"
        )

    # ------------------------------------------------------------------
    # Quit
    # ------------------------------------------------------------------

    def quit_application(self):
        """Disable the quit button and shut down the application."""
        self._ui.quit.setEnabled(False)
        self._shutdown()

    def closeEvent(self, event):  # pylint: disable=invalid-name
        """Shut down scanner thread when dialog closes."""
        self._shutdown()
        super().closeEvent(event)

    def _shutdown(self):
        if self.arp_scanner_thread is not None and self.arp_scanner_thread.isRunning():
            self.arp_scanner_thread.quit()
            self.arp_scanner_thread.wait()
        from PySide6.QtWidgets import QApplication  # pylint: disable=E0611

        QApplication.quit()


# ---------------------------------------------------------------------------
# ARP Scanner Thread
# ---------------------------------------------------------------------------


class ARPScannerThread(QThread):  # pylint: disable=too-few-public-methods
    """ARP scanner — supports parallel scanning and custom CIDR targets."""

    finished = Signal(list)
    partialResults = Signal(list)
    progressChanged = Signal(int)

    def __init__(self, interface, mac_vendor_lookup, timeout=1, target_cidr=None):
        super().__init__()
        self.interface = interface
        self.mac_vendor_lookup = mac_vendor_lookup
        self.timeout = timeout
        self.target_cidr = target_cidr
        self.is_macos = get_os() == "mac"
        self.use_native = self.is_macos and NATIVE_ARP_AVAILABLE

    def run(self):
        """Determine the target network and start the ARP scan."""
        src_ip = get_if_addr(self.interface)

        if self.target_cidr:
            try:
                network = ipaddress.IPv4Network(self.target_cidr, strict=False)
            except ValueError as e:
                print(f"Invalid target CIDR {self.target_cidr}: {e}")
                self.finished.emit([])
                return
        else:
            try:
                netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0][
                    "netmask"
                ]
                network_cidr = net.calculate_network_cidr(src_ip, netmask)
                network = ipaddress.IPv4Network(network_cidr)
            except KeyError:
                self.finished.emit([])
                return

        arp_results = self._scan_network(src_ip, network)
        self.finished.emit(arp_results)

    def _scan_network(self, src_ip, network):
        hosts = [str(ip) for ip in network.hosts() if str(ip) != src_ip]
        if self.use_native:
            print("Using native ARP scanner")
            return self._run_native_scan(src_ip, hosts)
        print(f"Using Scapy ARP scanner — {len(hosts)} hosts")
        return self._run_scapy_scan(hosts)

    # ------------------------------------------------------------------
    # Native (macOS) scan — sequential, one host at a time
    # ------------------------------------------------------------------

    def _run_native_scan(self, src_ip, hosts):
        """Scan hosts sequentially using the native C arpscanner extension."""
        arp_results = []
        total = len(hosts)
        for count, ip in enumerate(hosts, start=1):
            try:
                result = arpscanner.perform_arp_scan(
                    self.interface,
                    str(src_ip),
                    str(ip),
                    int(self.timeout * 1000),
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                print(f"Error scanning {ip}: {e}")
                result = None

            if result:
                mac = result["mac"]
                device_vendor = self.mac_vendor_lookup.lookup_vendor(mac)
                hostname = net.get_hostname(ip)
                arp_response = _make_arp_response(ip, mac)
                arp_results.append((ip, mac, hostname, device_vendor, arp_response))

            self._update_progress(count, total, arp_results)
        return arp_results

    # ------------------------------------------------------------------
    # Scapy scan — parallel bulk dispatch
    # ------------------------------------------------------------------

    def _run_scapy_scan(self, hosts):
        """
        Split hosts into chunks and scan them concurrently.
        Each chunk sends a bulk ARP request via srp() to minimise round-trips,
        then resolves hostnames in parallel.
        """
        chunk_size = 254
        chunks = [hosts[i : i + chunk_size] for i in range(0, len(hosts), chunk_size)]
        total_chunks = len(chunks)
        arp_results = []

        for chunk_idx, chunk in enumerate(chunks, start=1):
            pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in chunk]
            try:
                # inter=0.5ms between sends, retry=2 for slow/IoT devices,
                # timeout is per-round wait after the last packet is sent
                ans, _ = srp(
                    pkts,
                    timeout=self.timeout,
                    iface=self.interface,
                    inter=0.0005,
                    retry=2,
                    verbose=0,
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                print(f"Scapy error on chunk {chunk_idx}: {e}")
                ans = []

            # Resolve hostnames in parallel for all responding hosts
            responded = [(rcv.psrc, rcv.hwsrc, rcv) for _, rcv in ans]
            resolved = self._resolve_parallel(responded)
            arp_results.extend(resolved)

            # Emit partial results and progress after each chunk
            self.partialResults.emit(list(arp_results))
            progress = int((chunk_idx / total_chunks) * 100)
            self.progressChanged.emit(progress)

        return arp_results

    def _resolve_parallel(self, responded: list) -> list:
        """Resolve hostnames and vendor for a list of (ip, mac, packet) concurrently."""
        results = []

        def resolve_one(entry):
            ip, mac, pkt = entry
            device_vendor = self.mac_vendor_lookup.lookup_vendor(mac)
            hostname = net.get_hostname(ip)
            return ip, mac, hostname, device_vendor, pkt

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=_RESOLVE_WORKERS
        ) as pool:
            for result in pool.map(resolve_one, responded):
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_progress(self, count, total, arp_results):
        """Used only by native scan path (scapy uses chunk-based progress)."""
        progress = int((count / total) * 100)
        self.progressChanged.emit(progress)
        if count % 10 == 0:
            self.partialResults.emit(list(arp_results))


def _format_packet(pkt) -> str:
    """Return a human-readable multi-layer breakdown of a Scapy packet."""
    lines = []
    lines.append(f"{'─'*60}")
    lines.append(f"  {pkt.summary()}")
    lines.append(f"{'─'*60}")

    layer = pkt
    while layer:
        name = layer.__class__.__name__
        lines.append(f"\n[ {name} ]")
        for field, val in layer.fields.items():
            # Format bytes as hex, everything else as-is
            if isinstance(val, bytes):
                formatted = val.hex(" ") if val else "(empty)"
            else:
                formatted = str(val)
            lines.append(f"  {field:<20} {formatted}")
        # Move to next layer
        layer = (
            layer.payload
            if layer.payload and layer.payload.__class__.__name__ != "NoPayload"
            else None
        )

    # Raw payload hex dump if present
    raw = bytes(pkt)
    if raw:
        lines.append(f"\n[ Raw ({len(raw)} bytes) ]")
        for i in range(0, len(raw), 16):
            chunk = raw[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {i:04x}  {hex_part:<47}  {ascii_part}")

    return "\n".join(lines)


def _make_arp_response(ip_addr, mac):
    return type(
        "ARPResponse",
        (),
        {
            "psrc": ip_addr,
            "hwsrc": mac,
            "__str__": lambda self: f"ARP {self.psrc} is-at {self.hwsrc}",
        },
    )()
