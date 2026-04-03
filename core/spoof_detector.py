"""
ARP Spoofing Detector — passive detection via ARP traffic analysis.

Detects:
  - Same IP answered from two different MACs in one session (conflicting binding)
  - Gateway MAC change (classic MITM indicator)
  - Gratuitous ARP replies changing a known binding
"""

import netifaces
from PySide6.QtCore import QObject, QThread, Signal  # pylint: disable=E0611
from scapy.all import ARP, sniff  # pylint: disable=E0611


class SpoofDetector(QThread):
    """
    Background thread that sniffs ARP traffic and emits alerts when
    suspicious behaviour is detected.

    Signals:
        alert(str)  — human-readable alert message
    """

    alert = Signal(str)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self._running = False

        # ip -> set of MACs seen this session
        self._ip_mac_table: dict[str, set] = {}

        # Capture gateway MAC at startup for change detection
        self._gateway_ip = self._get_gateway_ip()
        self._gateway_mac: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def stop(self):
        self._running = False

    def seed_known_devices(self, devices: list[tuple[str, str]]):
        """Pre-populate the table from a previous scan result (ip, mac) pairs."""
        for ip, mac in devices:
            self._ip_mac_table.setdefault(ip, set()).add(mac.lower())

    # ------------------------------------------------------------------
    # QThread
    # ------------------------------------------------------------------

    def run(self):
        self._running = True
        sniff(
            iface=self.interface,
            filter="arp",
            prn=self._process_packet,
            stop_filter=lambda _: not self._running,
            store=False,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_gateway_ip() -> str | None:
        try:
            return netifaces.gateways()["default"][netifaces.AF_INET][0]
        except (KeyError, IndexError):
            return None

    def _process_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        ip = arp.psrc
        mac = arp.hwsrc.lower()

        if not ip or ip == "0.0.0.0":
            return

        known_macs = self._ip_mac_table.get(ip)

        if known_macs is None:
            # First time we see this IP — just record it
            self._ip_mac_table[ip] = {mac}
            return

        if mac not in known_macs:
            # New MAC for a known IP — potential spoofing
            old_macs = ", ".join(known_macs)
            msg = f"[SPOOF ALERT] IP {ip} changed MAC: was {old_macs}, now {mac}"
            self.alert.emit(msg)
            known_macs.add(mac)

            # Special case: gateway MAC changed
            if ip == self._gateway_ip:
                self.alert.emit(
                    f"[CRITICAL] Gateway {ip} MAC changed to {mac} — possible MITM attack!"
                )
