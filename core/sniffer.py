from PyQt6.QtCore import QObject, pyqtSignal as Signal
import scapy.all as scapy


class PacketCollector(QObject):
    packetCaptured = Signal(str)

    def __init__(self, iface, ip_addr, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.ip_addr = ip_addr
        self.running = False

    def start_capture(self):
        self.running = True
        scapy.sniff(
            iface=self.iface,
            stop_filter=self._stop_filter,
            filter=f'(not arp and host not {self.ip_addr})',
            prn=self.process_packet,
            store=False
        )

    def _stop_filter(self, packet):
        return not self.running

    def process_packet(self, packet):
        packet_summary = str(packet.summary())
        self.packetCaptured.emit(packet_summary)

    def stop_capture(self):
        self.running = False
