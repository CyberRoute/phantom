import scapy.all as sc
from PySide6.QtCore import QObject, Signal

class PacketCollector(QObject):
    packetCaptured = Signal(str)

    def __init__(self, iface, ip_addr, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.ip_addr = ip_addr

    def start_capture(self):
        sc.sniff(
            iface=self.iface,
            stop_filter=lambda _: not True,
            filter=f'(not arp and host not {self.ip_addr})',
            prn=self.process_packet,
            store=False
        )

    def process_packet(self, packet):
        packet_summary = str(packet.summary())
        print(packet_summary)
        self.packetCaptured.emit(packet_summary)