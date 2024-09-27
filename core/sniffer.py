"""Module Sniffer"""

from PyQt6.QtCore import QObject, pyqtSignal as Signal # pylint: disable=E0611
import scapy.all as scapy


class PacketCollector(QObject):
    """
    Class responsible for capturing network packets using Scapy.
    Emits a signal when a packet is captured.
    """
    packetCaptured = Signal(str)

    def __init__(self, iface, ip_addr, parent=None):
        """
        Initializes the PacketCollector.

        :param iface: Network interface to sniff on.
        :param ip_addr: IP address to exclude from capture.
        :param parent: Optional parent for QObject.
        """
        super().__init__(parent)
        self.iface = iface
        self.ip_addr = ip_addr
        self.running = False

    def start_capture(self):
        """
        Starts capturing packets on the specified network interface.
        The capture filters out ARP packets and packets originating from the specified IP address.
        """
        self.running = True
        scapy.sniff(
            iface=self.iface,
            stop_filter=self._stop_filter,
            filter=f'(not arp and host not {self.ip_addr})',
            prn=self.process_packet,
            store=False
        )

    def _stop_filter(self):
        """
        Stop filter for the sniffing process.
        Capture stops when 'running' is set to False.

        :param _: Placeholder for the packet argument (unused).
        :return: Boolean indicating whether to stop the capture.
        """
        return not self.running

    def process_packet(self, packet):
        """
        Processes a captured packet, emitting its summary as a signal.

        :param packet: The packet to process.
        """
        packet_summary = str(packet.summary())
        self.packetCaptured.emit(packet_summary)

    def stop_capture(self):
        """
        Stops capturing packets by setting the 'running' flag to False.
        """
        self.running = False
