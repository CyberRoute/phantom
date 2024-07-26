from PyQt6.QtCore import QObject, pyqtSignal as Signal
import scapy.all as sc
from openai import OpenAI

client = OpenAI(api_key='')  # Import OpenAI



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
        self.packetCaptured.emit(packet_summary)

    @staticmethod
    def analyze_packet_with_openai(packet_info):
        try:
            response = client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": f"Analyze the following packet information: {packet_info}"}
                ]
            )
            print(response.choices[0].message.content.strip())
        except Exception as e:
            return f"Error during OpenAI API call: {str(e)}"