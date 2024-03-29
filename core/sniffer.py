
import scapy.all as sc

def start_packet_collector(iface, ip_addr):

    # Continuously sniff packets for 30 second intervals
    cap = sc.sniff(
        iface=iface,
        stop_filter=lambda _: not True,
        filter=f'(not arp and host not {ip_addr})', # Avoid capturing packets to/from the host itself, except ARP, which we need for discovery -- this is for performance improvement
        timeout=30
    )
    cap.nsummary()