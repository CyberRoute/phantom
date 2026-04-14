<p align="center">
  <img alt="Phantom" src="https://raw.githubusercontent.com/CyberRoute/phantom/main/images/phantom_logo.png"/>
</p>

---

# Phantom

## Overview

Phantom is a **network reconnaissance and security auditing tool** designed for directly connected networks. It discovers devices via ARP scanning, tracks their history, detects ARP spoofing attacks, and can perform MITM interception with live packet analysis powered by a local LLM.

The GUI is built with **PySide6** (Qt framework) and uses **Scapy** for all packet-level operations.

---

## Features

- **ARP Network Scanning**: Discovers devices via ARP requests, displaying IP, MAC, hostname, and vendor.
- **Device History & Persistence**: Stores scan results in a local SQLite database; previously seen devices are shown on startup.
- **New Device & MAC Change Detection**: Highlights new devices (green) and IP-to-MAC binding changes (red) — a classic ARP spoofing indicator.
- **ARP Spoof Detection**: Passive background sniffer that alerts on conflicting ARP bindings and gateway MAC changes.
- **MITM Interception**: ARP-spoof a target to intercept its traffic; captured packets are displayed in real time with a full layer-by-layer breakdown.
- **LLM Packet Analysis**: Send any captured packet to a local [Ollama](https://ollama.com) instance for AI-assisted analysis (protocol identification, risk assessment, credential spotting).
- **PCAP Export**: Save captured packets from a MITM session as a `.pcap` file for offline analysis in Wireshark.
- **Scan Export**: Export scan results to JSON or CSV.
- **Progress Bar**: Live progress feedback during scanning.
- **Custom CIDR Target**: Scan a specific subnet instead of the local interface network.
- **Multithreading**: All network operations run in `QThread` workers — the UI stays responsive throughout.
- **C Extension (macOS)**: A native C extension provides accurate, parallel ARP scanning on macOS where Scapy bulk-send is unreliable.

---

## Requirements

- **Python 3.12+**
- **scapy** — ARP scanning and packet manipulation
- **PySide6** — graphical user interface
- **netifaces** — network interface introspection
- **requests** — Ollama API streaming
- **Ollama** (optional) — local LLM for packet analysis (`ollama serve`)

---

## Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/CyberRoute/phantom.git
    cd phantom
    ```

2. **Create a virtual environment and install dependencies**:

    ```bash
    virtualenv env
    source env/bin/activate
    pip install -r requirements.txt
    ```

3. **(macOS only) Build the native C extension**:

    ```bash
    pip install setuptools
    cd c_extension
    python setup.py build
    python setup.py install
    cd ..
    ```

4. **Run the application** (root/sudo is required for raw packet operations):

    ```bash
    sudo `which python3` main.py --interface <interface> --timeout 500
    ```

    Optional arguments:

    | Argument | Default | Description |
    |---|---|---|
    | `--interface` | *(required)* | Network interface name (e.g. `eth0`, `wlan0`) |
    | `--timeout` | `1000` | ARP scan timeout in milliseconds |
    | `--target` | interface network | Custom CIDR range to scan (e.g. `10.0.0.0/24`) |

### Troubleshooting (Ubuntu / xcb plugin error)

```
qt.qpa.plugin: Could not load the Qt platform plugin "xcb"
```

Fix:

```bash
sudo apt install libxcb-cursor0
```

---

## Usage

### 1. Scan the network

Click **Scan** to start an ARP sweep of the local network (or a custom CIDR if `--target` was specified). Devices appear as they respond:

- **White** — previously seen device, confirmed live
- **Green** — new device (first time seen)
- **Red** — IP address answered with a different MAC than before (possible ARP spoofing)
- **Grey** — device from the database not yet confirmed live in this scan

A progress bar tracks scan completion. Results can be exported to JSON or CSV with **Export Results**.

### 2. Inspect a device

Click any device in the list to open its detail window, which shows:

- IP, MAC, hostname, vendor
- First seen / last seen timestamps
- Full MAC address history (useful for spoofing audits)
- MITM controls

### 3. MITM interception

From the device detail window, click **Start MITM** to:

1. ARP-spoof the target and the gateway (Phantom inserts itself in the traffic path).
2. Enable IP forwarding so the target's internet access is preserved.
3. Capture all non-ARP traffic to/from the target in real time.

Click any captured packet to see a full hex dump and layer-by-layer field breakdown.  
Click **Save PCAP** to write the captured session to a `.pcap` file.

> **Note:** MITM requires root/sudo. IP forwarding is restored automatically when MITM is stopped.

### 4. LLM packet analysis (Ollama)

With [Ollama](https://ollama.com) running locally (`ollama serve`) and at least one model pulled:

1. Select a captured packet in the MITM window.
2. Choose a model from the **Model** drop-down (populated automatically from the running Ollama instance). Click **↻** to refresh the list after pulling a new model.
3. Optionally add context in the **Context** field (e.g. `"this is a smart TV"`).
4. Click **Analyse with LLM** — the analysis opens in a dedicated window and streams in token by token. Use **Copy analysis** to copy the result to the clipboard.

The LLM identifies protocol/service, describes what the endpoints are doing, flags security-relevant observations, and provides a risk rating.

> **Tip:** Any model available via `ollama list` can be used. Smaller models (e.g. `llama3.2:1b`) respond faster; larger ones (e.g. `llama3.1:8b`) give more detailed analysis.

---

## Architecture

```
main.py                  — entry point, CLI args, QApplication bootstrap
core/
  arp_scanner.py         — ARPScannerThread, DeviceDiscoveryDialog, DeviceDetailsWindow
  arp_spoofer.py         — low-level ARP spoof / restore primitives
  mitm.py                — MitmThread (spoof loop + sniffer), IP forwarding management
  spoof_detector.py      — passive ARP sniff-based spoof detection
  ollama_analyst.py      — OllamaThread for streaming LLM packet analysis
  db.py                  — SQLite persistence (device history, MAC audit trail)
  networking.py          — CIDR calculation, hostname resolution helpers
  vendor.py              — OUI/MAC vendor lookup
  platform.py            — OS detection helper
c_extension/             — native C ARP scanner for macOS
ui/                      — PySide6 .ui compiled files
```

---

## Contribute

Fork the repo and send PRs if you like :)
