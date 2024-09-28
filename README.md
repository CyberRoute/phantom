<p align="center">
  <img alt="Phantom" src="https://raw.githubusercontent.com/CyberRoute/phantom/main/images/phantom_logo.png"/>
  <p align="center">
  </p>
</p>

# Phantom

## Overview
Phantom is an **ARP Scanner** mostly designed to detect directly connected IoT devices. The tool provides details like IP addresses, MAC addresses, hostnames, and the manufacturers of the devices based on their MAC addresses.
The tool features a graphical user interface (GUI) built with **PySide6** (Qt framework) and utilizes **scapy** for ARP scanning.

---

## Features
- **Network Scanning**: Identifies devices on the network via ARP requests.
- **Device Details**: Displays IP address, MAC address, hostname, and vendor information.
- **Real-time Sniffing**: Captures and lists ARP packets in real-time.
- **Graphical User Interface**: Easy-to-use UI to display the scanned devices and packet information.
- **Multithreading**: Ensures non-blocking scans using Python's `QThread`.

---

## Prerequisites

Ensure the following dependencies are installed:

1. **Python 3.8 or higher**
2. **scapy**: Used for ARP scanning.
3. **PySide6 or PyQt6**: For building the GUI.
4. **netifaces**: To retrieve network interface details.

## Requirements

- **Python 3.8+**
- **pipenv**: For managing the virtual environment and dependencies.
- **scapy**: For ARP scanning and packet manipulation.
- **PySide6**: For building the graphical user interface.
- **netifaces**: To retrieve network interface details.

---

## Installation

1. **Clone the repository**:

    Clone the repository to your local machine:

    ```bash
    git clone https://github.com/CyberRoute/phantom.git
    cd phantom
    ```

2. **Install the dependencies with Pipenv**:

    Install `pipenv` if it's not already installed:

    ```bash
    sudo pip install pipenv
    ```

    Then, use `pipenv` to create the virtual environment and install the required dependencies:

    ```bash
    sudo pipenv install
    ```

    To activate the virtual environment:

    ```bash
    sudo pipenv shell
    ```

3. **Run the application**:

    Run the ARP Scanner using the following command. You need to provide the network interface (like `eth0`, `wlan0`, or `wlp0s20f3`) for your system:

    ```bash
    sudo pipenv run python3 main.py --interface <interface>
    ```

    Example:
    ```bash
    sudo pipenv run python3 main.py --interface wlp0s20f3
    ```

## Usage Instructions

1. **Start the Application**:

    After running the application with the correct interface, the GUI will launch.

<div align="center">
    <img src="/images/phantom.png" width="800px"</img>
</div>

2. **Scanning the Network**:

    - Click on the **"Scan"** button in the UI to initiate a network scan.
    - The tool will display a list of all detected devices in the network, including their IP addresses, MAC addresses, hostnames, and vendors.

3. **Viewing Packets**:

    - The tool also captures ARP packets in real-time. You can view these packets in a separate tab within the GUI.

4. **Device Details**:

    - Click on any device in the list to open a detailed window that shows more information about that particular device.

5. **Stopping the Scan**:

    - Press the **"Quit"** button to stop the ARP scan and close the application.

## Contribute
Fork the repo and send PRs if you like :)

