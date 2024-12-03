# 

import subprocess
import sys
import os
import pexpect  # type: ignore
from prettytable import PrettyTable  # type: ignore

# Required packages
required_packages = ['pexpect', 'prettytable']

# Function to install a package
def install_package(package):
    """Check if the package is installed and install if not."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check and install missing packages
def check_and_install_packages():
    """Check for missing packages and install them."""
    for package in required_packages:
        try:
            # Check if the package is installed
            __import__(package)
            print(f"{package} is already installed.")
        except ImportError:
            # Install the package if it's missing
            print(f"{package} is not installed, installing...")
            install_package(package)

# Check and install required packages
check_and_install_packages()

def scan_network():
    """Scan available Wi-Fi networks and display them in a table."""
    print("[*] Scanning Wi-Fi networks...")
    scan_result = subprocess.run(['iwlist', 'wlan0', 'scan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    networks = scan_result.stdout.split('Cell')
    
    table = PrettyTable()
    table.field_names = ["Index", "BSSID", "SSID", "Signal Strength", "Encryption"]
    
    bssid_list = []
    
    for idx, network in enumerate(networks[1:], start=1):
        lines = network.split("\n")
        bssid = None
        ssid = None
        signal_strength = None
        encryption = None
        
        for line in lines:
            if "Address:" in line:
                bssid = line.split("Address:")[1].strip()
            elif "ESSID:" in line:
                ssid = line.split('ESSID:"')[1].split('"')[0]
            elif "Signal level=" in line:
                signal_strength = line.split("Signal level=")[1].split(' ')[0]
            elif "Encryption key:" in line:
                encryption = "Enabled" if "on" in line else "Disabled"
        
        if bssid and ssid:
            bssid_list.append(bssid)
            table.add_row([idx, bssid, ssid, signal_strength, encryption])
    
    print(table)
    return bssid_list

def get_devices_in_network(target_ip):
    """List the devices connected to the given network."""
    print(f"[*] Scanning devices in the {target_ip} network...")
    result = subprocess.run(["nmap", "-sn", target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    devices = result.stdout.split("\n")
    
    devices_table = PrettyTable()
    devices_table.field_names = ["Index", "IP Address", "MAC Address"]
    
    device_list = []
    index = 1
    
    for device in devices:
        if "Nmap scan report" in device:
            ip_address = device.split("for")[1].strip()
            mac_address = "N/A"
            for line in devices:
                if "MAC Address" in line:
                    mac_address = line.split(" ")[1]
                    break
            devices_table.add_row([index, ip_address, mac_address])
            device_list.append(ip_address)
            index += 1

    if device_list:
        print(devices_table)
    else:
        print("[!] No devices found on the network.")
    
    return device_list

def scan_ports(ip_address):
    """Scan open ports on the specified IP address."""
    print(f"[*] Scanning open ports on {ip_address}...")
    result = subprocess.run(["nmap", "-p-", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(result.stdout)

def valid_bssid_index(bssid_list):
    """Get a valid index for BSSID selection."""
    while True:
        try:
            selected_index = int(input("\n[*] Enter the index number of the BSSID to scan (e.g., 1, 2, 3, etc.): "))
            if 1 <= selected_index <= len(bssid_list):
                return bssid_list[selected_index - 1]
            else:
                print("[!] Invalid index. Please select a valid number from the list.")
        except ValueError:
            print("[!] Invalid input. Please enter a valid number.")

def get_network_ip_from_user():
    """Prompt the user for the network IP (e.g., 192.168.1.0/24)."""
    while True:
        target_ip = input("\n[*] Enter the network's IP address (e.g., 192.168.1.0/24) to scan connected devices: ")
        if target_ip:
            return target_ip
        else:
            print("[!] Invalid input. Please enter a valid IP address range.")

def main():
    # Scan networks
    bssid_list = scan_network()
    
    # Get BSSID index from user
    selected_bssid = valid_bssid_index(bssid_list)
    print(f"[*] You selected BSSID: {selected_bssid}")
    
    # Get IP address range from user (network IP)
    target_ip = get_network_ip_from_user()
    
    # Scan devices in the given network (IP)
    device_list = get_devices_in_network(target_ip)
    
    if device_list:
        # Get the device IP for port scanning
        while True:
            device_ip = input("\n[*] Enter the IP address of the device for port scanning: ")
            if device_ip:
                scan_ports(device_ip)
                break
            else:
                print("[!] Invalid IP address. Please enter a valid IP.")
    else:
        print("[!] No devices found in the selected network range.")

if __name__ == "__main__":
    main()
