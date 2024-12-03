#!/bin/bash

# Required packages check (for nmap and iwlist)
check_packages() {
    if ! command -v iwlist &> /dev/null; then
        echo "iwlist is not installed. Please install it with: sudo apt install wireless-tools"
        exit 1
    fi

    if ! command -v nmap &> /dev/null; then
        echo "nmap is not installed. Please install it with: sudo apt install nmap"
        exit 1
    fi
}

# Scan Wi-Fi networks and display them
scan_network() {
    echo "[*] Scanning Wi-Fi networks..."
    iwlist wlan0 scan | grep "Cell\|Address\|ESSID\|Signal level" | awk '
    BEGIN {idx=1; print "+-------+-------------------+------------------------+-----------------+------------+"}
    /Cell/ {cell=idx++}
    /Address/ {bssid=$5}
    /ESSID/ {ssid=$2}
    /Signal level/ {signal=$4; sub(/Signal level=/, "", signal)}
    {if (bssid != "" && ssid != "") print "| " cell " | " bssid " | " ssid " | " signal " | Enabled |"}
    END {print "+-------+-------------------+------------------------+-----------------+------------+"}
    '
}

# Scan devices in the specified network
get_devices_in_network() {
    target_ip=$1
    echo "[*] Scanning devices in the $target_ip network..."
    nmap -sn $target_ip | grep "Nmap scan report" | awk '{print $5}' | while read ip; do
        echo "[*] Found device at IP: $ip"
    done
}

# Scan open ports on the specified device IP
scan_ports() {
    device_ip=$1
    echo "[*] Scanning open ports on $device_ip..."
    nmap -p- $device_ip
}

# Prompt user to select BSSID
select_bssid() {
    echo "[*] Enter the index number of the BSSID to scan (e.g., 1, 2, 3, etc.): "
    read index
    bssid=$(awk -v idx="$index" 'BEGIN {FS="|"} NR==idx {print $2}' <<< "$network_list")
    echo "[*] You selected BSSID: $bssid"
}

# Main function
main() {
    check_packages

    # Scan networks and store the results
    network_list=$(scan_network)

    # Prompt for BSSID selection
    select_bssid

    # Ask for the network IP address range to scan devices
    echo "[*] Enter the network's IP address (e.g., 192.168.1.0/24) to scan connected devices: "
    read target_ip

    # Get devices in the selected network
    get_devices_in_network $target_ip

    # Ask for the device IP to scan ports
    echo "[*] Enter the IP address of the device for port scanning: "
    read device_ip

    # Scan open ports on the selected device
    scan_ports $device_ip
}

# Run the script
main
